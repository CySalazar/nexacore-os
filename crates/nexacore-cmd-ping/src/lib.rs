//! # `nexacore-cmd-ping`
//!
//! ICMP ping command for NexaCore OS.
//!
//! Provides ICMP echo request/reply packet construction, response parsing, RTT
//! calculation, and statistics aggregation for the `ping` network diagnostic
//! tool.  This crate is a pure `no_std + alloc` library; the bare-metal binary
//! entry point lives in a sibling `-image` crate, following the same pattern
//! used by NexaCore OS userspace drivers.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`PingConfig`] | Session parameters (target, count, interval, timeout, …) |
//! | [`PingStatistics`] | Accumulate RTT samples and compute summary metrics |
//! | [`EchoReply`] | Parsed echo-reply fields (id, sequence, payload) |
//! | [`build_echo_request`] | Construct a valid ICMP echo-request byte vector |
//! | [`parse_echo_reply`] | Decode a raw ICMP echo-reply byte slice |
//! | [`format_ping_line`] | Format a single `64 bytes from …` output line |
//! | [`parse_args`] | Parse `ping [-c N] [-i I] [-W T] [-s S] <host>` args |
//! | [`PingError`] | Typed error returned by [`parse_args`] and parse helpers |
//!
//! ## Design decisions
//!
//! - **No `std`**: all formatting uses integer arithmetic to avoid the
//!   `clippy::float_arithmetic` lint and `f64` formatting that requires `std`.
//!   RTT values are carried in microseconds (`u64`) and converted to ms with
//!   manual integer division (whole-ms part) and modulo (fractional-ms part).
//! - **No `unsafe`**: `#![forbid(unsafe_code)]` is set unconditionally.
//! - **Checksum via `nexacore_types`**: `IcmpHeader::compute_checksum` already
//!   implements RFC 1071 internet checksum; this crate delegates to it.
//!
//! ## RFC references
//!
//! - RFC 792 — Internet Control Message Protocol
//! - RFC 1071 — Computing the Internet Checksum

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Technical terms like IPv4, ICMP, RFC are industry-standard abbreviations and
// do not need backtick wrapping in prose documentation.
// Integer division is used intentionally for RTT-to-milliseconds display
// formatting (truncation to whole ms is correct for ping output), and for
// converting microseconds to fractional ms (2 decimal places via `% 1000 / 10`).
// The suppression is applied at the function level where the divisions occur,
// not blanket across the crate.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        clippy::indexing_slicing,
    )
)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use nexacore_types::net::{IcmpCode, IcmpEchoHeader, IcmpHeader, IcmpType, Ipv4Addr};

// =============================================================================
// PingConfig
// =============================================================================

/// Configuration for a ping session.
///
/// Construct with [`PingConfig::default`] for a sensible starting point, then
/// override individual fields or use [`parse_args`] to populate from
/// command-line arguments.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ping::PingConfig;
/// use nexacore_types::net::Ipv4Addr;
///
/// let cfg = PingConfig {
///     target: Ipv4Addr([8, 8, 8, 8]),
///     count: 4,
///     ..PingConfig::default()
/// };
/// assert_eq!(cfg.count, 4);
/// assert_eq!(cfg.ttl, 64);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingConfig {
    /// Target IP address to send ICMP echo requests to.
    pub target: Ipv4Addr,
    /// Number of echo requests to send (`0` means unlimited).
    pub count: u32,
    /// Interval between successive pings in milliseconds.
    pub interval_ms: u64,
    /// Per-ping reply timeout in milliseconds.
    pub timeout_ms: u64,
    /// ICMP payload size in bytes (default 56; total ICMP = payload + 8-byte
    /// ICMP header = 64 bytes, matching the classic ping default).
    pub payload_size: u16,
    /// Identifier embedded in every echo request for this session (typically
    /// the process ID on POSIX systems; a constant in kernel contexts).
    pub identifier: u16,
    /// Initial IP Time-To-Live value.
    pub ttl: u8,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            target: Ipv4Addr::UNSPECIFIED,
            count: 0,
            interval_ms: 1000,
            timeout_ms: 5000,
            // Classic ping default: 56 bytes of payload + 8 bytes ICMP = 64.
            payload_size: 56,
            identifier: 1,
            ttl: 64,
        }
    }
}

// =============================================================================
// PingStatistics
// =============================================================================

/// Accumulated statistics for a completed (or in-progress) ping session.
///
/// Call [`PingStatistics::record_rtt`] for each successful echo reply, then
/// retrieve summary metrics via [`PingStatistics::avg_rtt_us`],
/// [`PingStatistics::packet_loss_percent`], or
/// [`PingStatistics::format_summary`].
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ping::PingStatistics;
///
/// let mut stats = PingStatistics::new();
/// stats.packets_sent = 3;
/// stats.record_rtt(1200);
/// stats.record_rtt(800);
/// stats.record_rtt(1000);
/// assert_eq!(stats.min_rtt_us, 800);
/// assert_eq!(stats.max_rtt_us, 1200);
/// assert_eq!(stats.avg_rtt_us(), 1000);
/// assert_eq!(stats.packet_loss_percent(), 0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct PingStatistics {
    /// Total number of ICMP echo requests transmitted.
    pub packets_sent: u32,
    /// Total number of ICMP echo replies received.
    pub packets_received: u32,
    /// Minimum observed round-trip time in microseconds.
    pub min_rtt_us: u64,
    /// Maximum observed round-trip time in microseconds.
    pub max_rtt_us: u64,
    /// Sum of all observed round-trip times in microseconds (for average
    /// computation).
    pub total_rtt_us: u64,
}

impl PingStatistics {
    /// Create a new, zeroed [`PingStatistics`].
    ///
    /// Equivalent to `PingStatistics::default()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_cmd_ping::PingStatistics;
    ///
    /// let stats = PingStatistics::new();
    /// assert_eq!(stats.packets_sent, 0);
    /// assert_eq!(stats.packets_received, 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful round-trip observation of `rtt_us` microseconds.
    ///
    /// Increments [`Self::packets_received`], adds `rtt_us` to
    /// [`Self::total_rtt_us`], and updates [`Self::min_rtt_us`] /
    /// [`Self::max_rtt_us`] as appropriate.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_cmd_ping::PingStatistics;
    ///
    /// let mut stats = PingStatistics::new();
    /// stats.record_rtt(500);
    /// assert_eq!(stats.packets_received, 1);
    /// assert_eq!(stats.min_rtt_us, 500);
    /// assert_eq!(stats.max_rtt_us, 500);
    /// ```
    pub fn record_rtt(&mut self, rtt_us: u64) {
        self.packets_received += 1;
        self.total_rtt_us += rtt_us;
        // On the first sample, unconditionally set min and max.
        // On subsequent samples, update only when the new value breaks the record.
        if self.packets_received == 1 || rtt_us < self.min_rtt_us {
            self.min_rtt_us = rtt_us;
        }
        if rtt_us > self.max_rtt_us {
            self.max_rtt_us = rtt_us;
        }
    }

    /// Compute the average RTT in microseconds.
    ///
    /// Returns `0` when no replies have been recorded (avoids division by zero).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_cmd_ping::PingStatistics;
    ///
    /// let mut stats = PingStatistics::new();
    /// assert_eq!(stats.avg_rtt_us(), 0);
    /// stats.record_rtt(1000);
    /// stats.record_rtt(2000);
    /// assert_eq!(stats.avg_rtt_us(), 1500);
    /// ```
    #[must_use]
    pub fn avg_rtt_us(&self) -> u64 {
        if self.packets_received == 0 {
            return 0;
        }
        // Intentional integer division: truncated average in microseconds.
        // The fractional part is negligible for network diagnostic output.
        #[allow(clippy::integer_division)]
        {
            self.total_rtt_us / u64::from(self.packets_received)
        }
    }

    /// Compute the packet loss percentage.
    ///
    /// Returns `0` when no packets have been sent (avoids division by zero).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_cmd_ping::PingStatistics;
    ///
    /// let mut stats = PingStatistics::new();
    /// stats.packets_sent = 4;
    /// stats.record_rtt(1000); // 1 received
    /// assert_eq!(stats.packet_loss_percent(), 75);
    /// ```
    #[must_use]
    pub fn packet_loss_percent(&self) -> u32 {
        if self.packets_sent == 0 {
            return 0;
        }
        let lost = self.packets_sent.saturating_sub(self.packets_received);
        // Intentional integer division: packet loss as a whole-percent value,
        // matching the output format produced by every standard ping utility.
        #[allow(clippy::integer_division)]
        {
            (lost * 100) / self.packets_sent
        }
    }

    /// Format the final statistics summary in the style of standard ping output.
    ///
    /// RTT values are expressed in milliseconds with two decimal places using
    /// purely integer arithmetic (no floating-point) so the output is correct
    /// under `no_std` where `f64` formatting is unavailable.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_cmd_ping::PingStatistics;
    /// use nexacore_types::net::Ipv4Addr;
    ///
    /// let mut stats = PingStatistics::new();
    /// stats.packets_sent = 1;
    /// stats.record_rtt(1500); // 1.50 ms
    /// let summary = stats.format_summary(Ipv4Addr([8, 8, 8, 8]));
    /// assert!(summary.contains("1 packets transmitted"));
    /// assert!(summary.contains("1 received"));
    /// assert!(summary.contains("0% packet loss"));
    /// assert!(summary.contains("1.50"));
    /// ```
    #[must_use]
    pub fn format_summary(&self, target: Ipv4Addr) -> String {
        // Convert microsecond values to "ms.cc" (two-decimal-place ms) using
        // integer arithmetic only.
        //
        // Whole milliseconds: us / 1000
        // Fractional 1/100 ms (centiseconds): (us % 1000) / 10
        //
        // Both divisions are intentional display truncations.
        #[allow(clippy::integer_division)]
        let min_ms = self.min_rtt_us / 1000;
        #[allow(clippy::integer_division)]
        let min_frac = (self.min_rtt_us % 1000) / 10;
        let raw_avg_us = self.avg_rtt_us();
        #[allow(clippy::integer_division)]
        let avg_ms = raw_avg_us / 1000;
        #[allow(clippy::integer_division)]
        let avg_frac = (raw_avg_us % 1000) / 10;
        #[allow(clippy::integer_division)]
        let max_ms = self.max_rtt_us / 1000;
        #[allow(clippy::integer_division)]
        let max_frac = (self.max_rtt_us % 1000) / 10;

        let sent = self.packets_sent;
        let recv = self.packets_received;
        let loss = self.packet_loss_percent();
        format!(
            "--- {target} ping statistics ---\n\
             {sent} packets transmitted, {recv} received, {loss}% packet loss\n\
             rtt min/avg/max = {min_ms}.{min_frac:02}/{avg_ms}.{avg_frac:02}/{max_ms}.{max_frac:02} ms"
        )
    }
}

// =============================================================================
// EchoReply
// =============================================================================

/// A successfully parsed ICMP echo reply.
///
/// Returned by [`parse_echo_reply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoReply {
    /// Echo identifier — should match the identifier in the outgoing request.
    pub id: u16,
    /// Echo sequence number.
    pub sequence: u16,
    /// Payload bytes following the 8-byte ICMP header.
    pub payload: Vec<u8>,
}

// =============================================================================
// Packet construction
// =============================================================================

/// Build a complete ICMP echo request packet (ICMP portion only, no IP header).
///
/// The returned `Vec<u8>` is:
///
/// ```text
/// [0]   type   = 8  (ICMP Echo Request)
/// [1]   code   = 0
/// [2..3] checksum (RFC 1071, computed over the full packet)
/// [4..5] identifier (big-endian)
/// [6..7] sequence  (big-endian)
/// [8..]  payload
/// ```
///
/// The checksum field is computed and filled in by this function; the caller
/// does not need to patch it.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ping::build_echo_request;
/// use nexacore_types::net::{IcmpHeader, IcmpType};
///
/// let payload = [0xABu8; 56];
/// let pkt = build_echo_request(0x1234, 1, &payload);
/// // Minimum length: 8-byte ICMP header + 56-byte payload = 64.
/// assert_eq!(pkt.len(), 64);
/// // Type byte must be Echo Request (8).
/// assert_eq!(pkt[0], IcmpType::ECHO_REQUEST.0);
/// // Code must be 0.
/// assert_eq!(pkt[1], 0);
/// // Verify checksum is valid.
/// let (hdr, rest) = IcmpHeader::parse(&pkt).unwrap();
/// assert!(hdr.verify_checksum(rest));
/// ```
#[must_use]
pub fn build_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    // Assemble the echo header into the `rest` field of IcmpHeader.
    let echo = IcmpEchoHeader { id, sequence: seq };
    let mut hdr = IcmpHeader {
        icmp_type: IcmpType::ECHO_REQUEST,
        code: IcmpCode::ZERO,
        checksum: 0, // filled in below
        rest: echo.to_rest(),
    };

    // Compute checksum over header (with checksum = 0) and payload.
    hdr.checksum = hdr.compute_checksum(payload);

    // Serialise into a contiguous buffer.
    let mut pkt = Vec::with_capacity(IcmpHeader::HEADER_LEN + payload.len());
    // Extend with 8 zeroed header bytes, then overwrite via serialize.
    pkt.resize(IcmpHeader::HEADER_LEN, 0u8);
    // serialize returns None only if the buffer is too small; we sized it
    // exactly to HEADER_LEN above, so this cannot return None.
    let _ = hdr.serialize(&mut pkt);
    pkt.extend_from_slice(payload);
    pkt
}

// =============================================================================
// Packet parsing
// =============================================================================

/// Parse an ICMP echo reply from raw ICMP data.
///
/// Returns `Some(EchoReply)` when `data` contains a well-formed ICMP echo reply
/// (type = 0).  Returns `None` on any of the following conditions:
///
/// - Buffer shorter than 8 bytes (minimum ICMP header length).
/// - ICMP type is not [`IcmpType::ECHO_REPLY`] (`0`).
///
/// The caller is responsible for checksum validation when required; this
/// function does not re-compute the checksum so it can be used in both
/// validated (post-kernel-TCP/IP-stack) and raw-socket contexts.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ping::{build_echo_request, parse_echo_reply};
///
/// let payload = b"test payload!!".as_slice();
/// // Build a request and manually flip the type byte to simulate a reply.
/// let mut pkt = build_echo_request(42, 7, payload);
/// pkt[0] = 0; // ICMP Echo Reply type
/// // Re-compute checksum since we changed the type.
/// use nexacore_types::net::{IcmpCode, IcmpEchoHeader, IcmpHeader, IcmpType};
/// let echo = IcmpEchoHeader {
///     id: 42,
///     sequence: 7,
/// };
/// let mut hdr = IcmpHeader {
///     icmp_type: IcmpType::ECHO_REPLY,
///     code: IcmpCode::ZERO,
///     checksum: 0,
///     rest: echo.to_rest(),
/// };
/// hdr.checksum = hdr.compute_checksum(payload);
/// hdr.serialize(&mut pkt).unwrap();
/// let reply = parse_echo_reply(&pkt).unwrap();
/// assert_eq!(reply.id, 42);
/// assert_eq!(reply.sequence, 7);
/// assert_eq!(reply.payload, payload);
/// ```
#[must_use]
pub fn parse_echo_reply(data: &[u8]) -> Option<EchoReply> {
    let (hdr, rest) = IcmpHeader::parse(data)?;
    if hdr.icmp_type != IcmpType::ECHO_REPLY {
        return None;
    }
    let echo = IcmpEchoHeader::from_rest(hdr.rest);
    Some(EchoReply {
        id: echo.id,
        sequence: echo.sequence,
        payload: rest.to_vec(),
    })
}

// =============================================================================
// Output formatting
// =============================================================================

/// Format a single ping response line in the style of standard ping output.
///
/// Produces output of the form:
///
/// ```text
/// 64 bytes from 8.8.8.8: icmp_seq=1 ttl=56 time=12.34 ms
/// ```
///
/// RTT is expressed in milliseconds with two decimal places using integer
/// arithmetic only (no `f64`).
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ping::format_ping_line;
/// use nexacore_types::net::Ipv4Addr;
///
/// let line = format_ping_line(64, Ipv4Addr([8, 8, 8, 8]), 1, 56, 12_340);
/// assert_eq!(
///     line,
///     "64 bytes from 8.8.8.8: icmp_seq=1 ttl=56 time=12.34 ms"
/// );
/// ```
#[must_use]
pub fn format_ping_line(bytes: u16, src_ip: Ipv4Addr, seq: u16, ttl: u8, rtt_us: u64) -> String {
    // Intentional integer divisions for display truncation to 2 decimal places.
    #[allow(clippy::integer_division)]
    let ms = rtt_us / 1000;
    #[allow(clippy::integer_division)]
    let frac = (rtt_us % 1000) / 10;
    format!("{bytes} bytes from {src_ip}: icmp_seq={seq} ttl={ttl} time={ms}.{frac:02} ms")
}

// =============================================================================
// PingError
// =============================================================================

/// Errors that can arise from [`parse_args`] or packet parsing helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingError {
    /// No target host/address was provided on the command line.
    MissingTarget,
    /// The value supplied for `-c` (count) could not be parsed as a `u32`.
    InvalidCount,
    /// The value supplied for `-i` (interval) could not be parsed as a `u64`.
    InvalidInterval,
    /// The value supplied for `-W` (timeout) could not be parsed as a `u64`.
    InvalidTimeout,
    /// The value supplied for `-s` (payload size) could not be parsed as a
    /// `u16` or exceeds the maximum supported size.
    InvalidSize,
    /// The target address string could not be parsed as a dotted-decimal `IPv4`
    /// address.
    InvalidAddress,
    /// An unrecognised flag was encountered.
    UnknownFlag,
    /// The ICMP checksum in a received packet did not match the computed value.
    ChecksumMismatch,
    /// The identifier field in a received echo reply did not match the session
    /// identifier.
    IdentifierMismatch,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `ping` command.
///
/// Supported flags (in any order before the target):
///
/// | Flag | Argument | Effect |
/// |------|----------|--------|
/// | `-c` | `<count>` | Number of packets to send (`0` = unlimited) |
/// | `-i` | `<interval>` | Inter-packet interval in milliseconds |
/// | `-W` | `<timeout>` | Per-packet reply timeout in milliseconds |
/// | `-s` | `<size>` | Payload size in bytes |
///
/// The final non-flag argument is treated as the target `IPv4` address in
/// dotted-decimal notation.
///
/// # Errors
///
/// Returns a [`PingError`] variant when any argument cannot be parsed:
///
/// - [`PingError::MissingTarget`] — no target was given.
/// - [`PingError::InvalidAddress`] — target is not a valid `IPv4` address.
/// - [`PingError::InvalidCount`] / [`PingError::InvalidInterval`] /
///   [`PingError::InvalidTimeout`] / [`PingError::InvalidSize`] — the
///   accompanying numeric argument is invalid.
/// - [`PingError::UnknownFlag`] — an unrecognised `-x` flag was given.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ping::{PingError, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// // Simplest usage: just a target.
/// let cfg = parse_args(&["8.8.8.8"]).unwrap();
/// assert_eq!(cfg.target, Ipv4Addr([8, 8, 8, 8]));
/// assert_eq!(cfg.count, 0); // unlimited by default
///
/// // All flags.
/// let cfg = parse_args(&["-c", "4", "-i", "500", "-W", "2000", "-s", "32", "1.1.1.1"]).unwrap();
/// assert_eq!(cfg.count, 4);
/// assert_eq!(cfg.interval_ms, 500);
/// assert_eq!(cfg.timeout_ms, 2000);
/// assert_eq!(cfg.payload_size, 32);
/// assert_eq!(cfg.target, Ipv4Addr([1, 1, 1, 1]));
///
/// // Missing target.
/// assert_eq!(parse_args(&["-c", "3"]), Err(PingError::MissingTarget));
///
/// // Bad address.
/// assert_eq!(parse_args(&["not-an-ip"]), Err(PingError::InvalidAddress));
/// ```
pub fn parse_args(args: &[&str]) -> Result<PingConfig, PingError> {
    let mut cfg = PingConfig::default();
    let mut target_str: Option<&str> = None;
    let mut idx = 0usize;

    while idx < args.len() {
        // Safe: idx < args.len() verified by loop condition.
        let arg = args.get(idx).copied().unwrap_or("");
        match arg {
            "-c" => {
                idx += 1;
                let val = args.get(idx).ok_or(PingError::InvalidCount)?;
                cfg.count = val.parse::<u32>().map_err(|_| PingError::InvalidCount)?;
            }
            "-i" => {
                idx += 1;
                let val = args.get(idx).ok_or(PingError::InvalidInterval)?;
                cfg.interval_ms = val.parse::<u64>().map_err(|_| PingError::InvalidInterval)?;
            }
            "-W" => {
                idx += 1;
                let val = args.get(idx).ok_or(PingError::InvalidTimeout)?;
                cfg.timeout_ms = val.parse::<u64>().map_err(|_| PingError::InvalidTimeout)?;
            }
            "-s" => {
                idx += 1;
                let val = args.get(idx).ok_or(PingError::InvalidSize)?;
                cfg.payload_size = val.parse::<u16>().map_err(|_| PingError::InvalidSize)?;
            }
            s if s.starts_with('-') => {
                return Err(PingError::UnknownFlag);
            }
            s => {
                // Non-flag argument is the target.
                target_str = Some(s);
            }
        }
        idx += 1;
    }

    let target_s = target_str.ok_or(PingError::MissingTarget)?;
    cfg.target = target_s
        .parse::<Ipv4Addr>()
        .map_err(|_| PingError::InvalidAddress)?;

    Ok(cfg)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // `vec!` is not automatically in scope under `no_std`; import the macro
    // explicitly so test helpers can build `Vec<u8>` literals.
    #[allow(unused_imports)]
    use alloc::vec;

    use super::*;

    // -------------------------------------------------------------------------
    // Echo request construction
    // -------------------------------------------------------------------------

    #[test]
    fn build_echo_request_correct_type_and_code() {
        let pkt = build_echo_request(1, 1, &[0u8; 56]);
        assert_eq!(pkt[0], IcmpType::ECHO_REQUEST.0, "type must be 8");
        assert_eq!(pkt[1], 0, "code must be 0");
    }

    #[test]
    fn build_echo_request_checksum_is_valid() {
        let payload = [0xAAu8; 56];
        let pkt = build_echo_request(0x1234, 7, &payload);
        let (hdr, rest) = IcmpHeader::parse(&pkt).unwrap();
        assert!(
            hdr.verify_checksum(rest),
            "checksum must be valid over header+payload"
        );
    }

    #[test]
    fn build_echo_request_contains_id_and_sequence() {
        let pkt = build_echo_request(0xBEEF, 0x0042, &[]);
        let (hdr, _rest) = IcmpHeader::parse(&pkt).unwrap();
        let echo = IcmpEchoHeader::from_rest(hdr.rest);
        assert_eq!(echo.id, 0xBEEF);
        assert_eq!(echo.sequence, 0x0042);
    }

    #[test]
    fn build_echo_request_includes_payload() {
        let payload = [1u8, 2, 3, 4, 5];
        let pkt = build_echo_request(1, 1, &payload);
        assert_eq!(pkt.len(), IcmpHeader::HEADER_LEN + payload.len());
        assert_eq!(&pkt[IcmpHeader::HEADER_LEN..], &payload);
    }

    #[test]
    fn build_echo_request_empty_payload() {
        let pkt = build_echo_request(0, 0, &[]);
        assert_eq!(pkt.len(), IcmpHeader::HEADER_LEN);
        let (hdr, rest) = IcmpHeader::parse(&pkt).unwrap();
        assert!(hdr.verify_checksum(rest));
    }

    // -------------------------------------------------------------------------
    // Echo reply parsing
    // -------------------------------------------------------------------------

    /// Build a valid ICMP echo reply byte vector for the given id/seq/payload.
    fn make_echo_reply(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let echo = IcmpEchoHeader { id, sequence: seq };
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::ECHO_REPLY,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: echo.to_rest(),
        };
        hdr.checksum = hdr.compute_checksum(payload);
        let mut pkt = vec![0u8; IcmpHeader::HEADER_LEN];
        hdr.serialize(&mut pkt).unwrap();
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_echo_reply_roundtrip() {
        let payload = b"roundtrip test".as_slice();
        let pkt = make_echo_reply(0xCAFE, 3, payload);
        let reply = parse_echo_reply(&pkt).unwrap();
        assert_eq!(reply.id, 0xCAFE);
        assert_eq!(reply.sequence, 3);
        assert_eq!(reply.payload, payload);
    }

    #[test]
    fn parse_echo_reply_wrong_type_returns_none() {
        // Type 8 = ECHO_REQUEST, not ECHO_REPLY.
        let pkt = build_echo_request(1, 1, &[0u8; 8]);
        assert!(parse_echo_reply(&pkt).is_none());
    }

    #[test]
    fn parse_echo_reply_too_short_returns_none() {
        // 7 bytes — shorter than the 8-byte ICMP header minimum.
        let short = [0u8; 7];
        assert!(parse_echo_reply(&short).is_none());
    }

    #[test]
    fn parse_echo_reply_minimum_length() {
        // Exactly 8 bytes (header only, no payload) is valid.
        let pkt = make_echo_reply(0, 0, &[]);
        let reply = parse_echo_reply(&pkt).unwrap();
        assert!(reply.payload.is_empty());
    }

    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------

    #[test]
    fn statistics_default_is_zero() {
        let s = PingStatistics::default();
        assert_eq!(s.packets_sent, 0);
        assert_eq!(s.packets_received, 0);
        assert_eq!(s.min_rtt_us, 0);
        assert_eq!(s.max_rtt_us, 0);
        assert_eq!(s.total_rtt_us, 0);
    }

    #[test]
    fn statistics_records_single_rtt() {
        let mut s = PingStatistics::new();
        s.record_rtt(12_345);
        assert_eq!(s.packets_received, 1);
        assert_eq!(s.min_rtt_us, 12_345);
        assert_eq!(s.max_rtt_us, 12_345);
        assert_eq!(s.total_rtt_us, 12_345);
    }

    #[test]
    fn statistics_min_max_avg_correct() {
        let mut s = PingStatistics::new();
        s.record_rtt(1_000);
        s.record_rtt(3_000);
        s.record_rtt(2_000);
        assert_eq!(s.min_rtt_us, 1_000);
        assert_eq!(s.max_rtt_us, 3_000);
        assert_eq!(s.avg_rtt_us(), 2_000);
    }

    #[test]
    fn statistics_packet_loss_percent() {
        let mut s = PingStatistics::new();
        s.packets_sent = 4;
        s.record_rtt(1_000); // 1 received, 3 lost
        assert_eq!(s.packet_loss_percent(), 75);
    }

    #[test]
    fn statistics_zero_sent_no_panic() {
        let s = PingStatistics::new();
        // Must not panic or divide by zero.
        assert_eq!(s.packet_loss_percent(), 0);
        assert_eq!(s.avg_rtt_us(), 0);
    }

    #[test]
    fn statistics_all_received_zero_loss() {
        let mut s = PingStatistics::new();
        s.packets_sent = 3;
        s.record_rtt(500);
        s.record_rtt(600);
        s.record_rtt(700);
        assert_eq!(s.packet_loss_percent(), 0);
    }

    // -------------------------------------------------------------------------
    // Output formatting
    // -------------------------------------------------------------------------

    #[test]
    fn format_ping_line_output() {
        let line = format_ping_line(64, Ipv4Addr([8, 8, 8, 8]), 1, 56, 12_340);
        assert_eq!(
            line,
            "64 bytes from 8.8.8.8: icmp_seq=1 ttl=56 time=12.34 ms"
        );
    }

    #[test]
    fn format_ping_line_sub_millisecond() {
        // 500 us = 0 ms 50 centiseconds => "0.50 ms"
        let line = format_ping_line(64, Ipv4Addr([127, 0, 0, 1]), 0, 64, 500);
        assert!(line.contains("time=0.50 ms"), "got: {line}");
    }

    #[test]
    fn format_summary_output() {
        let mut s = PingStatistics::new();
        s.packets_sent = 1;
        s.record_rtt(1_500); // 1.50 ms
        let summary = s.format_summary(Ipv4Addr([8, 8, 8, 8]));
        assert!(
            summary.contains("--- 8.8.8.8 ping statistics ---"),
            "got: {summary}"
        );
        assert!(summary.contains("1 packets transmitted"), "got: {summary}");
        assert!(summary.contains("1 received"), "got: {summary}");
        assert!(summary.contains("0% packet loss"), "got: {summary}");
        assert!(summary.contains("1.50"), "got: {summary}");
    }

    #[test]
    fn format_summary_with_loss() {
        let mut s = PingStatistics::new();
        s.packets_sent = 4;
        s.record_rtt(1_000);
        let summary = s.format_summary(Ipv4Addr([1, 1, 1, 1]));
        assert!(summary.contains("75% packet loss"), "got: {summary}");
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_simple_target() {
        let cfg = parse_args(&["8.8.8.8"]).unwrap();
        assert_eq!(cfg.target, Ipv4Addr([8, 8, 8, 8]));
        // Defaults must be untouched.
        assert_eq!(cfg.count, 0);
        assert_eq!(cfg.interval_ms, 1000);
        assert_eq!(cfg.timeout_ms, 5000);
        assert_eq!(cfg.payload_size, 56);
        assert_eq!(cfg.ttl, 64);
    }

    #[test]
    fn parse_args_with_count() {
        let cfg = parse_args(&["-c", "4", "1.1.1.1"]).unwrap();
        assert_eq!(cfg.count, 4);
        assert_eq!(cfg.target, Ipv4Addr([1, 1, 1, 1]));
    }

    #[test]
    fn parse_args_missing_target() {
        assert_eq!(parse_args(&["-c", "3"]), Err(PingError::MissingTarget));
    }

    #[test]
    fn parse_args_all_flags() {
        let cfg = parse_args(&[
            "-c",
            "5",
            "-i",
            "250",
            "-W",
            "3000",
            "-s",
            "128",
            "192.168.1.1",
        ])
        .unwrap();
        assert_eq!(cfg.count, 5);
        assert_eq!(cfg.interval_ms, 250);
        assert_eq!(cfg.timeout_ms, 3000);
        assert_eq!(cfg.payload_size, 128);
        assert_eq!(cfg.target, Ipv4Addr([192, 168, 1, 1]));
    }

    #[test]
    fn parse_args_invalid_address() {
        assert_eq!(parse_args(&["not-an-ip"]), Err(PingError::InvalidAddress));
    }

    #[test]
    fn parse_args_invalid_count() {
        assert_eq!(
            parse_args(&["-c", "abc", "1.1.1.1"]),
            Err(PingError::InvalidCount)
        );
    }

    #[test]
    fn parse_args_unknown_flag() {
        assert_eq!(parse_args(&["-z", "1.1.1.1"]), Err(PingError::UnknownFlag));
    }

    #[test]
    fn parse_args_empty_args() {
        assert_eq!(parse_args(&[]), Err(PingError::MissingTarget));
    }

    #[test]
    fn parse_args_flags_after_target() {
        // Target appears before flags — should still work because we accumulate
        // flags and the last non-flag arg wins as target.
        let cfg = parse_args(&["8.8.8.8", "-c", "2"]).unwrap();
        assert_eq!(cfg.count, 2);
        assert_eq!(cfg.target, Ipv4Addr([8, 8, 8, 8]));
    }

    // -------------------------------------------------------------------------
    // Property-based tests (proptest)
    // -------------------------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// Round-trip: build_echo_request then parse the request.
        /// Verifies that the checksum is always valid for arbitrary inputs.
        #[test]
        fn prop_build_echo_request_checksum_always_valid(
            id in 0u16..=u16::MAX,
            seq in 0u16..=u16::MAX,
            payload in proptest::collection::vec(0u8..=255, 0..128),
        ) {
            let pkt = build_echo_request(id, seq, &payload);
            let (hdr, rest) = IcmpHeader::parse(&pkt).unwrap();
            prop_assert!(hdr.verify_checksum(rest));
        }

        /// Echo reply roundtrip: a packet constructed as ECHO_REPLY must parse
        /// successfully and return the original id/seq.
        #[test]
        fn prop_echo_reply_roundtrip(
            id in 0u16..=u16::MAX,
            seq in 0u16..=u16::MAX,
            payload in proptest::collection::vec(0u8..=255, 0..64),
        ) {
            // Build via the test helper (not exported).
            let echo = IcmpEchoHeader { id, sequence: seq };
            let mut hdr = IcmpHeader {
                icmp_type: IcmpType::ECHO_REPLY,
                code: IcmpCode::ZERO,
                checksum: 0,
                rest: echo.to_rest(),
            };
            hdr.checksum = hdr.compute_checksum(&payload);
            let mut pkt = vec![0u8; IcmpHeader::HEADER_LEN];
            hdr.serialize(&mut pkt).unwrap();
            pkt.extend_from_slice(&payload);

            let reply = parse_echo_reply(&pkt).unwrap();
            prop_assert_eq!(reply.id, id);
            prop_assert_eq!(reply.sequence, seq);
            prop_assert_eq!(reply.payload, payload);
        }

        /// Statistics: avg_rtt_us is always between min_rtt_us and max_rtt_us
        /// when at least one sample has been recorded.
        #[test]
        fn prop_stats_avg_between_min_max(
            rtts in proptest::collection::vec(1u64..=1_000_000, 1..20),
        ) {
            let mut s = PingStatistics::new();
            for rtt in &rtts {
                s.record_rtt(*rtt);
            }
            let avg = s.avg_rtt_us();
            prop_assert!(avg >= s.min_rtt_us, "avg {avg} < min {}", s.min_rtt_us);
            prop_assert!(avg <= s.max_rtt_us, "avg {avg} > max {}", s.max_rtt_us);
        }
    }
}
