//! # `nexacore-cmd-traceroute`
//!
//! Traceroute command for NexaCore OS — ICMP TTL-based route discovery.
//!
//! This crate provides the pure-logic layer for the `traceroute` utility:
//! probe packet construction, response parsing, per-hop formatting, and
//! command-line argument parsing.  No I/O is performed; the caller drives
//! the send/receive loop and supplies results through [`HopResult`].
//!
//! ## How traceroute works
//!
//! Traceroute sends a series of ICMP Echo Request packets with successively
//! increasing IP TTL values (1, 2, 3, …).  When a router decrements the TTL
//! to zero it emits an ICMP "Time Exceeded" reply, revealing its address and
//! the RTT to that hop.  When the TTL finally reaches the target, an ICMP
//! Echo Reply is returned and the trace is complete.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`TracerouteConfig`] | Session parameters (target, max-hops, probes, …) |
//! | [`HopResult`] | All probe results for a single TTL value |
//! | [`ProbeResult`] | Outcome of a single probe (reply with RTT or timeout) |
//! | [`ProbeResponse`] | Parsed probe response (address + RTT) |
//! | [`build_probe_packet`] | Construct an ICMP Echo Request for a given TTL |
//! | [`parse_probe_response`] | Decode a raw ICMP response |
//! | [`format_hop`] | Format a single hop line |
//! | [`parse_args`] | Parse `traceroute [-m N] [-q N] [-w T] <host>` |
//! | [`TracerouteError`] | Typed errors from [`parse_args`] |
//!
//! ## RFC references
//!
//! - RFC 792 — Internet Control Message Protocol
//! - RFC 1393 — Traceroute Using an IP Option

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
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
// TracerouteConfig
// =============================================================================

/// Configuration for a traceroute session.
///
/// Construct with [`TracerouteConfig::default`] for sensible defaults or use
/// [`parse_args`] to populate from command-line arguments.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_traceroute::TracerouteConfig;
/// use nexacore_types::net::Ipv4Addr;
///
/// let cfg = TracerouteConfig {
///     target: Ipv4Addr([8, 8, 8, 8]),
///     max_hops: 20,
///     ..TracerouteConfig::default()
/// };
/// assert_eq!(cfg.max_hops, 20);
/// assert_eq!(cfg.probes_per_hop, 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracerouteConfig {
    /// Target IP address to trace the route to.
    pub target: Ipv4Addr,
    /// Maximum number of hops (TTL values) to probe before giving up.
    pub max_hops: u8,
    /// Number of probes to send per hop for RTT averaging.
    pub probes_per_hop: u8,
    /// Timeout per probe in milliseconds.
    pub timeout_ms: u64,
    /// ICMP identifier embedded in every probe packet for this session.
    pub identifier: u16,
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            target: Ipv4Addr::UNSPECIFIED,
            max_hops: 30,
            probes_per_hop: 3,
            timeout_ms: 5_000,
            identifier: 1,
        }
    }
}

// =============================================================================
// HopResult / ProbeResult / ProbeResponse
// =============================================================================

/// The aggregate result for a single TTL value (one hop in the trace).
///
/// `probes` has exactly [`TracerouteConfig::probes_per_hop`] entries.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_traceroute::{HopResult, ProbeResult};
/// use nexacore_types::net::Ipv4Addr;
///
/// let hop = HopResult {
///     ttl: 1,
///     probes: vec![
///         ProbeResult::Reply {
///             ip: Ipv4Addr([192, 168, 1, 1]),
///             rtt_us: 500,
///         },
///         ProbeResult::Timeout,
///     ],
/// };
/// assert_eq!(hop.ttl, 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopResult {
    /// The TTL value (1-based hop index) for this set of probes.
    pub ttl: u8,
    /// Individual probe outcomes for this hop.
    pub probes: Vec<ProbeResult>,
}

/// The outcome of a single traceroute probe.
///
/// Either a reply arrived (carrying the responding IP and RTT), or the probe
/// timed out with no response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// An ICMP Time Exceeded or Echo Reply was received within the timeout.
    Reply {
        /// IP address of the router or host that sent the ICMP reply.
        ip: Ipv4Addr,
        /// Round-trip time in microseconds.
        rtt_us: u64,
    },
    /// No reply arrived within the configured timeout.
    Timeout,
}

/// A successfully decoded probe response carrying the peer's IP and RTT.
///
/// Returned by [`parse_probe_response`] when a matching ICMP packet is found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeResponse {
    /// IP address of the responding router or destination host.
    pub ip: Ipv4Addr,
    /// Round-trip time in microseconds as measured by the caller.
    pub rtt_us: u64,
}

// =============================================================================
// Packet construction
// =============================================================================

/// Build an ICMP Echo Request probe packet for the given TTL, identifier, and
/// sequence number.
///
/// The caller is responsible for setting the IP TTL field when transmitting;
/// this function produces only the ICMP portion (no IP header).
///
/// The sequence number is typically `(ttl - 1) * probes_per_hop + probe_index`
/// to correlate replies with the hop/probe that sent them.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_traceroute::build_probe_packet;
/// use nexacore_types::net::{IcmpHeader, IcmpType};
///
/// let pkt = build_probe_packet(0x1234, 1, 1);
/// assert_eq!(pkt.len(), IcmpHeader::HEADER_LEN);
/// assert_eq!(pkt[0], IcmpType::ECHO_REQUEST.0);
/// assert_eq!(pkt[1], 0);
/// // Checksum must be valid.
/// let (hdr, rest) = IcmpHeader::parse(&pkt).unwrap();
/// assert!(hdr.verify_checksum(rest));
/// ```
#[must_use]
pub fn build_probe_packet(id: u16, seq: u16, _ttl: u8) -> Vec<u8> {
    // TTL is carried in the IP header, not the ICMP payload; the parameter is
    // accepted so callers can pass it directly without restructuring but it
    // does not affect the ICMP packet bytes.
    let echo = IcmpEchoHeader { id, sequence: seq };
    let mut hdr = IcmpHeader {
        icmp_type: IcmpType::ECHO_REQUEST,
        code: IcmpCode::ZERO,
        checksum: 0,
        rest: echo.to_rest(),
    };
    hdr.checksum = hdr.compute_checksum(&[]);

    let mut pkt = alloc::vec![0u8; IcmpHeader::HEADER_LEN];
    // serialize returns None only if the buffer is shorter than HEADER_LEN;
    // we sized it to exactly HEADER_LEN so this cannot fail.
    let _ = hdr.serialize(&mut pkt);
    pkt
}

// =============================================================================
// Response parsing
// =============================================================================

/// Parse a raw ICMP byte slice and return a [`ProbeResponse`] when the packet
/// matches `expected_id`.
///
/// Accepts two ICMP message types:
/// - **ICMP Echo Reply** (type 0) — the target host answered directly.
/// - **ICMP Time Exceeded** (type 11, code 0) — a router dropped the packet
///   because TTL reached zero.  The original ICMP header is embedded in the
///   first 8 bytes of the Time Exceeded payload; the identifier is extracted
///   from there.
///
/// Returns `None` when:
/// - The buffer is too short.
/// - The ICMP type is neither Echo Reply nor Time Exceeded.
/// - The identifier in the response does not match `expected_id`.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_traceroute::{build_probe_packet, parse_probe_response};
/// use nexacore_types::net::{IcmpCode, IcmpEchoHeader, IcmpHeader, IcmpType, Ipv4Addr};
///
/// // Build a probe and construct a fake Echo Reply.
/// let mut pkt = build_probe_packet(0xABCD, 1, 1);
/// pkt[0] = IcmpType::ECHO_REPLY.0; // flip type to Reply
/// // Re-compute checksum after changing the type.
/// let echo = IcmpEchoHeader {
///     id: 0xABCD,
///     sequence: 1,
/// };
/// let mut hdr = IcmpHeader {
///     icmp_type: IcmpType::ECHO_REPLY,
///     code: IcmpCode::ZERO,
///     checksum: 0,
///     rest: echo.to_rest(),
/// };
/// hdr.checksum = hdr.compute_checksum(&[]);
/// hdr.serialize(&mut pkt).unwrap();
/// let resp = parse_probe_response(&pkt, 0xABCD);
/// assert!(resp.is_some());
/// ```
#[must_use]
pub fn parse_probe_response(data: &[u8], expected_id: u16) -> Option<ProbeResponse> {
    let (hdr, rest) = IcmpHeader::parse(data)?;
    match hdr.icmp_type {
        IcmpType::ECHO_REPLY => {
            let echo = IcmpEchoHeader::from_rest(hdr.rest);
            if echo.id != expected_id {
                return None;
            }
            // RTT must be supplied by the caller; here we return 0 as a
            // placeholder — callers should overwrite rtt_us after measuring.
            Some(ProbeResponse {
                ip: Ipv4Addr::UNSPECIFIED,
                rtt_us: 0,
            })
        }
        IcmpType::TIME_EXCEEDED => {
            // The original datagram header (20 bytes IP + 8 bytes ICMP) is
            // embedded in the payload.  We only need the ICMP part to extract
            // the identifier.  Skip the first 20 bytes (IP header).
            let inner = rest.get(20..)?;
            let (inner_hdr, _) = IcmpHeader::parse(inner)?;
            let echo = IcmpEchoHeader::from_rest(inner_hdr.rest);
            if echo.id != expected_id {
                return None;
            }
            Some(ProbeResponse {
                ip: Ipv4Addr::UNSPECIFIED,
                rtt_us: 0,
            })
        }
        _ => None,
    }
}

// =============================================================================
// Output formatting
// =============================================================================

/// Format a single hop line in the style of standard traceroute output.
///
/// Produces lines of the form:
///
/// ```text
///  1  192.168.1.1  0.50 ms  0.48 ms  *
/// ```
///
/// Where `*` represents a timeout probe.  RTT values are expressed in
/// milliseconds with two decimal places using integer arithmetic only (no
/// `f64`).
///
/// # Examples
///
/// ```
/// use nexacore_cmd_traceroute::{HopResult, ProbeResult, format_hop};
/// use nexacore_types::net::Ipv4Addr;
///
/// let hop = HopResult {
///     ttl: 1,
///     probes: vec![
///         ProbeResult::Reply {
///             ip: Ipv4Addr([192, 168, 1, 1]),
///             rtt_us: 500,
///         },
///         ProbeResult::Timeout,
///     ],
/// };
/// let line = format_hop(&hop);
/// assert!(line.contains("192.168.1.1"));
/// assert!(line.contains('*'));
/// ```
#[must_use]
pub fn format_hop(hop: &HopResult) -> String {
    let mut out = format!("{:2}", hop.ttl);
    // Track the first responding IP for display on this hop line.
    let mut first_ip: Option<Ipv4Addr> = None;
    for probe in &hop.probes {
        match probe {
            ProbeResult::Reply { ip, rtt_us } => {
                if first_ip.is_none() {
                    first_ip = Some(*ip);
                    out.push_str(&format!("  {ip}"));
                }
                // Integer ms with 2 decimal places.
                #[allow(clippy::integer_division)]
                let ms = rtt_us / 1000;
                #[allow(clippy::integer_division)]
                let frac = (rtt_us % 1000) / 10;
                out.push_str(&format!("  {ms}.{frac:02} ms"));
            }
            ProbeResult::Timeout => {
                out.push_str("  *");
            }
        }
    }
    if first_ip.is_none() {
        out.push_str("  * * *");
    }
    out
}

// =============================================================================
// TracerouteError
// =============================================================================

/// Errors returned by [`parse_args`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracerouteError {
    /// No target host/address was provided.
    MissingTarget,
    /// The target string is not a valid `IPv4` address.
    InvalidAddress,
    /// The value supplied for `-m` (max hops) is not a valid `u8`.
    InvalidMaxHops,
    /// The value supplied for `-q` (probes per hop) is not a valid `u8`.
    InvalidProbes,
    /// The value supplied for `-w` (timeout) is not a valid `u64`.
    InvalidTimeout,
    /// An unrecognised flag was encountered.
    UnknownFlag,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `traceroute` command.
///
/// Supported flags:
///
/// | Flag | Argument | Effect |
/// |------|----------|--------|
/// | `-m` | `<hops>` | Maximum number of hops (default 30) |
/// | `-q` | `<probes>` | Probes per hop (default 3) |
/// | `-w` | `<timeout>` | Per-probe timeout in milliseconds (default 5000) |
///
/// The final non-flag argument is the target `IPv4` address in dotted-decimal
/// notation.
///
/// # Errors
///
/// Returns a [`TracerouteError`] variant when any argument cannot be parsed.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_traceroute::{TracerouteError, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// let cfg = parse_args(&["8.8.8.8"]).unwrap();
/// assert_eq!(cfg.target, Ipv4Addr([8, 8, 8, 8]));
/// assert_eq!(cfg.max_hops, 30);
///
/// let cfg = parse_args(&["-m", "15", "-q", "2", "1.1.1.1"]).unwrap();
/// assert_eq!(cfg.max_hops, 15);
/// assert_eq!(cfg.probes_per_hop, 2);
///
/// assert_eq!(parse_args(&[]), Err(TracerouteError::MissingTarget));
/// ```
pub fn parse_args(args: &[&str]) -> Result<TracerouteConfig, TracerouteError> {
    let mut cfg = TracerouteConfig::default();
    let mut target_str: Option<&str> = None;
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = args.get(idx).copied().unwrap_or("");
        match arg {
            "-m" => {
                idx += 1;
                let val = args.get(idx).ok_or(TracerouteError::InvalidMaxHops)?;
                cfg.max_hops = val
                    .parse::<u8>()
                    .map_err(|_| TracerouteError::InvalidMaxHops)?;
            }
            "-q" => {
                idx += 1;
                let val = args.get(idx).ok_or(TracerouteError::InvalidProbes)?;
                cfg.probes_per_hop = val
                    .parse::<u8>()
                    .map_err(|_| TracerouteError::InvalidProbes)?;
            }
            "-w" => {
                idx += 1;
                let val = args.get(idx).ok_or(TracerouteError::InvalidTimeout)?;
                cfg.timeout_ms = val
                    .parse::<u64>()
                    .map_err(|_| TracerouteError::InvalidTimeout)?;
            }
            s if s.starts_with('-') => return Err(TracerouteError::UnknownFlag),
            s => target_str = Some(s),
        }
        idx += 1;
    }

    let ts = target_str.ok_or(TracerouteError::MissingTarget)?;
    cfg.target = ts
        .parse::<Ipv4Addr>()
        .map_err(|_| TracerouteError::InvalidAddress)?;
    Ok(cfg)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    // -------------------------------------------------------------------------
    // Packet construction
    // -------------------------------------------------------------------------

    #[test]
    fn build_probe_packet_type_and_code() {
        let pkt = build_probe_packet(1, 1, 1);
        assert_eq!(pkt[0], IcmpType::ECHO_REQUEST.0);
        assert_eq!(pkt[1], 0);
    }

    #[test]
    fn build_probe_packet_valid_checksum() {
        let pkt = build_probe_packet(0x1234, 5, 3);
        let (hdr, rest) = IcmpHeader::parse(&pkt).unwrap();
        assert!(hdr.verify_checksum(rest));
    }

    #[test]
    fn build_probe_packet_encodes_id_and_seq() {
        let pkt = build_probe_packet(0xBEEF, 0x42, 10);
        let (hdr, _) = IcmpHeader::parse(&pkt).unwrap();
        let echo = IcmpEchoHeader::from_rest(hdr.rest);
        assert_eq!(echo.id, 0xBEEF);
        assert_eq!(echo.sequence, 0x42);
    }

    #[test]
    fn build_probe_packet_ttl_ignored_in_icmp() {
        // Different TTL values must produce identical ICMP bytes.
        let p1 = build_probe_packet(1, 1, 1);
        let p2 = build_probe_packet(1, 1, 255);
        assert_eq!(p1, p2);
    }

    // -------------------------------------------------------------------------
    // Response parsing
    // -------------------------------------------------------------------------

    fn make_echo_reply(id: u16, seq: u16) -> Vec<u8> {
        let echo = IcmpEchoHeader { id, sequence: seq };
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::ECHO_REPLY,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: echo.to_rest(),
        };
        hdr.checksum = hdr.compute_checksum(&[]);
        let mut pkt = alloc::vec![0u8; IcmpHeader::HEADER_LEN];
        hdr.serialize(&mut pkt).unwrap();
        pkt
    }

    #[test]
    fn parse_echo_reply_matching_id() {
        let pkt = make_echo_reply(0xCAFE, 3);
        let resp = parse_probe_response(&pkt, 0xCAFE);
        assert!(resp.is_some());
    }

    #[test]
    fn parse_echo_reply_wrong_id_returns_none() {
        let pkt = make_echo_reply(0xCAFE, 3);
        assert!(parse_probe_response(&pkt, 0x1234).is_none());
    }

    #[test]
    fn parse_too_short_returns_none() {
        let short = [0u8; 4];
        assert!(parse_probe_response(&short, 1).is_none());
    }

    #[test]
    fn parse_unknown_type_returns_none() {
        // ICMP type 3 (Destination Unreachable) — not handled by traceroute.
        let mut pkt = make_echo_reply(1, 1);
        pkt[0] = 3;
        assert!(parse_probe_response(&pkt, 1).is_none());
    }

    // -------------------------------------------------------------------------
    // Formatting
    // -------------------------------------------------------------------------

    #[test]
    fn format_hop_reply_shows_ip_and_rtt() {
        let hop = HopResult {
            ttl: 3,
            probes: vec![ProbeResult::Reply {
                ip: Ipv4Addr([10, 0, 0, 1]),
                rtt_us: 1500,
            }],
        };
        let line = format_hop(&hop);
        assert!(line.contains("10.0.0.1"), "got: {line}");
        assert!(line.contains("1.50 ms"), "got: {line}");
    }

    #[test]
    fn format_hop_all_timeout_shows_stars() {
        let hop = HopResult {
            ttl: 5,
            probes: vec![ProbeResult::Timeout, ProbeResult::Timeout],
        };
        let line = format_hop(&hop);
        assert!(line.contains('*'), "got: {line}");
    }

    #[test]
    fn format_hop_mixed_shows_both() {
        let hop = HopResult {
            ttl: 2,
            probes: vec![
                ProbeResult::Reply {
                    ip: Ipv4Addr([192, 168, 1, 1]),
                    rtt_us: 500,
                },
                ProbeResult::Timeout,
            ],
        };
        let line = format_hop(&hop);
        assert!(line.contains("192.168.1.1"), "got: {line}");
        assert!(line.contains('*'), "got: {line}");
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_simple_target() {
        let cfg = parse_args(&["8.8.8.8"]).unwrap();
        assert_eq!(cfg.target, Ipv4Addr([8, 8, 8, 8]));
        assert_eq!(cfg.max_hops, 30);
        assert_eq!(cfg.probes_per_hop, 3);
        assert_eq!(cfg.timeout_ms, 5000);
    }

    #[test]
    fn parse_args_all_flags() {
        let cfg = parse_args(&["-m", "20", "-q", "5", "-w", "2000", "1.1.1.1"]).unwrap();
        assert_eq!(cfg.max_hops, 20);
        assert_eq!(cfg.probes_per_hop, 5);
        assert_eq!(cfg.timeout_ms, 2000);
        assert_eq!(cfg.target, Ipv4Addr([1, 1, 1, 1]));
    }

    #[test]
    fn parse_args_missing_target() {
        assert_eq!(parse_args(&[]), Err(TracerouteError::MissingTarget));
    }

    #[test]
    fn parse_args_invalid_address() {
        assert_eq!(
            parse_args(&["not-an-ip"]),
            Err(TracerouteError::InvalidAddress)
        );
    }

    #[test]
    fn parse_args_invalid_max_hops() {
        assert_eq!(
            parse_args(&["-m", "abc", "1.1.1.1"]),
            Err(TracerouteError::InvalidMaxHops)
        );
    }

    #[test]
    fn parse_args_unknown_flag() {
        assert_eq!(
            parse_args(&["-z", "1.1.1.1"]),
            Err(TracerouteError::UnknownFlag)
        );
    }
}
