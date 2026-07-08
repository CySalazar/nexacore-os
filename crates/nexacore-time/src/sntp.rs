//! SNTP client (RFC 4330) — request build, response parse, offset (WS12-02.1).
//!
//! A minimal Simple NTP client: it builds a 48-byte client request stamped with
//! the local transmit time, parses a server reply, and computes the clock
//! offset and round-trip delay from the four NTP timestamps. The transport
//! (a UDP socket to port 123) lives in the caller; this module is pure
//! byte-logic so it is fully host-testable.
//!
//! NTP timestamps count seconds since 1900-01-01. This implementation assumes
//! NTP era 0 (valid until 2036-02-07); era handling is future work.
#![allow(
    // NTP timestamps are fixed-point; the second/fraction split uses exact
    // integer division by design.
    clippy::integer_division
)]

/// Seconds between the NTP epoch (1900) and the Unix epoch (1970).
pub const NTP_UNIX_OFFSET_SECS: u64 = 2_208_988_800;

/// Fixed 48-byte SNTP packet length.
pub const PACKET_LEN: usize = 48;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// A 64-bit NTP timestamp: 32-bit seconds since 1900 plus a 32-bit fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpTimestamp {
    /// Seconds since 1900-01-01 (era 0).
    pub secs: u32,
    /// Fractional seconds in units of `1 / 2^32`.
    pub frac: u32,
}

impl NtpTimestamp {
    /// Construct from an unsigned Unix time in nanoseconds.
    #[must_use]
    pub fn from_unix_nanos(unix_ns: u64) -> Self {
        let unix_secs = unix_ns / NANOS_PER_SEC;
        let sub_ns = unix_ns % NANOS_PER_SEC;
        let secs = u32::try_from(unix_secs + NTP_UNIX_OFFSET_SECS).unwrap_or(u32::MAX);
        // frac = sub_ns / 1e9 * 2^32
        let frac = u32::try_from((sub_ns << 32) / NANOS_PER_SEC).unwrap_or(0);
        Self { secs, frac }
    }

    /// Convert to Unix time in nanoseconds. Returns `None` for pre-1970
    /// timestamps (which cannot be represented as unsigned Unix time).
    #[must_use]
    pub fn to_unix_nanos(self) -> Option<u64> {
        let unix_secs = u64::from(self.secs).checked_sub(NTP_UNIX_OFFSET_SECS)?;
        let sub_ns = (u64::from(self.frac) * NANOS_PER_SEC) >> 32;
        Some(unix_secs * NANOS_PER_SEC + sub_ns)
    }

    /// The 8-byte big-endian wire representation.
    #[must_use]
    pub fn to_wire(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        let s = self.secs.to_be_bytes();
        let f = self.frac.to_be_bytes();
        if let Some(hi) = out.get_mut(0..4) {
            hi.copy_from_slice(&s);
        }
        if let Some(lo) = out.get_mut(4..8) {
            lo.copy_from_slice(&f);
        }
        out
    }

    /// Parse an 8-byte big-endian timestamp.
    #[must_use]
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        let s: [u8; 4] = bytes.get(0..4)?.try_into().ok()?;
        let f: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
        Some(Self {
            secs: u32::from_be_bytes(s),
            frac: u32::from_be_bytes(f),
        })
    }
}

/// Build a client SNTP request (mode 3, version 4) stamped with `transmit` as
/// the transmit timestamp (T1). All other fields are zero, per SNTP.
#[must_use]
pub fn build_client_request(transmit: NtpTimestamp) -> [u8; PACKET_LEN] {
    let mut pkt = [0u8; PACKET_LEN];
    // LI = 0, VN = 4, Mode = 3 (client) → 0b00_100_011 = 0x23.
    if let Some(first) = pkt.first_mut() {
        *first = 0x23;
    }
    if let Some(slot) = pkt.get_mut(40..48) {
        slot.copy_from_slice(&transmit.to_wire());
    }
    pkt
}

/// A parsed SNTP server reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpResponse {
    /// Leap-indicator (top 2 bits of byte 0).
    pub leap: u8,
    /// Stratum (byte 1); `0` is "kiss-o'-death" / unspecified.
    pub stratum: u8,
    /// Originate timestamp (T1, echoed from the request).
    pub originate: NtpTimestamp,
    /// Server receive timestamp (T2).
    pub receive: NtpTimestamp,
    /// Server transmit timestamp (T3).
    pub transmit: NtpTimestamp,
}

/// Parse a 48-byte SNTP reply. Rejects packets that are not server-mode (4) or
/// broadcast (5), or that are the wrong length.
#[must_use]
pub fn parse_response(pkt: &[u8]) -> Option<NtpResponse> {
    if pkt.len() < PACKET_LEN {
        return None;
    }
    let b0 = *pkt.first()?;
    let mode = b0 & 0b0000_0111;
    if mode != 4 && mode != 5 {
        return None;
    }
    let leap = b0 >> 6;
    let stratum = *pkt.get(1)?;
    let originate = NtpTimestamp::from_wire(pkt.get(24..32)?)?;
    let receive = NtpTimestamp::from_wire(pkt.get(32..40)?)?;
    let transmit = NtpTimestamp::from_wire(pkt.get(40..48)?)?;
    Some(NtpResponse {
        leap,
        stratum,
        originate,
        receive,
        transmit,
    })
}

/// The NTP offset and round-trip delay (both in nanoseconds) from the four
/// timestamps: `t1` client-transmit, `t2` server-receive, `t3` server-transmit,
/// `t4` client-receive.
///
/// * offset `θ = ((T2 − T1) + (T3 − T4)) / 2`
/// * delay  `δ = (T4 − T1) − (T3 − T2)`
///
/// Returns `None` if any timestamp predates 1970.
#[must_use]
pub fn offset_and_delay(
    t1: NtpTimestamp,
    t2: NtpTimestamp,
    t3: NtpTimestamp,
    t4: NtpTimestamp,
) -> Option<(i64, i64)> {
    let n1 = i64::try_from(t1.to_unix_nanos()?).ok()?;
    let n2 = i64::try_from(t2.to_unix_nanos()?).ok()?;
    let n3 = i64::try_from(t3.to_unix_nanos()?).ok()?;
    let n4 = i64::try_from(t4.to_unix_nanos()?).ok()?;
    let offset = ((n2 - n1) + (n3 - n4)) / 2;
    let delay = (n4 - n1) - (n3 - n2);
    Some((offset, delay))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap
    )]

    use super::*;

    #[test]
    fn ntp_unix_conversion_round_trips() {
        // 2024-01-01T00:00:00Z = 1704067200 unix secs.
        let unix_ns = 1_704_067_200u64 * NANOS_PER_SEC;
        let ts = NtpTimestamp::from_unix_nanos(unix_ns);
        assert_eq!(ts.secs, 1_704_067_200 + NTP_UNIX_OFFSET_SECS as u32);
        assert_eq!(ts.to_unix_nanos(), Some(unix_ns));
    }

    #[test]
    fn wire_round_trips() {
        let ts = NtpTimestamp {
            secs: 0x1234_5678,
            frac: 0x9abc_def0,
        };
        assert_eq!(NtpTimestamp::from_wire(&ts.to_wire()), Some(ts));
    }

    #[test]
    fn client_request_is_well_formed() {
        let t1 = NtpTimestamp::from_unix_nanos(1_000 * NANOS_PER_SEC);
        let pkt = build_client_request(t1);
        assert_eq!(pkt[0], 0x23);
        assert_eq!(NtpTimestamp::from_wire(&pkt[40..48]), Some(t1));
    }

    #[test]
    fn parse_rejects_client_mode_and_short() {
        let mut pkt = [0u8; 48];
        pkt[0] = 0x23; // client mode
        assert!(parse_response(&pkt).is_none());
        assert!(parse_response(&[0u8; 10]).is_none());
    }

    #[test]
    fn offset_computation_matches_definition() {
        // Client sends at T1, server receives at T2 (=T1+2s), transmits at
        // T3 (=T2+1s), client receives at T4 (=T1+3s). The server clock leads
        // the client by ~1s here → positive offset.
        let base = 1_704_067_200u64 * NANOS_PER_SEC;
        let t1 = NtpTimestamp::from_unix_nanos(base);
        let t2 = NtpTimestamp::from_unix_nanos(base + 2 * NANOS_PER_SEC);
        let t3 = NtpTimestamp::from_unix_nanos(base + 3 * NANOS_PER_SEC);
        let t4 = NtpTimestamp::from_unix_nanos(base + 3 * NANOS_PER_SEC);
        let (offset, delay) = offset_and_delay(t1, t2, t3, t4).unwrap();
        // θ = ((2s) + (0s))/2 = 1s ; δ = 3s − 1s = 2s.
        assert_eq!(offset, NANOS_PER_SEC as i64);
        assert_eq!(delay, 2 * NANOS_PER_SEC as i64);
    }

    #[test]
    fn parse_accepts_server_reply_round_trip() {
        let t1 = NtpTimestamp::from_unix_nanos(1_704_067_200u64 * NANOS_PER_SEC);
        // Build a server reply by hand: mode 4, stratum 2, echo T1 as originate.
        let mut pkt = [0u8; 48];
        pkt[0] = 0x24; // LI=0 VN=4 Mode=4
        pkt[1] = 2; // stratum
        pkt[24..32].copy_from_slice(&t1.to_wire());
        pkt[32..40].copy_from_slice(&t1.to_wire());
        pkt[40..48].copy_from_slice(&t1.to_wire());
        let resp = parse_response(&pkt).unwrap();
        assert_eq!(resp.stratum, 2);
        assert_eq!(resp.originate, t1);
        assert_eq!(resp.transmit, t1);
    }
}
