//! `ICMPv6` echo and error messages (WS4-04.2, RFC 4443).
//!
//! `ICMPv6` reuses the ICMP message shape (1-byte type, 1-byte code, 2-byte
//! checksum, 4-byte "rest of header", then a body) but differs from `ICMPv4` in
//! two ways that matter here:
//!
//! - Message types are renumbered: errors are `1..=127`, informational
//!   messages (echo) are `128..=255`.
//! - The checksum covers an `IPv6` pseudo-header (source + destination
//!   address, upper-layer length, and a `next_header` of 58), not just the
//!   message — so every build/verify function needs the packet's `IPv6`
//!   addresses.
//!
//! Build functions return the raw `ICMPv6` bytes (header + body); the caller
//! wraps them in `IPv6` via [`crate::ip::build_ipv6_packet`] with
//! `next_header = `[`NEXT_HEADER_ICMPV6`].

use alloc::vec::Vec;

use nexacore_types::net::{Ipv6Addr, checksum_combine};

/// The `IPv6` Next Header value identifying an `ICMPv6` payload.
pub const NEXT_HEADER_ICMPV6: u8 = 58;

/// The largest `ICMPv6` error body kept from the invoking packet.
///
/// RFC 4443 § 3 caps an `ICMPv6` error so the whole `IPv6` packet stays within
/// the minimum MTU (1280): `1280 - 40` (`IPv6` header) `- 8` (`ICMPv6` header).
const MAX_ERROR_BODY: usize = 1232;

/// An `ICMPv6` message type (RFC 4443 § 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Icmpv6Type(pub u8);

impl Icmpv6Type {
    /// Destination Unreachable (error, `1`).
    pub const DEST_UNREACHABLE: Self = Self(1);
    /// Packet Too Big (error, `2`).
    pub const PACKET_TOO_BIG: Self = Self(2);
    /// Time Exceeded (error, `3`).
    pub const TIME_EXCEEDED: Self = Self(3);
    /// Parameter Problem (error, `4`).
    pub const PARAMETER_PROBLEM: Self = Self(4);
    /// Echo Request (informational, `128`).
    pub const ECHO_REQUEST: Self = Self(128);
    /// Echo Reply (informational, `129`).
    pub const ECHO_REPLY: Self = Self(129);
    /// Router Solicitation (Neighbor Discovery, `133`).
    pub const ROUTER_SOLICITATION: Self = Self(133);
    /// Router Advertisement (Neighbor Discovery, `134`).
    pub const ROUTER_ADVERTISEMENT: Self = Self(134);
    /// Neighbor Solicitation (Neighbor Discovery, `135`).
    pub const NEIGHBOR_SOLICITATION: Self = Self(135);
    /// Neighbor Advertisement (Neighbor Discovery, `136`).
    pub const NEIGHBOR_ADVERTISEMENT: Self = Self(136);
    /// Redirect (Neighbor Discovery, `137`).
    pub const REDIRECT: Self = Self(137);

    /// Whether this is an error message (type `< 128`).
    #[must_use]
    pub const fn is_error(self) -> bool {
        self.0 < 128
    }
}

/// A parsed `ICMPv6` message header (the fixed 8-byte prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmpv6Header {
    /// Message type.
    pub msg_type: Icmpv6Type,
    /// Message code (type-specific).
    pub code: u8,
    /// Checksum as carried on the wire.
    pub checksum: u16,
    /// The 4-byte "rest of header" (e.g. id+sequence for echo, MTU for
    /// Packet Too Big, unused for most errors).
    pub rest: [u8; 4],
}

impl Icmpv6Header {
    /// The fixed `ICMPv6` header length in bytes.
    pub const HEADER_LEN: usize = 8;

    /// Parse the fixed header from `bytes`, returning `(header, body)` or
    /// `None` if the buffer is shorter than [`Self::HEADER_LEN`].
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < Self::HEADER_LEN {
            return None;
        }
        let hdr = Self {
            msg_type: Icmpv6Type(*bytes.first()?),
            code: *bytes.get(1)?,
            checksum: u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?),
            rest: bytes.get(4..8)?.try_into().ok()?,
        };
        Some((hdr, bytes.get(Self::HEADER_LEN..)?))
    }

    /// The echo identifier, valid for echo request/reply messages (the first
    /// two bytes of [`rest`](Self::rest)).
    #[must_use]
    pub fn echo_identifier(self) -> u16 {
        u16::from_be_bytes([self.rest[0], self.rest[1]])
    }

    /// The echo sequence number (the last two bytes of [`rest`](Self::rest)).
    #[must_use]
    pub fn echo_sequence(self) -> u16 {
        u16::from_be_bytes([self.rest[2], self.rest[3]])
    }
}

/// Compute the `ICMPv6` checksum over the `IPv6` pseudo-header and `message`.
///
/// `message` is the full `ICMPv6` message (header + body). Pass it with the
/// checksum field already zeroed to derive the checksum; pass it verbatim
/// (checksum field intact) to validate — a correct message then yields `0`.
#[must_use]
pub fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, message: &[u8]) -> u16 {
    let upper_len = u32::try_from(message.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes();
    // Pseudo-header tail: 3 zero bytes + Next Header (58).
    let tail = [0u8, 0, 0, NEXT_HEADER_ICMPV6];
    checksum_combine(&[&src.0, &dst.0, &upper_len, &tail, message])
}

/// Whether `message`'s embedded checksum is correct for the given addresses.
#[must_use]
pub fn verify_checksum(src: Ipv6Addr, dst: Ipv6Addr, message: &[u8]) -> bool {
    // Summing the message *including* its checksum field folds to zero when the
    // checksum is correct (one's-complement property).
    icmpv6_checksum(src, dst, message) == 0
}

/// Assemble an `ICMPv6` message and embed its pseudo-header checksum.
///
/// `rest` is the 4-byte "rest of header"; `body` follows the 8-byte header.
/// Shared with [`crate::ndp`], which layers Neighbor Discovery messages on top.
pub(crate) fn build_message(
    msg_type: Icmpv6Type,
    code: u8,
    rest: [u8; 4],
    body: &[u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
) -> Vec<u8> {
    let mut out = alloc::vec![0u8; Icmpv6Header::HEADER_LEN + body.len()];
    if let Some(b) = out.get_mut(0) {
        *b = msg_type.0;
    }
    if let Some(b) = out.get_mut(1) {
        *b = code;
    }
    // Bytes 2..4 (checksum) stay zero while we compute it.
    if let Some(slot) = out.get_mut(4..8) {
        slot.copy_from_slice(&rest);
    }
    if let Some(slot) = out.get_mut(Icmpv6Header::HEADER_LEN..) {
        slot.copy_from_slice(body);
    }
    let checksum = icmpv6_checksum(src, dst, &out);
    if let Some(slot) = out.get_mut(2..4) {
        slot.copy_from_slice(&checksum.to_be_bytes());
    }
    out
}

/// Build an `ICMPv6` Echo Request from `src` to `dst`.
#[must_use]
pub fn build_echo_request(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let rest = echo_rest(id, seq);
    build_message(Icmpv6Type::ECHO_REQUEST, 0, rest, payload, src, dst)
}

/// Build an `ICMPv6` Echo Reply from `src` to `dst`.
#[must_use]
pub fn build_echo_reply(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let rest = echo_rest(id, seq);
    build_message(Icmpv6Type::ECHO_REPLY, 0, rest, payload, src, dst)
}

/// Build the Echo Reply that answers `request` (an Echo Request message), as if
/// sent from `our_addr` back to `requester`.
///
/// Returns `None` if `request` is not a well-formed Echo Request.
#[must_use]
pub fn build_echo_reply_for(
    our_addr: Ipv6Addr,
    requester: Ipv6Addr,
    request: &[u8],
) -> Option<Vec<u8>> {
    let (hdr, body) = Icmpv6Header::parse(request)?;
    if hdr.msg_type != Icmpv6Type::ECHO_REQUEST {
        return None;
    }
    Some(build_echo_reply(
        our_addr,
        requester,
        hdr.echo_identifier(),
        hdr.echo_sequence(),
        body,
    ))
}

/// Build an `ICMPv6` Destination Unreachable error citing `invoking_packet`.
#[must_use]
pub fn build_dest_unreachable(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    code: u8,
    invoking_packet: &[u8],
) -> Vec<u8> {
    build_message(
        Icmpv6Type::DEST_UNREACHABLE,
        code,
        [0; 4],
        clamp_invoking(invoking_packet),
        src,
        dst,
    )
}

/// Build an `ICMPv6` Packet Too Big error advertising `mtu`.
#[must_use]
pub fn build_packet_too_big(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    mtu: u32,
    invoking_packet: &[u8],
) -> Vec<u8> {
    build_message(
        Icmpv6Type::PACKET_TOO_BIG,
        0,
        mtu.to_be_bytes(),
        clamp_invoking(invoking_packet),
        src,
        dst,
    )
}

/// Build an `ICMPv6` Time Exceeded error (e.g. hop limit reached) citing
/// `invoking_packet`.
#[must_use]
pub fn build_time_exceeded(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    code: u8,
    invoking_packet: &[u8],
) -> Vec<u8> {
    build_message(
        Icmpv6Type::TIME_EXCEEDED,
        code,
        [0; 4],
        clamp_invoking(invoking_packet),
        src,
        dst,
    )
}

/// Pack an echo identifier and sequence number into the 4-byte rest field.
fn echo_rest(id: u16, seq: u16) -> [u8; 4] {
    let id = id.to_be_bytes();
    let seq = seq.to_be_bytes();
    [id[0], id[1], seq[0], seq[1]]
}

/// Cap the invoking packet to the RFC 4443 minimum-MTU budget.
fn clamp_invoking(invoking: &[u8]) -> &[u8] {
    invoking.get(..MAX_ERROR_BODY).unwrap_or(invoking)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]
    use super::*;

    fn a() -> Ipv6Addr {
        Ipv6Addr([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    }
    fn b() -> Ipv6Addr {
        Ipv6Addr([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
    }

    #[test]
    fn echo_request_has_valid_checksum_and_fields() {
        let msg = build_echo_request(a(), b(), 0x1234, 0x5678, b"ping");
        assert!(verify_checksum(a(), b(), &msg));
        let (hdr, body) = Icmpv6Header::parse(&msg).unwrap();
        assert_eq!(hdr.msg_type, Icmpv6Type::ECHO_REQUEST);
        assert_eq!(hdr.code, 0);
        assert_eq!(hdr.echo_identifier(), 0x1234);
        assert_eq!(hdr.echo_sequence(), 0x5678);
        assert_eq!(body, b"ping");
    }

    #[test]
    fn reply_for_request_swaps_type_preserves_echo_and_validates() {
        let req = build_echo_request(b(), a(), 7, 9, b"hello");
        // We are `a`, replying to requester `b`.
        let reply = build_echo_reply_for(a(), b(), &req).unwrap();
        assert!(verify_checksum(a(), b(), &reply));
        let (hdr, body) = Icmpv6Header::parse(&reply).unwrap();
        assert_eq!(hdr.msg_type, Icmpv6Type::ECHO_REPLY);
        assert_eq!(hdr.echo_identifier(), 7);
        assert_eq!(hdr.echo_sequence(), 9);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn reply_for_rejects_non_echo_request() {
        // A reply message is not an echo *request*.
        let reply = build_echo_reply(a(), b(), 1, 1, &[]);
        assert!(build_echo_reply_for(a(), b(), &reply).is_none());
        // Truncated input is rejected too.
        assert!(build_echo_reply_for(a(), b(), &[0u8; 4]).is_none());
    }

    #[test]
    fn checksum_detects_corruption() {
        let mut msg = build_echo_request(a(), b(), 1, 2, b"data");
        assert!(verify_checksum(a(), b(), &msg));
        // Flip a payload bit: the checksum must no longer validate.
        msg[Icmpv6Header::HEADER_LEN] ^= 0xFF;
        assert!(!verify_checksum(a(), b(), &msg));
        // A different address pair also invalidates (pseudo-header coverage).
        let msg2 = build_echo_request(a(), b(), 1, 2, b"data");
        assert!(!verify_checksum(a(), a(), &msg2));
    }

    #[test]
    fn error_messages_are_well_formed() {
        let invoking = [0xAAu8; 64];
        let du = build_dest_unreachable(a(), b(), 4, &invoking); // code 4 = port unreachable
        assert!(verify_checksum(a(), b(), &du));
        let (hdr, body) = Icmpv6Header::parse(&du).unwrap();
        assert_eq!(hdr.msg_type, Icmpv6Type::DEST_UNREACHABLE);
        assert!(hdr.msg_type.is_error());
        assert_eq!(hdr.code, 4);
        assert_eq!(body, &invoking);

        let ptb = build_packet_too_big(a(), b(), 1280, &invoking);
        assert!(verify_checksum(a(), b(), &ptb));
        let (ptb_hdr, _) = Icmpv6Header::parse(&ptb).unwrap();
        assert_eq!(ptb_hdr.msg_type, Icmpv6Type::PACKET_TOO_BIG);
        // The MTU is carried in the rest-of-header field.
        assert_eq!(u32::from_be_bytes(ptb_hdr.rest), 1280);

        let te = build_time_exceeded(a(), b(), 0, &invoking);
        assert!(verify_checksum(a(), b(), &te));
        assert_eq!(
            Icmpv6Header::parse(&te).unwrap().0.msg_type,
            Icmpv6Type::TIME_EXCEEDED
        );
    }

    #[test]
    fn error_body_is_clamped_to_min_mtu_budget() {
        let invoking = alloc::vec![0u8; 4096];
        let du = build_dest_unreachable(a(), b(), 0, &invoking);
        // 8-byte header + at most MAX_ERROR_BODY bytes of the invoking packet.
        assert_eq!(du.len(), Icmpv6Header::HEADER_LEN + MAX_ERROR_BODY);
        assert!(verify_checksum(a(), b(), &du));
    }

    #[test]
    fn parse_rejects_truncated_header() {
        assert!(Icmpv6Header::parse(&[0u8; 7]).is_none());
        assert!(Icmpv6Header::parse(&[]).is_none());
    }
}
