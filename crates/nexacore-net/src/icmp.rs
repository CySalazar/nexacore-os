//! ICMP echo/reply handler (N2.3).
//!
//! Handles:
//! - Echo Request → Echo Reply (ping server behaviour)
//! - Echo Reply → RTT measurement (ping client behaviour)
//! - Destination Unreachable / Time Exceeded passthrough
//!
//! ## Packet layout
//!
//! ICMP packets are raw `IPv4` payloads (no transport header).  The `handle_icmp`
//! method receives the already-parsed [`IcmpHeader`] and the remaining payload
//! bytes.  Build functions return the raw ICMP bytes (header + payload); the
//! caller wraps them in `IPv4` via [`crate::ip::build_ipv4_packet`].
//!
//! ## Checksum
//!
//! All build functions compute and embed the correct RFC 792 checksum before
//! returning.

use alloc::{collections::BTreeMap, vec::Vec};

use nexacore_types::net::{IcmpCode, IcmpEchoHeader, IcmpHeader, IcmpType, Ipv4Addr};

// =============================================================================
// Types
// =============================================================================

/// State tracked for each active ping session (keyed by ICMP identifier).
#[derive(Debug, Default)]
pub struct PingState {
    /// Echo identifier — echoed back in the reply.
    pub identifier: u16,
    /// Next sequence number to use for outgoing Echo Requests.
    pub next_seq: u16,
    /// In-flight Echo Requests awaiting a reply.
    pub pending: BTreeMap<u16, PingPending>,
}

/// An in-flight Echo Request awaiting a reply.
#[derive(Debug, Clone)]
pub struct PingPending {
    /// Monotonic timestamp (nanoseconds) when the request was sent.
    pub sent_at: u64,
    /// Echo payload bytes.
    pub payload: Vec<u8>,
}

/// Result of processing an incoming ICMP message.
#[derive(Debug)]
pub enum IcmpHandleResult {
    /// We built an Echo Reply packet for the caller to send.
    Reply(IcmpReply),
    /// We received an Echo Reply matching a pending request.
    PingResponse {
        /// Echo identifier.
        id: u16,
        /// Echo sequence number.
        seq: u16,
        /// Round-trip time in nanoseconds.
        rtt_ns: u64,
    },
    /// Destination Unreachable received.
    DestUnreachable {
        /// ICMP code indicating the specific reason.
        code: IcmpCode,
    },
    /// Time Exceeded received (TTL expired or fragment reassembly).
    TimeExceeded,
    /// Packet did not require a response or was malformed.
    Ignored,
}

/// A ready-to-send ICMP reply.
#[derive(Debug, Clone)]
pub struct IcmpReply {
    /// Raw ICMP bytes (header + payload, no `IPv4` wrapper).
    pub data: Vec<u8>,
    /// Destination `IPv4` address.
    pub dst_ip: Ipv4Addr,
}

// =============================================================================
// IcmpHandler
// =============================================================================

/// Stateful ICMP message processor.
///
/// # Examples
///
/// ```
/// use nexacore_net::icmp::{IcmpHandleResult, IcmpHandler};
/// use nexacore_types::net::{IcmpCode, IcmpEchoHeader, IcmpHeader, IcmpType, Ipv4Addr};
///
/// let mut handler = IcmpHandler::new();
/// // Build an Echo Request and parse it back to simulate a round-trip.
/// let req_bytes = IcmpHandler::build_echo_request(1, 1, b"hello");
/// let (hdr, payload) = IcmpHeader::parse(&req_bytes).unwrap();
/// assert_eq!(hdr.icmp_type, IcmpType::ECHO_REQUEST);
/// assert!(hdr.verify_checksum(payload));
/// ```
#[derive(Debug, Default)]
pub struct IcmpHandler {
    /// Active ping sessions indexed by ICMP identifier.
    pending_pings: BTreeMap<u16, PingState>,
}

impl IcmpHandler {
    /// Construct a new ICMP handler with no active sessions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Process an incoming ICMP message.
    ///
    /// `now` is the current monotonic timestamp in nanoseconds; it is used to
    /// compute RTT for Echo Reply messages.
    pub fn handle_icmp(
        &mut self,
        header: IcmpHeader,
        payload: &[u8],
        src_ip: Ipv4Addr,
        our_ip: Ipv4Addr,
        now: u64,
    ) -> IcmpHandleResult {
        match header.icmp_type {
            IcmpType::ECHO_REQUEST => {
                // Build and return a reply.
                let reply_bytes = Self::build_echo_reply(header, payload);
                IcmpHandleResult::Reply(IcmpReply {
                    data: reply_bytes,
                    dst_ip: src_ip,
                })
            }
            IcmpType::ECHO_REPLY => {
                // Check if we have a pending ping for this id/seq.
                let echo = IcmpEchoHeader::from_rest(header.rest);
                let id = echo.id;
                let seq = echo.sequence;
                // Suppress unused-variable warning: our_ip is structurally
                // needed by the caller but not used inside this branch.
                let _ = our_ip;

                if let Some(state) = self.pending_pings.get_mut(&id) {
                    if let Some(pending) = state.pending.remove(&seq) {
                        let rtt_ns = now.saturating_sub(pending.sent_at);
                        return IcmpHandleResult::PingResponse { id, seq, rtt_ns };
                    }
                }
                IcmpHandleResult::Ignored
            }
            IcmpType::DEST_UNREACHABLE => IcmpHandleResult::DestUnreachable { code: header.code },
            IcmpType::TIME_EXCEEDED => IcmpHandleResult::TimeExceeded,
            _ => IcmpHandleResult::Ignored,
        }
    }

    /// Build a raw ICMP Echo Request packet (header + payload).
    ///
    /// The checksum is computed before returning.
    #[must_use]
    pub fn build_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let echo = IcmpEchoHeader { id, sequence: seq };
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::ECHO_REQUEST,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: echo.to_rest(),
        };
        hdr.checksum = hdr.compute_checksum(payload);
        let mut out = alloc::vec![0u8; IcmpHeader::HEADER_LEN + payload.len()];
        // SAFETY-NOTE: out is always at least HEADER_LEN bytes; get_mut guarantees
        // bounds-safe access. Use pattern to avoid indexing-slicing lint.
        if let Some(hdr_bytes) = out.get_mut(..IcmpHeader::HEADER_LEN) {
            let _ = hdr.serialize(hdr_bytes);
        }
        if let Some(dst) = out.get_mut(IcmpHeader::HEADER_LEN..) {
            dst.copy_from_slice(payload);
        }
        out
    }

    /// Build a raw ICMP Echo Reply for the given request header and payload.
    ///
    /// Swaps the type to `ECHO_REPLY` and recomputes the checksum.
    #[must_use]
    pub fn build_echo_reply(request_header: IcmpHeader, request_payload: &[u8]) -> Vec<u8> {
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::ECHO_REPLY,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: request_header.rest,
        };
        hdr.checksum = hdr.compute_checksum(request_payload);
        let mut out = alloc::vec![0u8; IcmpHeader::HEADER_LEN + request_payload.len()];
        if let Some(hdr_bytes) = out.get_mut(..IcmpHeader::HEADER_LEN) {
            let _ = hdr.serialize(hdr_bytes);
        }
        if let Some(dst) = out.get_mut(IcmpHeader::HEADER_LEN..) {
            dst.copy_from_slice(request_payload);
        }
        out
    }

    /// Build a Destination Unreachable ICMP message.
    ///
    /// `original_packet` should be the first 28 bytes of the original `IPv4`
    /// packet that could not be delivered (per RFC 792 §3.1).
    #[must_use]
    pub fn build_dest_unreachable(code: IcmpCode, original_packet: &[u8]) -> Vec<u8> {
        // RFC 792 specifies: type=3, code, unused=0 (4 bytes), then
        // the original IP header + first 8 bytes of original datagram.
        let payload_len = original_packet.len().min(28);
        let payload = original_packet
            .get(..payload_len)
            .unwrap_or(original_packet);
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::DEST_UNREACHABLE,
            code,
            checksum: 0,
            rest: [0, 0, 0, 0], // unused bytes
        };
        hdr.checksum = hdr.compute_checksum(payload);
        let mut out = alloc::vec![0u8; IcmpHeader::HEADER_LEN + payload.len()];
        if let Some(hdr_bytes) = out.get_mut(..IcmpHeader::HEADER_LEN) {
            let _ = hdr.serialize(hdr_bytes);
        }
        if let Some(dst) = out.get_mut(IcmpHeader::HEADER_LEN..) {
            dst.copy_from_slice(payload);
        }
        out
    }

    /// Register a new ping session for `id`.
    ///
    /// Returns a mutable reference so the caller can enqueue sequence numbers
    /// via [`Self::record_sent`].
    pub fn register_ping(&mut self, id: u16) -> &mut PingState {
        self.pending_pings.entry(id).or_insert_with(|| PingState {
            identifier: id,
            next_seq: 0,
            pending: BTreeMap::new(),
        })
    }

    /// Record that an Echo Request with `id`/`seq` was sent at `sent_at`
    /// (nanoseconds).
    pub fn record_sent(&mut self, id: u16, seq: u16, sent_at: u64, payload: Vec<u8>) {
        if let Some(state) = self.pending_pings.get_mut(&id) {
            state.pending.insert(seq, PingPending { sent_at, payload });
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::integer_division,
        clippy::map_unwrap_or,
        clippy::similar_names,
        clippy::too_many_lines,
        clippy::cognitive_complexity,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::used_underscore_binding
    )]
    #[allow(clippy::wildcard_imports)]
    use super::*;

    fn src_ip() -> Ipv4Addr {
        Ipv4Addr([192, 168, 1, 10])
    }

    fn our_ip() -> Ipv4Addr {
        Ipv4Addr([192, 168, 1, 1])
    }

    // Simulate receiving an Echo Request directed at us.
    fn make_echo_request(id: u16, seq: u16, payload: &[u8]) -> (IcmpHeader, Vec<u8>) {
        let echo = IcmpEchoHeader { id, sequence: seq };
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::ECHO_REQUEST,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: echo.to_rest(),
        };
        hdr.checksum = hdr.compute_checksum(payload);
        (hdr, payload.to_vec())
    }

    fn make_echo_reply(id: u16, seq: u16) -> (IcmpHeader, Vec<u8>) {
        let echo = IcmpEchoHeader { id, sequence: seq };
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::ECHO_REPLY,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: echo.to_rest(),
        };
        hdr.checksum = hdr.compute_checksum(&[]);
        (hdr, alloc::vec![])
    }

    #[test]
    fn new_handler_has_no_pending_pings() {
        let handler = IcmpHandler::new();
        assert!(handler.pending_pings.is_empty());
    }

    #[test]
    fn echo_request_produces_reply() {
        let mut handler = IcmpHandler::new();
        let (hdr, payload) = make_echo_request(42, 1, b"ping!");
        let result = handler.handle_icmp(hdr, &payload, src_ip(), our_ip(), 0);
        assert!(matches!(result, IcmpHandleResult::Reply(_)));
        if let IcmpHandleResult::Reply(reply) = result {
            assert_eq!(reply.dst_ip, src_ip());
            let (rhdr, rpayload) = IcmpHeader::parse(&reply.data).unwrap();
            assert_eq!(rhdr.icmp_type, IcmpType::ECHO_REPLY);
            assert!(rhdr.verify_checksum(rpayload));
        }
    }

    #[test]
    fn echo_reply_matches_pending_ping() {
        let mut handler = IcmpHandler::new();
        handler.register_ping(7);
        handler.record_sent(7, 3, 1_000_000, alloc::vec![]);
        let (hdr, payload) = make_echo_reply(7, 3);
        let result = handler.handle_icmp(hdr, &payload, src_ip(), our_ip(), 2_000_000);
        assert!(matches!(
            result,
            IcmpHandleResult::PingResponse {
                id: 7,
                seq: 3,
                rtt_ns: 1_000_000
            }
        ));
    }

    #[test]
    fn echo_reply_unknown_id_is_ignored() {
        let mut handler = IcmpHandler::new();
        let (hdr, payload) = make_echo_reply(99, 1);
        let result = handler.handle_icmp(hdr, &payload, src_ip(), our_ip(), 0);
        assert!(matches!(result, IcmpHandleResult::Ignored));
    }

    #[test]
    fn echo_reply_wrong_seq_is_ignored() {
        let mut handler = IcmpHandler::new();
        handler.register_ping(5);
        handler.record_sent(5, 1, 0, alloc::vec![]);
        let (hdr, payload) = make_echo_reply(5, 99); // seq 99 not recorded
        let result = handler.handle_icmp(hdr, &payload, src_ip(), our_ip(), 0);
        assert!(matches!(result, IcmpHandleResult::Ignored));
    }

    #[test]
    fn dest_unreachable_returns_correct_variant() {
        let mut handler = IcmpHandler::new();
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::DEST_UNREACHABLE,
            code: IcmpCode::PORT_UNREACHABLE,
            checksum: 0,
            rest: [0; 4],
        };
        hdr.checksum = hdr.compute_checksum(&[]);
        let result = handler.handle_icmp(hdr, &[], src_ip(), our_ip(), 0);
        assert!(matches!(
            result,
            IcmpHandleResult::DestUnreachable {
                code: IcmpCode::PORT_UNREACHABLE
            }
        ));
    }

    #[test]
    fn time_exceeded_returns_correct_variant() {
        let mut handler = IcmpHandler::new();
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::TIME_EXCEEDED,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: [0; 4],
        };
        hdr.checksum = hdr.compute_checksum(&[]);
        let result = handler.handle_icmp(hdr, &[], src_ip(), our_ip(), 0);
        assert!(matches!(result, IcmpHandleResult::TimeExceeded));
    }

    #[test]
    fn build_echo_request_has_correct_checksum() {
        let bytes = IcmpHandler::build_echo_request(1, 1, b"hello");
        let (hdr, payload) = IcmpHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.icmp_type, IcmpType::ECHO_REQUEST);
        assert!(hdr.verify_checksum(payload));
    }

    #[test]
    fn build_echo_reply_has_correct_checksum() {
        let (req_hdr, req_payload) = make_echo_request(3, 7, b"world");
        let bytes = IcmpHandler::build_echo_reply(req_hdr, &req_payload);
        let (hdr, payload) = IcmpHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.icmp_type, IcmpType::ECHO_REPLY);
        assert!(hdr.verify_checksum(payload));
    }

    #[test]
    fn build_echo_reply_preserves_id_and_seq() {
        let (req_hdr, req_payload) = make_echo_request(0xABCD, 42, &[]);
        let bytes = IcmpHandler::build_echo_reply(req_hdr, &req_payload);
        let (hdr, _) = IcmpHeader::parse(&bytes).unwrap();
        let echo = IcmpEchoHeader::from_rest(hdr.rest);
        assert_eq!(echo.id, 0xABCD);
        assert_eq!(echo.sequence, 42);
    }

    #[test]
    fn build_dest_unreachable_has_correct_checksum() {
        let orig = alloc::vec![0u8; 28];
        let bytes = IcmpHandler::build_dest_unreachable(IcmpCode::PORT_UNREACHABLE, &orig);
        let (hdr, payload) = IcmpHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.icmp_type, IcmpType::DEST_UNREACHABLE);
        assert!(hdr.verify_checksum(payload));
    }

    #[test]
    fn build_dest_unreachable_truncates_large_payload() {
        // RFC 792: include at most 28 bytes of original packet.
        let orig = alloc::vec![0u8; 100];
        let bytes = IcmpHandler::build_dest_unreachable(IcmpCode::NET_UNREACHABLE, &orig);
        // Header (8) + 28 bytes of original packet = 36 bytes.
        assert_eq!(bytes.len(), IcmpHeader::HEADER_LEN + 28);
    }

    #[test]
    fn register_ping_creates_state() {
        let mut handler = IcmpHandler::new();
        handler.register_ping(11);
        assert!(handler.pending_pings.contains_key(&11));
    }

    #[test]
    fn record_sent_adds_pending_entry() {
        let mut handler = IcmpHandler::new();
        handler.register_ping(2);
        handler.record_sent(2, 5, 100_000, alloc::vec![0xAA, 0xBB]);
        let state = handler.pending_pings.get(&2).unwrap();
        assert!(state.pending.contains_key(&5));
    }

    #[test]
    fn rtt_computed_correctly() {
        let mut handler = IcmpHandler::new();
        handler.register_ping(1);
        handler.record_sent(1, 0, 500, alloc::vec![]);
        let (hdr, payload) = make_echo_reply(1, 0);
        let result = handler.handle_icmp(hdr, &payload, src_ip(), our_ip(), 1500);
        assert!(
            matches!(result, IcmpHandleResult::PingResponse { rtt_ns: 1000, .. }),
            "unexpected result: {result:?}"
        );
    }
}
