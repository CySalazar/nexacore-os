//! Service-loop codec helpers — host-testable encode/decode layer.
//!
//! This module bridges the pure driver logic ([`crate::driver::VirtioNetDriver`])
//! and the bare-metal image's IPC service loop
//! (`nexacore-driver-net-virtio-image/src/main.rs`).  Every function here is
//! `no_std + alloc`, free of MMIO and syscall calls, and therefore fully
//! exercisable in host unit tests.
//!
//! ## Responsibilities
//!
//! 1. **`decode_net_request`** — deserialise a raw IPC payload byte slice into
//!    a [`NetRequest`].  Returns a typed error instead of panicking on malformed
//!    input so the service loop can reply with
//!    [`NetResponse::InvalidArgument`] and continue.
//!
//! 2. **`encode_net_response`** — serialise a [`NetResponse`] into a postcard
//!    byte vector ready to hand to `IpcSend`.
//!
//! 3. **`encode_rx_event`** — wrap a received Ethernet frame in a
//!    [`NetEvent::FrameReceivedInline`] and serialise it for delivery on the
//!    event channel.
//!
//! ## Error handling
//!
//! All three entry points return `Result<_, ServiceLoopError>`.  Callers in
//! the image must not propagate a codec error into a kernel panic; they MUST
//! skip the message and continue the loop.
//!
//! ## Wire format
//!
//! All serialisation goes through
//! [`nexacore_types::wire::encode_canonical`] / [`nexacore_types::wire::decode_canonical`]
//! (postcard), consistent with `NCIP-Serde-004`.

extern crate alloc;

use alloc::vec::Vec;

use nexacore_types::{
    net_channel::{NetEvent, NetRequest, NetResponse},
    wire::{decode_canonical, encode_canonical},
};

// =============================================================================
// Error type
// =============================================================================

/// Errors that can occur during service-loop codec operations.
///
/// These are distinct from [`crate::tx_rx::NetDriverError`] (driver-level
/// errors) and from [`nexacore_types::NexaCoreError`] (wire-level errors). A
/// `ServiceLoopError` always means "a message could not be decoded or
/// encoded"; the caller MUST skip the offending message and continue the
/// service loop rather than crashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceLoopError {
    /// The raw byte slice could not be deserialised into the expected type.
    ///
    /// Cause: the IPC payload is truncated, contains trailing bytes, or was
    /// encoded with an incompatible schema version.
    Decode,
    /// The value could not be serialised into a postcard byte vector.
    ///
    /// Cause: the encode buffer ran out of capacity (should never happen in
    /// practice given `MAX_PAYLOAD = 4096` and the `NetResponse` wire size of
    /// ≤ 1 byte for unit variants, but treated as an error for correctness).
    Encode,
}

impl core::fmt::Display for ServiceLoopError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode => f.write_str("service-loop codec: decode failed"),
            Self::Encode => f.write_str("service-loop codec: encode failed"),
        }
    }
}

// =============================================================================
// decode_net_request
// =============================================================================

/// Deserialise a raw IPC payload into a [`NetRequest`].
///
/// The input `buf` is the byte slice copied from the IPC message by
/// `IpcReceive`; it must contain exactly one postcard-encoded `NetRequest`
/// with no trailing bytes (the decoder rejects trailing bytes per
/// `NCIP-Serde-004`).
///
/// # Errors
///
/// Returns [`ServiceLoopError::Decode`] if the bytes are malformed or if
/// trailing bytes are present.
///
/// # Example
///
/// ```
/// use nexacore_driver_net_virtio::service_loop::decode_net_request;
/// use nexacore_types::{net_channel::NetRequest, wire::encode_canonical};
///
/// let req = NetRequest::GetMac;
/// let bytes = encode_canonical(&req).unwrap();
/// let decoded = decode_net_request(&bytes).unwrap();
/// assert_eq!(decoded, NetRequest::GetMac);
/// ```
pub fn decode_net_request(buf: &[u8]) -> Result<NetRequest, ServiceLoopError> {
    decode_canonical::<NetRequest>(buf).map_err(|_| ServiceLoopError::Decode)
}

// =============================================================================
// encode_net_response
// =============================================================================

/// Serialise a [`NetResponse`] into a postcard byte vector for `IpcSend`.
///
/// The returned bytes are ready to pass as the payload argument to
/// `IpcSend` on the command channel (as a Reply message).
///
/// # Errors
///
/// Returns [`ServiceLoopError::Encode`] if serialisation fails (in practice
/// this is unreachable for `NetResponse` because all variants are unit or small
/// fixed-size, but the error is propagated for correctness).
///
/// # Example
///
/// ```
/// use nexacore_driver_net_virtio::service_loop::encode_net_response;
/// use nexacore_types::net_channel::NetResponse;
///
/// let bytes = encode_net_response(NetResponse::Ok).unwrap();
/// // NetResponse::Ok encodes to a single discriminant byte (0x00).
/// assert_eq!(bytes, &[0x00]);
/// ```
pub fn encode_net_response(resp: NetResponse) -> Result<Vec<u8>, ServiceLoopError> {
    encode_canonical(&resp).map_err(|_| ServiceLoopError::Encode)
}

// =============================================================================
// encode_rx_event
// =============================================================================

/// Wrap a received Ethernet frame in a [`NetEvent::FrameReceivedInline`] and
/// serialise it for delivery on the event channel.
///
/// `frame` MUST be an Ethernet frame with the virtio-net 10-byte header
/// already stripped by [`crate::driver::VirtioNetDriver::poll_rx`].  The
/// caller MUST verify that `frame.len() ≤ MAX_FRAME_SIZE` before calling
/// this function; frames that exceed the kernel `MAX_PAYLOAD = 4096` will
/// cause the `IpcSend` syscall to fail (not this function — the encode
/// succeeds but the kernel rejects the oversized payload).
///
/// The returned bytes are ready to pass as the payload argument to
/// `IpcSend` on the event channel.
///
/// # Errors
///
/// Returns [`ServiceLoopError::Encode`] if serialisation fails.
///
/// # Example
///
/// ```
/// use nexacore_driver_net_virtio::service_loop::encode_rx_event;
/// use nexacore_types::{net_channel::NetEvent, wire::decode_canonical};
///
/// let frame = vec![0xAAu8; 60];
/// let bytes = encode_rx_event(frame.clone()).unwrap();
///
/// // Decode and verify the round-trip.
/// let evt: NetEvent = decode_canonical(&bytes).unwrap();
/// match evt {
///     NetEvent::FrameReceivedInline { bytes: b } => assert_eq!(b, frame),
///     _ => panic!("wrong variant"),
/// }
/// ```
pub fn encode_rx_event(frame: Vec<u8>) -> Result<Vec<u8>, ServiceLoopError> {
    let event = NetEvent::FrameReceivedInline { bytes: frame };
    encode_canonical(&event).map_err(|_| ServiceLoopError::Encode)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use nexacore_types::wire::encode_canonical;

    use super::*;

    // -------------------------------------------------------------------------
    // decode_net_request
    // -------------------------------------------------------------------------

    #[test]
    fn decode_net_request_get_mac_round_trip() {
        let req = NetRequest::GetMac;
        let bytes = encode_canonical(&req).unwrap();
        let decoded = decode_net_request(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn decode_net_request_get_link_state_round_trip() {
        let req = NetRequest::GetLinkState;
        let bytes = encode_canonical(&req).unwrap();
        let decoded = decode_net_request(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn decode_net_request_send_frame_inline_round_trip() {
        let frame: Vec<u8> = (0u8..64).collect();
        let req = NetRequest::SendFrameInline {
            bytes: frame.clone(),
        };
        let bytes = encode_canonical(&req).unwrap();
        let decoded = decode_net_request(&bytes).unwrap();
        match decoded {
            NetRequest::SendFrameInline { bytes: b } => assert_eq!(b, frame),
            _ => panic!("wrong variant after round-trip"),
        }
    }

    #[test]
    fn decode_net_request_set_promisc_round_trip() {
        let req = NetRequest::SetPromisc { on: true };
        let bytes = encode_canonical(&req).unwrap();
        let decoded = decode_net_request(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn decode_net_request_empty_input_returns_decode_error() {
        let err = decode_net_request(&[]).unwrap_err();
        assert_eq!(err, ServiceLoopError::Decode);
    }

    #[test]
    fn decode_net_request_trailing_bytes_returns_decode_error() {
        let req = NetRequest::GetMac;
        let mut bytes = encode_canonical(&req).unwrap();
        bytes.push(0xFF); // trailing byte — rejected by postcard
        let err = decode_net_request(&bytes).unwrap_err();
        assert_eq!(err, ServiceLoopError::Decode);
    }

    #[test]
    fn decode_net_request_truncated_input_returns_decode_error() {
        // SendFrame has a non-trivial encoding; truncating it must fail.
        let req = NetRequest::SendFrame {
            bytes_iova: 0xDEAD_BEEF,
            bytes_len: 100,
        };
        let bytes = encode_canonical(&req).unwrap();
        assert!(
            bytes.len() >= 2,
            "sanity: encoding must be at least 2 bytes"
        );
        let err = decode_net_request(&bytes[..bytes.len() - 1]).unwrap_err();
        assert_eq!(err, ServiceLoopError::Decode);
    }

    // -------------------------------------------------------------------------
    // encode_net_response
    // -------------------------------------------------------------------------

    #[test]
    fn encode_net_response_ok_is_single_byte_zero() {
        // NetResponse::Ok is the first variant (discriminant 0) with no payload.
        let bytes = encode_net_response(NetResponse::Ok).unwrap();
        assert_eq!(bytes.as_slice(), &[0x00]);
    }

    #[test]
    fn encode_net_response_all_variants_are_nonempty() {
        for resp in [
            NetResponse::Ok,
            NetResponse::FrameTooLarge,
            NetResponse::LinkDown,
            NetResponse::NotSupported,
            NetResponse::InvalidArgument,
        ] {
            let bytes = encode_net_response(resp).unwrap();
            assert!(
                !bytes.is_empty(),
                "encode must produce at least 1 byte for {resp:?}"
            );
        }
    }

    #[test]
    fn encode_net_response_round_trips_via_decode() {
        use nexacore_types::wire::decode_canonical;

        for resp in [
            NetResponse::Ok,
            NetResponse::FrameTooLarge,
            NetResponse::LinkDown,
            NetResponse::NotSupported,
            NetResponse::InvalidArgument,
        ] {
            let bytes = encode_net_response(resp).unwrap();
            let decoded: NetResponse = decode_canonical(&bytes).unwrap();
            assert_eq!(decoded, resp);
        }
    }

    // -------------------------------------------------------------------------
    // encode_rx_event
    // -------------------------------------------------------------------------

    #[test]
    fn encode_rx_event_round_trips_small_frame() {
        use nexacore_types::wire::decode_canonical;

        let frame = alloc::vec![0x01u8, 0x02, 0x03, 0x04];
        let bytes = encode_rx_event(frame.clone()).unwrap();
        let evt: NetEvent = decode_canonical(&bytes).unwrap();
        match evt {
            NetEvent::FrameReceivedInline { bytes: b } => assert_eq!(b, frame),
            _ => panic!("expected FrameReceivedInline"),
        }
    }

    #[test]
    fn encode_rx_event_round_trips_minimum_ethernet_frame() {
        use nexacore_types::wire::decode_canonical;

        // Minimum Ethernet frame after header strip = MIN_FRAME_SIZE (14 bytes).
        // `encode_rx_event` consumes the Vec so we pass it directly.
        let bytes = encode_rx_event(alloc::vec![0u8; 14]).unwrap();
        let evt: NetEvent = decode_canonical(&bytes).unwrap();
        match evt {
            NetEvent::FrameReceivedInline { bytes: b } => assert_eq!(b.len(), 14),
            _ => panic!("expected FrameReceivedInline"),
        }
    }

    #[test]
    fn encode_rx_event_round_trips_maximum_ethernet_frame() {
        use nexacore_types::wire::decode_canonical;

        // Maximum frame after strip = MAX_FRAME_SIZE (1514 bytes).
        // `encode_rx_event` consumes the Vec so we pass it directly.
        let bytes = encode_rx_event(alloc::vec![0xFFu8; 1514]).unwrap();
        let evt: NetEvent = decode_canonical(&bytes).unwrap();
        match evt {
            NetEvent::FrameReceivedInline { bytes: b } => assert_eq!(b.len(), 1514),
            _ => panic!("expected FrameReceivedInline"),
        }
    }

    #[test]
    fn encode_rx_event_preserves_frame_content() {
        use nexacore_types::wire::decode_canonical;

        // Verify byte-level fidelity, not just length.
        let frame: Vec<u8> = (0u8..=63).collect();
        let bytes = encode_rx_event(frame.clone()).unwrap();
        let evt: NetEvent = decode_canonical(&bytes).unwrap();
        match evt {
            NetEvent::FrameReceivedInline { bytes: b } => assert_eq!(b, frame),
            _ => panic!("expected FrameReceivedInline"),
        }
    }

    #[test]
    fn encode_rx_event_empty_frame_still_encodes() {
        // An empty frame is structurally invalid at the Ethernet layer but the
        // codec must not panic — the driver validates size separately.
        let result = encode_rx_event(alloc::vec![]);
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------------
    // ServiceLoopError display
    // -------------------------------------------------------------------------

    #[test]
    fn service_loop_error_display_decode() {
        let msg = alloc::format!("{}", ServiceLoopError::Decode);
        assert!(msg.contains("decode"), "expected 'decode' in: {msg}");
    }

    #[test]
    fn service_loop_error_display_encode() {
        let msg = alloc::format!("{}", ServiceLoopError::Encode);
        assert!(msg.contains("encode"), "expected 'encode' in: {msg}");
    }

    #[test]
    fn service_loop_error_variants_are_distinct() {
        assert_ne!(ServiceLoopError::Decode, ServiceLoopError::Encode);
    }
}
