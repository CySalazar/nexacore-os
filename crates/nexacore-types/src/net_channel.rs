//! NET channel ABI types (N0.7) — IPC protocol between NIC drivers and the
//! network stack service.
//!
//! This module defines the canonical request/response/event shape carried on
//! the `nexacore.svc.net.<ifaceN>` IPC channels. The NIC driver is the
//! **producer** that implements this contract; the network stack service is the
//! **consumer** that issues requests and processes events. Future NIC drivers
//! (virtio-net, physical NICs, software taps) MUST expose the same shape so
//! that the network stack mediates against a single contract.
//!
//! ## Why the NET channel is a separate type module
//!
//! The user-space NIC driver, the network stack service, and any diagnostic
//! client (interface inspector, packet-capture tool) all need to encode/decode
//! these types. Placing them in `nexacore-types` keeps them in the foundational
//! layer that every workspace member is already allowed to depend on, and
//! ensures the wire shape goes through [`crate::wire::encode_canonical`] (the
//! single workspace audit point for serialization, per `NCIP-Serde-004`).
//!
//! ## Backward-compatibility policy
//!
//! Backward-compatible additions to [`NetRequest`], [`NetResponse`], and
//! [`NetEvent`] (new variants) MAY land via PR without an NCIP. All three
//! enums therefore carry `#[non_exhaustive]` so downstream `match` expressions
//! are forced to provide a `_ =>` arm, and adding a variant does not break
//! source-level consumers.
//!
//! ## Buffer ownership
//!
//! [`NetRequest::SendFrame`] and [`NetEvent::FrameReceived`] carry
//! `bytes_iova`, an IOVA-space address minted by a prior `DmaMap` syscall on
//! the caller side. The NIC driver is the **transient owner** of the buffer
//! for the lifetime of one operation: it reads from `bytes_iova` (send) or
//! writes into `bytes_iova` (receive), then returns a response or emits an
//! event and relinquishes ownership. The caller MUST NOT touch the buffer
//! between issuing the request or registering the receive buffer and observing
//! the completion signal.
//!
//! ## Channel layout
//!
//! Each NIC driver exposes exactly two IPC channels per network interface:
//!
//! 1. **Command channel** (`nexacore.svc.net.<iface>`): carries
//!    [`NetRequest`] → [`NetResponse`] round-trips.
//! 2. **Event channel** (`nexacore.svc.net.<iface>.evt`): carries
//!    unsolicited [`NetEvent`] messages from the driver to the network stack.
//!
//! Use [`net_channel_name`] and [`net_event_channel_name`] to construct these
//! names from an interface identifier string.

use alloc::{format, string::String, vec::Vec};

use serde::{Deserialize, Serialize};

// =============================================================================
// Constants
// =============================================================================

/// Channel-name prefix for every NET command and event channel.
///
/// The kernel IPC registry uses this prefix to authorize capability-gated
/// access taps. The full command-channel name is the prefix concatenated with
/// the interface identifier (e.g., `"eth0"`, `"virtio0"`); the event channel
/// appends [`NET_EVENT_CHANNEL_SUFFIX`] on top of that. Both suffixes are
/// owned by the producing driver.
///
/// Use [`net_channel_name`] and [`net_event_channel_name`] to build well-formed
/// channel names from an interface identifier.
pub const NET_CHANNEL_PREFIX: &str = "nexacore.svc.net.";

/// Suffix appended to the command channel name to form the event channel name.
///
/// The event channel carries unsolicited [`NetEvent`] messages (received
/// frames, link-state changes, MAC changes) from the NIC driver to the
/// network stack. Appending this suffix to the result of [`net_channel_name`]
/// yields the correct event channel name; alternatively, use
/// [`net_event_channel_name`] directly.
pub const NET_EVENT_CHANNEL_SUFFIX: &str = ".evt";

// =============================================================================
// NetRequest — network-stack-facing
// =============================================================================

/// A request sent by the network stack service to a NIC driver.
///
/// Each variant maps to exactly one driver operation. All variants use
/// `repr(Rust)` because the canonical wire format is `postcard`-encoded
/// via [`crate::wire::encode_canonical`]; the in-memory layout is irrelevant
/// for the cross-process contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetRequest {
    /// Transmit a raw Ethernet frame.
    ///
    /// The `bytes_iova` field is the IOVA-space address of the frame buffer
    /// (minted by a prior `DmaMap` syscall). `bytes_len` is the number of
    /// bytes to transmit; it MUST be at least 14 (minimum Ethernet header
    /// length). The driver MUST return [`NetResponse::FrameTooLarge`] if
    /// `bytes_len` exceeds the interface's MTU + 14-byte Ethernet header.
    SendFrame {
        /// IOVA-space address of the Ethernet frame to transmit.
        bytes_iova: u64,
        /// Length of the frame in bytes. Must fit within the interface MTU.
        bytes_len: u16,
    },
    /// Query the current link state of the interface.
    ///
    /// The driver replies with the [`LinkState`] embedded in a
    /// [`NetResponse::Ok`] variant. Because the NET channel does not carry
    /// structured response payloads, the actual [`LinkState`] is conveyed
    /// out-of-band via a companion `GetLinkState` response message; see the
    /// driver NCIP for the full exchange protocol.
    GetLinkState,
    /// Query the interface MAC address.
    ///
    /// The driver replies with the 6-byte MAC in a companion response
    /// message per the driver NCIP. Distinct from [`NetEvent::MacChanged`],
    /// which is an unsolicited notification of a hot-plug MAC change.
    GetMac,
    /// Enable or disable promiscuous mode on the interface.
    ///
    /// When `on` is `true`, the driver MUST forward all received frames to
    /// the event channel regardless of destination MAC. When `false`, the
    /// driver reverts to normal unicast / multicast filtering. Drivers that
    /// do not support promiscuous mode MUST return
    /// [`NetResponse::NotSupported`].
    SetPromisc {
        /// `true` to enable promiscuous mode; `false` to disable it.
        on: bool,
    },
    /// Transmit a raw Ethernet frame carried *inline* in the IPC payload.
    ///
    /// This is the M0 transport: instead of referencing an IOVA buffer (see
    /// [`Self::SendFrame`]), the full frame bytes travel inside the
    /// `postcard`-encoded message. This is sound because a maximum Ethernet
    /// frame (1514 bytes, `nexacore-driver-net-virtio` `MAX_FRAME_SIZE`) fits well
    /// within the kernel IPC `MAX_PAYLOAD` of 4096 bytes. The zero-copy
    /// IOVA path ([`Self::SendFrame`]) remains the long-term high-throughput
    /// transport and is reserved for a future driver-framework milestone.
    ///
    /// `bytes` MUST be a complete Ethernet II frame (dst MAC + src MAC +
    /// `EtherType` + payload), at least 14 bytes and at most the interface
    /// MTU + 14. The driver MUST reply [`NetResponse::FrameTooLarge`] when the
    /// frame exceeds that bound, or [`NetResponse::InvalidArgument`] when it is
    /// shorter than a 14-byte Ethernet header.
    SendFrameInline {
        /// The complete Ethernet frame to transmit, carried inline.
        bytes: Vec<u8>,
    },
}

// =============================================================================
// NetResponse — driver-emitted
// =============================================================================

/// A response emitted by a NIC driver in reply to a [`NetRequest`].
///
/// Each variant carries the minimum information needed by the network stack
/// to decide between retry / propagate / abort. Detailed diagnostic telemetry
/// MUST go through the driver's event channel (`nexacore.svc.net.<iface>.evt`)
/// rather than being inlined into the NET response, because the command
/// channel is rate-critical and additional payload directly throttles
/// throughput.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetResponse {
    /// The request completed successfully.
    Ok,
    /// The frame submitted via [`NetRequest::SendFrame`] exceeds the
    /// interface's maximum transmission unit (MTU) plus Ethernet header.
    ///
    /// The caller SHOULD fragment before retrying, or reduce `bytes_len`.
    FrameTooLarge,
    /// The driver cannot complete the request because the physical link is
    /// down (no cable, no radio association, etc.).
    ///
    /// The network stack SHOULD wait for a [`NetEvent::LinkStateChange`] with
    /// `up = true` before retrying.
    LinkDown,
    /// The driver does not implement this request variant.
    ///
    /// The caller SHOULD NOT retry; the response is structural.
    NotSupported,
    /// One of the request's fields is structurally invalid (e.g., `bytes_len
    /// == 0`, malformed IOVA address).
    ///
    /// The caller SHOULD treat this as a programming error and log the
    /// offending request for triage.
    InvalidArgument,
}

// =============================================================================
// NetEvent — unsolicited driver events
// =============================================================================

/// An asynchronous event emitted by a NIC driver to the network stack.
///
/// Events are delivered on the event channel
/// (`nexacore.svc.net.<iface>.evt`). The network stack MUST NOT send requests
/// on the event channel; it is unidirectional driver → stack.
///
/// All variants carry `#[non_exhaustive]` — future drivers may introduce
/// additional event kinds (e.g., hardware offload completions) without a
/// wire-format break.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetEvent {
    /// A raw Ethernet frame was received from the network and written into
    /// the receive buffer at `bytes_iova`.
    ///
    /// `bytes_iova` is the IOVA-space address of the buffer the network
    /// stack pre-registered for receive operations. `bytes_len` is the
    /// number of valid bytes written into that buffer. The network stack
    /// becomes the owner of `bytes_iova` once this event is delivered and
    /// MUST NOT present the same buffer for a subsequent receive until after
    /// processing is complete.
    FrameReceived {
        /// IOVA-space address of the receive buffer containing the frame.
        bytes_iova: u64,
        /// Number of valid bytes in the receive buffer.
        bytes_len: u16,
    },
    /// The physical link state has changed.
    ///
    /// `up` indicates whether the link is now active. `speed_mbps` and
    /// `duplex_full` are only meaningful when `up == true`; drivers SHOULD
    /// set them to `0` and `false` respectively when `up == false`.
    LinkStateChange {
        /// `true` if the link is now up; `false` if it went down.
        up: bool,
        /// Link speed in megabits per second (meaningless when `up == false`).
        speed_mbps: u32,
        /// `true` for full-duplex; `false` for half-duplex.
        duplex_full: bool,
    },
    /// The interface's MAC address has changed (hot-plug scenario).
    ///
    /// Some virtual NIC backends allow the MAC address to be changed at
    /// runtime. The network stack MUST re-read the MAC after receiving this
    /// event and update any layer-2 state that depends on it.
    MacChanged {
        /// The new 6-byte MAC address in network byte order.
        mac: [u8; 6],
    },
    /// A raw Ethernet frame was received and is carried *inline* in the IPC
    /// payload.
    ///
    /// This is the M0 receive transport — the counterpart of
    /// [`NetRequest::SendFrameInline`]. Instead of handing the network stack
    /// ownership of an IOVA receive buffer (see [`Self::FrameReceived`]), the
    /// driver copies the received frame bytes directly into the
    /// `postcard`-encoded event. Sound for the same reason: a maximum frame
    /// (1514 bytes) fits within the IPC `MAX_PAYLOAD` of 4096 bytes.
    ///
    /// `bytes` is the complete received Ethernet frame with the virtio-net
    /// 10-byte virtio header already stripped by the driver. The IOVA path
    /// ([`Self::FrameReceived`]) remains reserved for a future zero-copy
    /// milestone.
    FrameReceivedInline {
        /// The complete received Ethernet frame, carried inline.
        bytes: Vec<u8>,
    },
}

// =============================================================================
// LinkState — snapshot value type
// =============================================================================

/// Snapshot of a network interface's link state.
///
/// Returned as the data payload accompanying a `GetLinkState` response per
/// the driver NCIP. Consumers MUST treat this as a point-in-time snapshot;
/// the authoritative live state is conveyed via [`NetEvent::LinkStateChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LinkState {
    /// `true` if the physical link is currently active.
    pub up: bool,
    /// Link speed in megabits per second. Meaningful only when `up == true`.
    pub speed_mbps: u32,
    /// `true` for full-duplex; `false` for half-duplex. Meaningful only when
    /// `up == true`.
    pub duplex_full: bool,
    /// The interface's current MAC address in network byte order.
    pub mac: [u8; 6],
}

// =============================================================================
// Channel-name helpers
// =============================================================================

/// Build the command channel name for a network interface.
///
/// The returned name has the form `"nexacore.svc.net.<interface>"` and identifies
/// the command channel on which the network stack issues [`NetRequest`]
/// messages and the NIC driver replies with [`NetResponse`] messages.
///
/// # Example
///
/// ```
/// # use nexacore_types::net_channel::net_channel_name;
/// assert_eq!(net_channel_name("eth0"), "nexacore.svc.net.eth0");
/// assert_eq!(net_channel_name("virtio0"), "nexacore.svc.net.virtio0");
/// ```
#[must_use]
pub fn net_channel_name(interface: &str) -> String {
    format!("{NET_CHANNEL_PREFIX}{interface}")
}

/// Build the event channel name for a network interface.
///
/// The returned name has the form `"nexacore.svc.net.<interface>.evt"` and
/// identifies the event channel on which the NIC driver delivers unsolicited
/// [`NetEvent`] messages to the network stack.
///
/// # Example
///
/// ```
/// # use nexacore_types::net_channel::net_event_channel_name;
/// assert_eq!(net_event_channel_name("eth0"), "nexacore.svc.net.eth0.evt");
/// assert_eq!(
///     net_event_channel_name("virtio0"),
///     "nexacore.svc.net.virtio0.evt"
/// );
/// ```
#[must_use]
pub fn net_event_channel_name(interface: &str) -> String {
    format!("{NET_CHANNEL_PREFIX}{interface}{NET_EVENT_CHANNEL_SUFFIX}")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::wire::{decode_canonical, encode_canonical};

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    #[test]
    fn net_channel_prefix_is_correct() {
        // Locked by the channel-naming convention in the driver NCIP.
        // Changing this value breaks the kernel IPC registry cap-gate; the
        // assertion is a tripwire.
        assert_eq!(NET_CHANNEL_PREFIX, "nexacore.svc.net.");
    }

    #[test]
    fn net_event_channel_suffix_is_correct() {
        // Locked by the channel-naming convention. Changing it desynchronizes
        // the driver and the network stack at registration time.
        assert_eq!(NET_EVENT_CHANNEL_SUFFIX, ".evt");
    }

    // -------------------------------------------------------------------------
    // Channel-name helpers
    // -------------------------------------------------------------------------

    #[test]
    fn net_channel_name_eth0() {
        assert_eq!(net_channel_name("eth0"), "nexacore.svc.net.eth0");
    }

    #[test]
    fn net_channel_name_virtio0() {
        assert_eq!(net_channel_name("virtio0"), "nexacore.svc.net.virtio0");
    }

    #[test]
    fn net_event_channel_name_eth0() {
        assert_eq!(net_event_channel_name("eth0"), "nexacore.svc.net.eth0.evt");
    }

    #[test]
    fn net_event_channel_name_virtio0() {
        assert_eq!(
            net_event_channel_name("virtio0"),
            "nexacore.svc.net.virtio0.evt"
        );
    }

    #[test]
    fn event_channel_name_is_command_channel_name_plus_suffix() {
        // The event channel name must be constructible by appending the suffix
        // to the command channel name. This property is relied upon by tooling
        // that derives event channel names from command channel names.
        let cmd = net_channel_name("tap0");
        let evt = net_event_channel_name("tap0");
        assert_eq!(evt, format!("{cmd}{NET_EVENT_CHANNEL_SUFFIX}"));
    }

    // -------------------------------------------------------------------------
    // NetRequest round-trips — one per variant
    // -------------------------------------------------------------------------

    #[test]
    fn net_request_send_frame_round_trip() {
        let value = NetRequest::SendFrame {
            bytes_iova: 0xDEAD_BEEF_CAFE_BABE,
            bytes_len: 1514,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_request_get_link_state_round_trip() {
        let value = NetRequest::GetLinkState;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_request_get_mac_round_trip() {
        let value = NetRequest::GetMac;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_request_set_promisc_on_round_trip() {
        let value = NetRequest::SetPromisc { on: true };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_request_set_promisc_off_round_trip() {
        let value = NetRequest::SetPromisc { on: false };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // NetResponse round-trips — one per variant
    // -------------------------------------------------------------------------

    #[test]
    fn net_response_ok_round_trip() {
        let value = NetResponse::Ok;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_response_frame_too_large_round_trip() {
        let value = NetResponse::FrameTooLarge;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_response_link_down_round_trip() {
        let value = NetResponse::LinkDown;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_response_not_supported_round_trip() {
        let value = NetResponse::NotSupported;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_response_invalid_argument_round_trip() {
        let value = NetResponse::InvalidArgument;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // NetEvent round-trips — one per variant
    // -------------------------------------------------------------------------

    #[test]
    fn net_event_frame_received_round_trip() {
        let value = NetEvent::FrameReceived {
            bytes_iova: 0x1_0000_0000,
            bytes_len: 60,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_request_send_frame_inline_round_trips() {
        let value = NetRequest::SendFrameInline {
            bytes: alloc::vec![0xAA; 1514],
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_event_frame_received_inline_round_trips() {
        let value = NetEvent::FrameReceivedInline {
            bytes: alloc::vec![0x55; 1514],
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    /// The M0 inline frame transport is only sound if a maximum-size Ethernet
    /// frame (1514 bytes) encodes to at most the kernel IPC `MAX_PAYLOAD` of
    /// 4096 bytes. This tripwire fails loudly if a future wire-format change
    /// bloats the envelope past that ceiling.
    #[test]
    fn inline_frame_fits_in_ipc_max_payload() {
        const IPC_MAX_PAYLOAD: usize = 4096;
        const MAX_FRAME: usize = 1514;
        let tx = encode_canonical(&NetRequest::SendFrameInline {
            bytes: alloc::vec![0xFF; MAX_FRAME],
        })
        .expect("encode tx");
        assert!(
            tx.len() <= IPC_MAX_PAYLOAD,
            "inline TX frame envelope {} B exceeds IPC MAX_PAYLOAD {} B",
            tx.len(),
            IPC_MAX_PAYLOAD
        );
        let rx = encode_canonical(&NetEvent::FrameReceivedInline {
            bytes: alloc::vec![0xFF; MAX_FRAME],
        })
        .expect("encode rx");
        assert!(
            rx.len() <= IPC_MAX_PAYLOAD,
            "inline RX frame envelope {} B exceeds IPC MAX_PAYLOAD {} B",
            rx.len(),
            IPC_MAX_PAYLOAD
        );
    }

    #[test]
    fn net_event_link_state_change_up_round_trip() {
        let value = NetEvent::LinkStateChange {
            up: true,
            speed_mbps: 1000,
            duplex_full: true,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_event_link_state_change_down_round_trip() {
        let value = NetEvent::LinkStateChange {
            up: false,
            speed_mbps: 0,
            duplex_full: false,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn net_event_mac_changed_round_trip() {
        let value = NetEvent::MacChanged {
            mac: [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF],
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: NetEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // LinkState round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn link_state_round_trip() {
        let value = LinkState {
            up: true,
            speed_mbps: 10_000,
            duplex_full: true,
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: LinkState = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn link_state_down_round_trip() {
        let value = LinkState {
            up: false,
            speed_mbps: 0,
            duplex_full: false,
            mac: [0xFF; 6],
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: LinkState = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // Wire-format invariants
    // -------------------------------------------------------------------------

    #[test]
    fn net_request_encoding_is_deterministic() {
        // Same value → same bytes. This is the signature-pre-image invariant.
        let value = NetRequest::SendFrame {
            bytes_iova: 0x4000,
            bytes_len: 128,
        };
        let a = encode_canonical(&value).expect("encode-a");
        let b = encode_canonical(&value).expect("encode-b");
        assert_eq!(a, b);
    }

    #[test]
    fn net_response_encoding_is_deterministic() {
        let value = NetResponse::Ok;
        let a = encode_canonical(&value).expect("encode-a");
        let b = encode_canonical(&value).expect("encode-b");
        assert_eq!(a, b);
    }

    #[test]
    fn net_event_encoding_is_deterministic() {
        let value = NetEvent::LinkStateChange {
            up: true,
            speed_mbps: 100,
            duplex_full: false,
        };
        let a = encode_canonical(&value).expect("encode-a");
        let b = encode_canonical(&value).expect("encode-b");
        assert_eq!(a, b);
    }

    #[test]
    fn net_request_decode_rejects_trailing_bytes() {
        // Defence-in-depth: the wire module already rejects trailing bytes;
        // assert the property on a NET type explicitly so an encoder swap that
        // loses the rejection trips this test.
        let value = NetRequest::GetLinkState;
        let mut bytes = encode_canonical(&value).expect("encode");
        bytes.push(0x00);
        let err = decode_canonical::<NetRequest>(&bytes).expect_err("must reject trailing");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    #[test]
    fn net_response_decode_rejects_empty_input() {
        // Postcard enums are encoded as varint(discriminant) + payload;
        // an empty input is never a valid discriminant.
        let err = decode_canonical::<NetResponse>(&[]).expect_err("must reject empty");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    #[test]
    fn net_event_decode_rejects_trailing_bytes() {
        let value = NetEvent::MacChanged {
            mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        };
        let mut bytes = encode_canonical(&value).expect("encode");
        bytes.push(0xFF);
        let err = decode_canonical::<NetEvent>(&bytes).expect_err("must reject trailing");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    // -------------------------------------------------------------------------
    // Wire discriminant distinguishability
    // -------------------------------------------------------------------------

    #[test]
    fn net_request_variants_are_distinguishable_on_the_wire() {
        // Every variant must produce a distinct first byte (the postcard
        // varint discriminant) so a decoder that only peeks at the head can
        // correctly dispatch. Declaration order: SendFrame=0, GetLinkState=1,
        // GetMac=2, SetPromisc=3.
        let send_frame = encode_canonical(&NetRequest::SendFrame {
            bytes_iova: 0,
            bytes_len: 0,
        })
        .expect("encode-send-frame");
        let get_link_state =
            encode_canonical(&NetRequest::GetLinkState).expect("encode-get-link-state");
        let get_mac = encode_canonical(&NetRequest::GetMac).expect("encode-get-mac");
        let set_promisc =
            encode_canonical(&NetRequest::SetPromisc { on: false }).expect("encode-set-promisc");

        assert_eq!(send_frame.first(), Some(&0));
        assert_eq!(get_link_state.first(), Some(&1));
        assert_eq!(get_mac.first(), Some(&2));
        assert_eq!(set_promisc.first(), Some(&3));
    }

    #[test]
    fn net_response_variants_are_distinguishable_on_the_wire() {
        // Declaration order: Ok=0, FrameTooLarge=1, LinkDown=2,
        // NotSupported=3, InvalidArgument=4.
        let ok = encode_canonical(&NetResponse::Ok).expect("encode-ok");
        let frame_too_large =
            encode_canonical(&NetResponse::FrameTooLarge).expect("encode-frame-too-large");
        let link_down = encode_canonical(&NetResponse::LinkDown).expect("encode-link-down");
        let not_supported =
            encode_canonical(&NetResponse::NotSupported).expect("encode-not-supported");
        let invalid_argument =
            encode_canonical(&NetResponse::InvalidArgument).expect("encode-invalid-argument");

        assert_eq!(ok.first(), Some(&0));
        assert_eq!(frame_too_large.first(), Some(&1));
        assert_eq!(link_down.first(), Some(&2));
        assert_eq!(not_supported.first(), Some(&3));
        assert_eq!(invalid_argument.first(), Some(&4));
    }

    #[test]
    fn net_event_variants_are_distinguishable_on_the_wire() {
        // Declaration order: FrameReceived=0, LinkStateChange=1, MacChanged=2.
        let frame_received = encode_canonical(&NetEvent::FrameReceived {
            bytes_iova: 0,
            bytes_len: 0,
        })
        .expect("encode-frame-received");
        let link_state_change = encode_canonical(&NetEvent::LinkStateChange {
            up: false,
            speed_mbps: 0,
            duplex_full: false,
        })
        .expect("encode-link-state-change");
        let mac_changed =
            encode_canonical(&NetEvent::MacChanged { mac: [0u8; 6] }).expect("encode-mac-changed");

        assert_eq!(frame_received.first(), Some(&0));
        assert_eq!(link_state_change.first(), Some(&1));
        assert_eq!(mac_changed.first(), Some(&2));
    }

    #[test]
    fn net_response_ok_encodes_to_single_byte() {
        // The unit variant has no payload — its canonical encoding is the
        // discriminant byte alone.
        let bytes = encode_canonical(&NetResponse::Ok).expect("encode");
        assert_eq!(bytes.as_slice(), &[0]);
    }

    // -------------------------------------------------------------------------
    // Cross-variant integration
    // -------------------------------------------------------------------------

    #[test]
    fn request_and_response_buffers_share_no_state() {
        // Encoding a request and a response into separate buffers must not
        // entangle their bytes. Catches an accidental shared scratch buffer.
        let req = NetRequest::SendFrame {
            bytes_iova: 0x8000,
            bytes_len: 1500,
        };
        let resp = NetResponse::Ok;
        let req_bytes: Vec<u8> = encode_canonical(&req).expect("encode-req");
        let resp_bytes: Vec<u8> = encode_canonical(&resp).expect("encode-resp");
        let req2: NetRequest = decode_canonical(&req_bytes).expect("decode-req");
        let resp2: NetResponse = decode_canonical(&resp_bytes).expect("decode-resp");
        assert_eq!(req2, req);
        assert_eq!(resp2, resp);
        assert_ne!(req_bytes, resp_bytes);
    }

    #[test]
    fn net_request_decode_rejects_truncated_input() {
        // Truncating the encoded bytes must surface an NexaCoreError::Wire and not
        // silently coerce to a default variant.
        let value = NetRequest::SendFrame {
            bytes_iova: 0x1234_5678,
            bytes_len: 100,
        };
        let bytes = encode_canonical(&value).expect("encode");
        assert!(bytes.len() >= 2, "encoding sanity check");
        let truncated = &bytes[..bytes.len() - 1];
        let err = decode_canonical::<NetRequest>(truncated).expect_err("must reject truncated");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }
}
