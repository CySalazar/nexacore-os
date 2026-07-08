//! Host-mode integration tests for MB13.d signed-token IPC.
//!
//! Exercises the end-to-end flow that the `IpcCreateChannel(20)` syscall
//! handler runs on bare metal: take postcard-encoded
//! [`nexacore_capability::CapabilityToken`] bytes, decode them, run full
//! Ed25519 verification (signature + time window + TEE binding) via
//! [`nexacore_kernel::capabilities::Ed25519CapabilityProvider`], and register
//! a channel whose `send_subject` / `recv_subject` slots are populated
//! from the verified tokens.
//!
//! The bare-metal `SYSCALL` plumbing (user-buffer copy, register
//! marshalling) is exercised by the QEMU `mb12-userprobe` smoke; these
//! tests cover everything that does not require Ring 3 hardware
//! semantics, which is the full decode + verify + capability-gate path.

#![cfg(feature = "bare-metal")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    clippy::uninlined_format_args,
    clippy::doc_markdown,
    clippy::integer_division,
    clippy::indexing_slicing
)]

use nexacore_capability::{
    CapabilityToken,
    scope::{Action, Resource, Scope, TimeWindow},
};
use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_kernel::{
    capabilities::{
        Ed25519CapabilityProvider, KernelAction, KernelPrincipal, decode_and_authenticate_token,
    },
    ipc::{
        BackpressurePolicy, ChannelPolicy, KernelIpcRegistry, MessageEnvelope, MessageKind,
        WakeAction,
    },
    scheduling::TaskId,
};
use nexacore_types::{identity::NodeId, wire};

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

const NODE_HASH: [u8; 32] = [0xAB; 32];
const TOKEN_NBF: u64 = 100;
const TOKEN_NAF: u64 = 200;
const TOKEN_NOW: u64 = 150;

fn fresh_node_id() -> NodeId {
    NodeId::from_attestation_hash(NODE_HASH)
}

fn mint_signed_token(action: Action, channel_hint: u64) -> (CapabilityToken, NodeId) {
    let issuer_key = NexaCoreSigningKey::generate();
    let node_id = fresh_node_id();
    let scope = Scope {
        action,
        resource: Resource::IpcChannel(channel_hint),
        window: TimeWindow::new(TOKEN_NBF, TOKEN_NAF).expect("valid window"),
        caveats: alloc::vec::Vec::new(),
    };
    let token = CapabilityToken::mint(&issuer_key, node_id, scope, None).expect("mint");
    (token, node_id)
}

fn encode_token(token: &CapabilityToken) -> alloc::vec::Vec<u8> {
    wire::encode_canonical(token).expect("encode")
}

fn provider_bound_to(node: NodeId) -> Ed25519CapabilityProvider {
    Ed25519CapabilityProvider::with_node_id(*node.as_bytes())
}

fn default_policy() -> ChannelPolicy {
    ChannelPolicy {
        queue_depth: 4,
        backpressure: BackpressurePolicy::Block,
        tee_bound: false,
    }
}

// -----------------------------------------------------------------------------
// 1. decode_and_authenticate_token — pure verification surface
// -----------------------------------------------------------------------------

extern crate alloc;

#[test]
fn decode_authenticate_accepts_freshly_minted_send_token() {
    let (token, node) = mint_signed_token(Action::IpcSend, 7);
    let bytes = encode_token(&token);
    let provider = provider_bound_to(node);

    let principal =
        decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NOW)
            .expect("authentic send token verifies");
    assert_eq!(principal.as_bytes(), node.as_bytes());
}

#[test]
fn decode_authenticate_rejects_bit_flipped_postcard_bytes() {
    let (token, node) = mint_signed_token(Action::IpcSend, 7);
    let mut bytes = encode_token(&token);
    // Flip a high-order bit in the middle of the payload pre-image.
    // The signature is computed over the canonical encoding, so any
    // mutation here turns the verify path into a Denied verdict.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x40;
    let provider = provider_bound_to(node);

    let err = decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NOW);
    assert!(err.is_err(), "tampered bytes must be rejected");
}

#[test]
fn decode_authenticate_rejects_action_mismatch() {
    // Token claims IpcSend; kernel slot expects IpcRecv.
    let (token, node) = mint_signed_token(Action::IpcSend, 7);
    let bytes = encode_token(&token);
    let provider = provider_bound_to(node);

    let err = decode_and_authenticate_token(&bytes, KernelAction::IpcRecv, &provider, TOKEN_NOW);
    assert!(err.is_err(), "action mismatch must be rejected");
}

#[test]
fn decode_authenticate_rejects_outside_time_window() {
    let (token, node) = mint_signed_token(Action::IpcSend, 7);
    let bytes = encode_token(&token);
    let provider = provider_bound_to(node);

    // `now = 50` < `not_before = 100`.
    let early =
        decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NBF - 50);
    assert!(early.is_err(), "pre-window time must be rejected");

    // `now = 250` >= `not_after = 200`.
    let late =
        decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NAF + 50);
    assert!(late.is_err(), "post-window time must be rejected");
}

#[test]
fn decode_authenticate_rejects_attestation_mismatch() {
    let (token, _node_a) = mint_signed_token(Action::IpcSend, 7);
    let bytes = encode_token(&token);
    // Provider claims a different node id than the one the token was
    // minted against; TEE binding must fail.
    let provider = Ed25519CapabilityProvider::with_node_id([0xCC; 32]);

    let err = decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NOW);
    assert!(err.is_err(), "TEE binding mismatch must be rejected");
}

#[test]
fn decode_authenticate_rejects_non_ipc_resource() {
    // Mint a token authorising a non-IPC resource (e.g. Any). The
    // MB13.d gate only accepts `Resource::IpcChannel(_)` tokens.
    let issuer_key = NexaCoreSigningKey::generate();
    let node_id = fresh_node_id();
    let scope = Scope {
        action: Action::IpcSend,
        resource: Resource::Any,
        window: TimeWindow::new(TOKEN_NBF, TOKEN_NAF).expect("window"),
        caveats: alloc::vec::Vec::new(),
    };
    let token = CapabilityToken::mint(&issuer_key, node_id, scope, None).expect("mint");
    let bytes = encode_token(&token);
    let provider = provider_bound_to(node_id);

    let err = decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NOW);
    assert!(err.is_err(), "non-IpcChannel resource must be rejected");
}

#[test]
fn decode_authenticate_rejects_truncated_postcard() {
    let (token, node) = mint_signed_token(Action::IpcSend, 7);
    let mut bytes = encode_token(&token);
    bytes.truncate(bytes.len() / 2);
    let provider = provider_bound_to(node);

    let err = decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NOW);
    assert!(err.is_err(), "truncated postcard must be rejected");
}

// -----------------------------------------------------------------------------
// 2. KernelIpcRegistry::create_channel_signed — full ABI flow
// -----------------------------------------------------------------------------

#[test]
fn signed_create_channel_authenticates_send_token_and_registers_subject() {
    let (token, node) = mint_signed_token(Action::IpcSend, 0);
    let bytes = encode_token(&token);
    let provider = provider_bound_to(node);

    let mut registry = KernelIpcRegistry::new();
    let id = registry
        .create_channel_signed(
            TaskId(1),
            default_policy(),
            Some(&bytes),
            None,
            &provider,
            TOKEN_NOW,
        )
        .expect("signed create_channel succeeds");

    let channel = registry.channel(id).expect("channel registered");
    let send_subject = channel.send_subject.expect("send_subject populated");
    assert_eq!(send_subject.as_bytes(), node.as_bytes());
    assert!(channel.recv_subject.is_none(), "recv unauthenticated");
}

#[test]
fn signed_create_channel_open_path_matches_legacy_create_channel() {
    // (send = None, recv = None) must behave byte-for-byte like the
    // MB12 open-channel pre-create used by `mb12-userprobe`.
    let provider = Ed25519CapabilityProvider::placeholder();
    let mut registry = KernelIpcRegistry::new();
    let id = registry
        .create_channel_signed(TaskId(1), default_policy(), None, None, &provider, 0)
        .expect("open-channel path succeeds");

    let channel = registry.channel(id).expect("channel registered");
    assert!(channel.send_subject.is_none());
    assert!(channel.recv_subject.is_none());
}

#[test]
fn signed_create_channel_rejects_invalid_send_token() {
    let (token, node) = mint_signed_token(Action::IpcSend, 0);
    let mut bytes = encode_token(&token);
    bytes[0] ^= 0xFF; // Corrupt the leading varint discriminant.
    let provider = provider_bound_to(node);

    let mut registry = KernelIpcRegistry::new();
    let res = registry.create_channel_signed(
        TaskId(1),
        default_policy(),
        Some(&bytes),
        None,
        &provider,
        TOKEN_NOW,
    );
    assert!(res.is_err(), "corrupt token must be rejected");
    assert_eq!(
        registry.channel_count(),
        0,
        "no channel registered on failure"
    );
}

#[test]
fn signed_create_channel_enforces_per_ipc_send_subject_gate() {
    // Full round-trip: register a channel with a Send-authenticated
    // subject, then verify that `send` from a different principal is
    // rejected and from the matching principal is accepted.
    let (token, node) = mint_signed_token(Action::IpcSend, 0);
    let bytes = encode_token(&token);
    let provider = provider_bound_to(node);

    let mut registry = KernelIpcRegistry::new();
    let id = registry
        .create_channel_signed(
            TaskId(1),
            default_policy(),
            Some(&bytes),
            None,
            &provider,
            TOKEN_NOW,
        )
        .expect("signed create_channel succeeds");

    let authorised = KernelPrincipal::from_bytes(*node.as_bytes());
    let intruder = KernelPrincipal::from_bytes([0x99; 32]);

    let envelope_ok = MessageEnvelope {
        sender: TaskId(2),
        channel: id,
        kind: MessageKind::Notification,
        payload: alloc::vec::Vec::new(),
    };
    let wake = registry
        .send(envelope_ok, TaskId(2), authorised)
        .expect("authorised sender accepted");
    assert!(matches!(wake, WakeAction::None | WakeAction::Wake(_)));

    let envelope_bad = MessageEnvelope {
        sender: TaskId(3),
        channel: id,
        kind: MessageKind::Notification,
        payload: alloc::vec::Vec::new(),
    };
    let denied = registry.send(envelope_bad, TaskId(3), intruder);
    assert!(denied.is_err(), "unauthorised sender rejected at send-time");
}
