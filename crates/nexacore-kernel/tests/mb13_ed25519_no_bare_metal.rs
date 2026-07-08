//! MB13 integration tests — Ed25519 capability provider, no feature flags required.
//!
//! These tests exercise the full Ed25519-signed capability path from a
//! standard `cargo test` invocation (no `--features bare-metal` needed).
//! They are the host-mode counterpart of `mb13_capability_signed.rs` and
//! cover the three mandatory MB13 scenarios:
//!
//! 1. **User probe with real Ed25519 capabilities** — the
//!    `decode_and_authenticate_token` + `create_channel_signed` flow that
//!    the `IpcCreateChannel(20)` syscall handler uses at channel creation.
//! 2. **Signed token roundtrip** — mint → postcard-encode → decode →
//!    `verify_signature` + `verify_full`, asserting byte-identical
//!    round-trip semantics that the kernel depends on for replay-resistance.
//! 3. **Token revocation and expiration** — both the time-window and the
//!    revocation-list rejection paths of `verify_full`, confirming that
//!    the `Ed25519CapabilityProvider` correctly translates these into
//!    `CapabilityVerdict::Denied`.
//!
//! ## Design note
//!
//! `Ed25519CapabilityProvider`, `decode_and_authenticate_token`, and
//! `KernelIpcRegistry::create_channel_signed` are compiled unconditionally
//! (no `#[cfg(feature = "bare-metal")]` guard). The tests here therefore
//! exercise the real production code paths without any feature flag. The
//! bare-metal boot wiring consumes the same code paths — nothing is stubbed
//! out here.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::uninlined_format_args,
    clippy::doc_markdown,
    clippy::integer_division,
    clippy::indexing_slicing,
    clippy::option_if_let_else
)]

extern crate alloc;

use alloc::vec::Vec;

use nexacore_capability::{
    CapabilityToken,
    revocation::RevocationList,
    scope::{Action, Resource, Scope, TimeWindow},
    tee::StubAttestation,
};
use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_kernel::{
    capabilities::{
        CapabilityVerdict, Ed25519CapabilityProvider, KernelAction, KernelPrincipal,
        decode_and_authenticate_token,
    },
    ipc::{BackpressurePolicy, ChannelPolicy, KernelIpcRegistry},
    scheduling::TaskId,
};
use nexacore_types::{identity::NodeId, wire};

// =============================================================================
// Shared test fixtures
// =============================================================================

/// All tokens in these tests share this node-identity hash.
const NODE_HASH: [u8; 32] = [0xAB; 32];

/// Token validity window: `[100, 200)` seconds (Unix epoch).
const TOKEN_NBF: u64 = 100;
const TOKEN_NAF: u64 = 200;

/// A timestamp strictly inside the window `[100, 200)`.
const TOKEN_NOW: u64 = 150;

/// Construct the `NodeId` used as the TEE attestation identity
/// in these tests.
fn fresh_node_id() -> NodeId {
    NodeId::from_attestation_hash(NODE_HASH)
}

/// Mint a signed [`CapabilityToken`] for the given IPC action, bound to
/// `fresh_node_id()` with the window `[TOKEN_NBF, TOKEN_NAF)`.
///
/// `channel_hint` populates `Resource::IpcChannel(channel_hint)`.
fn mint_ipc_token(
    action: Action,
    channel_hint: u64,
) -> (CapabilityToken, NodeId, NexaCoreSigningKey) {
    let issuer_key = NexaCoreSigningKey::generate();
    let node_id = fresh_node_id();
    let scope = Scope {
        action,
        resource: Resource::IpcChannel(channel_hint),
        window: TimeWindow::new(TOKEN_NBF, TOKEN_NAF).expect("valid window"),
        caveats: Vec::new(),
    };
    let token = CapabilityToken::mint(&issuer_key, node_id, scope, None).expect("mint ok");
    (token, node_id, issuer_key)
}

/// Encode a token to postcard bytes via the canonical wire helper.
fn encode_token(token: &CapabilityToken) -> Vec<u8> {
    wire::encode_canonical(token).expect("postcard encode ok")
}

/// Construct an `Ed25519CapabilityProvider` whose TEE attestation identity
/// matches `node`.
fn provider_for(node: NodeId) -> Ed25519CapabilityProvider {
    Ed25519CapabilityProvider::with_node_id(*node.as_bytes())
}

/// A minimal `ChannelPolicy` used across registry tests.
fn default_policy() -> ChannelPolicy {
    ChannelPolicy {
        queue_depth: 4,
        backpressure: BackpressurePolicy::Block,
        tee_bound: false,
    }
}

// =============================================================================
// Test 1 — User probe with real Ed25519 capabilities
// =============================================================================
//
// This scenario models what the `IpcCreateChannel(20)` syscall handler
// does on bare metal: take a postcard-encoded `CapabilityToken` that
// user space presents in a register, decode it, run full Ed25519
// verification (signature + time window + TEE binding), and register
// a channel whose `send_subject` is populated from the verified token.
//
// Sub-tests cover:
//   a. Freshly minted send token → `Authorised`, subject extracted.
//   b. Freshly minted recv token → `Authorised`, subject extracted.
//   c. Both slots populated → both subjects visible on the channel.
//   d. Per-IPC send gate: the `send` call with a mismatched principal
//      is denied after the signed channel is registered.

/// a. A freshly minted IpcSend token is accepted; the subject is extracted
///    and registered as the channel's `send_subject`.
#[test]
fn user_probe_signed_send_token_registers_subject() {
    let (token, node, _key) = mint_ipc_token(Action::IpcSend, 0);
    let bytes = encode_token(&token);
    let provider = provider_for(node);

    // Decode + authenticate via the raw helper — mirrors the kernel's
    // per-syscall path before creating the channel entry.
    let principal =
        decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NOW)
            .expect("signed send token must authenticate");
    assert_eq!(
        principal.as_bytes(),
        node.as_bytes(),
        "extracted principal must match the token's subject"
    );

    // Full registry path: create a channel that enforces the send subject.
    let mut registry = KernelIpcRegistry::new();
    let channel_id = registry
        .create_channel_signed(
            TaskId(1),
            default_policy(),
            Some(&bytes),
            None,
            &provider,
            TOKEN_NOW,
        )
        .expect("signed create_channel must succeed");

    let channel = registry.channel(channel_id).expect("channel registered");
    let send_subject = channel.send_subject.expect("send_subject populated");
    assert_eq!(
        send_subject.as_bytes(),
        node.as_bytes(),
        "channel send_subject must match node identity"
    );
    assert!(channel.recv_subject.is_none(), "recv slot must be open");
}

/// b. A freshly minted IpcRecv token is accepted and wired as
///    `recv_subject`.
#[test]
fn user_probe_signed_recv_token_registers_subject() {
    let (token, node, _key) = mint_ipc_token(Action::IpcRecv, 0);
    let bytes = encode_token(&token);
    let provider = provider_for(node);

    let mut registry = KernelIpcRegistry::new();
    let channel_id = registry
        .create_channel_signed(
            TaskId(1),
            default_policy(),
            None,
            Some(&bytes),
            &provider,
            TOKEN_NOW,
        )
        .expect("signed create_channel with recv token must succeed");

    let channel = registry.channel(channel_id).expect("channel registered");
    assert!(channel.send_subject.is_none(), "send slot must be open");
    let recv_subject = channel.recv_subject.expect("recv_subject populated");
    assert_eq!(
        recv_subject.as_bytes(),
        node.as_bytes(),
        "channel recv_subject must match node identity"
    );
}

/// c. Both send and recv slots authenticated from separate tokens that
///    share a node identity.
#[test]
fn user_probe_both_slots_authenticated() {
    // Both tokens are issued by the same key for the same node so a
    // single provider can authenticate both.
    let shared_node = fresh_node_id();
    let issuer = NexaCoreSigningKey::generate();

    let tok_send = CapabilityToken::mint(
        &issuer,
        shared_node,
        Scope {
            action: Action::IpcSend,
            resource: Resource::IpcChannel(0),
            window: TimeWindow::new(TOKEN_NBF, TOKEN_NAF).expect("window"),
            caveats: Vec::new(),
        },
        None,
    )
    .expect("mint send");

    let tok_recv = CapabilityToken::mint(
        &issuer,
        shared_node,
        Scope {
            action: Action::IpcRecv,
            resource: Resource::IpcChannel(0),
            window: TimeWindow::new(TOKEN_NBF, TOKEN_NAF).expect("window"),
            caveats: Vec::new(),
        },
        None,
    )
    .expect("mint recv");

    let bytes_send = encode_token(&tok_send);
    let bytes_recv = encode_token(&tok_recv);
    let provider = provider_for(shared_node);

    let mut registry = KernelIpcRegistry::new();
    let channel_id = registry
        .create_channel_signed(
            TaskId(1),
            default_policy(),
            Some(&bytes_send),
            Some(&bytes_recv),
            &provider,
            TOKEN_NOW,
        )
        .expect("both slots authenticated");

    let channel = registry.channel(channel_id).expect("channel registered");
    assert_eq!(
        channel.send_subject.expect("send_subject").as_bytes(),
        shared_node.as_bytes()
    );
    assert_eq!(
        channel.recv_subject.expect("recv_subject").as_bytes(),
        shared_node.as_bytes()
    );
}

/// d. Per-IPC gate: after signed channel creation the `send` call with a
///    mismatched principal is denied; the authorised principal proceeds.
#[test]
fn user_probe_per_ipc_send_gate_enforced_after_signed_create() {
    use nexacore_kernel::ipc::{MessageEnvelope, MessageKind, WakeAction};

    let (token, node, _key) = mint_ipc_token(Action::IpcSend, 0);
    let bytes = encode_token(&token);
    let provider = provider_for(node);

    let mut registry = KernelIpcRegistry::new();
    let channel_id = registry
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

    // Intruder is denied.
    let err = registry
        .send(
            MessageEnvelope {
                sender: TaskId(99),
                channel: channel_id,
                kind: MessageKind::Request,
                payload: Vec::new(),
            },
            TaskId(99),
            intruder,
        )
        .unwrap_err();
    assert_eq!(
        err,
        nexacore_kernel::KernelError::CapabilityDenied,
        "intruder must be denied by the per-IPC send gate"
    );

    // Authorised principal succeeds.
    let wake = registry
        .send(
            MessageEnvelope {
                sender: TaskId(2),
                channel: channel_id,
                kind: MessageKind::Request,
                payload: Vec::new(),
            },
            TaskId(2),
            authorised,
        )
        .expect("authorised principal must be accepted");
    assert!(
        matches!(wake, WakeAction::None | WakeAction::Wake(_)),
        "wake action must be None or Wake on successful send"
    );
}

// =============================================================================
// Test 2 — Signed token roundtrip
// =============================================================================
//
// Verifies the security-critical property: a token minted in memory,
// encoded to canonical postcard bytes, decoded back, and verified via
// `verify_signature` and `verify_full` produces the same result as
// operating on the in-memory token. This is the exact property the
// kernel relies on to prevent deserialization-divergence attacks.
//
// Sub-tests:
//   a. Signature verification survives encode → decode.
//   b. Full verification (sig + time + TEE) survives encode → decode.
//   c. Re-encoding the decoded token is byte-identical to the original.
//   d. A single bit-flip in the postcard bytes causes decode + verify
//      to produce a different result (tamper detection).

/// a. Signature verification survives a postcard encode → decode cycle.
#[test]
fn signed_token_roundtrip_signature_verifies_after_decode() {
    let (token, _node, _key) = mint_ipc_token(Action::IpcSend, 42);
    let bytes = encode_token(&token);

    let decoded: CapabilityToken =
        wire::decode_canonical(&bytes).expect("postcard decode must succeed");

    decoded
        .verify_signature()
        .expect("decoded token's signature must verify");
}

/// b. Full verification (`verify_full`) survives encode → decode.
#[test]
fn signed_token_roundtrip_full_verify_after_decode() {
    let node = fresh_node_id();
    let issuer = NexaCoreSigningKey::generate();
    let scope = Scope {
        action: Action::IpcSend,
        resource: Resource::IpcChannel(1),
        window: TimeWindow::new(TOKEN_NBF, TOKEN_NAF).expect("window"),
        caveats: Vec::new(),
    };
    let token = CapabilityToken::mint(&issuer, node, scope, None).expect("mint ok");
    let bytes = encode_token(&token);

    let decoded: CapabilityToken =
        wire::decode_canonical(&bytes).expect("postcard decode must succeed");

    let attestation = StubAttestation {
        fixed_node_id: node,
    };
    let revocation = RevocationList::new();
    decoded
        .verify_full(TOKEN_NOW, &attestation, &revocation)
        .expect("decoded token must pass verify_full inside the time window");
}

/// c. Re-encoding the decoded token produces byte-identical output.
///
/// This is the canonical-encoding determinism guarantee that makes
/// Ed25519 signatures reproducible across implementations.
#[test]
fn signed_token_roundtrip_reencoded_bytes_are_identical() {
    let (token, _node, _key) = mint_ipc_token(Action::IpcRecv, 7);
    let original_bytes = encode_token(&token);

    let decoded: CapabilityToken = wire::decode_canonical(&original_bytes).expect("decode ok");

    let re_encoded = wire::encode_canonical(&decoded).expect("re-encode ok");
    assert_eq!(
        original_bytes, re_encoded,
        "canonical encoding must be byte-identical across encode → decode → encode"
    );
}

/// d. A bit-flip in the postcard bytes causes signature verification to
///    fail, confirming tamper detection at the decode + verify boundary.
#[test]
fn signed_token_roundtrip_tampered_bytes_fail_verification() {
    let (token, _node, _key) = mint_ipc_token(Action::IpcSend, 7);
    let mut bytes = encode_token(&token);

    // Flip a bit in the middle of the encoded blob. The signature
    // covers the canonical payload encoding so any mutation surfaces as
    // `InvalidSignature` or a decode error.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x40;

    // The tampered bytes may decode to a structurally valid token (if
    // the flip happened to land in a non-framing byte) or may fail
    // decoding entirely. In both cases the outcome must NOT be
    // `Authorised`.
    let outcome = match wire::decode_canonical::<CapabilityToken>(&bytes) {
        Ok(decoded) => decoded.verify_signature().is_err(),
        Err(_) => true, // decode failure is also an acceptable rejection
    };
    assert!(
        outcome,
        "tampered postcard bytes must fail decode or signature verification"
    );
}

// =============================================================================
// Test 3 — Token revocation and expiration
// =============================================================================
//
// Verifies the two remaining `verify_full` rejection branches that the
// Ed25519CapabilityProvider translates into `CapabilityVerdict::Denied`.
// These are distinct from signature failure — both scenarios produce a
// structurally valid, correctly signed token that must nevertheless be
// rejected.
//
// Sub-tests:
//   a. Expired token (now >= not_after) → Denied.
//   b. Not-yet-valid token (now < not_before) → Denied.
//   c. Revoked token → Revoked error from verify_full.
//   d. Revoked child token, non-revoked root still passes.
//   e. Token for a different node is rejected (TEE binding).

/// a. An expired token (now == not_after, exclusive boundary) is rejected.
#[test]
fn token_expiration_at_not_after_boundary_is_rejected() {
    let (token, node, _key) = mint_ipc_token(Action::IpcSend, 1);
    let bytes = encode_token(&token);
    let provider = provider_for(node);

    // now = TOKEN_NAF = 200, which is the exclusive upper boundary.
    let verdict = provider.verify_signed_token(&token, TOKEN_NAF);
    assert_eq!(
        verdict,
        CapabilityVerdict::Denied,
        "token at exactly not_after must be expired"
    );

    // Also verify the kernel decode path rejects it.
    let err = decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NAF);
    assert!(
        err.is_err(),
        "expired token must be rejected by the kernel path"
    );
}

/// b. A not-yet-valid token (now < not_before) is rejected.
#[test]
fn token_not_before_boundary_is_rejected() {
    let (token, node, _key) = mint_ipc_token(Action::IpcSend, 1);
    let bytes = encode_token(&token);
    let provider = provider_for(node);

    // now = TOKEN_NBF - 1 = 99, one tick before the inclusive lower bound.
    let verdict = provider.verify_signed_token(&token, TOKEN_NBF - 1);
    assert_eq!(
        verdict,
        CapabilityVerdict::Denied,
        "token one tick before not_before must be rejected"
    );

    let err =
        decode_and_authenticate_token(&bytes, KernelAction::IpcSend, &provider, TOKEN_NBF - 1);
    assert!(
        err.is_err(),
        "pre-window token must be rejected by the kernel path"
    );
}

/// c. A revoked token is rejected by `verify_full` even though its
///    signature, time window, and TEE binding are all valid.
#[test]
fn revoked_token_is_rejected_by_verify_full() {
    use nexacore_types::error::{CapabilityErrorKind, NexaCoreError};

    let node = fresh_node_id();
    let issuer = NexaCoreSigningKey::generate();
    let scope = Scope {
        action: Action::IpcSend,
        resource: Resource::IpcChannel(5),
        window: TimeWindow::new(TOKEN_NBF, TOKEN_NAF).expect("window"),
        caveats: Vec::new(),
    };
    let token = CapabilityToken::mint(&issuer, node, scope, None).expect("mint ok");

    // The token should verify fine with an empty revocation list.
    let attestation = StubAttestation {
        fixed_node_id: node,
    };
    let empty_rev = RevocationList::new();
    token
        .verify_full(TOKEN_NOW, &attestation, &empty_rev)
        .expect("non-revoked token must pass verify_full");

    // Now revoke it and confirm rejection.
    let mut revocation = RevocationList::new();
    revocation.revoke(token.payload.id);

    let err = token
        .verify_full(TOKEN_NOW, &attestation, &revocation)
        .unwrap_err();

    match err {
        NexaCoreError::Capability { kind, .. } => {
            assert_eq!(
                kind,
                CapabilityErrorKind::Revoked,
                "revoked token must produce Revoked error"
            );
        }
        other => panic!("expected Capability::Revoked, got {other:?}"),
    }
}

/// d. A revoked child token is rejected at use time; the root token
///    (which is NOT revoked) still passes verification.
#[test]
fn revoked_child_token_is_rejected_at_use_time() {
    use nexacore_capability::token::TokenPayload;
    use nexacore_types::{
        error::{CapabilityErrorKind, NexaCoreError},
        identity::CapabilityId,
    };

    let node = fresh_node_id();
    let issuer = NexaCoreSigningKey::generate();

    let root = CapabilityToken::mint(
        &issuer,
        node,
        Scope {
            action: Action::IpcSend,
            resource: Resource::IpcChannel(3),
            window: TimeWindow::new(TOKEN_NBF, TOKEN_NAF).expect("window"),
            caveats: Vec::new(),
        },
        None,
    )
    .expect("mint root");

    // Build a child token by re-signing a narrower payload.
    let child_payload = TokenPayload {
        id: CapabilityId::new(),
        subject: node,
        issuer: issuer.verifying_key(),
        parent: Some(root.payload.id),
        scope: Scope {
            action: Action::IpcSend,
            resource: Resource::IpcChannel(3),
            window: TimeWindow::new(TOKEN_NBF + 10, TOKEN_NAF - 10).expect("narrower window"),
            caveats: Vec::new(),
        },
    };
    let child = CapabilityToken::sign_payload(&issuer, child_payload).expect("sign child");

    let attestation = StubAttestation {
        fixed_node_id: node,
    };
    let empty_rev = RevocationList::new();

    // Child passes without revocation.
    child
        .verify_full(TOKEN_NOW, &attestation, &empty_rev)
        .expect("non-revoked child must pass verify_full");

    // Revoke the child only.
    let mut revocation = RevocationList::new();
    revocation.revoke(child.payload.id);

    // Root is not revoked — still passes.
    root.verify_full(TOKEN_NOW, &attestation, &revocation)
        .expect("non-revoked root must still pass verify_full");

    // Child is revoked — rejected.
    let err = child
        .verify_full(TOKEN_NOW, &attestation, &revocation)
        .unwrap_err();

    match err {
        NexaCoreError::Capability { kind, .. } => {
            assert_eq!(
                kind,
                CapabilityErrorKind::Revoked,
                "revoked child must produce Revoked error"
            );
        }
        other => panic!("expected Capability::Revoked, got {other:?}"),
    }
}

/// e. A token bound to a different TEE node is rejected (TEE binding
///    check via `verify_signed_token`).
#[test]
fn token_tee_binding_mismatch_is_rejected() {
    let node_a = fresh_node_id();
    let node_b = NodeId::from_attestation_hash([0xCC; 32]);

    let issuer = NexaCoreSigningKey::generate();
    let scope = Scope {
        action: Action::IpcSend,
        resource: Resource::IpcChannel(9),
        window: TimeWindow::new(TOKEN_NBF, TOKEN_NAF).expect("window"),
        caveats: Vec::new(),
    };
    // Mint for node_a.
    let token = CapabilityToken::mint(&issuer, node_a, scope, None).expect("mint ok");

    // Provider claiming node_b rejects the token.
    let provider_b = provider_for(node_b);
    let verdict = provider_b.verify_signed_token(&token, TOKEN_NOW);
    assert_eq!(
        verdict,
        CapabilityVerdict::Denied,
        "token bound to node_a must be rejected by node_b's provider"
    );

    // Provider claiming node_a accepts it.
    let provider_a = provider_for(node_a);
    let verdict_a = provider_a.verify_signed_token(&token, TOKEN_NOW);
    assert_eq!(
        verdict_a,
        CapabilityVerdict::Authorised,
        "token bound to node_a must be accepted by node_a's provider"
    );
}
