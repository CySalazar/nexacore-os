//! End-to-end integration test for the foundational P1 layer.
//!
//! Exercises the full lifecycle of a capability token across the
//! three foundational crates, in the order a real NexaCore OS deployment
//! would touch them:
//!
//! 1. `nexacore-types`: `NodeId` / `ModelId` derived from attestation
//!    hashes, `Scope` built from typed `Action` / `Resource` /
//!    `TimeWindow` / `Caveat`s.
//! 2. `nexacore-crypto`: `Ed25519` issuer key generation; canonical token
//!    encoding signed via the typed signing API.
//! 3. `nexacore-capability`: token mint, attenuation chain (3 levels deep),
//!    chain-link verification, full validation against TEE attestation,
//!    revocation list, and time window.
//!
//! Each scenario is a separate `#[test]` so a regression in any
//! single property is reported in isolation.

// Tests legitimately use `unwrap` / `expect` / `panic` on assertion
// failure; that is the standard `#[test]` idiom and clippy's strict
// lints would otherwise fight the test style. The same allow-attribute
// pattern is used by the in-crate `mod tests` blocks; we replicate it
// here for the integration-test target.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nexacore_capability::{
    attenuation::{attenuate, verify_chain_link},
    revocation::RevocationList,
    scope::{Action, Caveat, Resource, Scope, TimeWindow},
    tee::StubAttestation,
    token::CapabilityToken,
};
use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_types::{
    error::{CapabilityErrorKind, NexaCoreError},
    identity::{ModelId, NodeId},
};

// =============================================================================
// Test fixtures
// =============================================================================

/// Concrete `NodeId` derived from a deterministic byte pattern. In
/// production this would come from the BLAKE3 of a TEE quote.
fn user_node() -> NodeId {
    NodeId::from_attestation_hash([0xA1; 32])
}

/// A representative model identifier (content-addressed manifest hash).
fn target_model() -> ModelId {
    ModelId::from_manifest_hash([0xB2; 32])
}

/// Convenience: build a root scope for inference on a specific model.
fn root_inference_scope() -> Scope {
    Scope {
        action: Action::ModelInfer,
        resource: Resource::Model(target_model()),
        // Wide window: 1000 → 10_000 (Unix seconds).
        window: TimeWindow::new(1_000, 10_000).expect("legal window"),
        caveats: alloc_vec(),
    }
}

// `alloc::vec::Vec::new` is `const`-stable in std contexts; this
// helper just keeps the test bodies tidy.
fn alloc_vec<T>() -> Vec<T> {
    Vec::new()
}

// =============================================================================
// Scenario 1: happy path — root mint, single attenuation, full verify.
// =============================================================================

#[test]
fn happy_path_root_then_single_attenuation_then_use() {
    let issuer = NexaCoreSigningKey::generate();
    let user = user_node();

    // 1. Issuer mints a root capability for the user node.
    let root = CapabilityToken::mint(&issuer, user, root_inference_scope(), None)
        .expect("root mint must succeed");
    root.verify_signature().expect("root signature must verify");

    // 2. Issuer attenuates: shrink window to [2_000, 5_000).
    let child = attenuate(
        &root,
        &issuer,
        &[Caveat::NotBefore(2_000), Caveat::ExpiresAt(5_000)],
    )
    .expect("attenuation must succeed");

    // 3. Chain link is sound.
    verify_chain_link(&root, &child).expect("chain link must hold");

    // 4. Full verification at a time inside the child window with
    //    correct attestation and empty revocation list.
    let attestation = StubAttestation {
        fixed_node_id: user,
    };
    let revocation = RevocationList::new();
    child
        .verify_full(3_500, &attestation, &revocation)
        .expect("verify_full inside child window must succeed");
}

// =============================================================================
// Scenario 2: 3-deep attenuation chain stays sound.
// =============================================================================

#[test]
fn three_level_attenuation_chain_remains_subset() {
    let issuer = NexaCoreSigningKey::generate();
    let user = user_node();

    let root = CapabilityToken::mint(&issuer, user, root_inference_scope(), None).unwrap();
    let lvl1 = attenuate(&root, &issuer, &[Caveat::ExpiresAt(8_000)]).unwrap();
    let lvl2 = attenuate(&lvl1, &issuer, &[Caveat::NotBefore(3_000)]).unwrap();
    let lvl3 = attenuate(&lvl2, &issuer, &[Caveat::ExpiresAt(4_500)]).unwrap();

    // Walk the chain: each link must be sound.
    verify_chain_link(&root, &lvl1).expect("root → lvl1");
    verify_chain_link(&lvl1, &lvl2).expect("lvl1 → lvl2");
    verify_chain_link(&lvl2, &lvl3).expect("lvl2 → lvl3");

    // The terminal child window is [3_000, 4_500), strictly inside
    // every ancestor's window.
    assert_eq!(lvl3.payload.scope.window.not_before, 3_000);
    assert_eq!(lvl3.payload.scope.window.not_after, 4_500);

    // And it carries every caveat from the chain.
    assert!(
        lvl3.payload
            .scope
            .caveats
            .contains(&Caveat::ExpiresAt(8_000))
    );
    assert!(
        lvl3.payload
            .scope
            .caveats
            .contains(&Caveat::NotBefore(3_000))
    );
    assert!(
        lvl3.payload
            .scope
            .caveats
            .contains(&Caveat::ExpiresAt(4_500))
    );
}

// =============================================================================
// Scenario 3: revoking the root invalidates a use under the attenuated
// child (revocation by `id` of the *exact* token used at the call site).
// =============================================================================

#[test]
fn revoking_the_used_token_blocks_verification() {
    let issuer = NexaCoreSigningKey::generate();
    let user = user_node();
    let root = CapabilityToken::mint(&issuer, user, root_inference_scope(), None).unwrap();
    let child = attenuate(&root, &issuer, &[Caveat::ExpiresAt(5_000)]).unwrap();

    let attestation = StubAttestation {
        fixed_node_id: user,
    };
    let mut revocation = RevocationList::new();
    revocation.revoke(child.payload.id);

    let err = child
        .verify_full(3_000, &attestation, &revocation)
        .unwrap_err();
    match err {
        NexaCoreError::Capability { kind, .. } => assert_eq!(kind, CapabilityErrorKind::Revoked),
        other => panic!("expected Capability::Revoked, got {other:?}"),
    }
}

// =============================================================================
// Scenario 4: TEE binding is enforced — a token issued for node A is
// rejected when the calling node attests as B.
// =============================================================================

#[test]
fn attestation_mismatch_blocks_verification() {
    let issuer = NexaCoreSigningKey::generate();
    let user_a = user_node();
    let user_b = NodeId::from_attestation_hash([0xC3; 32]);

    let token = CapabilityToken::mint(&issuer, user_a, root_inference_scope(), None).unwrap();

    // Caller's TEE attests as user_b — different from the token's subject.
    let bad_attestation = StubAttestation {
        fixed_node_id: user_b,
    };
    let revocation = RevocationList::new();

    let err = token
        .verify_full(5_000, &bad_attestation, &revocation)
        .unwrap_err();
    match err {
        NexaCoreError::Capability { kind, .. } => {
            assert_eq!(kind, CapabilityErrorKind::AttestationMismatch);
        }
        other => panic!("expected Capability::AttestationMismatch, got {other:?}"),
    }
}

// =============================================================================
// Scenario 5: time window enforcement at both ends of the half-open
// interval.
// =============================================================================

#[test]
fn time_window_enforces_both_boundaries() {
    let issuer = NexaCoreSigningKey::generate();
    let user = user_node();
    let token = CapabilityToken::mint(&issuer, user, root_inference_scope(), None).unwrap();
    let attestation = StubAttestation {
        fixed_node_id: user,
    };
    let revocation = RevocationList::new();

    // Window is [1_000, 10_000).
    // Before nbf -> NotYetValid.
    let err_before = token
        .verify_full(999, &attestation, &revocation)
        .unwrap_err();
    match err_before {
        NexaCoreError::Capability { kind, .. } => {
            assert_eq!(kind, CapabilityErrorKind::NotYetValid);
        }
        other => panic!("expected NotYetValid, got {other:?}"),
    }

    // Exactly at nbf -> ok.
    token
        .verify_full(1_000, &attestation, &revocation)
        .expect("nbf is inclusive");

    // Just before exp -> ok.
    token
        .verify_full(9_999, &attestation, &revocation)
        .expect("exp is exclusive");

    // Exactly at exp -> Expired.
    let err_at = token
        .verify_full(10_000, &attestation, &revocation)
        .unwrap_err();
    match err_at {
        NexaCoreError::Capability { kind, .. } => assert_eq!(kind, CapabilityErrorKind::Expired),
        other => panic!("expected Expired, got {other:?}"),
    }
}

// =============================================================================
// Scenario 6: tampered child is rejected even when re-signed by the
// original issuer (Macaroons monotonicity). This is the
// security-critical property exercised at the integration level.
// =============================================================================

#[test]
fn tampered_child_with_broader_window_is_rejected() {
    let issuer = NexaCoreSigningKey::generate();
    let user = user_node();
    let root = CapabilityToken::mint(&issuer, user, root_inference_scope(), None).unwrap();

    // Build a malicious child with a window broader than the root.
    let evil_payload = nexacore_capability::token::TokenPayload {
        id: nexacore_types::identity::CapabilityId::new(),
        subject: user,
        issuer: issuer.verifying_key(),
        parent: Some(root.payload.id),
        scope: Scope {
            window: TimeWindow::new(0, u64::MAX).unwrap(),
            ..root.payload.scope.clone()
        },
    };
    let evil_child = CapabilityToken::sign_payload(&issuer, evil_payload).unwrap();

    // The signature itself is valid (we signed it with the issuer key)
    // — that is exactly the attack.
    evil_child
        .verify_signature()
        .expect("attacker's signature is valid; verify_chain_link is what catches the broadening");

    // Chain-link verification MUST reject the broadened scope.
    let err = verify_chain_link(&root, &evil_child).unwrap_err();
    match err {
        NexaCoreError::Capability { kind, .. } => {
            assert_eq!(kind, CapabilityErrorKind::AttenuationViolation);
        }
        other => panic!("expected AttenuationViolation, got {other:?}"),
    }
}

// =============================================================================
// Scenario 7: deserialise a token from its canonical bytes and verify.
// Mirrors what a relay would do upon receiving a token over the wire.
// =============================================================================

#[test]
fn round_trip_through_canonical_encoding() {
    let issuer = NexaCoreSigningKey::generate();
    let user = user_node();
    let token = CapabilityToken::mint(&issuer, user, root_inference_scope(), None).expect("mint");

    // Encode the payload + signature via the canonical wire helper
    // (per `NCIP-Serde-004` M2 — `nexacore_types::wire` is the single audit
    // point; direct `postcard::*` calls are forbidden by clippy).
    let encoded = nexacore_types::wire::encode_canonical(&token).expect("serialise token");

    let decoded: CapabilityToken =
        nexacore_types::wire::decode_canonical(&encoded).expect("deserialise token");

    // The decoded token verifies just like the in-memory one.
    decoded
        .verify_signature()
        .expect("decoded signature verifies");
    let attestation = StubAttestation {
        fixed_node_id: user,
    };
    let revocation = RevocationList::new();
    decoded
        .verify_full(5_000, &attestation, &revocation)
        .expect("decoded token verifies fully");

    // And it byte-equals the original (the canonical encoding is
    // deterministic).
    let re_encoded = nexacore_types::wire::encode_canonical(&decoded).expect("re-serialise");
    assert_eq!(encoded, re_encoded);
}
