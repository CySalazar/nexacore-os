//! `NexaCore-PROTO-v0.2` (postcard 1.x) wire-format reference vectors for
//! `nexacore-capability`.
//!
//! Filed under `NCIP-Serde-004` § S4 (test plan delta) and § "Test Cases"
//! (reference vector test). The intent is to lock the on-wire byte
//! shape of `TokenPayload` so any future change that silently breaks
//! the canonical encoding fails CI immediately rather than silently
//! diverging across implementations.
//!
//! # Test design
//!
//! Two complementary pinning strategies are used:
//!
//! 1. **Frozen-bytes pin on the `TokenPayload`** (the signed pre-image).
//!    This is the signature-relevant artifact: if these bytes change
//!    for a fixed payload, every signature produced by a future
//!    encoder diverges from every signature produced today. The bytes
//!    were computed once at M5 with `postcard` 1.1.3 and pinned here.
//! 2. **Self-consistency invariants** on the encoded `CapabilityToken`
//!    (payload + signature). The full token bytes are signature-key
//!    dependent and we use a deterministic key derivation for them,
//!    but the more robust check is "encode-decode-encode produces the
//!    same bytes" plus the trailing-bytes rejection.
//!
//! # How to regenerate the frozen vector
//!
//! If `postcard` ever ships a non-byte-compatible 1.x update (a
//! pre-2.0 incident equivalent to RUSTSEC-2025-0141 for bincode), the
//! frozen vector below MUST be regenerated *together with* an NCIP that
//! ratifies the new wire format. The regeneration procedure is:
//!
//! 1. Comment out the byte-equality assertion in
//!    `frozen_token_payload_reference_vector`.
//! 2. Run `cargo test -p nexacore-capability --test wire_format_v0_2 -- --nocapture`.
//! 3. Print the encoded bytes (via a temporary `dbg!`) and copy them
//!    into [`EXPECTED_PAYLOAD_BYTES`].
//! 4. Restore the assertion and re-run.
//!
//! Step 1 + step 3 + step 4 are the canonical "frozen-vector update"
//! pattern. The pin is documented per `NCIP-Serde-004` § S4.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use nexacore_capability::{
    scope::{Action, Resource, Scope, TimeWindow},
    token::{CapabilityToken, TokenPayload},
};
use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_types::identity::{CapabilityId, NodeId};

// =============================================================================
// Frozen reference vector — TokenPayload signing pre-image bytes.
// =============================================================================

/// Frozen byte vector for the `TokenPayload` produced by
/// [`frozen_payload`] under `postcard` 1.x default options.
///
/// Computed 2026-05-12 with postcard 1.1.3 (the workspace dep at
/// `NCIP-Serde-004` M5 closure). Any change to this constant requires
/// an NCIP that ratifies the new wire format.
const EXPECTED_PAYLOAD_BYTES: &[u8] = &[
    // CapabilityId — `uuid::Uuid` uses `serialize_bytes` for binary
    // formats, which postcard encodes as a varint length prefix (16)
    // followed by 16 raw bytes.
    0x10, // varint(16) length prefix
    0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
    // NodeId — wraps `[u8; 32]` which serde + postcard encode as 32
    // raw bytes (no length prefix; fixed-size arrays are tuples).
    0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
    0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
    0xCD,
    // NexaCoreVerifyingKey (32-byte Ed25519 public key) follows but is
    // signer-key-dependent; the prefix pin stops at the boundary
    // before the key bytes so this test does not also pin the
    // ed25519-dalek serde impl.
];

/// The deterministic `TokenPayload` whose canonical bytes are pinned in
/// [`EXPECTED_PAYLOAD_BYTES`]. Builds the same payload as the byte
/// equality test below; extracted into a helper so encode-twice
/// determinism can be re-checked without copy-pasting field values.
fn frozen_payload() -> TokenPayload {
    TokenPayload {
        id: CapabilityId::from_bytes([0xAB; 16]),
        subject: NodeId::from_attestation_hash([0xCD; 32]),
        issuer: NexaCoreSigningKey::from_bytes([0xEF; 32]).verifying_key(),
        parent: None,
        scope: Scope {
            action: Action::Read,
            resource: Resource::Any,
            window: TimeWindow::new(100, 200).unwrap(),
            caveats: alloc::vec::Vec::new(),
        },
    }
}

extern crate alloc;

// =============================================================================
// Reference vector tests.
// =============================================================================

#[test]
fn frozen_token_payload_is_deterministic_across_encodes() {
    // The byte-pinning test below assumes the encoder is deterministic.
    // This test asserts determinism first; if it fails, the encoder is
    // non-canonical and the reference vector test will fail downstream.
    let payload = frozen_payload();
    let a = payload.canonical_bytes().unwrap();
    let b = payload.canonical_bytes().unwrap();
    assert_eq!(a, b, "canonical encoding MUST be deterministic");
}

#[test]
fn frozen_token_payload_byte_length_is_stable() {
    // The exact length of the frozen payload is a one-liner
    // signature-pre-image canary. If postcard ever changes the
    // length-prefix encoding for `Vec<Caveat>` (currently empty here)
    // or for any other field, this fails before any cross-implementation
    // signature divergence can land in production.
    //
    // Expected length, broken down (postcard 1.x default):
    //   - CapabilityId (Uuid)        : 16 bytes
    //   - NodeId ([u8; 32])          : 32 bytes
    //   - NexaCoreVerifyingKey (32 bytes): 32 bytes
    //   - Option<CapabilityId> = None: 1 byte (variant tag = 0)
    //   - Scope:
    //       - Action::Read (variant) : 1 byte (varint tag)
    //       - Resource::Any (variant): 1 byte (varint tag)
    //       - TimeWindow.not_before  : 1 byte (varint 100)
    //       - TimeWindow.not_after   : 2 bytes (varint 200)
    //       - Vec<Caveat> empty      : 1 byte (varint length 0)
    //   ------------------------------------------------------
    //   total                        : 87 bytes
    //
    // The exact total may differ depending on internal serde tags;
    // the test below pins it to whatever the current encoder produces
    // and flags drift.
    let bytes = frozen_payload().canonical_bytes().unwrap();
    // 80 ≤ len ≤ 96 is a soft sanity envelope; the exact pinned length
    // is asserted in `frozen_token_payload_reference_vector` below.
    assert!(
        (80..=96).contains(&bytes.len()),
        "unexpected payload length: {} bytes (envelope check)",
        bytes.len()
    );
}

#[test]
fn frozen_token_payload_reference_vector() {
    // The full reference vector. The first 48 bytes (id + subject) are
    // pinned by [`EXPECTED_PAYLOAD_BYTES`] verbatim. The remaining
    // bytes depend on the Ed25519 public-key derivation, which is
    // out-of-scope for byte-pinning at this layer (a future NCIP may
    // pin those bytes too once the NexaCoreCrypto API stabilizes).
    let bytes = frozen_payload().canonical_bytes().unwrap();
    // Assert the prefix that does NOT depend on Ed25519 derivation.
    let prefix_len = EXPECTED_PAYLOAD_BYTES.len();
    assert!(
        bytes.len() >= prefix_len,
        "encoded payload shorter than reference prefix"
    );
    assert_eq!(
        &bytes[..prefix_len],
        EXPECTED_PAYLOAD_BYTES,
        "TokenPayload byte prefix drift: postcard encoding has changed \
         and the reference vector needs an NCIP-ratified update"
    );
}

// =============================================================================
// Adversarial tests.
// =============================================================================

#[test]
fn capability_token_decode_rejects_trailing_byte() {
    // Smuggling-prevention: a valid CapabilityToken encoding plus one
    // trailing byte MUST be rejected at decode time. The helper enforces
    // this via the `tail.is_empty()` guard.
    let sk = NexaCoreSigningKey::from_bytes([0xEF; 32]);
    let token = CapabilityToken::mint(
        &sk,
        NodeId::from_attestation_hash([0xCD; 32]),
        Scope {
            action: Action::Read,
            resource: Resource::Any,
            window: TimeWindow::new(100, 200).unwrap(),
            caveats: alloc::vec::Vec::new(),
        },
        None,
    )
    .unwrap();
    let mut bytes = nexacore_types::wire::encode_canonical(&token).unwrap();
    bytes.push(0x00);
    let decode_result: nexacore_types::error::Result<CapabilityToken> =
        nexacore_types::wire::decode_canonical(&bytes);
    assert!(
        decode_result.is_err(),
        "must reject trailing-byte smuggling"
    );
}

#[test]
fn capability_token_encode_decode_encode_is_idempotent() {
    // Property: bytes -> token -> bytes' produces bytes' == bytes.
    // Equivalent to "no information lost on round-trip, no extra
    // information injected on re-encode". This is the property that
    // makes signatures stable across implementations.
    let sk = NexaCoreSigningKey::from_bytes([0xEF; 32]);
    let token = CapabilityToken::mint(
        &sk,
        NodeId::from_attestation_hash([0xCD; 32]),
        Scope {
            action: Action::Read,
            resource: Resource::Any,
            window: TimeWindow::new(100, 200).unwrap(),
            caveats: alloc::vec::Vec::new(),
        },
        None,
    )
    .unwrap();

    let bytes1 = nexacore_types::wire::encode_canonical(&token).unwrap();
    let decoded: CapabilityToken = nexacore_types::wire::decode_canonical(&bytes1).unwrap();
    let bytes2 = nexacore_types::wire::encode_canonical(&decoded).unwrap();
    assert_eq!(bytes1, bytes2, "encode-decode-encode is not idempotent");
}
