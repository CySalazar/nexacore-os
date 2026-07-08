//! Integration tests for [`nexacore_tee::MockTeeBackend`].
//!
//! These tests exercise the full attest → verify → seal → unseal →
//! `derive_key_for` flow end-to-end, simulating the typical
//! mesh-handshake shape from the consumer's perspective (`nexacore-mesh`
//! will replicate this pattern with a real backend in P4).

#![cfg(feature = "mock")]
// Integration-test code is allowed to panic on assertion failure: a
// failed `expect`/`unwrap`/index in a test surfaces as the test
// failure itself, which is the desired behaviour. `similar_names` is
// silenced because the two-actor handshake naming convention
// (alice/bob/blob) is more readable than longer, distinct names.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names
)]

use nexacore_tee::{
    Measurement, MockTeeBackend, Nonce, SealPolicy, TeeBackend, TeeErrorKind, TeeFamily,
};

#[test]
fn end_to_end_mock_handshake_simulation() {
    // Simulate two parties (`alice` and `bob`), each with their own mock
    // TEE running at a distinct measurement.
    let alice_measurement = Measurement([0x11u8; 48]);
    let bob_measurement = Measurement([0x22u8; 48]);
    let alice = MockTeeBackend::with_measurement(alice_measurement);
    let bob = MockTeeBackend::with_measurement(bob_measurement);

    // Alice sends a fresh nonce to Bob.
    let nonce_a_to_b = Nonce([0xA1u8; 32]);
    // Bob attests using Alice's nonce.
    let bob_quote = bob
        .attest(&nonce_a_to_b, Some(b"transcript-hash-1"))
        .unwrap();

    // Alice verifies Bob's quote, expecting Bob's known measurement.
    alice
        .verify_quote(&bob_quote, &nonce_a_to_b, &bob_measurement)
        .unwrap();

    // Symmetric direction: Bob sends a fresh nonce to Alice.
    let nonce_b_to_a = Nonce([0xB1u8; 32]);
    let alice_quote = alice.attest(&nonce_b_to_a, None).unwrap();
    bob.verify_quote(&alice_quote, &nonce_b_to_a, &alice_measurement)
        .unwrap();

    // Both sides derive a TEE-bound shared key from the peer's quote.
    // Per the XOR-fold mock impl, both sides must compute the same key
    // (XOR is commutative). The real impl will be HKDF over an attested
    // local secret + peer measurement, also symmetric.
    let key_a = alice.derive_key_for(&bob_quote).unwrap();
    let key_b = bob.derive_key_for(&alice_quote).unwrap();
    assert_eq!(key_a.as_bytes(), key_b.as_bytes());

    // The derived key is non-trivial — it depends on both measurements.
    assert!(!key_a.as_bytes().iter().all(|b| *b == 0));

    // Sealing under Alice's measurement, unsealing on Alice succeeds,
    // unsealing on Bob fails.
    let policy = SealPolicy::new(TeeFamily::Mock, alice_measurement);
    let blob = alice.seal(b"user secret payload", &policy).unwrap();
    let recovered = alice.unseal(&blob).unwrap();
    assert_eq!(recovered, b"user secret payload");
    assert_eq!(
        bob.unseal(&blob).unwrap_err().kind,
        TeeErrorKind::UnsealFailed
    );
}

#[test]
fn tampered_quote_is_rejected() {
    let backend = MockTeeBackend::new();
    let nonce = Nonce([0xCDu8; 32]);
    let mut quote = backend.attest(&nonce, None).unwrap();

    // Flip a bit in the body. The mock detects this via the marker-prefix
    // check (any tampering that doesn't preserve the marker is caught).
    quote.body[0] ^= 0x01;

    assert_eq!(
        backend
            .verify_quote(&quote, &nonce, backend.measurement())
            .unwrap_err()
            .kind,
        TeeErrorKind::QuoteSignatureInvalid
    );
}

#[test]
fn replayed_quote_rejected_via_nonce() {
    let backend = MockTeeBackend::new();
    let session_one_nonce = Nonce([0x01u8; 32]);
    let quote = backend.attest(&session_one_nonce, None).unwrap();

    // A later session uses a different nonce. Replaying the old quote
    // is detected at verification time.
    let session_two_nonce = Nonce([0x02u8; 32]);
    assert_eq!(
        backend
            .verify_quote(&quote, &session_two_nonce, backend.measurement())
            .unwrap_err()
            .kind,
        TeeErrorKind::QuoteNonceMismatch
    );
}

#[test]
fn cross_family_quote_rejected() {
    let backend = MockTeeBackend::new();
    let nonce = Nonce::zero();
    let mut quote = backend.attest(&nonce, None).unwrap();

    // Falsely claim TDX family on a quote produced by the Mock.
    quote.family = TeeFamily::IntelTdx;

    assert_eq!(
        backend
            .verify_quote(&quote, &nonce, backend.measurement())
            .unwrap_err()
            .kind,
        TeeErrorKind::QuoteSignatureInvalid
    );
}

// =============================================================================
// NCIP-Serde-004 M4 — postcard wire-format round-trip tests for Quote
// and SealedBlob via the canonical wire helper.
// =============================================================================
//
// These tests sit in the public integration-test surface (not under
// `#[cfg(test)]` inside src/) so they exercise the exact path a future
// `nexacore-mesh` consumer will use: encode a TEE artefact to bytes via
// `nexacore_types::wire::encode_canonical`, ship the bytes, decode via
// `nexacore_types::wire::decode_canonical`. Determinism and trailing-byte
// rejection are the two security-relevant properties.

#[test]
fn quote_round_trip_via_wire_helper_preserves_all_fields() {
    let backend = MockTeeBackend::with_measurement(Measurement([0x77u8; 48]));
    let nonce = Nonce([0x33u8; 32]);
    let quote = backend.attest(&nonce, Some(b"transcript-binding")).unwrap();

    let bytes = nexacore_types::wire::encode_canonical(&quote).expect("encode quote");
    let decoded: nexacore_tee::Quote =
        nexacore_types::wire::decode_canonical(&bytes).expect("decode quote");

    // Every public field must survive the round-trip byte-identically.
    assert_eq!(decoded.version, quote.version);
    assert_eq!(decoded.family, quote.family);
    assert_eq!(decoded.measurement, quote.measurement);
    assert_eq!(decoded.nonce, quote.nonce);
    assert_eq!(decoded.report_data, quote.report_data);
    assert_eq!(decoded.body, quote.body);

    // And the decoded quote still verifies. (This is the property a
    // remote verifier on the mesh relies on after receiving bytes from
    // a peer.)
    backend
        .verify_quote(&decoded, &nonce, backend.measurement())
        .expect("decoded quote verifies");
}

#[test]
fn quote_round_trip_is_byte_deterministic() {
    // Two encodes of the same quote MUST produce byte-identical
    // outputs. Without this, a signature pre-image computed by a peer
    // could diverge from the locally-computed one.
    let backend = MockTeeBackend::with_measurement(Measurement([0x66u8; 48]));
    let nonce = Nonce([0x99u8; 32]);
    let quote = backend.attest(&nonce, None).unwrap();
    let a = nexacore_types::wire::encode_canonical(&quote).expect("encode-a");
    let b = nexacore_types::wire::encode_canonical(&quote).expect("encode-b");
    assert_eq!(a, b);
}

#[test]
fn quote_decode_rejects_trailing_bytes() {
    let backend = MockTeeBackend::new();
    let nonce = Nonce([0xEEu8; 32]);
    let quote = backend.attest(&nonce, None).unwrap();
    let mut bytes = nexacore_types::wire::encode_canonical(&quote).expect("encode quote");
    bytes.push(0xFF);
    let result: nexacore_types::error::Result<nexacore_tee::Quote> =
        nexacore_types::wire::decode_canonical(&bytes);
    assert!(result.is_err(), "quote decode must reject trailing bytes");
}

#[test]
fn sealed_blob_round_trip_via_wire_helper() {
    let backend = MockTeeBackend::with_measurement(Measurement([0x55u8; 48]));
    let policy = SealPolicy::new(TeeFamily::Mock, *backend.measurement());
    let plaintext = b"NCIP-Serde-004 M4 round-trip integrity";
    let blob = backend.seal(plaintext, &policy).expect("seal");

    let encoded = nexacore_types::wire::encode_canonical(&blob).expect("encode blob");
    let decoded: nexacore_tee::SealedBlob =
        nexacore_types::wire::decode_canonical(&encoded).expect("decode blob");

    // The decoded blob unseals to the original plaintext under the same
    // backend (i.e., the SealedBlob round-trip is faithful end-to-end).
    let recovered = backend.unseal(&decoded).expect("unseal decoded");
    assert_eq!(recovered, plaintext);
}

#[test]
fn protocol_version_v0_2_constant_is_negotiable() {
    // Sanity check that the M4-introduced ProtocolVersion::V0_2
    // constant is wired up correctly. Belongs here (vs in nexacore-types)
    // because this is the consumer-facing integration suite that the
    // future `nexacore-mesh` handshake will mirror.
    use nexacore_types::version::{PROTOCOL_VERSION_V0_1, PROTOCOL_VERSION_V0_2};
    assert!(PROTOCOL_VERSION_V0_2 > PROTOCOL_VERSION_V0_1);
    assert!(PROTOCOL_VERSION_V0_2.is_compatible_with(PROTOCOL_VERSION_V0_1));
    assert!(!PROTOCOL_VERSION_V0_1.is_compatible_with(PROTOCOL_VERSION_V0_2));
}
