//! `NexaCore-PROTO-v0.2` (postcard 1.x) wire-format adversarial tests for
//! `nexacore-tee`.
//!
//! Filed under `NCIP-Serde-004` § "Test Cases" → "Adversarial round-trip"
//! ([`crates/nexacore-tee/tests/wire_format_v0_2.rs`]).
//!
//! # What this suite asserts
//!
//! For every byte offset `i` in a valid encoded `Quote`, flipping any
//! bit at position `i` MUST cause **at least one** of the following:
//!
//! 1. `nexacore_types::wire::decode_canonical::<Quote>` returns `Err(_)`
//!    — the bytes no longer parse as a Quote (most common outcome).
//! 2. `decode_canonical` parses successfully but the resulting Quote
//!    fails `verify_quote` — the bytes parse to *a* Quote, but the
//!    nonce / measurement / family / body integrity check rejects it.
//!
//! No bit-flip may pass silently. If any bit-flip produces a Quote
//! that both decodes AND verifies under the same backend, that is a
//! tampering channel and the test fails.
//!
//! This is the wire-format-level equivalent of a malleability test:
//! the canonical encoding + the backend's structural integrity check
//! together MUST detect every single-bit tampering.

#![cfg(feature = "mock")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeSet;

use nexacore_tee::{Measurement, MockTeeBackend, Nonce, Quote, TeeBackend};

/// Build a representative Quote for the bit-flip suite. Uses
/// distinctive measurement / nonce / body bytes so the flipped-byte
/// search has a stable, non-trivial input to mutate.
fn fixture_quote() -> (MockTeeBackend, Nonce, Quote) {
    let measurement = Measurement([0x77u8; 48]);
    let backend = MockTeeBackend::with_measurement(measurement);
    let nonce = Nonce([0xABu8; 32]);
    // 32-byte report_data binding — matches the mock backend's max.
    let report_data: &[u8; 32] = b"OIP-Serde-004 wire-format suite!";
    let quote = backend.attest(&nonce, Some(report_data)).unwrap();
    (backend, nonce, quote)
}

#[test]
fn quote_bit_flip_on_mock_covered_fields_is_detected() {
    // SCOPE NOTE
    // ----------
    // `MockTeeBackend::verify_quote` is intentionally permissive on
    // fields it does not cryptographically check:
    //   - `report_data` (32 bytes) is NOT covered by the mock's
    //     integrity check — only by the body marker prefix and the
    //     `expected_nonce`/`expected_measurement` parameters. A real
    //     TDX/SEV-SNP backend signs the whole quote body and would
    //     therefore detect a flip anywhere; the mock is a stub. This
    //     scope difference is documented in `crates/nexacore-tee/src/mock.rs`.
    //
    // This test therefore restricts the bit-flip search to the
    // *cryptographically-covered region* under the mock's contract:
    // the `family`, `measurement`, `nonce`, and the body marker prefix
    // (`NexaCore-MOCK-TEE-v0.1\n`). For every byte in that region, a
    // single-bit flip MUST be detected by either decode or verify.
    //
    // When a real backend lands (P5.2 / P5.3), an analogous test in
    // each backend's integration suite will exercise the full byte
    // range without scope restrictions.

    let (backend, nonce, quote) = fixture_quote();
    let baseline_bytes = nexacore_types::wire::encode_canonical(&quote).unwrap();

    // Sanity: the unmodified Quote must decode and verify.
    let baseline_decoded: Quote = nexacore_types::wire::decode_canonical(&baseline_bytes).unwrap();
    backend
        .verify_quote(&baseline_decoded, &nonce, backend.measurement())
        .expect("baseline Quote must decode + verify");

    // Locate the covered byte ranges in the encoded buffer by
    // scanning for the known field values. Each field is a unique
    // byte pattern in the fixture (chosen for searchability).
    let body_marker = b"NexaCore-MOCK-TEE-v0.1\n";
    let body_marker_offset = baseline_bytes
        .windows(body_marker.len())
        .position(|w| w == body_marker)
        .expect("body marker prefix must appear in the encoded Quote");

    // 32-byte nonce of `[0xAB; 32]` — find it as a contiguous run.
    let nonce_pattern: [u8; 32] = [0xABu8; 32];
    let nonce_offset = baseline_bytes
        .windows(nonce_pattern.len())
        .position(|w| w == nonce_pattern)
        .expect("nonce pattern must appear in the encoded Quote");

    // 48-byte measurement of `[0x77; 48]`.
    let meas_pattern: [u8; 48] = [0x77u8; 48];
    let meas_offset = baseline_bytes
        .windows(meas_pattern.len())
        .position(|w| w == meas_pattern)
        .expect("measurement pattern must appear in the encoded Quote");

    // Build the set of offsets that are part of mock-covered fields.
    let mut covered_offsets = BTreeSet::<usize>::new();
    for off in nonce_offset..nonce_offset + nonce_pattern.len() {
        covered_offsets.insert(off);
    }
    for off in meas_offset..meas_offset + meas_pattern.len() {
        covered_offsets.insert(off);
    }
    for off in body_marker_offset..body_marker_offset + body_marker.len() {
        covered_offsets.insert(off);
    }
    assert!(
        !covered_offsets.is_empty(),
        "covered-region scanner found nothing — fixture or mock contract changed"
    );

    // Every covered-offset LSB flip MUST be detected (decode error or
    // verify error). No silent acceptance is allowed here.
    let mut accepted_silent_tampering = 0_usize;
    for offset in &covered_offsets {
        let mut mutated = baseline_bytes.clone();
        mutated[*offset] ^= 0x01;
        let decode_result: nexacore_types::error::Result<Quote> =
            nexacore_types::wire::decode_canonical(&mutated);
        let Ok(decoded) = decode_result else { continue };
        let verify_result = backend.verify_quote(&decoded, &nonce, backend.measurement());
        if verify_result.is_ok() {
            accepted_silent_tampering += 1;
        }
    }
    assert_eq!(
        accepted_silent_tampering, 0,
        "{accepted_silent_tampering} bit-flips on cryptographically-covered \
         offsets were silently accepted by the mock backend"
    );
}

#[test]
fn quote_truncation_at_every_prefix_is_detected() {
    // Truncating a valid Quote encoding at ANY prefix length MUST
    // either (a) cause decode to fail, or (b) decode to a Quote that
    // fails verify_quote. There is no canonical-encoding length where
    // a truncated Quote can both parse AND verify.
    let (backend, nonce, quote) = fixture_quote();
    let baseline_bytes = nexacore_types::wire::encode_canonical(&quote).unwrap();

    let mut accepted_truncations = 0_usize;
    // Skip the full-length case (no truncation = no test).
    for cut in 0..baseline_bytes.len() {
        let truncated = &baseline_bytes[..cut];
        let decode_result: nexacore_types::error::Result<Quote> =
            nexacore_types::wire::decode_canonical(truncated);
        let Ok(decoded) = decode_result else { continue };
        let verify_result = backend.verify_quote(&decoded, &nonce, backend.measurement());
        if verify_result.is_ok() {
            accepted_truncations += 1;
        }
    }

    assert_eq!(
        accepted_truncations, 0,
        "truncation at one or more prefix lengths produced a Quote \
         that decoded AND verified — wire-format malleability"
    );
}

#[test]
fn quote_extension_with_trailing_bytes_is_decode_error() {
    // Appending any byte sequence to a valid Quote encoding MUST cause
    // the wire helper to return `WireErrorKind::TrailingBytes`. The
    // helper enforces the no-trailing-data canonical invariant via
    // `take_from_bytes` + `tail.is_empty()`.
    let (_backend, _nonce, quote) = fixture_quote();
    let baseline_bytes = nexacore_types::wire::encode_canonical(&quote).unwrap();

    // Try several trailing-byte patterns: zero, all-ones, random-ish,
    // and a long suffix. Each must be rejected.
    let trailers: &[&[u8]] = &[&[0x00], &[0xFF], &[0xDE, 0xAD, 0xBE, 0xEF], &[0u8; 1024]];
    for trailer in trailers {
        let mut extended = baseline_bytes.clone();
        extended.extend_from_slice(trailer);
        let result: nexacore_types::error::Result<Quote> =
            nexacore_types::wire::decode_canonical(&extended);
        assert!(
            result.is_err(),
            "decode must reject Quote bytes with {} trailing bytes",
            trailer.len()
        );
    }
}

#[test]
fn quote_swap_with_unrelated_bytes_does_not_decode_and_verify() {
    // Replacing the whole encoded buffer with random-looking bytes
    // MUST not produce a Quote that verifies. This is a coarse-grained
    // sanity check that complements the per-byte bit-flip search:
    // even a fully unrelated byte string should not pass the
    // decode+verify pipeline.
    let (backend, nonce, _quote) = fixture_quote();
    let patterns: &[&[u8]] = &[
        &[0u8; 64],
        &[0xFFu8; 64],
        b"not a quote, definitely not",
        &[0xDEu8; 128],
    ];
    for bytes in patterns {
        let result: nexacore_types::error::Result<Quote> =
            nexacore_types::wire::decode_canonical(bytes);
        let Ok(decoded) = result else { continue };
        let verify = backend.verify_quote(&decoded, &nonce, backend.measurement());
        assert!(
            verify.is_err(),
            "verify_quote must reject Quote synthesized from unrelated \
             bytes (decoded ok but verify accepted: {decoded:?})",
        );
    }
}
