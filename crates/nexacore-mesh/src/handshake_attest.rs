//! TEE-attestation binding for the mesh handshake (WS6-03.5).
//!
//! This is the concrete logic behind invariant **I3** (mutual TEE attestation):
//! each party proves that its static key is bound to a currently-valid TEE
//! measurement on an allowlisted hardware family. Per spec
//! (`docs/protocol/handshake.md` §3.1/§4.3, invariant I3), the attestation
//! `Quote` is woven into the handshake through two signed fields:
//!
//! - the quote **nonce** equals `H(transcript_so_far)` — so a `Quote` captured
//!   from an earlier session cannot be replayed into this one
//!   ([`attestation_nonce`]); and
//! - the quote **report-data** commits to the attestor's static identity key and
//!   ephemeral, so the measurement proven by the quote is bound to *this* peer's
//!   identity, not merely to some valid TEE ([`attestation_report_data`]).
//!
//! This module follows the "effects behind traits" pattern: it owns the
//! *protocol binding* (nonce derivation, report-data binding, allowlist
//! iteration, fail-closed rejection) but delegates the actual cryptographic
//! quote verification — vendor quote parsing, PCK-chain validation, TCB
//! freshness — to a [`TeeBackend`], so it is host-testable against the mock
//! backend without TEE hardware. No cryptographic primitive is implemented
//! here; the two derivations use the mandated domain-separated BLAKE3
//! ([`nexacore_crypto::hash::domain_separated_hash`]). This module remains
//! subject to the WS10-03 crypto review before production.

use nexacore_crypto::hash::domain_separated_hash;
use nexacore_tee::{
    Measurement, Nonce, Quote,
    traits::{TeeBackend, TeeErrorKind},
};

/// Domain separator for the attestation nonce (`H(transcript_so_far)`, §4.3).
pub const ATTESTATION_NONCE_DOMAIN: &str = "NexaCore-PROTO-v0.2/handshake/attestation-nonce";

/// Domain separator for the report-data that binds the static identity + epk.
pub const ATTESTATION_BINDING_DOMAIN: &str = "NexaCore-PROTO-v0.2/handshake/attestation-binding";

/// Derive the attestation nonce a verifier expects a peer's `Quote` to carry
/// (§4.3): the domain-separated BLAKE3 of the running transcript.
///
/// Binding the nonce to the transcript is what makes the quote non-replayable —
/// a `Quote` produced under a different transcript yields a different nonce and
/// the [`TeeBackend`] rejects it.
#[must_use]
pub fn attestation_nonce(transcript: &[u8; 32]) -> Nonce {
    Nonce(domain_separated_hash(ATTESTATION_NONCE_DOMAIN, transcript))
}

/// Derive the report-data that binds a node's static identity key and ephemeral
/// into its `Quote` (I3): `H(static_id || epk)`.
///
/// The attestor requests this as the quote's `report_data`; the verifier
/// recomputes it from the identity and ephemeral it received and requires an
/// exact match, so the attested measurement is tied to *this* peer's identity.
#[must_use]
pub fn attestation_report_data(static_id: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    let (lo, hi) = buf.split_at_mut(32);
    lo.copy_from_slice(static_id);
    hi.copy_from_slice(epk);
    domain_separated_hash(ATTESTATION_BINDING_DOMAIN, &buf)
}

/// Why a peer's attestation was rejected (I3). The state machine maps every
/// variant onto its terminal `AttestationInvalid` abort — all paths fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    /// The quote uses a non-production TEE family (e.g. the in-process `Mock`),
    /// which a production verifier must reject (§4.3).
    #[error("attestation quote uses a non-production TEE family")]
    NonProductionFamily,

    /// The quote's report-data does not bind the expected static identity and
    /// ephemeral — the attestation is not tied to this peer (I3).
    #[error("attestation report-data does not bind the expected static identity")]
    IdentityBindingMismatch,

    /// No measurement was supplied to check against — fail-closed, trust nothing.
    #[error("no measurement was supplied to check the attestation against")]
    EmptyAllowlist,

    /// The quote verified cryptographically but its measurement is not on the
    /// allowlist supplied by the verifier (§4.3).
    #[error("attestation quote is valid but its measurement is not allowlisted")]
    MeasurementNotAllowlisted,

    /// The [`TeeBackend`] rejected the quote for a non-measurement reason —
    /// bad signature, stale TCB, or a nonce mismatch (replay / wrong transcript).
    #[error("attestation quote failed verification: {0:?}")]
    QuoteInvalid(TeeErrorKind),
}

/// Verify a peer's attestation and bind it to the handshake (I3, §4.3).
///
/// Delegates the cryptographic quote check to `backend`, but owns the protocol
/// binding: the report-data must commit to `expected_static_id`/`expected_epk`,
/// the quote nonce must equal [`attestation_nonce`] of `transcript`, and the
/// attested measurement must appear on `allowlist`. On success the accepted
/// measurement is returned (for the caller to fold into the transcript / I8).
///
/// When `require_production` is set, a non-production family (the `Mock`
/// backend) is rejected outright, matching a production verifier.
///
/// # Errors
///
/// Returns the matching [`AttestationError`] on any failure. Every path is
/// fail-closed: a quote is accepted only when the family, identity binding,
/// nonce, and measurement all check out.
pub fn verify_peer_attestation<B: TeeBackend + ?Sized>(
    backend: &B,
    quote: &Quote,
    transcript: &[u8; 32],
    expected_static_id: &[u8; 32],
    expected_epk: &[u8; 32],
    allowlist: &[Measurement],
    require_production: bool,
) -> Result<Measurement, AttestationError> {
    if require_production && !quote.family.is_production() {
        return Err(AttestationError::NonProductionFamily);
    }

    let expected_report_data = attestation_report_data(expected_static_id, expected_epk);
    if quote.report_data != Some(expected_report_data) {
        return Err(AttestationError::IdentityBindingMismatch);
    }

    if allowlist.is_empty() {
        return Err(AttestationError::EmptyAllowlist);
    }

    let expected_nonce = attestation_nonce(transcript);
    let mut non_measurement_failure: Option<TeeErrorKind> = None;

    for measurement in allowlist {
        match backend.verify_quote(quote, &expected_nonce, measurement) {
            Ok(()) => return Ok(*measurement),
            Err(err) => {
                // A measurement mismatch just means "try the next candidate";
                // anything else (bad nonce/signature/TCB) is a real failure.
                if err.kind != TeeErrorKind::QuoteMeasurementRejected {
                    non_measurement_failure = Some(err.kind);
                }
            }
        }
    }

    non_measurement_failure.map_or(Err(AttestationError::MeasurementNotAllowlisted), |kind| {
        Err(AttestationError::QuoteInvalid(kind))
    })
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use nexacore_tee::{MockTeeBackend, QuoteVersion, traits::TeeFamily};

    use super::*;

    const BACKEND_MEASUREMENT: [u8; 48] = [0xABu8; 48];
    const STATIC_ID: [u8; 32] = [1u8; 32];
    const EPK: [u8; 32] = [2u8; 32];

    fn transcript() -> [u8; 32] {
        [7u8; 32]
    }

    fn m(seed: u8) -> Measurement {
        Measurement([seed; 48])
    }

    /// Build a mock quote bound to `report_data` under `nonce`. The mock's
    /// `attest` cannot fail for a 32-byte report-data; the `Err` arm yields an
    /// obviously-invalid quote so a caller's assertion fails loudly instead of
    /// panicking (which the lints forbid).
    fn bound_quote(backend: &MockTeeBackend, nonce: &Nonce, report_data: &[u8; 32]) -> Quote {
        backend
            .attest(nonce, Some(report_data))
            .unwrap_or_else(|_| Quote {
                version: QuoteVersion::V0_1,
                family: TeeFamily::Mock,
                measurement: Measurement::zero(),
                nonce: *nonce,
                report_data: None,
                body: Vec::new(),
            })
    }

    #[test]
    fn accepts_a_correctly_bound_quote() {
        let backend = MockTeeBackend::with_measurement(Measurement(BACKEND_MEASUREMENT));
        let t = transcript();
        let nonce = attestation_nonce(&t);
        let rd = attestation_report_data(&STATIC_ID, &EPK);
        let quote = bound_quote(&backend, &nonce, &rd);

        let outcome =
            verify_peer_attestation(&backend, &quote, &t, &STATIC_ID, &EPK, &[m(0xAB)], false);
        assert_eq!(outcome, Ok(m(0xAB)));
    }

    #[test]
    fn rejects_a_quote_bound_to_a_different_identity() {
        let backend = MockTeeBackend::with_measurement(Measurement(BACKEND_MEASUREMENT));
        let t = transcript();
        let nonce = attestation_nonce(&t);
        // Quote was bound to a *different* static id than the verifier expects.
        let rd = attestation_report_data(&[9u8; 32], &EPK);
        let quote = bound_quote(&backend, &nonce, &rd);

        let outcome =
            verify_peer_attestation(&backend, &quote, &t, &STATIC_ID, &EPK, &[m(0xAB)], false);
        assert_eq!(outcome, Err(AttestationError::IdentityBindingMismatch));
    }

    #[test]
    fn rejects_a_quote_with_no_report_data() {
        let backend = MockTeeBackend::with_measurement(Measurement(BACKEND_MEASUREMENT));
        let t = transcript();
        let nonce = attestation_nonce(&t);
        let Ok(quote) = backend.attest(&nonce, None) else {
            return;
        };

        let outcome =
            verify_peer_attestation(&backend, &quote, &t, &STATIC_ID, &EPK, &[m(0xAB)], false);
        assert_eq!(outcome, Err(AttestationError::IdentityBindingMismatch));
    }

    #[test]
    fn rejects_a_mock_family_quote_in_production() {
        let backend = MockTeeBackend::with_measurement(Measurement(BACKEND_MEASUREMENT));
        let t = transcript();
        let nonce = attestation_nonce(&t);
        let rd = attestation_report_data(&STATIC_ID, &EPK);
        let quote = bound_quote(&backend, &nonce, &rd);

        // require_production = true → the Mock family is refused before anything.
        let outcome =
            verify_peer_attestation(&backend, &quote, &t, &STATIC_ID, &EPK, &[m(0xAB)], true);
        assert_eq!(outcome, Err(AttestationError::NonProductionFamily));
    }

    #[test]
    fn rejects_when_the_measurement_is_not_allowlisted() {
        let backend = MockTeeBackend::with_measurement(Measurement(BACKEND_MEASUREMENT));
        let t = transcript();
        let nonce = attestation_nonce(&t);
        let rd = attestation_report_data(&STATIC_ID, &EPK);
        let quote = bound_quote(&backend, &nonce, &rd);

        // The quote's measurement (0xAB) is not on this allowlist.
        let outcome =
            verify_peer_attestation(&backend, &quote, &t, &STATIC_ID, &EPK, &[m(0x11)], false);
        assert_eq!(outcome, Err(AttestationError::MeasurementNotAllowlisted));
    }

    #[test]
    fn accepts_when_measurement_is_one_of_several_allowlisted() {
        let backend = MockTeeBackend::with_measurement(Measurement(BACKEND_MEASUREMENT));
        let t = transcript();
        let nonce = attestation_nonce(&t);
        let rd = attestation_report_data(&STATIC_ID, &EPK);
        let quote = bound_quote(&backend, &nonce, &rd);

        // First candidate mismatches, second matches → accepted.
        let outcome = verify_peer_attestation(
            &backend,
            &quote,
            &t,
            &STATIC_ID,
            &EPK,
            &[m(0x11), m(0xAB)],
            false,
        );
        assert_eq!(outcome, Ok(m(0xAB)));
    }

    #[test]
    fn rejects_an_empty_allowlist() {
        let backend = MockTeeBackend::with_measurement(Measurement(BACKEND_MEASUREMENT));
        let t = transcript();
        let nonce = attestation_nonce(&t);
        let rd = attestation_report_data(&STATIC_ID, &EPK);
        let quote = bound_quote(&backend, &nonce, &rd);

        let outcome = verify_peer_attestation(&backend, &quote, &t, &STATIC_ID, &EPK, &[], false);
        assert_eq!(outcome, Err(AttestationError::EmptyAllowlist));
    }

    #[test]
    fn rejects_a_quote_replayed_under_a_different_transcript() {
        let backend = MockTeeBackend::with_measurement(Measurement(BACKEND_MEASUREMENT));
        // Quote produced under transcript T1 (its nonce binds to T1)…
        let t1 = transcript();
        let nonce = attestation_nonce(&t1);
        let rd = attestation_report_data(&STATIC_ID, &EPK);
        let quote = bound_quote(&backend, &nonce, &rd);

        // …but verified under a different transcript T2 → nonce mismatch.
        let t2 = [8u8; 32];
        let outcome =
            verify_peer_attestation(&backend, &quote, &t2, &STATIC_ID, &EPK, &[m(0xAB)], false);
        assert_eq!(
            outcome,
            Err(AttestationError::QuoteInvalid(
                TeeErrorKind::QuoteNonceMismatch
            ))
        );
    }

    #[test]
    fn nonce_and_report_data_are_domain_separated() {
        // The two derivations must not collide even on identical input bytes.
        let same = [3u8; 32];
        let nonce = attestation_nonce(&same);
        let rd = attestation_report_data(&same, &same);
        assert_ne!(nonce.0, rd);
    }
}
