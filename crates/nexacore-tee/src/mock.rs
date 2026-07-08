//! [`MockTeeBackend`] — deterministic, in-process [`TeeBackend`]
//! implementation for tests.
//!
//! Every other crate in the workspace whose code paths touch the TEE
//! exercises them through `MockTeeBackend`. Real hardware backends
//! (TDX, SEV-SNP) are out of CI's reach; the mock keeps the test matrix
//! finite without requiring TEE-capable runners.
//!
//! **Do not enable the `mock` feature in production builds.** The
//! [`TeeBackend::verify_quote`] implementation here intentionally accepts
//! quotes that any real verifier would reject, because the goal is
//! exercising consumer code paths, not asserting attestation integrity.
//!
//! The mock has two operating modes:
//!
//!   - **Default** (`MockTeeBackend::new()`): permissive — accepts any
//!     well-formed quote that names `TeeFamily::Mock` and whose nonce
//!     matches.
//!   - **Strict** (`MockTeeBackend::strict()`): tighter checks for
//!     testing the consumer's failure-handling paths. Rejects quotes
//!     whose `measurement` is not on a configured allowlist.

use alloc::{vec, vec::Vec};

use crate::{
    attestation::{Measurement, Nonce, Quote, QuoteVersion},
    sealed_keys::{SealPolicy, SealedBlob, TeeSharedKey},
    traits::{TeeBackend, TeeError, TeeErrorKind, TeeFamily},
};

// -----------------------------------------------------------------------------
// MockTeeBackend
// -----------------------------------------------------------------------------

/// Deterministic mock backend used by every other crate's tests.
///
/// The mock's measurement is a configurable 48-byte value (default:
/// `[0xAB; 48]`, which is non-zero to satisfy production verifiers that
/// reject the all-zero measurement). The mock's "sealing" is a trivial
/// XOR-with-policy-hash; the test contract is that sealed → unsealed
/// round-trips equal, not that the ciphertext resists attack.
pub struct MockTeeBackend {
    /// The measurement this mock pretends its binary hashes to.
    measurement: Measurement,
    /// Optional allowlist for strict mode. `None` = permissive (default).
    /// `Some(set)` = strict; only quotes whose measurement is in the set
    /// are accepted by `verify_quote`.
    strict_allowlist: Option<Vec<Measurement>>,
}

impl MockTeeBackend {
    /// Creates a permissive mock with measurement `[0xAB; 48]`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            measurement: Measurement([0xABu8; 48]),
            strict_allowlist: None,
        }
    }

    /// Creates a permissive mock with a custom measurement value.
    #[must_use]
    pub const fn with_measurement(measurement: Measurement) -> Self {
        Self {
            measurement,
            strict_allowlist: None,
        }
    }

    /// Creates a strict mock that only accepts quotes whose measurement
    /// appears in `allowlist`.
    #[must_use]
    pub fn strict(measurement: Measurement, allowlist: Vec<Measurement>) -> Self {
        Self {
            measurement,
            strict_allowlist: Some(allowlist),
        }
    }

    /// Returns the measurement this mock advertises.
    #[must_use]
    pub const fn measurement(&self) -> &Measurement {
        &self.measurement
    }
}

impl Default for MockTeeBackend {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// TeeBackend impl
// -----------------------------------------------------------------------------

impl TeeBackend for MockTeeBackend {
    fn family(&self) -> TeeFamily {
        TeeFamily::Mock
    }

    fn attest(&self, nonce: &Nonce, report_data: Option<&[u8]>) -> Result<Quote, TeeError> {
        // Validate the report-data length up front. Real backends would
        // also enforce this; the mock keeps the contract consistent so
        // consumers don't change behaviour based on the backend.
        let report_data_array = match report_data {
            None => None,
            Some(slice) if slice.len() <= 32 => {
                let mut padded = [0u8; 32];
                for (dst, src) in padded.iter_mut().zip(slice.iter()) {
                    *dst = *src;
                }
                Some(padded)
            }
            Some(_) => {
                return Err(TeeError::new(
                    TeeErrorKind::Unsupported,
                    "mock: report_data longer than 32 bytes is unsupported",
                ));
            }
        };

        // The "body" of a mock quote is just a marker prefix plus the
        // nonce and measurement repeated, so a test that wants to assert
        // structural correctness can match on it.
        let mut body = vec![0u8; 0];
        body.extend_from_slice(b"NexaCore-MOCK-TEE-v0.1\n");
        body.extend_from_slice(&self.measurement.0);
        body.extend_from_slice(&nonce.0);
        if let Some(rd) = report_data_array {
            body.extend_from_slice(&rd);
        }

        Ok(Quote {
            version: QuoteVersion::V0_1,
            family: TeeFamily::Mock,
            measurement: self.measurement,
            nonce: *nonce,
            report_data: report_data_array,
            body,
        })
    }

    fn verify_quote(
        &self,
        quote: &Quote,
        expected_nonce: &Nonce,
        expected_measurement: &Measurement,
    ) -> Result<(), TeeError> {
        // Family check — even the mock refuses cross-family quotes so the
        // consumer's family-routing code is exercised.
        if quote.family != TeeFamily::Mock {
            return Err(TeeError::new(
                TeeErrorKind::QuoteSignatureInvalid,
                "mock: refuses non-Mock family quote",
            ));
        }

        // Nonce check.
        if &quote.nonce != expected_nonce {
            return Err(TeeError::new(
                TeeErrorKind::QuoteNonceMismatch,
                "mock: nonce mismatch",
            ));
        }

        // Measurement check.
        if &quote.measurement != expected_measurement {
            return Err(TeeError::new(
                TeeErrorKind::QuoteMeasurementRejected,
                "mock: measurement mismatch with expected",
            ));
        }

        // Strict-mode allowlist check.
        if let Some(allowlist) = &self.strict_allowlist {
            if !allowlist.iter().any(|m| m == &quote.measurement) {
                return Err(TeeError::new(
                    TeeErrorKind::QuoteMeasurementRejected,
                    "mock: measurement not on strict allowlist",
                ));
            }
        }

        // Structural sanity on the body (the mock writes a marker prefix).
        if !quote.body.starts_with(b"NexaCore-MOCK-TEE-v0.1\n") {
            return Err(TeeError::new(
                TeeErrorKind::QuoteSignatureInvalid,
                "mock: body marker prefix missing",
            ));
        }

        Ok(())
    }

    fn seal(&self, plaintext: &[u8], policy: &SealPolicy) -> Result<SealedBlob, TeeError> {
        // Mock sealing: XOR plaintext with a deterministic "key" derived
        // from the policy. NOT cryptographically meaningful; the goal is
        // round-trip integrity for tests.
        if policy.family != TeeFamily::Mock {
            return Err(TeeError::new(
                TeeErrorKind::SealFailed,
                "mock: refuses non-Mock policy.family",
            ));
        }

        let mut ciphertext = plaintext.to_vec();
        for (byte, key_byte) in ciphertext
            .iter_mut()
            .zip(policy.measurement.0.iter().cycle())
        {
            *byte ^= *key_byte;
        }

        Ok(SealedBlob {
            envelope_version: SealedBlob::CURRENT_ENVELOPE_VERSION,
            policy: policy.clone(),
            ciphertext,
        })
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<Vec<u8>, TeeError> {
        if blob.envelope_version != SealedBlob::CURRENT_ENVELOPE_VERSION {
            return Err(TeeError::new(
                TeeErrorKind::UnsealFailed,
                "mock: unsupported envelope version",
            ));
        }
        if !blob.policy.allows(TeeFamily::Mock, &self.measurement) {
            return Err(TeeError::new(
                TeeErrorKind::UnsealFailed,
                "mock: policy does not allow this mock's measurement",
            ));
        }
        let mut plaintext = blob.ciphertext.clone();
        for (byte, key_byte) in plaintext
            .iter_mut()
            .zip(blob.policy.measurement.0.iter().cycle())
        {
            *byte ^= *key_byte;
        }
        Ok(plaintext)
    }

    fn derive_key_for(&self, peer_attestation: &Quote) -> Result<TeeSharedKey, TeeError> {
        if peer_attestation.family != TeeFamily::Mock {
            return Err(TeeError::new(
                TeeErrorKind::KeyDerivationFailed,
                "mock: refuses non-Mock peer family",
            ));
        }
        // Derive a deterministic "shared secret" by XOR-folding the
        // peer's measurement and the local measurement. Sufficient for
        // tests; insufficient for any real cryptographic use.
        let mut bytes = [0u8; 32];
        for ((dst, local), peer) in bytes
            .iter_mut()
            .zip(self.measurement.0.iter())
            .zip(peer_attestation.measurement.0.iter())
        {
            *dst = local ^ peer;
        }
        Ok(TeeSharedKey::from_bytes_internal(bytes))
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

// Test code is allowed to panic on assertion failure: a failed
// `expect`/`unwrap`/index in a test surfaces as the test failure
// itself, which is the desired behaviour. The same allow pattern is
// applied to every test module that asserts on `Result`/`Option`
// shapes.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn attest_then_verify_round_trip_succeeds() {
        let backend = MockTeeBackend::new();
        let nonce = Nonce([0x55u8; 32]);
        let quote = backend.attest(&nonce, None).expect("attest");
        backend
            .verify_quote(&quote, &nonce, backend.measurement())
            .expect("verify");
    }

    #[test]
    fn verify_fails_on_nonce_mismatch() {
        let backend = MockTeeBackend::new();
        let nonce = Nonce([0x55u8; 32]);
        let other = Nonce([0xAAu8; 32]);
        let quote = backend.attest(&nonce, None).expect("attest");
        let err = backend
            .verify_quote(&quote, &other, backend.measurement())
            .expect_err("must reject");
        assert_eq!(err.kind, TeeErrorKind::QuoteNonceMismatch);
    }

    #[test]
    fn verify_fails_on_measurement_mismatch() {
        let backend = MockTeeBackend::new();
        let nonce = Nonce([0x55u8; 32]);
        let quote = backend.attest(&nonce, None).expect("attest");
        let mut wrong = [0u8; 48];
        wrong[0] = 0x99;
        let err = backend
            .verify_quote(&quote, &nonce, &Measurement(wrong))
            .expect_err("must reject");
        assert_eq!(err.kind, TeeErrorKind::QuoteMeasurementRejected);
    }

    #[test]
    fn report_data_round_trips_when_short() {
        let backend = MockTeeBackend::new();
        let nonce = Nonce::zero();
        let data = b"transcript-hash";
        let quote = backend.attest(&nonce, Some(data)).expect("attest");
        let rd = quote.report_data.expect("report data present");
        assert_eq!(&rd[..data.len()], data);
    }

    #[test]
    fn report_data_rejected_when_too_long() {
        let backend = MockTeeBackend::new();
        let nonce = Nonce::zero();
        let data = [0xFFu8; 33]; // one byte over
        let err = backend.attest(&nonce, Some(&data)).expect_err("reject");
        assert_eq!(err.kind, TeeErrorKind::Unsupported);
    }

    #[test]
    fn seal_unseal_round_trip_succeeds() {
        let backend = MockTeeBackend::new();
        let policy = SealPolicy::new(TeeFamily::Mock, *backend.measurement());
        let plaintext = b"hello, sealed world";
        let blob = backend.seal(plaintext, &policy).expect("seal");
        let recovered = backend.unseal(&blob).expect("unseal");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn unseal_fails_on_policy_mismatch() {
        let backend_a = MockTeeBackend::with_measurement(Measurement([1u8; 48]));
        let backend_b = MockTeeBackend::with_measurement(Measurement([2u8; 48]));
        let policy = SealPolicy::new(TeeFamily::Mock, *backend_a.measurement());
        let blob = backend_a.seal(b"hello", &policy).expect("seal");
        let err = backend_b.unseal(&blob).expect_err("must reject");
        assert_eq!(err.kind, TeeErrorKind::UnsealFailed);
    }

    #[test]
    fn strict_mode_rejects_off_allowlist() {
        let backend = MockTeeBackend::strict(
            Measurement([0x11u8; 48]),
            alloc::vec![Measurement([0x22u8; 48])], // does not contain the backend's own measurement
        );
        let nonce = Nonce([0x33u8; 32]);
        let quote = backend.attest(&nonce, None).expect("attest");
        let err = backend
            .verify_quote(&quote, &nonce, backend.measurement())
            .expect_err("must reject");
        assert_eq!(err.kind, TeeErrorKind::QuoteMeasurementRejected);
    }

    #[test]
    fn derive_key_for_self_is_zero() {
        let backend = MockTeeBackend::new();
        let nonce = Nonce::zero();
        let own_quote = backend.attest(&nonce, None).expect("attest");
        let key = backend.derive_key_for(&own_quote).expect("derive");
        // XOR of identical measurements is all-zero.
        assert!(key.as_bytes().iter().all(|b| *b == 0));
    }
}
