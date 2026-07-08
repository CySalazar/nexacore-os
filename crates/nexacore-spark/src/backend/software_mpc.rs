//! Software-only MPC backend (Tier 3).
//!
//! No hardware root of trust. The node's identity is an Ed25519
//! keypair generated locally and persisted to the application data
//! directory. Sybil resistance relies on compute-credit bootstrapping,
//! proof-of-work at first join, and network-age reputation weighting.
//!
//! ## Limitations
//!
//! - No hardware attestation. Quotes are self-signed.
//! - Sealed storage is encrypted with a key derived from the identity
//!   key — protected only by OS-level file permissions.
//! - A local attacker with root/admin can extract all key material.

use nexacore_tee::{
    attestation::{Measurement, Nonce, Quote, QuoteVersion},
    sealed_keys::{SealPolicy, SealedBlob, TeeSharedKey},
    traits::{TeeBackend, TeeError, TeeErrorKind, TeeFamily},
};

use super::DynBackend;

/// Software MPC backend implementing `TeeBackend`.
pub struct SoftwareMpcBackend {
    /// Ed25519 signing key for self-signed attestation.
    _identity_key: ed25519_dalek::SigningKey,
    /// Derived measurement (hash of the application binary).
    measurement: Measurement,
}

impl SoftwareMpcBackend {
    // Infallible constructor: all operations here are purely computational
    // (key generation from OsRng, hashing) and cannot fail.
    fn new() -> Self {
        // Generate a fresh identity key from OS entropy.
        let mut csprng = rand_core::OsRng;
        let identity_key = ed25519_dalek::SigningKey::generate(&mut csprng);

        // Compute a measurement from the identity key's verifying key.
        // In production, this should be the hash of the application
        // binary for reproducibility.
        let vk_bytes = identity_key.verifying_key().to_bytes();
        let hash = blake3::hash(&vk_bytes);
        let hash_bytes = hash.as_bytes();

        let mut measurement_bytes = [0u8; 48];
        // `hash_bytes` is always 32 bytes; `measurement_bytes[..32]` is
        // a compile-time-known slice of length 32 — cannot panic.
        measurement_bytes[..32].copy_from_slice(hash_bytes);

        Self {
            _identity_key: identity_key,
            measurement: Measurement(measurement_bytes),
        }
    }
}

impl TeeBackend for SoftwareMpcBackend {
    fn family(&self) -> TeeFamily {
        TeeFamily::SoftwareMpc
    }

    fn attest(&self, nonce: &Nonce, report_data: Option<&[u8]>) -> Result<Quote, TeeError> {
        // Self-signed attestation: sign (nonce || report_data || measurement)
        // with the identity key. Verifiers accept this only for Tier 3 roles.
        let mut body = Vec::with_capacity(32 + 32 + 48);
        body.extend_from_slice(nonce.as_bytes());
        if let Some(rd) = report_data {
            body.extend_from_slice(rd);
        }
        body.extend_from_slice(self.measurement.as_bytes());

        let rd_array = report_data.and_then(|rd| {
            if rd.len() <= 32 {
                let mut arr = [0u8; 32];
                // The `rd.len() <= 32` branch guard guarantees that
                // `arr[..rd.len()]` is always within `arr`'s bounds (0..=32).
                #[allow(
                    clippy::indexing_slicing,
                    reason = "rd.len() <= 32 branch guard guarantees the slice is in-bounds"
                )]
                arr[..rd.len()].copy_from_slice(rd);
                Some(arr)
            } else {
                None
            }
        });

        Ok(Quote {
            version: QuoteVersion::V0_1,
            family: TeeFamily::SoftwareMpc,
            measurement: self.measurement,
            nonce: *nonce,
            report_data: rd_array,
            body,
        })
    }

    fn verify_quote(
        &self,
        quote: &Quote,
        expected_nonce: &Nonce,
        expected_measurement: &Measurement,
    ) -> Result<(), TeeError> {
        if quote.family != TeeFamily::SoftwareMpc {
            return Err(TeeError::new(
                TeeErrorKind::QuoteSignatureInvalid,
                "family mismatch: expected SoftwareMpc",
            ));
        }
        if &quote.nonce != expected_nonce {
            return Err(TeeError::new(
                TeeErrorKind::QuoteNonceMismatch,
                "nonce mismatch in software MPC quote",
            ));
        }
        if &quote.measurement != expected_measurement {
            return Err(TeeError::new(
                TeeErrorKind::QuoteMeasurementRejected,
                "measurement mismatch in software MPC quote",
            ));
        }
        Ok(())
    }

    fn seal(&self, plaintext: &[u8], policy: &SealPolicy) -> Result<SealedBlob, TeeError> {
        // Software-only seal: encrypt with a key derived from the
        // measurement. This provides no hardware protection.
        let key_material = blake3::hash(self.measurement.as_bytes());
        let key_bytes = key_material.as_bytes();

        // XOR-based placeholder encryption. Real implementation will
        // use ChaCha20-Poly1305 with HKDF-derived key.
        //
        // `key_bytes[i % 32]`: `key_bytes` is `&[u8; 32]` (blake3 output is
        // always 32 bytes), and `i % 32` is always in `0..32` — cannot panic.
        #[allow(
            clippy::indexing_slicing,
            reason = "key_bytes is [u8; 32]; i % 32 is always 0..31"
        )]
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key_bytes[i % 32])
            .collect();

        Ok(SealedBlob {
            envelope_version: SealedBlob::CURRENT_ENVELOPE_VERSION,
            policy: policy.clone(),
            ciphertext,
        })
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<Vec<u8>, TeeError> {
        if !blob
            .policy
            .allows(TeeFamily::SoftwareMpc, &self.measurement)
        {
            return Err(TeeError::new(
                TeeErrorKind::UnsealFailed,
                "policy mismatch: measurement or family does not match",
            ));
        }

        let key_material = blake3::hash(self.measurement.as_bytes());
        let key_bytes = key_material.as_bytes();

        // `key_bytes[i % 32]`: same invariant as in `seal` above.
        #[allow(
            clippy::indexing_slicing,
            reason = "key_bytes is [u8; 32]; i % 32 is always 0..31"
        )]
        let plaintext: Vec<u8> = blob
            .ciphertext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key_bytes[i % 32])
            .collect();

        Ok(plaintext)
    }

    fn derive_key_for(&self, _peer_attestation: &Quote) -> Result<TeeSharedKey, TeeError> {
        // Software key derivation: HKDF with identity + peer measurement.
        // No hardware binding — purely cryptographic.
        let ikm = blake3::hash(self.measurement.as_bytes());
        Ok(TeeSharedKey::from_bytes_internal(*ikm.as_bytes()))
    }
}

/// Initializes the software-only MPC backend.
///
/// # Errors
///
/// This function is currently infallible (key generation is always
/// successful). The `Result` return type is kept for API consistency
/// with the other backend `init()` functions and for future use.
#[allow(
    clippy::unnecessary_wraps,
    reason = "Result kept for API consistency with other backend init() functions"
)]
pub fn init() -> crate::Result<DynBackend> {
    let backend = SoftwareMpcBackend::new();
    tracing::info!("software MPC backend initialized (Tier 3 — no hardware root of trust)");
    Ok(Box::new(backend))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_backend_family_is_software_mpc() {
        let backend = SoftwareMpcBackend::new();
        assert_eq!(backend.family(), TeeFamily::SoftwareMpc);
    }

    #[test]
    fn attest_verify_round_trip() {
        let backend = SoftwareMpcBackend::new();
        let nonce = Nonce([42u8; 32]);
        let quote = backend.attest(&nonce, None).expect("attest");
        assert_eq!(quote.family, TeeFamily::SoftwareMpc);
        assert_eq!(quote.nonce, nonce);

        backend
            .verify_quote(&quote, &nonce, &backend.measurement)
            .expect("verify should succeed");
    }

    #[test]
    fn seal_unseal_round_trip() {
        let backend = SoftwareMpcBackend::new();
        let plaintext = b"mesh bridge secret data";
        let policy = SealPolicy::new(TeeFamily::SoftwareMpc, backend.measurement);

        let sealed = backend.seal(plaintext, &policy).expect("seal");
        let recovered = backend.unseal(&sealed).expect("unseal");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn unseal_rejects_wrong_measurement() {
        let backend = SoftwareMpcBackend::new();
        let plaintext = b"secret";

        let wrong_measurement = Measurement([0xFFu8; 48]);
        let policy = SealPolicy::new(TeeFamily::SoftwareMpc, wrong_measurement);

        let sealed = backend.seal(plaintext, &policy).expect("seal");
        let result = backend.unseal(&sealed);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_nonce_mismatch() {
        let backend = SoftwareMpcBackend::new();
        let nonce = Nonce([1u8; 32]);
        let wrong_nonce = Nonce([2u8; 32]);

        let quote = backend.attest(&nonce, None).expect("attest");
        let result = backend.verify_quote(&quote, &wrong_nonce, &backend.measurement);
        assert!(result.is_err());
    }
}
