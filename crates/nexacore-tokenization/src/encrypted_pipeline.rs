//! Encrypted-by-default pipeline integration.
//!
//! This module bridges the tokenization pipeline with the encrypted-by-default
//! type system from `nexacore-types`. Every string that passes through the
//! [`EncryptedPipeline`] exits as one of the sealed marker types
//! ([`EncryptedString`], [`TokenizedEmail`], [`MaskedSSN`], [`AttestedHash`])
//! that carry a real `ChaCha20-Poly1305` AEAD ciphertext.
//!
//! # Architecture
//!
//! ```text
//! EncryptedPipeline
//!   ├── TokenizationService     — NER + policy + vault (existing)
//!   ├── encryption_key: [u8;32] — TEE-sealed 256-bit key
//!   └── nonce_counter: u64      — monotonic counter, 8 low bytes of nonce
//! ```
//!
//! The pipeline is the **only** caller of the `_tokenization_provider`-gated
//! `encrypt`/`decrypt` methods on the marker types. Callers outside this module
//! receive opaque encrypted values and cannot recover plaintext without the key.
//!
//! # Nonce strategy
//!
//! Nonces are 12 bytes wide. The counter occupies the low 8 bytes
//! (little-endian `u64`) and the high 4 bytes remain zero. A `u64` counter
//! can produce 2^64 nonces before overflow — orders of magnitude more than a
//! single pipeline instance would ever consume. The counter panics on overflow
//! to prevent nonce reuse (same rationale as `nexacore_crypto::aead::NonceCounter`).
//!
//! # Security notes
//!
//! - The `encryption_key` MUST be TEE-sealed before use in production. In the
//!   test suite it is supplied as a fixed all-zero/all-one array.
//! - The pipeline does NOT automatically rotate the key. The caller (the TEE
//!   runtime service) is responsible for key lifecycle.
//! - `process_text` produces an [`AttestedHash`] that binds the tokenized text
//!   to the live TEE measurement. This provides post-hoc verifiability: any
//!   party with the TEE measurement can confirm that the encrypted output was
//!   produced inside the trusted enclave.
//!
//! See [`/docs/04-security-model.md`](../../../docs/04-security-model.md)
//! § "Tokenization service — encrypted pipeline".

use std::sync::Arc;

use nexacore_crypto::hash::{Blake3, NexaCoreHash};
use nexacore_tee::{Nonce as TeeNonce, TeeBackend, TeeErrorKind};
use nexacore_types::{
    encrypted::{AttestedHash, EncryptedString, MaskedSSN, TokenizedEmail},
    error::{NexaCoreError, Result, TeeErrorKind as NexaCoreTeeErrorKind},
};
use tracing::instrument;

use crate::{TokenizationService, policy::PolicyPreset, types::EntityType, vault::TokenVault};

// =============================================================================
// Public result types
// =============================================================================

/// A single PII replacement in encrypted form.
///
/// Produced by [`EncryptedPipeline::process_text`] for each PII span that was
/// detected and tokenized. The original span coordinates refer to byte offsets
/// in the **original** (pre-tokenization) text.
#[derive(Debug, Clone)]
pub struct EncryptedReplacement {
    /// Byte offsets `(start, end)` of the PII span in the **original** text.
    /// Half-open: `text[start..end]` was the replaced substring.
    pub span: (usize, usize),
    /// The PII value (after NER classification and tokenization) encrypted as
    /// an [`EncryptedString`].
    pub encrypted_value: EncryptedString,
    /// The semantic category of the replaced span.
    pub entity_type: EntityType,
}

/// Result of a full-pipeline text processing operation.
///
/// Contains the encrypted form of the tokenized text, one
/// [`EncryptedReplacement`] per detected-and-tokenized PII span, and an
/// [`AttestedHash`] binding the output to the live TEE measurement.
#[derive(Debug)]
pub struct ProcessedText {
    /// The complete tokenized text (PII spans replaced by opaque tokens)
    /// encrypted as an [`EncryptedString`].
    pub encrypted_text: EncryptedString,
    /// Per-span replacement manifest. One entry per tokenized PII span,
    /// sorted by `span.0` ascending.
    pub replacements: Vec<EncryptedReplacement>,
    /// BLAKE3 hash of the tokenized text bound to the TEE attestation that
    /// witnessed this processing operation.
    pub attested_hash: AttestedHash,
}

// =============================================================================
// EncryptedPipeline
// =============================================================================

/// Tokenization + encryption pipeline for NexaCore OS.
///
/// Wraps a [`TokenizationService`] and adds real `ChaCha20-Poly1305`
/// encryption. Every value that exits this pipeline is one of the sealed
/// `nexacore-types` encrypted marker types; no plaintext escapes the TEE
/// boundary in typed form.
///
/// # Thread safety
///
/// `EncryptedPipeline` requires `&mut self` for all processing methods
/// because both the underlying `TokenizationService` (vault mutations) and
/// the nonce counter require exclusive access. Callers that need concurrent
/// access MUST wrap the pipeline in a `Mutex`.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use nexacore_tee::MockTeeBackend;
/// use nexacore_tokenization::encrypted_pipeline::EncryptedPipeline;
/// use nexacore_types::encrypted::EncryptedType;
///
/// let backend = Arc::new(MockTeeBackend::new());
/// let key = [0u8; 32]; // MUST be TEE-sealed in production
/// let mut pipeline = EncryptedPipeline::new(backend, key);
///
/// let es = pipeline
///     .process_string("hello, NexaCore")
///     .expect("process_string");
/// // The encrypted value is opaque; plaintext is not accessible outside the TEE.
/// assert!(!es.ciphertext().is_empty());
/// ```
pub struct EncryptedPipeline {
    /// Underlying tokenization service (NER + policy + vault).
    service: TokenizationService,
    /// TEE-sealed 256-bit symmetric key for ChaCha20-Poly1305.
    encryption_key: [u8; 32],
    /// Monotonic nonce counter. The low 8 bytes of the 12-byte nonce are
    /// the little-endian representation of this value.
    nonce_counter: u64,
    /// TEE backend, kept for attestation during [`EncryptedPipeline::process_text`].
    backend: Arc<dyn TeeBackend>,
}

impl EncryptedPipeline {
    /// Create a new `EncryptedPipeline` backed by `backend` using `key`.
    ///
    /// The pipeline creates a fresh, empty tokenization vault. Use
    /// [`EncryptedPipeline::from_vault`] to restore from a previously sealed
    /// vault.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::MockTeeBackend;
    /// use nexacore_tokenization::encrypted_pipeline::EncryptedPipeline;
    ///
    /// let backend = Arc::new(MockTeeBackend::new());
    /// let key = [0u8; 32];
    /// let pipeline = EncryptedPipeline::new(backend, key);
    /// ```
    #[must_use]
    pub fn new(backend: Arc<dyn TeeBackend>, key: [u8; 32]) -> Self {
        let service = TokenizationService::new(Arc::clone(&backend));
        Self {
            service,
            encryption_key: key,
            nonce_counter: 0,
            backend,
        }
    }

    /// Create an `EncryptedPipeline` from an existing [`TokenVault`].
    ///
    /// Use this constructor to restore a previously sealed vault:
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::{MockTeeBackend, SealedBlob};
    /// use nexacore_tokenization::{encrypted_pipeline::EncryptedPipeline, vault::TokenVault};
    ///
    /// fn restore(
    ///     backend: Arc<MockTeeBackend>,
    ///     blob: &SealedBlob,
    ///     key: [u8; 32],
    /// ) -> nexacore_types::error::Result<EncryptedPipeline> {
    ///     let vault = TokenVault::unseal_vault(Arc::clone(&backend) as _, blob)?;
    ///     Ok(EncryptedPipeline::from_vault(
    ///         Arc::clone(&backend) as _,
    ///         vault,
    ///         key,
    ///     ))
    /// }
    /// ```
    #[must_use]
    pub fn from_vault(backend: Arc<dyn TeeBackend>, vault: TokenVault, key: [u8; 32]) -> Self {
        Self {
            service: TokenizationService::from_vault(vault),
            encryption_key: key,
            nonce_counter: 0,
            backend,
        }
    }

    /// Encrypt `plaintext` as an [`EncryptedString`] regardless of PII
    /// classification.
    ///
    /// The plaintext is encrypted directly without NER classification. Use
    /// [`EncryptedPipeline::process_text`] if you need NER + policy filtering
    /// before encryption.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] if the AEAD operation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::MockTeeBackend;
    /// use nexacore_tokenization::encrypted_pipeline::EncryptedPipeline;
    /// use nexacore_types::encrypted::EncryptedType;
    ///
    /// let mut pipeline = EncryptedPipeline::new(Arc::new(MockTeeBackend::new()), [0u8; 32]);
    /// let es = pipeline
    ///     .process_string("arbitrary text")
    ///     .expect("process_string");
    /// assert!(!es.ciphertext().is_empty());
    /// ```
    #[instrument(skip(self, plaintext))]
    pub fn process_string(&mut self, plaintext: &str) -> Result<EncryptedString> {
        let nonce = self.next_nonce();
        EncryptedString::encrypt(plaintext, &self.encryption_key, &nonce)
    }

    /// Tokenize and encrypt an email address as a [`TokenizedEmail`].
    ///
    /// The email is encrypted using `ChaCha20-Poly1305`. The stored form is
    /// an opaque ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] if the AEAD operation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::MockTeeBackend;
    /// use nexacore_tokenization::encrypted_pipeline::EncryptedPipeline;
    /// use nexacore_types::encrypted::EncryptedType;
    ///
    /// let mut pipeline = EncryptedPipeline::new(Arc::new(MockTeeBackend::new()), [0u8; 32]);
    /// let te = pipeline
    ///     .process_email("user@example.com")
    ///     .expect("process_email");
    /// assert!(!te.ciphertext().is_empty());
    /// ```
    #[instrument(skip(self, email))]
    pub fn process_email(&mut self, email: &str) -> Result<TokenizedEmail> {
        let nonce = self.next_nonce();
        TokenizedEmail::encrypt(email, &self.encryption_key, &nonce)
    }

    /// Mask and encrypt a Social Security Number as a [`MaskedSSN`].
    ///
    /// The last 4 digit characters of `ssn` are stored as the visible suffix;
    /// the full value is encrypted with `ChaCha20-Poly1305`.
    ///
    /// # Errors
    ///
    /// - [`NexaCoreError::Identity`] with [`nexacore_types::error::IdentityErrorKind::InvalidLength`]
    ///   if `ssn` contains fewer than 4 digit characters.
    /// - [`NexaCoreError::Crypto`] if the AEAD operation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::MockTeeBackend;
    /// use nexacore_tokenization::encrypted_pipeline::EncryptedPipeline;
    ///
    /// let mut pipeline = EncryptedPipeline::new(Arc::new(MockTeeBackend::new()), [0u8; 32]);
    /// let masked = pipeline.process_ssn("123-45-6789").expect("process_ssn");
    /// assert_eq!(masked.visible_suffix(), b"6789");
    /// ```
    #[instrument(skip(self, ssn))]
    pub fn process_ssn(&mut self, ssn: &str) -> Result<MaskedSSN> {
        let nonce = self.next_nonce();
        MaskedSSN::encrypt(ssn, &self.encryption_key, &nonce)
    }

    /// Run the full NER → policy → tokenize → encrypt pipeline on `text`.
    ///
    /// Steps:
    /// 1. Classify PII spans with the NER classifier.
    /// 2. Filter spans through `policy` (only tokenize what the policy
    ///    mandates).
    /// 3. Replace filtered spans with opaque tokens (via the token vault).
    /// 4. Encrypt each replacement PII value as an [`EncryptedString`].
    /// 5. Encrypt the final tokenized text as an [`EncryptedString`].
    /// 6. Compute a BLAKE3 hash of the tokenized text and bind it to the
    ///    current TEE attestation to produce an [`AttestedHash`].
    ///
    /// The returned [`ProcessedText`] holds the encrypted text, per-span
    /// encrypted replacements, and the attested hash.
    ///
    /// # Errors
    ///
    /// - [`NexaCoreError::Internal`] if a span offset is out of bounds.
    /// - [`NexaCoreError::Crypto`] if any AEAD operation fails.
    /// - [`NexaCoreError::Tee`] if the attestation call fails.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::MockTeeBackend;
    /// use nexacore_tokenization::{encrypted_pipeline::EncryptedPipeline, policy::PolicyPreset};
    /// use nexacore_types::encrypted::EncryptedType;
    ///
    /// let mut pipeline = EncryptedPipeline::new(Arc::new(MockTeeBackend::new()), [0u8; 32]);
    /// let result = pipeline
    ///     .process_text("Contact alice@example.com today.", PolicyPreset::Gdpr)
    ///     .expect("process_text");
    /// // At least one replacement (the email).
    /// assert!(!result.replacements.is_empty());
    /// assert!(!result.encrypted_text.ciphertext().is_empty());
    /// ```
    #[instrument(skip(self, text), fields(policy = ?policy))]
    pub fn process_text(&mut self, text: &str, policy: PolicyPreset) -> Result<ProcessedText> {
        use crate::{ner::NerClassifier, policy::PolicyEngine};

        let ner = NerClassifier::new();
        let policy_engine = PolicyEngine::new(policy);

        // Classify → filter → sort descending so right-to-left replacement
        // does not invalidate earlier byte offsets.
        let mut spans: Vec<_> = ner
            .classify(text)
            .into_iter()
            .filter(|s| policy_engine.should_tokenize(&s.entity_type))
            .collect();
        spans.sort_by(|a, b| b.start.cmp(&a.start));

        // Build the tokenized text by replacing PII spans with vault tokens.
        let mut tokenized = text.to_string();
        // Collect replacements descending (matching spans), sort ascending later.
        let mut replacements: Vec<EncryptedReplacement> = Vec::with_capacity(spans.len());

        for span in &spans {
            if span.start > span.end || span.end > tokenized.len() {
                return Err(NexaCoreError::internal(
                    "encrypted_pipeline::process_text::span_out_of_bounds",
                ));
            }

            // Extract the PII value and replace with a vault token.
            let pii = tokenized[span.start..span.end].to_owned();
            let token = self.service.vault_tokenize(&pii, &span.entity_type)?;
            tokenized.replace_range(span.start..span.end, &token);

            // Encrypt the original PII value for the replacement manifest.
            let nonce = self.next_nonce();
            let encrypted_value = EncryptedString::encrypt(&pii, &self.encryption_key, &nonce)?;

            replacements.push(EncryptedReplacement {
                span: (span.start, span.end),
                encrypted_value,
                entity_type: span.entity_type.clone(),
            });
        }

        // Sort ascending by span start for the caller's convenience.
        replacements.sort_by_key(|r| r.span.0);

        // Encrypt the full tokenized text.
        let text_nonce = self.next_nonce();
        let encrypted_text =
            EncryptedString::encrypt(&tokenized, &self.encryption_key, &text_nonce)?;

        // Compute BLAKE3 hash of the tokenized text.
        // `Blake3::hash` returns `[u8; 32]` (HASH_LEN = 32).
        let hash = Blake3::hash(tokenized.as_bytes());

        // Bind the hash to the current TEE attestation.
        let attestation = self.obtain_attestation(&hash)?;
        let attested_hash = AttestedHash::from_parts(hash, attestation);

        Ok(ProcessedText {
            encrypted_text,
            replacements,
            attested_hash,
        })
    }

    /// Return the next 12-byte nonce and advance the counter.
    ///
    /// The counter occupies the low 8 bytes (little-endian); the high 4
    /// bytes are zero. Panics if the `u64` counter overflows — see the
    /// module-level docs for the rationale (nonce reuse under the same key
    /// is catastrophic).
    ///
    /// # Panics
    ///
    /// Panics if the counter would overflow `u64::MAX`. This requires
    /// encrypting more than 2^64 values with a single key, which is
    /// astronomically unlikely in any real deployment. Rotate the key before
    /// this limit is reached.
    pub fn next_nonce(&mut self) -> [u8; 12] {
        // Check before incrementing so we never produce a duplicate nonce.
        assert!(
            self.nonce_counter < u64::MAX,
            "EncryptedPipeline: nonce counter overflow — rotate the encryption key"
        );
        let counter = self.nonce_counter;
        self.nonce_counter += 1;

        let mut nonce = [0u8; 12];
        // Place the counter in the low 8 bytes (little-endian).
        // `to_le_bytes()` produces exactly 8 bytes; `nonce[..8]` is 8 bytes.
        #[allow(clippy::indexing_slicing)]
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Obtain a TEE attestation quote, using the provided `report_data`
    /// (the BLAKE3 hash of the tokenized text) as the user-controlled
    /// 32-byte measurement binding.
    fn obtain_attestation(&self, report_data: &[u8; 32]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes.copy_from_slice(report_data);
        let tee_nonce = TeeNonce(nonce_bytes);

        let quote = self
            .backend
            .attest(&tee_nonce, None)
            .map_err(|e| tee_error_to_nexacore(&e, "encrypted_pipeline::obtain_attestation"))?;

        Ok(quote.body)
    }
}

// =============================================================================
// TEE error conversion
// =============================================================================

/// Convert a [`nexacore_tee::TeeError`] to an [`NexaCoreError`].
fn tee_error_to_nexacore(err: &nexacore_tee::TeeError, context: &'static str) -> NexaCoreError {
    let kind = match err.kind {
        TeeErrorKind::SealFailed => NexaCoreTeeErrorKind::SealingFailed,
        TeeErrorKind::UnsealFailed => NexaCoreTeeErrorKind::UnsealingFailed,
        _ => NexaCoreTeeErrorKind::BackendFailure,
    };
    NexaCoreError::tee(kind, context)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::sync::Arc;

    use nexacore_tee::MockTeeBackend;
    use nexacore_types::encrypted::EncryptedType;

    use super::*;

    /// Fixed test key. Not secret — used only to exercise round-trips.
    const TEST_KEY: [u8; 32] = [0x11u8; 32];

    fn new_pipeline() -> EncryptedPipeline {
        EncryptedPipeline::new(Arc::new(MockTeeBackend::new()), TEST_KEY)
    }

    // -------------------------------------------------------------------------
    // process_string
    // -------------------------------------------------------------------------

    #[test]
    fn process_string_produces_valid_encrypted_string() {
        let mut p = new_pipeline();
        let es = p.process_string("hello world").expect("process_string");
        // Ciphertext must be non-empty (plaintext + 16-byte AEAD tag).
        assert!(!es.ciphertext().is_empty());
        assert_eq!(es.ciphertext().len(), "hello world".len() + 16);
    }

    #[test]
    fn process_string_empty_plaintext_still_produces_ciphertext() {
        let mut p = new_pipeline();
        let es = p.process_string("").expect("process_string empty");
        // Empty plaintext → only the 16-byte authentication tag.
        assert_eq!(es.ciphertext().len(), 16);
    }

    // -------------------------------------------------------------------------
    // process_email
    // -------------------------------------------------------------------------

    #[test]
    fn process_email_produces_valid_tokenized_email() {
        let mut p = new_pipeline();
        let te = p.process_email("alice@example.com").expect("process_email");
        assert!(!te.ciphertext().is_empty());
    }

    #[test]
    fn process_email_different_emails_produce_different_ciphertexts() {
        let mut p = new_pipeline();
        let te1 = p.process_email("alice@example.com").expect("te1");
        let te2 = p.process_email("bob@example.com").expect("te2");
        // Different nonces (counter incremented) → different ciphertexts.
        assert_ne!(te1.ciphertext(), te2.ciphertext());
    }

    // -------------------------------------------------------------------------
    // process_ssn
    // -------------------------------------------------------------------------

    #[test]
    fn process_ssn_produces_valid_masked_ssn_with_correct_suffix() {
        let mut p = new_pipeline();
        let masked = p.process_ssn("123-45-6789").expect("process_ssn");
        assert_eq!(masked.visible_suffix(), b"6789");
        assert!(!masked.ciphertext().is_empty());
    }

    #[test]
    fn process_ssn_too_few_digits_returns_error() {
        let mut p = new_pipeline();
        assert!(p.process_ssn("abc").is_err());
    }

    // -------------------------------------------------------------------------
    // process_text — PII present
    // -------------------------------------------------------------------------

    #[test]
    fn process_text_with_pii_produces_encrypted_replacements() {
        let mut p = new_pipeline();
        let result = p
            .process_text("Contact alice@example.com today.", PolicyPreset::Gdpr)
            .expect("process_text");
        assert!(!result.replacements.is_empty(), "email must be replaced");
        assert!(!result.encrypted_text.ciphertext().is_empty());
    }

    #[test]
    fn process_text_replacement_entity_type_is_email() {
        let mut p = new_pipeline();
        let result = p
            .process_text("Email: user@domain.org", PolicyPreset::Gdpr)
            .expect("process_text");
        let rep = result.replacements.first().expect("must have replacement");
        assert_eq!(rep.entity_type, EntityType::Email);
    }

    #[test]
    fn process_text_attested_hash_is_32_bytes() {
        let mut p = new_pipeline();
        let result = p
            .process_text("test input", PolicyPreset::Gdpr)
            .expect("process_text");
        assert_eq!(result.attested_hash.hash().len(), 32);
    }

    // -------------------------------------------------------------------------
    // process_text — no PII
    // -------------------------------------------------------------------------

    #[test]
    fn process_text_without_pii_still_encrypts_text() {
        let mut p = new_pipeline();
        let result = p
            .process_text("No PII in this sentence.", PolicyPreset::Gdpr)
            .expect("process_text no pii");
        // No replacements expected.
        assert!(result.replacements.is_empty());
        // But the text is still encrypted.
        assert!(!result.encrypted_text.ciphertext().is_empty());
    }

    // -------------------------------------------------------------------------
    // Nonce counter
    // -------------------------------------------------------------------------

    #[test]
    fn nonce_counter_increments_correctly() {
        let mut p = new_pipeline();
        assert_eq!(p.nonce_counter, 0);
        let n0 = p.next_nonce();
        assert_eq!(p.nonce_counter, 1);
        let n1 = p.next_nonce();
        assert_eq!(p.nonce_counter, 2);
        // Nonce bytes must differ.
        assert_ne!(n0, n1);
        // First nonce must be all-zero (counter=0, little-endian).
        assert_eq!(n0, [0u8; 12]);
        // Second nonce must have low byte = 1.
        let mut expected = [0u8; 12];
        expected[0] = 1;
        assert_eq!(n1, expected);
    }

    // -------------------------------------------------------------------------
    // AttestedHash round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn attested_hash_round_trip_via_from_parts() {
        // Directly exercise the provider-gated constructor for AttestedHash.
        let hash = [0xBEu8; 32];
        let attestation = vec![0x01u8, 0x02u8, 0x03u8];
        let ah = AttestedHash::from_parts(hash, attestation.clone());
        assert_eq!(ah.hash(), &hash);
        assert_eq!(ah.ciphertext(), &attestation[..]);
    }
}
