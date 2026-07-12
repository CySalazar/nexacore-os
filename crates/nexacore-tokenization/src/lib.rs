//! # `nexacore-tokenization`
//!
//! PII tokenization service for NexaCore OS.
//!
//! Replaces personally identifiable information (PII) with deterministic
//! tokens before any inference workload leaves the user's TEE. The
//! mapping between PII and tokens lives in a per-user vault inside the
//! TEE; the model only ever sees tokens, never raw PII.
//!
//! ## Architecture overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │             TokenizationService                  │
//! │  ┌──────────────┐  ┌──────────────┐             │
//! │  │ NerClassifier │  │ PolicyEngine │             │
//! │  └──────┬───────┘  └──────┬───────┘             │
//! │         │ NerSpans         │ should_tokenize?     │
//! │         └────────┬─────────┘                     │
//! │                  ▼                               │
//! │           ┌─────────────┐                        │
//! │           │  TokenVault │ (TEE-sealed)            │
//! │           └─────────────┘                        │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! ## Design rationale
//!
//! - **Local-only by construction**: tokenization runs inside the user's
//!   TEE. The vault never leaves the device; remote nodes see only tokens.
//! - **Deterministic tokens for the user, scrambled across sessions**:
//!   within a session the same PII produces the same token (so the model
//!   can reason about co-reference). Across sessions, tokens are
//!   re-scrambled to prevent linkability.
//! - **NER classifier on-device**: PII spans are detected by a small
//!   local model. False negatives are conservative — when in doubt, the
//!   data is treated as PII.
//! - **De-tokenization happens locally**: model responses containing
//!   tokens are de-tokenized inside the TEE on the user's device.
//!
//! ## Connection to `nexacore-types::encrypted`
//!
//! The marker types in [`nexacore_types::encrypted`] are the *stored form* of
//! values that this crate has processed:
//!
//! - [`nexacore_types::encrypted::EncryptedString`] — a string encrypted by
//!   this crate inside the TEE.
//! - [`nexacore_types::encrypted::TokenizedEmail`] — an email tokenized by this
//!   crate.
//! - [`nexacore_types::encrypted::MaskedSSN`] — an SSN masked and encrypted by
//!   this crate.
//! - [`nexacore_types::encrypted::AttestedHash`] — a hash bound to the TEE
//!   attestation that witnessed the tokenization.
//!
//! See [`/docs/04-security-model.md`](../../../docs/04-security-model.md)
//! § "Tokenization service".
//!
//! ## Modules
//!
//! - [`ner`] — Named Entity Recognition for PII spans.
//! - [`nerpack`] — signed monolingual NER language-pack format + manifest.
//! - [`detectors`] — extensible, user-defined detector registry (word/phrase
//!   dictionaries and format templates) for domain-specific sensitive data.
//! - [`vault`] — per-user token vault inside TEE.
//! - [`policy`] — policy for what counts as PII (configurable per
//!   regulatory regime: GDPR, HIPAA, etc.).
//! - [`types`] — request / response types for the tokenization API.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-tokenization")]
#![deny(missing_docs)]
// Allow unwrap/expect/panic in test code. Mirrors the workspace-level
// cfg-test allowances in `nexacore-types` and `nexacore-tee`.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
    )
)]

pub mod ai_chokepoint;
pub mod concept;
pub mod detectors;
pub mod egress;
pub mod encrypted_pipeline;
pub mod langid;
pub mod ner;
pub mod nerpack;
pub mod pack_registry;
pub mod policy;
pub mod privacy;
pub mod streaming;
pub mod types;
pub mod vault;

use std::sync::Arc;

use nexacore_tee::TeeBackend;
use nexacore_types::error::{NexaCoreError, Result};
use tracing::instrument;

use crate::{
    concept::{ConceptClassifier, ConceptDetector},
    detectors::DetectorRegistry,
    ner::{NerClassifier, NerSpan},
    policy::PolicyEngine,
    streaming::StreamingDetokenizer,
    types::{
        DetokenizeRequest, DetokenizeResponse, Replacement, TokenizeRequest, TokenizeResponse,
    },
    vault::TokenVault,
};

/// The optional on-device semantic concept layer (WS5-11.4): an embedding-based
/// [`ConceptClassifier`] plus the concepts to scan for. Held behind a trait
/// object because the model is loaded at runtime and is not serializable.
struct ConceptLayer {
    classifier: Box<dyn ConceptClassifier>,
    detectors: Vec<ConceptDetector>,
}

// =============================================================================
// TokenizationService
// =============================================================================

/// Top-level PII tokenization service.
///
/// `TokenizationService` composes the NER classifier, the policy engine,
/// and the token vault into the end-to-end request/response pipeline. It is
/// the single entry point for callers that want to tokenize or de-tokenize
/// text.
///
/// # Thread safety
///
/// `TokenizationService` is not `Sync` because [`TokenVault`] requires
/// `&mut self` for tokenization. Callers that need to share a service
/// instance across threads must wrap it in a `Mutex` or similar.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use nexacore_tee::MockTeeBackend;
/// use nexacore_tokenization::{
///     TokenizationService, policy::PolicyPreset, types::TokenizeRequest,
/// };
/// use nexacore_types::identity::SessionId;
///
/// let mut service = TokenizationService::new(Arc::new(MockTeeBackend::new()));
/// let req = TokenizeRequest {
///     session_id: SessionId::new(),
///     text: "Contact alice@example.com for details.".to_string(),
///     policy: PolicyPreset::Gdpr,
/// };
/// let resp = service.tokenize(req).expect("tokenize must succeed");
/// // The email should have been replaced.
/// assert!(!resp.tokenized_text.contains("alice@example.com"));
/// assert!(!resp.replacements.is_empty());
/// ```
pub struct TokenizationService {
    ner: NerClassifier,
    vault: TokenVault,
    detectors: DetectorRegistry,
    concept: Option<ConceptLayer>,
}

impl TokenizationService {
    /// Create a new `TokenizationService` backed by `backend`.
    ///
    /// The service creates a fresh, empty vault. Use
    /// [`TokenizationService::from_vault`] to start from a previously
    /// sealed vault.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::MockTeeBackend;
    /// use nexacore_tokenization::TokenizationService;
    ///
    /// let svc = TokenizationService::new(Arc::new(MockTeeBackend::new()));
    /// ```
    #[must_use]
    pub fn new(backend: Arc<dyn TeeBackend>) -> Self {
        Self {
            ner: NerClassifier::new(),
            vault: TokenVault::new(backend),
            detectors: DetectorRegistry::new(),
            concept: None,
        }
    }

    /// Create a `TokenizationService` from an existing [`TokenVault`].
    ///
    /// Use this constructor when restoring a session from a previously
    /// sealed blob:
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::{MockTeeBackend, SealedBlob};
    /// use nexacore_tokenization::{TokenizationService, vault::TokenVault};
    ///
    /// fn restore(
    ///     backend: Arc<MockTeeBackend>,
    ///     blob: &SealedBlob,
    /// ) -> nexacore_types::error::Result<TokenizationService> {
    ///     let vault = TokenVault::unseal_vault(backend, blob)?;
    ///     Ok(TokenizationService::from_vault(vault))
    /// }
    /// ```
    #[must_use]
    pub fn from_vault(vault: TokenVault) -> Self {
        Self {
            ner: NerClassifier::new(),
            vault,
            detectors: DetectorRegistry::new(),
            concept: None,
        }
    }

    /// Borrow the extensible detector registry (WS5-11.5).
    #[must_use]
    pub fn detectors(&self) -> &DetectorRegistry {
        &self.detectors
    }

    /// Mutably borrow the extensible detector registry to register, remove, or
    /// toggle user-defined detectors (WS5-11.1/.5).
    ///
    /// Spans matched by enabled detectors are **always** tokenized by
    /// [`tokenize`](TokenizationService::tokenize), independently of the
    /// regulatory [`PolicyPreset`](crate::policy::PolicyPreset): a deployment-registered detector marks data
    /// that must never reach a model, so it is an always-on overlay on top of
    /// the built-in PII policy (WS5-11.7).
    pub fn detectors_mut(&mut self) -> &mut DetectorRegistry {
        &mut self.detectors
    }

    /// Install the on-device semantic concept layer (WS5-11.4): `classifier`
    /// scores text windows against each of `detectors`' concepts, and matches
    /// at or above each detector's threshold are tokenized by
    /// [`tokenize`](TokenizationService::tokenize) — independently of the
    /// regulatory [`PolicyPreset`](crate::policy::PolicyPreset), exactly like the rule-based custom
    /// detectors (WS5-11.7).
    ///
    /// `classifier` runs entirely on-device and performs no egress; see
    /// [`ConceptClassifier`].
    pub fn set_concept_layer(
        &mut self,
        classifier: Box<dyn ConceptClassifier>,
        detectors: Vec<ConceptDetector>,
    ) {
        self.concept = Some(ConceptLayer {
            classifier,
            detectors,
        });
    }

    /// Remove the semantic concept layer, if any.
    pub fn clear_concept_layer(&mut self) {
        self.concept = None;
    }

    /// Whether a semantic concept layer is currently installed.
    #[must_use]
    pub const fn has_concept_layer(&self) -> bool {
        self.concept.is_some()
    }

    /// Crate-private helper: tokenize a single PII value via the vault.
    ///
    /// Exposed to `encrypted_pipeline` so that module can drive vault
    /// tokenization for individual spans without requiring a full
    /// [`TokenizeRequest`]. The vault's co-reference semantics are preserved:
    /// the same PII value under the same entity type returns the same token
    /// within a session.
    pub(crate) fn vault_tokenize(
        &mut self,
        pii: &str,
        entity_type: &crate::types::EntityType,
    ) -> Result<String> {
        self.vault.tokenize(pii, entity_type)
    }

    /// Tokenize the text in `req`, returning the tokenized text and
    /// the substitution manifest.
    ///
    /// The method:
    /// 1. Runs the NER classifier to detect PII spans.
    /// 2. Consults the policy engine (built from `req.policy`) to filter
    ///    to only the spans that must be tokenized under the active policy.
    /// 3. Processes spans right-to-left (highest byte offset first) so
    ///    earlier spans' offsets remain valid.
    /// 4. Returns the tokenized text and the substitution manifest.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError`] if the vault's tokenize operation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::MockTeeBackend;
    /// use nexacore_tokenization::{
    ///     TokenizationService, policy::PolicyPreset, types::TokenizeRequest,
    /// };
    /// use nexacore_types::identity::SessionId;
    ///
    /// let mut svc = TokenizationService::new(Arc::new(MockTeeBackend::new()));
    /// let req = TokenizeRequest {
    ///     session_id: SessionId::new(),
    ///     text: "Email alice@example.com".to_string(),
    ///     policy: PolicyPreset::Gdpr,
    /// };
    /// let resp = svc.tokenize(req).unwrap();
    /// assert!(!resp.tokenized_text.contains("alice@example.com"));
    /// ```
    #[instrument(skip(self, req), fields(policy = ?req.policy))]
    pub fn tokenize(&mut self, req: TokenizeRequest) -> Result<TokenizeResponse> {
        // Destructure the request so we can move individual fields without
        // triggering needless_pass_by_value (the value IS consumed here).
        let TokenizeRequest {
            session_id,
            text: original_text,
            policy: policy_preset,
        } = req;

        let policy = PolicyEngine::new(policy_preset);

        // Built-in NER spans, filtered to those the regulatory policy mandates.
        let mut spans: Vec<NerSpan> = self
            .ner
            .classify(&original_text)
            .into_iter()
            .filter(|span| policy.should_tokenize(&span.entity_type))
            .collect();
        // User-defined detector spans (WS5-11.7): always tokenized, independent
        // of the regulatory preset — a registered detector marks data that must
        // never reach a model.
        spans.extend(self.detectors.detect(&original_text));
        // Semantic concept spans (WS5-11.4): the on-device embedding classifier
        // scores text windows against each registered concept; matches are
        // tokenized like custom detectors (always-on overlay). The classifier
        // runs locally with no egress.
        if let Some(layer) = &self.concept {
            for det in &layer.detectors {
                spans.extend(det.detect_with(&original_text, layer.classifier.as_ref()));
            }
        }

        // Merge the two sources into a sorted, non-overlapping set so NER and
        // detector spans cannot corrupt each other's byte offsets during
        // replacement (earliest start wins; ties broken by the longer span).
        spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        let mut actionable: Vec<NerSpan> = Vec::with_capacity(spans.len());
        for span in spans {
            if actionable.last().is_none_or(|prev| span.start >= prev.end) {
                actionable.push(span);
            }
        }

        // Sort descending by start so right-to-left replacement preserves
        // earlier byte offsets.
        actionable.sort_by(|a, b| b.start.cmp(&a.start));

        let mut text = original_text;
        let mut replacements: Vec<Replacement> = Vec::with_capacity(actionable.len());

        for span in &actionable {
            // Bounds check: the classifier should only emit valid spans, but
            // we validate defensively to avoid panicking on unexpected input.
            if span.start > span.end || span.end > text.len() {
                return Err(NexaCoreError::internal(
                    "tokenization::tokenize::span_out_of_bounds",
                ));
            }

            let pii = text[span.start..span.end].to_owned();
            let token = self.vault.tokenize(&pii, &span.entity_type)?;

            // Replace the span in the text.
            text.replace_range(span.start..span.end, &token);

            replacements.push(Replacement {
                // The span's start is the original offset; the caller asked for
                // original_span coordinates, not post-substitution coordinates.
                original_span: (span.start, span.end),
                token,
                entity_type: span.entity_type.clone(),
            });
        }

        // Sort replacements ascending by span start for the caller's
        // convenience (we processed them descending but the manifest should
        // read left-to-right).
        replacements.sort_by_key(|r| r.original_span.0);

        Ok(TokenizeResponse {
            session_id,
            tokenized_text: text,
            replacements,
        })
    }

    /// De-tokenize the text in `req`, resolving tokens back to their
    /// original PII values.
    ///
    /// The method scans `req.tokenized_text` for substrings that match
    /// known tokens in the vault and replaces each one with the
    /// corresponding PII value. Tokens not present in the vault are left
    /// in place.
    ///
    /// # Errors
    ///
    /// Currently infallible (returns `Ok` always). Token lookup failures
    /// are silent (unknown tokens are left verbatim). Future versions may
    /// optionally return errors on unknown tokens.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use nexacore_tee::MockTeeBackend;
    /// use nexacore_tokenization::{
    ///     TokenizationService,
    ///     policy::PolicyPreset,
    ///     types::{DetokenizeRequest, TokenizeRequest},
    /// };
    /// use nexacore_types::identity::SessionId;
    ///
    /// let mut svc = TokenizationService::new(Arc::new(MockTeeBackend::new()));
    /// let session = SessionId::new();
    ///
    /// let tok_resp = svc
    ///     .tokenize(TokenizeRequest {
    ///         session_id: session,
    ///         text: "alice@example.com".to_string(),
    ///         policy: PolicyPreset::Gdpr,
    ///     })
    ///     .unwrap();
    ///
    /// let detok_resp = svc
    ///     .detokenize(DetokenizeRequest {
    ///         session_id: session,
    ///         tokenized_text: tok_resp.tokenized_text,
    ///     })
    ///     .unwrap();
    ///
    /// assert_eq!(detok_resp.text, "alice@example.com");
    /// ```
    #[instrument(skip(self, req))]
    pub fn detokenize(&self, req: DetokenizeRequest) -> Result<DetokenizeResponse> {
        // Destructure the request so we can move fields, consuming the value
        // and satisfying the clippy::needless_pass_by_value invariant.
        let DetokenizeRequest {
            session_id,
            tokenized_text,
        } = req;

        // Simple approach: try to look up every whitespace-delimited word in
        // the vault. If it resolves, replace it. If not, leave it.
        //
        // This is O(N*M) in the worst case where N is the number of words
        // and M is the vault size. For typical use cases (a few hundred
        // entries in the vault, a few paragraphs of text) this is
        // perfectly adequate. A trie-based approach would be needed at
        // scale.
        //
        // We process the text word-by-word from right to left (descending
        // byte offset) so that replacements do not shift the offsets of
        // words to the left.
        let mut sorted_spans = collect_token_spans(&tokenized_text);
        sorted_spans.sort_by(|a, b| b.0.cmp(&a.0));

        let mut result = tokenized_text.clone();
        for (start, end) in sorted_spans {
            let word = &tokenized_text[start..end];
            if let Ok(pii) = self.vault.detokenize(word) {
                result.replace_range(start..end, &pii);
            }
        }

        Ok(DetokenizeResponse {
            session_id,
            text: result,
        })
    }

    /// Feed one chunk of a streamed model response to `stream`, returning the
    /// detokenized text safe to emit now (WS5-11.9).
    ///
    /// Tokens split across chunk boundaries are buffered inside `stream` until
    /// proven complete, so a partial token is never leaked to the caller.
    /// Resolution happens against the on-device vault, so detokenization stays
    /// on the origin device. Call [`detokenize_stream_finish`] once the stream
    /// ends to flush the final buffered word.
    ///
    /// [`detokenize_stream_finish`]: TokenizationService::detokenize_stream_finish
    #[must_use]
    pub fn detokenize_stream_push(&self, stream: &mut StreamingDetokenizer, chunk: &str) -> String {
        stream.push(chunk, |word| self.vault.detokenize(word).ok())
    }

    /// Flush the final buffered word when a streamed response ends (WS5-11.9).
    #[must_use]
    pub fn detokenize_stream_finish(&self, stream: StreamingDetokenizer) -> String {
        stream.finish(|word| self.vault.detokenize(word).ok())
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Collect byte-offset spans for every whitespace-delimited word in `text`.
///
/// Returns `(start, end)` pairs where `text[start..end]` is the word.
fn collect_token_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut word_start: Option<usize> = None;

    for (i, &b) in bytes.iter().enumerate() {
        let is_ws = b == b' ' || b == b'\t' || b == b'\n' || b == b'\r';
        match (is_ws, word_start) {
            (false, None) => {
                word_start = Some(i);
            }
            (true, Some(start)) => {
                spans.push((start, i));
                word_start = None;
            }
            _ => {}
        }
    }
    if let Some(start) = word_start {
        spans.push((start, bytes.len()));
    }
    spans
}

// =============================================================================
// Integration tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use nexacore_tee::MockTeeBackend;
    use nexacore_types::identity::SessionId;

    use super::*;
    use crate::{
        policy::PolicyPreset,
        types::{DetokenizeRequest, TokenizeRequest},
    };

    fn new_service() -> TokenizationService {
        TokenizationService::new(Arc::new(MockTeeBackend::new()))
    }

    #[test]
    fn placeholder_test_from_original_scaffold_still_passes() {}

    #[test]
    fn custom_detectors_are_tokenized_independent_of_policy() {
        use crate::{
            detectors::{Detector, DetectorKind, WordDetector},
            types::EntityType,
        };

        let mut svc = new_service();
        svc.detectors_mut().add(Detector::new(
            "codename",
            DetectorKind::Words(WordDetector::new(["Bluefin"])),
        ));

        let req = TokenizeRequest {
            session_id: SessionId::new(),
            // GDPR does NOT tokenize Custom entities by policy; the detector
            // overlay must tokenize the codename regardless.
            text: "Email alice@example.com about Bluefin and Bluefin again".to_string(),
            policy: PolicyPreset::Gdpr,
        };
        let resp = svc.tokenize(req).expect("tokenize");

        // The custom codename is tokenized despite the GDPR preset...
        assert!(
            !resp.tokenized_text.contains("Bluefin"),
            "custom detector word must be tokenized: {}",
            resp.tokenized_text
        );
        // ...and the built-in email is tokenized per GDPR.
        assert!(!resp.tokenized_text.contains("alice@example.com"));

        // Co-reference: both "Bluefin" occurrences map to the same token.
        let custom_tokens: Vec<_> = resp
            .replacements
            .iter()
            .filter(|r| matches!(r.entity_type, EntityType::Custom(_)))
            .map(|r| r.token.clone())
            .collect();
        assert_eq!(custom_tokens.len(), 2, "both occurrences are replaced");
        assert_eq!(
            custom_tokens[0], custom_tokens[1],
            "same value → same token (referential consistency)"
        );

        // Round-trip restores both the custom value and the email.
        let det = svc
            .detokenize(DetokenizeRequest {
                session_id: resp.session_id,
                tokenized_text: resp.tokenized_text,
            })
            .expect("detokenize");
        assert!(det.text.contains("Bluefin"));
        assert!(det.text.contains("alice@example.com"));
    }

    #[test]
    fn streaming_detok_matches_non_streaming_across_chunk_splits() {
        use crate::streaming::StreamingDetokenizer;

        let mut svc = new_service();
        let session_id = SessionId::new();
        let tok = svc
            .tokenize(TokenizeRequest {
                session_id,
                text: "Email alice@example.com or bob@example.com now".to_string(),
                policy: PolicyPreset::Gdpr,
            })
            .expect("tokenize");

        // Reference: the one-shot non-streaming detokenization.
        let oneshot = svc
            .detokenize(DetokenizeRequest {
                session_id,
                tokenized_text: tok.tokenized_text.clone(),
            })
            .expect("detok")
            .text;
        assert!(oneshot.contains("alice@example.com"));
        assert!(oneshot.contains("bob@example.com"));

        // Stream the same tokenized text one byte at a time — the worst case
        // for token-straddling boundaries — and confirm it reassembles identically.
        let mut stream = StreamingDetokenizer::new();
        let mut streamed = String::new();
        for ch in tok.tokenized_text.chars() {
            streamed.push_str(&svc.detokenize_stream_push(&mut stream, &ch.to_string()));
        }
        streamed.push_str(&svc.detokenize_stream_finish(stream));
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn empty_detector_registry_leaves_ner_tokenization_unchanged() {
        // Regression guard: with no detectors registered, behaviour matches the
        // pre-WS5-11.7 NER-only pipeline.
        let mut svc = new_service();
        let req = TokenizeRequest {
            session_id: SessionId::new(),
            text: "Contact alice@example.com".to_string(),
            policy: PolicyPreset::Gdpr,
        };
        let resp = svc.tokenize(req).expect("tokenize");
        assert!(!resp.tokenized_text.contains("alice@example.com"));
        assert_eq!(resp.replacements.len(), 1);
    }

    // -------------------------------------------------------------------------
    // Tokenize round-trip integration
    // -------------------------------------------------------------------------

    #[test]
    fn tokenize_email_under_gdpr_replaces_span() {
        let mut svc = new_service();
        let resp = svc
            .tokenize(TokenizeRequest {
                session_id: SessionId::new(),
                text: "Contact alice@example.com for details.".to_string(),
                policy: PolicyPreset::Gdpr,
            })
            .expect("tokenize");
        assert!(
            !resp.tokenized_text.contains("alice@example.com"),
            "email must be replaced"
        );
        assert_eq!(resp.replacements.len(), 1);
    }

    #[test]
    fn tokenize_email_under_pci_does_not_replace_span() {
        let mut svc = new_service();
        let resp = svc
            .tokenize(TokenizeRequest {
                session_id: SessionId::new(),
                text: "Contact alice@example.com".to_string(),
                policy: PolicyPreset::Pci,
            })
            .expect("tokenize");
        // PCI does not cover Email.
        assert_eq!(
            resp.tokenized_text, "Contact alice@example.com",
            "PCI must not tokenize email"
        );
        assert!(resp.replacements.is_empty());
    }

    #[test]
    fn tokenize_then_detokenize_recovers_original() {
        let mut svc = new_service();
        let original = "Reach alice@example.com or call 555-123-4567 anytime.";
        let session = SessionId::new();

        let tok = svc
            .tokenize(TokenizeRequest {
                session_id: session,
                text: original.to_string(),
                policy: PolicyPreset::Strict,
            })
            .expect("tokenize");

        let detok = svc
            .detokenize(DetokenizeRequest {
                session_id: session,
                tokenized_text: tok.tokenized_text,
            })
            .expect("detokenize");

        assert_eq!(detok.text, original, "round-trip must recover original");
    }

    #[test]
    fn tokenize_empty_text_returns_empty_response() {
        let mut svc = new_service();
        let resp = svc
            .tokenize(TokenizeRequest {
                session_id: SessionId::new(),
                text: String::new(),
                policy: PolicyPreset::Gdpr,
            })
            .expect("empty tokenize");
        assert!(resp.tokenized_text.is_empty());
        assert!(resp.replacements.is_empty());
    }

    #[test]
    fn detokenize_unknown_token_leaves_it_verbatim() {
        let svc = new_service();
        let resp = svc
            .detokenize(DetokenizeRequest {
                session_id: SessionId::new(),
                tokenized_text: "Hello TKN-EMAIL-unknown world".to_string(),
            })
            .expect("detokenize");
        assert_eq!(resp.text, "Hello TKN-EMAIL-unknown world");
    }
}
