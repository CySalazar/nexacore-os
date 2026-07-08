//! The AI-path tokenization chokepoint (WS5-11.6/.8/.10).
//!
//! Every prompt bound for *any* inference destination — the on-device model or
//! a Tier-1/2/3 remote node — passes through a single [`AiPromptChokepoint`]
//! before it can leave the local AI syscall layer. The chokepoint:
//!
//! - **tokenizes the prompt** (rule detectors + NER + the semantic concept
//!   layer) so only opaque tokens, never raw sensitive data, reach the
//!   destination — including the local model, whose logs/caches must never hold
//!   plaintext PII (WS5-11.6);
//! - **fails closed** (WS5-11.10): if the tokenization pipeline is unavailable
//!   or errors, or if a tokenizer bug lets a detected value survive
//!   substitution, the chokepoint returns an error and **never** the raw
//!   prompt;
//! - **de-tokenizes non-streaming responses on-device** and only for a
//!   capability-authorized caller (WS5-11.8), so plaintext is reconstructed
//!   exclusively on the origin device and handed back solely to the authorized
//!   requester.
//!
//! The chokepoint owns the [`TokenizationService`]: obtaining an egress-ready
//! prompt is possible *only* through [`AiPromptChokepoint::prepare_prompt`],
//! which is what makes tokenization unavoidable on the AI path. The concrete
//! capability token and the live health signal are supplied by the kernel AI
//! syscall layer that drives this chokepoint; here they are modelled by the
//! [`DetokenizationAuthority`] trait and [`AiPromptChokepoint::set_available`]
//! so the full policy is host-testable.

use nexacore_types::{
    error::{NexaCoreError, Result},
    identity::SessionId,
};

use crate::{
    TokenizationService,
    egress::residual_pii_leak,
    policy::PolicyPreset,
    types::{DetokenizeRequest, TokenizeRequest},
};

/// The inference destination a prompt is bound for.
///
/// The chokepoint tokenizes for **every** destination, including
/// [`LocalModel`](Destination::LocalModel): a local model still keeps logs and
/// KV-caches that must never contain plaintext PII, and the privacy invariant
/// (the model sees only tokens) must hold uniformly so the response path can
/// detokenize on-device regardless of where inference ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Destination {
    /// Inference on the origin device's local model.
    LocalModel,
    /// A Tier-1 mesh node (highest assurance: attested hardware TEE).
    Tier1,
    /// A Tier-2 mesh node.
    Tier2,
    /// A Tier-3 destination (e.g. an external provider bridge).
    Tier3,
}

/// Whether the on-device tokenization pipeline is currently usable.
///
/// The kernel health-checks the local NER/concept models and the vault and
/// flips the chokepoint to [`Unavailable`](PipelineHealth::Unavailable) on any
/// fault; while unavailable, every prompt is blocked (fail-closed, WS5-11.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipelineHealth {
    /// The pipeline is healthy and prompts may be prepared.
    Available,
    /// The pipeline is degraded; the static reason is recorded for diagnostics.
    Unavailable(&'static str),
}

/// Authorizes on-device de-tokenization for a caller (WS5-11.8).
///
/// The kernel implements this over a real capability token; the chokepoint only
/// reconstructs plaintext for a caller this authority approves for the session.
pub trait DetokenizationAuthority {
    /// Whether the caller holds a capability to receive de-tokenized
    /// (plaintext) output for `session`.
    fn may_detokenize(&self, session: SessionId) -> bool;
}

/// A prompt that has passed the chokepoint and is safe to deliver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPrompt {
    /// The tokenized prompt text — the only thing that may leave the device.
    pub text: String,
    /// The destination this prompt was prepared for.
    pub destination: Destination,
    /// How many sensitive spans were tokenized.
    pub redactions: usize,
}

/// The single chokepoint every AI prompt passes through before delivery
/// (WS5-11.6/.8/.10).
///
/// Owns the [`TokenizationService`]; see the module docs.
pub struct AiPromptChokepoint {
    service: TokenizationService,
    health: PipelineHealth,
}

impl AiPromptChokepoint {
    /// Wrap an on-device tokenization service as the AI-path chokepoint
    /// (initially healthy).
    #[must_use]
    pub const fn new(service: TokenizationService) -> Self {
        Self {
            service,
            health: PipelineHealth::Available,
        }
    }

    /// Mutable access to the underlying service (detector / concept-layer
    /// registration).
    pub const fn service_mut(&mut self) -> &mut TokenizationService {
        &mut self.service
    }

    /// Borrow the underlying service.
    #[must_use]
    pub const fn service(&self) -> &TokenizationService {
        &self.service
    }

    /// Report the live pipeline health. Setting
    /// [`Unavailable`](PipelineHealth::Unavailable) forces every subsequent
    /// [`prepare_prompt`](Self::prepare_prompt) to fail closed (WS5-11.10).
    pub fn set_available(&mut self, health: PipelineHealth) {
        self.health = health;
    }

    /// The current pipeline health.
    #[must_use]
    pub const fn health(&self) -> &PipelineHealth {
        &self.health
    }

    /// Tokenize `text` for delivery to `destination`, failing closed on any
    /// problem (WS5-11.6/.10).
    ///
    /// The returned [`PreparedPrompt`] holds only tokenized text. The raw
    /// prompt is **never** returned: if the pipeline is unavailable, if
    /// tokenization errors, or if the fail-closed post-condition detects a
    /// detected value surviving substitution, this returns an error.
    ///
    /// # Errors
    ///
    /// - [`NexaCoreError`] if the pipeline is [`Unavailable`](PipelineHealth::Unavailable).
    /// - the tokenization error, if the vault/service fails.
    /// - [`NexaCoreError`] if residual sensitive data survives in the output.
    pub fn prepare_prompt(
        &mut self,
        session_id: SessionId,
        policy: PolicyPreset,
        destination: Destination,
        text: impl Into<String>,
    ) -> Result<PreparedPrompt> {
        // Fail-closed gate: a degraded pipeline blocks every prompt.
        if let PipelineHealth::Unavailable(reason) = self.health {
            return Err(NexaCoreError::internal(reason));
        }

        let original = text.into();
        // Any service error propagates as an error — the raw prompt is dropped,
        // never returned (fail-closed).
        let resp = self.service.tokenize(TokenizeRequest {
            session_id,
            text: original.clone(),
            policy,
        })?;

        // Defence in depth: no detected value may survive in the output.
        if let Some(leaked) = residual_pii_leak(&original, &resp.replacements, &resp.tokenized_text)
        {
            return Err(NexaCoreError::internal(leaked));
        }

        Ok(PreparedPrompt {
            text: resp.tokenized_text,
            destination,
            redactions: resp.replacements.len(),
        })
    }

    /// De-tokenize a **non-streaming** model response on-device, for a
    /// capability-authorized caller only (WS5-11.8).
    ///
    /// Reconstruction happens entirely on the origin device via the local
    /// vault; the plaintext is returned only when `authority` approves the
    /// caller for `session_id`. An unauthorized caller receives an error and
    /// never any reconstructed plaintext.
    ///
    /// # Errors
    ///
    /// - [`NexaCoreError`] if `authority` denies de-tokenization for the caller.
    /// - the de-tokenization error, if the service fails.
    pub fn receive_response(
        &self,
        session_id: SessionId,
        authority: &dyn DetokenizationAuthority,
        tokenized_response: impl Into<String>,
    ) -> Result<String> {
        if !authority.may_detokenize(session_id) {
            return Err(NexaCoreError::internal(
                "ai_chokepoint: caller not authorized to de-tokenize",
            ));
        }
        let resp = self.service.detokenize(DetokenizeRequest {
            session_id,
            tokenized_text: tokenized_response.into(),
        })?;
        Ok(resp.text)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use std::sync::Arc;

    use nexacore_tee::MockTeeBackend;

    use super::*;
    use crate::{
        concept::{ConceptDetector, KeywordConceptClassifier},
        detectors::{Detector, DetectorKind, WordDetector},
    };

    /// A chokepoint whose service has a custom word detector ("Bluefin") and a
    /// semantic concept detector (`medical_condition` → "Parkinson") registered.
    fn chokepoint_with_layers() -> AiPromptChokepoint {
        let mut service = TokenizationService::new(Arc::new(MockTeeBackend::new()));
        service.detectors_mut().add(Detector::new(
            "codename",
            DetectorKind::Words(WordDetector::new(["Bluefin"])),
        ));
        service.set_concept_layer(
            Box::new(KeywordConceptClassifier::new().with_phrase("medical_condition", "Parkinson")),
            vec![ConceptDetector::new("medical_condition", 0.5)],
        );
        AiPromptChokepoint::new(service)
    }

    /// An authority that approves (or denies) every session uniformly.
    struct FixedAuthority(bool);
    impl DetokenizationAuthority for FixedAuthority {
        fn may_detokenize(&self, _session: SessionId) -> bool {
            self.0
        }
    }

    // -- WS5-11.6: the chokepoint tokenizes before delivery to any destination --

    #[test]
    fn tokenizes_email_for_remote_and_local_destinations() {
        let mut cp = chokepoint_with_layers();
        let session = SessionId::new();
        for dest in [Destination::LocalModel, Destination::Tier3] {
            let prepared = cp
                .prepare_prompt(session, PolicyPreset::Gdpr, dest, "mail alice@example.com")
                .expect("prepares");
            assert!(!prepared.text.contains("alice@example.com"));
            assert!(prepared.redactions >= 1);
            assert_eq!(prepared.destination, dest);
        }
    }

    // -- WS5-11.10: fail-closed when the pipeline is unavailable ---------------

    #[test]
    fn fails_closed_when_pipeline_unavailable() {
        let mut cp = chokepoint_with_layers();
        cp.set_available(PipelineHealth::Unavailable("model not loaded"));
        let err = cp
            .prepare_prompt(
                SessionId::new(),
                PolicyPreset::Gdpr,
                Destination::Tier2,
                "mail alice@example.com",
            )
            .unwrap_err();
        // The error must carry the reason and never the raw prompt.
        let rendered = format!("{err:?}");
        assert!(!rendered.contains("alice@example.com"));
    }

    // -- WS5-11.8: non-streaming detok is on-device & capability-gated ---------

    #[test]
    fn detokenizes_response_only_for_authorized_caller() {
        let mut cp = chokepoint_with_layers();
        let session = SessionId::new();
        let prepared = cp
            .prepare_prompt(
                session,
                PolicyPreset::Gdpr,
                Destination::Tier1,
                "ping alice@example.com",
            )
            .expect("prepares");

        // The "model" echoes the tokenized text back. An authorized caller gets
        // the plaintext reconstructed on-device.
        let plain = cp
            .receive_response(session, &FixedAuthority(true), prepared.text.clone())
            .expect("authorized detok");
        assert!(plain.contains("alice@example.com"));

        // An unauthorized caller is refused and gets no plaintext.
        let denied = cp
            .receive_response(session, &FixedAuthority(false), prepared.text)
            .unwrap_err();
        let rendered = format!("{denied:?}");
        assert!(!rendered.contains("alice@example.com"));
    }

    // -- WS5-11.11: byte-exact absence of sensitive plaintext in the payload ---

    #[test]
    fn payload_has_no_sensitive_plaintext_local_or_remote() {
        let mut cp = chokepoint_with_layers();
        let session = SessionId::new();
        // Sensitive: an email (NER), a custom code-name (word detector), and a
        // medical concept (semantic detector).
        let prompt = "Email alice@example.com about Bluefin; patient has Parkinson.";

        for dest in [Destination::LocalModel, Destination::Tier3] {
            let prepared = cp
                .prepare_prompt(session, PolicyPreset::Gdpr, dest, prompt)
                .expect("prepares");
            // Byte-exact absence of every sensitive plaintext token.
            assert!(!prepared.text.contains("alice@example.com"), "email leaked");
            assert!(!prepared.text.contains("Bluefin"), "code-name leaked");
            assert!(!prepared.text.contains("Parkinson"), "concept leaked");
        }
    }

    // -- WS5-11.12: no vault material (plaintext/mapping) appears in egress -----

    #[test]
    fn egress_payload_contains_no_vault_material() {
        let mut cp = chokepoint_with_layers();
        let session = SessionId::new();
        let secrets = ["alice@example.com", "Bluefin", "Parkinson"];
        let prompt = "Email alice@example.com about Bluefin; patient has Parkinson.";

        let prepared = cp
            .prepare_prompt(session, PolicyPreset::Gdpr, Destination::Tier3, prompt)
            .expect("prepares");

        // The egress payload is exactly the tokenized text that goes on the
        // wire. It must contain none of the vault's plaintext mapping values…
        for secret in secrets {
            assert!(
                !prepared.text.contains(secret),
                "vault plaintext {secret} present in egress"
            );
        }
        // …and the mapping is not recoverable from the payload alone: dropping
        // the vault (a fresh service with no entries) cannot reverse the tokens.
        let empty = TokenizationService::new(Arc::new(MockTeeBackend::new()));
        let no_vault = empty
            .detokenize(DetokenizeRequest {
                session_id: session,
                tokenized_text: prepared.text.clone(),
            })
            .expect("detok");
        for secret in secrets {
            assert!(
                !no_vault.text.contains(secret),
                "token reversible without the vault — mapping leaked"
            );
        }
        // The payload did carry tokens (so it was non-trivially redacted).
        assert!(prepared.redactions >= 3);
    }
}
