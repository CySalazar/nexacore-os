//! Process-egress interposition: tokenize PII before it leaves the process
//! (WS5-06.9).
//!
//! Tokenization is only a privacy guarantee if it is **unavoidable**.  The
//! [`EgressGuard`] is the single chokepoint every outbound string passes through
//! before it can leave the originating process (and therefore the device): it
//! tokenizes the text via the on-device [`TokenizationService`] and then applies
//! a **defence-in-depth post-condition** — no detected PII value may survive in
//! the output.  If the post-condition fails, the guard **fails closed**
//! (returns an error and never the raw text), so a tokenizer bug can never leak
//! plaintext PII past the process boundary.

use nexacore_types::{
    error::{NexaCoreError, Result},
    identity::SessionId,
};

use crate::{TokenizationService, policy::PolicyPreset, types::TokenizeRequest};

/// Minimum PII-value length the post-condition checks for, to avoid flagging an
/// incidental one/two-character coincidence in surrounding non-PII text.
const MIN_RESIDUAL_LEN: usize = 3;

/// The sanitized result of an egress attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedEgress {
    /// The text that is safe to let leave the process.
    pub text: String,
    /// How many PII spans were redacted.
    pub redactions: usize,
}

/// The single chokepoint that sanitizes outbound text before process egress.
///
/// Owns the [`TokenizationService`] so the only way to obtain egress-ready text
/// is through [`EgressGuard::sanitize`].
pub struct EgressGuard {
    service: TokenizationService,
}

impl EgressGuard {
    /// Wrap an on-device tokenization service as the egress chokepoint.
    #[must_use]
    pub const fn new(service: TokenizationService) -> Self {
        Self { service }
    }

    /// Mutable access to the underlying service (detector registration, etc.).
    pub const fn service_mut(&mut self) -> &mut TokenizationService {
        &mut self.service
    }

    /// Consume the guard, returning the underlying service.
    #[must_use]
    pub fn into_service(self) -> TokenizationService {
        self.service
    }

    /// Sanitize `text` for egress under `policy` within `session_id`.
    ///
    /// Tokenizes the text, then verifies no detected PII value survives in the
    /// output.  On any residual PII it **fails closed**.
    ///
    /// # Errors
    /// Returns the tokenization error, or [`NexaCoreError`] if the
    /// post-condition detects residual PII (the raw text is never returned).
    pub fn sanitize(
        &mut self,
        session_id: SessionId,
        policy: PolicyPreset,
        text: impl Into<String>,
    ) -> Result<SanitizedEgress> {
        let original = text.into();
        let resp = self.service.tokenize(TokenizeRequest {
            session_id,
            text: original.clone(),
            policy,
        })?;

        // Defence in depth: no replaced PII value may remain in the output.
        if let Some(leaked) = residual_pii_leak(&original, &resp.replacements, &resp.tokenized_text)
        {
            return Err(NexaCoreError::internal(leaked));
        }

        Ok(SanitizedEgress {
            text: resp.tokenized_text,
            redactions: resp.replacements.len(),
        })
    }
}

/// Fail-closed post-condition shared by every egress chokepoint (the process
/// [`EgressGuard`] and the AI-path [`crate::ai_chokepoint::AiPromptChokepoint`]):
/// return a reason string if any replaced PII value of length
/// `>= MIN_RESIDUAL_LEN` still appears verbatim in `output`.
///
/// A non-`None` result means a tokenizer bug let raw PII survive substitution;
/// the caller must then refuse to emit `output` and fail closed.
pub(crate) fn residual_pii_leak(
    original: &str,
    replacements: &[crate::types::Replacement],
    output: &str,
) -> Option<&'static str> {
    for r in replacements {
        let (start, end) = r.original_span;
        let value = original.get(start..end).unwrap_or("");
        if value.len() >= MIN_RESIDUAL_LEN && output.contains(value) {
            return Some("egress post-condition failed: residual PII in output");
        }
    }
    None
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;
    use crate::types::{EntityType, Replacement, TokenizeResponse};

    fn guard() -> EgressGuard {
        use std::sync::Arc;

        use nexacore_tee::MockTeeBackend;
        EgressGuard::new(TokenizationService::new(Arc::new(MockTeeBackend::new())))
    }

    #[test]
    fn tokenizes_pii_before_egress() {
        let mut g = guard();
        let out = g
            .sanitize(
                SessionId::new(),
                PolicyPreset::Gdpr,
                "Email alice@example.com now",
            )
            .expect("sanitizes");
        assert!(!out.text.contains("alice@example.com"));
        assert!(out.redactions >= 1);
    }

    #[test]
    fn clean_text_passes_through_unchanged() {
        let mut g = guard();
        let out = g
            .sanitize(SessionId::new(), PolicyPreset::Gdpr, "no pii here at all")
            .expect("sanitizes");
        assert_eq!(out.text, "no pii here at all");
        assert_eq!(out.redactions, 0);
    }

    #[test]
    fn residual_leak_detects_surviving_value() {
        // Simulate a (hypothetical) tokenizer bug: a replacement is reported but
        // the value still appears in the output — the post-condition must catch
        // it so the guard fails closed.
        let original = "card 4111111111111111 end";
        let resp = TokenizeResponse {
            session_id: SessionId::new(),
            tokenized_text: "card 4111111111111111 end".to_string(),
            replacements: vec![Replacement {
                original_span: (5, 21),
                token: "TKN-CC-deadbeef".to_string(),
                entity_type: EntityType::CreditCard,
            }],
        };
        assert!(residual_pii_leak(original, &resp.replacements, &resp.tokenized_text).is_some());
    }

    #[test]
    fn residual_leak_ignores_clean_output() {
        let original = "card 4111111111111111 end";
        let resp = TokenizeResponse {
            session_id: SessionId::new(),
            tokenized_text: "card TKN-CC-deadbeef end".to_string(),
            replacements: vec![Replacement {
                original_span: (5, 21),
                token: "TKN-CC-deadbeef".to_string(),
                entity_type: EntityType::CreditCard,
            }],
        };
        assert!(residual_pii_leak(original, &resp.replacements, &resp.tokenized_text).is_none());
    }
}
