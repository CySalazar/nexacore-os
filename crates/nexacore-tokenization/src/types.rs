//! Request / response types for the tokenization API.
//!
//! These types represent the wire surface between callers of the
//! tokenization service and the service itself. All types are
//! `serde`-serializable so they can transit the IPC channels that connect
//! the user-facing NexaCore OS APIs to the TEE-resident vault.
//!
//! # Connection to `nexacore-types::encrypted`
//!
//! The types defined here describe the *interface* to the tokenization
//! service. The *result* of tokenization is reflected in the sealed marker
//! types in [`nexacore_types::encrypted`]:
//!
//! - [`nexacore_types::encrypted::TokenizedEmail`] — the stored form of an
//!   email that has been tokenized and encrypted by this service.
//! - [`nexacore_types::encrypted::EncryptedString`] — the stored form of an
//!   arbitrary string (e.g. a name or address) processed by this service.
//! - [`nexacore_types::encrypted::MaskedSSN`] — the stored form of a Social
//!   Security Number processed by this service.
//! - [`nexacore_types::encrypted::AttestedHash`] — a hash bound to the TEE
//!   attestation that witnessed the tokenization operation.
//!
//! Callers interact with the service through the types in this module;
//! the resulting encrypted markers are then stored and passed through the
//! rest of the NexaCore OS stack.

use nexacore_types::identity::SessionId;
use serde::{Deserialize, Serialize};

use crate::policy::PolicyPreset;

// =============================================================================
// EntityType
// =============================================================================

/// The semantic category of a PII span detected by the NER classifier.
///
/// `EntityType` drives the tokenization policy: the [`crate::policy::PolicyEngine`]
/// maps each `EntityType` to a boolean decision (tokenize vs. pass through)
/// based on the active [`PolicyPreset`].
///
/// # Extending the taxonomy
///
/// Adding a new variant is a backwards-incompatible change to the wire
/// format (existing encoded blobs will fail to decode). Such additions
/// require a Standards-Track NCIP. The `Custom` variant is provided as an
/// escape hatch for private deployments that have domain-specific PII
/// categories not represented here — it is not permitted in the NexaCore OS
/// shared mesh without an NCIP.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::types::EntityType;
/// let et = EntityType::Email;
/// assert_eq!(format!("{et:?}"), "Email");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EntityType {
    /// A person's full name or partial name.
    PersonName,
    /// An email address (`user@example.com`).
    Email,
    /// A phone number in any local or international format.
    Phone,
    /// A U.S. Social Security Number or equivalent national ID.
    Ssn,
    /// A payment-card number (PAN), any scheme.
    CreditCard,
    /// A physical or mailing address.
    Address,
    /// A deployment-specific PII category.
    ///
    /// Not permitted in the shared NexaCore mesh without a ratified NCIP.
    /// The inner string MUST be a stable machine-readable slug, not a
    /// human-readable description.
    Custom(String),
}

// =============================================================================
// Replacement
// =============================================================================

/// A single PII-to-token substitution produced during tokenization.
///
/// Each `Replacement` records:
/// - **where** in the original text the PII span started and ended,
/// - **what** token replaced it,
/// - **what kind** of PII the span was classified as.
///
/// Callers can use the list of replacements to reconstruct the
/// de-tokenized version of a response, or to audit which fields were
/// redacted.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::types::{EntityType, Replacement};
///
/// let r = Replacement {
///     original_span: (0, 17),
///     token: "TKN-EMAIL-001".to_string(),
///     entity_type: EntityType::Email,
/// };
/// assert_eq!(r.original_span.0, 0);
/// assert_eq!(r.original_span.1, 17);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replacement {
    /// Byte offsets `(start, end)` of the PII span in the **original**
    /// (pre-tokenization) text. The span is half-open: `text[start..end]`
    /// is the replaced string.
    pub original_span: (usize, usize),
    /// The opaque token that replaced the PII span.
    pub token: String,
    /// The semantic category of the replaced span.
    pub entity_type: EntityType,
}

// =============================================================================
// TokenizeRequest
// =============================================================================

/// Request to tokenize a text string.
///
/// The service tokenizes every PII span in `text` that the active policy
/// mandates, returning a [`TokenizeResponse`] with the tokenized text and
/// the list of replacements.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::{policy::PolicyPreset, types::TokenizeRequest};
/// use nexacore_types::identity::SessionId;
///
/// let req = TokenizeRequest {
///     session_id: SessionId::new(),
///     text: "Contact alice@example.com for details.".to_string(),
///     policy: PolicyPreset::Gdpr,
/// };
/// assert!(!req.text.is_empty());
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenizeRequest {
    /// The session this tokenization operation belongs to.
    ///
    /// Tokens produced within the same session are stable (the same PII
    /// produces the same token), enabling the model to reason about
    /// co-reference. Tokens are re-scrambled across sessions.
    pub session_id: SessionId,
    /// The raw text that may contain PII spans.
    pub text: String,
    /// The regulatory policy preset controlling which entity types are
    /// tokenized.
    pub policy: PolicyPreset,
}

// =============================================================================
// TokenizeResponse
// =============================================================================

/// Response from the tokenization service.
///
/// `tokenized_text` is a copy of the original text with every policy-
/// relevant PII span replaced by an opaque token. `replacements` is the
/// manifest of substitutions — callers retain this to drive
/// de-tokenization of model responses.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::types::{EntityType, Replacement, TokenizeResponse};
/// use nexacore_types::identity::SessionId;
///
/// let resp = TokenizeResponse {
///     session_id: SessionId::new(),
///     tokenized_text: "Contact [TKN-EMAIL-001] for details.".to_string(),
///     replacements: vec![Replacement {
///         original_span: (8, 25),
///         token: "TKN-EMAIL-001".to_string(),
///         entity_type: EntityType::Email,
///     }],
/// };
/// assert!(!resp.replacements.is_empty());
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenizeResponse {
    /// The session this response belongs to.
    pub session_id: SessionId,
    /// The text with PII spans replaced by opaque tokens.
    pub tokenized_text: String,
    /// Manifest of substitutions: one entry per replaced PII span.
    pub replacements: Vec<Replacement>,
}

// =============================================================================
// DetokenizeRequest
// =============================================================================

/// Request to de-tokenize a text string.
///
/// The `tokenized_text` may contain opaque tokens produced by a prior
/// [`TokenizeRequest`] in the same session. The service resolves each
/// token back to its original PII span (inside the TEE) and returns the
/// reconstructed plaintext.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::types::DetokenizeRequest;
/// use nexacore_types::identity::SessionId;
///
/// let req = DetokenizeRequest {
///     session_id: SessionId::new(),
///     tokenized_text: "Contact [TKN-EMAIL-001] for details.".to_string(),
/// };
/// assert!(req.tokenized_text.contains("TKN-EMAIL"));
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetokenizeRequest {
    /// The session that originally produced the tokens.
    pub session_id: SessionId,
    /// The text containing opaque tokens to be resolved.
    pub tokenized_text: String,
}

// =============================================================================
// DetokenizeResponse
// =============================================================================

/// Response from the de-tokenization service.
///
/// `text` is the plaintext with every known token resolved to its
/// original PII value. Tokens that cannot be found in the vault (e.g.
/// from a different session) are left in place as literal strings.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::types::DetokenizeResponse;
/// use nexacore_types::identity::SessionId;
///
/// let resp = DetokenizeResponse {
///     session_id: SessionId::new(),
///     text: "Contact alice@example.com for details.".to_string(),
/// };
/// assert!(resp.text.contains("alice@example.com"));
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetokenizeResponse {
    /// The session this response belongs to.
    pub session_id: SessionId,
    /// The reconstructed plaintext with PII values restored.
    pub text: String,
}
