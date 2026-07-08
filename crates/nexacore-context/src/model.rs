//! The personal-context schema (WS16-05.1).
//!
//! Personal context has three kinds of entry: free-form **preferences**
//! (key/value), **opt-in documents** the user has chosen to expose, and an
//! **interaction history**. The types derive `serde` so the store can be
//! encrypted at rest (WS16-05.3) and exported in full (WS16-05.9).

use serde::{Deserialize, Serialize};

/// Why a context entry was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContextError {
    /// A preference key was empty.
    #[error("context preference key is empty")]
    EmptyKey,
    /// A document id was empty.
    #[error("context document id is empty")]
    EmptyDocumentId,
}

/// A document the user may opt into exposing as personal context (WS16-05.1).
///
/// `included` records the explicit opt-in (WS16-05.5): a document is only ever
/// surfaced to agents when `included` is `true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptInDocument {
    /// A stable identifier for the document.
    pub id: String,
    /// A human-readable title.
    pub title: String,
    /// Whether the user has opted this document into their context.
    pub included: bool,
}

impl OptInDocument {
    /// A document record with an explicit opt-in flag.
    #[must_use]
    pub fn new(id: impl Into<String>, title: impl Into<String>, included: bool) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            included,
        }
    }
}

/// One interaction-history entry (WS16-05.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Caller-supplied timestamp in milliseconds.
    pub at_ms: u64,
    /// A short summary of the interaction.
    pub summary: String,
}

impl HistoryEntry {
    /// A history entry at `at_ms` with `summary`.
    #[must_use]
    pub fn new(at_ms: u64, summary: impl Into<String>) -> Self {
        Self {
            at_ms,
            summary: summary.into(),
        }
    }
}
