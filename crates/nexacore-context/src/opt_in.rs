//! The explicit document opt-in flow (WS16-05.5).
//!
//! A document is **never** exposed to an agent unless the user has explicitly
//! opted it in. This module makes that flow first-class:
//!
//! - [`add_excluded_document`] adds a document in the *excluded* state, so
//!   merely knowing about a document never exposes it — opt-in is a separate,
//!   deliberate act;
//! - [`opt_in_document`] / [`opt_out_document`] flip that state and report,
//!   verifiably, whether the state actually changed;
//! - [`is_opted_in`] reads the current state.
//!
//! Exposure itself ([`crate::tokenize::expose_for_agent`]) already filters to
//! opted-in documents; this module governs how a document *reaches* that state.

use crate::{
    model::{ContextError, OptInDocument},
    store::PersonalContextStore,
};

/// Whether a document is currently exposed to agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptInStatus {
    /// The user has opted this document into their context.
    Included,
    /// The document is present but excluded from agent exposure.
    Excluded,
}

/// The result of an opt-in / opt-out request (WS16-05.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptInOutcome {
    /// The document's status changed to the given value.
    Changed(OptInStatus),
    /// The document already had the requested status; nothing changed.
    Unchanged(OptInStatus),
    /// No document with that id exists.
    NotFound,
}

/// Add a document in the **excluded** state (WS16-05.5).
///
/// This is the safe entry point for registering a document: it is known to the
/// store but not exposed to any agent until [`opt_in_document`] is called.
///
/// # Errors
///
/// Returns [`ContextError::EmptyDocumentId`] if `id` is empty.
pub fn add_excluded_document(
    store: &mut PersonalContextStore,
    id: impl Into<String>,
    title: impl Into<String>,
) -> Result<(), ContextError> {
    store.add_document(OptInDocument::new(id, title, false))
}

/// The current opt-in status of a document, if it exists.
#[must_use]
pub fn opt_in_status(store: &PersonalContextStore, id: &str) -> Option<OptInStatus> {
    store.document(id).map(|doc| {
        if doc.included {
            OptInStatus::Included
        } else {
            OptInStatus::Excluded
        }
    })
}

/// Whether a document is currently opted in (and therefore exposable).
#[must_use]
pub fn is_opted_in(store: &PersonalContextStore, id: &str) -> bool {
    opt_in_status(store, id) == Some(OptInStatus::Included)
}

/// Explicitly opt a document into the context (WS16-05.5).
pub fn opt_in_document(store: &mut PersonalContextStore, id: &str) -> OptInOutcome {
    set_included(store, id, true, OptInStatus::Included)
}

/// Explicitly opt a document out of the context (WS16-05.5).
pub fn opt_out_document(store: &mut PersonalContextStore, id: &str) -> OptInOutcome {
    set_included(store, id, false, OptInStatus::Excluded)
}

fn set_included(
    store: &mut PersonalContextStore,
    id: &str,
    included: bool,
    target: OptInStatus,
) -> OptInOutcome {
    match store.document(id).map(|doc| doc.included) {
        None => OptInOutcome::NotFound,
        Some(current) if current == included => OptInOutcome::Unchanged(target),
        Some(_) => {
            store.set_document_included(id, included);
            OptInOutcome::Changed(target)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenize::{ContextTokenizer, expose_for_agent};

    struct Passthrough;
    impl ContextTokenizer for Passthrough {
        fn tokenize(&self, text: &str) -> String {
            text.to_owned()
        }
    }

    #[test]
    fn a_freshly_added_document_is_excluded_and_not_exposed() {
        let mut store = PersonalContextStore::new();
        assert_eq!(add_excluded_document(&mut store, "doc1", "Notes"), Ok(()));
        // Explicit-opt-in invariant: it is known but not exposed.
        assert_eq!(opt_in_status(&store, "doc1"), Some(OptInStatus::Excluded));
        assert!(!is_opted_in(&store, "doc1"));
        let exposed = expose_for_agent(&store, &Passthrough);
        assert!(exposed.documents.is_empty());
    }

    #[test]
    fn opt_in_then_opt_out_toggles_exposure() {
        let mut store = PersonalContextStore::new();
        assert_eq!(add_excluded_document(&mut store, "doc1", "Notes"), Ok(()));

        assert_eq!(
            opt_in_document(&mut store, "doc1"),
            OptInOutcome::Changed(OptInStatus::Included)
        );
        assert!(is_opted_in(&store, "doc1"));
        assert_eq!(expose_for_agent(&store, &Passthrough).documents.len(), 1);

        assert_eq!(
            opt_out_document(&mut store, "doc1"),
            OptInOutcome::Changed(OptInStatus::Excluded)
        );
        assert!(!is_opted_in(&store, "doc1"));
        assert!(expose_for_agent(&store, &Passthrough).documents.is_empty());
    }

    #[test]
    fn repeating_a_request_reports_unchanged() {
        let mut store = PersonalContextStore::new();
        assert_eq!(add_excluded_document(&mut store, "doc1", "Notes"), Ok(()));
        assert_eq!(
            opt_in_document(&mut store, "doc1"),
            OptInOutcome::Changed(OptInStatus::Included)
        );
        // Idempotent: opting in an already-included doc changes nothing.
        assert_eq!(
            opt_in_document(&mut store, "doc1"),
            OptInOutcome::Unchanged(OptInStatus::Included)
        );
    }

    #[test]
    fn opting_a_missing_document_reports_not_found() {
        let mut store = PersonalContextStore::new();
        assert_eq!(opt_in_document(&mut store, "ghost"), OptInOutcome::NotFound);
        assert_eq!(
            opt_out_document(&mut store, "ghost"),
            OptInOutcome::NotFound
        );
        assert_eq!(opt_in_status(&store, "ghost"), None);
    }

    #[test]
    fn add_excluded_document_rejects_empty_id() {
        let mut store = PersonalContextStore::new();
        assert_eq!(
            add_excluded_document(&mut store, "", "x"),
            Err(ContextError::EmptyDocumentId)
        );
    }
}
