//! The local-first personal-context store (WS16-05.2).
//!
//! [`PersonalContextStore`] holds the user's preferences, opt-in documents, and
//! interaction history entirely on the device. It is a plain in-memory store
//! with deterministic ordering (`BTreeMap`); persistence is layered on top with
//! encryption at rest (WS16-05.3). Agent queries go through the capability and
//! privacy-budget gate (WS16-05.6/.7), which is built separately; this store is
//! the data layer it reads.

use std::collections::BTreeMap;

use crate::model::{ContextError, HistoryEntry, OptInDocument};

/// The on-device store of personal context (WS16-05.2).
#[derive(Debug, Clone, Default)]
pub struct PersonalContextStore {
    preferences: BTreeMap<String, String>,
    documents: BTreeMap<String, OptInDocument>,
    history: Vec<HistoryEntry>,
}

impl PersonalContextStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // --- Preferences -------------------------------------------------------

    /// Set a preference (overwriting any existing value).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EmptyKey`] if `key` is empty.
    pub fn set_preference(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), ContextError> {
        let key = key.into();
        if key.is_empty() {
            return Err(ContextError::EmptyKey);
        }
        self.preferences.insert(key, value.into());
        Ok(())
    }

    /// The value of a preference, if set.
    #[must_use]
    pub fn preference(&self, key: &str) -> Option<&str> {
        self.preferences.get(key).map(String::as_str)
    }

    /// Remove a preference. Returns whether it was present.
    pub fn remove_preference(&mut self, key: &str) -> bool {
        self.preferences.remove(key).is_some()
    }

    // --- Opt-in documents --------------------------------------------------

    /// Add (or replace) a document record.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::EmptyDocumentId`] if the document id is empty.
    pub fn add_document(&mut self, document: OptInDocument) -> Result<(), ContextError> {
        if document.id.is_empty() {
            return Err(ContextError::EmptyDocumentId);
        }
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }

    /// The document record for `id`, if present.
    #[must_use]
    pub fn document(&self, id: &str) -> Option<&OptInDocument> {
        self.documents.get(id)
    }

    /// Set a document's opt-in flag (WS16-05.5). Returns whether the document
    /// existed.
    pub fn set_document_included(&mut self, id: &str, included: bool) -> bool {
        if let Some(doc) = self.documents.get_mut(id) {
            doc.included = included;
            true
        } else {
            false
        }
    }

    /// The documents the user has opted into exposing, in id order.
    pub fn included_documents(&self) -> impl Iterator<Item = &OptInDocument> {
        self.documents.values().filter(|d| d.included)
    }

    /// Remove a document. Returns whether it was present.
    pub fn remove_document(&mut self, id: &str) -> bool {
        self.documents.remove(id).is_some()
    }

    // --- History -----------------------------------------------------------

    /// Append an interaction-history entry.
    pub fn record(&mut self, entry: HistoryEntry) {
        self.history.push(entry);
    }

    /// All history entries in insertion order.
    #[must_use]
    pub fn history(&self) -> &[HistoryEntry] {
        &self.history
    }

    // --- Aggregate ---------------------------------------------------------

    /// Whether the store holds no context at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.preferences.is_empty() && self.documents.is_empty() && self.history.is_empty()
    }

    /// The total number of stored entries across all categories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.preferences
            .len()
            .saturating_add(self.documents.len())
            .saturating_add(self.history.len())
    }

    /// Erase all personal context — the mechanism behind one-click total
    /// deletion (WS16-05.10).
    pub fn clear(&mut self) {
        self.preferences.clear();
        self.documents.clear();
        self.history.clear();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    #[test]
    fn new_store_is_empty() {
        let store = PersonalContextStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn preferences_round_trip_and_reject_empty_key() {
        let mut store = PersonalContextStore::new();
        assert_eq!(store.set_preference("theme", "dark"), Ok(()));
        assert_eq!(store.preference("theme"), Some("dark"));
        // Overwrite.
        assert_eq!(store.set_preference("theme", "light"), Ok(()));
        assert_eq!(store.preference("theme"), Some("light"));
        assert_eq!(store.set_preference("", "x"), Err(ContextError::EmptyKey));
        assert!(store.remove_preference("theme"));
        assert!(!store.remove_preference("theme"));
        assert_eq!(store.preference("theme"), None);
    }

    #[test]
    fn documents_add_query_and_opt_in_toggle() {
        let mut store = PersonalContextStore::new();
        assert_eq!(
            store.add_document(OptInDocument::new("doc1", "Notes", false)),
            Ok(())
        );
        assert_eq!(
            store.add_document(OptInDocument::new("doc2", "Resume", true)),
            Ok(())
        );
        // Only opted-in documents are surfaced.
        let included: Vec<&str> = store.included_documents().map(|d| d.id.as_str()).collect();
        assert_eq!(included, vec!["doc2"]);
        // Opt doc1 in (WS16-05.5 mechanism).
        assert!(store.set_document_included("doc1", true));
        assert!(!store.set_document_included("missing", true));
        let mut included: Vec<&str> = store.included_documents().map(|d| d.id.as_str()).collect();
        included.sort_unstable();
        assert_eq!(included, vec!["doc1", "doc2"]);
        assert!(store.remove_document("doc1"));
        assert_eq!(store.document("doc1"), None);
    }

    #[test]
    fn add_document_rejects_empty_id() {
        let mut store = PersonalContextStore::new();
        assert_eq!(
            store.add_document(OptInDocument::new("", "x", true)),
            Err(ContextError::EmptyDocumentId)
        );
    }

    #[test]
    fn history_records_in_order() {
        let mut store = PersonalContextStore::new();
        store.record(HistoryEntry::new(1, "first"));
        store.record(HistoryEntry::new(2, "second"));
        assert_eq!(store.history().len(), 2);
        assert_eq!(
            store.history().first().map(|e| e.summary.as_str()),
            Some("first")
        );
        assert_eq!(
            store.history().last().map(|e| e.summary.as_str()),
            Some("second")
        );
    }

    #[test]
    fn clear_erases_everything() {
        let mut store = PersonalContextStore::new();
        store.set_preference("k", "v").expect("set");
        store
            .add_document(OptInDocument::new("d", "t", true))
            .expect("add");
        store.record(HistoryEntry::new(1, "h"));
        assert_eq!(store.len(), 3);
        store.clear();
        assert!(store.is_empty());
    }
}
