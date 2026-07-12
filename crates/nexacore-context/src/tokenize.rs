//! Tokenizing context elements before agent exposure (WS16-05.4).
//!
//! Personal context often contains PII (names, addresses, account numbers). An
//! agent should never see the raw values: before any context leaves the store
//! for an agent it is passed through the tokenization service (WS5-06), which
//! replaces PII with stable placeholder tokens that can be detokenized only
//! inside the trusted boundary.
//!
//! This module keeps `nexacore-context` decoupled from the tokenization service
//! via the [`ContextTokenizer`] seam — production wires in
//! `nexacore-tokenization`, while host tests use a simple double. Only opted-in
//! documents (WS16-05.5) are ever placed in the exposed view.

use std::{collections::BTreeMap, string::String, vec::Vec};

use serde::{Deserialize, Serialize};

use crate::store::PersonalContextStore;

/// Replaces PII in free text with stable placeholder tokens before exposure.
///
/// The production implementation is the WS5-06 tokenization service; this seam
/// keeps the context store host-testable and decoupled from it.
pub trait ContextTokenizer {
    /// Return `text` with any PII replaced by placeholder tokens.
    fn tokenize(&self, text: &str) -> String;
}

/// One opted-in document as exposed to an agent, with its title tokenized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposedDocument {
    /// The document's stable id (not free text — never tokenized).
    pub id: String,
    /// The tokenized title.
    pub title: String,
}

/// A tokenized, opt-in-filtered snapshot of personal context that is safe to
/// hand to an agent (WS16-05.4).
///
/// Preference *keys* and document *ids* are structural identifiers and are left
/// intact; every free-text value (preference values, document titles, history
/// summaries) is tokenized. Only documents the user opted in are included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposedContext {
    /// Preferences with tokenized values, in key order.
    pub preferences: BTreeMap<String, String>,
    /// Opted-in documents with tokenized titles, in id order.
    pub documents: Vec<ExposedDocument>,
    /// History summaries, tokenized, in insertion order.
    pub history: Vec<String>,
}

/// Produce the tokenized, opt-in-filtered view of `store` for agent exposure
/// (WS16-05.4).
///
/// Every free-text value passes through `tokenizer`; documents that the user has
/// not opted into are omitted entirely.
#[must_use]
pub fn expose_for_agent<T: ContextTokenizer + ?Sized>(
    store: &PersonalContextStore,
    tokenizer: &T,
) -> ExposedContext {
    let preferences = store
        .preferences()
        .map(|(key, value)| (key.to_owned(), tokenizer.tokenize(value)))
        .collect();

    let documents = store
        .included_documents()
        .map(|doc| ExposedDocument {
            id: doc.id.clone(),
            title: tokenizer.tokenize(&doc.title),
        })
        .collect();

    let history = store
        .history()
        .iter()
        .map(|entry| tokenizer.tokenize(&entry.summary))
        .collect();

    ExposedContext {
        preferences,
        documents,
        history,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HistoryEntry, OptInDocument};

    /// A stand-in for the WS5-06 service: replaces every run of ASCII digits
    /// with a fixed placeholder, so a test can assert PII (here, digits) never
    /// reaches the exposed view.
    struct DigitScrubber;

    impl ContextTokenizer for DigitScrubber {
        fn tokenize(&self, text: &str) -> String {
            let mut out = String::with_capacity(text.len());
            let mut in_digits = false;
            for ch in text.chars() {
                if ch.is_ascii_digit() {
                    if !in_digits {
                        out.push_str("[TOK]");
                        in_digits = true;
                    }
                } else {
                    out.push(ch);
                    in_digits = false;
                }
            }
            out
        }
    }

    fn store_with_pii() -> PersonalContextStore {
        let mut store = PersonalContextStore::new();
        assert_eq!(store.set_preference("phone", "call 5551234"), Ok(()));
        assert_eq!(store.set_preference("theme", "dark"), Ok(()));
        assert_eq!(
            store.add_document(OptInDocument::new("doc1", "Invoice 4567", true)),
            Ok(())
        );
        assert_eq!(
            store.add_document(OptInDocument::new("doc2", "Secret 9999", false)),
            Ok(())
        );
        store.record(HistoryEntry::new(1, "SSN 078051120 mentioned"));
        store
    }

    #[test]
    fn exposed_view_tokenizes_every_free_text_value() {
        let store = store_with_pii();
        let exposed = expose_for_agent(&store, &DigitScrubber);

        // Preference values are tokenized; keys are untouched.
        assert_eq!(
            exposed.preferences.get("phone").map(String::as_str),
            Some("call [TOK]")
        );
        assert_eq!(
            exposed.preferences.get("theme").map(String::as_str),
            Some("dark")
        );
        // History summaries are tokenized.
        assert_eq!(exposed.history, vec!["SSN [TOK] mentioned".to_owned()]);
    }

    #[test]
    fn only_opted_in_documents_are_exposed_and_titles_tokenized() {
        let store = store_with_pii();
        let exposed = expose_for_agent(&store, &DigitScrubber);

        // doc2 is not opted in → absent; doc1 present with tokenized title.
        assert_eq!(exposed.documents.len(), 1);
        assert_eq!(
            exposed.documents.first(),
            Some(&ExposedDocument {
                id: "doc1".to_owned(),
                title: "Invoice [TOK]".to_owned(),
            })
        );
    }

    #[test]
    fn no_raw_digit_pii_survives_into_the_exposed_view() {
        let store = store_with_pii();
        let exposed = expose_for_agent(&store, &DigitScrubber);

        let leaked = exposed
            .preferences
            .values()
            .chain(exposed.documents.iter().map(|d| &d.title))
            .chain(exposed.history.iter())
            .any(|value| value.chars().any(|c| c.is_ascii_digit()));
        assert!(!leaked);
    }

    #[test]
    fn an_empty_store_exposes_nothing() {
        let store = PersonalContextStore::new();
        let exposed = expose_for_agent(&store, &DigitScrubber);
        assert!(exposed.preferences.is_empty());
        assert!(exposed.documents.is_empty());
        assert!(exposed.history.is_empty());
    }
}
