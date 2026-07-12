//! One-click export and erasure of personal context (WS16-05.9/.10).
//!
//! The user owns their personal context, so two operations must be trivial and
//! total:
//!
//! - **Export** ([`export_context`]) — serialize the *entire* store into one
//!   portable blob the user can save or move to another device, with
//!   [`import_context`] to restore it. Nothing is left behind or omitted.
//! - **Erasure** ([`delete_all_context`]) — wipe every preference, document, and
//!   history entry in one action, returning a [`DeletionReceipt`] that proves
//!   the store is empty afterwards.
//!
//! Export uses the crate-canonical postcard encoding ([`nexacore_types::wire`]);
//! an exported blob captures every preference, document (opt-in state included),
//! and history entry.

use std::vec::Vec;

use nexacore_types::wire::{decode_canonical, encode_canonical};

use crate::store::PersonalContextStore;

/// Why exporting the personal context failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExportError {
    /// The store could not be canonically encoded (a bug or out-of-memory).
    #[error("failed to encode the personal context for export")]
    Encode,
}

/// Why importing a personal-context blob failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// The bytes did not decode as a personal-context store.
    #[error("failed to decode the personal-context export")]
    Decode,
}

/// Export the entire personal context to one portable blob (WS16-05.9).
///
/// The blob captures every preference, document (with its opt-in state), and
/// history entry — a complete, one-click snapshot the user can keep or migrate.
///
/// # Errors
///
/// Returns [`ExportError::Encode`] if the store cannot be canonically encoded.
pub fn export_context(store: &PersonalContextStore) -> Result<Vec<u8>, ExportError> {
    encode_canonical(store).map_err(|_| ExportError::Encode)
}

/// Restore a personal-context store from a blob produced by [`export_context`]
/// (WS16-05.9).
///
/// # Errors
///
/// Returns [`ImportError::Decode`] if `bytes` is not a valid export.
pub fn import_context(bytes: &[u8]) -> Result<PersonalContextStore, ImportError> {
    decode_canonical(bytes).map_err(|_| ImportError::Decode)
}

/// Verifiable evidence that a one-click deletion wiped the store (WS16-05.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeletionReceipt {
    /// How many entries (preferences + documents + history) were removed.
    pub entries_removed: usize,
    /// Whether the store holds nothing after the deletion. Always `true` for a
    /// successful erasure — the caller can assert on it as proof.
    pub is_empty_after: bool,
}

/// Erase all personal context in one action (WS16-05.10).
///
/// Wipes every preference, document, and history entry and returns a
/// [`DeletionReceipt`] recording how much was removed and confirming the store
/// is empty afterwards — so a UI can show the user verifiable proof that a
/// one-click "delete everything" left nothing behind.
pub fn delete_all_context(store: &mut PersonalContextStore) -> DeletionReceipt {
    let entries_removed = store.len();
    store.clear();
    DeletionReceipt {
        entries_removed,
        is_empty_after: store.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HistoryEntry, OptInDocument};

    fn populated() -> PersonalContextStore {
        let mut store = PersonalContextStore::new();
        assert_eq!(store.set_preference("theme", "dark"), Ok(()));
        assert_eq!(
            store.add_document(OptInDocument::new("doc1", "Notes", true)),
            Ok(())
        );
        assert_eq!(
            store.add_document(OptInDocument::new("doc2", "Draft", false)),
            Ok(())
        );
        store.record(HistoryEntry::new(7, "asked for a summary"));
        store
    }

    #[test]
    fn export_then_import_restores_the_whole_store() {
        let store = populated();
        let blob = export_context(&store);
        assert!(blob.is_ok());
        let Ok(blob) = blob else { return };
        // One-click completeness: the restored store equals the original,
        // including the non-opted-in document and its opt-in flag.
        assert_eq!(import_context(&blob), Ok(store));
    }

    #[test]
    fn an_empty_store_exports_and_reimports() {
        let store = PersonalContextStore::new();
        let blob = export_context(&store);
        assert!(blob.is_ok());
        let Ok(blob) = blob else { return };
        assert_eq!(import_context(&blob), Ok(PersonalContextStore::new()));
    }

    #[test]
    fn importing_garbage_is_rejected() {
        // A trailing byte past a valid encoding, or arbitrary bytes, must not
        // silently decode into a partial store.
        assert_eq!(
            import_context(&[0xFF, 0xFF, 0xFF, 0xFF]),
            Err(ImportError::Decode)
        );
    }

    #[test]
    fn delete_all_wipes_everything_with_a_verifiable_receipt() {
        let mut store = populated();
        let removed = store.len();
        let receipt = delete_all_context(&mut store);
        // The receipt is verifiable proof: it removed everything and the store
        // is provably empty afterwards.
        assert_eq!(
            receipt,
            DeletionReceipt {
                entries_removed: removed,
                is_empty_after: true,
            }
        );
        assert!(store.is_empty());
        assert_eq!(store.included_documents().count(), 0);
    }

    #[test]
    fn after_deletion_an_export_holds_nothing() {
        let mut store = populated();
        let _ = delete_all_context(&mut store);
        // Total erasure: what remains exports identically to an empty store.
        assert_eq!(
            export_context(&store),
            export_context(&PersonalContextStore::new())
        );
    }

    #[test]
    fn deleting_an_already_empty_store_removes_nothing() {
        let mut store = PersonalContextStore::new();
        let receipt = delete_all_context(&mut store);
        assert_eq!(
            receipt,
            DeletionReceipt {
                entries_removed: 0,
                is_empty_after: true,
            }
        );
    }
}
