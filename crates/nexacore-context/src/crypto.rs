//! Encryption at rest for the personal-context store (WS16-05.3).
//!
//! The personal-context store lives on the device; when it is persisted it MUST
//! be encrypted at rest. This module seals the store's canonical encoding under
//! authenticated encryption so that a stolen disk image reveals nothing without
//! the key, and any tampering with the ciphertext is detected on open.
//!
//! The intended production key is a per-volume key managed by the disk-at-rest
//! encryption layer (WS3-07) / the TEE sealed-key API; this module is agnostic
//! to where the key comes from — it takes a [`NexaCoreAeadKey`]. No cryptographic
//! primitive is implemented here: sealing uses `nexacore-crypto`'s vetted
//! ChaCha20-Poly1305 ([`nexacore_crypto::aead`]) and the store is encoded with
//! the crate-canonical postcard encoding ([`nexacore_types::wire`]).

use nexacore_crypto::aead::{self, NexaCoreAeadKey, NexaCoreCiphertext, NexaCoreNonce};
use nexacore_types::wire::{decode_canonical, encode_canonical};
use serde::{Deserialize, Serialize};

use crate::store::PersonalContextStore;

/// Associated data bound into every sealed context blob (domain separation).
///
/// Binding a fixed domain string as AEAD associated data means a ciphertext
/// produced for some other purpose under the same key cannot be opened as a
/// context blob.
pub const AT_REST_AAD: &[u8] = b"nexacore-context/at-rest/v1";

/// A sealed personal-context store: the AEAD nonce plus the ciphertext.
///
/// The nonce is public (it must be, to open the blob) and is carried alongside
/// the ciphertext. It derives `serde` so the sealed blob itself can be persisted
/// through the crate-canonical encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedContext {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl SealedContext {
    /// The raw ciphertext bytes (opaque without the key).
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Why sealing the context store failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// The store could not be canonically encoded (a bug or out-of-memory).
    #[error("failed to encode the context store for sealing")]
    Encode,
    /// The authenticated encryption step failed.
    #[error("failed to encrypt the context store")]
    Encrypt,
}

/// Why opening a sealed context store failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// Decryption failed — wrong key, wrong associated data, or tampering. The
    /// cause is deliberately opaque so it leaks nothing to an adversary.
    #[error("failed to decrypt the sealed context (wrong key or tampered)")]
    Decrypt,
    /// The decrypted bytes did not decode as a context store.
    #[error("failed to decode the decrypted context store")]
    Decode,
}

/// Seal `store` at rest under `key` and `nonce` (WS16-05.3).
///
/// The caller supplies a fresh, never-reused `nonce` for this key. The store is
/// canonically encoded, then encrypted with ChaCha20-Poly1305 binding
/// [`AT_REST_AAD`]. The nonce is returned inside the [`SealedContext`].
///
/// # Errors
///
/// Returns [`SealError`] if encoding or encryption fails.
pub fn seal_context(
    store: &PersonalContextStore,
    key: &NexaCoreAeadKey,
    nonce: NexaCoreNonce,
) -> Result<SealedContext, SealError> {
    let plaintext = encode_canonical(store).map_err(|_| SealError::Encode)?;
    let ciphertext =
        aead::seal(key, &nonce, AT_REST_AAD, &plaintext).map_err(|_| SealError::Encrypt)?;
    Ok(SealedContext {
        nonce: *nonce.as_bytes(),
        ciphertext: ciphertext.as_bytes().to_vec(),
    })
}

/// Open a [`SealedContext`] back into a [`PersonalContextStore`] (WS16-05.3).
///
/// # Errors
///
/// Returns [`OpenError::Decrypt`] on a wrong key or any tampering, and
/// [`OpenError::Decode`] if the decrypted bytes are not a valid store.
pub fn open_context(
    sealed: &SealedContext,
    key: &NexaCoreAeadKey,
) -> Result<PersonalContextStore, OpenError> {
    let nonce = NexaCoreNonce::from_bytes(sealed.nonce);
    let ciphertext = NexaCoreCiphertext::from_bytes(sealed.ciphertext.clone());
    let plaintext =
        aead::open(key, &nonce, AT_REST_AAD, &ciphertext).map_err(|_| OpenError::Decrypt)?;
    decode_canonical(&plaintext).map_err(|_| OpenError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HistoryEntry, OptInDocument};

    fn sample_store() -> PersonalContextStore {
        let mut store = PersonalContextStore::new();
        assert_eq!(store.set_preference("theme", "dark"), Ok(()));
        assert_eq!(
            store.add_document(OptInDocument::new("doc1", "Notes", true)),
            Ok(())
        );
        store.record(HistoryEntry::new(42, "asked about the weather"));
        store
    }

    fn key(seed: u8) -> NexaCoreAeadKey {
        NexaCoreAeadKey::from_bytes([seed; 32])
    }

    fn nonce(seed: u8) -> NexaCoreNonce {
        NexaCoreNonce::from_bytes([seed; 12])
    }

    #[test]
    fn seal_then_open_round_trips_the_store() {
        let store = sample_store();
        let sealed = seal_context(&store, &key(1), nonce(2));
        assert!(sealed.is_ok());
        let Ok(sealed) = sealed else { return };
        assert_eq!(open_context(&sealed, &key(1)), Ok(store));
    }

    #[test]
    fn an_empty_store_round_trips() {
        let store = PersonalContextStore::new();
        let sealed = seal_context(&store, &key(1), nonce(2));
        assert!(sealed.is_ok());
        let Ok(sealed) = sealed else { return };
        assert_eq!(open_context(&sealed, &key(1)), Ok(store));
    }

    #[test]
    fn a_wrong_key_fails_to_open() {
        let store = sample_store();
        let sealed = seal_context(&store, &key(1), nonce(2));
        assert!(sealed.is_ok());
        let Ok(sealed) = sealed else { return };
        // A different key must not decrypt — fail-closed, no plaintext leak.
        assert_eq!(open_context(&sealed, &key(9)), Err(OpenError::Decrypt));
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let store = sample_store();
        let sealed = seal_context(&store, &key(1), nonce(2));
        assert!(sealed.is_ok());
        let Ok(mut sealed) = sealed else { return };
        // Flip a ciphertext bit → AEAD tag mismatch on open.
        if let Some(first) = sealed.ciphertext.first_mut() {
            *first ^= 0x01;
        }
        assert_eq!(open_context(&sealed, &key(1)), Err(OpenError::Decrypt));
    }

    #[test]
    fn the_sealed_blob_hides_the_plaintext() {
        let store = sample_store();
        let sealed = seal_context(&store, &key(1), nonce(2));
        assert!(sealed.is_ok());
        let Ok(sealed) = sealed else { return };
        // The cleartext preference value must not appear in the ciphertext.
        assert!(!sealed.ciphertext().windows(4).any(|w| w == b"dark"));
    }
}
