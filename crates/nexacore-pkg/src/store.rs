//! Content-addressed package store (WS9-02.2).
//!
//! Packages are addressed by the `BLAKE3` (domain-separated) hash of their
//! bytes: [`content_address`]. A [`ContentStore`] maps each address to its
//! content, so identical artifacts deduplicate to one entry and any byte of
//! corruption changes the address — [`verify`] re-derives the address from
//! content to detect tampering, and [`ContentStore::put_verified`] is the
//! admission gate that refuses a tampered artifact (WS9-02.8).
//!
//! This is the in-memory store; a filesystem-backed store with the same
//! interface is a thin layer added at deploy time. The addressing and integrity
//! logic — the part that matters for correctness and security — lives here.

use std::collections::HashMap;

use nexacore_crypto::hash::domain_separated_hash;

use crate::manifest::CONTENT_HASH_LEN;

/// A package content address: the [`content_address`] of its bytes.
pub type ContentAddress = [u8; CONTENT_HASH_LEN];

/// Hash domain for package content addressing.
const CONTENT_DOMAIN: &str = "nexacore-pkg::content::v1";

/// The content address of `content`: its domain-separated `BLAKE3` hash.
///
/// This is the value that populates a manifest's
/// [`content_hash`](crate::manifest::PackageManifest::content_hash).
#[must_use]
pub fn content_address(content: &[u8]) -> ContentAddress {
    domain_separated_hash(CONTENT_DOMAIN, content)
}

/// Whether `content` actually hashes to `address` (an integrity / tamper check).
#[must_use]
pub fn verify(address: &ContentAddress, content: &[u8]) -> bool {
    &content_address(content) == address
}

/// A candidate artifact's bytes did not hash to the address a manifest declared
/// — the package is tampered and is refused admission (WS9-02.8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("integrity check failed: content does not match the declared address")]
pub struct IntegrityError {
    /// The address the manifest declared (its `content_hash`).
    pub declared: ContentAddress,
    /// The address the provided bytes actually hash to.
    pub actual: ContentAddress,
}

/// An in-memory content-addressed store (WS9-02.2).
#[derive(Debug, Clone, Default)]
pub struct ContentStore {
    blobs: HashMap<ContentAddress, Vec<u8>>,
}

impl ContentStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `content`, returning its content address. Storing identical content
    /// again is idempotent (one entry).
    pub fn put(&mut self, content: Vec<u8>) -> ContentAddress {
        let address = content_address(&content);
        self.blobs.entry(address).or_insert(content);
        address
    }

    /// Admit `content` only if it hashes to `expected` — a manifest's declared
    /// [`content_hash`](crate::manifest::PackageManifest::content_hash) (WS9-02.8).
    ///
    /// This is the trust boundary for untrusted artifacts (e.g. a network
    /// fetch, WS9-02.10): a tampered blob whose bytes no longer match the
    /// declared address is refused and never enters the store.
    ///
    /// # Errors
    /// [`IntegrityError`] if `content` does not hash to `expected`.
    pub fn put_verified(
        &mut self,
        expected: &ContentAddress,
        content: Vec<u8>,
    ) -> Result<ContentAddress, IntegrityError> {
        let actual = content_address(&content);
        if &actual != expected {
            return Err(IntegrityError {
                declared: *expected,
                actual,
            });
        }
        self.blobs.entry(actual).or_insert(content);
        Ok(actual)
    }

    /// The content stored at `address`, if any.
    #[must_use]
    pub fn get(&self, address: &ContentAddress) -> Option<&[u8]> {
        self.blobs.get(address).map(Vec::as_slice)
    }

    /// Whether `address` is present.
    #[must_use]
    pub fn contains(&self, address: &ContentAddress) -> bool {
        self.blobs.contains_key(address)
    }

    /// Remove the content at `address`. Returns whether it was present.
    pub fn remove(&mut self, address: &ContentAddress) -> bool {
        self.blobs.remove(address).is_some()
    }

    /// The number of distinct blobs stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn address_is_deterministic_and_content_sensitive() {
        assert_eq!(content_address(b"hello"), content_address(b"hello"));
        assert_ne!(content_address(b"hello"), content_address(b"world"));
    }

    #[test]
    fn put_returns_address_and_get_round_trips() {
        let mut store = ContentStore::new();
        let addr = store.put(b"package-bytes".to_vec());
        assert_eq!(addr, content_address(b"package-bytes"));
        assert_eq!(store.get(&addr), Some(b"package-bytes".as_slice()));
        assert!(store.contains(&addr));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn identical_content_deduplicates() {
        let mut store = ContentStore::new();
        let a = store.put(b"same".to_vec());
        let b = store.put(b"same".to_vec());
        assert_eq!(a, b);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn distinct_content_gets_distinct_addresses() {
        let mut store = ContentStore::new();
        let a = store.put(b"one".to_vec());
        let b = store.put(b"two".to_vec());
        assert_ne!(a, b);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn unknown_address_is_absent() {
        let store = ContentStore::new();
        let addr = content_address(b"never-stored");
        assert_eq!(store.get(&addr), None);
        assert!(!store.contains(&addr));
    }

    #[test]
    fn remove_evicts_content() {
        let mut store = ContentStore::new();
        let addr = store.put(b"temp".to_vec());
        assert!(store.remove(&addr));
        assert!(!store.remove(&addr));
        assert!(store.is_empty());
    }

    #[test]
    fn verify_detects_tampering() {
        let addr = content_address(b"trusted");
        assert!(verify(&addr, b"trusted"));
        assert!(!verify(&addr, b"tampered"));
    }

    #[test]
    fn put_verified_admits_matching_content() {
        let mut store = ContentStore::new();
        let expected = content_address(b"trusted");
        let addr = store
            .put_verified(&expected, b"trusted".to_vec())
            .expect("matches");
        assert_eq!(addr, expected);
        assert!(store.contains(&expected));
    }

    #[test]
    fn put_verified_rejects_tampered_content() {
        let mut store = ContentStore::new();
        let expected = content_address(b"trusted");
        // The declared address is for "trusted" but tampered bytes are supplied.
        let err = store
            .put_verified(&expected, b"tampered".to_vec())
            .expect_err("must reject");
        assert_eq!(err.declared, expected);
        assert_eq!(err.actual, content_address(b"tampered"));
        // Nothing was admitted to the store.
        assert!(store.is_empty());
    }
}
