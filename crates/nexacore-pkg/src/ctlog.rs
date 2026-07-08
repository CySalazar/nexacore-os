//! Transparency-log (CT-style) Merkle inclusion proofs (WS9-02.4).
//!
//! A package's manifest must be logged in an append-only transparency log before
//! it is trusted. This module verifies an **inclusion proof**: that a given leaf
//! sits in a Merkle tree with a known root, using the RFC-6962 audit-path
//! algorithm ([`verify_inclusion`]). [`MerkleTree`] builds a tree and emits
//! proofs so the verifier is exercised against a real prover (writer/verifier
//! co-validation).
//!
//! The tree hashing uses the same domain-separated `BLAKE3` primitive as the
//! package content store (WS9-02.2), so the transparency log is consistent with
//! NexaCore's content addressing. A bridge to a Google-CT (RFC-6962) log would
//! swap in `SHA-256`; the audit-path structure is identical.

use nexacore_crypto::hash::domain_separated_hash;

/// A transparency-log node hash (32-byte `BLAKE3`).
pub type Hash = [u8; 32];

/// Hash domain for leaf hashing (RFC-6962's `0x00` prefix).
const LEAF_DOMAIN: &str = "nexacore-pkg::ctlog::leaf::v1";
/// Hash domain for internal-node hashing (RFC-6962's `0x01` prefix).
const NODE_DOMAIN: &str = "nexacore-pkg::ctlog::node::v1";

/// The leaf hash of a log entry (`MTH` of a single leaf).
#[must_use]
pub fn leaf_hash(entry: &[u8]) -> Hash {
    domain_separated_hash(LEAF_DOMAIN, entry)
}

/// The internal-node hash of two children.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    domain_separated_hash(NODE_DOMAIN, &buf)
}

/// Why an inclusion-proof check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CtError {
    /// The leaf index is not within the tree.
    #[error("leaf index {index} is out of range for tree size {size}")]
    IndexOutOfRange {
        /// The offending index.
        index: u64,
        /// The tree size.
        size: u64,
    },
    /// The audit path has more hashes than the tree needs.
    #[error("audit path is too long for the tree")]
    ProofTooLong,
    /// The audit path has fewer hashes than the tree needs.
    #[error("audit path is too short for the tree")]
    ProofTooShort,
    /// The recomputed root did not match the expected root (not included).
    #[error("recomputed root does not match the expected root")]
    RootMismatch,
}

/// Recompute the tree root from an inclusion proof (RFC-6962 §2.1.1).
fn root_from_proof(
    leaf: Hash,
    index: u64,
    tree_size: u64,
    audit_path: &[Hash],
) -> Result<Hash, CtError> {
    if index >= tree_size {
        return Err(CtError::IndexOutOfRange {
            index,
            size: tree_size,
        });
    }
    let mut fnode = index;
    let mut snode = tree_size - 1;
    let mut r = leaf;
    for p in audit_path {
        if snode == 0 {
            return Err(CtError::ProofTooLong);
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            while fnode & 1 == 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    if snode != 0 {
        return Err(CtError::ProofTooShort);
    }
    Ok(r)
}

/// Verify that `leaf` is included at `index` in a tree of `tree_size` leaves with
/// the given `root`, using `audit_path` (WS9-02.4).
///
/// # Errors
/// [`CtError::IndexOutOfRange`], [`CtError::ProofTooLong`],
/// [`CtError::ProofTooShort`], or [`CtError::RootMismatch`] if the proof does not
/// reconstruct `root`.
pub fn verify_inclusion(
    leaf: Hash,
    index: u64,
    tree_size: u64,
    audit_path: &[Hash],
    root: &Hash,
) -> Result<(), CtError> {
    let computed = root_from_proof(leaf, index, tree_size, audit_path)?;
    if &computed == root {
        Ok(())
    } else {
        Err(CtError::RootMismatch)
    }
}

/// An inclusion proof for one leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// The leaf's index in the log.
    pub leaf_index: u64,
    /// The number of leaves in the tree.
    pub tree_size: u64,
    /// The sibling hashes bottom-to-top.
    pub audit_path: Vec<Hash>,
}

/// The largest power of two strictly less than `n` (for `n >= 2`).
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// The RFC-6962 Merkle Tree Hash of already-hashed `leaves`.
fn mth(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => domain_separated_hash(LEAF_DOMAIN, b""),
        [only] => *only,
        _ => {
            let (left, right) = leaves.split_at(split_point(leaves.len()));
            node_hash(&mth(left), &mth(right))
        }
    }
}

/// The RFC-6962 audit path for leaf `m` within `leaves`.
fn audit_path(m: usize, leaves: &[Hash]) -> Vec<Hash> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let k = split_point(leaves.len());
    let (left, right) = leaves.split_at(k);
    if m < k {
        let mut p = audit_path(m, left);
        p.push(mth(right));
        p
    } else {
        let mut p = audit_path(m - k, right);
        p.push(mth(left));
        p
    }
}

/// An append-only Merkle tree over log entries (the prover side, WS9-02.4).
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    leaves: Vec<Hash>,
}

impl MerkleTree {
    /// Build a tree from raw log entries.
    #[must_use]
    pub fn from_entries(entries: &[&[u8]]) -> Self {
        Self {
            leaves: entries.iter().map(|e| leaf_hash(e)).collect(),
        }
    }

    /// The number of leaves.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// The current Merkle root.
    #[must_use]
    pub fn root(&self) -> Hash {
        mth(&self.leaves)
    }

    /// The inclusion proof for the leaf at `index`, if in range.
    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }
        Some(InclusionProof {
            leaf_index: index as u64,
            tree_size: self.size(),
            audit_path: audit_path(index, &self.leaves),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]
    use super::*;

    fn entries(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![b'a' + i as u8]).collect()
    }

    #[test]
    fn every_leaf_verifies_against_the_root() {
        for size in 1..=9usize {
            let owned = entries(size);
            let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
            let tree = MerkleTree::from_entries(&refs);
            let root = tree.root();
            for (i, r) in refs.iter().enumerate() {
                let proof = tree.inclusion_proof(i).expect("in range");
                assert_eq!(
                    verify_inclusion(
                        leaf_hash(r),
                        proof.leaf_index,
                        proof.tree_size,
                        &proof.audit_path,
                        &root,
                    ),
                    Ok(()),
                    "size {size} index {i}"
                );
            }
        }
    }

    #[test]
    fn a_tampered_root_is_rejected() {
        let owned = entries(6);
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let tree = MerkleTree::from_entries(&refs);
        let mut root = tree.root();
        root[0] ^= 0xFF; // corrupt the root
        let proof = tree.inclusion_proof(3).unwrap();
        assert_eq!(
            verify_inclusion(leaf_hash(refs[3]), 3, 6, &proof.audit_path, &root),
            Err(CtError::RootMismatch)
        );
    }

    #[test]
    fn wrong_leaf_or_index_does_not_verify() {
        let owned = entries(6);
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        let tree = MerkleTree::from_entries(&refs);
        let root = tree.root();
        let proof = tree.inclusion_proof(3).unwrap();
        // A different leaf with the same path recomputes a different root.
        assert_eq!(
            verify_inclusion(leaf_hash(b"z"), 3, 6, &proof.audit_path, &root),
            Err(CtError::RootMismatch)
        );
        // Index beyond the tree is rejected structurally.
        assert_eq!(
            verify_inclusion(leaf_hash(refs[0]), 6, 6, &proof.audit_path, &root),
            Err(CtError::IndexOutOfRange { index: 6, size: 6 })
        );
    }

    #[test]
    fn single_leaf_tree_has_empty_path() {
        let tree = MerkleTree::from_entries(&[b"solo"]);
        let proof = tree.inclusion_proof(0).unwrap();
        assert!(proof.audit_path.is_empty());
        assert_eq!(tree.root(), leaf_hash(b"solo"));
        assert_eq!(
            verify_inclusion(leaf_hash(b"solo"), 0, 1, &[], &tree.root()),
            Ok(())
        );
    }
}
