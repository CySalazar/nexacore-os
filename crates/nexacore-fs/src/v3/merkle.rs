//! BLAKE3-keyed Merkle integrity tree (WS3-01.7).
//!
//! Every data block is hashed to a leaf with a volume-keyed BLAKE3; pairs of
//! nodes are folded up to a single root that is stored in the committed
//! superblock ([`super::superblock::SuperblockV3::merkle_root`]). Any change to
//! any block changes the root, so corruption — including a per-block rollback —
//! is detected on the read path. [`merkle_proof`] / [`verify_proof`] let the
//! read path authenticate a single block against the committed root without
//! rehashing the whole volume.
//!
//! Keying defends against an attacker who can write blocks but not learn the
//! volume key: they cannot forge a leaf/root that verifies.

use alloc::vec::Vec;

/// Length of a Merkle hash / the keying key.
pub const HASH_LEN: usize = 32;

/// A Merkle node / leaf hash.
pub type Hash = [u8; HASH_LEN];

/// The BLAKE3 keying key (derived from the volume key).
pub type MerkleKey = [u8; HASH_LEN];

/// Hash a data block into a keyed leaf.
#[must_use]
pub fn leaf_hash(key: &MerkleKey, block: &[u8]) -> Hash {
    *blake3::keyed_hash(key, block).as_bytes()
}

/// Hash two child nodes into their parent.
#[must_use]
pub fn node_hash(key: &MerkleKey, left: &Hash, right: &Hash) -> Hash {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Root of an empty tree (no leaves) — a fixed keyed sentinel.
#[must_use]
pub fn empty_root(key: &MerkleKey) -> Hash {
    *blake3::keyed_hash(key, b"NCFS-v3-empty-merkle").as_bytes()
}

/// Fold one level of nodes into the next (odd node paired with itself).
fn fold_level(key: &MerkleKey, level: &[Hash]) -> Vec<Hash> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    for pair in level.chunks(2) {
        let left = pair.first().copied().unwrap_or_default();
        let right = pair.get(1).copied().unwrap_or(left);
        next.push(node_hash(key, &left, &right));
    }
    next
}

/// Compute the Merkle root over the leaf hashes.
#[must_use]
pub fn merkle_root(key: &MerkleKey, leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return empty_root(key);
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = fold_level(key, &level);
    }
    level.first().copied().unwrap_or_else(|| empty_root(key))
}

/// Compute the Merkle root directly over the data blocks.
#[must_use]
pub fn root_over_blocks(key: &MerkleKey, blocks: &[&[u8]]) -> Hash {
    let leaves: Vec<Hash> = blocks.iter().map(|b| leaf_hash(key, b)).collect();
    merkle_root(key, &leaves)
}

/// Produce the sibling-path proof authenticating leaf `index` against the root.
/// `None` if `index` is out of range.
#[must_use]
pub fn merkle_proof(key: &MerkleKey, leaves: &[Hash], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    let mut idx = index;
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        // Odd tail with no sibling pairs with itself.
        let self_hash = level.get(idx).copied().unwrap_or_default();
        let sib = level.get(sibling).copied().unwrap_or(self_hash);
        proof.push(sib);
        level = fold_level(key, &level);
        idx /= 2;
    }
    Some(proof)
}

/// Verify a leaf against `root` using its sibling-path `proof`.
#[must_use]
pub fn verify_proof(
    key: &MerkleKey,
    root: &Hash,
    leaf: &Hash,
    index: usize,
    proof: &[Hash],
) -> bool {
    let mut h = *leaf;
    let mut idx = index;
    for sib in proof {
        h = if idx % 2 == 0 {
            node_hash(key, &h, sib)
        } else {
            node_hash(key, sib, &h)
        };
        idx /= 2;
    }
    &h == root
}

#[cfg(test)]
mod tests {
    // Test fixtures cast loop indices to bytes and forward slices.
    #![allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::redundant_closure_for_method_calls
    )]
    use super::*;

    const KEY: MerkleKey = [0x5A; HASH_LEN];

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&KEY, &[i as u8; 64])).collect()
    }

    #[test]
    fn root_is_stable_and_keyed() {
        let l = leaves(5);
        assert_eq!(
            merkle_root(&KEY, &l),
            merkle_root(&KEY, &l),
            "deterministic"
        );
        // A different key yields a different root.
        let other: MerkleKey = [0x01; HASH_LEN];
        assert_ne!(merkle_root(&KEY, &l), merkle_root(&other, &l));
    }

    #[test]
    fn empty_tree_has_sentinel_root() {
        assert_eq!(merkle_root(&KEY, &[]), empty_root(&KEY));
    }

    #[test]
    fn changing_a_block_changes_the_root() {
        let blocks_a: Vec<[u8; 64]> = (0..4).map(|i| [i as u8; 64]).collect();
        let refs_a: Vec<&[u8]> = blocks_a.iter().map(|b| b.as_slice()).collect();
        let root_a = root_over_blocks(&KEY, &refs_a);

        let mut blocks_b = blocks_a.clone();
        blocks_b[2][0] ^= 0x01; // flip one bit in block 2
        let refs_b: Vec<&[u8]> = blocks_b.iter().map(|b| b.as_slice()).collect();
        let root_b = root_over_blocks(&KEY, &refs_b);

        assert_ne!(root_a, root_b, "corruption must change the root");
    }

    #[test]
    fn proof_verifies_each_leaf() {
        let l = leaves(6);
        let root = merkle_root(&KEY, &l);
        for (i, leaf) in l.iter().enumerate() {
            let proof = merkle_proof(&KEY, &l, i).unwrap();
            assert!(verify_proof(&KEY, &root, leaf, i, &proof), "leaf {i}");
        }
    }

    #[test]
    fn proof_rejects_tampered_leaf() {
        let l = leaves(8);
        let root = merkle_root(&KEY, &l);
        let proof = merkle_proof(&KEY, &l, 3).unwrap();
        let mut bad = l[3];
        bad[0] ^= 0xFF;
        assert!(!verify_proof(&KEY, &root, &bad, 3, &proof));
    }

    #[test]
    fn proof_out_of_range_is_none() {
        let l = leaves(3);
        assert!(merkle_proof(&KEY, &l, 3).is_none());
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let l = leaves(1);
        assert_eq!(merkle_root(&KEY, &l), l[0]);
        let proof = merkle_proof(&KEY, &l, 0).unwrap();
        assert!(proof.is_empty(), "a single leaf needs no siblings");
        assert!(verify_proof(&KEY, &l[0], &l[0], 0, &proof));
    }

    /// Corruption-injection + per-block rollback detection over a block device
    /// (WS3-01.14): the mandatory read-path Merkle check must catch both a
    /// flipped byte and a block silently reverted to a stale version.
    #[test]
    fn block_corruption_and_rollback_are_detected() {
        use super::super::{
            BLOCK_SIZE,
            blockdev::{BlockDevice, MemBlockDevice},
            zero_block,
        };

        let key: MerkleKey = [0x33; HASH_LEN];
        let mut dev = MemBlockDevice::new(4);
        let mut originals: Vec<[u8; BLOCK_SIZE]> = Vec::new();
        for i in 0..4u64 {
            let mut b = zero_block();
            b[0] = (i as u8) + 1;
            dev.write_block(i, &b).unwrap();
            originals.push(b);
        }
        let read_all = |dev: &MemBlockDevice| -> Vec<[u8; BLOCK_SIZE]> {
            (0..4u64)
                .map(|i| {
                    let mut b = zero_block();
                    dev.read_block(i, &mut b).unwrap();
                    b
                })
                .collect()
        };

        // Committed root over the pristine blocks.
        let pristine = read_all(&dev);
        let pristine_refs: Vec<&[u8]> = pristine.iter().map(|b| b.as_slice()).collect();
        let committed = root_over_blocks(&key, &pristine_refs);
        assert_eq!(
            root_over_blocks(&key, &pristine_refs),
            committed,
            "baseline"
        );

        // Corruption injection: flip a byte in block 2 → the root changes.
        let mut corrupt = originals[2];
        corrupt[10] ^= 0xFF;
        dev.write_block(2, &corrupt).unwrap();
        let after = read_all(&dev);
        let after_refs: Vec<&[u8]> = after.iter().map(|b| b.as_slice()).collect();
        assert_ne!(
            root_over_blocks(&key, &after_refs),
            committed,
            "byte corruption undetected"
        );

        // A committed-root proof for block 2 verifies the pristine leaf but not
        // the corrupted one (per-block detection).
        let leaves: Vec<Hash> = pristine_refs.iter().map(|b| leaf_hash(&key, b)).collect();
        let proof = merkle_proof(&key, &leaves, 2).unwrap();
        assert!(verify_proof(
            &key,
            &committed,
            &leaf_hash(&key, &originals[2]),
            2,
            &proof
        ));
        assert!(
            !verify_proof(&key, &committed, &leaf_hash(&key, &corrupt), 2, &proof),
            "corrupt leaf must fail its proof"
        );

        // Per-block rollback: restore block 2, then revert block 1 to a stale
        // (zero) version → the root still diverges from the committed one.
        dev.write_block(2, &originals[2]).unwrap();
        dev.write_block(1, &zero_block()).unwrap();
        let rolled = read_all(&dev);
        let rolled_refs: Vec<&[u8]> = rolled.iter().map(|b| b.as_slice()).collect();
        assert_ne!(
            root_over_blocks(&key, &rolled_refs),
            committed,
            "block rollback undetected"
        );
    }
}
