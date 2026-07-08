//! In-memory revocation list with bloom-filter fast path.
//!
//! # Two-tier design
//!
//! Token revocation is a frequent question (every capability use
//! triggers one), so the data structure has two tiers:
//!
//! 1. **Bloom filter** (fast, may produce false positives): a bit array
//!    sized to the expected revocation cardinality. Membership test
//!    is O(k) where k is the number of hash functions.
//! 2. **Authoritative set** (`BTreeSet<CapabilityId>`): consulted only
//!    when the bloom filter says "probably yes", to rule out false
//!    positives. O(log n) lookup.
//!
//! False negatives are impossible (if a token is revoked, the bloom
//! filter always reports "probably yes"). False positives cost an
//! extra log-time set lookup but never accept a revoked token.
//!
//! # Lifecycle
//!
//! Lists are short-lived by design: combined with a 5–15 min TTL on
//! capability tokens, the list never needs to grow unbounded. The
//! roadmap (Phase 2) replaces this in-memory implementation with a
//! `sled`-backed persistent structure that participates in a mesh-
//! wide gossip protocol.

use alloc::{collections::BTreeSet, vec, vec::Vec};

use nexacore_crypto::hash::domain_separated_hash;
use nexacore_types::identity::CapabilityId;

// =============================================================================
// MicroBloom — minimal bloom filter implementation.
// =============================================================================

/// A small in-crate bloom filter.
///
/// We implement this in-tree rather than depending on a third-party
/// crate because (a) every off-the-shelf bloom-filter crate at
/// review time depended on `std` somewhere in its tree, and (b) the
/// implementation is small enough to audit in a single sitting.
///
/// Hashing uses [`nexacore_crypto::hash::domain_separated_hash`] with two
/// distinct domain strings, then derives `k` indices via the
/// Kirsch–Mitzenmacher technique: `idx_i = (h0 + i * h1) mod m`.
#[derive(Clone, Debug)]
struct MicroBloom {
    /// Backing bit array; length is `num_bits / 8` (rounded up).
    bits: Vec<u8>,
    /// Number of bits (= `bits.len() * 8`).
    num_bits: usize,
    /// Number of hash functions.
    num_hashes: u8,
}

impl MicroBloom {
    /// Construct a bloom filter sized for approximately `expected`
    /// elements at a target false-positive rate of ~1%.
    ///
    /// Sizing follows the standard formulas:
    ///   m = -n * ln(p) / (ln 2)^2
    ///   k = (m / n) * ln 2
    /// For `expected = 1024` and `p = 0.01`: m ≈ 9817 bits ≈ 1228 bytes,
    /// k = 7. We round to convenient byte boundaries.
    fn new(expected: usize) -> Self {
        // Floor to at least 64 bits to avoid pathological sizes.
        let n = expected.max(8);
        // Approximate: 10 bits per element (≈1% FP), 7 hashes.
        let num_bits = (n * 10).next_multiple_of(8);
        // `integer_division` allowed: `num_bits` is guaranteed a
        // multiple of 8 by `next_multiple_of` above, so the division
        // is exact.
        #[allow(clippy::integer_division)]
        let num_bytes = num_bits / 8;
        Self {
            bits: vec![0u8; num_bytes],
            num_bits,
            num_hashes: 7,
        }
    }

    /// Compute the two base hashes for an item, returning `(h0, h1)`
    /// as 64-bit truncations of two domain-separated 256-bit digests.
    fn base_hashes(item: &[u8]) -> (u64, u64) {
        let h0 = domain_separated_hash("nexacore-capability::bloom::h0", item);
        let h1 = domain_separated_hash("nexacore-capability::bloom::h1", item);
        let h0_u64 = u64::from_le_bytes([h0[0], h0[1], h0[2], h0[3], h0[4], h0[5], h0[6], h0[7]]);
        let h1_u64 = u64::from_le_bytes([h1[0], h1[1], h1[2], h1[3], h1[4], h1[5], h1[6], h1[7]]);
        (h0_u64, h1_u64)
    }

    /// Compute the `k` bit indices for an item.
    fn indices(&self, item: &[u8]) -> [usize; 8] {
        let (h0, h1) = Self::base_hashes(item);
        // Up to 8 indices; we use exactly `self.num_hashes` of them.
        let mut out = [0usize; 8];
        // `as usize` cast fine: `num_bits` ≤ `usize::MAX` in any realistic
        // configuration; truncation cannot happen at our input sizes.
        let m = self.num_bits as u64;
        for (i, slot) in out.iter_mut().enumerate().take(self.num_hashes as usize) {
            let raw = h0.wrapping_add((i as u64).wrapping_mul(h1));
            #[allow(clippy::cast_possible_truncation)]
            let idx = (raw % m) as usize;
            *slot = idx;
        }
        out
    }

    /// Insert an item into the filter.
    fn insert(&mut self, item: &[u8]) {
        let indices = self.indices(item);
        for &idx in indices.iter().take(self.num_hashes as usize) {
            // `integer_division`/`indexing_slicing` are bounded by the
            // `num_bits` modulus in `indices()` plus the constant
            // factor 8.
            #[allow(clippy::integer_division, clippy::indexing_slicing)]
            {
                let byte = idx / 8;
                let bit = idx % 8;
                self.bits[byte] |= 1 << bit;
            }
        }
    }

    /// Test whether an item *might* be in the filter. False positives
    /// are possible; false negatives are not.
    fn might_contain(&self, item: &[u8]) -> bool {
        let indices = self.indices(item);
        for &idx in indices.iter().take(self.num_hashes as usize) {
            #[allow(clippy::integer_division, clippy::indexing_slicing)]
            {
                let byte = idx / 8;
                let bit = idx % 8;
                if self.bits[byte] & (1 << bit) == 0 {
                    return false;
                }
            }
        }
        true
    }
}

// =============================================================================
// RevocationList
// =============================================================================

/// In-memory list of revoked capability identifiers.
///
/// Combines an in-crate `MicroBloom` fast path with a [`BTreeSet`]
/// for false-positive resolution. Membership testing is O(k) on the
/// bloom path and O(k + log n) when the bloom hits.
#[derive(Clone, Debug)]
pub struct RevocationList {
    bloom: MicroBloom,
    full: BTreeSet<CapabilityId>,
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationList {
    /// Construct an empty revocation list sized for approximately
    /// 1 024 entries before the bloom filter false-positive rate
    /// degrades.
    #[must_use]
    pub fn new() -> Self {
        Self::with_expected_capacity(1024)
    }

    /// Construct with a custom expected cardinality. Use this when
    /// the deployment scale is known (e.g., a tenant with a long
    /// revocation tail).
    #[must_use]
    pub fn with_expected_capacity(expected: usize) -> Self {
        Self {
            bloom: MicroBloom::new(expected),
            full: BTreeSet::new(),
        }
    }

    /// Add `id` to the revocation list.
    ///
    /// If `id` was already present, this is a no-op (`BTreeSet` semantics).
    pub fn revoke(&mut self, id: CapabilityId) {
        self.bloom.insert(id.as_bytes());
        self.full.insert(id);
    }

    /// Test whether `id` is revoked.
    ///
    /// Bloom filter is the fast path; on a hit we consult the
    /// authoritative set to rule out false positives.
    #[must_use]
    pub fn contains(&self, id: &CapabilityId) -> bool {
        if !self.bloom.might_contain(id.as_bytes()) {
            return false;
        }
        // Bloom said "probably". Confirm against the authoritative set.
        self.full.contains(id)
    }

    /// Number of distinct revoked IDs (authoritative count, not bloom).
    #[must_use]
    pub fn len(&self) -> usize {
        self.full.len()
    }

    /// Returns `true` iff the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.full.is_empty()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> CapabilityId {
        CapabilityId::from_bytes([b; 16])
    }

    #[test]
    fn empty_list_contains_nothing() {
        let r = RevocationList::new();
        assert!(!r.contains(&id(1)));
        assert!(r.is_empty());
    }

    #[test]
    fn revoke_then_contains() {
        let mut r = RevocationList::new();
        r.revoke(id(7));
        assert!(r.contains(&id(7)));
        assert!(!r.contains(&id(8)));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn revoke_idempotent() {
        let mut r = RevocationList::new();
        r.revoke(id(1));
        r.revoke(id(1));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn many_revocations_no_false_negatives() {
        // Insert 256 distinct IDs and verify all are reported as
        // contained.
        let mut r = RevocationList::with_expected_capacity(256);
        for b in 0u8..=255 {
            r.revoke(id(b));
        }
        for b in 0u8..=255 {
            assert!(r.contains(&id(b)), "missing id={b}");
        }
        assert_eq!(r.len(), 256);
    }

    #[test]
    fn bloom_might_contain_does_not_panic_on_unrelated_input() {
        let mut r = RevocationList::new();
        r.revoke(id(1));
        // Just exercise the path with arbitrary IDs; we don't assert
        // false-positive rates because they are inherent to bloom
        // filters and we pre-sized for ~1%.
        for b in 2u8..=20 {
            let _ = r.contains(&id(b));
        }
    }

    #[test]
    fn bloom_no_false_negative_property() {
        // Insert N items, check none reports "absent".
        let mut r = RevocationList::with_expected_capacity(64);
        let inserted: alloc::vec::Vec<CapabilityId> = (0u8..40).map(id).collect();
        for c in &inserted {
            r.revoke(*c);
        }
        for c in &inserted {
            assert!(r.contains(c));
        }
    }

    #[test]
    fn len_and_is_empty_consistency() {
        let mut r = RevocationList::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        r.revoke(id(1));
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);
        r.revoke(id(2));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn with_expected_capacity_does_not_affect_semantics() {
        let r0 = RevocationList::new();
        let r1024 = RevocationList::with_expected_capacity(1024);
        assert!(r0.is_empty());
        assert!(r1024.is_empty());
        assert!(!r0.contains(&id(1)));
        assert!(!r1024.contains(&id(1)));
    }
}
