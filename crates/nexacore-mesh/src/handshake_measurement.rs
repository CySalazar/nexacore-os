//! Measurement-list binding for the mesh handshake (WS6-03.6).
//!
//! This is the concrete logic behind invariant **I8** (measurement-list
//! binding): the *set* of allowlisted TEE measurements at session-establishment
//! time is committed into the handshake transcript, so that a measurement that
//! is later evicted from the allowlist cannot be retroactively honored, and so
//! that both peers agree on which measurements they mutually trust.
//!
//! Per spec (`docs/protocol/handshake.md` §3.2/§3.3/§4.5, invariant I8):
//! - `measurement_root` — the responder sends, in `m2`, a 32-byte BLAKE3 Merkle
//!   root of its *active measurement allowlist*. It is folded into
//!   `transcript_after_m2_payload`, so it is signed and mixed into the KDF.
//! - The initiator MUST verify that root matches its local view *up to staleness
//!   `Δ_measurement_window`* (default 24 h) — this is [`LocalMeasurementView`].
//! - `measurement_ack` — the initiator sends, in `m3`, a 32-byte BLAKE3 hash of
//!   the *intersection* of both allowlists. Both sides MUST compute the same
//!   value, else abort ([`measurement_ack`]).
//!
//! No cryptographic primitive is implemented here. Every hash is the mandated
//! domain-separated BLAKE3 ([`nexacore_crypto::hash::domain_separated_hash`]);
//! leaf and internal-node hashes use *distinct* domains so a leaf can never be
//! reinterpreted as an internal node (second-preimage hardening). The allowlist
//! is canonicalized (sorted + de-duplicated on the raw measurement bytes) before
//! the tree is built, so the root commits to the *set*, independent of insertion
//! order — both peers derive the same root from the same set. This module
//! remains subject to the WS10-03 crypto review before production.

use std::{collections::BTreeSet, vec::Vec};

use nexacore_crypto::hash::domain_separated_hash;
use nexacore_tee::Measurement;

/// Domain separator for a measurement *leaf* hash (I8 second-preimage hardening).
pub const MEASUREMENT_LEAF_DOMAIN: &str = "NexaCore-PROTO-v0.2/handshake/measurement-leaf";

/// Domain separator for an *internal-node* hash (distinct from the leaf domain).
pub const MEASUREMENT_NODE_DOMAIN: &str = "NexaCore-PROTO-v0.2/handshake/measurement-node";

/// Domain separator for the final `measurement_root` (type-tags the commitment).
pub const MEASUREMENT_ROOT_DOMAIN: &str = "NexaCore-PROTO-v0.2/handshake/measurement-root";

/// Domain separator for the `measurement_ack` (intersection commitment, §3.3).
pub const MEASUREMENT_ACK_DOMAIN: &str = "NexaCore-PROTO-v0.2/handshake/measurement-ack";

/// Default `Δ_measurement_window` (§4.5): 24 h of allowlist-propagation slack.
pub const DEFAULT_MEASUREMENT_WINDOW_SECS: u64 = 24 * 60 * 60;

/// A 32-byte digest — a Merkle root or an intersection commitment.
pub type Digest = [u8; 32];

/// Canonicalize an allowlist to a sorted, de-duplicated list of measurement
/// bytes. The Merkle root and the ack commit to the *set*, so ordering and
/// duplicates in the caller's input must not affect the result.
fn canonical_measurements(allowlist: &[Measurement]) -> Vec<[u8; 48]> {
    let mut bytes: Vec<[u8; 48]> = allowlist.iter().map(|m| *m.as_bytes()).collect();
    bytes.sort_unstable();
    bytes.dedup();
    bytes
}

/// Compute the `measurement_root` of an allowlist (I8, §3.2): the domain-
/// separated BLAKE3 Merkle root over the canonicalized measurement set.
///
/// An empty allowlist yields a distinct, well-defined root (the root domain over
/// no bytes), so an "empty allowlist" can never collide with a populated one.
/// A lone node is promoted unchanged (RFC-6962 style — no self-duplication).
#[must_use]
pub fn measurement_root(allowlist: &[Measurement]) -> Digest {
    let canon = canonical_measurements(allowlist);

    let mut level: Vec<Digest> = canon
        .iter()
        .map(|m| domain_separated_hash(MEASUREMENT_LEAF_DOMAIN, m))
        .collect();

    if level.is_empty() {
        return domain_separated_hash(MEASUREMENT_ROOT_DOMAIN, &[]);
    }

    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                if let [left, right] = pair {
                    let mut buf = [0u8; 64];
                    let (lo, hi) = buf.split_at_mut(32);
                    lo.copy_from_slice(left);
                    hi.copy_from_slice(right);
                    domain_separated_hash(MEASUREMENT_NODE_DOMAIN, &buf)
                } else {
                    // Lone tail node (odd level): promote it unchanged.
                    pair.first().copied().unwrap_or([0u8; 32])
                }
            })
            .collect();
    }

    let top = level.first().copied().unwrap_or([0u8; 32]);
    domain_separated_hash(MEASUREMENT_ROOT_DOMAIN, &top)
}

/// Compute `measurement_ack` (§3.3): a domain-separated BLAKE3 hash of the
/// *intersection* of the local and peer allowlists.
///
/// The intersection is symmetric and is serialized in canonical (sorted) order,
/// so both peers compute the identical value. The state machine aborts with
/// `MeasurementAckMismatch` when the two sides disagree.
#[must_use]
pub fn measurement_ack(local: &[Measurement], peer: &[Measurement]) -> Digest {
    let peer_set: BTreeSet<[u8; 48]> = peer.iter().map(|m| *m.as_bytes()).collect();

    let mut buf = Vec::new();
    for m in canonical_measurements(local) {
        if peer_set.contains(&m) {
            buf.extend_from_slice(&m);
        }
    }
    domain_separated_hash(MEASUREMENT_ACK_DOMAIN, &buf)
}

/// A time-stamped `measurement_root` this node held as its active view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasurementRootSnapshot {
    /// The Merkle root of the allowlist at [`Self::taken_at_secs`].
    pub root: Digest,
    /// Unix seconds at which this root was the node's active allowlist view.
    pub taken_at_secs: u64,
}

/// A node's local knowledge of recent `measurement_root` values, used to verify
/// a peer's root within the staleness window `Δ_measurement_window` (I8, §4.5).
///
/// Rather than tolerate a fuzzy match on the *hash* (impossible), the window is
/// applied to the *freshness* of a matching snapshot: the peer's root is
/// accepted iff this node held that exact root within `±window_secs` of the
/// handshake time, absorbing allowlist-propagation lag in either direction.
#[derive(Debug, Clone)]
pub struct LocalMeasurementView {
    snapshots: Vec<MeasurementRootSnapshot>,
    window_secs: u64,
}

impl LocalMeasurementView {
    /// Create an empty view with the given staleness window.
    #[must_use]
    pub fn new(window_secs: u64) -> Self {
        Self {
            snapshots: Vec::new(),
            window_secs,
        }
    }

    /// Create an empty view with the default 24 h staleness window (§4.5).
    #[must_use]
    pub fn with_default_window() -> Self {
        Self::new(DEFAULT_MEASUREMENT_WINDOW_SECS)
    }

    /// Record `root` as this node's active allowlist view at `now_secs`.
    pub fn record(&mut self, root: Digest, now_secs: u64) {
        self.snapshots.push(MeasurementRootSnapshot {
            root,
            taken_at_secs: now_secs,
        });
    }

    /// The most recently recorded root, if any (this node's current view).
    #[must_use]
    pub fn current_root(&self) -> Option<Digest> {
        self.snapshots
            .iter()
            .max_by_key(|snapshot| snapshot.taken_at_secs)
            .map(|snapshot| snapshot.root)
    }

    /// Verify a peer's `measurement_root` against the local view (I8 / §4.5).
    ///
    /// Returns `true` iff this node held exactly `peer_root` within
    /// `±window_secs` of `now_secs`. A root the node never held, or one only
    /// held outside the staleness window, is rejected (fail-closed) — the state
    /// machine then aborts with `MeasurementRootMismatch`.
    #[must_use]
    pub fn accepts(&self, peer_root: &Digest, now_secs: u64) -> bool {
        self.snapshots.iter().any(|snapshot| {
            &snapshot.root == peer_root
                && snapshot.taken_at_secs.abs_diff(now_secs) <= self.window_secs
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct test measurement seeded from a single byte.
    fn m(seed: u8) -> Measurement {
        Measurement([seed; 48])
    }

    #[test]
    fn root_is_order_and_duplicate_independent() {
        let a = measurement_root(&[m(1), m(2), m(3)]);
        let reordered = measurement_root(&[m(3), m(1), m(2)]);
        let with_dups = measurement_root(&[m(2), m(1), m(3), m(1), m(2)]);
        // The root commits to the set, not the insertion order or multiplicity.
        assert_eq!(a, reordered);
        assert_eq!(a, with_dups);
    }

    #[test]
    fn empty_allowlist_has_a_distinct_root() {
        let empty = measurement_root(&[]);
        let single = measurement_root(&[m(1)]);
        // Empty vs populated must never collide.
        assert_ne!(empty, single);
        // Empty is deterministic.
        assert_eq!(empty, measurement_root(&[]));
    }

    #[test]
    fn different_sets_have_different_roots() {
        let base = measurement_root(&[m(1), m(2)]);
        let grown = measurement_root(&[m(1), m(2), m(3)]);
        let swapped = measurement_root(&[m(1), m(9)]);
        assert_ne!(base, grown);
        assert_ne!(base, swapped);
    }

    #[test]
    fn root_changes_when_a_measurement_changes() {
        // Evicting/altering a single measurement must move the root — the whole
        // point of I8 (an evicted measurement cannot be retroactively honored).
        let before = measurement_root(&[m(1), m(2), m(3)]);
        let after = measurement_root(&[m(1), m(2), m(4)]);
        assert_ne!(before, after);
    }

    #[test]
    fn root_is_deterministic_across_sizes() {
        // Odd leaf counts exercise the lone-node promotion path.
        for n in 1u8..=6 {
            let set: Vec<Measurement> = (0..n).map(m).collect();
            assert_eq!(measurement_root(&set), measurement_root(&set));
        }
    }

    #[test]
    fn ack_is_symmetric_over_the_intersection() {
        let a = [m(1), m(2), m(3)];
        let b = [m(2), m(3), m(4)];
        // Both peers must compute the identical ack (§3.3).
        assert_eq!(measurement_ack(&a, &b), measurement_ack(&b, &a));
    }

    #[test]
    fn ack_reflects_only_the_shared_measurements() {
        let a = [m(1), m(2), m(3)];
        let b = [m(2), m(3), m(4)];
        // {2,3} is the intersection; a peer set that shares exactly {2,3}
        // yields the same ack regardless of its non-shared members.
        let b2 = [m(2), m(3), m(7), m(8)];
        assert_eq!(measurement_ack(&a, &b), measurement_ack(&a, &b2));
    }

    #[test]
    fn disjoint_allowlists_ack_as_the_empty_intersection() {
        let a = [m(1), m(2)];
        let b = [m(3), m(4)];
        let empty_intersection = measurement_ack(&[], &[]);
        assert_eq!(measurement_ack(&a, &b), empty_intersection);
    }

    #[test]
    fn ack_differs_when_the_intersection_differs() {
        let a = [m(1), m(2), m(3)];
        let shares_two = measurement_ack(&a, &[m(2), m(3)]);
        let shares_one = measurement_ack(&a, &[m(3)]);
        assert_ne!(shares_two, shares_one);
    }

    #[test]
    fn view_accepts_a_matching_root_within_the_window() {
        let root = measurement_root(&[m(1), m(2)]);
        let mut view = LocalMeasurementView::new(100);
        view.record(root, 1_000);
        assert!(view.accepts(&root, 1_050)); // 50 s later, within Δ=100
        assert!(view.accepts(&root, 960)); // 40 s earlier, within ±Δ
    }

    #[test]
    fn view_rejects_a_root_outside_the_window() {
        let root = measurement_root(&[m(1), m(2)]);
        let mut view = LocalMeasurementView::new(100);
        view.record(root, 1_000);
        // 200 s later — beyond Δ=100 → fail-closed.
        assert!(!view.accepts(&root, 1_200));
    }

    #[test]
    fn view_rejects_an_unknown_root() {
        let known = measurement_root(&[m(1)]);
        let unknown = measurement_root(&[m(9)]);
        let mut view = LocalMeasurementView::new(DEFAULT_MEASUREMENT_WINDOW_SECS);
        view.record(known, 1_000);
        // A root this node never held is rejected even at the exact same instant.
        assert!(!view.accepts(&unknown, 1_000));
    }

    #[test]
    fn view_accepts_a_recent_non_current_snapshot() {
        // Propagation lag: the node rotated to a new root, but a peer still on
        // the previous (recent) root is accepted while it is within the window.
        let old = measurement_root(&[m(1)]);
        let new = measurement_root(&[m(1), m(2)]);
        let mut view = LocalMeasurementView::new(3_600);
        view.record(old, 1_000);
        view.record(new, 2_000);
        assert_eq!(view.current_root(), Some(new));
        // Peer still on `old`, 500 s after the rotation — within Δ.
        assert!(view.accepts(&old, 2_500));
    }
}
