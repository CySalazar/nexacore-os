//! Kademlia DHT peer discovery (WS6-04).
//!
//! This module defines the foundations of the NexaCore OS Kademlia distributed
//! hash table: the **node ID space** and the **XOR distance metric**
//! (WS6-04.1), the **k-bucket routing table** (WS6-04.2), and the **RPC
//! protocol** with its local request handler (WS6-04.3). The iterative
//! lookup (WS6-04.4) builds on the [`NodeId`] / [`Distance`] /
//! [`RoutingTable`] / [`DhtNode`] types established here.
//!
//! # Node ID space
//!
//! A node's identity in NexaCore OS is its TEE attestation. Its DHT address —
//! the [`NodeId`] — is the [`domain_separated_hash`] of that identity's key
//! material, so it inherits `BLAKE3`'s 256-bit width and uniform
//! distribution. A 256-bit space (`2^256` addresses) makes accidental
//! collisions infeasible and gives the routing table [`ID_BITS`] k-buckets.
//!
//! Deriving the ID from a hash (rather than letting a node pick it) is what
//! makes Sybil/eclipse attacks expensive: a node cannot cheaply choose an ID
//! close to a victim, because it would have to grind attestations until the
//! hash landed in the target region of the keyspace.
//!
//! # XOR distance metric
//!
//! Kademlia measures "closeness" between two IDs as the bitwise XOR of their
//! values, interpreted as a big-endian unsigned integer
//! ([`NodeId::distance`]). XOR is a valid metric:
//!
//! - **Identity**: `d(x, x) == 0`, and `d(x, y) == 0` only if `x == y`.
//! - **Symmetry**: `d(x, y) == d(y, x)`.
//! - **Triangle inequality**: `d(x, y) <= d(x, z) + d(z, y)`.
//!
//! Crucially it is also **unidirectional**: for any `x` and any distance
//! `δ` there is exactly one `y` with `d(x, y) == δ`. That property lets all
//! lookups for a key converge on the same nodes regardless of where they
//! start, which is what makes the DHT consistent.
//!
//! The most-significant set bit of a distance selects the k-bucket a peer
//! belongs to ([`Distance::bucket_index`]): peers sharing a long ID prefix
//! with us are "near" (high bucket index reserved for the few far peers),
//! peers differing in the top bit are "far".
//!
//! [`domain_separated_hash`]: nexacore_crypto::hash::domain_separated_hash

use core::fmt;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
};

use nexacore_crypto::hash::{HASH_LEN, domain_separated_hash};

/// The width of a [`NodeId`] in bytes.
///
/// Locked to the protocol hash length so that a `NodeId` is exactly one
/// [`domain_separated_hash`]
/// digest with no truncation or padding.
pub const ID_BYTES: usize = HASH_LEN;

/// The width of a [`NodeId`] in bits (the number of k-buckets in a routing
/// table covering this keyspace).
pub const ID_BITS: usize = ID_BYTES * 8;

/// Hash domain for deriving a [`NodeId`] from node identity key material.
///
/// Registered in `/docs/04-security-model.md` § "Hash domain registry".
/// Versioned so the derivation can evolve without colliding with the old
/// scheme.
const NODE_ID_DOMAIN: &str = "nexacore-mesh::kademlia::node_id::v1";

/// A Kademlia node identifier: a point in the 256-bit DHT keyspace.
///
/// Stored big-endian (most-significant byte first) so that the derived
/// [`Ord`] is the natural unsigned-integer ordering. Equality is exact; the
/// notion of "closeness" used for routing is the XOR [`Distance`], not this
/// ordering — see [`NodeId::distance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId([u8; ID_BYTES]);

impl NodeId {
    /// The all-zero identifier (the keyspace origin).
    pub const ZERO: Self = Self([0u8; ID_BYTES]);

    /// Wrap raw big-endian bytes as a [`NodeId`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Derive a [`NodeId`] from a node's identity key material (e.g. the
    /// public key bound to its TEE attestation) via the protocol's
    /// domain-separated `BLAKE3` hash.
    ///
    /// Two nodes with distinct key material get distinct IDs with
    /// overwhelming probability; an attacker cannot cheaply target a region
    /// of the keyspace because doing so requires grinding the hash input.
    #[must_use]
    pub fn from_key_material(key_material: &[u8]) -> Self {
        Self(domain_separated_hash(NODE_ID_DOMAIN, key_material))
    }

    /// The raw big-endian bytes of this identifier.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_BYTES] {
        &self.0
    }

    /// The Kademlia XOR distance from this node to `other`.
    ///
    /// The result is the bitwise XOR of the two IDs, interpreted as a
    /// big-endian magnitude (see [`Distance`]).
    #[must_use]
    pub fn distance(&self, other: &Self) -> Distance {
        let mut out = [0u8; ID_BYTES];
        for (slot, (a, b)) in out.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *slot = a ^ b;
        }
        Distance(out)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A Kademlia XOR distance: the bitwise XOR of two [`NodeId`]s, interpreted
/// as a big-endian unsigned 256-bit magnitude.
///
/// The derived [`Ord`] compares distances numerically (most-significant byte
/// first), so `BTreeMap`/sort over `Distance` orders peers from nearest to
/// farthest — the ordering iterative lookup relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Distance([u8; ID_BYTES]);

impl Distance {
    /// The zero distance (a node to itself).
    pub const ZERO: Self = Self([0u8; ID_BYTES]);

    /// The raw big-endian magnitude bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_BYTES] {
        &self.0
    }

    /// Whether this is the zero distance.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// The number of leading zero bits in the big-endian magnitude
    /// (0 for a distance whose top bit is set, [`ID_BITS`] for zero).
    #[must_use]
    pub fn leading_zeros(&self) -> u32 {
        let mut count = 0u32;
        for &byte in &self.0 {
            if byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros();
                break;
            }
        }
        count
    }

    /// The index of the k-bucket this distance falls into:
    /// `floor(log2(distance))`, i.e. the position of the most-significant set
    /// bit (0 = least significant). Returns [`None`] for the zero distance,
    /// which has no bucket.
    ///
    /// Two nodes sharing a longer ID prefix produce a smaller distance and a
    /// lower bucket index; nodes differing in the top bit fall in the highest
    /// bucket, `ID_BITS - 1`.
    #[must_use]
    pub fn bucket_index(&self) -> Option<usize> {
        let lz = self.leading_zeros() as usize;
        if lz >= ID_BITS {
            None
        } else {
            Some(ID_BITS - 1 - lz)
        }
    }
}

impl fmt::Display for Distance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The Kademlia replication parameter *k*.
///
/// The maximum number of contacts a single k-bucket holds, and the number of
/// closest peers a lookup converges on. 20 is the value from the original
/// Kademlia paper — large enough that the probability of all *k* nodes in a
/// bucket failing within an hour is negligible.
pub const K: usize = 20;

/// The Kademlia lookup concurrency parameter *α*.
///
/// How many peers an iterative lookup queries per round. 3 is the value from
/// the original Kademlia paper — enough to route around a few slow or dead
/// peers without flooding the network with redundant queries.
pub const ALPHA: usize = 3;

/// A known peer in the DHT: its [`NodeId`] and the transport address it is
/// reachable at.
///
/// The address is a plain UDP/QUIC [`SocketAddr`] for now; NAT-traversal
/// candidate gathering (WS6-04.8) will enrich this later without changing the
/// routing-table contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Contact {
    /// The peer's Kademlia identifier.
    pub id: NodeId,
    /// The transport address the peer is reachable at.
    pub addr: SocketAddr,
}

impl Contact {
    /// Create a contact from an id and address.
    #[must_use]
    pub const fn new(id: NodeId, addr: SocketAddr) -> Self {
        Self { id, addr }
    }
}

/// The outcome of offering a [`Contact`] to a [`RoutingTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The contact is the local node itself and was ignored.
    SelfId,
    /// A new contact was added to a bucket with spare capacity.
    Inserted,
    /// An already-known contact was refreshed to most-recently-seen (and its
    /// address updated).
    Updated,
    /// The target bucket is full. The caller should PING `lru` (the
    /// least-recently-seen contact): if it replies, keep it and drop the new
    /// contact; if it does not, [`RoutingTable::remove`] it and re-offer the
    /// new contact. This least-recently-seen eviction policy is what gives
    /// Kademlia its resistance to flushing attacks — long-lived nodes are
    /// preferred over fresh, unproven ones.
    Full {
        /// The least-recently-seen contact in the full bucket.
        lru: Contact,
    },
}

/// A Kademlia k-bucket routing table (WS6-04.2).
///
/// The keyspace around the local node is partitioned into [`ID_BITS`] buckets
/// by XOR distance: bucket *i* holds peers whose [`Distance::bucket_index`] is
/// *i* (i.e. distance in `[2^i, 2^(i+1))`). Each bucket keeps up to [`K`]
/// contacts ordered least-recently-seen (front) to most-recently-seen (back),
/// so a full bucket can surface its eviction candidate in O(1).
///
/// The partition is naturally finer for nearby peers — the table knows many
/// peers close to itself and exponentially fewer far away — which is what
/// bounds lookup to O(log n) hops.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    local_id: NodeId,
    buckets: Vec<VecDeque<Contact>>,
}

impl RoutingTable {
    /// Create an empty routing table owned by `local_id`.
    #[must_use]
    pub fn new(local_id: NodeId) -> Self {
        let buckets = (0..ID_BITS).map(|_| VecDeque::new()).collect();
        Self { local_id, buckets }
    }

    /// The id of the node that owns this table.
    #[must_use]
    pub const fn local_id(&self) -> NodeId {
        self.local_id
    }

    /// Offer a contact to the table, applying Kademlia's bucket rules.
    ///
    /// See [`InsertOutcome`] for the four possible results. The local node's
    /// own id is never stored.
    pub fn insert(&mut self, contact: Contact) -> InsertOutcome {
        let Some(idx) = self.local_id.distance(&contact.id).bucket_index() else {
            return InsertOutcome::SelfId;
        };
        let Some(bucket) = self.buckets.get_mut(idx) else {
            // `idx` is always < ID_BITS == buckets.len(); unreachable in
            // practice, but handled without panicking.
            return InsertOutcome::SelfId;
        };
        if let Some(pos) = bucket.iter().position(|c| c.id == contact.id) {
            // Refresh: drop the stale entry and re-append the fresh one (which
            // also picks up any address change) as most-recently-seen.
            bucket.remove(pos);
            bucket.push_back(contact);
            return InsertOutcome::Updated;
        }
        if bucket.len() < K {
            bucket.push_back(contact);
            InsertOutcome::Inserted
        } else {
            bucket
                .front()
                .map_or(InsertOutcome::Inserted, |lru| InsertOutcome::Full {
                    lru: *lru,
                })
        }
    }

    /// Remove a contact by id (e.g. a node that failed to answer a PING).
    /// Returns whether it was present.
    pub fn remove(&mut self, id: &NodeId) -> bool {
        let Some(idx) = self.local_id.distance(id).bucket_index() else {
            return false;
        };
        let Some(bucket) = self.buckets.get_mut(idx) else {
            return false;
        };
        bucket.iter().position(|c| &c.id == id).is_some_and(|pos| {
            bucket.remove(pos);
            true
        })
    }

    /// The stored contact for `id`, if known.
    #[must_use]
    pub fn get(&self, id: &NodeId) -> Option<&Contact> {
        let idx = self.local_id.distance(id).bucket_index()?;
        self.buckets.get(idx)?.iter().find(|c| &c.id == id)
    }

    /// Whether `id` is in the table.
    #[must_use]
    pub fn contains(&self, id: &NodeId) -> bool {
        self.get(id).is_some()
    }

    /// The up-to-`count` known contacts closest to `target` by XOR distance,
    /// nearest first. This is the answer to a `FIND_NODE` and the seed set for
    /// an iterative lookup (WS6-04.4).
    #[must_use]
    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<Contact> {
        let mut all: Vec<Contact> = self.buckets.iter().flatten().copied().collect();
        all.sort_by_key(|c| target.distance(&c.id));
        all.truncate(count);
        all
    }

    /// The total number of contacts across all buckets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.iter().map(VecDeque::len).sum()
    }

    /// Whether the table holds no contacts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(VecDeque::is_empty)
    }

    /// The number of contacts in bucket `index` (0 if out of range).
    #[must_use]
    pub fn bucket_len(&self, index: usize) -> usize {
        self.buckets.get(index).map_or(0, VecDeque::len)
    }
}

/// A Kademlia RPC request (WS6-04.3).
///
/// Keys for [`Store`](RpcRequest::Store) / [`FindValue`](RpcRequest::FindValue)
/// share the [`NodeId`] keyspace (a key is the hash of the value it locates),
/// so the same XOR metric ranks both nodes and keys.
///
/// These are the protocol's semantic messages; their on-the-wire encoding is
/// added with the QUIC+Noise transport (WS6-04.6), under the serialization NCIP
/// that governs the mesh wire format — so no serde derives are committed here
/// yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcRequest {
    /// Liveness probe. Answered with [`RpcResponse::Pong`].
    Ping,
    /// Ask the recipient to store `value` under `key`.
    Store {
        /// The key the value is addressed by.
        key: NodeId,
        /// The value bytes to store.
        value: Vec<u8>,
    },
    /// Ask for the `K` contacts closest to `target` that the recipient knows.
    FindNode {
        /// The id being searched for.
        target: NodeId,
    },
    /// Ask for the value stored under `key`, or — if the recipient does not
    /// have it — the `K` closest contacts to continue the search.
    FindValue {
        /// The key being looked up.
        key: NodeId,
    },
}

/// A Kademlia RPC response (WS6-04.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcResponse {
    /// Reply to [`RpcRequest::Ping`].
    Pong,
    /// Reply to a successful [`RpcRequest::Store`].
    Stored,
    /// The closest known contacts — the answer to [`RpcRequest::FindNode`] and
    /// to a [`RpcRequest::FindValue`] miss.
    Nodes(Vec<Contact>),
    /// The stored value — the answer to a [`RpcRequest::FindValue`] hit.
    Value(Vec<u8>),
}

/// A node's local DHT engine: its [`RoutingTable`] plus the key/value records
/// it is responsible for storing (WS6-04.3).
///
/// [`handle`](DhtNode::handle) is the server side of the RPC protocol — it
/// answers a request and, as a side effect, learns about the sender (every
/// Kademlia message refreshes the routing table). The client side — issuing
/// requests and driving them across the network — is the iterative lookup
/// (WS6-04.4) over the QUIC transport (WS6-04.6).
#[derive(Debug, Clone)]
pub struct DhtNode {
    table: RoutingTable,
    store: HashMap<NodeId, Vec<u8>>,
}

impl DhtNode {
    /// Create an engine owned by `local_id` with an empty table and store.
    #[must_use]
    pub fn new(local_id: NodeId) -> Self {
        Self {
            table: RoutingTable::new(local_id),
            store: HashMap::new(),
        }
    }

    /// This node's id.
    #[must_use]
    pub const fn local_id(&self) -> NodeId {
        self.table.local_id()
    }

    /// Read-only access to the routing table.
    #[must_use]
    pub const fn routing_table(&self) -> &RoutingTable {
        &self.table
    }

    /// The value stored under `key`, if this node holds it.
    #[must_use]
    pub fn stored_value(&self, key: &NodeId) -> Option<&[u8]> {
        self.store.get(key).map(Vec::as_slice)
    }

    /// The number of key/value records held.
    #[must_use]
    pub fn stored_len(&self) -> usize {
        self.store.len()
    }

    /// Record that we heard from `contact` by offering it to the routing table.
    /// Used both by [`handle`](DhtNode::handle) and by bootstrap (WS6-04.5).
    pub fn note_contact(&mut self, contact: Contact) -> InsertOutcome {
        self.table.insert(contact)
    }

    /// Answer an RPC `request` from `sender`.
    ///
    /// The sender is offered to the routing table first, so the table stays
    /// fresh from ordinary traffic. A full bucket is left as-is here; proactive
    /// PING-and-evict of stale contacts is WS6-04.9.
    pub fn handle(&mut self, sender: Contact, request: RpcRequest) -> RpcResponse {
        self.table.insert(sender);
        match request {
            RpcRequest::Ping => RpcResponse::Pong,
            RpcRequest::Store { key, value } => {
                self.store.insert(key, value);
                RpcResponse::Stored
            }
            RpcRequest::FindNode { target } => RpcResponse::Nodes(self.table.closest(&target, K)),
            RpcRequest::FindValue { key } => self.store.get(&key).map_or_else(
                || RpcResponse::Nodes(self.table.closest(&key, K)),
                |value| RpcResponse::Value(value.clone()),
            ),
        }
    }

    /// Join the DHT from a list of `seeds` (WS6-04.5).
    ///
    /// The standard Kademlia bootstrap: insert the seed contacts, then run an
    /// iterative `FIND_NODE` for our *own* id (`query` resolves each hop, as in
    /// [`iterative_find_node`]). The self-lookup fills the routing table with
    /// the peers nearest to us — exactly the ones we most need — while the
    /// peers we contact simultaneously learn about us. Every discovered contact
    /// is inserted; our own id is never stored.
    ///
    /// Returns the number of peers known after bootstrap. Proactive refresh of
    /// the farther buckets is the periodic refresh task (WS6-04.9).
    pub fn bootstrap<F>(&mut self, seeds: &[Contact], mut query: F) -> usize
    where
        F: FnMut(Contact, NodeId) -> Vec<Contact>,
    {
        for &seed in seeds {
            self.table.insert(seed);
        }
        let me = self.local_id();
        let discovered = iterative_find_node(seeds, me, &mut query);
        for contact in discovered {
            self.table.insert(contact);
        }
        self.table.len()
    }
}

/// Sort `list` by XOR distance to `target` (nearest first) and drop duplicate
/// ids. Shared by the iterative lookups.
fn sort_dedup_by_distance(list: &mut Vec<Contact>, target: &NodeId) {
    list.sort_by_key(|c| target.distance(&c.id));
    list.dedup_by_key(|c| c.id);
}

/// Run an iterative `FIND_NODE` for `target` (WS6-04.4).
///
/// Starting from `seeds`, `query(peer, target)` is called to resolve each hop —
/// it returns the contacts `peer` believes are closest to `target`. The lookup
/// keeps a shortlist of the closest contacts seen, queries the [`ALPHA`]
/// closest not-yet-queried among the [`K`] best each round, and terminates once
/// those `K` closest have all been queried (the point past which no closer node
/// can surface). Returns up to `K` contacts closest to `target`, nearest first.
///
/// This is the transport-agnostic core; the async driver over the QUIC+Noise
/// transport (WS6-04.6) runs the same algorithm with real network RPCs.
pub fn iterative_find_node<F>(seeds: &[Contact], target: NodeId, mut query: F) -> Vec<Contact>
where
    F: FnMut(Contact, NodeId) -> Vec<Contact>,
{
    let mut shortlist: Vec<Contact> = seeds.to_vec();
    let mut queried: HashSet<NodeId> = HashSet::new();
    loop {
        sort_dedup_by_distance(&mut shortlist, &target);
        let batch: Vec<Contact> = shortlist
            .iter()
            .take(K)
            .filter(|c| !queried.contains(&c.id))
            .take(ALPHA)
            .copied()
            .collect();
        if batch.is_empty() {
            break;
        }
        for peer in batch {
            queried.insert(peer.id);
            shortlist.extend(query(peer, target));
        }
    }
    sort_dedup_by_distance(&mut shortlist, &target);
    shortlist.truncate(K);
    shortlist
}

/// What a peer returns for a `FIND_VALUE` hop: the value itself, or — if it
/// does not hold the key — the closer contacts to keep searching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindValueOutcome {
    /// The peer holds the value.
    Value(Vec<u8>),
    /// The peer does not hold the value; here are closer contacts.
    Nodes(Vec<Contact>),
}

/// The result of an iterative `FIND_VALUE` (WS6-04.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupValue {
    /// The value was found, along with the contact that returned it.
    Found {
        /// The located value bytes.
        value: Vec<u8>,
        /// The peer that held the value.
        from: Contact,
    },
    /// The value was not found anywhere reachable; the `K` closest contacts to
    /// the key are returned (e.g. to re-`STORE` the value near them).
    NotFound(Vec<Contact>),
}

/// Run an iterative `FIND_VALUE` for `key` (WS6-04.4).
///
/// Like [`iterative_find_node`], but each hop may short-circuit: the first peer
/// that holds the value ends the lookup with [`LookupValue::Found`]. If no peer
/// has it, the `K` closest contacts are returned as [`LookupValue::NotFound`].
pub fn iterative_find_value<F>(seeds: &[Contact], key: NodeId, mut query: F) -> LookupValue
where
    F: FnMut(Contact, NodeId) -> FindValueOutcome,
{
    let mut shortlist: Vec<Contact> = seeds.to_vec();
    let mut queried: HashSet<NodeId> = HashSet::new();
    loop {
        sort_dedup_by_distance(&mut shortlist, &key);
        let batch: Vec<Contact> = shortlist
            .iter()
            .take(K)
            .filter(|c| !queried.contains(&c.id))
            .take(ALPHA)
            .copied()
            .collect();
        if batch.is_empty() {
            break;
        }
        for peer in batch {
            queried.insert(peer.id);
            match query(peer, key) {
                FindValueOutcome::Value(value) => return LookupValue::Found { value, from: peer },
                FindValueOutcome::Nodes(nodes) => shortlist.extend(nodes),
            }
        }
    }
    sort_dedup_by_distance(&mut shortlist, &key);
    shortlist.truncate(K);
    LookupValue::NotFound(shortlist)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    /// Build a `NodeId` whose last byte is `tag` and the rest zero — handy
    /// for reasoning about low-order distances in tests.
    fn id_with_low_byte(tag: u8) -> NodeId {
        let mut bytes = [0u8; ID_BYTES];
        if let Some(last) = bytes.last_mut() {
            *last = tag;
        }
        NodeId::from_bytes(bytes)
    }

    /// Build a `NodeId` whose first byte is `tag` and the rest zero.
    fn id_with_high_byte(tag: u8) -> NodeId {
        let mut bytes = [0u8; ID_BYTES];
        if let Some(first) = bytes.first_mut() {
            *first = tag;
        }
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn id_space_width_matches_hash() {
        assert_eq!(ID_BYTES, 32);
        assert_eq!(ID_BITS, 256);
    }

    #[test]
    fn distance_to_self_is_zero() {
        let a = id_with_low_byte(0x42);
        assert_eq!(a.distance(&a), Distance::ZERO);
        assert!(a.distance(&a).is_zero());
    }

    #[test]
    fn distance_is_zero_only_for_equal_ids() {
        let a = id_with_low_byte(0x01);
        let b = id_with_low_byte(0x02);
        assert!(!a.distance(&b).is_zero());
    }

    #[test]
    fn distance_is_symmetric() {
        let a = id_with_high_byte(0xa5);
        let b = id_with_low_byte(0x3c);
        assert_eq!(a.distance(&b), b.distance(&a));
    }

    #[test]
    fn distance_is_bitwise_xor() {
        let a = id_with_low_byte(0b1010_1010);
        let b = id_with_low_byte(0b0110_0110);
        let d = a.distance(&b);
        // Only the last byte differs; it must be the XOR of the two.
        assert_eq!(d.as_bytes().last(), Some(&0b1100_1100));
    }

    #[test]
    fn unidirectionality_recovers_the_unique_peer() {
        // For a fixed `a` and distance `δ`, `b = a XOR δ` is the unique node
        // at that distance, and its distance back to `a` is exactly `δ`.
        let a = id_with_high_byte(0x11);
        let b = id_with_low_byte(0x99);
        let delta = a.distance(&b);
        // Reconstruct b from a and the distance bytes.
        let mut recovered = *a.as_bytes();
        for (slot, &d) in recovered.iter_mut().zip(delta.as_bytes().iter()) {
            *slot ^= d;
        }
        assert_eq!(NodeId::from_bytes(recovered), b);
    }

    #[test]
    // The d(a,b) pair-distance names mirror the metric notation; they are
    // intentionally close.
    #[allow(clippy::similar_names)]
    fn triangle_inequality_holds() {
        // d(x, y) <= d(x, z) + d(z, y) for the XOR metric. With small,
        // single-byte distances we can compare the numeric magnitudes.
        let x = id_with_low_byte(0x00);
        let y = id_with_low_byte(0x0f);
        let z = id_with_low_byte(0x03);
        let dxy = *x.distance(&y).as_bytes().last().unwrap_or(&0);
        let dxz = *x.distance(&z).as_bytes().last().unwrap_or(&0);
        let dzy = *z.distance(&y).as_bytes().last().unwrap_or(&0);
        assert!(u16::from(dxy) <= u16::from(dxz) + u16::from(dzy));
    }

    #[test]
    fn nearer_peers_have_smaller_distance_ordering() {
        let me = id_with_low_byte(0x00);
        let near = id_with_low_byte(0x01); // differs in the lowest bit
        let far = id_with_high_byte(0x80); // differs in the highest bit
        assert!(me.distance(&near) < me.distance(&far));
    }

    #[test]
    fn bucket_index_of_zero_distance_is_none() {
        assert_eq!(Distance::ZERO.bucket_index(), None);
    }

    #[test]
    fn bucket_index_lowest_bit_is_zero() {
        let me = id_with_low_byte(0x00);
        let neighbour = id_with_low_byte(0x01); // distance == 1, top bit at pos 0
        assert_eq!(me.distance(&neighbour).bucket_index(), Some(0));
    }

    #[test]
    fn bucket_index_highest_bit_is_top_bucket() {
        let me = id_with_high_byte(0x00);
        let far = id_with_high_byte(0x80); // top bit of the 256-bit space set
        assert_eq!(me.distance(&far).bucket_index(), Some(ID_BITS - 1));
    }

    #[test]
    fn derivation_is_deterministic_and_distinct() {
        let a1 = NodeId::from_key_material(b"node-A-pubkey");
        let a2 = NodeId::from_key_material(b"node-A-pubkey");
        let b = NodeId::from_key_material(b"node-B-pubkey");
        assert_eq!(a1, a2, "same input must derive the same id");
        assert_ne!(a1, b, "different input must derive different ids");
    }

    #[test]
    fn display_is_lowercase_hex_of_full_width() {
        let id = id_with_high_byte(0xab);
        let s = format!("{id}");
        assert_eq!(s.len(), ID_BYTES * 2);
        assert!(s.starts_with("ab"));
        assert!(s.ends_with("00"));
    }

    // --- Routing table (WS6-04.2) -------------------------------------------

    /// A contact whose id has its top byte set (so, from a `ZERO` local id, it
    /// lands in the highest bucket) and a `variant`-distinguished second byte.
    fn top_bucket_contact(variant: u8) -> Contact {
        let mut bytes = [0u8; ID_BYTES];
        if let Some(first) = bytes.first_mut() {
            *first = 0x80;
        }
        if let Some(second) = bytes.get_mut(1) {
            *second = variant;
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000);
        Contact::new(NodeId::from_bytes(bytes), addr)
    }

    fn contact_for(id: NodeId) -> Contact {
        Contact::new(
            id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4000),
        )
    }

    #[test]
    fn new_table_is_empty() {
        let rt = RoutingTable::new(NodeId::ZERO);
        assert!(rt.is_empty());
        assert_eq!(rt.len(), 0);
        assert_eq!(rt.local_id(), NodeId::ZERO);
    }

    #[test]
    fn inserting_self_is_ignored() {
        let mut rt = RoutingTable::new(NodeId::ZERO);
        assert_eq!(rt.insert(contact_for(NodeId::ZERO)), InsertOutcome::SelfId);
        assert!(rt.is_empty());
    }

    #[test]
    fn insert_then_contains_and_get() {
        let mut rt = RoutingTable::new(NodeId::ZERO);
        let c = top_bucket_contact(1);
        assert_eq!(rt.insert(c), InsertOutcome::Inserted);
        assert!(rt.contains(&c.id));
        assert_eq!(rt.get(&c.id), Some(&c));
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn reinsert_refreshes_without_growing() {
        let mut rt = RoutingTable::new(NodeId::ZERO);
        let c = top_bucket_contact(1);
        assert_eq!(rt.insert(c), InsertOutcome::Inserted);
        assert_eq!(rt.insert(c), InsertOutcome::Updated);
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn reinsert_updates_the_stored_address() {
        let mut rt = RoutingTable::new(NodeId::ZERO);
        let c = top_bucket_contact(1);
        rt.insert(c);
        let moved = Contact::new(
            c.id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );
        assert_eq!(rt.insert(moved), InsertOutcome::Updated);
        assert_eq!(rt.get(&c.id).map(|c| c.addr), Some(moved.addr));
    }

    #[test]
    fn full_bucket_reports_least_recently_seen() {
        let mut rt = RoutingTable::new(NodeId::ZERO);
        // Fill the top bucket to exactly K distinct contacts.
        for v in 0..K {
            let outcome = rt.insert(top_bucket_contact(u8::try_from(v).unwrap_or_default()));
            assert_eq!(outcome, InsertOutcome::Inserted);
        }
        assert_eq!(rt.len(), K);
        assert_eq!(rt.bucket_len(ID_BITS - 1), K);
        // One more → bucket full; the LRU is the first one inserted.
        let extra = top_bucket_contact(200);
        let first = top_bucket_contact(0);
        assert_eq!(rt.insert(extra), InsertOutcome::Full { lru: first });
        // The full bucket did not grow.
        assert_eq!(rt.len(), K);
    }

    #[test]
    fn refreshing_moves_a_contact_off_the_eviction_front() {
        let mut rt = RoutingTable::new(NodeId::ZERO);
        for v in 0..K {
            rt.insert(top_bucket_contact(u8::try_from(v).unwrap_or_default()));
        }
        // Touch the oldest contact → it becomes most-recently-seen, so the new
        // least-recently-seen is the second one inserted.
        assert_eq!(rt.insert(top_bucket_contact(0)), InsertOutcome::Updated);
        let extra = top_bucket_contact(201);
        let second = top_bucket_contact(1);
        assert_eq!(rt.insert(extra), InsertOutcome::Full { lru: second });
    }

    #[test]
    fn remove_evicts_a_contact() {
        let mut rt = RoutingTable::new(NodeId::ZERO);
        let c = top_bucket_contact(1);
        rt.insert(c);
        assert!(rt.remove(&c.id));
        assert!(!rt.contains(&c.id));
        // Removing again reports absence.
        assert!(!rt.remove(&c.id));
    }

    #[test]
    fn closest_returns_contacts_sorted_by_distance() {
        // local == target == ZERO, so distance(target, c) == c's id magnitude.
        let mut rt = RoutingTable::new(NodeId::ZERO);
        let near = contact_for(id_with_low_byte(0x01)); // distance 1   → bucket 0
        let mid = contact_for(id_with_low_byte(0x02)); // distance 2   → bucket 1
        let far = contact_for(id_with_high_byte(0x80)); // distance 2^255 → bucket 255
        rt.insert(far);
        rt.insert(near);
        rt.insert(mid);

        let two = rt.closest(&NodeId::ZERO, 2);
        assert_eq!(two, vec![near, mid]);

        let all = rt.closest(&NodeId::ZERO, 10);
        assert_eq!(all, vec![near, mid, far]);
    }

    #[test]
    fn closest_on_empty_table_is_empty() {
        let rt = RoutingTable::new(NodeId::ZERO);
        assert!(rt.closest(&id_with_low_byte(0x07), 8).is_empty());
    }

    // --- RPC handler (WS6-04.3) ---------------------------------------------

    #[test]
    fn handle_ping_returns_pong_and_learns_sender() {
        let mut node = DhtNode::new(NodeId::ZERO);
        let sender = top_bucket_contact(5);
        assert_eq!(node.handle(sender, RpcRequest::Ping), RpcResponse::Pong);
        // Every message teaches the node about its sender.
        assert!(node.routing_table().contains(&sender.id));
    }

    #[test]
    fn handle_store_then_find_value_returns_the_value() {
        let mut node = DhtNode::new(NodeId::ZERO);
        let sender = top_bucket_contact(1);
        let key = id_with_low_byte(0x2a);
        let value = b"hello-dht".to_vec();
        assert_eq!(
            node.handle(
                sender,
                RpcRequest::Store {
                    key,
                    value: value.clone(),
                },
            ),
            RpcResponse::Stored
        );
        assert_eq!(node.stored_len(), 1);
        assert_eq!(
            node.handle(sender, RpcRequest::FindValue { key }),
            RpcResponse::Value(value)
        );
    }

    #[test]
    fn find_value_miss_returns_closest_nodes() {
        let mut node = DhtNode::new(NodeId::ZERO);
        let a = top_bucket_contact(1);
        let b = top_bucket_contact(2);
        node.handle(a, RpcRequest::Ping);
        node.handle(b, RpcRequest::Ping);
        let resp = node.handle(
            a,
            RpcRequest::FindValue {
                key: id_with_low_byte(0x10),
            },
        );
        assert!(matches!(&resp, RpcResponse::Nodes(_)));
        if let RpcResponse::Nodes(nodes) = resp {
            assert!(nodes.iter().any(|c| c.id == a.id));
            assert!(nodes.iter().any(|c| c.id == b.id));
        }
    }

    #[test]
    fn find_node_returns_closest_contacts_nearest_first() {
        let mut node = DhtNode::new(NodeId::ZERO);
        let near = contact_for(id_with_low_byte(0x01));
        let far = contact_for(id_with_high_byte(0x80));
        node.handle(far, RpcRequest::Ping);
        node.handle(near, RpcRequest::Ping);
        let resp = node.handle(
            near,
            RpcRequest::FindNode {
                target: NodeId::ZERO,
            },
        );
        assert!(matches!(&resp, RpcResponse::Nodes(_)));
        if let RpcResponse::Nodes(nodes) = resp {
            assert_eq!(nodes.first().map(|c| c.id), Some(near.id));
        }
    }

    #[test]
    fn store_overwrites_existing_value() {
        let mut node = DhtNode::new(NodeId::ZERO);
        let sender = top_bucket_contact(1);
        let key = id_with_low_byte(0x05);
        node.handle(
            sender,
            RpcRequest::Store {
                key,
                value: b"v1".to_vec(),
            },
        );
        node.handle(
            sender,
            RpcRequest::Store {
                key,
                value: b"v2".to_vec(),
            },
        );
        assert_eq!(node.stored_len(), 1);
        assert_eq!(node.stored_value(&key), Some(b"v2".as_slice()));
    }

    #[test]
    fn note_contact_seeds_the_routing_table() {
        let mut node = DhtNode::new(NodeId::ZERO);
        let seed = top_bucket_contact(7);
        assert_eq!(node.note_contact(seed), InsertOutcome::Inserted);
        assert!(node.routing_table().contains(&seed.id));
    }

    // --- Iterative lookup (WS6-04.4) ----------------------------------------

    /// Build a chain network n1 → n2 → n4 → n8 (each node knows only the next),
    /// keyed by id, where the ids are `id_with_low_byte` of the given tags.
    fn chain_network() -> (HashMap<NodeId, DhtNode>, Vec<Contact>) {
        let tags = [0x01u8, 0x02, 0x04, 0x08];
        let contacts: Vec<Contact> = tags
            .iter()
            .map(|&t| contact_for(id_with_low_byte(t)))
            .collect();
        let mut net = HashMap::new();
        for (i, c) in contacts.iter().enumerate() {
            let mut node = DhtNode::new(c.id);
            // Each node knows only its successor in the chain.
            if let Some(next) = contacts.get(i + 1) {
                node.note_contact(*next);
            }
            net.insert(c.id, node);
        }
        (net, contacts)
    }

    #[test]
    fn iterative_find_node_walks_the_chain_to_the_target() {
        let (mut net, contacts) = chain_network();
        let me = contact_for(NodeId::ZERO);
        let target = id_with_low_byte(0x08); // the last node in the chain
        let seeds = contacts.first().copied().into_iter().collect::<Vec<_>>();

        let result = iterative_find_node(&seeds, target, |peer, t| {
            net.get_mut(&peer.id).map_or_else(Vec::new, |node| {
                match node.handle(me, RpcRequest::FindNode { target: t }) {
                    RpcResponse::Nodes(nodes) => nodes,
                    _ => Vec::new(),
                }
            })
        });

        // The node whose id == target has distance 0, so it must come first.
        assert_eq!(result.first().map(|c| c.id), Some(target));
    }

    #[test]
    fn iterative_find_value_returns_the_value_from_the_holder() {
        let (mut net, contacts) = chain_network();
        let me = contact_for(NodeId::ZERO);
        let key = id_with_low_byte(0x40);
        let value = b"federated-secret".to_vec();
        // Store the value at the last node in the chain.
        let holder = contacts.last().copied().unwrap_or(me);
        if let Some(node) = net.get_mut(&holder.id) {
            node.handle(
                me,
                RpcRequest::Store {
                    key,
                    value: value.clone(),
                },
            );
        }
        let seeds = contacts.first().copied().into_iter().collect::<Vec<_>>();

        let result = iterative_find_value(&seeds, key, |peer, k| {
            net.get_mut(&peer.id).map_or_else(
                || FindValueOutcome::Nodes(Vec::new()),
                |node| match node.handle(me, RpcRequest::FindValue { key: k }) {
                    RpcResponse::Value(v) => FindValueOutcome::Value(v),
                    RpcResponse::Nodes(nodes) => FindValueOutcome::Nodes(nodes),
                    _ => FindValueOutcome::Nodes(Vec::new()),
                },
            )
        });

        assert_eq!(
            result,
            LookupValue::Found {
                value,
                from: holder,
            }
        );
    }

    #[test]
    fn iterative_find_value_miss_returns_closest_nodes() {
        let (mut net, contacts) = chain_network();
        let me = contact_for(NodeId::ZERO);
        let key = id_with_low_byte(0x08); // nobody stores this key
        let seeds = contacts.first().copied().into_iter().collect::<Vec<_>>();

        let result = iterative_find_value(&seeds, key, |peer, k| {
            net.get_mut(&peer.id).map_or_else(
                || FindValueOutcome::Nodes(Vec::new()),
                |node| match node.handle(me, RpcRequest::FindValue { key: k }) {
                    RpcResponse::Value(v) => FindValueOutcome::Value(v),
                    RpcResponse::Nodes(nodes) => FindValueOutcome::Nodes(nodes),
                    _ => FindValueOutcome::Nodes(Vec::new()),
                },
            )
        });

        assert!(matches!(result, LookupValue::NotFound(_)));
        if let LookupValue::NotFound(nodes) = result {
            // The node whose id == key is the closest (distance 0).
            assert_eq!(nodes.first().map(|c| c.id), Some(key));
        }
    }

    #[test]
    fn iterative_find_node_with_no_seeds_is_empty() {
        let result = iterative_find_node(&[], id_with_low_byte(0x03), |_, _| Vec::new());
        assert!(result.is_empty());
    }

    // --- Bootstrap (WS6-04.5) -----------------------------------------------

    #[test]
    fn bootstrap_learns_the_reachable_network_from_one_seed() {
        let (mut net, contacts) = chain_network();
        let me = contact_for(NodeId::ZERO);
        let mut node = DhtNode::new(NodeId::ZERO);
        let seeds = contacts.first().copied().into_iter().collect::<Vec<_>>();

        let learned = node.bootstrap(&seeds, |peer, target| {
            net.get_mut(&peer.id).map_or_else(Vec::new, |n| {
                match n.handle(me, RpcRequest::FindNode { target }) {
                    RpcResponse::Nodes(nodes) => nodes,
                    _ => Vec::new(),
                }
            })
        });

        // The self-lookup transitively discovered the whole chain.
        assert_eq!(learned, contacts.len());
        for c in &contacts {
            assert!(node.routing_table().contains(&c.id));
        }
        // Our own id is never stored.
        assert!(!node.routing_table().contains(&NodeId::ZERO));
    }

    #[test]
    fn bootstrap_with_no_seeds_learns_nothing() {
        let mut node = DhtNode::new(NodeId::ZERO);
        let learned = node.bootstrap(&[], |_, _| Vec::new());
        assert_eq!(learned, 0);
        assert!(node.routing_table().is_empty());
    }

    #[test]
    fn bootstrap_skips_our_own_id_in_seeds() {
        let mut node = DhtNode::new(NodeId::ZERO);
        let self_seed = contact_for(NodeId::ZERO);
        let learned = node.bootstrap(&[self_seed], |_, _| Vec::new());
        assert_eq!(learned, 0);
        assert!(node.routing_table().is_empty());
    }
}
