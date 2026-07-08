//! 3-hop onion routing for sensitive workloads (WS6-07).
//!
//! Sensitive workloads are routed through a circuit of three relays so that no
//! single relay learns both who the origin is and what the workload is. This
//! module defines the **onion packet format** (WS6-07.1 of the onion
//! sub-feature, plan item WS6-07.7): the nested, layer-encrypted structure a
//! circuit carries. Building a circuit (layered encryption, WS6-07.8) and
//! peeling one hop (WS6-07.9) build on the types here.
//!
//! # Format
//!
//! A packet is wrapped once per hop. Each relay holds a symmetric key shared
//! with the origin and uses it to peel exactly one [`OnionLayer`]. The
//! cleartext of a layer is either:
//!
//! - a **forward** layer — `tag=1`, a 32-byte next-hop [`NodeId`], then the
//!   inner bytes (the next layer's ciphertext); or
//! - an **exit** layer — `tag=0`, then the final payload bytes.
//!
//! A relay that peels a forward layer learns only the *next* hop, never the
//! origin or the ultimate destination; the exit relay learns the payload but
//! not the origin. That asymmetry is what hides the origin from intermediaries
//! (the WS6-07.12 property).

use std::collections::HashSet;

use nexacore_crypto::aead::{NexaCoreAeadKey, NexaCoreCiphertext, NexaCoreNonce, open, seal};

use crate::{
    discovery::{Contact, ID_BYTES, NodeId},
    reputation::ReputationBook,
};

/// The number of relays a sensitive workload is routed through.
pub const ONION_HOPS: usize = 3;

/// Layer tag: this layer forwards its inner bytes to a next hop.
const LAYER_FORWARD: u8 = 1;
/// Layer tag: this layer is the exit; its inner bytes are the final payload.
const LAYER_EXIT: u8 = 0;

/// Why an onion operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OnionError {
    /// The byte buffer was too short to hold the expected fields.
    #[error("onion layer is truncated")]
    Truncated,
    /// The layer tag byte was neither forward nor exit.
    #[error("unknown onion layer tag {0}")]
    BadTag(u8),
    /// A circuit must have at least one hop.
    #[error("onion circuit has no hops")]
    EmptyCircuit,
    /// Sealing a layer failed (an internal AEAD invariant).
    #[error("onion layer encryption failed")]
    Encrypt,
    /// Opening a layer failed — wrong key, or the layer was tampered with.
    #[error("onion layer decryption failed")]
    Decrypt,
}

/// The cleartext content of one onion layer (WS6-07.7).
///
/// `next` is `Some(hop)` for an intermediate layer (forward `inner` to `hop`)
/// or `None` for the exit layer (`inner` is the final payload). [`encode`] and
/// [`decode`] are the canonical byte layout that gets AEAD-sealed per hop when
/// a circuit is built (WS6-07.8).
///
/// [`encode`]: OnionLayer::encode
/// [`decode`]: OnionLayer::decode
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionLayer {
    /// The next hop to forward `inner` to, or `None` at the exit.
    pub next: Option<NodeId>,
    /// The inner bytes: the next layer's ciphertext, or the final payload.
    pub inner: Vec<u8>,
}

impl OnionLayer {
    /// A forward layer routing `inner` to `next`.
    #[must_use]
    pub fn forward(next: NodeId, inner: Vec<u8>) -> Self {
        Self {
            next: Some(next),
            inner,
        }
    }

    /// An exit layer carrying the final `payload`.
    #[must_use]
    pub fn exit(payload: Vec<u8>) -> Self {
        Self {
            next: None,
            inner: payload,
        }
    }

    /// Whether this is the exit layer (no further hop).
    #[must_use]
    pub fn is_exit(&self) -> bool {
        self.next.is_none()
    }

    /// Serialize to the canonical layer byte layout.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + ID_BYTES + self.inner.len());
        match &self.next {
            Some(node) => {
                out.push(LAYER_FORWARD);
                out.extend_from_slice(node.as_bytes());
            }
            None => out.push(LAYER_EXIT),
        }
        out.extend_from_slice(&self.inner);
        out
    }

    /// Parse a layer from the canonical byte layout.
    ///
    /// # Errors
    ///
    /// Returns [`OnionError::Truncated`] if `bytes` is too short for the tag or
    /// next-hop id, or [`OnionError::BadTag`] if the tag is unrecognised.
    pub fn decode(bytes: &[u8]) -> Result<Self, OnionError> {
        let (&tag, rest) = bytes.split_first().ok_or(OnionError::Truncated)?;
        match tag {
            LAYER_EXIT => Ok(Self::exit(rest.to_vec())),
            LAYER_FORWARD => {
                let id_bytes = rest.get(..ID_BYTES).ok_or(OnionError::Truncated)?;
                let mut id = [0u8; ID_BYTES];
                id.copy_from_slice(id_bytes);
                let inner = rest.get(ID_BYTES..).unwrap_or(&[]).to_vec();
                Ok(Self::forward(NodeId::from_bytes(id), inner))
            }
            other => Err(OnionError::BadTag(other)),
        }
    }
}

/// An onion-wrapped packet ready to enter a circuit (WS6-07.7).
///
/// `entry` is the first relay to hand the packet to; `payload` is the
/// outermost ciphertext, which that relay peels by one [`OnionLayer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionPacket {
    /// The entry relay the packet is handed to.
    pub entry: NodeId,
    /// The outermost layer ciphertext.
    pub payload: Vec<u8>,
}

impl OnionPacket {
    /// Assemble a packet from its entry hop and outermost ciphertext.
    #[must_use]
    pub fn new(entry: NodeId, payload: Vec<u8>) -> Self {
        Self { entry, payload }
    }
}

/// A relay in an onion circuit: its [`NodeId`] plus the symmetric key and
/// nonce the origin shares with it to seal/peel exactly one layer (WS6-07.8).
///
/// The key is established out of band (the QUIC+Noise handshake, WS6-04.6); here
/// it is taken as given. Each hop's [`NodeId`] is bound into the layer as AEAD
/// associated data, so a layer sealed for one relay cannot be opened by another
/// (it pins each layer to its intended hop).
#[derive(Clone)]
pub struct CircuitHop {
    /// The relay's id.
    pub id: NodeId,
    /// The symmetric key shared with this relay.
    pub key: NexaCoreAeadKey,
    /// The nonce used for this relay's single layer.
    pub nonce: NexaCoreNonce,
}

impl CircuitHop {
    /// Assemble a circuit hop.
    #[must_use]
    pub const fn new(id: NodeId, key: NexaCoreAeadKey, nonce: NexaCoreNonce) -> Self {
        Self { id, key, nonce }
    }
}

/// Seal one layer under `hop`'s key, binding the hop id as associated data.
fn seal_layer(hop: &CircuitHop, layer: &OnionLayer) -> Result<Vec<u8>, OnionError> {
    seal(&hop.key, &hop.nonce, hop.id.as_bytes(), &layer.encode())
        .map(|ct| ct.as_bytes().to_vec())
        .map_err(|_| OnionError::Encrypt)
}

/// Build an onion-wrapped packet for a circuit of `hops`, carrying `payload`
/// to the exit relay (WS6-07.8).
///
/// Layers are sealed from the inside out: the exit relay's layer wraps the
/// `payload`, and each earlier relay's layer wraps the next relay's ciphertext
/// plus its id. The result is an [`OnionPacket`] addressed to the first hop. A
/// 3-hop circuit ([`ONION_HOPS`]) is the canonical depth; any non-empty circuit
/// is accepted.
///
/// # Errors
///
/// Returns [`OnionError::EmptyCircuit`] if `hops` is empty, or
/// [`OnionError::Encrypt`] if sealing a layer fails.
pub fn build_circuit(hops: &[CircuitHop], payload: &[u8]) -> Result<OnionPacket, OnionError> {
    let (Some(first), Some(last)) = (hops.first(), hops.last()) else {
        return Err(OnionError::EmptyCircuit);
    };
    // Innermost: the exit layer carrying the final payload.
    let mut current = seal_layer(last, &OnionLayer::exit(payload.to_vec()))?;
    // Wrap each earlier hop around the next hop's ciphertext, last-but-one first.
    for i in (0..hops.len().saturating_sub(1)).rev() {
        let hop = hops.get(i).ok_or(OnionError::EmptyCircuit)?;
        let next_id = hops
            .get(i.saturating_add(1))
            .ok_or(OnionError::EmptyCircuit)?
            .id;
        current = seal_layer(hop, &OnionLayer::forward(next_id, current))?;
    }
    Ok(OnionPacket::new(first.id, current))
}

/// Peel one layer of an onion at `hop` (WS6-07.9).
///
/// Opens `ciphertext` under the hop's key (with its id as associated data) and
/// decodes the revealed [`OnionLayer`]. A forward layer tells the relay the next
/// hop and the inner ciphertext to send on; an exit layer reveals the final
/// payload. The relay learns *only* the next hop — never the origin.
///
/// # Errors
///
/// Returns [`OnionError::Decrypt`] if the layer cannot be authenticated under
/// this hop's key, or a decode error ([`OnionError::Truncated`] /
/// [`OnionError::BadTag`]) if the revealed bytes are malformed.
pub fn peel_layer(hop: &CircuitHop, ciphertext: &[u8]) -> Result<OnionLayer, OnionError> {
    let sealed = NexaCoreCiphertext::from_bytes(ciphertext.to_vec());
    let plaintext =
        open(&hop.key, &hop.nonce, hop.id.as_bytes(), &sealed).map_err(|_| OnionError::Decrypt)?;
    OnionLayer::decode(&plaintext)
}

/// Select a circuit of [`ONION_HOPS`] relays from `candidates` (typically the
/// peers a [`RoutingTable`](crate::discovery::RoutingTable) knows), ranked by
/// `reputation` (WS6-07.10).
///
/// Candidates whose id is in `exclude` (e.g. ourselves and the destination) or
/// whose reputation score is below `min_trust` are dropped; the rest are sorted
/// most-trustworthy-first, deduplicated by id, and the top [`ONION_HOPS`] are
/// returned in circuit order (entry first). Returns [`None`] if fewer than
/// [`ONION_HOPS`] relays qualify — better to refuse than to route through an
/// untrusted hop.
///
/// The caller establishes a shared key with each selected relay (WS6-04.6) to
/// turn the [`Contact`]s into [`CircuitHop`]s for [`build_circuit`].
#[must_use]
pub fn select_circuit(
    candidates: &[Contact],
    reputation: &ReputationBook,
    exclude: &[NodeId],
    min_trust: f64,
) -> Option<Vec<Contact>> {
    let mut seen = HashSet::new();
    let mut pool: Vec<Contact> = candidates
        .iter()
        .copied()
        .filter(|c| !exclude.contains(&c.id))
        .filter(|c| reputation.score(&c.id) >= min_trust)
        .filter(|c| seen.insert(c.id))
        .collect();
    pool.sort_by(|a, b| reputation.score(&b.id).total_cmp(&reputation.score(&a.id)));
    pool.truncate(ONION_HOPS);
    (pool.len() == ONION_HOPS).then_some(pool)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::reputation::Outcome;

    fn node(tag: u8) -> NodeId {
        let mut bytes = [0u8; ID_BYTES];
        if let Some(first) = bytes.first_mut() {
            *first = tag;
        }
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn forward_layer_round_trips() {
        let layer = OnionLayer::forward(node(7), vec![1, 2, 3, 4]);
        assert_eq!(OnionLayer::decode(&layer.encode()), Ok(layer.clone()));
        assert!(!layer.is_exit());
        assert_eq!(layer.next, Some(node(7)));
        assert_eq!(layer.inner, vec![1, 2, 3, 4]);
    }

    #[test]
    fn exit_layer_round_trips() {
        let layer = OnionLayer::exit(b"final-payload".to_vec());
        assert_eq!(OnionLayer::decode(&layer.encode()), Ok(layer.clone()));
        assert!(layer.is_exit());
        assert_eq!(layer.next, None);
        assert_eq!(layer.inner, b"final-payload");
    }

    #[test]
    fn exit_layer_may_carry_an_empty_payload() {
        let layer = OnionLayer::exit(Vec::new());
        assert_eq!(OnionLayer::decode(&layer.encode()), Ok(layer.clone()));
        assert!(layer.is_exit());
        assert!(layer.inner.is_empty());
    }

    #[test]
    fn forward_layer_may_carry_an_empty_inner() {
        let layer = OnionLayer::forward(node(3), Vec::new());
        assert_eq!(OnionLayer::decode(&layer.encode()), Ok(layer.clone()));
        assert_eq!(layer.next, Some(node(3)));
        assert!(layer.inner.is_empty());
    }

    #[test]
    fn decode_rejects_empty_input() {
        assert_eq!(OnionLayer::decode(&[]), Err(OnionError::Truncated));
    }

    #[test]
    fn decode_rejects_truncated_forward_id() {
        // Forward tag but fewer than ID_BYTES of next-hop id.
        let mut bytes = vec![LAYER_FORWARD];
        bytes.extend_from_slice(&[0u8; ID_BYTES - 1]);
        assert_eq!(OnionLayer::decode(&bytes), Err(OnionError::Truncated));
    }

    #[test]
    fn decode_rejects_unknown_tag() {
        assert_eq!(OnionLayer::decode(&[9, 0, 0]), Err(OnionError::BadTag(9)));
    }

    #[test]
    fn packet_holds_entry_and_payload() {
        let packet = OnionPacket::new(node(1), vec![0xaa, 0xbb]);
        assert_eq!(packet.entry, node(1));
        assert_eq!(packet.payload, vec![0xaa, 0xbb]);
    }

    #[test]
    fn three_hop_circuit_is_the_configured_depth() {
        assert_eq!(ONION_HOPS, 3);
    }

    // --- Circuit build + peel (WS6-07.8 / WS6-07.9) -------------------------

    fn hop(tag: u8) -> CircuitHop {
        let mut key = [0u8; 32];
        if let Some(b) = key.first_mut() {
            *b = tag;
        }
        let mut nonce = [0u8; 12];
        if let Some(b) = nonce.first_mut() {
            *b = tag;
        }
        CircuitHop::new(
            node(tag),
            NexaCoreAeadKey::from_bytes(key),
            NexaCoreNonce::from_bytes(nonce),
        )
    }

    #[test]
    fn three_hop_circuit_round_trips_and_hides_origin() {
        let hops = [hop(1), hop(2), hop(3)];
        let payload = b"sensitive-workload".to_vec();
        let packet = build_circuit(&hops, &payload).expect("build");
        // The origin hands the packet to the entry relay.
        assert_eq!(packet.entry, node(1));

        // Hop 1 peels one layer and learns only that the next hop is hop 2.
        let l1 = peel_layer(&hops[0], &packet.payload).expect("peel 1");
        assert_eq!(l1.next, Some(node(2)));
        assert!(!l1.is_exit());
        // It cannot see the payload — its inner is still ciphertext.
        assert_ne!(l1.inner, payload);

        // Hop 2 peels: next hop is hop 3.
        let l2 = peel_layer(&hops[1], &l1.inner).expect("peel 2");
        assert_eq!(l2.next, Some(node(3)));
        assert_ne!(l2.inner, payload);

        // Hop 3 peels the exit layer and recovers the payload.
        let l3 = peel_layer(&hops[2], &l2.inner).expect("peel 3");
        assert!(l3.is_exit());
        assert_eq!(l3.inner, payload);
    }

    #[test]
    fn single_hop_circuit_round_trips() {
        let hops = [hop(5)];
        let packet = build_circuit(&hops, b"direct").expect("build");
        assert_eq!(packet.entry, node(5));
        let layer = peel_layer(&hops[0], &packet.payload).expect("peel");
        assert!(layer.is_exit());
        assert_eq!(layer.inner, b"direct");
    }

    #[test]
    fn empty_circuit_is_rejected() {
        assert_eq!(build_circuit(&[], b"x"), Err(OnionError::EmptyCircuit));
    }

    #[test]
    fn peeling_with_the_wrong_key_fails() {
        let hops = [hop(1), hop(2), hop(3)];
        let packet = build_circuit(&hops, b"x").expect("build");
        // A relay that is not hop 1 cannot open the entry layer.
        assert_eq!(
            peel_layer(&hop(9), &packet.payload),
            Err(OnionError::Decrypt)
        );
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let hops = [hop(1), hop(2), hop(3)];
        let mut packet = build_circuit(&hops, b"x").expect("build");
        if let Some(b) = packet.payload.first_mut() {
            *b ^= 0xFF;
        }
        assert_eq!(
            peel_layer(&hops[0], &packet.payload),
            Err(OnionError::Decrypt)
        );
    }

    // --- Reputation-aware hop selection (WS6-07.10) -------------------------

    fn contact(tag: u8) -> Contact {
        Contact::new(
            node(tag),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4000),
        )
    }

    /// A book where nodes 1,2,3,5 are increasingly trustworthy and node 4 is
    /// untrustworthy (a divergence).
    fn good_book() -> ReputationBook {
        let mut book = ReputationBook::new();
        for (tag, n) in [(1u8, 10u32), (2, 8), (3, 6), (5, 4)] {
            for _ in 0..n {
                book.observe(node(tag), Outcome::Success);
            }
        }
        book.observe(node(4), Outcome::Divergence);
        book
    }

    #[test]
    fn selects_top_relays_by_reputation() {
        let book = good_book();
        let candidates = vec![contact(4), contact(2), contact(1), contact(3), contact(5)];
        let circuit = select_circuit(&candidates, &book, &[], 0.5).expect("enough relays");
        assert_eq!(circuit.len(), ONION_HOPS);
        assert_eq!(circuit[0].id, node(1));
        assert_eq!(circuit[1].id, node(2));
        assert_eq!(circuit[2].id, node(3));
        // The low-reputation node 4 is never selected.
        assert!(circuit.iter().all(|c| c.id != node(4)));
    }

    #[test]
    fn excludes_listed_nodes() {
        let book = good_book();
        let candidates = vec![contact(1), contact(2), contact(3), contact(5)];
        let circuit = select_circuit(&candidates, &book, &[node(1)], 0.5).expect("enough relays");
        assert_eq!(
            circuit.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![node(2), node(3), node(5)]
        );
    }

    #[test]
    fn refuses_when_too_few_trusted_relays() {
        let book = good_book();
        let candidates = vec![contact(1), contact(2), contact(3), contact(5)];
        // A high threshold leaves only nodes 1 and 2 — fewer than ONION_HOPS.
        assert!(select_circuit(&candidates, &book, &[], 0.9).is_none());
    }

    #[test]
    fn deduplicates_candidates_by_id() {
        let book = good_book();
        // node 1 appears twice; it must be counted once.
        let candidates = vec![contact(1), contact(1), contact(2), contact(3)];
        let circuit = select_circuit(&candidates, &book, &[], 0.5).expect("enough relays");
        assert_eq!(
            circuit.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![node(1), node(2), node(3)]
        );
    }
}
