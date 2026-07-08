# Mesh Protocol

**Status:** Draft v0.1

## Overview

The NexaCore OS mesh is a peer-to-peer network of NexaCore OS instances that collectively perform AI inference (and, in v2, training) on behalf of their users. Privacy is enforced by cryptographic protocol design — not by node policy. A non-compliant node cannot produce valid network traffic; honest nodes reject malformed messages automatically.

This document specifies the protocol layers, from discovery to payload semantics.

## Design constraints

The protocol is designed to satisfy the following non-negotiable constraints:

1. **No central authority required at runtime.** Discovery, routing, authentication, and verification all proceed without a single point of trust.
2. **PII never appears in cleartext on the network.** Mandatory tokenization + TEE-only decryption envelopes.
3. **Every payload carries a compliance proof.** Honest nodes reject payloads without valid proofs.
4. **Forks are interoperable if protocol-compliant.** No vendor-specific extensions break the mesh.
5. **Hardware-rooted trust.** TEE attestation is required to participate.

## Protocol layers

### Discovery (Kademlia DHT)

Nodes discover peers via a Kademlia-based Distributed Hash Table.

- **Bootstrap**: handled by seed nodes operated by Stichting NexaCore in years 1–5; gradually decentralized via long-running well-reputed nodes.
- **Node ID**: derived from the TEE attestation report (deterministic but unforgeable).
- **Routing table**: standard Kademlia k-buckets, augmented with reputation and latency metadata.
- **Refresh**: periodic peer lookups to maintain table freshness.

### Transport (QUIC + Noise Protocol Framework)

All peer-to-peer connections use QUIC for transport, with the Noise Protocol Framework for cryptographic handshake.

QUIC is chosen for:

- Low-latency multiplexed streams (multiple concurrent inferences over one connection)
- Built-in encryption (no separate TLS layer required)
- 0-RTT resumption for repeat connections
- Connection migration support (mobile devices changing networks)
- Better behavior on lossy networks than TCP

Noise pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s` for mutual authentication. Mutual: both endpoints authenticate each other's TEE attestation. The NexaCore-specific handshake layer (Noise_IK + TEE attestation) negotiates `NexaCore-PROTO-v0.2`; see [`docs/protocol/handshake.md`](./protocol/handshake.md) for the full wire specification.

### Attestation (mandatory before any payload exchange)

Before any non-handshake traffic, both endpoints exchange remote attestation reports from their TEEs. The attestation report proves:

- The node runs a signed, unmodified NexaCore OS binary.
- The hardware is genuine and unmodified.
- The TEE measurements match a known-good state.

Attestation reports are verified using the TEE vendor's attestation chain (Intel TDX Quote Verification, AMD SEV-SNP attestation, etc.).

Failed attestation → connection terminated. No fallback to software-only attestation. This is the hard hardware requirement.

### Routing

Each node maintains a routing table indexing peers by:

- Latency (measured continuously via QUIC RTT)
- Reputation score (locally computed)
- Capability declarations (which experts/models the peer hosts)
- Geographic locality (optional, for jurisdiction-aware routing)

For each inference request, the local node selects a path optimizing for `latency × cost × (1 / reputation)`.

For sensitive workloads, optional onion routing through 3 hops is supported. Each hop sees only the previous and next hop, not the origin or the payload contents.

### Privacy primitives (mandatory at the protocol level)

Every payload on the mesh MUST:

1. **Be wrapped in a TEE-only decryption envelope.** The session key is sealed against the destination TEE's attestation. Only that specific TEE can decrypt.

2. **Contain a compliance proof.** A cryptographic proof (STARK (per NCIP-Crypto-002) for complex predicates, signature for simple predicates) demonstrating:
   - PII has been tokenized at the originating node.
   - The payload schema conforms to the protocol's encrypted-data-type definitions.
   - The session is bound to the attested TEE on the receiver.

3. **Use format-preserving encryption for routing metadata.** Even a peer node cannot tell what kind of inference is happening from headers alone.

A message lacking any of these three is rejected by every honest relay. Because relays revalidate, a malicious node cannot strip proofs and forward — the next honest hop will reject.

### Compute credits

A simple tit-for-tat ledger tracks compute contributed and consumed per node.

- Implemented as a signed, append-only log replicated via gossip protocol.
- Not a blockchain. Not a tradeable currency.
- Designed for v1 simplicity; can be replaced by a more sophisticated scheme via NCIP if needed.
- Anti-Sybil: credits accrue to attested TEE identities, not to bare network identities.

Credit semantics:

- 1 credit = 1 unit of standard compute work (TBD in detail; likely tied to FLOPs delivered or token output).
- Earn credits by serving inference; spend credits by requesting inference.
- Initial allocation: each newly-attested node receives a small starting balance to bootstrap participation.

### Reputation

Reputation is computed deterministically from observable signals:

- Uptime (rolling window)
- Successful inference completions (verified via redundancy checks)
- Consistency with peers (Byzantine detection: same input produces same output across redundant peers)
- Time in the network (sybil-resistance via age)

Reputation is **local**: each node computes its own view. Aggregate views are gossiped but never authoritative. This prevents reputation-system capture.

### Inference verification

For inference workloads where output integrity matters:

- Redundant execution on 2–3 independent peers
- Outputs compared bit-by-bit (deterministic quantization required)
- Disagreement triggers a "fourth-judge" run; majority wins
- Persistent disagreement is logged against the offending peer's reputation

For low-stakes workloads, single execution may be allowed by user policy.

## Workload distribution

### Personal Cluster (Tier 1)

- **Topology**: full mesh on LAN, no DHT needed.
- **Discovery**: mDNS.
- **Authentication**: shared secret bootstrapped at first device pairing, plus TEE attestation.
- **Workload split**: pipeline parallelism by default; tensor parallelism for very latency-sensitive tasks (only on LAN).
- **Models**: up to ~70B parameters across aggregated devices.

### Federated Mesh (Tier 2)

- **Topology**: Kademlia DHT.
- **Workload split**: expert parallelism (MoE).
- **Per-token routing**: only the 2 active experts per token need to be queried; other experts unaffected.
- **Latency**: dominated by network RTT × number of layers; suitable for async, long-form workloads.
- **Models**: 100B+ parameters distributed across hundreds of nodes.

## Wire format (v1 outline)

Messages on the mesh use a binary frame format:

```
+---------------------------------------------------+
| Frame header (FPE-encrypted routing metadata)     |
+---------------------------------------------------+
| Compliance proof envelope                         |
+---------------------------------------------------+
| TEE-sealed payload                                |
+---------------------------------------------------+
| HMAC over previous fields                         |
+---------------------------------------------------+
```

Detailed wire format will be specified in NCIP-001 prior to v1 release.

### Capability tokens (Macaroons-style)

Authority to perform a mesh action is carried by a `CapabilityToken` minted by the resource owner and verified by every relay. Tokens are defined in `crates/nexacore-capability` (closed P1.3 — 2026-05-10).

#### Pre-image layout

The signed pre-image is the canonical encoding of `TokenPayload`:

```
TokenPayload {
    id:      [u8; 16]      // CapabilityId (UUIDv4 layout)
    subject: [u8; 32]      // NodeId (BLAKE3 hash of TEE attestation quote)
    issuer:  [u8; 32]      // Ed25519 verifying key (compressed Edwards point)
    parent:  Option<[u8; 16]>  // None for root tokens, else parent CapabilityId
    scope:   Scope         // see below
}
```

`Scope` is encoded as the tuple `(action, resource, window, caveats)`:

```
Scope {
    action:   Action       // enum discriminant (Read | Write | Append | Execute |
                           //                    Delete | Connect | Listen |
                           //                    ModelInfer | ModelLoad |
                           //                    AgentSpawn | AgentSend)
    resource: Resource     // enum discriminant + payload (Any | Filesystem(String) |
                           //                              Network(String) | Model(ModelId) |
                           //                              Agent(AgentId) | Node(NodeId))
    window:   TimeWindow   // { not_before: u64, not_after: u64 } — Unix seconds
    caveats:  Vec<Caveat>  // length-prefixed sequence of attenuation caveats
}
```

`Caveat` variants are `ExpiresAt(u64)`, `NotBefore(u64)`, `BoundToNode(NodeId)`, `BoundToSession([u8; 16])`, and `Custom { tag: String, payload: Vec<u8> }`.

#### Encoding

* Encoder: `postcard` 1.0 via [`nexacore_types::wire::encode_canonical`](../crates/nexacore-types/src/wire.rs) per [`NCIP-Serde-004`](../oips/oip-serde-004.md) § S2 (Active since 2026-05-22 by `NCIP-Process-001` §5.3 ¶1 founder ballot — see [`docs/audits/ncip-editors-report-2026-Q2.md`](audits/oip-editors-report-2026-Q2.md)). Little-endian, length-prefixed `Vec` and `String` (varint length per postcard's canonical encoding), no length limit beyond `NexaCoreError::wire` bounds checking, no trailing data tolerated on decode (per `nexacore_types::wire::decode_canonical`'s explicit trailing-bytes check). See NCIP-Serde-004 § Motivation for the full history of why this encoder was selected over the originally-planned alternative.
* Field order: textual order in the struct definitions above. **Do NOT reorder fields without bumping the wire-protocol major version.**
* `Option`: 1-byte discriminant (`0x00` = `None`, `0x01` = `Some`) followed by the payload.
* Enum variants: 1-byte (or varint-extended) discriminant in source-declaration order.
* All integer types are little-endian.

This canonicalisation guarantees byte-identical pre-images across implementations and platforms — the security-critical invariant for `Ed25519` signature verification.

#### Signature

* Algorithm: `Ed25519` per RFC 8032. Verification uses `ed25519-dalek::VerifyingKey::verify_strict`, which rejects non-canonical R / A points (defends against malleability and small-subgroup attacks).
* Pre-image: the canonical encoding above.
* Signature length: 64 bytes (R || s).

#### Validation procedure

A relay or end-node validates a token by checking, in order:

1. **Signature** — `verify_strict` against the embedded `issuer` public key.
2. **Revocation** — token's `id` is not in the local `RevocationList`.
3. **Time window** — current monotonic clock time `now` satisfies `not_before ≤ now < not_after`.
4. **TEE binding** — the calling node's attestation derives a `NodeId` equal to the token's `subject`.
5. **Caveats** — every `Caveat` evaluates to `true` against the current request context. (`Custom` caveats are dispatched by `tag` to a `CaveatPredicate` impl registered by the consumer.)

For attenuated tokens, the validator additionally walks the parent chain and asserts at each step that the child scope is a subset of the parent scope (`nexacore_capability::attenuation::verify_chain_link`).

## Open problems (to be resolved before v1)

- **Anti-Sybil under TEE attestation**: how to prevent datacenter clones from gaming the system? Approach under consideration: rate-limit attestations per platform fingerprint + economic friction via compute credit bootstrapping.
- **MoE expert distribution policy**: who hosts which experts? Approach under consideration: voluntary advertisement + reputation-weighted assignment + redundant hosting for popular experts.
- **Cold start latency**: first-request latency when peers must be discovered. Approach: warm pool of pre-connected peers per node.
- **Bandwidth caps**: residential ISP-imposed caps interact poorly with mesh. Approach: scheduled-only mode (overnight) for residential nodes, cap honoring per user policy.
- **Quantum-resistant migration**: Noise + QUIC use classical crypto. Approach: PQ KEM hybridization (Kyber) by v1, full migration roadmap to 2030.

These will be addressed in NCIPs (NexaCore Improvement Proposals) before v1 release.

## Compatibility and forking

A fork of NexaCore OS that implements this protocol exactly is fully interoperable. Forks that modify the protocol form a separate mesh — they cannot poison the main mesh because honest nodes reject non-conforming traffic.

This is the structural guarantee against project capture: any captured Foundation can be forked, and the fork can rejoin the same mesh on the same protocol terms.
