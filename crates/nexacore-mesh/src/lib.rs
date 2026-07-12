//! # `nexacore-mesh`
//!
//! Federated mesh protocol implementation for NexaCore OS.
//!
//! Implements the peer-to-peer mesh that provides Tier 2 collective
//! compute. Specification lives in
//! [`/docs/03-mesh-protocol.md`](../../../docs/03-mesh-protocol.md);
//! this crate is the Rust implementation that conforms to it.
//!
//! ## Status
//!
//! Draft v0.1 — scaffold. Implementation arrives in Phase 4 per
//! [`/docs/06-roadmap.md`](../../../docs/06-roadmap.md). v1 release ships
//! with this crate's first stable interfaces.
//!
//! ## Design rationale
//!
//! - **Privacy by construction**: every payload carries a compliance proof
//!   and a TEE-only decryption envelope. Honest nodes (which is every
//!   node running this crate) reject malformed payloads. A non-compliant
//!   fork cannot pollute the mesh.
//! - **No central authority at runtime**: discovery is via Kademlia DHT;
//!   routing is locally decided per node; reputation is computed locally.
//! - **TEE attestation as identity**: a node's identity is its TEE
//!   attestation. Datacenter-cloning attacks are blocked at the
//!   attestation chain level.
//! - **MoE-friendly routing**: per-token expert dispatch with minimal
//!   cross-node traffic.
//!
//! ## Modules
//!
//! - [`discovery`] — Kademlia DHT peer discovery.
//! - [`transport`] — QUIC + Noise transport layer.
//! - [`attestation`] — peer attestation handshake.
//! - [`routing`] — workload routing across peers.
//! - [`credits`] — compute credit ledger (gossip-replicated).
//! - [`reputation`] — local reputation scoring.
//! - [`onion`] — 3-hop onion routing for sensitive workloads.
//! - [`compliance_proof`] — compliance proof envelope handling.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-mesh")]
#![deny(missing_docs)]

pub mod cluster_cert;

pub mod cluster_onboarding;

pub mod cluster_trust;

pub mod discovery;

pub mod handshake_attest;

pub mod handshake_auth;

pub mod handshake_fsm;

pub mod handshake_kex;

pub mod handshake_measurement;

pub mod handshake_version;

pub mod handshake_wire;

pub mod mdns;

pub mod mesh_handshake;

/// QUIC + Noise transport layer.
///
/// **Wire format (per NCIP-Serde-004, Active 2026-05-22).** All
/// mesh messages serialize via
/// [`nexacore_types::wire::encode_canonical`] / `decode_canonical`
/// (postcard 1.0). The wire schema is locked: little-endian
/// integers, postcard's varint length prefix on `Vec`/`String`,
/// enum discriminants in source-declaration order. See
/// `NCIP-Serde-004` § Motivation for the full history of this
/// choice; this docstring is the canonical pointer for future
/// maintainers.
pub mod transport {
    // TODO(phase-4): QUIC streams with Noise_XX handshake.
    //
    // Concrete message types arrive at the same time as the
    // QUIC streams (Phase 4 per docs/06-roadmap.md). At that
    // point the per-variant round-trip + maximum-size + fuzz
    // tests called for by TASK-022's acceptance criteria will
    // land in crates/nexacore-mesh/tests/wire_round_trip.rs; until
    // then there is nothing to round-trip and no test can
    // exist.
}

/// Peer attestation handshake.
pub mod attestation {
    // TODO(phase-4): mutual TEE attestation as part of handshake.
}

/// Workload routing across peers.
pub mod routing {
    // TODO(phase-4): per-token MoE expert routing.
}

pub mod credits;

pub mod onion;

pub mod reputation;

pub mod compliance_proof;

#[cfg(test)]
mod tests {
    /// Placeholder test asserting the crate compiles.
    #[test]
    fn placeholder() {}
}
