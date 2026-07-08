//! Mesh protocol client for `std` targets.
//!
//! This module embeds a subset of `nexacore-mesh` compiled for conventional
//! operating systems. It handles:
//!
//! - Kademlia DHT peer discovery (via bootstrap seed nodes).
//! - QUIC + Noise transport with tier-aware attestation handshake.
//! - Relay (forward-only) for Tier 2–3 nodes.
//! - Bandwidth contribution and reputation witness roles.
//! - Compute-credit ledger participation.
//!
//! Expert shard hosting and PII-bearing inference are available only
//! when the CVM backend is active (Tier 0).

use crate::platform::TrustTier;

/// Default QUIC port for mesh peer-to-peer traffic.
pub const DEFAULT_MESH_PORT: u16 = 4433;

/// Bootstrap seed nodes operated by Stichting NexaCore.
pub const BOOTSTRAP_SEEDS: &[&str] = &[
    // TODO(ncip-025-phase-1): Replace with actual seed node addresses.
    // These are placeholders for the bootstrap infrastructure.
];

/// Roles this node can perform based on its trust tier.
///
/// Each field maps directly to an NCIP-024 § S5 capability bit.
/// The boolean representation is intentional: it mirrors the wire
/// format and avoids a bitflags dependency for what is ultimately
/// a simple role record.
#[allow(
    clippy::struct_excessive_bools,
    reason = "Each bool is a distinct NCIP-024 role capability; a bitflags type would obscure the role semantics"
)]
#[derive(Debug, Clone)]
pub struct NodeRoles {
    /// Can relay encrypted packets without inspecting payloads.
    pub relay: bool,
    /// Can witness and attest to peer behavior for reputation.
    pub reputation_witness: bool,
    /// Can contribute bandwidth to the mesh.
    pub bandwidth_contributor: bool,
    /// Can host expert shards for MoE inference (Tier 0 only).
    pub expert_shard_host: bool,
    /// Can handle PII-bearing inference requests (Tier 0 only).
    pub pii_inference: bool,
}

impl NodeRoles {
    /// Determines roles based on the node's trust tier per NCIP-024 § S5.
    #[must_use]
    pub fn for_tier(tier: TrustTier) -> Self {
        match tier {
            TrustTier::FullTee => Self {
                relay: true,
                reputation_witness: true,
                bandwidth_contributor: true,
                expert_shard_host: true,
                pii_inference: true,
            },
            // Tier 1 and Tier 2 have identical role sets: relay + witness +
            // bandwidth, but no expert shard hosting or PII inference.
            TrustTier::EnclaveLimited | TrustTier::MeasuredBoot => Self {
                relay: true,
                reputation_witness: true,
                bandwidth_contributor: true,
                expert_shard_host: false,
                pii_inference: false,
            },
            TrustTier::SoftwareOnly => Self {
                relay: true,
                reputation_witness: false,
                bandwidth_contributor: true,
                expert_shard_host: false,
                pii_inference: false,
            },
        }
    }
}

/// Mesh connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected to any peers.
    Disconnected,
    /// Performing bootstrap DHT lookup.
    Bootstrapping,
    /// Connected to the mesh and participating.
    Connected {
        /// Number of connected peers.
        peer_count: usize,
    },
    /// Encountered an error; will retry.
    Reconnecting {
        /// Number of retry attempts so far.
        attempts: u32,
    },
}

/// Mesh client statistics exposed to the UI.
#[derive(Debug, Clone, Default)]
pub struct MeshStats {
    /// Current connection state.
    pub state: Option<ConnectionState>,
    /// Number of connected peers.
    pub peer_count: usize,
    /// Upload bytes per second (rolling average).
    pub upload_bps: u64,
    /// Download bytes per second (rolling average).
    pub download_bps: u64,
    /// Net compute credits (earned - spent).
    pub net_credits: f64,
    /// Uptime in seconds.
    pub uptime_secs: u64,
}

/// Connects to the mesh and begins participating.
///
/// This function runs until the application shuts down. It handles
/// reconnection on transient failures.
///
/// # Errors
///
/// Returns [`crate::BridgeError::MeshProtocol`] if the mesh connection
/// cannot be established after exhausting retries, or if a fatal
/// protocol error occurs during operation.
//
// `unused_async`: intentionally async; the main connection loop
// (QUIC bind, DHT bootstrap, peer handshake) will use `.await` in
// NCIP-025 Phase 1.
#[allow(
    clippy::unused_async,
    reason = "QUIC/DHT loop will use .await in NCIP-025 Phase 1"
)]
pub async fn connect(tier: TrustTier) -> crate::Result<()> {
    let roles = NodeRoles::for_tier(tier);
    tracing::info!(
        tier = tier as u8,
        relay = roles.relay,
        reputation_witness = roles.reputation_witness,
        expert_shard_host = roles.expert_shard_host,
        "mesh client starting with roles"
    );

    // TODO(ncip-025-phase-1): Mesh connection implementation.
    //
    // Steps:
    // 1. Bind QUIC listener on DEFAULT_MESH_PORT (or random if taken).
    // 2. Bootstrap DHT from BOOTSTRAP_SEEDS.
    // 3. Perform attestation handshake with discovered peers.
    // 4. Enter main loop: relay packets, update reputation, gossip credits.
    // 5. Handle graceful shutdown on SIGTERM / user quit.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_0_has_all_roles() {
        let roles = NodeRoles::for_tier(TrustTier::FullTee);
        assert!(roles.relay);
        assert!(roles.reputation_witness);
        assert!(roles.bandwidth_contributor);
        assert!(roles.expert_shard_host);
        assert!(roles.pii_inference);
    }

    #[test]
    fn tier_2_cannot_host_experts() {
        let roles = NodeRoles::for_tier(TrustTier::MeasuredBoot);
        assert!(roles.relay);
        assert!(!roles.expert_shard_host);
        assert!(!roles.pii_inference);
    }

    #[test]
    fn tier_3_minimal_roles() {
        let roles = NodeRoles::for_tier(TrustTier::SoftwareOnly);
        assert!(roles.relay);
        assert!(roles.bandwidth_contributor);
        assert!(!roles.reputation_witness);
        assert!(!roles.expert_shard_host);
        assert!(!roles.pii_inference);
    }
}
