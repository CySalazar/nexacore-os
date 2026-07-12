//! TEE attestation binding (placeholder for P5).
//!
//! This module declares the trait surface used by [`crate::token`] to
//! check that a capability's `subject` `NodeId` matches the
//! attestation of the calling node. The concrete implementation lands
//! in `nexacore-tee` (Phase 5 in the backlog); this trait exists in P1 so
//! the capability layer's API is final.
//!
//! # Why a trait, not a concrete type?
//!
//! Different TEE vendors expose different attestation formats (Intel
//! TDX `Quote v4`, AMD SEV-SNP `Attestation Report`, future `ARMv9`
//! CCA tokens). The capability layer must not bake in a single
//! format; instead it talks to the abstraction and lets the runtime
//! select the right backend.

use nexacore_types::{error::Result, identity::NodeId};

/// Source of TEE attestation evidence for the local node.
///
/// Implementors are vendor-specific (`nexacore_tee::tdx::TdxBackend`,
/// `nexacore_tee::snp::SnpBackend`, etc., per P5). The capability layer
/// uses this trait only to derive the calling node's `NodeId` from
/// its current attestation, so it can compare against the token's
/// declared `subject`.
pub trait AttestationSource {
    /// Return the `NodeId` derived from the current attestation
    /// quote.
    ///
    /// # Errors
    ///
    /// Returns an [`nexacore_types::NexaCoreError::Tee`] if attestation is
    /// unavailable, invalid, or stale.
    fn current_node_id(&self) -> Result<NodeId>;
}

/// A no-op attestation source for tests and offline tooling.
///
/// Returns the configured `NodeId` unconditionally. Production code
/// MUST NOT use this — it bypasses the TEE check entirely.
#[derive(Clone, Copy, Debug)]
pub struct StubAttestation {
    /// The fixed `NodeId` to return on every call.
    pub fixed_node_id: NodeId,
}

impl AttestationSource for StubAttestation {
    fn current_node_id(&self) -> Result<NodeId> {
        Ok(self.fixed_node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_configured_id() {
        let id = NodeId::from_attestation_hash([7u8; 32]);
        let stub = StubAttestation { fixed_node_id: id };
        assert_eq!(stub.current_node_id().unwrap(), id);
    }
}
