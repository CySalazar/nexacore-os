//! Per-container attestation surface.
//!
//! See `NCIP-Container-006` § 6 ("Per-container TEE attestation").
//!
//! On TEE-capable hardware (TDX / SEV-SNP) the container runs as a
//! confidential VM. The host generates a quote that **separately
//! attests** the container's identity from the host's mesh
//! attestation:
//!
//! - Host TEE measurement (from [`nexacore_tee::TeeBackend::attest`]).
//! - Guest kernel image hash (signed by Stichting NexaCore).
//! - Container OCI image digest.
//! - Granted capability set (canonical encoding, hashed).
//! - Verifier-supplied nonce.
//!
//! Mesh peers verify the quote before accepting work-offload to the
//! container. A node can be a trusted mesh participant overall while
//! specific containers on it are independently attestable.

use crate::image::OciImageRef;

/// Per-container attestation quote produced by
/// [`crate::engine::ContainerEngine::attest`].
///
/// v0.1 status: the type definition is the public commitment from
/// `NCIP-Container-006` § 6; the concrete encoding (cose-sign1 or
/// equivalent) lands in a follow-up NCIP that wires the TDX / SEV-SNP
/// hardware attestation path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerQuote {
    /// Host TEE measurement — produced by
    /// [`nexacore_tee::TeeBackend::attest`] for the **host** measurement,
    /// kept as a 48-byte cross-vendor measurement per
    /// [`nexacore_tee::Measurement`].
    pub host_measurement: nexacore_tee::Measurement,
    /// SHA-256 hash of the Stichting-signed guest kernel image used
    /// by this container (matches the manifest hash published in the
    /// CT-style transparency log per `NCIP-Container-006` § 2).
    pub guest_kernel_hash: [u8; 32],
    /// OCI digest of the container image. Canonical form is
    /// `sha256:<64-hex>`; v0.1 keeps it as a typed reference to the
    /// image rather than the raw digest bytes.
    pub image: OciImageRef,
    /// Hash of the canonical encoding of the granted capability set.
    /// Per `NCIP-Container-006` § 6, the encoding routes through
    /// `nexacore-types::wire` (postcard, per `NCIP-Serde-004`).
    pub capability_set_hash: [u8; 32],
    /// Verifier-supplied nonce — bound to the quote at sign time to
    /// defeat replay. Length is verifier-controlled.
    pub nonce: Vec<u8>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn quote_construction_smoke() {
        // Build a deterministic dummy quote so the struct shape is
        // reachable from tests. Real construction happens inside the
        // engine implementations in follow-up NCIPs.
        let q = ContainerQuote {
            host_measurement: nexacore_tee::Measurement([7u8; 48]),
            guest_kernel_hash: [11u8; 32],
            image: OciImageRef::parse("alpine:latest").expect("parses"),
            capability_set_hash: [13u8; 32],
            nonce: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };

        assert_eq!(q.host_measurement.as_bytes()[0], 7);
        assert_eq!(q.guest_kernel_hash[0], 11);
        assert_eq!(q.capability_set_hash[0], 13);
        assert_eq!(q.nonce, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    #[allow(clippy::redundant_clone)] // intentional: exercising the Clone impl
    fn quote_implements_clone_and_eq() {
        let q1 = ContainerQuote {
            host_measurement: nexacore_tee::Measurement::zero(),
            guest_kernel_hash: [0u8; 32],
            image: OciImageRef::parse("alpine:latest").expect("parses"),
            capability_set_hash: [0u8; 32],
            nonce: vec![],
        };
        let q2 = q1.clone();
        assert_eq!(q1, q2);
    }
}
