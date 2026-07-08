//! Confidential-VM mode selection and per-container attestation.
//!
//! See `NCIP-Container-006` § 6. On a TEE-capable host a container runs as a
//! *confidential VM* by default: its guest memory is hardware-encrypted (Intel
//! TDX or AMD SEV-SNP) and a per-container quote independently attests the
//! container's identity (guest kernel hash, OCI image digest, granted
//! capability set) separately from the host's mesh attestation.
//!
//! This module decides **which** confidential backend applies for a host CPU
//! ([`ConfidentialMode::for_vendor`]) and assembles the
//! [`crate::attestation::ContainerQuote`] by driving any
//! [`nexacore_tee::TeeBackend`] ([`build_container_quote`]). The vendor-specific
//! TDX/SEV-SNP hardware paths live in `nexacore-tee` (WS10-01 / WS10-02) and are
//! exercised on the rig; the selection logic and the quote assembly here are
//! platform-independent and host-tested with [`nexacore_tee::MockTeeBackend`].

use nexacore_tee::{CpuVendor, Nonce, TeeBackend, TeeFamily};

use crate::{ContainerError, ContainerResult, attestation::ContainerQuote, image::OciImageRef};

/// Which confidential-VM backend a container uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidentialMode {
    /// No hardware confidentiality (plain KVM). The container's memory is not
    /// hardware-encrypted; only software isolation applies.
    Disabled,
    /// Intel TDX trust domain.
    Tdx,
    /// AMD SEV-SNP encrypted VM.
    SevSnp,
}

impl ConfidentialMode {
    /// Select the confidential backend appropriate for a CPU vendor: Intel CPUs
    /// use TDX, AMD CPUs use SEV-SNP, anything else has no confidential mode.
    #[must_use]
    pub fn for_vendor(vendor: CpuVendor) -> Self {
        match vendor {
            CpuVendor::Intel => Self::Tdx,
            CpuVendor::Amd => Self::SevSnp,
            CpuVendor::Other => Self::Disabled,
        }
    }

    /// The TEE family this mode maps to, if any.
    #[must_use]
    pub fn tee_family(self) -> Option<TeeFamily> {
        match self {
            Self::Disabled => None,
            Self::Tdx => Some(TeeFamily::IntelTdx),
            Self::SevSnp => Some(TeeFamily::AmdSevSnp),
        }
    }

    /// Whether this mode provides hardware memory confidentiality.
    #[must_use]
    pub fn is_confidential(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// Per-container confidential-VM configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidentialVmConfig {
    /// The selected backend.
    pub mode: ConfidentialMode,
    /// When `true`, provisioning MUST fail closed if the confidential backend
    /// is unavailable rather than silently downgrading to a plain VM.
    pub required: bool,
}

impl ConfidentialVmConfig {
    /// A non-confidential configuration (plain KVM).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            mode: ConfidentialMode::Disabled,
            required: false,
        }
    }

    /// Auto-select the confidential backend for the host CPU vendor. The result
    /// is **not** marked `required`; a caller that demands confidentiality sets
    /// [`Self::required`] explicitly so provisioning fails closed.
    #[must_use]
    pub fn auto(vendor: CpuVendor) -> Self {
        Self {
            mode: ConfidentialMode::for_vendor(vendor),
            required: false,
        }
    }

    /// Whether confidentiality is active for this configuration.
    #[must_use]
    pub fn is_confidential(self) -> bool {
        self.mode.is_confidential()
    }
}

/// Build a [`ContainerQuote`] by challenging a [`TeeBackend`] with `nonce` and
/// binding the container's guest-kernel identity as the quote's report-data.
///
/// The host TEE measurement is taken from the backend's quote; the guest kernel
/// hash, OCI image, and capability-set hash are committed alongside it per
/// `NCIP-Container-006` § 6. A production binding hashes all three identity
/// fields into the report-data; this host-side assembly commits the guest
/// kernel hash (the primary container identity) and is the seam the
/// hardware-path NCIP extends.
///
/// # Errors
///
/// Returns [`ContainerError::Attestation`] if the backend's `attest` call
/// fails (e.g. no TEE hardware available).
pub fn build_container_quote(
    backend: &dyn TeeBackend,
    guest_kernel_hash: [u8; 32],
    image: OciImageRef,
    capability_set_hash: [u8; 32],
    nonce: &[u8],
) -> ContainerResult<ContainerQuote> {
    // The TEE nonce is a fixed 32 bytes; copy up to 32 of the verifier-supplied
    // bytes in, zero-padding any remainder.
    let mut nonce_bytes = [0u8; 32];
    let copy = nonce.len().min(32);
    if let (Some(dst), Some(src)) = (nonce_bytes.get_mut(..copy), nonce.get(..copy)) {
        dst.copy_from_slice(src);
    }
    let tee_nonce = Nonce(nonce_bytes);

    let quote = backend
        .attest(&tee_nonce, Some(&guest_kernel_hash))
        .map_err(|_| ContainerError::Attestation("confidential::attest"))?;

    Ok(ContainerQuote {
        host_measurement: quote.measurement,
        guest_kernel_hash,
        image,
        capability_set_hash,
        nonce: nonce.to_vec(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use nexacore_tee::{Measurement, MockTeeBackend};

    use super::*;

    #[test]
    fn vendor_selects_backend() {
        assert_eq!(
            ConfidentialMode::for_vendor(CpuVendor::Intel),
            ConfidentialMode::Tdx
        );
        assert_eq!(
            ConfidentialMode::for_vendor(CpuVendor::Amd),
            ConfidentialMode::SevSnp
        );
        assert_eq!(
            ConfidentialMode::for_vendor(CpuVendor::Other),
            ConfidentialMode::Disabled
        );
    }

    #[test]
    fn mode_maps_to_tee_family() {
        assert_eq!(
            ConfidentialMode::Tdx.tee_family(),
            Some(TeeFamily::IntelTdx)
        );
        assert_eq!(
            ConfidentialMode::SevSnp.tee_family(),
            Some(TeeFamily::AmdSevSnp)
        );
        assert_eq!(ConfidentialMode::Disabled.tee_family(), None);
        assert!(ConfidentialMode::Tdx.is_confidential());
        assert!(!ConfidentialMode::Disabled.is_confidential());
    }

    #[test]
    fn config_constructors() {
        assert!(!ConfidentialVmConfig::disabled().is_confidential());
        assert!(ConfidentialVmConfig::auto(CpuVendor::Intel).is_confidential());
        assert!(!ConfidentialVmConfig::auto(CpuVendor::Other).is_confidential());
    }

    #[test]
    fn quote_assembled_from_mock_backend() {
        let backend = MockTeeBackend::with_measurement(Measurement([9u8; 48]));
        let image = OciImageRef::parse("alpine:latest").expect("image");
        let quote =
            build_container_quote(&backend, [1u8; 32], image.clone(), [2u8; 32], &[0xAB, 0xCD])
                .expect("quote");
        assert_eq!(quote.guest_kernel_hash, [1u8; 32]);
        assert_eq!(quote.capability_set_hash, [2u8; 32]);
        assert_eq!(quote.image, image);
        assert_eq!(quote.nonce, vec![0xAB, 0xCD]);
        // The host measurement comes straight from the backend's quote.
        assert_eq!(quote.host_measurement.as_bytes(), &[9u8; 48]);
    }
}
