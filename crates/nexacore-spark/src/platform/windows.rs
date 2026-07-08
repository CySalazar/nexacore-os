//! Windows-specific platform probes.

#[cfg(any(feature = "cvm", feature = "tpm2"))]
use super::DetectedPlatform;

/// Probes for confidential VM support on Windows.
///
/// Checks for Hyper-V availability and SEV-SNP/TDX passthrough
/// capability via the Windows Hypervisor Platform (WHP) API.
#[cfg(feature = "cvm")]
pub(super) fn probe_cvm() -> Option<DetectedPlatform> {
    // TODO(ncip-025-phase-4): Check Hyper-V + WHP API availability.
    // For now, CVM on Windows requires manual detection.
    //
    // Detection strategy:
    // 1. Check if Hyper-V role is installed via WMI or registry.
    // 2. Check WHvGetCapability for WHvCapabilityCodeHypervisorPresent.
    // 3. Check for SEV-SNP/TDX passthrough capability.
    tracing::debug!("Windows CVM probe: not yet implemented");
    None
}

/// Probes for TPM 2.0 on Windows.
///
/// Uses the TPM Base Services (TBS) API to detect TPM presence and
/// version.
#[cfg(feature = "tpm2")]
pub(super) fn probe_tpm2() -> Option<DetectedPlatform> {
    // TODO(ncip-025-phase-2): Use Tbsi_GetDeviceInfo() to detect TPM.
    //
    // Detection strategy:
    // 1. Call Tbsi_GetDeviceInfo() — returns TPM_DEVICE_INFO.
    // 2. Check tpmVersion >= TPM_VERSION_20.
    // 3. Optionally check VBS availability for enhanced key protection.
    //
    // For now, assume TPM 2.0 is present on Windows 11 (it's a
    // hardware requirement), but return None until the TBS FFI is wired.
    tracing::debug!("Windows TPM probe: not yet implemented");
    None
}
