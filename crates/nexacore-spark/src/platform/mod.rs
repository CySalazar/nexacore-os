//! Host platform detection and trust-tier assignment.
//!
//! At startup the bridge probes the host for available security
//! primitives and determines the highest achievable trust tier per
//! NCIP-024's four-tier model. The probe sequence is:
//!
//! 1. **Confidential VM support** (SEV-SNP / TDX) → Tier 0
//! 2. **Platform enclave** (Apple Secure Enclave) → Tier 1
//! 3. **TPM 2.0** → Tier 2
//! 4. **Software-only** fallback → Tier 3
//!
//! Platform-specific probe logic is isolated in submodules gated by
//! `cfg(target_os)` so the crate compiles cleanly on every target.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use core::fmt;

/// Trust tier levels per NCIP-024 § S1.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustTier {
    /// Full confidential computing (TDX / SEV-SNP via CVM).
    FullTee = 0,
    /// Hardware enclave for crypto operations (Apple SE, ARM CCA).
    EnclaveLimited = 1,
    /// Measured boot via TPM 2.0, no runtime memory protection.
    MeasuredBoot = 2,
    /// No hardware root of trust; software-only protocols.
    SoftwareOnly = 3,
}

impl fmt::Display for TrustTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullTee => write!(f, "Tier 0 (Full TEE)"),
            Self::EnclaveLimited => write!(f, "Tier 1 (Enclave-limited)"),
            Self::MeasuredBoot => write!(f, "Tier 2 (Measured boot)"),
            Self::SoftwareOnly => write!(f, "Tier 3 (Software-only)"),
        }
    }
}

/// Identifies which security backend to use.
#[derive(Debug, Clone)]
pub enum BackendKind {
    /// Confidential `MicroVM` with SEV-SNP attestation.
    CvmSevSnp,
    /// Confidential `MicroVM` with TDX attestation.
    CvmTdx,
    /// Apple Secure Enclave (macOS Apple Silicon).
    AppleSecureEnclave,
    /// TPM 2.0 measured boot.
    Tpm2,
    /// Software-only MPC (Ed25519 identity).
    SoftwareMpc,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CvmSevSnp => write!(f, "Confidential VM (SEV-SNP)"),
            Self::CvmTdx => write!(f, "Confidential VM (TDX)"),
            Self::AppleSecureEnclave => write!(f, "Apple Secure Enclave"),
            Self::Tpm2 => write!(f, "TPM 2.0"),
            Self::SoftwareMpc => write!(f, "Software MPC"),
        }
    }
}

/// Result of platform detection.
#[derive(Debug, Clone)]
pub struct DetectedPlatform {
    /// Highest trust tier achievable on this host.
    pub max_tier: TrustTier,
    /// Which security backend to activate.
    pub backend: BackendKind,
    /// Whether a confidential `MicroVM` can be launched (hardware TEE
    /// present on host, even if the user has not opted into CVM mode).
    pub cvm_available: bool,
    /// Human-readable description of the host platform.
    pub platform_description: String,
}

impl DetectedPlatform {
    /// Returns a short name for the selected backend.
    pub fn backend_name(&self) -> &str {
        match self.backend {
            BackendKind::CvmSevSnp => "cvm-sev-snp",
            BackendKind::CvmTdx => "cvm-tdx",
            BackendKind::AppleSecureEnclave => "apple-se",
            BackendKind::Tpm2 => "tpm2",
            BackendKind::SoftwareMpc => "software-mpc",
        }
    }
}

/// Probes the host platform and returns the detection result.
///
/// # Errors
///
/// Returns [`crate::BridgeError::PlatformDetection`] if a critical probe
/// fails (e.g., permission denied accessing `/dev/tpm0`). A probe
/// that simply finds no hardware returns the next-lower tier, not an
/// error.
//
// `unnecessary_wraps`: the `Result` return type is intentional API surface;
// future probe implementations (tss-esapi, WHP) will return real errors.
#[allow(
    clippy::unnecessary_wraps,
    reason = "Result is intentional API surface; hardware backend probes will return errors"
)]
pub fn detect() -> crate::Result<DetectedPlatform> {
    // Tier 0: Confidential VM support
    #[cfg(feature = "cvm")]
    if let Some(cvm) = probe_cvm_support() {
        return Ok(cvm);
    }

    // Tier 1: Platform enclave
    #[cfg(all(target_os = "macos", feature = "apple-se"))]
    if let Some(se) = probe_secure_enclave() {
        return Ok(se);
    }

    // Tier 2: TPM 2.0
    #[cfg(feature = "tpm2")]
    if let Some(tpm) = probe_tpm2() {
        return Ok(tpm);
    }

    // Tier 3: Software-only fallback
    Ok(DetectedPlatform {
        max_tier: TrustTier::SoftwareOnly,
        backend: BackendKind::SoftwareMpc,
        cvm_available: false,
        platform_description: format!(
            "{} {} — no hardware security primitives detected",
            std::env::consts::OS,
            std::env::consts::ARCH,
        ),
    })
}

/// Probes for confidential VM launch capability (SEV-SNP or TDX on host).
#[cfg(feature = "cvm")]
fn probe_cvm_support() -> Option<DetectedPlatform> {
    // Each platform branch is mutually exclusive via cfg; the active branch
    // is the final expression of this function on that target.
    #[cfg(target_os = "linux")]
    return linux::probe_cvm();

    #[cfg(target_os = "windows")]
    return windows::probe_cvm();

    // macOS: no CVM support (no SEV-SNP/TDX on Apple Silicon)
    #[cfg(target_os = "macos")]
    return None;

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    None
}

/// Probes for Apple Secure Enclave (macOS Apple Silicon only).
#[cfg(all(target_os = "macos", feature = "apple-se"))]
fn probe_secure_enclave() -> Option<DetectedPlatform> {
    macos::probe_secure_enclave()
}

/// Probes for TPM 2.0 presence.
#[cfg(feature = "tpm2")]
fn probe_tpm2() -> Option<DetectedPlatform> {
    #[cfg(target_os = "linux")]
    return linux::probe_tpm2();

    #[cfg(target_os = "windows")]
    return windows::probe_tpm2();

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_tier_ordering() {
        assert!(TrustTier::FullTee < TrustTier::EnclaveLimited);
        assert!(TrustTier::EnclaveLimited < TrustTier::MeasuredBoot);
        assert!(TrustTier::MeasuredBoot < TrustTier::SoftwareOnly);
    }

    #[test]
    fn detect_returns_at_least_tier_3() {
        let detected = detect().expect("detect should not fail");
        assert!(detected.max_tier <= TrustTier::SoftwareOnly);
    }

    #[test]
    fn backend_name_is_kebab_case() {
        let names = [
            BackendKind::CvmSevSnp,
            BackendKind::CvmTdx,
            BackendKind::AppleSecureEnclave,
            BackendKind::Tpm2,
            BackendKind::SoftwareMpc,
        ];
        for kind in &names {
            let platform = DetectedPlatform {
                max_tier: TrustTier::SoftwareOnly,
                backend: kind.clone(),
                cvm_available: false,
                platform_description: String::new(),
            };
            let name = platform.backend_name();
            assert!(!name.is_empty());
            assert!(
                !name.contains(' '),
                "backend name should be kebab-case: {name}"
            );
        }
    }
}
