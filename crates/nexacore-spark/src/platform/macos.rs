//! macOS-specific platform probes.

#[cfg(feature = "apple-se")]
use super::{BackendKind, DetectedPlatform, TrustTier};

/// Probes for Apple Secure Enclave on macOS.
///
/// On Apple Silicon Macs, the Secure Enclave is always present. On
/// Intel Macs, it is not available. We detect architecture to
/// determine availability.
#[cfg(feature = "apple-se")]
pub(super) fn probe_secure_enclave() -> Option<DetectedPlatform> {
    // Apple Secure Enclave is available on Apple Silicon (aarch64).
    // Intel Macs do not have a Secure Enclave.
    if std::env::consts::ARCH == "aarch64" {
        tracing::info!("Apple Silicon detected — Secure Enclave available");
        Some(DetectedPlatform {
            max_tier: TrustTier::EnclaveLimited,
            backend: BackendKind::AppleSecureEnclave,
            cvm_available: false,
            platform_description: "macOS aarch64 — Apple Secure Enclave".into(),
        })
    } else {
        tracing::debug!("Intel Mac detected — no Secure Enclave");
        None
    }
}
