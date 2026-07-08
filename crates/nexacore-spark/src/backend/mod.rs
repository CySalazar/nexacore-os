//! Security substrate backends.
//!
//! Each backend implements the `nexacore_tee::TeeBackend` trait for a
//! specific security tier. The [`provision`] function selects and
//! initializes the appropriate backend based on platform detection.

pub mod cvm;
pub mod secure_enclave;
pub mod software_mpc;
pub mod tpm2;

use nexacore_tee::traits::TeeBackend;

use crate::{BridgeError, platform::DetectedPlatform};

/// A boxed, type-erased TEE backend suitable for mesh operations.
pub type DynBackend = Box<dyn TeeBackend>;

/// Provisions the security backend matching the detected platform.
///
/// # Errors
///
/// Returns [`BridgeError::BackendInit`] if the selected backend
/// fails to initialize (e.g., TPM 2.0 context creation fails due to
/// permissions).
pub fn provision(platform: &DetectedPlatform) -> crate::Result<DynBackend> {
    use crate::platform::BackendKind;

    match &platform.backend {
        #[cfg(feature = "cvm")]
        BackendKind::CvmSevSnp | BackendKind::CvmTdx => cvm::init(platform),

        #[cfg(all(target_os = "macos", feature = "apple-se"))]
        BackendKind::AppleSecureEnclave => secure_enclave::init(),

        #[cfg(feature = "tpm2")]
        BackendKind::Tpm2 => tpm2::init(),

        BackendKind::SoftwareMpc => software_mpc::init(),

        #[allow(unreachable_patterns)]
        other => Err(BridgeError::BackendInit(format!(
            "backend {other} not available in this build (missing feature flag)"
        ))),
    }
}
