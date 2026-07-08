//! Apple Secure Enclave backend (Tier 1).
//!
//! On macOS with Apple Silicon, the Secure Enclave provides:
//! - Hardware-bound key generation (P-256 ECDSA/ECDH).
//! - App Attest assertions for mesh attestation.
//! - Biometric-gated key release (Touch ID / Face ID).
//!
//! The private key never leaves the Secure Enclave. Signing and key
//! agreement operations are performed inside the enclave via the
//! Security.framework API.
//!
//! ## Entitlements required
//!
//! The application must declare:
//! - `com.apple.security.device.apple-secure-enclave`
//! - `com.apple.developer.devicecheck.appattest-environment`

#[cfg(all(target_os = "macos", feature = "apple-se"))]
use super::DynBackend;
#[cfg(all(target_os = "macos", feature = "apple-se"))]
use crate::BridgeError;

/// Initializes the Apple Secure Enclave backend.
///
/// Steps:
/// 1. Check Secure Enclave availability via `SecureEnclave.isAvailable`.
/// 2. Generate or load the mesh identity key in the Secure Enclave.
/// 3. Initialize the App Attest service for attestation.
/// 4. Return a `TeeBackend` that delegates crypto ops to the enclave.
#[cfg(all(target_os = "macos", feature = "apple-se"))]
pub fn init() -> crate::Result<DynBackend> {
    // TODO(ncip-025-phase-3): Secure Enclave integration via
    // Security.framework FFI.
    //
    // Implementation outline:
    // - SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave
    //   and kSecAttrKeyTypeECSECPrimeRandom (P-256).
    // - Store key reference in Keychain with
    //   kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
    // - DCAppAttestService.shared.attestKey() for App Attest.
    // - SecKeyCreateSignature for mesh handshake signatures.
    // - SecKeyCopyKeyExchangeResult for ECDH key agreement.

    Err(BridgeError::BackendInit(
        "Apple Secure Enclave backend not yet implemented — see NCIP-025 Phase 3".into(),
    ))
}
