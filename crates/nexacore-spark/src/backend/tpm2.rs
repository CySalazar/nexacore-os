//! TPM 2.0 measured-boot backend (Tier 2).
//!
//! Provides boot-time attestation via TPM 2.0 quotes and sealed
//! storage bound to PCR state. Runtime memory is NOT protected.
//!
//! ## Platform access
//!
//! | Platform | TPM interface                              |
//! |----------|--------------------------------------------|
//! | Linux    | `/dev/tpmrm0` via `tss-esapi` (Rust)      |
//! | Windows  | TBS API via `tss-esapi` Windows TBS TCTI   |
//!
//! ## PCR selection (NCIP-024 § S4.3)
//!
//! PCRs 0–7 cover firmware through boot loader. PCR 8–9 cover the
//! NexaCore Spark binary (via IMA on Linux, Measured Boot on
//! Windows).

#[cfg(feature = "tpm2")]
use super::DynBackend;
#[cfg(feature = "tpm2")]
use crate::BridgeError;

/// PCR indices included in the TPM quote.
pub const QUOTE_PCR_SELECTION: &[u32] = &[0, 1, 2, 4, 5, 7];

/// Extended PCR index for the application binary measurement.
pub const APP_MEASUREMENT_PCR: u32 = 14;

/// Initializes the TPM 2.0 backend.
///
/// Steps:
/// 1. Open a TPM context via the platform TCTI.
/// 2. Create or load an Attestation Identity Key (AIK).
/// 3. Verify TPM version is 2.0.
/// 4. Extend `APP_MEASUREMENT_PCR` with the bridge binary's hash.
/// 5. Return a `TeeBackend` that produces TPM quotes.
///
/// # Errors
///
/// Returns [`crate::BridgeError::BackendInit`] if the TPM context
/// cannot be opened (e.g., device missing, permission denied), the
/// AIK cannot be created, or PCR extension fails.
#[cfg(feature = "tpm2")]
pub fn init() -> crate::Result<DynBackend> {
    // TODO(ncip-025-phase-2): TPM 2.0 integration via tss-esapi.
    //
    // Implementation outline:
    // - tss_esapi::Context::new(Tcti::Device(DeviceConfig::default()))
    //   on Linux; Tcti::Tbs on Windows.
    // - TPM2_CreatePrimary for the storage root key (SRK).
    // - TPM2_Create for the AIK under the SRK.
    // - TPM2_PCR_Extend(APP_MEASUREMENT_PCR, SHA-384(self_binary)).
    // - TeeBackend::attest() → TPM2_Quote(aik, nonce, pcr_selection).
    // - TeeBackend::seal() → TPM2_Create with policyPCR.
    // - TeeBackend::unseal() → TPM2_Unseal.
    // - TeeBackend::derive_key_for() → TPM2_ECDH_ZGen + HKDF.
    //
    // Event log retrieval:
    // - Linux: read /sys/kernel/security/tpm0/binary_bios_measurements
    // - Windows: Tbsi_Get_TCG_Log()

    Err(BridgeError::BackendInit(
        "TPM 2.0 backend not yet implemented — see NCIP-025 Phase 2".into(),
    ))
}
