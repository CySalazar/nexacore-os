//! # `nexacore-spark`
//!
//! **NexaCore Spark** — cross-platform desktop application that enables
//! Linux, Windows, and macOS users to participate in the NexaCore OS mesh
//! at the highest trust tier their hardware supports.
//!
//! ## Architecture (NCIP-025)
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                       NexaCore Spark                             │
//! │                                                              │
//! │  ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
//! │  │  Platform   │  │  Tier        │  │  Mesh Protocol       │ │
//! │  │  Detector   │  │  Provisioner │  │  Client              │ │
//! │  └──────┬──────┘  └──────┬───────┘  └──────────┬───────────┘ │
//! │         │                │                      │            │
//! │  ┌──────▼────────────────▼──────────────────────▼─────────┐ │
//! │  │                Security Substrate                       │ │
//! │  │  ┌────────┐  ┌──────────┐  ┌───────┐  ┌────────────┐  │ │
//! │  │  │  CVM   │  │ Platform │  │ TPM   │  │ Software   │  │ │
//! │  │  │ Tier 0 │  │ Enclave  │  │ 2.0   │  │ MPC        │  │ │
//! │  │  │        │  │ Tier 1   │  │Tier 2 │  │ Tier 3     │  │ │
//! │  │  └────────┘  └──────────┘  └───────┘  └────────────┘  │ │
//! │  └────────────────────────────────────────────────────────┘ │
//! │                                                              │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │               System Tray / Status UI                   │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Modules
//!
//! - [`platform`] — host hardware detection and tier assignment.
//! - [`backend`] — security substrate backends (CVM, SE, TPM, MPC).
//! - [`mesh_client`] — mesh protocol client for `std` targets.
//! - [`hardening`] — application-level security hardening.
//! - [`ui`] — system tray and status interface.
//! - [`config`] — user configuration and persistence.
//! - [`update`] — signed auto-update mechanism.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-spark")]
#![deny(missing_docs)]
// This `cfg_attr(test, allow(...))` is explicitly whitelisted by ADR-0003.
// Test code calls `.expect()` and `.unwrap()` for concise failure messages;
// these panics are acceptable inside `#[test]` functions.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic,))]

pub mod backend;
pub mod config;
pub mod hardening;
pub mod mesh_client;
pub mod platform;
pub mod ui;
pub mod update;

/// Application-wide result type.
pub type Result<T> = std::result::Result<T, BridgeError>;

/// Top-level error type for NexaCore Spark.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// Platform detection failed.
    #[error("platform detection failed: {0}")]
    PlatformDetection(String),

    /// The selected backend could not be initialized.
    #[error("backend initialization failed: {0}")]
    BackendInit(String),

    /// Mesh protocol error.
    #[error("mesh protocol error: {0}")]
    MeshProtocol(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// The requested operation requires a higher trust tier.
    #[error("tier insufficient: have {have}, need {need}")]
    TierInsufficient {
        /// The node's current tier.
        have: u8,
        /// The minimum tier required for the operation.
        need: u8,
    },

    /// TEE backend error (delegated from `nexacore-tee`).
    #[error("tee backend: {0}")]
    Tee(#[from] nexacore_tee::TeeError),
}

/// Initializes NexaCore Spark.
///
/// This is the main entry point called from `main.rs`. It:
/// 1. Detects the host platform and available security primitives.
/// 2. Provisions the highest-tier backend.
/// 3. Applies application hardening.
/// 4. Connects to the mesh (placeholder — NCIP-025 Phase 1).
/// 5. Launches the system tray UI (placeholder — NCIP-025 Phase 5).
///
/// Returns only on shutdown (user quit or fatal error).
///
/// # Errors
///
/// Returns [`BridgeError::PlatformDetection`] if platform probing fails,
/// [`BridgeError::BackendInit`] if the selected backend cannot be
/// initialized, or any other [`BridgeError`] variant from sub-systems.
//
// `unused_async`: the signature is intentionally `async` so that callers
// (including `main.rs`'s `rt.block_on(...)`) have a stable API surface;
// awaited calls will be added in NCIP-025 Phase 1 & 5.
#[allow(
    clippy::unused_async,
    reason = "awaited calls added in NCIP-025 Phase 1 & 5"
)]
pub async fn run() -> Result<()> {
    run_detect_and_provision()?;

    // Phase 4: Connect to the mesh
    // TODO(ncip-025-phase-1): mesh_client::connect(&backend).await?;

    // Phase 5: Launch UI
    // TODO(ncip-025-phase-5): ui::run_tray(&detected).await?;

    Ok(())
}

/// Executes Phase 1–3 of startup (detect, provision, harden).
///
/// Extracted to reduce the cognitive complexity of [`run`].
///
/// # Errors
///
/// Propagates any [`BridgeError`] from the detection, provisioning, or
/// hardening steps.
//
// `cognitive_complexity`: the tracing::info! macro expands into branching
// code that inflates Clippy's score beyond what the source complexity
// warrants. The function body itself has no nesting.
#[allow(
    clippy::cognitive_complexity,
    reason = "tracing::info! macro expansion inflates score; source logic has no nesting"
)]
fn run_detect_and_provision() -> Result<()> {
    // Phase 1: Detect platform capabilities
    let detected = platform::detect()?;
    tracing::info!(
        tier = detected.max_tier as u8,
        backend = %detected.backend_name(),
        cvm_available = detected.cvm_available,
        "platform detection complete"
    );

    // Phase 2: Provision the security backend
    let _backend = backend::provision(&detected)?;
    tracing::info!("security backend provisioned");

    // Phase 3: Apply application hardening
    hardening::apply()?;
    tracing::info!("application hardening applied");

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
