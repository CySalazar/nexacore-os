//! System tray and status interface.
//!
//! NexaCore Spark runs as a system tray application:
//! - **Linux**: tray icon via `libappindicator` / `StatusNotifierItem`.
//! - **Windows**: notification area icon.
//! - **macOS**: menu bar extra.
//!
//! The tray menu shows: tier, peer count, bandwidth, credits, uptime,
//! and provides actions (upgrade tier, settings, pause, quit).

use crate::{mesh_client::MeshStats, platform::DetectedPlatform};

/// UI state passed to the tray renderer.
#[derive(Debug, Clone)]
pub struct TrayState {
    /// Platform detection result (tier, backend name).
    pub platform: DetectedPlatform,
    /// Live mesh statistics.
    pub stats: MeshStats,
    /// Whether the mesh client is paused by user request.
    pub paused: bool,
    /// Whether a CVM upgrade is available but not active.
    pub cvm_upgrade_available: bool,
}

/// User actions from the tray menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    /// User clicked "Upgrade to Tier 0" (launch CVM).
    UpgradeToCvm,
    /// User clicked "Settings".
    OpenSettings,
    /// User clicked "Pause" / "Resume".
    TogglePause,
    /// User clicked "Quit".
    Quit,
}

/// Launches the system tray UI.
///
/// This function blocks until the user quits. It periodically polls
/// `stats_rx` for updated mesh statistics and redraws the tray menu.
///
/// # Errors
///
/// Returns [`crate::BridgeError::BackendInit`] if the tray icon cannot
/// be created (e.g., no display server available on Linux).
//
// `unused_async`: intentionally async; the tray event loop will use
// `.await` in NCIP-025 Phase 5.
#[allow(
    clippy::unused_async,
    reason = "tray event loop will use .await in NCIP-025 Phase 5"
)]
pub async fn run_tray(_platform: &DetectedPlatform) -> crate::Result<()> {
    // TODO(ncip-025-phase-5): Tray UI implementation.
    //
    // Library candidates:
    // - `tray-icon` crate (cross-platform, Rust-native)
    // - `ksni` (Linux StatusNotifierItem)
    // - `winrt` for Windows notification area
    // - `objc2` / `cocoa` for macOS NSStatusItem
    //
    // The settings panel (bandwidth caps, CPU allocation, CVM memory,
    // schedule, auto-start) will use `iced` or `egui` in a separate
    // window spawned on demand.

    tracing::info!("tray UI: not yet implemented — running headless");
    Ok(())
}
