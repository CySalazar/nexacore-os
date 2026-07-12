//! Windows application path via Wine-in-container (WS9-04, NCIP P8.6).
//!
//! NexaCore runs Windows programs by launching them under **Wine inside a
//! NexaCore container** (the `nexacore/linux-wine:N-stable` guest image), with
//! their windows integrated into the desktop exactly like the Linux app path.
//! This module is the Wine-specific glue; it deliberately **composes** the
//! subsystems that already exist rather than re-implementing them:
//!
//! - **Window integration** ([`crate::appbridge`], WS9-03): the Wine guest runs
//!   the same guest agent, so its toplevels flow through the identical
//!   [`GuestImageManifest`],
//!   `GuestWindowRegistry`, `WindowBridge`, and clipboard/drag/audio channels.
//!   This module only adds the Wine-side adapters: the image builder, the
//!   `app_id` derivation, and the Windows→MIME clipboard mapping.
//! - **Confidential isolation** ([`crate::confidential`], WS9-01/WS10): the
//!   hardened-isolation option reuses [`ConfidentialVmConfig`].
//!
//! What is genuinely new here: the [`WinePrefix`] configuration (arch, Windows
//! version, DLL overrides, runtimes), the [`WineLaunchSpec`] for starting a
//! `.exe`, and the ProtonDB-style [`CompatDb`]. Building the real rootfs and the
//! the test VM end-to-end run (WS9-04.8) are the offline/rig follow-ups.

use std::collections::BTreeMap;

use nexacore_tee::CpuVendor;

use crate::{
    appbridge::image::{Digest, GuestImageManifest, GuestVirtioDevice, RootfsLayer},
    confidential::ConfidentialVmConfig,
};

/// Errors raised on the Wine app path.
///
/// The shared `Invalid` prefix reflects that every variant reports a
/// validation failure of a distinct input (executable / prefix / image).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub enum WineError {
    /// The launch target is not a plausible Windows executable.
    #[error("invalid Windows executable: {0}")]
    InvalidExecutable(&'static str),

    /// The Wine prefix configuration is inconsistent.
    #[error("invalid Wine prefix: {0}")]
    InvalidPrefix(&'static str),

    /// The assembled guest image failed validation (delegated to the app-bridge
    /// image validator).
    #[error("invalid Wine guest image: {0}")]
    InvalidImage(&'static str),
}

/// Result alias for the Wine app path.
pub type WineResult<T> = core::result::Result<T, WineError>;

// -----------------------------------------------------------------------------
// WS9-04.2 — Wine prefix + Windows runtimes
// -----------------------------------------------------------------------------

/// Wine prefix architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WineArch {
    /// 32-bit prefix (`win32`).
    Win32,
    /// 64-bit prefix (`win64`, WoW64-capable).
    Win64,
}

/// Emulated Windows version the prefix reports to applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsVersion {
    /// Windows 7.
    Win7,
    /// Windows 10.
    Win10,
    /// Windows 11.
    Win11,
}

/// A DLL load-order override (`WINEDLLOVERRIDES` semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DllOverride {
    /// Prefer the native (Windows) DLL.
    Native,
    /// Use Wine's built-in implementation.
    Builtin,
    /// Native first, built-in fallback.
    NativeThenBuiltin,
    /// Disable the DLL entirely.
    Disabled,
}

/// A Windows runtime component baked into the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsRuntime {
    /// Visual C++ 2015–2022 redistributable.
    Vcrun2022,
    /// .NET Framework 4.8.
    DotNet48,
    /// DXVK (`Direct3D` 9/10/11 → Vulkan).
    Dxvk,
    /// vkd3d-proton (`Direct3D` 12 → Vulkan).
    Vkd3dProton,
    /// Core Windows fonts.
    CoreFonts,
}

/// The Wine prefix configuration for a Windows guest image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinePrefix {
    /// Prefix architecture.
    pub arch: WineArch,
    /// Emulated Windows version.
    pub windows_version: WindowsVersion,
    /// Per-DLL load-order overrides.
    pub dll_overrides: BTreeMap<String, DllOverride>,
    /// Installed runtime components.
    pub runtimes: Vec<WindowsRuntime>,
}

impl WinePrefix {
    /// A sensible default: a 64-bit Windows 10 prefix with the common gaming /
    /// app runtimes (VC++ redist, DXVK, core fonts).
    #[must_use]
    pub fn default_win64() -> Self {
        Self {
            arch: WineArch::Win64,
            windows_version: WindowsVersion::Win10,
            dll_overrides: BTreeMap::new(),
            runtimes: vec![
                WindowsRuntime::Vcrun2022,
                WindowsRuntime::Dxvk,
                WindowsRuntime::CoreFonts,
            ],
        }
    }

    /// Add or replace a DLL override.
    #[must_use]
    pub fn with_override(mut self, dll: &str, mode: DllOverride) -> Self {
        self.dll_overrides.insert(dll.into(), mode);
        self
    }

    /// Whether the prefix installs `runtime`.
    #[must_use]
    pub fn has_runtime(&self, runtime: WindowsRuntime) -> bool {
        self.runtimes.contains(&runtime)
    }

    /// Validate the prefix configuration.
    ///
    /// # Errors
    ///
    /// [`WineError::InvalidPrefix`] if a Direct3D→Vulkan translation layer is
    /// requested on a `win32` prefix (DXVK/vkd3d require a 64-bit prefix), or a
    /// DLL override names an empty DLL.
    pub fn validate(&self) -> WineResult<()> {
        if self.dll_overrides.keys().any(String::is_empty) {
            return Err(WineError::InvalidPrefix("empty DLL override name"));
        }
        let needs_64 =
            self.has_runtime(WindowsRuntime::Dxvk) || self.has_runtime(WindowsRuntime::Vkd3dProton);
        if needs_64 && self.arch == WineArch::Win32 {
            return Err(WineError::InvalidPrefix(
                "DXVK/vkd3d require a 64-bit prefix",
            ));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// WS9-04.1 — Wine guest image assembly (over the app-bridge image manifest)
// -----------------------------------------------------------------------------

/// Builds the Wine-in-container guest image manifest.
///
/// The result is an ordinary [`GuestImageManifest`] (so the whole WS9-03 window
/// path applies unchanged) that additionally requires the audio and input
/// virtio devices Windows apps expect.
#[derive(Debug, Clone)]
pub struct WineImageBuilder {
    tag: String,
    kernel_digest: Digest,
    agent_path: String,
    agent_digest: Digest,
    layers: Vec<RootfsLayer>,
    prefix: WinePrefix,
}

impl WineImageBuilder {
    /// Start a builder for `tag` (e.g. `nexacore/linux-wine:1-stable`) over the
    /// given signed kernel, guest agent, and base rootfs layers.
    #[must_use]
    pub fn new(
        tag: String,
        kernel_digest: Digest,
        agent_path: String,
        agent_digest: Digest,
        layers: Vec<RootfsLayer>,
        prefix: WinePrefix,
    ) -> Self {
        Self {
            tag,
            kernel_digest,
            agent_path,
            agent_digest,
            layers,
            prefix,
        }
    }

    /// Assemble and validate the guest image manifest.
    ///
    /// # Errors
    ///
    /// [`WineError::InvalidPrefix`] if the prefix is inconsistent, or
    /// [`WineError::InvalidImage`] if the assembled manifest fails validation.
    pub fn build(self) -> WineResult<GuestImageManifest> {
        self.prefix.validate()?;
        let manifest = GuestImageManifest {
            tag: self.tag,
            kernel_digest: self.kernel_digest,
            agent_path: self.agent_path,
            agent_digest: self.agent_digest,
            rootfs_layers: self.layers,
            required_devices: vec![
                GuestVirtioDevice::Gpu,
                GuestVirtioDevice::Vsock,
                GuestVirtioDevice::Snd,
                GuestVirtioDevice::Input,
            ],
        };
        manifest
            .validate()
            .map_err(|_| WineError::InvalidImage("manifest validation failed"))?;
        Ok(manifest)
    }
}

// -----------------------------------------------------------------------------
// WS9-04.3 — launch a Windows executable
// -----------------------------------------------------------------------------

/// A request to launch a Windows executable inside the Wine container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WineLaunchSpec {
    /// Windows path of the executable (e.g. `C:\\Program Files\\App\\app.exe`).
    pub executable: String,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Optional working directory (Windows path).
    pub working_dir: Option<String>,
    /// Extra environment variables (`name`, `value`).
    pub env: Vec<(String, String)>,
}

impl WineLaunchSpec {
    /// A launch spec for `executable` with no arguments.
    #[must_use]
    pub fn new(executable: String) -> Self {
        Self {
            executable,
            args: Vec::new(),
            working_dir: None,
            env: Vec::new(),
        }
    }

    /// Validate the launch target.
    ///
    /// # Errors
    ///
    /// [`WineError::InvalidExecutable`] if the path is empty, contains a NUL, or
    /// does not end in `.exe`/`.bat`/`.com` (case-insensitive).
    // The extension check is intentionally case-insensitive: the path is
    // lower-cased first, so `ends_with` on a lower-case literal is correct.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    pub fn validate(&self) -> WineResult<()> {
        if self.executable.is_empty() {
            return Err(WineError::InvalidExecutable("empty path"));
        }
        if self.executable.contains('\0') {
            return Err(WineError::InvalidExecutable("path contains NUL"));
        }
        let lower = self.executable.to_ascii_lowercase();
        if !(lower.ends_with(".exe") || lower.ends_with(".bat") || lower.ends_with(".com")) {
            return Err(WineError::InvalidExecutable("not a Windows executable"));
        }
        Ok(())
    }

    /// The guest command line: `wine <exe> <args...>`.
    #[must_use]
    pub fn wine_command(&self) -> Vec<String> {
        let mut cmd = Vec::with_capacity(2 + self.args.len());
        cmd.push("wine".into());
        cmd.push(self.executable.clone());
        cmd.extend(self.args.iter().cloned());
        cmd
    }
}

// -----------------------------------------------------------------------------
// WS9-04.4 — window integration adapter (reuses WS9-03 appbridge)
// -----------------------------------------------------------------------------

/// Derive a stable Wayland-style `app_id` for a Wine window from its executable
/// path, so the WS9-03 [`WindowBridge`](crate::appbridge::WindowBridge) groups
/// and labels it like a native app.
///
/// `C:\\Program Files\\Foo\\bar.exe` → `wine.bar`.
#[must_use]
pub fn wine_app_id(executable: &str) -> String {
    let base = executable.rsplit(['\\', '/']).next().unwrap_or(executable);
    let stem = base.strip_suffix(".exe").unwrap_or(base);
    let stem = stem.strip_suffix(".EXE").unwrap_or(stem);
    let mut id = String::from("wine.");
    if stem.is_empty() {
        id.push_str("app");
    } else {
        id.push_str(&stem.to_ascii_lowercase());
    }
    id
}

// -----------------------------------------------------------------------------
// WS9-04.5 — Windows clipboard format mapping (transport reuses WS9-03)
// -----------------------------------------------------------------------------

/// A Windows clipboard format (`CF_*`) offered by a Wine app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardFormat {
    /// `CF_TEXT` (ANSI text).
    Text,
    /// `CF_UNICODETEXT`.
    UnicodeText,
    /// `CF_BITMAP` / `CF_DIB`.
    Bitmap,
    /// `CF_HDROP` (file drag list).
    FileList,
}

/// Map a Windows clipboard format to the MIME type the WS9-03
/// [`ClipboardBridge`](crate::appbridge::ClipboardBridge) carries.
#[must_use]
pub fn windows_clipboard_mime(format: ClipboardFormat) -> &'static str {
    match format {
        ClipboardFormat::Text => "text/plain",
        ClipboardFormat::UnicodeText => "text/plain;charset=utf-8",
        ClipboardFormat::Bitmap => "image/bmp",
        ClipboardFormat::FileList => "text/uri-list",
    }
}

// -----------------------------------------------------------------------------
// WS9-04.6 — ProtonDB-style compatibility tracking
// -----------------------------------------------------------------------------

/// Compatibility rating for a Windows application under Wine (ProtonDB-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompatRating {
    /// Does not run.
    Borked,
    /// Runs with significant issues.
    Bronze,
    /// Runs with minor issues.
    Silver,
    /// Runs well after tweaks.
    Gold,
    /// Runs flawlessly out of the box.
    Platinum,
}

impl CompatRating {
    /// Whether the app is usable (anything above [`CompatRating::Borked`]).
    #[must_use]
    pub fn is_playable(self) -> bool {
        self > Self::Borked
    }
}

/// A compatibility record for one application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatEntry {
    /// The app id ([`wine_app_id`]).
    pub app_id: String,
    /// Community compatibility rating.
    pub rating: CompatRating,
    /// Freeform notes (required tweaks, known issues).
    pub notes: String,
}

/// A local database of Windows-app compatibility, keyed by app id.
#[derive(Debug, Clone, Default)]
pub struct CompatDb {
    entries: BTreeMap<String, CompatEntry>,
}

impl CompatDb {
    /// An empty database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Insert or replace a compatibility record.
    pub fn record(&mut self, entry: CompatEntry) {
        self.entries.insert(entry.app_id.clone(), entry);
    }

    /// Look up an app's record.
    #[must_use]
    pub fn lookup(&self, app_id: &str) -> Option<&CompatEntry> {
        self.entries.get(app_id)
    }

    /// An app's rating, if known.
    #[must_use]
    pub fn rating_of(&self, app_id: &str) -> Option<CompatRating> {
        self.entries.get(app_id).map(|e| e.rating)
    }

    /// Number of recorded apps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// -----------------------------------------------------------------------------
// WS9-04.7 — hardened (confidential-VM) isolation option
// -----------------------------------------------------------------------------

/// The isolation posture of a Wine container.
///
/// Reuses [`ConfidentialVmConfig`] (WS9-01/WS10): "standard" is plain KVM,
/// "hardened" runs the container as a confidential VM (Intel TDX / AMD SEV-SNP)
/// so untrusted Windows software cannot read host memory even under a host
/// compromise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WineIsolation {
    /// The underlying confidential-VM configuration.
    pub vm_config: ConfidentialVmConfig,
}

impl WineIsolation {
    /// Standard isolation (software only, no hardware memory encryption).
    #[must_use]
    pub fn standard() -> Self {
        Self {
            vm_config: ConfidentialVmConfig::disabled(),
        }
    }

    /// Hardened isolation: a confidential VM chosen automatically for the host
    /// CPU vendor (falls back to standard on non-CoCo hardware).
    #[must_use]
    pub fn hardened(vendor: CpuVendor) -> Self {
        Self {
            vm_config: ConfidentialVmConfig::auto(vendor),
        }
    }

    /// Whether the container runs as a hardware-confidential VM.
    #[must_use]
    pub fn is_confidential(self) -> bool {
        self.vm_config.is_confidential()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn default_prefix_is_valid_and_win64() {
        let p = WinePrefix::default_win64();
        assert_eq!(p.arch, WineArch::Win64);
        assert!(p.has_runtime(WindowsRuntime::Dxvk));
        assert!(p.validate().is_ok());
    }

    #[test]
    fn dxvk_on_win32_is_rejected() {
        let mut p = WinePrefix::default_win64();
        p.arch = WineArch::Win32;
        assert_eq!(
            p.validate(),
            Err(WineError::InvalidPrefix(
                "DXVK/vkd3d require a 64-bit prefix"
            ))
        );
    }

    #[test]
    fn image_builder_requires_all_devices() {
        let builder = WineImageBuilder::new(
            "nexacore/linux-wine:1-stable".to_string(),
            [1u8; 32],
            "/usr/bin/nexacore-guest-agent".to_string(),
            [2u8; 32],
            vec![RootfsLayer {
                digest: [3u8; 32],
                uncompressed_size: 512 * 1024 * 1024,
            }],
            WinePrefix::default_win64(),
        );
        let manifest = builder.build().unwrap();
        assert!(manifest.requires(GuestVirtioDevice::Gpu));
        assert!(manifest.requires(GuestVirtioDevice::Snd));
        assert!(manifest.requires(GuestVirtioDevice::Input));
    }

    #[test]
    fn launch_spec_validates_executable() {
        assert!(
            WineLaunchSpec::new("C:\\App\\app.exe".to_string())
                .validate()
                .is_ok()
        );
        assert_eq!(
            WineLaunchSpec::new("C:\\App\\readme.txt".to_string()).validate(),
            Err(WineError::InvalidExecutable("not a Windows executable"))
        );
        assert_eq!(
            WineLaunchSpec::new(String::new()).validate(),
            Err(WineError::InvalidExecutable("empty path"))
        );
    }

    #[test]
    fn wine_command_prefixes_wine() {
        let mut spec = WineLaunchSpec::new("game.exe".to_string());
        spec.args = vec!["-fullscreen".to_string()];
        assert_eq!(
            spec.wine_command(),
            vec![
                "wine".to_string(),
                "game.exe".to_string(),
                "-fullscreen".to_string()
            ]
        );
    }

    #[test]
    fn app_id_derives_from_exe_basename() {
        assert_eq!(wine_app_id("C:\\Program Files\\Foo\\Bar.exe"), "wine.bar");
        assert_eq!(wine_app_id("notepad.EXE"), "wine.notepad");
        assert_eq!(wine_app_id("/mnt/c/app/x.exe"), "wine.x");
    }

    #[test]
    fn clipboard_formats_map_to_mime() {
        assert_eq!(
            windows_clipboard_mime(ClipboardFormat::UnicodeText),
            "text/plain;charset=utf-8"
        );
        assert_eq!(
            windows_clipboard_mime(ClipboardFormat::FileList),
            "text/uri-list"
        );
    }

    #[test]
    fn compat_db_records_and_ranks() {
        let mut db = CompatDb::new();
        db.record(CompatEntry {
            app_id: "wine.game".to_string(),
            rating: CompatRating::Gold,
            notes: "needs DXVK".to_string(),
        });
        assert_eq!(db.rating_of("wine.game"), Some(CompatRating::Gold));
        assert!(db.rating_of("wine.game").unwrap().is_playable());
        assert!(!CompatRating::Borked.is_playable());
        assert_eq!(db.rating_of("wine.unknown"), None);
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn isolation_standard_vs_hardened() {
        assert!(!WineIsolation::standard().is_confidential());
        assert!(WineIsolation::hardened(CpuVendor::Intel).is_confidential());
        assert!(WineIsolation::hardened(CpuVendor::Amd).is_confidential());
    }
}
