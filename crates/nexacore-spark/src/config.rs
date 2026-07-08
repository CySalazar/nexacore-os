//! User configuration and persistence.
//!
//! Configuration is stored as a TOML file in the platform-appropriate
//! application data directory:
//!
//! | Platform | Path                                                |
//! |----------|-----------------------------------------------------|
//! | Linux    | `$XDG_CONFIG_HOME/nexacore-spark/config.toml`     |
//! | macOS    | `~/Library/Application Support/nexacore-spark/config.toml` |
//! | Windows  | `%APPDATA%\nexacore-spark\config.toml`            |

use std::path::PathBuf;

/// Application configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeConfig {
    /// Maximum upload bandwidth in Mbps (0 = unlimited).
    #[serde(default = "default_bandwidth_cap")]
    pub upload_cap_mbps: u32,

    /// Maximum download bandwidth in Mbps (0 = unlimited).
    #[serde(default = "default_bandwidth_cap")]
    pub download_cap_mbps: u32,

    /// Percentage of CPU cores available to the mesh (1–100).
    #[serde(default = "default_cpu_percent")]
    pub cpu_percent: u8,

    /// Memory allocated to the CVM in MiB (only used in CVM mode).
    #[serde(default = "default_cvm_memory")]
    pub cvm_memory_mib: u32,

    /// Whether to start the bridge at system login.
    #[serde(default)]
    pub auto_start: bool,

    /// Whether CVM mode is enabled (opt-in, requires TEE hardware).
    #[serde(default)]
    pub cvm_enabled: bool,

    /// Update channel: "stable" or "beta".
    #[serde(default = "default_update_channel")]
    pub update_channel: String,

    /// Mesh schedule: if set, the bridge only participates during
    /// these hours (24h format, local time). E.g., "22:00-06:00".
    #[serde(default)]
    pub schedule: Option<String>,
}

fn default_bandwidth_cap() -> u32 {
    0
}
fn default_cpu_percent() -> u8 {
    50
}
fn default_cvm_memory() -> u32 {
    512
}
fn default_update_channel() -> String {
    "stable".into()
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            upload_cap_mbps: default_bandwidth_cap(),
            download_cap_mbps: default_bandwidth_cap(),
            cpu_percent: default_cpu_percent(),
            cvm_memory_mib: default_cvm_memory(),
            auto_start: false,
            cvm_enabled: false,
            update_channel: default_update_channel(),
            schedule: None,
        }
    }
}

/// Returns the platform-appropriate configuration directory.
#[must_use]
pub fn config_dir() -> PathBuf {
    let base = dirs_path();
    base.join("nexacore-spark")
}

/// Returns the path to the configuration file.
#[must_use]
pub fn config_file() -> PathBuf {
    config_dir().join("config.toml")
}

/// Loads the configuration from disk, or returns defaults if the
/// file does not exist.
///
/// # Errors
///
/// Returns [`crate::BridgeError::Config`] if the configuration file
/// exists but cannot be read (e.g., permission denied) or contains
/// invalid TOML.
pub fn load() -> crate::Result<BridgeConfig> {
    let path = config_file();
    if !path.exists() {
        tracing::info!("no config file found at {}, using defaults", path.display());
        return Ok(BridgeConfig::default());
    }

    let contents = std::fs::read_to_string(&path)
        .map_err(|e| crate::BridgeError::Config(format!("read {}: {e}", path.display())))?;

    toml_parse(&contents)
}

/// Saves the configuration to disk.
///
/// # Errors
///
/// Returns [`crate::BridgeError::Config`] if the configuration
/// directory cannot be created, the file cannot be written, or
/// serialization fails.
pub fn save(config: &BridgeConfig) -> crate::Result<()> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| crate::BridgeError::Config(format!("create dir {}: {e}", dir.display())))?;

    let path = config_file();
    let contents = toml_serialize(config)?;
    std::fs::write(&path, contents)
        .map_err(|e| crate::BridgeError::Config(format!("write {}: {e}", path.display())))?;

    tracing::info!("configuration saved to {}", path.display());
    Ok(())
}

// `disallowed_methods`: `std::env::var` is used here only to resolve the
// platform-appropriate base config directory. This is a bootstrap-time,
// read-only operation isolated in a private function. A full config crate
// (figment/config) will be added in NCIP-025 Phase 5 when the config
// schema is finalized.
#[allow(
    clippy::disallowed_methods,
    reason = "env::var used only for XDG_CONFIG_HOME / HOME path resolution; auditable bootstrap-time read"
)]
fn dirs_path() -> PathBuf {
    // Platform-appropriate base directory.
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CONFIG_HOME").map_or_else(
            |_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                PathBuf::from(home).join(".config")
            },
            PathBuf::from,
        )
    }

    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join("Library/Application Support")
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").map_or_else(
            |_| PathBuf::from("C:\\Users\\Default\\AppData\\Roaming"),
            PathBuf::from,
        )
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/tmp")
    }
}

// `unnecessary_wraps`: Result is intentional API surface; real TOML
// parsing (NCIP-025 Phase 5) will return parse errors on malformed input.
#[allow(
    clippy::unnecessary_wraps,
    reason = "Result is intentional API surface; TOML parse errors will propagate once parsing is implemented"
)]
fn toml_parse(contents: &str) -> crate::Result<BridgeConfig> {
    // Minimal TOML parsing. In production, use the `toml` crate.
    // For now, return defaults (the config format is not yet finalized).
    let _ = contents;
    tracing::warn!("TOML parsing not yet implemented — using defaults");
    Ok(BridgeConfig::default())
}

fn toml_serialize(config: &BridgeConfig) -> crate::Result<String> {
    // Minimal TOML serialization placeholder.
    serde_json::to_string_pretty(config)
        .map_err(|e| crate::BridgeError::Config(format!("serialize: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_sane() {
        let config = BridgeConfig::default();
        assert_eq!(config.cpu_percent, 50);
        assert_eq!(config.cvm_memory_mib, 512);
        assert!(!config.auto_start);
        assert!(!config.cvm_enabled);
        assert_eq!(config.update_channel, "stable");
    }

    #[test]
    fn config_dir_is_non_empty() {
        let dir = config_dir();
        assert!(!dir.as_os_str().is_empty());
    }
}
