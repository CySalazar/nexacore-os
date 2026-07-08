//! NCIP-007 §2 — Autonomy-level configuration and resolution.
//!
//! The autonomy level controls how much the Guidance (and other) agents
//! act without explicit user confirmation. Three levels are defined:
//!
//! | Level | Behaviour |
//! |-------|-----------|
//! | `Autonomous` | Agent decides and acts; post-action notification only. |
//! | `Guided` | Agent presents ranked options with a recommendation; user selects. |
//! | `Inform` | Agent presents options without a recommendation; user selects. |
//!
//! In **High-Risk Mode** the `Autonomous` level is forbidden and is
//! transparently downgraded to `Guided` (NCIP-022 §S3.2 / §T4.5).
//!
//! Per-context overrides allow different autonomy levels for specific
//! operation contexts (e.g. `pkg:install` may be `Guided` even when the
//! global setting is `Autonomous`).
//!
//! See NCIP-007 §2 and NCIP-Agent-Arch-022 §S3.2.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::mode::OperationalMode;

/// The three autonomy levels supported by the Guidance Agent (NCIP-007 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutonomyLevel {
    /// Agent decides and acts; post-action notification.
    Autonomous,
    /// Agent presents ranked options with recommendation; user selects.
    Guided,
    /// Agent presents options without recommendation; user selects.
    Inform,
}

impl Default for AutonomyLevel {
    fn default() -> Self {
        Self::Guided
    }
}

/// Per-agent autonomy configuration with optional per-context overrides.
///
/// The global level applies when no context-specific override is set.
/// Overrides are keyed by an arbitrary context string (e.g. `"pkg:install"`,
/// `"fs:delete"`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AutonomyConfig {
    /// Global default autonomy level.
    pub global: AutonomyLevel,
    /// Context-scoped overrides (context label → level).
    pub overrides: BTreeMap<String, AutonomyLevel>,
}

impl AutonomyConfig {
    /// Create a config with the given global level and no overrides.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::autonomy::{AutonomyConfig, AutonomyLevel};
    ///
    /// let cfg = AutonomyConfig::new(AutonomyLevel::Autonomous);
    /// assert_eq!(cfg.global, AutonomyLevel::Autonomous);
    /// assert!(cfg.overrides.is_empty());
    /// ```
    #[must_use]
    pub fn new(global: AutonomyLevel) -> Self {
        Self {
            global,
            overrides: BTreeMap::new(),
        }
    }
}

/// Resolves the effective autonomy level for a given context and mode.
///
/// The manager merges the global config, context overrides, and the
/// mode-imposed ceiling into one effective level.
#[derive(Debug)]
pub struct AutonomyManager {
    config: AutonomyConfig,
}

impl AutonomyManager {
    /// Create a manager with the given initial config.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::autonomy::{AutonomyConfig, AutonomyManager};
    ///
    /// let mgr = AutonomyManager::new(AutonomyConfig::default());
    /// ```
    #[must_use]
    pub fn new(config: AutonomyConfig) -> Self {
        Self { config }
    }

    /// Create a manager with the default config (`Guided`, no overrides).
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(AutonomyConfig::default())
    }

    /// Resolve the effective autonomy level for `context` under `mode`.
    ///
    /// Resolution order:
    /// 1. Look up the context-specific override; fall back to global level.
    /// 2. In `HighRisk` mode, clamp `Autonomous` → `Guided`.
    /// 3. In `EmergencyRecovery` mode apply the same clamp as `HighRisk`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{
    ///     guidance::autonomy::{AutonomyConfig, AutonomyLevel, AutonomyManager},
    ///     mode::OperationalMode,
    /// };
    ///
    /// let mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Autonomous));
    /// // High-Risk mode forces Autonomous down to Guided.
    /// assert_eq!(
    ///     mgr.resolve_level("any", OperationalMode::HighRisk),
    ///     AutonomyLevel::Guided,
    /// );
    /// ```
    #[must_use]
    pub fn resolve_level(&self, context: &str, mode: OperationalMode) -> AutonomyLevel {
        // Context override takes priority over the global setting.
        let base = self
            .config
            .overrides
            .get(context)
            .copied()
            .unwrap_or(self.config.global);

        // High-Risk and Emergency-Recovery modes forbid Autonomous (NCIP-022 §S3.2).
        match mode {
            OperationalMode::HighRisk | OperationalMode::EmergencyRecovery => {
                if base == AutonomyLevel::Autonomous {
                    debug!(
                        context,
                        ?mode,
                        "autonomy downgraded Autonomous → Guided (mode restriction)"
                    );
                    AutonomyLevel::Guided
                } else {
                    base
                }
            }
            OperationalMode::Standard => base,
        }
    }

    /// Set a context-specific override.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{
    ///     guidance::autonomy::{AutonomyConfig, AutonomyLevel, AutonomyManager},
    ///     mode::OperationalMode,
    /// };
    ///
    /// let mut mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Autonomous));
    /// mgr.set_override("pkg:install", AutonomyLevel::Guided);
    /// assert_eq!(
    ///     mgr.resolve_level("pkg:install", OperationalMode::Standard),
    ///     AutonomyLevel::Guided,
    /// );
    /// ```
    pub fn set_override(&mut self, context: impl Into<String>, level: AutonomyLevel) {
        self.config.overrides.insert(context.into(), level);
    }

    /// Remove a context-specific override, reverting that context to the global level.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{
    ///     guidance::autonomy::{AutonomyConfig, AutonomyLevel, AutonomyManager},
    ///     mode::OperationalMode,
    /// };
    ///
    /// let mut mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Autonomous));
    /// mgr.set_override("pkg:install", AutonomyLevel::Guided);
    /// mgr.clear_override("pkg:install");
    /// assert_eq!(
    ///     mgr.resolve_level("pkg:install", OperationalMode::Standard),
    ///     AutonomyLevel::Autonomous,
    /// );
    /// ```
    pub fn clear_override(&mut self, context: &str) {
        self.config.overrides.remove(context);
    }

    /// Returns the global default autonomy level (before mode clamping).
    #[must_use]
    pub fn global_level(&self) -> AutonomyLevel {
        self.config.global
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::OperationalMode;

    #[test]
    fn default_autonomy_level_is_guided() {
        assert_eq!(AutonomyLevel::default(), AutonomyLevel::Guided);
    }

    #[test]
    fn standard_mode_preserves_autonomous() {
        let mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Autonomous));
        assert_eq!(
            mgr.resolve_level("ctx", OperationalMode::Standard),
            AutonomyLevel::Autonomous
        );
    }

    #[test]
    fn high_risk_mode_downgrades_autonomous_to_guided() {
        let mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Autonomous));
        assert_eq!(
            mgr.resolve_level("ctx", OperationalMode::HighRisk),
            AutonomyLevel::Guided
        );
    }

    #[test]
    fn emergency_recovery_mode_downgrades_autonomous_to_guided() {
        let mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Autonomous));
        assert_eq!(
            mgr.resolve_level("ctx", OperationalMode::EmergencyRecovery),
            AutonomyLevel::Guided
        );
    }

    #[test]
    fn high_risk_preserves_guided() {
        let mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Guided));
        assert_eq!(
            mgr.resolve_level("ctx", OperationalMode::HighRisk),
            AutonomyLevel::Guided
        );
    }

    #[test]
    fn high_risk_preserves_inform() {
        let mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Inform));
        assert_eq!(
            mgr.resolve_level("ctx", OperationalMode::HighRisk),
            AutonomyLevel::Inform
        );
    }

    #[test]
    fn context_override_takes_priority_over_global() {
        let mut mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Autonomous));
        mgr.set_override("pkg:install", AutonomyLevel::Guided);
        assert_eq!(
            mgr.resolve_level("pkg:install", OperationalMode::Standard),
            AutonomyLevel::Guided
        );
        // Other contexts still use the global.
        assert_eq!(
            mgr.resolve_level("fs:read", OperationalMode::Standard),
            AutonomyLevel::Autonomous
        );
    }

    #[test]
    fn clear_override_restores_global() {
        let mut mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Autonomous));
        mgr.set_override("pkg:install", AutonomyLevel::Guided);
        mgr.clear_override("pkg:install");
        assert_eq!(
            mgr.resolve_level("pkg:install", OperationalMode::Standard),
            AutonomyLevel::Autonomous
        );
    }

    #[test]
    fn override_in_high_risk_still_clamped() {
        // Even a context override of Autonomous is clamped in High-Risk mode.
        let mut mgr = AutonomyManager::new(AutonomyConfig::new(AutonomyLevel::Guided));
        mgr.set_override("special", AutonomyLevel::Autonomous);
        assert_eq!(
            mgr.resolve_level("special", OperationalMode::HighRisk),
            AutonomyLevel::Guided
        );
    }
}
