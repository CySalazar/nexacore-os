//! NCIP-007 §3 — Mandatory-escalation taxonomy.
//!
//! Certain action categories MUST always escalate to at least a minimum
//! autonomy level, regardless of the user's global autonomy setting.
//! This module classifies actions and enforces those minimums.
//!
//! | Class | Minimum autonomy |
//! |-------|-----------------|
//! | `Destructive` | `Guided` |
//! | `PrivacyViolating` | `Guided` |
//! | `CapabilityEscalation` | `Inform` |
//! | `Borderline` | `Inform` |
//!
//! See NCIP-007 §3 and NCIP-Agent-Arch-022 §S3.1.

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::guidance::autonomy::AutonomyLevel;

/// Mandatory-escalation class for an action (NCIP-007 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscalationClass {
    /// Action deletes, overwrites, or irreversibly modifies data or config.
    Destructive,
    /// Action exposes, transfers, or processes PII or sensitive user data.
    PrivacyViolating,
    /// Action requests capabilities beyond the agent's current grant.
    CapabilityEscalation,
    /// Action has ambiguous risk; could be destructive or privacy-violating.
    Borderline,
}

impl EscalationClass {
    /// Short label used in audit log entries.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Destructive => "destructive",
            Self::PrivacyViolating => "privacy-violating",
            Self::CapabilityEscalation => "capability-escalation",
            Self::Borderline => "borderline",
        }
    }
}

/// Classifies actions and determines their mandatory-escalation floor.
///
/// Phase 2 uses keyword heuristics. A later sprint will replace this with
/// a structured semantic classifier backed by the local Tier-0 model.
#[derive(Debug, Default)]
pub struct EscalationPolicy;

impl EscalationPolicy {
    /// Create a new policy instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Classify `action_description` into an escalation class, if any applies.
    ///
    /// Returns `None` when no mandatory-escalation class matches, meaning the
    /// action can proceed at whatever autonomy level the user has configured.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::escalation::{EscalationClass, EscalationPolicy};
    ///
    /// let policy = EscalationPolicy::new();
    /// assert_eq!(
    ///     policy.classify("delete all user files"),
    ///     Some(EscalationClass::Destructive),
    /// );
    /// ```
    // `&self` is intentional: a future version may carry user-configurable keyword
    // lists or a trained classifier as instance state.
    #[allow(clippy::unused_self, clippy::cognitive_complexity)]
    #[must_use]
    pub fn classify(&self, action_description: &str) -> Option<EscalationClass> {
        let lower = action_description.to_lowercase();

        // Destructive keywords (checked first — highest priority).
        if contains_any(
            &lower,
            &[
                "delete",
                "remove",
                "wipe",
                "erase",
                "format",
                "overwrite",
                "drop table",
                "rm -rf",
                "purge",
                "truncate",
            ],
        ) {
            debug!(
                action = action_description,
                class = "destructive",
                "escalation classified"
            );
            return Some(EscalationClass::Destructive);
        }

        // Privacy-violating keywords.
        if contains_any(
            &lower,
            &[
                "send email",
                "upload",
                "share",
                "transmit",
                "pii",
                "personal data",
                "private key",
                "password",
                "secret",
                "credentials",
                "egress",
                "exfil",
            ],
        ) {
            debug!(
                action = action_description,
                class = "privacy-violating",
                "escalation classified"
            );
            return Some(EscalationClass::PrivacyViolating);
        }

        // Capability-escalation keywords.
        if contains_any(
            &lower,
            &[
                "sudo",
                "root",
                "privilege",
                "escalate",
                "capability",
                "grant",
                "install driver",
                "load kernel module",
                "chmod 777",
                "setuid",
            ],
        ) {
            debug!(
                action = action_description,
                class = "capability-escalation",
                "escalation classified"
            );
            return Some(EscalationClass::CapabilityEscalation);
        }

        // Borderline keywords.
        if contains_any(
            &lower,
            &[
                "modify",
                "update config",
                "change setting",
                "disable",
                "enable",
                "expose",
            ],
        ) {
            debug!(
                action = action_description,
                class = "borderline",
                "escalation classified"
            );
            return Some(EscalationClass::Borderline);
        }

        None
    }

    /// Returns the minimum autonomy level that MUST be enforced for `class`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::{
    ///     autonomy::AutonomyLevel,
    ///     escalation::{EscalationClass, EscalationPolicy},
    /// };
    ///
    /// let policy = EscalationPolicy::new();
    /// assert_eq!(
    ///     policy.minimum_autonomy(EscalationClass::Destructive),
    ///     AutonomyLevel::Guided,
    /// );
    /// ```
    // `&self` is intentional for API consistency and forward compatibility.
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn minimum_autonomy(&self, class: EscalationClass) -> AutonomyLevel {
        match class {
            // Highest-risk classes require the user to consciously select an option.
            EscalationClass::Destructive | EscalationClass::PrivacyViolating => {
                AutonomyLevel::Guided
            }
            // Capability-escalation and borderline must at least inform the user.
            EscalationClass::CapabilityEscalation | EscalationClass::Borderline => {
                AutonomyLevel::Inform
            }
        }
    }

    /// Resolve the effective autonomy level after applying mandatory-escalation rules.
    ///
    /// If the action is classified, the effective level is the stricter of
    /// `requested` and `minimum_autonomy(class)`. Otherwise `requested` is
    /// returned unchanged.
    ///
    /// "Stricter" means: `Guided` > `Inform` > `Autonomous` in terms of
    /// user-visibility (higher index = more user involvement).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::{autonomy::AutonomyLevel, escalation::EscalationPolicy};
    ///
    /// let policy = EscalationPolicy::new();
    /// // Even Autonomous is forced to Guided for a destructive action.
    /// assert_eq!(
    ///     policy.apply("delete all logs", AutonomyLevel::Autonomous),
    ///     AutonomyLevel::Guided,
    /// );
    /// // Non-classified actions keep their requested level.
    /// assert_eq!(
    ///     policy.apply("list files", AutonomyLevel::Autonomous),
    ///     AutonomyLevel::Autonomous,
    /// );
    /// ```
    #[must_use]
    pub fn apply(&self, action_description: &str, requested: AutonomyLevel) -> AutonomyLevel {
        // Pick the "stricter" level (more user-involvement wins) when a class applies.
        self.classify(action_description)
            .map_or(requested, |class| {
                strictest(requested, self.minimum_autonomy(class))
            })
    }
}

// ── Private helpers ────────────────────────────────────────────────────────

/// Returns `true` if `haystack` contains any of the `needles`.
fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Returns the autonomy level requiring more user involvement.
///
/// Ordering: Autonomous < Inform < Guided (higher = more involvement).
fn strictest(a: AutonomyLevel, b: AutonomyLevel) -> AutonomyLevel {
    fn rank(l: AutonomyLevel) -> u8 {
        match l {
            AutonomyLevel::Autonomous => 0,
            AutonomyLevel::Inform => 1,
            AutonomyLevel::Guided => 2,
        }
    }
    if rank(a) >= rank(b) { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guidance::autonomy::AutonomyLevel;

    fn policy() -> EscalationPolicy {
        EscalationPolicy::new()
    }

    // ── classify ─────────────────────────────────────────────────────────

    #[test]
    fn classify_destructive_delete() {
        assert_eq!(
            policy().classify("delete all user files"),
            Some(EscalationClass::Destructive)
        );
    }

    #[test]
    fn classify_destructive_wipe() {
        assert_eq!(
            policy().classify("wipe the disk partition"),
            Some(EscalationClass::Destructive)
        );
    }

    #[test]
    fn classify_privacy_upload() {
        assert_eq!(
            policy().classify("upload personal data to the server"),
            Some(EscalationClass::PrivacyViolating)
        );
    }

    #[test]
    fn classify_privacy_password() {
        assert_eq!(
            policy().classify("store password in plaintext"),
            Some(EscalationClass::PrivacyViolating)
        );
    }

    #[test]
    fn classify_capability_escalation_sudo() {
        assert_eq!(
            policy().classify("run sudo apt-get install"),
            Some(EscalationClass::CapabilityEscalation)
        );
    }

    #[test]
    fn classify_borderline_disable() {
        assert_eq!(
            policy().classify("disable the firewall temporarily"),
            Some(EscalationClass::Borderline)
        );
    }

    #[test]
    fn classify_none_for_benign_action() {
        assert_eq!(policy().classify("list directory contents"), None);
    }

    // ── minimum_autonomy ─────────────────────────────────────────────────

    #[test]
    fn minimum_autonomy_destructive_is_guided() {
        assert_eq!(
            policy().minimum_autonomy(EscalationClass::Destructive),
            AutonomyLevel::Guided
        );
    }

    #[test]
    fn minimum_autonomy_privacy_is_guided() {
        assert_eq!(
            policy().minimum_autonomy(EscalationClass::PrivacyViolating),
            AutonomyLevel::Guided
        );
    }

    #[test]
    fn minimum_autonomy_capability_is_inform() {
        assert_eq!(
            policy().minimum_autonomy(EscalationClass::CapabilityEscalation),
            AutonomyLevel::Inform
        );
    }

    #[test]
    fn minimum_autonomy_borderline_is_inform() {
        assert_eq!(
            policy().minimum_autonomy(EscalationClass::Borderline),
            AutonomyLevel::Inform
        );
    }

    // ── apply ─────────────────────────────────────────────────────────────

    #[test]
    fn apply_autonomous_becomes_guided_for_destructive() {
        assert_eq!(
            policy().apply("delete all logs", AutonomyLevel::Autonomous),
            AutonomyLevel::Guided
        );
    }

    #[test]
    fn apply_guided_stays_guided_for_destructive() {
        assert_eq!(
            policy().apply("delete all logs", AutonomyLevel::Guided),
            AutonomyLevel::Guided
        );
    }

    #[test]
    fn apply_autonomous_becomes_inform_for_borderline() {
        assert_eq!(
            policy().apply("disable the firewall", AutonomyLevel::Autonomous),
            AutonomyLevel::Inform
        );
    }

    #[test]
    fn apply_guided_stays_guided_for_borderline() {
        // Guided is already stricter than Inform.
        assert_eq!(
            policy().apply("disable the firewall", AutonomyLevel::Guided),
            AutonomyLevel::Guided
        );
    }

    #[test]
    fn apply_passthrough_for_benign() {
        assert_eq!(
            policy().apply("list files", AutonomyLevel::Autonomous),
            AutonomyLevel::Autonomous
        );
    }

    #[test]
    fn escalation_class_labels_are_unique() {
        let labels = [
            EscalationClass::Destructive.label(),
            EscalationClass::PrivacyViolating.label(),
            EscalationClass::CapabilityEscalation.label(),
            EscalationClass::Borderline.label(),
        ];
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len());
    }
}
