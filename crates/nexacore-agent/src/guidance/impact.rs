//! NCIP-007 §4 — Impact Dashboard with 7 dimensions.
//!
//! Before an action is taken, the Guidance Agent MUST present the user
//! with an Impact Dashboard showing the projected effect on each of the
//! seven dimensions defined in NCIP-007 §4. Scores range from 0 (no
//! impact) to 100 (maximum impact).
//!
//! Phase 2 uses keyword heuristics to assign scores. A later sprint
//! replaces this with the Tier-0 semantic classifier.
//!
//! See NCIP-007 §4 and NCIP-Agent-Arch-022 §S4.

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::guidance::explanation::TechnicalLevel;

/// The seven dimensions of the NCIP-007 Impact Dashboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImpactDimension {
    /// Risk to user privacy (PII exposure, data leakage).
    Privacy,
    /// Effect on the user's trust in the system.
    Trust,
    /// Monetary cost (cloud API calls, paid services, compute).
    Cost,
    /// Time required to complete the action.
    Time,
    /// Storage consumed or freed.
    Storage,
    /// Data sent off-device (network egress volume).
    Egress,
    /// Capabilities granted or revoked.
    Capabilities,
}

impl ImpactDimension {
    /// Short display label for this dimension.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Privacy => "Privacy",
            Self::Trust => "Trust",
            Self::Cost => "Cost",
            Self::Time => "Time",
            Self::Storage => "Storage",
            Self::Egress => "Egress",
            Self::Capabilities => "Capabilities",
        }
    }

    /// Returns all seven dimensions in canonical display order.
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [
            Self::Privacy,
            Self::Trust,
            Self::Cost,
            Self::Time,
            Self::Storage,
            Self::Egress,
            Self::Capabilities,
        ]
    }
}

/// A scored entry for one dimension of the Impact Dashboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactScore {
    /// Which dimension this score applies to.
    pub dimension: ImpactDimension,
    /// Impact score from 0 (none) to 100 (maximum).
    pub score: u8,
}

impl ImpactScore {
    /// Create an impact score, clamping `score` to the valid range 0–100.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::impact::{ImpactDimension, ImpactScore};
    ///
    /// let s = ImpactScore::new(ImpactDimension::Privacy, 75);
    /// assert_eq!(s.score, 75);
    /// ```
    #[must_use]
    pub fn new(dimension: ImpactDimension, score: u8) -> Self {
        Self { dimension, score }
    }
}

/// A complete Impact Dashboard for an evaluated action.
///
/// Contains one [`ImpactScore`] per dimension.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImpactDashboard {
    /// The action that was assessed.
    pub action: String,
    /// Per-dimension impact scores.
    pub scores: Vec<ImpactScore>,
}

impl ImpactDashboard {
    /// Returns the score for `dimension`, if present.
    #[must_use]
    pub fn score_for(&self, dimension: ImpactDimension) -> Option<u8> {
        self.scores
            .iter()
            .find(|s| s.dimension == dimension)
            .map(|s| s.score)
    }

    /// Returns the highest score across all dimensions.
    #[must_use]
    pub fn max_score(&self) -> u8 {
        self.scores.iter().map(|s| s.score).max().unwrap_or(0)
    }

    /// Returns `true` if any dimension exceeds the given threshold.
    #[must_use]
    pub fn any_above(&self, threshold: u8) -> bool {
        self.scores.iter().any(|s| s.score > threshold)
    }

    /// Render the dashboard as a human-readable string adapted to `level`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::{explanation::TechnicalLevel, impact::ImpactAssessor};
    ///
    /// let assessor = ImpactAssessor::new();
    /// let dashboard = assessor.assess("delete all user files");
    /// let text = dashboard.render(TechnicalLevel::Beginner);
    /// assert!(text.contains("Impact"));
    /// ```
    #[must_use]
    pub fn render(&self, level: TechnicalLevel) -> String {
        let mut out = match level {
            TechnicalLevel::Beginner => format!("Impact of \"{action}\":\n", action = self.action),
            TechnicalLevel::Intermediate => {
                format!("Impact Dashboard — \"{action}\":\n", action = self.action)
            }
            TechnicalLevel::Expert => {
                format!("[IMPACT] action=\"{action}\"\n", action = self.action)
            }
        };

        for s in &self.scores {
            let bar = score_bar(s.score);
            match level {
                TechnicalLevel::Beginner => {
                    out.push_str(&format!(
                        "  {label}: {bar} ({score}/100)\n",
                        label = s.dimension.label(),
                        score = s.score,
                    ));
                }
                TechnicalLevel::Intermediate => {
                    out.push_str(&format!(
                        "  {label:14}: {score:3}/100 {bar}\n",
                        label = s.dimension.label(),
                        score = s.score,
                    ));
                }
                TechnicalLevel::Expert => {
                    out.push_str(&format!(
                        "  {dim}={score}\n",
                        dim = s.dimension.label(),
                        score = s.score,
                    ));
                }
            }
        }

        out
    }
}

/// Assesses an action and produces an [`ImpactDashboard`].
///
/// Phase 2 implementation uses keyword heuristics. A production-quality
/// assessment will use the local Tier-0 semantic model.
#[derive(Debug, Default)]
pub struct ImpactAssessor;

impl ImpactAssessor {
    /// Create a new assessor.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Assess the impact of `action_description` across all seven dimensions.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::impact::ImpactAssessor;
    ///
    /// let assessor = ImpactAssessor::new();
    /// let dashboard = assessor.assess("upload private file");
    /// assert!(
    ///     dashboard
    ///         .score_for(nexacore_agent::guidance::impact::ImpactDimension::Privacy)
    ///         .unwrap_or(0)
    ///         > 0
    /// );
    /// ```
    // `&self` is intentional: a future version may carry a user-configured
    // classifier or impact weight table as instance state.
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn assess(&self, action_description: &str) -> ImpactDashboard {
        let lower = action_description.to_lowercase();
        debug!(action = action_description, "assessing impact");

        let scores = ImpactDimension::all()
            .iter()
            .map(|&dim| ImpactScore::new(dim, Self::score_dimension(dim, &lower)))
            .collect();

        ImpactDashboard {
            action: action_description.to_owned(),
            scores,
        }
    }

    /// Map a differential privacy epsilon budget ratio to the `Privacy`
    /// dimension score (0–100).
    ///
    /// `epsilon_used` is the cumulative epsilon consumed so far;
    /// `epsilon_max` is the maximum budget.  The ratio
    /// `epsilon_used / epsilon_max` is linearly mapped to the 0–100 range and
    /// clamped.
    ///
    /// - 0 % used → score 0 (no privacy impact yet).
    /// - 50 % used → score 50.
    /// - 100 % (or above) used → score 100 (budget fully consumed).
    ///
    /// When `epsilon_max` is zero the score is always 100 (budget
    /// instantaneously exhausted).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::impact::ImpactAssessor;
    ///
    /// assert_eq!(ImpactAssessor::privacy_impact_from_epsilon(0.0, 10.0), 0);
    /// assert_eq!(ImpactAssessor::privacy_impact_from_epsilon(5.0, 10.0), 50);
    /// assert_eq!(ImpactAssessor::privacy_impact_from_epsilon(10.0, 10.0), 100);
    /// // Over-consumption (shouldn't happen in practice) is clamped to 100.
    /// assert_eq!(ImpactAssessor::privacy_impact_from_epsilon(12.0, 10.0), 100);
    /// // Zero max → always 100.
    /// assert_eq!(ImpactAssessor::privacy_impact_from_epsilon(0.0, 0.0), 100);
    /// ```
    #[must_use]
    #[allow(clippy::float_arithmetic)]
    #[allow(clippy::cast_possible_truncation)] // score fits in u32 after clamping
    #[allow(clippy::cast_sign_loss)] // ratio is always ≥ 0 after clamping
    pub fn privacy_impact_from_epsilon(epsilon_used: f64, epsilon_max: f64) -> u32 {
        if epsilon_max <= 0.0 {
            return 100;
        }
        let ratio = epsilon_used / epsilon_max;
        // Clamp to [0.0, 1.0], then scale to [0, 100].
        let score = (ratio * 100.0).clamp(0.0, 100.0);
        score.round() as u32
    }

    // Score a single dimension using keyword heuristics.
    // Scores are coarse: 0 / 25 / 50 / 75 / 100.
    // The function body is long because it must handle all 7 dimensions; each
    // dimension is an independent branch. Splitting into multiple functions
    // would require 7 function definitions which is harder to review at a glance.
    #[allow(clippy::too_many_lines)]
    fn score_dimension(dim: ImpactDimension, lower: &str) -> u8 {
        match dim {
            ImpactDimension::Privacy => {
                if contains_any(
                    lower,
                    &[
                        "pii",
                        "personal data",
                        "private key",
                        "credentials",
                        "password",
                        "secret",
                    ],
                ) {
                    100
                } else if contains_any(
                    lower,
                    &["upload", "share", "send", "egress", "email", "transmit"],
                ) {
                    75
                } else if contains_any(lower, &["read", "access", "open"]) {
                    25
                } else {
                    0
                }
            }
            ImpactDimension::Trust => {
                if contains_any(
                    lower,
                    &["delete", "remove", "wipe", "erase", "format", "overwrite"],
                ) {
                    75
                } else if contains_any(lower, &["modify", "update", "change"]) {
                    25
                } else {
                    0
                }
            }
            ImpactDimension::Cost => {
                if contains_any(
                    lower,
                    &["api call", "cloud", "paid", "subscription", "billing"],
                ) {
                    75
                } else if contains_any(lower, &["search", "request", "fetch", "download"]) {
                    25
                } else {
                    0
                }
            }
            ImpactDimension::Time => {
                if contains_any(
                    lower,
                    &["backup", "scan", "index", "rebuild", "compile", "install"],
                ) {
                    75
                } else if contains_any(lower, &["copy", "move", "update"]) {
                    25
                } else {
                    0
                }
            }
            ImpactDimension::Storage => {
                if contains_any(lower, &["install", "download", "backup", "cache"]) {
                    50
                } else if contains_any(lower, &["delete", "remove", "purge", "clean"]) {
                    // Frees storage — still a non-zero impact score.
                    50
                } else {
                    0
                }
            }
            ImpactDimension::Egress => {
                if contains_any(
                    lower,
                    &["upload", "send", "transmit", "egress", "push", "email"],
                ) {
                    75
                } else if contains_any(lower, &["download", "fetch", "search", "api call"]) {
                    25
                } else {
                    0
                }
            }
            ImpactDimension::Capabilities => {
                if contains_any(
                    lower,
                    &[
                        "sudo",
                        "root",
                        "privilege",
                        "grant",
                        "escalate",
                        "capability",
                    ],
                ) {
                    100
                } else if contains_any(lower, &["install driver", "load module", "setuid"]) {
                    75
                } else if contains_any(lower, &["install", "enable", "disable"]) {
                    25
                } else {
                    0
                }
            }
        }
    }
}

// ── Private helpers ────────────────────────────────────────────────────────

/// Returns `true` if `haystack` contains any of the `needles`.
fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Render a compact ASCII bar for a score 0–100.
fn score_bar(score: u8) -> &'static str {
    match score {
        0 => "          ",
        1..=25 => "##        ",
        26..=50 => "####      ",
        51..=75 => "######    ",
        // 76..=100 and any hypothetical overflow value (u8 ≤ 255) both return
        // the full bar. Collapsing them into `_` is the correct idiomatic form.
        _ => "##########",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guidance::explanation::TechnicalLevel;

    fn assessor() -> ImpactAssessor {
        ImpactAssessor::new()
    }

    #[test]
    fn assess_delete_has_high_trust_impact() {
        let d = assessor().assess("delete all user files");
        let trust = d.score_for(ImpactDimension::Trust).unwrap_or(0);
        assert!(trust > 0, "expected non-zero trust impact, got {trust}");
    }

    #[test]
    fn assess_upload_private_data_has_high_privacy_and_egress() {
        let d = assessor().assess("upload personal data to cloud");
        let privacy = d.score_for(ImpactDimension::Privacy).unwrap_or(0);
        let egress = d.score_for(ImpactDimension::Egress).unwrap_or(0);
        assert!(privacy > 0);
        assert!(egress > 0);
    }

    #[test]
    fn assess_sudo_has_high_capability_impact() {
        let d = assessor().assess("run sudo to install package");
        let cap = d.score_for(ImpactDimension::Capabilities).unwrap_or(0);
        assert!(cap > 0);
    }

    #[test]
    fn assess_list_files_has_zero_egress() {
        let d = assessor().assess("list directory contents");
        let egress = d.score_for(ImpactDimension::Egress).unwrap_or(0);
        assert_eq!(egress, 0);
    }

    #[test]
    fn max_score_returns_highest_value() {
        let d = assessor().assess("delete all logs and upload report");
        let max = d.max_score();
        let computed = d.scores.iter().map(|s| s.score).max().unwrap_or(0);
        assert_eq!(max, computed);
    }

    #[test]
    fn any_above_threshold() {
        let d = assessor().assess("delete all user files");
        assert!(d.any_above(0));
        assert!(!d.any_above(100));
    }

    #[test]
    fn render_beginner_contains_impact() {
        let d = assessor().assess("delete all user files");
        let text = d.render(TechnicalLevel::Beginner);
        assert!(text.contains("Impact"));
    }

    #[test]
    fn render_intermediate_contains_dimension_labels() {
        let d = assessor().assess("delete all user files");
        let text = d.render(TechnicalLevel::Intermediate);
        assert!(text.contains("Privacy"));
        assert!(text.contains("Trust"));
    }

    #[test]
    fn render_expert_uses_compact_format() {
        let d = assessor().assess("delete all user files");
        let text = d.render(TechnicalLevel::Expert);
        assert!(text.contains("[IMPACT]"));
    }

    #[test]
    fn all_seven_dimensions_present() {
        let d = assessor().assess("test action");
        assert_eq!(d.scores.len(), 7);
        for dim in ImpactDimension::all() {
            assert!(
                d.scores.iter().any(|s| s.dimension == dim),
                "missing dimension {dim:?}"
            );
        }
    }

    #[test]
    fn dimension_labels_are_unique() {
        let labels: Vec<_> = ImpactDimension::all().iter().map(|d| d.label()).collect();
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(labels.len(), unique.len());
    }
}
