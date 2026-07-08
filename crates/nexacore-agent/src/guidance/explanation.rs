//! NCIP-007 §5 — Plain-language explanation engine.
//!
//! The Guidance Agent adapts all user-facing text to the user's declared
//! technical level. Three levels are supported:
//!
//! | Level | Description |
//! |-------|-------------|
//! | `Beginner` | Avoid jargon; use analogies and plain language. |
//! | `Intermediate` | Standard technical terms; skip basic definitions. |
//! | `Expert` | Full technical depth; assume domain knowledge. |
//!
//! The engine handles three explanation surfaces:
//! - **Action explanations**: what an operation does and why it was requested.
//! - **Veto explanations**: why the Security Agent blocked an action.
//! - **Cross-agent explanations**: what another agent did on the user's behalf.
//!
//! See NCIP-007 §5 and NCIP-Agent-Arch-022 §S4.

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    agent::AgentKind,
    message::{VetoDecision, VetoOutcome},
};

/// User's declared technical level for explanation adaptation (NCIP-007 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TechnicalLevel {
    /// Avoid jargon; use analogies and plain language.
    Beginner,
    /// Use standard technical terms; skip basic definitions.
    Intermediate,
    /// Full technical depth; assume domain knowledge.
    Expert,
}

impl Default for TechnicalLevel {
    fn default() -> Self {
        Self::Intermediate
    }
}

/// Produces user-facing text adapted to a configured technical level.
///
/// The engine is stateless except for the configured level; all methods
/// are pure functions of their inputs.
#[derive(Debug, Clone)]
pub struct ExplanationEngine {
    level: TechnicalLevel,
}

impl ExplanationEngine {
    /// Create an engine configured to the given technical level.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::explanation::{ExplanationEngine, TechnicalLevel};
    ///
    /// let engine = ExplanationEngine::new(TechnicalLevel::Beginner);
    /// assert_eq!(engine.level(), TechnicalLevel::Beginner);
    /// ```
    #[must_use]
    pub fn new(level: TechnicalLevel) -> Self {
        Self { level }
    }

    /// Returns the currently configured technical level.
    #[must_use]
    pub fn level(&self) -> TechnicalLevel {
        self.level
    }

    /// Update the technical level.
    pub fn set_level(&mut self, level: TechnicalLevel) {
        self.level = level;
    }

    /// Generate a plain-language explanation of an action at the configured level.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::explanation::{ExplanationEngine, TechnicalLevel};
    ///
    /// let engine = ExplanationEngine::new(TechnicalLevel::Beginner);
    /// let text = engine.explain_action("install Firefox", TechnicalLevel::Beginner);
    /// assert!(text.contains("Firefox"));
    /// ```
    // `&self` is intentional: the engine may carry configuration (tone, locale)
    // in a future sprint that affects output.
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn explain_action(&self, action: &str, level: TechnicalLevel) -> String {
        debug!(action, ?level, "explaining action");
        match level {
            TechnicalLevel::Beginner => format!(
                "The system is about to: {action}. \
                 This means it will perform this task for you automatically."
            ),
            TechnicalLevel::Intermediate => format!("Executing action: {action}."),
            TechnicalLevel::Expert => format!("ACTION {action}"),
        }
    }

    /// Generate a plain-language explanation of an action using the engine's own level.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::explanation::{ExplanationEngine, TechnicalLevel};
    ///
    /// let engine = ExplanationEngine::new(TechnicalLevel::Expert);
    /// let text = engine.explain("install Firefox");
    /// assert!(text.contains("ACTION"));
    /// ```
    #[must_use]
    pub fn explain(&self, action: &str) -> String {
        self.explain_action(action, self.level)
    }

    /// Generate a plain-language explanation of a veto decision at the given level.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{
    ///     guidance::explanation::{ExplanationEngine, TechnicalLevel},
    ///     message::{VetoDecision, VetoOutcome},
    /// };
    ///
    /// let engine = ExplanationEngine::new(TechnicalLevel::Beginner);
    /// let decision = VetoDecision {
    ///     request_id: 1,
    ///     outcome: VetoOutcome::Approved,
    /// };
    /// let text = engine.explain_veto(&decision, TechnicalLevel::Beginner);
    /// assert_eq!(text, "Action approved.");
    /// ```
    // `&self` intentional for forward compatibility (tone, locale config).
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn explain_veto(&self, decision: &VetoDecision, level: TechnicalLevel) -> String {
        debug!(?level, request_id = decision.request_id, "explaining veto");
        match &decision.outcome {
            VetoOutcome::Approved => "Action approved.".to_owned(),
            VetoOutcome::Vetoed {
                risk_class,
                policy_violated,
                alternatives,
            } => match level {
                TechnicalLevel::Beginner => format!(
                    "This action was blocked for safety reasons ({risk_class}). \
                     The system detected a potential risk. {alt}",
                    alt = if alternatives.is_empty() {
                        "No alternatives are available.".to_owned()
                    } else {
                        format!("You can try: {}", alternatives.join(", "))
                    }
                ),
                TechnicalLevel::Intermediate => format!(
                    "Vetoed: {risk_class} — policy '{policy_violated}' violated. \
                     Alternatives: {alt}",
                    alt = if alternatives.is_empty() {
                        "none".to_owned()
                    } else {
                        alternatives.join("; ")
                    }
                ),
                TechnicalLevel::Expert => format!(
                    "VETO [{risk_class}] policy={policy_violated} alt=[{alt}]",
                    alt = alternatives.join(", ")
                ),
            },
        }
    }

    /// Generate a cross-agent explanation describing what `agent_kind` did.
    ///
    /// Cross-agent explanations are used when the Guidance Agent must explain
    /// actions taken by another agent (e.g., `SysAdmin` installed a package).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{
    ///     agent::AgentKind,
    ///     guidance::explanation::{ExplanationEngine, TechnicalLevel},
    /// };
    ///
    /// let engine = ExplanationEngine::new(TechnicalLevel::Beginner);
    /// let text = engine.explain_cross_agent(
    ///     AgentKind::SysAdmin,
    ///     "installed Firefox",
    ///     TechnicalLevel::Beginner,
    /// );
    /// assert!(text.contains("Firefox"));
    /// ```
    // `&self` intentional for forward compatibility (tone, locale config).
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn explain_cross_agent(
        &self,
        agent_kind: AgentKind,
        operation: &str,
        level: TechnicalLevel,
    ) -> String {
        debug!(
            ?agent_kind,
            operation,
            ?level,
            "explaining cross-agent operation"
        );
        let agent_name = match level {
            TechnicalLevel::Beginner => agent_kind.display_it(),
            TechnicalLevel::Intermediate | TechnicalLevel::Expert => agent_kind.short_id(),
        };
        match level {
            TechnicalLevel::Beginner => format!(
                "The {agent_name} completed a task for you: {operation}. \
                 Everything went smoothly."
            ),
            TechnicalLevel::Intermediate => format!("Agent [{agent_name}] performed: {operation}."),
            TechnicalLevel::Expert => format!("AGENT[{agent_name}] OP={operation}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{VetoDecision, VetoOutcome};

    fn engine(level: TechnicalLevel) -> ExplanationEngine {
        ExplanationEngine::new(level)
    }

    // ── explain_action ────────────────────────────────────────────────────

    #[test]
    fn explain_action_beginner_contains_action() {
        let text = engine(TechnicalLevel::Beginner)
            .explain_action("install Firefox", TechnicalLevel::Beginner);
        assert!(text.contains("Firefox"));
        assert!(text.contains("automatically"));
    }

    #[test]
    fn explain_action_intermediate() {
        let text = engine(TechnicalLevel::Intermediate)
            .explain_action("install Firefox", TechnicalLevel::Intermediate);
        assert!(text.contains("Executing"));
        assert!(text.contains("Firefox"));
    }

    #[test]
    fn explain_action_expert_compact() {
        let text = engine(TechnicalLevel::Expert)
            .explain_action("install Firefox", TechnicalLevel::Expert);
        assert!(text.contains("ACTION"));
        assert!(text.contains("Firefox"));
    }

    // ── explain (own level) ───────────────────────────────────────────────

    #[test]
    fn explain_uses_engine_level() {
        let text = engine(TechnicalLevel::Expert).explain("rm -rf /tmp/cache");
        assert!(text.contains("ACTION"));
    }

    // ── explain_veto ─────────────────────────────────────────────────────

    #[test]
    fn explain_veto_approved() {
        let d = VetoDecision {
            request_id: 1,
            outcome: VetoOutcome::Approved,
        };
        let text = engine(TechnicalLevel::Beginner).explain_veto(&d, TechnicalLevel::Beginner);
        assert_eq!(text, "Action approved.");
    }

    #[test]
    fn explain_veto_beginner_contains_safety() {
        let d = VetoDecision {
            request_id: 1,
            outcome: VetoOutcome::Vetoed {
                risk_class: "destructive".into(),
                policy_violated: "no-delete-without-backup".into(),
                alternatives: vec!["create a backup first".into()],
            },
        };
        let text = engine(TechnicalLevel::Beginner).explain_veto(&d, TechnicalLevel::Beginner);
        assert!(text.contains("safety reasons"));
        assert!(text.contains("create a backup first"));
    }

    #[test]
    fn explain_veto_intermediate_contains_policy() {
        let d = VetoDecision {
            request_id: 2,
            outcome: VetoOutcome::Vetoed {
                risk_class: "capability-escalation".into(),
                policy_violated: "least-privilege".into(),
                alternatives: vec![],
            },
        };
        let text =
            engine(TechnicalLevel::Intermediate).explain_veto(&d, TechnicalLevel::Intermediate);
        assert!(text.contains("Vetoed"));
        assert!(text.contains("least-privilege"));
        assert!(text.contains("none"));
    }

    #[test]
    fn explain_veto_expert_compact() {
        let d = VetoDecision {
            request_id: 3,
            outcome: VetoOutcome::Vetoed {
                risk_class: "capability-escalation".into(),
                policy_violated: "least-privilege".into(),
                alternatives: vec![],
            },
        };
        let text = engine(TechnicalLevel::Expert).explain_veto(&d, TechnicalLevel::Expert);
        assert!(text.contains("VETO"));
        assert!(text.contains("capability-escalation"));
    }

    // ── explain_cross_agent ───────────────────────────────────────────────

    #[test]
    fn cross_agent_beginner_uses_italian_name() {
        let text = engine(TechnicalLevel::Beginner).explain_cross_agent(
            AgentKind::SysAdmin,
            "installed Firefox",
            TechnicalLevel::Beginner,
        );
        // Beginner mode uses display_it() = "Amministratore"
        assert!(text.contains("Amministratore"));
        assert!(text.contains("Firefox"));
    }

    #[test]
    fn cross_agent_intermediate_uses_short_id() {
        let text = engine(TechnicalLevel::Intermediate).explain_cross_agent(
            AgentKind::SysAdmin,
            "installed Firefox",
            TechnicalLevel::Intermediate,
        );
        assert!(text.contains("sadm"));
        assert!(text.contains("Firefox"));
    }

    #[test]
    fn cross_agent_expert_compact() {
        let text = engine(TechnicalLevel::Expert).explain_cross_agent(
            AgentKind::Task,
            "downloaded report",
            TechnicalLevel::Expert,
        );
        assert!(text.contains("AGENT"));
        assert!(text.contains("task"));
        assert!(text.contains("downloaded report"));
    }

    // ── TechnicalLevel ────────────────────────────────────────────────────

    #[test]
    fn default_technical_level_is_intermediate() {
        assert_eq!(TechnicalLevel::default(), TechnicalLevel::Intermediate);
    }

    #[test]
    fn set_level_updates_engine() {
        let mut e = engine(TechnicalLevel::Beginner);
        e.set_level(TechnicalLevel::Expert);
        assert_eq!(e.level(), TechnicalLevel::Expert);
    }
}
