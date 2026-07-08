//! Guidance Agent — user assistant and educator.
//!
//! Implements all NCIP-Helper-007 responsibilities within the five-agent
//! topology defined in NCIP-Agent-Arch-022 §S4:
//!
//! | NCIP-007 component | Module |
//! |--------------------|--------|
//! | Trigger sources (§1) | [`crate::guidance::triggers`] |
//! | Autonomy levels (§2) | [`crate::guidance::autonomy`] |
//! | Mandatory-escalation taxonomy (§3) | [`crate::guidance::escalation`] |
//! | Impact Dashboard (§4) | [`crate::guidance::impact`] |
//! | Plain-Language Explanation Engine (§5) | [`crate::guidance::explanation`] |
//! | Undo window (§6) | [`crate::guidance::undo`] |
//! | Audit log (§7) | [`crate::guidance::audit`] |
//!
//! The Guidance Agent extends NCIP-007 with:
//! - **Veto explanation**: plain-language rendering of Security Agent veto
//!   decisions per the user's technical level.
//! - **Cross-agent explanation**: explains actions performed by other agents.
//! - **Proactive guidance**: Standard Mode may surface security improvements
//!   using the Impact Dashboard.
//!
//! See NCIP-Agent-Arch-022 §S4.

// ── Sub-modules (NCIP-007 §1 – §7) ────────────────────────────────────────

/// NCIP-007 §1 — Trigger sources for the Guidance Agent.
pub mod triggers;

/// NCIP-007 §2 — Autonomy-level configuration and resolution.
pub mod autonomy;

/// NCIP-007 §3 — Mandatory-escalation taxonomy.
pub mod escalation;

/// NCIP-007 §4 — Impact Dashboard with 7 dimensions.
pub mod impact;

/// NCIP-007 §5 — Plain-language explanation engine.
pub mod explanation;

/// NCIP-007 §6 — Undo/rollback window.
pub mod undo;

/// NCIP-007 §7 — Decision audit logging.
pub mod audit;

// ── Re-exports ─────────────────────────────────────────────────────────────

// ── Implementation ─────────────────────────────────────────────────────────
use async_trait::async_trait;
pub use autonomy::AutonomyLevel;
pub use explanation::TechnicalLevel;
use nexacore_types::{AgentId, Result};
use tracing::{debug, info, instrument};

use self::{
    audit::AuditLog,
    autonomy::{AutonomyConfig, AutonomyManager},
    escalation::EscalationPolicy,
    explanation::ExplanationEngine,
    impact::ImpactAssessor,
    undo::UndoWindow,
};
use crate::{
    agent::{Agent, AgentKind, AgentState},
    budget::Budget,
    message::{AgentMessage, MessageKind, MessagePayload, OperationResult, VetoDecision},
};

/// The Guidance Agent.
///
/// Handles user interaction, explanations, tutorials, and need detection.
/// This agent IS `nexacore-helper` (NCIP-007), positioned within the five-agent
/// topology of NCIP-022. All NCIP-007 sub-systems are initialized and owned
/// by this struct.
#[derive(Debug)]
pub struct GuidanceAgent {
    /// Stable unique instance identifier.
    id: AgentId,
    /// Current lifecycle state.
    state: AgentState,
    /// Computational budget (enforced in a later sprint).
    #[allow(dead_code)]
    budget: Budget,
    /// Autonomy level manager (NCIP-007 §2).
    autonomy_manager: AutonomyManager,
    /// Plain-language explanation engine (NCIP-007 §5).
    explanation_engine: ExplanationEngine,
    /// Impact Dashboard assessor (NCIP-007 §4).
    impact_assessor: ImpactAssessor,
    /// 30-second undo/rollback window (NCIP-007 §6).
    undo_window: UndoWindow,
    /// Append-only decision audit log (NCIP-007 §7).
    audit_log: AuditLog,
    /// Mandatory-escalation taxonomy policy (NCIP-007 §3).
    escalation_policy: EscalationPolicy,
}

impl GuidanceAgent {
    /// Create a new Guidance Agent with default NCIP-007 sub-system configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::{AutonomyLevel, GuidanceAgent, TechnicalLevel};
    /// use nexacore_types::AgentId;
    ///
    /// let agent = GuidanceAgent::new(AgentId::from_bytes([0x02; 16]));
    /// assert_eq!(agent.autonomy_level(), AutonomyLevel::Guided);
    /// assert_eq!(agent.technical_level(), TechnicalLevel::Intermediate);
    /// ```
    #[must_use]
    pub fn new(id: AgentId) -> Self {
        Self {
            id,
            state: AgentState::Initializing,
            budget: Budget::guidance_default(),
            autonomy_manager: AutonomyManager::default_config(),
            explanation_engine: ExplanationEngine::new(TechnicalLevel::default()),
            impact_assessor: ImpactAssessor::new(),
            undo_window: UndoWindow::new(),
            audit_log: AuditLog::new(),
            escalation_policy: EscalationPolicy::new(),
        }
    }

    // ── Configuration setters ──────────────────────────────────────────────

    /// Set the user's technical level for all explanation surfaces.
    pub fn set_technical_level(&mut self, level: TechnicalLevel) {
        self.explanation_engine.set_level(level);
    }

    /// Set the global autonomy level.
    ///
    /// Note: in High-Risk mode `Autonomous` is silently downgraded to
    /// `Guided` by [`AutonomyManager::resolve_level`].
    pub fn set_autonomy_level(&mut self, level: AutonomyLevel) {
        self.autonomy_manager = AutonomyManager::new(AutonomyConfig::new(level));
    }

    // ── Pure getters ───────────────────────────────────────────────────────

    /// Returns the global autonomy level (before mode clamping).
    #[must_use]
    pub fn autonomy_level(&self) -> AutonomyLevel {
        self.autonomy_manager.global_level()
    }

    /// Returns the currently configured technical level.
    #[must_use]
    pub fn technical_level(&self) -> TechnicalLevel {
        self.explanation_engine.level()
    }

    /// Returns a reference to the audit log for inspection.
    #[must_use]
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Returns a mutable reference to the undo window.
    #[must_use]
    pub fn undo_window_mut(&mut self) -> &mut UndoWindow {
        &mut self.undo_window
    }

    /// Returns a reference to the escalation policy.
    #[must_use]
    pub fn escalation_policy(&self) -> &EscalationPolicy {
        &self.escalation_policy
    }

    /// Returns a reference to the impact assessor.
    #[must_use]
    pub fn impact_assessor(&self) -> &ImpactAssessor {
        &self.impact_assessor
    }

    // ── High-level helpers (kept for API compatibility) ────────────────────

    /// Generate a plain-language explanation of a veto decision.
    ///
    /// Delegates to the [`ExplanationEngine`] using the agent's configured
    /// technical level.
    #[must_use]
    pub fn explain_veto(&self, decision: &VetoDecision) -> String {
        self.explanation_engine
            .explain_veto(decision, self.explanation_engine.level())
    }

    /// Generate a plain-language explanation of an operation result.
    #[must_use]
    pub fn explain_operation(&self, result: &OperationResult) -> String {
        match self.explanation_engine.level() {
            TechnicalLevel::Beginner => {
                if result.success {
                    format!("Done! {}", result.summary)
                } else {
                    format!("Something went wrong: {}", result.summary)
                }
            }
            TechnicalLevel::Intermediate | TechnicalLevel::Expert => {
                let status = if result.success { "OK" } else { "FAILED" };
                format!("[{status}] {}", result.summary)
            }
        }
    }
}

#[async_trait]
impl Agent for GuidanceAgent {
    fn kind(&self) -> AgentKind {
        AgentKind::Guidance
    }

    fn id(&self) -> AgentId {
        self.id
    }

    fn state(&self) -> AgentState {
        self.state
    }

    #[instrument(skip(self), fields(agent = "guid"))]
    async fn spawn(&mut self) -> Result<()> {
        info!("guidance agent spawning");
        self.state = AgentState::Running;
        Ok(())
    }

    #[instrument(skip(self, message), fields(agent = "guid", msg_kind = ?message.kind))]
    async fn handle_message(&mut self, message: AgentMessage) -> Result<AgentMessage> {
        debug!(from = ?message.from, "processing message");

        let response_payload = match &message.payload {
            MessagePayload::Intent(intent) => {
                // Use the explanation engine to adapt the response to the user's level.
                let explanation = self.explanation_engine.explain(&intent.content);
                MessagePayload::OperationResult(OperationResult {
                    request_id: intent.request_id,
                    success: true,
                    summary: explanation,
                })
            }
            MessagePayload::VetoDecision(decision) => {
                let explanation = self.explain_veto(decision);
                MessagePayload::OperationResult(OperationResult {
                    request_id: decision.request_id,
                    success: false,
                    summary: explanation,
                })
            }
            MessagePayload::OperationResult(result) => {
                let explanation = self.explain_operation(result);
                MessagePayload::OperationResult(OperationResult {
                    request_id: result.request_id,
                    success: result.success,
                    summary: explanation,
                })
            }
            _ => MessagePayload::Empty,
        };

        Ok(AgentMessage {
            id: message.id,
            from: self.id,
            to: message.from,
            timestamp: message.timestamp,
            kind: MessageKind::Result,
            payload: response_payload,
            capabilities: vec![],
            mode: message.mode,
        })
    }

    async fn suspend(&mut self) -> Result<()> {
        self.state = AgentState::Suspended;
        Ok(())
    }

    async fn resume(&mut self) -> Result<()> {
        self.state = AgentState::Running;
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("guidance agent shutting down");
        self.state = AgentState::Shutdown;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::VetoOutcome;

    fn test_agent_id() -> AgentId {
        AgentId::from_bytes([0x02; 16])
    }

    #[test]
    fn default_autonomy_is_guided() {
        let agent = GuidanceAgent::new(test_agent_id());
        assert_eq!(agent.autonomy_level(), AutonomyLevel::Guided);
    }

    #[test]
    fn default_technical_level_is_intermediate() {
        let agent = GuidanceAgent::new(test_agent_id());
        assert_eq!(agent.technical_level(), TechnicalLevel::Intermediate);
    }

    #[test]
    fn explain_veto_beginner() {
        let mut agent = GuidanceAgent::new(test_agent_id());
        agent.set_technical_level(TechnicalLevel::Beginner);
        let decision = VetoDecision {
            request_id: 1,
            outcome: VetoOutcome::Vetoed {
                risk_class: "destructive".into(),
                policy_violated: "no-delete-without-backup".into(),
                alternatives: vec!["create a backup first".into()],
            },
        };
        let explanation = agent.explain_veto(&decision);
        assert!(explanation.contains("safety reasons"));
        assert!(explanation.contains("create a backup first"));
    }

    #[test]
    fn explain_veto_expert() {
        let mut agent = GuidanceAgent::new(test_agent_id());
        agent.set_technical_level(TechnicalLevel::Expert);
        let decision = VetoDecision {
            request_id: 1,
            outcome: VetoOutcome::Vetoed {
                risk_class: "capability-escalation".into(),
                policy_violated: "least-privilege".into(),
                alternatives: vec![],
            },
        };
        let explanation = agent.explain_veto(&decision);
        assert!(explanation.contains("VETO"));
        assert!(explanation.contains("capability-escalation"));
    }

    #[test]
    fn explain_approved_veto() {
        let agent = GuidanceAgent::new(test_agent_id());
        let decision = VetoDecision {
            request_id: 1,
            outcome: VetoOutcome::Approved,
        };
        assert_eq!(agent.explain_veto(&decision), "Action approved.");
    }

    #[test]
    fn explain_operation_success_beginner() {
        let mut agent = GuidanceAgent::new(test_agent_id());
        agent.set_technical_level(TechnicalLevel::Beginner);
        let result = OperationResult {
            request_id: 1,
            success: true,
            summary: "Firefox installed".into(),
        };
        let explanation = agent.explain_operation(&result);
        assert!(explanation.starts_with("Done!"));
    }

    #[test]
    fn explain_operation_failure_intermediate() {
        let mut agent = GuidanceAgent::new(test_agent_id());
        agent.set_technical_level(TechnicalLevel::Intermediate);
        let result = OperationResult {
            request_id: 1,
            success: false,
            summary: "package not found".into(),
        };
        let explanation = agent.explain_operation(&result);
        assert!(explanation.starts_with("[FAILED]"));
    }

    #[tokio::test]
    async fn spawn_and_shutdown() {
        let mut agent = GuidanceAgent::new(test_agent_id());
        agent.spawn().await.unwrap();
        assert_eq!(agent.state(), AgentState::Running);
        agent.shutdown().await.unwrap();
        assert_eq!(agent.state(), AgentState::Shutdown);
    }

    #[test]
    fn agent_kind_is_guidance() {
        let agent = GuidanceAgent::new(test_agent_id());
        assert_eq!(agent.kind(), AgentKind::Guidance);
    }

    // ── Tests for new sub-system integration ──────────────────────────────

    #[test]
    fn set_autonomy_level_propagates() {
        let mut agent = GuidanceAgent::new(test_agent_id());
        agent.set_autonomy_level(AutonomyLevel::Autonomous);
        assert_eq!(agent.autonomy_level(), AutonomyLevel::Autonomous);
    }

    #[test]
    fn set_technical_level_propagates() {
        let mut agent = GuidanceAgent::new(test_agent_id());
        agent.set_technical_level(TechnicalLevel::Expert);
        assert_eq!(agent.technical_level(), TechnicalLevel::Expert);
    }

    #[test]
    fn audit_log_initially_empty() {
        let agent = GuidanceAgent::new(test_agent_id());
        assert_eq!(agent.audit_log().entry_count(), 0);
    }

    #[test]
    fn undo_window_initially_empty() {
        let mut agent = GuidanceAgent::new(test_agent_id());
        assert!(agent.undo_window_mut().is_empty());
    }

    #[test]
    fn escalation_policy_accessible() {
        let agent = GuidanceAgent::new(test_agent_id());
        // Policy must detect destructive actions.
        let class = agent.escalation_policy().classify("delete all files");
        assert!(class.is_some());
    }

    #[test]
    fn impact_assessor_accessible() {
        let agent = GuidanceAgent::new(test_agent_id());
        let dashboard = agent.impact_assessor().assess("upload private file");
        assert_eq!(dashboard.scores.len(), 7);
    }
}
