//! Orchestrator Agent — central coordinator.
//!
//! Receives all user intents, classifies them, and dispatches work to
//! the appropriate agent(s). Manages the priority queue and composes
//! multi-agent workflows.
//!
//! See NCIP-Agent-Arch-022 §S2.

use async_trait::async_trait;
use nexacore_types::{AgentId, Result};
use tracing::{debug, info, instrument};

use crate::{
    agent::{Agent, AgentKind, AgentState},
    budget::Budget,
    message::{
        AgentMessage, IntentClass, IntentPayload, MessageKind, MessagePayload, OperationResult,
        VetoOutcome,
    },
    mode::OperationalMode,
};

/// The Orchestrator Agent.
///
/// Acts as the central dispatcher for all user intents. It MUST NOT
/// execute system operations or generate user-facing explanations
/// directly (NCIP-022 §S1).
#[derive(Debug)]
pub struct OrchestratorAgent {
    id: AgentId,
    state: AgentState,
    #[allow(dead_code)] // enforced in a later sprint
    budget: Budget,
}

impl OrchestratorAgent {
    /// Create a new Orchestrator agent.
    #[must_use]
    pub fn new(id: AgentId) -> Self {
        Self {
            id,
            state: AgentState::Initializing,
            budget: Budget::orchestrator_default(),
        }
    }

    /// Classify a raw intent string into an [`IntentClass`].
    ///
    /// Phase 2 stub: uses keyword-based heuristics. A future phase will
    /// use the local Tier-0 model for intent classification.
    #[must_use]
    pub fn classify_intent(content: &str) -> IntentClass {
        let lower = content.to_lowercase();

        let is_security = lower.contains("security")
            || lower.contains("threat")
            || lower.contains("audit")
            || lower.contains("sicurezza")
            || lower.contains("hardening");

        let is_admin = lower.contains("install")
            || lower.contains("update")
            || lower.contains("configure")
            || lower.contains("driver")
            || lower.contains("configura")
            || lower.contains("installa");

        let is_guidance = lower.contains("explain")
            || lower.contains("help")
            || lower.contains("tutorial")
            || lower.contains("how")
            || lower.contains("spiega")
            || lower.contains("aiuto");

        let is_task = lower.contains("find")
            || lower.contains("search")
            || lower.contains("create")
            || lower.contains("organize")
            || lower.contains("draft")
            || lower.contains("monitor")
            || lower.contains("compare")
            || lower.contains("cerca")
            || lower.contains("trovami")
            || lower.contains("crea")
            || lower.contains("riorganizza");

        let flags = [is_security, is_admin, is_guidance, is_task];
        let count = flags.iter().filter(|&&f| f).count();

        if count > 1 {
            return IntentClass::Composite;
        }

        if is_security {
            IntentClass::Security
        } else if is_admin {
            IntentClass::Administration
        } else if is_task {
            IntentClass::Task
        } else {
            IntentClass::Guidance
        }
    }

    /// Determine the dispatch target agent for a given intent class.
    #[must_use]
    pub fn dispatch_target(class: IntentClass) -> AgentKind {
        match class {
            IntentClass::Guidance | IntentClass::Composite => AgentKind::Guidance,
            IntentClass::Administration => AgentKind::SysAdmin,
            IntentClass::Security => AgentKind::Security,
            IntentClass::Task => AgentKind::Task,
        }
    }

    /// Returns `true` if the current mode requires Security Agent
    /// pre-authorization before dispatch.
    #[must_use]
    pub fn requires_preauth(mode: OperationalMode) -> bool {
        matches!(mode, OperationalMode::HighRisk)
    }

    /// Build a dispatch response for an intent.
    #[allow(clippy::unused_self)] // will use self for stateful workflow composition
    fn handle_intent(
        &self,
        intent: &IntentPayload,
        mode: OperationalMode,
    ) -> (IntentClass, AgentKind, bool) {
        let class = Self::classify_intent(&intent.content);
        let target = Self::dispatch_target(class);
        let needs_preauth = Self::requires_preauth(mode);
        (class, target, needs_preauth)
    }
}

#[async_trait]
impl Agent for OrchestratorAgent {
    fn kind(&self) -> AgentKind {
        AgentKind::Orchestrator
    }

    fn id(&self) -> AgentId {
        self.id
    }

    fn state(&self) -> AgentState {
        self.state
    }

    #[instrument(skip(self), fields(agent = "orch"))]
    async fn spawn(&mut self) -> Result<()> {
        info!("orchestrator agent spawning");
        self.state = AgentState::Running;
        Ok(())
    }

    #[instrument(skip(self, message), fields(agent = "orch", msg_kind = ?message.kind))]
    async fn handle_message(&mut self, message: AgentMessage) -> Result<AgentMessage> {
        debug!(from = ?message.from, kind = ?message.kind, "processing message");

        match &message.payload {
            MessagePayload::Intent(intent) => {
                let (class, target, needs_preauth) = self.handle_intent(intent, message.mode);

                debug!(?class, ?target, needs_preauth, "intent classified");

                let summary =
                    format!("classified as {class:?}, target: {target}, preauth: {needs_preauth}");

                Ok(AgentMessage {
                    id: message.id,
                    from: self.id,
                    to: message.from,
                    timestamp: message.timestamp,
                    kind: MessageKind::Result,
                    payload: MessagePayload::OperationResult(OperationResult {
                        request_id: intent.request_id,
                        success: true,
                        summary,
                    }),
                    capabilities: vec![],
                    mode: message.mode,
                })
            }
            MessagePayload::VetoDecision(decision) => {
                match &decision.outcome {
                    VetoOutcome::Approved => {
                        debug!(
                            request_id = decision.request_id,
                            "veto approved, proceeding"
                        );
                    }
                    VetoOutcome::Vetoed { risk_class, .. } => {
                        info!(
                            request_id = decision.request_id,
                            risk_class, "action vetoed by security agent"
                        );
                    }
                }
                Ok(AgentMessage {
                    id: message.id,
                    from: self.id,
                    to: message.from,
                    timestamp: message.timestamp,
                    kind: MessageKind::Result,
                    payload: MessagePayload::Empty,
                    capabilities: vec![],
                    mode: message.mode,
                })
            }
            MessagePayload::Heartbeat(_) => Ok(AgentMessage {
                id: message.id,
                from: self.id,
                to: message.from,
                timestamp: message.timestamp,
                kind: MessageKind::Heartbeat,
                payload: MessagePayload::Heartbeat(crate::message::HeartbeatPayload {
                    sequence: 0,
                    is_response: true,
                }),
                capabilities: vec![],
                mode: message.mode,
            }),
            _ => Ok(AgentMessage {
                id: message.id,
                from: self.id,
                to: message.from,
                timestamp: message.timestamp,
                kind: MessageKind::Result,
                payload: MessagePayload::Empty,
                capabilities: vec![],
                mode: message.mode,
            }),
        }
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
        info!("orchestrator agent shutting down");
        self.state = AgentState::Shutdown;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent_id() -> AgentId {
        AgentId::from_bytes([0x01; 16])
    }

    #[test]
    fn classify_security_intent() {
        assert_eq!(
            OrchestratorAgent::classify_intent("run a security audit"),
            IntentClass::Security
        );
    }

    #[test]
    fn classify_admin_intent() {
        assert_eq!(
            OrchestratorAgent::classify_intent("install firefox"),
            IntentClass::Administration
        );
    }

    #[test]
    fn classify_guidance_intent() {
        assert_eq!(
            OrchestratorAgent::classify_intent("explain how the mesh works"),
            IntentClass::Guidance
        );
    }

    #[test]
    fn classify_composite_intent() {
        assert_eq!(
            OrchestratorAgent::classify_intent("install nginx and explain how to configure it"),
            IntentClass::Composite
        );
    }

    #[test]
    fn classify_default_is_guidance() {
        assert_eq!(
            OrchestratorAgent::classify_intent("hello world"),
            IntentClass::Guidance
        );
    }

    #[test]
    fn dispatch_target_mapping() {
        assert_eq!(
            OrchestratorAgent::dispatch_target(IntentClass::Guidance),
            AgentKind::Guidance
        );
        assert_eq!(
            OrchestratorAgent::dispatch_target(IntentClass::Administration),
            AgentKind::SysAdmin
        );
        assert_eq!(
            OrchestratorAgent::dispatch_target(IntentClass::Security),
            AgentKind::Security
        );
    }

    #[test]
    fn high_risk_requires_preauth() {
        assert!(OrchestratorAgent::requires_preauth(
            OperationalMode::HighRisk
        ));
        assert!(!OrchestratorAgent::requires_preauth(
            OperationalMode::Standard
        ));
    }

    #[tokio::test]
    async fn spawn_transitions_to_running() {
        let mut agent = OrchestratorAgent::new(test_agent_id());
        assert_eq!(agent.state(), AgentState::Initializing);
        agent.spawn().await.unwrap();
        assert_eq!(agent.state(), AgentState::Running);
    }

    #[tokio::test]
    async fn suspend_and_resume() {
        let mut agent = OrchestratorAgent::new(test_agent_id());
        agent.spawn().await.unwrap();
        agent.suspend().await.unwrap();
        assert_eq!(agent.state(), AgentState::Suspended);
        agent.resume().await.unwrap();
        assert_eq!(agent.state(), AgentState::Running);
    }

    #[tokio::test]
    async fn shutdown_transitions_to_shutdown() {
        let mut agent = OrchestratorAgent::new(test_agent_id());
        agent.spawn().await.unwrap();
        agent.shutdown().await.unwrap();
        assert_eq!(agent.state(), AgentState::Shutdown);
    }

    #[test]
    fn agent_kind_is_orchestrator() {
        let agent = OrchestratorAgent::new(test_agent_id());
        assert_eq!(agent.kind(), AgentKind::Orchestrator);
    }
}
