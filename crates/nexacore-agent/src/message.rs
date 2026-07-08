//! Inter-agent communication protocol.
//!
//! All communication between agents uses a structured [`crate::message::AgentMessage`]
//! envelope that carries sender identity, capability tokens, and the
//! current operational mode. Messages are validated by the receiver
//! before processing.
//!
//! See NCIP-Agent-Arch-022 §S7 for the normative specification.

use nexacore_capability::CapabilityToken;
use nexacore_types::AgentId;
use serde::{Deserialize, Serialize};

use crate::mode::OperationalMode;

/// Monotonically increasing message identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MessageId(u64);

impl MessageId {
    /// Create a message ID from a raw counter value.
    #[must_use]
    pub const fn from_raw(v: u64) -> Self {
        Self(v)
    }

    /// Returns the raw counter value.
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self.0
    }
}

/// Structured envelope for all inter-agent communication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentMessage {
    /// Unique message identifier for correlation and audit.
    pub id: MessageId,
    /// Sending agent.
    pub from: AgentId,
    /// Receiving agent.
    pub to: AgentId,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// Message type.
    pub kind: MessageKind,
    /// Message body.
    pub payload: MessagePayload,
    /// Capability tokens authorizing this message.
    pub capabilities: Vec<CapabilityToken>,
    /// Current system operational mode at send time.
    pub mode: OperationalMode,
}

/// The type of an inter-agent message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageKind {
    /// Orchestrator dispatching work to an agent.
    Dispatch,
    /// Agent returning work result to the Orchestrator.
    Result,
    /// Orchestrator requesting Security Agent pre-authorization.
    VetoRequest,
    /// Security Agent responding to a veto request.
    VetoResponse,
    /// Periodic liveness check (Security Agent ↔ Orchestrator).
    Heartbeat,
    /// Security Agent raising a threat alert.
    Alert,
    /// Agent escalating an action per NCIP-007 taxonomy.
    Escalation,
}

/// The body of an inter-agent message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessagePayload {
    /// A user intent to be processed.
    Intent(IntentPayload),
    /// Result of a dispatched operation.
    OperationResult(OperationResult),
    /// Veto decision from the Security Agent.
    VetoDecision(VetoDecision),
    /// Heartbeat ping/pong.
    Heartbeat(HeartbeatPayload),
    /// Security alert.
    SecurityAlert(SecurityAlertPayload),
    /// Empty payload (for simple signals).
    Empty,
}

/// A user intent forwarded by the Orchestrator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentPayload {
    /// Classification of the intent.
    pub classification: IntentClass,
    /// Raw intent text or structured representation.
    pub content: String,
    /// Caller-assigned request ID for end-to-end correlation.
    pub request_id: u64,
}

/// Intent classification per NCIP-022 §S2.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentClass {
    /// Explanation, tutorial, question.
    Guidance,
    /// System operation, config, install.
    Administration,
    /// Threat query, hardening request, audit query.
    Security,
    /// Research, content creation, file management, monitoring.
    Task,
    /// Requires multiple agents.
    Composite,
}

/// The result of a dispatched operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationResult {
    /// The original request ID.
    pub request_id: u64,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Human-readable summary of what happened.
    pub summary: String,
}

/// A veto decision from the Security Agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VetoDecision {
    /// The request ID of the action being evaluated.
    pub request_id: u64,
    /// The decision.
    pub outcome: VetoOutcome,
}

/// The outcome of a Security Agent veto evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VetoOutcome {
    /// Action is approved.
    Approved,
    /// Action is vetoed.
    Vetoed {
        /// Which threat class triggered the veto.
        risk_class: String,
        /// The specific policy or rule violated.
        policy_violated: String,
        /// Alternative actions the user may take.
        alternatives: Vec<String>,
    },
}

/// Heartbeat ping/pong payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    /// Sequence number for ordering.
    pub sequence: u64,
    /// Whether this is a ping (request) or pong (response).
    pub is_response: bool,
}

/// Security alert raised by the Security Agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityAlertPayload {
    /// Severity level.
    pub severity: AlertSeverity,
    /// Description of the detected threat.
    pub description: String,
    /// Recommended action.
    pub recommendation: String,
}

/// Severity levels for security alerts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Informational — no immediate action required.
    Info,
    /// Warning — potential threat detected.
    Warning,
    /// Critical — active threat requiring immediate response.
    Critical,
}

/// Counter for generating monotonically increasing message IDs.
#[derive(Debug)]
pub struct MessageIdGenerator {
    next: std::sync::atomic::AtomicU64,
}

impl MessageIdGenerator {
    /// Create a new generator starting at 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Generate the next message ID.
    pub fn next_id(&self) -> MessageId {
        let v = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        MessageId::from_raw(v)
    }
}

impl Default for MessageIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_round_trip() {
        let id = MessageId::from_raw(42);
        assert_eq!(id.as_raw(), 42);
    }

    #[test]
    fn message_id_ordering() {
        let a = MessageId::from_raw(1);
        let b = MessageId::from_raw(2);
        assert!(a < b);
    }

    #[test]
    fn message_id_generator_monotonic() {
        let id_gen = MessageIdGenerator::new();
        let a = id_gen.next_id();
        let b = id_gen.next_id();
        let c = id_gen.next_id();
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn intent_class_equality() {
        assert_eq!(IntentClass::Guidance, IntentClass::Guidance);
        assert_ne!(IntentClass::Guidance, IntentClass::Administration);
    }

    #[test]
    fn alert_severity_ordering() {
        assert!(AlertSeverity::Info < AlertSeverity::Warning);
        assert!(AlertSeverity::Warning < AlertSeverity::Critical);
    }

    #[test]
    fn veto_outcome_approved() {
        let decision = VetoDecision {
            request_id: 1,
            outcome: VetoOutcome::Approved,
        };
        assert!(matches!(decision.outcome, VetoOutcome::Approved));
    }

    #[test]
    fn veto_outcome_vetoed_has_alternatives() {
        let decision = VetoDecision {
            request_id: 2,
            outcome: VetoOutcome::Vetoed {
                risk_class: "capability-escalation".into(),
                policy_violated: "least-privilege".into(),
                alternatives: vec!["use scoped token".into()],
            },
        };
        if let VetoOutcome::Vetoed { alternatives, .. } = &decision.outcome {
            assert_eq!(alternatives.len(), 1);
        } else {
            panic!("expected Vetoed");
        }
    }
}
