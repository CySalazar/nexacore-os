//! Core `Agent` trait and `AgentKind` taxonomy.
//!
//! Every system agent implements the [`Agent`] trait, which defines the
//! lifecycle methods (spawn, suspend, resume, shutdown) and the message
//! handler. The [`AgentKind`] enum enumerates the five agent types
//! defined in NCIP-Agent-Arch-022 §S1.

use async_trait::async_trait;
use nexacore_types::{AgentId, Result};
use serde::{Deserialize, Serialize};

use crate::{budget::Budget, message::AgentMessage};

/// The five system agents defined in NCIP-022 §S1.
///
/// `#[non_exhaustive]` is intentionally NOT applied: the agent taxonomy
/// is a closed set. Adding or removing an agent requires an NCIP amendment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentKind {
    /// Central coordinator — dispatches intents to other agents.
    Orchestrator,
    /// User assistant — explanations, tutorials, need detection.
    Guidance,
    /// Technical operator — system config, packages, drivers.
    SysAdmin,
    /// Security guardian — threat monitoring, veto, performance.
    Security,
    /// User-delegated productive work — research, content, file mgmt.
    Task,
}

impl AgentKind {
    /// The stable four-character identifier used in audit logs and
    /// inter-agent messages (NCIP-022 §S1).
    #[must_use]
    pub const fn short_id(self) -> &'static str {
        match self {
            Self::Orchestrator => "orch",
            Self::Guidance => "guid",
            Self::SysAdmin => "sadm",
            Self::Security => "secp",
            Self::Task => "task",
        }
    }

    /// Italian display name for user-facing surfaces.
    #[must_use]
    pub const fn display_it(self) -> &'static str {
        match self {
            Self::Orchestrator => "Orchestratore",
            Self::Guidance => "Assistente",
            Self::SysAdmin => "Amministratore",
            Self::Security => "Sicurezza",
            Self::Task => "Esecutore",
        }
    }

    /// Returns all five agent kinds in the canonical boot order.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::Security,     // boots first (monitors others)
            Self::Orchestrator, // boots second (coordinator)
            Self::Guidance,     // boots third (user-facing)
            Self::SysAdmin,     // boots fourth (system ops)
            Self::Task,         // boots last (user tasks)
        ]
    }
}

impl core::fmt::Display for AgentKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str((*self).short_id())
    }
}

/// Lifecycle state of a running agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentState {
    /// Agent is being initialized.
    Initializing,
    /// Agent is running and processing messages.
    Running,
    /// Agent is temporarily suspended (state preserved).
    Suspended,
    /// Agent has been shut down.
    Shutdown,
    /// Agent encountered a fatal error.
    Failed,
}

/// Metadata identifying a running agent instance.
#[derive(Clone, Debug)]
pub struct AgentInfo {
    /// Unique identifier for this agent instance.
    pub id: AgentId,
    /// Which of the five agent types this is.
    pub kind: AgentKind,
    /// Current lifecycle state.
    pub state: AgentState,
    /// Computational budget.
    pub budget: Budget,
}

/// The core trait that all five system agents implement.
///
/// The lifecycle follows: `spawn` → `Running` → `suspend`/`resume` →
/// `shutdown`. Messages are delivered via `handle_message` while the
/// agent is in the `Running` state.
#[async_trait]
pub trait Agent: Send + Sync {
    /// Returns the agent kind.
    fn kind(&self) -> AgentKind;

    /// Returns the agent's unique instance identifier.
    fn id(&self) -> AgentId;

    /// Returns the current lifecycle state.
    fn state(&self) -> AgentState;

    /// Initialize and start the agent.
    ///
    /// Called exactly once at system boot. After successful spawn, the
    /// agent transitions to [`AgentState::Running`].
    async fn spawn(&mut self) -> Result<()>;

    /// Process an incoming inter-agent message.
    ///
    /// The caller (IPC dispatcher) guarantees that the message's
    /// capability tokens have been validated before delivery.
    async fn handle_message(&mut self, message: AgentMessage) -> Result<AgentMessage>;

    /// Temporarily suspend the agent, preserving state.
    ///
    /// KV-cache is flushed on suspend per the security model.
    async fn suspend(&mut self) -> Result<()>;

    /// Resume a suspended agent.
    async fn resume(&mut self) -> Result<()>;

    /// Gracefully shut down the agent.
    ///
    /// After shutdown, the agent transitions to [`AgentState::Shutdown`]
    /// and will not process further messages.
    async fn shutdown(&mut self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_kind_short_ids_are_four_chars() {
        for kind in AgentKind::all() {
            assert_eq!(kind.short_id().len(), 4);
        }
    }

    #[test]
    fn agent_kind_short_ids_are_unique() {
        let ids: Vec<&str> = AgentKind::all().iter().map(|k| k.short_id()).collect();
        let mut deduped = ids.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len());
    }

    #[test]
    fn agent_kind_display_is_short_id() {
        for kind in AgentKind::all() {
            assert_eq!(format!("{kind}"), kind.short_id());
        }
    }

    #[test]
    fn agent_kind_all_has_five_entries() {
        assert_eq!(AgentKind::all().len(), 5);
    }

    #[test]
    fn agent_kind_boot_order_security_first() {
        assert_eq!(AgentKind::all()[0], AgentKind::Security);
    }

    #[test]
    fn agent_kind_italian_names() {
        assert_eq!(AgentKind::Orchestrator.display_it(), "Orchestratore");
        assert_eq!(AgentKind::Guidance.display_it(), "Assistente");
        assert_eq!(AgentKind::SysAdmin.display_it(), "Amministratore");
        assert_eq!(AgentKind::Security.display_it(), "Sicurezza");
    }
}
