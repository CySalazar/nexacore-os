//! Sandboxed execution environment for agents.
//!
//! Each agent runs in its own sandbox to enforce isolation boundaries.
//! Phase 2 uses a lightweight in-process sandbox; a WASM-based sandbox
//! (via wasmtime) is planned for a future phase.
//!
//! See `docs/04-security-model.md` § Secure agent sandboxing.

use serde::{Deserialize, Serialize};

use crate::agent::AgentKind;

/// The type of sandbox an agent runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SandboxType {
    /// In-process sandbox (Phase 2 default).
    InProcess,
    /// WASM-based sandbox via wasmtime (future).
    Wasm,
    /// Process-level isolation (alternative to WASM).
    Process,
}

impl Default for SandboxType {
    fn default() -> Self {
        Self::InProcess
    }
}

/// Configuration for an agent's sandbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// The agent this sandbox is for.
    pub agent: AgentKind,
    /// The type of sandbox.
    pub sandbox_type: SandboxType,
    /// Maximum memory the sandbox may use (bytes).
    pub memory_limit: u64,
    /// Whether the sandbox has network access.
    pub network_access: bool,
    /// Whether the sandbox has filesystem access.
    pub filesystem_access: bool,
}

impl SandboxConfig {
    /// Default sandbox config for a given agent kind.
    #[must_use]
    pub fn default_for(agent: AgentKind) -> Self {
        match agent {
            AgentKind::Orchestrator => Self {
                agent,
                sandbox_type: SandboxType::InProcess,
                memory_limit: 64 * 1024 * 1024,
                network_access: false,
                filesystem_access: false,
            },
            AgentKind::Guidance | AgentKind::Security => Self {
                agent,
                sandbox_type: SandboxType::InProcess,
                memory_limit: 128 * 1024 * 1024,
                network_access: false,
                filesystem_access: false,
            },
            AgentKind::SysAdmin | AgentKind::Task => Self {
                agent,
                sandbox_type: SandboxType::InProcess,
                memory_limit: 256 * 1024 * 1024,
                network_access: true,
                filesystem_access: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orchestrator_sandbox_no_fs_no_net() {
        let cfg = SandboxConfig::default_for(AgentKind::Orchestrator);
        assert!(!cfg.filesystem_access);
        assert!(!cfg.network_access);
    }

    #[test]
    fn sysadmin_sandbox_has_fs_and_net() {
        let cfg = SandboxConfig::default_for(AgentKind::SysAdmin);
        assert!(cfg.filesystem_access);
        assert!(cfg.network_access);
    }

    #[test]
    fn security_sandbox_no_fs_no_net() {
        let cfg = SandboxConfig::default_for(AgentKind::Security);
        assert!(!cfg.filesystem_access);
        assert!(!cfg.network_access);
    }

    #[test]
    fn guidance_sandbox_no_fs_no_net() {
        let cfg = SandboxConfig::default_for(AgentKind::Guidance);
        assert!(!cfg.filesystem_access);
        assert!(!cfg.network_access);
    }

    #[test]
    fn default_sandbox_type_is_in_process() {
        assert_eq!(SandboxType::default(), SandboxType::InProcess);
    }

    #[test]
    fn all_agents_have_default_config() {
        for kind in AgentKind::all() {
            let cfg = SandboxConfig::default_for(kind);
            assert_eq!(cfg.agent, kind);
            assert!(cfg.memory_limit > 0);
        }
    }
}
