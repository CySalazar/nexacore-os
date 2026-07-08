//! Per-agent capability policy declarations.
//!
//! Defines the minimum and forbidden capability sets for each agent
//! kind, enforcing the principle of least privilege per NCIP-022 §S1.2.
//!
//! The policy is evaluated at agent spawn time and on every capability
//! request: an agent cannot acquire capabilities outside its allowed
//! set, and it must hold all capabilities in its required set before
//! it can transition to the `Running` state.

use nexacore_capability::scope::Action;
use serde::{Deserialize, Serialize};

use crate::agent::AgentKind;

/// A named capability scope for policy declarations.
///
/// These are logical capability names that map to (Action, Resource)
/// pairs in the capability system. The mapping is intentionally
/// human-readable for audit purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AgentCapability {
    /// Analyze user intents.
    IntentAnalyze,
    /// Dispatch work to other agents.
    AgentDispatch,
    /// Compose multi-step workflows.
    WorkflowCompose,
    /// Generate user-facing explanations.
    UserExplain,
    /// Render Impact Dashboard.
    ImpactRender,
    /// Query autonomy level configuration.
    AutonomyQuery,
    /// Read from the filesystem.
    FsRead,
    /// Write to the filesystem.
    FsWrite,
    /// Install packages via nexacore-pkg.
    PkgInstall,
    /// Remove packages via nexacore-pkg.
    PkgRemove,
    /// Configure system settings.
    SysConfigure,
    /// Administer network settings.
    NetAdmin,
    /// Load drivers.
    DriverLoad,
    /// Monitor threats.
    ThreatMonitor,
    /// Enforce taint tracking.
    TaintEnforce,
    /// Gate model outputs.
    OutputGate,
    /// Validate capability tokens.
    CapabilityValidate,
    /// Profile system performance.
    PerfProfile,
    /// Write to audit log.
    AuditWrite,
    /// Read from audit log.
    AuditRead,
    /// Veto actions (High-Risk mode only).
    SecurityVeto,
    /// Network egress.
    NetEgress,
    /// Search the web.
    WebSearch,
    /// Call external APIs.
    ApiCall,
    /// Create content (documents, presentations, reports).
    ContentCreate,
}

impl AgentCapability {
    /// Maps this logical capability to the underlying `Action` type.
    #[must_use]
    pub const fn to_action(self) -> Action {
        match self {
            Self::IntentAnalyze
            | Self::WorkflowCompose
            | Self::PkgInstall
            | Self::DriverLoad
            | Self::TaintEnforce
            | Self::OutputGate
            | Self::CapabilityValidate
            | Self::SecurityVeto
            | Self::WebSearch
            | Self::ApiCall
            | Self::ContentCreate => Action::Execute,
            Self::AgentDispatch => Action::AgentSend,
            Self::UserExplain
            | Self::ImpactRender
            | Self::AutonomyQuery
            | Self::FsRead
            | Self::AuditRead
            | Self::ThreatMonitor
            | Self::PerfProfile => Action::Read,
            Self::FsWrite
            | Self::AuditWrite
            | Self::SysConfigure
            | Self::NetAdmin
            | Self::NetEgress => Action::Write,
            Self::PkgRemove => Action::Delete,
        }
    }
}

/// Capability policy for a specific agent kind.
#[derive(Clone, Debug)]
pub struct AgentPolicy {
    /// Agent kind this policy applies to.
    pub agent: AgentKind,
    /// Capabilities the agent MUST hold to operate.
    pub required: &'static [AgentCapability],
    /// Capabilities the agent MUST NOT hold.
    pub forbidden: &'static [AgentCapability],
}

impl AgentPolicy {
    /// Returns `true` if `cap` is in the required set.
    #[must_use]
    pub fn requires(&self, cap: AgentCapability) -> bool {
        self.required.contains(&cap)
    }

    /// Returns `true` if `cap` is in the forbidden set.
    #[must_use]
    pub fn forbids(&self, cap: AgentCapability) -> bool {
        self.forbidden.contains(&cap)
    }

    /// Validate a set of capabilities against this policy.
    ///
    /// Returns `Ok` if all required capabilities are present and no
    /// forbidden capabilities are present.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyViolation::MissingRequired`] if a required
    /// capability is absent, or [`PolicyViolation::ForbiddenHeld`]
    /// if a forbidden capability is present.
    pub fn validate(&self, held: &[AgentCapability]) -> Result<(), PolicyViolation> {
        for req in self.required {
            if !held.contains(req) {
                return Err(PolicyViolation::MissingRequired {
                    agent: self.agent,
                    capability: *req,
                });
            }
        }
        for cap in held {
            if self.forbidden.contains(cap) {
                return Err(PolicyViolation::ForbiddenHeld {
                    agent: self.agent,
                    capability: *cap,
                });
            }
        }
        Ok(())
    }
}

/// Error when an agent's capabilities violate its policy.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyViolation {
    /// A required capability is missing.
    #[error("agent {agent:?} missing required capability {capability:?}")]
    MissingRequired {
        /// The agent whose policy was violated.
        agent: AgentKind,
        /// The missing capability.
        capability: AgentCapability,
    },
    /// A forbidden capability is held.
    #[error("agent {agent:?} holds forbidden capability {capability:?}")]
    ForbiddenHeld {
        /// The agent whose policy was violated.
        agent: AgentKind,
        /// The forbidden capability.
        capability: AgentCapability,
    },
}

/// Returns the capability policy for the given agent kind.
#[must_use]
pub fn policy_for(kind: AgentKind) -> AgentPolicy {
    match kind {
        AgentKind::Orchestrator => AgentPolicy {
            agent: kind,
            required: &[
                AgentCapability::IntentAnalyze,
                AgentCapability::AgentDispatch,
                AgentCapability::WorkflowCompose,
                AgentCapability::AuditWrite,
            ],
            forbidden: &[
                AgentCapability::FsWrite,
                AgentCapability::NetEgress,
                AgentCapability::PkgInstall,
                AgentCapability::UserExplain,
            ],
        },
        AgentKind::Guidance => AgentPolicy {
            agent: kind,
            required: &[
                AgentCapability::UserExplain,
                AgentCapability::ImpactRender,
                AgentCapability::AutonomyQuery,
                AgentCapability::AuditWrite,
            ],
            forbidden: &[
                AgentCapability::FsWrite,
                AgentCapability::NetAdmin,
                AgentCapability::PkgInstall,
                AgentCapability::SysConfigure,
            ],
        },
        AgentKind::SysAdmin => AgentPolicy {
            agent: kind,
            required: &[
                AgentCapability::FsRead,
                AgentCapability::FsWrite,
                AgentCapability::PkgInstall,
                AgentCapability::PkgRemove,
                AgentCapability::SysConfigure,
                AgentCapability::NetAdmin,
                AgentCapability::DriverLoad,
                AgentCapability::AuditWrite,
            ],
            forbidden: &[
                AgentCapability::UserExplain,
                AgentCapability::AgentDispatch,
                AgentCapability::SecurityVeto,
            ],
        },
        AgentKind::Security => AgentPolicy {
            agent: kind,
            required: &[
                AgentCapability::ThreatMonitor,
                AgentCapability::TaintEnforce,
                AgentCapability::OutputGate,
                AgentCapability::CapabilityValidate,
                AgentCapability::PerfProfile,
                AgentCapability::AuditWrite,
                AgentCapability::AuditRead,
            ],
            forbidden: &[AgentCapability::UserExplain, AgentCapability::PkgInstall],
        },
        AgentKind::Task => AgentPolicy {
            agent: kind,
            required: &[
                AgentCapability::FsRead,
                AgentCapability::FsWrite,
                AgentCapability::NetEgress,
                AgentCapability::WebSearch,
                AgentCapability::ApiCall,
                AgentCapability::ContentCreate,
                AgentCapability::AuditWrite,
            ],
            forbidden: &[
                AgentCapability::PkgInstall,
                AgentCapability::SysConfigure,
                AgentCapability::DriverLoad,
                AgentCapability::SecurityVeto,
                AgentCapability::AgentDispatch,
            ],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orchestrator_must_not_hold_fs_write() {
        let policy = policy_for(AgentKind::Orchestrator);
        assert!(policy.forbids(AgentCapability::FsWrite));
    }

    #[test]
    fn orchestrator_requires_dispatch() {
        let policy = policy_for(AgentKind::Orchestrator);
        assert!(policy.requires(AgentCapability::AgentDispatch));
    }

    #[test]
    fn sysadmin_must_not_hold_veto() {
        let policy = policy_for(AgentKind::SysAdmin);
        assert!(policy.forbids(AgentCapability::SecurityVeto));
    }

    #[test]
    fn sysadmin_must_not_dispatch() {
        let policy = policy_for(AgentKind::SysAdmin);
        assert!(policy.forbids(AgentCapability::AgentDispatch));
    }

    #[test]
    fn guidance_must_not_write_fs() {
        let policy = policy_for(AgentKind::Guidance);
        assert!(policy.forbids(AgentCapability::FsWrite));
    }

    #[test]
    fn security_must_not_install_packages() {
        let policy = policy_for(AgentKind::Security);
        assert!(policy.forbids(AgentCapability::PkgInstall));
    }

    #[test]
    fn validate_passes_with_all_required() {
        let policy = policy_for(AgentKind::Orchestrator);
        let held: Vec<AgentCapability> = policy.required.to_vec();
        policy.validate(&held).unwrap();
    }

    #[test]
    fn validate_fails_missing_required() {
        let policy = policy_for(AgentKind::Orchestrator);
        let err = policy.validate(&[]).unwrap_err();
        assert!(matches!(err, PolicyViolation::MissingRequired { .. }));
    }

    #[test]
    fn validate_fails_forbidden_held() {
        let policy = policy_for(AgentKind::Orchestrator);
        let mut held: Vec<AgentCapability> = policy.required.to_vec();
        held.push(AgentCapability::FsWrite); // forbidden for orchestrator
        let err = policy.validate(&held).unwrap_err();
        assert!(matches!(err, PolicyViolation::ForbiddenHeld { .. }));
    }

    #[test]
    fn all_agents_have_audit_write() {
        for kind in AgentKind::all() {
            let policy = policy_for(kind);
            assert!(
                policy.requires(AgentCapability::AuditWrite),
                "{kind:?} missing AuditWrite"
            );
        }
    }

    #[test]
    fn no_policy_has_contradictory_sets() {
        for kind in AgentKind::all() {
            let policy = policy_for(kind);
            for req in policy.required {
                assert!(
                    !policy.forbidden.contains(req),
                    "{kind:?} has {req:?} in both required and forbidden"
                );
            }
        }
    }
}
