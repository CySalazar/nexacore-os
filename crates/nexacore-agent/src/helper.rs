//! NexaCore Helper — the always-on system agentic layer (WS16-01, NCIP-Helper-007).
//!
//! The Helper is the system-level service that turns the five-agent framework
//! (NCIP-Agent-Arch-022) and the Guidance Agent's NCIP-007 sub-systems into a
//! coherent, always-reachable assistant that can *act* on the system — under
//! capability gating, a privacy budget, an Impact Dashboard, and a 30-second
//! undo window.
//!
//! ## What lives where
//!
//! The NCIP-007 *reasoning logic* already exists inside [`crate::guidance`]:
//! autonomy levels ([`crate::guidance::autonomy`], §2), the mandatory-escalation
//! taxonomy ([`crate::guidance::escalation`], §3), the Impact Dashboard
//! ([`crate::guidance::impact`], §4), the undo window ([`crate::guidance::undo`],
//! §6), the decision audit log ([`crate::guidance::audit`], §7), and the trigger
//! sources ([`crate::guidance::triggers`], §1). This module does **not**
//! re-implement any of that — it *composes* those pieces into a system service
//! and adds the integration that only makes sense at the system layer:
//!
//! | WS16-01 sub-task | This module |
//! |------------------|-------------|
//! | `.2` always-on daemon | [`HelperService`] lifecycle (`start`/`stop`/`is_running`) |
//! | `.3` five-agent reasoning backend | [`ReasoningBackend`](crate::helper::ReasoningBackend) + [`FiveAgentReasoner`](crate::helper::FiveAgentReasoner) (binds the Orchestrator's classify/route) |
//! | `.4` need detection | [`HelperService::detect_need`] (drives the trigger evaluator) |
//! | `.5` 3 autonomy levels + policy selector | [`HelperService::resolve_autonomy`] (autonomy ∧ escalation floor) |
//! | `.6` mandatory Impact Dashboard (Privacy/Trust/Cost/Time) | [`HelperProposal::mandatory_axes`] |
//! | `.7` 30s undo + pre-action snapshot | [`HelperService::execute`] + [`HelperService::undo_last`] + [`StateSnapshot`](crate::helper::StateSnapshot) |
//! | `.8` escalation taxonomy + authorization prompt | [`HelperProposal::authorization_prompt`] |
//! | `.9` privacy-budget escalation gate | [`HelperService::execute`] charges the WS5-07 [`PrivacyLedger`](nexacore_runtime::privacy_budget::PrivacyLedger) |
//! | `.10` global hotkey | [`HELPER_HOTKEY`] + [`HotkeyRegistrar`](crate::helper::HotkeyRegistrar) |
//! | `.11` capability-gated execution | [`HelperService::execute`] behind [`CapabilityGate`](crate::helper::CapabilityGate) + [`ActionExecutor`](crate::helper::ActionExecutor) |
//!
//! ## Effects stay behind traits
//!
//! Every effect the Helper can have on the world — authorizing a capability,
//! mutating system state, registering a hotkey — is a trait the integration
//! layer backs with the real implementation (a verified [`nexacore_capability`]
//! token check, a kernel syscall, the [`crate::guidance`] runtime). The decision
//! logic is therefore pure and host-testable with in-memory doubles, mirroring
//! the `ProcessActions` pattern in `nexacore-monitor` and `EgressGuard` in
//! `nexacore-tokenization`.

use nexacore_runtime::{
    privacy_budget::{BudgetHolder, EgressEvent, PrivacyLedger},
    router::ExecutionTier,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, instrument};

use crate::{
    agent::AgentKind,
    guidance::{
        audit::{AuditEntry, AuditLog},
        autonomy::{AutonomyConfig, AutonomyLevel, AutonomyManager},
        escalation::{EscalationClass, EscalationPolicy},
        impact::{ImpactAssessor, ImpactDashboard, ImpactDimension, ImpactScore},
        triggers::{TriggerEvaluator, TriggerEvent},
    },
    message::IntentClass,
    mode::OperationalMode,
    orchestrator::OrchestratorAgent,
};

// =============================================================================
// Global hotkey (WS16-01.10)
// =============================================================================

/// Canonical descriptor for the system-wide hotkey that opens the Helper from
/// anywhere (WS16-01.10).
///
/// The Helper does not own the input stack; it declares *what* to bind and the
/// integration layer (the desktop runtime's `ShortcutRegistry`, WS17-04) does
/// the actual registration through [`HotkeyRegistrar`]. The descriptor carries
/// platform-appropriate default chords so the binding matches each OS's
/// convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotkeyDescriptor {
    /// Stable action id the registry binds (`"helper.toggle"`).
    pub action_id: &'static str,
    /// Default chord on macOS-class platforms.
    pub default_macos: &'static str,
    /// Default chord on every other platform.
    pub default_other: &'static str,
    /// Human-readable description for the shortcut settings panel.
    pub description: &'static str,
}

/// The Helper's canonical global hotkey (WS16-01.10).
///
/// `Meta+Shift+Space` on macOS, `Ctrl+Shift+Space` elsewhere — chosen to avoid
/// clobbering the OS launcher chords while staying reachable from any app.
pub const HELPER_HOTKEY: HotkeyDescriptor = HotkeyDescriptor {
    action_id: "helper.toggle",
    default_macos: "Meta+Shift+Space",
    default_other: "Ctrl+Shift+Space",
    description: "Open the NexaCore Helper",
};

impl HotkeyDescriptor {
    /// Returns the default chord for the running platform family.
    #[must_use]
    pub const fn default_for(self, macos: bool) -> &'static str {
        if macos {
            self.default_macos
        } else {
            self.default_other
        }
    }
}

/// Seam to the desktop runtime's global shortcut registry (WS16-01.10).
///
/// The real implementation binds [`HELPER_HOTKEY`] into the WS17-04
/// `ShortcutRegistry` at `Scope::Global`; tests use an in-memory double.
pub trait HotkeyRegistrar {
    /// Register the Helper's global hotkey so it opens the Helper from anywhere.
    ///
    /// Returns the canonical chord string actually bound.
    ///
    /// # Errors
    ///
    /// [`HelperError::Hotkey`] when the registry rejects the binding (e.g. an
    /// unresolved conflict with an existing global shortcut).
    fn register_global(&mut self, descriptor: &HotkeyDescriptor) -> Result<String, HelperError>;
}

// =============================================================================
// Errors
// =============================================================================

/// Why a Helper operation failed. Carried back to the caller; never panics.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HelperError {
    /// The capability gate refused the action (WS16-01.11). Fail-closed.
    #[error("capability denied for action: {0}")]
    CapabilityDenied(String),
    /// The privacy budget could not cover the action's egress (WS16-01.9).
    /// Fail-closed: the action is never executed.
    #[error("privacy budget exhausted: requested {requested}, remaining {remaining}")]
    BudgetExhausted {
        /// Budget units the egress required.
        requested: u64,
        /// Budget units that remained for the holder.
        remaining: u64,
    },
    /// The action executor reported a failure performing the effect.
    #[error("action execution failed: {0}")]
    Executor(String),
    /// Restoring a pre-action snapshot during undo failed.
    #[error("undo failed: {0}")]
    Undo(String),
    /// Global-hotkey registration failed.
    #[error("hotkey registration failed: {0}")]
    Hotkey(String),
    /// There was no in-window action to undo (WS16-01.7).
    #[error("nothing to undo within the 30s window")]
    NothingToUndo,
}

// =============================================================================
// Reasoning backend (WS16-01.3) — bind the five-agent framework
// =============================================================================

/// The route the five-agent framework chose for a need/intent (WS16-01.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReasonedRoute {
    /// Intent class the Orchestrator assigned.
    pub intent_class: IntentClass,
    /// Agent responsible for handling the intent.
    pub responsible_agent: AgentKind,
    /// Whether the current mode requires Security-agent pre-authorization.
    pub requires_preauth: bool,
}

/// The Helper's reasoning backend: maps a natural-language need to the agent
/// that should handle it (WS16-01.3).
///
/// Abstracted so the Helper's decision path stays synchronous and host-testable.
/// The production backend is [`FiveAgentReasoner`], which binds the five-agent
/// framework's Orchestrator classification; generative answers continue to flow
/// through the existing [`crate::runtime_link::RuntimeLink`] seam at the agent
/// layer.
pub trait ReasoningBackend {
    /// Route `intent` to the responsible agent under `mode`.
    fn route(&self, intent: &str, mode: OperationalMode) -> ReasonedRoute;
}

/// Binds the five-agent framework (`nexacore-agent`) as the Helper's reasoning
/// backend (WS16-01.3).
///
/// Delegates to the Orchestrator's pure classification — the same routing the
/// async agent mesh uses — so the Helper reasons *through* the five agents
/// rather than re-deriving intent handling.
#[derive(Debug, Default, Clone, Copy)]
pub struct FiveAgentReasoner;

impl ReasoningBackend for FiveAgentReasoner {
    fn route(&self, intent: &str, mode: OperationalMode) -> ReasonedRoute {
        let intent_class = OrchestratorAgent::classify_intent(intent);
        ReasonedRoute {
            intent_class,
            responsible_agent: OrchestratorAgent::dispatch_target(intent_class),
            requires_preauth: OrchestratorAgent::requires_preauth(mode),
        }
    }
}

// =============================================================================
// System action + effect seams (WS16-01.11)
// =============================================================================

/// A concrete system action the Helper proposes to perform (WS16-01.11).
///
/// `tier` drives the privacy-budget charge (WS16-01.9): a `Local` action egresses
/// nothing and is free; higher tiers cost budget before they may run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAction {
    /// Stable id assigned by [`HelperService`] for correlation and undo.
    pub id: u64,
    /// Plain-language description (also fed to escalation/impact classifiers).
    pub description: String,
    /// Execution tier the action's effect/inference runs on.
    pub tier: ExecutionTier,
    /// Egress destination label recorded on the privacy ledger.
    pub destination: String,
    /// Whether the effect can be mechanically reversed within the undo window.
    pub reversible: bool,
}

impl SystemAction {
    /// Construct a local, reversible action (the common, free case).
    #[must_use]
    pub fn local(id: u64, description: impl Into<String>) -> Self {
        Self {
            id,
            description: description.into(),
            tier: ExecutionTier::Local,
            destination: String::from("local"),
            reversible: true,
        }
    }
}

/// Pre-action state snapshot captured before an effect runs (WS16-01.7).
///
/// Opaque to the Helper: the [`ActionExecutor`] produces it and consumes it on
/// restore, so the Helper never has to understand subsystem-specific state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSnapshot {
    /// The action this snapshot precedes.
    pub action_id: u64,
    /// Opaque, executor-defined serialized prior state.
    pub state: Vec<u8>,
}

/// Capability gate for Helper actions (WS16-01.11).
///
/// The real implementation verifies a [`nexacore_capability::CapabilityToken`]
/// against the action's required scope; the in-memory double allows/denies by
/// rule. Mirrors `nexacore_monitor::actions::ActionCapability`.
pub trait CapabilityGate {
    /// Returns `true` if the holder is authorized to perform `action`.
    fn authorize(&self, action: &SystemAction) -> bool;
}

/// The effect seam: performs (and reverses) a proposed system action
/// (WS16-01.7/.11).
pub trait ActionExecutor {
    /// Capture the pre-action state so the effect can be undone (WS16-01.7).
    fn snapshot(&self, action: &SystemAction) -> StateSnapshot;

    /// Perform the effect, returning a plain-language outcome summary.
    ///
    /// # Errors
    ///
    /// [`HelperError::Executor`] with a human-readable cause; the Helper folds
    /// it into a failed receipt (no panics).
    fn execute(&mut self, action: &SystemAction) -> Result<String, HelperError>;

    /// Reverse a previously executed action from its snapshot (WS16-01.7).
    ///
    /// # Errors
    ///
    /// [`HelperError::Undo`] when the prior state cannot be restored.
    fn restore(&mut self, snapshot: &StateSnapshot) -> Result<(), HelperError>;
}

// =============================================================================
// Proposal (WS16-01.5/.6/.8)
// =============================================================================

/// What the Helper does with a proposal once autonomy is resolved (WS16-01.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelperDisposition {
    /// `Autonomous`: act now, notify after (post-action undo window applies).
    AutoExecute,
    /// `Guided`: present ranked options with a recommendation; user selects.
    AskGuided,
    /// `Inform`: present options without a recommendation; user selects.
    Inform,
}

impl HelperDisposition {
    /// Map a resolved autonomy level to a disposition.
    #[must_use]
    pub const fn from_autonomy(level: AutonomyLevel) -> Self {
        match level {
            AutonomyLevel::Autonomous => Self::AutoExecute,
            AutonomyLevel::Guided => Self::AskGuided,
            AutonomyLevel::Inform => Self::Inform,
        }
    }
}

/// The four mandatory Impact Dashboard axes (WS16-01.6).
///
/// A subset of the seven [`ImpactDimension`]s that NCIP-Helper-007 §4 mandates
/// be shown for *every* proposal.
pub const MANDATORY_AXES: [ImpactDimension; 4] = [
    ImpactDimension::Privacy,
    ImpactDimension::Trust,
    ImpactDimension::Cost,
    ImpactDimension::Time,
];

/// A fully-evaluated Helper proposal: routing, risk, impact, and disposition
/// (WS16-01.3/.5/.6/.8).
#[derive(Clone, Debug)]
pub struct HelperProposal {
    /// The concrete action to perform.
    pub action: SystemAction,
    /// Which agent the five-agent framework routed this to (WS16-01.3).
    pub route: ReasonedRoute,
    /// Mandatory-escalation class, if the action triggers one (WS16-01.8).
    pub escalation_class: Option<EscalationClass>,
    /// Effective autonomy level after the escalation floor + mode clamp (.5).
    pub autonomy: AutonomyLevel,
    /// What the Helper will do with the proposal (WS16-01.5).
    pub disposition: HelperDisposition,
    /// Full seven-dimension Impact Dashboard (WS16-01.6, NCIP-007 §4).
    pub impact: ImpactDashboard,
}

impl HelperProposal {
    /// The four mandatory dashboard axes (Privacy/Trust/Cost/Time), in canonical
    /// order, projected from the full dashboard (WS16-01.6).
    #[must_use]
    pub fn mandatory_axes(&self) -> Vec<ImpactScore> {
        MANDATORY_AXES
            .iter()
            .map(|&dim| ImpactScore::new(dim, self.impact.score_for(dim).unwrap_or(0)))
            .collect()
    }

    /// Render the capability-authorization prompt shown to the user before an
    /// escalating action runs (WS16-01.8).
    ///
    /// The prompt names the action, its mandatory-escalation class, the four
    /// mandatory impact axes, and the autonomy level the user must engage at.
    #[must_use]
    pub fn authorization_prompt(&self) -> String {
        let risk = self.escalation_class.map_or("none", EscalationClass::label);
        let mut prompt = format!(
            "NexaCore Helper requests authorization to:\n  {desc}\nRisk class: {risk}\nImpact:",
            desc = self.action.description,
        );
        for score in self.mandatory_axes() {
            prompt.push_str(&format!(
                "\n  {label}: {score}/100",
                label = score.dimension.label(),
                score = score.score,
            ));
        }
        let ask = match self.disposition {
            HelperDisposition::AutoExecute => "Proceed automatically? (undo available for 30s)",
            HelperDisposition::AskGuided => "Approve this recommended action?",
            HelperDisposition::Inform => "Select an option to proceed.",
        };
        prompt.push_str(&format!("\n{ask}"));
        prompt
    }
}

/// A receipt for an executed Helper action (WS16-01.7/.9/.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperReceipt {
    /// The action that ran.
    pub action_id: u64,
    /// Plain-language outcome summary from the executor.
    pub outcome: String,
    /// Budget units charged for the egress (0 for a `Local` action).
    pub budget_charged: u64,
    /// Whether the action was recorded in the 30s undo window.
    pub undoable: bool,
}

// =============================================================================
// HelperService (WS16-01.2)
// =============================================================================

/// The NexaCore Helper system service (WS16-01.2).
///
/// Always-on once [`start`](Self::start)ed: it watches for needs (WS16-01.4),
/// turns them into fully-evaluated [`HelperProposal`]s (WS16-01.3/.5/.6/.8), and
/// executes approved actions behind a capability gate + privacy budget, with a
/// 30-second undo window (WS16-01.7/.9/.11).
///
/// All NCIP-007 reasoning sub-systems are owned here; the Helper is their
/// system-layer host.
#[derive(Debug)]
pub struct HelperService {
    autonomy: AutonomyManager,
    escalation: EscalationPolicy,
    impact: ImpactAssessor,
    triggers: TriggerEvaluator,
    undo: crate::guidance::undo::UndoWindow,
    audit: AuditLog,
    mode: OperationalMode,
    running: bool,
    next_action_id: u64,
}

impl HelperService {
    /// Create a Helper with the default autonomy level (`Guided`) in Standard mode.
    ///
    /// The service is created *stopped*; call [`start`](Self::start) to bring the
    /// always-on daemon up.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::helper::HelperService;
    ///
    /// let helper = HelperService::new();
    /// assert!(!helper.is_running());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            autonomy: AutonomyManager::default_config(),
            escalation: EscalationPolicy::new(),
            impact: ImpactAssessor::new(),
            triggers: TriggerEvaluator::new(),
            undo: crate::guidance::undo::UndoWindow::new(),
            audit: AuditLog::new(),
            mode: OperationalMode::Standard,
            running: false,
            next_action_id: 1,
        }
    }

    /// Set the global autonomy level (WS16-01.5).
    #[must_use]
    pub fn with_autonomy(mut self, level: AutonomyLevel) -> Self {
        self.autonomy = AutonomyManager::new(AutonomyConfig::new(level));
        self
    }

    /// Set the operational mode (Standard / High-Risk / Emergency Recovery).
    #[must_use]
    pub fn with_mode(mut self, mode: OperationalMode) -> Self {
        self.mode = mode;
        self
    }

    // ── Daemon lifecycle (WS16-01.2) ────────────────────────────────────────

    /// Bring the always-on Helper daemon up.
    #[instrument(skip(self), fields(service = "helper"))]
    pub fn start(&mut self) {
        info!("nexacore helper starting");
        self.running = true;
    }

    /// Take the Helper daemon down.
    #[instrument(skip(self), fields(service = "helper"))]
    pub fn stop(&mut self) {
        info!("nexacore helper stopping");
        self.running = false;
    }

    /// Returns `true` while the daemon is up.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// The current operational mode.
    #[must_use]
    pub const fn mode(&self) -> OperationalMode {
        self.mode
    }

    /// Read-only access to the decision audit log (NCIP-007 §7).
    #[must_use]
    pub const fn audit_log(&self) -> &AuditLog {
        &self.audit
    }

    // ── Need detection (WS16-01.4) ──────────────────────────────────────────

    /// Decide whether a trigger event should surface a Helper proposal
    /// (WS16-01.4).
    ///
    /// Only fires while the daemon is running; otherwise the Helper is silent.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{
    ///     guidance::triggers::{TriggerEvent, TriggerSource},
    ///     helper::HelperService,
    /// };
    ///
    /// let mut helper = HelperService::new();
    /// helper.start();
    /// let need = TriggerEvent::new(TriggerSource::FailureDriven, "disk full", 0);
    /// assert!(helper.detect_need(&need));
    /// ```
    #[must_use]
    pub fn detect_need(&self, event: &TriggerEvent) -> bool {
        self.running && self.triggers.should_fire(event)
    }

    // ── Autonomy resolution (WS16-01.5) ─────────────────────────────────────

    /// Resolve the effective autonomy level for `action` in `context`
    /// (WS16-01.5).
    ///
    /// Combines the per-context autonomy config (clamped by the operational
    /// mode) with the mandatory-escalation floor (NCIP-007 §3): the result is
    /// the *stricter* of the two, so a destructive action can never run more
    /// autonomously than `Guided` even when the user set `Autonomous`.
    #[must_use]
    pub fn resolve_autonomy(&self, action_description: &str, context: &str) -> AutonomyLevel {
        let requested = self.autonomy.resolve_level(context, self.mode);
        self.escalation.apply(action_description, requested)
    }

    // ── Proposal building (WS16-01.3/.5/.6/.8) ──────────────────────────────

    /// Build a fully-evaluated proposal for `intent`/`action` (WS16-01.3/.5/.6/.8).
    ///
    /// Routes the intent through the five-agent reasoning backend (.3), classifies
    /// the mandatory-escalation class (.8), resolves the effective autonomy level
    /// (.5), and assembles the Impact Dashboard (.6). It does **not** execute
    /// anything — [`execute`](Self::execute) is the only effecting path.
    pub fn propose<R: ReasoningBackend>(
        &self,
        reasoner: &R,
        intent: &str,
        action: SystemAction,
        context: &str,
    ) -> HelperProposal {
        let route = reasoner.route(intent, self.mode);
        let escalation_class = self.escalation.classify(&action.description);
        let autonomy = self.resolve_autonomy(&action.description, context);
        let impact = self.impact.assess(&action.description);
        HelperProposal {
            action,
            route,
            escalation_class,
            autonomy,
            disposition: HelperDisposition::from_autonomy(autonomy),
            impact,
        }
    }

    /// Allocate the next stable action id (for callers constructing actions).
    pub fn next_action_id(&mut self) -> u64 {
        let id = self.next_action_id;
        self.next_action_id = self.next_action_id.saturating_add(1);
        id
    }

    // ── Execution (WS16-01.7/.9/.11) ────────────────────────────────────────

    /// Execute a proposal's action behind the capability gate (.11), the privacy
    /// budget (.9), and the 30-second undo window (.7).
    ///
    /// Order is fail-closed and deliberate:
    /// 1. **Capability gate** (.11) — refuse before any other work if unauthorized.
    /// 2. **Privacy budget** (.9) — charge the WS5-07 ledger for the action's
    ///    egress tier; a non-`Local` action that can't be afforded never runs and
    ///    never touches the executor (no partial egress).
    /// 3. **Pre-action snapshot** (.7) — capture reversible state *before* the effect.
    /// 4. **Effect** (.11) — run the executor.
    /// 5. **Undo + audit** — record the snapshot in the 30s window and log the decision.
    ///
    /// `now` is the wall-clock second used for audit/undo timestamps (the kernel
    /// clock at the call site; injected so the logic stays deterministic).
    ///
    /// # Errors
    ///
    /// - [`HelperError::CapabilityDenied`] — the gate refused the action.
    /// - [`HelperError::BudgetExhausted`] — the privacy budget can't cover the egress.
    /// - [`HelperError::Executor`] — the effect itself failed (budget already
    ///   charged is reported; the failure is audited).
    #[allow(clippy::too_many_arguments)]
    pub fn execute<G: CapabilityGate, E: ActionExecutor>(
        &mut self,
        proposal: &HelperProposal,
        gate: &G,
        executor: &mut E,
        ledger: &mut PrivacyLedger,
        holder: &BudgetHolder,
        now: u64,
    ) -> Result<HelperReceipt, HelperError> {
        let action = &proposal.action;

        // 1. Capability gate (WS16-01.11) — fail closed.
        if !gate.authorize(action) {
            self.audit.log_decision(AuditEntry::new(
                AgentKind::Guidance,
                action.description.clone(),
                "denied",
                "capability gate refused the action",
                now,
                self.mode,
            ));
            return Err(HelperError::CapabilityDenied(action.description.clone()));
        }

        // 2. Privacy budget (WS16-01.9) — charge egress before the effect.
        let budget_charged = if action.tier == ExecutionTier::Local {
            0
        } else {
            let event = EgressEvent {
                holder: holder.clone(),
                tier: action.tier,
                destination: action.destination.clone(),
            };
            match ledger.charge_egress(&event) {
                Ok(receipt) => receipt.cost,
                Err(exhausted) => {
                    self.audit.log_decision(AuditEntry::new(
                        AgentKind::Guidance,
                        action.description.clone(),
                        "blocked",
                        "privacy budget exhausted before egress",
                        now,
                        self.mode,
                    ));
                    return Err(HelperError::BudgetExhausted {
                        requested: exhausted.requested,
                        remaining: exhausted.remaining,
                    });
                }
            }
        };

        // 3. Pre-action snapshot (WS16-01.7) — only for reversible actions.
        let snapshot = action.reversible.then(|| executor.snapshot(action));

        // 4. Effect (WS16-01.11).
        let outcome = executor.execute(action).inspect_err(|err| {
            self.audit.log_decision(AuditEntry::new(
                AgentKind::Guidance,
                action.description.clone(),
                "failed",
                err.to_string(),
                now,
                self.mode,
            ));
        })?;

        // 5. Undo window (WS16-01.7) + audit (NCIP-007 §7).
        let undoable = snapshot.is_some();
        if let Some(snapshot) = snapshot {
            self.undo.record_with_snapshot(
                crate::guidance::undo::UndoEntry::new(
                    action.id,
                    action.description.clone(),
                    now,
                    true,
                ),
                snapshot.state,
            );
        }
        self.audit.log_decision(AuditEntry::new(
            AgentKind::Guidance,
            action.description.clone(),
            "executed",
            format!(
                "tier={tier:?} budget_charged={budget_charged}",
                tier = action.tier
            ),
            now,
            self.mode,
        ));

        Ok(HelperReceipt {
            action_id: action.id,
            outcome,
            budget_charged,
            undoable,
        })
    }

    /// Undo the most recent in-window reversible action (WS16-01.7).
    ///
    /// Restores the pre-action snapshot through the executor and returns the
    /// undone entry's description. Returns [`HelperError::NothingToUndo`] when the
    /// 30-second window holds no reversible action.
    ///
    /// # Errors
    ///
    /// - [`HelperError::NothingToUndo`] — no in-window action to reverse.
    /// - [`HelperError::Undo`] — the executor could not restore the prior state.
    pub fn undo_last<E: ActionExecutor>(
        &mut self,
        executor: &mut E,
        now: u64,
    ) -> Result<String, HelperError> {
        let (entry, state) = self
            .undo
            .undo_last_with_snapshot()
            .ok_or(HelperError::NothingToUndo)?;
        let snapshot = StateSnapshot {
            action_id: entry.action_id,
            state,
        };
        executor.restore(&snapshot)?;
        self.audit.log_decision(AuditEntry::new(
            AgentKind::Guidance,
            entry.description.clone(),
            "undone",
            "pre-action snapshot restored within the 30s window",
            now,
            self.mode,
        ));
        Ok(entry.description)
    }

    /// Register the Helper's global hotkey through `registrar` (WS16-01.10).
    ///
    /// # Errors
    ///
    /// Propagates [`HelperError::Hotkey`] from the registrar.
    // `&self` is intentional: the hotkey is the running service's affordance, and
    // a future version may consult instance config (e.g. a user-rebound chord).
    #[allow(clippy::unused_self)]
    pub fn register_hotkey<H: HotkeyRegistrar>(
        &self,
        registrar: &mut H,
    ) -> Result<String, HelperError> {
        registrar.register_global(&HELPER_HOTKEY)
    }
}

impl Default for HelperService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guidance::triggers::{TriggerEvent, TriggerSource};

    // ── Test doubles ────────────────────────────────────────────────────────

    /// Capability gate that allows everything except descriptions on a deny-list.
    struct RuleGate {
        deny_substr: Option<&'static str>,
    }
    impl RuleGate {
        const fn allow_all() -> Self {
            Self { deny_substr: None }
        }
        const fn deny(substr: &'static str) -> Self {
            Self {
                deny_substr: Some(substr),
            }
        }
    }
    impl CapabilityGate for RuleGate {
        fn authorize(&self, action: &SystemAction) -> bool {
            self.deny_substr
                .is_none_or(|s| !action.description.contains(s))
        }
    }

    /// Executor that records executed/restored ids and can be forced to fail.
    #[derive(Default)]
    struct RecordingExecutor {
        executed: Vec<u64>,
        restored: Vec<u64>,
        fail: bool,
    }
    impl ActionExecutor for RecordingExecutor {
        fn snapshot(&self, action: &SystemAction) -> StateSnapshot {
            StateSnapshot {
                action_id: action.id,
                state: action.description.clone().into_bytes(),
            }
        }
        fn execute(&mut self, action: &SystemAction) -> Result<String, HelperError> {
            if self.fail {
                return Err(HelperError::Executor("forced failure".into()));
            }
            self.executed.push(action.id);
            Ok(format!("did: {}", action.description))
        }
        fn restore(&mut self, snapshot: &StateSnapshot) -> Result<(), HelperError> {
            self.restored.push(snapshot.action_id);
            Ok(())
        }
    }

    fn holder() -> BudgetHolder {
        BudgetHolder::new(1, "helper")
    }

    fn ledger() -> PrivacyLedger {
        PrivacyLedger::new(100)
    }

    // ── .2 daemon lifecycle ─────────────────────────────────────────────────

    #[test]
    fn new_service_is_stopped() {
        let helper = HelperService::new();
        assert!(!helper.is_running());
    }

    #[test]
    fn start_stop_toggles_running() {
        let mut helper = HelperService::new();
        helper.start();
        assert!(helper.is_running());
        helper.stop();
        assert!(!helper.is_running());
    }

    // ── .4 need detection ───────────────────────────────────────────────────

    #[test]
    fn detect_need_silent_until_started() {
        let helper = HelperService::new();
        let ev = TriggerEvent::new(TriggerSource::ExplicitInvoke, "help", 0);
        // Even an always-firing explicit invoke is silent while stopped.
        assert!(!helper.detect_need(&ev));
    }

    #[test]
    fn detect_need_fires_when_running() {
        let mut helper = HelperService::new();
        helper.start();
        let ev = TriggerEvent::new(TriggerSource::WatchAlwaysOn, "cpu spike", 0);
        assert!(helper.detect_need(&ev));
        let empty = TriggerEvent::new(TriggerSource::WatchAlwaysOn, "", 0);
        assert!(!helper.detect_need(&empty));
    }

    // ── .3 five-agent reasoning backend ─────────────────────────────────────

    #[test]
    fn reasoner_binds_five_agent_routing() {
        let r = FiveAgentReasoner;
        let route = r.route(
            "explain how disk encryption works",
            OperationalMode::Standard,
        );
        assert_eq!(route.responsible_agent, AgentKind::Guidance);
        let admin = r.route("install the nvidia driver", OperationalMode::Standard);
        assert_eq!(admin.responsible_agent, AgentKind::SysAdmin);
        let sec = r.route("run a security audit", OperationalMode::HighRisk);
        assert_eq!(sec.responsible_agent, AgentKind::Security);
        assert!(sec.requires_preauth, "high-risk routing requires pre-auth");
    }

    // ── .5 autonomy resolution (autonomy ∧ escalation floor) ────────────────

    #[test]
    fn resolve_autonomy_applies_escalation_floor() {
        let helper = HelperService::new().with_autonomy(AutonomyLevel::Autonomous);
        // Benign action keeps the global Autonomous level.
        assert_eq!(
            helper.resolve_autonomy("list files", "fs:list"),
            AutonomyLevel::Autonomous
        );
        // Destructive action is floored to Guided even at Autonomous.
        assert_eq!(
            helper.resolve_autonomy("delete all logs", "fs:delete"),
            AutonomyLevel::Guided
        );
    }

    #[test]
    fn resolve_autonomy_high_risk_clamps_then_floors() {
        let helper = HelperService::new()
            .with_autonomy(AutonomyLevel::Autonomous)
            .with_mode(OperationalMode::HighRisk);
        // High-Risk mode clamps Autonomous → Guided before the (lower) borderline floor.
        assert_eq!(
            helper.resolve_autonomy("disable the firewall", "net:firewall"),
            AutonomyLevel::Guided
        );
    }

    // ── .6 mandatory impact axes ────────────────────────────────────────────

    #[test]
    fn proposal_exposes_four_mandatory_axes() {
        let mut helper = HelperService::new();
        let action = SystemAction::local(helper.next_action_id(), "upload personal data to cloud");
        let proposal = helper.propose(&FiveAgentReasoner, "upload my data", action, "net:upload");
        let axes = proposal.mandatory_axes();
        assert_eq!(axes.len(), 4);
        let dims: Vec<_> = axes.iter().map(|a| a.dimension).collect();
        assert_eq!(dims, MANDATORY_AXES.to_vec());
        // The privacy axis is non-zero for a personal-data upload.
        let privacy = axes
            .iter()
            .find(|a| a.dimension == ImpactDimension::Privacy)
            .map_or(0, |a| a.score);
        assert!(privacy > 0);
    }

    // ── .8 escalation taxonomy + authorization prompt ───────────────────────

    #[test]
    fn authorization_prompt_names_risk_and_axes() {
        let mut helper = HelperService::new().with_autonomy(AutonomyLevel::Autonomous);
        let action = SystemAction::local(helper.next_action_id(), "delete all user files");
        let proposal = helper.propose(&FiveAgentReasoner, "clean up", action, "fs:delete");
        assert_eq!(
            proposal.escalation_class,
            Some(EscalationClass::Destructive)
        );
        assert_eq!(proposal.disposition, HelperDisposition::AskGuided);
        let prompt = proposal.authorization_prompt();
        assert!(prompt.contains("destructive"));
        assert!(prompt.contains("Privacy"));
        assert!(prompt.contains("Trust"));
        assert!(prompt.contains("authorization"));
    }

    // ── .11 capability-gated execution ──────────────────────────────────────

    #[test]
    fn execute_refuses_when_capability_denied() {
        let mut helper = HelperService::new();
        let action = SystemAction::local(helper.next_action_id(), "delete secret keys");
        let proposal = helper.propose(&FiveAgentReasoner, "wipe", action, "fs:delete");
        let gate = RuleGate::deny("delete");
        let mut exec = RecordingExecutor::default();
        let mut led = ledger();
        let err = helper
            .execute(&proposal, &gate, &mut exec, &mut led, &holder(), 100)
            .unwrap_err();
        assert!(matches!(err, HelperError::CapabilityDenied(_)));
        // Fail-closed: the effect was never attempted.
        assert!(exec.executed.is_empty());
    }

    #[test]
    fn execute_runs_local_action_free_and_undoable() {
        let mut helper = HelperService::new();
        let action = SystemAction::local(helper.next_action_id(), "rename config file");
        let proposal = helper.propose(&FiveAgentReasoner, "rename", action, "fs:rename");
        let mut exec = RecordingExecutor::default();
        let mut led = ledger();
        let receipt = helper
            .execute(
                &proposal,
                &RuleGate::allow_all(),
                &mut exec,
                &mut led,
                &holder(),
                100,
            )
            .expect("execute");
        assert_eq!(receipt.budget_charged, 0, "local egress is free");
        assert!(receipt.undoable);
        assert_eq!(exec.executed, vec![receipt.action_id]);
        // Budget untouched for a local action.
        assert_eq!(led.spent(&holder()), 0);
    }

    // ── .9 privacy-budget gate ──────────────────────────────────────────────

    #[test]
    fn execute_charges_budget_for_non_local_tier() {
        let mut helper = HelperService::new();
        let mut action = SystemAction::local(helper.next_action_id(), "summarize doc on cluster");
        action.tier = ExecutionTier::FederatedMesh;
        action.destination = "mesh-node-7".into();
        let proposal = helper.propose(&FiveAgentReasoner, "summarize", action, "ai:summarize");
        let mut exec = RecordingExecutor::default();
        let mut led = ledger();
        let receipt = helper
            .execute(
                &proposal,
                &RuleGate::allow_all(),
                &mut exec,
                &mut led,
                &holder(),
                100,
            )
            .expect("execute");
        // FederatedMesh costs 5 budget units (WS5-07 cost model).
        assert_eq!(receipt.budget_charged, 5);
        assert_eq!(led.spent(&holder()), 5);
    }

    #[test]
    fn execute_fails_closed_when_budget_exhausted() {
        let mut helper = HelperService::new();
        let mut action = SystemAction::local(helper.next_action_id(), "cloud inference call");
        action.tier = ExecutionTier::Cloud; // costs 20
        action.destination = "cloud".into();
        let proposal = helper.propose(&FiveAgentReasoner, "infer", action, "ai:infer");
        let mut exec = RecordingExecutor::default();
        let mut led = PrivacyLedger::new(10); // < 20, can't afford
        let err = helper
            .execute(
                &proposal,
                &RuleGate::allow_all(),
                &mut exec,
                &mut led,
                &holder(),
                100,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            HelperError::BudgetExhausted {
                requested: 20,
                remaining: 10
            }
        ));
        // Fail-closed: no egress effect, no spend.
        assert!(exec.executed.is_empty());
        assert_eq!(led.spent(&holder()), 0);
    }

    // ── .7 undo within the 30s window ───────────────────────────────────────

    #[test]
    fn undo_restores_last_action() {
        let mut helper = HelperService::new();
        let action = SystemAction::local(helper.next_action_id(), "move file a to b");
        let proposal = helper.propose(&FiveAgentReasoner, "move", action, "fs:move");
        let mut exec = RecordingExecutor::default();
        let mut led = ledger();
        let receipt = helper
            .execute(
                &proposal,
                &RuleGate::allow_all(),
                &mut exec,
                &mut led,
                &holder(),
                100,
            )
            .expect("execute");
        let undone = helper.undo_last(&mut exec, 110).expect("undo");
        assert_eq!(undone, "move file a to b");
        assert_eq!(exec.restored, vec![receipt.action_id]);
    }

    #[test]
    fn undo_with_empty_window_errs() {
        let mut helper = HelperService::new();
        let mut exec = RecordingExecutor::default();
        assert_eq!(
            helper.undo_last(&mut exec, 100).unwrap_err(),
            HelperError::NothingToUndo
        );
    }

    // ── audit trail ─────────────────────────────────────────────────────────

    #[test]
    fn execution_is_audited() {
        let mut helper = HelperService::new();
        let action = SystemAction::local(helper.next_action_id(), "open settings");
        let proposal = helper.propose(&FiveAgentReasoner, "open", action, "ui:open");
        let mut exec = RecordingExecutor::default();
        let mut led = ledger();
        assert_eq!(helper.audit_log().entry_count(), 0);
        helper
            .execute(
                &proposal,
                &RuleGate::allow_all(),
                &mut exec,
                &mut led,
                &holder(),
                100,
            )
            .expect("execute");
        assert_eq!(helper.audit_log().entry_count(), 1);
        assert_eq!(helper.audit_log().all_entries()[0].decision, "executed");
    }

    // ── .10 global hotkey ───────────────────────────────────────────────────

    #[test]
    fn hotkey_descriptor_is_platform_aware() {
        assert_eq!(HELPER_HOTKEY.default_for(true), "Meta+Shift+Space");
        assert_eq!(HELPER_HOTKEY.default_for(false), "Ctrl+Shift+Space");
        assert_eq!(HELPER_HOTKEY.action_id, "helper.toggle");
    }

    #[test]
    fn register_hotkey_delegates_to_registrar() {
        struct CaptureRegistrar {
            bound: Option<String>,
        }
        impl HotkeyRegistrar for CaptureRegistrar {
            fn register_global(
                &mut self,
                descriptor: &HotkeyDescriptor,
            ) -> Result<String, HelperError> {
                let chord = descriptor.default_other.to_string();
                self.bound = Some(chord.clone());
                Ok(chord)
            }
        }
        let helper = HelperService::new();
        let mut reg = CaptureRegistrar { bound: None };
        let bound = helper.register_hotkey(&mut reg).expect("register");
        assert_eq!(bound, "Ctrl+Shift+Space");
        assert_eq!(reg.bound.as_deref(), Some("Ctrl+Shift+Space"));
    }
}
