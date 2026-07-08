//! Security & Performance Agent — guardian of the system.
//!
//! Monitors threats, enforces taint tracking, validates capability
//! tokens, gates model outputs, and optimizes performance. In Standard
//! mode acts as advisory consigliere; in High-Risk mode has absolute
//! veto over all actors.
//!
//! See NCIP-Agent-Arch-022 §S6.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use nexacore_types::{AgentId, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::{
    agent::{Agent, AgentKind, AgentState},
    budget::Budget,
    message::{
        AgentMessage, AlertSeverity, HeartbeatPayload, MessageKind, MessagePayload,
        OperationResult, SecurityAlertPayload, VetoDecision, VetoOutcome,
    },
    mode::OperationalMode,
    privacy::{DataSensitivity, PrivacyBudgetAccountant, PrivacyError},
};

// ─────────────────────────────────────────────────────────────────────────────
// Heartbeat monitor (private, internal to SecurityAgent)
// ─────────────────────────────────────────────────────────────────────────────

/// Heartbeat monitoring state for the Orchestrator.
#[derive(Debug)]
struct HeartbeatMonitor {
    last_seen: Option<Instant>,
    #[allow(dead_code)] // used in production heartbeat loop
    interval: Duration,
    timeout: Duration,
    missed_count: u32,
    max_missed: u32,
}

impl HeartbeatMonitor {
    fn new() -> Self {
        Self {
            last_seen: None,
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(15),
            missed_count: 0,
            max_missed: 3,
        }
    }

    fn record_heartbeat(&mut self) {
        self.last_seen = Some(Instant::now());
        self.missed_count = 0;
    }

    fn is_alive(&self) -> bool {
        self.last_seen.is_some_and(|t| t.elapsed() < self.timeout)
    }

    fn record_miss(&mut self) {
        self.missed_count += 1;
    }

    fn should_failover(&self) -> bool {
        self.missed_count >= self.max_missed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk classification
// ─────────────────────────────────────────────────────────────────────────────

/// Risk classification for veto evaluations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskClass {
    /// Action would destroy data or resources.
    Destructive,
    /// Action would violate privacy (PII exposure, telemetry).
    PrivacyViolating,
    /// Action would escalate capabilities beyond scope.
    CapabilityEscalation,
    /// Action is borderline (user-configurable escalation).
    Borderline,
    /// No risk detected.
    Safe,
}

// ─────────────────────────────────────────────────────────────────────────────
// Taint tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Origin of a data taint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintSource {
    /// Data entered directly by the user.
    UserInput,
    /// Data received from a third-party API.
    ExternalApi,
    /// Data produced by an untrusted or unverified model.
    UntrustedModel,
    /// Data read from the local file system.
    FileSystem,
}

/// A single taint label applied to a data entity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaintTag {
    /// Where the tainted data originated.
    pub source: TaintSource,
    /// Semantic class of the entity, e.g. `"email_address"`, `"phone_number"`.
    pub entity_class: String,
    /// Unix timestamp (seconds) at which the taint was applied.
    pub applied_at: u64,
}

/// Result of an egress check against the active taint set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TaintCheckResult {
    /// No active taints match the egress candidate.
    Clean,
    /// One or more taints match; egress should be blocked or sanitized.
    Tainted {
        /// The matching taint tags.
        tags: Vec<TaintTag>,
    },
}

/// Tracks data taints across the agent pipeline.
///
/// Phase 2 implementation uses an in-memory linear list. A Phase 3
/// replacement will use a proper data-flow graph for precise propagation.
#[derive(Debug, Default)]
pub struct TaintTracker {
    active_taints: Vec<TaintTag>,
}

impl TaintTracker {
    /// Create an empty `TaintTracker`.
    ///
    /// # Examples
    /// ```
    /// use nexacore_agent::security::TaintTracker;
    /// let tracker = TaintTracker::new();
    /// assert_eq!(tracker.active_taint_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new taint tag.
    pub fn apply_taint(&mut self, tag: TaintTag) {
        debug!(entity_class = %tag.entity_class, source = ?tag.source, "taint applied");
        self.active_taints.push(tag);
    }

    /// Check whether tainted data would be included in an egress operation.
    ///
    /// The `data_description` is matched against active taint entity classes
    /// using case-insensitive substring search. This is a Phase 2 heuristic;
    /// Phase 3 will use precise data-flow analysis.
    ///
    /// # Examples
    /// ```
    /// use nexacore_agent::security::{TaintCheckResult, TaintSource, TaintTag, TaintTracker};
    /// let mut tracker = TaintTracker::new();
    /// tracker.apply_taint(TaintTag {
    ///     source: TaintSource::UserInput,
    ///     entity_class: "email_address".into(),
    ///     applied_at: 0,
    /// });
    /// assert!(matches!(
    ///     tracker.check_egress("sending email_address to remote server"),
    ///     TaintCheckResult::Tainted { .. }
    /// ));
    /// ```
    #[must_use]
    pub fn check_egress(&self, data_description: &str) -> TaintCheckResult {
        let lower = data_description.to_lowercase();
        let matching: Vec<TaintTag> = self
            .active_taints
            .iter()
            .filter(|t| lower.contains(t.entity_class.to_lowercase().as_str()))
            .cloned()
            .collect();

        if matching.is_empty() {
            TaintCheckResult::Clean
        } else {
            warn!(
                count = matching.len(),
                "tainted data detected in egress candidate"
            );
            TaintCheckResult::Tainted { tags: matching }
        }
    }

    /// Propagate all taints from a source label to a destination label.
    ///
    /// Any taint whose `entity_class` matches `from` (case-insensitive) will
    /// have a copy registered for `to`. This models IPC/pipe propagation at
    /// Phase 2 granularity.
    pub fn propagate(&mut self, from: &str, to: &str) {
        let from_lower = from.to_lowercase();
        // Collect taints from the source label first to avoid borrow conflicts.
        let propagated: Vec<TaintTag> = self
            .active_taints
            .iter()
            .filter(|t| t.entity_class.to_lowercase() == from_lower)
            .map(|t| TaintTag {
                source: t.source.clone(),
                entity_class: to.to_owned(),
                applied_at: t.applied_at,
            })
            .collect();

        if !propagated.is_empty() {
            debug!(from, to, count = propagated.len(), "taint propagated");
        }
        self.active_taints.extend(propagated);
    }

    /// Remove all taints matching `entity_class` (e.g. after tokenization).
    pub fn clear_taint(&mut self, entity_class: &str) {
        let lower = entity_class.to_lowercase();
        let before = self.active_taints.len();
        self.active_taints
            .retain(|t| t.entity_class.to_lowercase() != lower);
        let removed = before - self.active_taints.len();
        if removed > 0 {
            info!(entity_class, removed, "taint cleared");
        }
    }

    /// Returns the number of currently active taint tags.
    #[must_use]
    pub fn active_taint_count(&self) -> usize {
        self.active_taints.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Output gating
// ─────────────────────────────────────────────────────────────────────────────

/// A named filter used by the output gate to block harmful content.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstitutionalFilter {
    /// Human-readable name used in audit records.
    pub name: String,
    /// Keyword or phrase to match (case-insensitive substring).
    ///
    /// Phase 2 uses plain-text matching; Phase 3 will use semantic
    /// similarity via the embedded model.
    pub pattern: String,
    /// Severity of alerts raised when this filter triggers.
    pub severity: AlertSeverity,
}

/// Result of evaluating model output through the output gate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OutputGateResult {
    /// Output passed all filters and blocked patterns.
    Passed,
    /// Output was blocked by a filter.
    Blocked {
        /// The name of the filter that triggered.
        filter_name: String,
        /// Human-readable reason for the block.
        reason: String,
    },
}

/// Guards model outputs by enforcing constitutional filters and blocked
/// keyword patterns before any content is surfaced to the user or
/// forwarded to another agent.
#[derive(Debug, Default)]
pub struct OutputGate {
    blocked_patterns: Vec<String>,
    constitutional_filters: Vec<ConstitutionalFilter>,
}

impl OutputGate {
    /// Create a new `OutputGate` with no filters or blocked patterns.
    ///
    /// # Examples
    /// ```
    /// use nexacore_agent::security::OutputGate;
    /// let gate = OutputGate::new();
    /// assert_eq!(gate.filter_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate `output` against all registered filters and blocked patterns.
    ///
    /// Returns [`OutputGateResult::Blocked`] on the first match, preserving
    /// fail-safe ordering (most restrictive check wins). Returns
    /// [`OutputGateResult::Passed`] only when all checks clear.
    ///
    /// # Examples
    /// ```
    /// use nexacore_agent::security::{OutputGate, OutputGateResult};
    /// let mut gate = OutputGate::new();
    /// gate.add_blocked_pattern("HARM");
    /// assert!(matches!(
    ///     gate.evaluate_output("this output contains HARM"),
    ///     OutputGateResult::Blocked { .. }
    /// ));
    /// ```
    #[must_use]
    pub fn evaluate_output(&self, output: &str) -> OutputGateResult {
        let lower = output.to_lowercase();

        // Check hard-blocked patterns first (fastest path).
        for pattern in &self.blocked_patterns {
            if lower.contains(pattern.to_lowercase().as_str()) {
                warn!(pattern, "output blocked by keyword pattern");
                return OutputGateResult::Blocked {
                    filter_name: "blocked-pattern".into(),
                    reason: format!("output contains blocked pattern: {pattern}"),
                };
            }
        }

        // Check constitutional filters.
        for filter in &self.constitutional_filters {
            if lower.contains(filter.pattern.to_lowercase().as_str()) {
                warn!(filter_name = %filter.name, "output blocked by constitutional filter");
                return OutputGateResult::Blocked {
                    filter_name: filter.name.clone(),
                    reason: format!(
                        "constitutional filter '{}' matched pattern '{}'",
                        filter.name, filter.pattern
                    ),
                };
            }
        }

        OutputGateResult::Passed
    }

    /// Add a constitutional filter to the gate.
    pub fn add_filter(&mut self, filter: ConstitutionalFilter) {
        info!(name = %filter.name, "constitutional filter registered");
        self.constitutional_filters.push(filter);
    }

    /// Add a raw blocked-keyword pattern to the gate.
    ///
    /// Matching is case-insensitive substring search against the output text.
    pub fn add_blocked_pattern(&mut self, pattern: impl Into<String>) {
        self.blocked_patterns.push(pattern.into());
    }

    /// Returns the total number of constitutional filters registered.
    #[must_use]
    pub fn filter_count(&self) -> usize {
        self.constitutional_filters.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Veto context
// ─────────────────────────────────────────────────────────────────────────────

/// All context required to perform a full security veto evaluation.
///
/// Passed by reference to [`SecurityAgent::veto_with_context`] so that
/// callers can assemble context without cloning the underlying trackers.
pub struct VetoContext<'a> {
    /// Current taint tracker state.
    pub taint_state: &'a TaintTracker,
    /// Current output gate state.
    pub output_gate: &'a OutputGate,
    /// The agent that sourced the action being evaluated.
    pub agent_source: AgentKind,
}

// ─────────────────────────────────────────────────────────────────────────────
// Performance baseline tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks inference latency and resource utilisation to detect anomalies.
///
/// Uses a rolling window of past latency samples. When the most recent
/// sample deviates more than `anomaly_threshold` standard deviations from
/// the window mean, `is_anomalous` returns `true` and `generate_alert`
/// produces a [`SecurityAlertPayload`].
#[derive(Debug)]
pub struct PerformanceBaseline {
    /// Rolling window of inference latency samples (milliseconds).
    inference_latency_ms: Vec<u64>,
    /// Most recently recorded memory pressure (0–100 %).
    memory_pressure_percent: u8,
    /// Most recently recorded CPU utilisation (0–100 %).
    cpu_utilization_percent: u8,
    /// Number of standard deviations beyond which a sample is anomalous.
    anomaly_threshold: f64,
    /// Maximum number of samples kept in the rolling window.
    window_size: usize,
}

impl PerformanceBaseline {
    /// Create a new baseline tracker.
    ///
    /// `window_size` is the maximum number of latency samples retained.
    /// `anomaly_threshold` is the number of standard deviations that define
    /// an anomaly (e.g. `2.0` for 2σ, `3.0` for 3σ).
    ///
    /// # Examples
    /// ```
    /// use nexacore_agent::security::PerformanceBaseline;
    /// let baseline = PerformanceBaseline::new(50, 2.0);
    /// assert_eq!(baseline.average_latency(), None);
    /// ```
    #[must_use]
    pub fn new(window_size: usize, anomaly_threshold: f64) -> Self {
        Self {
            inference_latency_ms: Vec::with_capacity(window_size.max(1)),
            memory_pressure_percent: 0,
            cpu_utilization_percent: 0,
            anomaly_threshold,
            window_size: window_size.max(1),
        }
    }

    /// Record an inference latency sample (milliseconds).
    ///
    /// If the window is full, the oldest sample is evicted (FIFO).
    pub fn record_inference_latency(&mut self, ms: u64) {
        if self.inference_latency_ms.len() >= self.window_size {
            self.inference_latency_ms.remove(0);
        }
        self.inference_latency_ms.push(ms);
        debug!(latency_ms = ms, "inference latency recorded");
    }

    /// Record the latest resource usage snapshot.
    pub fn record_resource_usage(&mut self, memory_pct: u8, cpu_pct: u8) {
        self.memory_pressure_percent = memory_pct;
        self.cpu_utilization_percent = cpu_pct;
        debug!(memory_pct, cpu_pct, "resource usage snapshot recorded");
    }

    /// Returns the average latency over the current window, or `None` if
    /// no samples have been recorded yet.
    ///
    /// # Examples
    /// ```
    /// use nexacore_agent::security::PerformanceBaseline;
    /// let mut b = PerformanceBaseline::new(10, 2.0);
    /// b.record_inference_latency(100);
    /// b.record_inference_latency(200);
    /// assert_eq!(b.average_latency(), Some(150));
    /// ```
    #[must_use]
    #[allow(clippy::integer_division)] // intentional: approximate average suffices for monitoring
    pub fn average_latency(&self) -> Option<u64> {
        if self.inference_latency_ms.is_empty() {
            return None;
        }
        let sum: u64 = self.inference_latency_ms.iter().sum();
        // Integer division is intentional; callers only need an approximate average.
        Some(sum / self.inference_latency_ms.len() as u64)
    }

    /// Returns `true` if the most recent latency sample deviates by more than
    /// `anomaly_threshold` standard deviations from the window mean.
    ///
    /// Returns `false` when fewer than two samples are present (no meaningful
    /// baseline exists yet).
    ///
    /// # Panics
    ///
    /// This function cannot panic in practice: the guard `n < 2` ensures
    /// both `last()` and `average_latency()` return `Some` before they are
    /// used. The `unwrap_or` fallbacks are present for type-system
    /// completeness only.
    #[must_use]
    #[allow(clippy::float_arithmetic)]
    #[allow(clippy::cast_precision_loss)] // monitoring heuristic; f64 precision is sufficient
    pub fn is_anomalous(&self) -> bool {
        let n = self.inference_latency_ms.len();
        if n < 2 {
            return false;
        }

        // Both unwrap_or branches are unreachable: length >= 2 guarantees Some.
        let last = *self.inference_latency_ms.last().unwrap_or(&0);
        let mean = self.average_latency().unwrap_or(0) as f64;

        // Population standard deviation over the window.
        let variance: f64 = self
            .inference_latency_ms
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n as f64;

        let stddev = variance.sqrt();

        // Avoid division by zero when all samples are identical.
        if stddev < f64::EPSILON {
            return false;
        }

        let z = (last as f64 - mean).abs() / stddev;
        z > self.anomaly_threshold
    }

    /// Produce a security alert if current metrics are anomalous.
    ///
    /// Returns `None` when within normal operating parameters.
    #[must_use]
    pub fn generate_alert(&self) -> Option<SecurityAlertPayload> {
        if !self.is_anomalous() {
            return None;
        }

        let avg = self.average_latency().unwrap_or(0);
        let last = self.inference_latency_ms.last().copied().unwrap_or(0);

        Some(SecurityAlertPayload {
            severity: AlertSeverity::Warning,
            description: format!(
                "Inference latency anomaly detected: last={last}ms, avg={avg}ms, \
                 memory={}%, cpu={}%",
                self.memory_pressure_percent, self.cpu_utilization_percent
            ),
            recommendation: "Investigate inference backend load or memory pressure".into(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecurityAgent
// ─────────────────────────────────────────────────────────────────────────────

/// The Security & Performance Agent.
///
/// In Standard mode: monitors and advises. In High-Risk mode: monitors,
/// advises, AND vetoes. The only agent that may act without Orchestrator
/// dispatch (for continuous monitoring and alerts).
#[derive(Debug)]
pub struct SecurityAgent {
    id: AgentId,
    state: AgentState,
    #[allow(dead_code)] // enforced in a later sprint
    budget: Budget,
    orchestrator_monitor: HeartbeatMonitor,
    is_degraded_coordinator: bool,
    restart_attempts: u32,
    /// Active taint tracker for incoming data flows.
    pub taint_tracker: TaintTracker,
    /// Output gate for constitutional filtering.
    pub output_gate: OutputGate,
    /// Performance baseline for anomaly detection.
    pub performance_baseline: PerformanceBaseline,
}

/// Maximum Orchestrator restart attempts before entering safe mode.
const MAX_RESTART_ATTEMPTS: u32 = 3;

/// Default rolling window size for the performance baseline.
const DEFAULT_BASELINE_WINDOW: usize = 100;

/// Default anomaly detection threshold (2 standard deviations).
const DEFAULT_ANOMALY_THRESHOLD: f64 = 2.0;

impl SecurityAgent {
    /// Create a new Security agent.
    #[must_use]
    pub fn new(id: AgentId) -> Self {
        Self {
            id,
            state: AgentState::Initializing,
            budget: Budget::security_default(),
            orchestrator_monitor: HeartbeatMonitor::new(),
            is_degraded_coordinator: false,
            restart_attempts: 0,
            taint_tracker: TaintTracker::new(),
            output_gate: OutputGate::new(),
            performance_baseline: PerformanceBaseline::new(
                DEFAULT_BASELINE_WINDOW,
                DEFAULT_ANOMALY_THRESHOLD,
            ),
        }
    }

    /// Evaluate an action for risk and produce a veto decision.
    ///
    /// In Standard mode, always returns `Approved` (advisory only).
    /// In High-Risk mode, evaluates the action against the risk
    /// taxonomy and may veto.
    #[must_use]
    pub fn evaluate_action(&self, description: &str, mode: OperationalMode) -> VetoDecision {
        let risk = self.classify_risk(description);

        let outcome = match mode {
            OperationalMode::Standard | OperationalMode::EmergencyRecovery => VetoOutcome::Approved,
            OperationalMode::HighRisk => match risk {
                RiskClass::Safe | RiskClass::Borderline => VetoOutcome::Approved,
                _ => VetoOutcome::Vetoed {
                    risk_class: format!("{risk:?}"),
                    policy_violated: self.policy_for_risk(&risk),
                    alternatives: self.alternatives_for_risk(&risk),
                },
            },
        };

        VetoDecision {
            request_id: 0,
            outcome,
        }
    }

    /// Perform a full contextual veto evaluation combining risk classification,
    /// taint propagation, output gating, and source-agent capability checks.
    ///
    /// This is the production High-Risk path. `evaluate_action` remains for
    /// simpler call sites that do not yet have full context assembled.
    ///
    /// Veto order (fail-fast):
    /// 1. Risk classification (keyword heuristic).
    /// 2. Taint egress check (if the action description mentions tainted data).
    /// 3. Output gate check (if the action produces output).
    /// 4. Source-agent capability cross-check (logged; enforcement at dispatcher).
    #[must_use]
    pub fn veto_with_context(
        &self,
        action: &str,
        mode: OperationalMode,
        context: &VetoContext<'_>,
    ) -> VetoDecision {
        // In non-vetoing modes, skip all checks.
        if mode != OperationalMode::HighRisk {
            return VetoDecision {
                request_id: 0,
                outcome: VetoOutcome::Approved,
            };
        }

        // 1. Risk classification.
        let risk = self.classify_risk(action);
        match risk {
            RiskClass::Destructive
            | RiskClass::PrivacyViolating
            | RiskClass::CapabilityEscalation => {
                return VetoDecision {
                    request_id: 0,
                    outcome: VetoOutcome::Vetoed {
                        risk_class: format!("{risk:?}"),
                        policy_violated: self.policy_for_risk(&risk),
                        alternatives: self.alternatives_for_risk(&risk),
                    },
                };
            }
            _ => {}
        }

        // 2. Taint egress check.
        if let TaintCheckResult::Tainted { tags } = context.taint_state.check_egress(action) {
            let classes: Vec<String> = tags.iter().map(|t| t.entity_class.clone()).collect();
            return VetoDecision {
                request_id: 0,
                outcome: VetoOutcome::Vetoed {
                    risk_class: "PrivacyViolating".into(),
                    policy_violated: "no-pii-egress".into(),
                    alternatives: vec![
                        format!(
                            "tokenize tainted entities ({}) before sending",
                            classes.join(", ")
                        ),
                        "use local-only processing".into(),
                    ],
                },
            };
        }

        // 3. Output gate check.
        if let OutputGateResult::Blocked {
            filter_name,
            reason,
        } = context.output_gate.evaluate_output(action)
        {
            return VetoDecision {
                request_id: 0,
                outcome: VetoOutcome::Vetoed {
                    risk_class: "ConstitutionalViolation".into(),
                    policy_violated: filter_name,
                    alternatives: vec![reason],
                },
            };
        }

        // 4. Source-agent capability cross-check.
        // Enforcement is the dispatcher's responsibility; here we log only.
        if context.agent_source == AgentKind::Security {
            debug!("veto_with_context: source is Security agent, all checks passed");
        }

        VetoDecision {
            request_id: 0,
            outcome: VetoOutcome::Approved,
        }
    }

    /// Check whether a proposed operation is permitted given the current
    /// privacy budget.
    ///
    /// This is a **pure pre-flight check** — it does NOT consume any budget.
    /// Call [`crate::privacy::PrivacyBudgetAccountant::consume`] after the
    /// check passes to actually deduct the cost.
    ///
    /// Integrates with [`RiskClass::PrivacyViolating`]: if the accountant
    /// would deny the operation, callers should treat this as a
    /// `PrivacyViolating` risk and apply their veto policy accordingly.
    ///
    /// # Errors
    ///
    /// Propagates [`PrivacyError`] from the accountant without modification:
    ///
    /// - [`PrivacyError::AgentNotFound`] — no allocation for `agent_id`.
    /// - [`PrivacyError::BudgetExhausted`] — system budget is exhausted.
    /// - [`PrivacyError::AgentBudgetExhausted`] — agent's allocation is
    ///   exhausted.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{
    ///     privacy::{DataSensitivity, PrivacyBudgetAccountant},
    ///     security::SecurityAgent,
    /// };
    ///
    /// let mut accountant = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
    /// accountant.allocate_agent("task-agent", 5.0).unwrap();
    ///
    /// // Pre-flight check passes — budget is available.
    /// assert!(
    ///     SecurityAgent::check_privacy_budget(&accountant, "task-agent", DataSensitivity::Personal,)
    ///         .is_ok()
    /// );
    /// ```
    #[allow(
        clippy::cognitive_complexity,
        reason = "privacy-budget gate: branches enumerate the budget decision states"
    )]
    pub fn check_privacy_budget(
        accountant: &PrivacyBudgetAccountant,
        agent_id: &str,
        sensitivity: DataSensitivity,
    ) -> core::result::Result<(), PrivacyError> {
        let cost = PrivacyBudgetAccountant::sensitivity_cost(sensitivity);

        // Public data never costs anything; always permit.
        if cost == 0.0 {
            debug!(agent_id, "privacy check: public data, no cost");
            return Ok(());
        }

        // Verify the agent has a registered allocation.
        let agent_remaining = accountant
            .remaining_agent(agent_id)
            .map_err(|_| PrivacyError::AgentNotFound(agent_id.to_owned()))?;

        // Check system-wide remaining.
        let sys_remaining = accountant.remaining_system();
        #[allow(clippy::float_arithmetic)]
        if cost > sys_remaining + f64::EPSILON {
            warn!(
                agent_id,
                cost, sys_remaining, "privacy pre-flight: system budget would be exceeded"
            );
            return Err(PrivacyError::BudgetExhausted {
                requested: cost,
                remaining: sys_remaining,
            });
        }

        // Check per-agent remaining.
        #[allow(clippy::float_arithmetic)]
        if cost > agent_remaining + f64::EPSILON {
            warn!(
                agent_id,
                cost, agent_remaining, "privacy pre-flight: agent budget would be exceeded"
            );
            return Err(PrivacyError::AgentBudgetExhausted {
                agent_id: agent_id.to_owned(),
                requested: cost,
                remaining: agent_remaining,
            });
        }

        debug!(
            agent_id,
            cost, agent_remaining, sys_remaining, "privacy pre-flight: budget available"
        );
        Ok(())
    }

    /// Classify the risk level of an action description.
    ///
    /// Phase 2 stub: uses keyword heuristics. A future phase will use
    /// the taint tracker and capability validator for precise
    /// classification.
    #[must_use]
    #[allow(clippy::unused_self)] // will use self for stateful threat context
    pub fn classify_risk(&self, description: &str) -> RiskClass {
        let lower = description.to_lowercase();

        if lower.contains("delete")
            || lower.contains("format")
            || lower.contains("wipe")
            || lower.contains("rm -rf")
            || lower.contains("cancella")
            || lower.contains("elimina")
        {
            return RiskClass::Destructive;
        }

        if lower.contains("send pii")
            || lower.contains("telemetry")
            || lower.contains("upload personal")
            || lower.contains("dati personali")
        {
            return RiskClass::PrivacyViolating;
        }

        if lower.contains("escalate")
            || lower.contains("root")
            || lower.contains("sudo")
            || lower.contains("system-trust")
        {
            return RiskClass::CapabilityEscalation;
        }

        if lower.contains("unsigned")
            || lower.contains("unknown source")
            || lower.contains("non-whitelisted")
        {
            return RiskClass::Borderline;
        }

        RiskClass::Safe
    }

    /// Returns `true` if the Security Agent is acting as degraded
    /// coordinator (Orchestrator failure, NCIP-022 §S2.4).
    #[must_use]
    pub fn is_degraded_coordinator(&self) -> bool {
        self.is_degraded_coordinator
    }

    /// Process an Orchestrator heartbeat.
    pub fn process_heartbeat(&mut self) {
        self.orchestrator_monitor.record_heartbeat();
        if self.is_degraded_coordinator {
            info!("orchestrator recovered, exiting degraded coordinator mode");
            self.is_degraded_coordinator = false;
            self.restart_attempts = 0;
        }
    }

    /// Check if the Orchestrator is alive and handle failure.
    ///
    /// Returns `Some(alert)` if the Orchestrator has failed.
    pub fn check_orchestrator_health(&mut self) -> Option<SecurityAlertPayload> {
        if self.orchestrator_monitor.is_alive() {
            return None;
        }

        self.orchestrator_monitor.record_miss();

        if self.orchestrator_monitor.should_failover() {
            self.restart_attempts += 1;

            if self.restart_attempts > MAX_RESTART_ATTEMPTS {
                warn!("orchestrator restart attempts exhausted, entering safe mode");
                return Some(SecurityAlertPayload {
                    severity: AlertSeverity::Critical,
                    description: "Orchestrator unresponsive after 3 restart attempts".into(),
                    recommendation: "System entering safe mode".into(),
                });
            }

            if !self.is_degraded_coordinator {
                info!("assuming degraded coordinator role");
                self.is_degraded_coordinator = true;
            }

            Some(SecurityAlertPayload {
                severity: AlertSeverity::Warning,
                description: format!(
                    "Orchestrator heartbeat missed (attempt {}/{})",
                    self.restart_attempts, MAX_RESTART_ATTEMPTS
                ),
                recommendation: "Attempting Orchestrator restart".into(),
            })
        } else {
            None
        }
    }

    #[allow(clippy::unused_self)] // will use self for configurable policies
    fn policy_for_risk(&self, risk: &RiskClass) -> String {
        match risk {
            RiskClass::Destructive => "no-destructive-without-backup".into(),
            RiskClass::PrivacyViolating => "no-pii-egress".into(),
            RiskClass::CapabilityEscalation => "least-privilege".into(),
            RiskClass::Borderline => "user-configurable-borderline".into(),
            RiskClass::Safe => "none".into(),
        }
    }

    #[allow(clippy::unused_self)] // will use self for context-aware alternatives
    fn alternatives_for_risk(&self, risk: &RiskClass) -> Vec<String> {
        match risk {
            RiskClass::Destructive => vec![
                "create a backup before proceeding".into(),
                "use a non-destructive alternative".into(),
            ],
            RiskClass::PrivacyViolating => vec![
                "tokenize PII before sending".into(),
                "use local-only processing".into(),
            ],
            RiskClass::CapabilityEscalation => vec![
                "use a scoped capability token".into(),
                "request minimal privileges".into(),
            ],
            RiskClass::Borderline | RiskClass::Safe => vec![],
        }
    }
}

#[async_trait]
impl Agent for SecurityAgent {
    fn kind(&self) -> AgentKind {
        AgentKind::Security
    }

    fn id(&self) -> AgentId {
        self.id
    }

    fn state(&self) -> AgentState {
        self.state
    }

    #[instrument(skip(self), fields(agent = "secp"))]
    async fn spawn(&mut self) -> Result<()> {
        info!("security agent spawning");
        self.state = AgentState::Running;
        Ok(())
    }

    #[instrument(skip(self, message), fields(agent = "secp", msg_kind = ?message.kind))]
    async fn handle_message(&mut self, message: AgentMessage) -> Result<AgentMessage> {
        debug!(from = ?message.from, "processing message");

        let response_payload = match &message.payload {
            MessagePayload::Intent(intent) => {
                // Run taint check on incoming intent before evaluating.
                // A tainted intent in High-Risk mode triggers an immediate veto.
                let taint_result = self.taint_tracker.check_egress(&intent.content);
                let decision = if message.mode == OperationalMode::HighRisk {
                    if let TaintCheckResult::Tainted { tags } = taint_result {
                        let classes: Vec<String> =
                            tags.iter().map(|t| t.entity_class.clone()).collect();
                        VetoDecision {
                            request_id: intent.request_id,
                            outcome: VetoOutcome::Vetoed {
                                risk_class: "PrivacyViolating".into(),
                                policy_violated: "no-pii-egress".into(),
                                alternatives: vec![format!(
                                    "tokenize tainted entities ({}) before sending",
                                    classes.join(", ")
                                )],
                            },
                        }
                    } else {
                        let base = self.evaluate_action(&intent.content, message.mode);
                        VetoDecision {
                            request_id: intent.request_id,
                            outcome: base.outcome,
                        }
                    }
                } else {
                    let base = self.evaluate_action(&intent.content, message.mode);
                    VetoDecision {
                        request_id: intent.request_id,
                        outcome: base.outcome,
                    }
                };
                MessagePayload::VetoDecision(decision)
            }
            MessagePayload::Heartbeat(hb) => {
                if !hb.is_response {
                    self.process_heartbeat();
                }
                MessagePayload::Heartbeat(HeartbeatPayload {
                    sequence: hb.sequence,
                    is_response: true,
                })
            }
            _ => MessagePayload::OperationResult(OperationResult {
                request_id: 0,
                success: true,
                summary: "acknowledged".into(),
            }),
        };

        Ok(AgentMessage {
            id: message.id,
            from: self.id,
            to: message.from,
            timestamp: message.timestamp,
            kind: match &response_payload {
                MessagePayload::VetoDecision(_) => MessageKind::VetoResponse,
                MessagePayload::Heartbeat(_) => MessageKind::Heartbeat,
                _ => MessageKind::Result,
            },
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
        info!("security agent shutting down");
        self.state = AgentState::Shutdown;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent_id() -> AgentId {
        AgentId::from_bytes([0x04; 16])
    }

    // ── Existing tests (preserved verbatim) ──────────────────────────────────

    #[test]
    fn classify_destructive() {
        let agent = SecurityAgent::new(test_agent_id());
        assert_eq!(
            agent.classify_risk("delete all user files"),
            RiskClass::Destructive
        );
    }

    #[test]
    fn classify_privacy_violating() {
        let agent = SecurityAgent::new(test_agent_id());
        assert_eq!(
            agent.classify_risk("send PII to cloud"),
            RiskClass::PrivacyViolating
        );
    }

    #[test]
    fn classify_capability_escalation() {
        let agent = SecurityAgent::new(test_agent_id());
        assert_eq!(
            agent.classify_risk("escalate to root privileges"),
            RiskClass::CapabilityEscalation
        );
    }

    #[test]
    fn classify_borderline() {
        let agent = SecurityAgent::new(test_agent_id());
        assert_eq!(
            agent.classify_risk("install unsigned package"),
            RiskClass::Borderline
        );
    }

    #[test]
    fn classify_safe() {
        let agent = SecurityAgent::new(test_agent_id());
        assert_eq!(
            agent.classify_risk("list installed packages"),
            RiskClass::Safe
        );
    }

    #[test]
    fn evaluate_standard_mode_always_approves() {
        let agent = SecurityAgent::new(test_agent_id());
        let decision = agent.evaluate_action("delete everything", OperationalMode::Standard);
        assert!(matches!(decision.outcome, VetoOutcome::Approved));
    }

    #[test]
    fn evaluate_high_risk_vetoes_destructive() {
        let agent = SecurityAgent::new(test_agent_id());
        let decision = agent.evaluate_action("delete all files", OperationalMode::HighRisk);
        assert!(matches!(decision.outcome, VetoOutcome::Vetoed { .. }));
    }

    #[test]
    fn evaluate_high_risk_approves_safe() {
        let agent = SecurityAgent::new(test_agent_id());
        let decision = agent.evaluate_action("list files", OperationalMode::HighRisk);
        assert!(matches!(decision.outcome, VetoOutcome::Approved));
    }

    #[test]
    fn evaluate_emergency_recovery_approves() {
        let agent = SecurityAgent::new(test_agent_id());
        let decision =
            agent.evaluate_action("delete everything", OperationalMode::EmergencyRecovery);
        assert!(matches!(decision.outcome, VetoOutcome::Approved));
    }

    #[test]
    fn veto_includes_alternatives() {
        let agent = SecurityAgent::new(test_agent_id());
        let decision = agent.evaluate_action("delete database", OperationalMode::HighRisk);
        if let VetoOutcome::Vetoed { alternatives, .. } = &decision.outcome {
            assert!(!alternatives.is_empty());
        } else {
            panic!("expected Vetoed");
        }
    }

    #[test]
    fn heartbeat_monitor_initially_not_alive() {
        let agent = SecurityAgent::new(test_agent_id());
        assert!(!agent.orchestrator_monitor.is_alive());
    }

    #[test]
    fn heartbeat_monitor_alive_after_heartbeat() {
        let mut agent = SecurityAgent::new(test_agent_id());
        agent.process_heartbeat();
        assert!(agent.orchestrator_monitor.is_alive());
    }

    #[test]
    fn degraded_coordinator_after_failures() {
        let mut agent = SecurityAgent::new(test_agent_id());
        agent.process_heartbeat(); // mark alive first
        // Simulate three missed heartbeats
        for _ in 0..3 {
            agent.orchestrator_monitor.record_miss();
        }
        assert!(agent.orchestrator_monitor.should_failover());
    }

    #[test]
    fn not_degraded_coordinator_initially() {
        let agent = SecurityAgent::new(test_agent_id());
        assert!(!agent.is_degraded_coordinator());
    }

    #[tokio::test]
    async fn spawn_and_shutdown() {
        let mut agent = SecurityAgent::new(test_agent_id());
        agent.spawn().await.unwrap();
        assert_eq!(agent.state(), AgentState::Running);
        agent.shutdown().await.unwrap();
        assert_eq!(agent.state(), AgentState::Shutdown);
    }

    #[test]
    fn agent_kind_is_security() {
        let agent = SecurityAgent::new(test_agent_id());
        assert_eq!(agent.kind(), AgentKind::Security);
    }

    // ── TaintTracker tests ───────────────────────────────────────────────────

    #[test]
    fn taint_tracker_empty_initially() {
        let tracker = TaintTracker::new();
        assert_eq!(tracker.active_taint_count(), 0);
    }

    #[test]
    fn taint_tracker_apply_increments_count() {
        let mut tracker = TaintTracker::new();
        tracker.apply_taint(TaintTag {
            source: TaintSource::UserInput,
            entity_class: "email_address".into(),
            applied_at: 1_000,
        });
        assert_eq!(tracker.active_taint_count(), 1);
    }

    #[test]
    fn taint_tracker_clean_when_no_match() {
        let mut tracker = TaintTracker::new();
        tracker.apply_taint(TaintTag {
            source: TaintSource::UserInput,
            entity_class: "phone_number".into(),
            applied_at: 0,
        });
        assert!(matches!(
            tracker.check_egress("send a harmless greeting"),
            TaintCheckResult::Clean
        ));
    }

    #[test]
    fn taint_tracker_detects_egress_match() {
        let mut tracker = TaintTracker::new();
        tracker.apply_taint(TaintTag {
            source: TaintSource::ExternalApi,
            entity_class: "email_address".into(),
            applied_at: 42,
        });
        assert!(matches!(
            tracker.check_egress("upload email_address to remote"),
            TaintCheckResult::Tainted { .. }
        ));
    }

    #[test]
    fn taint_tracker_clear_removes_matching() {
        let mut tracker = TaintTracker::new();
        tracker.apply_taint(TaintTag {
            source: TaintSource::FileSystem,
            entity_class: "ssn".into(),
            applied_at: 0,
        });
        tracker.apply_taint(TaintTag {
            source: TaintSource::UserInput,
            entity_class: "email_address".into(),
            applied_at: 0,
        });
        tracker.clear_taint("ssn");
        assert_eq!(tracker.active_taint_count(), 1);
        assert!(matches!(
            tracker.check_egress("ssn"),
            TaintCheckResult::Clean
        ));
    }

    #[test]
    fn taint_tracker_propagate_creates_new_entry() {
        let mut tracker = TaintTracker::new();
        tracker.apply_taint(TaintTag {
            source: TaintSource::UntrustedModel,
            entity_class: "raw_input".into(),
            applied_at: 0,
        });
        tracker.propagate("raw_input", "processed_output");
        // Original + propagated
        assert_eq!(tracker.active_taint_count(), 2);
        assert!(matches!(
            tracker.check_egress("processed_output"),
            TaintCheckResult::Tainted { .. }
        ));
    }

    #[test]
    fn taint_tracker_propagate_no_source_is_noop() {
        let mut tracker = TaintTracker::new();
        tracker.propagate("nonexistent", "dest");
        assert_eq!(tracker.active_taint_count(), 0);
    }

    // ── OutputGate tests ─────────────────────────────────────────────────────

    #[test]
    fn output_gate_passes_clean_output() {
        let gate = OutputGate::new();
        assert!(matches!(
            gate.evaluate_output("Here is a harmless response."),
            OutputGateResult::Passed
        ));
    }

    #[test]
    fn output_gate_blocks_on_keyword_pattern() {
        let mut gate = OutputGate::new();
        gate.add_blocked_pattern("HARM");
        assert!(matches!(
            gate.evaluate_output("This output contains HARM content."),
            OutputGateResult::Blocked { .. }
        ));
    }

    #[test]
    fn output_gate_filter_count_increments() {
        let mut gate = OutputGate::new();
        assert_eq!(gate.filter_count(), 0);
        gate.add_filter(ConstitutionalFilter {
            name: "no-violence".into(),
            pattern: "violence".into(),
            severity: AlertSeverity::Warning,
        });
        assert_eq!(gate.filter_count(), 1);
    }

    #[test]
    fn output_gate_constitutional_filter_triggers() {
        let mut gate = OutputGate::new();
        gate.add_filter(ConstitutionalFilter {
            name: "no-hate-speech".into(),
            pattern: "hate speech".into(),
            severity: AlertSeverity::Critical,
        });
        let result = gate.evaluate_output("This contains hate speech.");
        if let OutputGateResult::Blocked { filter_name, .. } = result {
            assert_eq!(filter_name, "no-hate-speech");
        } else {
            panic!("expected Blocked");
        }
    }

    #[test]
    fn output_gate_case_insensitive_match() {
        let mut gate = OutputGate::new();
        gate.add_blocked_pattern("forbidden");
        assert!(matches!(
            gate.evaluate_output("This is FORBIDDEN content."),
            OutputGateResult::Blocked { .. }
        ));
    }

    // ── veto_with_context tests ──────────────────────────────────────────────

    #[test]
    fn veto_with_context_approves_in_standard_mode() {
        let agent = SecurityAgent::new(test_agent_id());
        let tracker = TaintTracker::new();
        let gate = OutputGate::new();
        let ctx = VetoContext {
            taint_state: &tracker,
            output_gate: &gate,
            agent_source: AgentKind::Task,
        };
        let decision =
            agent.veto_with_context("delete everything", OperationalMode::Standard, &ctx);
        assert!(matches!(decision.outcome, VetoOutcome::Approved));
    }

    #[test]
    fn veto_with_context_vetoes_destructive_in_high_risk() {
        let agent = SecurityAgent::new(test_agent_id());
        let tracker = TaintTracker::new();
        let gate = OutputGate::new();
        let ctx = VetoContext {
            taint_state: &tracker,
            output_gate: &gate,
            agent_source: AgentKind::SysAdmin,
        };
        let decision =
            agent.veto_with_context("delete all user data", OperationalMode::HighRisk, &ctx);
        assert!(matches!(decision.outcome, VetoOutcome::Vetoed { .. }));
    }

    #[test]
    fn veto_with_context_vetoes_tainted_egress() {
        let agent = SecurityAgent::new(test_agent_id());
        let mut tracker = TaintTracker::new();
        tracker.apply_taint(TaintTag {
            source: TaintSource::UserInput,
            entity_class: "credit_card".into(),
            applied_at: 0,
        });
        let gate = OutputGate::new();
        let ctx = VetoContext {
            taint_state: &tracker,
            output_gate: &gate,
            agent_source: AgentKind::Task,
        };
        let decision = agent.veto_with_context(
            "send credit_card to payment processor",
            OperationalMode::HighRisk,
            &ctx,
        );
        assert!(matches!(decision.outcome, VetoOutcome::Vetoed { .. }));
    }

    #[test]
    fn veto_with_context_vetoes_on_output_gate_match() {
        let agent = SecurityAgent::new(test_agent_id());
        let tracker = TaintTracker::new();
        let mut gate = OutputGate::new();
        gate.add_filter(ConstitutionalFilter {
            name: "no-exfil".into(),
            pattern: "exfiltrate".into(),
            severity: AlertSeverity::Critical,
        });
        let ctx = VetoContext {
            taint_state: &tracker,
            output_gate: &gate,
            agent_source: AgentKind::Task,
        };
        let decision =
            agent.veto_with_context("exfiltrate system logs", OperationalMode::HighRisk, &ctx);
        assert!(matches!(decision.outcome, VetoOutcome::Vetoed { .. }));
    }

    #[test]
    fn veto_with_context_approves_safe_in_high_risk() {
        let agent = SecurityAgent::new(test_agent_id());
        let tracker = TaintTracker::new();
        let gate = OutputGate::new();
        let ctx = VetoContext {
            taint_state: &tracker,
            output_gate: &gate,
            agent_source: AgentKind::Guidance,
        };
        let decision =
            agent.veto_with_context("show help documentation", OperationalMode::HighRisk, &ctx);
        assert!(matches!(decision.outcome, VetoOutcome::Approved));
    }

    // ── PerformanceBaseline tests ────────────────────────────────────────────

    #[test]
    fn baseline_no_samples_returns_none() {
        let b = PerformanceBaseline::new(10, 2.0);
        assert_eq!(b.average_latency(), None);
        assert!(!b.is_anomalous());
    }

    #[test]
    fn baseline_average_latency_computed() {
        let mut b = PerformanceBaseline::new(10, 2.0);
        b.record_inference_latency(100);
        b.record_inference_latency(200);
        b.record_inference_latency(300);
        assert_eq!(b.average_latency(), Some(200));
    }

    #[test]
    fn baseline_rolling_window_evicts_oldest() {
        let mut b = PerformanceBaseline::new(3, 2.0);
        b.record_inference_latency(10);
        b.record_inference_latency(20);
        b.record_inference_latency(30);
        b.record_inference_latency(90); // evicts 10
        // window is now [20, 30, 90], avg = 46
        assert_eq!(b.average_latency(), Some(46));
    }

    #[test]
    fn baseline_not_anomalous_within_threshold() {
        let mut b = PerformanceBaseline::new(10, 2.0);
        for &v in &[95, 100, 105, 98, 102, 97, 103, 99, 101, 100] {
            b.record_inference_latency(v);
        }
        assert!(!b.is_anomalous());
    }

    #[test]
    fn baseline_anomalous_spike() {
        let mut b = PerformanceBaseline::new(10, 2.0);
        for _ in 0..9 {
            b.record_inference_latency(100);
        }
        b.record_inference_latency(1_000); // extreme spike
        assert!(b.is_anomalous());
    }

    #[test]
    fn baseline_generate_alert_when_anomalous() {
        let mut b = PerformanceBaseline::new(10, 2.0);
        for _ in 0..9 {
            b.record_inference_latency(100);
        }
        b.record_inference_latency(10_000);
        assert!(b.generate_alert().is_some());
    }

    #[test]
    fn baseline_no_alert_when_normal() {
        let mut b = PerformanceBaseline::new(10, 2.0);
        for v in [100u64, 102, 98, 101, 99] {
            b.record_inference_latency(v);
        }
        assert!(b.generate_alert().is_none());
    }

    #[test]
    fn baseline_resource_usage_recorded() {
        let mut b = PerformanceBaseline::new(10, 2.0);
        b.record_resource_usage(75, 40);
        // Verify the fields are accessible via anomaly check (no panic).
        let _ = b.is_anomalous();
    }

    // ── SecurityAgent new-field initialization tests ─────────────────────────

    #[test]
    fn security_agent_starts_with_empty_taint_tracker() {
        let agent = SecurityAgent::new(test_agent_id());
        assert_eq!(agent.taint_tracker.active_taint_count(), 0);
    }

    #[test]
    fn security_agent_starts_with_empty_output_gate() {
        let agent = SecurityAgent::new(test_agent_id());
        assert_eq!(agent.output_gate.filter_count(), 0);
    }

    #[test]
    fn security_agent_starts_with_no_latency_samples() {
        let agent = SecurityAgent::new(test_agent_id());
        assert_eq!(agent.performance_baseline.average_latency(), None);
    }
}
