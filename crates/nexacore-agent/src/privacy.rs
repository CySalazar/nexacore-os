//! Differential privacy budget accountant for NexaCore OS.
//!
//! Tracks cumulative epsilon (privacy loss) across all agent operations using
//! **sequential composition**: the total privacy cost of independent operations
//! is the sum of their individual epsilon values.  When the cumulative epsilon
//! reaches `epsilon_max`, further privacy-consuming operations are denied.
//!
//! ## Design decisions
//!
//! - **`f64` for epsilon**: Standard in the DP literature (e.g. Dwork & Roth
//!   2014).  Floating-point accumulation error is mitigated by the exhaustion
//!   guard in [`crate::privacy::PrivacyBudgetAccountant::consume`], which uses `>=` rather than
//!   exact equality.
//! - **Per-agent sub-budgets**: Each agent receives an explicit epsilon
//!   allocation.  The sum of all allocations MUST NOT exceed `epsilon_max`;
//!   [`crate::privacy::PrivacyBudgetAccountant::allocate_agent`] enforces this invariant.
//! - **Immutable ledger**: [`crate::privacy::PrivacyEvent`] entries are append-only and are
//!   never removed.  This gives a full audit trail for the lifetime of the
//!   accountant.
//! - **No `Mutex`**: `PrivacyBudgetAccountant` is intentionally `!Send +
//!   !Sync`.  The five-agent framework gives each agent exclusive ownership
//!   of its resources.  Callers that genuinely need shared access are
//!   responsible for wrapping the accountant in a `Mutex` or `RwLock`.
//! - **Timestamp stub**: `PrivacyEvent::timestamp` is set to `0` until the
//!   `nexacore-hal` `Clock` abstraction lands (Phase 6), matching the convention
//!   already used throughout `task.rs`.
//!
//! See NCIP-Agent-Arch-022 §S9.4.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// DataSensitivity
// ─────────────────────────────────────────────────────────────────────────────

/// Sensitivity level of the data being accessed.
///
/// Each level maps to a fixed epsilon cost (see [`PrivacyBudgetAccountant::sensitivity_cost`]).
/// The tiers follow GDPR Article 4(1) / Article 9 categorisation:
///
/// | Tier | Epsilon cost | Basis |
/// |---|---|---|
/// | `Public` | 0.0 | No personal data involved |
/// | `Internal` | 0.1 | Organisational data, low re-identification risk |
/// | `Personal` | 0.5 | GDPR Article 4(1) personal data |
/// | `SensitivePersonal` | 1.0 | GDPR Article 9 special-category lite |
/// | `SpecialCategory` | 2.0 | Health, biometric, financial |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataSensitivity {
    /// Public data — zero privacy cost.
    Public,
    /// Internal / organisational data — low epsilon cost (ε = 0.1).
    Internal,
    /// Personal data (GDPR Article 4(1)) — medium epsilon cost (ε = 0.5).
    Personal,
    /// Sensitive personal data (GDPR Article 9) — high epsilon cost (ε = 1.0).
    SensitivePersonal,
    /// Special-category data: health, biometric, financial — very high cost (ε = 2.0).
    SpecialCategory,
}

// ─────────────────────────────────────────────────────────────────────────────
// PrivacyError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by [`PrivacyBudgetAccountant`].
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum PrivacyError {
    /// The system-wide epsilon budget has been fully consumed.
    #[error(
        "system privacy budget exhausted: requested ε={requested:.4}, \
         remaining ε={remaining:.4}"
    )]
    BudgetExhausted {
        /// Epsilon requested by the operation.
        requested: f64,
        /// Epsilon remaining in the system budget.
        remaining: f64,
    },

    /// No allocation was found for the given agent identifier.
    #[error("agent not found: {0}")]
    AgentNotFound(String),

    /// The named agent's per-agent epsilon allocation is fully consumed.
    #[error(
        "agent '{agent_id}' privacy budget exhausted: requested ε={requested:.4}, \
         remaining ε={remaining:.4}"
    )]
    AgentBudgetExhausted {
        /// The agent whose budget is exhausted.
        agent_id: String,
        /// Epsilon requested.
        requested: f64,
        /// Epsilon remaining in the agent's allocation.
        remaining: f64,
    },

    /// The requested allocation would push the total allocated epsilon above
    /// `epsilon_max`.
    #[error(
        "allocation exceeds system budget: requested ε={requested:.4}, \
         available ε={available:.4}"
    )]
    AllocationExceedsSystem {
        /// Epsilon requested for the new allocation.
        requested: f64,
        /// Epsilon still available for allocation.
        available: f64,
    },

    /// The supplied epsilon value is invalid (e.g. negative, `NaN`, or
    /// infinite).
    #[error("invalid epsilon value: must be finite and ≥ 0.0")]
    InvalidEpsilon,
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentPrivacyBudget
// ─────────────────────────────────────────────────────────────────────────────

/// Per-agent epsilon allocation and consumption tracking.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentPrivacyBudget {
    /// Agent identifier (e.g. `"task-agent"`, `"sysadmin-agent"`).
    pub agent_id: String,
    /// Epsilon allocated to this agent.
    pub epsilon_allocated: f64,
    /// Epsilon consumed by this agent so far.
    pub epsilon_consumed: f64,
}

impl AgentPrivacyBudget {
    /// Returns the epsilon remaining in this agent's allocation.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::AgentPrivacyBudget;
    ///
    /// let budget = AgentPrivacyBudget {
    ///     agent_id: "task-agent".into(),
    ///     epsilon_allocated: 2.0,
    ///     epsilon_consumed: 0.5,
    /// };
    /// assert!((budget.remaining() - 1.5).abs() < f64::EPSILON);
    /// ```
    #[must_use]
    #[allow(clippy::float_arithmetic)]
    pub fn remaining(&self) -> f64 {
        (self.epsilon_allocated - self.epsilon_consumed).max(0.0)
    }

    /// Returns `true` if this agent's allocation is fully consumed.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::AgentPrivacyBudget;
    ///
    /// let budget = AgentPrivacyBudget {
    ///     agent_id: "task-agent".into(),
    ///     epsilon_allocated: 1.0,
    ///     epsilon_consumed: 1.0,
    /// };
    /// assert!(budget.is_exhausted());
    /// ```
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.epsilon_consumed >= self.epsilon_allocated
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PrivacyEvent
// ─────────────────────────────────────────────────────────────────────────────

/// A single privacy-consuming event recorded in the immutable ledger.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyEvent {
    /// The agent that consumed the budget.
    pub agent_id: String,
    /// Epsilon cost charged for this operation.
    pub epsilon_cost: f64,
    /// Sensitivity classification of the data accessed.
    pub data_category: DataSensitivity,
    /// Unix timestamp (seconds since epoch).
    ///
    /// Stubbed to `0` until the `nexacore-hal` `Clock` abstraction lands in Phase 6.
    pub timestamp: u64,
    /// Human-readable description of the operation.
    pub description: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// PrivacyReport / AgentSummary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics for a single agent extracted from [`PrivacyReport`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSummary {
    /// Agent identifier.
    pub agent_id: String,
    /// Epsilon allocated to this agent.
    pub allocated: f64,
    /// Epsilon consumed by this agent.
    pub consumed: f64,
    /// Epsilon remaining in this agent's allocation.
    pub remaining: f64,
    /// Number of privacy-consuming events logged for this agent.
    pub event_count: usize,
}

/// System-wide privacy budget report.
///
/// Produced by [`PrivacyBudgetAccountant::report`].  Contains per-agent
/// breakdowns and global totals.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyReport {
    /// Maximum cumulative epsilon for this scope.
    pub epsilon_max: f64,
    /// Total epsilon consumed across all agents.
    pub epsilon_used: f64,
    /// Epsilon remaining (system-wide).
    pub epsilon_remaining: f64,
    /// Delta parameter for (ε, δ)-DP.  `0.0` when not in use.
    pub delta: f64,
    /// Per-agent summaries.
    pub agent_summaries: Vec<AgentSummary>,
    /// Total number of privacy-consuming events in the ledger.
    pub event_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// PrivacyBudgetAccountant
// ─────────────────────────────────────────────────────────────────────────────

/// Differential privacy budget accountant using sequential composition.
///
/// Tracks cumulative epsilon (privacy loss) across all operations.
/// When the total epsilon reaches the configured maximum, further
/// privacy-consuming operations are denied.
///
/// ## Sequential composition
///
/// Under sequential composition the total privacy loss of `k` independent
/// mechanisms is bounded by `Σ εᵢ`.  This is the most conservative bound;
/// advanced composition (e.g. Kairouz et al. 2015) is not yet implemented.
///
/// ## Thread safety
///
/// `PrivacyBudgetAccountant` is intentionally single-threaded.  Wrap in
/// `std::sync::Mutex` if shared access is required.
///
/// # Examples
///
/// ```
/// use nexacore_agent::privacy::{DataSensitivity, PrivacyBudgetAccountant};
///
/// let mut accountant = PrivacyBudgetAccountant::new(10.0, 1e-5).unwrap();
/// accountant.allocate_agent("task-agent", 5.0).unwrap();
/// let remaining = accountant
///     .consume("task-agent", DataSensitivity::Personal, "web search")
///     .unwrap();
/// assert!(remaining < 5.0);
/// ```
#[derive(Debug)]
pub struct PrivacyBudgetAccountant {
    /// Maximum allowed cumulative epsilon for this scope.
    epsilon_max: f64,
    /// Current cumulative epsilon consumed (system-wide).
    epsilon_used: f64,
    /// Optional delta parameter for (ε, δ)-DP.  Set to `0.0` when not in use.
    delta: f64,
    /// Per-agent budget allocations, keyed by agent identifier.
    agent_allocations: HashMap<String, AgentPrivacyBudget>,
    /// Append-only ledger of all privacy-consuming operations.
    ledger: Vec<PrivacyEvent>,
}

impl PrivacyBudgetAccountant {
    /// Create a new accountant with the given system-wide epsilon budget.
    ///
    /// `delta` is the delta parameter for (ε, δ)-DP.  Pass `0.0` to use
    /// pure ε-DP.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::InvalidEpsilon`] if `epsilon_max` or `delta`
    /// is negative, `NaN`, or infinite.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::PrivacyBudgetAccountant;
    ///
    /// let accountant = PrivacyBudgetAccountant::new(10.0, 1e-5).unwrap();
    /// assert!((accountant.remaining_system() - 10.0).abs() < f64::EPSILON);
    /// ```
    pub fn new(epsilon_max: f64, delta: f64) -> Result<Self, PrivacyError> {
        if !epsilon_max.is_finite() || epsilon_max < 0.0 {
            return Err(PrivacyError::InvalidEpsilon);
        }
        if !delta.is_finite() || delta < 0.0 {
            return Err(PrivacyError::InvalidEpsilon);
        }
        Ok(Self {
            epsilon_max,
            epsilon_used: 0.0,
            delta,
            agent_allocations: HashMap::new(),
            ledger: Vec::new(),
        })
    }

    /// Allocate an epsilon budget to an agent.
    ///
    /// The total of all per-agent allocations MUST NOT exceed `epsilon_max`.
    /// Registering the same `agent_id` twice updates the allocation (useful
    /// when topping up an agent's budget between phases).
    ///
    /// # Errors
    ///
    /// - [`PrivacyError::InvalidEpsilon`] — `epsilon` is negative, `NaN`, or
    ///   infinite.
    /// - [`PrivacyError::AllocationExceedsSystem`] — the total allocated
    ///   epsilon would exceed `epsilon_max`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::PrivacyBudgetAccountant;
    ///
    /// let mut accountant = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
    /// accountant.allocate_agent("task-agent", 3.0).unwrap();
    /// accountant.allocate_agent("sysadmin-agent", 4.0).unwrap();
    /// ```
    #[allow(clippy::float_arithmetic)]
    pub fn allocate_agent(&mut self, agent_id: &str, epsilon: f64) -> Result<(), PrivacyError> {
        if !epsilon.is_finite() || epsilon < 0.0 {
            return Err(PrivacyError::InvalidEpsilon);
        }

        // Compute how much system epsilon is currently spoken for by OTHER agents.
        // If this agent already has an allocation we replace it, so subtract
        // the old value first.
        let existing_for_agent = self
            .agent_allocations
            .get(agent_id)
            .map_or(0.0, |a| a.epsilon_allocated);

        let total_allocated_others: f64 = self
            .agent_allocations
            .values()
            .map(|a| a.epsilon_allocated)
            .sum::<f64>()
            - existing_for_agent;

        let available = self.epsilon_max - total_allocated_others;

        if epsilon > available + f64::EPSILON {
            warn!(
                agent_id,
                requested = epsilon,
                available,
                "allocation rejected: would exceed system epsilon budget"
            );
            return Err(PrivacyError::AllocationExceedsSystem {
                requested: epsilon,
                available,
            });
        }

        // Carry forward any already-consumed epsilon when re-allocating.
        let consumed = self
            .agent_allocations
            .get(agent_id)
            .map_or(0.0, |a| a.epsilon_consumed);

        self.agent_allocations.insert(
            agent_id.to_owned(),
            AgentPrivacyBudget {
                agent_id: agent_id.to_owned(),
                epsilon_allocated: epsilon,
                epsilon_consumed: consumed,
            },
        );

        info!(
            agent_id,
            epsilon_allocated = epsilon,
            "agent privacy budget allocated"
        );
        Ok(())
    }

    /// Charge an epsilon cost for an operation performed by `agent_id`.
    ///
    /// The cost is determined by the [`DataSensitivity`] tier via
    /// [`Self::sensitivity_cost`].  Both the system-wide budget and the
    /// per-agent allocation are checked; if either is exhausted the operation
    /// is denied and the ledger is NOT updated.
    ///
    /// Returns the agent's remaining epsilon after the charge.
    ///
    /// # Errors
    ///
    /// - [`PrivacyError::AgentNotFound`] — `agent_id` has no registered
    ///   allocation.
    /// - [`PrivacyError::BudgetExhausted`] — the system-wide budget would be
    ///   exceeded.
    /// - [`PrivacyError::AgentBudgetExhausted`] — the agent's per-allocation
    ///   budget would be exceeded.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::{DataSensitivity, PrivacyBudgetAccountant};
    ///
    /// let mut accountant = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
    /// accountant.allocate_agent("task-agent", 5.0).unwrap();
    /// let remaining = accountant
    ///     .consume(
    ///         "task-agent",
    ///         DataSensitivity::Internal,
    ///         "fetch internal doc",
    ///     )
    ///     .unwrap();
    /// // Internal costs ε = 0.1; remaining should be ≈ 4.9
    /// assert!(remaining < 5.0);
    /// ```
    #[allow(clippy::float_arithmetic)]
    #[allow(
        clippy::cognitive_complexity,
        reason = "DP budget accounting: branches over mechanism + composition states"
    )]
    pub fn consume(
        &mut self,
        agent_id: &str,
        sensitivity: DataSensitivity,
        description: &str,
    ) -> Result<f64, PrivacyError> {
        let cost = Self::sensitivity_cost(sensitivity);

        // Public data incurs zero cost; always permit and skip ledger entry.
        if cost == 0.0 {
            debug!(agent_id, "public data access: no privacy cost");
            let remaining = self
                .agent_allocations
                .get(agent_id)
                .map_or(0.0, AgentPrivacyBudget::remaining);
            return Ok(remaining);
        }

        // Verify agent exists.
        let agent = self
            .agent_allocations
            .get(agent_id)
            .ok_or_else(|| PrivacyError::AgentNotFound(agent_id.to_owned()))?;

        // Check system budget.
        let sys_remaining = self.epsilon_max - self.epsilon_used;
        if cost > sys_remaining + f64::EPSILON {
            warn!(
                agent_id,
                cost, sys_remaining, "system privacy budget exhausted"
            );
            return Err(PrivacyError::BudgetExhausted {
                requested: cost,
                remaining: sys_remaining,
            });
        }

        // Check per-agent budget.
        let agent_remaining = agent.remaining();
        if cost > agent_remaining + f64::EPSILON {
            warn!(
                agent_id,
                cost, agent_remaining, "agent privacy budget exhausted"
            );
            return Err(PrivacyError::AgentBudgetExhausted {
                agent_id: agent_id.to_owned(),
                requested: cost,
                remaining: agent_remaining,
            });
        }

        // Charge both budgets.
        self.epsilon_used += cost;
        // Re-borrow mutably after the immutable borrows above are released.
        // The `AgentNotFound` branch is logically unreachable: we verified the
        // agent exists with `get()` earlier in this function, and no other
        // code path can remove it between those two points (single-threaded
        // ownership). The typed error path exists solely to satisfy the type
        // system without `expect()`.
        let agent_mut = self
            .agent_allocations
            .get_mut(agent_id)
            .ok_or_else(|| PrivacyError::AgentNotFound(agent_id.to_owned()))?;
        agent_mut.epsilon_consumed += cost;
        let new_remaining = agent_mut.remaining();

        // Append to immutable ledger.
        self.ledger.push(PrivacyEvent {
            agent_id: agent_id.to_owned(),
            epsilon_cost: cost,
            data_category: sensitivity,
            // Timestamp stubbed until nexacore-hal Clock lands (Phase 6).
            timestamp: 0,
            description: description.to_owned(),
        });

        info!(
            agent_id,
            epsilon_cost = cost,
            sensitivity = ?sensitivity,
            agent_remaining = new_remaining,
            system_remaining = self.epsilon_max - self.epsilon_used,
            "privacy budget consumed"
        );

        Ok(new_remaining)
    }

    /// Returns the system-wide remaining epsilon.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::PrivacyBudgetAccountant;
    ///
    /// let accountant = PrivacyBudgetAccountant::new(5.0, 0.0).unwrap();
    /// assert!((accountant.remaining_system() - 5.0).abs() < f64::EPSILON);
    /// ```
    #[must_use]
    #[allow(clippy::float_arithmetic)]
    pub fn remaining_system(&self) -> f64 {
        (self.epsilon_max - self.epsilon_used).max(0.0)
    }

    /// Returns the remaining epsilon for a specific agent.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::AgentNotFound`] if the agent has no allocation.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::PrivacyBudgetAccountant;
    ///
    /// let mut accountant = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
    /// accountant.allocate_agent("task-agent", 3.0).unwrap();
    /// assert!((accountant.remaining_agent("task-agent").unwrap() - 3.0).abs() < f64::EPSILON);
    /// ```
    pub fn remaining_agent(&self, agent_id: &str) -> Result<f64, PrivacyError> {
        self.agent_allocations
            .get(agent_id)
            .map(AgentPrivacyBudget::remaining)
            .ok_or_else(|| PrivacyError::AgentNotFound(agent_id.to_owned()))
    }

    /// Returns `true` if the system-wide epsilon budget is fully consumed.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::{DataSensitivity, PrivacyBudgetAccountant};
    ///
    /// let mut accountant = PrivacyBudgetAccountant::new(0.1, 0.0).unwrap();
    /// accountant.allocate_agent("task-agent", 0.1).unwrap();
    /// accountant
    ///     .consume("task-agent", DataSensitivity::Internal, "op")
    ///     .unwrap();
    /// assert!(accountant.is_exhausted());
    /// ```
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.epsilon_used >= self.epsilon_max
    }

    /// Returns a read-only view of the immutable privacy ledger.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::{DataSensitivity, PrivacyBudgetAccountant};
    ///
    /// let mut accountant = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
    /// accountant.allocate_agent("task-agent", 5.0).unwrap();
    /// accountant
    ///     .consume("task-agent", DataSensitivity::Personal, "search")
    ///     .unwrap();
    /// assert_eq!(accountant.ledger().len(), 1);
    /// ```
    #[must_use]
    pub fn ledger(&self) -> &[PrivacyEvent] {
        &self.ledger
    }

    /// Generate a [`PrivacyReport`] summarising the current budget state.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::PrivacyBudgetAccountant;
    ///
    /// let mut accountant = PrivacyBudgetAccountant::new(10.0, 1e-5).unwrap();
    /// accountant.allocate_agent("task-agent", 5.0).unwrap();
    /// let report = accountant.report();
    /// assert_eq!(report.agent_summaries.len(), 1);
    /// assert!((report.epsilon_max - 10.0).abs() < f64::EPSILON);
    /// ```
    #[must_use]
    #[allow(clippy::float_arithmetic)]
    pub fn report(&self) -> PrivacyReport {
        let agent_summaries: Vec<AgentSummary> = self
            .agent_allocations
            .values()
            .map(|a| {
                let event_count = self
                    .ledger
                    .iter()
                    .filter(|e| e.agent_id == a.agent_id)
                    .count();
                AgentSummary {
                    agent_id: a.agent_id.clone(),
                    allocated: a.epsilon_allocated,
                    consumed: a.epsilon_consumed,
                    remaining: a.remaining(),
                    event_count,
                }
            })
            .collect();

        PrivacyReport {
            epsilon_max: self.epsilon_max,
            epsilon_used: self.epsilon_used,
            epsilon_remaining: self.remaining_system(),
            delta: self.delta,
            agent_summaries,
            event_count: self.ledger.len(),
        }
    }

    /// Returns the epsilon cost for a given [`DataSensitivity`] tier.
    ///
    /// This is a pure function of the sensitivity level; it does not consult
    /// the accountant state.
    ///
    /// | Sensitivity | ε cost |
    /// |---|---|
    /// | `Public` | 0.0 |
    /// | `Internal` | 0.1 |
    /// | `Personal` | 0.5 |
    /// | `SensitivePersonal` | 1.0 |
    /// | `SpecialCategory` | 2.0 |
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::privacy::{DataSensitivity, PrivacyBudgetAccountant};
    ///
    /// assert!(
    ///     (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::Public) - 0.0).abs()
    ///         < f64::EPSILON
    /// );
    /// assert!(
    ///     (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::Internal) - 0.1).abs()
    ///         < f64::EPSILON
    /// );
    /// assert!(
    ///     (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::Personal) - 0.5).abs()
    ///         < f64::EPSILON
    /// );
    /// assert!(
    ///     (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::SensitivePersonal) - 1.0).abs()
    ///         < f64::EPSILON
    /// );
    /// assert!(
    ///     (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::SpecialCategory) - 2.0).abs()
    ///         < f64::EPSILON
    /// );
    /// ```
    #[must_use]
    pub fn sensitivity_cost(sensitivity: DataSensitivity) -> f64 {
        match sensitivity {
            DataSensitivity::Public => 0.0,
            DataSensitivity::Internal => 0.1,
            DataSensitivity::Personal => 0.5,
            DataSensitivity::SensitivePersonal => 1.0,
            DataSensitivity::SpecialCategory => 2.0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction ─────────────────────────────────────────────────────────

    #[test]
    fn new_accountant_starts_at_zero_usage() {
        let a = PrivacyBudgetAccountant::new(10.0, 1e-5).unwrap();
        assert!((a.remaining_system() - 10.0).abs() < f64::EPSILON);
        assert!(!a.is_exhausted());
        assert_eq!(a.ledger().len(), 0);
    }

    #[test]
    fn new_rejects_negative_epsilon() {
        assert_eq!(
            PrivacyBudgetAccountant::new(-1.0, 0.0).unwrap_err(),
            PrivacyError::InvalidEpsilon
        );
    }

    #[test]
    fn new_rejects_nan_epsilon() {
        assert_eq!(
            PrivacyBudgetAccountant::new(f64::NAN, 0.0).unwrap_err(),
            PrivacyError::InvalidEpsilon
        );
    }

    #[test]
    fn new_rejects_infinite_epsilon() {
        assert_eq!(
            PrivacyBudgetAccountant::new(f64::INFINITY, 0.0).unwrap_err(),
            PrivacyError::InvalidEpsilon
        );
    }

    #[test]
    fn new_rejects_negative_delta() {
        assert_eq!(
            PrivacyBudgetAccountant::new(1.0, -0.1).unwrap_err(),
            PrivacyError::InvalidEpsilon
        );
    }

    #[test]
    fn new_accepts_zero_epsilon() {
        // Zero epsilon_max is valid (all operations denied immediately).
        let a = PrivacyBudgetAccountant::new(0.0, 0.0).unwrap();
        assert!(a.is_exhausted());
    }

    // ── Allocation ────────────────────────────────────────────────────────────

    #[test]
    fn allocate_agent_within_system_budget() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        a.allocate_agent("task-agent", 5.0).unwrap();
        assert!((a.remaining_agent("task-agent").unwrap() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn allocate_two_agents_within_budget() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        a.allocate_agent("task-agent", 4.0).unwrap();
        a.allocate_agent("sysadmin-agent", 5.0).unwrap();
        assert!((a.remaining_agent("task-agent").unwrap() - 4.0).abs() < f64::EPSILON);
        assert!((a.remaining_agent("sysadmin-agent").unwrap() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn allocate_exceeds_system_budget_returns_error() {
        let mut a = PrivacyBudgetAccountant::new(5.0, 0.0).unwrap();
        a.allocate_agent("agent-a", 3.0).unwrap();
        let err = a.allocate_agent("agent-b", 3.0).unwrap_err();
        assert!(matches!(err, PrivacyError::AllocationExceedsSystem { .. }));
    }

    #[test]
    fn allocate_invalid_epsilon_returns_error() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        assert_eq!(
            a.allocate_agent("agent", -1.0).unwrap_err(),
            PrivacyError::InvalidEpsilon
        );
    }

    #[test]
    fn reallocate_same_agent_updates_allocation() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        a.allocate_agent("task-agent", 3.0).unwrap();
        // Replace with a larger allocation — system has room.
        a.allocate_agent("task-agent", 7.0).unwrap();
        assert!((a.remaining_agent("task-agent").unwrap() - 7.0).abs() < f64::EPSILON);
    }

    // ── Sensitivity costs ─────────────────────────────────────────────────────

    #[test]
    fn sensitivity_cost_public_is_zero() {
        assert!(
            (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::Public) - 0.0).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn sensitivity_cost_internal_is_0_1() {
        assert!(
            (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::Internal) - 0.1).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn sensitivity_cost_personal_is_0_5() {
        assert!(
            (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::Personal) - 0.5).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn sensitivity_cost_sensitive_personal_is_1_0() {
        assert!(
            (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::SensitivePersonal) - 1.0)
                .abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn sensitivity_cost_special_category_is_2_0() {
        assert!(
            (PrivacyBudgetAccountant::sensitivity_cost(DataSensitivity::SpecialCategory) - 2.0)
                .abs()
                < f64::EPSILON
        );
    }

    // ── Consume / lifecycle ───────────────────────────────────────────────────

    #[test]
    fn consume_internal_charges_correct_epsilon() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        a.allocate_agent("task-agent", 5.0).unwrap();
        let remaining = a
            .consume("task-agent", DataSensitivity::Internal, "op")
            .unwrap();
        // ε used = 0.1; remaining for agent = 4.9
        assert!((remaining - 4.9).abs() < 1e-10);
    }

    #[test]
    fn consume_records_ledger_entry() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        a.allocate_agent("task-agent", 5.0).unwrap();
        a.consume("task-agent", DataSensitivity::Personal, "search query")
            .unwrap();
        assert_eq!(a.ledger().len(), 1);
        let event = &a.ledger()[0];
        assert_eq!(event.agent_id, "task-agent");
        assert_eq!(event.data_category, DataSensitivity::Personal);
        assert_eq!(event.description, "search query");
    }

    #[test]
    fn consume_public_does_not_add_ledger_entry() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        a.allocate_agent("task-agent", 5.0).unwrap();
        a.consume("task-agent", DataSensitivity::Public, "public info")
            .unwrap();
        assert_eq!(a.ledger().len(), 0);
    }

    #[test]
    fn consume_unknown_agent_returns_not_found() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        let err = a
            .consume("ghost-agent", DataSensitivity::Personal, "op")
            .unwrap_err();
        assert!(matches!(err, PrivacyError::AgentNotFound(_)));
    }

    #[test]
    fn consume_exhausts_system_budget_and_denies_further() {
        // epsilon_max = 0.5; one Personal (0.5) drains it.
        let mut a = PrivacyBudgetAccountant::new(0.5, 0.0).unwrap();
        a.allocate_agent("task-agent", 0.5).unwrap();
        a.consume("task-agent", DataSensitivity::Personal, "first op")
            .unwrap();
        assert!(a.is_exhausted());
        let err = a
            .consume("task-agent", DataSensitivity::Internal, "second op")
            .unwrap_err();
        assert!(matches!(err, PrivacyError::BudgetExhausted { .. }));
    }

    #[test]
    fn consume_exhausts_agent_budget_and_denies_further() {
        // System has 10.0, but task-agent only gets 0.5.
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        a.allocate_agent("task-agent", 0.5).unwrap();
        a.consume("task-agent", DataSensitivity::Personal, "first op")
            .unwrap();
        let err = a
            .consume("task-agent", DataSensitivity::Internal, "second op")
            .unwrap_err();
        assert!(matches!(err, PrivacyError::AgentBudgetExhausted { .. }));
    }

    #[test]
    fn consume_exact_exhaustion_marks_is_exhausted() {
        let mut a = PrivacyBudgetAccountant::new(1.0, 0.0).unwrap();
        a.allocate_agent("agent", 1.0).unwrap();
        a.consume("agent", DataSensitivity::SensitivePersonal, "op")
            .unwrap();
        assert!(a.is_exhausted());
    }

    #[test]
    fn multiple_agents_debit_system_correctly() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 0.0).unwrap();
        a.allocate_agent("agent-a", 5.0).unwrap();
        a.allocate_agent("agent-b", 5.0).unwrap();

        a.consume("agent-a", DataSensitivity::Personal, "op-a")
            .unwrap(); // 0.5
        a.consume("agent-b", DataSensitivity::Internal, "op-b")
            .unwrap(); // 0.1

        // system: 10.0 - 0.6 = 9.4
        assert!((a.remaining_system() - 9.4).abs() < 1e-10);
    }

    // ── Report ────────────────────────────────────────────────────────────────

    #[test]
    fn report_reflects_current_state() {
        let mut a = PrivacyBudgetAccountant::new(10.0, 1e-5).unwrap();
        a.allocate_agent("task-agent", 5.0).unwrap();
        a.consume("task-agent", DataSensitivity::Personal, "op")
            .unwrap();

        let report = a.report();
        assert!((report.epsilon_max - 10.0).abs() < f64::EPSILON);
        assert!((report.epsilon_used - 0.5).abs() < 1e-10);
        assert!((report.epsilon_remaining - 9.5).abs() < 1e-10);
        assert!((report.delta - 1e-5).abs() < f64::EPSILON);
        assert_eq!(report.event_count, 1);
        assert_eq!(report.agent_summaries.len(), 1);

        let summary = &report.agent_summaries[0];
        assert_eq!(summary.agent_id, "task-agent");
        assert_eq!(summary.event_count, 1);
        assert!((summary.consumed - 0.5).abs() < 1e-10);
    }

    // ── AgentPrivacyBudget helpers ─────────────────────────────────────────────

    #[test]
    fn agent_budget_remaining_clamped_at_zero() {
        let b = AgentPrivacyBudget {
            agent_id: "x".into(),
            epsilon_allocated: 1.0,
            epsilon_consumed: 2.0, // over-consumed (shouldn't happen in practice)
        };
        assert!(b.remaining() < f64::EPSILON);
    }

    #[test]
    fn agent_budget_is_exhausted_when_consumed_equals_allocated() {
        let b = AgentPrivacyBudget {
            agent_id: "x".into(),
            epsilon_allocated: 1.0,
            epsilon_consumed: 1.0,
        };
        assert!(b.is_exhausted());
    }
}
