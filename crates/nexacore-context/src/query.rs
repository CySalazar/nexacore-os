//! The capability + privacy-budget query gate (WS16-05.6).
//!
//! Agents never touch [`PersonalContextStore`] directly. Every read of personal
//! context goes through [`query_context`], which enforces two independent gates
//! before returning anything:
//!
//! 1. **Capability** — the caller must present a [`ContextReadCapability`],
//!    minted by the capability broker (WS7-09). Absence is a hard denial.
//! 2. **Privacy budget** — the caller's [`PrivacyBudget`] (WS5-07) must not be
//!    exhausted. A depleted budget denies the read.
//!
//! On success the caller receives an [`ExposedContext`] — already tokenized and
//! filtered to opted-in documents (WS16-05.4/.5). Charging the budget per access
//! is layered on in this module as WS16-05.7.
//!
//! The privacy budget is tracked in **integer micro-epsilon units** rather than
//! floating point, so accounting is exact and free of rounding surprises.

use crate::{
    store::PersonalContextStore,
    tokenize::{ContextTokenizer, ExposedContext, expose_for_agent},
};

/// A capability authorizing a read of personal context (WS16-05.6).
///
/// It is an unforgeable token: the only way to obtain one is
/// [`ContextReadCapability::granted`], which the capability broker (WS7-09)
/// calls when it has authorized the caller. Passing `None` where a
/// `&ContextReadCapability` is expected is an unauthorized read.
#[derive(Debug, Clone, Copy)]
pub struct ContextReadCapability(());

impl ContextReadCapability {
    /// Mint a granted capability. Called by the capability broker once it has
    /// authorized the caller; not something an agent can fabricate on its own.
    #[must_use]
    pub const fn granted() -> Self {
        Self(())
    }
}

/// A caller's differential-privacy budget for context access (WS5-07 / WS16-05).
///
/// Tracked in integer micro-epsilon units so the arithmetic is exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyBudget {
    allocated_units: u64,
    consumed_units: u64,
}

impl PrivacyBudget {
    /// A budget with `allocated_units` micro-epsilon available and none spent.
    #[must_use]
    pub const fn new(allocated_units: u64) -> Self {
        Self {
            allocated_units,
            consumed_units: 0,
        }
    }

    /// The micro-epsilon units still available.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.allocated_units.saturating_sub(self.consumed_units)
    }

    /// Whether the budget is fully consumed.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.remaining() == 0
    }

    /// Whether `cost` units can still be afforded.
    #[must_use]
    pub const fn can_afford(&self, cost: u64) -> bool {
        self.remaining() >= cost
    }

    /// Charge `cost` units against the budget (WS16-05.7).
    ///
    /// If the cost is affordable it is deducted and `true` is returned;
    /// otherwise the budget is left untouched and `false` is returned — there is
    /// no partial charge.
    pub const fn charge(&mut self, cost: u64) -> bool {
        if self.can_afford(cost) {
            self.consumed_units = self.consumed_units.saturating_add(cost);
            true
        } else {
            false
        }
    }
}

/// The default privacy cost of a single context access, in micro-epsilon units.
pub const DEFAULT_ACCESS_COST_UNITS: u64 = 1;

/// Why a context query was denied (WS16-05.6). Every variant is fail-closed —
/// no context is returned unless all gates pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// Personal context is switched off by the user (WS16-05.8).
    #[error("context read denied: personal context is disabled")]
    Disabled,
    /// No capability was presented — the read is unauthorized.
    #[error("context read is not authorized (no capability presented)")]
    Unauthorized,
    /// The caller's privacy budget is exhausted.
    #[error("context read denied: privacy budget exhausted")]
    BudgetExhausted,
}

/// The user's master switch for personal-context exposure (WS16-05.8).
///
/// When off, *no* context reaches any agent regardless of capability or budget,
/// and no budget is spent — disabling excludes context with no side effects, so
/// the exclusion is verifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextSwitch {
    enabled: bool,
}

impl ContextSwitch {
    /// A switch in the enabled position (context may be read, gates permitting).
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// A switch in the disabled position (context is fully excluded).
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    /// Whether personal context is currently enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }

    /// Set the switch. `true` enables context exposure, `false` disables it.
    pub const fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for ContextSwitch {
    fn default() -> Self {
        Self::enabled()
    }
}

/// Read personal context through the capability + privacy-budget gate
/// (WS16-05.6).
///
/// Returns the tokenized, opt-in-filtered [`ExposedContext`] only when a
/// capability is presented and the budget is not exhausted. This form performs
/// the gate check without charging the budget — an availability check; the
/// charging read (`query_and_charge`) is layered on as WS16-05.7.
///
/// # Errors
///
/// - [`QueryError::Unauthorized`] if `capability` is `None`.
/// - [`QueryError::BudgetExhausted`] if `budget` has no units left.
pub fn query_context<T: ContextTokenizer + ?Sized>(
    store: &PersonalContextStore,
    tokenizer: &T,
    capability: Option<&ContextReadCapability>,
    budget: &PrivacyBudget,
) -> Result<ExposedContext, QueryError> {
    let _capability = capability.ok_or(QueryError::Unauthorized)?;
    if budget.is_exhausted() {
        return Err(QueryError::BudgetExhausted);
    }
    Ok(expose_for_agent(store, tokenizer))
}

/// Read personal context through the gate and **charge** the budget for the
/// access (WS16-05.7).
///
/// This is the read agents perform: on success it deducts `cost` micro-epsilon
/// units from `budget`, so each access measurably depletes the privacy budget
/// and repeated access eventually exhausts it. The capability is checked first,
/// so an unauthorized read never charges the budget; the charge is all-or-
/// nothing, so a denied read leaves the budget untouched.
///
/// # Errors
///
/// - [`QueryError::Unauthorized`] if `capability` is `None` (budget untouched).
/// - [`QueryError::BudgetExhausted`] if `cost` cannot be afforded (budget
///   untouched).
pub fn query_and_charge<T: ContextTokenizer + ?Sized>(
    store: &PersonalContextStore,
    tokenizer: &T,
    capability: Option<&ContextReadCapability>,
    budget: &mut PrivacyBudget,
    cost: u64,
) -> Result<ExposedContext, QueryError> {
    let _capability = capability.ok_or(QueryError::Unauthorized)?;
    if !budget.charge(cost) {
        return Err(QueryError::BudgetExhausted);
    }
    Ok(expose_for_agent(store, tokenizer))
}

/// The fully-gated context read (WS16-05.8): the user's master switch, then the
/// capability, then the charged privacy-budget gate.
///
/// The switch is checked **first**: when personal context is disabled the read
/// returns [`QueryError::Disabled`] before any capability or budget is touched,
/// so a disabled context is excluded with no side effects — the exclusion is
/// verifiable (nothing is returned, no budget is spent).
///
/// # Errors
///
/// - [`QueryError::Disabled`] if `switch` is off (budget untouched).
/// - [`QueryError::Unauthorized`] if `capability` is `None` (budget untouched).
/// - [`QueryError::BudgetExhausted`] if `cost` cannot be afforded (budget
///   untouched).
pub fn query_gated<T: ContextTokenizer + ?Sized>(
    switch: ContextSwitch,
    store: &PersonalContextStore,
    tokenizer: &T,
    capability: Option<&ContextReadCapability>,
    budget: &mut PrivacyBudget,
    cost: u64,
) -> Result<ExposedContext, QueryError> {
    if !switch.is_enabled() {
        return Err(QueryError::Disabled);
    }
    query_and_charge(store, tokenizer, capability, budget, cost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HistoryEntry;

    struct Passthrough;
    impl ContextTokenizer for Passthrough {
        fn tokenize(&self, text: &str) -> String {
            text.to_owned()
        }
    }

    fn store() -> PersonalContextStore {
        let mut store = PersonalContextStore::new();
        store.record(HistoryEntry::new(1, "hello"));
        store
    }

    #[test]
    fn a_granted_capability_and_budget_returns_context() {
        let cap = ContextReadCapability::granted();
        let budget = PrivacyBudget::new(10);
        let result = query_context(&store(), &Passthrough, Some(&cap), &budget);
        assert!(result.is_ok());
        let Ok(view) = result else { return };
        assert_eq!(view.history, vec!["hello".to_owned()]);
    }

    #[test]
    fn a_missing_capability_is_unauthorized() {
        let budget = PrivacyBudget::new(10);
        assert_eq!(
            query_context(&store(), &Passthrough, None, &budget),
            Err(QueryError::Unauthorized)
        );
    }

    #[test]
    fn an_exhausted_budget_is_denied() {
        let cap = ContextReadCapability::granted();
        let budget = PrivacyBudget::new(0);
        assert_eq!(
            query_context(&store(), &Passthrough, Some(&cap), &budget),
            Err(QueryError::BudgetExhausted)
        );
    }

    #[test]
    fn budget_accounting_is_exact() {
        let budget = PrivacyBudget::new(3);
        assert_eq!(budget.remaining(), 3);
        assert!(budget.can_afford(3));
        assert!(!budget.can_afford(4));
        assert!(!budget.is_exhausted());
        assert!(PrivacyBudget::new(0).is_exhausted());
    }

    #[test]
    fn each_access_debits_the_budget() {
        let cap = ContextReadCapability::granted();
        let mut budget = PrivacyBudget::new(3);
        let result = query_and_charge(
            &store(),
            &Passthrough,
            Some(&cap),
            &mut budget,
            DEFAULT_ACCESS_COST_UNITS,
        );
        assert!(result.is_ok());
        assert_eq!(budget.remaining(), 2); // charged one unit
    }

    #[test]
    fn repeated_access_exhausts_then_denies() {
        let cap = ContextReadCapability::granted();
        let mut budget = PrivacyBudget::new(2);
        for expected_remaining in [1u64, 0] {
            let result = query_and_charge(&store(), &Passthrough, Some(&cap), &mut budget, 1);
            assert!(result.is_ok());
            assert_eq!(budget.remaining(), expected_remaining);
        }
        // Third access: budget is spent → denied, and stays at zero.
        assert_eq!(
            query_and_charge(&store(), &Passthrough, Some(&cap), &mut budget, 1),
            Err(QueryError::BudgetExhausted)
        );
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn an_unauthorized_access_does_not_charge() {
        let mut budget = PrivacyBudget::new(3);
        assert_eq!(
            query_and_charge(&store(), &Passthrough, None, &mut budget, 1),
            Err(QueryError::Unauthorized)
        );
        // Budget untouched — no charge on an unauthorized read.
        assert_eq!(budget.remaining(), 3);
    }

    #[test]
    fn an_unaffordable_cost_is_all_or_nothing() {
        let cap = ContextReadCapability::granted();
        let mut budget = PrivacyBudget::new(1);
        // Cost exceeds remaining → denied, budget untouched (no partial charge).
        assert_eq!(
            query_and_charge(&store(), &Passthrough, Some(&cap), &mut budget, 2),
            Err(QueryError::BudgetExhausted)
        );
        assert_eq!(budget.remaining(), 1);
    }

    #[test]
    fn disabling_context_verifiably_excludes_it() {
        let cap = ContextReadCapability::granted();
        let mut budget = PrivacyBudget::new(3);
        let switch = ContextSwitch::disabled();

        // Even with a valid capability and budget, a disabled switch returns
        // nothing and spends no budget — the exclusion is verifiable.
        assert_eq!(
            query_gated(switch, &store(), &Passthrough, Some(&cap), &mut budget, 1),
            Err(QueryError::Disabled)
        );
        assert_eq!(budget.remaining(), 3);
    }

    #[test]
    fn re_enabling_context_restores_access() {
        let cap = ContextReadCapability::granted();
        let mut budget = PrivacyBudget::new(3);
        let mut switch = ContextSwitch::disabled();
        switch.set_enabled(true);

        let result = query_gated(switch, &store(), &Passthrough, Some(&cap), &mut budget, 1);
        assert!(result.is_ok());
        assert_eq!(budget.remaining(), 2); // now it charges again
    }

    #[test]
    fn the_switch_defaults_to_enabled() {
        assert!(ContextSwitch::default().is_enabled());
    }
}
