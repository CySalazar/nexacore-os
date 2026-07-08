//! Privacy-budget accountant (WS5-07).
//!
//! Tracks and limits each user/app's "privacy spend" as workloads egress to
//! higher execution tiers. Local (Tier 0) inference is free — data never leaves
//! the device — while personal-cluster, mesh, and especially commercial-cloud
//! egress each cost budget. When a holder's budget is exhausted, the cloud gate
//! blocks the call (WS5-07.5).
//!
//! This module is the pure ledger + cost model + gate (WS5-07.1/.2/.3/.5). The
//! wiring to actual egress events (WS5-07.4), on-disk persistence (WS5-07.6 —
//! needs WS3 storage), and the Impact Dashboard surface (WS5-07.7) build on it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::router::ExecutionTier;

/// The privacy cost, in budget units, of one egress to `tier` (WS5-07.3).
///
/// Local execution is free (no egress). The cost grows as data travels further
/// from the device: personal cluster < federated mesh < commercial cloud.
#[must_use]
pub const fn egress_cost(tier: ExecutionTier) -> u64 {
    match tier {
        ExecutionTier::Local => 0,
        ExecutionTier::PersonalCluster => 1,
        ExecutionTier::FederatedMesh => 5,
        ExecutionTier::Cloud => 20,
    }
}

/// Identifies a budget holder: a user and the app acting on their behalf
/// (WS5-07.1, per-user/per-app).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BudgetHolder {
    /// The user id.
    pub user: u64,
    /// The app's stable identifier.
    pub app: String,
}

impl BudgetHolder {
    /// A holder for `user` running `app`.
    #[must_use]
    pub fn new(user: u64, app: impl Into<String>) -> Self {
        Self {
            user,
            app: app.into(),
        }
    }
}

/// A denied charge: applying it would overspend the remaining budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExhausted {
    /// Units requested.
    pub requested: u64,
    /// Units still available.
    pub remaining: u64,
}

impl core::fmt::Display for BudgetExhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "privacy budget exhausted: requested {} units, {} remaining",
            self.requested, self.remaining
        )
    }
}

impl core::error::Error for BudgetExhausted {}

/// One outbound egress the budget chokepoint is asked to authorize (WS5-07.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressEvent {
    /// Who the egress is charged to.
    pub holder: BudgetHolder,
    /// The execution tier the workload egresses to.
    pub tier: ExecutionTier,
    /// A human-readable destination label (provider/node), for the audit log.
    pub destination: String,
}

/// The receipt of an authorized egress: what was charged (WS5-07.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressReceipt {
    /// The tier charged for.
    pub tier: ExecutionTier,
    /// Budget units charged (0 for local egress).
    pub cost: u64,
}

/// A recorded, charged egress kept in the in-memory audit log (WS5-07.4). The
/// log is transient runtime state — only the durable budget (limits + spend) is
/// persisted across reboots (WS5-07.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChargedEgress {
    /// The tier egressed to.
    pub tier: ExecutionTier,
    /// Units charged.
    pub cost: u64,
    /// Destination label.
    pub destination: String,
}

/// Per-user/per-app privacy-budget ledger with atomic charging (WS5-07.1/.2).
///
/// Each holder has a limit (a per-holder override, else the ledger default) and
/// an accumulated spend. A charge succeeds only if it fits within the remaining
/// budget, so a partial overspend can never occur.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PrivacyLedger {
    default_limit: u64,
    limits: BTreeMap<BudgetHolder, u64>,
    spent: BTreeMap<BudgetHolder, u64>,
    /// Per-holder audit log of charged egress events (WS5-07.4). Transient —
    /// excluded from the persisted form, rebuilt as egress happens.
    #[serde(skip)]
    events: BTreeMap<BudgetHolder, Vec<ChargedEgress>>,
}

impl PrivacyLedger {
    /// A ledger granting every holder `default_limit` units per window.
    #[must_use]
    pub fn new(default_limit: u64) -> Self {
        Self {
            default_limit,
            limits: BTreeMap::new(),
            spent: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    /// Override the per-window limit for a specific holder.
    pub fn set_limit(&mut self, holder: &BudgetHolder, limit: u64) {
        self.limits.insert(holder.clone(), limit);
    }

    /// The limit for `holder` (its override, else the ledger default).
    #[must_use]
    pub fn limit_for(&self, holder: &BudgetHolder) -> u64 {
        self.limits
            .get(holder)
            .copied()
            .unwrap_or(self.default_limit)
    }

    /// Units already spent by `holder` this window.
    #[must_use]
    pub fn spent(&self, holder: &BudgetHolder) -> u64 {
        self.spent.get(holder).copied().unwrap_or(0)
    }

    /// Units still available to `holder`.
    #[must_use]
    pub fn remaining(&self, holder: &BudgetHolder) -> u64 {
        self.limit_for(holder).saturating_sub(self.spent(holder))
    }

    /// Atomically charge `amount` to `holder` (WS5-07.2): the spend is applied
    /// only if it fits within the remaining budget; otherwise nothing changes
    /// and [`BudgetExhausted`] is returned.
    ///
    /// # Errors
    ///
    /// [`BudgetExhausted`] if `amount` exceeds the remaining budget.
    pub fn try_charge(
        &mut self,
        holder: &BudgetHolder,
        amount: u64,
    ) -> Result<(), BudgetExhausted> {
        let remaining = self.remaining(holder);
        if amount > remaining {
            return Err(BudgetExhausted {
                requested: amount,
                remaining,
            });
        }
        let slot = self.spent.entry(holder.clone()).or_insert(0);
        *slot = slot.saturating_add(amount);
        Ok(())
    }

    /// Whether `holder` can afford one egress to `tier` without charging — the
    /// gate preview (WS5-07.5). Local is always affordable (free).
    #[must_use]
    pub fn can_afford_tier(&self, holder: &BudgetHolder, tier: ExecutionTier) -> bool {
        egress_cost(tier) <= self.remaining(holder)
    }

    /// Charge the egress cost of `tier` to `holder`, atomically (WS5-07.5).
    ///
    /// Local egress is free and always succeeds; a cloud (Tier-3) or mesh call
    /// on an exhausted budget is blocked.
    ///
    /// # Errors
    ///
    /// [`BudgetExhausted`] if the tier's egress cost exceeds the remaining
    /// budget.
    pub fn charge_for_tier(
        &mut self,
        holder: &BudgetHolder,
        tier: ExecutionTier,
    ) -> Result<(), BudgetExhausted> {
        self.try_charge(holder, egress_cost(tier))
    }

    /// Reset `holder`'s spend to zero (e.g. at the start of a new window).
    pub fn reset(&mut self, holder: &BudgetHolder) {
        self.spent.remove(holder);
    }

    // -------------------------------------------------------------------------
    // Egress-event chokepoint (WS5-07.4)
    // -------------------------------------------------------------------------

    /// Authorize and charge one egress event (WS5-07.4) — the single chokepoint
    /// the Tier-3/mesh egress path drives before letting data leave the device.
    ///
    /// Local egress is free and always authorized. A personal-cluster, mesh, or
    /// cloud egress charges [`egress_cost`] of its tier atomically; on success
    /// the event is recorded in the audit log and a receipt returned, and on an
    /// exhausted budget the call is **blocked** (`Err`) with nothing charged or
    /// recorded — so an over-budget Tier-3 call can never egress.
    ///
    /// # Errors
    ///
    /// [`BudgetExhausted`] if the tier's egress cost exceeds the remaining
    /// budget.
    pub fn charge_egress(&mut self, event: &EgressEvent) -> Result<EgressReceipt, BudgetExhausted> {
        let cost = egress_cost(event.tier);
        self.try_charge(&event.holder, cost)?;
        self.events
            .entry(event.holder.clone())
            .or_default()
            .push(ChargedEgress {
                tier: event.tier,
                cost,
                destination: event.destination.clone(),
            });
        Ok(EgressReceipt {
            tier: event.tier,
            cost,
        })
    }

    /// The recorded egress events charged to `holder` this session (WS5-07.4).
    #[must_use]
    pub fn events_for(&self, holder: &BudgetHolder) -> &[ChargedEgress] {
        self.events.get(holder).map_or(&[], Vec::as_slice)
    }

    // -------------------------------------------------------------------------
    // Persistence across reboots (WS5-07.6)
    // -------------------------------------------------------------------------

    /// Serialize the durable budget state (default limit, per-holder limits, and
    /// accumulated spend) to canonical bytes for on-disk persistence (WS5-07.6).
    ///
    /// The transient egress audit log is **not** persisted; only the budget
    /// state that must survive a reboot is. The encoding is canonical
    /// ([`nexacore_types::wire::encode_canonical`]), so the same ledger state
    /// always produces the same bytes.
    ///
    /// # Errors
    ///
    /// [`nexacore_types::error::NexaCoreError::Wire`] if encoding fails.
    pub fn to_bytes(&self) -> nexacore_types::error::Result<Vec<u8>> {
        nexacore_types::wire::encode_canonical(self)
    }

    /// Restore a ledger from bytes produced by [`to_bytes`](Self::to_bytes)
    /// (WS5-07.6). The restored ledger preserves limits and spend; the egress
    /// audit log starts empty.
    ///
    /// # Errors
    ///
    /// [`nexacore_types::error::NexaCoreError::Wire`] if the bytes cannot be
    /// decoded.
    pub fn from_bytes(bytes: &[u8]) -> nexacore_types::error::Result<Self> {
        nexacore_types::wire::decode_canonical(bytes)
    }

    // -------------------------------------------------------------------------
    // Impact Dashboard surface (WS5-07.7)
    // -------------------------------------------------------------------------

    /// The per-holder budget status for the Helper's Impact Dashboard
    /// (WS5-07.7): every holder with a configured limit or any spend, sorted by
    /// holder.
    #[must_use]
    pub fn dashboard(&self) -> Vec<BudgetStatus> {
        // Union of holders that have a limit override or have spent anything.
        let mut holders: Vec<&BudgetHolder> = self.limits.keys().chain(self.spent.keys()).collect();
        holders.sort_unstable();
        holders.dedup();
        holders
            .into_iter()
            .map(|h| {
                let limit = self.limit_for(h);
                let spent = self.spent(h);
                BudgetStatus {
                    holder: h.clone(),
                    limit,
                    spent,
                    remaining: self.remaining(h),
                    used_permille: permille(spent, limit),
                }
            })
            .collect()
    }
}

/// One row of the Impact Dashboard budget view (WS5-07.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetStatus {
    /// The budget holder.
    pub holder: BudgetHolder,
    /// The holder's budget limit (units).
    pub limit: u64,
    /// Units spent so far.
    pub spent: u64,
    /// Units still available.
    pub remaining: u64,
    /// Fraction of the budget used, in permille (0..=1000); 0 if the limit is 0.
    pub used_permille: u32,
}

/// `spent / limit` as permille (0 when `limit` is 0), saturating to 1000.
#[allow(
    clippy::integer_division,
    reason = "a permille gauge is an integer ratio; the truncation is intended"
)]
fn permille(spent: u64, limit: u64) -> u32 {
    if limit == 0 {
        return 0;
    }
    let pm = spent.saturating_mul(1000) / limit;
    u32::try_from(pm.min(1000)).unwrap_or(1000)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    fn holder() -> BudgetHolder {
        BudgetHolder::new(1, "chat")
    }

    #[test]
    fn egress_cost_is_ordered_by_distance_from_device() {
        assert_eq!(egress_cost(ExecutionTier::Local), 0);
        assert!(
            egress_cost(ExecutionTier::Local) < egress_cost(ExecutionTier::PersonalCluster)
                && egress_cost(ExecutionTier::PersonalCluster)
                    < egress_cost(ExecutionTier::FederatedMesh)
                && egress_cost(ExecutionTier::FederatedMesh) < egress_cost(ExecutionTier::Cloud)
        );
    }

    #[test]
    fn new_ledger_grants_default_limit() {
        let ledger = PrivacyLedger::new(100);
        let h = holder();
        assert_eq!(ledger.limit_for(&h), 100);
        assert_eq!(ledger.spent(&h), 0);
        assert_eq!(ledger.remaining(&h), 100);
    }

    #[test]
    fn try_charge_is_atomic_and_accumulates() {
        let mut ledger = PrivacyLedger::new(10);
        let h = holder();
        assert!(ledger.try_charge(&h, 4).is_ok());
        assert_eq!(ledger.remaining(&h), 6);
        assert!(ledger.try_charge(&h, 6).is_ok());
        assert_eq!(ledger.remaining(&h), 0);
        // Over-charge is rejected and changes nothing (atomic).
        assert_eq!(
            ledger.try_charge(&h, 1),
            Err(BudgetExhausted {
                requested: 1,
                remaining: 0
            })
        );
        assert_eq!(ledger.spent(&h), 10);
    }

    #[test]
    fn local_tier_is_always_free() {
        let mut ledger = PrivacyLedger::new(0);
        let h = holder();
        // Even with zero budget, local egress costs nothing and is allowed.
        assert!(ledger.can_afford_tier(&h, ExecutionTier::Local));
        assert!(ledger.charge_for_tier(&h, ExecutionTier::Local).is_ok());
    }

    #[test]
    fn cloud_call_blocked_when_budget_exhausted() {
        // WS5-07.5 (host analogue of the the test VM test .8): a Tier-3 call is
        // blocked once the budget cannot cover its egress cost.
        let mut ledger = PrivacyLedger::new(10); // Cloud costs 20 > 10
        let h = holder();
        assert!(!ledger.can_afford_tier(&h, ExecutionTier::Cloud));
        assert!(ledger.charge_for_tier(&h, ExecutionTier::Cloud).is_err());
        // Mesh (cost 5) is affordable twice, then exhausted.
        assert!(
            ledger
                .charge_for_tier(&h, ExecutionTier::FederatedMesh)
                .is_ok()
        );
        assert!(
            ledger
                .charge_for_tier(&h, ExecutionTier::FederatedMesh)
                .is_ok()
        );
        assert_eq!(ledger.remaining(&h), 0);
        assert!(
            ledger
                .charge_for_tier(&h, ExecutionTier::FederatedMesh)
                .is_err()
        );
    }

    #[test]
    fn per_holder_limit_override_and_reset() {
        let mut ledger = PrivacyLedger::new(10);
        let power_user = BudgetHolder::new(2, "research");
        ledger.set_limit(&power_user, 1000);
        assert_eq!(ledger.remaining(&power_user), 1000);
        assert!(ledger.try_charge(&power_user, 500).is_ok());
        assert_eq!(ledger.remaining(&power_user), 500);
        // A fresh window resets the spend.
        ledger.reset(&power_user);
        assert_eq!(ledger.remaining(&power_user), 1000);
    }

    #[test]
    fn holders_are_independent() {
        let mut ledger = PrivacyLedger::new(10);
        let a = BudgetHolder::new(1, "chat");
        let b = BudgetHolder::new(1, "mail"); // same user, different app
        assert!(ledger.try_charge(&a, 10).is_ok());
        // a is exhausted; b is untouched.
        assert_eq!(ledger.remaining(&a), 0);
        assert_eq!(ledger.remaining(&b), 10);
    }

    // -- WS5-07.4: egress-event chokepoint ------------------------------------

    fn egress(h: &BudgetHolder, tier: ExecutionTier, dst: &str) -> EgressEvent {
        EgressEvent {
            holder: h.clone(),
            tier,
            destination: dst.into(),
        }
    }

    #[test]
    fn charge_egress_charges_records_and_gates() {
        let mut ledger = PrivacyLedger::new(25);
        let h = holder();
        // A cloud egress (cost 20) is authorized, charged, and recorded.
        let receipt = ledger
            .charge_egress(&egress(&h, ExecutionTier::Cloud, "openai"))
            .expect("first cloud call fits the budget");
        assert_eq!(receipt.cost, 20);
        assert_eq!(ledger.spent(&h), 20);
        assert_eq!(ledger.events_for(&h).len(), 1);
        assert_eq!(ledger.events_for(&h)[0].destination, "openai");

        // A second cloud egress (another 20) exceeds the remaining 5 → blocked,
        // and neither the spend nor the audit log changes (fail-closed).
        let denied = ledger.charge_egress(&egress(&h, ExecutionTier::Cloud, "openai"));
        assert!(denied.is_err());
        assert_eq!(ledger.spent(&h), 20);
        assert_eq!(ledger.events_for(&h).len(), 1);
    }

    #[test]
    fn local_egress_is_free_and_recorded_at_zero_cost() {
        let mut ledger = PrivacyLedger::new(0); // zero budget
        let h = holder();
        // Local egress never touches the budget, so it is authorized even at 0.
        let receipt = ledger
            .charge_egress(&egress(&h, ExecutionTier::Local, "on-device"))
            .expect("local egress is always free");
        assert_eq!(receipt.cost, 0);
        assert_eq!(ledger.spent(&h), 0);
    }

    // -- WS5-07.6: persistence across reboots ---------------------------------

    #[test]
    fn ledger_round_trips_through_bytes() {
        let mut ledger = PrivacyLedger::new(100);
        let a = BudgetHolder::new(1, "chat");
        let b = BudgetHolder::new(2, "browser");
        ledger.set_limit(&b, 50);
        ledger.charge_for_tier(&a, ExecutionTier::Cloud).unwrap(); // a spends 20
        ledger
            .charge_for_tier(&b, ExecutionTier::FederatedMesh)
            .unwrap(); // b spends 5

        let bytes = ledger.to_bytes().expect("encode");
        let restored = PrivacyLedger::from_bytes(&bytes).expect("decode");

        // Durable state survives: default limit, per-holder limit, and spend.
        assert_eq!(restored.limit_for(&a), 100);
        assert_eq!(restored.limit_for(&b), 50);
        assert_eq!(restored.spent(&a), 20);
        assert_eq!(restored.spent(&b), 5);
        assert_eq!(restored.remaining(&a), 80);
    }

    #[test]
    fn persisted_form_is_deterministic_and_omits_transient_events() {
        let mut ledger = PrivacyLedger::new(100);
        let h = holder();
        ledger
            .charge_egress(&egress(&h, ExecutionTier::Cloud, "openai"))
            .unwrap();
        let first = ledger.to_bytes().expect("encode");
        // Re-encoding the same state is byte-identical (canonical).
        assert_eq!(first, ledger.to_bytes().expect("encode again"));
        // The transient audit log is not persisted: a restored ledger has none.
        let restored = PrivacyLedger::from_bytes(&first).expect("decode");
        assert!(restored.events_for(&h).is_empty());
        assert_eq!(restored.spent(&h), 20); // but the spend persists
    }

    // -- WS5-07.7: Impact Dashboard surface -----------------------------------

    #[test]
    fn dashboard_reports_each_holder_sorted_with_usage() {
        let mut ledger = PrivacyLedger::new(100);
        let a = BudgetHolder::new(1, "chat");
        let b = BudgetHolder::new(2, "browser");
        ledger.set_limit(&b, 40);
        ledger.charge_for_tier(&a, ExecutionTier::Cloud).unwrap(); // 20/100
        ledger.charge_for_tier(&b, ExecutionTier::Cloud).unwrap(); // 20/40

        let rows = ledger.dashboard();
        assert_eq!(rows.len(), 2);
        // Sorted by holder (user 1 before user 2).
        assert_eq!(rows[0].holder, a);
        assert_eq!(rows[0].used_permille, 200); // 20/100 = 200‰
        assert_eq!(rows[1].holder, b);
        assert_eq!(rows[1].limit, 40);
        assert_eq!(rows[1].remaining, 20);
        assert_eq!(rows[1].used_permille, 500); // 20/40 = 500‰
    }

    #[test]
    fn dashboard_skips_untouched_holders() {
        let ledger = PrivacyLedger::new(100);
        // No limits set, no spend → nothing to show.
        assert!(ledger.dashboard().is_empty());
    }
}
