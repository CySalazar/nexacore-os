//! NCIP-007 §7 — Decision audit logging.
//!
//! Every decision made by the Guidance Agent — autonomy level resolution,
//! escalation classification, veto explanation, undo operations — is
//! appended to an in-memory audit log.
//!
//! Phase 2: the log is in-memory (Vec). Phase 3 will replace this with a
//! Merkle-chained, persistent audit store as described in the security model
//! (`docs/04-security-model.md` § Audit log).
//!
//! The log is append-only: entries can never be removed or modified. Any
//! future persistence layer MUST maintain this invariant.
//!
//! See NCIP-007 §7 and NCIP-Agent-Arch-022 §S4.

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{agent::AgentKind, mode::OperationalMode};

/// A single decision recorded in the audit log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The agent that made the decision.
    pub agent_id: AgentKind,
    /// The action that was evaluated.
    pub action: String,
    /// The decision reached (e.g. "approved", "vetoed", "escalated").
    pub decision: String,
    /// Reasoning behind the decision (in plain English).
    pub reasoning: String,
    /// Unix timestamp (seconds) when the decision was recorded.
    pub timestamp: u64,
    /// Operational mode at decision time.
    pub mode: OperationalMode,
}

impl AuditEntry {
    /// Construct a new audit entry.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{agent::AgentKind, guidance::audit::AuditEntry, mode::OperationalMode};
    ///
    /// let entry = AuditEntry::new(
    ///     AgentKind::Guidance,
    ///     "install Firefox",
    ///     "approved",
    ///     "no escalation class matched",
    ///     0,
    ///     OperationalMode::Standard,
    /// );
    /// assert_eq!(entry.decision, "approved");
    /// ```
    #[must_use]
    pub fn new(
        agent_id: AgentKind,
        action: impl Into<String>,
        decision: impl Into<String>,
        reasoning: impl Into<String>,
        timestamp: u64,
        mode: OperationalMode,
    ) -> Self {
        Self {
            agent_id,
            action: action.into(),
            decision: decision.into(),
            reasoning: reasoning.into(),
            timestamp,
            mode,
        }
    }
}

/// Append-only in-memory audit log.
///
/// Phase 2 stores entries in a `Vec`. A later sprint integrates Merkle
/// chaining and persistent storage. The append-only contract is enforced
/// by the public API (no `remove` or `clear` methods are exposed).
#[derive(Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Create a new, empty audit log.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::audit::AuditLog;
    ///
    /// let log = AuditLog::new();
    /// assert_eq!(log.entry_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append a new entry to the log.
    ///
    /// This is the only mutation operation; entries are never removed.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{
    ///     agent::AgentKind,
    ///     guidance::audit::{AuditEntry, AuditLog},
    ///     mode::OperationalMode,
    /// };
    ///
    /// let mut log = AuditLog::new();
    /// log.log_decision(AuditEntry::new(
    ///     AgentKind::Guidance,
    ///     "install Firefox",
    ///     "approved",
    ///     "no escalation",
    ///     0,
    ///     OperationalMode::Standard,
    /// ));
    /// assert_eq!(log.entry_count(), 1);
    /// ```
    pub fn log_decision(&mut self, entry: AuditEntry) {
        info!(
            agent = ?entry.agent_id,
            action = %entry.action,
            decision = %entry.decision,
            ts = entry.timestamp,
            "audit: decision recorded"
        );
        self.entries.push(entry);
    }

    /// Returns all entries with a timestamp >= `since`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::{
    ///     agent::AgentKind,
    ///     guidance::audit::{AuditEntry, AuditLog},
    ///     mode::OperationalMode,
    /// };
    ///
    /// let mut log = AuditLog::new();
    /// log.log_decision(AuditEntry::new(
    ///     AgentKind::Guidance,
    ///     "a",
    ///     "ok",
    ///     "",
    ///     10,
    ///     OperationalMode::Standard,
    /// ));
    /// log.log_decision(AuditEntry::new(
    ///     AgentKind::Guidance,
    ///     "b",
    ///     "ok",
    ///     "",
    ///     20,
    ///     OperationalMode::Standard,
    /// ));
    /// let recent = log.entries_since(15);
    /// assert_eq!(recent.len(), 1);
    /// assert_eq!(recent[0].timestamp, 20);
    /// ```
    #[must_use]
    pub fn entries_since(&self, since: u64) -> &[AuditEntry] {
        // `partition_point` returns a value in `[0, len]`, so `.get(start..)`
        // always succeeds; the fallback to `&[]` is unreachable but satisfies
        // the borrow checker without unsafe indexing.
        let start = self.entries.partition_point(|e| e.timestamp < since);
        self.entries.get(start..).unwrap_or(&[])
    }

    /// Returns the total number of entries in the log.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns a slice of all log entries.
    #[must_use]
    pub fn all_entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agent::AgentKind, mode::OperationalMode};

    fn make_entry(action: &str, ts: u64) -> AuditEntry {
        AuditEntry::new(
            AgentKind::Guidance,
            action,
            "approved",
            "test",
            ts,
            OperationalMode::Standard,
        )
    }

    #[test]
    fn new_log_is_empty() {
        let log = AuditLog::new();
        assert_eq!(log.entry_count(), 0);
    }

    #[test]
    fn log_decision_increases_count() {
        let mut log = AuditLog::new();
        log.log_decision(make_entry("action1", 1));
        assert_eq!(log.entry_count(), 1);
        log.log_decision(make_entry("action2", 2));
        assert_eq!(log.entry_count(), 2);
    }

    #[test]
    fn append_only_no_removal() {
        // The public API does not expose any method to remove entries.
        // This test documents the contract by verifying count only grows.
        let mut log = AuditLog::new();
        for i in 0..10u64 {
            log.log_decision(make_entry("a", i));
        }
        assert_eq!(log.entry_count(), 10);
    }

    #[test]
    fn entries_since_filters_correctly() {
        let mut log = AuditLog::new();
        log.log_decision(make_entry("early", 5));
        log.log_decision(make_entry("mid", 10));
        log.log_decision(make_entry("late", 20));

        let slice = log.entries_since(10);
        assert_eq!(slice.len(), 2);
        assert_eq!(slice[0].action, "mid");
        assert_eq!(slice[1].action, "late");
    }

    #[test]
    fn entries_since_zero_returns_all() {
        let mut log = AuditLog::new();
        log.log_decision(make_entry("a", 1));
        log.log_decision(make_entry("b", 2));
        assert_eq!(log.entries_since(0).len(), 2);
    }

    #[test]
    fn entries_since_future_returns_empty() {
        let mut log = AuditLog::new();
        log.log_decision(make_entry("a", 1));
        assert!(log.entries_since(9999).is_empty());
    }

    #[test]
    fn all_entries_returns_all() {
        let mut log = AuditLog::new();
        for i in 0..5u64 {
            log.log_decision(make_entry("x", i));
        }
        assert_eq!(log.all_entries().len(), 5);
    }

    #[test]
    fn entry_fields_are_preserved() {
        let mut log = AuditLog::new();
        let entry = AuditEntry::new(
            AgentKind::Security,
            "veto action",
            "vetoed",
            "policy violated",
            42,
            OperationalMode::HighRisk,
        );
        log.log_decision(entry);
        let stored = &log.all_entries()[0];
        assert_eq!(stored.agent_id, AgentKind::Security);
        assert_eq!(stored.action, "veto action");
        assert_eq!(stored.decision, "vetoed");
        assert_eq!(stored.reasoning, "policy violated");
        assert_eq!(stored.timestamp, 42);
        assert_eq!(stored.mode, OperationalMode::HighRisk);
    }
}
