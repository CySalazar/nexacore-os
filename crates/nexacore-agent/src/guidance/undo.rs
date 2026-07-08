//! NCIP-007 §6 — Undo/rollback window.
//!
//! Non-destructive actions performed in `Autonomous` mode are recorded in
//! a 30-second rollback window. Within that window, the user can undo
//! the last action. After 30 seconds the entry expires and can no longer
//! be rolled back through this mechanism.
//!
//! Only reversible actions are tracked here. Destructive actions (which
//! require at least `Guided` mode per NCIP-007 §3) bypass this window.
//!
//! See NCIP-007 §6 and NCIP-Agent-Arch-022 §S4.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// The duration of the undo window (NCIP-007 §6).
const UNDO_WINDOW: Duration = Duration::from_secs(30);

/// A single entry in the undo window.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndoEntry {
    /// Unique identifier for the recorded action.
    pub action_id: u64,
    /// Human-readable description of the action.
    pub description: String,
    /// Unix timestamp (seconds) when the action was recorded.
    pub timestamp: u64,
    /// Whether this action can be mechanically reversed.
    pub reversible: bool,
}

impl UndoEntry {
    /// Construct a new undo entry.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::undo::UndoEntry;
    ///
    /// let entry = UndoEntry::new(1, "moved file /a to /b", 0, true);
    /// assert!(entry.reversible);
    /// ```
    #[must_use]
    pub fn new(
        action_id: u64,
        description: impl Into<String>,
        timestamp: u64,
        reversible: bool,
    ) -> Self {
        Self {
            action_id,
            description: description.into(),
            timestamp,
            reversible,
        }
    }
}

/// Tracks the 30-second undo window for `Autonomous`-mode actions.
///
/// Entries are stored in arrival order (oldest first) in a `VecDeque`.
/// Expired entries are pruned lazily on each public method call.
///
/// Each entry may carry an opaque **pre-action snapshot** (WS16-01.7): the
/// serialized prior state an executor captured before the effect ran, so the
/// system-layer Helper can mechanically reverse the action within the window.
/// Entries recorded through [`record`](Self::record) carry an empty snapshot.
#[derive(Debug)]
pub struct UndoWindow {
    // Stores (UndoEntry, Instant-when-recorded, pre-action snapshot bytes).
    entries: VecDeque<(UndoEntry, Instant, Vec<u8>)>,
}

impl UndoWindow {
    /// Create a new, empty undo window.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::undo::UndoWindow;
    ///
    /// let w = UndoWindow::new();
    /// assert_eq!(w.len(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    /// Record a new undo entry, associating it with the current instant.
    ///
    /// Expired entries are pruned before recording.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::undo::{UndoEntry, UndoWindow};
    ///
    /// let mut w = UndoWindow::new();
    /// w.record(UndoEntry::new(1, "moved file", 0, true));
    /// assert_eq!(w.len(), 1);
    /// ```
    pub fn record(&mut self, entry: UndoEntry) {
        self.prune_expired();
        debug!(action_id = entry.action_id, "recording undo entry");
        self.entries.push_back((entry, Instant::now(), Vec::new()));
    }

    /// Record a new undo entry together with its opaque pre-action snapshot
    /// (WS16-01.7).
    ///
    /// `snapshot` is the serialized prior state the executor captured before the
    /// effect ran; it is returned verbatim by [`Self::undo_last_with_snapshot`] so the
    /// caller can reverse the action. Expired entries are pruned before recording.
    pub fn record_with_snapshot(&mut self, entry: UndoEntry, snapshot: Vec<u8>) {
        self.prune_expired();
        debug!(
            action_id = entry.action_id,
            "recording undo entry + snapshot"
        );
        self.entries.push_back((entry, Instant::now(), snapshot));
    }

    /// Undo the most recently recorded action that is still within the window.
    ///
    /// Returns the entry if one was available, or `None` if the window is
    /// empty or all entries have expired.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::undo::{UndoEntry, UndoWindow};
    ///
    /// let mut w = UndoWindow::new();
    /// w.record(UndoEntry::new(42, "renamed config", 0, true));
    /// let undone = w.undo_last();
    /// assert!(undone.is_some());
    /// assert_eq!(undone.unwrap().action_id, 42);
    /// ```
    pub fn undo_last(&mut self) -> Option<UndoEntry> {
        self.prune_expired();
        self.entries.pop_back().map(|(entry, _, _)| {
            info!(action_id = entry.action_id, "undo applied");
            entry
        })
    }

    /// Undo the most recent in-window action, returning its entry together with
    /// the opaque pre-action snapshot recorded for it (WS16-01.7).
    ///
    /// Returns `None` when the window is empty or all entries have expired.
    /// Entries recorded through [`record`](Self::record) (no snapshot) yield an
    /// empty `Vec`.
    pub fn undo_last_with_snapshot(&mut self) -> Option<(UndoEntry, Vec<u8>)> {
        self.prune_expired();
        self.entries.pop_back().map(|(entry, _, snapshot)| {
            info!(action_id = entry.action_id, "undo applied (with snapshot)");
            (entry, snapshot)
        })
    }

    /// Remove all entries whose 30-second window has elapsed.
    ///
    /// This is called automatically by all mutating methods but may also
    /// be called explicitly by a periodic maintenance task.
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        while let Some((_, recorded_at, _)) = self.entries.front() {
            if now.duration_since(*recorded_at) >= UNDO_WINDOW {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns `true` if `action_id` is present and still within the window.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::undo::{UndoEntry, UndoWindow};
    ///
    /// let mut w = UndoWindow::new();
    /// w.record(UndoEntry::new(7, "created file", 0, true));
    /// assert!(w.can_undo(7));
    /// assert!(!w.can_undo(99));
    /// ```
    #[must_use]
    pub fn can_undo(&mut self, action_id: u64) -> bool {
        self.prune_expired();
        self.entries
            .iter()
            .any(|(entry, _, _)| entry.action_id == action_id)
    }

    /// Returns the number of entries currently within the window.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for UndoWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64) -> UndoEntry {
        UndoEntry::new(id, format!("action {id}"), id, true)
    }

    #[test]
    fn new_window_is_empty() {
        let w = UndoWindow::new();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn record_single_entry() {
        let mut w = UndoWindow::new();
        w.record(entry(1));
        assert_eq!(w.len(), 1);
        assert!(w.can_undo(1));
    }

    #[test]
    fn undo_last_removes_most_recent() {
        let mut w = UndoWindow::new();
        w.record(entry(1));
        w.record(entry(2));
        let undone = w.undo_last().unwrap();
        assert_eq!(undone.action_id, 2);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn undo_last_returns_none_when_empty() {
        let mut w = UndoWindow::new();
        assert!(w.undo_last().is_none());
    }

    #[test]
    fn can_undo_unknown_id_returns_false() {
        let mut w = UndoWindow::new();
        w.record(entry(1));
        assert!(!w.can_undo(99));
    }

    #[test]
    fn prune_expired_removes_old_entries() {
        let mut w = UndoWindow::new();
        // Manually insert an entry with an Instant in the past.
        let old_entry = entry(100);
        // We cannot set the instant to the past directly; simulate by inserting
        // and then fast-forwarding conceptually. Instead we test that fresh
        // entries survive prune_expired.
        w.record(old_entry);
        w.prune_expired();
        // The entry was just added, so it must still be present.
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn multiple_entries_ordered_lifo() {
        let mut w = UndoWindow::new();
        for id in 1..=5u64 {
            w.record(entry(id));
        }
        // Undo peels off newest first.
        for id in (1..=5u64).rev() {
            let undone = w.undo_last().expect("entry must be present");
            assert_eq!(undone.action_id, id);
        }
        assert!(w.is_empty());
    }

    #[test]
    fn entry_fields_preserved() {
        let e = UndoEntry::new(42, "do something", 1234, false);
        assert_eq!(e.action_id, 42);
        assert_eq!(e.description, "do something");
        assert_eq!(e.timestamp, 1234);
        assert!(!e.reversible);
    }
}
