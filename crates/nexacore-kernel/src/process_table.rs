//! Kernel process table — parent-child tracking and wait/exit bookkeeping.
//!
//! This module is intentionally **not** gated behind the `bare-metal`
//! feature so the wait/exit logic is exercisable in host-side unit tests
//! without needing the full page-table / ELF-loader infrastructure.
//!
//! ## Design rationale
//!
//! The [`crate::process_table::ProcessTable`] is a flat `BTreeMap<u64, ProcessEntry>` keyed on
//! `TaskId.0`. A `BTreeMap` is chosen over `HashMap` because:
//!
//! - It is available from `alloc` with no additional dependencies and
//!   compiles on `x86_64-unknown-none`.
//! - Iteration order is deterministic (ascending by key), which simplifies
//!   both `list()` and `reap_child()` — the oldest child (lowest `TaskId`)
//!   is reaped first, giving a stable and auditable wait-queue order.
//! - `O(log n)` lookup is acceptable for Phase 1 process counts
//!   (hundreds, not millions).
//!
//! ## Wait / exit protocol
//!
//! 1. A process calls `record_exit` when it terminates. The entry's
//!    `exit_code` is set and the parent's `children` list is retained so
//!    `reap_child` can find it.
//! 2. The parent calls `reap_child`. The first exited child in the
//!    parent's `children` list is removed from the table and its
//!    `(TaskId, exit_code)` pair is returned.
//! 3. Zombie avoidance: if the parent exits before the child, the child
//!    becomes an orphan (parent `None`). The `record_exit` return value
//!    will be `None` in that case, so the scheduler knows it does not need
//!    to wake anyone.
//!
//! ## Thread safety
//!
//! `ProcessTable` is not `Sync`. In the bare-metal kernel it lives behind
//! the existing `SCHED_LOCK` spinlock (see `scheduling::SCHED_LOCK`). In
//! host tests each test owns its own local instance, so no additional
//! synchronisation is required.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use crate::scheduling::TaskId;

// ---------------------------------------------------------------------------
// ProcessEntry
// ---------------------------------------------------------------------------

/// A single entry in the kernel process table.
///
/// This is kept separate from `crate::process::ProcessControlBlock`
/// because the PCB is only available under `feature = "bare-metal"` (it
/// holds raw page-table pointers and ELF metadata), whereas the wait/exit
/// bookkeeping must be testable on host builds.
///
/// # Fields
///
/// All fields are `pub` so the scheduler and syscall handlers can read
/// them directly without going through an accessor for every attribute.
/// Mutation is expected to go through the [`ProcessTable`] methods to keep
/// the parent-child invariants intact.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    /// Kernel-side task identifier for this process.
    pub id: TaskId,
    /// Parent task ID. `None` for the init process or an orphaned process
    /// whose parent exited before it did.
    pub parent: Option<TaskId>,
    /// Task IDs of child processes spawned from this one. Entries are
    /// removed when the child is reaped by [`ProcessTable::reap_child`].
    pub children: Vec<TaskId>,
    /// Exit code recorded by [`ProcessTable::record_exit`]. `None` while
    /// the process is still running.
    pub exit_code: Option<u64>,
    /// Absolute path of the process's current working directory. Starts
    /// at `"/"` for every freshly registered process; updated by
    /// [`ProcessTable::set_cwd`].
    pub cwd: String,
    /// Human-readable process name (binary base-name or thread label).
    pub name: String,
}

// ---------------------------------------------------------------------------
// ProcessTable
// ---------------------------------------------------------------------------

/// Kernel process table for parent-child tracking and wait/exit.
///
/// Holds one [`ProcessEntry`] per live or zombie process. A process is
/// removed from the table only when:
///
/// - Its parent calls [`reap_child`](ProcessTable::reap_child) (normal
///   path), **or**
/// - [`remove`](ProcessTable::remove) is called explicitly (cleanup path
///   for orphans after init reaping).
///
/// # Example
///
/// ```
/// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
///
/// let mut table = ProcessTable::new();
/// table.register(TaskId(1), None, "init".into());
/// table.register(TaskId(2), Some(TaskId(1)), "shell".into());
///
/// // Shell exits with code 0.
/// let parent_id = table.record_exit(TaskId(2), 0);
/// assert_eq!(parent_id, Some(TaskId(1)));
///
/// // Init reaps the shell.
/// let reaped = table.reap_child(TaskId(1));
/// assert_eq!(reaped, Some((TaskId(2), 0)));
/// ```
#[derive(Debug)]
pub struct ProcessTable {
    /// Map from `TaskId.0` to the corresponding process entry.
    ///
    /// `BTreeMap` gives deterministic ordering (ascending `TaskId`) so
    /// `reap_child` always returns the oldest exited child — a simpler
    /// invariant than "first exited" which would require a timestamp.
    entries: BTreeMap<u64, ProcessEntry>,
}

impl ProcessTable {
    /// Create an empty process table.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::process_table::ProcessTable;
    /// let table = ProcessTable::new();
    /// assert!(table.list().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Register a new process in the table.
    ///
    /// The new entry starts with:
    /// - `exit_code = None` (process is running)
    /// - `cwd = "/"`
    /// - `children = []`
    ///
    /// If `parent` is `Some(p)` and `p` is already in the table, `id` is
    /// appended to `p`'s `children` list. If the parent entry does not
    /// exist (e.g. it has already been reaped), the child is still
    /// registered with `parent = Some(p)` so the caller can observe the
    /// intended lineage; but the parent's children list is not modified
    /// (it is gone).
    ///
    /// Calling `register` with a `TaskId` that is already in the table
    /// silently overwrites the previous entry. Callers are responsible for
    /// ensuring uniqueness of `id` (the scheduler's monotone counter
    /// guarantees this in practice).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
    ///
    /// let mut table = ProcessTable::new();
    /// table.register(TaskId(1), None, "init".into());
    /// assert!(table.get(TaskId(1)).is_some());
    /// ```
    pub fn register(&mut self, id: TaskId, parent: Option<TaskId>, name: String) {
        // Insert the new entry first so a self-parent edge (degenerate
        // case) does not cause a double-borrow.
        self.entries.insert(
            id.0,
            ProcessEntry {
                id,
                parent,
                children: Vec::new(),
                exit_code: None,
                cwd: String::from("/"),
                name,
            },
        );
        // Wire up the parent → child link, if the parent exists.
        if let Some(parent_id) = parent {
            if let Some(parent_entry) = self.entries.get_mut(&parent_id.0) {
                parent_entry.children.push(id);
            }
        }
    }

    /// Record that process `id` has exited with the given `exit_code`.
    ///
    /// Returns `Some(parent_id)` if the process has a registered parent
    /// (so the scheduler can wake the parent from a `WaitPid` block).
    /// Returns `None` if the process is an orphan (no parent in the table).
    ///
    /// This method **does not** remove the entry from the table — the
    /// entry becomes a zombie and must be collected by the parent via
    /// [`reap_child`](Self::reap_child) or by an explicit
    /// [`remove`](Self::remove) call.
    ///
    /// If `id` is not in the table the method is a no-op and returns
    /// `None`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
    ///
    /// let mut table = ProcessTable::new();
    /// table.register(TaskId(10), None, "init".into());
    /// table.register(TaskId(11), Some(TaskId(10)), "worker".into());
    ///
    /// let wakeup = table.record_exit(TaskId(11), 42);
    /// assert_eq!(wakeup, Some(TaskId(10)));
    /// assert_eq!(table.get(TaskId(11)).unwrap().exit_code, Some(42));
    /// ```
    pub fn record_exit(&mut self, id: TaskId, exit_code: u64) -> Option<TaskId> {
        let entry = self.entries.get_mut(&id.0)?;
        entry.exit_code = Some(exit_code);
        // Return the parent TaskId so the caller can unblock a waiting parent.
        // We look up the parent field from the now-mutated entry.
        entry.parent
    }

    /// Check whether any child of `parent` has exited; if so, reap it.
    ///
    /// Scans `parent`'s `children` list in ascending `TaskId` order
    /// (smallest ID first) for the first entry whose `exit_code` is
    /// `Some`. When found:
    ///
    /// 1. The child entry is removed from the table.
    /// 2. The child's ID is removed from `parent`'s `children` list.
    /// 3. `Some((child_id, exit_code))` is returned.
    ///
    /// Returns `None` if:
    /// - `parent` has no children, or
    /// - no child has exited yet (all are still running), or
    /// - `parent` is not in the table.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
    ///
    /// let mut table = ProcessTable::new();
    /// table.register(TaskId(1), None, "init".into());
    /// table.register(TaskId(2), Some(TaskId(1)), "child".into());
    /// table.record_exit(TaskId(2), 7);
    ///
    /// assert_eq!(table.reap_child(TaskId(1)), Some((TaskId(2), 7)));
    /// assert!(table.get(TaskId(2)).is_none());
    /// assert!(table.reap_child(TaskId(1)).is_none());
    /// ```
    pub fn reap_child(&mut self, parent: TaskId) -> Option<(TaskId, u64)> {
        // Clone the children Vec to release the immutable borrow on `entries`
        // before the subsequent mutable remove + retain calls below.
        let child_ids: Vec<TaskId> = self.entries.get(&parent.0)?.children.clone();

        // Find the first child (lowest TaskId — BTreeMap sort order) that
        // has already exited. Because `child_ids` was collected from a Vec
        // (insertion order), we sort by TaskId so the oldest child is
        // always reaped first, giving a deterministic reap order.
        let mut sorted_child_ids = child_ids;
        sorted_child_ids.sort_unstable_by_key(|t| t.0);

        let (child_id, exit_code) = sorted_child_ids.iter().find_map(|&cid| {
            let entry = self.entries.get(&cid.0)?;
            entry.exit_code.map(|code| (cid, code))
        })?;

        // Remove the child entry from the table (reaping completes here).
        self.entries.remove(&child_id.0);

        // Remove the child from the parent's children list.
        if let Some(parent_entry) = self.entries.get_mut(&parent.0) {
            parent_entry.children.retain(|&id| id.0 != child_id.0);
        }

        Some((child_id, exit_code))
    }

    /// Look up a process entry by `TaskId`.
    ///
    /// Returns `None` if no such process is registered.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
    ///
    /// let mut table = ProcessTable::new();
    /// table.register(TaskId(5), None, "proc".into());
    /// assert_eq!(table.get(TaskId(5)).unwrap().id, TaskId(5));
    /// assert!(table.get(TaskId(99)).is_none());
    /// ```
    #[must_use]
    pub fn get(&self, id: TaskId) -> Option<&ProcessEntry> {
        self.entries.get(&id.0)
    }

    /// Look up a process entry mutably by `TaskId`.
    ///
    /// Returns `None` if no such process is registered.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
    ///
    /// let mut table = ProcessTable::new();
    /// table.register(TaskId(3), None, "svc".into());
    /// let entry = table.get_mut(TaskId(3)).unwrap();
    /// entry.name = "svc-renamed".into();
    /// assert_eq!(table.get(TaskId(3)).unwrap().name, "svc-renamed");
    /// ```
    pub fn get_mut(&mut self, id: TaskId) -> Option<&mut ProcessEntry> {
        self.entries.get_mut(&id.0)
    }

    /// Return the current working directory of process `id`.
    ///
    /// Returns `None` if no such process is registered.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
    ///
    /// let mut table = ProcessTable::new();
    /// table.register(TaskId(1), None, "sh".into());
    /// assert_eq!(table.get_cwd(TaskId(1)), Some("/"));
    /// ```
    #[must_use]
    pub fn get_cwd(&self, id: TaskId) -> Option<&str> {
        self.entries.get(&id.0).map(|e| e.cwd.as_str())
    }

    /// Update the current working directory of process `id`.
    ///
    /// Returns `true` if the update succeeded, `false` if no such process
    /// is registered (the caller should surface `ESRCH` to userspace in
    /// that case).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
    ///
    /// let mut table = ProcessTable::new();
    /// table.register(TaskId(1), None, "sh".into());
    /// assert!(table.set_cwd(TaskId(1), "/usr/local".into()));
    /// assert_eq!(table.get_cwd(TaskId(1)), Some("/usr/local"));
    /// assert!(!table.set_cwd(TaskId(999), "/nowhere".into()));
    /// ```
    pub fn set_cwd(&mut self, id: TaskId, cwd: String) -> bool {
        match self.entries.get_mut(&id.0) {
            Some(entry) => {
                entry.cwd = cwd;
                true
            }
            None => false,
        }
    }

    /// Return a `Vec` of references to all entries in ascending `TaskId`
    /// order. Useful for implementing the `ProcessList` syscall (`ps`).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
    ///
    /// let mut table = ProcessTable::new();
    /// table.register(TaskId(1), None, "init".into());
    /// table.register(TaskId(2), Some(TaskId(1)), "shell".into());
    /// let list = table.list();
    /// assert_eq!(list.len(), 2);
    /// assert_eq!(list[0].id, TaskId(1));
    /// assert_eq!(list[1].id, TaskId(2));
    /// ```
    #[must_use]
    pub fn list(&self) -> Vec<&ProcessEntry> {
        // BTreeMap iterates in ascending key order, so the output is
        // always sorted by TaskId without an explicit sort step.
        self.entries.values().collect()
    }

    /// Remove a fully-reaped process entry from the table.
    ///
    /// Returns `true` if an entry was found and removed, `false` if no
    /// entry with `id` exists.
    ///
    /// This is the cleanup path for orphaned processes (whose parent has
    /// already exited) and for any case where the scheduler tears down a
    /// process without waiting for a `reap_child` call (e.g. `SIGKILL`
    /// handling in future milestones).
    ///
    /// Note: this method does **not** remove `id` from its parent's
    /// `children` list. If the parent is still alive, the caller is
    /// responsible for also calling `get_mut(parent_id).children.retain`
    /// as needed. For the normal wait/exit path use
    /// [`reap_child`](Self::reap_child) instead.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::{process_table::ProcessTable, scheduling::TaskId};
    ///
    /// let mut table = ProcessTable::new();
    /// table.register(TaskId(7), None, "daemon".into());
    /// assert!(table.remove(TaskId(7)));
    /// assert!(table.get(TaskId(7)).is_none());
    /// assert!(!table.remove(TaskId(7)));
    /// ```
    pub fn remove(&mut self, id: TaskId) -> bool {
        self.entries.remove(&id.0).is_some()
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions use direct index access for clarity; panics are the intended failure mode"
)]
mod tests {
    use super::*;

    // Helper: build a table with init(1) → shell(2) → editor(3).
    fn three_level_table() -> ProcessTable {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "shell".into());
        t.register(TaskId(3), Some(TaskId(2)), "editor".into());
        t
    }

    // -----------------------------------------------------------------------
    // register / get
    // -----------------------------------------------------------------------

    #[test]
    fn register_creates_entry_with_correct_parent_none() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        let e = t.get(TaskId(1)).expect("init must be registered");
        assert_eq!(e.id, TaskId(1));
        assert_eq!(e.parent, None);
        assert_eq!(e.name, "init");
    }

    #[test]
    fn register_creates_entry_with_correct_parent_some() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "shell".into());
        let e = t.get(TaskId(2)).expect("shell must be registered");
        assert_eq!(e.parent, Some(TaskId(1)));
    }

    #[test]
    fn register_adds_child_to_parent_children_list() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "shell".into());
        let parent = t.get(TaskId(1)).expect("init present");
        assert!(parent.children.contains(&TaskId(2)));
    }

    #[test]
    fn register_multiple_children_all_appear_in_parent_list() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "child-a".into());
        t.register(TaskId(3), Some(TaskId(1)), "child-b".into());
        t.register(TaskId(4), Some(TaskId(1)), "child-c".into());
        let parent = t.get(TaskId(1)).expect("init present");
        assert_eq!(parent.children.len(), 3);
        assert!(parent.children.contains(&TaskId(2)));
        assert!(parent.children.contains(&TaskId(3)));
        assert!(parent.children.contains(&TaskId(4)));
    }

    #[test]
    fn fresh_entry_has_default_cwd_slash() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        assert_eq!(t.get(TaskId(1)).unwrap().cwd, "/");
    }

    #[test]
    fn fresh_entry_has_empty_children_vec() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        assert!(t.get(TaskId(1)).unwrap().children.is_empty());
    }

    #[test]
    fn fresh_entry_has_none_exit_code() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        assert_eq!(t.get(TaskId(1)).unwrap().exit_code, None);
    }

    #[test]
    fn get_returns_none_for_absent_id() {
        let t = ProcessTable::new();
        assert!(t.get(TaskId(999)).is_none());
    }

    // -----------------------------------------------------------------------
    // record_exit
    // -----------------------------------------------------------------------

    #[test]
    fn record_exit_stores_exit_code() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "worker".into());
        t.record_exit(TaskId(2), 42);
        assert_eq!(t.get(TaskId(2)).unwrap().exit_code, Some(42));
    }

    #[test]
    fn record_exit_returns_parent_task_id() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "worker".into());
        let parent = t.record_exit(TaskId(2), 0);
        assert_eq!(parent, Some(TaskId(1)));
    }

    #[test]
    fn record_exit_returns_none_for_orphan() {
        let mut t = ProcessTable::new();
        t.register(TaskId(5), None, "orphan".into());
        let parent = t.record_exit(TaskId(5), 1);
        assert_eq!(parent, None);
    }

    #[test]
    fn record_exit_returns_none_for_absent_id() {
        let mut t = ProcessTable::new();
        let result = t.record_exit(TaskId(99), 0);
        assert_eq!(result, None);
    }

    #[test]
    fn record_exit_does_not_remove_entry() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.record_exit(TaskId(1), 0);
        assert!(t.get(TaskId(1)).is_some());
    }

    // -----------------------------------------------------------------------
    // reap_child
    // -----------------------------------------------------------------------

    #[test]
    fn reap_child_returns_exited_child() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "child".into());
        t.record_exit(TaskId(2), 7);
        assert_eq!(t.reap_child(TaskId(1)), Some((TaskId(2), 7)));
    }

    #[test]
    fn reap_child_removes_child_from_table() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "child".into());
        t.record_exit(TaskId(2), 0);
        t.reap_child(TaskId(1));
        assert!(t.get(TaskId(2)).is_none());
    }

    #[test]
    fn reap_child_removes_child_id_from_parent_children_list() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "child".into());
        t.record_exit(TaskId(2), 0);
        t.reap_child(TaskId(1));
        assert!(t.get(TaskId(1)).unwrap().children.is_empty());
    }

    #[test]
    fn reap_child_returns_none_when_no_child_exited() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "child".into());
        // Child has NOT exited yet.
        assert_eq!(t.reap_child(TaskId(1)), None);
    }

    #[test]
    fn reap_child_returns_none_for_absent_parent() {
        let mut t = ProcessTable::new();
        assert_eq!(t.reap_child(TaskId(999)), None);
    }

    #[test]
    fn reap_child_multiple_children_reaps_oldest_first() {
        // Three children; middle one exits first in real time, but we
        // record exits for 4 and 2 (ascending id order).  Reap must
        // return TaskId(2) first (smallest exited id), then TaskId(4).
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "init".into());
        t.register(TaskId(2), Some(TaskId(1)), "a".into());
        t.register(TaskId(3), Some(TaskId(1)), "b".into());
        t.register(TaskId(4), Some(TaskId(1)), "c".into());
        // Exit 4 and 2; leave 3 running.
        t.record_exit(TaskId(4), 10);
        t.record_exit(TaskId(2), 20);

        // Oldest exited child by TaskId should come first.
        assert_eq!(t.reap_child(TaskId(1)), Some((TaskId(2), 20)));
        assert_eq!(t.reap_child(TaskId(1)), Some((TaskId(4), 10)));
        // Child 3 still running — nothing to reap.
        assert_eq!(t.reap_child(TaskId(1)), None);
    }

    // -----------------------------------------------------------------------
    // get_cwd / set_cwd
    // -----------------------------------------------------------------------

    #[test]
    fn get_cwd_returns_default_slash() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "sh".into());
        assert_eq!(t.get_cwd(TaskId(1)), Some("/"));
    }

    #[test]
    fn set_cwd_roundtrip() {
        let mut t = ProcessTable::new();
        t.register(TaskId(1), None, "sh".into());
        assert!(t.set_cwd(TaskId(1), "/home/user".into()));
        assert_eq!(t.get_cwd(TaskId(1)), Some("/home/user"));
    }

    #[test]
    fn set_cwd_on_nonexistent_process_returns_false() {
        let mut t = ProcessTable::new();
        assert!(!t.set_cwd(TaskId(999), "/tmp".into()));
    }

    #[test]
    fn get_cwd_returns_none_for_absent_id() {
        let t = ProcessTable::new();
        assert_eq!(t.get_cwd(TaskId(42)), None);
    }

    // -----------------------------------------------------------------------
    // list
    // -----------------------------------------------------------------------

    #[test]
    fn list_returns_all_processes_in_ascending_task_id_order() {
        let mut t = ProcessTable::new();
        // Register in non-ascending order to confirm BTreeMap sorts.
        t.register(TaskId(10), None, "c".into());
        t.register(TaskId(1), None, "a".into());
        t.register(TaskId(5), None, "b".into());
        let list = t.list();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].id, TaskId(1));
        assert_eq!(list[1].id, TaskId(5));
        assert_eq!(list[2].id, TaskId(10));
    }

    #[test]
    fn list_on_empty_table_returns_empty_vec() {
        let t = ProcessTable::new();
        assert!(t.list().is_empty());
    }

    // -----------------------------------------------------------------------
    // remove
    // -----------------------------------------------------------------------

    #[test]
    fn remove_removes_entry_and_returns_true() {
        let mut t = ProcessTable::new();
        t.register(TaskId(7), None, "daemon".into());
        assert!(t.remove(TaskId(7)));
        assert!(t.get(TaskId(7)).is_none());
    }

    #[test]
    fn remove_absent_entry_returns_false() {
        let mut t = ProcessTable::new();
        assert!(!t.remove(TaskId(7)));
    }

    // -----------------------------------------------------------------------
    // Parent-child chain: init → shell → editor
    // -----------------------------------------------------------------------

    #[test]
    fn three_level_chain_parent_pointers_correct() {
        let t = three_level_table();
        assert_eq!(t.get(TaskId(1)).unwrap().parent, None);
        assert_eq!(t.get(TaskId(2)).unwrap().parent, Some(TaskId(1)));
        assert_eq!(t.get(TaskId(3)).unwrap().parent, Some(TaskId(2)));
    }

    #[test]
    fn three_level_chain_children_lists_correct() {
        let t = three_level_table();
        // init has shell as child; shell has editor; editor has none.
        assert_eq!(t.get(TaskId(1)).unwrap().children, vec![TaskId(2)]);
        assert_eq!(t.get(TaskId(2)).unwrap().children, vec![TaskId(3)]);
        assert!(t.get(TaskId(3)).unwrap().children.is_empty());
    }

    #[test]
    fn three_level_chain_reap_propagates_correctly() {
        let mut t = three_level_table();
        // Editor exits first.
        let wakeup_shell = t.record_exit(TaskId(3), 1);
        assert_eq!(wakeup_shell, Some(TaskId(2)));

        // Shell reaps editor.
        assert_eq!(t.reap_child(TaskId(2)), Some((TaskId(3), 1)));
        assert!(t.get(TaskId(3)).is_none());

        // Now shell exits.
        let wakeup_init = t.record_exit(TaskId(2), 0);
        assert_eq!(wakeup_init, Some(TaskId(1)));

        // Init reaps shell.
        assert_eq!(t.reap_child(TaskId(1)), Some((TaskId(2), 0)));
        assert!(t.get(TaskId(2)).is_none());

        // Table now has only init.
        assert_eq!(t.list().len(), 1);
        assert_eq!(t.list()[0].id, TaskId(1));
    }

    // -----------------------------------------------------------------------
    // Default impl
    // -----------------------------------------------------------------------

    #[test]
    fn default_produces_empty_table() {
        let t = ProcessTable::default();
        assert!(t.list().is_empty());
    }
}
