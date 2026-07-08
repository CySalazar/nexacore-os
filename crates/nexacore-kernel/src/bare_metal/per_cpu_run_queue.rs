//! MB14.e.2 — per-CPU run-queue scaffold.
//!
//! Adds a sibling-CPU run-queue array keyed on `cpu_id`. The BSP's local
//! queue is `RUN_QUEUES[0]`; APs index `1..=MAX_AP_SLOTS`. Each queue is
//! a per-priority array of [`alloc::vec::Vec<u64>`] (task ids) protected
//! by a spinlock — `nexacore-kernel` does not yet pull `spin` as a
//! dependency (see `crates/nexacore-kernel/Cargo.toml` MB13.c § 4), so the
//! lock is a small in-tree primitive scoped to this module.
//!
//! ## Scope
//!
//! - **Owned by the kernel scheduler**, not by user-space.
//! - **Compatible with the existing single-CPU dispatch.** The cooperative
//!   round-robin scheduler in [`super::super::scheduling`] still owns the
//!   canonical `tasks` / `processes` pools; this module owns only the
//!   *dispatch* metadata (which task id is ready on which CPU). The
//!   scheduler's existing `run_queues` field stays in place as the BSP's
//!   queue mirror — the new API simply lets a caller specify
//!   `cpu_id != 0` so APs can be primed with work in MB14.e.3.
//! - **Stealing primitive in MB14.e.3.** [`pop_for_cpu_with_stealing`]
//!   first drains the local queue, then scans sibling CPUs FIFO order
//!   and steals from the back to avoid head-cache-line contention.
//!
//! ## Why a spinlock and not a lock-free queue
//!
//! A Treiber stack or an MPMC ring would scale better, but MB14.e is a
//! scheduling refactor, not a contention-bound benchmark; a fair-effort
//! spinlock with a `core::hint::spin_loop` body is enough at the current
//! AP count (≤ 32) and aligns with the kernel-house style. The lock
//! primitive is internal — callers stay on the queue API. ADR-0007
//! § Roadmap MB14.e covers the eventual swap to a lock-free queue once
//! Phase 2 driver workloads push the steal rate.

#![allow(
    unsafe_code,
    reason = "static-mut access to the per-CPU run-queue table — protected by per-slot spinlock"
)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{mp::MAX_CPUS, per_cpu::MAX_AP_SLOTS};
use crate::scheduling::PriorityClass;

/// Number of priority classes — must stay aligned with [`PriorityClass`]'s
/// `#[repr(u8)]` cardinality.
const NUM_PRIORITY_CLASSES: usize = 6;

/// Total slots: BSP (`cpu_id` == 0) + every AP slot.
const NUM_CPU_SLOTS: usize = 1 + MAX_AP_SLOTS;

// Static-size sanity: the per-CPU table must accommodate every logical
// CPU the topology layer can enumerate.
const _: () = assert!(NUM_CPU_SLOTS == MAX_CPUS);

/// In-tree spinlock — `lock()` busy-waits until [`Self::flag`] flips
/// from `false` to `true` (Acquire semantics on the successful CAS).
struct SpinLock {
    flag: AtomicBool,
}

impl SpinLock {
    const fn new() -> Self {
        Self {
            flag: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> SpinGuard<'_> {
        // Test-and-set with a relaxed read inside the spin loop to keep
        // the cache line readable until the prior owner releases.
        loop {
            if self
                .flag
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return SpinGuard { lock: self };
            }
            while self.flag.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }
}

/// RAII guard — releases the spinlock on drop.
struct SpinGuard<'a> {
    lock: &'a SpinLock,
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.lock.flag.store(false, Ordering::Release);
    }
}

/// One run-queue per CPU. Six priority classes mirror the cardinality of
/// [`PriorityClass`]; the inner `Vec<u64>` stores raw `TaskId.0` values
/// (the kernel-side `TaskId` does not impl `Hash + Eq` constraints the
/// queue needs, but its `u64` payload does).
struct PerCpuRunQueue {
    queues: [Vec<u64>; NUM_PRIORITY_CLASSES],
}

impl PerCpuRunQueue {
    const fn new() -> Self {
        Self {
            queues: [
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ],
        }
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "PriorityClass as usize < NUM_PRIORITY_CLASSES by #[repr(u8)] enum"
    )]
    fn push_back(&mut self, task: u64, priority: PriorityClass) {
        self.queues[priority as usize].push(task);
    }

    /// P11.1 residual (flagged, not a defect today): this scan ranks by
    /// enum discriminant, i.e. System (0) ahead of `RealTime` (1) — it does
    /// NOT implement the strict `RealTime` bypass that
    /// `RoundRobinScheduler::pick_next` gives the BSP path (WS1-01).
    /// No `RealTime` task is AP-schedulable today; extend the bypass here
    /// (and revisit `steal_back`'s lowest-first preference) before Phase 2
    /// `RealTime` workloads land on AP run-queues. Tracked in todo.md P11.1.
    fn pop_front(&mut self) -> Option<u64> {
        for queue in &mut self.queues {
            if !queue.is_empty() {
                return Some(queue.remove(0));
            }
        }
        None
    }

    /// Steal from the back of the lowest-priority non-empty queue.
    ///
    /// Stealing from the back (vs front) leaves the local victim's head
    /// cache line untouched, reducing pingpong with the victim CPU's
    /// next [`Self::pop_front`]. Stealing from the lowest-priority
    /// non-empty queue preserves the global priority ordering — a high-
    /// priority task on the victim is more likely to be needed there
    /// than at the stealer.
    fn steal_back(&mut self) -> Option<u64> {
        for queue in self.queues.iter_mut().rev() {
            if let Some(task) = queue.pop() {
                return Some(task);
            }
        }
        None
    }

    fn total_len(&self) -> usize {
        self.queues.iter().map(Vec::len).sum()
    }

    #[cfg(test)]
    fn drain_all(&mut self) {
        for queue in &mut self.queues {
            queue.clear();
        }
    }
}

/// Per-CPU run-queue slot — a [`PerCpuRunQueue`] plus its protecting
/// spinlock. Static lifetime + interior mutability so callers can index
/// the global [`RUN_QUEUES`] array without going through `static mut`.
struct CpuSlot {
    lock: SpinLock,
    queue: core::cell::UnsafeCell<PerCpuRunQueue>,
}

impl CpuSlot {
    const fn new() -> Self {
        Self {
            lock: SpinLock::new(),
            queue: core::cell::UnsafeCell::new(PerCpuRunQueue::new()),
        }
    }
}

// SAFETY: every access to `queue` goes through `SpinLock::lock`, which
// provides mutual exclusion across CPUs. The lock primitive itself is
// `Sync` (atomic flag).
unsafe impl Sync for CpuSlot {}

/// Global per-CPU run-queue array. Indexed by `cpu_id`.
static RUN_QUEUES: [CpuSlot; NUM_CPU_SLOTS] = [const { CpuSlot::new() }; NUM_CPU_SLOTS];

/// Enqueue `task` on `cpu_id`'s local run-queue under `priority`.
///
/// Returns `false` if `cpu_id` is out of range (>= [`MAX_CPUS`]); the
/// caller is expected to fall back to the BSP slot in that case.
pub fn enqueue_on_cpu(cpu_id: u32, task: u64, priority: PriorityClass) -> bool {
    let Some(slot) = RUN_QUEUES.get(cpu_id as usize) else {
        return false;
    };
    let _guard = slot.lock.lock();
    // SAFETY: the lock guard guarantees exclusive access to `queue`
    // for the duration of this block.
    let q = unsafe { &mut *slot.queue.get() };
    q.push_back(task, priority);
    true
}

/// Pop the next runnable task from `cpu_id`'s local run-queue. Returns
/// `None` if either the slot is out-of-range or the queue is empty.
///
/// Does **not** attempt to steal — the dispatcher should call
/// [`pop_for_cpu_with_stealing`] for the full pick path.
#[must_use]
pub fn pop_for_cpu(cpu_id: u32) -> Option<u64> {
    let slot = RUN_QUEUES.get(cpu_id as usize)?;
    let _guard = slot.lock.lock();
    // SAFETY: see `enqueue_on_cpu`.
    let q = unsafe { &mut *slot.queue.get() };
    q.pop_front()
}

/// Steal a task from `victim_cpu`'s local run-queue (back of the
/// lowest-priority non-empty queue). Returns `None` if the victim slot
/// is out-of-range or empty.
///
/// Steals only one task per call so the caller (the stealing CPU's idle
/// loop) can re-evaluate after dispatching the stolen task — avoiding
/// hoarding when multiple stealers contend for the same victim.
#[must_use]
pub fn steal_from(victim_cpu: u32) -> Option<u64> {
    let slot = RUN_QUEUES.get(victim_cpu as usize)?;
    let _guard = slot.lock.lock();
    // SAFETY: see `enqueue_on_cpu`.
    let q = unsafe { &mut *slot.queue.get() };
    q.steal_back()
}

/// Pop with work-stealing fallback — MB14.e.3.
///
/// 1. Try the local queue.
/// 2. If empty, scan every other CPU (BSP first, then APs in `cpu_id`
///    order) and attempt to steal one task.
/// 3. Return `None` only if every queue (local + siblings) is empty.
///
/// The BSP-first scan order biases stealers toward draining the busiest
/// queue (the BSP runs the boot wiring + the demo / userprobe smoke,
/// so its queue is the most likely to have tasks at this stage).
#[must_use]
pub fn pop_for_cpu_with_stealing(cpu_id: u32) -> Option<u64> {
    if let Some(t) = pop_for_cpu(cpu_id) {
        return Some(t);
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "NUM_CPU_SLOTS = MAX_CPUS = 32 fits u32 trivially"
    )]
    for victim in 0..(NUM_CPU_SLOTS as u32) {
        if victim == cpu_id {
            continue;
        }
        if let Some(t) = steal_from(victim) {
            return Some(t);
        }
    }
    None
}

/// Total task count on `cpu_id`'s queue. Test / diagnostic helper —
/// production callers should not race on this value.
#[must_use]
pub fn local_len(cpu_id: u32) -> usize {
    let Some(slot) = RUN_QUEUES.get(cpu_id as usize) else {
        return 0;
    };
    let _guard = slot.lock.lock();
    // SAFETY: see `enqueue_on_cpu`.
    let q = unsafe { &*slot.queue.get() };
    q.total_len()
}

/// Drain every CPU's run-queue. Test-only — production has no need for
/// a global reset (task termination removes entries individually).
#[cfg(test)]
pub fn drain_all_for_tests() {
    for slot in &RUN_QUEUES {
        let _guard = slot.lock.lock();
        // SAFETY: see `enqueue_on_cpu`.
        let q = unsafe { &mut *slot.queue.get() };
        q.drain_all();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialise test execution against the global `RUN_QUEUES` so
    /// `cargo test` ordering does not interleave enqueues/pops. Re-uses
    /// the in-tree [`SpinLock`] primitive so the test driver does not
    /// pull `std::sync::Mutex` (workspace-banned by the
    /// `disallowed-methods` clippy lint over poison semantics) and the
    /// guard's drop releases without a closure body — matching the
    /// production lock's API one-to-one.
    static TEST_LOCK: SpinLock = SpinLock::new();
    fn test_lock() -> SpinGuard<'static> {
        TEST_LOCK.lock()
    }

    #[test]
    fn enqueue_then_pop_round_trips() {
        let _g = test_lock();
        drain_all_for_tests();
        assert!(enqueue_on_cpu(0, 42, PriorityClass::Interactive));
        assert_eq!(pop_for_cpu(0), Some(42));
        assert_eq!(pop_for_cpu(0), None);
    }

    #[test]
    fn out_of_range_cpu_id_rejects_enqueue() {
        let _g = test_lock();
        drain_all_for_tests();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "MAX_CPUS fits u32 trivially"
        )]
        let oor = MAX_CPUS as u32;
        assert!(!enqueue_on_cpu(oor, 1, PriorityClass::Background));
    }

    #[test]
    fn out_of_range_cpu_id_rejects_pop() {
        let _g = test_lock();
        drain_all_for_tests();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "MAX_CPUS fits u32 trivially"
        )]
        let oor = MAX_CPUS as u32;
        assert_eq!(pop_for_cpu(oor), None);
    }

    #[test]
    fn priority_order_within_one_cpu() {
        let _g = test_lock();
        drain_all_for_tests();
        // Push lowest first, then highest — pick must surface highest.
        assert!(enqueue_on_cpu(0, 100, PriorityClass::Idle));
        assert!(enqueue_on_cpu(0, 200, PriorityClass::System));
        assert_eq!(pop_for_cpu(0), Some(200));
        assert_eq!(pop_for_cpu(0), Some(100));
    }

    #[test]
    fn fifo_within_one_priority() {
        let _g = test_lock();
        drain_all_for_tests();
        for id in [1u64, 2, 3, 4] {
            assert!(enqueue_on_cpu(0, id, PriorityClass::Interactive));
        }
        for expected in [1u64, 2, 3, 4] {
            assert_eq!(pop_for_cpu(0), Some(expected));
        }
        assert_eq!(pop_for_cpu(0), None);
    }

    #[test]
    fn local_len_tracks_enqueue() {
        let _g = test_lock();
        drain_all_for_tests();
        assert_eq!(local_len(0), 0);
        assert!(enqueue_on_cpu(0, 1, PriorityClass::Interactive));
        assert!(enqueue_on_cpu(0, 2, PriorityClass::Background));
        assert_eq!(local_len(0), 2);
        let _ = pop_for_cpu(0);
        assert_eq!(local_len(0), 1);
    }

    // -------------------------------------------------------------------------
    // MB14.e.3 — work-stealing protocol tests.
    // -------------------------------------------------------------------------

    #[test]
    fn steal_from_returns_back_of_lowest_priority_queue() {
        let _g = test_lock();
        drain_all_for_tests();
        // Victim CPU 0: high-prio task 10, then two low-prio tasks 20, 21.
        // Steal must surface 21 (back of Background queue), leaving 10
        // and 20 in place.
        assert!(enqueue_on_cpu(0, 10, PriorityClass::Interactive));
        assert!(enqueue_on_cpu(0, 20, PriorityClass::Background));
        assert!(enqueue_on_cpu(0, 21, PriorityClass::Background));
        assert_eq!(steal_from(0), Some(21));
        // Remaining: 10 (Interactive) + 20 (Background); pick path
        // surfaces them in priority order.
        assert_eq!(pop_for_cpu(0), Some(10));
        assert_eq!(pop_for_cpu(0), Some(20));
    }

    #[test]
    fn steal_from_empty_victim_returns_none() {
        let _g = test_lock();
        drain_all_for_tests();
        assert_eq!(steal_from(0), None);
        assert_eq!(steal_from(1), None);
    }

    #[test]
    fn pop_with_stealing_falls_back_to_sibling() {
        let _g = test_lock();
        drain_all_for_tests();
        // Stealer = cpu 1, victim = cpu 0. Cpu 1 is empty so the call
        // must steal from cpu 0.
        assert!(enqueue_on_cpu(0, 999, PriorityClass::Interactive));
        assert_eq!(pop_for_cpu_with_stealing(1), Some(999));
        // Cpu 0 is now drained too.
        assert_eq!(pop_for_cpu(0), None);
    }

    #[test]
    fn pop_with_stealing_prefers_local_first() {
        let _g = test_lock();
        drain_all_for_tests();
        // Both cpu 0 and cpu 1 have tasks; cpu 1's pick must surface
        // cpu 1's own task first (no steal), preserving locality.
        assert!(enqueue_on_cpu(0, 100, PriorityClass::Interactive));
        assert!(enqueue_on_cpu(1, 200, PriorityClass::Background));
        assert_eq!(pop_for_cpu_with_stealing(1), Some(200));
        // Cpu 1 drained; subsequent call must steal cpu 0's task.
        assert_eq!(pop_for_cpu_with_stealing(1), Some(100));
        assert_eq!(pop_for_cpu_with_stealing(1), None);
    }

    #[test]
    fn pop_with_stealing_skips_self_during_scan() {
        let _g = test_lock();
        drain_all_for_tests();
        // Only cpu 2 has work. Stealer = cpu 2's own pick path drains
        // it locally; a different stealer surfaces it via the scan.
        assert!(enqueue_on_cpu(2, 333, PriorityClass::System));
        assert_eq!(pop_for_cpu_with_stealing(3), Some(333));
    }

    #[test]
    fn pop_with_stealing_returns_none_when_all_empty() {
        let _g = test_lock();
        drain_all_for_tests();
        assert_eq!(pop_for_cpu_with_stealing(0), None);
        assert_eq!(pop_for_cpu_with_stealing(5), None);
    }
}
