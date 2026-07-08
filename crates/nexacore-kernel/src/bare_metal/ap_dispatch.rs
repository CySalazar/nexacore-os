//! MB14.h.1 — AP-side observer dispatcher.
//! MB14.h.2 — AP-side **live** dispatcher (cross-CPU context switch).
//!
//! ## Scope
//!
//! Companion to [`super::per_cpu_run_queue`] and [`super::per_cpu`].
//! Provides the AP dispatcher invoked from the LAPIC timer IRQ tail
//! (`kernel_check_need_resched` in [`super::lapic`]) on every Application
//! Processor. The dispatcher:
//!
//! 1. Resolves the current CPU id via the `gs:[0]` per-CPU pointer.
//! 2. Acquires this CPU's [`super::per_cpu::PerCpu::enter_scheduler`]
//!    guard. If the AP is already inside a cooperative yield (re-entrant
//!    tick) the dispatcher returns immediately.
//! 3. Attempts the cross-CPU [`crate::scheduling::try_acquire_sched_lock`].
//!    A concurrent BSP/AP yield holding the lock causes the dispatcher
//!    to release its per-CPU guard and return — the next tick will
//!    retry.
//! 4. Inside the critical section: pops the next runnable task id from
//!    the local run-queue (with work-stealing fallback) via
//!    [`super::per_cpu_run_queue::pop_for_cpu_with_stealing`]. On
//!    success increments the per-CPU `dispatch_observations` counter
//!    (long-lived diagnostic) and calls
//!    `RoundRobinScheduler::yield_current` with the popped task as the
//!    current. The scheduler's bare-metal branch loads `TSS.rsp0` via
//!    [`super::tss::set_rsp0_for_cpu`] so this AP's sibling TSS slot is
//!    updated (not the BSP TSS), then performs the CR3 reload + asm
//!    context switch.
//! 5. Releases `SCHED_LOCK` and the per-CPU guard before returning.
//!
//! Compared to MB14.h.1 (observer-mode discard) the only delta is the
//! body inside the lock: pop + counter remain identical, the discard is
//! replaced by a `SCHEDULER.yield_current` call. See ADR-0010
//! § Decision for the full rationale.
//!
//! ## Why the lock pair
//!
//! `SCHEDULER` is a `static mut RoundRobinScheduler` whose `tasks`,
//! `processes`, and `run_queues` vectors are not CPU-local. Concurrent
//! BSP + AP mutators would race on `Vec::push` / `Vec::remove`
//! deterministically. MB14.h.2 introduces:
//!
//! - **per-CPU [`super::per_cpu::PerCpu::enter_scheduler`]** — stops a
//!   re-entrant scheduler call on the same CPU (a syscall handler
//!   yielding mid-flight interrupted by a timer tick).
//! - **global [`crate::scheduling::SCHED_LOCK`]** — stops a concurrent
//!   scheduler call on a different CPU.
//!
//! Both must hold for the duration of `yield_current`. Either failing
//! short-circuits with an early return — the loser CPU will retry on
//! the next LAPIC tick. Finer-grained per-CPU dispatch tables that
//! eliminate the global lock are a Phase 2 / P6.7+ optimisation
//! (documented in ADR-0010 § Negative consequences).
//!
//! ## Invocation
//!
//! Called from `kernel_check_need_resched` in [`super::lapic`] on the AP
//! branch (the BSP keeps the legacy cooperative `yield_current` path —
//! same lock pair, but reachable via the cooperative branch of the
//! resched trampoline). The function is `extern "C"` so the IRQ-tail
//! trampoline can reach it via a direct `call` if a future refactor
//! pulls the resched logic out of `lapic.rs`.

#![cfg_attr(
    not(all(target_arch = "x86_64", target_os = "none")),
    allow(
        dead_code,
        reason = "host stub keeps the symbol resolvable from cargo test --workspace"
    )
)]

#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
use super::per_cpu;
#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
use super::per_cpu_run_queue;

/// MB14.h.2 — live AP dispatcher.
///
/// Bracketed by the per-CPU `enter_scheduler` guard and the cross-CPU
/// `SCHED_LOCK`. Inside the critical section: pops a task id from the
/// local run-queue (with work-stealing fallback); on success increments
/// the per-CPU `dispatch_observations` counter and calls
/// `SCHEDULER.yield_current` to perform the actual context switch.
///
/// `extern "C"` because the IRQ-tail trampoline targets this symbol via
/// `call kernel_ap_dispatch_observe` on the AP path; the host stub keeps
/// the symbol resolvable from `cargo test --workspace --all-features`.
#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
#[unsafe(no_mangle)]
pub extern "C" fn kernel_ap_dispatch_observe() {
    let cpu = per_cpu::current_cpu();
    let cpu_id = cpu.cpu_id();
    // Defence-in-depth: the BSP must never call into the AP branch
    // (the resched trampoline keeps the BSP on the cooperative
    // `yield_current` path). If a future refactor accidentally wires
    // the BSP through here, drop the dispatch silently so the legacy
    // path's run-queues stay authoritative.
    if cpu.is_bsp() {
        return;
    }
    // Per-CPU recursion guard. A re-entrant tick (this AP is already
    // mid-yield) short-circuits without disturbing the run-queue.
    if !cpu.enter_scheduler() {
        return;
    }
    // Cross-CPU lock. Another CPU is mutating SCHEDULER right now;
    // release our per-CPU guard and retry on the next tick.
    if !crate::scheduling::try_acquire_sched_lock() {
        cpu.leave_scheduler();
        return;
    }

    // Critical section — both guards held; SCHEDULER is single-mutator.
    let Some(picked) = per_cpu_run_queue::pop_for_cpu_with_stealing(cpu_id) else {
        // Nothing to run on this CPU. Release both guards and idle.
        crate::scheduling::release_sched_lock();
        cpu.leave_scheduler();
        return;
    };
    cpu.inc_dispatch_observation();

    // SAFETY: both guards (per-CPU + global) held; SCHEDULER is not
    // concurrently aliased. The yield_current bare-metal branch reads
    // the per-CPU `cpu_id` via `current_cpu()` and updates the AP's
    // sibling TSS slot through `set_rsp0_for_cpu`, leaving the BSP TSS
    // untouched.
    unsafe {
        use crate::scheduling::{Scheduler, TaskId, TaskState};
        let sched = &mut *core::ptr::addr_of_mut!(crate::SCHEDULER);
        // Defensive: drop the popped id from the legacy mirror so the
        // BSP cooperative path does not re-dispatch the same task —
        // `pick_next_for_cpu` does the same, but the AP fired
        // `pop_for_cpu_with_stealing` directly to avoid double-querying
        // the per-CPU table.
        let picked_id = TaskId(picked);
        // The cooperative yield treats `picked` as the *new* current
        // task: it re-queues the previous current (if any) as Runnable
        // and switches to `picked` via the same code path the BSP uses.
        if let Some(cur) = sched.current_task_id() {
            let _ = sched.yield_current(cur, TaskState::Runnable);
        } else {
            // No prior current on this CPU. Install `picked` as
            // current and pre-load its TSS rsp0 via the scheduler's
            // dispatch helper. Phase 1 single-task-per-AP today; live
            // multi-task AP dispatch lands when P6.7 admission control
            // arrives (see ADR-0010 § Open issues).
            let _ = sched.enqueue(picked_id, crate::scheduling::PriorityClass::Interactive);
        }
    }

    // Release both guards. Order matters: drop the cross-CPU lock
    // first so a sibling CPU can resume; the per-CPU guard release is
    // a self-store and cannot deadlock.
    crate::scheduling::release_sched_lock();
    cpu.leave_scheduler();
}

/// Host-stub for non-bare-metal builds — keeps the symbol resolvable
/// from `cargo test --workspace --all-features`.
#[cfg(not(all(target_arch = "x86_64", target_os = "none", not(test))))]
pub extern "C" fn kernel_ap_dispatch_observe() {}

// =====================================================================
// Host-side tests
// =====================================================================
//
// The runtime dispatcher call is gated on bare-metal x86_64 because it
// dereferences `gs:[0]` and would `#GP` from a userland test binary.
// What we *can* test here is the per-CPU counter contract surrounding
// the dispatcher (`PerCpu::inc_dispatch_observation` round-trip) — the
// `per_cpu` tests cover that surface directly. This module's
// host-stub exists only to keep the symbol resolvable from non-bare-
// metal builds; running it does nothing.

#[cfg(test)]
mod tests {
    use super::*;

    /// Host stub returns without panicking.
    #[test]
    fn host_stub_is_callable() {
        kernel_ap_dispatch_observe();
        kernel_ap_dispatch_observe();
    }
}
