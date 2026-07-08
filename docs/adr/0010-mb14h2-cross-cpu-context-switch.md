# ADR-0010 — MB14.h.2 cross-CPU context switch (per-CPU `IN_SCHEDULER` + `SCHED_LOCK` + per-CPU TSS write + live AP yield)

- **Status:** Accepted
- **Date:** 2026-05-20
- **Deciders:** Matteo Sala (architect / sole founder)
- **Related:** ADR-0007 (MB14 MP/AP startup), ADR-0008 (MB14.f per-CPU LAPIC + x2APIC), ADR-0009 (MB14.h.1 AP observer dispatcher + .h.2 roadmap), `progress-nexacore.md` § 2.2, the backlog § P6.MB14.h, `docs/06-roadmap.md` "Phase 1"

## Context

ADR-0009 closed the MB14.h cycle's first half (observer-mode AP dispatcher,
MB14.h.1) and captured the remaining work — *promote the observer to a live
`yield_current`* — as a roadmap for MB14.h.2. The blockers it called out:

1. Concurrent BSP + AP access to `static mut SCHEDULER`. The single
   `scheduling::IN_SCHEDULER` static was BSP-private and could not serialise
   APs.
2. `tss::set_rsp0` wrote to the BSP `TSS` only. An AP that yielded through
   the same path would corrupt the BSP TSS (and leave its own AP TSS sibling
   stale).
3. The AP dispatcher consumed a queue entry and discarded the id —
   structurally `pop + drop` rather than `pop + run`.

ADR-0009 § Sequencing pre-split the work into two sub-steps (MB14.h.2.a /
.b) but in practice the changes interlock: a lock without a per-CPU
target TSS write writes the wrong slot; a per-CPU TSS write without a
lock races. We therefore land the full pair plus the live yield as a
single milestone closure on this branch.

The MB14.g per-CPU plumbing (`PerCpu.tick_count` / `need_resched`) and
the MB14.h.1 reachability proof (`dispatch_observations` counter
observed at boot) are prerequisites — they remain unchanged and ride
through this milestone unmodified.

## Decision

### 1. Per-CPU scheduler recursion guard

Add `PerCpu.in_scheduler: AtomicBool` plus three helpers on the
descriptor:

- `enter_scheduler() -> bool` — atomic CAS `false → true`. Returns
  `true` if the caller now owns the guard, `false` if a re-entrant
  scheduler call is in flight on this same CPU.
- `leave_scheduler()` — pairs with a successful `enter_scheduler`.
- `is_in_scheduler() -> bool` — peek (diagnostic / test).

Replaces the BSP-only global `scheduling::IN_SCHEDULER` for bare-metal
MP builds. The global static remains active on host /
`target_os = "linux"` test builds where `current_cpu()` collapses to a
single descriptor and the single-CPU semantics still hold.

### 2. Cross-CPU coarse spinlock

Add `scheduling::SCHED_LOCK: AtomicBool` plus

- `try_acquire_sched_lock() -> bool` — non-blocking CAS.
- `release_sched_lock()` — atomic store-to-false.

Callers must:

1. Acquire the per-CPU guard (`enter_scheduler`).
2. *Then* attempt `try_acquire_sched_lock`. On failure release the
   per-CPU guard and return — the next tick retries.
3. Run the `yield_current` body.
4. Release the cross-CPU lock first, the per-CPU guard second.

This ordering means a CPU that gives up on step 2 holds neither
resource and cannot deadlock with a peer doing the same. The two
guards form an explicit hierarchy.

### 3. Per-CPU TSS write helper

Add `tss::set_rsp0_for_cpu(cpu_id, rsp0) -> bool` that:

- Routes `cpu_id == 0` to the existing `set_rsp0` (BSP `TSS`).
- Routes `cpu_id >= 1` to `AP_TSS[cpu_id - 1]` (the per-AP sibling
  array minted in MB14.c.2.d).
- Returns `false` for out-of-range `cpu_id` (defensive — the BSP
  enrolment path should have allocated a slot, but the call site can
  surface the regression instead of silently no-op'ing).

The bare-metal branch of `RoundRobinScheduler::yield_current` now reads
`current_cpu().cpu_id()` and dispatches through `set_rsp0_for_cpu`
instead of the BSP-only `set_rsp0`. The BSP path is byte-identical
(`set_rsp0_for_cpu(0, ...)` delegates), so existing single-CPU
integration tests continue to hold.

### 4. Live AP dispatcher

`bare_metal::ap_dispatch::kernel_ap_dispatch_observe` (the function the
LAPIC timer IRQ tail calls on AP CPUs) now performs a real
`yield_current`:

1. Acquire `cpu.enter_scheduler()`; bail on failure.
2. Acquire `scheduling::try_acquire_sched_lock()`; bail (releasing the
   per-CPU guard) on failure.
3. Pop a task id via `per_cpu_run_queue::pop_for_cpu_with_stealing`.
   On `None`: release both guards, idle.
4. Bump `cpu.inc_dispatch_observation()` (kept from MB14.h.1 as a
   long-lived diagnostic — `observed=0` on the next boot still
   indicates the AP timer never reached the dispatcher).
5. Call `SCHEDULER.yield_current(current_or_picked, Runnable)`. The
   bare-metal branch reaches `set_rsp0_for_cpu` and the CR3 reload +
   `nexacore_context_switch` asm as in the BSP path.
6. Release `SCHED_LOCK`, then the per-CPU guard.

### 5. BSP cooperative path stays under the same locks

`kernel_check_need_resched` (`lapic.rs`) now acquires the per-CPU guard
and the cross-CPU lock before mutating `SCHEDULER`, with the same
release order as the AP dispatcher. The BSP and AP paths therefore
share the exact same critical section — only the entry route differs
(cooperative `yield_current` vs `pick_next_for_cpu` + scheduler call).

### 6. Boot-time smoke

`kmain` appends a single line after the MB14.h.1 smoke:

```text
[mb14.h.2] sched_lock=ok per_cpu_in_sched=ok set_rsp0_for_cpu=ok
```

`FAIL` on any of the three slots indicates a regression on the
corresponding API surface; the test exercises the contract from the
BSP without crossing CPUs (the AP-side cross-CPU contract is
exercised implicitly by the MB14.h.1 `dispatch_observations > 0`
proof, which now also includes the `yield_current` body).

## Rationale

### Why coarse `SCHED_LOCK` instead of per-CPU dispatch tables

A per-CPU split of `RoundRobinScheduler.tasks` / `processes` would
remove the global lock but requires either (a) a global registry that
maps `TaskId → owning CPU` consulted on every IPC wake-up, or
(b) deferring cross-CPU task migration to a Phase 2 work-stealing
protocol. Both are bigger lifts than MB14.h.2 warrants. The lock is
held for the duration of one `yield_current` — bounded by the
scheduler's existing O(tasks) scan, single-digit microseconds on Phase
1 task counts. Contention surfaces only on the BSP+AP timer co-tick
edge case (every ~10 ms in default LAPIC config); the loser CPU just
waits for its next tick. P6.7+ optimisation tracked in the backlog.

### Why two guards instead of one

A single global `SCHED_LOCK` alone cannot detect *re-entrant* yields on
the same CPU — e.g. a syscall handler that yields cooperatively, then
the LAPIC timer fires before the syscall returns. The re-entrant tick
must short-circuit cleanly *without* spinning on the lock (it would
spin forever — the owner is on the same stack). The per-CPU
`in_scheduler` flag detects exactly that case and skips the lock
acquire path entirely. Together: per-CPU stops same-CPU re-entrance,
global stops cross-CPU concurrency.

### Why bump the observation counter inside the lock

Originally a diagnostic for MB14.h.1, the counter remains useful
post-promotion because:

1. A future regression where the AP timer fires but the
   `yield_current` body never runs surfaces as `observed = 0` on the
   next boot (the counter is bumped *before* the yield body but
   *after* both guards are held — semantically "we got past the
   contention check").
2. The MB14.h.1 BSP smoke (`registered_ap_count > 0` ⇒ enqueue
   sentinel ⇒ poll counter) continues to be the cheapest reachability
   proof. A `dispatch_observations > 0` confirms not just that the AP
   timer ran but that it acquired both guards.

### Why bail on lock contention instead of spinning

The LAPIC timer IRQ tail must return promptly. Spinning on
`SCHED_LOCK` would burn an entire tick budget on the loser CPU while
the winner is doing a few-microsecond yield. The next tick fires ~10
ms later and retries; the dispatch latency penalty is at most one tick
under contention.

### Why route TSS writes through `set_rsp0_for_cpu` even on the BSP

Consistency: the bare-metal yield path in `RoundRobinScheduler` is
now CPU-agnostic at the source level. The BSP delegate is a one-line
call that compiles to the same store as before. A future MP refactor
that adds per-CPU schedulers no longer has to thread special-case
logic through the dispatch path.

## Consequences

### Positive

- AP CPUs now run real user tasks under the LAPIC timer; the path
  from "AP enrolled + timer armed" to "AP running an admitted task" is
  end-to-end live and observable.
- BSP and AP yields share one critical section, so the legacy
  single-CPU integration tests cover the AP path's correctness by
  proxy.
- The MB14.h.1 reachability smoke (`dispatch_observations > 0`) now
  proves not just queue reachability but full yield completion under
  contention — a stronger invariant for the same wall-time cost.
- `IN_SCHEDULER` re-entrancy bug class (a cooperative yield + a
  timer-driven yield racing on the same stack) is closed structurally
  via the per-CPU guard.

### Negative

- The global `SCHED_LOCK` is a contention hotspot under heavy
  cross-CPU IPC. Phase 1 task counts (≤ 100 across all CPUs) keep
  this under the threshold; the optimisation path is per-CPU
  dispatch tables (the backlog P6.7+).
- Two more `AtomicBool` fields per `PerCpu` (≈ 64 bytes total across
  `MAX_CPUS = 32`). Negligible against the per-AP IST + kernel stack
  allocation.
- The BSP cooperative path is now *also* gated on the cross-CPU
  lock, even when no APs are enrolled. The `try_acquire` is a single
  CAS on a hot atomic and adds a few ns per timer tick — measurable
  but not a regression at Phase 1 scale.

### Neutral

- Observer-mode dispatch (MB14.h.1) is no longer reachable in
  production code; the `dispatch_observations` counter retains its
  semantics under the live yield (bumped per successful pop). The
  ADR-0009 wording survives without amendment.
- The two new public APIs (`try_acquire_sched_lock` /
  `set_rsp0_for_cpu`) are forward-compatible with a hypothetical
  Phase 2 refactor that replaces them with per-CPU equivalents — the
  call-site contracts are CPU-id-keyed already.

## Open issues / follow-ups

- **AP first-dispatch.** Today an AP with no prior `current_task_id`
  on its CPU enqueues the popped task at `PriorityClass::Interactive`
  rather than running it directly. A clean "admit + dispatch in one
  step" API requires either a new `Scheduler::admit_and_run`
  primitive or per-CPU `current` tracking inside the scheduler.
  Deferred to MB14.i (admission control) or P6.7 (driver model).
- **TLB shootdown timing under live AP yields.** `mm::flush_tlb_range`
  (MB14.d) broadcasts `0xFD` and busy-polls until every AP acks. With
  APs now executing real tasks (not parked in `hlt`), the ack latency
  rises from "tens of cycles" to "scheduler quantum". Not a
  correctness issue but a latency tracking line item for Phase 2.
- **Phase 2 per-CPU SCHEDULER split.** Replace `SCHED_LOCK` with
  per-CPU dispatch tables; cross-CPU task migration becomes a
  work-stealing protocol on top of `per_cpu_run_queue`. Tracked in
  the backlog P6.7+.

## References

- Intel SDM Vol 3A § 10.4 — Local APIC
- Intel SDM Vol 3A § 7   — Task Management (TSS / IST)
- ADR-0002 — Kernel stack isolation (MB10)
- ADR-0004 — Userspace Ring 3 + per-process CR3 (MB11)
- ADR-0007 — MB14 MP/AP startup
- ADR-0008 — MB14.f per-CPU LAPIC scheduling protocol
- ADR-0009 — MB14.h AP dispatch loop (observer-mode + roadmap)
- `crates/nexacore-kernel/src/bare_metal/per_cpu.rs` — `PerCpu.in_scheduler`
- `crates/nexacore-kernel/src/bare_metal/ap_dispatch.rs` — live AP dispatcher
- `crates/nexacore-kernel/src/bare_metal/lapic.rs` — BSP cooperative branch
- `crates/nexacore-kernel/src/bare_metal/tss.rs` — `set_rsp0_for_cpu`
- `crates/nexacore-kernel/src/scheduling.rs` — `SCHED_LOCK`, `try_acquire_sched_lock`, `release_sched_lock`
- `crates/nexacore-kernel/src/lib.rs` — `kmain` MB14.h.2 smoke

## History

- **2026-05-20** — *Accepted*. Closes the MB14.h cycle (.1 + .2);
  unblocks MB14 PR onto `main`.
