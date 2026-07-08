# ADR-0009 — MB14.h AP-side dispatch loop (observer-mode + cross-CPU context switch roadmap)

- **Status:** Accepted (MB14.h.1 only; .h.2 design captured as roadmap)
- **Date:** 2026-05-20
- **Deciders:** Matteo Sala (architect / sole founder)
- **Related:** ADR-0007 (MB14 MP/AP startup), ADR-0008 (MB14.f per-CPU LAPIC + x2APIC), `progress-nexacore.md` § 4.1.8, the backlog § P6.MB14.h, `docs/06-roadmap.md` "Phase 1"

## Context

MB14.g closed the per-CPU plumbing layer: each `PerCpu` descriptor owns
its own `tick_count: AtomicU64` and `need_resched: AtomicBool`; the LAPIC
periodic-timer ISR (`kernel_lapic_timer_tick`) writes only into
`current_cpu()` and the `is_bsp()` early-return that gated MB14.f has
been dropped. `RoundRobinScheduler` exposes
`enqueue_for_cpu(cpu_id, task, prio)` / `pick_next_for_cpu(cpu_id)` with
dual-write/dual-read against the bare-metal `per_cpu_run_queue` table
and the legacy single-CPU `run_queues` mirror.

At MB14.h the question is: **what runs on the Application Processor
between two LAPIC timer ticks?** Today (post-MB14.g) the answer is "the
`hlt; jmp 80b` park in `kmain_ap` — the AP serves IPIs but executes no
task on its kernel stack." The eventual answer (Phase 1 deliverable
P6.7, user-space drivers) is "the AP runs whichever task the per-CPU
run-queue dispatches, with full Ring 0 / Ring 3 transitions, IST stack
isolation, and cross-AS context switches."

The gap between the two is **the most invasive change of the MB14
cycle**: it requires every one of:

1. **A live `kernel_check_need_resched` consumer on the AP** — currently
   the AP branch drains `need_resched` and returns; it does not consult
   the per-CPU run-queue, increment any counter, or attempt any kind of
   dispatch.
2. **Per-CPU `IN_SCHEDULER` recursion guards** — the BSP path uses a
   single `scheduling::IN_SCHEDULER` static. With APs running the
   scheduler concurrently, that flag's BSP-only semantics break.
3. **`SCHEDULER` access serialised across CPUs** — today `SCHEDULER` is
   a `static mut RoundRobinScheduler` accessed by the BSP cooperative
   path under a one-thread-at-a-time invariant (`IN_SCHEDULER`).
   `yield_current` mutates both `tasks` and `processes` vectors plus
   the legacy `run_queues` mirror — none of those are CPU-local.
4. **Cross-CPU context switch primitive** — `nexacore_context_switch` saves
   callee-saved on the *current* kernel stack and restores from the
   *incoming* one. The incoming stack must live in a VA that the
   incoming task's PML4 maps; today the kernel half is mirrored by
   reference across every per-process PML4 (MB13.b), so this part is
   structurally sound, but the AP needs to commit to a *specific*
   kernel stack before it loads the next task — its own per-CPU
   `PerCpu.kernel_rsp` slot, set by `tss::set_rsp0` when a task is
   admitted.
5. **TSS.rsp0 per-CPU updates** — `crate::bare_metal::tss::set_rsp0`
   currently writes to a single global TSS; APs land on the same TSS
   slot. The AP-side dispatch needs to write into *its own* per-CPU
   TSS sibling (MB14.c.2.d allocated the per-AP TSS array but
   `set_rsp0` doesn't address it by `cpu_id` yet).

Wiring all five at once on the Proxmox test VM has a high chance of
triple-faulting at first boot, with no debug surface beyond the serial
port. The MB14.h cycle therefore splits into **two sub-blocks**:

- **MB14.h.1** — *observer-mode dispatcher*. The AP `kernel_check_need_resched`
  branch now calls a new `kernel_ap_dispatch_observe()` Rust function
  that pops a task id from `per_cpu_run_queue::pop_for_cpu_with_stealing`,
  increments a per-CPU counter, and **discards the id**. No context
  switch, no `SCHEDULER` access, no TSS update. Bounded boot-time smoke:
  BSP enqueues a sentinel on `cpu_id = 1`, busy-polls the AP's
  observation counter for up to ~1 s, logs `[mb14.h.1] ap_dispatch
  observed=N (ok | timeout)`. This is the present ADR scope.

- **MB14.h.2** — *cross-CPU context switch*. Replaces the discard in
  the observer with a live `yield_current` call, lifting items (2)-(5)
  above to per-CPU. Tracked here as roadmap; opens its own ADR-0010
  on closure.

## Decision

### MB14.h.1 — observer-mode dispatcher (this ADR)

#### 1. `PerCpu.dispatch_observations: AtomicU64`

A new atomic counter on the `PerCpu` descriptor, incremented by the AP
observer every time it pops a task id from the per-CPU run-queue. The
counter is per-descriptor (one per CPU), `Release` on write, `Acquire`
on read — paired with the existing memory ordering on the other
`PerCpu` atomics (`tick_count`, `need_resched`).

API surface:

- `PerCpu::inc_dispatch_observation()` — called only by the observer.
- `PerCpu::dispatch_observations() -> u64` — polled by the BSP smoke.

The host-side unit tests pin: default-zero, monotonic-on-single-CPU,
per-descriptor isolation.

#### 2. `bare_metal::ap_dispatch::kernel_ap_dispatch_observe()`

A new module-local function exposed as `extern "C"` so a future
refactor can wire it directly into the IRQ-tail trampoline without
indirection. Body (bare-metal x86_64, observer-mode):

```text
let cpu = per_cpu::current_cpu();
let cpu_id = cpu.cpu_id();
if cpu.is_bsp() { return; }                       // defence-in-depth
if let Some(_picked) = per_cpu_run_queue::pop_for_cpu_with_stealing(cpu_id) {
    cpu.inc_dispatch_observation();                // discard the id
}
```

Notable choices:

- **Pop, not peek.** The observer consumes the queue entry. The BSP
  smoke enqueues a sentinel exactly once per boot; the observer
  drains it. This matches the intended semantics for MB14.h.2 (where
  the popped id will be the next task to run on this CPU) without
  introducing a peek API that would have to be retracted later.
- **Stealing fallback.** Reusing `pop_for_cpu_with_stealing` means an
  idle AP will steal from a busy sibling (including the BSP) even in
  observer mode. The smoke validates the local-pop path; the steal
  path is exercised by host-side tests in `per_cpu_run_queue::tests`
  and inherited transitively.
- **BSP early-return.** Defence-in-depth: should a future refactor
  accidentally route the BSP branch of `kernel_check_need_resched`
  through here, the dispatcher short-circuits rather than racing the
  legacy cooperative path. The host stub (used on `cargo test`) is a
  no-op for the same reason.

#### 3. IRQ-tail wire in `lapic::kernel_check_need_resched`

The AP branch (post-`take_resched`) now calls
`ap_dispatch::kernel_ap_dispatch_observe()` before returning. The BSP
branch is unchanged — it still falls through to the cooperative
`yield_current` path under `IN_SCHEDULER`.

#### 4. Boot-time smoke in `kmain`

Inserted immediately after the MB14.g per-CPU plumbing smoke, guarded
on `per_cpu::registered_ap_count() > 0` (single-CPU dev VMs report
`BSP-only` and skip):

```text
[mb14.h.1] ap_dispatch observed=N (ok | timeout — AP did not observe)
[mb14.h.1] ap_dispatch BSP-only — no AP enrolled
```

The poll budget (200 M busy-loop iterations) gives ~1 s on modern
silicon, an order of magnitude above the first AP timer tick after
`kernel_ap_lapic_init`.

### MB14.h.2 — cross-CPU context switch (roadmap, not yet implemented)

Captured here so the implementation review at MB14.h.2 closure can
verify the design held under contact with the hardware.

#### Safety invariants

1. **`SCHEDULER` is `static mut`; concurrent AP access requires a
   coarse lock.** The simplest path is a single `scheduling::SCHED_LOCK:
   AtomicBool` taken on the cooperative path *and* the AP observer
   path. Coarse but matches the rest of the kernel's spinlock style
   and pins the contention at the boot path's only hot spot. A
   finer-grained per-CPU dispatch table fragmenting `SCHEDULER` is a
   Phase 2 optimisation (P6.7+).

2. **`IN_SCHEDULER` becomes per-CPU.** Today the global flag
   `scheduling::IN_SCHEDULER` guards the BSP cooperative path. The
   straightforward swap is `PerCpu.in_scheduler: AtomicBool`, with the
   resched trampoline reading from `current_cpu()` instead of the
   global. Host tests keep the global for the legacy `target_os =
   "linux"` cfg branch (single-CPU semantics).

3. **TSS.rsp0 must be the per-CPU TSS.** MB14.c.2.d already allocates
   the per-AP TSS array (`bare_metal::tss::AP_TSS`). The current
   `tss::set_rsp0` writes to the global TSS only; the MB14.h.2 swap
   replaces it with `set_rsp0_for_cpu(cpu_id, kernel_stack_top)` that
   walks the AP TSS array by `cpu_id`. The BSP TSS write stays in
   place for the BSP path; an `if cpu_id == 0 { set_rsp0(...) } else
   { set_rsp0_for_cpu(...) }` shim covers the transition window.

4. **`nexacore_context_switch` is callable from an IRQ tail.** It is
   today (the BSP timer path uses it). The AP path arrives via the
   same trampoline (`nexacore_lapic_timer_handler` → `kernel_check_need_resched`
   → `yield_current`), so the only delta is which kernel stack is
   active when the asm runs — `RSP` has already been swapped to the
   per-AP kernel stack by `kmain_ap` step 3. No additional code
   change required.

5. **CR3 reload on user-task dispatch.** The existing BSP path
   (`scheduling::yield_current` bare-metal branch) reloads `CR3`
   before `context_switch` when the incoming task is a user process
   (MB13.f). This step is CPU-agnostic — the per-process PML4 mirrors
   the kernel half by reference (MB13.b ET_DYN), so the AP can issue
   `mov cr3, <phys>` without losing the next instruction fetch.

6. **IST stack sharing rules.** Today the IDT installs handlers on a
   single global IST (one stack frame per IST index, MB14.c.2.d
   allocates one IST per AP). The MB14.h.2 work needs to verify that
   every IST-bound handler (currently only `#DF` and `nexacore_tlb_shootdown_handler`)
   writes a `cpu_id`-indexed IST stack into the AP TSS — already
   done for `AP_TSS` at MB14.c.2.d but not yet pinned by tests.

#### Sequencing

MB14.h.2 will land as `MB14.h.2.a` (per-CPU `IN_SCHEDULER` + `SCHED_LOCK`)
followed by `MB14.h.2.b` (`set_rsp0_for_cpu` + live yield in the AP
observer). Each sub-step ships its own ADR closure note.

## Rationale

### Why observer-mode first

Lighting up cross-CPU context switching on Proxmox / QEMU has a small
debug surface — the kernel either boots or triple-faults, with serial
COM1 as the only post-mortem channel. Splitting the change so that
MB14.h.1 lands the wire (AP timer ISR reaches the per-CPU run-queue,
`gs:[0]` stays live across the call) without touching shared mutable
state collapses the MB14.h.2 risk surface to context-switch primitives
alone.

The cost is one extra commit and one extra boot smoke; the benefit is
that, if MB14.h.2 triple-faults, the regression is narrowly bounded to
items (2)-(5) in the Context section.

### Why discard the popped task

In observer mode the popped id is not re-enqueued. Three reasons:

1. **Re-enqueuing creates a hot loop** — the AP would pop the sentinel
   on every tick forever, masking a real regression where a second
   sentinel never lands.
2. **The MB14.h.2 successor is a live `yield_current`** — at that
   point the popped id will be the next task to run, not a sentinel.
   Pop-and-discard makes the MB14.h.1 → MB14.h.2 diff small (replace
   the discard branch with a call into `SCHEDULER.yield_current`).
3. **Cross-CPU re-enqueue races the BSP** — without a per-CPU
   `SCHED_LOCK`, an AP-side re-enqueue concurrent with the BSP's
   `yield_current` corrupts `run_queues`. MB14.h.2 introduces that
   lock; MB14.h.1 avoids the dependency.

### Why a counter and not a return value

The BSP smoke needs to *observe* the AP's activity from a different
CPU. A return value from `kernel_ap_dispatch_observe` would only reach
the AP's stack frame — the BSP cannot see it. An atomic counter on
the per-CPU descriptor is BSP-readable via `ap_slot(cpu_id)` and
cross-CPU coherent under the existing `Release` / `Acquire` pairing on
the other `PerCpu` atomics.

## Consequences

### Positive

- The AP timer ISR now reaches the per-CPU run-queue every tick, with
  bounded execution time and zero shared-mutable state.
- The BSP boot-time smoke (`[mb14.h.1] ap_dispatch observed=N ...`)
  proves end-to-end reachability from queue enqueue to AP-side pop,
  without any context-switch risk.
- The MB14.h.2 diff is constrained to the discard branch — the wire
  itself is already verified at boot.
- The `dispatch_observations` counter becomes a long-lived
  diagnostic: a future regression in the AP timer path surfaces as
  `observed=0` on the next boot.

### Negative

- The observer consumes queue entries without dispatching them. If a
  caller mistakes the per-CPU run-queue for the canonical task pool
  (it is not — the scheduler `tasks` / `processes` vectors are
  authoritative), entries vanish silently. Documented in
  `ap_dispatch.rs` and pinned by the host stubs.
- Adds a per-CPU `AtomicU64` to every `PerCpu` (32 × 8 = 256 bytes).
  Negligible against the per-AP kernel stack (4 KiB) + IST stacks (2 ×
  4 KiB) + TSS already allocated.

### Neutral

- The MB14.h.2 timeline is unchanged: the observer is an additive
  step on the critical path, not a detour.

## References

- Intel SDM Vol 3A § 10.4 — Local APIC
- Intel SDM Vol 3A § 7   — Task Management (TSS / IST)
- ADR-0002 — Kernel stack isolation (MB10)
- ADR-0004 — Userspace Ring 3 + per-process CR3 (MB11)
- ADR-0007 — MB14 MP/AP startup
- ADR-0008 — MB14.f per-CPU LAPIC scheduling protocol
- `crates/nexacore-kernel/src/bare_metal/per_cpu.rs` — `PerCpu` layout
- `crates/nexacore-kernel/src/bare_metal/ap_dispatch.rs` — observer body
- `crates/nexacore-kernel/src/bare_metal/lapic.rs` — `kernel_check_need_resched` AP branch
- `crates/nexacore-kernel/src/bare_metal/per_cpu_run_queue.rs` — pop / stealing primitives
- `crates/nexacore-kernel/src/lib.rs` — `kmain` boot smoke

## History

- **2026-05-20** — *Accepted* for MB14.h.1 scope. MB14.h.2 captured as
  roadmap; will open ADR-0010 on closure.
