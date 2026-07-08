# ADR-0025: Scheduler Fairness — Slot-Table Class Rotation in `pick_next`

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar
**Refs:** PLAN.md TASK-06, todo-desktop.md CHECKPOINT 8/10/24,
`docs/plans/bug5-scheduler-user-resume.md` (context-switch constraints)

## Context

`RoundRobinScheduler::pick_next` (`scheduling.rs:671`) is strict-priority
FIFO: it walks the per-class run queues in `PriorityClass` order and returns
the first runnable task. The System-class service loops (`nexacore-net`, the
virtio-net driver) are busy-poll loops that `TaskYield` when idle — each
yield re-enqueues them at the back of the System queue, so as long as ANY
System task is runnable, **no Interactive (shell) or Background task ever
runs** (CHECKPOINT 10). Observed consequences:

- The shell (Interactive, `lib.rs:1941`) never prints its REPL banner on
  the test VM (operator-approved deferral from TASK-01/03 to this task).
- `nexacore-netcheck` had to be spawned at System priority as an explicit
  temporary mitigation (`lib.rs:2098` comment) — the acceptance for this
  task removes it.

PLAN.md offers exactly two policies: **(a)** time-slice round-robin between
classes, or **(c)** a kernel multi-channel block-wait primitive (services
block on their IPC channels and stop being runnable when idle). This is a
Ring 0 change in the same family as Bug 5, so the chosen design must not
perturb the context-switch path (`yield_current`'s dispatch block, the
`saved_rsp == 0` first-dispatch sentinel machinery) and requires adversarial
review before deploy.

## Decision

**Option (a), as a deterministic slot-table rotation inside `pick_next`** —
no changes to enqueue/dequeue, `yield_current`'s dispatch block, the per-CPU
queues, any syscall, or any userspace image's structure.

A `pick_counter` cycles through an 8-slot table:

```text
slot:    0       1       2            3       4            5            6       7
prefer:  strict  strict  Interactive  strict  AiInference  Interactive  strict  Background
```

- A `strict` slot behaves exactly like today (System first, class order).
- A *preferred* slot tries the named class's queue first and **falls back
  to strict order when that queue is empty** — fairness slots are never
  wasted on idle classes.
- FIFO order within every class is unchanged.

### Guarantees (under full contention, per 8-pick window)

| Class       | Picks | Bound                                       |
|-------------|-------|---------------------------------------------|
| System      | 4 (+ all fallbacks) | unchanged dominance               |
| Interactive | 2     | a runnable Interactive task waits ≤ 6 picks |
| AiInference | 1     | waits ≤ 8 picks                             |
| Background  | 1     | waits ≤ 8 picks                             |

Starvation is impossible by construction: every class with a runnable task
is first-preference at least once per cycle. Priority is respected "a
parità di condizioni": System > Interactive > AiInference ≥ Background in
guaranteed throughput. `Idle` keeps its strict-order position (never named
by a fairness slot; runs only when everything else is empty).

**`RealTime` caveat (adversarial-review finding #3):** the enum already
ranked System *above* RealTime (pre-existing, unchanged), but the fairness
slots add a NEW inversion: when System is idle, a runnable RealTime task —
which strict priority would have given every pick — now loses the 4
preferred slots per cycle to Interactive/AiInference/Background (it keeps
the 4 strict slots, so it cannot starve). No RealTime task exists today;
**before Phase 2 spawns RealTime workloads** one of these must land
(tracked in the backlog P11.1): move RealTime above System in the enum, give
RealTime a strict bypass ahead of the slot table, or supersede this
mechanism with option (c).

> **Resolved 2026-06-12 (plan WS1-01):** the strict-bypass option landed —
> `pick_next` drains a runnable RealTime task ahead of the slot table
> (and of System), without advancing `pick_counter`, so the non-RealTime
> pick subsequence follows this ADR's rotation verbatim and every
> guarantee in the table above is unchanged. Residual: the per-CPU AP
> dispatch path (`per_cpu_run_queue::pop_front`) still ranks by enum
> discriminant; flagged in the backlog P11.1 for when RealTime workloads
> become AP-schedulable.

### Companion change

`nexacore-netcheck` returns to **Background** priority (`lib.rs:2098`), removing
the documented temporary mitigation — the acceptance scenario (2 busy System
loops + 1 Interactive + 1 Background all make progress) is exactly the M0
boot topology.

## Alternatives Considered

- **(c) Multi-channel block-wait primitive** (services block on
  `{cmd_ch, irq_ch}` / `{stack, evt_ch}` and leave the run queue when
  idle): the better end-state — it eliminates busy-polling entirely (CPU
  and power) rather than rationing it. Rejected *for this task* on blast
  radius: it needs a new stable syscall (number + ABI + stability assert),
  multi-queue waiter membership with wake-time removal from sibling queues
  (interacting with the WI-2 waiter-dedup bounds), rewritten service loops
  in BOTH images, and analysis of the interplay with the relay's blocking
  rendezvous. Every one of those surfaces is adversarial-review territory;
  the rotation achieves the acceptance criteria touching none of them.
  Tracked as the natural follow-up when TASK-11 reworks service IPC for
  the AI runtime wiring.
- **Priority aging / dynamic boosts** (decay a starved task's effective
  class): classic, but stateful per-task and timing-dependent — harder to
  test deterministically and to bound formally. The slot table gives exact,
  enumerable guarantees with one `u64` of state.
- **Time-slice budgets per class (true quantum accounting):** requires
  hooking the LAPIC tick into per-class budget bookkeeping (a Ring 0 timer
  path change — exactly the family of code this task must avoid touching).
  The pick-granularity rotation approximates it because every System
  service yields each iteration (their loop structure makes pick counts ≈
  time slices).

## Consequences

- The shell reaches its REPL while both service loops are live; netcheck
  completes the M0 exchange from Background (re-verified on the test VM as part
  of this task, capture in CHECKPOINT 25).
- System services lose at most 4/8 of pick bandwidth under full contention
  — in practice less, since fairness slots fall back to strict order
  whenever lower classes are idle. M0 latency impact is negligible (the
  netcheck poll loop yields anyway).
- The scheduler gains one `u64` counter and a `const` table; the
  context-switch path, first-dispatch sentinel (`saved_rsp == 0`), TSS/CR3
  reload logic, and per-CPU stealing are byte-identical.
- Host tests can assert exact pick sequences (the table is deterministic).
