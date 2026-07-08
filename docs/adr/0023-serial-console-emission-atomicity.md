# ADR-0023: Serial Console Emission Atomicity (Whole-Buffer Lock for `WriteConsole`)

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar
**Refs:** PLAN.md TASK-03, todo-desktop.md CHECKPOINT 20 item 3, commit `8a89206`

## Context

Serial (COM1) output is the primary diagnostics channel for hardware
verification on the test VM. Three writer classes share it:

1. **Kernel boot logging** — lines composed piecewise from multiple
   `early_console::write_str` / `write_usize` calls (261 call sites in
   `driver_loader.rs` alone).
2. **Ring 3 `WriteConsole` (syscall 60)** — user buffers copied via the
   `uaccess` SMAP layer in 256-byte chunks, each chunk emitted separately.
3. **Panic path** — non-allocating, interrupts already disabled, must never
   block.

Commit `8a89206` made each *single* `emit(bytes)` slice atomic against LAPIC
timer preemption by masking IF for the slice duration. Two splice windows
remain:

- A user buffer larger than 256 bytes is emitted as several independent
  atomic chunks; a preempt landing between chunks interleaves another task's
  output into the middle of one logical user write.
- A kernel line built from N `write_str` calls can be preempted between
  slices; the dispatched Ring 3 task's (atomic) write then lands mid-line —
  the fused-line artifact `[driver-loader]   bus[nexacore-net] service starting`
  observed on the test VM.

Additionally, the module was **not host-testable**: on an `x86_64` host the
`arch` module exposes the *real* `cli`/`outb` instructions (ring-3 execution
faults — the same class as the historical P10.3 SIGSEGV), so no unit test
could exercise emission interleaving.

## Decision

1. **Console guard primitive** (`early_console::lock() -> ConsoleGuard`):
   an RAII guard that (a) snapshots and disables IF, then (b) acquires a
   global `spin::Mutex<()>` (`CONSOLE_LOCK`). Release order is the inverse:
   mutex first, then conditional IF restore. Acquisition order (IF off →
   mutex) guarantees a same-CPU holder can never be preempted while holding
   the lock, so a second task on the same CPU can never spin on a parked
   holder; cross-CPU waiters spin bounded by the holder's drain time. The
   mutex is future-proofing for SMP consoles (APs currently never emit).

2. **`emit()` = `lock()` + whole-slice byte loop** — behavior identical to
   today for single slices; `write_str`/`write_usize` unchanged semantics
   (`write_usize` now routes its single `'0'` byte through `emit` too).

3. **`WriteConsole` whole-buffer atomicity, bounded**: the syscall handler
   takes the guard **once** and emits every 256-byte chunk under it when
   `len <= ATOMIC_CONSOLE_WRITE_MAX = 1024` bytes. The `uaccess`
   STAC/CLAC bracketing per chunk is unchanged (page-probe precedes the
   copy, WI-4b #32, so no #PF is possible inside the IF-off window). Larger
   writes keep today's per-chunk atomicity. Rationale for 1024: it mirrors
   `PANIC_RECORD_MAX_BYTES` and its documented drain budget (≈ 90 ms at
   115 200 baud) — the longest IF-off window the project already accepts.
   An unbounded atomic window would let an adversarial Ring 3 task freeze
   scheduling for seconds (Security > Stability: bounded by design). Real
   log lines are far below 1 KiB, so the acceptance behavior (no fused
   lines) is covered. No syscall ABI change.

4. **Panic path bypasses the lock**: `emit_raw()` becomes a genuinely
   lock-free byte loop and `panic.rs` uses it exclusively. A panic raised
   *while the console lock is held* (e.g. an exception inside an emitting
   context) must still produce forensics; spinning on the dead holder's
   mutex would deadlock the machine. The cost is that a panic record may
   splice into a partially-emitted line — forensics beat formatting.

5. **Host-testable backend split**: the byte sink and IF control are
   cfg-selected — real UART + real IF masking only on
   `target_arch = "x86_64", target_os = "none"`; a `std`-backed test sink
   under `cfg(test)` on hosts; no-ops otherwise (unchanged for non-x86
   hosts). This removes the latent host-fault (`cli` from ring 3) and makes
   the interleaving guarantee assertable in `cargo test`.

## Alternatives Considered

- **Buffer kernel lines and emit once per line** (CP20 item 3 suggestion):
  correct but requires touching every piecewise call site (261 in
  `driver_loader.rs` alone) or a `core::fmt` writer with a line buffer on
  the panic-sensitive path. Deferred — the guard primitive introduced here
  is the building block; call-site migration can happen incrementally.
- **Unbounded whole-buffer lock** (lock once regardless of `len`): simplest
  and matches the TASK-03 wording literally, but hands Ring 3 an
  IF-off-for-seconds DoS primitive. Rejected on Security > Stability.
- **Per-byte locking (status quo ante `8a89206`)**: maximal fairness, no
  line coherence at all. Rejected — diagnostics are the prerequisite for
  every later hardware investigation (TASK-04/05).
- **`spin::Mutex` only, no IF masking**: insufficient on a single CPU — a
  timer preempt while holding the mutex parks the holder; any other task
  emitting then spins forever (cooperative scheduler, no priority
  inheritance). IF-first ordering is load-bearing.

## Consequences

- One logical `WriteConsole` ≤ 1 KiB can never interleave with any other
  emission (kernel or user) — fused-line grep on a full the test VM boot must
  return 0 for user-vs-user and user-vs-kernel-slice splices.
- Kernel piecewise lines remain splice-able *between* slices (only their
  individual slices are atomic). Full kernel-line coherence is follow-up
  work on top of `ConsoleGuard` (tracked in todo-desktop CP20 item 3).
- The panic path is documented as lock-bypassing; its output may splice.
- `early_console` is now unit-tested on hosts, including the concurrency
  guarantee (thread-based interleaving test against the test sink).
