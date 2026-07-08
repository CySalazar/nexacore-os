//! Process and thread scheduling.
//!
//! ## Status
//!
//! P6.4 scaffold. Trait surface for the [`Scheduler`] is defined; the
//! v1 reference implementation (a multi-level feedback queue with
//! thermal awareness and an AI-workload class) lands once IPC is
//! operational.
//!
//! ## Design rationale
//!
//! - **One scheduler trait, multiple policies.** The kernel ships a
//!   default scheduler; alternate policies are an NCIP-ratified extension
//!   point.
//! - **AI workloads are a distinct class.** AI inference produces bursty,
//!   memory-bandwidth-bound load that interacts poorly with classic
//!   round-robin. The scheduler is aware of an `AI_PRIORITY_CLASS` and
//!   factors NPU/GPU availability into dispatch.
//! - **Thermal awareness.** On hardware that exposes temperature
//!   counters, the scheduler can throttle a class without throttling
//!   the whole CPU.

// The scheduler interfaces directly with `nexacore_context_switch` (assembly)
// and reads/writes `TaskControlBlock::context.rsp` via raw pointers; the
// kernel-task spawn path also relies on raw pointer arithmetic over the
// bootloader direct-map. Each `unsafe` block carries a `// SAFETY:` comment.
#![allow(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    reason = "trait scaffold methods return NotYetImplemented until full scheduler activates"
)]
#![allow(
    clippy::doc_markdown,
    reason = "module references inline asm symbols (`nexacore_context_switch`) without ticks in prose"
)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{KernelError, KernelResult};

// -----------------------------------------------------------------------------
// MB8 preemption signaling — atomic flags used by the LAPIC timer path
// -----------------------------------------------------------------------------

/// LAPIC quantum-expired flag.
///
/// Set to `true` by the LAPIC timer tick when the current task's quantum has
/// expired. Consumed by `kernel_check_need_resched` (bare_metal::lapic) at the
/// safe tail of the timer interrupt, just before `iretq`.
///
/// Decoupling the tick (sets the flag, returns immediately) from the actual
/// `yield_current` call (runs at the very end of the IRQ stub, with the trap
/// frame still in place) keeps the interrupt path lock-free and isolates the
/// scheduler from re-entrancy by future interrupt sources (keyboard, disk,
/// NIC) that may set the same flag without knowing how a context switch
/// works.
pub static NEED_RESCHED: AtomicBool = AtomicBool::new(false);

/// Scheduler-recursion guard.
///
/// Set to `true` for the duration of any call into `RoundRobinScheduler::yield_current`
/// (or `preempt`). The timer interrupt's `check_need_resched` consults this to
/// avoid recursing into the scheduler if the previous yield (e.g. from a
/// cooperative `TaskYield` syscall) is still on the stack.
///
/// **MB14.h.2 (bare-metal MP) — superseded by the per-CPU equivalent.**
/// On bare-metal x86_64 the BSP and every AP now consult
/// `super::bare_metal::per_cpu::current_cpu().enter_scheduler()` /
/// `leave_scheduler()` instead of this global, so a concurrent BSP+AP
/// yield cannot poison a sibling CPU's guard. This static remains
/// active on host / `target_os = "linux"` test builds where
/// `current_cpu()` collapses to a single descriptor and the global
/// flag's single-CPU semantics still hold.
pub static IN_SCHEDULER: AtomicBool = AtomicBool::new(false);

/// MB14.h.2 — cross-CPU coarse spinlock serialising mutations of the
/// global `SCHEDULER` (`tasks` / `processes` / `run_queues` legacy mirror).
///
/// The BSP and every AP attempt `try_acquire` before entering
/// `RoundRobinScheduler::yield_current`; the winner runs the scheduler
/// body, the loser short-circuits (the next tick will retry). Coarse
/// because Phase 1 has only one scheduler instance — a finer-grained
/// per-CPU dispatch table fragmenting `SCHEDULER` is a P6.7+ refactor
/// (see ADR-0010 § Negative consequences).
///
/// Pairs with `super::bare_metal::per_cpu::PerCpu::enter_scheduler`:
/// the per-CPU flag stops *re-entrant* scheduler calls on the *same* CPU;
/// `SCHED_LOCK` stops *concurrent* scheduler calls across *different*
/// CPUs. Both must hold for the duration of one `yield_current` body.
pub static SCHED_LOCK: AtomicBool = AtomicBool::new(false);

/// MB14.h.2 — non-blocking attempt to claim the cross-CPU scheduler lock.
///
/// Returns `true` if the caller now owns the lock (and must release it
/// via [`release_sched_lock`]); `false` if another CPU holds it.
/// Callers should short-circuit on `false` rather than spinning so the
/// IRQ tail returns promptly — the next timer tick will retry.
#[must_use]
pub fn try_acquire_sched_lock() -> bool {
    SCHED_LOCK
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// MB14.h.2 — release the cross-CPU scheduler lock. Must only be
/// called after a successful [`try_acquire_sched_lock`].
pub fn release_sched_lock() {
    SCHED_LOCK.store(false, Ordering::Release);
}

// -----------------------------------------------------------------------------
// Task identifier
// -----------------------------------------------------------------------------

/// Kernel-side task identifier. Opaque to userspace.
///
/// Distinct from `nexacore_types::AgentId` (an agent is a higher-level
/// concept that may map to multiple tasks). The kernel does not know
/// about agents; userspace bridges the two via the runtime service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(pub u64);

/// Priority class for a task.
///
/// The enum is `#[repr(u8)]` so it can be stored compactly in the task
/// control block.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PriorityClass {
    /// System (kernel-internal services).
    System = 0,
    /// Real-time (e.g., audio, video).
    ///
    /// P11.1 / WS1-01: the discriminant order is a queue-indexing detail
    /// only — `pick_next` gives RealTime a strict bypass ahead of both the
    /// fairness slot table and the System queue, so the EFFECTIVE
    /// scheduling rank is RealTime above System. (The per-CPU AP dispatch
    /// path still ranks by discriminant; see
    /// `per_cpu_run_queue::PerCpuRunQueue::pop_front`.)
    RealTime = 1,
    /// Interactive (foreground user processes).
    Interactive = 2,
    /// AI inference (bursty, memory-bandwidth-bound).
    AiInference = 3,
    /// Background (batch work, indexing).
    Background = 4,
    /// Idle.
    Idle = 5,
}

// -----------------------------------------------------------------------------
// Scheduler state
// -----------------------------------------------------------------------------

/// State of a task as the scheduler sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskState {
    /// The task is on the run queue.
    Runnable,
    /// The task is executing on a CPU.
    Running,
    /// The task is blocked on IPC.
    BlockedOnIpc,
    /// The task is blocked on a syscall.
    BlockedOnSyscall,
    /// The task is sleeping until a deadline.
    Sleeping,
    /// The task has exited.
    Terminated,
}

// -----------------------------------------------------------------------------
// Scheduler trait
// -----------------------------------------------------------------------------

/// The scheduler trait.
///
/// The kernel holds exactly one `dyn Scheduler` per CPU. Cross-CPU work
/// stealing is implemented inside the chosen scheduler, not at the trait
/// boundary; this keeps the trait small and lets specific schedulers
/// pick the right policy.
pub trait Scheduler {
    /// Adds `task` to the scheduler's queues with the given priority.
    fn enqueue(&mut self, task: TaskId, priority: PriorityClass) -> KernelResult<()>;

    /// Removes `task` from the scheduler. Called when the task exits.
    fn dequeue(&mut self, task: TaskId) -> KernelResult<()>;

    /// Selects the next task to run on this CPU. Returns `None` if no
    /// task is runnable (in which case the caller can idle the CPU).
    fn pick_next(&mut self) -> Option<TaskId>;

    /// Records that the currently-running task is yielding the CPU
    /// voluntarily (e.g., it blocked on IPC).
    fn yield_current(&mut self, current: TaskId, new_state: TaskState) -> KernelResult<()>;

    /// Records that the currently-running task has exhausted its time
    /// slice; the scheduler may rotate it to the back of its priority
    /// queue.
    fn preempt(&mut self, current: TaskId) -> KernelResult<()>;
}

// -----------------------------------------------------------------------------
// CpuContext & TaskControlBlock — MB6
// -----------------------------------------------------------------------------

/// Saved CPU context for a kernel task.
///
/// Only RSP is stored here; the full callee-saved register set is pushed onto
/// the task's kernel stack by `context_switch` before saving RSP.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CpuContext {
    /// Saved kernel stack pointer. Points to the top of the callee-saved
    /// frame that `context_switch` left on the stack.
    pub rsp: u64,
}

/// Per-task kernel state (Task Control Block).
#[derive(Debug)]
pub struct TaskControlBlock {
    /// Kernel-side identifier.
    pub id: TaskId,
    /// Current scheduling state.
    pub state: TaskState,
    /// Priority class assigned at creation.
    pub priority: PriorityClass,
    /// Saved CPU context (kernel-stack RSP + callee-saved regs on that stack).
    pub context: CpuContext,
    /// Physical base address of this task's kernel stack (4 KiB frame).
    /// Retained for deallocation in `TaskExit` (MB7+).
    pub kernel_stack_phys: u64,
    /// Virtual base address of the task's kernel stack (MB10): the *bottom*
    /// of the writable 4 KiB page (its *top* is `kernel_stack_va +
    /// KERNEL_STACK_SIZE`). `0` is the sentinel used by
    /// `spawn_bootstrap_task` — the bootstrap kmain task re-uses the boot
    /// stack and has no entry in the isolated VA range.
    pub kernel_stack_va: u64,
}

// -----------------------------------------------------------------------------
// MB10 — Kernel stack isolation constants
// -----------------------------------------------------------------------------

/// Base of the kernel-only VA range that holds kernel-task stacks.
///
/// `0xFFFF_C000_0000_0000` is half-canonical kernel-half on x86_64 long mode;
/// disjoint from the bootloader's direct-map (`0xFFFF_8800_…` on
/// `bootloader 0.11`) and from the future user-space range planned for MB11
/// (`0x0000_0040_…`). See `docs/adr/0002-mb10-kernel-stack-isolation.md`.
pub const KERNEL_STACK_VA_BASE: u64 = 0xFFFF_C000_0000_0000;

/// Exclusive upper bound of the kernel-stack VA range.
///
/// 8 TiB of address space (`~1 G slots`), ample for Phase 1.
pub const KERNEL_STACK_VA_END: u64 = 0xFFFF_C800_0000_0000;

/// Writable kernel-stack size per task, in bytes (16 KiB, 4 frames).
///
/// Enlarged from a single 4 KiB frame (2026-06-03) when the SYSCALL fast path
/// was migrated off the user stack onto this per-task kernel stack
/// (`nexacore_syscall_entry`): the deep syscall call chains — notably the
/// kernel→nexacore-net socket relay (`net_socket_relay_full`) with its postcard
/// encode + IPC send/receive — need more than 4 KiB of kernel stack. The guard
/// page below still traps overflow with `#PF`.
pub const KERNEL_STACK_SIZE: u64 = 0x4000;

/// Address-space stride per slot.
///
/// 16 KiB guard region (not mapped) + 16 KiB stack region (mapped). Walking the
/// range by `KERNEL_STACK_STRIDE` gives the *guard* VA of each slot; adding
/// `KERNEL_STACK_SIZE` (= guard size) gives the writable stack base. Mirrors
/// the userspace stack geometry (`user_stack::USER_STACK_STRIDE`).
pub const KERNEL_STACK_STRIDE: u64 = 0x8000;

// -----------------------------------------------------------------------------
// RoundRobinScheduler — MB6 concrete implementation
// -----------------------------------------------------------------------------

const NUM_PRIORITY_CLASSES: usize = 6;

/// Cooperative, single-CPU, round-robin scheduler.
///
/// One run queue per [`PriorityClass`]. `pick_next` first drains a runnable
/// `RealTime` task (P11.1 strict bypass), then consults the TASK-06
/// fairness slot table, then falls back to a strict scan from `System` (0)
/// to `Idle` (5), taking the head of the first non-empty queue. No
/// preemption in MB6 — the LAPIC timer and `preempt` path land in MB7.
pub struct RoundRobinScheduler {
    /// All task control blocks (searched by `TaskId`).
    tasks: Vec<TaskControlBlock>,
    /// MB11 — user-process control blocks, parallel to `tasks` by
    /// `TaskId`. A task with a matching PCB entry is a userspace
    /// process; absence means a kernel-only task (idle, bootstrap).
    #[cfg(feature = "bare-metal")]
    processes: Vec<crate::process::ProcessControlBlock>,
    /// Per-priority run queues storing `TaskId.0` values.
    run_queues: [Vec<u64>; NUM_PRIORITY_CLASSES],
    /// `TaskId.0` of the task currently on-CPU (`None` until first switch).
    current: Option<u64>,
    /// Monotonically increasing counter for fresh `TaskId` allocation.
    /// Read only in cfg-gated code (bare-metal + test); suppress the lint.
    #[allow(dead_code)]
    next_id: u64,
    /// MB10 — index of the next kernel-stack slot to hand out from the
    /// isolated VA range `[KERNEL_STACK_VA_BASE, KERNEL_STACK_VA_END)`.
    /// Pure bump allocator: slots are never reused (task-exit dealloc
    /// arrives with the process model in MB11+).
    ///
    /// Read only by `allocate_stack_slot`, which itself is cfg-gated for
    /// the bare-metal x86_64 spawn path and the host-side unit tests.
    /// Suppress dead-code lint on non-x86_64 host clippy runs.
    #[allow(dead_code)]
    next_kernel_stack_slot: usize,
    /// TASK-06 / ADR-0025 — monotonic pick counter driving the fairness
    /// slot rotation in [`Scheduler::pick_next`]. Increments on every
    /// `pick_next` call NOT satisfied by the P11.1 strict RealTime bypass
    /// (including calls that return `None`); wraps. The slot index is
    /// `pick_counter % FAIRNESS_CYCLE.len()`. Freezing the phase across
    /// RealTime bursts keeps the non-RealTime pick subsequence identical
    /// to the ADR-0025 rotation, preserving its starvation bounds.
    pick_counter: u64,
    /// WS1-10 — current CPU thermal band, fed by [`Self::set_cpu_temperature`].
    /// `Normal` by default, so [`crate::thermal::fairness_cycle_for`] returns the
    /// unmodified ADR-0025 cycle and behaviour is identical until a temperature
    /// reading raises it.
    thermal: crate::thermal::ThermalLevel,
    /// WS1-10 — the dominant runnable load class the platform last reported, fed
    /// by [`Self::set_cpu_load_class`]. Makes the thermal AiInference favour
    /// *workload-aware* (see [`crate::thermal::should_favour_ai`]).
    cpu_load_class: PriorityClass,
}

/// TASK-06 / ADR-0025 — deterministic fairness rotation for `pick_next`.
///
/// One entry per slot of the 8-pick cycle. `None` = strict priority order
/// (System first, exactly the pre-TASK-06 behaviour); `Some(class)` = try
/// `class`'s run queue first, falling back to strict order when that queue
/// is empty — a fairness slot is never wasted on an idle class.
///
/// Guarantees under full contention, per 8-pick window: System 4 picks
/// (plus every fallback), Interactive 2, `AiInference` 1, Background 1 —
/// so no class with a runnable task can starve (every class is
/// first-preference at least once per cycle), while priority remains
/// respected at parity (System > Interactive > `AiInference` ≥ Background
/// in guaranteed throughput). `Idle` keeps its strict-order position;
/// `RealTime` is never named by a slot because the P11.1 strict bypass in
/// `pick_next` drains it ahead of the whole table. See the ADR for the
/// alternatives analysis and review finding #3 for the bypass rationale.
pub(crate) const FAIRNESS_CYCLE: [Option<PriorityClass>; 8] = [
    None,
    None,
    Some(PriorityClass::Interactive),
    None,
    Some(PriorityClass::AiInference),
    Some(PriorityClass::Interactive),
    None,
    Some(PriorityClass::Background),
];

/// Cycle length as `u64` for the `pick_counter` modulo — `2^64 % 8 == 0`,
/// so the slot sequence is seamless across counter wraparound.
const FAIRNESS_LEN: u64 = FAIRNESS_CYCLE.len() as u64;

impl RoundRobinScheduler {
    /// Create an empty scheduler.
    ///
    /// `const fn` so it can initialise a `static mut` without a lazy wrapper.
    #[allow(
        clippy::new_without_default,
        reason = "const fn required for static mut SCHEDULER init; Default cannot be const"
    )]
    pub const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            #[cfg(feature = "bare-metal")]
            processes: Vec::new(),
            run_queues: [
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ],
            current: None,
            next_id: 1,
            next_kernel_stack_slot: 0,
            pick_counter: 0,
            thermal: crate::thermal::ThermalLevel::Normal,
            cpu_load_class: PriorityClass::Interactive,
        }
    }

    /// Report the current CPU temperature (milli-°C) to the scheduler (WS1-10.2).
    ///
    /// Updates the thermal band consulted by [`Scheduler::pick_next`]; while the
    /// band is `Normal` the fairness rotation is identical to ADR-0025.
    pub fn set_cpu_temperature(&mut self, cpu_temp_millicelsius: u32) {
        self.thermal = crate::thermal::thermal_level(cpu_temp_millicelsius);
    }

    /// Report the dominant runnable load class to the scheduler (WS1-10.3).
    ///
    /// Makes the thermal AiInference favour workload-aware: the boost is intended
    /// for AI-dominated load (see [`crate::thermal::should_favour_ai`]).
    pub const fn set_cpu_load_class(&mut self, class: PriorityClass) {
        self.cpu_load_class = class;
    }

    /// The CPU thermal band the scheduler is currently using (WS1-10).
    #[must_use]
    pub const fn thermal_level(&self) -> crate::thermal::ThermalLevel {
        self.thermal
    }

    /// The dominant load class the scheduler last observed (WS1-10.3).
    #[must_use]
    pub const fn cpu_load_class(&self) -> PriorityClass {
        self.cpu_load_class
    }

    /// MB11 — allocate a fresh `TaskId` without enqueuing anything.
    /// Used by `ProcessControlBlock::spawn_from_elf` to reserve an ID
    /// before fully constructing the PCB.
    pub fn allocate_task_id(&mut self) -> TaskId {
        let id = TaskId(self.next_id);
        self.next_id += 1;
        id
    }

    /// MB11 — register a constructed `TaskControlBlock` with the
    /// scheduler at the given priority and enqueue it as Runnable.
    /// Mirror of `mock_enqueue` for the user-process spawn path.
    #[allow(
        clippy::indexing_slicing,
        reason = "priority as usize < NUM_PRIORITY_CLASSES by enum repr"
    )]
    pub fn register_process(&mut self, tcb: TaskControlBlock, priority: PriorityClass) {
        let id_u64 = tcb.id.0;
        self.tasks.push(tcb);
        self.run_queues[priority as usize].push(id_u64);
    }

    /// MB11 — attach the per-process page-table + user stack metadata.
    /// The `task` field inside the PCB is a defensive duplicate of the
    /// TCB registered in `tasks`; the scheduler uses the PCB only when
    /// it needs CR3 / user_entry / user_stack_top context.
    #[cfg(feature = "bare-metal")]
    pub fn attach_process(&mut self, _id: TaskId, pcb: crate::process::ProcessControlBlock) {
        self.processes.push(pcb);
    }

    /// MB11 — look up the PCB for the given `TaskId`, if any.
    /// Returns `None` for kernel-only tasks (idle, bootstrap).
    #[cfg(feature = "bare-metal")]
    #[must_use]
    pub fn process(&self, id: TaskId) -> Option<&crate::process::ProcessControlBlock> {
        self.processes.iter().find(|p| p.task.id.0 == id.0)
    }

    /// P6.7.8.1 — look up the PCB for the given `TaskId` for mutation.
    /// Used by the `MmioMap` syscall handler to record the per-process
    /// MMIO mapping table entry on a successful install, and by
    /// `task_exit` to drain the table at teardown.
    #[cfg(feature = "bare-metal")]
    pub fn process_mut(&mut self, id: TaskId) -> Option<&mut crate::process::ProcessControlBlock> {
        self.processes.iter_mut().find(|p| p.task.id.0 == id.0)
    }

    /// P11.2 (WS1-02) — resolve the scheduling class for `id`: TCB
    /// (`self.tasks`) first, PCB second, `Interactive` last.
    ///
    /// The TCB is the live source of truth — `enqueue` rewrites
    /// `tcb.priority` on every re-enqueue, while the PCB's `task` field
    /// is a defensive duplicate frozen at spawn. Kernel-only tasks
    /// (idle, the bootstrap kmain task) own a TCB but no PCB; with the
    /// previous PCB-only lookup they hard-fell to `Interactive` on
    /// unpark, demoting a System task into fairness slots 2/5 instead
    /// of the strict System sweep. Used by the syscall-entry `unpark`
    /// path to pick the re-enqueue class.
    #[must_use]
    pub fn resolve_priority(&self, id: TaskId) -> PriorityClass {
        // 1. TCB — authoritative, present for every registered task.
        if let Some(tcb) = self.tasks.iter().find(|t| t.id.0 == id.0) {
            return tcb.priority;
        }
        // 2. PCB — defensive fallback should a process ever hold a PCB
        //    without its TCB twin in `tasks`.
        #[cfg(feature = "bare-metal")]
        if let Some(pcb) = self.process(id) {
            return pcb.task.priority;
        }
        // 3. Unknown id — keep the historical `Interactive` default.
        PriorityClass::Interactive
    }

    /// MB10 — returns the next kernel-stack VA slot, advancing the bump
    /// allocator. Returns `None` if the isolated range is exhausted
    /// (would require ~1 G task spawns).
    ///
    /// Called only by `spawn_kernel_task` (bare-metal x86_64) and by the
    /// host-side unit tests; suppress dead-code lint on non-x86_64
    /// `cargo clippy --workspace` runs.
    #[allow(dead_code)]
    pub(crate) fn allocate_stack_slot(&mut self) -> Option<u64> {
        let slot = self.next_kernel_stack_slot as u64;
        let slot_base = KERNEL_STACK_VA_BASE.checked_add(slot.checked_mul(KERNEL_STACK_STRIDE)?)?;
        // Guard page sits at slot_base; stack page sits at slot_base +
        // KERNEL_STACK_SIZE; stack top (the value used for the initial RSP)
        // is slot_base + KERNEL_STACK_STRIDE — must remain inside the range.
        let stack_top = slot_base.checked_add(KERNEL_STACK_STRIDE)?;
        if stack_top > KERNEL_STACK_VA_END {
            return None;
        }
        self.next_kernel_stack_slot = self.next_kernel_stack_slot.checked_add(1)?;
        // Return the writable stack base (i.e. the guard page is right *below* it).
        Some(slot_base + KERNEL_STACK_SIZE)
    }

    /// Return the `TaskId` of the task currently running on this CPU.
    pub fn current_task_id(&self) -> Option<TaskId> {
        self.current.map(TaskId)
    }

    /// Spawn a kernel-mode task from a function pointer and a pre-allocated
    /// physical kernel stack frame, mapping the frame into the isolated
    /// kernel-stack VA range introduced in MB10 (ADR-0002).
    ///
    /// Layout per slot (one slot = `KERNEL_STACK_STRIDE` bytes of VA):
    ///
    /// ```text
    ///   slot_base                          ┐ 4 KiB guard page — NOT mapped
    ///   slot_base + KERNEL_STACK_SIZE      ┤ stack bottom — PRESENT|WRITABLE|NX
    ///   slot_base + KERNEL_STACK_STRIDE    ┘ stack top (initial RSP target)
    /// ```
    ///
    /// Stack overflow past `KERNEL_STACK_SIZE` bytes triggers `#PF` on the
    /// guard page with `CR2` = guard VA — caught by the IDT handler from
    /// MB3.
    ///
    /// `kernel_stack_phys` is the physical base of a 4 KiB frame already
    /// allocated from `alloc` by the caller (so `spawn_kernel_task` itself
    /// can stay infallible w.r.t. physical exhaustion: the caller already
    /// surfaced that case). `mapper` and `alloc` are required by the inner
    /// `PageMapper::map_4k` call.
    ///
    /// # Safety
    ///
    /// `kernel_stack_phys` must be the base of a valid, exclusively owned
    /// 4 KiB frame. `mapper` and `alloc` must point at the kernel's active
    /// `PageMapper` / `BitmapFrameAllocator` — calling this from any
    /// non-kernel context corrupts the bootloader page tables.
    #[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
    #[allow(
        clippy::indexing_slicing,
        reason = "priority as usize < NUM_PRIORITY_CLASSES by enum repr"
    )]
    pub unsafe fn spawn_kernel_task<const N: usize>(
        &mut self,
        entry: fn() -> !,
        kernel_stack_phys: u64,
        mapper: &mut crate::bare_metal::paging::PageMapper,
        alloc: &mut crate::memory::BitmapFrameAllocator<N>,
        priority: PriorityClass,
    ) -> KernelResult<TaskId> {
        use crate::{
            bare_metal::{
                context_switch::setup_task_frame,
                paging::{PTE_NO_EXEC, PTE_PRESENT, PTE_WRITABLE},
            },
            memory::{PhysAddr, VirtAddr},
        };

        let kernel_stack_va = self
            .allocate_stack_slot()
            .ok_or(KernelError::ResourceExhausted)?;

        // Map the whole writable stack region (KERNEL_STACK_SIZE, 16 KiB =
        // 4 frames); deliberately leave the guard region
        // (`[kernel_stack_va - KERNEL_STACK_SIZE, kernel_stack_va)`) un-mapped.
        // `kernel_stack_phys` is the caller-provided first frame; the remaining
        // pages are allocated here (frames need not be physically contiguous —
        // only the VA range is).
        #[allow(
            clippy::integer_division,
            reason = "KERNEL_STACK_SIZE is a 4 KiB multiple by construction"
        )]
        let pages = KERNEL_STACK_SIZE / 0x1000;
        let mut page_i: u64 = 0;
        while page_i < pages {
            let frame = if page_i == 0 {
                kernel_stack_phys
            } else {
                alloc.alloc_frame().ok_or(KernelError::ResourceExhausted)?.0
            };
            if !mapper.map_4k(
                VirtAddr(kernel_stack_va + page_i * 0x1000),
                PhysAddr(frame),
                PTE_PRESENT | PTE_WRITABLE | PTE_NO_EXEC,
                alloc,
            ) {
                return Err(KernelError::ResourceExhausted);
            }
            page_i += 1;
        }

        // Stack grows downward; initial RSP = top of the writable region.
        let stack_virt_top = kernel_stack_va + KERNEL_STACK_SIZE;
        // SAFETY: stack_virt_top is the top of a 4 KiB writable kernel
        // stack page that we just mapped exclusively for this task.
        #[allow(
            clippy::fn_to_numeric_cast,
            reason = "canonical kernel-task RSP packing — entry RIP must be u64"
        )]
        let initial_rsp = unsafe { setup_task_frame(stack_virt_top, entry as u64) };

        let id = TaskId(self.next_id);
        self.next_id += 1;

        self.tasks.push(TaskControlBlock {
            id,
            state: TaskState::Runnable,
            priority,
            context: CpuContext { rsp: initial_rsp },
            kernel_stack_phys,
            kernel_stack_va,
        });
        self.run_queues[priority as usize].push(id.0);
        Ok(id)
    }

    /// Register the currently-executing kernel flow (i.e. `kmain` itself)
    /// as a scheduler-visible task without allocating a fresh kernel stack.
    ///
    /// Required by MB8 preemption: the LAPIC timer's `yield_current` needs a
    /// `current` task to save state into. Before `sti` we don't yet have one
    /// because `kmain` is running on the boot stack, outside the scheduler.
    /// This method creates a placeholder TCB whose `context.rsp` is `0`
    /// (sentinel — meaningful only until the first preemption overwrites it)
    /// and whose `kernel_stack_phys` is `0` (no owned frame: re-uses the boot
    /// stack), then installs it as `current`.
    ///
    /// The very first timer tick after `sti` will trigger `nexacore_context_switch`,
    /// which pushes kmain's callee-saved registers onto the boot stack and
    /// stores the real RSP in this TCB. From that moment kmain is a regular
    /// preemptible task.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "signature parity with future fallible spawn paths (MB11+ user-process)"
    )]
    pub fn spawn_bootstrap_task(&mut self, priority: PriorityClass) -> KernelResult<TaskId> {
        let id = TaskId(self.next_id);
        self.next_id += 1;
        self.tasks.push(TaskControlBlock {
            id,
            state: TaskState::Running,
            priority,
            // Sentinel: overwritten by the first `context_switch` save.
            context: CpuContext { rsp: 0 },
            // No owned stack frame; the boot stack is used in-place.
            kernel_stack_phys: 0,
            // Sentinel: bootstrap kmain task lives on the boot stack, not in
            // the MB10 isolated VA range.
            kernel_stack_va: 0,
        });
        // CRUCIAL: timer's `kernel_check_need_resched` would early-return
        // without this; the placeholder must be the current task already.
        self.current = Some(id.0);
        Ok(id)
    }

    /// MB14.g — enqueue a task on a specific CPU's run-queue.
    ///
    /// Dual-write contract:
    /// 1. The legacy `self.run_queues[priority]` mirror is pushed so the
    ///    existing BSP dispatch paths (and every host-side unit test)
    ///    keep working unchanged during the MB14.g transition window.
    /// 2. On bare-metal builds the task is also pushed into
    ///    `crate::bare_metal::per_cpu_run_queue` under `cpu_id`, where
    ///    the MB14.h AP-side dispatch loop will pull it via
    ///    `pop_for_cpu_with_stealing`. On host / test builds step 2 is a
    ///    no-op because the per-CPU table aliases a single global and
    ///    cross-test interleaving would obscure the legacy-mirror
    ///    assertions.
    ///
    /// Returns `true` if the per-CPU table accepted the push (or `true`
    /// vacuously on host/test); `false` only when `cpu_id >= MAX_CPUS`
    /// on bare-metal — the legacy mirror is still populated in that
    /// case, so the task is reachable through the BSP dispatch path.
    #[allow(
        clippy::indexing_slicing,
        reason = "priority as usize < NUM_PRIORITY_CLASSES by enum repr"
    )]
    pub fn enqueue_for_cpu(&mut self, cpu_id: u32, task: TaskId, priority: PriorityClass) -> bool {
        // Step 1 — legacy mirror push (BSP / host source of truth).
        self.run_queues[priority as usize].push(task.0);
        // Step 2 — per-CPU dispatch table (bare-metal only; see doc).
        #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
        {
            crate::bare_metal::per_cpu_run_queue::enqueue_on_cpu(cpu_id, task.0, priority)
        }
        #[cfg(not(all(feature = "bare-metal", target_os = "none", not(test))))]
        {
            let _ = cpu_id;
            true
        }
    }

    /// MB14.g — pick the next runnable task for `cpu_id`, consulting the
    /// per-CPU run-queue (with work-stealing fallback) on bare-metal
    /// builds. Removes the picked task from the legacy
    /// `self.run_queues` mirror so the two sources stay coherent. On
    /// host / test builds delegates to [`Self::pick_next`] for parity
    /// with single-CPU unit tests.
    ///
    /// Returns `None` if every CPU's queue is empty.
    pub fn pick_next_for_cpu(&mut self, cpu_id: u32) -> Option<TaskId> {
        #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
        {
            let picked = crate::bare_metal::per_cpu_run_queue::pop_for_cpu_with_stealing(cpu_id)?;
            // Drop the same task from the legacy mirror — defensive
            // sync so a follow-up MB14.h that rewires BSP `pick_next`
            // through this helper does not surface a stale id.
            for queue in &mut self.run_queues {
                queue.retain(|&id| id != picked);
            }
            Some(TaskId(picked))
        }
        #[cfg(not(all(feature = "bare-metal", target_os = "none", not(test))))]
        {
            let _ = cpu_id;
            self.pick_next()
        }
    }

    /// Test helper: create a minimal TCB with a zeroed context and enqueue it.
    #[cfg(test)]
    #[allow(
        clippy::indexing_slicing,
        reason = "priority as usize < NUM_PRIORITY_CLASSES by enum repr"
    )]
    pub fn mock_enqueue(&mut self, priority: PriorityClass) -> TaskId {
        let id = TaskId(self.next_id);
        self.next_id += 1;
        self.tasks.push(TaskControlBlock {
            id,
            state: TaskState::Runnable,
            priority,
            context: CpuContext::default(),
            kernel_stack_phys: 0,
            kernel_stack_va: 0,
        });
        self.run_queues[priority as usize].push(id.0);
        id
    }
}

impl Scheduler for RoundRobinScheduler {
    #[allow(
        clippy::indexing_slicing,
        reason = "priority as usize < NUM_PRIORITY_CLASSES by enum repr"
    )]
    fn enqueue(&mut self, task: TaskId, priority: PriorityClass) -> KernelResult<()> {
        let tcb = self
            .tasks
            .iter_mut()
            .find(|t| t.id.0 == task.0)
            .ok_or(KernelError::InvalidArgument)?;
        tcb.state = TaskState::Runnable;
        tcb.priority = priority;
        self.run_queues[priority as usize].push(task.0);
        Ok(())
    }

    fn dequeue(&mut self, task: TaskId) -> KernelResult<()> {
        for queue in &mut self.run_queues {
            queue.retain(|&id| id != task.0);
        }
        if let Some(tcb) = self.tasks.iter_mut().find(|t| t.id.0 == task.0) {
            tcb.state = TaskState::Terminated;
        }
        if self.current == Some(task.0) {
            self.current = None;
        }
        Ok(())
    }

    fn pick_next(&mut self) -> Option<TaskId> {
        // P11.1 / WS1-01 (ADR-0025 adversarial-review finding #3) — strict
        // RealTime bypass AHEAD of the fairness slot table: a runnable
        // RealTime task wins every pick, including over System. The
        // #[repr(u8)] enum keeps `System = 0 < RealTime = 1` for queue
        // indexing only — the effective scheduling rank is RealTime first.
        //
        // The bypass deliberately does NOT advance `pick_counter`: the
        // non-RealTime pick subsequence therefore follows the slot table
        // with exactly the phase and weights proven in ADR-0025, so the
        // no-starvation guarantee among the remaining classes is preserved
        // verbatim whenever the RealTime queue is empty. By strict-bypass
        // construction a RealTime task that never blocks monopolises the
        // CPU — RealTime workloads are expected to be periodic and
        // block/yield between deadlines; admission control is a Phase 2
        // concern (todo.md P11.1 resolution note).
        #[allow(
            clippy::indexing_slicing,
            reason = "RealTime as usize = 1 < NUM_PRIORITY_CLASSES by enum repr"
        )]
        let rt_queue = &mut self.run_queues[PriorityClass::RealTime as usize];
        if !rt_queue.is_empty() {
            return Some(TaskId(rt_queue.remove(0)));
        }

        // Invariant relied upon below: FAIRNESS_CYCLE never names RealTime
        // and the strict fallback can only run with this queue drained —
        // the bypass above is the single consumer of the RealTime class.
        #[allow(
            clippy::indexing_slicing,
            reason = "RealTime as usize = 1 < NUM_PRIORITY_CLASSES by enum repr"
        )]
        {
            debug_assert!(
                self.run_queues[PriorityClass::RealTime as usize].is_empty(),
                "RealTime queue must be empty past the strict bypass"
            );
        }

        // TASK-06 / ADR-0025 — fairness slot rotation. Strict-priority FIFO
        // starves Interactive/Background behind the System busy-yield service
        // loops (CHECKPOINT 10); designated slots of an 8-pick cycle give a
        // lower class first preference, falling back to strict order when
        // that class has nothing runnable. The context-switch path is
        // untouched: only WHICH queue is consulted first changes.
        //
        // WS1-10 — the cycle is thermal-aware: at `Normal` it is the exact
        // ADR-0025 `FAIRNESS_CYCLE` (so the starvation bounds and every existing
        // test are unchanged); warmer bands favour AiInference to drain an
        // inference burst while keeping the Interactive floor.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "slot < FAIRNESS_LEN = 8 by modulo"
        )]
        let slot = (self.pick_counter % FAIRNESS_LEN) as usize;
        self.pick_counter = self.pick_counter.wrapping_add(1);
        let cycle = crate::thermal::fairness_cycle_for(self.thermal);

        #[allow(
            clippy::indexing_slicing,
            reason = "slot bounded by modulo above; class repr < NUM_PRIORITY_CLASSES"
        )]
        if let Some(preferred) = cycle[slot] {
            let queue = &mut self.run_queues[preferred as usize];
            if !queue.is_empty() {
                return Some(TaskId(queue.remove(0)));
            }
        }

        // Strict priority order (System first) — the pre-TASK-06 behaviour
        // and the fallback for fairness slots whose class is idle. The
        // RealTime queue is necessarily empty here (drained by the bypass),
        // so this scan can never surface a RealTime task.
        for queue in &mut self.run_queues {
            if !queue.is_empty() {
                return Some(TaskId(queue.remove(0)));
            }
        }
        None
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "cur_idx/next_idx derived from Vec::position; priority<NUM_PRIORITY_CLASSES"
    )]
    fn yield_current(&mut self, current: TaskId, new_state: TaskState) -> KernelResult<()> {
        let cur_idx = self
            .tasks
            .iter()
            .position(|t| t.id.0 == current.0)
            .ok_or(KernelError::InvalidArgument)?;

        // Update state and re-queue if still runnable.
        let prio = self.tasks[cur_idx].priority as usize;
        self.tasks[cur_idx].state = new_state;
        if new_state == TaskState::Runnable {
            self.run_queues[prio].push(current.0);
        }

        let Some(next) = self.pick_next() else {
            return Ok(());
        };

        // Same task picked (only one runnable) — resume without switching.
        if next.0 == current.0 {
            self.tasks[cur_idx].state = TaskState::Running;
            self.current = Some(next.0);
            return Ok(());
        }

        let next_idx = self
            .tasks
            .iter()
            .position(|t| t.id.0 == next.0)
            .ok_or(KernelError::Internal)?;
        self.tasks[next_idx].state = TaskState::Running;
        self.current = Some(next.0);

        // MB12.0a + MB12.0b — if the incoming task owns a userspace PCB,
        // load its TSS.rsp0 (so the next Ring 3 → Ring 0 transition lands
        // on this task's kernel stack) and reload CR3 (so user-half VAs
        // resolve in this process's PML4). The kernel half is mirrored
        // by reference across every per-process PML4, so the trampoline
        // and the rest of this function stay mapped after the CR3 reload.
        //
        // The process metadata is captured by Copy *before* the mutable
        // borrow of `self.tasks` for `from_rsp_ptr`; this avoids a
        // simultaneous immutable + mutable borrow of `self`.
        #[cfg(all(feature = "bare-metal", target_arch = "x86_64", not(test)))]
        let process_dispatch: Option<(u64, u64, u64, u64, u64)> = self
            .processes
            .iter()
            .find(|p| p.task.id.0 == next.0)
            .map(|p| {
                (
                    p.task.kernel_stack_va,
                    p.address_space.pml4_phys.0,
                    p.user_entry,
                    p.user_stack_top,
                    self.tasks[next_idx].context.rsp,
                )
            });

        #[cfg(all(feature = "bare-metal", target_arch = "x86_64", not(test)))]
        if let Some((kernel_stack_va, cr3_phys, user_entry, user_stack_top, saved_rsp)) =
            process_dispatch
        {
            let kernel_stack_top = kernel_stack_va + KERNEL_STACK_SIZE;
            // MB14.h.2 — route the TSS.rsp0 write through the per-CPU
            // helper so an AP running this code updates its own
            // `AP_TSS[cpu_id - 1]` slot instead of the BSP TSS. The
            // BSP keeps writing the legacy static via
            // `set_rsp0_for_cpu(0, _)` → `set_rsp0`.
            let cpu_id = crate::bare_metal::per_cpu::current_cpu().cpu_id();
            let _ = crate::bare_metal::tss::set_rsp0_for_cpu(cpu_id, kernel_stack_top);

            // Keep the SYSCALL fast path's kernel-stack pointer in lock-step
            // with TSS.rsp0: `nexacore_syscall_entry` switches RSP to this value so
            // syscalls run on the task's isolated kernel stack rather than the
            // user stack (2026-06-03 corruption fix). Per-CPU (NCIP-026 WI-5):
            // set_syscall_kernel_rsp writes THIS CPU's GS-relative slot, so an
            // AP running a user task updates its own pointer, not the BSP's.
            crate::bare_metal::syscall_entry::set_syscall_kernel_rsp(kernel_stack_top);

            // MB12 first-dispatch detection: a freshly-spawned user task
            // has `context.rsp = 0` (the sentinel from `spawn_from_elf`).
            // It has no saved register frame on its kernel stack — a plain
            // `context_switch` into it would pop garbage. Instead we use
            // `save_and_enter_user_mode`, which FIRST saves the OUTGOING
            // task's resumable kernel context (the step the old bare
            // `enter_user_mode` skipped, causing Bug 5) and THEN performs the
            // iretq trampoline (its own stack swap + `mov cr3`) into Ring 3.
            //
            // The kernel ELF lives entirely in the canonical upper half
            // (MB13.b ET_DYN/PIE relocation) and the destination task's
            // kernel stack is in the MB10 isolated range
            // `[KERNEL_STACK_VA_BASE, KERNEL_STACK_VA_END)`, both of
            // which the per-process PML4 mirrors by reference. The
            // `enter_user_mode` trampoline therefore swaps RSP onto
            // `kernel_stack_top` BEFORE the CR3 reload (MB13.f), keeping
            // the `push` sequence that builds the iretq frame on a page
            // that is mapped in the incoming address space — without
            // this swap the CR3 reload would leave RSP dangling on the
            // outgoing task's user stack (unmapped in the new PML4) and
            // the next push would triple-fault.
            if saved_rsp == 0 {
                // First dispatch of a freshly-spawned user task. We must STILL
                // save the OUTGOING task's resumable kernel context before the
                // iretq into Ring 3 — otherwise the outgoing task's
                // `context.rsp` stays the 0 sentinel and the next time the
                // scheduler selects it, it is wrongly re-treated as
                // first-dispatch and its `_start` runs a second time (Bug 5,
                // observed as nexacore-net printing "service starting" twice from a
                // single spawn). `save_and_enter_user_mode` saves the outgoing
                // frame (context_switch-resume-compatible) AND performs the same
                // stack-swap + CR3 reload + iretq as `enter_user_mode`. It
                // "returns" here only when the OUTGOING task is later resumed by
                // a `context_switch`; we then `return Ok(())` and unwind back to
                // that task's syscall / interrupt entry.
                //
                // SAFETY: user_entry + user_stack_top are validated by
                // `spawn_from_elf` to reside in the user half; `kernel_stack_top`
                // is the destination task's MB10 isolated kstk slot, mirrored in
                // every per-process PML4; `from_rsp_ptr` points at the outgoing
                // task's TCB (kernel-half `SCHEDULER` static, mapped under both
                // CR3s) and is written before the CR3 reload.
                let from_rsp_ptr: *mut u64 =
                    core::ptr::addr_of_mut!(self.tasks[cur_idx].context.rsp);
                unsafe {
                    crate::bare_metal::context_switch::save_and_enter_user_mode(
                        from_rsp_ptr,
                        user_entry,
                        user_stack_top,
                        crate::bare_metal::usermode::USER_RFLAGS,
                        cr3_phys,
                        kernel_stack_top,
                    );
                }
                return Ok(());
            }

            // Resume path: the incoming task is a user task that previously
            // saved its kernel context (`saved_rsp != 0`). Reload CR3 here
            // before the `context_switch` asm restores the callee-saved
            // registers from `to_rsp_val`.
            //
            // SAFETY: per-process PML4 owned by this PCB; kernel half is
            // mirrored from boot CR3 so subsequent instructions stay mapped.
            unsafe {
                core::arch::asm!(
                    "mov cr3, {}",
                    in(reg) cr3_phys,
                    options(nostack, preserves_flags)
                );
            }
        }

        // SAFETY: single-CPU, non-preemptive; both stack frames are valid
        // kernel memory established by spawn_kernel_task or a prior switch.
        #[cfg(all(feature = "bare-metal", target_arch = "x86_64", not(test)))]
        #[allow(
            clippy::borrow_as_ptr,
            reason = "raw *mut u64 deliberately passed by FFI to context_switch asm"
        )]
        unsafe {
            let to_rsp_val = self.tasks[next_idx].context.rsp;
            // Defensive guard against context-switching into a null stack.
            //
            // A saved RSP of 0 is the "never context-switched out" sentinel set
            // by `spawn_bootstrap_task`. By construction it should never reach
            // here as a switch *target*: a never-run USER task is entered via
            // `enter_user_mode` in the `saved_rsp == 0` branch above (which does
            // not return), and a never-run KERNEL task is given a valid
            // trampoline RSP by `setup_task_frame` at spawn. The only task that
            // legitimately still carries rsp == 0 is the bootstrap/kmain task,
            // which is always `current`, never `next`.
            //
            // If the invariant is ever violated (e.g. an exit-driven
            // `yield_current` selecting a peer whose context was not fully
            // initialised), loading RSP = 0 and then `pop`/`ret`-ing through it
            // dereferences virtual address 0 inside the Ring-0 `context_switch`
            // asm, faulting as `#PF code=0 cr2=0 cs=8` — a kernel crash. Skip
            // the switch instead and let the caller (e.g. `task_exit`) fall
            // through to `halt_forever`, trading a stalled task for a live
            // kernel. Security > Stability > Performance.
            if to_rsp_val == 0 {
                return Ok(());
            }
            let from_rsp_ptr: *mut u64 = &mut self.tasks[cur_idx].context.rsp as *mut u64;
            crate::bare_metal::context_switch::context_switch(from_rsp_ptr, to_rsp_val);
        }
        let _ = next_idx; // suppress unused-variable on non-bare-metal builds

        Ok(())
    }

    fn preempt(&mut self, current: TaskId) -> KernelResult<()> {
        // Rotate current task to the back of its priority queue and switch to
        // the next runnable task. Called by the LAPIC timer handler (MB8+).
        self.yield_current(current, TaskState::Runnable)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_class_fits_in_one_byte() {
        assert_eq!(core::mem::size_of::<PriorityClass>(), 1);
    }

    #[test]
    fn task_id_round_trips() {
        let t = TaskId(0xDEAD_BEEFu64);
        assert_eq!(t.0, 0xDEAD_BEEFu64);
    }

    #[test]
    fn round_robin_yields_in_priority_order() {
        let mut sched = RoundRobinScheduler::new();
        let idle = sched.mock_enqueue(PriorityClass::Idle);
        let sys = sched.mock_enqueue(PriorityClass::System);
        // System (0) must be picked before Idle (5).
        assert_eq!(sched.pick_next(), Some(sys));
        assert_eq!(sched.pick_next(), Some(idle));
        assert_eq!(sched.pick_next(), None);
    }

    #[test]
    fn round_robin_within_same_priority() {
        let mut sched = RoundRobinScheduler::new();
        let t1 = sched.mock_enqueue(PriorityClass::Interactive);
        let t2 = sched.mock_enqueue(PriorityClass::Interactive);
        assert_eq!(sched.pick_next(), Some(t1));
        assert_eq!(sched.pick_next(), Some(t2));
        assert_eq!(sched.pick_next(), None);
    }

    #[test]
    fn yield_current_re_enqueues_runnable() {
        let mut sched = RoundRobinScheduler::new();
        let t1 = sched.mock_enqueue(PriorityClass::Interactive);
        let t2 = sched.mock_enqueue(PriorityClass::Interactive);
        sched.current = Some(t1.0);
        // Drain t1 from the queue (simulate it being picked and running).
        let _ = sched.pick_next(); // picks t1
        // Now t2 is still in queue. Yield t1 as Runnable — should switch to t2.
        sched.yield_current(t1, TaskState::Runnable).unwrap();
        // After yield, t2 should be current.
        assert_eq!(sched.current_task_id(), Some(t2));
    }

    #[test]
    fn dequeue_removes_from_run_queue() {
        let mut sched = RoundRobinScheduler::new();
        let t = sched.mock_enqueue(PriorityClass::Background);
        sched.dequeue(t).unwrap();
        assert_eq!(sched.pick_next(), None);
    }

    #[test]
    fn preempt_is_noop() {
        let mut sched = RoundRobinScheduler::new();
        let t = sched.mock_enqueue(PriorityClass::RealTime);
        assert!(sched.preempt(t).is_ok());
    }

    // -------------------------------------------------------------------------
    // MB14.g — `enqueue_for_cpu` / `pick_next_for_cpu` API surface.
    //
    // The per-CPU dispatch table is `#[cfg]`-gated to bare-metal in the
    // production code; on host tests the new methods fall back to the
    // existing single-CPU run-queues mirror. The assertions below pin
    // the host fallback so future MB14.h refactors that touch the bare-
    // metal branch cannot accidentally regress the host contract.
    // -------------------------------------------------------------------------

    #[test]
    fn enqueue_for_cpu_host_falls_back_to_local_mirror() {
        let mut sched = RoundRobinScheduler::new();
        let id = sched.allocate_task_id();
        // Reserve the TCB entry — `register_process` is the canonical
        // build path, but a minimal mock_enqueue-style TCB suffices here.
        sched.tasks.push(TaskControlBlock {
            id,
            state: TaskState::Runnable,
            priority: PriorityClass::Interactive,
            context: CpuContext::default(),
            kernel_stack_phys: 0,
            kernel_stack_va: 0,
        });
        assert!(sched.enqueue_for_cpu(0, id, PriorityClass::Interactive));
        // Legacy mirror sees the task; per-CPU table is a no-op on host.
        assert_eq!(sched.pick_next(), Some(id));
    }

    #[test]
    fn pick_next_for_cpu_host_delegates_to_pick_next() {
        let mut sched = RoundRobinScheduler::new();
        let t = sched.mock_enqueue(PriorityClass::System);
        // Host build: per-CPU table is empty, but pick_next_for_cpu
        // falls back to pick_next which reads the legacy mirror.
        assert_eq!(sched.pick_next_for_cpu(0), Some(t));
        assert_eq!(sched.pick_next_for_cpu(0), None);
    }

    #[test]
    fn enqueue_for_cpu_respects_priority_order_on_legacy_mirror() {
        let mut sched = RoundRobinScheduler::new();
        let low = sched.allocate_task_id();
        let high = sched.allocate_task_id();
        for (id, prio) in [(low, PriorityClass::Idle), (high, PriorityClass::System)] {
            sched.tasks.push(TaskControlBlock {
                id,
                state: TaskState::Runnable,
                priority: prio,
                context: CpuContext::default(),
                kernel_stack_phys: 0,
                kernel_stack_va: 0,
            });
            assert!(sched.enqueue_for_cpu(0, id, prio));
        }
        // System (0) wins over Idle (5).
        assert_eq!(sched.pick_next_for_cpu(0), Some(high));
        assert_eq!(sched.pick_next_for_cpu(0), Some(low));
        assert_eq!(sched.pick_next_for_cpu(0), None);
    }

    // -------------------------------------------------------------------------
    // MB10 — kernel-stack VA range invariants
    // -------------------------------------------------------------------------

    #[test]
    fn mb10_first_slot_starts_after_guard_page() {
        let mut sched = RoundRobinScheduler::new();
        let va = sched.allocate_stack_slot().expect("first slot");
        // Slot 0: guard at BASE, stack at BASE + KERNEL_STACK_SIZE.
        assert_eq!(va, KERNEL_STACK_VA_BASE + KERNEL_STACK_SIZE);
        // The guard page sits one stack-size BELOW the writable stack base.
        assert_eq!(va - KERNEL_STACK_SIZE, KERNEL_STACK_VA_BASE);
    }

    #[test]
    fn mb10_consecutive_slots_advance_by_stride() {
        let mut sched = RoundRobinScheduler::new();
        let va0 = sched.allocate_stack_slot().expect("slot 0");
        let va1 = sched.allocate_stack_slot().expect("slot 1");
        let va2 = sched.allocate_stack_slot().expect("slot 2");
        assert_eq!(va1 - va0, KERNEL_STACK_STRIDE);
        assert_eq!(va2 - va1, KERNEL_STACK_STRIDE);
        // All stay inside the dedicated range.
        for va in [va0, va1, va2] {
            assert!(va >= KERNEL_STACK_VA_BASE + KERNEL_STACK_SIZE);
            assert!(va + KERNEL_STACK_SIZE <= KERNEL_STACK_VA_END);
        }
    }

    #[test]
    fn mb10_guard_page_layout_is_below_each_stack() {
        let mut sched = RoundRobinScheduler::new();
        for expected_slot in 0u64..4 {
            let va = sched.allocate_stack_slot().expect("slot");
            let slot_base = KERNEL_STACK_VA_BASE + expected_slot * KERNEL_STACK_STRIDE;
            // Guard page is the 4 KiB ABOVE slot_base; stack page is the next 4 KiB.
            assert_eq!(va, slot_base + KERNEL_STACK_SIZE);
        }
    }

    #[test]
    fn mb10_constants_fit_their_arithmetic_invariants() {
        // 8 TiB total range (BASE = 0xFFFF_C000_…, END = 0xFFFF_C800_…).
        assert_eq!(KERNEL_STACK_VA_END - KERNEL_STACK_VA_BASE, 8u64 << 40);
        // Stride = 2 × stack region (guard + stack).
        assert_eq!(KERNEL_STACK_STRIDE, KERNEL_STACK_SIZE * 2);
        // Stack region = 16 KiB (4 frames); enlarged 2026-06-03 when the
        // SYSCALL fast path moved onto the kernel stack.
        assert_eq!(KERNEL_STACK_SIZE, 0x4000);
        // Range capacity ≈ 268 M slots (8 TiB / 32 KiB stride) — much more than
        // Phase 1 needs. (Was ≈ 1 G with the old 8 KiB stride; the 16 KiB stack
        // + 16 KiB guard quadrupled the stride, 2026-06-03.)
        #[allow(
            clippy::integer_division,
            reason = "STRIDE divides END-BASE evenly by const construction"
        )]
        let slots = (KERNEL_STACK_VA_END - KERNEL_STACK_VA_BASE) / KERNEL_STACK_STRIDE;
        assert!(slots >= 100_000_000);
    }

    #[test]
    fn bootstrap_task_is_installed_as_current_with_sentinel_rsp() {
        let mut sched = RoundRobinScheduler::new();
        let id = sched.spawn_bootstrap_task(PriorityClass::System).unwrap();
        assert_eq!(sched.current_task_id(), Some(id));
        let tcb = sched
            .tasks
            .iter()
            .find(|t| t.id.0 == id.0)
            .expect("bootstrap TCB must be present");
        // Sentinel values — both filled by the first preemption.
        assert_eq!(tcb.context.rsp, 0);
        assert_eq!(tcb.kernel_stack_phys, 0);
        // Bootstrap task is *not* enqueued on a run queue: it is already
        // executing. The first `yield_current` will re-queue it as Runnable.
        assert!(sched.run_queues.iter().all(Vec::is_empty));
        assert_eq!(tcb.state, TaskState::Running);
    }

    // -------------------------------------------------------------------------
    // TASK-06 / ADR-0025 — fairness slot rotation
    // -------------------------------------------------------------------------

    /// TASK-06 acceptance (1): with 2 busy-yield System tasks plus one
    /// Interactive and one Background task, ALL FOUR run within a bounded
    /// number of picks — the exact M0 boot topology that starved the shell
    /// (CHECKPOINT 10). "Busy-yield" is simulated by re-enqueueing every
    /// picked task, exactly what `yield_current(Runnable)` does.
    #[test]
    fn fairness_no_starvation_all_four_tasks_run_within_one_cycle() {
        let mut sched = RoundRobinScheduler::new();
        let sys_a = sched.mock_enqueue(PriorityClass::System);
        let sys_b = sched.mock_enqueue(PriorityClass::System);
        let shell = sched.mock_enqueue(PriorityClass::Interactive);
        let netcheck = sched.mock_enqueue(PriorityClass::Background);

        let mut seen = [false; 4];
        let ids = [sys_a, sys_b, shell, netcheck];
        for pick_no in 0..FAIRNESS_CYCLE.len() {
            let picked = sched.pick_next().expect("queues are never empty here");
            for (slot, id) in ids.iter().enumerate() {
                if picked == *id {
                    seen[slot] = true;
                }
            }
            // Busy-yield: the task immediately becomes runnable again.
            let prio = sched
                .tasks
                .iter()
                .find(|t| t.id == picked)
                .expect("picked task has a TCB")
                .priority;
            sched.run_queues[prio as usize].push(picked.0);
            let _ = pick_no;
        }
        assert!(
            seen.iter().all(|&s| s),
            "every class must run within one 8-pick cycle: System {}/{}, \
             Interactive {}, Background {}",
            seen[0],
            seen[1],
            seen[2],
            seen[3]
        );
    }

    /// TASK-06 acceptance (2): priority is respected at parity — under full
    /// contention (one always-runnable task per class) the per-class pick
    /// counts over whole cycles are exactly the slot-table weights:
    /// System 4, Interactive 2, `AiInference` 1, Background 1 per cycle.
    #[test]
    fn fairness_priority_weights_exact_under_full_contention() {
        const CYCLES: usize = 4;
        let mut sched = RoundRobinScheduler::new();
        let sys = sched.mock_enqueue(PriorityClass::System);
        let inter = sched.mock_enqueue(PriorityClass::Interactive);
        let ai = sched.mock_enqueue(PriorityClass::AiInference);
        let bg = sched.mock_enqueue(PriorityClass::Background);

        let mut counts = [0usize; 4];
        for _ in 0..(CYCLES * FAIRNESS_CYCLE.len()) {
            let picked = sched.pick_next().expect("full contention");
            match picked {
                p if p == sys => counts[0] += 1,
                p if p == inter => counts[1] += 1,
                p if p == ai => counts[2] += 1,
                p if p == bg => counts[3] += 1,
                other => panic!("unknown task picked: {other:?}"),
            }
            let prio = sched
                .tasks
                .iter()
                .find(|t| t.id == picked)
                .expect("picked task has a TCB")
                .priority;
            sched.run_queues[prio as usize].push(picked.0);
        }
        assert_eq!(counts[0], 4 * CYCLES, "System gets 4 picks per cycle");
        assert_eq!(counts[1], 2 * CYCLES, "Interactive gets 2 picks per cycle");
        assert_eq!(counts[2], CYCLES, "AiInference gets 1 pick per cycle");
        assert_eq!(counts[3], CYCLES, "Background gets 1 pick per cycle");
        // Monotone with class semantics: System > Interactive > AiInference
        // >= Background.
        assert!(counts[0] > counts[1] && counts[1] > counts[2] && counts[2] >= counts[3]);
    }

    /// WS1-10.6 — host simulation of an AI-inference burst under thermal
    /// pressure. With System, Interactive, and AiInference all saturated, a
    /// `Hot` band must FAVOUR the AiInference burst (3 designated slots/cycle vs
    /// 1 at `Normal`) while the Interactive class keeps its floor (≥2/cycle) —
    /// the burst is drained faster but Interactive is never starved (WS1-10.4/.5).
    #[test]
    fn thermal_hot_favours_ai_burst_without_starving_interactive() {
        const CYCLES: usize = 4;
        let mut sched = RoundRobinScheduler::new();
        let sys = sched.mock_enqueue(PriorityClass::System);
        let inter = sched.mock_enqueue(PriorityClass::Interactive);
        let ai = sched.mock_enqueue(PriorityClass::AiInference);

        // The platform reports an AI-dominated load at 85 °C → `Hot` band.
        sched.set_cpu_load_class(PriorityClass::AiInference);
        sched.set_cpu_temperature(85_000);
        assert_eq!(sched.thermal_level(), crate::thermal::ThermalLevel::Hot);
        assert!(crate::thermal::should_favour_ai(
            sched.thermal_level(),
            sched.cpu_load_class()
        ));

        let mut ai_picks = 0usize;
        let mut inter_picks = 0usize;
        let _ = sys;
        for _ in 0..(CYCLES * FAIRNESS_CYCLE.len()) {
            let picked = sched.pick_next().expect("a runnable task");
            if picked == ai {
                ai_picks += 1;
            } else if picked == inter {
                inter_picks += 1;
            }
            // Re-enqueue the picked task to keep its class saturated.
            let prio = sched
                .tasks
                .iter()
                .find(|t| t.id == picked)
                .expect("picked task has a TCB")
                .priority;
            sched.run_queues[prio as usize].push(picked.0);
        }

        // AiInference is favoured to 3 designated slots/cycle at `Hot` (vs 1 at
        // `Normal`, pinned by `fairness_priority_weights_exact_under_full_contention`).
        assert_eq!(
            ai_picks,
            3 * CYCLES,
            "Hot band must favour the AiInference burst"
        );
        // Interactive keeps its 2-slot floor — never starved by the favouring.
        assert!(
            inter_picks >= crate::thermal::INTERACTIVE_FLOOR * CYCLES,
            "Interactive starved under thermal favour: {inter_picks}"
        );
    }

    /// A fairness slot whose preferred class is empty falls back to strict
    /// order — and the slot table keeps being consulted on every later
    /// cycle: after a full System-only cycle (all 8 picks fall back to
    /// System), an Interactive task enqueued afterwards IS picked at the
    /// next cycle's first Interactive slot (slot 2), proving the fallback
    /// path does not disable or skip the rotation (review finding #1).
    #[test]
    fn fairness_slot_falls_back_to_strict_when_preferred_class_idle() {
        let mut sched = RoundRobinScheduler::new();
        let sys = sched.mock_enqueue(PriorityClass::System);
        for _ in 0..FAIRNESS_CYCLE.len() {
            let picked = sched.pick_next().expect("System stays runnable");
            assert_eq!(picked, sys, "all picks must fall back to System");
            sched.run_queues[PriorityClass::System as usize].push(picked.0);
        }

        // Cycle 2: Interactive becomes runnable. Slots 0,1 are strict
        // (System); slot 2 prefers Interactive and MUST pick it.
        let inter = sched.mock_enqueue(PriorityClass::Interactive);
        for expected_sys_pick in 0..2 {
            let picked = sched.pick_next().expect("System stays runnable");
            assert_eq!(picked, sys, "strict slot {expected_sys_pick} → System");
            sched.run_queues[PriorityClass::System as usize].push(picked.0);
        }
        assert_eq!(
            sched.pick_next(),
            Some(inter),
            "slot 2 must prefer the now-runnable Interactive task"
        );
    }

    /// Pins the `pick_counter` contract (review finding #2, amended by
    /// P11.1): the counter advances on every `pick_next` call NOT satisfied
    /// by the RealTime bypass, including calls that return `None` — no
    /// future caller may rely on the slot phase being aligned to the first
    /// runnable task's arrival. (The bypass freeze is pinned separately by
    /// `realtime_bypass_freezes_slot_rotation_phase`.)
    #[test]
    fn fairness_pick_counter_advances_on_none_returns() {
        let mut sched = RoundRobinScheduler::new();
        for _ in 0..16 {
            assert_eq!(sched.pick_next(), None);
        }
        assert_eq!(sched.pick_counter, 16);
    }

    /// Strict order is preserved inside strict slots: with System idle,
    /// Interactive (higher) wins every strict slot over Background, and
    /// Background still gets its dedicated slot — no inversion, no
    /// starvation.
    #[test]
    fn fairness_strict_slots_keep_class_order_without_system() {
        let mut sched = RoundRobinScheduler::new();
        let inter = sched.mock_enqueue(PriorityClass::Interactive);
        let bg = sched.mock_enqueue(PriorityClass::Background);

        let mut inter_picks = 0;
        let mut bg_picks = 0;
        for _ in 0..FAIRNESS_CYCLE.len() {
            let picked = sched.pick_next().expect("both stay runnable");
            if picked == inter {
                inter_picks += 1;
            } else if picked == bg {
                bg_picks += 1;
            }
            let prio = sched
                .tasks
                .iter()
                .find(|t| t.id == picked)
                .expect("picked task has a TCB")
                .priority;
            sched.run_queues[prio as usize].push(picked.0);
        }
        // 7 slots resolve to Interactive (strict slots + its own 2 +
        // AiInference fallback), 1 to Background (its dedicated slot).
        assert_eq!(inter_picks, 7);
        assert_eq!(bg_picks, 1);
    }

    /// The rotation must not manufacture picks: all queues empty → `None`,
    /// on every slot of the cycle.
    #[test]
    fn fairness_empty_queues_yield_none_on_every_slot() {
        let mut sched = RoundRobinScheduler::new();
        for _ in 0..FAIRNESS_CYCLE.len() {
            assert_eq!(sched.pick_next(), None);
        }
    }

    // -------------------------------------------------------------------------
    // WS1-01 / P11.1 — strict RealTime bypass ahead of the slot table
    // (ADR-0025 adversarial-review finding #3)
    // -------------------------------------------------------------------------

    /// P11.1 acceptance (1): with System idle, a runnable RealTime task wins
    /// EVERY pick — the fairness slots no longer divert its picks to
    /// Interactive/`AiInference`/Background (the inversion that opened the
    /// finding: pre-bypass, RealTime kept only the 4 strict slots per cycle).
    #[test]
    fn realtime_bypass_wins_every_pick_with_system_idle() {
        let mut sched = RoundRobinScheduler::new();
        let rt = sched.mock_enqueue(PriorityClass::RealTime);
        let _inter = sched.mock_enqueue(PriorityClass::Interactive);
        let _ai = sched.mock_enqueue(PriorityClass::AiInference);
        let _bg = sched.mock_enqueue(PriorityClass::Background);

        for pick_no in 0..(2 * FAIRNESS_CYCLE.len()) {
            let picked = sched.pick_next().expect("RealTime stays runnable");
            assert_eq!(
                picked, rt,
                "pick {pick_no}: a runnable RealTime task must win every pick"
            );
            // Busy-yield: RealTime immediately becomes runnable again.
            sched.run_queues[PriorityClass::RealTime as usize].push(picked.0);
        }
    }

    /// P11.1: the bypass outranks System too — the effective scheduling
    /// rank is RealTime first even though the `#[repr(u8)]` enum keeps
    /// `System = 0` for queue indexing (pre-existing oddity, unchanged).
    #[test]
    fn realtime_bypass_outranks_system() {
        let mut sched = RoundRobinScheduler::new();
        let sys = sched.mock_enqueue(PriorityClass::System);
        let rt = sched.mock_enqueue(PriorityClass::RealTime);
        assert_eq!(sched.pick_next(), Some(rt), "RealTime beats System");
        assert_eq!(
            sched.pick_next(),
            Some(sys),
            "System resumes once RealTime drained"
        );
    }

    /// P11.1: FIFO order within the RealTime class is preserved by the
    /// bypass (it consumes the queue head, same discipline as every class).
    #[test]
    fn realtime_bypass_keeps_fifo_within_class() {
        let mut sched = RoundRobinScheduler::new();
        let rt1 = sched.mock_enqueue(PriorityClass::RealTime);
        let rt2 = sched.mock_enqueue(PriorityClass::RealTime);
        assert_eq!(sched.pick_next(), Some(rt1));
        assert_eq!(sched.pick_next(), Some(rt2));
        assert_eq!(sched.pick_next(), None);
    }

    /// P11.1: bypass picks do NOT advance `pick_counter` — the slot phase
    /// freezes across a RealTime burst and the rotation resumes exactly
    /// where it left off, so the non-RealTime subsequence keeps the precise
    /// ADR-0025 slot sequence (this is what keeps the starvation bounds
    /// valid verbatim).
    #[test]
    fn realtime_bypass_freezes_slot_rotation_phase() {
        let mut sched = RoundRobinScheduler::new();
        let sys = sched.mock_enqueue(PriorityClass::System);
        let inter = sched.mock_enqueue(PriorityClass::Interactive);

        // Consume strict slots 0 and 1 (System wins both over Interactive).
        for slot in 0..2 {
            let picked = sched.pick_next().expect("System stays runnable");
            assert_eq!(picked, sys, "strict slot {slot} → System");
            sched.run_queues[PriorityClass::System as usize].push(picked.0);
        }
        assert_eq!(sched.pick_counter, 2, "rotation sits on slot 2");

        // RealTime burst: three bypass picks, counter must not move.
        let rt = sched.mock_enqueue(PriorityClass::RealTime);
        for _ in 0..3 {
            let picked = sched.pick_next().expect("RealTime stays runnable");
            assert_eq!(picked, rt);
            sched.run_queues[PriorityClass::RealTime as usize].push(picked.0);
        }
        // RealTime blocks: drain it instead of re-enqueueing.
        let picked = sched.pick_next().expect("last burst pick");
        assert_eq!(picked, rt);
        assert_eq!(
            sched.pick_counter, 2,
            "bypass picks must not advance the slot rotation"
        );

        // Rotation resumes at slot 2 — the Interactive-preferred slot —
        // so Interactive must be picked over the runnable System task.
        assert_eq!(
            sched.pick_next(),
            Some(inter),
            "slot 2 (Interactive-preferred) resumes after the burst"
        );
    }

    /// WS1-01.7 — TASK-06 fairness non-regression: a RealTime burst that
    /// then blocks leaves the slot rotation untouched, so the exact
    /// per-cycle weights of `fairness_priority_weights_exact_under_full_contention`
    /// (System 4, Interactive 2, `AiInference` 1, Background 1) still hold
    /// over whole cycles run AFTER the burst — the M0 shell + netcheck
    /// coexistence guarantee is unchanged.
    #[test]
    fn realtime_burst_then_block_leaves_task06_fairness_intact() {
        const CYCLES: usize = 4;
        let mut sched = RoundRobinScheduler::new();
        let sys = sched.mock_enqueue(PriorityClass::System);
        let inter = sched.mock_enqueue(PriorityClass::Interactive);
        let ai = sched.mock_enqueue(PriorityClass::AiInference);
        let bg = sched.mock_enqueue(PriorityClass::Background);

        // RealTime burst before the measured window: 5 busy-yield picks,
        // then the task blocks (not re-enqueued on its last pick).
        let rt = sched.mock_enqueue(PriorityClass::RealTime);
        for _ in 0..4 {
            let picked = sched.pick_next().expect("RealTime stays runnable");
            assert_eq!(picked, rt);
            sched.run_queues[PriorityClass::RealTime as usize].push(picked.0);
        }
        assert_eq!(sched.pick_next(), Some(rt), "final burst pick, then block");

        // Full-contention window: exact TASK-06 weights, as if the burst
        // never happened (the bypass froze the rotation at slot 0).
        let mut counts = [0usize; 4];
        for _ in 0..(CYCLES * FAIRNESS_CYCLE.len()) {
            let picked = sched.pick_next().expect("full contention");
            match picked {
                p if p == sys => counts[0] += 1,
                p if p == inter => counts[1] += 1,
                p if p == ai => counts[2] += 1,
                p if p == bg => counts[3] += 1,
                other => panic!("unknown task picked: {other:?}"),
            }
            let prio = sched
                .tasks
                .iter()
                .find(|t| t.id == picked)
                .expect("picked task has a TCB")
                .priority;
            sched.run_queues[prio as usize].push(picked.0);
        }
        assert_eq!(counts[0], 4 * CYCLES, "System keeps 4 picks per cycle");
        assert_eq!(counts[1], 2 * CYCLES, "Interactive keeps 2 picks per cycle");
        assert_eq!(counts[2], CYCLES, "AiInference keeps 1 pick per cycle");
        assert_eq!(counts[3], CYCLES, "Background keeps 1 pick per cycle");
    }

    // -------------------------------------------------------------------------
    // WS1-02 / P11.2 — `current_priority` TCB-first lookup
    // (TASK-06 adversarial-review finding #4)
    // -------------------------------------------------------------------------

    /// P11.2 acceptance: a System task with no PCB (the bootstrap kmain
    /// shape) parked on IPC re-enqueues on the System queue, not
    /// Interactive. Mirrors the syscall-entry `park_until_woken` →
    /// `unpark` contract: unpark re-enqueues at `resolve_priority(task)`.
    #[test]
    fn no_pcb_system_task_reenqueues_as_system() {
        let mut sched = RoundRobinScheduler::new();
        let kmain = sched
            .spawn_bootstrap_task(PriorityClass::System)
            .expect("bootstrap spawn is infallible");

        // Park: BlockedOnIpc, no other runnable task → no switch.
        sched
            .yield_current(kmain, TaskState::BlockedOnIpc)
            .expect("park");

        // Unpark: the resolved class must come from the TCB (System),
        // not the pre-P11.2 hard fallback (Interactive).
        let prio = sched.resolve_priority(kmain);
        assert_eq!(prio, PriorityClass::System, "TCB-first lookup → System");
        sched.enqueue(kmain, prio).expect("re-enqueue");
        assert!(
            sched.run_queues[PriorityClass::System as usize].contains(&kmain.0),
            "re-enqueued on the System queue"
        );
        assert!(
            !sched.run_queues[PriorityClass::Interactive as usize].contains(&kmain.0),
            "must not land in fairness slots 2/5 as Interactive"
        );
    }

    /// P11.2: the TCB lookup reads the LIVE priority — `enqueue` rewrites
    /// `tcb.priority`, and a later resolve must observe the rewrite (the
    /// PCB duplicate, frozen at spawn, would not).
    #[test]
    fn resolve_priority_tracks_live_tcb_priority() {
        let mut sched = RoundRobinScheduler::new();
        let id = sched.mock_enqueue(PriorityClass::Interactive);
        assert_eq!(sched.resolve_priority(id), PriorityClass::Interactive);
        sched
            .enqueue(id, PriorityClass::Background)
            .expect("requeue");
        assert_eq!(sched.resolve_priority(id), PriorityClass::Background);
    }

    /// P11.2: an id with neither TCB nor PCB keeps the historical
    /// `Interactive` final fallback.
    #[test]
    fn resolve_priority_unknown_id_falls_back_to_interactive() {
        let sched = RoundRobinScheduler::new();
        assert_eq!(
            sched.resolve_priority(TaskId(0xDEAD)),
            PriorityClass::Interactive
        );
    }

    // -------------------------------------------------------------------------
    // Property tests: scheduler invariants (WS13-02.7)
    // -------------------------------------------------------------------------

    use proptest::prelude::*;

    /// Map a 0..=5 code to a [`PriorityClass`] for property generation.
    fn prio(code: u8) -> PriorityClass {
        match code {
            0 => PriorityClass::System,
            1 => PriorityClass::RealTime,
            2 => PriorityClass::Interactive,
            3 => PriorityClass::AiInference,
            4 => PriorityClass::Background,
            _ => PriorityClass::Idle,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// For any sequence of enqueued tasks at random priorities, draining
        /// the scheduler with `pick_next` must hold these invariants (which are
        /// true regardless of the weighted anti-starvation rotation between
        /// classes):
        ///   (a) **termination + no loss / no duplication** — draining halts
        ///       and the picked set equals the enqueued set, each task exactly
        ///       once (the scheduler neither drops nor double-schedules work);
        ///   (b) **FIFO within a class** — same-priority tasks are picked in
        ///       their enqueue order (no reordering/starvation within a class).
        ///
        /// Strict cross-class priority order is deliberately NOT asserted: the
        /// scheduler interleaves lower-priority classes on a weighted rotation
        /// to prevent starvation, so a lower-priority task may legitimately be
        /// picked while a higher-priority one is still runnable.
        #[test]
        fn pick_next_drains_in_priority_order_without_loss(
            codes in proptest::collection::vec(0u8..6, 1..40),
        ) {
            let mut sched = RoundRobinScheduler::new();

            // Enqueue, remembering (id, priority code, enqueue index).
            let mut enq: Vec<(TaskId, u8, usize)> = Vec::new();
            for (i, &c) in codes.iter().enumerate() {
                let id = sched.mock_enqueue(prio(c));
                enq.push((id, c, i));
            }

            // Drain (the while loop terminating IS the termination invariant;
            // the bound below guards against a pick_next that never empties).
            let mut picked: Vec<TaskId> = Vec::new();
            while let Some(id) = sched.pick_next() {
                picked.push(id);
                prop_assert!(picked.len() <= enq.len(),
                    "pick_next returned more tasks than were enqueued");
            }

            // (a) No loss / no duplication: same multiset of ids.
            prop_assert_eq!(picked.len(), enq.len());
            let mut got: Vec<u64> = picked.iter().map(|t| t.0).collect();
            let mut want: Vec<u64> = enq.iter().map(|(t, _, _)| t.0).collect();
            got.sort_unstable();
            want.sort_unstable();
            prop_assert_eq!(got, want, "picked set differs from enqueued set");

            // (b) FIFO within each priority class.
            for class in 0u8..6 {
                let picked_order: Vec<usize> = picked
                    .iter()
                    .filter_map(|id| {
                        enq.iter()
                            .find(|(t, c, _)| t == id && *c == class)
                            .map(|(_, _, idx)| *idx)
                    })
                    .collect();
                let mut sorted = picked_order.clone();
                sorted.sort_unstable();
                prop_assert_eq!(picked_order, sorted,
                    "FIFO order violated within a priority class");
            }
        }
    }
}
