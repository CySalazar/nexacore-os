//! Per-CPU descriptor scaffold — MB14.a foundation for MP/AP enable.
//!
//! Extended in MB14.b with `IA32_GS_BASE` / `IA32_KERNEL_GS_BASE` wiring
//! and a GS-relative [`current_cpu`] accessor, then in MB14.c.2.d with
//! a sibling `AP_SLOTS` array so every logical CPU has a stable per-CPU
//! descriptor reachable by `lapic_id` lookup.
//!
//! ## Scope (MB14.a + MB14.b + MB14.c.2.d)
//!
//! - **`BSP`** is initialised from [`init_bsp`] after
//!   [`super::lapic::lapic_init`] has succeeded.
//! - **`AP_SLOTS`** is an array of [`MAX_CPUS - 1`] descriptors, one per
//!   Application Processor. The BSP populates the slots pre-fire via
//!   [`register_ap`]; the AP itself reads the slot pointer the BSP
//!   stamped into `super::mp_ap_entry::AP_RUNTIME_CONTROL` and parks
//!   it in its `gs:[0]` via `wrmsr` (MB14.c.2.d landing code).
//! - **`GS_BASE` per-CPU pointer (MB14.b).** [`init_gs_base`] writes the
//!   address of the supplied descriptor into the two GS-base MSRs:
//!   `IA32_GS_BASE` (`0xC000_0101`, active in kernel mode) and
//!   `IA32_KERNEL_GS_BASE` (`0xC000_0102`, shadow swapped in on
//!   `swapgs`). The descriptor stores a self-pointer at offset 0 so a
//!   single `mov rax, gs:[0]` returns the active `&'static PerCpu`.
//! - **No AP startup.** Only the BSP's LAPIC ID is recorded. Application
//!   processors land in MB14.c (INIT-SIPI-SIPI handshake with a real-mode
//!   trampoline).
//!
//! ## Why now
//!
//! MB13 closed the `nexacore-capability` integration cycle (ADR-0006) and the
//! kernel is single-CPU end-to-end. The driver model (P6.7) needs:
//! 1. cross-CPU TLB shootdown (broadcast `invlpg`), which presupposes
//!    a way to identify the local CPU and address sibling cores;
//! 2. per-CPU schedulers / run-queues, which need a per-CPU storage slot
//!    addressable in constant time from any kernel context.
//!
//! Both require a stable per-CPU descriptor reachable by a constant-time
//! instruction sequence. MB14.b makes that sequence a single `gs:[0]`
//! load, agnostic to which CPU is executing the code path.
//!
//! ## Why atomics
//!
//! The four fields are `core::sync::atomic` even though MB14.b touches
//! only the BSP. The descriptor is intentionally `Sync` so that future
//! AP code can populate sibling slots — in an `[PerCpu; MAX_CPUS]`
//! array — without taking a global lock on the cold paths.

#![allow(
    unsafe_code,
    reason = "static descriptor access + MSR writes + gs:[0] inline asm; MB14.b is single-CPU, BSP-only"
)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::mp::MAX_CPUS;

/// Sentinel: the descriptor has not yet been seeded by [`init_bsp`].
/// Chosen as `u32::MAX` so it cannot collide with a valid xAPIC ID
/// (8-bit field, max 255).
pub const CPU_ID_UNINIT: u32 = u32::MAX;

/// `IA32_GS_BASE` — active GS base while running in kernel mode.
/// Holds the per-CPU pointer between `swapgs` flips on Ring 3 → Ring 0
/// transitions (and the inverse before sysretq / iretq returns).
#[cfg(all(target_arch = "x86_64", not(test)))]
const MSR_GS_BASE: u32 = 0xC000_0101;

/// `IA32_KERNEL_GS_BASE` — shadow GS base. `swapgs` exchanges this with
/// the active `GS_BASE`, so userspace can keep its own value while the
/// kernel keeps the per-CPU pointer parked here.
#[cfg(all(target_arch = "x86_64", not(test)))]
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Per-CPU descriptor. One instance per logical CPU; MB14.a allocated
/// only the BSP slot.
///
/// `#[repr(C)]` is mandatory: the `self_ptr` field MUST live at offset 0
/// so a `gs:[0]` load returns `&PerCpu` after [`init_gs_base`].
///
/// Field semantics:
///
/// - `self_ptr`: address of `self` reachable via `gs:[0]` once
///   [`init_gs_base`] has wired the MSRs. `0` before `init_gs_base`.
/// - `cpu_id`: dense, 0-based kernel-local identifier. BSP is always 0.
/// - `lapic_id`: physical LAPIC ID as read from LAPIC register 0x20.
///   May be sparse (e.g., 0, 2, 4, … on some NUMA topologies).
/// - `is_bsp`: true on the Bootstrap Processor, false on Application
///   Processors. Used by the IPI broadcast logic to skip self.
/// - `kernel_rsp`: MB14.c.2.d — top of the per-CPU kernel stack, used by
///   the AP entry stub to materialise `RSP` before any push/pop. Stays
///   `0` for the BSP (which has been running on the boot stack since
///   reset).
/// - `tick_count`: MB14.g — LAPIC periodic-timer tick counter, owned by
///   this CPU. Incremented by `kernel_lapic_timer_tick` running on
///   whichever CPU received the interrupt; previously a single
///   `static mut TICK_COUNT` global, which race-shifted to per-CPU once
///   APs began servicing their own timers (MB14.f).
/// - `need_resched`: MB14.g — per-CPU rearm flag for the cooperative
///   resched trampoline. Replaces the global `scheduling::NEED_RESCHED`
///   on bare-metal builds so the BSP and every AP can independently
///   schedule their own next pick without cross-CPU thrash. The static
///   flag in `scheduling` stays for host / test builds (where there is
///   only one CPU and `current_cpu()` collapses to `&BSP`).
/// - `dispatch_observations`: MB14.h.1 — per-CPU counter incremented by
///   the AP-side dispatcher in
///   [`super::ap_dispatch::kernel_ap_dispatch_observe`] every time it
///   successfully pops a task from this CPU's run-queue (or steals one
///   from a sibling). MB14.h.2 promotes the dispatcher from observer
///   (pop+discard) to live yield (`SCHEDULER.yield_current`); the
///   counter remains a long-lived diagnostic so a future regression in
///   the AP timer path surfaces as `observed=0` on the next boot. See
///   ADR-0010 § Decision.
/// - `in_scheduler`: MB14.h.2 — per-CPU recursion guard for the
///   cooperative `yield_current` path (replaces the global
///   `scheduling::IN_SCHEDULER` static for bare-metal MP builds). Set
///   on entry by `kernel_check_need_resched` / `kernel_ap_dispatch_observe`
///   before they take `SCHED_LOCK` and call into `SCHEDULER`; cleared on
///   exit. A re-entrant tick on the same CPU (e.g. a cooperative
///   `TaskYield` syscall still on the stack when the timer fires)
///   observes the flag set and short-circuits — exactly the recursion
///   prevention the global flag delivered on single-CPU builds, now
///   per-CPU so concurrent BSP+AP yields cannot poison each other's
///   guard. The legacy global flag remains active on host / non-x86_64
///   builds where `current_cpu()` collapses to `&BSP`.
#[derive(Debug)]
#[repr(C)]
pub struct PerCpu {
    self_ptr: AtomicU64,
    cpu_id: AtomicU32,
    lapic_id: AtomicU32,
    is_bsp: AtomicBool,
    kernel_rsp: AtomicU64,
    tick_count: AtomicU64,
    need_resched: AtomicBool,
    dispatch_observations: AtomicU64,
    in_scheduler: AtomicBool,
    /// Kernel stack top for the SYSCALL fast path of the task this CPU is
    /// currently running (NCIP-026 WI-5). Updated per dispatch by
    /// `scheduling::yield_current`; read GS-relative by `nexacore_syscall_entry`
    /// via [`SYSCALL_RSP_OFFSET`]. Distinct from [`PerCpu::kernel_rsp`] (the
    /// AP's fixed boot/idle stack): this tracks the *current task's* stack so
    /// each CPU's syscalls land on the right per-task kernel stack.
    syscall_rsp: AtomicU64,
    /// Scratch cell holding the user RSP across the SYSCALL entry stack switch.
    /// Written/read only in the first three instructions of `nexacore_syscall_entry`
    /// (interrupts masked); per-CPU so two CPUs entering concurrently never
    /// clobber each other (read GS-relative via [`SYSCALL_SCRATCH_OFFSET`]).
    syscall_scratch: AtomicU64,
}

/// Byte offset of the per-CPU `syscall_rsp` field within the `#[repr(C)]`
/// struct. Consumed as a `const` operand by the `nexacore_syscall_entry` `gs:[..]`
/// asm.
pub const SYSCALL_RSP_OFFSET: usize = core::mem::offset_of!(PerCpu, syscall_rsp);

/// Byte offset of the per-CPU `syscall_scratch` field. See [`SYSCALL_RSP_OFFSET`].
pub const SYSCALL_SCRATCH_OFFSET: usize = core::mem::offset_of!(PerCpu, syscall_scratch);

impl PerCpu {
    /// Construct an uninitialised descriptor (suitable for a `static`).
    /// All identifier fields are seeded with [`CPU_ID_UNINIT`].
    #[must_use]
    pub const fn new_uninit() -> Self {
        Self {
            self_ptr: AtomicU64::new(0),
            cpu_id: AtomicU32::new(CPU_ID_UNINIT),
            lapic_id: AtomicU32::new(CPU_ID_UNINIT),
            is_bsp: AtomicBool::new(false),
            kernel_rsp: AtomicU64::new(0),
            tick_count: AtomicU64::new(0),
            need_resched: AtomicBool::new(false),
            dispatch_observations: AtomicU64::new(0),
            in_scheduler: AtomicBool::new(false),
            syscall_rsp: AtomicU64::new(0),
            syscall_scratch: AtomicU64::new(0),
        }
    }

    /// Record (per dispatch) the kernel stack top for this CPU's SYSCALL fast
    /// path (NCIP-026 WI-5). Called from `scheduling::yield_current` and the
    /// dev-userprobe first-dispatch. `Release` pairs with the entry stub's
    /// GS-relative read (which runs with interrupts masked on this same CPU).
    pub fn set_syscall_rsp(&self, rsp_top: u64) {
        self.syscall_rsp.store(rsp_top, Ordering::Release);
    }

    /// Read this CPU's current SYSCALL kernel stack top (telemetry / tests).
    #[must_use]
    pub fn syscall_rsp(&self) -> u64 {
        self.syscall_rsp.load(Ordering::Acquire)
    }

    /// MB14.c.2.d — set the per-CPU kernel stack top (read by the AP
    /// entry stub before any push/pop). `Release` so the AP — which
    /// loads this with a plain `mov` after observing the slot pointer
    /// via `AP_RUNTIME_CONTROL` — sees the latest value.
    pub fn set_kernel_rsp(&self, rsp_top: u64) {
        self.kernel_rsp.store(rsp_top, Ordering::Release);
    }

    /// MB14.c.2.d — read-back of the per-CPU kernel stack top.
    #[must_use]
    pub fn kernel_rsp(&self) -> u64 {
        self.kernel_rsp.load(Ordering::Acquire)
    }

    /// Dense kernel-local CPU identifier (BSP = 0).
    #[must_use]
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id.load(Ordering::Acquire)
    }

    /// Physical LAPIC ID for this logical CPU.
    #[must_use]
    pub fn lapic_id(&self) -> u32 {
        self.lapic_id.load(Ordering::Acquire)
    }

    /// `true` iff this descriptor belongs to the Bootstrap Processor.
    #[must_use]
    pub fn is_bsp(&self) -> bool {
        self.is_bsp.load(Ordering::Acquire)
    }

    /// `true` once the descriptor has been populated by [`init_bsp`] (or
    /// in the future by the AP startup path).
    #[must_use]
    pub fn is_initialised(&self) -> bool {
        self.cpu_id() != CPU_ID_UNINIT
    }

    /// MB14.g — increment this CPU's monotonic timer-tick counter.
    ///
    /// Called from the LAPIC periodic-timer ISR (`kernel_lapic_timer_tick`)
    /// running on whichever CPU received the interrupt. Each CPU writes
    /// only its own counter; cross-CPU reads use `Acquire`.
    pub fn inc_tick(&self) {
        self.tick_count.fetch_add(1, Ordering::Release);
    }

    /// MB14.g — read this CPU's monotonic timer-tick counter.
    #[must_use]
    pub fn tick_count(&self) -> u64 {
        self.tick_count.load(Ordering::Acquire)
    }

    /// MB14.g — signal that this CPU should run the cooperative resched
    /// trampoline at the next interrupt-tail safe point. `Release` so the
    /// matching `take_resched` reads paired data in coherent order.
    pub fn request_resched(&self) {
        self.need_resched.store(true, Ordering::Release);
    }

    /// MB14.g — consume the resched flag (atomic swap to `false`).
    /// Returns `true` if a resched was pending. Called from the IRQ-tail
    /// trampoline.
    #[must_use]
    pub fn take_resched(&self) -> bool {
        self.need_resched.swap(false, Ordering::AcqRel)
    }

    /// MB14.g — peek the resched flag without consuming it (test
    /// helper / diagnostic).
    #[must_use]
    pub fn resched_pending(&self) -> bool {
        self.need_resched.load(Ordering::Acquire)
    }

    /// MB14.h.1 — record one observer-mode dispatch pick on this CPU.
    ///
    /// Called from
    /// [`super::ap_dispatch::kernel_ap_dispatch_observe`] every time it
    /// successfully pops a task id from the per-CPU run-queue (or steals
    /// one from a sibling). Observer mode discards the popped id; the
    /// counter exists exclusively so the BSP boot-time smoke can confirm
    /// the AP timer ISR reached the dispatcher.
    pub fn inc_dispatch_observation(&self) {
        self.dispatch_observations.fetch_add(1, Ordering::Release);
    }

    /// MB14.h.1 — read this CPU's observer-mode dispatch counter.
    ///
    /// Polled by the BSP smoke in
    /// [`crate::kmain`](crate) after enqueuing a sentinel task on this
    /// CPU's run-queue, to assert the AP ran the observer at least once.
    #[must_use]
    pub fn dispatch_observations(&self) -> u64 {
        self.dispatch_observations.load(Ordering::Acquire)
    }

    /// MB14.h.2 — try to claim this CPU's scheduler-recursion guard.
    ///
    /// Returns `true` if the guard was previously clear (the caller now
    /// owns it) and `false` if a re-entrant scheduler call is already
    /// in flight on this CPU. The caller must pair every `true` return
    /// with exactly one [`Self::leave_scheduler`] call.
    ///
    /// Replaces the global `scheduling::IN_SCHEDULER` static for
    /// bare-metal MP builds where each AP runs its own cooperative
    /// `yield_current` path: a tick that arrives while the previous
    /// yield is still on this CPU's stack short-circuits cleanly
    /// without poisoning a sibling CPU's guard.
    #[must_use]
    pub fn enter_scheduler(&self) -> bool {
        // `compare_exchange` with `AcqRel` on success / `Acquire` on
        // failure: the success edge publishes to a paired `leave_scheduler`
        // store; the failure edge synchronises with the prior `enter`
        // that observed the guard clear.
        self.in_scheduler
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// MB14.h.2 — release this CPU's scheduler-recursion guard. Must
    /// only be called after a successful [`Self::enter_scheduler`].
    pub fn leave_scheduler(&self) {
        self.in_scheduler.store(false, Ordering::Release);
    }

    /// MB14.h.2 — peek the scheduler-recursion guard (diagnostic only).
    #[must_use]
    pub fn is_in_scheduler(&self) -> bool {
        self.in_scheduler.load(Ordering::Acquire)
    }

    /// Address that `gs:[0]` resolves to after [`init_gs_base`].
    ///
    /// Returns `0` until `init_gs_base` runs. Primarily used by tests
    /// and the boot serial dump to confirm the MSR was wired.
    #[must_use]
    pub fn self_ptr(&self) -> u64 {
        self.self_ptr.load(Ordering::Acquire)
    }

    /// Seed the descriptor in-place. `Release` stores so a later
    /// `Acquire` read in another execution context observes all three
    /// fields populated together.
    fn seed(&self, cpu_id: u32, lapic_id: u32, is_bsp: bool) {
        self.lapic_id.store(lapic_id, Ordering::Release);
        self.is_bsp.store(is_bsp, Ordering::Release);
        self.cpu_id.store(cpu_id, Ordering::Release);
    }
}

/// Singleton Bootstrap Processor descriptor (`cpu_id = 0`, always).
///
/// MB14.a only wrote this slot. MB14.c.2.d adds [`AP_SLOTS`] for sibling
/// Application Processors; the BSP descriptor stays distinct so the
/// existing single-CPU code paths (every kernel reference to
/// `current_cpu()` and `bsp()`) remain byte-identical.
static BSP: PerCpu = PerCpu::new_uninit();

/// Maximum number of Application Processors the kernel tracks. Equal to
/// `MAX_CPUS - 1` (the BSP occupies its own slot).
pub const MAX_AP_SLOTS: usize = MAX_CPUS - 1;

/// Sibling array indexed by `ap_index = cpu_id - 1` for `cpu_id >= 1`.
///
/// MB14.c.2.d populates this from the BSP pre-fire via [`register_ap`].
/// Each entry is independently `Sync` (atomic fields) so a hypothetical
/// concurrent observer cannot tear a partially-initialised descriptor.
static AP_SLOTS: [PerCpu; MAX_AP_SLOTS] = [const { PerCpu::new_uninit() }; MAX_AP_SLOTS];

/// Seed the BSP descriptor with `lapic_id` (typically read via
/// [`super::lapic::read_lapic_id`]).
///
/// Idempotent: the BSP's `cpu_id` is always 0 and `is_bsp` is always
/// true, so a redundant call is harmless. Subsequent reads see the
/// last-written values.
pub fn init_bsp(lapic_id: u32) {
    BSP.seed(0, lapic_id, true);
}

/// MB14.c.2.d — populate an Application Processor descriptor.
///
/// `cpu_id` MUST be in `1..MAX_CPUS`; `cpu_id = 0` is the BSP and is
/// rejected. Returns `None` on out-of-range `cpu_id`, the populated
/// `&'static PerCpu` otherwise.
///
/// The slot reference returned is `'static` because it aliases
/// `AP_SLOTS[cpu_id - 1]`, which is a `static`. The BSP stores this
/// address inside `super::mp_ap_entry::AP_RUNTIME_CONTROL` so the AP
/// can recover it after the CR3 switch.
#[must_use]
pub fn register_ap(cpu_id: u32, lapic_id: u32) -> Option<&'static PerCpu> {
    if cpu_id == 0 {
        return None;
    }
    let idx = (cpu_id as usize).checked_sub(1)?;
    let slot = AP_SLOTS.get(idx)?;
    slot.seed(cpu_id, lapic_id, false);
    // MB14.f.1 follow-up — stamp the slot's self-pointer at offset 0.
    // The AP's `kmain_ap` asm writes `IA32_GS_BASE` with the slot
    // address; the very next `current_cpu()` call from this AP reads
    // `gs:[0]` (the slot's `self_ptr` field) expecting to recover
    // `&PerCpu`. Without this stamp the field is `0`, and the first
    // method call on the resulting NULL pointer (e.g.
    // `current_cpu().is_bsp()` from `kernel_lapic_timer_tick` after
    // the AP timer fires) faults at `cr2 = 0x10` (the offset of
    // `is_bsp` inside `PerCpu`).
    let slot_addr = core::ptr::from_ref::<PerCpu>(slot) as u64;
    slot.self_ptr.store(slot_addr, Ordering::Release);
    Some(slot)
}

/// MB14.c.2.d — read-back accessor for an AP slot by `cpu_id` (>= 1).
///
/// Returns `None` for `cpu_id = 0` (BSP — use [`bsp`]) or an out-of-range
/// `cpu_id`.
#[must_use]
pub fn ap_slot(cpu_id: u32) -> Option<&'static PerCpu> {
    let idx = (cpu_id as usize).checked_sub(1)?;
    AP_SLOTS.get(idx)
}

/// Number of slots actively populated by [`register_ap`].
///
/// MB14.c.2.d uses this for the boot-log line and the host-side tests
/// that scan `AP_SLOTS` for `is_initialised()` entries.
#[must_use]
pub fn registered_ap_count() -> usize {
    AP_SLOTS.iter().filter(|s| s.is_initialised()).count()
}

/// MB14.c.2.d — monotonic counter incremented by each AP once it has
/// reached the parked state (post-`lgdt`/`lidt`/`ltr`/`sti`-free park).
/// The BSP polls this from `kmain` after `start_aps_live` returns to
/// confirm the per-AP init sequence completed.
///
/// `no_mangle` because the AP entry asm (see [`super::mp_ap_entry`])
/// emits a `lock inc qword ptr [rip + AP_ONLINE_ACK]` referencing this
/// symbol directly.
#[unsafe(no_mangle)]
static AP_ONLINE_ACK: AtomicU64 = AtomicU64::new(0);

/// MB14.c.2.d — read the AP online ack counter.
#[must_use]
pub fn ap_online_ack() -> u64 {
    AP_ONLINE_ACK.load(Ordering::Acquire)
}

/// MB14.c.2.d — symbol address of the AP online ack counter so the
/// AP-entry asm can emit `lock inc qword ptr [rip + AP_ONLINE_ACK]`
/// against it without round-tripping through a register.
#[must_use]
pub fn ap_online_ack_addr() -> u64 {
    core::ptr::addr_of!(AP_ONLINE_ACK) as u64
}

/// Reference to the descriptor for the CPU currently running this code.
///
/// On bare-metal `x86_64`, this dereferences the self-pointer parked at
/// `gs:[0]` by [`init_gs_base`] — a single instruction, constant time,
/// agnostic to which CPU is executing. On host / non-x86_64 builds the
/// function returns the BSP singleton (the only descriptor that exists
/// in those test environments).
#[must_use]
pub fn current_cpu() -> &'static PerCpu {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let ptr: *const PerCpu;
        // SAFETY: `init_gs_base` ran during boot, parking `&BSP` at
        // offset 0 of the GS segment. The pointer is `'static` because
        // it aliases `static BSP`. Future AP code will park its own
        // per-CPU descriptor pointer the same way before enabling
        // interrupts, so the load remains valid on every CPU.
        unsafe {
            core::arch::asm!(
                "mov {ptr}, gs:[0]",
                ptr = out(reg) ptr,
                options(nomem, nostack, preserves_flags),
            );
            &*ptr
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    {
        &BSP
    }
}

/// Convenience: the BSP descriptor specifically. Useful for AP code that
/// wants to address the BSP without going through [`current_cpu`].
#[must_use]
pub fn bsp() -> &'static PerCpu {
    &BSP
}

/// MB14.b — wire the GS-base MSRs to the supplied descriptor.
///
/// Writes the descriptor's address into `IA32_GS_BASE` (active in
/// kernel mode) and `IA32_KERNEL_GS_BASE` (shadow for `swapgs`), and
/// stamps the self-pointer at offset 0 of the descriptor so that
/// `gs:[0]` resolves to `&pc` from any kernel context.
///
/// Both MSRs receive the same value so that:
///
/// - During kernel boot (before any Ring 3 entry) the active GS base
///   is the per-CPU pointer, allowing `current_cpu()` to work the
///   moment this call returns.
/// - After the first Ring 3 → Ring 0 transition (syscall entry has
///   `swapgs` as its first instruction), the swap brings the per-CPU
///   pointer from the shadow MSR back into the active slot — leaving
///   userspace's GS base preserved in the shadow until sysretq swaps
///   it back. Both starting values being identical means a misordered
///   `swapgs` (e.g., during early panic before user mode is reached)
///   still leaves the kernel with a valid per-CPU pointer.
///
/// # Safety
///
/// Caller must hold a `&'static` reference to `pc`. MSR writes are
/// privileged (Ring 0) but otherwise side-effect-free: they affect
/// only the addressing base used by GS-segment overrides on this
/// logical CPU.
#[cfg(all(target_arch = "x86_64", not(test)))]
pub fn init_gs_base(pc: &'static PerCpu) {
    let pc_ptr = core::ptr::from_ref::<PerCpu>(pc) as u64;
    // Stamp the self-pointer first so it is observable the instant the
    // MSRs are armed. `Release` pairs with the `Acquire` load in
    // `current_cpu`'s consumers (e.g., a future scheduler tick that
    // reads `cpu_id` after observing `self_ptr`).
    pc.self_ptr.store(pc_ptr, Ordering::Release);

    // SAFETY: both MSRs are documented in Intel SDM Vol 3A §10.4 /
    // §3.4.4 and accept any 64-bit value as the GS base. The pointer
    // is a valid kernel address (`pc` is `&'static`). We are running
    // in Ring 0 at boot time, single-CPU, with no preemption.
    unsafe {
        wrmsr(MSR_GS_BASE, pc_ptr);
        wrmsr(MSR_KERNEL_GS_BASE, pc_ptr);
    }
}

/// Field-stamp-only path for non-bare-metal builds.
///
/// Covers non-x86_64 hosts AND `cfg(test)` on any target. The `wrmsr`
/// instruction is Ring 0; running it from a userland test binary on
/// `x86_64-unknown-linux-gnu` would raise #GP and the host kernel
/// would deliver SIGSEGV (the historical cargo-test failure tracked
/// against this suite). The field-stamp half is independently
/// verifiable and is what tests exercise.
#[cfg(any(not(target_arch = "x86_64"), test))]
pub fn init_gs_base(pc: &'static PerCpu) {
    let pc_ptr = core::ptr::from_ref::<PerCpu>(pc) as u64;
    pc.self_ptr.store(pc_ptr, Ordering::Release);
}

/// Privileged write to model-specific register `msr`.
///
/// # Safety
///
/// Ring 0 only. The caller must ensure `msr` accepts the value and is
/// architecturally defined (no reserved bits set).
#[cfg(all(target_arch = "x86_64", not(test)))]
unsafe fn wrmsr(msr: u32, value: u64) {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "MSR encoding splits the 64-bit value into lo:eax / hi:edx by spec"
    )]
    let lo = value as u32;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "right-shift then `as u32` is the canonical MSR hi-half encoding"
    )]
    let hi = (value >> 32) as u32;
    // SAFETY: `wrmsr` is a ring-0 instruction; caller invariants above.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uninit_marks_descriptor_as_uninitialised() {
        let pc = PerCpu::new_uninit();
        assert_eq!(pc.cpu_id(), CPU_ID_UNINIT);
        assert_eq!(pc.lapic_id(), CPU_ID_UNINIT);
        assert!(!pc.is_bsp());
        assert!(!pc.is_initialised());
        assert_eq!(pc.self_ptr(), 0);
    }

    #[test]
    fn seed_populates_all_three_fields() {
        let pc = PerCpu::new_uninit();
        pc.seed(0, 7, true);
        assert_eq!(pc.cpu_id(), 0);
        assert_eq!(pc.lapic_id(), 7);
        assert!(pc.is_bsp());
        assert!(pc.is_initialised());
    }

    #[test]
    fn seed_ap_does_not_set_bsp_flag() {
        let pc = PerCpu::new_uninit();
        pc.seed(3, 12, false);
        assert_eq!(pc.cpu_id(), 3);
        assert!(!pc.is_bsp());
        assert!(pc.is_initialised());
    }

    #[test]
    fn init_bsp_seeds_global_descriptor() {
        // The global BSP is shared across tests; this test asserts only
        // the invariants that must hold post-seed regardless of who ran
        // first (cpu_id == 0, is_bsp == true). The lapic_id value is
        // implementation-detail of whatever test seeded it last; we
        // assert that the descriptor is marked initialised.
        init_bsp(0);
        let cpu = current_cpu();
        assert_eq!(cpu.cpu_id(), 0);
        assert!(cpu.is_bsp());
        assert!(cpu.is_initialised());
    }

    #[test]
    fn current_cpu_returns_bsp_singleton() {
        // Host build: `current_cpu()` collapses to `&BSP`; bare-metal
        // build dereferences `gs:[0]`. Both must agree on identity.
        let a = current_cpu() as *const PerCpu;
        let b = bsp() as *const PerCpu;
        assert_eq!(a, b);
    }

    #[test]
    fn cpu_id_uninit_sentinel_does_not_collide_with_xapic_ids() {
        // xAPIC IDs are 8-bit (max 255); CPU_ID_UNINIT must not be a
        // value any real LAPIC could legitimately report. Static
        // assertion via const_assert — clippy::assertions_on_constants
        // (`assert!(true)`) fires on runtime asserts of pure constants.
        const _: () = assert!(CPU_ID_UNINIT > 0xFF);
    }

    /// MB14.b — the self-pointer is the first field of [`PerCpu`] so a
    /// `gs:[0]` load on bare-metal returns `&PerCpu`. This test pins the
    /// layout: the address of `self_ptr` must equal the address of the
    /// containing struct.
    #[test]
    fn self_ptr_field_at_offset_zero() {
        let pc = PerCpu::new_uninit();
        let struct_addr = core::ptr::addr_of!(pc) as usize;
        let field_addr = core::ptr::addr_of!(pc.self_ptr) as usize;
        assert_eq!(struct_addr, field_addr);
    }

    /// MB14.b — host stub of [`init_gs_base`] stamps the self-pointer.
    /// Bare-metal builds additionally wire two MSRs; the field-stamp
    /// half is verifiable here.
    #[test]
    fn init_gs_base_stamps_self_pointer() {
        init_gs_base(bsp());
        let stamped = bsp().self_ptr();
        let expected = core::ptr::from_ref::<PerCpu>(bsp()) as u64;
        assert_eq!(stamped, expected);
    }

    // -----------------------------------------------------------------
    // MB14.c.2.d — AP slot array + register/lookup helpers.
    // -----------------------------------------------------------------

    /// `MAX_AP_SLOTS` matches `MAX_CPUS - 1` (BSP occupies its own slot).
    #[test]
    fn max_ap_slots_is_max_cpus_minus_one() {
        assert_eq!(MAX_AP_SLOTS, MAX_CPUS - 1);
    }

    /// `register_ap(0, _)` is rejected — `cpu_id = 0` is reserved for BSP.
    #[test]
    fn register_ap_rejects_bsp_cpu_id() {
        assert!(register_ap(0, 12).is_none());
    }

    /// `register_ap(MAX_CPUS, _)` is rejected — out-of-range cpu_id.
    #[test]
    fn register_ap_rejects_out_of_range_cpu_id() {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "MAX_CPUS = 32 fits u32 trivially; reject path"
        )]
        let oor = MAX_CPUS as u32;
        assert!(register_ap(oor, 99).is_none());
    }

    /// `register_ap(k, l)` returns an aliased `'static` slot whose
    /// `cpu_id`/`lapic_id` reflect the call.
    #[test]
    fn register_ap_seeds_slot_with_lapic_id() {
        // Use cpu_id == 1 (first AP slot) — different tests share static
        // state, so assert relative-to-input rather than relative-to-zero.
        let slot = register_ap(1, 7).expect("AP slot 1 must register");
        assert_eq!(slot.cpu_id(), 1);
        assert_eq!(slot.lapic_id(), 7);
        assert!(!slot.is_bsp());
        assert!(slot.is_initialised());
    }

    /// `ap_slot(k)` returns the same pointer as `register_ap(k, _)`.
    #[test]
    fn ap_slot_returns_same_pointer_as_register_ap() {
        let a = register_ap(2, 9).expect("slot 2");
        let b = ap_slot(2).expect("slot 2 readback");
        assert_eq!(core::ptr::from_ref(a), core::ptr::from_ref(b));
    }

    /// `ap_slot(0)` returns `None` (BSP); use `bsp()` instead.
    #[test]
    fn ap_slot_zero_is_none() {
        assert!(ap_slot(0).is_none());
    }

    /// `set_kernel_rsp` round-trips through `kernel_rsp`.
    #[test]
    fn kernel_rsp_round_trip() {
        let pc = PerCpu::new_uninit();
        assert_eq!(pc.kernel_rsp(), 0);
        pc.set_kernel_rsp(0xFFFF_C001_0000_0000);
        assert_eq!(pc.kernel_rsp(), 0xFFFF_C001_0000_0000);
    }

    /// `ap_online_ack_addr` returns a non-null, stable address (same
    /// across consecutive calls).
    #[test]
    fn ap_online_ack_addr_is_stable_and_nonzero() {
        let a = ap_online_ack_addr();
        let b = ap_online_ack_addr();
        assert_ne!(a, 0);
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------
    // MB14.g — per-CPU tick counter + need_resched flag.
    // -----------------------------------------------------------------

    /// Fresh descriptor reports `tick_count = 0` and `need_resched = false`.
    #[test]
    fn tick_and_resched_default_zero() {
        let pc = PerCpu::new_uninit();
        assert_eq!(pc.tick_count(), 0);
        assert!(!pc.resched_pending());
    }

    /// `inc_tick` produces a monotonic counter scoped to this descriptor.
    #[test]
    fn inc_tick_is_monotonic_per_descriptor() {
        let pc = PerCpu::new_uninit();
        pc.inc_tick();
        pc.inc_tick();
        pc.inc_tick();
        assert_eq!(pc.tick_count(), 3);
    }

    /// `request_resched` flips the flag; `take_resched` consumes it.
    #[test]
    fn need_resched_request_then_take_round_trip() {
        let pc = PerCpu::new_uninit();
        assert!(!pc.resched_pending());
        pc.request_resched();
        assert!(pc.resched_pending());
        assert!(pc.take_resched());
        assert!(!pc.resched_pending());
        // Second take returns false (flag was consumed).
        assert!(!pc.take_resched());
    }

    /// Two descriptors keep their own tick counters — pinning the
    /// per-CPU isolation guarantee MB14.g relies on.
    #[test]
    fn tick_counters_are_per_descriptor() {
        let a = PerCpu::new_uninit();
        let b = PerCpu::new_uninit();
        a.inc_tick();
        a.inc_tick();
        b.inc_tick();
        assert_eq!(a.tick_count(), 2);
        assert_eq!(b.tick_count(), 1);
    }

    // -----------------------------------------------------------------
    // MB14.h.1 — per-CPU observer-mode dispatch counter.
    // -----------------------------------------------------------------

    /// Fresh descriptor reports zero dispatch observations.
    #[test]
    fn dispatch_observations_default_zero() {
        let pc = PerCpu::new_uninit();
        assert_eq!(pc.dispatch_observations(), 0);
    }

    /// `inc_dispatch_observation` is monotonic on a single descriptor.
    #[test]
    fn inc_dispatch_observation_is_monotonic_per_descriptor() {
        let pc = PerCpu::new_uninit();
        pc.inc_dispatch_observation();
        pc.inc_dispatch_observation();
        pc.inc_dispatch_observation();
        pc.inc_dispatch_observation();
        assert_eq!(pc.dispatch_observations(), 4);
    }

    /// Two descriptors keep independent dispatch counters — pins the
    /// per-CPU isolation guarantee MB14.h.1 relies on (the BSP smoke
    /// reads `ap_slot(1).dispatch_observations()` without touching the
    /// BSP's own counter).
    #[test]
    fn dispatch_counters_are_per_descriptor() {
        let a = PerCpu::new_uninit();
        let b = PerCpu::new_uninit();
        a.inc_dispatch_observation();
        a.inc_dispatch_observation();
        b.inc_dispatch_observation();
        assert_eq!(a.dispatch_observations(), 2);
        assert_eq!(b.dispatch_observations(), 1);
    }

    // -----------------------------------------------------------------
    // MB14.h.2 — per-CPU scheduler recursion guard.
    // -----------------------------------------------------------------

    /// Fresh descriptor reports its scheduler guard clear.
    #[test]
    fn in_scheduler_default_false() {
        let pc = PerCpu::new_uninit();
        assert!(!pc.is_in_scheduler());
    }

    /// First `enter_scheduler` claims the guard; second call refuses.
    /// `leave_scheduler` releases it; a follow-up `enter` claims again.
    #[test]
    fn enter_scheduler_is_mutually_exclusive_per_descriptor() {
        let pc = PerCpu::new_uninit();
        assert!(pc.enter_scheduler());
        assert!(pc.is_in_scheduler());
        // Re-entrant attempt on the same descriptor must fail.
        assert!(!pc.enter_scheduler());
        pc.leave_scheduler();
        assert!(!pc.is_in_scheduler());
        // After leave, the descriptor is claimable again.
        assert!(pc.enter_scheduler());
        pc.leave_scheduler();
    }

    /// Two descriptors hold independent guards — pinning the per-CPU
    /// isolation guarantee MB14.h.2 relies on (BSP holding its scheduler
    /// guard cannot block an AP claiming its own guard concurrently).
    #[test]
    fn scheduler_guards_are_per_descriptor() {
        let a = PerCpu::new_uninit();
        let b = PerCpu::new_uninit();
        assert!(a.enter_scheduler());
        // a is busy, but b is independent.
        assert!(b.enter_scheduler());
        assert!(a.is_in_scheduler());
        assert!(b.is_in_scheduler());
        a.leave_scheduler();
        assert!(!a.is_in_scheduler());
        // b still held.
        assert!(b.is_in_scheduler());
        b.leave_scheduler();
    }

    /// MB14.f.1 follow-up — `register_ap` must stamp the slot's
    /// `self_ptr` to its own address so an AP `mov rax, gs:[0]`
    /// recovers `&PerCpu`. Without this stamp the AP timer handler
    /// `current_cpu().is_bsp()` page-faults at `cr2 = 0x10` (the
    /// `is_bsp` offset). Pin the invariant so a future refactor of
    /// `register_ap` cannot regress this without surfacing in CI.
    #[test]
    fn register_ap_stamps_self_pointer_at_offset_zero() {
        // Pick a cpu_id distinct from earlier register_ap tests to
        // avoid relying on slot-level idempotency: each call rewrites
        // the slot's self_ptr to its own address, so even a re-used
        // slot must end up with self_ptr = &slot after this call.
        let slot = register_ap(4, 0xAB).expect("slot 4 must register");
        let expected = core::ptr::from_ref(slot) as u64;
        assert_eq!(slot.self_ptr(), expected);
    }

    /// NCIP-026 WI-5 — `nexacore_syscall_entry` reads the per-CPU SYSCALL RSP and
    /// scratch cells GS-relative using these exported byte offsets, and
    /// `self_ptr` MUST stay at offset 0 (the `gs:[0]` → `&PerCpu` invariant).
    /// Pin all three so a field reorder cannot silently desync the asm from the
    /// struct layout, and confirm the slot round-trips.
    #[test]
    fn syscall_rsp_slots_have_stable_offsets_and_round_trip() {
        assert_eq!(core::mem::offset_of!(PerCpu, self_ptr), 0);
        // 8-byte aligned (AtomicU64) and distinct, so each GS-relative load is
        // naturally aligned and the two cells never overlap.
        assert_eq!(SYSCALL_RSP_OFFSET % 8, 0);
        assert_eq!(SYSCALL_SCRATCH_OFFSET % 8, 0);
        assert_ne!(SYSCALL_RSP_OFFSET, SYSCALL_SCRATCH_OFFSET);
        assert!(SYSCALL_RSP_OFFSET + 8 <= core::mem::size_of::<PerCpu>());
        assert!(SYSCALL_SCRATCH_OFFSET + 8 <= core::mem::size_of::<PerCpu>());

        let pc = PerCpu::new_uninit();
        assert_eq!(pc.syscall_rsp(), 0);
        pc.set_syscall_rsp(0xDEAD_BEEF_0000_1000);
        assert_eq!(pc.syscall_rsp(), 0xDEAD_BEEF_0000_1000);
    }
}
