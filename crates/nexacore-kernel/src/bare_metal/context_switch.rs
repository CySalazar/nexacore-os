//! `x86_64` cooperative context switch — MB6 deliverable + MB8 trampoline.
//!
//! Provides three items used by [`crate::scheduling::RoundRobinScheduler`]:
//!
//! - `context_switch`: assembly routine that saves the current task's
//!   callee-saved registers + RSP to `*from_rsp`, then resumes the task
//!   whose kernel-stack pointer is `to_rsp`.
//! - `nexacore_task_entry_trampoline`: tiny stub (`sti; ret`) that wraps a
//!   freshly-spawned task's entry point so the task starts with `IF = 1`
//!   even when the first `context_switch` into it runs inside the LAPIC
//!   timer's Interrupt Gate (which masks `IF`). MB8.
//! - `setup_task_frame`: Rust helper that writes the initial stack frame
//!   for a freshly-spawned kernel task so that the first `context_switch`
//!   into it lands at the trampoline, which immediately enables interrupts
//!   and then jumps to the real entry function.
//!
//! ## Stack layout after `context_switch` saves a task
//!
//! ```text
//! higher address (stack top)
//!   ┌────────────────────────┐
//!   │  RIP (return address)  │  ← pushed implicitly by `call context_switch`
//!   │  RBP                   │  ← pushed by the stub
//!   │  RBX                   │
//!   │  R12                   │
//!   │  R13                   │
//!   │  R14                   │
//!   │  R15                   │  ← RSP saved here in TCB
//!   └────────────────────────┘
//! lower address (stack grows ↓)
//! ```
//!
//! ## Stack layout produced by `setup_task_frame` (MB8)
//!
//! ```text
//! higher address (stack top)
//!   ┌────────────────────────────────┐
//!   │  entry (real fn() -> !)        │  ← popped by trampoline's `ret`
//!   │  nexacore_task_entry_trampoline    │  ← popped by context_switch's `ret`
//!   │  RBP = 0                       │
//!   │  RBX = 0                       │
//!   │  R12 = 0                       │
//!   │  R13 = 0                       │
//!   │  R14 = 0                       │
//!   │  R15 = 0                       │  ← initial RSP saved in TCB
//!   └────────────────────────────────┘
//! ```
//!
//! The trampoline is the indirection that solves the "first switch from
//! inside an Interrupt Gate leaves IF=0" problem: an Interrupt Gate clears
//! IF on entry; if the very first scheduler entry into a brand-new task is
//! triggered by the timer IRQ, the task would otherwise run with interrupts
//! permanently disabled (no further preemption possible).

#![allow(unsafe_code)]

// Only meaningful on x86_64 — all items are gated accordingly.
#[cfg(target_arch = "x86_64")]
use core::arch::global_asm;

// ---------------------------------------------------------------------------
// Assembly stub
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    /// Save the current task's callee-saved registers to `*from_rsp`, then
    /// resume the task whose kernel stack pointer is `to_rsp`.
    ///
    /// Calling convention (System V AMD64):
    /// - `from_rsp` (RDI): address of the `rsp` field in the current TCB.
    /// - `to_rsp`   (RSI): value to load into RSP for the next task.
    ///
    /// On entry the CPU has already pushed the return address via `call`.
    /// The stub pushes RBP, RBX, R12–R15 (6 × 8 = 48 bytes), stores RSP,
    /// then loads `to_rsp`, pops the registers in reverse order, and `ret`s
    /// into the next task at its saved RIP.
    ///
    /// # Safety
    ///
    /// - `from_rsp` must point to a valid `u64` in the current task's TCB.
    /// - `to_rsp` must be an RSP value saved by a previous `context_switch`
    ///   call OR the initial RSP set up by [`setup_task_frame`].
    /// - Must be called with interrupts disabled (IF = 0).
    /// - Must be called on a single CPU (no SMP in MB6 scope).
    #[link_name = "nexacore_context_switch"]
    pub fn context_switch(from_rsp: *mut u64, to_rsp: u64);
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".global nexacore_context_switch",
    "nexacore_context_switch:",
    // Save callee-saved registers (System V AMD64 §3.2.1).
    // RIP is already on the stack (pushed by the `call` instruction).
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    // Store current RSP in *from_rsp (RDI = first argument).
    "    mov [rdi], rsp",
    // Load next task's RSP (RSI = second argument).
    "    mov rsp, rsi",
    // Restore next task's callee-saved registers.
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    // Return to the next task's saved RIP.
    "    ret",
);

// ---------------------------------------------------------------------------
// Save-and-enter-user-mode (Bug 5 fix)
// ---------------------------------------------------------------------------
//
// First dispatch of a freshly-spawned user task must STILL save the OUTGOING
// task's resumable kernel context before the `iretq` into Ring 3. The plain
// `enter_user_mode` (usermode.rs) only does the "enter" half and diverges, so
// when the scheduler used it for first dispatch the outgoing task's
// `context.rsp` was never written — it stayed the `0` sentinel, and the next
// time that task was selected it was wrongly re-treated as first-dispatch and
// its `_start` ran again (Bug 5: nexacore-net printed "service starting" twice
// from a single spawn).
//
// This routine does both halves atomically:
//   1. Push the callee-saved registers in the SAME order as
//      `nexacore_context_switch`, then `mov [rdi], rsp` — producing a frame that a
//      later `nexacore_context_switch` resume (`pop r15..rbp; ret`) unwinds
//      exactly, returning into the caller (`yield_current`) right after the
//      call. This is what makes the outgoing task resumable.
//   2. Perform the identical stack-swap → CR3 reload → iretq sequence as
//      `enter_user_mode` to enter the incoming first-dispatch task in Ring 3.
//
// From the OUTGOING task's perspective the call "returns" (normally, with
// callee-saved registers intact per the C ABI) only when a future
// `context_switch` resumes it.
//
// USER_SS (0x1B = GDT slot 3 | RPL 3) and USER_CS (0x23 = GDT slot 4 | RPL 3)
// are hardcoded as immediates; the `const _` block below static-asserts they
// still match `gdt`, so a GDT change breaks the build loudly instead of
// silently faulting at iretq.
#[cfg(target_arch = "x86_64")]
const _: () = {
    assert!(
        super::gdt::USER_SS == 0x1B,
        "USER_SS selector drifted from asm immediate"
    );
    assert!(
        super::gdt::USER_CS == 0x23,
        "USER_CS selector drifted from asm immediate"
    );
};

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    /// Save the OUTGOING task's resumable kernel context to `*from_rsp` (in a
    /// layout byte-compatible with [`context_switch`]'s save), then enter Ring 3
    /// for the INCOMING first-dispatch task via `iretq`.
    ///
    /// Calling convention (System V AMD64):
    /// - `from_rsp` (RDI): address of the outgoing task's `context.rsp` field.
    /// - `user_rip` (RSI), `user_rsp` (RDX), `user_rflags` (RCX),
    ///   `cr3_phys` (R8), `kernel_stack_top` (R9): the incoming task's iretq
    ///   parameters, identical to [`super::usermode::enter_user_mode`].
    ///
    /// "Returns" (normally, callee-saved registers preserved) only when the
    /// outgoing task is later resumed by a [`context_switch`].
    ///
    /// # Safety
    ///
    /// Same invariants as [`super::usermode::enter_user_mode`] for the incoming
    /// parameters, plus: `from_rsp` must point at the outgoing task's
    /// `context.rsp` (a valid `u64` in the kernel-half `SCHEDULER` static,
    /// mapped under both the outgoing and incoming CR3). Must be called with
    /// interrupts disabled, on a single CPU.
    #[link_name = "nexacore_save_and_enter_user_mode"]
    pub fn save_and_enter_user_mode(
        from_rsp: *mut u64,
        user_rip: u64,
        user_rsp: u64,
        user_rflags: u64,
        cr3_phys: u64,
        kernel_stack_top: u64,
    );
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".global nexacore_save_and_enter_user_mode",
    "nexacore_save_and_enter_user_mode:",
    // --- Save the OUTGOING task (same push order as nexacore_context_switch) ---
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov [rdi], rsp", // *from_rsp = outgoing kernel RSP (resume point)
    // --- Enter the INCOMING first-dispatch task (mirror of enter_user_mode) ---
    "    mov rsp, r9", // swap to incoming kernel stack BEFORE cr3 (MB13.f)
    "    mov cr3, r8", // switch to incoming address space
    "    push 0x1b",   // iretq frame: SS     = gdt::USER_SS (slot 3 | RPL 3)
    "    push rdx",    //             RSP    = user_stack_top
    "    push rcx",    //             RFLAGS = USER_RFLAGS
    "    push 0x23",   //             CS     = gdt::USER_CS (slot 4 | RPL 3)
    "    push rsi",    //             RIP    = user_entry
    "    iretq",
);

// ---------------------------------------------------------------------------
// Task entry trampoline (MB8)
// ---------------------------------------------------------------------------
//
// A freshly-spawned task whose first `context_switch` lands inside an
// Interrupt Gate handler (e.g. the LAPIC timer) would otherwise start with
// `IF = 0` and never be preempted again. The trampoline reopens the IF
// gate before transferring control to the real entry function.
//
// Calling convention: invoked via `ret` from `nexacore_context_switch`. The
// callee-saved registers and the real entry RIP are already on the stack
// in the layout produced by `setup_task_frame`. `sti` enables interrupts;
// `ret` then pops the real `entry` and jumps to it.
#[cfg(target_arch = "x86_64")]
global_asm!(
    ".global nexacore_task_entry_trampoline",
    "nexacore_task_entry_trampoline:",
    "    sti",
    "    ret",
);

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    /// Address-only handle to the asm trampoline; we never `call` it from
    /// Rust — `setup_task_frame` only takes its address and pushes it onto
    /// the new task's stack so `context_switch`'s `ret` lands inside it.
    #[link_name = "nexacore_task_entry_trampoline"]
    fn nexacore_task_entry_trampoline();
}

// ---------------------------------------------------------------------------
// Initial stack frame helper
// ---------------------------------------------------------------------------

/// Writes an initial stack frame for a newly-spawned task.
///
/// The first [`context_switch`] into it lands in the `nexacore_task_entry_trampoline`
/// (which enables interrupts) and then in the real `entry` function.
///
/// The frame writes 8 words downward from `stack_top`:
///
/// 1. `entry` — popped by the trampoline's `ret`, becomes the task's first RIP.
/// 2. `nexacore_task_entry_trampoline` address — popped by `context_switch`'s `ret`.
/// 3. Six zero-initialised callee-saved registers (RBP, RBX, R12, R13, R14, R15)
///    in the order `context_switch` pops them (words 3 through 8 of the frame).
///
/// Returns the initial RSP value to store in the task's `CpuContext`.
///
/// # Safety
///
/// `stack_top` must be the virtual address of the top (highest address) of a
/// valid, writable, exclusively-owned kernel stack of at least 64 bytes
/// (8 × 8 = the frame written here). In practice the caller allocates a full
/// 4 KiB frame so this is always satisfied.
#[cfg(target_arch = "x86_64")]
pub unsafe fn setup_task_frame(stack_top: u64, entry: u64) -> u64 {
    let trampoline_addr = nexacore_task_entry_trampoline as *const () as usize as u64;
    let mut sp = stack_top;
    unsafe {
        sp -= 8;
        // Popped by the trampoline's `ret`: becomes the task's real RIP.
        (sp as *mut u64).write(entry);
        sp -= 8;
        // Popped by `context_switch`'s `ret`: enters the trampoline.
        (sp as *mut u64).write(trampoline_addr);
        sp -= 8;
        (sp as *mut u64).write(0); // RBP = 0
        sp -= 8;
        (sp as *mut u64).write(0); // RBX = 0
        sp -= 8;
        (sp as *mut u64).write(0); // R12 = 0
        sp -= 8;
        (sp as *mut u64).write(0); // R13 = 0
        sp -= 8;
        (sp as *mut u64).write(0); // R14 = 0
        sp -= 8;
        (sp as *mut u64).write(0); // R15 = 0
    }
    sp
}
