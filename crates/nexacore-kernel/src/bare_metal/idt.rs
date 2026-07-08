//! Interrupt Descriptor Table (IDT) for `x86_64` long mode (Track B, MB3).
//!
//! Installs a comprehensive synchronous-exception IDT — every CPU vector
//! between 0 and 21 (the full set defined by Intel SDM Vol 3A §6.15 plus
//! AMD's #VC/#SX) is wired to a Rust handler that writes the vector and
//! optional error code to the early console before halting the CPU.
//!
//! ## Critical vectors with dedicated diagnostics
//!
//! | Vector | Mnemonic | Name               | Error code? | Notes |
//! |--------|----------|--------------------|-------------|-------|
//! | 0      | #DE      | Divide Error       | No          | dedicated handler |
//! | 8      | #DF      | Double Fault       | Yes (always 0) | dedicated handler |
//! | 13     | #GP      | General Protection | Yes         | dedicated handler |
//! | 14     | #PF      | Page Fault         | Yes         | dedicated handler — also prints CR2 |
//!
//! ## Catch-all vectors (MB13.g)
//!
//! All remaining synchronous vectors share two generic handlers
//! (`kernel_handle_exception_noerr` / `kernel_handle_exception_witherr`)
//! that record `vec=NN` followed by the [`ExceptionFrame`] — giving us
//! post-mortem visibility on previously-silent triple-faults (e.g., a
//! mis-built iretq frame faulting to #SS or #NP and cascading to #DF on
//! a missing IDT entry):
//!
//! | Vector | Mnemonic | Error code? |
//! |--------|----------|-------------|
//! | 1  | #DB  | No  |
//! | 2  | NMI  | No  |
//! | 3  | #BP  | No  |
//! | 4  | #OF  | No  |
//! | 5  | #BR  | No  |
//! | 6  | #UD  | No  |
//! | 7  | #NM  | No  |
//! | 10 | #TS  | Yes |
//! | 11 | #NP  | Yes |
//! | 12 | #SS  | Yes |
//! | 16 | #MF  | No  |
//! | 17 | #AC  | Yes |
//! | 18 | #MC  | No  |
//! | 19 | #XF  | No  |
//! | 20 | #VE  | No  |
//! | 21 | #CP  | Yes |
//!
//! The IDT is loaded with `lidt` but interrupts are NOT enabled with
//! `sti` in this release — the IDT only catches synchronous (fault/trap)
//! exceptions.
//!
//! ## Calling convention
//!
//! `x86_64` stable Rust does not expose `extern "x86-interrupt"` on the
//! stable channel (it is a nightly-only ABI). The handlers are therefore
//! implemented as `extern "C"` functions invoked from minimal `global_asm!`
//! stubs that set up the correct argument registers before the call.
//!
//! ## Pattern
//!
//! Follows the exact same pattern as [`super::gdt`] — a static descriptor
//! table, a pseudo-descriptor struct (`Idtr` / `Gdtr`), and an `_init()`
//! function that loads the table via a privileged instruction.

#![allow(
    unsafe_code,
    reason = "lidt + raw handler pointer construction; SAFETY per call site"
)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "IDT byte-size limit fits u16; vector indexing bounded by IDT_SIZE = 256"
)]

use super::early_console;

// -----------------------------------------------------------------------
// IDT entry (16 bytes in x86_64 long mode)
// -----------------------------------------------------------------------

/// A single `x86_64` IDT entry for a 64-bit interrupt gate.
///
/// Layout (all fields little-endian):
///
/// | Bytes  | Field         | Description                          |
/// |--------|---------------|--------------------------------------|
/// | 0–1    | offset_low    | Handler VA bits \[15:0\]               |
/// | 2–3    | selector      | Code segment selector (0x08)         |
/// | 4      | ist_and_zero  | IST index in bits \[2:0\]; rest zero   |
/// | 5      | type_and_attr | P=1, DPL=0, type=0xE (interrupt gate)|
/// | 6–7    | offset_mid    | Handler VA bits \[31:16\]              |
/// | 8–11   | offset_high   | Handler VA bits \[63:32\]              |
/// | 12–15  | _reserved     | Must be zero                         |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist_and_zero: u8,
    type_and_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

impl IdtEntry {
    /// Creates a not-present (all-zero) sentinel entry.
    ///
    /// Using `const fn` allows `[IdtEntry::missing(); 256]` in a static
    /// without requiring runtime initialization.
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist_and_zero: 0,
            type_and_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            _reserved: 0,
        }
    }

    /// Creates a 64-bit interrupt gate for `handler` using `selector`.
    ///
    /// - `type_and_attr` = `0x8E` (P=1, DPL=00, type=0xE = 64-bit interrupt gate)
    /// - IST index = 0 (no IST switching)
    #[must_use]
    pub fn interrupt_gate(handler: u64, selector: u16) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector,
            ist_and_zero: 0x00,
            type_and_attr: 0x8E, // P=1, DPL=0, type=0xE
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            _reserved: 0,
        }
    }

    /// MB13.h — like [`Self::interrupt_gate`] but routes the vector to
    /// `TSS.ist[ist_index]` instead of the normal `TSS.rsp0` slot.
    ///
    /// Only the low 3 bits of `ist_index` are honored (valid range
    /// 1..=7; value 0 disables IST switching and is equivalent to
    /// `interrupt_gate`). Used by `idt_init` to give #DF (IST=1) and
    /// #PF (IST=2) their own dedicated kernel stacks, so a stack-related
    /// fault cannot cascade to a silent triple fault.
    #[must_use]
    pub fn interrupt_gate_with_ist(handler: u64, selector: u16, ist_index: u8) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector,
            ist_and_zero: ist_index & 0x07,
            type_and_attr: 0x8E, // P=1, DPL=0, type=0xE
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            _reserved: 0,
        }
    }
}

// -----------------------------------------------------------------------
// Exception frame pushed by the CPU on the stack
// -----------------------------------------------------------------------

/// The interrupt/exception stack frame pushed by the CPU before calling
/// the handler stub. Fields ordered from lowest to highest stack address.
#[derive(Debug)]
#[repr(C)]
pub struct ExceptionFrame {
    /// Instruction pointer of the faulting instruction.
    pub rip: u64,
    /// Code segment selector at the time of the fault.
    pub cs: u64,
    /// RFLAGS at the time of the fault.
    pub rflags: u64,
    /// Stack pointer at the time of the fault.
    pub rsp: u64,
    /// Stack segment at the time of the fault.
    pub ss: u64,
}

// -----------------------------------------------------------------------
// IDTR pseudo-descriptor
// -----------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

// -----------------------------------------------------------------------
// Static IDT — 256 entries, all initially "missing"
// -----------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
static mut IDT: [IdtEntry; 256] = [IdtEntry::missing(); 256];

#[cfg(target_arch = "x86_64")]
const KERNEL_CS: u16 = 0x08;

// -----------------------------------------------------------------------
// ISR assembly stubs (x86_64 only, Intel syntax)
// -----------------------------------------------------------------------
//
// Each stub aligns the stack (System V AMD64 ABI §3.2.2) before calling
// the extern "C" Rust handler. Exceptions without an error code have 5
// items on the stack (40 bytes; 8 mod 16 from a 16-aligned interrupt);
// we add 8 bytes of padding to restore 0 mod 16 alignment before `call`.
// Exceptions with an error code have 6 items (48 bytes; 0 mod 16), so
// we pop the error code into RSI (2nd arg) and add 8 bytes of padding.
//
// Stubs end with `ud2` (undefined instruction) — the Rust handlers call
// `halt_forever()` and never return, so this is a safety net.
//
// Notes on `lea rdi, [rsp+8]`:  after `sub rsp, 8`, RSP points to the
// 8-byte alignment pad; the ExceptionFrame starts 8 bytes above at RSP+8.

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    // ---- #DE: Divide Error — no error code ----
    ".global isr_de",
    "isr_de:",
    "    sub rsp, 8",
    "    lea rdi, [rsp + 8]",
    "    call kernel_handle_de",
    "    ud2",
    // ---- #DF: Double Fault — error code (always 0) ----
    ".global isr_df",
    "isr_df:",
    "    pop rsi",
    "    sub rsp, 8",
    "    lea rdi, [rsp + 8]",
    "    call kernel_handle_df",
    "    ud2",
    // ---- #GP: General Protection Fault — error code ----
    ".global isr_gp",
    "isr_gp:",
    "    pop rsi",
    "    sub rsp, 8",
    "    lea rdi, [rsp + 8]",
    "    call kernel_handle_gp",
    "    ud2",
    // ---- #PF: Page Fault — error code ----
    ".global isr_pf",
    "isr_pf:",
    "    pop rsi",
    "    sub rsp, 8",
    "    lea rdi, [rsp + 8]",
    "    call kernel_handle_pf",
    "    ud2",
    // ============================================================
    // MB13.g — catch-all stubs for the remaining synchronous CPU
    // exception vectors. Each stub loads the vector number into RDI,
    // the ExceptionFrame pointer into RSI, and (for the error-code
    // variants) the CPU-pushed error code into RDX, then calls into a
    // generic Rust handler.
    //
    // No-error-code variant alignment math: on entry the CPU has
    // pushed SS:RSP:RFLAGS:CS:RIP (40 bytes; 8 mod 16 from a 16-byte
    // aligned interrupt boundary). `sub rsp, 8` restores 16-byte
    // alignment before the C-ABI `call`.
    //
    // Error-code variant alignment math: 48 bytes pushed (0 mod 16);
    // `pop rdx` removes the error code (40 bytes left; 8 mod 16);
    // `sub rsp, 8` then restores 16-byte alignment.
    // ============================================================

    // ---- #DB (1): Debug — no error code ----
    ".global isr_db",
    "isr_db:",
    "    sub rsp, 8",
    "    mov rdi, 1",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- NMI (2): Non-Maskable Interrupt — no error code ----
    ".global isr_nmi",
    "isr_nmi:",
    "    sub rsp, 8",
    "    mov rdi, 2",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #BP (3): Breakpoint — no error code ----
    ".global isr_bp",
    "isr_bp:",
    "    sub rsp, 8",
    "    mov rdi, 3",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #OF (4): Overflow — no error code ----
    ".global isr_of",
    "isr_of:",
    "    sub rsp, 8",
    "    mov rdi, 4",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #BR (5): BOUND Range Exceeded — no error code ----
    ".global isr_br",
    "isr_br:",
    "    sub rsp, 8",
    "    mov rdi, 5",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #UD (6): Invalid Opcode — no error code ----
    ".global isr_ud",
    "isr_ud:",
    "    sub rsp, 8",
    "    mov rdi, 6",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #NM (7): Device Not Available — no error code ----
    ".global isr_nm",
    "isr_nm:",
    "    sub rsp, 8",
    "    mov rdi, 7",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #TS (10): Invalid TSS — error code ----
    ".global isr_ts",
    "isr_ts:",
    "    pop rdx",
    "    sub rsp, 8",
    "    mov rdi, 10",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_witherr",
    "    ud2",
    // ---- #NP (11): Segment Not Present — error code ----
    ".global isr_np",
    "isr_np:",
    "    pop rdx",
    "    sub rsp, 8",
    "    mov rdi, 11",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_witherr",
    "    ud2",
    // ---- #SS (12): Stack-Segment Fault — error code ----
    ".global isr_ss",
    "isr_ss:",
    "    pop rdx",
    "    sub rsp, 8",
    "    mov rdi, 12",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_witherr",
    "    ud2",
    // ---- #MF (16): x87 FPU Floating-Point Error — no error code ----
    ".global isr_mf",
    "isr_mf:",
    "    sub rsp, 8",
    "    mov rdi, 16",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #AC (17): Alignment Check — error code ----
    ".global isr_ac",
    "isr_ac:",
    "    pop rdx",
    "    sub rsp, 8",
    "    mov rdi, 17",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_witherr",
    "    ud2",
    // ---- #MC (18): Machine Check — no error code ----
    ".global isr_mc",
    "isr_mc:",
    "    sub rsp, 8",
    "    mov rdi, 18",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #XF (19): SIMD FP Exception — no error code ----
    ".global isr_xf",
    "isr_xf:",
    "    sub rsp, 8",
    "    mov rdi, 19",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #VE (20): Virtualization Exception — no error code ----
    ".global isr_ve",
    "isr_ve:",
    "    sub rsp, 8",
    "    mov rdi, 20",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_noerr",
    "    ud2",
    // ---- #CP (21): Control Protection Exception — error code ----
    ".global isr_cp",
    "isr_cp:",
    "    pop rdx",
    "    sub rsp, 8",
    "    mov rdi, 21",
    "    lea rsi, [rsp + 8]",
    "    call kernel_handle_exception_witherr",
    "    ud2",
);

// Extern declarations so that Rust can take the address of each stub.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn isr_de();
    fn isr_df();
    fn isr_gp();
    fn isr_pf();
    fn isr_db();
    fn isr_nmi();
    fn isr_bp();
    fn isr_of();
    fn isr_br();
    fn isr_ud();
    fn isr_nm();
    fn isr_ts();
    fn isr_np();
    fn isr_ss();
    fn isr_mf();
    fn isr_ac();
    fn isr_mc();
    fn isr_xf();
    fn isr_ve();
    fn isr_cp();
}

// -----------------------------------------------------------------------
// Exception handlers (extern "C" so stubs can call them)
// -----------------------------------------------------------------------

#[unsafe(no_mangle)]
extern "C" fn kernel_handle_de(frame: *const ExceptionFrame) {
    // Fatal, never returns: break a possibly-held console lock so the
    // dump below cannot deadlock (ADR-0023 § 4).
    early_console::begin_fatal_dump();
    early_console::write_str("\n[NexaCore OS EXCEPTION] #DE Divide Error\n");
    log_frame(frame);
    super::arch::halt_forever()
}

#[unsafe(no_mangle)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "error code fits usize on any supported target"
)]
extern "C" fn kernel_handle_df(frame: *const ExceptionFrame, error_code: u64) {
    // Fatal, never returns — see kernel_handle_de (ADR-0023 § 4).
    early_console::begin_fatal_dump();
    early_console::write_str("\n[NexaCore OS EXCEPTION] #DF Double Fault  code=");
    early_console::write_usize(error_code as usize);
    early_console::write_str("\n");
    log_frame(frame);
    super::arch::halt_forever()
}

#[unsafe(no_mangle)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "error code fits usize on any supported target"
)]
extern "C" fn kernel_handle_gp(frame: *const ExceptionFrame, error_code: u64) {
    // Fatal, never returns — see kernel_handle_de (ADR-0023 § 4).
    early_console::begin_fatal_dump();
    early_console::write_str("\n[NexaCore OS EXCEPTION] #GP General Protection  code=");
    early_console::write_usize(error_code as usize);
    early_console::write_str("\n");
    log_frame(frame);
    super::arch::halt_forever()
}

#[unsafe(no_mangle)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "error code fits usize on any supported target"
)]
extern "C" fn kernel_handle_pf(frame: *const ExceptionFrame, error_code: u64) {
    // Snapshot CR2 (faulting linear address) before anything else can
    // touch it — `early_console::write_*` are pure I/O, but be defensive.
    let cr2 = super::arch::read_cr2();
    // Fatal, never returns — see kernel_handle_de (ADR-0023 § 4).
    early_console::begin_fatal_dump();
    early_console::write_str("\n[NexaCore OS EXCEPTION] #PF Page Fault  code=");
    early_console::write_usize(error_code as usize);
    early_console::write_str("  cr2=");
    early_console::write_usize(cr2 as usize);
    early_console::write_str("\n");
    log_frame(frame);
    super::arch::halt_forever()
}

/// Generic catch-all for synchronous exceptions without a CPU-pushed
/// error code (MB13.g). The vector number is supplied by the assembly
/// stub so the same Rust function serves every no-error-code vector.
#[unsafe(no_mangle)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "vector number fits usize trivially"
)]
extern "C" fn kernel_handle_exception_noerr(vector: u64, frame: *const ExceptionFrame) {
    // Fatal, never returns — see kernel_handle_de (ADR-0023 § 4).
    early_console::begin_fatal_dump();
    early_console::write_str("\n[NexaCore OS EXCEPTION] vec=");
    early_console::write_usize(vector as usize);
    early_console::write_str("  (no error code)\n");
    log_frame(frame);
    super::arch::halt_forever()
}

/// Generic catch-all for synchronous exceptions that do push a CPU
/// error code (MB13.g). For #PF the dedicated [`kernel_handle_pf`]
/// is preferred because it also dumps `CR2`.
#[unsafe(no_mangle)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "vector number and error code fit usize trivially"
)]
extern "C" fn kernel_handle_exception_witherr(
    vector: u64,
    frame: *const ExceptionFrame,
    error_code: u64,
) {
    // Fatal, never returns — see kernel_handle_de (ADR-0023 § 4).
    early_console::begin_fatal_dump();
    early_console::write_str("\n[NexaCore OS EXCEPTION] vec=");
    early_console::write_usize(vector as usize);
    early_console::write_str("  code=");
    early_console::write_usize(error_code as usize);
    early_console::write_str("\n");
    log_frame(frame);
    super::arch::halt_forever()
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "register values fit usize on x86_64"
)]
fn log_frame(frame: *const ExceptionFrame) {
    if frame.is_null() {
        return;
    }
    // SAFETY: the stub guarantees the pointer is valid — it points to
    // the CPU-pushed exception frame on the kernel stack.
    let f = unsafe { &*frame };
    early_console::write_str("  rip=");
    early_console::write_usize(f.rip as usize);
    early_console::write_str("  cs=");
    early_console::write_usize(f.cs as usize);
    early_console::write_str("  rflags=");
    early_console::write_usize(f.rflags as usize);
    // RSP + SS are the CPU-pushed stack pointer/segment at fault time. For a
    // Ring 3 (user) fault these pinpoint a bad user stack — e.g. a task
    // dispatched with a near-null RSP — which rip/cr2 alone cannot distinguish
    // from a wild store. Always present in the long-mode interrupt frame.
    early_console::write_str("  rsp=");
    early_console::write_usize(f.rsp as usize);
    early_console::write_str("  ss=");
    early_console::write_usize(f.ss as usize);
    early_console::write_str("\n");
}

// -----------------------------------------------------------------------
// idt_init — loads the IDT via `lidt`
// -----------------------------------------------------------------------

/// Installs the kernel IDT and loads it with `lidt`.
///
/// Must be called from `kmain` after [`super::gdt::gdt_init`]. Does NOT
/// issue `sti` — interrupts remain disabled; only synchronous (fault)
/// exceptions are handled.
///
/// # Vectors installed
///
/// Vectors 0/8/13/14 have dedicated handlers that emit a mnemonic and
/// (for #PF) the faulting CR2. All other synchronous CPU vectors in
/// 1..=21 share two generic handlers that record `vec=NN` plus the
/// optional error code, so a previously-silent triple-fault becomes a
/// loggable single fault (MB13.g).
#[cfg(target_arch = "x86_64")]
pub fn idt_init() {
    use core::arch::asm;

    // SAFETY: single-core bare-metal; IDT is not aliased by any other
    // code path at this point in initialisation.
    let idt = unsafe { &mut *core::ptr::addr_of_mut!(IDT) };

    // Dedicated diagnostics handlers. MB13.h routes #DF to IST1 and
    // #PF to IST2 so a stack-related fault has a known-good kernel
    // stack to land on, eliminating the silent triple-fault cascade.
    idt[0] = IdtEntry::interrupt_gate(isr_de as *const () as usize as u64, KERNEL_CS);
    idt[8] = IdtEntry::interrupt_gate_with_ist(isr_df as *const () as usize as u64, KERNEL_CS, 1);
    idt[13] = IdtEntry::interrupt_gate(isr_gp as *const () as usize as u64, KERNEL_CS);
    idt[14] = IdtEntry::interrupt_gate_with_ist(isr_pf as *const () as usize as u64, KERNEL_CS, 2);

    // MB13.g catch-all coverage for the remaining synchronous vectors.
    idt[1] = IdtEntry::interrupt_gate(isr_db as *const () as usize as u64, KERNEL_CS);
    idt[2] = IdtEntry::interrupt_gate(isr_nmi as *const () as usize as u64, KERNEL_CS);
    idt[3] = IdtEntry::interrupt_gate(isr_bp as *const () as usize as u64, KERNEL_CS);
    idt[4] = IdtEntry::interrupt_gate(isr_of as *const () as usize as u64, KERNEL_CS);
    idt[5] = IdtEntry::interrupt_gate(isr_br as *const () as usize as u64, KERNEL_CS);
    idt[6] = IdtEntry::interrupt_gate(isr_ud as *const () as usize as u64, KERNEL_CS);
    idt[7] = IdtEntry::interrupt_gate(isr_nm as *const () as usize as u64, KERNEL_CS);
    idt[10] = IdtEntry::interrupt_gate(isr_ts as *const () as usize as u64, KERNEL_CS);
    idt[11] = IdtEntry::interrupt_gate(isr_np as *const () as usize as u64, KERNEL_CS);
    idt[12] = IdtEntry::interrupt_gate(isr_ss as *const () as usize as u64, KERNEL_CS);
    idt[16] = IdtEntry::interrupt_gate(isr_mf as *const () as usize as u64, KERNEL_CS);
    idt[17] = IdtEntry::interrupt_gate(isr_ac as *const () as usize as u64, KERNEL_CS);
    idt[18] = IdtEntry::interrupt_gate(isr_mc as *const () as usize as u64, KERNEL_CS);
    idt[19] = IdtEntry::interrupt_gate(isr_xf as *const () as usize as u64, KERNEL_CS);
    idt[20] = IdtEntry::interrupt_gate(isr_ve as *const () as usize as u64, KERNEL_CS);
    idt[21] = IdtEntry::interrupt_gate(isr_cp as *const () as usize as u64, KERNEL_CS);

    // MB14.d — TLB shootdown IPI handler (vector 0xFD). The asm stub
    // saves caller-saved registers, calls
    // `kernel_tlb_shootdown_handler`, restores them, `iretq`. Installed
    // pre-AP-fire so every AP that hits its `lidt` step in
    // `kmain_ap` sees the handler at the same offset.
    idt[usize::from(super::tlb_shootdown::TLB_SHOOTDOWN_VECTOR)] = IdtEntry::interrupt_gate(
        super::tlb_shootdown::nexacore_tlb_shootdown_handler as *const () as usize as u64,
        KERNEL_CS,
    );

    let idtr = Idtr {
        limit: (core::mem::size_of_val(idt) - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };

    // SAFETY: Ring-0 bare-metal. `lidt` is a privileged but otherwise
    // side-effect-free instruction that installs the IDT. The table we
    // pass is valid for 64-bit long mode (256 × 16-byte interrupt gates).
    unsafe {
        asm!(
            "lidt [{idtr}]",
            idtr = in(reg) core::ptr::addr_of!(idtr) as u64,
            options(nostack, preserves_flags),
        );
    }
}

/// No-op stub for non-x86_64 hosts (developer machines on ARM, etc.).
#[cfg(not(target_arch = "x86_64"))]
pub fn idt_init() {}

// -----------------------------------------------------------------------
// idt_set_vector — install a single interrupt gate after idt_init
// -----------------------------------------------------------------------

/// Installs a single 64-bit interrupt gate at `vector` in the IDT.
///
/// Can be called after [`idt_init`] to register additional vectors. Used
/// by `syscall_entry::syscall_init` to register the `INT 0x80` fallback.
#[cfg(target_arch = "x86_64")]
pub fn idt_set_vector(vector: usize, handler: u64) {
    // SAFETY: single-core bare-metal; IDT is not aliased elsewhere.
    let idt = unsafe { &mut *core::ptr::addr_of_mut!(IDT) };
    idt[vector] = IdtEntry::interrupt_gate(handler, KERNEL_CS);
}

/// No-op stub for non-x86_64 host builds.
#[cfg(not(target_arch = "x86_64"))]
pub fn idt_set_vector(_vector: usize, _handler: u64) {}

// =====================================================================
// MB14.c.2.d — exposed (base, limit) of the kernel IDT so the AP entry
// asm can re-issue `lidt` after the CR3 switch without rebuilding the
// pseudo-descriptor itself.
// =====================================================================

/// Returns the (base, limit) values the BSP loaded into the IDTR during
/// [`idt_init`]. The limit equals `sizeof(IDT) - 1 = 256 * 16 - 1 = 4095`.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn idt_base_and_limit() -> (u64, u16) {
    let base = core::ptr::addr_of!(IDT) as u64;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "256 × 16 - 1 = 4095, fits u16 trivially"
    )]
    let limit = (256 * core::mem::size_of::<IdtEntry>() - 1) as u16;
    (base, limit)
}

/// Host stub returning (0, 0) — non-x86_64 hosts cannot install an IDT.
#[cfg(not(target_arch = "x86_64"))]
#[must_use]
pub fn idt_base_and_limit() -> (u64, u16) {
    (0, 4095)
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_entry_is_all_zero() {
        let e = IdtEntry::missing();
        assert_eq!(e.offset_low, 0);
        assert_eq!(e.selector, 0);
        assert_eq!(e.ist_and_zero, 0);
        assert_eq!(e.type_and_attr, 0);
        assert_eq!(e.offset_mid, 0);
        assert_eq!(e.offset_high, 0);
        #[allow(
            clippy::used_underscore_binding,
            reason = "_reserved is the literal field name in the x86_64 SDM IDT layout"
        )]
        let r = e._reserved;
        assert_eq!(r, 0);
    }

    #[test]
    fn interrupt_gate_size_is_16_bytes() {
        assert_eq!(core::mem::size_of::<IdtEntry>(), 16);
    }

    #[test]
    fn interrupt_gate_sets_selector_and_type() {
        let entry = IdtEntry::interrupt_gate(0, 0x08);
        assert_eq!(entry.selector, 0x08);
        assert_eq!(entry.type_and_attr, 0x8E);
        assert_eq!(entry.ist_and_zero, 0x00);
        #[allow(
            clippy::used_underscore_binding,
            reason = "_reserved is the literal field name in the x86_64 SDM IDT layout"
        )]
        let r = entry._reserved;
        assert_eq!(r, 0);
    }

    #[test]
    fn interrupt_gate_encodes_low_handler_bits() {
        let handler: u64 = 0xABCD_EF12_3456_7890;
        let entry = IdtEntry::interrupt_gate(handler, 0x08);
        // bits [15:0]  = 0x7890, bits [31:16] = 0x3456, bits [63:32] = 0xABCD_EF12
        assert_eq!(entry.offset_low, 0x7890u16);
        assert_eq!(entry.offset_mid, 0x3456u16);
        assert_eq!(entry.offset_high, 0xABCD_EF12u32);
    }

    #[test]
    fn interrupt_gate_reconstructs_full_address() {
        let handler: u64 = 0x0000_CAFE_BABE_BEEF;
        let entry = IdtEntry::interrupt_gate(handler, 0x08);
        let recovered = u64::from(entry.offset_low)
            | (u64::from(entry.offset_mid) << 16)
            | (u64::from(entry.offset_high) << 32);
        assert_eq!(recovered, handler);
    }

    #[test]
    fn idt_array_size() {
        assert_eq!(core::mem::size_of::<[IdtEntry; 256]>(), 256 * 16);
    }

    #[test]
    fn exception_frame_size() {
        // 5 × u64 = 40 bytes.
        assert_eq!(core::mem::size_of::<ExceptionFrame>(), 40);
    }

    /// MB13.h — `interrupt_gate_with_ist` encodes the IST index in the
    /// low 3 bits of byte 4 and leaves the type/attr byte untouched.
    #[test]
    fn interrupt_gate_with_ist_sets_index() {
        let entry = IdtEntry::interrupt_gate_with_ist(0xCAFE_F00D, 0x08, 1);
        assert_eq!(entry.ist_and_zero, 0x01);
        assert_eq!(entry.type_and_attr, 0x8E);
        assert_eq!(entry.selector, 0x08);

        let entry2 = IdtEntry::interrupt_gate_with_ist(0xCAFE_F00D, 0x08, 2);
        assert_eq!(entry2.ist_and_zero, 0x02);
    }

    /// MB13.h — the helper masks the IST index to the low 3 bits so any
    /// future caller passing a too-large value does not corrupt the
    /// reserved bits 3..7 of the IST byte.
    #[test]
    fn interrupt_gate_with_ist_masks_high_bits() {
        let entry = IdtEntry::interrupt_gate_with_ist(0, 0x08, 0xFF);
        assert_eq!(entry.ist_and_zero, 0x07);
    }

    /// MB13.g — every CPU synchronous vector in 0..=21 must be covered
    /// by an IDT entry. Vectors 9 and 15 are architecturally reserved
    /// and intentionally left as `missing()` sentinels.
    #[test]
    fn mb13g_synchronous_vectors_covered() {
        const COVERED: &[usize] = &[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21,
        ];
        const RESERVED: &[usize] = &[9, 15];
        assert_eq!(COVERED.len(), 20);
        assert_eq!(RESERVED.len(), 2);
        // Reserved must not overlap with covered.
        for &r in RESERVED {
            assert!(
                !COVERED.contains(&r),
                "reserved vector {r} appears in covered list"
            );
        }
        // Covered list is monotonically increasing.
        for w in COVERED.windows(2) {
            assert!(w[0] < w[1]);
        }
    }
}
