//! MB14.c.2.c — Application Processor landing stub + higher-half entry.
//!
//! ## MB14.c.2.d additions
//!
//! The `cli; hlt; jmp $-2` body of `kmain_ap` is replaced with a real
//! per-CPU initialisation sequence (read LAPIC ID via `cpuid`, load
//! per-AP RSP, wire `GS_BASE` / `KERNEL_GS_BASE` to the AP slot, `lgdt`
//! / `lidt` / `ltr` against the BSP's kernel descriptor tables, reload
//! data segments, then park `cli; hlt`). The BSP populates a runtime
//! control block (`AP_RUNTIME_CONTROL`) pre-fire that tells each AP
//! exactly which per-CPU slot, stack top, and TSS selector to use.
//!
//! Companion to [`mp_trampoline`](super::mp_trampoline) /
//! [`mp_emplacement`](super::mp_emplacement). The trampoline brings each AP
//! from 16-bit real mode to 64-bit long mode and jumps to a caller-supplied
//! `kernel_ap_entry`. MB14.c.2.c routes that jump through a small low-memory
//! landing stub that:
//!
//! 1. Atomically increments an ack counter mapped in the temp paging window.
//! 2. Loads the BSP's kernel `CR3` (the active kernel address space).
//! 3. Switches `CR3` to the kernel address space.
//! 4. Jumps to a higher-half [`kmain_ap`] entry point with the kernel
//!    address space active.
//!
//! Step 2 reads `CR3` and the [`kmain_ap`] VA from per-call slots emplaced
//! by the BSP at well-known offsets inside the trampoline page (`0x8148`
//! and `0x8150`). Both reads happen **before** the `mov cr3, rax`, so the
//! values reach a register while the temp PML4 still identity-maps the
//! trampoline page. After the switch, the next instruction (`jmp rcx`) is
//! still fetched from `RIP` ≈ `0x813X` because the BSP's kernel address
//! space also identity-maps the trampoline page (the c.2.b.2 emplacement
//! installs that mapping defensively for exactly this reason).
//!
//! [`kmain_ap`] is a `#[naked]` `extern "C"` function: no prologue,
//! no stack accesses. The AP arrives with no stack and the trampoline never
//! sets `RSP`; the `cli; hlt; jmp $-2` body is stack-free by construction.
//! Per-AP stack allocation lands in MB14.c.2.d together with the per-AP
//! `PerCpu` wiring.
//!
//! ## Layout inside the trampoline page (phys `0x0000_8000`)
//!
//! | Offset    | Size  | Content                                           |
//! |----------:|------:|---------------------------------------------------|
//! | `0x000`   | 256 B | Trampoline blob (see [`super::mp_trampoline`])    |
//! | `0x100`   | 32 B  | AP landing stub (this module)                     |
//! | `0x140`   | 8  B  | `AP_ACK_COUNTER` — `AtomicU64`, BSP reads it      |
//! | `0x148`   | 8  B  | `AP_KERNEL_CR3` — BSP writes pre-fire             |
//! | `0x150`   | 8  B  | `AP_KMAIN_AP_VA` — BSP writes pre-fire            |
//!
//! ## References
//!
//! - Intel SDM Vol 2 — `MOV CRn`, `JMP r/m64`, `LOCK ADD` opcodes
//! - Intel SDM Vol 3A § 4.10 — TLB invalidation on `MOV CR3`
//! - Intel SDM Vol 3A § 8.4   — MP Initialization Protocol

#![allow(
    unsafe_code,
    reason = "naked AP entry + raw landing-stub byte writer; both are MB14.c.2.c primitives"
)]
#![allow(
    clippy::cast_possible_truncation,
    reason = "every `as u8` extracts a single byte from a wider integer that has been explicitly bit-shifted to isolate it"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "every stub index is a compile-time constant within AP_LANDING_STUB_SIZE"
)]

// =====================================================================
// Layout constants — offsets relative to the trampoline page base.
// =====================================================================

/// Offset of the AP landing stub within the trampoline page.
///
/// The trampoline blob occupies `0x000..0x100` (see
/// [`mp_trampoline::TRAMPOLINE_BLOB_SIZE`]); the landing stub sits in the
/// next aligned slot so the two never overlap.
///
/// [`mp_trampoline::TRAMPOLINE_BLOB_SIZE`]: super::mp_trampoline::TRAMPOLINE_BLOB_SIZE
pub const AP_LANDING_STUB_OFFSET: usize = 0x100;

/// Length of the AP landing stub in bytes.
///
/// 32 bytes is enough for the four-instruction sequence emitted by
/// [`build_ap_landing_stub`] (`lock inc` + two `mov r64, [mem]` + `mov cr3`
/// + `jmp r/m64`). The trailing bytes are zero-padded.
pub const AP_LANDING_STUB_SIZE: usize = 32;

/// Offset of the `AP_ACK_COUNTER` slot (8-byte, little-endian) within the
/// trampoline page. The BSP zeroes this before firing INIT-SIPI; each AP
/// `lock inc`s it once before switching `CR3`.
pub const AP_ACK_COUNTER_OFFSET: usize = 0x140;

/// Offset of the `AP_KERNEL_CR3` slot (8-byte, little-endian) within the
/// trampoline page. Holds the physical address the AP will load into
/// `CR3` to enter the kernel address space.
pub const AP_KERNEL_CR3_OFFSET: usize = 0x148;

/// Offset of the `AP_KMAIN_AP_VA` slot (8-byte, little-endian) within the
/// trampoline page. Holds the virtual address of [`kmain_ap`] in the
/// higher-half kernel mapping.
pub const AP_KMAIN_AP_VA_OFFSET: usize = 0x150;

// =====================================================================
// Pure-function landing-stub builder.
// =====================================================================

/// Build the 32-byte AP landing stub.
///
/// `tramp_base_paddr` is the physical address of the trampoline page
/// (always [`super::mp_emplacement::TRAMPOLINE_PHYS_BASE`] = `0x0000_8000`
/// in MB14.c.2.c). The four slot addresses are derived from it.
///
/// The stub is **position-dependent**: the absolute addresses of the
/// `AP_ACK_COUNTER`, `AP_KERNEL_CR3`, and `AP_KMAIN_AP_VA` slots are
/// embedded as 32-bit displacements in `mov r64, [mem32]` instructions
/// (with REX.W + 0xA1 / 0x8B opcodes — see below). Slots must therefore
/// fit in 32 bits, which holds for any low-memory trampoline placement.
///
/// ## Instruction sequence
///
/// ```text
///   F0 48 FF 04 25 <ack32>     ; lock inc qword ptr [ack32]
///   48 8B 0C 25 <cr3_32>       ; mov rcx, [cr3_32]      (kernel CR3)
///   48 8B 14 25 <vaslot32>     ; mov rdx, [vaslot32]    (kmain_ap VA)
///   0F 22 D9                   ; mov cr3, rcx           (switch AS)
///   FF E2                      ; jmp rdx                (enter kmain_ap)
/// ```
///
/// The sequence has been picked so that **both** runtime slots reach a
/// register **before** the `mov cr3` clobbers the address space. After
/// the switch the next byte fetched is the `jmp rdx` opcode at
/// `tramp_base + 0x11D`, which the BSP's kernel CR3 must also map (the
/// c.2.b.2 emplacement identity-maps the trampoline page in active CR3
/// for exactly this reason).
#[must_use]
pub fn build_ap_landing_stub(tramp_base_paddr: u32) -> [u8; AP_LANDING_STUB_SIZE] {
    let mut s = [0u8; AP_LANDING_STUB_SIZE];

    let ack_paddr = tramp_base_paddr.wrapping_add(AP_ACK_COUNTER_OFFSET as u32);
    let cr3_paddr = tramp_base_paddr.wrapping_add(AP_KERNEL_CR3_OFFSET as u32);
    let va_paddr = tramp_base_paddr.wrapping_add(AP_KMAIN_AP_VA_OFFSET as u32);

    // -----------------------------------------------------------------
    // 0x00  F0 48 FF 04 25 <imm32>   lock inc qword ptr [imm32]
    //   F0      = LOCK prefix
    //   48      = REX.W (64-bit operand)
    //   FF /0   = INC r/m64; ModR/M 04 = mod=00 reg=0 (/0=INC) rm=100 (SIB)
    //   25      = SIB scale=00 index=100 (none) base=101 (disp32 absolute)
    //   imm32   = absolute physical address of AP_ACK_COUNTER slot
    // -----------------------------------------------------------------
    s[0x00] = 0xF0;
    s[0x01] = 0x48;
    s[0x02] = 0xFF;
    s[0x03] = 0x04;
    s[0x04] = 0x25;
    s[0x05] = ack_paddr as u8;
    s[0x06] = (ack_paddr >> 8) as u8;
    s[0x07] = (ack_paddr >> 16) as u8;
    s[0x08] = (ack_paddr >> 24) as u8;

    // -----------------------------------------------------------------
    // 0x09  48 8B 0C 25 <imm32>   mov rcx, [imm32]
    //   48      = REX.W
    //   8B      = MOV r64, r/m64
    //   0C      = ModR/M mod=00 reg=001 (RCX) rm=100 (SIB)
    //   25      = SIB scale=00 index=100 (none) base=101 (disp32 absolute)
    //   imm32   = absolute physical address of AP_KERNEL_CR3 slot
    // -----------------------------------------------------------------
    s[0x09] = 0x48;
    s[0x0A] = 0x8B;
    s[0x0B] = 0x0C;
    s[0x0C] = 0x25;
    s[0x0D] = cr3_paddr as u8;
    s[0x0E] = (cr3_paddr >> 8) as u8;
    s[0x0F] = (cr3_paddr >> 16) as u8;
    s[0x10] = (cr3_paddr >> 24) as u8;

    // -----------------------------------------------------------------
    // 0x11  48 8B 14 25 <imm32>   mov rdx, [imm32]
    //   14 = ModR/M reg=010 (RDX) rm=100 (SIB) — same SIB byte.
    // -----------------------------------------------------------------
    s[0x11] = 0x48;
    s[0x12] = 0x8B;
    s[0x13] = 0x14;
    s[0x14] = 0x25;
    s[0x15] = va_paddr as u8;
    s[0x16] = (va_paddr >> 8) as u8;
    s[0x17] = (va_paddr >> 16) as u8;
    s[0x18] = (va_paddr >> 24) as u8;

    // -----------------------------------------------------------------
    // 0x19  0F 22 D9   mov cr3, rcx
    //   0F 22  = MOV CR, r64 family
    //   D9     = ModR/M mod=11 reg=011 (CR3) rm=001 (RCX)
    // -----------------------------------------------------------------
    s[0x19] = 0x0F;
    s[0x1A] = 0x22;
    s[0x1B] = 0xD9;

    // -----------------------------------------------------------------
    // 0x1C  FF E2   jmp rdx
    //   FF /4  = JMP r/m64; ModR/M E2 = mod=11 reg=100 (/4) rm=010 (RDX)
    // -----------------------------------------------------------------
    s[0x1C] = 0xFF;
    s[0x1D] = 0xE2;

    // 0x1E..0x20 zero padding (NOPs would be equivalent; the AP never
    // executes past `jmp rdx`).
    s
}

// =====================================================================
// MB14.c.2.d — AP runtime control block + per-AP allocation helpers.
// =====================================================================

use super::mp::MAX_CPUS;
use crate::memory::BitmapFrameAllocator;

/// `lgdt` / `lidt` pseudo-descriptor: 16-bit limit + 64-bit base, packed
/// (no padding between fields). 10 bytes total.
///
/// This is the on-the-wire format the `LGDT`/`LIDT` instructions read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
pub struct PseudoDescriptor {
    /// Byte-size of the table minus 1.
    pub limit: u16,
    /// Linear address of the table.
    pub base: u64,
}

impl PseudoDescriptor {
    /// Construct a zeroed pseudo-descriptor (suitable for a `static`).
    #[must_use]
    pub const fn zero() -> Self {
        Self { limit: 0, base: 0 }
    }
}

// Offset constants — hardcoded into the AP-entry asm. A divergence
// between these and the actual `ApRuntimeControl` layout would only
// surface as a triple-fault on a real AP, so we pin both via host-side
// tests below (`ap_runtime_control_*_at_offset_*`).
//
// `dead_code` allow: these constants are referenced via `const`
// operands inside the `kmain_ap` `global_asm!` block (gated to bare-metal
// `target_os = "none"`). Host clippy builds skip the asm and therefore
// see the constants as unused.
#[allow(
    dead_code,
    reason = "consumed by the bare-metal kmain_ap asm const-operands; host-side build skips the asm but the consts pin the layout for unit tests"
)]
const OFFSET_GDTR: usize = 0x00;
#[allow(
    dead_code,
    reason = "consumed by the bare-metal kmain_ap asm const-operands"
)]
const OFFSET_IDTR: usize = 0x10;
#[allow(
    dead_code,
    reason = "consumed by the bare-metal kmain_ap asm const-operands"
)]
const OFFSET_LAPIC_TO_CPU: usize = 0x20;
#[allow(
    dead_code,
    reason = "consumed by the bare-metal kmain_ap asm const-operands"
)]
const OFFSET_KSTACK_TOP: usize = 0xA0;
#[allow(
    dead_code,
    reason = "consumed by the bare-metal kmain_ap asm const-operands"
)]
const OFFSET_PER_CPU_PTR: usize = 0x1A0;
#[allow(
    dead_code,
    reason = "consumed by the bare-metal kmain_ap asm const-operands"
)]
const OFFSET_TSS_SEL: usize = 0x2A0;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "pinned by the `ap_runtime_control_total_size_matches_asm_constant` host-side test; the asm references field offsets, not the total size"
    )
)]
const AP_RUNTIME_CONTROL_SIZE: usize = 0x2E0;

/// MB14.c.2.d — BSP-populated runtime control block read by every AP
/// during its post-trampoline initialisation.
///
/// Layout is locked at offset granularity so the [`kmain_ap`] asm can
/// reach individual fields via constant displacements; see the
/// `OFFSET_*` constants above.
///
/// All slots are indexed by **kernel-local `cpu_id`** (BSP = 0, AP k = k).
/// Slot 0 entries describe the BSP and are written for completeness
/// (BSP-side debugging / future code) but never read by an AP.
#[repr(C, align(16))]
pub struct ApRuntimeControl {
    /// GDTR pseudo-descriptor (offset 0x00). `lgdt [rdi]` source.
    pub gdtr: PseudoDescriptor,
    _pad_after_gdtr: [u8; 6],
    /// IDTR pseudo-descriptor (offset 0x10). `lidt [rdi + 0x10]` source.
    pub idtr: PseudoDescriptor,
    _pad_after_idtr: [u8; 6],
    /// `lapic_to_cpu[k]` = LAPIC ID of CPU `k`. Unused slots remain
    /// `CPU_ID_UNINIT` (= `u32::MAX`) — chosen so a stray match against
    /// a real LAPIC ID (8-bit xAPIC up to 255) is impossible.
    pub lapic_to_cpu: [u32; MAX_CPUS],
    /// `cpu_kstack_top[k]` = top-of-kernel-stack VA for CPU `k`. The
    /// AP loads this into RSP before any push/pop.
    pub cpu_kstack_top: [u64; MAX_CPUS],
    /// `cpu_per_cpu_ptr[k]` = address of `&'static PerCpu` slot for
    /// CPU `k`. The AP writes this to `IA32_GS_BASE` /
    /// `IA32_KERNEL_GS_BASE`.
    pub cpu_per_cpu_ptr: [u64; MAX_CPUS],
    /// `cpu_tss_sel[k]` = GDT selector to `ltr` for CPU `k`'s TSS.
    pub cpu_tss_sel: [u16; MAX_CPUS],
}

impl ApRuntimeControl {
    /// Zero-initialised control block. Every slot defaults to "AP not
    /// registered" (LAPIC sentinel + zero pointers).
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            gdtr: PseudoDescriptor::zero(),
            _pad_after_gdtr: [0; 6],
            idtr: PseudoDescriptor::zero(),
            _pad_after_idtr: [0; 6],
            lapic_to_cpu: [u32::MAX; MAX_CPUS],
            cpu_kstack_top: [0; MAX_CPUS],
            cpu_per_cpu_ptr: [0; MAX_CPUS],
            cpu_tss_sel: [0; MAX_CPUS],
        }
    }
}

/// Singleton control block. BSP populates pre-fire via the helpers
/// below; APs read it via the `kmain_ap` global asm.
#[unsafe(no_mangle)]
static mut AP_RUNTIME_CONTROL: ApRuntimeControl = ApRuntimeControl::zero();

/// MB14.c.2.d — populate the GDTR / IDTR descriptor pair shared by every
/// AP. Called once from the BSP after `gdt_init` + `idt_init` have run.
pub fn install_descriptor_tables(gdtr_base: u64, gdtr_limit: u16, idtr_base: u64, idtr_limit: u16) {
    // SAFETY: single-core pre-fire wiring; no AP has been signalled yet.
    unsafe {
        let p = core::ptr::addr_of_mut!(AP_RUNTIME_CONTROL);
        (*p).gdtr = PseudoDescriptor {
            limit: gdtr_limit,
            base: gdtr_base,
        };
        (*p).idtr = PseudoDescriptor {
            limit: idtr_limit,
            base: idtr_base,
        };
    }
}

/// MB14.c.2.d — populate the per-CPU runtime slots for the given AP.
///
/// `cpu_id` must be in `1..MAX_CPUS` (BSP entries are written by the
/// BSP itself; APs never read slot 0 of the runtime control). Returns
/// `false` for invalid `cpu_id`.
///
/// All four slots are populated atomically (single-writer, BSP-only
/// pre-fire).
pub fn register_ap_runtime_slot(
    cpu_id: u32,
    lapic_id: u32,
    kstack_top: u64,
    per_cpu_ptr: u64,
    tss_selector: u16,
) -> bool {
    let idx = cpu_id as usize;
    if idx == 0 || idx >= MAX_CPUS {
        return false;
    }
    // SAFETY: single-core pre-fire wiring; the AP for this slot has
    // not yet been signalled.
    unsafe {
        let p = core::ptr::addr_of_mut!(AP_RUNTIME_CONTROL);
        (*p).lapic_to_cpu[idx] = lapic_id;
        (*p).cpu_kstack_top[idx] = kstack_top;
        (*p).cpu_per_cpu_ptr[idx] = per_cpu_ptr;
        (*p).cpu_tss_sel[idx] = tss_selector;
    }
    true
}

/// MB14.c.2.d — read-back accessor for the runtime control block. Used
/// by host-side tests to verify the slot was populated as expected.
#[must_use]
pub fn read_ap_runtime_slot(cpu_id: u32) -> Option<(u32, u64, u64, u16)> {
    let idx = cpu_id as usize;
    if idx >= MAX_CPUS {
        return None;
    }
    // SAFETY: read of u32/u64/u16 fields via raw pointer; single-
    // writer (BSP pre-fire) + single-reader (this test / the AP).
    unsafe {
        let p = core::ptr::addr_of!(AP_RUNTIME_CONTROL);
        Some((
            (*p).lapic_to_cpu[idx],
            (*p).cpu_kstack_top[idx],
            (*p).cpu_per_cpu_ptr[idx],
            (*p).cpu_tss_sel[idx],
        ))
    }
}

/// MB14.c.2.d — allocate a single 4 KiB physical frame and return its
/// top-of-stack virtual address via the bootloader direct-map window.
///
/// Used as the back-end for both per-AP kernel stacks and per-AP IST
/// stacks (the latter at 4 KiB each: enough for the MB13.g diagnostic
/// halt handlers, which only push the `ExceptionFrame` before stopping).
///
/// **No guard page** in MB14.c.2.d — the AP never executes user code or
/// deep stack-using kernel routines in this milestone (it parks in
/// `cli; hlt` straight away). MB14.e's per-CPU scheduler will need to
/// adopt the MB10 guard-page layout when AP scheduling lands.
///
/// Returns `None` if the allocator is exhausted.
#[must_use]
pub fn allocate_ap_stack_frame<const N: usize>(
    allocator: &mut BitmapFrameAllocator<N>,
    phys_offset: u64,
) -> Option<u64> {
    let frame = allocator.alloc_frame()?;
    // Top-of-stack = base + frame_size. The AP's first push will
    // decrement RSP into the writable frame.
    Some(phys_offset.wrapping_add(frame.0).wrapping_add(0x1000))
}

// Higher-half landing point for every Application Processor in
// MB14.c.2.c. The AP arrives here with:
//
// - `CR3` = the BSP's kernel address space (loaded by the landing stub
//   from the AP_KERNEL_CR3 slot).
// - No stack. `RSP` is whatever the firmware left at AP reset; we do
//   not touch it.
// - No IDT loaded on this CPU. Interrupts are masked (CLI from the
//   trampoline's first instruction); the HLT loop above relies on
//   maskable interrupts staying disabled.
// - The temp GDT from the trampoline page still in `GDTR`. The AP
//   never returns from this function, so reloading a real per-CPU GDT
//   is deferred to MB14.c.2.d.
//
// MB14.c.2.d body — per-CPU initialisation sequence, extended in
// MB14.f.1 + MB14.f.2 + MB14.f.3:
//
//   1. Read x2APIC ID (CPUID leaf 0xB sub-leaf 0, EDX). The 32-bit
//      value subsumes the 8-bit xAPIC ID — in xAPIC mode EDX equals
//      EBX[31:24] zero-extended — so the same `mov ebx, edx` works in
//      either mode (MB14.f.2 widening).
//   2. Linear-search `AP_RUNTIME_CONTROL.lapic_to_cpu[]` for our cpu_id.
//   3. Load RSP from `cpu_kstack_top[cpu_id]` (no stack until now).
//   4. `lgdt` the kernel GDT and `lidt` the kernel IDT.
//   5. Reload data segments to kernel-data (`0x10`) and zero FS/GS.
//   6. `wrmsr` `IA32_GS_BASE` + `IA32_KERNEL_GS_BASE` with the per-CPU
//      pointer (MUST be after the `mov gs, dx` zero — segment-register
//      loads invalidate the hidden GS base).
//   7. `ltr` the per-CPU TSS selector.
//   8. **MB14.f.1 + MB14.f.3** — `call kernel_ap_lapic_init`. Enables
//      the local LAPIC (SIVR + TPR) and arms the periodic timer at
//      vector `0x20`. Without this, Fixed-delivery IPIs (e.g. the
//      `0xFD` TLB shootdown vector) never reach the IDT on this AP —
//      the MB14.e.4 ack-timeout root cause.
//   9. `lock inc` the online-ack counter (BSP polls this).
//  10. `sti` to unmask IPIs (MB14.e.1) so the local 0xFD TLB shootdown
//      handler and the per-CPU timer can fire. Per-CPU dispatch
//      enrolment is deferred to MB14.g; the AP timer handler currently
//      EOIs early (`current_cpu().is_bsp() == false` short-circuit in
//      `kernel_lapic_timer_tick`).
//  11. `hlt; jmp $-2` — idle park; resumes on any unmasked IPI, then
//      `iretq` returns straight back to the `hlt`.
//
// Note: `extern` blocks cannot carry rustdoc; document via this comment.
#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
core::arch::global_asm!(
    ".section .text.kmain_ap, \"ax\", @progbits",
    ".global kmain_ap",
    ".type kmain_ap, @function",
    "kmain_ap:",
    "    cli",
    // ---- Step 1 (MB14.f.2): read x2APIC ID via CPUID leaf 0xB sub-leaf 0 EDX ----
    // EDX yields the 32-bit ID in both xAPIC and x2APIC modes; in xAPIC
    // mode it equals EBX[31:24] zero-extended (Intel SDM Vol 2 — CPUID
    // leaf 0BH: "x2APIC ID the current logical processor"). Leaf 0xB is
    // supported on every x86_64 CPU since Nehalem (2008) and on every
    // KVM/QEMU/Proxmox-exposed virtual CPU.
    "    mov eax, 0x0B",
    "    xor ecx, ecx",
    "    cpuid",
    "    mov ebx, edx",
    // ---- Step 2: linear-search lapic_to_cpu[] for our cpu_id ----
    "    lea rdi, [rip + AP_RUNTIME_CONTROL]",
    "    xor r8d, r8d",
    "20:",
    "    cmp r8d, {max_cpus}",
    "    je 90f",
    "    mov edx, dword ptr [rdi + {off_lapic} + r8*4]",
    "    cmp edx, ebx",
    "    je 30f",
    "    inc r8d",
    "    jmp 20b",
    "30:",
    // r8 = cpu_id, rdi = &AP_RUNTIME_CONTROL, ebx = lapic_id
    // ---- Step 3: load RSP from cpu_kstack_top[cpu_id] ----
    "    mov rsp, [rdi + {off_kstk} + r8*8]",
    // ---- Step 4a: lgdt with the kernel GDTR ----
    "    lgdt [rdi + {off_gdtr}]",
    // ---- Step 4b: far return to reload CS from kernel GDT ----
    // After lgdt the CS hidden cache still holds the trampoline temp-GDT
    // slot 3 (`0x18` = 64-bit code in the temp). The kernel GDT slot 3
    // is *user-data* (DPL=3 udata), so any subsequent fault that
    // re-validates CS through the GDT would `#GP` and triple-fault.
    // Reload CS to the kernel 64-bit code selector (`0x08`) via a far
    // return: push the new selector + RIP, then `retfq`.
    "    mov rax, 0x08",                       // KERNEL_CS
    "    push rax",
    "    lea rax, [rip + 40f]",
    "    push rax",
    "    retfq",
    "40:",
    // ---- Step 5: lidt with the kernel IDTR ----
    "    lidt [rdi + {off_idtr}]",
    // ---- Step 6: reload data segments to kernel-data ----
    "    mov dx, 0x10",
    "    mov ds, dx",
    "    mov es, dx",
    "    mov ss, dx",
    "    xor dx, dx",
    "    mov fs, dx",
    "    mov gs, dx",
    // ---- Step 7: wrmsr IA32_GS_BASE + IA32_KERNEL_GS_BASE ----
    // MUST come AFTER the data-segment reload (mov gs, dx zeroes the
    // hidden GS base; only a subsequent wrmsr re-arms it).
    "    mov rax, [rdi + {off_pc} + r8*8]",
    "    mov rdx, rax",
    "    shr rdx, 32",
    "    mov ecx, 0xC0000101",
    "    wrmsr",
    "    mov rax, [rdi + {off_pc} + r8*8]",
    "    mov rdx, rax",
    "    shr rdx, 32",
    "    mov ecx, 0xC0000102",
    "    wrmsr",
    // ---- Step 7b: ltr <per-CPU TSS selector> ----
    "    mov ax, word ptr [rdi + {off_sel} + r8*2]",
    "    ltr ax",
    // ---- Step 8 (MB14.f.1 + MB14.f.3): enable the local LAPIC + arm
    //      its periodic timer at vector 0x20. The Rust callee
    //      `kernel_ap_lapic_init` is `extern "C"`, no arguments, no
    //      return value. Caller-saved registers (rax, rcx, rdx, rsi,
    //      rdi, r8-r11) may be clobbered — at this point rdi (the
    //      AP_RUNTIME_CONTROL pointer) and r8 (cpu_id) are no longer
    //      needed by the remaining steps (rip-relative addressing only),
    //      so clobbering them is safe.
    //
    //      RSP at the call site is the freshly-loaded per-CPU kernel
    //      stack top (step 3), which is page-aligned (and therefore
    //      16-byte aligned) — exactly what the System V AMD64 ABI
    //      requires at the `call` site.
    "    call kernel_ap_lapic_init",
    // ---- Step 9: bump online-ack counter (BSP polls this) ----
    "    lock inc qword ptr [rip + AP_ONLINE_ACK]",
    // ---- Step 10: enable maskable interrupts + park (MB14.e.1) ----
    // The whole pre-park init sequence ran with IF=0 (set by the
    // landing-stub's implicit `cli` and never flipped since). At this
    // point GDT/IDT/TSS/GS_BASE are all wired so the local 0xFD ISR
    // (and any future per-CPU vector) can safely fire on this AP. `sti`
    // sets IF=1; the subsequent `hlt` halts the AP until any unmasked
    // IPI arrives, at which point the handler runs on the per-CPU
    // kernel stack (TSS.rsp0 from MB14.c.2.d) and `iretq` resumes here.
    // The `jmp 80b` after `hlt` re-enters the wait state — IF remains
    // set across `hlt`, so we do not re-issue `sti` per iteration.
    "    sti",
    "80:",
    "    hlt",
    "    jmp 80b",
    // ---- park_unknown: LAPIC ID not in lapic_to_cpu table ----
    // Never reached on a correctly-configured boot (the BSP populates
    // lapic_to_cpu[1..N] for every enabled non-BSP AP pre-fire). Kept
    // as a distinct park label so a disassembler shows the missed-AP
    // path is reachable in principle, and so a stray AP with an
    // unexpected LAPIC ID has a defined landing place rather than
    // running off the end of the function.
    "90:",
    "    cli",
    "91:",
    "    hlt",
    "    jmp 91b",
    max_cpus = const MAX_CPUS,
    off_gdtr = const OFFSET_GDTR,
    off_idtr = const OFFSET_IDTR,
    off_lapic = const OFFSET_LAPIC_TO_CPU,
    off_kstk = const OFFSET_KSTACK_TOP,
    off_pc = const OFFSET_PER_CPU_PTR,
    off_sel = const OFFSET_TSS_SEL,
);

#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
unsafe extern "C" {
    /// AP entry point — defined via the `global_asm!` block above.
    pub fn kmain_ap() -> !;
}

/// Host-stub for non-bare-metal builds.
#[cfg(not(all(target_arch = "x86_64", target_os = "none", not(test))))]
#[allow(
    dead_code,
    reason = "host stub keeps the symbol resolvable from `cargo test --workspace --all-features` builds"
)]
pub extern "C" fn kmain_ap() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// =====================================================================
// Host-side tests
// =====================================================================

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "tests panic on bounds violation by design — surfaces builder regressions as test failures, not silent wrong bytes"
)]
mod tests {
    use super::*;

    /// Canonical trampoline base used by every MB14.c.2.* test.
    const TRAMP: u32 = 0x0000_8000;

    #[test]
    fn stub_starts_with_lock_inc_ack_counter() {
        let s = build_ap_landing_stub(TRAMP);
        // F0 48 FF 04 25 <imm32>
        assert_eq!(s[0x00], 0xF0, "LOCK prefix");
        assert_eq!(s[0x01], 0x48, "REX.W");
        assert_eq!(s[0x02], 0xFF, "INC opcode");
        assert_eq!(s[0x03], 0x04, "ModR/M /0 + SIB-mode");
        assert_eq!(s[0x04], 0x25, "SIB disp32 absolute");
        let imm = u32::from_le_bytes([s[0x05], s[0x06], s[0x07], s[0x08]]);
        assert_eq!(
            imm,
            TRAMP + AP_ACK_COUNTER_OFFSET as u32,
            "ack-counter disp32 must point at AP_ACK_COUNTER slot"
        );
    }

    #[test]
    fn stub_loads_kernel_cr3_before_cr3_switch() {
        let s = build_ap_landing_stub(TRAMP);
        // 48 8B 0C 25 <imm32> = mov rcx, [imm32]
        assert_eq!(&s[0x09..0x0D], &[0x48, 0x8B, 0x0C, 0x25]);
        let imm = u32::from_le_bytes([s[0x0D], s[0x0E], s[0x0F], s[0x10]]);
        assert_eq!(
            imm,
            TRAMP + AP_KERNEL_CR3_OFFSET as u32,
            "CR3 disp32 must point at AP_KERNEL_CR3 slot"
        );
    }

    #[test]
    fn stub_loads_kmain_ap_va_before_cr3_switch() {
        let s = build_ap_landing_stub(TRAMP);
        // 48 8B 14 25 <imm32> = mov rdx, [imm32]
        assert_eq!(&s[0x11..0x15], &[0x48, 0x8B, 0x14, 0x25]);
        let imm = u32::from_le_bytes([s[0x15], s[0x16], s[0x17], s[0x18]]);
        assert_eq!(
            imm,
            TRAMP + AP_KMAIN_AP_VA_OFFSET as u32,
            "kmain_ap-VA disp32 must point at AP_KMAIN_AP_VA slot"
        );
    }

    #[test]
    fn stub_switches_cr3_via_rcx() {
        let s = build_ap_landing_stub(TRAMP);
        // 0F 22 D9 = mov cr3, rcx
        assert_eq!(&s[0x19..0x1C], &[0x0F, 0x22, 0xD9]);
    }

    #[test]
    fn stub_jumps_to_rdx_after_cr3_switch() {
        let s = build_ap_landing_stub(TRAMP);
        // FF E2 = jmp rdx
        assert_eq!(&s[0x1C..0x1E], &[0xFF, 0xE2]);
    }

    #[test]
    fn stub_tail_is_zero_padded() {
        // Bytes after `jmp rdx` are never executed; pin the padding so a
        // future refactor cannot smuggle live bytes past the jump.
        let s = build_ap_landing_stub(TRAMP);
        for (i, b) in s.iter().enumerate().skip(0x1E) {
            assert_eq!(*b, 0, "stub byte {i:#x} must stay zero");
        }
    }

    #[test]
    fn stub_size_matches_constant() {
        let s = build_ap_landing_stub(TRAMP);
        assert_eq!(s.len(), AP_LANDING_STUB_SIZE);
    }

    #[test]
    fn slot_offsets_do_not_overlap_with_blob_or_stub() {
        // Trampoline blob at [0x000..0x100), landing stub at
        // [0x100..0x120), slots at [0x140..0x158). The 32-byte gap
        // between stub end and first slot is reserved for future
        // expansion (e.g. per-AP stack-top pointers in MB14.c.2.d).
        const _STUB_DOES_NOT_OVERLAP_BLOB: () = assert!(AP_LANDING_STUB_OFFSET >= 256);
        const _STUB_FITS_BEFORE_SLOTS: () =
            assert!(AP_LANDING_STUB_OFFSET + AP_LANDING_STUB_SIZE <= AP_ACK_COUNTER_OFFSET);
        const _SLOTS_ARE_8_BYTE_ALIGNED: () = assert!(
            AP_ACK_COUNTER_OFFSET % 8 == 0
                && AP_KERNEL_CR3_OFFSET % 8 == 0
                && AP_KMAIN_AP_VA_OFFSET % 8 == 0
        );
        const _SLOTS_ARE_DISTINCT_AND_ORDERED: () = assert!(
            AP_ACK_COUNTER_OFFSET < AP_KERNEL_CR3_OFFSET
                && AP_KERNEL_CR3_OFFSET < AP_KMAIN_AP_VA_OFFSET
        );
    }

    #[test]
    fn slot_offsets_reach_within_one_page() {
        const _ALL_SLOTS_IN_PAGE: () = assert!(AP_KMAIN_AP_VA_OFFSET + 8 <= 4096);
    }

    #[test]
    fn ack_counter_disp_changes_when_base_changes() {
        // Pin: the ack-counter disp32 isolates to a single 4-byte
        // window. A different trampoline base must change only that
        // window plus the two other slot disp fields.
        let a = build_ap_landing_stub(0x0000_8000);
        let b = build_ap_landing_stub(0x0000_9000);
        // Bytes 0x00..0x04 (LOCK / REX / opcode / ModR/M / SIB) stay.
        assert_eq!(&a[0x00..0x05], &b[0x00..0x05]);
        // 0x05..0x09 (ack disp32) differ.
        assert_ne!(&a[0x05..0x09], &b[0x05..0x09]);
    }

    // =====================================================================
    // MB14.c.2.d — `ApRuntimeControl` layout + slot register/read tests.
    //
    // The `kmain_ap` asm hard-codes the field offsets of
    // `ApRuntimeControl`. If we ever move a field (or change `MAX_CPUS`
    // such that array padding shifts), the AP triple-faults on real
    // silicon with no diagnostic. These tests pin the byte offsets so a
    // refactor surfaces as a unit-test failure instead.
    // =====================================================================

    #[test]
    fn ap_runtime_control_total_size_matches_asm_constant() {
        assert_eq!(
            core::mem::size_of::<ApRuntimeControl>(),
            AP_RUNTIME_CONTROL_SIZE
        );
    }

    #[test]
    fn ap_runtime_control_gdtr_at_offset_zero() {
        let c = ApRuntimeControl::zero();
        let base = core::ptr::addr_of!(c) as usize;
        let field = core::ptr::addr_of!(c.gdtr) as usize;
        assert_eq!(field - base, OFFSET_GDTR);
    }

    #[test]
    fn ap_runtime_control_idtr_at_offset_0x10() {
        let c = ApRuntimeControl::zero();
        let base = core::ptr::addr_of!(c) as usize;
        let field = core::ptr::addr_of!(c.idtr) as usize;
        assert_eq!(field - base, OFFSET_IDTR);
    }

    #[test]
    fn ap_runtime_control_lapic_to_cpu_at_offset_0x20() {
        let c = ApRuntimeControl::zero();
        let base = core::ptr::addr_of!(c) as usize;
        let field = core::ptr::addr_of!(c.lapic_to_cpu) as usize;
        assert_eq!(field - base, OFFSET_LAPIC_TO_CPU);
    }

    #[test]
    fn ap_runtime_control_kstack_top_at_offset_0xa0() {
        let c = ApRuntimeControl::zero();
        let base = core::ptr::addr_of!(c) as usize;
        let field = core::ptr::addr_of!(c.cpu_kstack_top) as usize;
        assert_eq!(field - base, OFFSET_KSTACK_TOP);
    }

    #[test]
    fn ap_runtime_control_per_cpu_ptr_at_offset_0x1a0() {
        let c = ApRuntimeControl::zero();
        let base = core::ptr::addr_of!(c) as usize;
        let field = core::ptr::addr_of!(c.cpu_per_cpu_ptr) as usize;
        assert_eq!(field - base, OFFSET_PER_CPU_PTR);
    }

    #[test]
    fn ap_runtime_control_tss_sel_at_offset_0x2a0() {
        let c = ApRuntimeControl::zero();
        let base = core::ptr::addr_of!(c) as usize;
        let field = core::ptr::addr_of!(c.cpu_tss_sel) as usize;
        assert_eq!(field - base, OFFSET_TSS_SEL);
    }

    #[test]
    fn pseudo_descriptor_is_ten_bytes() {
        // `lgdt` / `lidt` expect a 10-byte limit:base layout. The
        // packed repr (no padding) is the only encoding the CPU accepts.
        assert_eq!(core::mem::size_of::<PseudoDescriptor>(), 10);
    }

    #[test]
    fn zero_initialised_lapic_table_uses_uninit_sentinel() {
        // Every slot defaults to `u32::MAX` so the AP linear search
        // cannot accidentally match a slot the BSP never registered.
        let c = ApRuntimeControl::zero();
        for slot in c.lapic_to_cpu {
            assert_eq!(slot, u32::MAX);
        }
    }

    #[test]
    fn register_ap_runtime_slot_rejects_bsp_and_oor() {
        assert!(!register_ap_runtime_slot(0, 1, 0, 0, 0));
        #[allow(
            clippy::cast_possible_truncation,
            reason = "MAX_CPUS = 32 fits u32 trivially"
        )]
        let oor = MAX_CPUS as u32;
        assert!(!register_ap_runtime_slot(oor, 1, 0, 0, 0));
    }

    #[test]
    fn register_ap_runtime_slot_round_trips_fields() {
        let cpu_id: u32 = 1;
        let lapic = 0xAA;
        let kstk = 0xFFFF_C000_DEAD_BEEF;
        let pc = 0xFFFF_C000_CAFE_F00D;
        let sel: u16 = 0x38;
        assert!(register_ap_runtime_slot(cpu_id, lapic, kstk, pc, sel));
        let (l, k, p, s) = read_ap_runtime_slot(cpu_id).expect("slot");
        assert_eq!(l, lapic);
        assert_eq!(k, kstk);
        assert_eq!(p, pc);
        assert_eq!(s, sel);
    }

    #[test]
    fn install_descriptor_tables_round_trips() {
        install_descriptor_tables(0xDEAD_BEEF_C000_0000, 0x37, 0xCAFE_F00D_0000_0000, 0xFFF);
        // SAFETY: single-threaded host test; AP_RUNTIME_CONTROL is the
        // only writer (via install_descriptor_tables).
        let (g_limit, g_base, i_limit, i_base) = unsafe {
            let p = core::ptr::addr_of!(AP_RUNTIME_CONTROL);
            // `read_unaligned` because PseudoDescriptor is `packed`.
            let g = core::ptr::addr_of!((*p).gdtr).read_unaligned();
            let i = core::ptr::addr_of!((*p).idtr).read_unaligned();
            (g.limit, g.base, i.limit, i.base)
        };
        assert_eq!(g_limit, 0x37);
        assert_eq!(g_base, 0xDEAD_BEEF_C000_0000);
        assert_eq!(i_limit, 0xFFF);
        assert_eq!(i_base, 0xCAFE_F00D_0000_0000);
    }
}
