//! xAPIC Local APIC driver — MB7 deliverable + MB8 preemption hook.
//!
//! Extended in MB14.f with:
//! - **x2APIC mode awareness** (`detect_lapic_mode`, `is_x2apic_enabled`).
//!   When firmware/bootloader has already flipped `IA32_APIC_BASE` bit 10
//!   the kernel routes every LAPIC access through the MSR-based registers
//!   (`IA32_X2APIC_*`, MSR base `0x800`); otherwise the MB7-era xAPIC
//!   MMIO path stays in use byte-for-byte.
//! - **`kernel_ap_lapic_init`** — Rust callable invoked from the
//!   `kmain_ap` `global_asm`! block (MB14.c.2.d) immediately after `ltr`,
//!   so every Application Processor leaves the per-CPU init sequence
//!   with its own LAPIC enabled (SIVR.bit8 + spurious vector 0xFF, TPR=0)
//!   and the periodic timer armed. Without this, the 0xFD ISR cannot run
//!   on the AP and the BSP's TLB shootdown busy-poll times out — the
//!   MB14.e.4 follow-up scoped to MB14.f.
//!
//! Responsibilities:
//! - Disable the legacy 8259 PIC (remap + mask all IRQs).
//! - Read the LAPIC physical base address from `IA32_APIC_BASE` MSR.
//! - Enable the xAPIC via the Spurious Interrupt Vector Register.
//! - Start a periodic timer at IDT vector 0x20 (~160 ms on QEMU TCG).
//! - Send EOI after each hardware-interrupt handler.
//! - MB8: set `NEED_RESCHED`; at the safe tail of the IRQ stub call
//!   `kernel_check_need_resched`, which invokes the existing cooperative
//!   `yield_current` while the trap frame is still on the task's stack.
//! - MB14.f.3: AP timer setup mirrors the BSP timer setup so every
//!   per-CPU timer fires on vector 0x20.
//! - MB14.g: each CPU records its own tick counter + resched flag inside
//!   its `PerCpu` descriptor; the timer ISR writes only `current_cpu()`
//!   storage, and `kernel_check_need_resched` consumes that flag. The
//!   AP path drains its flag and returns until MB14.h wires the AP-side
//!   dispatch loop.
//!
//! ### Why the two-stage tick → resched split
//!
//! Keeping the tick handler (`kernel_lapic_timer_tick`) minimal — only
//! `TICK_COUNT++`, EOI, set flag — avoids re-entering the scheduler with
//! the LAPIC EOI still pending. The actual `yield_current` runs *after*
//! EOI, at the very end of the asm stub, where the only state on the
//! stack is the trap frame (caller-saved + CPU-pushed RIP/CS/RFLAGS/RSP/SS).
//! `nexacore_context_switch` then layers its callee-saved frame on top of
//! that, and the original task is later resumed via the matching `iretq`
//! in this stub — see `docs/changelog.md` for the layout.

#![allow(unsafe_code)]

// All items in this file are x86_64-only.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("bare_metal::lapic is x86_64-only");

use core::arch::global_asm;

// ---------------------------------------------------------------------------
// xAPIC MMIO register offsets (from LAPIC base address)
// ---------------------------------------------------------------------------

const LAPIC_ID: u32 = 0x0020; // Local APIC ID Register (xAPIC: ID in bits 31:24)
const LAPIC_TPR: u32 = 0x0080; // Task Priority Register (write 0 to accept every priority)
const LAPIC_EOI: u32 = 0x00B0; // End-of-Interrupt (write 0 to ACK)
const LAPIC_SIVR: u32 = 0x00F0; // Spurious Interrupt Vector Register
/// xAPIC Interrupt Command Register, low dword (writes here latch and fire the IPI).
const LAPIC_ICR_LO: u32 = 0x0300;
/// xAPIC Interrupt Command Register, high dword (write before [`LAPIC_ICR_LO`]).
const LAPIC_ICR_HI: u32 = 0x0310;
const LAPIC_LVT_TIMER: u32 = 0x0320; // Local Vector Table — Timer entry
const LAPIC_TIMER_ICR: u32 = 0x0380; // Initial Count Register
const LAPIC_TIMER_DCR: u32 = 0x03E0; // Divide Configuration Register

// ---------------------------------------------------------------------------
// MB14.f.2 — x2APIC MSR addresses (Intel SDM Vol 3A § 10.12.1.2)
//
// Every xAPIC MMIO offset has a 1:1 MSR counterpart at `0x800 + (offset >> 4)`.
// In x2APIC mode the MMIO window is disabled (writes #GP) and all LAPIC
// accesses go through these MSRs. ICR is a single 64-bit MSR instead of
// the xAPIC split LO/HI pair.
// ---------------------------------------------------------------------------

const MSR_IA32_APIC_BASE: u32 = 0x0000_001B;
const APIC_BASE_X2APIC_ENABLE: u64 = 1 << 10;
const APIC_BASE_GLOBAL_ENABLE: u64 = 1 << 11;

const MSR_X2APIC_APICID: u32 = 0x0000_0802;
const MSR_X2APIC_TPR: u32 = 0x0000_0808;
const MSR_X2APIC_EOI: u32 = 0x0000_080B;
const MSR_X2APIC_SIVR: u32 = 0x0000_080F;
const MSR_X2APIC_ICR: u32 = 0x0000_0830;
const MSR_X2APIC_LVT_TIMER: u32 = 0x0000_0832;
const MSR_X2APIC_TIMER_ICR: u32 = 0x0000_0838;
const MSR_X2APIC_TIMER_DCR: u32 = 0x0000_083E;

/// Bit 12 of `ICR_LO`: `Delivery Status` (RO). Set while a previously
/// issued IPI is still pending on the APIC bus; the BSP must spin until
/// it clears before writing a new ICR command (Intel SDM Vol 3A § 10.6.1).
const LAPIC_ICR_BUSY_MASK: u32 = 1 << 12;

const LAPIC_ENABLE: u32 = 1 << 8; // SIVR bit 8: enable xAPIC
const LVT_TIMER_PERIODIC: u32 = 1 << 17; // LVT timer mode: periodic

/// Spurious vector value programmed into both SIVR encodings. `0xFF` is
/// the canonical Intel SDM placeholder — distinct from every other vector
/// the kernel installs in the IDT.
const SPURIOUS_VECTOR: u32 = 0xFF;
/// Timer divider value (divide-by-16). Pinned here so the BSP and every
/// AP arm an identical tick cadence.
const TIMER_DIVIDE_BY_16: u32 = 0x3;
/// Periodic timer initial count. ~160 ms on QEMU TCG (100 `MHz` bus / 16).
const TIMER_INITIAL_COUNT: u32 = 1_000_000;
/// IDT vector used for the periodic LAPIC timer interrupt.
const TIMER_VECTOR: u32 = 0x20;

// ---------------------------------------------------------------------------
// Globals.
// ---------------------------------------------------------------------------

/// Virtual address of the mapped xAPIC MMIO register window. Zero before
/// [`lapic_init`] has succeeded. Unused (but kept addressable) when the
/// kernel runs in x2APIC mode: x2APIC accesses always go through the
/// MSR helpers.
static mut LAPIC_BASE: u64 = 0;

/// `true` once [`lapic_init`] has observed `IA32_APIC_BASE` bit 10 set on
/// the BSP. APs check this in [`kernel_ap_lapic_init`] to decide whether
/// to enable their own x2APIC mode before writing SIVR/TPR.
static X2APIC_MODE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// LAPIC operating mode for diagnostic / dispatch decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LapicMode {
    /// Legacy memory-mapped Local APIC (`IA32_APIC_BASE` bit 10 = 0).
    XApic,
    /// MSR-based extended Local APIC (`IA32_APIC_BASE` bit 10 = 1).
    X2Apic,
}

// ---------------------------------------------------------------------------
// MSR helpers (local copies — same implementation as syscall_entry.rs but
// private here to keep the modules independent)
// ---------------------------------------------------------------------------

unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// MB14.f.2 — privileged 64-bit MSR write.
///
/// # Safety
///
/// Ring 0 only. Caller is responsible for selecting a valid `msr` index
/// and a value the MSR accepts (some MSRs reject `#GP` on reserved bits).
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

// ---------------------------------------------------------------------------
// MMIO helpers (volatile reads/writes — required for memory-mapped registers)
// ---------------------------------------------------------------------------

unsafe fn lapic_read(base: u64, reg: u32) -> u32 {
    unsafe { ((base + u64::from(reg)) as *const u32).read_volatile() }
}

unsafe fn lapic_write(base: u64, reg: u32, val: u32) {
    unsafe { ((base + u64::from(reg)) as *mut u32).write_volatile(val) }
}

// ---------------------------------------------------------------------------
// LAPIC physical base address from IA32_APIC_BASE MSR (0x1B)
// ---------------------------------------------------------------------------

fn lapic_phys_base() -> u64 {
    // Bits [51:12] hold the 4 KiB-aligned physical base address.
    unsafe { rdmsr(0x1B) & 0x000F_FFFF_FFFF_F000 }
}

// ---------------------------------------------------------------------------
// Legacy 8259 PIC: remap to vectors 0x20-0x2F, then mask all IRQs.
//
// This must be done before enabling the LAPIC; otherwise spurious PIC
// interrupts (mapped to exceptions 0x08-0x0F by default) would triple-fault.
// ---------------------------------------------------------------------------

unsafe fn disable_legacy_pic() {
    use super::arch::{inb, outb};

    // ICW1: cascade mode, edge-triggered, need ICW4.
    unsafe {
        outb(0x20, 0x11);
        outb(0xA0, 0x11);
    }
    // ICW2: remap master IRQs 0-7 → vectors 0x20-0x27,
    //        slave IRQs 8-15 → vectors 0x28-0x2F.
    unsafe {
        outb(0x21, 0x20);
        outb(0xA1, 0x28);
    }
    // ICW3: master has slave on IRQ2; slave cascade identity = 2.
    unsafe {
        outb(0x21, 0x04);
        outb(0xA1, 0x02);
    }
    // ICW4: 8086/8088 mode.
    unsafe {
        outb(0x21, 0x01);
        outb(0xA1, 0x01);
    }
    // OCW1: mask all IRQs on both PICs.
    unsafe {
        outb(0x21, 0xFF);
        outb(0xA1, 0xFF);
    }
    // Brief I/O delay to let the PIC settle (dummy read from port 0x80).
    unsafe {
        let _ = inb(0x80);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialise the xAPIC and start a periodic timer at IDT vector 0x20.
///
/// Returns `true` on success, `false` if the CPU reports a zero LAPIC base
/// (should not happen on any `x86_64` hardware or QEMU VM).
///
/// Must be called after:
/// - [`super::idt::idt_init`] (IDT must be loaded before registering 0x20).
/// - Physical memory has been mapped via the bootloader direct-map window.
///
/// # Safety invariant
///
/// Single-CPU, non-preemptive. The `LAPIC_BASE` global is written once here
/// and subsequently read (never written) from the timer interrupt handler.
pub fn lapic_init(phys_offset: u64) -> bool {
    let phys = lapic_phys_base();
    if phys == 0 {
        return false;
    }
    let virt = phys + phys_offset;

    // SAFETY: rdmsr/wrmsr/MMIO writes are ring-0 operations; we are
    // running in the BSP single-CPU init phase before any preemption
    // has been enabled.
    unsafe {
        // Step 0 (MB14.f.2): observe the LAPIC mode the firmware /
        // bootloader left us in. If `IA32_APIC_BASE` bit 10 is set the
        // BSP already runs in x2APIC mode and the xAPIC MMIO window is
        // disabled — every subsequent register access must go via the
        // MSR helpers. Otherwise stay in xAPIC mode for the duration
        // of this milestone (we do not flip the bit ourselves; that is
        // a deliberate decision in MB14.f.2 scope to avoid invalidating
        // the bootloader-mapped MMIO window mid-boot).
        let mode = detect_lapic_mode();
        X2APIC_MODE.store(
            matches!(mode, LapicMode::X2Apic),
            core::sync::atomic::Ordering::Release,
        );

        // Step 1: disable legacy PIC so its IRQs cannot fire.
        disable_legacy_pic();

        // Step 2: store virtual base for the xAPIC MMIO fast path BEFORE
        // we program SIVR/TPR/timer. `program_lapic_local` consults
        // `LAPIC_BASE` for the xAPIC path; storing it first lets the
        // function be reused verbatim by `kernel_ap_lapic_init`.
        LAPIC_BASE = virt;

        // Step 3..6: program SIVR / TPR / LVT timer in mode-correct
        // fashion.
        program_lapic_local(mode);

        // Step 7: register the timer interrupt handler in IDT slot 0x20.
        super::idt::idt_set_vector(
            TIMER_VECTOR as usize,
            nexacore_lapic_timer_handler as *const () as usize as u64,
        );
    }

    true
}

/// MB14.f.2 — read the LAPIC mode currently in effect on this CPU.
///
/// Bit 10 (EXTD) of `IA32_APIC_BASE` distinguishes xAPIC vs x2APIC
/// (Intel SDM Vol 3A § 10.12.1). Bit 11 (EN) is the global enable; we
/// expect it to already be set by the firmware/bootloader on any CPU
/// the kernel sees.
#[must_use]
pub fn detect_lapic_mode() -> LapicMode {
    // SAFETY: rdmsr of IA32_APIC_BASE is well-defined on every x86_64
    // CPU since the original Pentium IV; no side effects.
    let base = unsafe { rdmsr(MSR_IA32_APIC_BASE) };
    if base & APIC_BASE_X2APIC_ENABLE != 0 {
        LapicMode::X2Apic
    } else {
        LapicMode::XApic
    }
}

/// MB14.f.2 — `true` iff the BSP observed x2APIC mode at
/// [`lapic_init`] time.
#[must_use]
pub fn is_x2apic_enabled() -> bool {
    X2APIC_MODE.load(core::sync::atomic::Ordering::Acquire)
}

/// Program SIVR + TPR + LVT timer on the current logical CPU. Used by
/// both [`lapic_init`] (BSP, with the matching mode-detect already done)
/// and [`kernel_ap_lapic_init`] (every AP, mirrors the BSP).
///
/// # Safety
///
/// Ring 0; assumes `mode` reflects the actual mode of the executing CPU
/// (in MB14.f.2 the BSP and every AP agree on the firmware-left mode —
/// we never flip the bit at runtime).
unsafe fn program_lapic_local(mode: LapicMode) {
    match mode {
        LapicMode::XApic => {
            // SAFETY: read the LAPIC base after `lapic_init` has stored it.
            let virt = unsafe { LAPIC_BASE };
            if virt == 0 {
                return;
            }
            // SAFETY: `virt` is the bootloader-mapped LAPIC MMIO window;
            // each register lives inside that 4 KiB page.
            unsafe {
                lapic_write(virt, LAPIC_SIVR, LAPIC_ENABLE | SPURIOUS_VECTOR);
                lapic_write(virt, LAPIC_TPR, 0);
                lapic_write(virt, LAPIC_TIMER_DCR, TIMER_DIVIDE_BY_16);
                lapic_write(virt, LAPIC_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR);
                lapic_write(virt, LAPIC_TIMER_ICR, TIMER_INITIAL_COUNT);
            }
        }
        LapicMode::X2Apic => {
            // SAFETY: MSR-based x2APIC accesses are valid on every CPU
            // whose `IA32_APIC_BASE` bit 10 is set.
            unsafe {
                wrmsr(MSR_X2APIC_SIVR, u64::from(LAPIC_ENABLE | SPURIOUS_VECTOR));
                wrmsr(MSR_X2APIC_TPR, 0);
                wrmsr(MSR_X2APIC_TIMER_DCR, u64::from(TIMER_DIVIDE_BY_16));
                wrmsr(
                    MSR_X2APIC_LVT_TIMER,
                    u64::from(LVT_TIMER_PERIODIC | TIMER_VECTOR),
                );
                wrmsr(MSR_X2APIC_TIMER_ICR, u64::from(TIMER_INITIAL_COUNT));
            }
        }
    }
}

/// Send an End-of-Interrupt signal to the LAPIC.
///
/// Must be called at the end of every hardware interrupt handler before
/// returning via `iretq`; failing to do so masks all future LAPIC
/// interrupts. Routes to `IA32_X2APIC_EOI` (MSR `0x80B`) in x2APIC mode
/// or to the xAPIC MMIO `LAPIC_EOI` register otherwise.
pub fn lapic_eoi() {
    if X2APIC_MODE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: MSR write is well-defined on a CPU running in x2APIC
        // mode; value 0 is the canonical EOI write.
        unsafe {
            wrmsr(MSR_X2APIC_EOI, 0);
        }
        return;
    }
    // SAFETY: `LAPIC_BASE` is set once at boot before any handler runs;
    // the EOI register lives inside the same 4 KiB MMIO page.
    unsafe {
        if LAPIC_BASE != 0 {
            lapic_write(LAPIC_BASE, LAPIC_EOI, 0);
        }
    }
}

/// MB14.f.1 — initialise the local LAPIC on the current CPU.
///
/// Called from the `kmain_ap` `global_asm`! block (see
/// [`super::mp_ap_entry`]) immediately after `ltr` and before `sti`. The
/// AP arrives with a per-CPU kernel stack already loaded (step 3 of the
/// MB14.c.2.d sequence) so a regular Rust ABI call is safe.
///
/// What it does on this CPU:
/// 1. Match the BSP-observed [`LapicMode`]. If x2APIC, the AP must
///    flip `IA32_APIC_BASE` bit 10 locally — the MSR is per-CPU and
///    starts in xAPIC mode on every AP regardless of the BSP setting.
/// 2. Write SIVR with `LAPIC_ENABLE | 0xFF` (spurious vector). Without
///    this the LAPIC stays disabled and Fixed-delivery IPIs (e.g.
///    `0xFD` TLB shootdown) never reach the IDT — the MB14.e.4 ack
///    timeout root cause.
/// 3. Write TPR=0 so every priority level is accepted.
/// 4. (MB14.f.3) Arm the periodic LAPIC timer at vector `0x20`,
///    matching the BSP cadence. The handler `nexacore_lapic_timer_handler`
///    is already installed in the kernel IDT (shared across CPUs).
///
/// `no_mangle` because the call site is a `call kernel_ap_lapic_init`
/// emitted inside the `kmain_ap` `global_asm!` block.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_ap_lapic_init() {
    // Read the BSP-observed mode. APs do not flip the bit themselves
    // unless the BSP did first — keeping the two CPUs in lock-step.
    let want_x2apic = X2APIC_MODE.load(core::sync::atomic::Ordering::Acquire);

    // SAFETY: ring-0; this AP has a per-CPU kernel stack and the
    // mode-coherent path below performs only the writes the AP's own
    // LAPIC documents as legal.
    unsafe {
        if want_x2apic {
            // Bring this AP's IA32_APIC_BASE into x2APIC mode (per-CPU
            // MSR — the BSP's flip does not propagate). Bit 11 (EN)
            // should already be set; we OR it in defensively.
            let mut base = rdmsr(MSR_IA32_APIC_BASE);
            base |= APIC_BASE_GLOBAL_ENABLE | APIC_BASE_X2APIC_ENABLE;
            wrmsr(MSR_IA32_APIC_BASE, base);
            program_lapic_local(LapicMode::X2Apic);
        } else {
            program_lapic_local(LapicMode::XApic);
        }
    }
}

/// Send an Inter-Processor Interrupt via the xAPIC Interrupt Command
/// Register (MB14.c.2.c).
///
/// `high` is written to `ICR_HI` first (destination field); `low` is
/// written to `ICR_LO` second, which latches the command and dispatches
/// the IPI onto the APIC bus.
///
/// The function busy-waits for `ICR_LO` bit 12 (`Delivery Status`) to
/// clear before writing the new command, per Intel SDM Vol 3A § 10.6.1.
/// The post-write busy poll is the caller's responsibility — see
/// [`lapic_icr_busy`] — because INIT/SIPI sequencing typically interposes
/// a PIT delay between the busy poll and the next write.
///
/// Returns `false` if [`lapic_init`] has not yet succeeded (LAPIC base
/// not mapped); no MMIO occurs in that case. Returns `true` after the
/// MMIO sequence has been issued.
///
/// # Safety
///
/// Caller is responsible for the semantic correctness of `(low, high)`
/// — i.e. that the encoded command is a valid IPI for the current LAPIC
/// configuration. The MMIO sequence itself is unsafe but well-defined.
#[must_use]
pub fn lapic_send_ipi(low: u32, high: u32) -> bool {
    if X2APIC_MODE.load(core::sync::atomic::Ordering::Acquire) {
        // MB14.f.2 — x2APIC ICR is a single 64-bit MSR. The xAPIC
        // (low, high) split maps directly: low → bits 0..31, high →
        // bits 32..63. Bit 12 (`Delivery Status`) does not exist in
        // x2APIC mode (Intel SDM Vol 3A § 10.12.9), so the busy-wait
        // is unnecessary — the MSR write is itself the latch.
        let value = (u64::from(high) << 32) | u64::from(low);
        // SAFETY: this CPU is in x2APIC mode (the BSP enabled it at
        // boot and every AP mirrored via `kernel_ap_lapic_init`); the
        // MSR `IA32_X2APIC_ICR` accepts any 64-bit value.
        unsafe {
            wrmsr(MSR_X2APIC_ICR, value);
        }
        return true;
    }
    // SAFETY: single-CPU LAPIC base read; the only writer is `lapic_init`
    // which runs once at boot before any caller of this function.
    let base = unsafe { LAPIC_BASE };
    if base == 0 {
        return false;
    }
    // SAFETY: `base` is the bootloader-mapped LAPIC MMIO window; the
    // four register offsets (`ICR_LO` / `ICR_HI`) live inside that 4 KiB
    // page. Volatile reads/writes are mandatory — LAPIC registers are
    // not cacheable RAM.
    unsafe {
        // Drain any prior pending IPI before issuing this one.
        while (lapic_read(base, LAPIC_ICR_LO) & LAPIC_ICR_BUSY_MASK) != 0 {
            core::hint::spin_loop();
        }
        // Write the destination (HI) first, then the command (LO);
        // writing LO latches and fires the IPI.
        lapic_write(base, LAPIC_ICR_HI, high);
        lapic_write(base, LAPIC_ICR_LO, low);
    }
    true
}

/// Poll the `ICR_LO` `Delivery Status` bit (Intel SDM Vol 3A § 10.6.1).
///
/// Returns `true` while a previously issued IPI is still propagating on
/// the APIC bus and a new write to ICR would be discarded. Returns
/// `false` once the bus is idle. Also returns `false` when [`lapic_init`]
/// has not yet been called (LAPIC base unmapped).
#[must_use]
pub fn lapic_icr_busy() -> bool {
    if X2APIC_MODE.load(core::sync::atomic::Ordering::Acquire) {
        // x2APIC ICR is single-write atomic — no "Delivery Status" bit
        // exists in the MSR layout (Intel SDM Vol 3A § 10.12.9). A
        // caller reading "busy" while still on an x2APIC CPU is always
        // false.
        return false;
    }
    // SAFETY: same single-CPU invariant as [`lapic_send_ipi`].
    let base = unsafe { LAPIC_BASE };
    if base == 0 {
        return false;
    }
    // SAFETY: see [`lapic_send_ipi`] — `ICR_LO` is a 32-bit MMIO register
    // inside the bootloader-mapped LAPIC window.
    let raw = unsafe { lapic_read(base, LAPIC_ICR_LO) };
    (raw & LAPIC_ICR_BUSY_MASK) != 0
}

/// Read the Local APIC ID of the current CPU.
///
/// Mode-aware (MB14.f.2):
/// - **xAPIC** (legacy): reads the 32-bit MMIO register at LAPIC offset
///   `0x20` and extracts bits `31:24` (Intel SDM Vol 3A § 10.4.6).
/// - **x2APIC**: reads MSR `IA32_X2APIC_APICID` (`0x802`) which yields
///   the full 32-bit ID — sufficient for LAPIC IDs above 255 on
///   server-class topologies.
///
/// Returns `None` if [`lapic_init`] has not yet succeeded (LAPIC MMIO
/// base not mapped) AND the CPU is not in x2APIC mode. In x2APIC mode
/// the MSR read is always valid.
///
/// MMIO accesses must be volatile (the LAPIC register window is not
/// cacheable RAM) — `lapic_read` issues `read_volatile`.
#[must_use]
pub fn read_lapic_id() -> Option<u32> {
    if X2APIC_MODE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: `IA32_X2APIC_APICID` is a read-only MSR available on
        // every CPU that is in x2APIC mode — which we just asserted.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "MSR holds the 32-bit LAPIC ID in the low dword; high dword is reserved 0"
        )]
        let id = unsafe { rdmsr(MSR_X2APIC_APICID) } as u32;
        return Some(id);
    }
    // SAFETY: single-CPU read of a static u64 — the only writer is
    // `lapic_init` which runs once at boot before any caller of this
    // function. After that, `LAPIC_BASE` is treated as read-only.
    let base = unsafe { LAPIC_BASE };
    if base == 0 {
        return None;
    }
    // SAFETY: `base` is the virtual address of the LAPIC MMIO window
    // mapped by the bootloader's direct-map; `lapic_read` performs a
    // volatile 32-bit read from a 4 KiB-aligned page that holds the
    // LAPIC register block.
    let raw = unsafe { lapic_read(base, LAPIC_ID) };
    Some(raw >> 24)
}

/// Read the in-service vector currently being handled by this CPU.
///
/// Scans the LAPIC In-Service Register banks `ISR.B0..ISR.B7`
/// (xAPIC MMIO offsets `0x100..0x180` step 16; x2APIC MSRs
/// `0x810..0x817`) from the **highest** bank down so the
/// highest-priority active vector wins (Intel SDM Vol 3A § 10.8.4).
///
/// Returns `None` when no vector is in service (spurious interrupt)
/// or when the LAPIC base has not been mapped yet.
///
/// Wired by `super::syscall_entry::kernel_irq_dispatch_handler` (the
/// C-ABI Rust callback the IRQ trampoline calls) for P6.7.8.3 — the
/// shared IRQ-attach trampoline needs to recover the vector that fired
/// without threading it through the asm stub.
#[must_use]
pub fn read_in_service_vector() -> Option<u8> {
    if X2APIC_MODE.load(core::sync::atomic::Ordering::Acquire) {
        // x2APIC ISR registers occupy MSRs `0x810..=0x817`.
        for bank in (0..8u32).rev() {
            let msr = 0x810 + bank;
            // SAFETY: x2APIC mode asserted; ISR MSRs are read-only and
            // architecturally defined on any CPU in x2APIC mode.
            #[allow(
                clippy::cast_possible_truncation,
                reason = "the ISR MSR returns 32 valid bits in the low dword"
            )]
            let raw = unsafe { rdmsr(msr) } as u32;
            if raw != 0 {
                let bit = 31 - raw.leading_zeros();
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "bank ≤ 7 and bit < 32 ⇒ bank * 32 + bit < 256, fits u8"
                )]
                let vector = (bank * 32 + bit) as u8;
                return Some(vector);
            }
        }
        return None;
    }
    // SAFETY: LAPIC_BASE is set once at boot before any handler runs.
    let base = unsafe { LAPIC_BASE };
    if base == 0 {
        return None;
    }
    for bank in (0..8u32).rev() {
        let reg = 0x0100 + bank * 0x10;
        // SAFETY: lapic_read performs a volatile 32-bit read against
        // the LAPIC MMIO window mapped by the bootloader's direct-map.
        let raw = unsafe { lapic_read(base, reg) };
        if raw != 0 {
            let bit = 31 - raw.leading_zeros();
            #[allow(
                clippy::cast_possible_truncation,
                reason = "bank ≤ 7 and bit < 32 ⇒ bank * 32 + bit < 256, fits u8"
            )]
            let vector = (bank * 32 + bit) as u8;
            return Some(vector);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Timer interrupt handler — IDT vector 0x20
// ---------------------------------------------------------------------------

// Assembly stub: save caller-saved registers, call the tick handler, then
// call the resched trampoline (which may perform a cooperative context
// switch via `nexacore_context_switch`), restore caller-saved, `iretq`.
//
// Stack alignment check (System V AMD64 ABI):
//   Interrupt entry: CPU pushes SS, RSP, RFLAGS, CS, RIP = 5 × 8 = 40 bytes.
//   Before interrupt, RSP was 16-byte aligned → after CPU push, RSP % 16 = 8.
//   We push 9 caller-saved registers × 8 bytes = 72 bytes → RSP % 16 = 8+72 = 80 ≡ 0.
//   `call` pushes 8-byte return address → RSP % 16 = 8 at function entry. ✓
//   The second `call` (kernel_check_need_resched) starts from the same
//   alignment because the first `call` has fully returned (its RA popped).
global_asm!(
    ".global nexacore_lapic_timer_handler",
    "nexacore_lapic_timer_handler:",
    "    push rax",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    call kernel_lapic_timer_tick",
    "    call kernel_check_need_resched",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rax",
    "    iretq",
);

unsafe extern "C" {
    fn nexacore_lapic_timer_handler();
}

/// Rust callback invoked on every LAPIC timer tick (IDT vector 0x20).
///
/// Strict subset of work that is safe inside an Interrupt Gate handler:
/// monotonic counter, EOI ack, and a single atomic flag store. The actual
/// reschedule decision happens in [`kernel_check_need_resched`] just
/// before `iretq`.
#[unsafe(no_mangle)]
extern "C" fn kernel_lapic_timer_tick() {
    // MB14.g — every CPU writes only its own counter + resched flag via
    // `current_cpu()`. `current_cpu()` reads `gs:[0]`, which the BSP set
    // in `init_gs_base` and every AP set in `kmain_ap` after `wrmsr`'ing
    // `IA32_GS_BASE`, so the lookup is constant-time and race-free.
    //
    // Before MB14.g this ISR wrote a single global `TICK_COUNT` static
    // and a single global `NEED_RESCHED` flag; MB14.f gated the AP path
    // with an `is_bsp()` early-return so APs would not race the BSP
    // writer. With MB14.g the per-CPU storage removes that hazard, and
    // the early-return is no longer required — every CPU now records
    // its own ticks for future per-CPU diagnostics + dispatch (the AP
    // dispatch loop itself lands in MB14.h).
    #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
    {
        let cpu = super::per_cpu::current_cpu();
        cpu.inc_tick();
        lapic_eoi();
        cpu.request_resched();
    }
    // Host / test build: no GS-base wiring, no real LAPIC. Fall back to
    // the legacy global flag so cargo-test can exercise the resched
    // trampoline contract without a `gs:[0]` load.
    #[cfg(not(all(feature = "bare-metal", target_os = "none", not(test))))]
    {
        lapic_eoi();
        crate::scheduling::NEED_RESCHED.store(true, core::sync::atomic::Ordering::Release);
    }
}

/// Tail-of-interrupt trampoline: if the LAPIC tick requested a resched
/// on this CPU, run the cooperative `yield_current` path so the next
/// task is on-CPU before the `iretq` restores the trap frame.
///
/// Re-entrancy / cross-CPU concurrency (MB14.h.2):
///
/// - **Per-CPU recursion guard.** On bare-metal MP each CPU consults its
///   own `PerCpu::enter_scheduler` flag; a tick that arrives while the
///   same CPU is mid-yield (e.g. a cooperative `TaskYield` syscall still
///   on the stack) short-circuits without touching `SCHEDULER`.
/// - **Cross-CPU lock.** Even if both BSP and an AP pass their per-CPU
///   guard simultaneously, `scheduling::try_acquire_sched_lock` ensures
///   exactly one CPU enters the `yield_current` body at a time; the
///   other returns and retries on its next tick.
/// - **Host fallback.** The legacy global `IN_SCHEDULER` / `NEED_RESCHED`
///   path remains active on `target_os = "linux"` test builds where
///   `current_cpu()` collapses to `&BSP` and a single mutex would
///   serialise just as effectively.
// The early-return guard at the top is `return;` followed by the unsafe
// block; on host builds (`target_os = "linux"`) the unsafe block is
// `#[cfg]`-ed out, so `return;` becomes the last statement and clippy
// flags it as needless. The early return is the intended IRQ-tail
// pattern (read flags, leave if nothing to do), keep it.
#[allow(clippy::needless_return)]
#[unsafe(no_mangle)]
extern "C" fn kernel_check_need_resched() {
    // MB14.g + MB14.h.2 — consume the per-CPU resched flag set by
    // `kernel_lapic_timer_tick` running on this same CPU, then take
    // the per-CPU recursion guard. AP branch dispatches through
    // `kernel_ap_dispatch_observe` which now performs a live
    // `yield_current` under `SCHED_LOCK` (MB14.h.2 promotion of the
    // MB14.h.1 observer; see ADR-0010 § Decision).
    #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
    {
        let cpu = super::per_cpu::current_cpu();
        if !cpu.take_resched() {
            return;
        }
        if !cpu.is_bsp() {
            // MB14.h.2 — AP live dispatcher: takes per-CPU
            // `in_scheduler` + cross-CPU `SCHED_LOCK`, runs
            // `SCHEDULER.yield_current` with TSS.rsp0 routed via
            // `set_rsp0_for_cpu`, then releases both. The
            // `dispatch_observations` counter still bumps for
            // diagnostics (BSP boot smoke + future regressions).
            super::ap_dispatch::kernel_ap_dispatch_observe();
            return;
        }
        // BSP cooperative path. Use the per-CPU recursion guard so a
        // future bare-metal flow that yields the BSP from a syscall
        // handler (e.g. an IPC-block path that hits a timer tick mid-
        // syscall) cannot recurse.
        if !cpu.enter_scheduler() {
            return;
        }
        // Cross-CPU lock — another CPU's yield may be in flight on
        // SCHEDULER even though our per-CPU guard is clear.
        if !crate::scheduling::try_acquire_sched_lock() {
            cpu.leave_scheduler();
            return;
        }
    }

    // Host / test build: stay on the legacy global static so existing
    // unit tests continue to pin the trampoline contract. Bare-metal
    // builds short-circuit above and never reach this branch.
    #[cfg(not(all(feature = "bare-metal", target_os = "none", not(test))))]
    {
        use core::sync::atomic::Ordering;
        if !crate::scheduling::NEED_RESCHED.swap(false, Ordering::AcqRel)
            || crate::scheduling::IN_SCHEDULER.load(Ordering::Acquire)
        {
            return;
        }
    }

    // SAFETY: BSP at the moment of this call holds both its per-CPU
    // `in_scheduler` guard AND the global `SCHED_LOCK` (MB14.h.2). The
    // AP cooperative path arrives via `kernel_ap_dispatch_observe`
    // which takes the same pair before invoking `yield_current`, so
    // `SCHEDULER` is single-mutator for the duration of this block.
    #[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
    unsafe {
        use crate::scheduling::Scheduler;
        let sched = &mut *core::ptr::addr_of_mut!(crate::SCHEDULER);
        if let Some(cur) = sched.current_task_id() {
            let _ = sched.yield_current(cur, crate::scheduling::TaskState::Runnable);
        }
        crate::scheduling::release_sched_lock();
        super::per_cpu::current_cpu().leave_scheduler();
    }
}

// =============================================================================
// MB14.f host-side tests (mode-detection only — MSR + MMIO writes are
// ring-0 and stay out of reach on a userspace test binary)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lapic_mode_variants_compare_independently() {
        // Pin the two-variant enum so a future expansion is a deliberate
        // surface change visible in `cargo test`.
        assert_ne!(LapicMode::XApic, LapicMode::X2Apic);
        assert_eq!(LapicMode::XApic, LapicMode::XApic);
    }

    #[test]
    fn x2apic_msr_addresses_match_intel_sdm_table_10_6() {
        // Pin every MSR constant against Intel SDM Vol 3A Table 10-6.
        // A typo here would silently send an EOI to (e.g.) the LVT
        // Thermal Sensor MSR; trapping the divergence in CI surfaces
        // such regressions instead of waiting for a runtime fault.
        assert_eq!(MSR_X2APIC_APICID, 0x802);
        assert_eq!(MSR_X2APIC_TPR, 0x808);
        assert_eq!(MSR_X2APIC_EOI, 0x80B);
        assert_eq!(MSR_X2APIC_SIVR, 0x80F);
        assert_eq!(MSR_X2APIC_ICR, 0x830);
        assert_eq!(MSR_X2APIC_LVT_TIMER, 0x832);
        assert_eq!(MSR_X2APIC_TIMER_ICR, 0x838);
        assert_eq!(MSR_X2APIC_TIMER_DCR, 0x83E);
    }

    #[test]
    fn apic_base_msr_layout_matches_intel_sdm() {
        // Bit 10 = x2APIC enable, bit 11 = global enable. Pin both so a
        // refactor does not flip them.
        assert_eq!(MSR_IA32_APIC_BASE, 0x1B);
        assert_eq!(APIC_BASE_X2APIC_ENABLE, 1 << 10);
        assert_eq!(APIC_BASE_GLOBAL_ENABLE, 1 << 11);
    }

    #[test]
    fn x2apic_mode_flag_defaults_to_xapic_before_init() {
        // The global `X2APIC_MODE` flag starts cleared; `lapic_init`
        // is the only writer. On host tests it is never called, so the
        // flag must read `false` — otherwise an unrelated bare-metal
        // path could accidentally trigger an MSR read in a userspace
        // test binary (which would `#GP`).
        assert!(!is_x2apic_enabled());
    }

    #[test]
    fn xapic_mmio_offsets_pinned_against_intel_sdm_table_10_1() {
        // Pin the MMIO offsets the BSP path still uses.
        assert_eq!(LAPIC_ID, 0x20);
        assert_eq!(LAPIC_TPR, 0x80);
        assert_eq!(LAPIC_EOI, 0xB0);
        assert_eq!(LAPIC_SIVR, 0xF0);
        assert_eq!(LAPIC_ICR_LO, 0x300);
        assert_eq!(LAPIC_ICR_HI, 0x310);
        assert_eq!(LAPIC_LVT_TIMER, 0x320);
        assert_eq!(LAPIC_TIMER_ICR, 0x380);
        assert_eq!(LAPIC_TIMER_DCR, 0x3E0);
    }

    #[test]
    fn x2apic_msr_offsets_match_mmio_via_canonical_shift() {
        // Intel SDM Vol 3A § 10.12.1.2 spec: x2APIC MSR = `0x800 +
        // (mmio_offset >> 4)`. Pin the algebraic relation so any
        // future MSR addition cannot drift.
        let shift = |mmio: u32| 0x800 + (mmio >> 4);
        assert_eq!(MSR_X2APIC_APICID, shift(LAPIC_ID));
        assert_eq!(MSR_X2APIC_TPR, shift(LAPIC_TPR));
        assert_eq!(MSR_X2APIC_EOI, shift(LAPIC_EOI));
        assert_eq!(MSR_X2APIC_SIVR, shift(LAPIC_SIVR));
        // ICR low dword shares the MMIO base (high dword fused into MSR).
        assert_eq!(MSR_X2APIC_ICR, shift(LAPIC_ICR_LO));
        assert_eq!(MSR_X2APIC_LVT_TIMER, shift(LAPIC_LVT_TIMER));
        assert_eq!(MSR_X2APIC_TIMER_ICR, shift(LAPIC_TIMER_ICR));
        assert_eq!(MSR_X2APIC_TIMER_DCR, shift(LAPIC_TIMER_DCR));
    }
}
