//! Task State Segment (`TSS`) for `x86_64` long mode (MB11 + MB13.h +
//! MB14.c.2.d).
//!
//! MB14.c.2.d extends the single BSP `TSS` with a sibling `AP_TSS` array
//! indexed by `cpu_id - 1`. Each AP gets its own `Tss` plus dedicated
//! IST1 / IST2 stack tops (caller-supplied physical/virtual addresses —
//! they live in dynamically-allocated frames, not `.bss`, to keep the
//! kernel image small under `MAX_CPUS = 32`).
//!
//! In long mode the TSS no longer holds full task state for hardware
//! task switching (the feature is unavailable in 64-bit mode). It does
//! still serve two essential roles:
//!
//! 1. **`rsp0`** — the kernel stack pointer the CPU loads when a Ring 3
//!    → Ring 0 privilege transition happens via an interrupt or
//!    exception. Without a valid `rsp0`, a #PF arriving while user code
//!    is executing would land on the user stack and likely fault again.
//! 2. **`ist1..ist7`** — Interrupt Stack Table entries: per-vector
//!    dedicated kernel stacks used when the corresponding IDT entry's
//!    IST field is non-zero. MB13.h wires IST1 to `#DF` and IST2 to
//!    `#PF` so that a stack-related fault (the post-iretq stall root
//!    cause) lands on a known-good kernel stack instead of cascading
//!    silently to a triple fault.
//!
//! ## Init order (MB13.h)
//!
//! `kmain` must call, in this exact order:
//!
//! 1. [`super::gdt::gdt_init`] — populates the TSS descriptor in GDT
//!    slots 5+6.
//! 2. [`init_ist_stacks`] — fills `TSS.ist1` / `TSS.ist2` with the top
//!    pointers of the two static IST stacks.
//! 3. [`ltr_load`] — issues `ltr 0x28` so the CPU's task register
//!    points at the static TSS. Without this step, a Ring 3 → Ring 0
//!    transition cannot resolve `TSS.rsp0` and cascades to triple
//!    fault. This was the root cause of the MB13.f post-iretq stall.
//! 4. [`super::idt::idt_init`] — installs the IDT entries; #DF uses
//!    IST=1, #PF uses IST=2.

#![allow(unsafe_code, reason = "static mut TSS + ltr asm; SAFETY per init fn")]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

/// `x86_64` TSS layout per Intel SDM Vol 3A §7.7. 104 bytes packed.
#[repr(C, packed)]
pub struct Tss {
    reserved0: u32,
    /// Ring 0 kernel stack pointer. CPU loads this on Ring 3 → Ring 0
    /// transition via interrupt/exception.
    pub rsp0: u64,
    /// Ring 1 stack pointer (unused in long mode but field is reserved).
    pub rsp1: u64,
    /// Ring 2 stack pointer (unused in long mode but field is reserved).
    pub rsp2: u64,
    reserved1: u64,
    /// Interrupt Stack Table entry 1 — dedicated stack for #DF.
    pub ist1: u64,
    /// Interrupt Stack Table entry 2 — dedicated stack for #PF.
    pub ist2: u64,
    /// Interrupt Stack Table entry 3 (reserved for future use).
    pub ist3: u64,
    /// Interrupt Stack Table entry 4 (reserved for future use).
    pub ist4: u64,
    /// Interrupt Stack Table entry 5 (reserved for future use).
    pub ist5: u64,
    /// Interrupt Stack Table entry 6 (reserved for future use).
    pub ist6: u64,
    /// Interrupt Stack Table entry 7 (reserved for future use).
    pub ist7: u64,
    reserved2: u64,
    reserved3: u16,
    /// I/O permission bitmap base — set to `sizeof(Tss)` (104) to
    /// indicate that there is no I/O bitmap.
    pub iomap_base: u16,
}

impl Tss {
    /// Construct an all-zero TSS with `iomap_base` set to 104 (the
    /// canonical "no I/O bitmap" value).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved1: 0,
            ist1: 0,
            ist2: 0,
            ist3: 0,
            ist4: 0,
            ist5: 0,
            ist6: 0,
            ist7: 0,
            reserved2: 0,
            reserved3: 0,
            iomap_base: 104,
        }
    }
}

impl Default for Tss {
    fn default() -> Self {
        Self::new()
    }
}

/// Single, global, ring-0 TSS. MB11 is single-CPU; MP will introduce
/// per-CPU TSS arrays in a future milestone.
#[unsafe(no_mangle)]
static mut TSS: Tss = Tss::new();

/// Size of each IST stack (16 KiB). Sized to match the regular kernel
/// stack (`scheduling::KERNEL_STACK_SIZE`) so a fault handler has the
/// same headroom as the normal kernel-mode path.
pub const IST_STACK_SIZE: usize = 16 * 1024;

/// 16-byte aligned static IST stack buffer. Lives in the kernel image
/// `.bss` so it is mapped by the bootloader and remains valid across
/// every per-process CR3 reload (kernel half is shared by reference
/// via `AddressSpace::new_with_kernel_half`).
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

/// IST stack dedicated to #DF (Double Fault). Wired via [`init_ist_stacks`].
#[unsafe(no_mangle)]
static mut IST1_STACK: IstStack = IstStack([0; IST_STACK_SIZE]);

/// IST stack dedicated to #PF (Page Fault). Wired via [`init_ist_stacks`].
#[unsafe(no_mangle)]
static mut IST2_STACK: IstStack = IstStack([0; IST_STACK_SIZE]);

/// Populate `TSS.ist1` / `TSS.ist2` with the top-of-stack pointers of
/// the two static IST buffers (MB13.h).
///
/// The CPU treats the IST field of an IDT entry as a 1-based index into
/// `TSS.ist1..ist7`; when non-zero it overrides the normal `rsp0`
/// kernel-stack lookup on Ring 3 → Ring 0 transition for that specific
/// vector. This is the only reliable way to handle a stack-related
/// fault (e.g., the post-iretq stall root cause where `rsp0` itself
/// points to an unmapped page after a CR3 reload).
///
/// Must be called once at boot AFTER [`super::gdt::gdt_init`] and
/// BEFORE [`ltr_load`].
pub fn init_ist_stacks() {
    // SAFETY: single-core init; TSS + IST stacks are not aliased by
    // any other code path at this point. We compute the
    // one-past-the-end address of each buffer (legal as a u64 pointer
    // value) and store it in the corresponding TSS slot.
    unsafe {
        let tss_p = core::ptr::addr_of_mut!(TSS);
        let ist1_base = core::ptr::addr_of!(IST1_STACK) as u64;
        let ist2_base = core::ptr::addr_of!(IST2_STACK) as u64;
        (*tss_p).ist1 = ist1_base + IST_STACK_SIZE as u64;
        (*tss_p).ist2 = ist2_base + IST_STACK_SIZE as u64;
    }
}

/// Read-back helper for tests / diagnostics.
#[must_use]
pub fn current_ist1() -> u64 {
    // SAFETY: single-core; read of u64 field via raw pointer.
    unsafe {
        let p = core::ptr::addr_of!(TSS);
        (*p).ist1
    }
}

/// Read-back helper for tests / diagnostics.
#[must_use]
pub fn current_ist2() -> u64 {
    // SAFETY: single-core; read of u64 field via raw pointer.
    unsafe {
        let p = core::ptr::addr_of!(TSS);
        (*p).ist2
    }
}

/// Set the kernel-stack pointer the CPU loads on Ring 3 → Ring 0
/// privilege transitions (interrupts / exceptions from user mode).
///
/// Must be called by the scheduler on every context switch into a
/// user-process task, with `rsp0` set to the top of that process's
/// kernel stack.
///
/// This writes the **BSP** TSS only. MP builds must route through
/// [`set_rsp0_for_cpu`] instead so each CPU updates its own TSS sibling.
#[cfg(target_arch = "x86_64")]
pub fn set_rsp0(rsp0: u64) {
    // SAFETY: single-core; TSS is not aliased; raw pointer write.
    unsafe {
        let p = core::ptr::addr_of_mut!(TSS);
        (*p).rsp0 = rsp0;
    }
}

/// Stub for non-x86_64 host builds.
#[cfg(not(target_arch = "x86_64"))]
pub fn set_rsp0(_rsp0: u64) {}

/// MB14.h.2 — set `rsp0` on the TSS belonging to `cpu_id`.
///
/// Routes BSP (`cpu_id == 0`) to [`set_rsp0`] (the static `TSS`
/// referenced by `ltr 0x28`); APs (`cpu_id >= 1`) to their sibling
/// slot in `AP_TSS`. The AP `ltr` selector installed by `kmain_ap`
/// references the per-AP descriptor minted in `gdt::gdt_set_ap_tss`,
/// so writing into `AP_TSS[cpu_id - 1]` reaches the TSS the AP CPU
/// actually consults on Ring 3 → Ring 0 transitions.
///
/// Out-of-range `cpu_id` returns `false` without writing; the BSP /
/// any-CPU caller can use this as a recoverable signal that a future
/// regression of the AP enrolment path slipped past `register_ap`.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn set_rsp0_for_cpu(cpu_id: u32, rsp0: u64) -> bool {
    if cpu_id == 0 {
        set_rsp0(rsp0);
        return true;
    }
    let Some(idx) = (cpu_id as usize).checked_sub(1) else {
        return false;
    };
    if idx >= MAX_AP_SLOTS {
        return false;
    }
    // SAFETY: each AP slot is single-writer in normal operation —
    // the AP itself updates its own slot from within its own
    // cooperative `yield_current` path, and the BSP pre-fire phase
    // wrote rsp0 once before the AP came online. The `SCHED_LOCK`
    // taken by the cooperative path serialises any cross-CPU
    // intervention; idx < MAX_AP_SLOTS is checked above.
    unsafe {
        let p = core::ptr::addr_of_mut!(AP_TSS);
        let slot = (*p).as_mut_ptr().add(idx);
        (*slot).rsp0 = rsp0;
    }
    true
}

/// Stub for non-x86_64 host builds.
#[cfg(not(target_arch = "x86_64"))]
#[must_use]
pub fn set_rsp0_for_cpu(_cpu_id: u32, _rsp0: u64) -> bool {
    true
}

/// TSS GDT selector — slot 5 with RPL=0 = `0x28`.
pub const TSS_SELECTOR: u16 = 0x28;

/// Compute the two 8-byte words that encode a 64-bit TSS descriptor at
/// GDT slots `[slot, slot+1]`.
///
/// Per Intel SDM Vol 3A §7.2.3:
/// - Low word: limit\[15:0\], base\[15:0\], base\[23:16\], type=0x9
///   (available 64-bit TSS), S=0, DPL=0, P=1, limit\[19:16\], G=0,
///   base\[31:24\].
/// - High word: base\[63:32\], reserved.
#[must_use]
pub fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    let limit_lo = u64::from(limit) & 0xFFFF;
    let limit_hi = (u64::from(limit) >> 16) & 0xF;
    let base_lo = base & 0xFFFF;
    let base_mid = (base >> 16) & 0xFF;
    let base_mid_hi = (base >> 24) & 0xFF;
    let base_hi = base >> 32;
    // Access byte 0x89 = P=1, DPL=00, S=0, type=0x9 (avail. 64-bit TSS).
    // Flags nibble bits 52..56 = 0 (G=0).
    let low = limit_lo
        | (base_lo << 16)
        | (base_mid << 32)
        | (0x89_u64 << 40)
        | (limit_hi << 48)
        | (base_mid_hi << 56);
    let high = base_hi;
    (low, high)
}

/// Build the (low, high) TSS descriptor words for the static `TSS`.
#[must_use]
pub fn tss_descriptor_for_static() -> (u64, u64) {
    let base = core::ptr::addr_of!(TSS) as u64;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "sizeof(Tss) = 104 fits u32 trivially"
    )]
    let limit = (core::mem::size_of::<Tss>() - 1) as u32;
    tss_descriptor(base, limit)
}

/// Issue `ltr <selector>` to install the TSS as the current task
/// register. Called once at boot after `lgdt`.
#[cfg(target_arch = "x86_64")]
pub fn ltr_load() {
    // SAFETY: ltr is privileged but legal at CPL=0; selector points to
    // a present TSS descriptor in the current GDT.
    unsafe {
        asm!("ltr {sel:x}", sel = in(reg) TSS_SELECTOR, options(nostack, preserves_flags));
    }
}

/// Stub for non-x86_64 host builds.
#[cfg(not(target_arch = "x86_64"))]
pub fn ltr_load() {}

// =========================================================================
// MB14.c.2.d — Application Processor TSS sibling array.
// =========================================================================

use super::per_cpu::MAX_AP_SLOTS;

/// `MAX_AP_SLOTS` TSS instances, one per `cpu_id` in `1..MAX_CPUS`. The
/// BSP keeps using the legacy [`TSS`] static so existing call sites
/// continue to work byte-for-byte.
///
/// Each AP slot is zero-initialised; the BSP calls [`init_ap_tss`] pre-fire
/// to populate `rsp0` + `ist1` + `ist2` for the corresponding AP.
#[unsafe(no_mangle)]
static mut AP_TSS: [Tss; MAX_AP_SLOTS] = [const { Tss::new() }; MAX_AP_SLOTS];

/// MB14.c.2.d — populate the TSS for AP `cpu_id` (must be in `1..MAX_CPUS`).
///
/// `rsp0` is the top of the per-AP kernel stack (loaded on Ring 3 → Ring 0
/// transitions); `ist1_top` / `ist2_top` are the tops of the per-AP IST1
/// / IST2 stacks (loaded by `#DF` / `#PF` respectively, per MB13.h).
///
/// Returns `false` if `cpu_id` is out of range (0 or `>= MAX_CPUS`).
/// On success the BSP must read [`ap_tss_addr`] to obtain the TSS base
/// address for the GDT descriptor.
pub fn init_ap_tss(cpu_id: u32, rsp0: u64, ist1_top: u64, ist2_top: u64) -> bool {
    let Some(idx) = (cpu_id as usize).checked_sub(1) else {
        return false;
    };
    if idx >= MAX_AP_SLOTS {
        return false;
    }
    // SAFETY: single-core pre-fire wiring; the AP for this slot has
    // not been signalled yet (BSP is still in INIT-SIPI pre-amble),
    // so the slot is exclusively owned by the BSP.
    unsafe {
        let p = core::ptr::addr_of_mut!(AP_TSS);
        // `idx < MAX_AP_SLOTS` guaranteed above.
        let slot = (*p).as_mut_ptr().add(idx);
        (*slot).rsp0 = rsp0;
        (*slot).ist1 = ist1_top;
        (*slot).ist2 = ist2_top;
    }
    true
}

/// MB14.c.2.d — virtual address of the AP TSS for `cpu_id`. Used by the
/// GDT descriptor builder ([`tss_descriptor`]) and by host-side tests.
///
/// Returns `0` if `cpu_id` is out of range.
#[must_use]
pub fn ap_tss_addr(cpu_id: u32) -> u64 {
    let Some(idx) = (cpu_id as usize).checked_sub(1) else {
        return 0;
    };
    if idx >= MAX_AP_SLOTS {
        return 0;
    }
    // SAFETY: addr_of! does not deref; we just compute the address.
    unsafe {
        let p = core::ptr::addr_of!(AP_TSS);
        (*p).as_ptr().add(idx) as u64
    }
}

/// MB14.c.2.d — read-back of `AP_TSS[cpu_id - 1].rsp0` for tests.
///
/// Returns `0` for out-of-range `cpu_id` (BSP or beyond `MAX_CPUS`).
#[must_use]
pub fn ap_tss_rsp0(cpu_id: u32) -> u64 {
    let Some(idx) = (cpu_id as usize).checked_sub(1) else {
        return 0;
    };
    if idx >= MAX_AP_SLOTS {
        return 0;
    }
    // SAFETY: read of u64 field via raw pointer; AP_TSS is `static mut`
    // but each per-AP slot is single-writer (BSP pre-fire) + single-reader
    // (the AP after CR3 switch, or this read-back for tests).
    unsafe {
        let p = core::ptr::addr_of!(AP_TSS);
        (*(*p).as_ptr().add(idx)).rsp0
    }
}

/// Read-back of `AP_TSS[cpu_id - 1].ist1` for tests.
#[must_use]
pub fn ap_tss_ist1(cpu_id: u32) -> u64 {
    let Some(idx) = (cpu_id as usize).checked_sub(1) else {
        return 0;
    };
    if idx >= MAX_AP_SLOTS {
        return 0;
    }
    // SAFETY: same as `ap_tss_rsp0`.
    unsafe {
        let p = core::ptr::addr_of!(AP_TSS);
        (*(*p).as_ptr().add(idx)).ist1
    }
}

/// Read-back of `AP_TSS[cpu_id - 1].ist2` for tests.
#[must_use]
pub fn ap_tss_ist2(cpu_id: u32) -> u64 {
    let Some(idx) = (cpu_id as usize).checked_sub(1) else {
        return 0;
    };
    if idx >= MAX_AP_SLOTS {
        return 0;
    }
    // SAFETY: same as `ap_tss_rsp0`.
    unsafe {
        let p = core::ptr::addr_of!(AP_TSS);
        (*(*p).as_ptr().add(idx)).ist2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_size_is_104_bytes() {
        assert_eq!(core::mem::size_of::<Tss>(), 104);
    }

    #[test]
    fn iomap_base_equals_104() {
        let t = Tss::new();
        let iomap = t.iomap_base;
        assert_eq!(iomap, 104);
    }

    #[test]
    fn tss_selector_is_0x28() {
        assert_eq!(TSS_SELECTOR, 0x28);
    }

    #[test]
    fn descriptor_access_byte_is_0x89() {
        let (low, _high) = tss_descriptor(0xDEAD_BEEF_CAFE_F00D, 103);
        let access = (low >> 40) & 0xFF;
        assert_eq!(access, 0x89);
    }

    #[test]
    fn descriptor_limit_encoded() {
        let (low, _high) = tss_descriptor(0, 103);
        let limit_lo = low & 0xFFFF;
        let limit_hi = (low >> 48) & 0xF;
        assert_eq!(limit_lo, 103);
        assert_eq!(limit_hi, 0);
    }

    /// MB13.h — IST stacks must be 16 KiB to match the regular kernel
    /// stack size and give the #DF / #PF handlers the same headroom.
    #[test]
    fn ist_stack_size_is_16_kib() {
        assert_eq!(IST_STACK_SIZE, 16 * 1024);
    }

    /// MB13.h — `init_ist_stacks` writes non-zero, distinct top-of-stack
    /// values into TSS.ist1 / TSS.ist2. The values must equal
    /// `base + IST_STACK_SIZE` so the CPU's pre-decrement push lands
    /// inside the buffer.
    #[test]
    fn init_ist_stacks_writes_top_of_each_buffer() {
        init_ist_stacks();
        let ist1 = current_ist1();
        let ist2 = current_ist2();
        assert_ne!(ist1, 0);
        assert_ne!(ist2, 0);
        assert_ne!(ist1, ist2);
        let ist1_base = core::ptr::addr_of!(IST1_STACK) as u64;
        let ist2_base = core::ptr::addr_of!(IST2_STACK) as u64;
        assert_eq!(ist1, ist1_base + IST_STACK_SIZE as u64);
        assert_eq!(ist2, ist2_base + IST_STACK_SIZE as u64);
    }

    // -----------------------------------------------------------------
    // MB14.c.2.d — AP TSS sibling array.
    // -----------------------------------------------------------------

    /// `init_ap_tss(0, _, _, _)` rejects BSP cpu_id.
    #[test]
    fn init_ap_tss_rejects_bsp_cpu_id() {
        assert!(!init_ap_tss(0, 0x1000, 0x2000, 0x3000));
    }

    /// `init_ap_tss` for a valid cpu_id writes rsp0 / ist1 / ist2.
    #[test]
    fn init_ap_tss_populates_rsp0_and_ist_slots() {
        // Use cpu_id == 1 — single-writer pre-fire semantics, so a
        // shared test-host run sees the most recent write.
        let rsp0 = 0xFFFF_C001_DEAD_BEEF;
        let ist1 = 0xFFFF_C002_CAFE_0001;
        let ist2 = 0xFFFF_C002_CAFE_0002;
        assert!(init_ap_tss(1, rsp0, ist1, ist2));
        assert_eq!(ap_tss_rsp0(1), rsp0);
        assert_eq!(ap_tss_ist1(1), ist1);
        assert_eq!(ap_tss_ist2(1), ist2);
    }

    /// `ap_tss_addr` returns distinct addresses for distinct cpu_ids
    /// (the array stride is `sizeof(Tss)` = 104 bytes).
    #[test]
    fn ap_tss_addr_strides_by_tss_size() {
        let a = ap_tss_addr(1);
        let b = ap_tss_addr(2);
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_eq!(b - a, core::mem::size_of::<Tss>() as u64);
    }

    /// `ap_tss_addr(0)` is 0 — the BSP uses the legacy single static.
    #[test]
    fn ap_tss_addr_zero_for_bsp() {
        assert_eq!(ap_tss_addr(0), 0);
    }

    // -----------------------------------------------------------------
    // MB14.h.2 — set_rsp0_for_cpu cross-CPU TSS write helper.
    // -----------------------------------------------------------------

    /// `set_rsp0_for_cpu(0, _)` delegates to the BSP `set_rsp0` and
    /// returns true. Read-back via [`current_rsp0`].
    #[test]
    fn set_rsp0_for_cpu_zero_writes_bsp_tss() {
        let rsp = 0xFFFF_C000_0000_BEEF;
        assert!(set_rsp0_for_cpu(0, rsp));
        // Read-back: the BSP TSS lives in the static `TSS`.
        // SAFETY: single-core test, raw read of u64.
        let observed = unsafe {
            let p = core::ptr::addr_of!(TSS);
            (*p).rsp0
        };
        assert_eq!(observed, rsp);
    }

    /// `set_rsp0_for_cpu(k, _)` for valid k writes AP_TSS[k-1].rsp0
    /// without disturbing the BSP TSS.
    #[test]
    fn set_rsp0_for_cpu_ap_writes_sibling_slot() {
        // Snapshot BSP rsp0 first so a cross-test interleave does not
        // false-flag a delta caused by another test's set_rsp0.
        // SAFETY: single-core test, raw read of u64.
        let bsp_before = unsafe {
            let p = core::ptr::addr_of!(TSS);
            (*p).rsp0
        };
        let rsp = 0xFFFF_C000_0001_F00D;
        assert!(set_rsp0_for_cpu(3, rsp));
        assert_eq!(ap_tss_rsp0(3), rsp);
        // SAFETY: same as above.
        let bsp_after = unsafe {
            let p = core::ptr::addr_of!(TSS);
            (*p).rsp0
        };
        // BSP slot is untouched by an AP-targeted call.
        assert_eq!(bsp_before, bsp_after);
    }

    /// Out-of-range cpu_id (>= MAX_CPUS) returns false and writes nothing.
    #[test]
    fn set_rsp0_for_cpu_out_of_range_returns_false() {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "MAX_CPUS = 32 fits u32 trivially; reject path"
        )]
        let oor = (MAX_AP_SLOTS as u32) + 1; // cpu_id one past the last AP slot.
        assert!(!set_rsp0_for_cpu(oor, 0xDEAD));
    }
}
