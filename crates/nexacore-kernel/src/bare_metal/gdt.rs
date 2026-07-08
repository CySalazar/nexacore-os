//! Kernel Global Descriptor Table (`GDT`) for `x86_64` long mode.
//!
//! Installs a 7-entry GDT under kernel control, replacing the
//! bootloader's temporary GDT. Layout per ADR-0004 § 1:
//!
//! | Slot | Selector | Contenuto             | Access | Flags | DPL |
//! |------|----------|-----------------------|--------|-------|-----|
//! | 0    | 0x00     | null                  | —      | —     | —   |
//! | 1    | 0x08     | kcode64               | 0x9B   | 0xA   | 0   |
//! | 2    | 0x10     | kdata64               | 0x93   | 0xC   | 0   |
//! | 3    | 0x18     | user-data placeholder | 0xF2   | 0xC   | 3   |
//! | 4    | 0x20     | ucode64               | 0xFA   | 0xA   | 3   |
//! | 5    | 0x28     | TSS low word          | (sys)  | 0x0   | 0   |
//! | 6    | —        | TSS high word         | —      | —     | —   |
//!
//! Selectors used by other subsystems:
//!
//! - `MSR_STAR[63:48] = 0x10` produces SYSRET q `CS = 0x10+16|3 = 0x23`
//!   (slot 4 = ucode64) and `SS = 0x10+8|3 = 0x1B` (slot 3 = user-data).
//! - `iretq` to Ring 3 pushes `CS = 0x23` and `SS = 0x1B`.
//! - `ltr 0x28` installs the static TSS in [`super::tss`].
//!
//! Call [`gdt_init`] once from `kmain` BEFORE [`super::tss::ltr_load`].

#![allow(
    unsafe_code,
    reason = "lgdt + segment-register loads via inline asm; SAFETY per call site"
)]
#![allow(
    clippy::cast_possible_truncation,
    reason = "GDT byte-size limit fits u16 by construction"
)]

// -----------------------------------------------------------------------------
// GDT entry descriptors (x86_64 long mode)
//
// Each entry is a u64 encoding:
//   [0:15]  limit low
//   [16:39] base low
//   [40:47] access byte (P, DPL, S, type)
//   [48:51] limit high
//   [52:55] flags (G, D/B, L, AVL)
//   [56:63] base high
//
// In 64-bit long mode, base and limit are ignored for code/data segments
// (flat model). Only the access byte and the L/D bits in flags matter.
// -----------------------------------------------------------------------------

/// 64-bit kernel code segment (DPL=0, L=1, D=0, G=1).
///
/// Access 0x9B = P=1, DPL=00, S=1, type=0xB (execute/read, A=1 pre-set).
/// Flags  0xA  = G=1, L=1, D/B=0, AVL=0.
#[cfg(target_arch = "x86_64")]
const KCODE64: u64 = 0x00AF_9B00_0000_FFFF;

/// Kernel data segment (DPL=0, G=1, D/B=1).
///
/// Access 0x93 = P=1, DPL=00, S=1, type=0x3 (read/write, A=1 pre-set).
/// Flags  0xC  = G=1, D/B=1, L=0, AVL=0.
#[cfg(target_arch = "x86_64")]
const KDATA64: u64 = 0x00CF_9300_0000_FFFF;

/// User data segment (DPL=3, G=1, D/B=1).
///
/// Access 0xF2 = P=1, DPL=11, S=1, type=0x2 (read/write, A=0).
/// Flags  0xC  = G=1, D/B=1, L=0, AVL=0.
///
/// Used as the SS selector for Ring 3 (selector 0x1B = slot 3 | RPL=3).
#[cfg(any(target_arch = "x86_64", test))]
const UDATA64: u64 = 0x00CF_F200_0000_FFFF;

/// 64-bit user code segment (DPL=3, L=1, D=0, G=1).
///
/// Access 0xFA = P=1, DPL=11, S=1, type=0xA (execute/read, A=0).
/// Flags  0xA  = G=1, L=1, D/B=0, AVL=0.
///
/// Used as the CS selector for Ring 3 (selector 0x23 = slot 4 | RPL=3).
#[cfg(any(target_arch = "x86_64", test))]
const UCODE64: u64 = 0x00AF_FA00_0000_FFFF;

/// Number of u64 slots in the GDT.
///
/// MB14.c.2.d extends the layout from 7 slots (BSP-only) to
/// `7 + 2 * MAX_AP_SLOTS`. Slots 5+6 still host the BSP TSS descriptor;
/// each AP `cpu_id k >= 1` claims slots `7 + 2*(k-1)..=7 + 2*(k-1) + 1`
/// for its own TSS descriptor. With `MAX_AP_SLOTS = 31` the GDT has 69
/// u64 entries (552 bytes — comfortably under the 64 KiB `lgdt` limit).
const GDT_LEN: usize = 7 + 2 * super::per_cpu::MAX_AP_SLOTS;

/// GDT slots. Slots 5+6 are filled in by `gdt_init` from the static TSS.
/// MB14.c.2.d AP TSS descriptors land via [`gdt_set_ap_tss`].
#[unsafe(no_mangle)]
static mut GDT: [u64; GDT_LEN] = [0; GDT_LEN];

/// User code segment selector (slot 4, RPL=3). Loaded into `CS` by the
/// `iretq` Ring 3 trampoline.
pub const USER_CS: u16 = 0x23;

/// User data segment selector (slot 3, RPL=3). Loaded into `SS` by the
/// `iretq` Ring 3 trampoline.
pub const USER_SS: u16 = 0x1B;

/// Kernel code segment selector (slot 1, RPL=0).
pub const KERNEL_CS: u16 = 0x08;

/// Kernel data segment selector (slot 2, RPL=0).
pub const KERNEL_SS: u16 = 0x10;

/// `MSR_STAR[63:48]` value that yields `SYSRET q` `CS = USER_CS = 0x23`
/// and `SS = USER_SS = 0x1B`. Derived from the SDM arithmetic
/// `CS = base + 16 | 3`, `SS = base + 8 | 3`.
pub const STAR_USER_BASE: u16 = 0x10;

/// `MSR_STAR[47:32]` value that yields `SYSCALL` `CS = KERNEL_CS = 0x08`
/// and `SS = KERNEL_SS = 0x10`. Derived from the SDM arithmetic
/// `CS = base`, `SS = base + 8`.
pub const STAR_KERNEL_BASE: u16 = 0x08;

/// GDTR pseudo-descriptor: 2-byte limit + 8-byte base (10 bytes, packed).
#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct Gdtr {
    limit: u16,
    base: u64,
}

/// Installs the kernel GDT and reloads all segment registers.
///
/// Must be called once from `kmain` before interrupts or any other
/// subsystem that depends on segment registers. Safe to call on the
/// existing stack; does not touch the heap.
///
/// # Order
///
/// `gdt_init` must precede [`super::tss::ltr_load`] (the TSS descriptor
/// at slots 5+6 must be in place before `ltr 0x28` executes).
///
/// # Segment selectors after return
///
/// | Segment | Selector  |
/// |---------|-----------|
/// | CS      | `0x08`    |
/// | DS/ES/SS| `0x10`    |
/// | FS/GS   | `0x00`    |
#[cfg(target_arch = "x86_64")]
pub fn gdt_init() {
    use core::arch::asm;

    // Populate the GDT entries. Slot 5+6 = TSS descriptor (low+high).
    let (tss_low, tss_high) = super::tss::tss_descriptor_for_static();
    // SAFETY: single-core init; GDT is not aliased.
    unsafe {
        let p = core::ptr::addr_of_mut!(GDT);
        (*p)[0] = 0;
        (*p)[1] = KCODE64;
        (*p)[2] = KDATA64;
        (*p)[3] = UDATA64;
        (*p)[4] = UCODE64;
        (*p)[5] = tss_low;
        (*p)[6] = tss_high;
    }

    let gdtr = Gdtr {
        // SAFETY: GDT has 7 u64 entries → limit = 7*8-1 = 55. Use raw
        // pointer to avoid taking a reference to a mutable static.
        limit: (GDT_LEN * core::mem::size_of::<u64>() - 1) as u16,
        // SAFETY: &raw GDT is a valid non-null pointer for the lifetime
        // of the kernel.
        base: core::ptr::addr_of!(GDT) as u64,
    };

    // SAFETY: Ring-0 bare-metal. `lgdt` and segment-register moves are
    // privileged but legal at CPL=0. The GDT we install is valid for
    // 64-bit long mode (L=1 code segments, flat data). We skip the
    // far-return CS reload because the bootloader uses the identical CS
    // selector (0x08) with the same attributes; the processor's cached
    // CS descriptor remains correct without an explicit flush.
    unsafe {
        asm!(
            // 1. Load our GDT.
            "lgdt [{gdtr}]",
            // 2. Reload data segments with kernel data selector (0x10).
            "mov {ds:e}, 0x10",
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov ss, {ds:x}",
            // 3. Null out FS and GS (no thread-local storage yet).
            "xor {ds:e}, {ds:e}",
            "mov fs, {ds:x}",
            "mov gs, {ds:x}",
            gdtr = in(reg) core::ptr::addr_of!(gdtr) as u64,
            ds   = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// No-op stub for non-x86_64 hosts (host unit-test builds on ARM, etc.).
#[cfg(not(target_arch = "x86_64"))]
pub fn gdt_init() {}

// =====================================================================
// MB14.c.2.d — per-CPU TSS descriptor placement + selector arithmetic.
// =====================================================================

/// First u64 slot index reserved for an AP TSS descriptor.
///
/// BSP occupies slots 5..=6; AP `cpu_id=1` starts at slot 7.
const AP_TSS_FIRST_SLOT: usize = 7;

/// Number of u64 slots a single 64-bit TSS descriptor occupies in the
/// GDT (high + low words).
const TSS_DESCRIPTOR_SLOTS: usize = 2;

/// MB14.c.2.d — compute the GDT selector for the TSS belonging to
/// logical CPU `cpu_id`.
///
/// BSP (`cpu_id = 0`) yields the legacy [`super::tss::TSS_SELECTOR`]
/// (`0x28`); every AP yields a unique selector derived from
/// `AP_TSS_FIRST_SLOT + 2 * (cpu_id - 1)`.
///
/// Returns `0` (the null selector — always rejected by `ltr`) when
/// `cpu_id >= MAX_CPUS` so callers can pattern-match on a sentinel
/// without separate error plumbing.
#[must_use]
pub fn tss_selector_for_cpu(cpu_id: u32) -> u16 {
    if cpu_id == 0 {
        return super::tss::TSS_SELECTOR;
    }
    let Some(off) = (cpu_id as usize).checked_sub(1) else {
        return 0;
    };
    if off >= super::per_cpu::MAX_AP_SLOTS {
        return 0;
    }
    let slot = AP_TSS_FIRST_SLOT + TSS_DESCRIPTOR_SLOTS * off;
    // selector = slot * 8 (RPL=0).
    #[allow(
        clippy::cast_possible_truncation,
        reason = "MAX_AP_SLOTS=31 → max slot 67 → selector 67*8=0x218, fits u16 trivially"
    )]
    let sel = (slot as u16) << 3;
    sel
}

/// MB14.c.2.d — write the TSS descriptor for AP `cpu_id` into the
/// kernel GDT.
///
/// `tss_base` is the linear address of the per-AP TSS (e.g. via
/// [`super::tss::ap_tss_addr`]); the limit is fixed at
/// `sizeof(Tss) - 1`. Returns `false` for invalid `cpu_id` (0 or
/// `>= MAX_CPUS`).
///
/// Must be called BEFORE the AP fires INIT-SIPI — once the AP issues
/// `ltr <sel>` against this slot, the descriptor is observed live.
#[allow(
    clippy::indexing_slicing,
    reason = "slot derived from `tss_selector_for_cpu` arithmetic and bounded by `off < MAX_AP_SLOTS`; `slot + 1 < GDT_LEN` holds by construction"
)]
pub fn gdt_set_ap_tss(cpu_id: u32, tss_base: u64) -> bool {
    let Some(off) = (cpu_id as usize).checked_sub(1) else {
        return false;
    };
    if off >= super::per_cpu::MAX_AP_SLOTS {
        return false;
    }
    let slot = AP_TSS_FIRST_SLOT + TSS_DESCRIPTOR_SLOTS * off;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "sizeof(Tss) = 104 fits u32 trivially"
    )]
    let limit = (core::mem::size_of::<super::tss::Tss>() - 1) as u32;
    let (low, high) = super::tss::tss_descriptor(tss_base, limit);
    // SAFETY: single-core pre-fire wiring; the AP for this slot has not
    // been signalled yet so the GDT slot is exclusively owned by BSP.
    unsafe {
        let p = core::ptr::addr_of_mut!(GDT);
        // `slot + 1 < GDT_LEN` because `off < MAX_AP_SLOTS` and
        // `GDT_LEN = 7 + 2 * MAX_AP_SLOTS`.
        (*p)[slot] = low;
        (*p)[slot + 1] = high;
    }
    true
}

/// Read-back of the (low, high) u64 pair at GDT slot `slot, slot+1`.
/// Used by host-side tests to verify [`gdt_set_ap_tss`] wrote the
/// expected descriptor words.
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "`slot + 1 < GDT_LEN` guarded above"
)]
pub fn gdt_read_pair(slot: usize) -> (u64, u64) {
    if slot + 1 >= GDT_LEN {
        return (0, 0);
    }
    // SAFETY: read of u64 fields via raw pointer; single-writer
    // semantics during pre-fire wiring.
    unsafe {
        let p = core::ptr::addr_of!(GDT);
        ((*p)[slot], (*p)[slot + 1])
    }
}

/// MB14.c.2.d — exposed (base, limit) of the kernel GDT for the AP
/// landing asm.
///
/// The AP cannot reuse the stack-local pseudo-descriptor [`gdt_init`]
/// built (it was freed when `gdt_init` returned). This accessor returns
/// the persistent values so the BSP can stamp them into the AP runtime
/// control block.
#[must_use]
pub fn gdt_base_and_limit() -> (u64, u16) {
    let base = core::ptr::addr_of!(GDT) as u64;
    let limit = (GDT_LEN * core::mem::size_of::<u64>() - 1) as u16;
    (base, limit)
}

/// Total number of u64 slots in the GDT (visible for host-side tests
/// that pin the MB14.c.2.d expansion).
#[must_use]
pub const fn gdt_total_slots() -> usize {
    GDT_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_selector_is_0x23() {
        assert_eq!(USER_CS, 0x23);
    }

    #[test]
    fn user_ss_selector_is_0x1b() {
        assert_eq!(USER_SS, 0x1B);
    }

    #[test]
    fn kernel_selectors_unchanged() {
        assert_eq!(KERNEL_CS, 0x08);
        assert_eq!(KERNEL_SS, 0x10);
    }

    #[test]
    fn sysret_arithmetic_matches_intel_sdm() {
        // STAR[63:48] = 0x10
        //   SYSRET q CS = base + 16 | 3
        //   SYSRET q SS = base + 8  | 3
        let base = u32::from(STAR_USER_BASE);
        let cs = (base + 16) | 3;
        let ss = (base + 8) | 3;
        assert_eq!(cs as u16, USER_CS);
        assert_eq!(ss as u16, USER_SS);
    }

    #[test]
    fn syscall_arithmetic_matches_intel_sdm() {
        // STAR[47:32] = 0x08
        //   SYSCALL CS = base
        //   SYSCALL SS = base + 8
        let base = u32::from(STAR_KERNEL_BASE);
        let cs = base;
        let ss = base + 8;
        assert_eq!(cs as u16, KERNEL_CS);
        assert_eq!(ss as u16, KERNEL_SS);
    }

    #[test]
    fn user_data_descriptor_access_is_0xf2() {
        let access = (UDATA64 >> 40) & 0xFF;
        assert_eq!(access, 0xF2);
    }

    #[test]
    fn user_code_descriptor_access_is_0xfa() {
        let access = (UCODE64 >> 40) & 0xFF;
        assert_eq!(access, 0xFA);
    }

    #[test]
    fn user_code_descriptor_is_long_mode() {
        // Flags nibble (bits 52..56) must include L=1 (bit 53).
        let flags = (UCODE64 >> 52) & 0xF;
        assert_eq!(flags & 0x2, 0x2);
    }

    // -----------------------------------------------------------------
    // MB14.c.2.d — GDT extension + per-CPU TSS selector arithmetic.
    // -----------------------------------------------------------------

    /// GDT grew to `7 + 2 * MAX_AP_SLOTS` slots to host one TSS
    /// descriptor per AP (16-byte 64-bit TSS descriptor = 2 u64 slots).
    #[test]
    fn gdt_extended_for_ap_tss_descriptors() {
        assert_eq!(
            gdt_total_slots(),
            7 + 2 * super::super::per_cpu::MAX_AP_SLOTS
        );
    }

    /// `tss_selector_for_cpu(0)` returns the legacy BSP selector (`0x28`).
    #[test]
    fn tss_selector_for_bsp_is_legacy_value() {
        assert_eq!(tss_selector_for_cpu(0), super::super::tss::TSS_SELECTOR);
    }

    /// `tss_selector_for_cpu(k)` for AP `k>=1` derives from
    /// `slot 7 + 2*(k-1)` × 8, no RPL bits set.
    #[test]
    fn tss_selector_for_first_ap_is_slot_seven() {
        // cpu_id=1 → slot 7 → selector = 56 = 0x38.
        assert_eq!(tss_selector_for_cpu(1), 0x38);
        // cpu_id=2 → slot 9 → selector = 72 = 0x48.
        assert_eq!(tss_selector_for_cpu(2), 0x48);
    }

    /// Out-of-range cpu_ids yield the null selector (caller-detectable
    /// sentinel — `ltr 0` faults).
    #[test]
    fn tss_selector_out_of_range_is_null() {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "MAX_CPUS = 32 fits u32 trivially"
        )]
        let oor = super::super::mp::MAX_CPUS as u32;
        assert_eq!(tss_selector_for_cpu(oor), 0);
    }

    /// `gdt_set_ap_tss(0, _)` rejects BSP cpu_id (false return).
    #[test]
    fn gdt_set_ap_tss_rejects_bsp() {
        assert!(!gdt_set_ap_tss(0, 0xDEAD));
    }

    /// `gdt_set_ap_tss` writes the (low, high) u64 pair returned by
    /// [`super::super::tss::tss_descriptor`] at the slot derived from
    /// `tss_selector_for_cpu`.
    #[test]
    fn gdt_set_ap_tss_writes_descriptor_at_correct_slot() {
        // Use cpu_id=1 → slot 7.
        let base = 0xFFFF_C100_0000_1000_u64;
        assert!(gdt_set_ap_tss(1, base));
        #[allow(clippy::cast_possible_truncation, reason = "sizeof(Tss) = 104")]
        let limit = (core::mem::size_of::<super::super::tss::Tss>() - 1) as u32;
        let expected = super::super::tss::tss_descriptor(base, limit);
        let actual = gdt_read_pair(7);
        assert_eq!(actual, expected);
    }

    /// `gdt_base_and_limit` returns the persistent base + a limit equal
    /// to `GDT_LEN * 8 - 1`.
    #[test]
    fn gdt_base_and_limit_returns_persistent_descriptor_values() {
        let (base, limit) = gdt_base_and_limit();
        assert_ne!(base, 0);
        #[allow(
            clippy::cast_possible_truncation,
            reason = "GDT_LEN * 8 - 1 fits u16 by construction"
        )]
        let expected_limit = (gdt_total_slots() * 8 - 1) as u16;
        assert_eq!(limit, expected_limit);
    }
}
