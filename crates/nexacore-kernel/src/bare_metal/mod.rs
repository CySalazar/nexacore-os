//! Bare-metal kernel runtime — panic handler, global allocator, early
//! console, and arch-specific intrinsics.
//!
//! This module is the **K3 deliverable of `NCIP-Kernel-003` § 3**,
//! specified by [`NCIP-Kernel-012`](../../../../ncips/ncip-kernel-012.md).
//! Its files exist only when the `bare-metal` feature is enabled;
//! removing the feature folds the module out of the crate's source.
//!
//! ## Layout
//!
//! - [`mod@panic`] — `#[panic_handler]` plus the structured `PanicRecord`
//!   type emitted to the early-boot console. Non-allocating, interrupt-
//!   disabled, halt-on-completion (see `NCIP-Kernel-012` § S1).
//! - [`heap`] — `SlabHeap` reclaiming global allocator (slab + free-list,
//!   `NCIP-Kernel-Alloc-029`, installed as of WS1-08.6), with the legacy
//!   never-free `BumpHeap` (`NCIP-Kernel-012` § S2) retained for reference.
//! - [`early_console`] — pre-init writer to the 16550 UART on COM1
//!   (0x3f8). The panic record is encoded into a static buffer and
//!   flushed via this module byte-by-byte.
//! - [`arch`] — architecture-specific intrinsics: interrupt disable,
//!   halt-forever, port I/O. The `x86_64` impl uses `core::arch::asm`;
//!   a no-op stub exists for non-x86 hosts so that host tests on
//!   developer ARM machines still compile.
//!
//! ## Visibility under `cfg(test)`
//!
//! The **types** in this module (`PanicRecord`, `PanicLocation`,
//! `BumpHeap`) are visible under both `cfg(test)` and the bare-metal
//! build. The **attribute-bearing items** — `#[panic_handler]`,
//! `#[global_allocator]` — are gated `#[cfg(not(test))]` because the
//! standard test harness installs its own panic handler and allocator
//! and would conflict otherwise.
//!
//! This split is what makes `cargo test --workspace --all-features`
//! (with `bare-metal` on) still pass: the type surface is tested
//! against a synthetic heap region in host mode, while the attribute-
//! bearing globals are only present in the bare-metal binary.

#![allow(unsafe_code)]

pub mod address_space;
pub mod ap_dispatch;
pub mod arch;

// =============================================================================
// Global bootloader direct-map offset
//
// `kmain` reads `BootInfo.physical_memory_offset` once and publishes it
// here so subsystems that run after init (LAPIC init, syscall handlers,
// driver framework) can rebuild a `PageMapper` without threading the
// value through every callsite. Writers are `kmain` only (one-shot at
// boot); readers may race but the value is constant for the lifetime
// of the boot image. `Relaxed` ordering is sufficient — there is no
// data the offset coordinates with.
// =============================================================================

/// Bootloader-supplied direct-map offset, in the canonical kernel-half
/// virtual address space (`BootInfo.physical_memory_offset`).
///
/// Reads before [`set_phys_offset`] return `0`, which surfaces as a
/// translate-fault rather than a silent miss when a driver framework
/// path tries to walk page tables before kmain has run.
pub static PHYS_OFFSET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// One-shot setter for the bootloader direct-map offset. Called by
/// `kmain` early in boot, before any user-process spawn or syscall
/// dispatch can observe the value.
#[inline]
pub fn set_phys_offset(value: u64) {
    PHYS_OFFSET.store(value, core::sync::atomic::Ordering::Relaxed);
}

/// Read the bootloader direct-map offset.
///
/// Returns `0` before [`set_phys_offset`] has been called — callers
/// that hit this case SHOULD treat the read as an internal kernel
/// invariant violation (kmain ordering bug) and reject the operation.
#[must_use]
#[inline]
pub fn phys_offset() -> u64 {
    PHYS_OFFSET.load(core::sync::atomic::Ordering::Relaxed)
}

// =============================================================================
// Boot PML4 (boot CR3) anchor
//
// `kmain` records the bootloader-built PML4 physical base here so the
// `DriverLoad (73)` syscall handler can clone its kernel-half into the
// new driver process's address space without depending on the calling
// process's CR3 (which is the loader, not the kernel image). Single
// one-shot writer at boot; `Relaxed` ordering for the same reason as
// [`PHYS_OFFSET`].
// =============================================================================

/// Bootloader-built PML4 physical address, low 12 bits zero.
///
/// Reads before [`set_boot_cr3`] return `0` and surface as an
/// `EFAULT`-equivalent at the syscall layer, exactly as
/// [`PHYS_OFFSET`] does.
pub static BOOT_CR3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// One-shot setter for the boot PML4 physical address. Called by
/// `kmain` after reading `CR3` and before any user-process spawn.
#[inline]
pub fn set_boot_cr3(value: u64) {
    BOOT_CR3.store(value & !0xFFF, core::sync::atomic::Ordering::Relaxed);
}

/// Read the boot PML4 physical address.
#[must_use]
#[inline]
pub fn boot_cr3() -> u64 {
    BOOT_CR3.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod boot_cr3_tests {
    use core::sync::atomic::Ordering;

    use super::{boot_cr3, set_boot_cr3};

    /// `set_boot_cr3` masks the low 12 bits so callers can pass the
    /// raw CR3 register value (which carries PCD/PWT/PCID flags below
    /// the page-aligned PML4 base).
    #[test]
    fn set_boot_cr3_masks_low_12_bits() {
        // Save + restore the global so other host tests are not
        // perturbed by this one running first (the global is shared
        // across the whole test process).
        let prior = super::BOOT_CR3.load(Ordering::Relaxed);
        set_boot_cr3(0x0010_0000 | 0xABC);
        assert_eq!(boot_cr3(), 0x0010_0000);
        super::BOOT_CR3.store(prior, Ordering::Relaxed);
    }

    #[test]
    fn boot_cr3_returns_zero_when_unset_observer() {
        // Pin the contract: a fresh observer would read 0 (the AtomicU64
        // default) — captured here by snapshotting before our test
        // mutation and asserting after restore.
        let prior = super::BOOT_CR3.load(Ordering::Relaxed);
        super::BOOT_CR3.store(0, Ordering::Relaxed);
        assert_eq!(boot_cr3(), 0);
        super::BOOT_CR3.store(prior, Ordering::Relaxed);
    }

    #[test]
    fn set_boot_cr3_round_trips_aligned_value() {
        let prior = super::BOOT_CR3.load(Ordering::Relaxed);
        set_boot_cr3(0xDEAD_F000);
        assert_eq!(boot_cr3(), 0xDEAD_F000);
        super::BOOT_CR3.store(prior, Ordering::Relaxed);
    }
}
#[cfg(target_arch = "x86_64")]
pub mod context_switch;
pub mod cpu_features;
#[cfg(target_arch = "x86_64")]
pub mod cpuinfo;
pub mod cursor;
pub mod demo;
pub mod driver_loader;
pub mod early_console;
pub mod elf_loader;
pub mod font;
pub mod gdt;
pub mod graphics;
pub mod heap;
pub mod idt;
pub mod input;
pub mod iommu;
pub mod ipi;
#[cfg(target_arch = "x86_64")]
pub mod lapic;
#[cfg(all(
    target_arch = "x86_64",
    target_os = "none",
    feature = "mb8-smoke",
    not(test)
))]
pub mod mb8_smoke;
pub mod mp;
pub mod mp_ap_entry;
pub mod mp_emplacement;
pub mod mp_trampoline;
/// Kernel-side MSI-X table programming for Ring 3 drivers (TASK-14,
/// ADR-0036). Bare-metal x86_64 only.
#[cfg(all(target_arch = "x86_64", target_os = "none", not(test)))]
pub mod msix;
pub mod paging;
pub mod panic;
pub mod pci_scan;
pub mod per_cpu;
pub mod per_cpu_run_queue;
pub mod pit_delay;
pub mod syscall_entry;
pub mod tlb_shootdown;
pub mod tss;
pub mod uaccess;
pub mod user_stack;
pub mod usermode;
pub mod userprobe;
pub mod userprobe_mb12;
pub mod vga;
pub mod virtio_tablet;
pub mod widget;
pub mod wm;
