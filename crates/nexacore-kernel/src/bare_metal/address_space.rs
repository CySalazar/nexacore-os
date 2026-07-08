//! Per-process address space (MB11, ADR-0004 § 4).
//!
//! Each `ProcessControlBlock` owns an [`AddressSpace`] backed by a
//! dedicated PML4 frame. On construction the kernel half (PML4 indices
//! 256..512) is **memcpy-cloned** from the boot CR3 — copying only the
//! 8-byte entry words, not the underlying PDPTs. The kernel half is
//! therefore shared by reference across all processes: a `vmap` of a
//! new kernel-side frame is visible to every process without explicit
//! TLB shoot-down (post-MP this changes; Phase 1 single-CPU).
//!
//! The user half (PML4 indices 0..256) is initialised to zero and
//! populated per-process via [`AddressSpace::map_user_4k`], which is a
//! thin wrapper around [`super::paging::PageMapper::map_4k_into`]
//! forced through `self.pml4_phys`.

#![allow(
    unsafe_code,
    reason = "PML4 clone via raw direct-map deref + CR3 wrcr3; SAFETY per fn"
)]
#![allow(
    clippy::doc_markdown,
    reason = "module references PML4, CR3, PDPT, TLB without ticks in prose"
)]

use super::paging::PageMapper;
use crate::memory::{BitmapFrameAllocator, PhysAddr, VirtAddr};

/// Kernel-half boundary: PML4 indices below this are user space,
/// indices at or above are kernel space. On x86_64 long mode the
/// canonical split is 256 entries → 256 entries, mapping the lower
/// 128 TiB to user and the upper 128 TiB (kernel half) to the kernel.
const KERNEL_PML4_START: usize = 256;

/// Total number of u64 entries in a PML4 (4 KiB / 8 bytes = 512).
const PML4_ENTRIES: usize = 512;

/// A per-process address space.
///
/// Owns a single PML4 frame; the user half is private, the kernel
/// half mirrors the boot CR3 by reference.
#[derive(Debug, Clone, Copy)]
pub struct AddressSpace {
    /// Physical address of the PML4 (low 12 bits zero).
    pub pml4_phys: PhysAddr,
}

impl AddressSpace {
    /// Allocate a fresh PML4 frame and populate the kernel half by
    /// memcpy from the boot PML4 at `boot_cr3`.
    ///
    /// Only entries 256..511 (the canonical kernel half) are cloned;
    /// the user half (0..255) is initialised to zero so per-process
    /// user mappings remain private. The boot-time configuration
    /// (`kernel-runner` `BootloaderConfig::dynamic_range_start =
    /// 0xFFFF_8000_…`) keeps every boot-installed mapping in the
    /// kernel half so this clone is sufficient.
    ///
    /// Returns `None` if the allocator cannot provide a 4 KiB frame.
    pub fn new_with_kernel_half<const N: usize>(
        boot_cr3: PhysAddr,
        mapper: &PageMapper,
        alloc: &mut BitmapFrameAllocator<N>,
    ) -> Option<Self> {
        let frame = alloc.alloc_frame()?;

        // SAFETY: `frame` was just allocated; not aliased. `boot_cr3` is
        // the live CR3 root, whose direct-map view is read-only here.
        unsafe {
            let phys_offset = mapper.phys_offset();
            let dst = phys_offset.wrapping_add(frame.0) as *mut u64;
            let src = phys_offset.wrapping_add(boot_cr3.0) as *const u64;

            // Zero the entire frame first.
            core::ptr::write_bytes(dst.cast::<u8>(), 0, 4096);

            // Copy kernel-half entries (256..512) verbatim from boot PML4.
            // This shares the underlying PDPTs by reference: a kernel-side
            // `vmap` of a new frame in any sub-PDPT becomes visible to
            // every process whose PML4 was cloned here.
            for i in KERNEL_PML4_START..PML4_ENTRIES {
                let v = core::ptr::read(src.add(i));
                core::ptr::write(dst.add(i), v);
            }
        }

        Some(Self { pml4_phys: frame })
    }

    /// Map a single 4 KiB user-space page into this address space.
    ///
    /// Thin wrapper over [`PageMapper::map_4k_into`]: the leaf PTE
    /// flags are taken from `flags` as-is (caller is expected to set
    /// `PTE_PRESENT | PTE_USER` and any of `PTE_WRITABLE | PTE_NO_EXEC`).
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "AddressSpace is the conceptual receiver; pass by-ref for callsite ergonomics"
    )]
    pub fn map_user_4k<const N: usize>(
        &self,
        mapper: &mut PageMapper,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: u64,
        alloc: &mut BitmapFrameAllocator<N>,
    ) -> bool {
        // The leaf must be in user-half VA range (PML4 indices 0..256).
        debug_assert!(
            virt.0 < 0x0000_8000_0000_0000,
            "AddressSpace::map_user_4k expects a user-half VA"
        );
        mapper.map_4k_into(self.pml4_phys, virt, phys, flags, alloc)
    }

    /// Reload CR3 to make this address space the active one.
    ///
    /// MUST be called only by the scheduler at context-switch time when
    /// entering a process whose `AddressSpace` is `self`. The kernel
    /// half remains valid because every per-process PML4 mirrors the
    /// boot CR3's kernel half by reference (the post-clone identity
    /// established by [`Self::new_with_kernel_half`]).
    #[cfg(target_arch = "x86_64")]
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "AddressSpace is the conceptual receiver; by-ref keeps API uniform"
    )]
    pub fn activate(&self) {
        use core::arch::asm;
        // SAFETY: `pml4_phys` is a valid PML4 frame owned by this
        // process; CR3 reload is a privileged but legal Ring-0 op.
        unsafe {
            asm!(
                "mov cr3, {}",
                in(reg) self.pml4_phys.0,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Stub for non-x86_64 host test builds.
    #[cfg(not(target_arch = "x86_64"))]
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        clippy::unused_self,
        reason = "non-x86_64 stub mirrors the x86_64 signature for source-compat"
    )]
    pub const fn activate(&self) {}

    /// Invalidate a single TLB entry. Useful when unmapping a user
    /// page without doing a full CR3 reload.
    #[cfg(target_arch = "x86_64")]
    pub fn invlpg(va: VirtAddr) {
        use core::arch::asm;
        // SAFETY: invlpg is a privileged Ring-0 instruction with no
        // side effect beyond TLB invalidation.
        unsafe {
            asm!("invlpg [{}]", in(reg) va.0, options(nostack, preserves_flags));
        }
    }

    /// Stub for non-x86_64 host test builds.
    #[cfg(not(target_arch = "x86_64"))]
    pub const fn invlpg(_va: VirtAddr) {}
}

#[cfg(test)]
mod tests {
    use core::alloc::Layout;

    use super::*;
    use crate::memory::BitmapFrameAllocator;

    const ARENA_FRAMES: u64 = 16;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "16 frames fits usize on every supported target"
    )]
    const ARENA_SIZE: usize = ARENA_FRAMES as usize * 4096;
    const PHYS_BASE: u64 = 0x0100_0000;

    struct TestArena {
        ptr: *mut u8,
        layout: Layout,
    }

    impl TestArena {
        fn new() -> Self {
            let layout = Layout::from_size_align(ARENA_SIZE, 4096).unwrap();
            // SAFETY: layout is non-zero and valid.
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null());
            Self { ptr, layout }
        }

        fn phys_offset(&self) -> u64 {
            self.ptr as u64 - PHYS_BASE
        }
    }

    impl Drop for TestArena {
        fn drop(&mut self) {
            // SAFETY: same layout used in `new`.
            unsafe { std::alloc::dealloc(self.ptr, self.layout) };
        }
    }

    fn make_alloc() -> BitmapFrameAllocator<1> {
        let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(PHYS_BASE));
        alloc.mark_range_free(PhysAddr(PHYS_BASE), ARENA_SIZE as u64);
        alloc
    }

    #[test]
    fn kernel_half_clone_copies_entries_256_to_511() {
        let arena = TestArena::new();
        let phys_offset = arena.phys_offset();
        let boot_cr3 = PhysAddr(PHYS_BASE);
        let user_cr3 = PhysAddr(PHYS_BASE + 4096);

        // Mark frame 0 (boot PML4) used so the allocator gives us frame 1.
        let mut alloc = make_alloc();
        alloc.mark_range_used(boot_cr3, 4096);

        // Populate boot PML4 with sentinel values in kernel-half entries.
        // SAFETY: arena memory just allocated, not aliased.
        unsafe {
            let p = phys_offset.wrapping_add(boot_cr3.0) as *mut u64;
            for i in 256..512 {
                core::ptr::write(p.add(i), 0xCAFE_0000 | i as u64);
            }
        }

        let mapper = PageMapper::new(phys_offset, boot_cr3);
        let addr_space =
            AddressSpace::new_with_kernel_half(boot_cr3, &mapper, &mut alloc).expect("clone");

        // Expect the user_cr3 frame to be selected.
        assert_eq!(addr_space.pml4_phys.0, user_cr3.0);

        // SAFETY: arena memory.
        unsafe {
            let p = phys_offset.wrapping_add(addr_space.pml4_phys.0) as *const u64;
            for i in 256..512 {
                let v = core::ptr::read(p.add(i));
                assert_eq!(v, 0xCAFE_0000 | i as u64);
            }
        }
    }

    #[test]
    fn user_half_is_zero_after_clone() {
        let arena = TestArena::new();
        let phys_offset = arena.phys_offset();
        let boot_cr3 = PhysAddr(PHYS_BASE);
        let mut alloc = make_alloc();
        alloc.mark_range_used(boot_cr3, 4096);

        // Pre-populate the boot PML4 user half with sentinels too, to
        // verify they are NOT copied.
        // SAFETY: arena memory.
        unsafe {
            let p = phys_offset.wrapping_add(boot_cr3.0) as *mut u64;
            for i in 0..256 {
                core::ptr::write(p.add(i), 0xBADC_0DE0 | i as u64);
            }
        }

        let mapper = PageMapper::new(phys_offset, boot_cr3);
        let addr_space =
            AddressSpace::new_with_kernel_half(boot_cr3, &mapper, &mut alloc).expect("clone");

        // SAFETY: arena memory.
        unsafe {
            let p = phys_offset.wrapping_add(addr_space.pml4_phys.0) as *const u64;
            for i in 0..256 {
                assert_eq!(
                    core::ptr::read(p.add(i)),
                    0,
                    "user-half entry {i} must be zero (boot pushes mappings to upper half)"
                );
            }
        }
    }
}
