//! MB14.c.2.b.2 — bare-metal emplacement of the AP startup trampoline.
//!
//! [`mp_trampoline`](super::mp_trampoline) supplies pure-function
//! builders for the trampoline blob, the temporary GDT, and the
//! temporary 4-level paging hierarchy that identity-maps the first
//! 2 MiB of physical memory. This module is the bare-metal counterpart:
//! it allocates three physical frames for the temporary
//! PML4 / PDPT / PD, materialises their contents through the
//! bootloader's direct-map window, identity-maps the trampoline page
//! `0x0000_8000` in the active CR3 (defensive measure), and copies the
//! 256-byte blob to physical `0x0000_8000`.
//!
//! After this runs, the system is one ICR write away from
//! INIT–SIPI–SIPI on each enumerated AP — but no LAPIC MMIO is emitted
//! here. The actual live fire stays in MB14.c.2.c.
//!
//! ## References
//!
//! - Intel SDM Vol 3A § 8.4 — MP Initialization Protocol
//! - Intel SDM Vol 3A § 4.5 — IA-32e Paging
//! - AMD64 APM Vol 2 § 14.8 — startup-IPI handshake & trampoline pattern

#![allow(
    unsafe_code,
    reason = "MB14.c.2.b.2 emplaces a 256-byte trampoline + 3 page-table frames via the bootloader direct map; each write is fenced by per-frame SAFETY comments"
)]

use crate::{
    bare_metal::{
        mp_ap_entry::{
            AP_ACK_COUNTER_OFFSET, AP_KERNEL_CR3_OFFSET, AP_KMAIN_AP_VA_OFFSET,
            AP_LANDING_STUB_OFFSET, AP_LANDING_STUB_SIZE, build_ap_landing_stub,
        },
        mp_trampoline::{TRAMPOLINE_BLOB_SIZE, build_temp_identity_paging, build_trampoline_blob},
        paging::{PTE_PRESENT, PTE_WRITABLE, PageMapper},
    },
    memory::{BitmapFrameAllocator, PhysAddr, VirtAddr},
};

/// Physical address at which the AP startup trampoline is emplaced.
///
/// Intel SDM Vol 3A § 8.4: the SIPI vector field `V` (8 bits) causes the
/// AP to begin executing at `CS:IP = (V << 12):0000`. Choosing `V = 0x08`
/// places the trampoline at physical `0x0000_8000`, well above the BIOS
/// IVT / BDA / EBDA and well below the 1 MiB legacy boundary, so it sits
/// in a region every PC firmware reserves for legacy real-mode use.
pub const TRAMPOLINE_PHYS_BASE: u32 = 0x0000_8000;

/// SIPI vector byte that corresponds to [`TRAMPOLINE_PHYS_BASE`]
/// (`TRAMPOLINE_PHYS_BASE >> 12`).
///
/// Surfaced for the MB14.c.2.c orchestrator, which encodes this value
/// into the ICR `vector` field for the two SIPI writes.
#[allow(
    clippy::cast_possible_truncation,
    reason = "TRAMPOLINE_PHYS_BASE >> 12 = 0x08, well within u8::MAX (asserted by sipi_vector_matches_trampoline_base)"
)]
pub const TRAMPOLINE_SIPI_VECTOR: u8 = (TRAMPOLINE_PHYS_BASE >> 12) as u8;

/// Number of u64 entries in a single page-table page (PML4 / PDPT / PD).
const PT_ENTRIES_PER_PAGE: usize = 512;

/// Outcome of a successful [`place_trampoline`] call.
///
/// `trampoline_paddr` is always [`TRAMPOLINE_PHYS_BASE`]; it is returned
/// alongside `temp_pml4_paddr` so the MB14.c.2.c orchestrator can hand
/// both to the AP via the trampoline's relocations without re-deriving
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmplacedTrampoline {
    /// Physical address where the 256-byte trampoline blob lives.
    /// Always equals [`TRAMPOLINE_PHYS_BASE`].
    pub trampoline_paddr: u32,
    /// Physical address of the temporary PML4 the trampoline will load
    /// into `CR3` while still in 32-bit protected mode.
    pub temp_pml4_paddr: u64,
}

/// Reasons [`place_trampoline`] can refuse to emplace the trampoline.
///
/// All variants leave the system in a state safe for BSP-only operation:
/// no AP has been signalled, the active CR3 mapping is either unchanged
/// or reverted to a state equivalent to the pre-call situation, and any
/// frames allocated by this function are released back to `allocator`
/// before returning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmplacementError {
    /// `allocator.alloc_frame()` returned `None` while we were trying to
    /// reserve the three pages for the temp PML4 / PDPT / PD.
    OutOfFrames,
    /// The frame allocator handed us a PML4 frame whose physical address
    /// exceeds 4 GiB. The trampoline loads `CR3` while still in 32-bit
    /// protected mode via `mov eax, imm32`, so the temp PML4 must live
    /// in the low 4 GiB.
    Pml4Above4GiB,
    /// The trampoline VA (`0x8000`) is already mapped to a frame other
    /// than `0x8000` in the active CR3. We refuse to clobber an existing
    /// non-identity mapping rather than risk a triple-fault.
    TrampolineVaConflict,
    /// `mapper.map_4k` failed — most likely because adding the
    /// trampoline page-table entries exhausted `allocator` mid-way.
    MapFailed,
}

/// Emplace the AP startup trampoline at physical
/// [`TRAMPOLINE_PHYS_BASE`].
///
/// Allocates the three temp page-table frames, materialises the
/// identity-paging hierarchy through the bootloader direct map,
/// identity-maps the trampoline page in the active CR3, and copies
/// the 256-byte blob to physical `0x0000_8000`.
///
/// # Parameters
///
/// - `allocator` — the global physical frame allocator. Three frames
///   are consumed (PML4, PDPT, PD) plus up to four more for the active
///   CR3's intermediate page tables on the path to VA `0x8000`. The
///   trampoline page itself (`0x0000_8000`) is **not** allocated from
///   here: it sits in the low 1 MiB region that `kmain` reserves
///   wholesale, so the allocator never hands it out.
/// - `mapper` — a [`PageMapper`] rooted at the active CR3. Used to walk
///   and extend the active page-table tree so the trampoline VA is
///   reachable from the BSP.
/// - `kernel_ap_entry` — the higher-half kernel entry point the AP
///   jumps to once long mode is active (`jmp rax` at trampoline offset
///   `0x6C`).
///
/// # Returns
///
/// `Ok(EmplacedTrampoline)` on success. The temp PML4 physical address
/// is stored inside the trampoline blob (relocation at offset `0x32`),
/// so the AP can transition into 32-bit paging without further help
/// from the BSP.
///
/// # Errors
///
/// See [`EmplacementError`]. All error paths return the frames they
/// allocated back to `allocator` before returning, so the function is
/// safe to retry.
#[allow(
    clippy::similar_names,
    reason = "tramp_va / tramp_pa mirror the VirtAddr/PhysAddr pair pattern used across paging.rs"
)]
pub fn place_trampoline<const N: usize>(
    allocator: &mut BitmapFrameAllocator<N>,
    mapper: &mut PageMapper,
    kernel_ap_entry: u64,
) -> Result<EmplacedTrampoline, EmplacementError> {
    // 1. Reserve three frames for the temporary 4-level paging hierarchy
    //    that the trampoline will install in CR3 while still in 32-bit
    //    protected mode.
    let pml4_paddr = allocator
        .alloc_frame()
        .ok_or(EmplacementError::OutOfFrames)?;
    let Some(pdpt_paddr) = allocator.alloc_frame() else {
        let _ = allocator.free_frame(pml4_paddr);
        return Err(EmplacementError::OutOfFrames);
    };
    let Some(pd_paddr) = allocator.alloc_frame() else {
        let _ = allocator.free_frame(pdpt_paddr);
        let _ = allocator.free_frame(pml4_paddr);
        return Err(EmplacementError::OutOfFrames);
    };

    // The trampoline's 32-bit `mov eax, temp_pml4_paddr` is a u32 imm,
    // so the temp PML4 must live in the low 4 GiB. The other two frames
    // are referenced through 64-bit PML4 / PDPT entries (bits 51:12) and
    // can sit anywhere in the 52-bit physical space — but on x86_64 in
    // practice they come from the same low-memory pool as the PML4.
    if pml4_paddr.0 > u64::from(u32::MAX) {
        let _ = allocator.free_frame(pd_paddr);
        let _ = allocator.free_frame(pdpt_paddr);
        let _ = allocator.free_frame(pml4_paddr);
        return Err(EmplacementError::Pml4Above4GiB);
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "checked above: pml4_paddr.0 ≤ u32::MAX"
    )]
    let pml4_u32 = pml4_paddr.0 as u32;

    // 2. Build the temp identity-paging contents as plain u64 arrays.
    //    No physical writes yet — the bytes live on the BSP kernel stack.
    let temp = build_temp_identity_paging(pdpt_paddr.0, pd_paddr.0);

    // 3. Materialise the three pages by writing each [u64; 512] through
    //    the bootloader's direct-map window. `phys_offset + p` is
    //    guaranteed mapped for every physical address the allocator
    //    can hand out (see `register_direct_mapped_regions` in
    //    `nexacore_kernel::kmain`).
    let phys_offset = mapper.phys_offset();

    // SAFETY: pml4_paddr / pdpt_paddr / pd_paddr come from the global
    // frame allocator, which only hands out frames that live in
    // bootloader-direct-mapped Usable regions (MB9 invariant). Writes
    // through `phys_offset + p` therefore cannot fault. The frames were
    // freshly allocated in this function and are not aliased.
    unsafe {
        write_page_table_frame(phys_offset, pml4_paddr.0, &temp.pml4);
        write_page_table_frame(phys_offset, pdpt_paddr.0, &temp.pdpt);
        write_page_table_frame(phys_offset, pd_paddr.0, &temp.pd);
    }

    // 4. Identity-map the trampoline page in the active CR3.
    //
    // The BSP writes the trampoline blob via the direct map below, so
    // this identity mapping is not strictly required for the copy
    // itself. It exists as a defensive guarantee that physical
    // `0x8000` is reachable both as `phys_offset + 0x8000` (BSP-side
    // direct map) and as VA `0x8000` (identity map) for future debug
    // / inspection paths. MB14.c.2.c will retain this property when
    // it flips `start_aps` to Live.
    let tramp_va = VirtAddr(u64::from(TRAMPOLINE_PHYS_BASE));
    let tramp_pa = PhysAddr(u64::from(TRAMPOLINE_PHYS_BASE));
    match mapper.translate(tramp_va) {
        Some(existing) if existing.0 == tramp_pa.0 => {
            // Already identity-mapped — nothing to do (idempotent).
        }
        Some(_) => {
            let _ = allocator.free_frame(pd_paddr);
            let _ = allocator.free_frame(pdpt_paddr);
            let _ = allocator.free_frame(pml4_paddr);
            return Err(EmplacementError::TrampolineVaConflict);
        }
        None => {
            // Map writable: the BSP-side copy below proceeds through the
            // direct map, but a writable identity mapping keeps the page
            // patchable from kernel code without re-walking on every
            // edit. Per-AP isolation is enforced by the temp PML4 the
            // AP loads, not by this kernel-side mapping.
            if !mapper.map_4k(tramp_va, tramp_pa, PTE_PRESENT | PTE_WRITABLE, allocator) {
                let _ = allocator.free_frame(pd_paddr);
                let _ = allocator.free_frame(pdpt_paddr);
                let _ = allocator.free_frame(pml4_paddr);
                return Err(EmplacementError::MapFailed);
            }
        }
    }

    // 5. Build the trampoline blob with the live PML4 relocation and
    //    copy it to physical `0x0000_8000` through the direct map.
    let blob = build_trampoline_blob(TRAMPOLINE_PHYS_BASE, pml4_u32, kernel_ap_entry);

    // SAFETY: physical `0x0000_8000` is in the low 1 MiB that `kmain`
    // wholesale-reserves via `mark_range_used(PhysAddr(0), 0x10_0000)`,
    // so the frame allocator never hands it out. The bootloader's
    // direct map covers all physical memory below the highest Usable
    // region, so `phys_offset + 0x8000` resolves to writable kernel-
    // accessible memory. The destination is not aliased: nothing else
    // in MB14.c.2.b.2 touches `0x8000`.
    unsafe {
        write_trampoline_blob(phys_offset, &blob);
    }

    Ok(EmplacedTrampoline {
        trampoline_paddr: TRAMPOLINE_PHYS_BASE,
        temp_pml4_paddr: pml4_paddr.0,
    })
}

/// MB14.c.2.c — emplace the live AP startup payload.
///
/// Wraps [`place_trampoline`] with the additional steps required to
/// route the AP through the [`super::mp_ap_entry`] landing stub instead
/// of the inert higher-half placeholder used by MB14.c.2.b.2:
///
/// 1. Call [`place_trampoline`] passing `kernel_ap_entry =
///    TRAMPOLINE_PHYS_BASE + AP_LANDING_STUB_OFFSET` so the trampoline
///    `jmp rax` lands inside the landing stub.
/// 2. Write the 32-byte landing stub at offset `AP_LANDING_STUB_OFFSET`
///    inside the trampoline page (i.e. phys `0x8000 + 0x100`).
/// 3. Zero the [`AP_ACK_COUNTER_OFFSET`] slot.
/// 4. Write `kernel_cr3` to the [`AP_KERNEL_CR3_OFFSET`] slot — the AP
///    loads this into `CR3` to enter the kernel address space.
/// 5. Write `kmain_ap_va` to the [`AP_KMAIN_AP_VA_OFFSET`] slot — the AP
///    `jmp`s to this VA after the `CR3` switch.
///
/// # Errors
///
/// Same as [`place_trampoline`]. Caller does not need to free anything
/// on error; allocations are returned to `allocator` before each
/// `Err(_)` propagates.
#[allow(
    clippy::similar_names,
    reason = "kernel_cr3 / kernel_ap_entry mirror the runtime artefacts they configure (CR3 vs RIP target)"
)]
pub fn place_trampoline_live<const N: usize>(
    allocator: &mut BitmapFrameAllocator<N>,
    mapper: &mut PageMapper,
    kernel_cr3: u64,
    kmain_ap_va: u64,
) -> Result<EmplacedTrampoline, EmplacementError> {
    // Step 1 — emplace the trampoline blob with `kernel_ap_entry`
    // pointing at the landing-stub offset inside the trampoline page.
    let landing_va = u64::from(TRAMPOLINE_PHYS_BASE) + AP_LANDING_STUB_OFFSET as u64;
    let emplaced = place_trampoline(allocator, mapper, landing_va)?;

    // Step 2 — write the landing stub.
    let stub = build_ap_landing_stub(TRAMPOLINE_PHYS_BASE);
    let phys_offset = mapper.phys_offset();

    // SAFETY: the trampoline page at phys 0x8000 is reserved by `kmain`
    // (mark_range_used PhysAddr(0), 0x10_0000) so no other writer aliases
    // it. The bootloader direct map covers low physical memory.
    unsafe {
        write_landing_stub_bytes(
            phys_offset,
            u64::from(TRAMPOLINE_PHYS_BASE) + AP_LANDING_STUB_OFFSET as u64,
            &stub,
        );
        // Step 3 — zero the ack counter.
        write_runtime_slot(
            phys_offset,
            u64::from(TRAMPOLINE_PHYS_BASE) + AP_ACK_COUNTER_OFFSET as u64,
            0,
        );
        // Step 4 — write the kernel CR3 the AP will load.
        write_runtime_slot(
            phys_offset,
            u64::from(TRAMPOLINE_PHYS_BASE) + AP_KERNEL_CR3_OFFSET as u64,
            kernel_cr3,
        );
        // Step 5 — write the kmain_ap VA the AP will jump to.
        write_runtime_slot(
            phys_offset,
            u64::from(TRAMPOLINE_PHYS_BASE) + AP_KMAIN_AP_VA_OFFSET as u64,
            kmain_ap_va,
        );
    }

    Ok(emplaced)
}

/// Read the current AP ack counter via the bootloader direct map.
///
/// MB14.c.2.c uses this from the BSP after firing INIT-SIPI to detect
/// when all targeted APs have entered the landing stub. The counter is
/// updated by the APs themselves via `lock inc qword ptr [imm32]`
/// (a strongly-ordered atomic on x86), so a plain volatile read on the
/// BSP observes the post-increment value once it is committed to memory.
///
/// # Safety
///
/// `phys_offset` must be the bootloader-supplied direct-map offset
/// covering low physical memory (true under the MB9 invariant on every
/// supported boot path).
#[must_use]
pub unsafe fn read_ack_counter(phys_offset: u64) -> u64 {
    let slot_paddr = u64::from(TRAMPOLINE_PHYS_BASE) + AP_ACK_COUNTER_OFFSET as u64;
    let src = phys_offset.wrapping_add(slot_paddr) as *const u64;
    // SAFETY: forwarded to the caller (see function-level invariant).
    unsafe { core::ptr::read_volatile(src) }
}

/// Write the 32-byte AP landing stub at `paddr` (must point inside the
/// trampoline page).
///
/// # Safety
///
/// `phys_offset + paddr` must be a writable kernel-accessible 32-byte
/// region not aliased by any other live reference (true for the
/// trampoline page on the MB14.c.2.c path).
unsafe fn write_landing_stub_bytes(
    phys_offset: u64,
    paddr: u64,
    stub: &[u8; AP_LANDING_STUB_SIZE],
) {
    let dst = phys_offset.wrapping_add(paddr) as *mut u8;
    for (i, byte) in stub.iter().enumerate() {
        // SAFETY: dst..dst+32 lives in the trampoline page (caller
        // invariant). Volatile to prevent reordering past the
        // subsequent INIT-SIPI ICR write.
        unsafe {
            core::ptr::write_volatile(dst.add(i), *byte);
        }
    }
}

/// Write an 8-byte runtime slot at `paddr` (`AP_ACK_COUNTER`,
/// `AP_KERNEL_CR3`, or `AP_KMAIN_AP_VA`).
///
/// # Safety
///
/// Same caveat as [`write_landing_stub_bytes`].
unsafe fn write_runtime_slot(phys_offset: u64, paddr: u64, value: u64) {
    let dst = phys_offset.wrapping_add(paddr) as *mut u64;
    // SAFETY: caller invariant — see function-level note.
    unsafe {
        core::ptr::write_volatile(dst, value);
    }
}

/// Write a 512-entry page-table page to physical `paddr` via the
/// bootloader direct map at `phys_offset + paddr`.
///
/// # Safety
///
/// `phys_offset + paddr` must point to a 4 KiB writable region that is
/// not aliased by any other live reference. Page-table frames freshly
/// returned by the global frame allocator satisfy this; the caller is
/// responsible for not passing aliased frames.
unsafe fn write_page_table_frame(phys_offset: u64, paddr: u64, src: &[u64; PT_ENTRIES_PER_PAGE]) {
    let dst = phys_offset.wrapping_add(paddr) as *mut u64;
    for (i, entry) in src.iter().enumerate() {
        // SAFETY: dst..dst+512 lives entirely in the 4 KiB frame at
        // paddr (caller invariant). Volatile writes prevent the
        // compiler from re-ordering them past the trampoline copy or
        // any subsequent CR3 / ICR access.
        unsafe {
            core::ptr::write_volatile(dst.add(i), *entry);
        }
    }
}

/// Copy the 256-byte trampoline blob to physical
/// [`TRAMPOLINE_PHYS_BASE`] via `phys_offset + 0x8000`.
///
/// # Safety
///
/// `phys_offset + 0x8000` must be a writable kernel-accessible address
/// (true under the MB9 direct-map invariant for any low-1-MiB physical
/// address on a standard PC firmware).
unsafe fn write_trampoline_blob(phys_offset: u64, blob: &[u8; TRAMPOLINE_BLOB_SIZE]) {
    let dst = phys_offset.wrapping_add(u64::from(TRAMPOLINE_PHYS_BASE)) as *mut u8;
    for (i, byte) in blob.iter().enumerate() {
        // SAFETY: dst..dst+256 lives entirely in the trampoline page
        // (caller invariant). Volatile writes prevent re-ordering past
        // the subsequent INIT-SIPI ICR write (MB14.c.2.c).
        unsafe {
            core::ptr::write_volatile(dst.add(i), *byte);
        }
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
#[allow(
    clippy::cast_ptr_alignment,
    reason = "TestArena is 4 KiB-aligned and paddr is a multiple of 8 (page-table entries), so casts from *mut u8 to *mut u64 are aligned"
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "test paddr values are all bounded by ARENA_SIZE (~1.5 MiB) — usize/u64 truncation cannot occur on 64-bit test hosts"
)]
#[allow(
    clippy::checked_conversions,
    reason = "<= u64::from(u32::MAX) reads more naturally than try_from in test assertions"
)]
mod tests {
    use super::*;
    use crate::{
        bare_metal::mp_trampoline::{
            TRAMPOLINE_BLOB_SIZE, build_temp_identity_paging, build_trampoline_blob,
        },
        memory::BitmapFrameAllocator,
    };

    /// Number of 4 KiB frames in the test arena (1.5 MiB / 4 KiB = 384).
    ///
    /// Sized to cover BOTH the trampoline page at phys `0x8000` (low
    /// 1 MiB) and the allocator-handed-out frames (above the 1 MiB
    /// reserved region). 1.5 MiB is the smallest size that lets us
    /// mirror the real-system layout, where the low 1 MiB is reserved
    /// wholesale and the first Usable region begins at `0x10_0000`.
    const ARENA_FRAMES: u64 = 384;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "384 fits usize on every supported test target"
    )]
    const ARENA_SIZE: usize = ARENA_FRAMES as usize * 4096;

    /// First physical address handed out by the allocator. Matches
    /// `kmain`, which calls `mark_range_used(PhysAddr(0), 0x10_0000)`
    /// to reserve the BIOS / IVT / BDA / EBDA region.
    const FREE_BASE: u64 = 0x10_0000;

    /// Heap-allocated 4 KiB-aligned arena standing in for the
    /// bootloader-direct-mapped physical memory window.
    ///
    /// `phys_offset` equals `arena.ptr`, so physical address `p` maps
    /// to host pointer `arena.ptr + p`. This mirrors the bare-metal
    /// invariant: `phys_offset + p` is the kernel-side view of physical
    /// memory.
    struct TestArena {
        ptr: *mut u8,
        layout: std::alloc::Layout,
    }

    impl TestArena {
        fn new() -> Self {
            let layout = std::alloc::Layout::from_size_align(ARENA_SIZE, 4096).unwrap();
            // SAFETY: layout has non-zero size; alloc_zeroed returns a
            // valid allocation or null (checked below).
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null(), "test arena allocation failed");
            Self { ptr, layout }
        }

        fn phys_offset(&self) -> u64 {
            // phys 0 → arena.ptr ; phys p → arena.ptr + p.
            self.ptr as u64
        }

        /// Reads the 4 KiB frame at physical `paddr` (which must live
        /// inside the arena) back as a `[u64; 512]`.
        fn read_pt_frame(&self, paddr: u64) -> [u64; 512] {
            assert!(
                paddr + 4096 <= ARENA_SIZE as u64,
                "read_pt_frame paddr {paddr:#x} outside arena ({ARENA_SIZE:#x} bytes)"
            );
            let src = unsafe { self.ptr.add(paddr as usize) }.cast::<u64>();
            let mut out = [0u64; 512];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = unsafe { core::ptr::read_volatile(src.add(i)) };
            }
            out
        }

        /// Reads `len` bytes starting at physical `paddr`.
        fn read_bytes(&self, paddr: u64, len: usize) -> Vec<u8> {
            assert!(
                paddr + len as u64 <= ARENA_SIZE as u64,
                "read_bytes paddr {paddr:#x} len {len} outside arena"
            );
            let src = unsafe { self.ptr.add(paddr as usize) };
            let mut out = vec![0u8; len];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = unsafe { core::ptr::read_volatile(src.add(i)) };
            }
            out
        }
    }

    impl Drop for TestArena {
        fn drop(&mut self) {
            // SAFETY: layout matches the original allocation.
            unsafe { std::alloc::dealloc(self.ptr, self.layout) };
        }
    }

    /// Build a mapper rooted at the first allocator-handed-out frame
    /// (PML4), plus an allocator with the remaining post-1-MiB frames
    /// marked free.
    fn make_mapper_and_alloc() -> (TestArena, PageMapper, BitmapFrameAllocator<8>) {
        let arena = TestArena::new();
        let phys_offset = arena.phys_offset();

        let mut alloc = BitmapFrameAllocator::<8>::new(PhysAddr(0));
        alloc.mark_range_free(PhysAddr(FREE_BASE), ARENA_FRAMES * 4096 - FREE_BASE);

        // Carve out the first free frame as the active-CR3 PML4. The
        // page is already zeroed by alloc_zeroed in TestArena::new.
        let pml4_pa = alloc.alloc_frame().expect("PML4 frame from arena");

        let mapper = PageMapper::new(phys_offset, pml4_pa);
        (arena, mapper, alloc)
    }

    const KERNEL_AP_ENTRY: u64 = 0xFFFF_FFFF_8010_0000;

    #[test]
    fn place_trampoline_returns_canonical_trampoline_paddr() {
        let (_arena, mut mapper, mut alloc) = make_mapper_and_alloc();
        let r = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("emplacement should succeed in the test arena");
        assert_eq!(
            r.trampoline_paddr, TRAMPOLINE_PHYS_BASE,
            "trampoline must land at 0x8000 (SIPI vector 0x08)"
        );
    }

    #[test]
    fn place_trampoline_temp_pml4_is_in_low_4gib() {
        let (_arena, mut mapper, mut alloc) = make_mapper_and_alloc();
        let r = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("emplacement should succeed");
        assert!(
            r.temp_pml4_paddr <= u64::from(u32::MAX),
            "temp PML4 must fit in the trampoline's 32-bit CR3 load"
        );
        assert_eq!(
            r.temp_pml4_paddr & 0xFFF,
            0,
            "temp PML4 must be 4 KiB-aligned"
        );
    }

    #[test]
    fn place_trampoline_consumes_three_frames_from_allocator() {
        let (_arena, mut mapper, mut alloc) = make_mapper_and_alloc();
        let before = alloc.free_frames();
        let _r = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("emplacement should succeed");
        let after = alloc.free_frames();
        // Three temp-paging frames are mandatory; the identity-mapping
        // of VA 0x8000 in the active CR3 consumes up to four more
        // (PDPT + PD + PT + leaf-PT frames depending on PML4 layout).
        let consumed = before - after;
        assert!(
            (3..=7).contains(&consumed),
            "expected 3..=7 frames consumed, got {consumed}"
        );
    }

    #[test]
    fn place_trampoline_materialises_pml4_pointing_at_pdpt() {
        let (arena, mut mapper, mut alloc) = make_mapper_and_alloc();
        let r = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("emplacement should succeed");
        let pml4 = arena.read_pt_frame(r.temp_pml4_paddr);
        assert_ne!(pml4[0], 0, "PML4 entry 0 must be populated");
        assert_eq!(pml4[0] & 1, 1, "PML4[0] must be present");
        assert_eq!(pml4[0] & 0b10, 0b10, "PML4[0] must be writable");
        // All other entries are zero.
        for (i, e) in pml4.iter().enumerate().skip(1) {
            assert_eq!(*e, 0, "PML4[{i}] must be zero");
        }
    }

    #[test]
    fn place_trampoline_materialises_pd_with_2mib_identity_entry() {
        let (arena, mut mapper, mut alloc) = make_mapper_and_alloc();
        let r = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("emplacement should succeed");
        // Pull the PDPT physical from the PML4, then the PD physical
        // from the PDPT, both via the arena read helper.
        let pml4 = arena.read_pt_frame(r.temp_pml4_paddr);
        let pdpt_paddr = pml4[0] & 0x000F_FFFF_FFFF_F000;
        let pdpt = arena.read_pt_frame(pdpt_paddr);
        let pd_paddr = pdpt[0] & 0x000F_FFFF_FFFF_F000;
        let pd = arena.read_pt_frame(pd_paddr);
        // PD[0] must be the 2 MiB PS=1 identity entry mapping 0..2 MiB.
        assert_eq!(pd[0] & 1, 1, "PD[0] must be present");
        assert_eq!(pd[0] & 0b10, 0b10, "PD[0] must be writable");
        assert_eq!(pd[0] & 0x80, 0x80, "PD[0] must have PS=1 (2 MiB page)");
        assert_eq!(
            pd[0] & 0x000F_FFFF_FFE0_0000,
            0,
            "PD[0] must map phys 0..2 MiB"
        );
    }

    #[test]
    fn place_trampoline_pml4_contents_match_pure_builder() {
        let (arena, mut mapper, mut alloc) = make_mapper_and_alloc();
        let r = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("emplacement should succeed");
        let pml4 = arena.read_pt_frame(r.temp_pml4_paddr);
        let pdpt_paddr = pml4[0] & 0x000F_FFFF_FFFF_F000;
        let pdpt = arena.read_pt_frame(pdpt_paddr);
        let pd_paddr = pdpt[0] & 0x000F_FFFF_FFFF_F000;
        let pd = arena.read_pt_frame(pd_paddr);
        // The materialised contents must be byte-identical to what the
        // pure builder would have produced for the same input.
        let expected = build_temp_identity_paging(pdpt_paddr, pd_paddr);
        for i in 0..512 {
            assert_eq!(pml4[i], expected.pml4[i], "PML4[{i}] mismatch");
            assert_eq!(pdpt[i], expected.pdpt[i], "PDPT[{i}] mismatch");
            assert_eq!(pd[i], expected.pd[i], "PD[{i}] mismatch");
        }
    }

    #[test]
    fn place_trampoline_handles_repeat_calls_consistently() {
        // Two successive calls must each succeed and produce
        // structurally-valid (though not identical) emplacements. We
        // never reclaim the temp frames, so each call advances the
        // allocator forward — proving the function does not leak any
        // state into the page-table tree it cannot reproduce.
        let (_arena, mut mapper, mut alloc) = make_mapper_and_alloc();
        let r1 = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("first emplacement must succeed");
        let r2 = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("second emplacement must succeed");
        assert_eq!(r1.trampoline_paddr, r2.trampoline_paddr);
        assert_ne!(
            r1.temp_pml4_paddr, r2.temp_pml4_paddr,
            "second call must use a different temp PML4 frame"
        );
    }

    #[test]
    fn place_trampoline_returns_out_of_frames_when_allocator_empty() {
        let arena = TestArena::new();
        let phys_offset = arena.phys_offset();
        // Allocator anchored at phys 0 with capacity 64 frames (1 word).
        // Mark the first frame free then used → allocator is drained.
        let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(0));
        alloc.mark_range_free(PhysAddr(FREE_BASE), 4096);
        alloc.mark_range_used(PhysAddr(FREE_BASE), 4096);
        let mut mapper = PageMapper::new(phys_offset, PhysAddr(FREE_BASE));
        let err = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect_err("emplacement must fail when no frames are free");
        assert_eq!(err, EmplacementError::OutOfFrames);
    }

    #[test]
    fn place_trampoline_writes_blob_to_phys_8000() {
        // The arena covers physical [0, 1.5 MiB), so the trampoline
        // page at phys 0x8000 lives inside it. Read the 256 bytes back
        // through the arena and assert byte-equality with what the
        // pure builder would have produced for the same inputs.
        let (arena, mut mapper, mut alloc) = make_mapper_and_alloc();
        let r = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("emplacement should succeed");
        #[allow(
            clippy::cast_possible_truncation,
            reason = "tested allocator only hands out frames below 4 GiB"
        )]
        let pml4_u32 = r.temp_pml4_paddr as u32;
        let expected = build_trampoline_blob(TRAMPOLINE_PHYS_BASE, pml4_u32, KERNEL_AP_ENTRY);

        let observed = arena.read_bytes(u64::from(TRAMPOLINE_PHYS_BASE), TRAMPOLINE_BLOB_SIZE);
        for i in 0..TRAMPOLINE_BLOB_SIZE {
            assert_eq!(
                observed[i], expected[i],
                "trampoline byte {i:#x} mismatch (emplaced != pure builder)"
            );
        }
    }

    #[test]
    fn place_trampoline_blob_starts_with_cli_cld_in_memory() {
        // Sanity-check the first two opcodes of the emplaced blob: the
        // AP starts execution here in real mode, so any drift would
        // surface as a triple-fault before MB14.c.2.c even fires SIPI.
        let (arena, mut mapper, mut alloc) = make_mapper_and_alloc();
        let _ = place_trampoline(&mut alloc, &mut mapper, KERNEL_AP_ENTRY)
            .expect("emplacement should succeed");
        let head = arena.read_bytes(u64::from(TRAMPOLINE_PHYS_BASE), 2);
        assert_eq!(head[0], 0xFA, "trampoline byte 0 must be `cli` (0xFA)");
        assert_eq!(head[1], 0xFC, "trampoline byte 1 must be `cld` (0xFC)");
    }

    #[test]
    fn sipi_vector_matches_trampoline_base() {
        // Pinned invariant: the SIPI vector field is the upper 8 bits
        // of (TRAMPOLINE_PHYS_BASE / 4096). MB14.c.2.c encodes this
        // into the ICR vector field for both SIPI writes.
        const _CHECK: () = assert!(
            (TRAMPOLINE_PHYS_BASE >> 12) <= 0xFF,
            "SIPI vector must fit in 8 bits"
        );
        assert_eq!(TRAMPOLINE_SIPI_VECTOR, 0x08);
    }
}
