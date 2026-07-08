//! Host-mode integration tests for the MB11 userspace plumbing.
//!
//! These tests run on the host (non-x86_64 OK) and exercise the
//! cross-module wiring that the unit tests in each module cannot
//! verify in isolation:
//!
//! - The userprobe ELF parses + the segment iterator returns one
//!   `PT_LOAD` with the expected flags and entry point.
//! - The `AddressSpace::new_with_kernel_half` clones the kernel half
//!   of a synthetic boot PML4 by value (cloning entries 256..512).
//! - The user-stack slot allocator hands out disjoint, guard-page-
//!   separated stack tops.
//! - `validate_user_buffer` rejects out-of-range ptr+len pairs.
//!
//! The Ring 3 entry path itself (the `iretq` trampoline + the
//! `WriteConsole` / `TaskExit` syscall round trip) requires QEMU and
//! the `mb11-userprobe` feature; the assertions in `kmain` boot-wiring
//! produce the smoke output documented in ADR-0004 § Verifica.

#![cfg(feature = "bare-metal")]
#![allow(
    unsafe_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    clippy::uninlined_format_args,
    clippy::doc_markdown,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::unreadable_literal
)]

use nexacore_kernel::{
    bare_metal::{
        address_space::AddressSpace,
        elf_loader::{Elf64, PF_R, PF_X},
        paging::PageMapper,
        user_stack::{USER_STACK_SIZE, USER_STACK_STRIDE, USER_STACK_VA_BASE, slot_writable_base},
        usermode::{USER_HALF_END, ValidateError, validate_user_buffer},
        userprobe::USERPROBE_ELF,
    },
    memory::{BitmapFrameAllocator, PhysAddr},
};

// ----- Userprobe ELF integration ---------------------------------------------

#[test]
fn userprobe_elf_parses_and_advertises_ring3_entry() {
    let elf = Elf64::parse(USERPROBE_ELF).expect("userprobe must parse");
    assert_eq!(elf.entry_point(), 0x4000_0000);

    let segs: Vec<_> = elf.load_segments().collect();
    assert_eq!(segs.len(), 1, "userprobe should have exactly one PT_LOAD");
    let seg = segs[0].expect("PT_LOAD must parse");

    // The entry segment must be marked executable and readable, and the
    // VA must land below USER_HALF_END.
    assert_eq!(seg.virt_addr, 0x4000_0000);
    assert_eq!(seg.flags & PF_X, PF_X);
    assert_eq!(seg.flags & PF_R, PF_R);
    assert!(seg.virt_addr < USER_HALF_END);
}

#[test]
fn userprobe_segment_carries_hello_message() {
    let elf = Elf64::parse(USERPROBE_ELF).unwrap();
    let seg = elf.load_segments().next().unwrap().unwrap();
    // "hello\n" sits at byte 0x29 of the segment data, immediately after
    // the `jmp $` (`eb fe`) instruction.
    assert_eq!(&seg.file_data[0x29..0x2F], b"hello\n");
}

// ----- AddressSpace integration ---------------------------------------------

const ARENA_PHYS_BASE: u64 = 0x0100_0000;
const ARENA_FRAMES: u64 = 32;
const ARENA_SIZE: usize = ARENA_FRAMES as usize * 4096;

struct Arena {
    ptr: *mut u8,
    layout: core::alloc::Layout,
}

impl Arena {
    fn new() -> Self {
        let layout = core::alloc::Layout::from_size_align(ARENA_SIZE, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        Self { ptr, layout }
    }

    fn phys_offset(&self) -> u64 {
        self.ptr as u64 - ARENA_PHYS_BASE
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

fn make_alloc() -> BitmapFrameAllocator<1> {
    let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(ARENA_PHYS_BASE));
    alloc.mark_range_free(PhysAddr(ARENA_PHYS_BASE), ARENA_SIZE as u64);
    alloc
}

#[test]
fn address_space_clones_kernel_half_only() {
    // MB12 invariant — `new_with_kernel_half` clones PML4 entries
    // 256..511. The boot configuration (`BootloaderConfig::
    // dynamic_range_start = 0xFFFF_8000_0000_0000` in `kernel-runner`)
    // keeps every boot-installed mapping in the upper half so this
    // partial clone is sufficient: per-process PML4s see the kernel
    // image / stack / framebuffer / direct map by reference, and the
    // user half stays private.
    let arena = Arena::new();
    let phys_offset = arena.phys_offset();
    let boot_cr3 = PhysAddr(ARENA_PHYS_BASE);

    let mut alloc = make_alloc();
    // Reserve the boot CR3 frame so the allocator hands out frame 1 for
    // the new address space's PML4.
    alloc.mark_range_used(boot_cr3, 4096);

    // Pre-populate the boot PML4 with sentinel values in all 512 entries.
    unsafe {
        let pml4 = phys_offset.wrapping_add(boot_cr3.0) as *mut u64;
        for i in 0..512 {
            core::ptr::write(pml4.add(i), 0xC0FF_EE00_0000_u64 | i as u64);
        }
    }

    let mapper = PageMapper::new(phys_offset, boot_cr3);
    let addr_space =
        AddressSpace::new_with_kernel_half(boot_cr3, &mapper, &mut alloc).expect("clone");

    unsafe {
        let new_pml4 = phys_offset.wrapping_add(addr_space.pml4_phys.0) as *const u64;
        // User half (0..256) MUST be zero.
        for i in 0..256 {
            assert_eq!(
                core::ptr::read(new_pml4.add(i)),
                0,
                "user-half entry {} should be zero (boot mappings live in upper half)",
                i
            );
        }
        // Kernel half (256..512) MUST mirror the boot PML4 entries.
        for i in 256..512 {
            assert_eq!(
                core::ptr::read(new_pml4.add(i)),
                0xC0FF_EE00_0000_u64 | i as u64,
                "kernel-half entry {} should mirror boot CR3",
                i
            );
        }
    }
}

// ----- User-stack slot allocator --------------------------------------------

#[test]
fn user_stack_slots_are_disjoint_with_guard_pages() {
    let s0 = slot_writable_base(0).expect("slot 0");
    let s1 = slot_writable_base(1).expect("slot 1");
    let s2 = slot_writable_base(2).expect("slot 2");

    // Stride invariant.
    assert_eq!(s1 - s0, USER_STACK_STRIDE);
    assert_eq!(s2 - s1, USER_STACK_STRIDE);

    // Each writable base is preceded by a USER_STACK_SIZE-byte guard page.
    assert_eq!(s0 - USER_STACK_VA_BASE, USER_STACK_SIZE);
    // No slot crosses the USER_HALF_END boundary.
    assert!(s2 + USER_STACK_SIZE < USER_HALF_END);
}

// ----- validate_user_buffer --------------------------------------------------

#[test]
fn validate_rejects_kernel_addresses() {
    let arena = Arena::new();
    let mapper = PageMapper::new(arena.phys_offset(), PhysAddr(ARENA_PHYS_BASE));
    let addr_space = AddressSpace {
        pml4_phys: PhysAddr(ARENA_PHYS_BASE),
    };
    // Buffer that starts in user-half but crosses into kernel-half.
    let result = validate_user_buffer(&addr_space, USER_HALF_END - 5, 100, &mapper);
    assert_eq!(result, Err(ValidateError::OutOfRange));
}

#[test]
fn validate_accepts_zero_len_anywhere_in_user_half() {
    let arena = Arena::new();
    let mapper = PageMapper::new(arena.phys_offset(), PhysAddr(ARENA_PHYS_BASE));
    let addr_space = AddressSpace {
        pml4_phys: PhysAddr(ARENA_PHYS_BASE),
    };
    assert!(validate_user_buffer(&addr_space, 0x4000_0000, 0, &mapper).is_ok());
}
