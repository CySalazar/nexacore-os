//! User-probe spawn helper (MB11.7+ scaffold).
//!
//! Scaffold that boot-wires the embedded user-probe ELF into a Ring 3
//! task via [`ProcessControlBlock::spawn_from_elf`].
//!
//! Until that PR lands, this module holds the boot-wiring glue:
//!
//! - [`USERPROBE_ELF`] — placeholder embedded ELF bytes (currently
//!   reuses the MB5 `TEST_ELF` header-only ELF for syntactic
//!   parity; the real probe replaces the bytes).
//! - [`spawn_userprobe`] — orchestrator entry point: parses the ELF,
//!   builds an `AddressSpace`, allocates a user stack, registers the
//!   `ProcessControlBlock` with the scheduler.
//!
//! Once the real probe is embedded, [`spawn_userprobe`] becomes the
//! single function `kmain` calls to launch the first Ring 3 task.
//! The `iretq` trampoline that actually enters Ring 3 lives in
//! [`super::usermode::enter_user_mode`].

#![allow(
    unsafe_code,
    reason = "wraps ProcessControlBlock::spawn_from_elf which is itself unsafe"
)]
#![allow(
    clippy::doc_markdown,
    reason = "module references ELF, PT_LOAD, p_offset and x86_64 register names in prose"
)]

#[cfg(target_arch = "x86_64")]
use crate::{
    KernelResult,
    bare_metal::paging::PageMapper,
    capabilities::KernelPrincipal,
    memory::{BitmapFrameAllocator, PhysAddr},
    process::ProcessControlBlock,
    scheduling::{PriorityClass, RoundRobinScheduler, TaskId},
};

/// Hand-crafted ELF64 + machine code for the MB11 user probe.
///
/// Issues two syscalls from Ring 3 then loops on itself:
///
/// ```text
///   mov rax, 60          ; WriteConsole
///   lea rdi, [rip+0x1b]  ; ptr → msg
///   mov rsi, 6           ; len
///   syscall
///   mov rax, 11          ; TaskExit
///   mov rdi, 0           ; exit code
///   syscall              ; (never returns — kernel halts)
///   jmp $                ; safety loop
///   msg: "hello\n"
/// ```
///
/// ELF layout (167 bytes total):
/// - Offset 0x00..0x3F — ELF64 header (e_entry = 0x4000_0000)
/// - Offset 0x40..0x77 — single PT_LOAD program header
///     (p_offset = 0x78, p_vaddr = 0x4000_0000, p_filesz = p_memsz = 47)
/// - Offset 0x78..0xA6 — 47 bytes of x86_64 code + "hello\n" data
///
/// The 0x4000_0000 entry point matches the convention used by MB5's
/// `TEST_ELF` and `nexacore-userprobe-helloworld`'s linker layout. The
/// `lea rdi, [rip+disp]` displacement is `msg_va - (lea_va + 7) =
/// 0x4000_0029 - 0x4000_000E = 0x1B`.
///
/// This ELF is a 1:1 representation of what a hypothetical
/// `nexacore-userprobe-helloworld` no_std crate would assemble; embedding
/// the bytes directly avoids a recursive cargo build in `build.rs`
/// (closes MB11.7 without the build-script complexity).
pub const USERPROBE_ELF: &[u8] = &[
    // -------------------------------------------------------------------
    // ELF64 header — 64 bytes
    // -------------------------------------------------------------------
    // e_ident[0..16]: magic + class64 + LE + version + osabi + padding
    0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, // e_type = ET_EXEC (2)
    0x02, 0x00, // e_machine = EM_X86_64 (62)
    0x3e, 0x00, // e_version = 1
    0x01, 0x00, 0x00, 0x00, // e_entry = 0x4000_0000
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // e_phoff = 0x40
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // e_flags = 0, e_ehsize = 64, e_phentsize = 56, e_phnum = 1
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00,
    // e_shentsize = 0, e_shnum = 0, e_shstrndx = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // -------------------------------------------------------------------
    // Program header — 56 bytes (PT_LOAD)
    // -------------------------------------------------------------------
    // p_type = PT_LOAD (1)
    0x01, 0x00, 0x00, 0x00, // p_flags = PF_R | PF_X (5)
    0x05, 0x00, 0x00, 0x00, // p_offset = 0x78 (immediately after the program header)
    0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr = 0x4000_0000
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // p_paddr = 0x4000_0000
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // p_filesz = 47 bytes
    0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz = 47 bytes (no BSS)
    0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align = 0x1000 (4 KiB)
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // -------------------------------------------------------------------
    // Code + data at file offset 0x78, mapped to VA 0x4000_0000 — 47 bytes
    // -------------------------------------------------------------------
    // mov rax, 60                                — 7 bytes
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,
    // lea rdi, [rip + 0x1b]   (→ "hello\n")     — 7 bytes
    0x48, 0x8d, 0x3d, 0x1b, 0x00, 0x00, 0x00,
    // mov rsi, 6                                 — 7 bytes
    0x48, 0xc7, 0xc6, 0x06, 0x00, 0x00, 0x00,
    // syscall  (WriteConsole)                    — 2 bytes
    0x0f, 0x05, // mov rax, 11                                — 7 bytes
    0x48, 0xc7, 0xc0, 0x0b, 0x00, 0x00, 0x00,
    // mov rdi, 0                                 — 7 bytes
    0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00,
    // syscall  (TaskExit)                        — 2 bytes
    0x0f, 0x05,
    // jmp $   (loop on self — TaskExit halts kernel; this is belt+suspenders) — 2 bytes
    0xeb, 0xfe, // "hello\n"                                  — 6 bytes
    b'h', b'e', b'l', b'l', b'o', b'\n',
];

/// Spawn the embedded user-probe binary as a Ring 3 process.
///
/// Reads CR3 to anchor the per-process page-table clone, parses
/// [`USERPROBE_ELF`], allocates a user stack, registers the
/// `ProcessControlBlock` with the scheduler. The first dispatch tick
/// after this call will hand the CPU to the new task via
/// [`super::usermode::enter_user_mode`].
///
/// # Errors
///
/// Same as [`ProcessControlBlock::spawn_from_elf`].
///
/// # Safety
///
/// The caller must own the kernel singletons (single-CPU, no aliasing).
#[cfg(target_arch = "x86_64")]
pub unsafe fn spawn_userprobe<const N: usize>(
    mapper: &mut PageMapper,
    alloc: &mut BitmapFrameAllocator<N>,
    scheduler: &mut RoundRobinScheduler,
) -> KernelResult<TaskId> {
    // SAFETY: caller invariants documented above.
    unsafe {
        let boot_cr3 = PhysAddr(mapper.root_phys.0);
        ProcessControlBlock::spawn_from_elf(
            USERPROBE_ELF,
            boot_cr3,
            mapper,
            alloc,
            scheduler,
            PriorityClass::Interactive,
            // MB11 user-probe is a kernel-spawned developer smoke test;
            // no userspace authority has minted it a token. The zero
            // principal is the conventional "unauthenticated kernel
            // task" identity used in dev mode.
            KernelPrincipal::ZERO,
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "tests assert on fixed-offset slices of a static ELF blob"
)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::bare_metal::elf_loader::{Elf64, PF_R, PF_X};

    #[test]
    fn elf_parses_cleanly() {
        Elf64::parse(USERPROBE_ELF).expect("userprobe ELF should parse");
    }

    #[test]
    fn elf_entry_is_0x4000_0000() {
        let elf = Elf64::parse(USERPROBE_ELF).unwrap();
        assert_eq!(elf.entry_point(), 0x4000_0000);
    }

    #[test]
    fn single_load_segment_with_rx_flags() {
        let elf = Elf64::parse(USERPROBE_ELF).unwrap();
        let segs: alloc::vec::Vec<_> = elf.load_segments().collect();
        assert_eq!(segs.len(), 1);
        let seg = segs[0].expect("PT_LOAD must parse");
        assert_eq!(seg.virt_addr, 0x4000_0000);
        assert_eq!(seg.mem_size, 47);
        assert_eq!(seg.flags & PF_X, PF_X);
        assert_eq!(seg.flags & PF_R, PF_R);
    }

    #[test]
    fn code_carries_hello_message() {
        let elf = Elf64::parse(USERPROBE_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        // "hello\n" lives at the end of the segment (offset 0x29 .. 0x2F).
        assert_eq!(&seg.file_data[0x29..0x2F], b"hello\n");
    }

    #[test]
    fn code_opens_with_syscall_setup() {
        let elf = Elf64::parse(USERPROBE_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        // mov rax, 60 — first 7 bytes.
        assert_eq!(
            &seg.file_data[0..7],
            &[0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn lea_displacement_points_at_message() {
        let elf = Elf64::parse(USERPROBE_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        // lea rdi, [rip+0x1b] — bytes 7..14: 48 8d 3d 1b 00 00 00
        assert_eq!(
            &seg.file_data[7..14],
            &[0x48, 0x8d, 0x3d, 0x1b, 0x00, 0x00, 0x00]
        );
        // The displacement (0x1b at byte 10) plus the lea-instruction end
        // (byte 14 = lea_va + 7) must point at the "hello\n" message
        // start (byte 0x29 = 41). 14 + 0x1B = 41. ✓
        assert_eq!(14 + 0x1B, 0x29);
    }
}
