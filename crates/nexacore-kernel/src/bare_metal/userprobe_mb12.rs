//! MB12 — cross-process IPC smoke probe (sender + receiver ELFs).
//!
//! Two hand-crafted ELF64 binaries that, when spawned together,
//! exercise the entire MB12 IPC path: `IpcCreateChannel`, `IpcSend`,
//! `IpcReceive`, capability gating, and the multi-task scheduler
//! dispatch (TSS.rsp0 + CR3 reload + first-dispatch via
//! `enter_user_mode`).
//!
//! ## Scenario
//!
//! `kmain` pre-creates channel **1** (open, no capability subject set)
//! and spawns two user processes:
//!
//! - [`USERPROBE_RECEIVER_ELF`] — calls `IpcReceive(1, buf, 64, 1)`
//!   blocking; on wake, calls `WriteConsole(buf, bytes_received)` and
//!   `TaskExit(0)`.
//! - [`USERPROBE_SENDER_ELF`] — calls `IpcSend(1, kind=Notification,
//!   "ping", 4)`, then `TaskExit(0)`.
//!
//! With FIFO scheduling and the receiver registered first, the
//! expected serial trace is:
//!
//! ```text
//! [user] exit=0    (sender)
//! ping             (emitted by receiver after IpcReceive completes)
//! [user] exit=0    (receiver)
//! ```
//!
//! ## Why hand-crafted (rather than a separate `nexacore-userprobe-helloworld` crate)
//!
//! A no_std no_main user crate with a `build.rs` cross-build for
//! `x86_64-unknown-none` is tracked as MB13 follow-up; for MB12 the
//! 1:1 hand-crafted byte pattern (mirroring MB11.7's `USERPROBE_ELF`)
//! avoids the recursive-cargo-build fragility entirely. Each probe is
//! a small, self-contained byte literal that the ELF loader and
//! integration tests both consume.
//!
//! ## Syscall ABI quick-reference (used below)
//!
//! | Number | Name              | a0       | a1       | a2          | a3          |
//! |--------|-------------------|----------|----------|-------------|-------------|
//! | 11     | TaskExit          | code     | —        | —           | —           |
//! | 22     | IpcSend           | channel  | kind     | payload_ptr | payload_len |
//! | 23     | IpcReceive        | channel  | dst_ptr  | dst_cap     | blocking    |
//! | 60     | WriteConsole      | ptr      | len      | —           | —           |
//!
//! Linux SysV syscall register mapping: a0=RDI, a1=RSI, a2=RDX,
//! a3=R10, a4=R8, a5=R9. Both probes follow this convention.

#![allow(
    unsafe_code,
    reason = "wraps ProcessControlBlock::spawn_from_elf which is itself unsafe"
)]
#![allow(
    clippy::doc_markdown,
    reason = "module references ELF, RIP-relative addressing, PT_LOAD in prose"
)]

#[cfg(target_arch = "x86_64")]
use crate::{
    KernelResult,
    bare_metal::paging::PageMapper,
    capabilities::KernelPrincipal,
    ipc::{BackpressurePolicy, ChannelPolicy},
    memory::{BitmapFrameAllocator, PhysAddr},
    process::ProcessControlBlock,
    scheduling::{PriorityClass, RoundRobinScheduler, TaskId},
};

// =============================================================================
// USERPROBE_SENDER_ELF
// =============================================================================
//
// Code layout (offsets relative to segment start, mapped at 0x4000_0000):
//
//   0x00: mov rax, 22           ; IpcSend                      (7 bytes)
//   0x07: mov rdi, 1            ; channel_id                    (7 bytes)
//   0x0E: mov rsi, 3            ; kind = Notification           (7 bytes)
//   0x15: lea rdx, [rip+0x1B]   ; payload_ptr → "ping"          (7 bytes)
//   0x1C: mov r10, 4            ; payload_len                   (7 bytes)
//   0x23: syscall                                               (2 bytes)
//   0x25: mov rax, 11           ; TaskExit                      (7 bytes)
//   0x2C: mov rdi, 0            ; exit_code                     (7 bytes)
//   0x33: syscall                                               (2 bytes)
//   0x35: jmp $                 ; belt+suspenders               (2 bytes)
//   0x37: "ping"                                                (4 bytes)
//
// lea displacement: target (0x37) − (lea_va + 7 = 0x1C) = 0x1B. ✓
//
// Segment: file_size = mem_size = 59 (0x3B). PF_R | PF_X = 5.

/// Hand-crafted ELF64 carrying the MB12 IPC sender code path.
///
/// Total: 0x78 (header + phdr) + 0x3B (code+data) = 179 bytes.
pub const USERPROBE_SENDER_ELF: &[u8] = &[
    // -------------------------------------------------------------------
    // ELF64 header — 64 bytes
    // -------------------------------------------------------------------
    0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00, // e_type = ET_EXEC
    0x3e, 0x00, // e_machine = EM_X86_64
    0x01, 0x00, 0x00, 0x00, // e_version = 1
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // e_entry = 0x4000_0000
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff = 0x40
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff = 0
    0x00, 0x00, 0x00, 0x00, // e_flags
    0x40, 0x00, // e_ehsize = 64
    0x38, 0x00, // e_phentsize = 56
    0x01, 0x00, // e_phnum = 1
    0x00, 0x00, // e_shentsize
    0x00, 0x00, // e_shnum
    0x00, 0x00, // e_shstrndx
    // -------------------------------------------------------------------
    // Program header — 56 bytes (PT_LOAD, R+X)
    // -------------------------------------------------------------------
    0x01, 0x00, 0x00, 0x00, // p_type = PT_LOAD
    0x05, 0x00, 0x00, 0x00, // p_flags = PF_R | PF_X
    0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset = 0x78
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // p_vaddr = 0x4000_0000
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // p_paddr = 0x4000_0000
    0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz = 59
    0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz  = 59
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align  = 0x1000
    // -------------------------------------------------------------------
    // Code + data — 59 bytes at file offset 0x78
    // -------------------------------------------------------------------
    // mov rax, 22 (IpcSend)
    0x48, 0xc7, 0xc0, 0x16, 0x00, 0x00, 0x00, // mov rdi, 1 (channel_id)
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rsi, 3 (kind = Notification)
    0x48, 0xc7, 0xc6, 0x03, 0x00, 0x00, 0x00, // lea rdx, [rip+0x1B] (→ "ping")
    0x48, 0x8d, 0x15, 0x1b, 0x00, 0x00, 0x00, // mov r10, 4 (payload_len)
    0x49, 0xc7, 0xc2, 0x04, 0x00, 0x00, 0x00, // syscall
    0x0f, 0x05, // mov rax, 11 (TaskExit)
    0x48, 0xc7, 0xc0, 0x0b, 0x00, 0x00, 0x00, // mov rdi, 0
    0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00, // syscall
    0x0f, 0x05, // jmp $
    0xeb, 0xfe, // "ping" (4 bytes)
    b'p', b'i', b'n', b'g',
];

// =============================================================================
// USERPROBE_RECEIVER_ELF
// =============================================================================
//
// Code layout (offsets relative to segment start, mapped at 0x4000_0000):
//
//   0x00: mov rax, 23           ; IpcReceive                    (7 bytes)
//   0x07: mov rdi, 1            ; channel_id                    (7 bytes)
//   0x0E: lea rsi, [rip+0x38]   ; dst_ptr → buf                 (7 bytes)
//   0x15: mov rdx, 64           ; dst_cap                       (7 bytes)
//   0x1C: mov r10, 1            ; blocking = true               (7 bytes)
//   0x23: syscall                                               (2 bytes)
//   0x25: mov r11, rax          ; save bytes_received           (3 bytes)
//   0x28: mov rax, 60           ; WriteConsole                  (7 bytes)
//   0x2F: lea rdi, [rip+0x17]   ; ptr → buf                     (7 bytes)
//   0x36: mov rsi, r11          ; len                           (3 bytes)
//   0x39: syscall                                               (2 bytes)
//   0x3B: mov rax, 11           ; TaskExit                      (7 bytes)
//   0x42: mov rdi, 0                                            (7 bytes)
//   0x49: syscall                                               (2 bytes)
//   0x4B: jmp $                                                 (2 bytes)
//   0x4D: buf — 64-byte BSS slot                                (64 bytes)
//
// lea displacement 1 (rsi @ 0x0E): target (0x4D) − (0x0E + 7 = 0x15) = 0x38. ✓
// lea displacement 2 (rdi @ 0x2F): target (0x4D) − (0x2F + 7 = 0x36) = 0x17. ✓
//
// Segment: file_size = 0x4D (77, code+jmp), mem_size = 0x8D (141, +64 BSS).
// PF_R | PF_W | PF_X = 7 (writable buf in same page as code — phase 1 only).

/// Hand-crafted ELF64 carrying the MB12 IPC receiver code path.
///
/// Total: 0x78 (header + phdr) + 0x4D (code) = 197 bytes on disk.
/// In memory, the loaded segment occupies 141 bytes (BSS-extended).
pub const USERPROBE_RECEIVER_ELF: &[u8] = &[
    // -------------------------------------------------------------------
    // ELF64 header — 64 bytes
    // -------------------------------------------------------------------
    0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00, // e_type = ET_EXEC
    0x3e, 0x00, // e_machine = EM_X86_64
    0x01, 0x00, 0x00, 0x00, // e_version = 1
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // e_entry = 0x4000_0000
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff = 0x40
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff = 0
    0x00, 0x00, 0x00, 0x00, // e_flags
    0x40, 0x00, // e_ehsize = 64
    0x38, 0x00, // e_phentsize = 56
    0x01, 0x00, // e_phnum = 1
    0x00, 0x00, // e_shentsize
    0x00, 0x00, // e_shnum
    0x00, 0x00, // e_shstrndx
    // -------------------------------------------------------------------
    // Program header — 56 bytes (PT_LOAD, R+W+X for code+buf same page)
    // -------------------------------------------------------------------
    0x01, 0x00, 0x00, 0x00, // p_type = PT_LOAD
    0x07, 0x00, 0x00, 0x00, // p_flags = PF_R | PF_W | PF_X
    0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset = 0x78
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // p_vaddr = 0x4000_0000
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // p_paddr = 0x4000_0000
    0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz = 77
    0x8d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz  = 141 (+64 BSS)
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align  = 0x1000
    // -------------------------------------------------------------------
    // Code — 77 bytes at file offset 0x78
    // -------------------------------------------------------------------
    // mov rax, 23 (IpcReceive)
    0x48, 0xc7, 0xc0, 0x17, 0x00, 0x00, 0x00, // mov rdi, 1 (channel_id)
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
    // lea rsi, [rip+0x38] (→ buf at offset 0x4D)
    0x48, 0x8d, 0x35, 0x38, 0x00, 0x00, 0x00, // mov rdx, 64 (dst_cap)
    0x48, 0xc7, 0xc2, 0x40, 0x00, 0x00, 0x00, // mov r10, 1 (blocking = true)
    0x49, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00, // syscall — rax = bytes_received
    0x0f, 0x05, // mov r11, rax
    0x49, 0x89, 0xc3, // mov rax, 60 (WriteConsole)
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // lea rdi, [rip+0x17] (→ buf)
    0x48, 0x8d, 0x3d, 0x17, 0x00, 0x00, 0x00, // mov rsi, r11 (len)
    0x4c, 0x89, 0xde, // syscall
    0x0f, 0x05, // mov rax, 11 (TaskExit)
    0x48, 0xc7, 0xc0, 0x0b, 0x00, 0x00, 0x00, // mov rdi, 0
    0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00, // syscall
    0x0f, 0x05, // jmp $
    0xeb, 0xfe,
];

// =============================================================================
// Boot helper — spawn the pair
// =============================================================================

/// Bring up the MB12 IPC cross-process smoke: pre-create channel 1,
/// spawn receiver + sender, both registered as `Runnable` on the
/// scheduler. Returns `(receiver_id, sender_id)`.
///
/// `kmain` calls this once, then yields its bootstrap task to let
/// the scheduler dispatch the user processes.
///
/// # Errors
///
/// - [`crate::KernelError::ResourceExhausted`] from frame allocator or
///   from a malformed registry interaction.
/// - [`crate::KernelError::InvalidArgument`] if the embedded ELF bytes
///   fail to parse (would indicate a typo in this file's byte arrays).
///
/// # Safety
///
/// Caller must own the kernel singletons (single-CPU, no aliasing).
#[cfg(target_arch = "x86_64")]
pub unsafe fn spawn_userprobe_mb12<const N: usize>(
    mapper: &mut PageMapper,
    alloc: &mut BitmapFrameAllocator<N>,
    scheduler: &mut RoundRobinScheduler,
) -> KernelResult<(TaskId, TaskId)> {
    use crate::ipc::ipc_registry_mut;

    let boot_cr3 = PhysAddr(mapper.root_phys.0);

    // SAFETY: caller invariants documented above.
    let receiver_id = unsafe {
        ProcessControlBlock::spawn_from_elf(
            USERPROBE_RECEIVER_ELF,
            boot_cr3,
            mapper,
            alloc,
            scheduler,
            PriorityClass::Interactive,
            KernelPrincipal::ZERO,
        )?
    };

    // SAFETY: same as above.
    let sender_id = unsafe {
        ProcessControlBlock::spawn_from_elf(
            USERPROBE_SENDER_ELF,
            boot_cr3,
            mapper,
            alloc,
            scheduler,
            PriorityClass::Interactive,
            KernelPrincipal::ZERO,
        )?
    };

    // Pre-create the channel the probes will use. The kernel owns it
    // (the synthetic principal is `KernelPrincipal::ZERO`; the channel
    // is open on both directions, matching the probes' assumption).
    //
    // MB13.e: the boot wiring goes through `create_channel_signed`
    // with both token slots `None`; the registry's `(None, None)`
    // shortcut delegates to `create_channel` with the same
    // `Ed25519CapabilityProvider` placeholder we hand in here. Per-IPC
    // verify is identical O(1) shape-matching on either provider, so
    // the open-channel semantics the MB12 probes rely on are preserved.
    // `StubCapabilityProvider` is now `#[cfg(test)]`-only and unreachable
    // from the boot path.
    //
    // SAFETY: IPC_REGISTRY singleton; single-CPU; no other borrow live.
    let _channel = unsafe {
        ipc_registry_mut().create_channel_signed(
            scheduler.current_task_id().unwrap_or(TaskId(0)),
            ChannelPolicy {
                queue_depth: 4,
                backpressure: BackpressurePolicy::Block,
                tee_bound: false,
            },
            None,
            None,
            &crate::capabilities::Ed25519CapabilityProvider::placeholder(),
            0,
        )?
    };

    Ok((receiver_id, sender_id))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "tests assert on fixed-offset slices of a static ELF blob"
)]
mod tests {
    use super::*;
    use crate::bare_metal::elf_loader::{Elf64, PF_R, PF_W, PF_X};

    #[test]
    fn sender_elf_parses() {
        Elf64::parse(USERPROBE_SENDER_ELF).expect("sender ELF parses");
    }

    #[test]
    fn sender_entry_is_0x4000_0000() {
        let elf = Elf64::parse(USERPROBE_SENDER_ELF).unwrap();
        assert_eq!(elf.entry_point(), 0x4000_0000);
    }

    #[test]
    fn sender_segment_is_rx_59_bytes() {
        let elf = Elf64::parse(USERPROBE_SENDER_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        assert_eq!(seg.virt_addr, 0x4000_0000);
        assert_eq!(seg.mem_size, 59);
        assert_eq!(seg.flags, PF_R | PF_X);
    }

    #[test]
    fn sender_payload_is_ping() {
        let elf = Elf64::parse(USERPROBE_SENDER_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        assert_eq!(&seg.file_data[0x37..0x3B], b"ping");
    }

    #[test]
    fn sender_first_syscall_is_ipc_send() {
        let elf = Elf64::parse(USERPROBE_SENDER_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        // mov rax, 22 — first 7 bytes (22 = 0x16 = IpcSend).
        assert_eq!(
            &seg.file_data[0..7],
            &[0x48, 0xc7, 0xc0, 0x16, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn sender_lea_displacement_lands_on_payload() {
        let elf = Elf64::parse(USERPROBE_SENDER_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        // lea rdx, [rip+0x1B] — disp at byte 0x18 = 0x1B.
        assert_eq!(seg.file_data[0x18], 0x1B);
        // (lea_va + 7) = 0x1C; 0x1C + 0x1B = 0x37 = payload offset.
        assert_eq!(0x1C + 0x1B, 0x37);
    }

    #[test]
    fn receiver_elf_parses() {
        Elf64::parse(USERPROBE_RECEIVER_ELF).expect("receiver ELF parses");
    }

    #[test]
    fn receiver_segment_is_rwx_with_bss_buf() {
        let elf = Elf64::parse(USERPROBE_RECEIVER_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        assert_eq!(seg.virt_addr, 0x4000_0000);
        // file_data carries only the code+jmp; mem_size extends 64 bytes
        // of zeroed buffer for the receive scratch space.
        assert_eq!(seg.file_data.len(), 77);
        assert_eq!(seg.mem_size, 141);
        assert_eq!(seg.flags, PF_R | PF_W | PF_X);
    }

    #[test]
    fn receiver_first_syscall_is_ipc_receive() {
        let elf = Elf64::parse(USERPROBE_RECEIVER_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        // mov rax, 23 (= 0x17 = IpcReceive).
        assert_eq!(
            &seg.file_data[0..7],
            &[0x48, 0xc7, 0xc0, 0x17, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn receiver_lea_displacements_land_on_buffer() {
        let elf = Elf64::parse(USERPROBE_RECEIVER_ELF).unwrap();
        let seg = elf.load_segments().next().unwrap().unwrap();
        // lea rsi, [rip+0x38] — disp at byte 0x11 = 0x38.
        assert_eq!(seg.file_data[0x11], 0x38);
        // (lea_va + 7) = 0x15; 0x15 + 0x38 = 0x4D = buf offset.
        assert_eq!(0x15 + 0x38, 0x4D);

        // lea rdi, [rip+0x17] — disp at byte 0x32 = 0x17.
        assert_eq!(seg.file_data[0x32], 0x17);
        // (lea_va + 7) = 0x36; 0x36 + 0x17 = 0x4D = buf offset.
        assert_eq!(0x36 + 0x17, 0x4D);
    }
}
