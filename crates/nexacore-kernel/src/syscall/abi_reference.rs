//! Machine-readable syscall ABI reference + markdown generator (WS14-01).
//!
//! The authoritative numeric ABI is [`crate::syscall::SyscallNumber`], frozen
//! and name/number-hashed by WS1-12 (`crate::syscall::SYSCALL_ABI`). This
//! module is the *detailed* companion: it pairs every frozen syscall with its
//! full ABI surface — register-level signature, capability gate, possible
//! `errno`s, and a one-line summary — in a single machine-readable table
//! [`crate::syscall::abi_reference::SYSCALL_ABI_REF`].
//!
//! From that one source it:
//!
//! 1. **Generates** the human-readable reference `docs/15-syscall-abi.md`
//!    ([`crate::syscall::abi_reference::render_reference`]) — the document is no longer hand-maintained; the
//!    `examples/gen-syscall-abi.rs` binary writes it.
//! 2. **Pins a detail hash** ([`crate::syscall::abi_reference::SYSCALL_ABI_DETAIL_HASH`] vs
//!    [`crate::syscall::abi_reference::SYSCALL_ABI_DETAIL_HASH_PINNED`]) with a compile-time `const _` guard,
//!    so any change to a *documented detail* (an ABI signature, a capability
//!    gate, an `errno`) trips the build the same way WS1-12's name/number guard
//!    trips on a rename/renumber.
//! 3. **Cross-checks** the detailed table against `SYSCALL_ABI` and the
//!    `SyscallNumber` enum (test `ref_table_agrees_with_frozen_abi`) so the two
//!    sources can never drift.
//! 4. **Stays in sync** with the committed document (test
//!    `generated_doc_matches_committed`) — the host/CI consistency check
//!    (WS14-01.7): regenerate the doc whenever this table changes or the test
//!    fails.
//!
//! Pure `core` + `alloc` (the crate's `extern crate alloc` is unconditional),
//! so the generator compiles under the bare-metal `no_std` build as well; only
//! the markdown-comparison test and the example are host-only.

use alloc::string::String;

use crate::syscall::SYSCALL_ABI_VERSION;

/// One fully-documented syscall in the frozen ABI.
///
/// `number`/`name` MUST mirror the corresponding [`crate::syscall::SyscallNumber`] variant and
/// its [`crate::syscall::SYSCALL_ABI`] row exactly; the cross-check test enforces it.
#[derive(Debug, Clone, Copy)]
pub struct SyscallAbiRef {
    /// Stable syscall number (part of the userspace ABI).
    pub number: u32,
    /// Variant name, matching [`crate::syscall::SyscallNumber`].
    pub name: &'static str,
    /// Register-level signature `(a0, …, a5) -> ret` (`rax`, plus `rdx` where a
    /// two-register return or an `errno` is noted).
    pub abi: &'static str,
    /// Capability gate, or `"—"` when the syscall is unprivileged.
    pub capability: &'static str,
    /// Possible `errno`(s) surfaced (in `rdx` or as a documented sentinel), or
    /// `"—"` when the syscall does not fail with an `errno`.
    pub errno: &'static str,
    /// One-line summary (mirrors the `SyscallNumber` doc comment).
    pub summary: &'static str,
}

/// A subsystem grouping, used to lay out the reference document by decade.
#[derive(Debug, Clone, Copy)]
pub struct SyscallAbiGroup {
    /// Section title, e.g. `"Memory"`.
    pub title: &'static str,
    /// Human-readable number range, e.g. `"1–2"`.
    pub range: &'static str,
    /// NCIP/ADR provenance note, or `""`.
    pub note: &'static str,
    /// Inclusive first number of the group.
    pub first: u32,
    /// Inclusive last number of the group.
    pub last: u32,
}

/// The frozen syscall ABI in full detail — the single source of truth for the
/// generated reference document. Sorted by ascending number; mirrors
/// [`crate::syscall::SYSCALL_ABI`] one-to-one.
pub const SYSCALL_ABI_REF: &[SyscallAbiRef] = &[
    // ----- Memory (1–2) -----
    SyscallAbiRef {
        number: 1,
        name: "MemMap",
        abi: "(addr, len, prot, flags, 0, 0) -> va_base",
        capability: "—",
        errno: "—",
        summary: "Map an anonymous page region (mmap-equivalent).",
    },
    SyscallAbiRef {
        number: 2,
        name: "MemUnmap",
        abi: "(addr, len, 0, 0, 0, 0) -> 0",
        capability: "—",
        errno: "—",
        summary: "Unmap a previously-mapped region.",
    },
    // ----- Scheduling / process (10–17) -----
    SyscallAbiRef {
        number: 10,
        name: "TaskCreate",
        abi: "(entry, arg, stack, flags, 0, 0) -> task_id",
        capability: "—",
        errno: "—",
        summary: "Create a new task (process or thread).",
    },
    SyscallAbiRef {
        number: 11,
        name: "TaskExit",
        abi: "(code, 0, 0, 0, 0, 0) -> !",
        capability: "—",
        errno: "—",
        summary: "Terminate the calling task.",
    },
    SyscallAbiRef {
        number: 12,
        name: "TaskYield",
        abi: "(0, 0, 0, 0, 0, 0) -> 0",
        capability: "—",
        errno: "—",
        summary: "Yield the CPU voluntarily.",
    },
    SyscallAbiRef {
        number: 13,
        name: "TaskSleep",
        abi: "(deadline_nanos, 0, 0, 0, 0, 0) -> 0",
        capability: "—",
        errno: "—",
        summary: "Sleep until a monotonic deadline.",
    },
    SyscallAbiRef {
        number: 14,
        name: "ProcessSpawn",
        abi: "(elf_path_ptr, elf_path_len, argv_ptr, argv_count, envp_ptr, envp_count) -> child_pid",
        capability: "—",
        errno: "—",
        summary: "Spawn a process with argv/envp and inherited file descriptors.",
    },
    SyscallAbiRef {
        number: 15,
        name: "ProcessWait",
        abi: "(child_pid, flags, 0, 0, 0, 0) -> (rax=exit_code, rdx=child_pid)",
        capability: "—",
        errno: "ECHILD",
        summary: "Wait for a child to exit (pid 0 = any; flags bit0 = WNOHANG).",
    },
    SyscallAbiRef {
        number: 16,
        name: "GetCwd",
        abi: "(buf_ptr, buf_len, 0, 0, 0, 0) -> path_len",
        capability: "—",
        errno: "EFAULT",
        summary: "Get the calling process's current working directory.",
    },
    SyscallAbiRef {
        number: 17,
        name: "SetCwd",
        abi: "(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "ENOENT / EINVAL",
        summary: "Set the calling process's current working directory.",
    },
    // ----- IPC (20–24) -----
    SyscallAbiRef {
        number: 20,
        name: "IpcCreateChannel",
        abi: "(queue_depth, flags, 0, 0, 0, 0) -> channel_id",
        capability: "per-owner quota",
        errno: "—",
        summary: "Create a new IPC channel.",
    },
    SyscallAbiRef {
        number: 21,
        name: "IpcDestroyChannel",
        abi: "(channel_id, 0, 0, 0, 0, 0) -> 0",
        capability: "owner",
        errno: "—",
        summary: "Destroy a channel.",
    },
    SyscallAbiRef {
        number: 22,
        name: "IpcSend",
        abi: "(channel_id, buf_ptr, buf_len, 0, 0, 0) -> bytes_sent",
        capability: "per-channel token",
        errno: "—",
        summary: "Send a message.",
    },
    SyscallAbiRef {
        number: 23,
        name: "IpcReceive",
        abi: "(channel_id, buf_ptr, buf_len, 0, 0, 0) -> bytes_read",
        capability: "per-channel token",
        errno: "—",
        summary: "Receive a message (blocking — parks the caller until one arrives).",
    },
    SyscallAbiRef {
        number: 24,
        name: "IpcTryReceive",
        abi: "(channel_id, buf_ptr, buf_len, 0, 0, 0) -> (rax=bytes_read, rdx=errno)",
        capability: "per-channel token",
        errno: "EAGAIN",
        summary: "Receive without blocking (EAGAIN when the queue is empty).",
    },
    // ----- Capabilities (30–32) -----
    SyscallAbiRef {
        number: 30,
        name: "CapValidate",
        abi: "(cap_ptr, cap_len, 0, 0, 0, 0) -> 0",
        capability: "—",
        errno: "EACCES",
        summary: "Validate a capability.",
    },
    SyscallAbiRef {
        number: 31,
        name: "CapRevoke",
        abi: "(cap_ptr, cap_len, 0, 0, 0, 0) -> 0",
        capability: "issuer",
        errno: "—",
        summary: "Revoke a capability.",
    },
    SyscallAbiRef {
        number: 32,
        name: "CapAttenuate",
        abi: "(cap_ptr, cap_len, caveat_ptr, caveat_len, out_ptr, out_cap) -> out_len",
        capability: "Macaroons-style",
        errno: "—",
        summary: "Derive an attenuated capability.",
    },
    // ----- TEE / attestation (40–43) -----
    SyscallAbiRef {
        number: 40,
        name: "TeeAttest",
        abi: "(report_data_ptr, len, out_ptr, out_cap, 0, 0) -> quote_len",
        capability: "—",
        errno: "—",
        summary: "Request a TEE attestation quote.",
    },
    SyscallAbiRef {
        number: 41,
        name: "TeeVerifyQuote",
        abi: "(quote_ptr, quote_len, 0, 0, 0, 0) -> 0",
        capability: "—",
        errno: "—",
        summary: "Verify a peer's quote.",
    },
    SyscallAbiRef {
        number: 42,
        name: "TeeSeal",
        abi: "(blob_ptr, blob_len, out_ptr, out_cap, 0, 0) -> sealed_len",
        capability: "—",
        errno: "—",
        summary: "Seal a blob under the current TEE measurement.",
    },
    SyscallAbiRef {
        number: 43,
        name: "TeeUnseal",
        abi: "(sealed_ptr, sealed_len, out_ptr, out_cap, 0, 0) -> blob_len",
        capability: "—",
        errno: "—",
        summary: "Unseal a blob.",
    },
    // ----- Time (50) -----
    SyscallAbiRef {
        number: 50,
        name: "TimeMonotonicNanos",
        abi: "(0, 0, 0, 0, 0, 0) -> nanos_since_boot",
        capability: "—",
        errno: "—",
        summary: "Get monotonic time (nanoseconds since boot).",
    },
    // ----- I/O + file descriptors (60–68) -----
    SyscallAbiRef {
        number: 60,
        name: "WriteConsole",
        abi: "(ptr, len, 0, 0, 0, 0) -> len",
        capability: "—",
        errno: "u64::MAX sentinel on validation failure",
        summary: "Write a user byte slice to the kernel console (COM1).",
    },
    SyscallAbiRef {
        number: 61,
        name: "ReadConsole",
        abi: "(buf_ptr, buf_len, 0, 0, 0, 0) -> bytes_read",
        capability: "—",
        errno: "—",
        summary: "Read from the console input buffer (line-buffered).",
    },
    SyscallAbiRef {
        number: 62,
        name: "PipeCreate",
        abi: "(0, 0, 0, 0, 0, 0) -> (rax=read_fd, rdx=write_fd)",
        capability: "—",
        errno: "—",
        summary: "Create an anonymous pipe.",
    },
    SyscallAbiRef {
        number: 63,
        name: "FdRead",
        abi: "(fd, buf_ptr, buf_len, 0, 0, 0) -> bytes_read",
        capability: "—",
        errno: "EBADF",
        summary: "Read from a file descriptor (console, pipe, or file).",
    },
    SyscallAbiRef {
        number: 64,
        name: "FdWrite",
        abi: "(fd, buf_ptr, buf_len, 0, 0, 0) -> bytes_written",
        capability: "—",
        errno: "EBADF / EPIPE",
        summary: "Write to a file descriptor (console, pipe, or file).",
    },
    SyscallAbiRef {
        number: 65,
        name: "FdClose",
        abi: "(fd, 0, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "EBADF",
        summary: "Close a file descriptor.",
    },
    SyscallAbiRef {
        number: 66,
        name: "FdDup",
        abi: "(fd, 0, 0, 0, 0, 0) -> new_fd",
        capability: "—",
        errno: "EBADF",
        summary: "Duplicate a file descriptor (lowest available number).",
    },
    SyscallAbiRef {
        number: 67,
        name: "FdDup2",
        abi: "(old_fd, new_fd, 0, 0, 0, 0) -> new_fd",
        capability: "—",
        errno: "EBADF",
        summary: "Duplicate a file descriptor to a specific target number.",
    },
    SyscallAbiRef {
        number: 68,
        name: "FdSeek",
        abi: "(fd, offset_i64, whence, 0, 0, 0) -> new_offset",
        capability: "—",
        errno: "EBADF / ESPIPE",
        summary: "Seek on a file descriptor (whence 0=SET, 1=CUR, 2=END).",
    },
    // ----- Driver framework (70–75) — NCIP-013 / NCIP-016 -----
    SyscallAbiRef {
        number: 70,
        name: "MmioMap",
        abi: "(phys_base, len, flags, cap_ptr, cap_len) -> (rax=va_base, rdx=errno)",
        capability: "MmioMap cap",
        errno: "EACCES",
        summary: "Map a PCI BAR MMIO region into the caller's address space.",
    },
    SyscallAbiRef {
        number: 71,
        name: "DmaMap",
        abi: "(iova_base, len, direction, cap_ptr, cap_len) -> 0",
        capability: "DmaMap cap",
        errno: "EACCES",
        summary: "Install an IOMMU DMA window.",
    },
    SyscallAbiRef {
        number: 72,
        name: "IrqAttach",
        abi: "(irq_line, ipc_channel_id, cap_ptr, cap_len, 0) -> 0",
        capability: "IrqAttach cap",
        errno: "EACCES",
        summary: "Attach an IRQ line to a per-driver IPC channel.",
    },
    SyscallAbiRef {
        number: 73,
        name: "DriverLoad",
        abi: "(manifest_ptr, manifest_len, image_ptr, image_len, 0) -> driver_pid",
        capability: "signed manifest",
        errno: "EACCES",
        summary: "Load a signed driver image.",
    },
    SyscallAbiRef {
        number: 74,
        name: "TeeTdcall",
        abi: "(leaf, r10, r11, r12, r13) -> rax_packed",
        capability: "Ring 0 only",
        errno: "—",
        summary: "Issue a kernel-mediated Intel TDX TDCALL.",
    },
    SyscallAbiRef {
        number: 75,
        name: "TeeMsr",
        abi: "(msr_index, value_lo, value_hi, payload_ptr, payload_len) -> 0",
        capability: "Ring 0 only",
        errno: "—",
        summary: "Issue a kernel-mediated SEV-SNP MSR write.",
    },
    // ----- BLK service-channel registry (76–78) — NCIP-Driver-NVMe-014 -----
    SyscallAbiRef {
        number: 76,
        name: "BlkRegister",
        abi: "(disk_slot_ptr, disk_slot_len, channel_id, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "channel owner",
        errno: "EACCES / EEXIST",
        summary: "Record an nexacore.svc.blk.<disk_slot> channel in the registry.",
    },
    SyscallAbiRef {
        number: 77,
        name: "BlkUnregister",
        abi: "(disk_slot_ptr, disk_slot_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "owner",
        errno: "EACCES",
        summary: "Remove an owned BLK channel mapping.",
    },
    SyscallAbiRef {
        number: 78,
        name: "BlkLookup",
        abi: "(disk_slot_ptr, disk_slot_len, 0, 0, 0, 0) -> (rax=channel_id, rdx=0)",
        capability: "read-only",
        errno: "ENOENT",
        summary: "Resolve a BLK disk slot to its live channel id.",
    },
    // ----- Display server (79) — ADR-0040 -----
    SyscallAbiRef {
        number: 79,
        name: "DisplayMap",
        abi: "(offset, len, flags, cap_ptr, cap_len, 0) -> (rax=user_va, rdx=errno)",
        capability: "DisplayMap cap",
        errno: "EACCES",
        summary: "Map the GOP framebuffer (or a sub-window) into a Ring-3 compositor.",
    },
    // ----- AI runtime surface (80–84) — NCIP-Phase2-Entry-021 -----
    SyscallAbiRef {
        number: 80,
        name: "AiInvoke",
        abi: "(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len",
        capability: "AiInvoke cap",
        errno: "EACCES / ENOSPC",
        summary: "Invoke a loaded model for synchronous single-turn inference.",
    },
    SyscallAbiRef {
        number: 81,
        name: "AiStream",
        abi: "(model_id_ptr, model_id_len, input_ptr, input_len, stream_channel_id, 0) -> session_id",
        capability: "AiInvoke cap",
        errno: "EACCES",
        summary: "Start a streaming inference session (tokens delivered via IPC).",
    },
    SyscallAbiRef {
        number: 82,
        name: "AiEmbed",
        abi: "(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len",
        capability: "AiInvoke cap",
        errno: "EACCES / ENOSPC",
        summary: "Compute a dense embedding vector for the given input.",
    },
    SyscallAbiRef {
        number: 83,
        name: "AiClassify",
        abi: "(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len",
        capability: "AiInvoke cap",
        errno: "EACCES / ENOSPC",
        summary: "Classify input into a set of scored categories.",
    },
    SyscallAbiRef {
        number: 84,
        name: "AiTranscribe",
        abi: "(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len",
        capability: "AiInvoke cap",
        errno: "EACCES / ENOSPC",
        summary: "Transcribe an audio buffer reference to text.",
    },
    // ----- Filesystem + process management (90–97) -----
    SyscallAbiRef {
        number: 90,
        name: "FsOpen",
        abi: "(path_ptr, path_len, flags, 0, 0, 0) -> fd",
        capability: "OpenFlags",
        errno: "ENOENT",
        summary: "Open a file and return a file descriptor.",
    },
    SyscallAbiRef {
        number: 91,
        name: "FsStat",
        abi: "(path_ptr, path_len, stat_buf_ptr, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "ENOENT",
        summary: "Stat a file or directory into a FileStat buffer.",
    },
    SyscallAbiRef {
        number: 92,
        name: "FsListDir",
        abi: "(path_ptr, path_len, buf_ptr, buf_len, 0, 0) -> entry_count",
        capability: "—",
        errno: "ENOENT",
        summary: "List the entries in a directory.",
    },
    SyscallAbiRef {
        number: 93,
        name: "FsCreate",
        abi: "(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "EEXIST",
        summary: "Create an empty regular file.",
    },
    SyscallAbiRef {
        number: 94,
        name: "FsDelete",
        abi: "(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "ENOTEMPTY",
        summary: "Delete a file or empty directory.",
    },
    SyscallAbiRef {
        number: 95,
        name: "FsMkdir",
        abi: "(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "EEXIST",
        summary: "Create a directory.",
    },
    SyscallAbiRef {
        number: 96,
        name: "ProcessList",
        abi: "(buf_ptr, buf_len, 0, 0, 0, 0) -> entry_count",
        capability: "—",
        errno: "—",
        summary: "List all running processes.",
    },
    SyscallAbiRef {
        number: 97,
        name: "ProcessKill",
        abi: "(target_pid, 0, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "ESRCH",
        summary: "Terminate another process.",
    },
    // ----- Networking (100–113) — NCIP-Driver-Net-015 -----
    SyscallAbiRef {
        number: 100,
        name: "NetRegister",
        abi: "(if_name_ptr, name_len, channel_id, event_channel_id, mac_ptr, mac_len) -> (rax=0, rdx=errno)",
        capability: "channel owner",
        errno: "EACCES",
        summary: "Record an nexacore.svc.net.<interface> channel pair.",
    },
    SyscallAbiRef {
        number: 101,
        name: "NetUnregister",
        abi: "(if_name_ptr, name_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "owner",
        errno: "EACCES",
        summary: "Remove an owned NET interface mapping.",
    },
    SyscallAbiRef {
        number: 102,
        name: "NetLookup",
        abi: "(if_name_ptr, name_len, 0, 0, 0, 0) -> (rax=channel_id, rdx=event_channel_id)",
        capability: "read-only",
        errno: "ENOENT",
        summary: "Resolve a NET interface to its live channel pair.",
    },
    SyscallAbiRef {
        number: 103,
        name: "NetSocket",
        abi: "(domain, type, 0, 0, 0, 0) -> socket_handle",
        capability: "—",
        errno: "—",
        summary: "Create a new socket handle via the nexacore-net service.",
    },
    SyscallAbiRef {
        number: 104,
        name: "NetBind",
        abi: "(handle, addr_ptr, addr_len, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "EADDRINUSE",
        summary: "Bind a socket handle to a local address.",
    },
    SyscallAbiRef {
        number: 105,
        name: "NetListen",
        abi: "(handle, backlog, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "—",
        summary: "Mark a bound socket as passive (listening).",
    },
    SyscallAbiRef {
        number: 106,
        name: "NetAccept",
        abi: "(handle, addr_buf_ptr, addr_buf_len, 0, 0, 0) -> new_handle",
        capability: "—",
        errno: "—",
        summary: "Accept an incoming connection on a listening socket.",
    },
    SyscallAbiRef {
        number: 107,
        name: "NetConnect",
        abi: "(handle, addr_ptr, addr_len, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "ECONNREFUSED / ETIMEDOUT / ENETUNREACH",
        summary: "Initiate an outgoing connection.",
    },
    SyscallAbiRef {
        number: 108,
        name: "NetSend",
        abi: "(handle, buf_ptr, buf_len, 0, 0, 0) -> bytes_sent",
        capability: "—",
        errno: "ENOTCONN",
        summary: "Send data on a connected socket.",
    },
    SyscallAbiRef {
        number: 109,
        name: "NetRecv",
        abi: "(handle, buf_ptr, buf_len, 0, 0, 0) -> bytes_received",
        capability: "—",
        errno: "ENOTCONN",
        summary: "Receive data from a connected socket.",
    },
    SyscallAbiRef {
        number: 110,
        name: "NetSendTo",
        abi: "(handle, buf_ptr, buf_len, addr_ptr, addr_len, 0) -> bytes_sent",
        capability: "—",
        errno: "—",
        summary: "Send data to an explicit destination (connectionless).",
    },
    SyscallAbiRef {
        number: 111,
        name: "NetRecvFrom",
        abi: "(handle, buf_ptr, buf_len, addr_buf_ptr, 0, 0) -> bytes_received",
        capability: "—",
        errno: "—",
        summary: "Receive data and record the sender's address (connectionless).",
    },
    SyscallAbiRef {
        number: 112,
        name: "NetClose",
        abi: "(handle, 0, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "—",
        summary: "Close a socket handle.",
    },
    SyscallAbiRef {
        number: 113,
        name: "NetShutdown",
        abi: "(handle, how, 0, 0, 0, 0) -> (rax=0, rdx=errno)",
        capability: "—",
        errno: "how: 0=rd, 1=wr, 2=both",
        summary: "Shut down part or all of a full-duplex connection.",
    },
    // ----- System information (114) -----
    SyscallAbiRef {
        number: 114,
        name: "SysInfo",
        abi: "(out_ptr, out_cap, 0, 0, 0, 0) -> (rax=bytes_written=24, rdx=errno)",
        capability: "—",
        errno: "EFAULT: bad/undersized buffer",
        summary: "Read live CPU/RAM telemetry (free_mib, total_mib, cpu_count) into a 24-byte buffer.",
    },
];

/// Subsystem groupings for the generated document, in document order.
pub const SYSCALL_ABI_GROUPS: &[SyscallAbiGroup] = &[
    SyscallAbiGroup {
        title: "Memory",
        range: "1–2",
        note: "",
        first: 1,
        last: 2,
    },
    SyscallAbiGroup {
        title: "Scheduling / process",
        range: "10–17",
        note: "",
        first: 10,
        last: 17,
    },
    SyscallAbiGroup {
        title: "IPC",
        range: "20–24",
        note: "",
        first: 20,
        last: 24,
    },
    SyscallAbiGroup {
        title: "Capabilities",
        range: "30–32",
        note: "",
        first: 30,
        last: 32,
    },
    SyscallAbiGroup {
        title: "TEE / attestation",
        range: "40–43",
        note: "",
        first: 40,
        last: 43,
    },
    SyscallAbiGroup {
        title: "Time",
        range: "50",
        note: "",
        first: 50,
        last: 50,
    },
    SyscallAbiGroup {
        title: "I/O + file descriptors",
        range: "60–68",
        note: "",
        first: 60,
        last: 68,
    },
    SyscallAbiGroup {
        title: "Driver framework",
        range: "70–75",
        note: "NCIP-013 / NCIP-016",
        first: 70,
        last: 75,
    },
    SyscallAbiGroup {
        title: "BLK service-channel registry",
        range: "76–78",
        note: "NCIP-Driver-NVMe-014",
        first: 76,
        last: 78,
    },
    SyscallAbiGroup {
        title: "Display server",
        range: "79",
        note: "ADR-0040",
        first: 79,
        last: 79,
    },
    SyscallAbiGroup {
        title: "AI runtime surface",
        range: "80–84",
        note: "NCIP-Phase2-Entry-021",
        first: 80,
        last: 84,
    },
    SyscallAbiGroup {
        title: "Filesystem + process management",
        range: "90–97",
        note: "",
        first: 90,
        last: 97,
    },
    SyscallAbiGroup {
        title: "Networking",
        range: "100–113",
        note: "NCIP-Driver-Net-015",
        first: 100,
        last: 113,
    },
    SyscallAbiGroup {
        title: "System information",
        range: "114",
        note: "",
        first: 114,
        last: 114,
    },
];

// -----------------------------------------------------------------------------
// Detail hash (WS14-01.6) — trips the build on any documented-detail change
// -----------------------------------------------------------------------------

/// `const`-evaluable FNV-1a 64-bit hash step over `bytes`, folding into `hash`.
/// A tripwire, not a security hash (mirrors `syscall::fnv1a64`, kept local so
/// the WS1-12 name/number guard stays self-contained).
#[allow(
    clippy::indexing_slicing,
    reason = "index i is bounded by the `i < bytes.len()` loop condition"
)]
const fn fnv1a64(bytes: &[u8], mut hash: u64) -> u64 {
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    hash
}

/// Order-sensitive hash of every documented field of [`SYSCALL_ABI_REF`].
///
/// Each entry contributes its little-endian number, then its `name`, `abi`,
/// `capability`, `errno`, and `summary`, each followed by a `0xff` field
/// separator; the table length is folded in last so truncation is detected.
#[allow(
    clippy::indexing_slicing,
    reason = "index i is bounded by the `i < table.len()` loop condition"
)]
const fn compute_detail_hash(table: &[SyscallAbiRef]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 64-bit offset basis
    let mut i = 0;
    while i < table.len() {
        let e = table[i];
        h = fnv1a64(&e.number.to_le_bytes(), h);
        h = fnv1a64(e.name.as_bytes(), h);
        h = fnv1a64(&[0xff], h);
        h = fnv1a64(e.abi.as_bytes(), h);
        h = fnv1a64(&[0xff], h);
        h = fnv1a64(e.capability.as_bytes(), h);
        h = fnv1a64(&[0xff], h);
        h = fnv1a64(e.errno.as_bytes(), h);
        h = fnv1a64(&[0xff], h);
        h = fnv1a64(e.summary.as_bytes(), h);
        h = fnv1a64(&[0xff], h);
        i += 1;
    }
    fnv1a64(&(table.len() as u64).to_le_bytes(), h)
}

/// Compile-time detail hash of [`SYSCALL_ABI_REF`]. Compared against
/// [`SYSCALL_ABI_DETAIL_HASH_PINNED`] by the guard below.
pub const SYSCALL_ABI_DETAIL_HASH: u64 = compute_detail_hash(SYSCALL_ABI_REF);

/// The pinned detail hash for [`crate::syscall::SYSCALL_ABI_VERSION`].
///
/// Currently v2 (adding `SysInfo (114)`). Re-pin ONLY together with a
/// deliberate ABI-detail change AND a regeneration of `docs/15-syscall-abi.md`.
pub const SYSCALL_ABI_DETAIL_HASH_PINNED: u64 = 6_708_899_875_477_705_014;

/// Compile-time guard: any change to a documented ABI detail (an `abi`
/// signature, a `capability` gate, an `errno`, or a summary) flips
/// [`SYSCALL_ABI_DETAIL_HASH`] and fails the build here — forcing the document
/// to be regenerated and the hash re-pinned, exactly as WS1-12's name/number
/// guard does for the surface itself.
const _: () = assert!(
    SYSCALL_ABI_DETAIL_HASH == SYSCALL_ABI_DETAIL_HASH_PINNED,
    "Syscall ABI detail changed: regenerate docs/15-syscall-abi.md \
     (cargo run -p nexacore-kernel --example gen-syscall-abi) and re-pin \
     SYSCALL_ABI_DETAIL_HASH_PINNED to the new SYSCALL_ABI_DETAIL_HASH value."
);

// -----------------------------------------------------------------------------
// Markdown generator (WS14-01.2)
// -----------------------------------------------------------------------------

/// Render the full `docs/15-syscall-abi.md` reference from [`SYSCALL_ABI_REF`].
///
/// The output is the single authoritative form of the document; the
/// `gen-syscall-abi` example writes it and the `generated_doc_matches_committed`
/// test pins the committed file to it. Pure `alloc` — no `std`.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "flat document generator: a linear sequence of section writes mirroring the 1:1 \
              structure of the rendered markdown; splitting it would obscure that correspondence"
)]
pub fn render_reference() -> String {
    use core::fmt::Write as _;

    let mut out = String::with_capacity(8 * 1024);

    // Header + provenance. The detail hash is stamped into the document so the
    // human-readable form carries the same guard value the build checks.
    let _ = writeln!(
        out,
        "# NexaCore OS — Syscall ABI Reference (frozen, versioned)\n"
    );
    let _ = writeln!(
        out,
        "> **ABI version: {SYSCALL_ABI_VERSION}** · **Surface: {} syscalls** · \
         **Detail hash: `{:#018x}`**",
        SYSCALL_ABI_REF.len(),
        SYSCALL_ABI_DETAIL_HASH,
    );
    let _ = writeln!(
        out,
        "> Source of truth: \
         [`crates/nexacore-kernel/src/syscall/abi_reference.rs`](../crates/nexacore-kernel/src/syscall/abi_reference.rs) \
         (`SYSCALL_ABI_REF`).\n"
    );
    let _ = writeln!(
        out,
        "**Generated file — do not edit by hand.** Regenerate with \
         `cargo run -p nexacore-kernel --example gen-syscall-abi > docs/15-syscall-abi.md`. \
         The numeric surface is frozen by WS1-12 (`SyscallNumber` enum + \
         `SYSCALL_ABI` table, `SYSCALL_ABI_HASH` guard); this document and its \
         `SYSCALL_ABI_REF` source add the per-syscall argument / capability / \
         `errno` detail, guarded in turn by `SYSCALL_ABI_DETAIL_HASH`. Any \
         accidental change to the surface or its detail fails the build.\n"
    );

    // Stability policy.
    let _ = writeln!(out, "## Stability policy\n");
    let _ = writeln!(
        out,
        "- **Numbers are immutable after v1.** Never renumber an existing \
         variant; only append new variants (with new numbers) at the end of a \
         decade range."
    );
    let _ = writeln!(
        out,
        "- **Removing a syscall** requires an NCIP and a multi-year \
         deprecation window."
    );
    let _ = writeln!(
        out,
        "- **Numeric ranges are reserved by subsystem** (decades): `1–2` \
         memory, `10–17` scheduling/process, `20–24` IPC, `30–32` \
         capabilities, `40–43` TEE/attestation, `50` time, `60–68` I/O + file \
         descriptors, `70–75` driver framework, `76–78` BLK registry, `79` \
         display, `80–84` AI runtime, `90–97` filesystem + process mgmt, \
         `100–113` networking, `114` system information."
    );
    let _ = writeln!(
        out,
        "- The two-register return convention (`rax`, `rdx`) and the \
         POSIX-aligned `errno` codes are defined in `syscall.rs` \
         (`SyscallReturn`, `syscall_errno`).\n"
    );

    // Versioning.
    let _ = writeln!(out, "## Versioning\n");
    let _ = writeln!(
        out,
        "`SYSCALL_ABI_VERSION` is a single monotonically-increasing integer. \
         Bumping it is the deliberate act of changing the ABI; it MUST \
         accompany: (1) the table edit in `syscall.rs` / `abi_reference.rs`, \
         (2) a re-pin of `SYSCALL_ABI_HASH_PINNED` and \
         `SYSCALL_ABI_DETAIL_HASH_PINNED`, (3) a regeneration of this document, \
         and (4) an NCIP describing the change.\n"
    );

    // Frozen table, grouped by subsystem.
    let _ = writeln!(out, "## Frozen table (v{SYSCALL_ABI_VERSION})\n");
    let _ = writeln!(
        out,
        "Notation: `ABI: (a0, a1, …) -> ret`. Args are the up-to-6 \
         general-purpose register slots; `ret` is `rax` (plus `rdx` where a \
         two-register return or an `errno` is noted). \"Cap\" lists the \
         capability gate where one applies; \"Errno\" lists the documented \
         failure codes.\n"
    );

    for group in SYSCALL_ABI_GROUPS {
        if group.note.is_empty() {
            let _ = writeln!(out, "### {} ({})\n", group.title, group.range);
        } else {
            let _ = writeln!(
                out,
                "### {} ({}) — {}\n",
                group.title, group.range, group.note
            );
        }
        let _ = writeln!(out, "| # | Name | ABI | Cap | Errno | Summary |");
        let _ = writeln!(out, "|---|------|-----|-----|-------|---------|");
        for e in SYSCALL_ABI_REF {
            if e.number >= group.first && e.number <= group.last {
                let _ = writeln!(
                    out,
                    "| {} | `{}` | `{}` | {} | {} | {} |",
                    e.number, e.name, e.abi, e.capability, e.errno, e.summary
                );
            }
        }
        out.push('\n');
    }

    // Errno legend.
    let _ = writeln!(out, "## Errno codes\n");
    let _ = writeln!(
        out,
        "POSIX-aligned, defined in `syscall.rs::syscall_errno`: `ENOENT=2`, \
         `ESRCH=3`, `EIO=5`, `EBADF=9`, `ECHILD=10`, `EAGAIN=11`, `EACCES=13`, \
         `EFAULT=14`, `EEXIST=17`, `EINVAL=22`, `ENOSPC=28`, `ESPIPE=29`, \
         `EPIPE=32`, `ENOSYS=38`, `ENOTEMPTY=39`, `EADDRINUSE=98`, \
         `ENETUNREACH=101`, `ECONNABORTED=103`, `ECONNRESET=104`, \
         `EISCONN=106`, `ENOTCONN=107`, `ETIMEDOUT=110`, `ECONNREFUSED=111`, \
         `EHOSTUNREACH=113`.\n"
    );

    let _ = writeln!(out, "---\n");
    let _ = writeln!(
        out,
        "*Generated under WS14-01 from `SYSCALL_ABI_REF` \
         (`crates/nexacore-kernel/src/syscall/abi_reference.rs`) by the \
         `gen-syscall-abi` example. The numeric surface is frozen by WS1-12; \
         this detail table moves with it under the \
         `SYSCALL_ABI_DETAIL_HASH` guard.*"
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::SYSCALL_ABI;

    /// The detailed table mirrors the frozen `(number, name)` surface exactly,
    /// in the same order — so the two sources can never silently drift.
    #[test]
    fn ref_table_agrees_with_frozen_abi() {
        assert_eq!(
            SYSCALL_ABI_REF.len(),
            SYSCALL_ABI.len(),
            "detailed table has a different syscall count than SYSCALL_ABI"
        );
        for (detail, &(num, name)) in SYSCALL_ABI_REF.iter().zip(SYSCALL_ABI.iter()) {
            assert_eq!(detail.number, num, "number mismatch for {name}");
            assert_eq!(detail.name, name, "name mismatch at number {num}");
        }
    }

    /// Numbers are strictly ascending (matches the document layout and the
    /// `SYSCALL_ABI` invariant).
    #[test]
    fn ref_numbers_strictly_ascending() {
        for w in SYSCALL_ABI_REF.windows(2) {
            assert!(
                w[0].number < w[1].number,
                "numbers not strictly ascending: {} then {}",
                w[0].number,
                w[1].number
            );
        }
    }

    /// Every group covers a contiguous, non-empty slice and every syscall
    /// falls into exactly one group (no orphan rows in the document).
    #[test]
    fn every_syscall_belongs_to_exactly_one_group() {
        for e in SYSCALL_ABI_REF {
            let hits = SYSCALL_ABI_GROUPS
                .iter()
                .filter(|g| e.number >= g.first && e.number <= g.last)
                .count();
            assert_eq!(
                hits, 1,
                "syscall {} ({}) is in {hits} groups",
                e.number, e.name
            );
        }
    }

    /// The detail hash is pinned: any documented-detail edit must be a
    /// deliberate re-pin (the `const _` guard enforces the same at build time).
    #[test]
    fn detail_hash_is_pinned() {
        assert_eq!(
            SYSCALL_ABI_DETAIL_HASH, SYSCALL_ABI_DETAIL_HASH_PINNED,
            "ABI detail hash changed; regenerate the doc and re-pin"
        );
    }

    /// The committed `docs/15-syscall-abi.md` is byte-identical to the
    /// generator output (WS14-01.7 consistency check; runs on host now and in
    /// CI once the doc-build workflow exists).
    #[test]
    fn generated_doc_matches_committed() {
        let committed = include_str!("../../../../docs/15-syscall-abi.md");
        let generated = render_reference();
        assert_eq!(
            committed, generated,
            "docs/15-syscall-abi.md is stale; regenerate with \
             `cargo run -p nexacore-kernel --example gen-syscall-abi > docs/15-syscall-abi.md`"
        );
    }
}
