//! System call dispatch.
//!
//! ## Status
//!
//! P6.5 scaffold. The syscall *number* enumeration is locked in for
//! the v0.1 protocol surface; the actual dispatcher (which lives in
//! arch-specific entry code, e.g. `int 0x80` / `syscall` / `sysenter`
//! handlers on `x86_64`) is owned by the bootloader integration in P6.2.
//!
//! ## Design rationale
//!
//! - **Stable numeric ABI.** Syscall numbers are immutable after v1.0;
//!   adding a syscall is an NCIP. This is the closest the kernel comes
//!   to a userspace ABI guarantee.
//! - **Capability-checked at the entry point.** Every syscall validates
//!   the caller's capability for the requested action before dispatching
//!   to the subsystem.
//! - **Small surface.** The v1 kernel exposes a deliberately small set
//!   of syscalls. Higher-level functionality (e.g. AI invocation) is
//!   provided by userspace services reached via IPC, not by direct
//!   syscall.

#![allow(
    clippy::missing_errors_doc,
    reason = "trait scaffold dispatch returns NotYetImplemented until MB11/MB12 wire handlers"
)]

use crate::KernelResult;

/// Detailed, machine-readable ABI reference + markdown generator (WS14-01).
///
/// The frozen numeric surface below is the authority; `abi_reference` adds the
/// per-syscall argument / capability / `errno` detail and generates
/// `docs/15-syscall-abi.md` from a single source, under its own detail-hash
/// guard.
pub mod abi_reference;

// -----------------------------------------------------------------------------
// Syscall numbers
// -----------------------------------------------------------------------------

/// Stable numeric identifiers for kernel syscalls.
///
/// **The numeric value is part of the userspace ABI.** Do NOT renumber
/// existing variants; only append new variants at the end. Removing a
/// variant requires an NCIP and a multi-year deprecation window.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallNumber {
    // ----- Memory -----
    /// `mmap` equivalent: map an anonymous page region.
    MemMap = 1,
    /// Unmap a previously-mapped region.
    MemUnmap = 2,

    // ----- Scheduling / process -----
    /// Create a new task (process or thread).
    TaskCreate = 10,
    /// Terminate the calling task.
    TaskExit = 11,
    /// Yield the CPU voluntarily.
    TaskYield = 12,
    /// Sleep until a deadline.
    TaskSleep = 13,
    /// Spawn a new process with argv/envp and inherited file descriptors.
    /// ABI: `(elf_path_ptr, elf_path_len, argv_ptr, argv_count, envp_ptr, envp_count) -> child_pid`.
    ProcessSpawn = 14,
    /// Wait for a child process to exit.
    /// ABI: `(child_pid, flags, 0, 0, 0, 0) -> (rax=exit_code, rdx=child_pid)`.
    /// Pass `child_pid = 0` to wait for any child. Flags: bit 0 = WNOHANG.
    ProcessWait = 15,
    /// Get the calling process's current working directory.
    /// ABI: `(buf_ptr, buf_len, 0, 0, 0, 0) -> path_len`.
    GetCwd = 16,
    /// Set the calling process's current working directory.
    /// ABI: `(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    SetCwd = 17,

    // ----- IPC -----
    /// Create a new channel.
    IpcCreateChannel = 20,
    /// Destroy a channel.
    IpcDestroyChannel = 21,
    /// Send a message.
    IpcSend = 22,
    /// Receive a message (blocking: parks the caller until a message is
    /// available on the channel).
    IpcReceive = 23,
    /// Receive a message without blocking.
    ///
    /// ABI: `(channel_id, buf_ptr, buf_len, 0, 0, 0) -> (rax = bytes_read,
    /// rdx = errno)`. Returns `rdx = EAGAIN` when the channel queue is empty
    /// instead of parking the caller. This is the non-blocking counterpart of
    /// [`SyscallNumber::IpcReceive`], required by userspace services that must
    /// poll more than one channel without starving any of them (e.g. the
    /// `nexacore-net` service polling both the socket-API channel and the NIC
    /// driver event channel; the virtio-net driver polling both its command
    /// channel and its IRQ-notify channel).
    IpcTryReceive = 24,

    // ----- Capabilities -----
    /// Validate a capability.
    CapValidate = 30,
    /// Revoke a capability.
    CapRevoke = 31,
    /// Derive an attenuated capability (Macaroons-style).
    CapAttenuate = 32,

    // ----- TEE / Attestation -----
    /// Request a TEE attestation quote.
    TeeAttest = 40,
    /// Verify a peer's quote.
    TeeVerifyQuote = 41,
    /// Seal a blob under the current TEE measurement.
    TeeSeal = 42,
    /// Unseal a blob.
    TeeUnseal = 43,

    // ----- Time -----
    /// Get monotonic time (nanoseconds since boot).
    TimeMonotonicNanos = 50,

    // ----- I/O (MB11) -----
    /// Write a user-supplied byte slice to the kernel console. ABI:
    /// `(ptr: u64, len: u64) -> u64`. Returns `len` on success or
    /// `u64::MAX` on a validation failure.
    WriteConsole = 60,
    /// Read bytes from the console input buffer (keyboard / serial).
    /// ABI: `(buf_ptr, buf_len, 0, 0, 0, 0) -> bytes_read`.
    /// Line-buffered: blocks until `\n` or `buf_len` bytes available.
    ReadConsole = 61,
    /// Create an anonymous pipe.
    /// ABI: `(0, 0, 0, 0, 0, 0) -> (rax=read_fd, rdx=write_fd)`.
    PipeCreate = 62,
    /// Read from a file descriptor (console, pipe, or file).
    /// ABI: `(fd, buf_ptr, buf_len, 0, 0, 0) -> bytes_read`.
    FdRead = 63,
    /// Write to a file descriptor (console, pipe, or file).
    /// ABI: `(fd, buf_ptr, buf_len, 0, 0, 0) -> bytes_written`.
    FdWrite = 64,
    /// Close a file descriptor.
    /// ABI: `(fd, 0, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    FdClose = 65,
    /// Duplicate a file descriptor (lowest available number).
    /// ABI: `(fd, 0, 0, 0, 0, 0) -> new_fd`.
    FdDup = 66,
    /// Duplicate a file descriptor to a specific target number.
    /// ABI: `(old_fd, new_fd, 0, 0, 0, 0) -> new_fd`.
    FdDup2 = 67,
    /// Seek on a file descriptor.
    /// ABI: `(fd, offset_i64, whence, 0, 0, 0) -> new_offset`.
    /// Whence: 0 = `SEEK_SET`, 1 = `SEEK_CUR`, 2 = `SEEK_END`.
    FdSeek = 68,

    // ----- Driver framework (NCIP-013, P6.7.3 skeleton) -----
    // Numeric decade `7x` reserved for the user-space driver framework.
    // See `NCIP-Driver-Framework-013` Appendix A for the reconciliation
    // rationale (the original Draft proposed `22..=25` but those slots
    // are MB12-IPC-locked). Handlers are scaffolded to
    // `KernelError::NotYetImplemented` (ENOSYS-equivalent) until the
    // P6.7.8 first-party driver implementations land.
    //
    /// Map a PCI BAR MMIO region into the caller's address space.
    /// ABI: `(phys_base, len, flags, cap_ptr, cap_len) -> va_base`.
    /// See `NCIP-Driver-Framework-013` § S2.
    MmioMap = 70,
    /// Install an IOMMU DMA window.
    /// ABI: `(iova_base, len, direction, cap_ptr, cap_len) -> 0`.
    /// See `NCIP-Driver-Framework-013` § S3.
    DmaMap = 71,
    /// Attach an IRQ line to a per-driver IPC channel.
    /// ABI: `(irq_line, ipc_channel_id, cap_ptr, cap_len, 0) -> 0`.
    /// See `NCIP-Driver-Framework-013` § S4.
    IrqAttach = 72,
    /// Load a signed driver image.
    /// ABI: `(manifest_ptr, manifest_len, image_ptr, image_len, 0) -> driver_pid`.
    /// See `NCIP-Driver-Framework-013` § S5.
    DriverLoad = 73,
    /// Issue a kernel-mediated TDCALL on Intel TDX (Ring 0 only).
    /// ABI: `(leaf, r10, r11, r12, r13) -> rax_packed`.
    /// See `NCIP-Driver-TEE-016` § S5.3 (editorially reconciled to 74).
    TeeTdcall = 74,
    /// Issue a kernel-mediated SEV-SNP MSR write (Ring 0 only).
    /// ABI: `(msr_index, value_lo, value_hi, payload_ptr, payload_len) -> 0`.
    /// See `NCIP-Driver-TEE-016` § S6.3 (editorially reconciled to 75).
    TeeMsr = 75,

    // ----- BLK service-channel registry (NCIP-Driver-NVMe-014 § S4) -----
    // Numeric range `76..=78` reserved for the kernel-mediated BLK
    // channel registry that backs the `nexacore.svc.blk.<diskN>` IPC
    // channel namespace. Producer drivers (NVMe today, future
    // SATA / virtio-blk) call `BlkRegister` after they create the
    // channel via `IpcCreateChannel`; the consumer filesystem
    // service calls `BlkLookup` to resolve `disk_slot → ChannelId`
    // without sniffing the IPC layer by string. See
    // `NCIP-Driver-NVMe-014` § S4 + § S6 step 12.
    /// Record an `nexacore.svc.blk.<disk_slot>` channel in the kernel
    /// BLK registry. ABI:
    /// `(disk_slot_ptr, disk_slot_len, channel_id, 0, 0, 0) -> (rax=0, rdx=errno)`.
    /// The caller MUST already own the supplied `channel_id`; the
    /// kernel rejects the call with `EACCES` otherwise. Disk-slot
    /// validation matches `crate::services::blk::BlkChannelRegistry::register`
    /// (ASCII `[A-Za-z0-9_-]`, ≤ `MAX_DISK_SLOT_LEN` bytes).
    BlkRegister = 76,
    /// Remove an `nexacore.svc.blk.<disk_slot>` mapping the caller owns.
    /// ABI: `(disk_slot_ptr, disk_slot_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    /// Returns `EACCES` if the caller is not the recorded owner;
    /// task-exit clean-up is handled separately via
    /// `crate::services::blk::BlkChannelRegistry::clear_for_owner`.
    BlkUnregister = 77,
    /// Resolve `nexacore.svc.blk.<disk_slot>` to its live channel id.
    /// ABI: `(disk_slot_ptr, disk_slot_len, 0, 0, 0, 0) -> (rax=channel_id, rdx=0)`
    /// on success; `(rax=0, rdx=ENOENT)` if the slot is not
    /// registered. Read-only — the channel id alone confers no
    /// IPC authority (`IpcSend` / `IpcRecv` still require the
    /// per-channel capability tokens minted at create time).
    BlkLookup = 78,

    // ----- Display server (M3, DE-C1, ADR-0040) -----
    /// Map the GOP framebuffer (or a page-aligned sub-window) into the
    /// calling Ring-3 compositor's address space, NX + writable + uncached.
    /// ABI: `(offset, len, flags, cap_ptr, cap_len, 0) -> (rax=user_va, rdx=errno)`.
    /// `offset`/`len` name a sub-window of THE framebuffer (the kernel
    /// supplies the phys base); both 4 KiB-aligned, `offset + len <=`
    /// framebuffer size. Capability-checked: the caller must present a
    /// `DisplayMap` token scoped to a `Resource::Framebuffer` that
    /// contains the requested window (`EACCES` otherwise). The input-event
    /// path reuses `IpcTryReceive (24)` — no new number. Mirrors
    /// `MmioMap (70)`.
    DisplayMap = 79,

    // ----- Filesystem (shell terminal support) -----
    // Numeric range `90..=95` reserved for the in-kernel VFS syscalls
    // that back the shell's filesystem operations. Phase 1: dispatched
    // directly to `InMemoryVfs`. Phase 2: proxied via IPC to the
    // `nexacore-fs` userspace service.
    /// Open a file and return a file descriptor.
    /// ABI: `(path_ptr, path_len, flags, 0, 0, 0) -> fd`.
    /// Flags follow the `OpenFlags` bitfield (`O_RDONLY`, `O_WRONLY`, `O_RDWR`,
    /// `O_CREAT`, `O_TRUNC`, `O_APPEND`).
    FsOpen = 90,
    /// Stat a file or directory.
    /// ABI: `(path_ptr, path_len, stat_buf_ptr, 0, 0, 0) -> (rax=0, rdx=errno)`.
    /// Writes `FileStat` (inode: u64, size: u64, `file_type`: u8) to `stat_buf_ptr`.
    FsStat = 91,
    /// List the entries in a directory.
    /// ABI: `(path_ptr, path_len, buf_ptr, buf_len, 0, 0) -> entry_count`.
    /// Writes `\n`-separated entry names to `buf_ptr`.
    FsListDir = 92,
    /// Create an empty regular file.
    /// ABI: `(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    FsCreate = 93,
    /// Delete a file or empty directory.
    /// ABI: `(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    FsDelete = 94,
    /// Create a directory.
    /// ABI: `(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    FsMkdir = 95,
    /// List all running processes.
    /// ABI: `(buf_ptr, buf_len, 0, 0, 0, 0) -> entry_count`.
    ProcessList = 96,
    /// Terminate another process.
    /// ABI: `(target_pid, 0, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    ProcessKill = 97,

    // ----- AI Runtime (Phase 2 Sprint 2, NCIP-Phase2-Entry-021 § AI Surface) -----
    // Numeric decade `8x` reserved for the AI syscall surface. These are
    // thin kernel entry points that validate the caller's capability and
    // forward the request via IPC to the `nexacore-runtime` service. The kernel
    // does not interpret inference payloads — it is a capability-checked
    // relay.
    /// Invoke a loaded model for synchronous inference.
    /// ABI: `(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len`.
    /// Capability-checked: caller must hold an `AiInvoke` capability for the target model.
    AiInvoke = 80,

    /// Start a streaming inference session.
    /// ABI: `(model_id_ptr, model_id_len, input_ptr, input_len, stream_channel_id, 0) -> session_id`.
    /// Returns a `session_id` that the caller uses to receive streamed tokens via IPC.
    AiStream = 81,

    /// Compute an embedding vector for the given input.
    /// ABI: `(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len`.
    AiEmbed = 82,

    /// Classify input into a set of categories.
    /// ABI: `(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len`.
    AiClassify = 83,

    /// Transcribe audio input to text.
    /// ABI: `(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len`.
    AiTranscribe = 84,

    // ----- NET service-channel registry (NCIP-Driver-Net-015 § S2) -----
    // Numeric range `100..=113` reserved for the kernel-mediated NET
    // channel registry and the microkernel IPC proxy for socket
    // operations. NIC drivers call `NetRegister` after they create
    // both the command and event channels via `IpcCreateChannel`; the
    // network stack calls `NetLookup` to resolve `interface_name →
    // (ChannelId, EventChannelId)` without sniffing the IPC layer by
    // string. The socket syscalls (103–113) are thin capability-checked
    // relays that forward to the `nexacore-net` user-space network service.
    //
    // See `NCIP-Driver-Net-015` § S2 for the full reconciliation.
    //
    /// Record an `nexacore.svc.net.<interface>` channel pair in the kernel
    /// NET registry. ABI:
    /// `(interface_name_ptr, name_len, channel_id, event_channel_id, mac_ptr, mac_len) -> (rax=0, rdx=errno)`.
    /// The caller MUST already own both supplied channel ids; the
    /// kernel rejects the call with `EACCES` otherwise.
    /// Interface-name validation matches
    /// `crate::services::net::NetChannelRegistry::register`
    /// (ASCII `[A-Za-z0-9_-]`, ≤ `MAX_INTERFACE_NAME_LEN` bytes).
    NetRegister = 100,
    /// Remove an `nexacore.svc.net.<interface>` mapping the caller owns.
    /// ABI: `(interface_name_ptr, name_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    /// Returns `EACCES` if the caller is not the recorded owner;
    /// task-exit clean-up is handled separately via
    /// `crate::services::net::NetChannelRegistry::clear_for_owner`.
    NetUnregister = 101,
    /// Resolve `nexacore.svc.net.<interface>` to its live command channel id.
    /// ABI: `(interface_name_ptr, name_len, 0, 0, 0, 0) -> (rax=channel_id, rdx=0)`
    /// on success; `(rax=0, rdx=ENOENT)` if the interface is not
    /// registered. Read-only.
    NetLookup = 102,
    /// Create a new socket handle via the `nexacore-net` service.
    /// ABI: `(domain, type, 0, 0, 0, 0) -> socket_handle`.
    NetSocket = 103,
    /// Bind a socket handle to a local address.
    /// ABI: `(handle, addr_ptr, addr_len, 0, 0, 0) -> (rax=0, rdx=errno)`.
    NetBind = 104,
    /// Mark a bound socket as passive (listening).
    /// ABI: `(handle, backlog, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    NetListen = 105,
    /// Accept an incoming connection on a listening socket.
    /// ABI: `(handle, addr_buf_ptr, addr_buf_len, 0, 0, 0) -> new_handle`.
    NetAccept = 106,
    /// Initiate an outgoing connection.
    /// ABI: `(handle, addr_ptr, addr_len, 0, 0, 0) -> (rax=0, rdx=errno)`.
    NetConnect = 107,
    /// Send data on a connected socket.
    /// ABI: `(handle, buf_ptr, buf_len, 0, 0, 0) -> bytes_sent`.
    NetSend = 108,
    /// Receive data from a connected socket.
    /// ABI: `(handle, buf_ptr, buf_len, 0, 0, 0) -> bytes_received`.
    NetRecv = 109,
    /// Send data to an explicit destination address (connectionless).
    /// ABI: `(handle, buf_ptr, buf_len, addr_ptr, addr_len, 0) -> bytes_sent`.
    NetSendTo = 110,
    /// Receive data and record the sender's address (connectionless).
    /// ABI: `(handle, buf_ptr, buf_len, addr_buf_ptr, 0, 0) -> bytes_received`.
    NetRecvFrom = 111,
    /// Close a socket handle.
    /// ABI: `(handle, 0, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    NetClose = 112,
    /// Shut down part or all of a full-duplex connection.
    /// ABI: `(handle, how, 0, 0, 0, 0) -> (rax=0, rdx=errno)`.
    /// `how`: 0 = shut read, 1 = shut write, 2 = shut both.
    NetShutdown = 113,
    // ----- System information (telemetry) -----
    /// Read live CPU/RAM telemetry into a caller-supplied 24-byte buffer.
    /// ABI: `(out_ptr, out_cap, 0, 0, 0, 0) -> (rax=bytes_written=24, rdx=errno)`.
    /// Layout (little-endian): `free_mib: u64 @0`, `total_mib: u64 @8`,
    /// `cpu_count: u32 @16`, `_reserved: u32 @20` (24 bytes total).
    SysInfo = 114,
}

// -----------------------------------------------------------------------------
// Frozen syscall ABI table + compile-time integrity guard (WS1-12)
// -----------------------------------------------------------------------------
//
// The `SyscallNumber` enum above is the authoritative numeric ABI. The table
// and hash below freeze that ABI so an accidental renumber, rename, insertion,
// removal, or reorder fails the build (via the `const _` guard) instead of
// silently breaking a driver manifest or userspace binary signed against the
// old surface. The human-readable, versioned table lives in
// `docs/15-syscall-abi.md`; this code is its machine-checkable mirror.

/// Current version of the frozen syscall ABI.
///
/// Format: a single monotonically-increasing integer. Bump it (and re-pin
/// [`SYSCALL_ABI_HASH_PINNED`]) only for a deliberate, NCIP-approved ABI
/// change. v1 froze the 69-syscall surface present at the WS1-12 close; v2
/// adds `SysInfo (114)`, a read-only CPU/RAM telemetry syscall.
pub const SYSCALL_ABI_VERSION: u32 = 2;

/// Frozen `(number, name)` table for every syscall in the userspace ABI.
///
/// MUST stay sorted by ascending number and mirror the [`SyscallNumber`]
/// enum exactly. The companion document `docs/15-syscall-abi.md` carries the
/// full per-syscall argument / capability / errno detail. Any edit here flips
/// [`SYSCALL_ABI_HASH`] and trips the compile-time guard below.
pub const SYSCALL_ABI: &[(u32, &str)] = &[
    // Memory
    (1, "MemMap"),
    (2, "MemUnmap"),
    // Scheduling / process
    (10, "TaskCreate"),
    (11, "TaskExit"),
    (12, "TaskYield"),
    (13, "TaskSleep"),
    (14, "ProcessSpawn"),
    (15, "ProcessWait"),
    (16, "GetCwd"),
    (17, "SetCwd"),
    // IPC
    (20, "IpcCreateChannel"),
    (21, "IpcDestroyChannel"),
    (22, "IpcSend"),
    (23, "IpcReceive"),
    (24, "IpcTryReceive"),
    // Capabilities
    (30, "CapValidate"),
    (31, "CapRevoke"),
    (32, "CapAttenuate"),
    // TEE / attestation
    (40, "TeeAttest"),
    (41, "TeeVerifyQuote"),
    (42, "TeeSeal"),
    (43, "TeeUnseal"),
    // Time
    (50, "TimeMonotonicNanos"),
    // I/O + file descriptors
    (60, "WriteConsole"),
    (61, "ReadConsole"),
    (62, "PipeCreate"),
    (63, "FdRead"),
    (64, "FdWrite"),
    (65, "FdClose"),
    (66, "FdDup"),
    (67, "FdDup2"),
    (68, "FdSeek"),
    // Driver framework (NCIP-013 / NCIP-016)
    (70, "MmioMap"),
    (71, "DmaMap"),
    (72, "IrqAttach"),
    (73, "DriverLoad"),
    (74, "TeeTdcall"),
    (75, "TeeMsr"),
    // BLK service-channel registry (NCIP-Driver-NVMe-014)
    (76, "BlkRegister"),
    (77, "BlkUnregister"),
    (78, "BlkLookup"),
    // Display server (ADR-0040)
    (79, "DisplayMap"),
    // AI runtime surface (NCIP-Phase2-Entry-021)
    (80, "AiInvoke"),
    (81, "AiStream"),
    (82, "AiEmbed"),
    (83, "AiClassify"),
    (84, "AiTranscribe"),
    // Filesystem + process management (shell terminal support)
    (90, "FsOpen"),
    (91, "FsStat"),
    (92, "FsListDir"),
    (93, "FsCreate"),
    (94, "FsDelete"),
    (95, "FsMkdir"),
    (96, "ProcessList"),
    (97, "ProcessKill"),
    // NET service-channel registry + socket IPC proxy (NCIP-Driver-Net-015)
    (100, "NetRegister"),
    (101, "NetUnregister"),
    (102, "NetLookup"),
    (103, "NetSocket"),
    (104, "NetBind"),
    (105, "NetListen"),
    (106, "NetAccept"),
    (107, "NetConnect"),
    (108, "NetSend"),
    (109, "NetRecv"),
    (110, "NetSendTo"),
    (111, "NetRecvFrom"),
    (112, "NetClose"),
    (113, "NetShutdown"),
    // System information (telemetry)
    (114, "SysInfo"),
];

/// `const`-evaluable FNV-1a 64-bit hash step over `bytes`, folding into
/// the running `hash`. Used only for the ABI tripwire — not a security hash.
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

/// Order-sensitive hash of the whole `(number, name)` ABI table.
///
/// Each entry contributes its little-endian number, its UTF-8 name, and a
/// `0xff` separator (so `("Ab","c")` and `("A","bc")` cannot collide); the
/// table length is folded in last so truncation is also detected.
#[allow(
    clippy::indexing_slicing,
    reason = "index i is bounded by the `i < table.len()` loop condition"
)]
const fn compute_abi_hash(table: &[(u32, &str)]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 64-bit offset basis
    let mut i = 0;
    while i < table.len() {
        let (number, name) = table[i];
        h = fnv1a64(&number.to_le_bytes(), h);
        h = fnv1a64(name.as_bytes(), h);
        h = fnv1a64(&[0xff], h);
        i += 1;
    }
    fnv1a64(&(table.len() as u64).to_le_bytes(), h)
}

/// Compile-time hash of [`SYSCALL_ABI`]. Compared against
/// [`SYSCALL_ABI_HASH_PINNED`] by the guard below.
pub const SYSCALL_ABI_HASH: u64 = compute_abi_hash(SYSCALL_ABI);

/// The pinned hash for [`SYSCALL_ABI_VERSION`] (v2: the 70-syscall surface,
/// adding `SysInfo (114)`). Re-pin ONLY together with a deliberate,
/// NCIP-approved ABI change.
///
/// Public so the pinned value is part of the documented ABI surface; it is
/// consumed by the `const _` guard below and the `abi_hash_is_pinned` test.
pub const SYSCALL_ABI_HASH_PINNED: u64 = 17_133_148_374_168_782_533;

/// Compile-time guard: an accidental change to [`SYSCALL_ABI`] (renumber,
/// rename, insert, remove, or reorder) flips [`SYSCALL_ABI_HASH`] and fails
/// the build here, forcing an explicit ABI-version bump instead of a silent
/// break of a signed driver manifest or a userspace binary.
const _: () = assert!(
    SYSCALL_ABI_HASH == SYSCALL_ABI_HASH_PINNED,
    "Syscall ABI changed: update docs/15-syscall-abi.md, bump \
     SYSCALL_ABI_VERSION, and re-pin SYSCALL_ABI_HASH_PINNED to the new \
     SYSCALL_ABI_HASH value."
);

// -----------------------------------------------------------------------------
// Two-register return value (NCIP-013 § S2)
// -----------------------------------------------------------------------------

/// Two-register syscall return value.
///
/// The single-register dispatch path returns its value in `RAX`. Some
/// syscalls — initially `MmioMap` per `NCIP-Driver-Framework-013` § S2 —
/// also report a POSIX-style error code in `RDX`. The `#[repr(C)]`
/// layout matches the System V AMD64 return convention for a struct
/// of two `INTEGER`-class fields: `rax = first u64`, `rdx = second
/// u64`. The kernel's `extern "C"` syscall dispatcher returns this
/// type by value; the assembly trampoline preserves RDX through to
/// the user-mode `sysretq` / `iretq` so user space observes the pair.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyscallReturn {
    /// Primary return value (`RAX`). Convention: non-zero on success
    /// for handlers that return a handle/VA/length; zero on hard
    /// errors when paired with a non-zero `rdx`.
    pub rax: u64,
    /// Secondary return value (`RDX`). `0` on success; one of the
    /// [`syscall_errno`] codes on error.
    pub rdx: u64,
}

impl SyscallReturn {
    /// Build a successful return with the supplied primary value and
    /// `rdx = 0` (no error).
    #[must_use]
    pub const fn ok(rax: u64) -> Self {
        Self { rax, rdx: 0 }
    }

    /// Build a successful return carrying two values: a primary value (`rax`)
    /// and a secondary value (`rdx`). Used by syscalls that return a pair on
    /// success rather than an errno in `rdx` — e.g. `NetLookup` returns the
    /// command channel id in `rax` and the event channel id in `rdx`.
    #[must_use]
    pub const fn ok2(primary: u64, secondary: u64) -> Self {
        Self {
            rax: primary,
            rdx: secondary,
        }
    }

    /// Build an error return with `rax = 0` and the supplied errno
    /// code in `rdx`.
    #[must_use]
    #[allow(
        clippy::similar_names,
        reason = "rax/rdx are the canonical x86_64 return-register names"
    )]
    pub const fn err(errno: u64) -> Self {
        Self { rax: 0, rdx: errno }
    }
}

/// POSIX-aligned syscall errno codes used in the two-register return
/// path. Numbering follows Linux `errno-base.h` for the subset that
/// `NCIP-Driver-Framework-013` § S2.3 references.
pub mod syscall_errno {
    /// No such entry — used by the BLK lookup syscall when the
    /// requested disk slot is not registered. POSIX `ENOENT = 2`.
    pub const ENOENT: u64 = 2;
    /// Permission denied — capability verification failed.
    pub const EACCES: u64 = 13;
    /// Bad address — user pointer or length is invalid.
    pub const EFAULT: u64 = 14;
    /// Invalid argument — alignment, range, or reserved bits.
    pub const EINVAL: u64 = 22;
    /// No space left — driver VA range exhausted, or BLK registry
    /// full (`MAX_BLK_CHANNELS`).
    pub const ENOSPC: u64 = 28;
    /// Function not implemented — feature requires runtime support
    /// that has not been initialised (e.g. PAT for WC mappings).
    pub const ENOSYS: u64 = 38;
    /// Object already exists — BLK registry already holds an entry
    /// for the requested disk slot. POSIX `EEXIST = 17`.
    pub const EEXIST: u64 = 17;
    /// Internal kernel invariant violation — surfaces
    /// `crate::services::blk::BlkRegistryError::Internal` at
    /// the BLK syscall boundary without aborting the kernel. POSIX
    /// `EIO = 5`.
    pub const EIO: u64 = 5;
    /// Bad file descriptor — `fd` is not open or is not valid.
    /// POSIX `EBADF = 9`.
    pub const EBADF: u64 = 9;
    /// No child processes — `ProcessWait` called but the caller has no
    /// children to wait for. POSIX `ECHILD = 10`.
    pub const ECHILD: u64 = 10;
    /// Broken pipe — write to a pipe whose read end has been closed.
    /// POSIX `EPIPE = 32`.
    pub const EPIPE: u64 = 32;
    /// Illegal seek — the fd does not support seeking (pipes, consoles).
    /// POSIX `ESPIPE = 29`.
    pub const ESPIPE: u64 = 29;
    /// No such process — target PID does not exist.
    /// POSIX `ESRCH = 3`.
    pub const ESRCH: u64 = 3;
    /// File or directory is not empty — `FsDelete` on a non-empty
    /// directory. POSIX `ENOTEMPTY = 39`.
    pub const ENOTEMPTY: u64 = 39;
    /// AI runtime service is not available — the nexacore-runtime IPC channel
    /// has not been registered. POSIX `EAGAIN = 11`.
    pub const EAGAIN: u64 = 11;
    /// Address already in use — the local address supplied to `NetBind`
    /// is already bound by another socket. POSIX `EADDRINUSE = 98`.
    pub const EADDRINUSE: u64 = 98;
    /// Connection refused — the remote host actively rejected the
    /// connection attempt (`NetConnect`). POSIX `ECONNREFUSED = 111`.
    pub const ECONNREFUSED: u64 = 111;
    /// Connection timed out — `NetConnect` or `NetRecv` did not
    /// complete within the allotted time. POSIX `ETIMEDOUT = 110`.
    pub const ETIMEDOUT: u64 = 110;
    /// Network unreachable — no route to the destination network.
    /// POSIX `ENETUNREACH = 101`.
    pub const ENETUNREACH: u64 = 101;
    /// Host unreachable — no route to the destination host.
    /// POSIX `EHOSTUNREACH = 113`.
    pub const EHOSTUNREACH: u64 = 113;
    /// Connection reset by peer. POSIX `ECONNRESET = 104`.
    pub const ECONNRESET: u64 = 104;
    /// Connection aborted by local policy or error.
    /// POSIX `ECONNABORTED = 103`.
    pub const ECONNABORTED: u64 = 103;
    /// Socket is not connected — `NetSend` / `NetRecv` on an
    /// unconnected socket. POSIX `ENOTCONN = 107`.
    pub const ENOTCONN: u64 = 107;
    /// Socket is already connected — `NetConnect` called on a socket
    /// that already has a peer. POSIX `EISCONN = 106`.
    pub const EISCONN: u64 = 106;
}

// -----------------------------------------------------------------------------
// Syscall dispatcher trait
// -----------------------------------------------------------------------------

/// Trait for the kernel syscall dispatcher.
///
/// The arch-specific entry code (`int 0x80` etc) translates the
/// arch-level register state into a call to `dispatch`; this trait
/// keeps the dispatch logic arch-neutral.
pub trait SyscallDispatcher {
    /// Dispatches a syscall by number with up to 6 generic register
    /// arguments (the `x86_64` ABI fits in 6 GPRs). Returns the syscall
    /// result code or [`crate::KernelError`].
    fn dispatch(&mut self, number: SyscallNumber, args: [u64; 6]) -> KernelResult<u64>;

    /// Dispatches a syscall and returns both `RAX` and `RDX`.
    ///
    /// Default implementation defers to [`Self::dispatch`] and wraps
    /// the result as [`SyscallReturn::ok`] on success or
    /// `SyscallReturn::err(syscall_errno::EINVAL)` on a `KernelError`.
    /// Handlers that need the richer two-register ABI (e.g. `MmioMap`)
    /// override this method to return the specific errno.
    fn dispatch_full(
        &mut self,
        number: SyscallNumber,
        args: [u64; 6],
    ) -> KernelResult<SyscallReturn> {
        self.dispatch(number, args).map(SyscallReturn::ok)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(
        clippy::cognitive_complexity,
        reason = "ABI stability test must enumerate every pinned syscall number in one place"
    )]
    fn syscall_numbers_are_stable() {
        // These constants form the userspace ABI. Any test failure
        // here is a deliberate ABI change and MUST go through NCIP.
        assert_eq!(SyscallNumber::MemMap as u32, 1);
        assert_eq!(SyscallNumber::TaskCreate as u32, 10);
        assert_eq!(SyscallNumber::ProcessSpawn as u32, 14);
        assert_eq!(SyscallNumber::ProcessWait as u32, 15);
        assert_eq!(SyscallNumber::GetCwd as u32, 16);
        assert_eq!(SyscallNumber::SetCwd as u32, 17);
        assert_eq!(SyscallNumber::IpcSend as u32, 22);
        assert_eq!(SyscallNumber::IpcReceive as u32, 23);
        assert_eq!(SyscallNumber::IpcTryReceive as u32, 24);
        assert_eq!(SyscallNumber::CapValidate as u32, 30);
        assert_eq!(SyscallNumber::TeeAttest as u32, 40);
        assert_eq!(SyscallNumber::TimeMonotonicNanos as u32, 50);
        // Shell I/O + fd syscalls (terminal support).
        assert_eq!(SyscallNumber::ReadConsole as u32, 61);
        assert_eq!(SyscallNumber::PipeCreate as u32, 62);
        assert_eq!(SyscallNumber::FdRead as u32, 63);
        assert_eq!(SyscallNumber::FdWrite as u32, 64);
        assert_eq!(SyscallNumber::FdClose as u32, 65);
        assert_eq!(SyscallNumber::FdDup as u32, 66);
        assert_eq!(SyscallNumber::FdDup2 as u32, 67);
        assert_eq!(SyscallNumber::FdSeek as u32, 68);
        // Filesystem syscalls (shell terminal support).
        assert_eq!(SyscallNumber::FsOpen as u32, 90);
        assert_eq!(SyscallNumber::FsStat as u32, 91);
        assert_eq!(SyscallNumber::FsListDir as u32, 92);
        assert_eq!(SyscallNumber::FsCreate as u32, 93);
        assert_eq!(SyscallNumber::FsDelete as u32, 94);
        assert_eq!(SyscallNumber::FsMkdir as u32, 95);
        assert_eq!(SyscallNumber::ProcessList as u32, 96);
        assert_eq!(SyscallNumber::ProcessKill as u32, 97);
        // NCIP-013 + NCIP-016 driver-framework decade (P6.7.3 skeleton).
        // Pinning these here prevents an accidental renumber that would
        // silently break a driver manifest signed against the old number.
        assert_eq!(SyscallNumber::MmioMap as u32, 70);
        assert_eq!(SyscallNumber::DmaMap as u32, 71);
        assert_eq!(SyscallNumber::IrqAttach as u32, 72);
        assert_eq!(SyscallNumber::DriverLoad as u32, 73);
        assert_eq!(SyscallNumber::TeeTdcall as u32, 74);
        assert_eq!(SyscallNumber::TeeMsr as u32, 75);
        // NCIP-Driver-NVMe-014 § S4 + § S6 step 12 BLK registry decade.
        // Pinning these numbers prevents an accidental renumber that
        // would silently break a future NVMe / SATA / virtio-blk
        // driver manifest signed against the old numbers.
        assert_eq!(SyscallNumber::BlkRegister as u32, 76);
        assert_eq!(SyscallNumber::BlkUnregister as u32, 77);
        assert_eq!(SyscallNumber::BlkLookup as u32, 78);
        // Display server (M3, DE-C1, ADR-0040). Pinned so a future
        // compositor / nexacore-usys display wrapper signed against 79 keeps
        // working.
        assert_eq!(SyscallNumber::DisplayMap as u32, 79);
        // NCIP-Phase2-Entry-021 AI syscall surface (P2 Sprint 2).
        assert_eq!(SyscallNumber::AiInvoke as u32, 80);
        assert_eq!(SyscallNumber::AiStream as u32, 81);
        assert_eq!(SyscallNumber::AiEmbed as u32, 82);
        assert_eq!(SyscallNumber::AiClassify as u32, 83);
        assert_eq!(SyscallNumber::AiTranscribe as u32, 84);
        // NCIP-Driver-Net-015 § S2 NET registry + socket IPC proxy.
        // Pinning these prevents an accidental renumber that would
        // silently break a NIC driver manifest or the network stack
        // ABI signed against the old numbers.
        assert_eq!(SyscallNumber::NetRegister as u32, 100);
        assert_eq!(SyscallNumber::NetUnregister as u32, 101);
        assert_eq!(SyscallNumber::NetLookup as u32, 102);
        assert_eq!(SyscallNumber::NetSocket as u32, 103);
        assert_eq!(SyscallNumber::NetBind as u32, 104);
        assert_eq!(SyscallNumber::NetListen as u32, 105);
        assert_eq!(SyscallNumber::NetAccept as u32, 106);
        assert_eq!(SyscallNumber::NetConnect as u32, 107);
        assert_eq!(SyscallNumber::NetSend as u32, 108);
        assert_eq!(SyscallNumber::NetRecv as u32, 109);
        assert_eq!(SyscallNumber::NetSendTo as u32, 110);
        assert_eq!(SyscallNumber::NetRecvFrom as u32, 111);
        assert_eq!(SyscallNumber::NetClose as u32, 112);
        assert_eq!(SyscallNumber::NetShutdown as u32, 113);
        // v2: read-only CPU/RAM telemetry.
        assert_eq!(SyscallNumber::SysInfo as u32, 114);
    }

    #[test]
    fn net_syscall_numbers_are_stable() {
        // Dedicated tripwire for the NET syscall range (100–113).
        // This test is intentionally redundant with the slice in
        // `syscall_numbers_are_stable`; the duplication makes it
        // trivial to grep for NET-specific stability assertions.
        assert_eq!(SyscallNumber::NetRegister as u32, 100);
        assert_eq!(SyscallNumber::NetUnregister as u32, 101);
        assert_eq!(SyscallNumber::NetLookup as u32, 102);
        assert_eq!(SyscallNumber::NetSocket as u32, 103);
        assert_eq!(SyscallNumber::NetBind as u32, 104);
        assert_eq!(SyscallNumber::NetListen as u32, 105);
        assert_eq!(SyscallNumber::NetAccept as u32, 106);
        assert_eq!(SyscallNumber::NetConnect as u32, 107);
        assert_eq!(SyscallNumber::NetSend as u32, 108);
        assert_eq!(SyscallNumber::NetRecv as u32, 109);
        assert_eq!(SyscallNumber::NetSendTo as u32, 110);
        assert_eq!(SyscallNumber::NetRecvFrom as u32, 111);
        assert_eq!(SyscallNumber::NetClose as u32, 112);
        assert_eq!(SyscallNumber::NetShutdown as u32, 113);
    }

    #[test]
    fn syscall_abi_table_is_well_formed() {
        // 70-syscall surface (SYSCALL_ABI_VERSION 2: WS1-12's 69-syscall
        // surface plus SysInfo (114)).
        assert_eq!(SYSCALL_ABI.len(), 70, "ABI table size changed");
        // Strictly ascending numbers ⇒ unique; names non-empty.
        let mut prev: Option<u32> = None;
        for &(num, name) in SYSCALL_ABI {
            assert!(!name.is_empty(), "empty syscall name in ABI table");
            if let Some(p) = prev {
                assert!(
                    num > p,
                    "ABI table not strictly ascending at {num} (after {p})"
                );
            }
            prev = Some(num);
        }
        assert_eq!(SYSCALL_ABI.first().map(|e| e.0), Some(1));
        assert_eq!(SYSCALL_ABI.last().map(|e| e.0), Some(114));
    }

    #[test]
    #[allow(
        clippy::cognitive_complexity,
        reason = "ABI cross-check maps every syscall name to its enum value in one place"
    )]
    fn syscall_abi_table_agrees_with_enum() {
        // Map a frozen-table name back to the LIVE enum's numeric value.
        // Renumbering or renaming a variant makes this disagree with the
        // table and fails — the table↔enum tripwire complementing the
        // hash guard.
        fn enum_num(name: &str) -> Option<u32> {
            Some(match name {
                "MemMap" => SyscallNumber::MemMap as u32,
                "MemUnmap" => SyscallNumber::MemUnmap as u32,
                "TaskCreate" => SyscallNumber::TaskCreate as u32,
                "TaskExit" => SyscallNumber::TaskExit as u32,
                "TaskYield" => SyscallNumber::TaskYield as u32,
                "TaskSleep" => SyscallNumber::TaskSleep as u32,
                "ProcessSpawn" => SyscallNumber::ProcessSpawn as u32,
                "ProcessWait" => SyscallNumber::ProcessWait as u32,
                "GetCwd" => SyscallNumber::GetCwd as u32,
                "SetCwd" => SyscallNumber::SetCwd as u32,
                "IpcCreateChannel" => SyscallNumber::IpcCreateChannel as u32,
                "IpcDestroyChannel" => SyscallNumber::IpcDestroyChannel as u32,
                "IpcSend" => SyscallNumber::IpcSend as u32,
                "IpcReceive" => SyscallNumber::IpcReceive as u32,
                "IpcTryReceive" => SyscallNumber::IpcTryReceive as u32,
                "CapValidate" => SyscallNumber::CapValidate as u32,
                "CapRevoke" => SyscallNumber::CapRevoke as u32,
                "CapAttenuate" => SyscallNumber::CapAttenuate as u32,
                "TeeAttest" => SyscallNumber::TeeAttest as u32,
                "TeeVerifyQuote" => SyscallNumber::TeeVerifyQuote as u32,
                "TeeSeal" => SyscallNumber::TeeSeal as u32,
                "TeeUnseal" => SyscallNumber::TeeUnseal as u32,
                "TimeMonotonicNanos" => SyscallNumber::TimeMonotonicNanos as u32,
                "WriteConsole" => SyscallNumber::WriteConsole as u32,
                "ReadConsole" => SyscallNumber::ReadConsole as u32,
                "PipeCreate" => SyscallNumber::PipeCreate as u32,
                "FdRead" => SyscallNumber::FdRead as u32,
                "FdWrite" => SyscallNumber::FdWrite as u32,
                "FdClose" => SyscallNumber::FdClose as u32,
                "FdDup" => SyscallNumber::FdDup as u32,
                "FdDup2" => SyscallNumber::FdDup2 as u32,
                "FdSeek" => SyscallNumber::FdSeek as u32,
                "MmioMap" => SyscallNumber::MmioMap as u32,
                "DmaMap" => SyscallNumber::DmaMap as u32,
                "IrqAttach" => SyscallNumber::IrqAttach as u32,
                "DriverLoad" => SyscallNumber::DriverLoad as u32,
                "TeeTdcall" => SyscallNumber::TeeTdcall as u32,
                "TeeMsr" => SyscallNumber::TeeMsr as u32,
                "BlkRegister" => SyscallNumber::BlkRegister as u32,
                "BlkUnregister" => SyscallNumber::BlkUnregister as u32,
                "BlkLookup" => SyscallNumber::BlkLookup as u32,
                "DisplayMap" => SyscallNumber::DisplayMap as u32,
                "AiInvoke" => SyscallNumber::AiInvoke as u32,
                "AiStream" => SyscallNumber::AiStream as u32,
                "AiEmbed" => SyscallNumber::AiEmbed as u32,
                "AiClassify" => SyscallNumber::AiClassify as u32,
                "AiTranscribe" => SyscallNumber::AiTranscribe as u32,
                "FsOpen" => SyscallNumber::FsOpen as u32,
                "FsStat" => SyscallNumber::FsStat as u32,
                "FsListDir" => SyscallNumber::FsListDir as u32,
                "FsCreate" => SyscallNumber::FsCreate as u32,
                "FsDelete" => SyscallNumber::FsDelete as u32,
                "FsMkdir" => SyscallNumber::FsMkdir as u32,
                "ProcessList" => SyscallNumber::ProcessList as u32,
                "ProcessKill" => SyscallNumber::ProcessKill as u32,
                "NetRegister" => SyscallNumber::NetRegister as u32,
                "NetUnregister" => SyscallNumber::NetUnregister as u32,
                "NetLookup" => SyscallNumber::NetLookup as u32,
                "NetSocket" => SyscallNumber::NetSocket as u32,
                "NetBind" => SyscallNumber::NetBind as u32,
                "NetListen" => SyscallNumber::NetListen as u32,
                "NetAccept" => SyscallNumber::NetAccept as u32,
                "NetConnect" => SyscallNumber::NetConnect as u32,
                "NetSend" => SyscallNumber::NetSend as u32,
                "NetRecv" => SyscallNumber::NetRecv as u32,
                "NetSendTo" => SyscallNumber::NetSendTo as u32,
                "NetRecvFrom" => SyscallNumber::NetRecvFrom as u32,
                "NetClose" => SyscallNumber::NetClose as u32,
                "NetShutdown" => SyscallNumber::NetShutdown as u32,
                "SysInfo" => SyscallNumber::SysInfo as u32,
                _ => return None,
            })
        }
        for &(num, name) in SYSCALL_ABI {
            assert_eq!(
                enum_num(name),
                Some(num),
                "ABI table entry {name}={num} disagrees with the enum"
            );
        }
    }

    #[test]
    fn abi_hash_is_pinned() {
        // Tripwire: any change to SYSCALL_ABI flips this hash. If intentional,
        // bump SYSCALL_ABI_VERSION and re-pin SYSCALL_ABI_HASH_PINNED to the
        // new SYSCALL_ABI_HASH value (and update docs/15-syscall-abi.md).
        assert_eq!(
            SYSCALL_ABI_HASH, SYSCALL_ABI_HASH_PINNED,
            "syscall ABI changed; see docs/15-syscall-abi.md"
        );
    }

    #[test]
    fn syscall_number_fits_in_u32() {
        assert_eq!(core::mem::size_of::<SyscallNumber>(), 4);
    }

    // ---- Two-register return path (NCIP-013 § S2) -------------------------

    #[test]
    fn syscall_return_ok_zero_errno() {
        let r = SyscallReturn::ok(0x4000_0000);
        assert_eq!(r.rax, 0x4000_0000);
        assert_eq!(r.rdx, 0);
    }

    #[test]
    fn syscall_return_err_zero_rax() {
        let r = SyscallReturn::err(syscall_errno::EACCES);
        assert_eq!(r.rax, 0);
        assert_eq!(r.rdx, 13);
    }

    #[test]
    fn syscall_return_is_two_u64_struct() {
        // Repr(C) on x86_64 places two u64 fields in (rax, rdx) at the
        // SysV ABI boundary. Pin the layout so a re-order would surface
        // as a failing test before the ABI breaks. Field-offset checks
        // are sufficient — the SysV "two INTEGER fields ≤ 16 bytes →
        // return in (rax, rdx)" rule is keyed on the in-memory layout.
        assert_eq!(core::mem::size_of::<SyscallReturn>(), 16);
        assert_eq!(core::mem::align_of::<SyscallReturn>(), 8);
        let r = SyscallReturn { rax: 1, rdx: 2 };
        assert_eq!(r.rax, 1);
        assert_eq!(r.rdx, 2);
        assert_eq!(core::mem::offset_of!(SyscallReturn, rax), 0);
        assert_eq!(core::mem::offset_of!(SyscallReturn, rdx), 8);
    }

    #[test]
    fn syscall_errno_codes_are_posix_aligned() {
        assert_eq!(syscall_errno::ENOENT, 2);
        assert_eq!(syscall_errno::EIO, 5);
        assert_eq!(syscall_errno::EACCES, 13);
        assert_eq!(syscall_errno::EFAULT, 14);
        assert_eq!(syscall_errno::EEXIST, 17);
        assert_eq!(syscall_errno::EINVAL, 22);
        assert_eq!(syscall_errno::ENOSPC, 28);
        assert_eq!(syscall_errno::ENOSYS, 38);
        // AI runtime errno — matches POSIX EAGAIN = 11.
        assert_eq!(syscall_errno::EAGAIN, 11);
    }

    #[test]
    fn ai_syscall_errno_eagain() {
        assert_eq!(syscall_errno::EAGAIN, 11);
    }

    #[test]
    fn net_syscall_errno_codes_are_posix_aligned() {
        // These values match the Linux `errno.h` numbers for the
        // NET socket error family. Any deviation from the POSIX table
        // must be accompanied by an NCIP and a comment explaining why.
        assert_eq!(syscall_errno::EADDRINUSE, 98);
        assert_eq!(syscall_errno::ECONNREFUSED, 111);
        assert_eq!(syscall_errno::ETIMEDOUT, 110);
        assert_eq!(syscall_errno::ENETUNREACH, 101);
        assert_eq!(syscall_errno::EHOSTUNREACH, 113);
        assert_eq!(syscall_errno::ECONNRESET, 104);
        assert_eq!(syscall_errno::ECONNABORTED, 103);
        assert_eq!(syscall_errno::ENOTCONN, 107);
        assert_eq!(syscall_errno::EISCONN, 106);
    }
}
