# NexaCore OS — Syscall ABI Reference (frozen, versioned)

> **ABI version: 2** · **Surface: 70 syscalls** · **Detail hash: `0x5d1acce43782d136`**
> Source of truth: [`crates/nexacore-kernel/src/syscall/abi_reference.rs`](../crates/nexacore-kernel/src/syscall/abi_reference.rs) (`SYSCALL_ABI_REF`).

**Generated file — do not edit by hand.** Regenerate with `cargo run -p nexacore-kernel --example gen-syscall-abi > docs/15-syscall-abi.md`. The numeric surface is frozen by WS1-12 (`SyscallNumber` enum + `SYSCALL_ABI` table, `SYSCALL_ABI_HASH` guard); this document and its `SYSCALL_ABI_REF` source add the per-syscall argument / capability / `errno` detail, guarded in turn by `SYSCALL_ABI_DETAIL_HASH`. Any accidental change to the surface or its detail fails the build.

## Stability policy

- **Numbers are immutable after v1.** Never renumber an existing variant; only append new variants (with new numbers) at the end of a decade range.
- **Removing a syscall** requires an NCIP and a multi-year deprecation window.
- **Numeric ranges are reserved by subsystem** (decades): `1–2` memory, `10–17` scheduling/process, `20–24` IPC, `30–32` capabilities, `40–43` TEE/attestation, `50` time, `60–68` I/O + file descriptors, `70–75` driver framework, `76–78` BLK registry, `79` display, `80–84` AI runtime, `90–97` filesystem + process mgmt, `100–113` networking, `114` system information.
- The two-register return convention (`rax`, `rdx`) and the POSIX-aligned `errno` codes are defined in `syscall.rs` (`SyscallReturn`, `syscall_errno`).

## Versioning

`SYSCALL_ABI_VERSION` is a single monotonically-increasing integer. Bumping it is the deliberate act of changing the ABI; it MUST accompany: (1) the table edit in `syscall.rs` / `abi_reference.rs`, (2) a re-pin of `SYSCALL_ABI_HASH_PINNED` and `SYSCALL_ABI_DETAIL_HASH_PINNED`, (3) a regeneration of this document, and (4) an NCIP describing the change.

## Frozen table (v2)

Notation: `ABI: (a0, a1, …) -> ret`. Args are the up-to-6 general-purpose register slots; `ret` is `rax` (plus `rdx` where a two-register return or an `errno` is noted). "Cap" lists the capability gate where one applies; "Errno" lists the documented failure codes.

### Memory (1–2)

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 1 | `MemMap` | `(addr, len, prot, flags, 0, 0) -> va_base` | — | — | Map an anonymous page region (mmap-equivalent). |
| 2 | `MemUnmap` | `(addr, len, 0, 0, 0, 0) -> 0` | — | — | Unmap a previously-mapped region. |

### Scheduling / process (10–17)

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 10 | `TaskCreate` | `(entry, arg, stack, flags, 0, 0) -> task_id` | — | — | Create a new task (process or thread). |
| 11 | `TaskExit` | `(code, 0, 0, 0, 0, 0) -> !` | — | — | Terminate the calling task. |
| 12 | `TaskYield` | `(0, 0, 0, 0, 0, 0) -> 0` | — | — | Yield the CPU voluntarily. |
| 13 | `TaskSleep` | `(deadline_nanos, 0, 0, 0, 0, 0) -> 0` | — | — | Sleep until a monotonic deadline. |
| 14 | `ProcessSpawn` | `(elf_path_ptr, elf_path_len, argv_ptr, argv_count, envp_ptr, envp_count) -> child_pid` | — | — | Spawn a process with argv/envp and inherited file descriptors. |
| 15 | `ProcessWait` | `(child_pid, flags, 0, 0, 0, 0) -> (rax=exit_code, rdx=child_pid)` | — | ECHILD | Wait for a child to exit (pid 0 = any; flags bit0 = WNOHANG). |
| 16 | `GetCwd` | `(buf_ptr, buf_len, 0, 0, 0, 0) -> path_len` | — | EFAULT | Get the calling process's current working directory. |
| 17 | `SetCwd` | `(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | — | ENOENT / EINVAL | Set the calling process's current working directory. |

### IPC (20–24)

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 20 | `IpcCreateChannel` | `(queue_depth, flags, 0, 0, 0, 0) -> channel_id` | per-owner quota | — | Create a new IPC channel. |
| 21 | `IpcDestroyChannel` | `(channel_id, 0, 0, 0, 0, 0) -> 0` | owner | — | Destroy a channel. |
| 22 | `IpcSend` | `(channel_id, buf_ptr, buf_len, 0, 0, 0) -> bytes_sent` | per-channel token | — | Send a message. |
| 23 | `IpcReceive` | `(channel_id, buf_ptr, buf_len, 0, 0, 0) -> bytes_read` | per-channel token | — | Receive a message (blocking — parks the caller until one arrives). |
| 24 | `IpcTryReceive` | `(channel_id, buf_ptr, buf_len, 0, 0, 0) -> (rax=bytes_read, rdx=errno)` | per-channel token | EAGAIN | Receive without blocking (EAGAIN when the queue is empty). |

### Capabilities (30–32)

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 30 | `CapValidate` | `(cap_ptr, cap_len, 0, 0, 0, 0) -> 0` | — | EACCES | Validate a capability. |
| 31 | `CapRevoke` | `(cap_ptr, cap_len, 0, 0, 0, 0) -> 0` | issuer | — | Revoke a capability. |
| 32 | `CapAttenuate` | `(cap_ptr, cap_len, caveat_ptr, caveat_len, out_ptr, out_cap) -> out_len` | Macaroons-style | — | Derive an attenuated capability. |

### TEE / attestation (40–43)

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 40 | `TeeAttest` | `(report_data_ptr, len, out_ptr, out_cap, 0, 0) -> quote_len` | — | — | Request a TEE attestation quote. |
| 41 | `TeeVerifyQuote` | `(quote_ptr, quote_len, 0, 0, 0, 0) -> 0` | — | — | Verify a peer's quote. |
| 42 | `TeeSeal` | `(blob_ptr, blob_len, out_ptr, out_cap, 0, 0) -> sealed_len` | — | — | Seal a blob under the current TEE measurement. |
| 43 | `TeeUnseal` | `(sealed_ptr, sealed_len, out_ptr, out_cap, 0, 0) -> blob_len` | — | — | Unseal a blob. |

### Time (50)

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 50 | `TimeMonotonicNanos` | `(0, 0, 0, 0, 0, 0) -> nanos_since_boot` | — | — | Get monotonic time (nanoseconds since boot). |

### I/O + file descriptors (60–68)

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 60 | `WriteConsole` | `(ptr, len, 0, 0, 0, 0) -> len` | — | u64::MAX sentinel on validation failure | Write a user byte slice to the kernel console (COM1). |
| 61 | `ReadConsole` | `(buf_ptr, buf_len, 0, 0, 0, 0) -> bytes_read` | — | — | Read from the console input buffer (line-buffered). |
| 62 | `PipeCreate` | `(0, 0, 0, 0, 0, 0) -> (rax=read_fd, rdx=write_fd)` | — | — | Create an anonymous pipe. |
| 63 | `FdRead` | `(fd, buf_ptr, buf_len, 0, 0, 0) -> bytes_read` | — | EBADF | Read from a file descriptor (console, pipe, or file). |
| 64 | `FdWrite` | `(fd, buf_ptr, buf_len, 0, 0, 0) -> bytes_written` | — | EBADF / EPIPE | Write to a file descriptor (console, pipe, or file). |
| 65 | `FdClose` | `(fd, 0, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | — | EBADF | Close a file descriptor. |
| 66 | `FdDup` | `(fd, 0, 0, 0, 0, 0) -> new_fd` | — | EBADF | Duplicate a file descriptor (lowest available number). |
| 67 | `FdDup2` | `(old_fd, new_fd, 0, 0, 0, 0) -> new_fd` | — | EBADF | Duplicate a file descriptor to a specific target number. |
| 68 | `FdSeek` | `(fd, offset_i64, whence, 0, 0, 0) -> new_offset` | — | EBADF / ESPIPE | Seek on a file descriptor (whence 0=SET, 1=CUR, 2=END). |

### Driver framework (70–75) — NCIP-013 / NCIP-016

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 70 | `MmioMap` | `(phys_base, len, flags, cap_ptr, cap_len) -> (rax=va_base, rdx=errno)` | MmioMap cap | EACCES | Map a PCI BAR MMIO region into the caller's address space. |
| 71 | `DmaMap` | `(iova_base, len, direction, cap_ptr, cap_len) -> 0` | DmaMap cap | EACCES | Install an IOMMU DMA window. |
| 72 | `IrqAttach` | `(irq_line, ipc_channel_id, cap_ptr, cap_len, 0) -> 0` | IrqAttach cap | EACCES | Attach an IRQ line to a per-driver IPC channel. |
| 73 | `DriverLoad` | `(manifest_ptr, manifest_len, image_ptr, image_len, 0) -> driver_pid` | signed manifest | EACCES | Load a signed driver image. |
| 74 | `TeeTdcall` | `(leaf, r10, r11, r12, r13) -> rax_packed` | Ring 0 only | — | Issue a kernel-mediated Intel TDX TDCALL. |
| 75 | `TeeMsr` | `(msr_index, value_lo, value_hi, payload_ptr, payload_len) -> 0` | Ring 0 only | — | Issue a kernel-mediated SEV-SNP MSR write. |

### BLK service-channel registry (76–78) — NCIP-Driver-NVMe-014

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 76 | `BlkRegister` | `(disk_slot_ptr, disk_slot_len, channel_id, 0, 0, 0) -> (rax=0, rdx=errno)` | channel owner | EACCES / EEXIST | Record an nexacore.svc.blk.<disk_slot> channel in the registry. |
| 77 | `BlkUnregister` | `(disk_slot_ptr, disk_slot_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | owner | EACCES | Remove an owned BLK channel mapping. |
| 78 | `BlkLookup` | `(disk_slot_ptr, disk_slot_len, 0, 0, 0, 0) -> (rax=channel_id, rdx=0)` | read-only | ENOENT | Resolve a BLK disk slot to its live channel id. |

### Display server (79) — ADR-0040

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 79 | `DisplayMap` | `(offset, len, flags, cap_ptr, cap_len, 0) -> (rax=user_va, rdx=errno)` | DisplayMap cap | EACCES | Map the GOP framebuffer (or a sub-window) into a Ring-3 compositor. |

### AI runtime surface (80–84) — NCIP-Phase2-Entry-021

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 80 | `AiInvoke` | `(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len` | AiInvoke cap | EACCES / ENOSPC | Invoke a loaded model for synchronous single-turn inference. |
| 81 | `AiStream` | `(model_id_ptr, model_id_len, input_ptr, input_len, stream_channel_id, 0) -> session_id` | AiInvoke cap | EACCES | Start a streaming inference session (tokens delivered via IPC). |
| 82 | `AiEmbed` | `(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len` | AiInvoke cap | EACCES / ENOSPC | Compute a dense embedding vector for the given input. |
| 83 | `AiClassify` | `(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len` | AiInvoke cap | EACCES / ENOSPC | Classify input into a set of scored categories. |
| 84 | `AiTranscribe` | `(model_id_ptr, model_id_len, input_ptr, input_len, output_ptr, output_cap) -> output_len` | AiInvoke cap | EACCES / ENOSPC | Transcribe an audio buffer reference to text. |

### Filesystem + process management (90–97)

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 90 | `FsOpen` | `(path_ptr, path_len, flags, 0, 0, 0) -> fd` | OpenFlags | ENOENT | Open a file and return a file descriptor. |
| 91 | `FsStat` | `(path_ptr, path_len, stat_buf_ptr, 0, 0, 0) -> (rax=0, rdx=errno)` | — | ENOENT | Stat a file or directory into a FileStat buffer. |
| 92 | `FsListDir` | `(path_ptr, path_len, buf_ptr, buf_len, 0, 0) -> entry_count` | — | ENOENT | List the entries in a directory. |
| 93 | `FsCreate` | `(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | — | EEXIST | Create an empty regular file. |
| 94 | `FsDelete` | `(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | — | ENOTEMPTY | Delete a file or empty directory. |
| 95 | `FsMkdir` | `(path_ptr, path_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | — | EEXIST | Create a directory. |
| 96 | `ProcessList` | `(buf_ptr, buf_len, 0, 0, 0, 0) -> entry_count` | — | — | List all running processes. |
| 97 | `ProcessKill` | `(target_pid, 0, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | — | ESRCH | Terminate another process. |

### Networking (100–113) — NCIP-Driver-Net-015

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 100 | `NetRegister` | `(if_name_ptr, name_len, channel_id, event_channel_id, mac_ptr, mac_len) -> (rax=0, rdx=errno)` | channel owner | EACCES | Record an nexacore.svc.net.<interface> channel pair. |
| 101 | `NetUnregister` | `(if_name_ptr, name_len, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | owner | EACCES | Remove an owned NET interface mapping. |
| 102 | `NetLookup` | `(if_name_ptr, name_len, 0, 0, 0, 0) -> (rax=channel_id, rdx=event_channel_id)` | read-only | ENOENT | Resolve a NET interface to its live channel pair. |
| 103 | `NetSocket` | `(domain, type, 0, 0, 0, 0) -> socket_handle` | — | — | Create a new socket handle via the nexacore-net service. |
| 104 | `NetBind` | `(handle, addr_ptr, addr_len, 0, 0, 0) -> (rax=0, rdx=errno)` | — | EADDRINUSE | Bind a socket handle to a local address. |
| 105 | `NetListen` | `(handle, backlog, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | — | — | Mark a bound socket as passive (listening). |
| 106 | `NetAccept` | `(handle, addr_buf_ptr, addr_buf_len, 0, 0, 0) -> new_handle` | — | — | Accept an incoming connection on a listening socket. |
| 107 | `NetConnect` | `(handle, addr_ptr, addr_len, 0, 0, 0) -> (rax=0, rdx=errno)` | — | ECONNREFUSED / ETIMEDOUT / ENETUNREACH | Initiate an outgoing connection. |
| 108 | `NetSend` | `(handle, buf_ptr, buf_len, 0, 0, 0) -> bytes_sent` | — | ENOTCONN | Send data on a connected socket. |
| 109 | `NetRecv` | `(handle, buf_ptr, buf_len, 0, 0, 0) -> bytes_received` | — | ENOTCONN | Receive data from a connected socket. |
| 110 | `NetSendTo` | `(handle, buf_ptr, buf_len, addr_ptr, addr_len, 0) -> bytes_sent` | — | — | Send data to an explicit destination (connectionless). |
| 111 | `NetRecvFrom` | `(handle, buf_ptr, buf_len, addr_buf_ptr, 0, 0) -> bytes_received` | — | — | Receive data and record the sender's address (connectionless). |
| 112 | `NetClose` | `(handle, 0, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | — | — | Close a socket handle. |
| 113 | `NetShutdown` | `(handle, how, 0, 0, 0, 0) -> (rax=0, rdx=errno)` | — | how: 0=rd, 1=wr, 2=both | Shut down part or all of a full-duplex connection. |

### System information (114)

| # | Name | ABI | Cap | Errno | Summary |
|---|------|-----|-----|-------|---------|
| 114 | `SysInfo` | `(out_ptr, out_cap, 0, 0, 0, 0) -> (rax=bytes_written=24, rdx=errno)` | — | EFAULT: bad/undersized buffer | Read live CPU/RAM telemetry (free_mib, total_mib, cpu_count) into a 24-byte buffer. |

## Errno codes

POSIX-aligned, defined in `syscall.rs::syscall_errno`: `ENOENT=2`, `ESRCH=3`, `EIO=5`, `EBADF=9`, `ECHILD=10`, `EAGAIN=11`, `EACCES=13`, `EFAULT=14`, `EEXIST=17`, `EINVAL=22`, `ENOSPC=28`, `ESPIPE=29`, `EPIPE=32`, `ENOSYS=38`, `ENOTEMPTY=39`, `EADDRINUSE=98`, `ENETUNREACH=101`, `ECONNABORTED=103`, `ECONNRESET=104`, `EISCONN=106`, `ENOTCONN=107`, `ETIMEDOUT=110`, `ECONNREFUSED=111`, `EHOSTUNREACH=113`.

---

*Generated under WS14-01 from `SYSCALL_ABI_REF` (`crates/nexacore-kernel/src/syscall/abi_reference.rs`) by the `gen-syscall-abi` example. The numeric surface is frozen by WS1-12; this detail table moves with it under the `SYSCALL_ABI_DETAIL_HASH` guard.*
