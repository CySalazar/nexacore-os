//! Bare-metal TASK-22 NCFS FS service daemon for NexaCore OS (ADR-0044, DE-D4).
//!
//! A `no_std + no_main` Ring 3 ELF the kernel spawns to mount the NCFS root
//! volume from the NVMe BLK service and then serve file-system requests over
//! IPC for the lifetime of the OS session.
//!
//! ## Start-up sequence
//!
//! ```text
//! _start()
//!   find IpcSend capability token
//!   BlkLookup("nvme0")          -> req_channel
//!   BlkLookup("nvme0-reply")    -> reply_channel
//!   read all NVMe blocks into RAM
//!   OnDiskVolume::mount (or ::format on first boot)
//!   boot-counter self-check (/test.txt proof, TASK-15 retained)
//!   sync volume back to NVMe
//!   IpcCreateChannel            -> fs_req_ch
//!   IpcCreateChannel            -> fs_reply_ch
//!   NetRegister("ncfs",       fs_req_ch)
//!   NetRegister("ncfs-reply", fs_reply_ch)
//!   loop forever: IpcTryReceive(fs_req_ch) -> FsRequest -> handle() -> FsResponse
//! ```
//!
//! ## Whole-volume-in-RAM mount
//!
//! `OnDiskVolume::mount` takes a whole-volume `&[u8]`.  The daemon reads all
//! `total_blocks` blocks (one `BlkRequest::Read` per block) into a 32 MiB BSS
//! heap buffer, then calls `mount`.  Each block is one IPC round-trip; the root
//! volume is capped at 128 blocks (512 KiB) to keep boot-time I/O bounded.
//!
//! ## Format-on-first-boot fallback
//!
//! A fresh NVMe image is zeros → block 0 has no `OMNIFS01` magic → `mount`
//! rejects it.  The daemon treats "no valid NCFS on nvme0" as the fallback:
//! it formats a fresh 128-block volume, creates `/test.txt`, and syncs all 128
//! blocks to disk.
//!
//! A volume that has the magic but fails integrity / parse is a HARD error:
//! the daemon logs and exits without overwriting, to avoid silently destroying
//! possibly-recoverable data.
//!
//! ## Boot-counter persistence proof (TASK-15 retained)
//!
//! `/test.txt` holds `NexaCore-OS persistent root — boot N\n`.  First boot
//! (fallback) formats and writes `boot 1`.  After `qm reset 103`, the daemon
//! mounts the existing volume, reads `boot 1`, writes `boot 2`, and syncs.
//! The two-boot capture in the serial log proves persistence across reboot.
//! This self-check runs BEFORE the service loop starts.
//!
//! ## FS service loop
//!
//! After the boot-counter proof the daemon registers two IPC channels:
//! - `nexacore.fs`       — receives [`FsRequest`] messages from clients.
//! - `nexacore.fs-reply` — sends [`FsResponse`] messages back to clients.
//!
//! The loop decodes every inbound message as a [`FsRequest`] (postcard).
//! Malformed or unrecognised messages return [`FsResponse::Error(InvalidArgument)`]
//! and never cause a panic. The loop never exits on its own.
//!
//! ## Heap caveat (never-freeing bump allocator)
//!
//! The bump allocator never frees; each `Read`, `ListDir`, and `Sync` response
//! allocates a `Vec` that is never reclaimed. The 32 MiB heap is sufficient for
//! a long interactive session (hundreds of file operations before exhaustion).
//! A proper slab allocator is tracked as NCIP-026 WI-9.
//!
//! ## Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | `1`  | Panic handler invoked |
//! | `2`  | No IpcSend capability token in the kernel deposit window |
//! | `3`  | Driver never registered (ENOENT budget exhausted) |
//! | `4`  | Block I/O error (read or write) |
//! | `5`  | Mount failed — volume has magic but failed integrity / parse |
//! | `6`  | NCFS operation error during boot-counter self-check |
//! | `7`  | IpcCreateChannel failed (cannot create FS service channels) |
//! | `8`  | NetRegister failed (cannot advertise FS service) |
//!
//! The daemon does NOT exit on success; exit code 0 is never produced.

#![no_std]
#![no_main]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use nexacore_fs::ondisk::OnDiskVolume;
use nexacore_types::blk::{BlkRequest, BlkResponse};
use nexacore_types::fs_service::{CHANNEL_NAME, FS_MAX_INLINE_BYTES, FsErrno, FsRequest, FsResponse};
use nexacore_types::wire::{decode_canonical, encode_canonical, encode_into_slice};

// =============================================================================
// Bump allocator (32 MiB static heap)
// =============================================================================

/// Size of the static heap backing the bump allocator (32 MiB).
///
/// 32 MiB is sufficient to hold:
/// - A 128-block (512 KiB) whole-volume buffer for `mount`.
/// - The in-memory `OnDiskVolume` maps (`BTreeMap` nodes for inodes,
///   data blocks, integrity tags).
/// - A second 512 KiB buffer from `sync_to_bytes` during write-back.
/// - Postcard encode/decode scratch (< 1 KiB per call).
/// - Hundreds of `read_file` / `list_directory` result `Vec`s that the
///   never-freeing bump allocator retains (heap caveat — see module doc).
const HEAP_SIZE: usize = 32 * 1024 * 1024;

/// Backing storage for the bump allocator (BSS — zero-initialised by the ELF
/// loader before `_start` runs).
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// Current bump cursor (byte offset into [`HEAP`]).
///
/// Single-threaded task; no atomics required.  Accessed only through
/// `addr_of_mut!` to avoid forming a reference to `static mut`.
static mut HEAP_POS: usize = 0;

/// Never-freeing bump allocator.
///
/// Provides the `alloc` crate's `GlobalAlloc` contract with a static arena.
/// `dealloc` is a deliberate no-op: the heap caveat (module doc) documents
/// the known unbounded growth and tracks it as a follow-up work item.
struct BumpAllocator;

// SAFETY: single-threaded Ring 3 task; allocation bumps a static arena;
// `dealloc` is a documented no-op (never-freeing by design).
unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let align = layout.align().max(1);
        // SAFETY: single-threaded; HEAP_POS is only mutated here.
        unsafe {
            let pos = *core::ptr::addr_of!(HEAP_POS);
            let base = core::ptr::addr_of_mut!(HEAP).cast::<u8>();
            let aligned = (pos + align - 1) & !(align - 1);
            let end = aligned.saturating_add(layout.size());
            if end > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            *core::ptr::addr_of_mut!(HEAP_POS) = end;
            // SAFETY: `aligned` is within [0, HEAP_SIZE) and `base` points to
            // the start of the static HEAP array.
            base.add(aligned)
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Never-freeing bump allocator: dealloc is intentionally a no-op.
        // See the module-doc heap caveat.
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

/// Current bump-allocator cursor (bytes consumed) — diagnostic only.
fn heap_used() -> u64 {
    // SAFETY: single-threaded read of the bump cursor.
    unsafe { *core::ptr::addr_of!(HEAP_POS) as u64 }
}

// =============================================================================
// Syscall numbers + ABI constants
// =============================================================================

/// `TaskExit (11)` — terminate the calling task.
const SYS_TASK_EXIT: u64 = 11;

/// `TaskYield (12)` — yield the CPU to the next runnable task.
const SYS_TASK_YIELD: u64 = 12;

/// `IpcCreateChannel (20)` — create an anonymous IPC channel.
///
/// ABI: `(queue_depth, backpressure_policy, tee_bound, 0, 0, 0) → (rax=channel_id, rdx=errno)`.
const SYS_IPC_CREATE_CHANNEL: u64 = 20;

/// `IpcSend (22)` — send a message on a channel.
const SYS_IPC_SEND: u64 = 22;

/// `IpcTryReceive (24)` — non-blocking receive.
const SYS_IPC_TRY_RECEIVE: u64 = 24;

/// `WriteConsole (60)` — write bytes to the kernel console (COM1).
const SYS_WRITE_CONSOLE: u64 = 60;

/// `BlkLookup (78)` — resolve a disk-slot name to a channel id,
/// capability-gated (ADR-0036 D6).
///
/// ABI: `(slot_ptr, slot_len, cap_ptr, cap_len) → (rax=channel_id, rdx=errno)`.
const SYS_BLK_LOOKUP: u64 = 78;

/// `NetRegister (100)` — bind a channel id to an interface name in the kernel
/// registry so other tasks can resolve it via `NetLookup (102)`.
///
/// ABI: `(name_ptr, name_len, channel_id, 0, 0, 0) → (rax=0_or_error, rdx=errno)`.
/// Returns `rdx = 0` on success; non-zero `rdx` on failure.
const SYS_NET_REGISTER: u64 = 100;

/// `MessageKind::Request = 1` — discriminant for BLK request messages (both
/// postcard-encoded `BlkRequest` header and raw data chunks per ADR-0036 D3).
const IPC_KIND_REQUEST: u64 = 1;

/// `MessageKind::Reply = 2` — discriminant for FS service response messages.
///
/// Clients waiting on `nexacore.fs-reply` use a blocking receive expecting
/// `Reply`-kind messages.
const IPC_KIND_REPLY: u64 = 2;

/// Backpressure policy `Block (0)` for `IpcCreateChannel`.
const IPC_BACKPRESSURE_BLOCK: u64 = 0;

/// TEE binding off `(0)` for `IpcCreateChannel`.
const IPC_TEE_BOUND_OFF: u64 = 0;

/// Queue depth for the FS service request channel.
///
/// A depth of 16 allows up to 16 client requests to be queued before the
/// channel blocks the sender, providing enough headroom for the single-file
/// editor and terminal to pipeline requests without tight synchronisation.
const FS_QUEUE_DEPTH: u64 = 16;

/// `ENOENT (2)` — the BLK slot is not yet registered by the driver.
const ENOENT: u64 = 2;

/// `SYSCALL_ERROR` sentinel: `u64::MAX` returned in `rax` on error.
const SYSCALL_ERROR: u64 = u64::MAX;

/// Retry budget while waiting for the NVMe driver to register its BLK slot.
///
/// 200 000 TaskYield iterations is generous enough to survive early-boot
/// scheduling jitter on VM-103 without blocking indefinitely.
const ENOENT_RETRY_BUDGET: u32 = 200_000;

/// Poll budget for waiting on an IPC reply (per block Read or Write).
///
/// Each iteration issues one `IpcTryReceive` + one `TaskYield`.
const REPLY_POLL_BUDGET: u32 = 2_000_000;

/// Wire-format discriminant for the `IpcSend` action in the kernel
/// capability deposit window (ADR-0036 D6, ACTION_TAG_IPC_SEND = 6).
const ACTION_TAG_IPC_SEND: u32 = 6;

/// Inline-chunk size for the ADR-0036 D3 inline data transport
/// (sector / 2 = 2048 bytes per chunk; two chunks per 4 KiB sector).
const CHUNK_SIZE: usize = 2048;

/// Total sector size (4 KiB) — the BLK layer block size per NCIP-014 § M4.
const SECTOR_SIZE: usize = 4096;

/// Sanity cap on `total_blocks` read from the superblock.
///
/// An on-disk volume larger than 128 blocks would require more heap than the
/// daemon allocates (32 MiB supports many 128-block copies with room to spare,
/// but a corrupt superblock might claim a huge value and OOM the bump
/// allocator before we can log anything useful).  128 is the documented root
/// volume size (ADR-0037 D2).
const MAX_TOTAL_BLOCKS: u64 = 128;

// =============================================================================
// Syscall stubs (System V AMD64 ABI — full-clobber, ADR-0035 lesson)
// =============================================================================

/// Issue a two-register-return syscall with all argument registers declared
/// as clobbered.
///
/// The kernel's syscall entry shuffles `rdi/rsi/rdx/r10/r8/r9` and returns
/// `(rax, rdx)` WITHOUT restoring any argument registers.  A minimal stub
/// that only clobbers `rcx/r11` lets the compiler keep live values in the
/// argument registers across a `TaskYield`, which is the exact systemic bug
/// documented in ADR-0035.  The generic 6-argument form is used for ALL
/// syscalls — including `TaskYield` — to guarantee the full clobber set
/// regardless of the number of arguments actually consumed by the syscall.
///
/// # Safety
///
/// Pointer arguments must be valid for the duration of the call.  The caller
/// is responsible for upholding the platform ABI (no stack alignment issues;
/// no live values in `rdi..r9` past the call).
#[inline(always)]
unsafe fn syscall(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> (u64, u64) {
    let rax: u64;
    let rdx: u64;
    // SAFETY: canonical Ring 3 → Ring 0 transition; caller upholds pointer
    // validity; ALL argument registers (rdi, rsi, rdx, r10, r8, r9) are
    // declared `inout(…) => _` so the compiler treats them as clobbered
    // after the syscall, preventing the use-after-syscall register aliasing
    // that caused ADR-0035.  `rcx` and `r11` are clobbered by SYSCALL as
    // per the AMD64 specification; `nostack` and `preserves_flags` hold
    // because the kernel restores RFLAGS and does not touch our stack.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => rax,
            inout("rdi") a0 => _,
            inout("rsi") a1 => _,
            inlateout("rdx") a2 => rdx,
            inout("r10") a3 => _,
            inout("r8")  a4 => _,
            inout("r9")  a5 => _,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    (rax, rdx)
}

/// Write `msg` to the kernel console (best-effort; errors are silently
/// ignored — a console write failing should never abort the daemon).
fn write(msg: &str) {
    write_bytes(msg.as_bytes());
}

/// Write a raw byte slice to the kernel console (best-effort).
fn write_bytes(b: &[u8]) {
    // SAFETY: `b` is a valid slice for the duration of the syscall.
    let _ = unsafe {
        syscall(
            SYS_WRITE_CONSOLE,
            b.as_ptr() as u64,
            b.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
}

/// Write `val` as a fixed 16-digit hex literal (`0x…`) to the console.
///
/// Used for printing numeric diagnostics where no formatting infrastructure
/// is available.
fn write_hex(val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut i: usize = 0;
    while i < 16 {
        let shift: u32 = (15 - i as u32) * 4;
        #[allow(clippy::cast_possible_truncation, reason = "nibble masked to 0..16")]
        let nibble = ((val >> shift) & 0xF) as usize;
        buf[2 + i] = HEX[nibble];
        i += 1;
    }
    write_bytes(&buf);
}

/// Yield the CPU to the next runnable task.
///
/// Issued through the generic 6-argument stub on purpose: the kernel entry
/// shuffles all argument registers and does not restore them; a minimal stub
/// that only clobbers `rcx/r11` would allow the compiler to keep live values
/// (e.g. the next syscall's arguments) in registers that the kernel just
/// destroyed.  See `syscall` doc and ADR-0035 for the heisenbug this prevents.
fn task_yield() {
    // SAFETY: TaskYield takes no arguments; zeros passed for unused slots.
    // Full clobber set is declared by the generic stub.
    let _ = unsafe { syscall(SYS_TASK_YIELD, 0, 0, 0, 0, 0, 0) };
}

/// Terminate the calling task with the given exit `code`.  Never returns.
fn exit(code: u32) -> ! {
    // SAFETY: TaskExit terminates the task unconditionally; the `noreturn`
    // option informs the compiler this path is a diverging point.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") u64::from(code),
            options(noreturn),
        );
    }
}

/// Create an anonymous IPC channel with `queue_depth` slots.
///
/// Returns the channel id on success, or [`SYSCALL_ERROR`] on failure.
fn sys_ipc_create_channel(queue_depth: u64) -> u64 {
    // SAFETY: scalar arguments only; no pointer arguments.
    let (rax, _rdx) = unsafe {
        syscall(
            SYS_IPC_CREATE_CHANNEL,
            queue_depth,
            IPC_BACKPRESSURE_BLOCK,
            IPC_TEE_BOUND_OFF,
            0,
            0,
            0,
        )
    };
    rax
}

/// Send `data` on `channel_id` with message `kind`.
///
/// Returns `true` on success; `false` when the kernel returns
/// [`SYSCALL_ERROR`] (channel full, bad id, etc.).
fn sys_ipc_send(channel_id: u64, kind: u64, data: &[u8]) -> bool {
    // SAFETY: `data` is a valid slice for the duration of the syscall.
    let (rax, _rdx) = unsafe {
        syscall(
            SYS_IPC_SEND,
            channel_id,
            kind,
            data.as_ptr() as u64,
            data.len() as u64,
            0,
            0,
        )
    };
    rax != SYSCALL_ERROR
}

/// Non-blocking receive: `Some(n)` bytes copied into `buf` on success,
/// `None` when the queue is empty.
fn sys_ipc_try_receive(channel_id: u64, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: `buf` is a valid writable slice; the kernel writes at most
    // `buf.len()` bytes.
    let (rax, _rdx) = unsafe {
        syscall(
            SYS_IPC_TRY_RECEIVE,
            channel_id,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
        )
    };
    if rax == SYSCALL_ERROR {
        None
    } else {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "kernel copies at most buf.len() ≤ IPC envelope bound bytes"
        )]
        Some(rax as usize)
    }
}

/// Register `channel_id` under `name` in the kernel network registry.
///
/// Other tasks resolve this channel by calling `NetLookup(102)` with the same
/// name.  The FS service calls this twice: once for `nexacore.fs` (requests) and
/// once for `nexacore.fs-reply` (responses).
///
/// Returns `true` on success (`rdx == 0`), `false` on failure.
fn sys_net_register(name: &[u8], channel_id: u64) -> bool {
    // SAFETY: `name` is a valid slice for the duration of the syscall.
    let (_rax, rdx) = unsafe {
        syscall(
            SYS_NET_REGISTER,
            name.as_ptr() as u64,
            name.len() as u64,
            channel_id,
            0,
            0,
            0,
        )
    };
    rdx == 0
}

/// Issue `BlkLookup(78)` with the given slot name and optional capability
/// token bytes.
///
/// Returns `(channel_id, errno)`.  On success `errno = 0`.  On failure
/// `errno` carries the POSIX error code (`ENOENT`, `EACCES`, …).
fn sys_blk_lookup(slot: &[u8], cap_bytes: &[u8]) -> (u64, u64) {
    // SAFETY: `slot` and `cap_bytes` are valid slices for the duration of
    // the syscall.  Zero-length `cap_bytes` is a documented valid case
    // (cap_len = 0 signals "no capability presented").
    unsafe {
        syscall(
            SYS_BLK_LOOKUP,
            slot.as_ptr() as u64,
            slot.len() as u64,
            cap_bytes.as_ptr() as u64,
            cap_bytes.len() as u64,
            0,
            0,
        )
    }
}

// =============================================================================
// Panic handler
// =============================================================================

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    write("[nexacore-fsd] PANIC\n");
    exit(1)
}

// =============================================================================
// BSS buffers (NOT on the 4 KiB user stack)
// =============================================================================

/// Staging buffer for the superblock block (block 0, 4 KiB).
///
/// Read first to determine whether a valid `OMNIFS01` volume exists and to
/// extract `total_blocks`.  Declared as `static mut` so it lives in BSS
/// (not the tiny Ring 3 stack).  Accessed only from `_start` (single-threaded)
/// exclusively through `addr_of_mut!`.
static mut SUPERBLOCK_BUF: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

/// Receive staging buffer for IPC messages (`BlkResponse` + raw data chunks,
/// and inbound `FsRequest` messages from clients).
///
/// Sized to the IPC envelope maximum (4096 bytes) so it can hold any single
/// message the NVMe driver or an FS client sends.
static mut RECV_BUF: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

/// Request receive buffer for the FS service loop.
///
/// Separate from [`RECV_BUF`] so the NVMe path (boot-counter sync) and the
/// FS service path never alias.  4 KiB matches the maximum IPC message size.
static mut FS_REQ_BUF: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

/// Response encode buffer for the FS service loop.
///
/// Used by [`encode_into_slice`] so [`FsResponse`] messages are encoded into
/// BSS rather than the heap, keeping the response path allocation-free.
static mut FS_RESP_BUF: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

// =============================================================================
// BLK client helpers
// =============================================================================

/// Poll `reply_channel` until a `BlkResponse` arrives; postcard-decode and
/// return it.
///
/// On decode failure or budget exhaustion logs a diagnostic and calls
/// `exit(fail_code)` — never returns `None`.
///
/// Callers MUST supply a `recv_buf` derived from a `static mut` BSS array via
/// `addr_of_mut!` (not a stack allocation) because the kernel writes directly
/// into the slice.
fn poll_for_response(
    reply_channel: u64,
    recv_buf: &mut [u8; SECTOR_SIZE],
    fail_code: u32,
) -> BlkResponse {
    let mut attempts: u32 = 0;
    loop {
        if let Some(n) = sys_ipc_try_receive(reply_channel, recv_buf) {
            let bytes = &recv_buf[..n];
            match decode_canonical::<BlkResponse>(bytes) {
                Ok(resp) => return resp,
                Err(_) => {
                    write("[nexacore-fsd] BlkResponse decode FAILED\n");
                    exit(fail_code);
                }
            }
        }
        attempts = attempts.saturating_add(1);
        if attempts >= REPLY_POLL_BUDGET {
            write("[nexacore-fsd] reply poll budget exhausted\n");
            exit(fail_code);
        }
        task_yield();
    }
}

/// Poll `reply_channel` for a raw data chunk (non-postcard bytes), copying up
/// to `buf.len()` bytes into `buf`.
///
/// Returns the number of bytes received.  On budget exhaustion calls
/// `exit(fail_code)`.
///
/// Used for the inline data transport chunks (ADR-0036 D3): the driver sends
/// raw sector data after the `BlkResponse::Ok` confirmation; each chunk is a
/// plain byte slice of [`CHUNK_SIZE`] bytes.
fn poll_for_raw_chunk(reply_channel: u64, buf: &mut [u8], fail_code: u32) -> usize {
    let mut attempts: u32 = 0;
    loop {
        if let Some(n) = sys_ipc_try_receive(reply_channel, buf) {
            return n;
        }
        attempts = attempts.saturating_add(1);
        if attempts >= REPLY_POLL_BUDGET {
            write("[nexacore-fsd] chunk poll budget exhausted\n");
            exit(fail_code);
        }
        task_yield();
    }
}

/// Read a single 4 KiB sector at `lba` from the NVMe driver into `out`.
///
/// Protocol (ADR-0036 D3 inline transport, mirroring `nexacore-blkcheck-image`):
/// 1. Encode `BlkRequest::Read{lba, count:1, buf_iova:0}` via postcard.
/// 2. `IpcSend(req_channel, KIND_REQUEST, encoded_header)`.
/// 3. Poll `reply_channel` for `BlkResponse::Ok`.
/// 4. Poll `reply_channel` for raw chunk-0 (2048 bytes) into `out[0..2048]`.
/// 5. Poll `reply_channel` for raw chunk-1 (2048 bytes) into `out[2048..4096]`.
///
/// Returns `true` on success, `false` on any encode / send / response error.
/// Chunk size mismatches are treated as errors (logged, returns false).
fn read_block(req_ch: u64, reply_ch: u64, lba: u64, out: &mut [u8; SECTOR_SIZE]) -> bool {
    let req = BlkRequest::Read {
        lba,
        count: 1,
        buf_iova: 0,
    };
    let encoded = match encode_canonical(&req) {
        Ok(b) => b,
        Err(_) => {
            write("[nexacore-fsd] read_block encode FAILED\n");
            return false;
        }
    };
    if !sys_ipc_send(req_ch, IPC_KIND_REQUEST, &encoded) {
        write("[nexacore-fsd] read_block IpcSend FAILED\n");
        return false;
    }

    // Receive BlkResponse.
    // SAFETY: RECV_BUF is a static BSS buffer; the pointer is valid for the
    // lifetime of this call.  addr_of_mut! avoids forming a reference to
    // static mut.
    let recv: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };
    let resp = poll_for_response(reply_ch, recv, 4);
    match resp {
        BlkResponse::Ok => {}
        _ => {
            write("[nexacore-fsd] read_block BlkResponse not Ok\n");
            return false;
        }
    }

    // Receive chunk-0 (bytes 0..2048).
    let n0 = poll_for_raw_chunk(reply_ch, &mut out[..CHUNK_SIZE], 4);
    if n0 != CHUNK_SIZE {
        write("[nexacore-fsd] read_block chunk-0 wrong size=");
        write_hex(n0 as u64);
        write("\n");
        return false;
    }

    // Receive chunk-1 (bytes 2048..4096).
    let n1 = poll_for_raw_chunk(reply_ch, &mut out[CHUNK_SIZE..], 4);
    if n1 != CHUNK_SIZE {
        write("[nexacore-fsd] read_block chunk-1 wrong size=");
        write_hex(n1 as u64);
        write("\n");
        return false;
    }

    true
}

/// Write a single 4 KiB sector at `lba` from `data` to the NVMe driver.
///
/// Protocol (ADR-0036 D3 inline transport, mirroring `nexacore-blkcheck-image`):
/// 1. Encode `BlkRequest::Write{lba, count:1, buf_iova:0}` via postcard.
/// 2. `IpcSend(req_channel, KIND_REQUEST, encoded_header)`.
/// 3. `IpcSend(req_channel, KIND_REQUEST, data[0..2048])` — chunk-0.
/// 4. `IpcSend(req_channel, KIND_REQUEST, data[2048..4096])` — chunk-1.
/// 5. Poll `reply_channel` for `BlkResponse::Ok`.
///
/// Returns `true` on success, `false` on any error.
fn write_block(req_ch: u64, reply_ch: u64, lba: u64, data: &[u8; SECTOR_SIZE]) -> bool {
    let req = BlkRequest::Write {
        lba,
        count: 1,
        buf_iova: 0,
    };
    let encoded = match encode_canonical(&req) {
        Ok(b) => b,
        Err(_) => {
            write("[nexacore-fsd] write_block encode FAILED\n");
            return false;
        }
    };
    if !sys_ipc_send(req_ch, IPC_KIND_REQUEST, &encoded) {
        write("[nexacore-fsd] write_block IpcSend (header) FAILED\n");
        return false;
    }

    // Send chunk-0 (bytes 0..2048).
    if !sys_ipc_send(req_ch, IPC_KIND_REQUEST, &data[..CHUNK_SIZE]) {
        write("[nexacore-fsd] write_block IpcSend (chunk-0) FAILED\n");
        return false;
    }

    // Send chunk-1 (bytes 2048..4096).
    if !sys_ipc_send(req_ch, IPC_KIND_REQUEST, &data[CHUNK_SIZE..]) {
        write("[nexacore-fsd] write_block IpcSend (chunk-1) FAILED\n");
        return false;
    }

    // Poll reply channel for BlkResponse::Ok.
    let recv: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };
    let resp = poll_for_response(reply_ch, recv, 4);
    match resp {
        BlkResponse::Ok => true,
        _ => {
            write("[nexacore-fsd] write_block BlkResponse not Ok\n");
            false
        }
    }
}

/// Flush the in-memory volume to NVMe by serialising it and writing every
/// block back via the BLK service.
///
/// Reused both by the boot-counter proof startup path and by the
/// `FsRequest::Sync` handler. Returns `true` on success, `false` if any
/// `write_block` call fails.
fn sync_volume_to_nvme(vol: &OnDiskVolume, req_ch: u64, reply_ch: u64) -> bool {
    // sync_to_bytes fails closed (FsError::MetadataOverflow) instead of
    // truncating metadata; surface the failure on serial and abort the
    // sync — the on-disk image keeps its previous (consistent) contents.
    let raw = match vol.sync_to_bytes() {
        Ok(bytes) => bytes,
        Err(_) => {
            write("[nexacore-fsd] sync_to_bytes FAILED: metadata overflow — sync aborted\n");
            return false;
        }
    };
    #[allow(
        clippy::cast_possible_truncation,
        reason = "raw.len() / SECTOR_SIZE ≤ 128 fits comfortably in u64"
    )]
    let n_blocks = (raw.len() / SECTOR_SIZE) as u64;
    let mut i: u64 = 0;
    while i < n_blocks {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "i ≤ 127; i * SECTOR_SIZE ≤ 520192 fits in usize on 64-bit"
        )]
        let off = (i as usize) * SECTOR_SIZE;
        // SAFETY: `raw` has `n_blocks * SECTOR_SIZE` bytes returned by
        // `sync_to_bytes`; `off + SECTOR_SIZE <= raw.len()` because
        // `i < n_blocks`.
        let chunk: &[u8; SECTOR_SIZE] = unsafe {
            &*(raw[off..off + SECTOR_SIZE]
                .as_ptr()
                .cast::<[u8; SECTOR_SIZE]>())
        };
        if !write_block(req_ch, reply_ch, i, chunk) {
            write("[nexacore-fsd] write_block FAILED at lba=");
            write_hex(i);
            write("\n");
            return false;
        }
        i += 1;
    }
    true
}

// =============================================================================
// Decimal integer helpers
// =============================================================================

/// Parse the trailing decimal integer after the last space in `s`.
///
/// Returns `0` if no such integer is found or if parsing fails.
/// Used to extract the boot counter from `"NexaCore-OS persistent root — boot N\n"`.
fn parse_trailing_decimal(s: &[u8]) -> u64 {
    // Find the last space byte.
    let mut last_space: Option<usize> = None;
    let mut i = 0usize;
    while i < s.len() {
        if s[i] == b' ' {
            last_space = Some(i);
        }
        i += 1;
    }
    let start = match last_space {
        Some(idx) => idx + 1,
        None => return 0,
    };
    // Parse digits from `start`, stopping at the first non-digit.
    let mut val: u64 = 0;
    let mut found_digit = false;
    let mut j = start;
    while j < s.len() {
        let b = s[j];
        if b.is_ascii_digit() {
            val = val.saturating_mul(10).saturating_add(u64::from(b - b'0'));
            found_digit = true;
        } else {
            break;
        }
        j += 1;
    }
    if found_digit { val } else { 0 }
}

/// Write the decimal representation of `n` into `buf` starting at `pos`.
///
/// Returns the new position (exclusive end of written digits).
/// `buf` must have enough space; at most 20 bytes are written (u64::MAX is
/// 20 digits).
fn write_decimal(buf: &mut [u8], pos: usize, n: u64) -> usize {
    if n == 0 {
        if pos < buf.len() {
            buf[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    // Convert to digits in reverse, then flip.
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    let mut v = n;
    while v > 0 && len < 20 {
        #[allow(clippy::cast_possible_truncation, reason = "v % 10 is always 0..9")]
        let digit = (v % 10) as u8;
        tmp[len] = b'0' + digit;
        len += 1;
        v /= 10;
    }
    // Write digits in forward order.
    let mut out_pos = pos;
    let mut d = len;
    while d > 0 {
        d -= 1;
        if out_pos < buf.len() {
            buf[out_pos] = tmp[d];
            out_pos += 1;
        }
    }
    out_pos
}

// =============================================================================
// FS error mapping
// =============================================================================

/// Map an `nexacore_fs::FsError` to the stable [`FsErrno`] wire vocabulary.
///
/// The mapping is intentionally lossy: several nexacore-fs error categories
/// collapse to `InvalidArgument` because they represent programmer errors
/// (path too long, wrong file type) rather than runtime conditions the client
/// can meaningfully distinguish.
///
/// The `DirectoryNotEmpty` variant is kept distinct (TASK-23, ADR-0045 D3) so
/// the file-manager client can show a specific "directory is not empty" message
/// rather than a generic I/O failure.
fn map_fs_error(e: nexacore_fs::FsError) -> FsErrno {
    match e {
        nexacore_fs::FsError::FileNotFound | nexacore_fs::FsError::VolumeNotFound => FsErrno::NotFound,
        nexacore_fs::FsError::FileAlreadyExists => FsErrno::AlreadyExists,
        nexacore_fs::FsError::IntegrityViolation => FsErrno::Integrity,
        // Surface non-empty directory deletes as a distinct error so callers
        // can present actionable feedback (ADR-0045 D3 "delete di non-vuoto").
        nexacore_fs::FsError::DirectoryNotEmpty => FsErrno::DirectoryNotEmpty,
        nexacore_fs::FsError::PathTooLong
        | nexacore_fs::FsError::NotAFile
        | nexacore_fs::FsError::NotADirectory
        | nexacore_fs::FsError::NoSpace
        | nexacore_fs::FsError::InvalidSlotName
        | nexacore_fs::FsError::InvalidChannelId => FsErrno::InvalidArgument,
        _ => FsErrno::Io,
    }
}

// =============================================================================
// FS service request handler
// =============================================================================

/// Dispatch one decoded [`FsRequest`] to the live `OnDiskVolume`.
///
/// All nine request variants are fully handled:
///
/// - `Create`  → [`OnDiskVolume::create_file`]
/// - `Write`   → [`OnDiskVolume::exists`] + optionally `create_file`, then
///               [`OnDiskVolume::write_file`]
/// - `Read`    → [`OnDiskVolume::read_file`] (len capped at
///               [`FS_MAX_INLINE_BYTES`])
/// - `Mkdir`   → [`OnDiskVolume::create_directory`] (TASK-23, ADR-0045 D3)
/// - `Delete`  → [`OnDiskVolume::delete_file`] first; on `NotAFile` falls
///               through to [`OnDiskVolume::delete_directory`] so that both
///               files and empty directories are removed with a single request
///               (TASK-23, ADR-0045 D3). A non-empty directory surfaces as
///               [`FsErrno::DirectoryNotEmpty`].
/// - `ListDir` → [`OnDiskVolume::list_directory`]
/// - `Stat`    → [`OnDiskVolume::stat_file`]
/// - `Sync`    → [`sync_volume_to_nvme`] (flushes the whole volume to NVMe)
///
/// The function NEVER panics: any `FsError` is mapped to [`FsErrno`] and
/// returned as [`FsResponse::Error`].
fn handle(vol: &mut OnDiskVolume, req: FsRequest, req_ch: u64, reply_ch: u64) -> FsResponse {
    match req {
        FsRequest::Create { path } => match vol.create_file(&path) {
            Ok(_) => FsResponse::Created,
            Err(e) => FsResponse::Error(map_fs_error(e)),
        },

        FsRequest::Write { path, offset, data } => {
            // Guard: payload must not exceed the inline size cap.
            if data.len() > FS_MAX_INLINE_BYTES {
                return FsResponse::Error(FsErrno::TooLarge);
            }
            // Auto-create: if the file does not yet exist, create it so that
            // a "save new file" workflow does not require a separate Create.
            if !vol.exists(&path) {
                if let Err(e) = vol.create_file(&path) {
                    return FsResponse::Error(map_fs_error(e));
                }
            }
            match vol.write_file(&path, offset, &data) {
                Ok(_) => FsResponse::Ok,
                Err(e) => FsResponse::Error(map_fs_error(e)),
            }
        }

        FsRequest::Read { path, offset, len } => {
            // Cap the requested length to the inline byte limit so the
            // response always fits inside a single IPC message.
            #[allow(
                clippy::cast_possible_truncation,
                reason = "capped to FS_MAX_INLINE_BYTES which fits in u32"
            )]
            let capped_len = len.min(FS_MAX_INLINE_BYTES as u64) as u32;
            match vol.read_file(&path, offset, capped_len) {
                Ok(bytes) => FsResponse::Data { bytes },
                Err(e) => FsResponse::Error(map_fs_error(e)),
            }
        }

        // TASK-23 (ADR-0045 D3): create a directory at `path`.
        // `create_directory` rejects an existing path (`AlreadyExists`),
        // an invalid component (`InvalidSlotName`), and a path that is too
        // long (`PathTooLong`).  All errors are mapped via `map_fs_error`.
        FsRequest::Mkdir { path } => match vol.create_directory(&path) {
            Ok(_ino) => FsResponse::Created,
            Err(e) => FsResponse::Error(map_fs_error(e)),
        },

        // TASK-23 (ADR-0045 D3): delete either a file or an empty directory.
        //
        // Strategy: try `delete_file` first.  If the path holds a directory
        // (signalled by `FsError::NotAFile`) fall through to
        // `delete_directory`.  Any other error from `delete_file` (e.g.
        // `FileNotFound`) is returned immediately without calling
        // `delete_directory`, so we never attempt a double-delete.
        // A non-empty directory surfaces as `FsErrno::DirectoryNotEmpty`.
        FsRequest::Delete { path } => match vol.delete_file(&path) {
            Ok(()) => FsResponse::Ok,
            Err(nexacore_fs::FsError::NotAFile) => match vol.delete_directory(&path) {
                Ok(()) => FsResponse::Ok,
                Err(e) => FsResponse::Error(map_fs_error(e)),
            },
            Err(e) => FsResponse::Error(map_fs_error(e)),
        },

        FsRequest::ListDir { path } => {
            // `OnDiskVolume::list_directory` returns the direct child
            // basenames of the directory at `path`.  The root (`"/"`) is
            // always present as an inode in a formatted volume.
            match vol.list_directory(&path) {
                Ok(names) => FsResponse::Listing { names },
                Err(e) => FsResponse::Error(map_fs_error(e)),
            }
        }

        FsRequest::Stat { path } => match vol.stat_file(&path) {
            Ok(meta) => FsResponse::Stat {
                size: meta.size,
                is_dir: false,
            },
            Err(e) => FsResponse::Error(map_fs_error(e)),
        },

        FsRequest::Sync => {
            // Durability point: serialise the whole volume and flush every
            // block to NVMe.  A successful Sync guarantees that prior Writes
            // survive a subsequent reboot (the TASK-15 / TASK-22 acceptance).
            if sync_volume_to_nvme(vol, req_ch, reply_ch) {
                write("[nexacore-fsd] Sync: volume flushed to NVMe\n");
                FsResponse::Ok
            } else {
                FsResponse::Error(FsErrno::Io)
            }
        }

        // `FsRequest` is `#[non_exhaustive]`; new variants added in later
        // tasks will fall here and return InvalidArgument rather than
        // crashing the service.
        _ => FsResponse::Error(FsErrno::InvalidArgument),
    }
}

// =============================================================================
// ELF entry point
// =============================================================================

/// ELF entry point.
///
/// Runs the TASK-15 NCFS persistence proof (boot-counter self-check) then
/// registers the FS service channels and serves [`FsRequest`] messages forever.
///
/// See the module-level doc for the full control flow and exit-code table.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("[nexacore-fsd] start\n");

    // ── Step 1: look up the deposited IpcSend capability token ───────────────
    //
    // The kernel deposited an attenuated CapabilityToken with action IpcSend
    // in the deposit window at 0x0010_0000 (DRIVER_CAP_DEPOSIT_VA) under
    // deposit tag ACTION_TAG_IPC_SEND = 6 (ADR-0036 D6).
    //
    // SAFETY: `find_token` reads the kernel-mapped read-only deposit window.
    // We are running inside a correctly launched NexaCore OS process whose kernel
    // guaranteed the window was mapped before transferring execution to
    // `_start` (NCIP-013 § S5.3 step 8 / ADR-0036 D1 boot-spawn pattern).
    let cap_bytes: &[u8] = match nexacore_driver_shared::caps::find_token(
        ACTION_TAG_IPC_SEND,
        |_| true, // accept the first IpcSend token
    ) {
        Some(b) => b,
        None => {
            write("[nexacore-fsd] no client token in deposit window\n");
            exit(2);
        }
    };

    // ── Step 2: BlkLookup nvme0 (request channel) ────────────────────────────
    //
    // Poll with ENOENT-retry: the NVMe driver spawns before us but may not
    // have registered its BLK slot yet.  On ENOENT → yield + retry.
    // On any other non-zero errno → token problem or unrecoverable error.
    let req_channel: u64;
    {
        let mut enoent_count: u32 = 0;
        loop {
            let (ch, errno) = sys_blk_lookup(b"nvme0", cap_bytes);
            if errno == 0 {
                req_channel = ch;
                break;
            }
            if errno == ENOENT {
                enoent_count = enoent_count.saturating_add(1);
                if enoent_count >= ENOENT_RETRY_BUDGET {
                    write("[nexacore-fsd] nvme0 driver never registered\n");
                    exit(3);
                }
                task_yield();
                continue;
            }
            write("[nexacore-fsd] BlkLookup(nvme0) FAILED errno=");
            write_hex(errno);
            write("\n");
            exit(3);
        }
    }
    write("[nexacore-fsd] req_channel=");
    write_hex(req_channel);
    write("\n");

    // ── Step 3: BlkLookup nvme0-reply (reply channel) ────────────────────────
    let reply_channel: u64;
    {
        let mut enoent_count: u32 = 0;
        loop {
            let (ch, errno) = sys_blk_lookup(b"nvme0-reply", cap_bytes);
            if errno == 0 {
                reply_channel = ch;
                break;
            }
            if errno == ENOENT {
                enoent_count = enoent_count.saturating_add(1);
                if enoent_count >= ENOENT_RETRY_BUDGET {
                    write("[nexacore-fsd] nvme0-reply driver never registered\n");
                    exit(3);
                }
                task_yield();
                continue;
            }
            write("[nexacore-fsd] BlkLookup(nvme0-reply) FAILED errno=");
            write_hex(errno);
            write("\n");
            exit(3);
        }
    }
    write("[nexacore-fsd] reply_channel=");
    write_hex(reply_channel);
    write("\n");

    // ── Step 3b: Register the FS service channels EARLY ──────────────────────
    //
    // Register BEFORE the (slow) mount + boot-counter proof + 128-block sync so
    // clients (the apps image) can resolve `ncfs`/`ncfs-reply` via NetLookup
    // promptly at boot. The serve loop still starts after the proof; any client
    // request that arrives meanwhile buffers in the channel queue (depth
    // FS_QUEUE_DEPTH) and is drained once the loop runs. (TASK-22 fix: the apps
    // image's bounded NetLookup retry expired before a late registration.)
    let fs_req_ch = sys_ipc_create_channel(FS_QUEUE_DEPTH);
    let fs_reply_ch = sys_ipc_create_channel(FS_QUEUE_DEPTH);
    if fs_req_ch == SYSCALL_ERROR || fs_reply_ch == SYSCALL_ERROR {
        write("[nexacore-fsd] IpcCreateChannel FAILED\n");
        exit(7);
    }
    if !sys_net_register(CHANNEL_NAME.as_bytes(), fs_req_ch) {
        write("[nexacore-fsd] NetRegister(ncfs) FAILED\n");
        exit(8);
    }
    if !sys_net_register(b"ncfs-reply", fs_reply_ch) {
        write("[nexacore-fsd] NetRegister(ncfs-reply) FAILED\n");
        exit(8);
    }
    write("[nexacore-fsd] FS service registered (ncfs / ncfs-reply) fs_req_ch=");
    write_hex(fs_req_ch);
    write(" fs_reply_ch=");
    write_hex(fs_reply_ch);
    write("\n");

    // ── Step 4: Read block 0 (superblock) ────────────────────────────────────
    //
    // SAFETY: SUPERBLOCK_BUF is a static BSS buffer; the pointer is valid for
    // the lifetime of this block.  addr_of_mut! avoids forming a reference to
    // static mut.
    let sb_buf: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(SUPERBLOCK_BUF) };

    if !read_block(req_channel, reply_channel, 0, sb_buf) {
        write("[nexacore-fsd] block 0 read FAILED\n");
        exit(4);
    }

    // ── Step 5: Dispatch on magic ─────────────────────────────────────────────
    //
    // After the mount+proof+sync block, `vol` is moved into the serve loop
    // below.  The `if/else` branches both produce a `vol: OnDiskVolume` and
    // then fall through to the common service-registration + serve-loop code.
    let mut vol: OnDiskVolume;

    if sb_buf[..8] == *b"OMNIFS01" {
        // ── VALID volume path ─────────────────────────────────────────────────

        // Extract total_blocks from superblock bytes[16..24] (u64 LE).
        // Verified against `write_superblock_to_block` (ondisk.rs:1078) and
        // `parse_superblock` (ondisk.rs:1120-1123):
        //   block[16..24] = sb.total_blocks.to_le_bytes()
        let total_blocks = u64::from_le_bytes([
            sb_buf[16], sb_buf[17], sb_buf[18], sb_buf[19], sb_buf[20], sb_buf[21], sb_buf[22],
            sb_buf[23],
        ]);

        if total_blocks == 0 || total_blocks > MAX_TOTAL_BLOCKS {
            write("[nexacore-fsd] implausible total_blocks=");
            write_hex(total_blocks);
            write("\n");
            exit(4);
        }

        // Allocate a Vec<u8> of total_blocks * 4096 bytes and read all blocks.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "total_blocks <= 128; total * 4096 <= 524288, fits in usize on 64-bit"
        )]
        let total_bytes = (total_blocks as usize) * SECTOR_SIZE;
        // Zero-filled buffer; the read loop overwrites every byte in sequence.
        let mut vol_buf: Vec<u8> = vec![0u8; total_bytes];

        // Block 0 is already in sb_buf — copy it in, then read the rest.
        vol_buf[..SECTOR_SIZE].copy_from_slice(sb_buf);

        let mut blk: u64 = 1;
        while blk < total_blocks {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "blk <= 127, blk * 4096 <= 520192 fits in usize on 64-bit"
            )]
            let offset = (blk as usize) * SECTOR_SIZE;
            // Extract a fixed-size array ref from the slice for read_block.
            // SAFETY: vol_buf has total_bytes capacity; offset + SECTOR_SIZE
            // <= total_bytes because blk < total_blocks.
            let chunk: &mut [u8; SECTOR_SIZE] = unsafe {
                &mut *(vol_buf[offset..offset + SECTOR_SIZE]
                    .as_mut_ptr()
                    .cast::<[u8; SECTOR_SIZE]>())
            };
            if !read_block(req_channel, reply_channel, blk, chunk) {
                write("[nexacore-fsd] block read FAILED at lba=");
                write_hex(blk);
                write("\n");
                exit(4);
            }
            blk += 1;
        }

        write("[nexacore-fsd] root mounted from nvme0 (");
        write_hex(total_blocks);
        write(" blocks)\n");

        // Mount the volume from the byte buffer.
        let mut mounted = match OnDiskVolume::mount(&vol_buf) {
            Ok(v) => v,
            Err(_) => {
                write("[nexacore-fsd] mount FAILED (integrity/parse) — NOT overwriting\n");
                exit(5);
            }
        };

        // ── TASK-15 boot-counter proof (retained) ─────────────────────────────
        //
        // Read /test.txt to get the current boot counter.
        // `unwrap_or_default()` returns an empty Vec on any error (e.g.
        // FileNotFound on first mount after a bare format), which
        // parse_trailing_decimal interprets as counter = 0.
        let old_content = mounted.read_file("/test.txt", 0, 256).unwrap_or_default();

        write("[nexacore-fsd] /test.txt was: ");
        write_bytes(&old_content);
        write("\n");

        let n = parse_trailing_decimal(&old_content);

        // Build the new counter string: "NexaCore-OS persistent root — boot N+1\n"
        // The em-dash (—) is UTF-8: 0xE2 0x80 0x94.
        // Use a fixed-size stack buffer — max: prefix(36) + 20 digits + newline.
        let mut new_content = [0u8; 64];
        let prefix: &[u8] = b"NexaCore-OS persistent root \xE2\x80\x94 boot ";
        let copy_len = prefix.len().min(new_content.len());
        new_content[..copy_len].copy_from_slice(&prefix[..copy_len]);
        let mut pos = copy_len;
        pos = write_decimal(&mut new_content, pos, n.saturating_add(1));
        if pos < new_content.len() {
            new_content[pos] = b'\n';
            pos += 1;
        }
        let new_str = &new_content[..pos];

        // Write /test.txt: delete + recreate to ensure clean content (no
        // trailing bytes from a shorter-then-longer counter sequence).
        let _ = mounted.delete_file("/test.txt"); // ignore if not found
        if let Err(_e) = mounted.create_file("/test.txt") {
            write("[nexacore-fsd] create_file /test.txt FAILED\n");
            exit(6);
        }
        if let Err(_e) = mounted.write_file("/test.txt", 0, new_str) {
            write("[nexacore-fsd] write_file /test.txt FAILED\n");
            exit(6);
        }

        // Sync the boot-counter update to NVMe.
        if !sync_volume_to_nvme(&mounted, req_channel, reply_channel) {
            write("[nexacore-fsd] boot-counter sync FAILED\n");
            exit(4);
        }

        write("[nexacore-fsd] boot ");
        let mut dec_buf = [0u8; 22];
        let dec_len = write_decimal(&mut dec_buf, 0, n.saturating_add(1));
        write_bytes(&dec_buf[..dec_len]);
        write(" persisted\n");

        vol = mounted;
    } else {
        // ── FRESH DISK (no valid NCFS magic) — format fallback ─────────────

        write("[nexacore-fsd] nvme0 has no NCFS volume — formatting fresh root\n");

        let mut fresh = OnDiskVolume::format(128);
        write("[nexacore-fsd] format complete, heap=");
        write_hex(heap_used());
        write("\n");

        if let Err(_e) = fresh.create_file("/test.txt") {
            write("[nexacore-fsd] create_file /test.txt FAILED\n");
            exit(6);
        }
        let initial: &[u8] = b"NexaCore-OS persistent root \xE2\x80\x94 boot 1\n";
        if let Err(_e) = fresh.write_file("/test.txt", 0, initial) {
            write("[nexacore-fsd] write_file /test.txt FAILED\n");
            exit(6);
        }
        write("[nexacore-fsd] /test.txt written, heap=");
        write_hex(heap_used());
        write("\n");

        // Sync the freshly formatted volume to NVMe.
        if !sync_volume_to_nvme(&fresh, req_channel, reply_channel) {
            write("[nexacore-fsd] fresh-format sync FAILED\n");
            exit(4);
        }

        write("[nexacore-fsd] formatted + /test.txt = boot 1 (128 blocks synced)\n");

        vol = fresh;
    }

    write("[nexacore-fsd] TASK-15 persistence proof complete — entering serve loop\n");

    // ── Step 7: Serve loop (never exits) ─────────────────────────────────────
    //
    // The loop polls `fs_req_ch` for inbound `FsRequest` messages.  On each
    // message it decodes the postcard payload, dispatches to `handle()`, and
    // sends the `FsResponse` back on `fs_reply_ch`.
    //
    // Invariants:
    //   - A malformed or unrecognised message is answered with
    //     `FsResponse::Error(InvalidArgument)` and never panics.
    //   - `handle()` takes `&mut vol` so the volume is mutated in place and
    //     persists across requests; `Sync` explicitly flushes to NVMe.
    //   - The buffers (FS_REQ_BUF, FS_RESP_BUF) are BSS statics — they avoid
    //     the tiny Ring-3 stack and are safe to pass by mutable reference.

    // SAFETY: both bufs are static BSS arrays; addr_of_mut! avoids forming a
    // reference to static mut.  The serve loop is the sole writer/reader after
    // this point (single-threaded task).
    let req_buf: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(FS_REQ_BUF) };
    let resp_buf: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(FS_RESP_BUF) };

    loop {
        match sys_ipc_try_receive(fs_req_ch, req_buf) {
            Some(n) => {
                // Decode the inbound FsRequest from the first `n` bytes of the
                // buffer.  Any decode failure (truncated message, wrong type
                // tag, trailing bytes) is answered with InvalidArgument —
                // never a panic.
                let response = match decode_canonical::<FsRequest>(&req_buf[..n]) {
                    Ok(req) => handle(&mut vol, req, req_channel, reply_channel),
                    Err(_) => {
                        write("[nexacore-fsd] FsRequest decode error — InvalidArgument\n");
                        FsResponse::Error(FsErrno::InvalidArgument)
                    }
                };

                // Encode the FsResponse into the BSS response buffer
                // (no heap allocation on the hot path).
                match encode_into_slice(&response, resp_buf) {
                    Ok(len) => {
                        if !sys_ipc_send(fs_reply_ch, IPC_KIND_REPLY, &resp_buf[..len]) {
                            // The reply channel is full or the client disconnected.
                            // Log and continue — never abort the service.
                            write("[nexacore-fsd] IpcSend(reply) FAILED — dropped\n");
                        }
                    }
                    Err(_) => {
                        // Response too large for the BSS buffer (should not
                        // happen within the FS_MAX_INLINE_BYTES contract, but
                        // guard it defensively).
                        write("[nexacore-fsd] FsResponse encode overflow — sending Error\n");
                        let fallback = FsResponse::Error(FsErrno::Io);
                        if let Ok(len) = encode_into_slice(&fallback, resp_buf) {
                            let _ = sys_ipc_send(fs_reply_ch, IPC_KIND_REPLY, &resp_buf[..len]);
                        }
                    }
                }
            }
            None => {
                // No pending request — yield the CPU to avoid busy-spinning.
                task_yield();
            }
        }
    }
}
