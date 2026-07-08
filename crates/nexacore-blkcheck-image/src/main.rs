//! Bare-metal TASK-14 BLK service smoke client for NexaCore OS (ADR-0036 D7).
//!
//! A `no_std + no_main` Ring 3 ELF the kernel spawns to validate the
//! NVMe BLK service loop end to end.  The kernel also spawns the NVMe
//! driver image at `System` priority before this client.
//!
//! ## Test plan
//!
//! ```text
//! _start()
//!     1. Negative path — BlkLookup("nvme0") without a capability token.
//!        Expected: ENOENT (driver not yet registered) → retry with
//!        TaskYield; EACCES (registered, gate active) → the test passes.
//!
//!     2. Capability lookup — read the deposited IpcSend token from the
//!        kernel deposit window at the well-known VA 0x0010_0000.
//!        Missing token → exit(4).
//!
//!     3. Positive BlkLookup — resolve "nvme0" (req channel) and
//!        "nvme0-reply" (reply channel) using the deposited token.
//!        Errno ≠ 0 → exit(6) / exit(7).
//!
//!     4. Write — send BlkRequest::Write{lba:42, count:1, buf_iova:0}
//!        postcard-encoded via IpcSend(req_channel, KIND_REQUEST), then
//!        two 2048-byte data chunks (raw, KIND_REQUEST) per ADR-0036 D3.
//!        Poll reply channel; expect BlkResponse::Ok → exit(8) on failure.
//!
//!     5. Flush — send BlkRequest::Flush, poll reply → expect
//!        BlkResponse::Ok → exit(9) on failure.
//!
//!     6. Read — send BlkRequest::Read{lba:42, count:1, buf_iova:0},
//!        receive BlkResponse::Ok, then two 2048-byte data chunks.
//!
//!     7. Compare — byte-identical to the write pattern →
//!        "[blkcheck] readback MATCH (4096 bytes, LBA 42)".
//!        First mismatch → print differing index, exit(10).
//!
//!     8. Out-of-range negative (NCIP-014 TC4) — Read at LBA u64::MAX/2
//!        → expect BlkResponse::OutOfRange → exit(11) on anything else.
//!
//!     9. exit(0) on full success.
//! ```
//!
//! ## Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | `0`  | All tests passed; readback byte-identical |
//! | `1`  | Panic handler invoked |
//! | `2`  | (reserved) |
//! | `3`  | Negative BlkLookup did NOT return EACCES within budget |
//! | `4`  | No IpcSend capability token in the kernel deposit window |
//! | `5`  | Driver never registered (ENOENT budget exhausted) |
//! | `6`  | BlkLookup("nvme0") with token failed |
//! | `7`  | BlkLookup("nvme0-reply") with token failed |
//! | `8`  | Write command failed |
//! | `9`  | Flush command failed |
//! | `10` | Readback byte mismatch |
//! | `11` | Out-of-range Read did NOT return BlkResponse::OutOfRange |
//!
//! ## Heap note
//!
//! A 64 KiB never-freeing bump allocator backs the `alloc` crate.  This
//! is sufficient for the handful of postcard encode/decode calls this
//! client makes (`BlkRequest` variants are small; `BlkResponse` variants
//! are tiny).  The `dealloc` no-op is a documented design choice shared
//! with all other image binaries in this workspace.

#![no_std]
#![no_main]
#![allow(unsafe_code)]

extern crate alloc;

use core::panic::PanicInfo;

use nexacore_types::blk::{BlkRequest, BlkResponse};
use nexacore_types::wire::{decode_canonical, encode_canonical};

// =============================================================================
// Bump allocator (64 KiB static heap)
// =============================================================================

/// Size of the static heap backing the bump allocator (64 KiB).
///
/// Sufficient for the handful of postcard encode/decode calls this client
/// performs during its lifetime (`BlkRequest` variants ≤ ~30 B encoded;
/// `BlkResponse` variants ≤ ~5 B encoded).
const HEAP_SIZE: usize = 64 * 1024;

/// Backing storage for the bump allocator (BSS).
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// Current bump cursor (byte offset into [`HEAP`]).
///
/// Single-threaded task; no atomics required.  Accessed only through
/// `addr_of_mut!` to avoid forming references to `static mut`.
static mut HEAP_POS: usize = 0;

/// Never-freeing bump allocator.
///
/// Provides the `alloc` crate's `GlobalAlloc` contract with a static
/// arena.  `dealloc` is a deliberate no-op: this client is a one-shot
/// smoke test that exits after each test sequence; freeing allocations
/// would add complexity with no benefit.
struct BumpAllocator;

// SAFETY: single-threaded Ring 3 task; allocation is a bump on a static
// arena; `dealloc` is a documented no-op (never-freeing by design).
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
            // SAFETY: `aligned` is within [0, HEAP_SIZE) and `base` is
            // the start of the static HEAP array.
            base.add(aligned)
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Never-freeing bump allocator: dealloc is intentionally a no-op.
        // See the module-doc heap note.
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

// =============================================================================
// Syscall numbers + ABI constants (mirror nexacore_kernel::syscall)
// =============================================================================

/// `TaskExit (11)` — terminate the calling task.
const SYS_TASK_EXIT: u64 = 11;
/// `TaskYield (12)` — yield the CPU to the next runnable task.
const SYS_TASK_YIELD: u64 = 12;
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
/// `cap_len = 0` (no token) → `EACCES` if the slot is registered by
/// another task (fail-closed gate).
const SYS_BLK_LOOKUP: u64 = 78;

/// `MessageKind::Request = 1` — discriminant used for BLK request messages
/// (both the postcard-encoded `BlkRequest` header and the raw data chunks
/// per ADR-0036 D3 inline transport).
const IPC_KIND_REQUEST: u64 = 1;

/// `ENOENT (2)` — the BLK slot is not yet registered by the driver.
const ENOENT: u64 = 2;
/// `EACCES (13)` — the slot is registered but the caller lacks a valid
/// capability token (ADR-0036 D6 gate, fail-closed).
const EACCES: u64 = 13;

/// `SYSCALL_ERROR` sentinel: `u64::MAX` returned in `rax` by single-value
/// syscalls (e.g. `IpcSend`, `IpcTryReceive`) on error.
const SYSCALL_ERROR: u64 = u64::MAX;

/// Retry budget while waiting for the NVMe driver to register its BLK slot.
///
/// Each iteration issues one `BlkLookup` + one `TaskYield`.  200 000 yields
/// is generous enough to survive early-boot scheduling jitter on VM-103
/// without blocking indefinitely.
const ENOENT_RETRY_BUDGET: u32 = 200_000;

/// Poll budget for waiting on an IPC reply (Write / Flush / Read).
///
/// Each iteration issues one `IpcTryReceive` + one `TaskYield`.
const REPLY_POLL_BUDGET: u32 = 2_000_000;

/// Wire-format discriminant for the `IpcSend` action in the kernel
/// capability deposit window.
///
/// The existing deposit tags are:
///   1 = MmioMap, 2 = DmaMap, 3 = IrqAttach,
///   4 = PciConfigRead, 5 = PciConfigWrite.
///
/// `IpcSend` is the next value in the same sequence, assigned by
/// ADR-0036 D6 as the tag the kernel writes when depositing the
/// blkcheck client's channel-send capability.  `nexacore-driver-shared`
/// does not yet export this constant because only this image needs it
/// in Phase 1; it will be upstreamed with the kernel deposit encoder
/// change (TASK-14 in-flight).
const ACTION_TAG_IPC_SEND: u32 = 6;

/// The inline-chunk size for the ADR-0036 D3 inline data transport
/// (sector / 2 = 2048 bytes per chunk; two chunks per 4 KiB sector).
const CHUNK_SIZE: usize = 2048;

/// Total sector size (4 KiB) — the BLK layer block size per NCIP-014 § M4.
const SECTOR_SIZE: usize = 4096;

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
/// Pointer arguments must be valid for the duration of the call.  The
/// caller is responsible for upholding the platform ABI (no stack
/// alignment issues; no live values in `rdi..r9` past the call).
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
/// ignored — a console write failing should never abort a test sequence).
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
/// Used for printing errno values and numeric diagnostics in contexts
/// where formatting infrastructure is unavailable.
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
/// Issued through the generic 6-argument stub **on purpose**: the kernel
/// entry shuffles all argument registers and does not restore them; a
/// minimal stub that only clobbers `rcx/r11` would allow the compiler to
/// keep live values (e.g. the NEXT syscall's arguments) in registers that
/// the kernel just destroyed.  See the `syscall` function doc and
/// ADR-0035 for the hardware-observed heisenbug this prevents.
fn task_yield() {
    // SAFETY: TaskYield takes no arguments; all zeros passed for unused
    // slots.  Full clobber set is declared by the generic stub.
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

/// Send `data` on `channel_id` with message `kind`.
///
/// Returns `true` on success; `false` when the kernel returns
/// [`SYSCALL_ERROR`] (e.g. channel full under Drop policy, or bad id).
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

/// Issue `BlkLookup(78)` with the given slot name and optional capability
/// token bytes.
///
/// Returns `(channel_id, errno)`.  On success, `errno = 0` and
/// `channel_id` is the assigned kernel channel id.  On failure, `errno`
/// carries the POSIX error code (`ENOENT`, `EACCES`, …) and `channel_id`
/// is unspecified.
///
/// Pass `cap_bytes = &[]` (zero length) to exercise the no-token path
/// (ADR-0036 D6 negative test → expect `EACCES` once registered).
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
    write("[blkcheck] PANIC\n");
    exit(1)
}

// =============================================================================
// BSS buffers (NOT on the 4 KiB user stack)
// =============================================================================

/// Write pattern buffer: 4096 bytes filled with the deterministic pattern
/// `byte[i] = ((i as u8).wrapping_mul(31)).wrapping_add(7)`.
///
/// Declared as `static mut` so it lives in BSS (not the tiny Ring 3 stack).
/// Accessed only from `_start` (single-threaded), exclusively through
/// `addr_of_mut!`.
static mut WRITE_BUF: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

/// Readback buffer: receives the two 2048-byte data chunks from the
/// driver's Read reply path.  Same lifetime and access discipline as
/// [`WRITE_BUF`].
static mut READ_BUF: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

/// Receive staging buffer for IPC messages (BlkResponse + raw data chunks).
///
/// Sized to the IPC envelope maximum (4096 bytes) so it can hold any
/// single message the driver sends.
static mut RECV_BUF: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];

// =============================================================================
// ELF entry point
// =============================================================================

/// ELF entry point.  Runs the TASK-14 BLK service smoke test and exits.
///
/// See the module-level doc for the full test plan and exit-code table.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("[blkcheck] start\n");

    // ── Step 1: initialise the write pattern ────────────────────────────────
    // Fill WRITE_BUF with the position-dependent pattern
    // `byte[i] = ((i as u8).wrapping_mul(31)).wrapping_add(7)`.
    // The cast from usize to u8 is intentional: i cycles modulo 256,
    // producing a position-dependent repeating pattern.  This must happen
    // before any postcard allocation so the bump cursor stays low for the
    // encode/decode calls.
    //
    // SAFETY: single-threaded; WRITE_BUF is only written here and only
    // read during the compare step; addr_of_mut! avoids a reference to
    // static mut.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "i truncated to u8 intentionally: position-dependent pattern, wrapping by design"
    )]
    unsafe {
        let buf: *mut [u8; SECTOR_SIZE] = core::ptr::addr_of_mut!(WRITE_BUF);
        let mut i: usize = 0;
        while i < SECTOR_SIZE {
            (*buf)[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
            i += 1;
        }
    }

    // ── Step 2: NEGATIVE TEST — BlkLookup without a capability token ────────
    //
    // Poll until either:
    //   - ENOENT (slot not yet registered)  → yield and retry
    //   - EACCES (slot registered, gate OK) → the negative test PASSES
    //   - Any other outcome                 → unexpected; exit(3)
    //
    // If the budget is exhausted without EACCES → the driver never
    // registered → exit(5).
    let mut enoent_count: u32 = 0;
    loop {
        let (_ch, errno) = sys_blk_lookup(b"nvme0", &[]);
        if errno == ENOENT {
            enoent_count = enoent_count.saturating_add(1);
            if enoent_count >= ENOENT_RETRY_BUDGET {
                write("[blkcheck] driver never registered\n");
                exit(5);
            }
            task_yield();
            continue;
        }
        if errno == EACCES {
            write("[blkcheck] no-cap lookup rejected (EACCES) OK\n");
            break;
        }
        // Unexpected errno on the negative path.
        write("[blkcheck] negative BlkLookup unexpected errno=");
        write_hex(errno);
        write("\n");
        exit(3);
    }

    write("[blkcheck] enoent_yields=");
    write_hex(u64::from(enoent_count));
    write("\n");

    // ── Step 3: Read deposited capability token ──────────────────────────────
    //
    // The kernel deposited an attenuated `CapabilityToken` with action
    // `IpcSend` in the deposit window at 0x0010_0000 (DRIVER_CAP_DEPOSIT_VA)
    // under deposit tag ACTION_TAG_IPC_SEND (= 6, ADR-0036 D6).
    //
    // SAFETY: `find_token` reads the kernel-mapped read-only deposit
    // window.  We are running inside a correctly launched NexaCore OS process
    // whose kernel guaranteed the window was mapped before transferring
    // execution to `_start` (NCIP-013 § S5.3 step 8 / ADR-0036 D1 boot-spawn
    // pattern).  The function itself performs the unsafe VA read internally
    // and is a safe public API once the caller satisfies the contract above.
    let cap_bytes: &[u8] = match nexacore_driver_shared::caps::find_token(
        ACTION_TAG_IPC_SEND,
        |_| true, // accept the first IpcSend token — this client expects exactly one
    ) {
        Some(b) => b,
        None => {
            write("[blkcheck] no client token in deposit window\n");
            exit(4);
        }
    };

    // ── Step 4: POSITIVE BlkLookup with the deposited token ─────────────────
    let (req_channel, req_errno) = sys_blk_lookup(b"nvme0", cap_bytes);
    if req_errno != 0 {
        write("[blkcheck] BlkLookup(nvme0) FAILED errno=");
        write_hex(req_errno);
        write("\n");
        exit(6);
    }
    write("[blkcheck] req_channel=");
    write_hex(req_channel);
    write("\n");

    let (reply_channel, reply_errno) = sys_blk_lookup(b"nvme0-reply", cap_bytes);
    if reply_errno != 0 {
        write("[blkcheck] BlkLookup(nvme0-reply) FAILED errno=");
        write_hex(reply_errno);
        write("\n");
        exit(7);
    }
    write("[blkcheck] reply_channel=");
    write_hex(reply_channel);
    write("\n");

    // ── Step 5: WRITE — LBA 42, 1 sector (4096 bytes), inline chunks ────────
    //
    // Per ADR-0036 D3 inline transport:
    //   Message 1: postcard-encoded BlkRequest::Write{lba:42, count:1,
    //               buf_iova:0} on req_channel (KIND_REQUEST)
    //   Message 2: first 2048-byte chunk of write data (KIND_REQUEST)
    //   Message 3: second 2048-byte chunk of write data (KIND_REQUEST)

    let write_req = BlkRequest::Write {
        lba: 42,
        count: 1,
        buf_iova: 0,
    };
    let encoded_write_req = match encode_canonical(&write_req) {
        Ok(b) => b,
        Err(_) => {
            write("[blkcheck] write request encode FAILED\n");
            exit(8);
        }
    };
    if !sys_ipc_send(req_channel, IPC_KIND_REQUEST, &encoded_write_req) {
        write("[blkcheck] write request IpcSend FAILED\n");
        exit(8);
    }

    // Send 2 data chunks (2048 bytes each) containing the write pattern.
    // SAFETY: WRITE_BUF is a static BSS buffer; the pointer is valid for
    // the lifetime of this call.  We read it immutably here; the mutable
    // initialisation above has already completed.
    let write_buf_ref: &[u8; SECTOR_SIZE] = unsafe { &*core::ptr::addr_of!(WRITE_BUF) };

    if !sys_ipc_send(req_channel, IPC_KIND_REQUEST, &write_buf_ref[..CHUNK_SIZE]) {
        write("[blkcheck] write chunk-0 IpcSend FAILED\n");
        exit(8);
    }
    if !sys_ipc_send(req_channel, IPC_KIND_REQUEST, &write_buf_ref[CHUNK_SIZE..]) {
        write("[blkcheck] write chunk-1 IpcSend FAILED\n");
        exit(8);
    }

    // Poll the reply channel for BlkResponse.
    // SAFETY: RECV_BUF is a static BSS buffer used only here.
    let recv_buf: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };

    let write_resp = poll_for_response(reply_channel, recv_buf, 8);
    match write_resp {
        BlkResponse::Ok => {
            write("[blkcheck] write LBA42 OK\n");
        }
        _ => {
            write("[blkcheck] write LBA42 unexpected response\n");
            exit(8);
        }
    }

    // ── Step 6: FLUSH ────────────────────────────────────────────────────────
    let encoded_flush = match encode_canonical(&BlkRequest::Flush) {
        Ok(b) => b,
        Err(_) => {
            write("[blkcheck] flush encode FAILED\n");
            exit(9);
        }
    };
    if !sys_ipc_send(req_channel, IPC_KIND_REQUEST, &encoded_flush) {
        write("[blkcheck] flush IpcSend FAILED\n");
        exit(9);
    }

    // SAFETY: same as the write recv above.
    let recv_buf2: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };
    let flush_resp = poll_for_response(reply_channel, recv_buf2, 9);
    match flush_resp {
        BlkResponse::Ok => {
            write("[blkcheck] flush OK\n");
        }
        _ => {
            write("[blkcheck] flush unexpected response\n");
            exit(9);
        }
    }

    // ── Step 7: READ — LBA 42, 1 sector (4096 bytes), inline chunks ─────────
    //
    // Per ADR-0036 D3:
    //   Send:    postcard-encoded BlkRequest::Read{lba:42, count:1, buf_iova:0}
    //   Receive: [BlkResponse (postcard)] then [chunk-0 (2048 B)] then [chunk-1 (2048 B)]
    //
    // Message ordering on the reply channel is deterministic (FIFO queue).
    let read_req = BlkRequest::Read {
        lba: 42,
        count: 1,
        buf_iova: 0,
    };
    let encoded_read_req = match encode_canonical(&read_req) {
        Ok(b) => b,
        Err(_) => {
            write("[blkcheck] read request encode FAILED\n");
            exit(10);
        }
    };
    if !sys_ipc_send(req_channel, IPC_KIND_REQUEST, &encoded_read_req) {
        write("[blkcheck] read request IpcSend FAILED\n");
        exit(10);
    }

    // Receive the BlkResponse (first message on reply_channel).
    // SAFETY: same RECV_BUF access pattern.
    let recv_buf3: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };
    let read_resp = poll_for_response(reply_channel, recv_buf3, 10);
    match read_resp {
        BlkResponse::Ok => {}
        _ => {
            write("[blkcheck] read LBA42 response not Ok\n");
            exit(10);
        }
    }

    // Receive data chunks into READ_BUF.
    // SAFETY: READ_BUF is a static BSS buffer accessed only here.
    let read_buf: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(READ_BUF) };

    // Chunk 0
    let chunk0_n = poll_for_raw_chunk(reply_channel, &mut read_buf[..CHUNK_SIZE], 10);
    if chunk0_n != CHUNK_SIZE {
        write("[blkcheck] read chunk-0 wrong size=");
        write_hex(chunk0_n as u64);
        write("\n");
        exit(10);
    }

    // Chunk 1
    let chunk1_n = poll_for_raw_chunk(reply_channel, &mut read_buf[CHUNK_SIZE..], 10);
    if chunk1_n != CHUNK_SIZE {
        write("[blkcheck] read chunk-1 wrong size=");
        write_hex(chunk1_n as u64);
        write("\n");
        exit(10);
    }

    // ── Step 8: COMPARE ──────────────────────────────────────────────────────
    // SAFETY: both buffers are static BSS; we hold the only references here.
    let write_buf_cmp: &[u8; SECTOR_SIZE] = unsafe { &*core::ptr::addr_of!(WRITE_BUF) };
    let read_buf_cmp: &[u8; SECTOR_SIZE] = unsafe { &*core::ptr::addr_of!(READ_BUF) };

    let mut i: usize = 0;
    while i < SECTOR_SIZE {
        if write_buf_cmp[i] != read_buf_cmp[i] {
            write("[blkcheck] readback MISMATCH at index=");
            write_hex(i as u64);
            write(" expected=");
            write_hex(u64::from(write_buf_cmp[i]));
            write(" got=");
            write_hex(u64::from(read_buf_cmp[i]));
            write("\n");
            exit(10);
        }
        i += 1;
    }
    write("[blkcheck] readback MATCH (4096 bytes, LBA 42)\n");

    // ── Step 9: OUT-OF-RANGE NEGATIVE (NCIP-014 TC4) ──────────────────────────
    //
    // Read at an LBA that is guaranteed to be out of range for any device
    // that fits within a 64-bit address space.  The driver MUST reply with
    // `BlkResponse::OutOfRange`.
    let oor_lba: u64 = u64::MAX / 2;
    let oor_req = BlkRequest::Read {
        lba: oor_lba,
        count: 1,
        buf_iova: 0,
    };
    let encoded_oor = match encode_canonical(&oor_req) {
        Ok(b) => b,
        Err(_) => {
            write("[blkcheck] OOR read encode FAILED\n");
            exit(11);
        }
    };
    if !sys_ipc_send(req_channel, IPC_KIND_REQUEST, &encoded_oor) {
        write("[blkcheck] OOR read IpcSend FAILED\n");
        exit(11);
    }

    // SAFETY: same RECV_BUF pattern.
    let recv_buf4: &mut [u8; SECTOR_SIZE] = unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };
    let oor_resp = poll_for_response(reply_channel, recv_buf4, 11);
    match oor_resp {
        BlkResponse::OutOfRange => {
            write("[blkcheck] out-of-range rejected OK\n");
        }
        _ => {
            write("[blkcheck] OOR test unexpected response\n");
            exit(11);
        }
    }

    write(
        "[blkcheck] TASK-14 E2E COMPLETE: BlkLookup(cap) -> Write -> Flush -> Read -> byte-identical\n",
    );
    write("[blkcheck] done\n");
    exit(0)
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Poll `reply_channel` with bounded retries until a message arrives, then
/// postcard-decode it as a [`BlkResponse`].
///
/// On decode failure or budget exhaustion the function prints a diagnostic
/// and calls `exit(fail_code)` — it never returns `None` to avoid
/// propagating an error type through the no-heap-no-Result entry path.
///
/// `recv_buf` must be at least [`SECTOR_SIZE`] bytes; the first `n` bytes
/// of `recv_buf` are populated by the kernel and then passed to
/// `decode_canonical`.
///
/// # Safety of callers
///
/// Callers must supply a `recv_buf` derived from a `static mut` BSS array
/// via `addr_of_mut!` — not a stack allocation — because the kernel writes
/// directly into the slice.
fn poll_for_response(
    reply_channel: u64,
    recv_buf: &mut [u8; SECTOR_SIZE],
    fail_code: u32,
) -> BlkResponse {
    let mut attempts: u32 = 0;
    loop {
        let n = sys_ipc_try_receive(reply_channel, recv_buf);
        if let Some(n) = n {
            let bytes = &recv_buf[..n];
            match decode_canonical::<BlkResponse>(bytes) {
                Ok(resp) => return resp,
                Err(_) => {
                    write("[blkcheck] BlkResponse decode FAILED\n");
                    exit(fail_code);
                }
            }
        }
        attempts = attempts.saturating_add(1);
        if attempts >= REPLY_POLL_BUDGET {
            write("[blkcheck] reply poll budget exhausted\n");
            exit(fail_code);
        }
        task_yield();
    }
}

/// Poll `reply_channel` for a raw data chunk (non-postcard bytes), copying
/// up to `buf.len()` bytes into `buf`.
///
/// Returns the number of bytes received.  On budget exhaustion the function
/// calls `exit(fail_code)`.
///
/// Used for the inline data transport chunks (ADR-0036 D3): the driver sends
/// raw sector data after the `BlkResponse::Ok` confirmation; each chunk is
/// NOT postcard-wrapped, it is a plain byte slice of [`CHUNK_SIZE`] bytes.
fn poll_for_raw_chunk(reply_channel: u64, buf: &mut [u8], fail_code: u32) -> usize {
    let mut attempts: u32 = 0;
    loop {
        let n = sys_ipc_try_receive(reply_channel, buf);
        if let Some(n) = n {
            return n;
        }
        attempts = attempts.saturating_add(1);
        if attempts >= REPLY_POLL_BUDGET {
            write("[blkcheck] chunk poll budget exhausted\n");
            exit(fail_code);
        }
        task_yield();
    }
}
