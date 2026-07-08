//! Bare-metal AI syscall self-test client for NexaCore OS (TASK-11 transport,
//! TASK-13 M1 dual-backend smoke).
//!
//! A `no_std + no_main` Ring 3 ELF the kernel spawns to validate the AI
//! syscall path end to end (DE-G6/DE-G9, ADR-0032, ADR-0034, ADR-0035):
//!
//! 1. **Positive (M1):** `AiInvoke (80)` with the real prompt
//!    `"what is 2+2?"` → the kernel relay carries it over the
//!    `"ai"`/`"ai_reply"` IPC rendezvous to the nexacore-runtime service
//!    image, whose on-device backend router serves it via Ollama
//!    (`backend_used=RemoteGpu`) or — when the GPU is unreachable — via
//!    the embedded REAL CPU engine (`backend_used=LocalCpu`).  The
//!    client asserts TRANSPORT success only (errno 0, non-empty answer)
//!    and prints the answer; WHICH backend served is proven by the
//!    service's serial audit line (`[ai-svc] rid=.. backend_used=..`),
//!    captured verbatim by the M1 smoke for both scenarios (ADR-0035
//!    D6 — scenario A's LLM text is non-deterministic, so no literal
//!    golden here; the engine golden `"ab"`→`"dddd"` stays pinned by
//!    the host suite).
//! 2. **Negative (WI-4b on hardware):** `AiInvoke` with an invalid input
//!    pointer must return `EFAULT` — the uaccess probe rejects it; the
//!    kernel must NOT page-fault (`Page Fault = 0` on the serial).
//! 3. **Negative:** `AiInvoke` with an output capacity of 0 bytes must
//!    return `ENOSPC` (any non-empty response exceeds the buffer).
//! 4. **Positive (WS5-03.9):** `AiEmbed (82)` returns a dense vector
//!    (postcard `Vec<f32>`) and is STABLE — two identical calls produce
//!    byte-identical payloads (the VM-103 ".11 embedding stabile" smoke,
//!    end to end through the relay and the runtime engine's embed arm).
//!
//! ## Exit codes
//!
//! `0` success · `1` panic · `2` AiInvoke failed · `3` EFAULT negative
//! test failed · `4` ENOSPC negative test failed · `5` service never
//! registered (ENOENT budget exhausted) · `6` response mismatch ·
//! `7` AiEmbed failed / not stable.
//!
//! No dependencies, no heap; BSS buffers (not the 4 KiB user stack).

#![no_std]
#![no_main]
#![allow(unsafe_code)]

use core::panic::PanicInfo;

// =============================================================================
// Syscall numbers + errnos (mirror nexacore_kernel::syscall)
// =============================================================================

/// `TaskExit (11)` — terminate the calling task.
const SYS_TASK_EXIT: u64 = 11;
/// `TaskYield (12)` — yield the CPU to the next runnable task.
const SYS_TASK_YIELD: u64 = 12;
/// `WriteConsole (60)` — write a byte slice to the kernel console (COM1).
const SYS_WRITE_CONSOLE: u64 = 60;
/// `AiInvoke (80)` — single-turn inference. ABI
/// `(model_id_ptr, model_id_len=16, input_ptr, input_len, output_ptr,
/// output_cap) -> (rax=output_len, rdx=errno)`.
const SYS_AI_INVOKE: u64 = 80;
/// `AiEmbed (82)` — dense embedding; the reply payload is a postcard
/// `Vec<f32>`. Same buffer ABI as `AiInvoke`.
const SYS_AI_EMBED: u64 = 82;

/// `ENOENT (2)` — the runtime service has not registered `"ai"` yet.
const ENOENT: u64 = 2;
/// `EFAULT (14)` — invalid user pointer (uaccess probe rejection).
const EFAULT: u64 = 14;
/// `ENOSPC (28)` — response exceeds the caller's output capacity.
const ENOSPC: u64 = 28;

/// Bounded retry budget while waiting for the service to register
/// (one AiInvoke + one TaskYield per attempt).
const ENOENT_RETRY_BUDGET: u32 = 50_000;

// =============================================================================
// Syscall stubs (System V AMD64 ABI — same clobber set as netcheck)
// =============================================================================

/// Issue a two-register-return syscall.
///
/// # Safety
///
/// Pointer arguments must be valid for the duration of the call.
#[inline(always)]
unsafe fn syscall(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> (u64, u64) {
    let rax: u64;
    let rdx: u64;
    // SAFETY: canonical Ring 3 → Ring 0 transition; caller upholds pointer
    // validity; argument registers marked clobbered (kernel entry shuffles
    // them and does not restore).
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

/// Write `msg` to the kernel console (best-effort).
fn write(msg: &str) {
    write_bytes(msg.as_bytes());
}

/// Write a raw byte slice to the kernel console (best-effort).
fn write_bytes(b: &[u8]) {
    // SAFETY: b is valid for the duration of the syscall.
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

/// Write `val` as a fixed 16-digit hex string (`0x…`) to the console.
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

/// Yield the CPU so the service can register / serve.
fn task_yield() {
    // SAFETY: TaskYield takes no arguments. Issued through the generic
    // 6-argument stub ON PURPOSE: the kernel syscall entry SHUFFLES the
    // argument registers (rdi/rsi/rdx/r10/r8/r9) and returns a value pair
    // in rax/rdx WITHOUT restoring any of them, so a minimal `asm!` that
    // clobbers only rcx/r11 lets the compiler keep live values (e.g. the
    // NEXT syscall's arguments) in registers the kernel destroys.
    // Hardware-observed as a boot-timing heisenbug (TASK-13: corrupted
    // input_len -> spurious EINVAL after one ENOENT retry); the generic
    // stub declares the full clobber set.
    let _ = unsafe { syscall(SYS_TASK_YIELD, 0, 0, 0, 0, 0, 0) };
}

/// Terminate with exit `code`. Never returns.
fn exit(code: u32) -> ! {
    // SAFETY: TaskExit terminates the task and never returns.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") u64::from(code),
            options(noreturn),
        );
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    write("[aicheck] PANIC\n");
    exit(1)
}

// =============================================================================
// Entry point
// =============================================================================

/// Compact 16-byte model id (the ABI's mandatory `model_id_len = 16`).
/// The service router does not interpret it; any value proves marshalling.
static MODEL_ID: [u8; 16] = *b"gemma4-m1-000001";

/// The M1 smoke prompt — a real question (PLAN.md TASK-13 acceptance).
static PROMPT: &[u8] = b"what is 2+2?";

/// Output buffer capacity (well above the expected response).
const OUT_CAP: usize = 4096;

/// Response buffer — BSS, not the 4 KiB user stack.
static mut OUT: [u8; OUT_CAP] = [0; OUT_CAP];

/// Second response buffer for the embed stability check (compare two
/// independent AiEmbed replies byte-for-byte). BSS, not the user stack.
static mut OUT2: [u8; OUT_CAP] = [0; OUT_CAP];

/// A canonical non-mapped user address for the EFAULT negative test
/// (user half, far from any mapping the loader creates).
const BAD_USER_PTR: u64 = 0x0000_7FFF_DEAD_0000;

/// ELF entry point. Runs the TASK-11 AI syscall self-test and exits.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("[aicheck] start\n");

    // ── 1. Positive: AiInvoke with a bounded ENOENT retry budget (the
    //       System-priority service registers its channels first, but
    //       spawn ordering must not be load-bearing). ──
    let mut attempts: u32 = 0;
    let (out_len, errno) = loop {
        // SAFETY: MODEL_ID/PROMPT are static buffers; OUT is a static BSS
        // buffer; all valid for the syscall duration.
        let (rax, rdx) = unsafe {
            syscall(
                SYS_AI_INVOKE,
                MODEL_ID.as_ptr() as u64,
                MODEL_ID.len() as u64,
                PROMPT.as_ptr() as u64,
                PROMPT.len() as u64,
                core::ptr::addr_of_mut!(OUT) as u64,
                OUT_CAP as u64,
            )
        };
        if rdx == ENOENT {
            attempts += 1;
            if attempts >= ENOENT_RETRY_BUDGET {
                write("[aicheck] service never registered (ENOENT budget)\n");
                exit(5);
            }
            task_yield();
            continue;
        }
        break (rax, rdx);
    };

    write("[aicheck] enoent_retries=");
    write_hex(u64::from(attempts));
    write("\n");
    if errno != 0 {
        write("[aicheck] AiInvoke FAILED, errno=");
        write_hex(errno);
        write("\n");
        exit(2);
    }
    write("[aicheck] AiInvoke OK, output_len=");
    write_hex(out_len);
    write("\n");

    // Print and verify the response payload.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "kernel bounds output_len to OUT_CAP = 4096"
    )]
    let n = (out_len as usize).min(OUT_CAP);
    // SAFETY: single-threaded task; n ≤ OUT_CAP; build the slice directly
    // from the raw pointer (no intermediate `&array` autoref).
    let response = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(OUT).cast::<u8>(), n) };
    write("[aicheck] answer=");
    write_bytes(response);
    write("\n");
    if response.is_empty() {
        write("[aicheck] EMPTY answer (transport ok but no content)\n");
        exit(6);
    }
    write("[aicheck] M1 OK: real answer received from the backend router\n");

    // ── 2. Negative (WI-4b): invalid input pointer → EFAULT, no kernel
    //       #PF (the boot summary's `Page Fault` counter must stay 0). ──
    // SAFETY: BAD_USER_PTR is deliberately unmapped — the uaccess probe
    // must reject it BEFORE any dereference; no kernel memory is touched.
    let (_r, efault_errno) = unsafe {
        syscall(
            SYS_AI_INVOKE,
            MODEL_ID.as_ptr() as u64,
            MODEL_ID.len() as u64,
            BAD_USER_PTR,
            PROMPT.len() as u64,
            core::ptr::addr_of_mut!(OUT) as u64,
            OUT_CAP as u64,
        )
    };
    if efault_errno == EFAULT {
        write("[aicheck] EFAULT negative test OK (bad pointer rejected, no #PF)\n");
    } else {
        write("[aicheck] EFAULT negative test FAILED, errno=");
        write_hex(efault_errno);
        write("\n");
        exit(3);
    }

    // ── 3. Negative: output capacity 0 bytes → ENOSPC (ANY non-empty
    //       response exceeds it; nothing is written). Capacity 0 (not 1)
    //       because the M1 answer is model-generated — gemma4 answers
    //       "what is 2+2?" with a single byte ("4"), which FITS in 1. ──
    // SAFETY: as the positive call; output capacity deliberately zero.
    let (_r2, enospc_errno) = unsafe {
        syscall(
            SYS_AI_INVOKE,
            MODEL_ID.as_ptr() as u64,
            MODEL_ID.len() as u64,
            PROMPT.as_ptr() as u64,
            PROMPT.len() as u64,
            core::ptr::addr_of_mut!(OUT) as u64,
            0,
        )
    };
    if enospc_errno == ENOSPC {
        write("[aicheck] ENOSPC negative test OK (tiny output buffer rejected)\n");
    } else {
        write("[aicheck] ENOSPC negative test FAILED, errno=");
        write_hex(enospc_errno);
        write("\n");
        exit(4);
    }

    // ── 4. Positive: AiEmbed (82) — the embedding path returns a dense
    //       vector, and it is STABLE: two identical calls produce
    //       byte-identical postcard `Vec<f32>` payloads (WS5-03.9; the
    //       VM-103 ".11 embedding stabile" smoke, end to end through the
    //       kernel relay and the runtime service's embed arm). ──
    let (e_len1, e_errno1) = unsafe {
        syscall(
            SYS_AI_EMBED,
            MODEL_ID.as_ptr() as u64,
            MODEL_ID.len() as u64,
            PROMPT.as_ptr() as u64,
            PROMPT.len() as u64,
            core::ptr::addr_of_mut!(OUT) as u64,
            OUT_CAP as u64,
        )
    };
    if e_errno1 != 0 {
        write("[aicheck] AiEmbed FAILED, errno=");
        write_hex(e_errno1);
        write("\n");
        exit(7);
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "kernel bounds output_len to OUT_CAP = 4096"
    )]
    let en1 = (e_len1 as usize).min(OUT_CAP);
    if en1 == 0 {
        write("[aicheck] AiEmbed EMPTY vector (transport ok but no content)\n");
        exit(7);
    }
    write("[aicheck] AiEmbed OK, vec_bytes=");
    write_hex(e_len1);
    write("\n");

    // Second call — must be deterministic.
    let (e_len2, e_errno2) = unsafe {
        syscall(
            SYS_AI_EMBED,
            MODEL_ID.as_ptr() as u64,
            MODEL_ID.len() as u64,
            PROMPT.as_ptr() as u64,
            PROMPT.len() as u64,
            core::ptr::addr_of_mut!(OUT2) as u64,
            OUT_CAP as u64,
        )
    };
    #[allow(
        clippy::cast_possible_truncation,
        reason = "kernel bounds output_len to OUT_CAP = 4096"
    )]
    let en2 = (e_len2 as usize).min(OUT_CAP);
    // SAFETY: single-threaded task; en1, en2 ≤ OUT_CAP; the buffers are
    // initialized BSS and stay valid for the comparison. Build the slices
    // directly from the raw pointers (no intermediate `&array` autoref).
    let first = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(OUT).cast::<u8>(), en1) };
    let second =
        unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(OUT2).cast::<u8>(), en2) };
    if e_errno2 != 0 || en2 != en1 || first != second {
        write("[aicheck] AiEmbed NOT STABLE (errno/len/bytes differ across calls)\n");
        exit(7);
    }
    write("[aicheck] AiEmbed STABLE: two calls byte-identical (deterministic embedding)\n");

    write(
        "[aicheck] TASK-13 M1 E2E COMPLETE: prompt -> AI syscall -> IPC relay -> backend router -> answer\n",
    );
    write(
        "[aicheck] WS5-03 embed E2E COMPLETE: ai_embed -> relay -> runtime engine -> stable Vec<f32>\n",
    );
    write("[aicheck] done\n");
    exit(0)
}
