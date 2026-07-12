//! Bare-metal AI runtime service endpoint for NexaCore OS (TASK-11 transport,
//! TASK-13-pre real engine — DE-G6 / ADR-0032 / ADR-0034).
//!
//! A `no_std + no_main` Ring 3 ELF the kernel spawns as the userspace
//! counterpart of the AI syscall relay (`ai_handlers::ai_relay`,
//! ADR-0032). Startup sequence:
//!
//! ```text
//! _start()
//!     initialise the bump allocator (512 KiB static heap)
//!     build the REAL CPU engine (CpuEngine::from_gguf on the embedded
//!         Q8_0 fixture model — GGUF parse, dequant, weight mapping)
//!     IpcCreateChannel  -> ai_channel        (requests:  kernel -> service)
//!     IpcCreateChannel  -> ai_reply_channel  (replies:   service -> kernel)
//!     NetRegister("ai",       ai_channel)
//!     NetRegister("ai_reply", ai_reply_channel)
//!     loop forever:
//!         IpcTryReceive(ai_channel) -> AiSyscallRequest (postcard)
//!             -> serve: on-device backend router (TASK-13, ADR-0035 D4)
//!                  RemoteGpu: Ollama POST /api/generate over the NET
//!                             syscalls (mod remote)
//!                  LocalCpu:  embedded fixture engine on ANY remote
//!                             failure (BPE encode -> sync forward ->
//!                             greedy argmax -> BPE decode)
//!                  serial audit: "[ai-svc] rid=.. backend_used=.."
//!             -> AiSyscallResponse
//!             -> IpcSend(ai_reply_channel, Reply)
//!         else TaskYield
//! ```
//!
//! ## The REAL engine in Ring 3 (TASK-13-pre)
//!
//! The TASK-11 image shipped a labelled MOCK because the Sprint 7/8 engine
//! was std/tokio-bound. The `no_std` port (ADR-0034) made the whole chain
//! — `nexacore_runtime::{gguf, tensor_loader, bpe, engine}` over
//! `nexacore_hal::transformer_forward_sync` — build for `x86_64-unknown-none`,
//! so this image now serves `AiInvoke` with the SAME audited engine body
//! the host golden tests pin (operator decision: M1 closes with the real
//! engine, no mock-labelled fallback):
//!
//! - `Invoke` / `Stream` → greedy generation on the embedded fixture
//!   model (`"ab"` → `"dddd"` with the 4-token golden budget);
//! - `Embed`             → mean-pooled, L2-normalized hidden state of the
//!   fixture engine (WS5-03.5/.9); the reply is the postcard `Vec<f32>` the
//!   userspace `ai_embed` wrapper decodes;
//! - `Classify` / `Transcribe` → structured "not yet supported" error.
//!
//! The session-capability gating contract is enforced here exactly as the
//! host engine enforces it (`SessionCapability` well-formedness: length in
//! `[1, 4096]`, first byte non-zero), so a caller without a capability
//! gets the same rejection on hardware as in the host tests.
//!
//! ## Heap caveat (known, shared with every image binary)
//!
//! The bump allocator never frees; engine construction (~10 KiB) plus
//! per-request forward-pass allocations (~15 KiB per 4-token generation on
//! the fixture) consume heap monotonically. 512 KiB serves the M1 smoke
//! comfortably (tens of requests); the freeing-allocator work is
//! NCIP-026 WI-9 / M1 follow-up.

#![no_std]
#![no_main]
#![allow(unsafe_code)]

extern crate alloc;

/// Remote (Ollama) backend over the NET syscalls — TASK-13 / ADR-0035 D4.
mod remote;

use alloc::string::String;
use core::panic::PanicInfo;

use nexacore_runtime::{embed::Pooling, engine::CpuEngine, fixture};
use nexacore_types::ai::{
    AI_MAX_PAYLOAD, AiSyscallNumber, AiSyscallRequest, AiSyscallResponse, BackendKind,
    BackendStatusEvent,
};

// =============================================================================
// Bump allocator (512 KiB static heap)
// =============================================================================

/// Size of the static heap backing the bump allocator (512 KiB).
///
/// Doubled from the TASK-11 mock's 256 KiB: the real engine adds one-time
/// construction allocations (GGUF bytes + dequantised F32 weights, ~10 KiB)
/// and ~15 KiB of never-freed forward-pass temporaries per 4-token request
/// (see the module-doc heap caveat).
const HEAP_SIZE: usize = 512 * 1024;

/// Backing storage for the bump allocator (BSS).
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// Current bump cursor (offset into [`HEAP`]). Single-threaded task — no
/// atomicity required, but a `static mut` needs `addr_of_mut!` access.
static mut HEAP_POS: usize = 0;

/// Never-freeing bump allocator (same approach as the other image
/// binaries; see the module doc for the heap caveat).
struct BumpAllocator;

// SAFETY: single-threaded Ring 3 task; allocation is a bump on a static
// arena; `dealloc` is a documented no-op (never-freeing by design).
unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let align = layout.align().max(1);
        // SAFETY: single-threaded; HEAP_POS only mutated here.
        unsafe {
            let pos = *core::ptr::addr_of!(HEAP_POS);
            let base = core::ptr::addr_of_mut!(HEAP).cast::<u8>();
            let aligned = (pos + align - 1) & !(align - 1);
            let end = aligned.saturating_add(layout.size());
            if end > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            *core::ptr::addr_of_mut!(HEAP_POS) = end;
            base.add(aligned)
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Never-freeing bump allocator (module-doc caveat).
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
/// `IpcCreateChannel (20)` — create an anonymous IPC channel.
const SYS_IPC_CREATE_CHANNEL: u64 = 20;
/// `IpcSend (22)` — send a message on a channel.
const SYS_IPC_SEND: u64 = 22;
/// `IpcTryReceive (24)` — non-blocking receive.
const SYS_IPC_TRY_RECEIVE: u64 = 24;
/// `WriteConsole (60)` — write bytes to the kernel console (COM1).
const SYS_WRITE_CONSOLE: u64 = 60;
/// `NetRegister (100)` — bind a channel pair to an interface name.
const SYS_NET_REGISTER: u64 = 100;
/// `NetLookup (102)` — resolve a named channel registered via `NetRegister`.
/// Returns the channel id in `rax` and `errno` in `rdx`; `errno == 0`
/// means success. Used to find the `ncfs` / `ncfs-reply` channels
/// (TASK-23, ADR-0045 D5).
const SYS_NET_LOOKUP: u64 = 102;

/// Backpressure policy `Block` (0) for `IpcCreateChannel`.
const IPC_BACKPRESSURE_BLOCK: u64 = 0;
/// TEE binding off (0) for `IpcCreateChannel`.
const IPC_TEE_BOUND_OFF: u64 = 0;
/// `MessageKind::Request = 1` — used when sending an `FsRequest` to the
/// FS service over its registered channel.
const IPC_KIND_REQUEST: u64 = 1;
/// `MessageKind::Reply = 2` — the kernel relay's blocking receive on
/// `"ai_reply"` is reply-only, so responses MUST carry this kind.
const IPC_KIND_REPLY: u64 = 2;
/// `MessageKind::Notification = 3` — used for the `ai_status` channel;
/// status events are not replies to a specific request.
const IPC_KIND_NOTIFICATION: u64 = 3;
/// `SYSCALL_ERROR` sentinel returned in `rax` by single-register syscalls.
const SYSCALL_ERROR: u64 = u64::MAX;

/// Request-channel queue depth. The kernel relay serialises callers (one
/// blocking rendezvous at a time), so a small queue is ample.
const QUEUE_DEPTH: u64 = 16;

/// Number of idle loop iterations (each ending in a `TaskYield`) between
/// consecutive Ollama reachability probes.
///
/// The cooperative serve loop yields once per empty `IpcTryReceive`.  Each
/// `TaskYield` takes on the order of a scheduler quantum (~1–5 ms on the
/// NexaCore scheduler as measured in TASK-06).  Probing every 500 idle ticks
/// therefore fires roughly every 0.5–2.5 s when the AI channel is quiet,
/// which satisfies the "a few seconds" cadence required by ADR-0043 D2.
/// Under load (requests arriving every tick) the idle counter advances
/// slowly, so the probe runs less frequently — this is intentional; when
/// requests are flowing the `serve()` call already exercises the remote
/// path and the status bar is implicitly current.
///
/// NOTE (TASK-24, 2026-06-08): each probe opens a fresh TCP connection to
/// Ollama. The `nexacore-net` TCP service does NOT yet reclaim CLOSED connection
/// state (a tracked nexacore-net follow-up), so a high probe rate piles up
/// connection blocks and OOM-kills `nexacore-net` after a few dozen probes. Until
/// nexacore-net prunes closed connections, this interval is kept large so a normal
/// interactive session never accumulates enough probe connections to exhaust
/// nexacore-net's heap. The badge therefore refreshes on the order of tens of
/// seconds rather than ~1 s — acceptable for a status indicator.
const PROBE_IDLE_INTERVAL: u32 = 4_000_000;

// =============================================================================
// Syscall stubs (System V AMD64 ABI)
// =============================================================================

/// Issue a two-register-return syscall (see nexacore-net-image for the
/// clobber rationale: the kernel entry shuffles the argument registers
/// and does not restore them).
///
/// # Safety
///
/// Pointer arguments must be valid for the duration of the call.
#[inline(always)]
pub(crate) unsafe fn syscall2(
    number: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> (u64, u64) {
    let rax: u64;
    let rdx: u64;
    // SAFETY: canonical Ring 3 → Ring 0 transition; caller upholds
    // pointer validity; argument registers marked clobbered.
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
pub(crate) fn write(msg: &str) {
    let b = msg.as_bytes();
    // SAFETY: b is valid for the duration of the syscall.
    let _ = unsafe {
        syscall2(
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

/// Yield the CPU.
pub(crate) fn task_yield() {
    // SAFETY: TaskYield takes no arguments. Issued through the generic
    // 6-argument stub ON PURPOSE: the kernel syscall entry SHUFFLES the
    // argument registers (rdi/rsi/rdx/r10/r8/r9) and returns a value pair
    // in rax/rdx WITHOUT restoring any of them, so a minimal `asm!` that
    // clobbers only rcx/r11 lets the compiler keep live values (e.g. the
    // NEXT syscall's arguments) in registers the kernel destroys.
    // Hardware-observed as a boot-timing heisenbug (TASK-13: corrupted
    // input_len -> spurious EINVAL after one ENOENT retry); the generic
    // stub declares the full clobber set.
    let _ = unsafe { syscall2(SYS_TASK_YIELD, 0, 0, 0, 0, 0, 0) };
}

/// Terminate with exit `code`. Never returns.
fn sys_exit(code: u32) -> ! {
    // SAFETY: TaskExit terminates the task.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") u64::from(code),
            options(noreturn),
        );
    }
}

/// Create an anonymous IPC channel; returns the id or [`SYSCALL_ERROR`].
fn sys_ipc_create_channel(queue_depth: u64) -> u64 {
    // SAFETY: scalar arguments only.
    let (rax, _rdx) = unsafe {
        syscall2(
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

/// Send `data` on `channel_id` with message `kind`. `true` on success.
fn sys_ipc_send(channel_id: u64, kind: u64, data: &[u8]) -> bool {
    // SAFETY: data is valid for the duration of the syscall.
    let (rax, _rdx) = unsafe {
        syscall2(
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

/// Non-blocking receive: `Some(n)` bytes copied into `buf`, `None` when
/// the queue is empty.
fn sys_ipc_try_receive(channel_id: u64, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: buf is a valid writable slice; the kernel writes at most
    // buf.len() bytes.
    let (rax, _rdx) = unsafe {
        syscall2(
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
            reason = "kernel copies at most buf.len() ≤ 4096 bytes"
        )]
        Some(rax as usize)
    }
}

/// Register `channel_id` under `iface_name` in the kernel registry
/// (no event channel, no MAC for the AI pseudo-interfaces).
fn sys_net_register(iface_name: &str, channel_id: u64) -> bool {
    let name = iface_name.as_bytes();
    // SAFETY: name is valid for the duration of the syscall.
    let (_rax, rdx) = unsafe {
        syscall2(
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

/// Look up a named IPC channel via `NetLookup (102)`.
///
/// Returns `(channel_id, errno)`.  `errno == 0` means success and
/// `channel_id` is the resolved handle.  Any non-zero `errno` means the
/// channel is not yet registered.
fn sys_net_lookup(name: &[u8]) -> (u64, u64) {
    // SAFETY: `name` is a valid byte slice for the duration of the syscall.
    unsafe {
        syscall2(
            SYS_NET_LOOKUP,
            name.as_ptr() as u64,
            name.len() as u64,
            0,
            0,
            0,
            0,
        )
    }
}

// =============================================================================
// Config-read at boot (TASK-23, ADR-0045 D5)
// =============================================================================

/// Read `/config/ai.cfg` from the NCFS service and configure the
/// runtime endpoint.
///
/// Steps:
/// 1. `NetLookup("ncfs")` + `NetLookup("ncfs-reply")` — bounded retry
///    ([`FS_LOOKUP_RETRIES`] each, `TaskYield` between attempts).
/// 2. Encode `FsRequest::Read { path: AI_CONFIG_PATH, offset: 0,
///    len: FS_MAX_INLINE_BYTES }` → `IpcSend` on the request channel.
/// 3. Poll the reply channel (bounded [`FS_REPLY_POLL_BUDGET`],
///    `TaskYield` between polls) for an `FsResponse`.
/// 4. On `FsResponse::Data { bytes }`:
///    - `decode_canonical::<AiEndpointConfig>(&bytes)` — on success and
///      `to_connect_addr()` succeeds: call `remote::set_connect_addr`
///      and `remote::set_model`; log the configured endpoint.
///    - On decode error or invalid address: keep default; log "corrupt".
/// 5. On `FsResponse::Error(NotFound)` or timeout / lookup failure:
///    keep default; log "absent" or "FS service unavailable".
///
/// This function NEVER panics and NEVER blocks forever.  The runtime
/// always exits this function with a working endpoint.
fn fs_read_config() {
    use nexacore_types::config::{AI_CONFIG_PATH, AiEndpointConfig};
    use nexacore_types::fs_service::{FS_MAX_INLINE_BYTES, FsRequest, FsResponse};

    // ── Step 1: resolve ncfs / ncfs-reply channels. ──
    let mut req_ch: u64 = 0;
    for _ in 0..FS_LOOKUP_RETRIES {
        let (ch, err) = sys_net_lookup(b"ncfs");
        if err == 0 {
            req_ch = ch;
            break;
        }
        task_yield();
    }

    if req_ch == 0 {
        write(
            "[ai-svc] AI config: FS service not found -- using default endpoint (127.0.0.1:11434)\n",
        );
        return;
    }

    let mut reply_ch: u64 = 0;
    for _ in 0..FS_LOOKUP_RETRIES {
        let (ch, err) = sys_net_lookup(b"ncfs-reply");
        if err == 0 {
            reply_ch = ch;
            break;
        }
        task_yield();
    }

    if reply_ch == 0 {
        write(
            "[ai-svc] AI config: FS reply channel not found -- using default endpoint (127.0.0.1:11434)\n",
        );
        return;
    }

    // ── Step 2: encode the Read request. ──
    let fs_req = FsRequest::Read {
        path: alloc::string::String::from(AI_CONFIG_PATH),
        offset: 0,
        len: FS_MAX_INLINE_BYTES as u64,
    };

    // SAFETY: FS_REQ_BUF is a static BSS buffer; single-threaded task;
    // no concurrent access; addr_of_mut! does not form a &mut reference.
    let encoded_len = {
        let buf: &mut [u8; FS_REQ_BUF_CAP] = unsafe { &mut *core::ptr::addr_of_mut!(FS_REQ_BUF) };
        match nexacore_types::wire::encode_into_slice(&fs_req, buf) {
            Ok(n) => n,
            Err(_) => {
                write("[ai-svc] AI config: request encode failed -- using default endpoint\n");
                return;
            }
        }
    };

    // ── Step 3: send + poll, RE-SENDING across attempts. ──
    //
    // `nexacore-fsd` registers its channels EARLY (before its slow boot-counter
    // mount/sync) but only enters its serve loop AFTER that work, so a single
    // send+poll can expire before the request is ever served. We therefore
    // re-send the (idempotent, read-only) request up to `FS_READ_ATTEMPTS`
    // times, polling each round, until a reply arrives. Surplus replies from
    // earlier re-sends simply buffer unread in the one-shot reply channel.
    let n: usize = 'attempts: {
        for _ in 0..FS_READ_ATTEMPTS {
            // SAFETY: FS_REQ_BUF[..encoded_len] is valid; encoded_len bounded above.
            let sent = {
                let buf: &[u8; FS_REQ_BUF_CAP] = unsafe { &*core::ptr::addr_of!(FS_REQ_BUF) };
                sys_ipc_send(req_ch, IPC_KIND_REQUEST, &buf[..encoded_len])
            };
            if !sent {
                // Channel full (FS service not draining yet) — yield + retry.
                task_yield();
                continue;
            }
            let mut budget = FS_REPLY_POLL_BUDGET;
            loop {
                // SAFETY: FS_REPLY_BUF is a static BSS buffer; single-threaded.
                let reply_buf: &mut [u8; FS_REPLY_BUF_CAP] =
                    unsafe { &mut *core::ptr::addr_of_mut!(FS_REPLY_BUF) };
                if let Some(got) = sys_ipc_try_receive(reply_ch, reply_buf) {
                    break 'attempts got;
                }
                if budget == 0 {
                    break;
                }
                budget = budget.saturating_sub(1);
                task_yield();
            }
        }
        write("[ai-svc] AI config absent -- using default endpoint (127.0.0.1:11434)\n");
        return;
    };

    // ── Step 4: decode the FsResponse. ──
    // SAFETY: FS_REPLY_BUF[..n] was written by sys_ipc_try_receive;
    // n <= FS_REPLY_BUF_CAP (the kernel writes at most buf.len() bytes).
    let response_bytes = unsafe { &(*core::ptr::addr_of!(FS_REPLY_BUF))[..n] };

    let fs_resp = match nexacore_types::wire::decode_canonical::<FsResponse>(response_bytes) {
        Ok(r) => r,
        Err(_) => {
            write("[ai-svc] AI config: FsResponse decode failed -- using default endpoint\n");
            return;
        }
    };

    match fs_resp {
        FsResponse::Data { bytes } => {
            // Attempt to decode the AiEndpointConfig from the file bytes.
            match nexacore_types::wire::decode_canonical::<AiEndpointConfig>(&bytes) {
                Ok(cfg) => match cfg.to_connect_addr() {
                    Ok(addr) => {
                        remote::set_connect_addr(addr);
                        remote::set_model(&cfg.model);
                        write("[ai-svc] AI config: ");
                        write(&cfg.host);
                        write(":");
                        // Write port as decimal — build a tiny stack buf.
                        write_u16_decimal(cfg.port);
                        write(" model=");
                        write(&cfg.model);
                        write("\n");
                    }
                    Err(_) => {
                        write(
                            "[ai-svc] AI config corrupt (invalid address) -- using default endpoint\n",
                        );
                    }
                },
                Err(_) => {
                    write("[ai-svc] AI config corrupt -- using default endpoint\n");
                }
            }
        }
        FsResponse::Error(nexacore_types::fs_service::FsErrno::NotFound) => {
            write("[ai-svc] AI config absent -- using default endpoint (127.0.0.1:11434)\n");
        }
        _ => {
            // Any other response (error variant, unexpected type) → default.
            write("[ai-svc] AI config: unexpected FS response -- using default endpoint\n");
        }
    }
}

/// Write `v` as a decimal number to the console (no allocation, stack only).
///
/// Supports the full `u16` range (`0`–`65535`).
fn write_u16_decimal(v: u16) {
    // Five chars maximum for u16 ("65535") + a zero-initialiser.
    let mut buf = [0u8; 5];
    let mut n = v;
    let mut pos = 5usize;
    // Fill from the right.
    loop {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if let Ok(s) = core::str::from_utf8(&buf[pos..]) {
        write(s);
    }
}

// =============================================================================
// Panic handler
// =============================================================================

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    write("[ai-svc] PANIC\n");
    sys_exit(1)
}

// =============================================================================
// Real-engine serving (TASK-13-pre / ADR-0034)
// =============================================================================

/// Greedy generation budget for the LOCAL fixture engine.
///
/// Pinned to 4 so the fixture goldens stay predictable (the host suite
/// pins `"ab"` → `"dddd"` with this budget —
/// `engine::tests::golden_ab_to_dddd_via_sync_engine_surface`). The wire
/// contract has no per-request budget field yet (TASK-21+ scope).
const LOCAL_MAX_NEW_TOKENS: u32 = 4;

/// Run the LOCAL fixture engine on `prompt`, filtering it to the
/// fixture's vocabulary first (ADR-0035 D5).
///
/// The Q8_0 fixture knows only the bytes `a..=h`; out-of-vocab bytes
/// would encode to `unk` (255) and fault at the 8-row embedding lookup.
/// The fallback therefore keeps only in-vocab bytes (e.g.
/// `"what is 2+2?"` → `"ha"`) and uses the canonical probe `"ab"` when
/// nothing survives — the REAL tokenizer/engine on a documented
/// sub-alphabet, never fabricated token ids.  The filtering is logged so
/// the serial capture shows exactly what the degraded fixture served.
fn local_generate(engine: &CpuEngine, prompt: &str) -> Result<String, ()> {
    let filtered: String = prompt.chars().filter(|c| ('a'..='h').contains(c)).collect();
    let effective: &str = if filtered.is_empty() { "ab" } else { &filtered };
    if effective != prompt {
        write("[ai-svc] fixture filter: prompt reduced to in-vocab \"");
        write(effective);
        write("\"\n");
    }
    match engine.generate_text(effective, LOCAL_MAX_NEW_TOKENS) {
        Ok((text, _tokens)) => Ok(text),
        Err(_) => Err(()),
    }
}

/// Serve one decoded request through the on-device backend router
/// (TASK-13 / ADR-0035 D4): RemoteGpu (Ollama over the NET syscalls)
/// first, LocalCpu (the embedded fixture engine) on ANY remote failure.
///
/// `backend_used` does not cross the syscall ABI (no wire change —
/// PLAN constraint); it is emitted as a serial audit line instead:
/// `[ai-svc] rid=<hex> backend_used=RemoteGpu|LocalCpu`.
///
/// Mirrors the host engine's gating order: capability well-formedness
/// first (the `SessionCapability` contract), then the payload bound,
/// then per-syscall routing.
fn serve(engine: &CpuEngine, request: &AiSyscallRequest) -> AiSyscallResponse {
    let rid = request.request_id;

    // Capability gating — same well-formedness contract as
    // `nexacore-runtime::serving::SessionCapability` (Sprint 11.a).
    let cap = &request.capability;
    let cap_ok = !cap.is_empty() && cap.len() <= 4096 && cap.first().copied().unwrap_or(0) != 0;
    if !cap_ok {
        return AiSyscallResponse::error(rid, 0, "capability rejected");
    }

    if request.input_data.len() > AI_MAX_PAYLOAD {
        return AiSyscallResponse::error(rid, 0, "input exceeds AI_MAX_PAYLOAD");
    }

    match request.syscall {
        AiSyscallNumber::Invoke | AiSyscallNumber::Stream => {
            // The prompt is the UTF-8 input payload (same convention as
            // the host serving path).
            let Ok(prompt) = core::str::from_utf8(&request.input_data) else {
                return AiSyscallResponse::error(rid, 0, "prompt is not valid UTF-8");
            };

            // ── RemoteGpu first (M1 routing policy: PreferRemoteGpu). ──
            let (text, backend) = match remote::generate(prompt) {
                Ok((text, _eval_count)) => (text, "RemoteGpu"),
                Err(e) => {
                    // Failover: ANY remote failure routes to LocalCpu —
                    // the on-device mirror of BackendRouter's
                    // within-request fallback (TASK-10).
                    write("[ai-svc] remote unavailable (");
                    write(e.tag());
                    write(") -> LocalCpu fallback\n");
                    match local_generate(engine, prompt) {
                        Ok(text) => (text, "LocalCpu"),
                        Err(()) => {
                            return AiSyscallResponse::error(
                                rid,
                                0,
                                "engine generation failed (both backends)",
                            );
                        }
                    }
                }
            };

            // Serial audit line — the M1 smoke's backend_used evidence
            // (ADR-0035 D4; host deployments use AuditRecord instead).
            write("[ai-svc] rid=");
            write_hex_u64(rid);
            write(" backend_used=");
            write(backend);
            write("\n");

            // Bound the reply to the AI payload contract (truncate on a
            // char boundary; the kernel enforces the same ceiling).
            let mut out = text.into_bytes();
            if out.len() > AI_MAX_PAYLOAD {
                let mut cut = AI_MAX_PAYLOAD;
                while cut > 0 && (out.get(cut).copied().unwrap_or(0) & 0xC0) == 0x80 {
                    cut -= 1;
                }
                out.truncate(cut);
            }

            AiSyscallResponse {
                request_id: rid,
                success: true,
                output_data: out,
                // No monotonic clock syscall is exposed to Ring 3 yet;
                // latency is measured by the caller (aicheck) and on
                // the host path (TASK-10 audit).
                latency_us: 0,
                error_message: None,
            }
        }
        AiSyscallNumber::Embed => {
            // Embedding path (WS5-03.5/.9): pool the transformer's final
            // hidden state into a dense vector. The fixture knows only the
            // bytes a..=h, so filter the prompt the same way local_generate
            // does, then mean-pool + L2-normalize. The reply payload is the
            // postcard `Vec<f32>` the userspace `ai_embed` wrapper decodes.
            let Ok(prompt) = core::str::from_utf8(&request.input_data) else {
                return AiSyscallResponse::error(rid, 0, "prompt is not valid UTF-8");
            };
            let filtered: String = prompt.chars().filter(|c| ('a'..='h').contains(c)).collect();
            let effective: &str = if filtered.is_empty() { "ab" } else { &filtered };
            let vector = match engine.embed_text(effective, Pooling::Mean, true) {
                Ok(v) => v,
                Err(_) => return AiSyscallResponse::error(rid, 0, "embedding failed"),
            };
            write("[ai-svc] rid=");
            write_hex_u64(rid);
            write(" embed dim=");
            write_hex_u64(u64::try_from(vector.len()).unwrap_or(u64::MAX));
            write("\n");
            match nexacore_types::wire::encode_canonical(&vector) {
                Ok(bytes) if bytes.len() <= AI_MAX_PAYLOAD => AiSyscallResponse {
                    request_id: rid,
                    success: true,
                    output_data: bytes,
                    latency_us: 0,
                    error_message: None,
                },
                Ok(_) => AiSyscallResponse::error(rid, 0, "embedding exceeds AI_MAX_PAYLOAD"),
                Err(_) => AiSyscallResponse::error(rid, 0, "embedding encode failed"),
            }
        }
        AiSyscallNumber::Classify | AiSyscallNumber::Transcribe => {
            AiSyscallResponse::error(rid, 0, "not yet supported (Phase 2 CPU engine endpoint)")
        }
    }
}

/// Write `v` to the console as a fixed-width hex literal (audit lines).
fn write_hex_u64(v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nibble = ((v >> ((15 - i) * 4)) & 0xF) as usize;
        buf[2 + i] = HEX[nibble];
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        write(s);
    }
}

// =============================================================================
// ELF entry point + service loop
// =============================================================================

/// Receive staging buffer — BSS, not the 4 KiB user stack.
static mut REQ_BUF: [u8; AI_MAX_PAYLOAD] = [0; AI_MAX_PAYLOAD];

/// Maximum postcard-encoded size of a [`BackendStatusEvent`].
///
/// `BackendStatusEvent` is three fields: one 1-byte postcard enum
/// discriminant (`BackendKind`) + two booleans = 3 bytes. 16 bytes gives
/// ample margin for any future no-std postcard framing overhead.
const STATUS_BUF_CAP: usize = 16;

/// Encode buffer for outbound [`BackendStatusEvent`] payloads — BSS.
///
/// Sized generously; the actual encoded event is at most 3 bytes.
static mut STATUS_BUF: [u8; STATUS_BUF_CAP] = [0; STATUS_BUF_CAP];

/// Encodes `event` into [`STATUS_BUF`] and sends it on the `ai_status`
/// notification channel.
///
/// Logs — but does not hard-fail on — an encode/send error: a dropped status
/// update is cosmetic, and the periodic probe re-publishes on the next change.
fn publish_backend_status(channel: u64, event: BackendStatusEvent) {
    // SAFETY: STATUS_BUF is a static BSS buffer accessed only from this
    // single-threaded task; no concurrent access.
    let encode_result = nexacore_types::wire::encode_into_slice(&event, unsafe {
        &mut *core::ptr::addr_of_mut!(STATUS_BUF)
    });
    match encode_result {
        Ok(n) => {
            // SAFETY: STATUS_BUF is valid; n ≤ STATUS_BUF_CAP.
            let bytes = unsafe { &(*core::ptr::addr_of!(STATUS_BUF))[..n] };
            if !sys_ipc_send(channel, IPC_KIND_NOTIFICATION, bytes) {
                write("[ai-svc] status send FAILED\n");
            }
        }
        Err(_) => write("[ai-svc] status encode FAILED\n"),
    }
}

// =============================================================================
// Config-read machinery (TASK-23, ADR-0045 D5)
// =============================================================================

/// Retry budget for `NetLookup("ncfs")` / `NetLookup("ncfs-reply")`.
///
/// The FS service registers early but its mount + proof loop may not
/// have completed yet when the runtime reaches the config-read step.
/// 100 000 bounded retries (each ending in a `TaskYield`) give the FS
/// service ample startup time — the same budget as `nexacore-apps-image`
/// (ADR-0044 / TASK-22 proven on VM103).  If the budget is exhausted
/// the runtime falls back to the built-in default and continues serving;
/// it NEVER blocks forever.
const FS_LOOKUP_RETRIES: u32 = 100_000;

/// Poll budget for the FS reply after sending the config-read request.
///
/// One `IpcTryReceive` + one `TaskYield` per iteration.  A 2 000 000
/// budget matches `nexacore-apps-image` (ADR-0044 / TASK-22) and gives the
/// FS service time to process the request even when the disk is busy
/// with its own mount/proof.  Budget exhaustion → keep default; never hang.
const FS_REPLY_POLL_BUDGET: u32 = 2_000_000;

/// Number of times the config-read request is re-sent while waiting for the
/// FS service to enter its serve loop (it registers early but serves only
/// after its boot-counter mount/sync). Each attempt polls
/// [`FS_REPLY_POLL_BUDGET`] iterations; the read is idempotent so re-sending
/// is safe. Exhausting all attempts → keep the default endpoint; never hang.
const FS_READ_ATTEMPTS: u32 = 16;

/// BSS encode buffer for the outbound `FsRequest::Read` message.
///
/// The request encodes to well under 512 bytes (path ≤ 15 chars, two
/// 8-byte integers, postcard varint overhead); 4 096 bytes is the same
/// allocation used by `nexacore-apps-image` for correctness margin.
const FS_REQ_BUF_CAP: usize = 4096;

/// BSS decode buffer for the inbound `FsResponse::Data` message.
///
/// The config file (`AiEndpointConfig`) is a tiny struct (≤ 300 bytes
/// postcard-encoded with `CONFIG_MAX_STR = 128`); a 4 096-byte buffer
/// covers the maximum `FsResponse::Data { bytes: [u8; FS_MAX_INLINE_BYTES] }`
/// envelope with margin.
const FS_REPLY_BUF_CAP: usize = 4096;

/// BSS encode buffer for FS requests — avoids stack allocation.
static mut FS_REQ_BUF: [u8; FS_REQ_BUF_CAP] = [0; FS_REQ_BUF_CAP];

/// BSS decode buffer for FS responses — avoids stack allocation.
static mut FS_REPLY_BUF: [u8; FS_REPLY_BUF_CAP] = [0; FS_REPLY_BUF_CAP];

/// ELF entry point: build the engine, create + register the channel pair,
/// then serve forever.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("[ai-svc] start\n");

    // Build the REAL engine from the embedded fixture model: GGUF parse →
    // tensor load/dequantise → weight mapping → tokenizer (TASK-13-pre /
    // ADR-0034). One-time cost at startup; the serve loop borrows it.
    let gguf = fixture::build_synthetic_q8_0_gguf();
    let engine = match CpuEngine::from_gguf(&gguf, fixture::config(), fixture::tokenizer()) {
        Ok(engine) => engine,
        Err(_) => {
            write("[ai-svc] engine build FAILED\n");
            sys_exit(4);
        }
    };
    write("[ai-svc] real CPU engine ready (Q8_0 fixture, vocab=8)\n");

    let ai_channel = sys_ipc_create_channel(QUEUE_DEPTH);
    let ai_reply_channel = sys_ipc_create_channel(QUEUE_DEPTH);
    let ai_status_channel = sys_ipc_create_channel(QUEUE_DEPTH);
    if ai_channel == SYSCALL_ERROR
        || ai_reply_channel == SYSCALL_ERROR
        || ai_status_channel == SYSCALL_ERROR
    {
        write("[ai-svc] IpcCreateChannel FAILED\n");
        sys_exit(2);
    }

    if !sys_net_register("ai", ai_channel)
        || !sys_net_register("ai_reply", ai_reply_channel)
        || !sys_net_register("ai_status", ai_status_channel)
    {
        write("[ai-svc] NetRegister FAILED\n");
        sys_exit(3);
    }
    write("[ai-svc] registered ai/ai_reply — serving (real CPU engine)\n");
    write("[ai-svc] ai_status channel registered id=");
    write_hex_u64(ai_status_channel);
    write("\n");

    // Announce the CPU engine as ready right away. The local fixture engine is
    // already serving (above), so the honest initial status is LocalCpu — the
    // assistant is up on the CPU fallback. The periodic probe below upgrades
    // this to RemoteGpu if/when the Ollama endpoint answers. Publishing here,
    // not only after the first probe, means the desktop AI badge shows the real
    // "AI on CPU" state even when the remote probe is slow or the VM's route to
    // the endpoint is unreachable — instead of a misleading "offline".
    write("[ai-svc] status -> CPU (initial: local engine ready)\n");
    publish_backend_status(
        ai_status_channel,
        BackendStatusEvent {
            backend: BackendKind::LocalCpu,
            healthy: true,
            degraded: true,
        },
    );

    // ── Read the AI endpoint config from NCFS (TASK-23, ADR-0045 D5). ──
    //
    // This runs once at boot, AFTER our own channels are registered (so the
    // kernel's NET registry is initialised), and BEFORE the serve loop.
    // `fs_read_config()` performs a bounded `NetLookup` retry to wait for
    // the FS service, then reads `/config/ai.cfg` and calls
    // `remote::set_connect_addr` + `remote::set_model` if valid.
    // Absent or corrupt config → built-in default; never a hard fail.
    fs_read_config();

    // ── Periodic-probe state. ──
    //
    // `last_reachable`: the last probed reachability state, or `None` before
    // the very first probe fires. `None` causes an unconditional publish at
    // startup so the status bar always gets an initial value.
    let mut last_reachable: Option<bool> = None;

    // Idle-iteration counter: incremented only when `IpcTryReceive` returns
    // `None` (the channel is empty).  Reset after each probe.  Saturates at
    // `PROBE_IDLE_INTERVAL` to avoid overflow on very long idle stretches.
    let mut idle_ticks: u32 = 0;

    loop {
        // ── Periodic Ollama probe (idle-only, non-blocking). ──
        //
        // The probe runs ONLY on idle ticks (IpcTryReceive returned None in
        // the previous iteration OR at startup before the first receive).
        // This ensures that arriving requests are served with minimal latency:
        // a busy channel never triggers the probe.
        //
        // The `idle_ticks` counter is advanced only in the idle branch below,
        // so the probe fires at most once every `PROBE_IDLE_INTERVAL` yields.
        if idle_ticks >= PROBE_IDLE_INTERVAL || last_reachable.is_none() {
            idle_ticks = 0;
            let reachable = remote::probe_ollama_reachable();

            // De-dup: only publish on a change OR on the very first probe
            // (initial value for the status bar).
            if last_reachable != Some(reachable) {
                last_reachable = Some(reachable);

                // Map reachability to the canonical BackendStatusEvent:
                // - reachable  → RemoteGpu healthy  (GPU up, bar shows green)
                // - unreachable → LocalCpu degraded (GPU down, bar shows amber)
                let event = if reachable {
                    write("[ai-svc] status -> GPU\n");
                    BackendStatusEvent {
                        backend: BackendKind::RemoteGpu,
                        healthy: true,
                        degraded: false,
                    }
                } else {
                    write("[ai-svc] status -> CPU(degraded)\n");
                    BackendStatusEvent {
                        backend: BackendKind::LocalCpu,
                        healthy: true,
                        degraded: true,
                    }
                };

                publish_backend_status(ai_status_channel, event);
            }
        }

        // ── Drain one AI request (non-blocking). ──
        // SAFETY: single-threaded task; REQ_BUF is a static BSS buffer
        // accessed only here.
        let received = sys_ipc_try_receive(ai_channel, unsafe {
            &mut *core::ptr::addr_of_mut!(REQ_BUF)
        });
        let Some(n) = received else {
            // Idle: yield instead of busy-spinning (TASK-06 lesson), and
            // advance the idle counter so the next probe fires on schedule.
            idle_ticks = idle_ticks.saturating_add(1);
            task_yield();
            continue;
        };

        // A request arrived — do NOT advance idle_ticks; reset it instead so
        // the probe is deferred while the channel is busy (serve first).
        idle_ticks = 0;

        // SAFETY: single-threaded task; n ≤ AI_MAX_PAYLOAD.
        let bytes = unsafe { &(*core::ptr::addr_of!(REQ_BUF))[..n] };
        write("[ai-svc] req received\n");
        let response = match nexacore_types::wire::decode_canonical::<AiSyscallRequest>(bytes) {
            Ok(request) => serve(&engine, &request),
            // Malformed request: reply with request_id 0 so the relay's
            // decode still succeeds and maps to EIO (never silent-drop —
            // the kernel relay is parked waiting for a reply).
            Err(_) => AiSyscallResponse::error(0, 0, "malformed request"),
        };

        match nexacore_types::wire::encode_canonical(&response) {
            Ok(encoded) => {
                if !sys_ipc_send(ai_reply_channel, IPC_KIND_REPLY, &encoded) {
                    write("[ai-svc] reply send FAILED\n");
                }
            }
            Err(_) => write("[ai-svc] reply encode FAILED\n"),
        }
    }
}
