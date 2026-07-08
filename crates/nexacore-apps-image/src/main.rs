//! TASK-23/24 (DE-D2 + DE-D3 + DE-D5) Ring 3 display image: terminal + system
//! monitor + file manager + settings + NexaCore Helper chat, 2×2 utility grid +
//! centred chat overlay, NCFS service client (ADR-0045, ADR-0046).
//!
//! This image is the Ring 3 display task for M4.  It owns the framebuffer and
//! hosts **FIVE** native `nexacore-ui` application windows on the compositor,
//! each dressed in the shared `nexacore-desktop-shell` window chrome (42px
//! titlebar, 17px corners, dark tokens) at the initial positions and sizes of
//! the design mockup (`brand/design/NexaCore-OS.dc.html`, Task 7): Terminal,
//! System Monitor, File Manager, Settings, and the NexaCore Helper chat.
//!
//! ## Terminal window (DE-D1)
//!
//! A windowed `nexacore-shell` REPL.  Keyboard input builds a command line;
//! **Enter** runs it through `nexacore_shell::repl::process_line` and appends the
//! output to a scrolling history rendered in the window (monospace font8x8,
//! prompt + echo + output lines).  `ls` and `cd` are backed by the FS service
//! when it is available (`FsQuery` impl issues `FsRequest::ListDir`).  Its
//! frame uses `FrameVariant::Terminal` (always-dark titlebar) and is created
//! LAST so it starts focused, per the mockup's `focused:'terminal'`.
//!
//! ## System Monitor window (DE-D4, WS7 desktop M5)
//!
//! A read-only status display: an "AI Backend" card (live, reused from the
//! existing AI-status channel), a Mesh card and a TEE Attestation card
//! (both static placeholders — no host-reachable IPC surface exists for
//! either), and a CPU/Memory/Uptime tile row (Uptime live, CPU/Memory static
//! placeholders). No editable content, no persistence, no dedicated key
//! handling beyond the shared shell chrome (drag/focus/min/max/close). See
//! `crate::apps::monitor` and `docs/superpowers/plans/2026-07-06-desktop-shell-m5.md`.
//!
//! ## File Manager window (DE-D2)
//!
//! Browse and perform CRUD on NCFS via `FsRequest`.  State: a current
//! working directory, a list of entries (name + is_dir flag, bounded to
//! [`FM_ENTRIES_CAP`]), a selection cursor, and a status line.
//! Keys: Up/Down move selection; Enter descends into a directory; Backspace
//! goes to the parent; `n` creates a folder (`Mkdir`); `f` creates a file
//! (`Create`); `d` deletes the selected entry (`Delete`) — a non-empty
//! directory is rejected with `FsErrno::DirectoryNotEmpty` shown on screen.
//!
//! ## Settings window (DE-D3)
//!
//! Edit the AI endpoint and persist it to NCFS at
//! [`nexacore_types::config::AI_CONFIG_PATH`].  On open it reads the config
//! (falling back to
//! [`AiEndpointConfig::default`](nexacore_types::config::AiEndpointConfig) on
//! absent or corrupt data).  The user edits a `"host:port"` buffer; **Esc**
//! saves: the value is validated via
//! [`AiEndpointConfig::validate`](nexacore_types::config::AiEndpointConfig::validate) — an
//! invalid endpoint is REJECTED with an on-screen message and NEVER written.
//! A valid value is persisted via `Mkdir /config` + `Write` + `Sync`.
//!
//! ## NexaCore Helper chat window (DE-D5, ADR-0046)
//!
//! At the mockup's `chat` position/size.  It owns a
//! [`nexacore_ui::chat::ChatState`] and a `chat_input` line buffer (cap 512 chars).
//! Keys when focused: printable → append; Backspace → pop; Enter → send.  The
//! send flow calls `AiInvoke (80)` (blocking) with `MODEL_ID` and the prompt,
//! retrying on `ENOENT` (service not yet ready) up to `AI_INVOKE_RETRY_BUDGET`
//! times, measures round-trip latency via `TimeMonotonicNanos (50)`, and
//! reveals the answer progressively in chunks of `CHAT_CHUNK_SIZE` characters
//! (streaming visual, ADR-0046 §D3).  When complete, `finish_assistant` stamps
//! the message with `bar.state()` (the live ai_status badge, §D4).  It is the
//! only window that still shows the AI status strip (below its titlebar) —
//! the menu-bar pill for the other four arrives in M2.
//!
//! ## Input model
//!
//! - **Tab (0x09)**: `compositor.wm.cycle_focus()` — cycles focus across all
//!   five windows in round-robin order.  The Terminal window is created last
//!   so it starts focused and is raised to the front by the WM.
//! - All other keys route to the **focused** window and are handled as above.
//!
//! ## FS service client
//!
//! `NetLookup("ncfs")` and `NetLookup("ncfs-reply")` resolve the FS
//! service channels (bounded retry, `task_yield` between attempts).  If
//! unresolved, Settings/Files degrade gracefully (see their own docs); the
//! terminal uses an empty `FsQuery`.  The rest of the UI works regardless.
//!
//! ## Exit codes
//!
//! | Code  | Meaning |
//! |-------|---------|
//! | `0`   | Unreachable in normal operation (daemon loops indefinitely) |
//! | `1`   | Panic handler invoked |
//! | `2`   | No device-info / degenerate geometry / bpp != 4 |
//! | `3`   | No Display capability token in deposit window |
//! | `40+` | DisplayMap syscall failed; `code - 40` is the raw kernel errno |
//! | `50`  | Canvas construction failed (internal invariant violation) |
//!
//! ## Desktop chrome (WS7 desktop M2)
//!
//! The branded [constellation
//! wallpaper](../../../brand/wallpapers/compiled/README.md) is embedded
//! (`WALLPAPER_NXWP`), decoded once at boot, and installed on the compositor
//! before the first frame. A `crate::gfx::ChromeState` (menu bar model + dock
//! tile model + two reused scratch pixel buffers) is threaded through every
//! `present` call; `gfx::present`'s chrome pass repaints the menu bar and/or
//! dock strips whenever this frame's dirty rects touch them, so a window
//! sliding under either leaves no stale fringe. All five windows exist and
//! run continuously in M2; since M5 every dock tile (including `Monitor`)
//! shows the running indicator, all five app windows genuinely reachable.
//!
//! ## Heap note
//!
//! A 64 MiB never-freeing bump allocator backs the `alloc` crate.  Covers:
//! back buffer 1280×800 ≈ 4 MiB, the five window surfaces at their mockup
//! sizes (each well under 1 MiB), compositor internals, shell command history
//! (`Vec<String>`), file-manager entry list,
//! `ChatState` message history (bounded 64 turns × 8 KiB cap = 512 KiB worst
//! case), and per-render widget tree allocations.  Total well within 64 MiB
//! with generous headroom.

#![no_std]
#![no_main]
#![allow(unsafe_code)]

extern crate alloc;

mod apps;
mod gfx;
mod shellsync;
mod sysinfo;

use alloc::{string::String, vec, vec::Vec};
use core::panic::PanicInfo;

use nexacore_desktop_shell::{
    dock,
    frame::{FrameButton, FRAME_RADIUS},
    router::{AppId, PointerAction, PointerRouter},
    tokens::ShellTokens,
};
use nexacore_display::{
    compositor::{Compositor, WindowDecoration},
    effects::Shadow,
    geometry::Rect,
    surface::{Surface, SurfaceId, WindowId},
};
use nexacore_cmd_ifconfig::InterfaceDisplay;
use nexacore_net::ifconfig::{InterfaceInfo, NetConfigRequest, NetConfigResponse};
use nexacore_types::{
    ai::{BackendKind, BackendStatusEvent},
    display_channel::DisplayInputEvent,
    fs_service::{FsErrno, FsRequest, FsResponse},
    wire::decode_canonical,
};
use nexacore_shell::netquery::NetQuery;
use nexacore_ui::{
    chat::ChatState,
    status_bar::{BackendState, StatusBar},
};

use apps::files::{errno_str, fm_refresh, path_join, path_parent, render_file_manager};
use apps::helper::{chat_send, render_chat};
use apps::monitor::render_monitor;
use apps::settings::{appearance_rects, render_settings, settings_load, settings_save};
use apps::system_info::render_system_info;
use apps::terminal::{push_history, render_terminal};
use gfx::{
    cursor_rect, draw_cursor, init_fonts, present, shadow_padded, uptime_minutes_now, ChromeState,
};
use shellsync::ShellSync;

// =============================================================================
// Bump allocator (64 MiB static heap)
// =============================================================================

/// Size of the static heap backing the bump allocator (64 MiB).
///
/// Covers: back buffer 1280×800×4 ≈ 4 MiB, four ~620×360 window surfaces
/// ≈ 880 KiB each, compositor Vec internals, shell history (`Vec<String>`),
/// file-manager entry list, per-render widget allocations, with generous
/// headroom (was 48 MiB for 2 windows; 64 MiB for 4).
const HEAP_SIZE: usize = 64 * 1024 * 1024;

/// Backing storage for the bump allocator (BSS).
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// Current bump cursor (byte offset into [`HEAP`]).
///
/// Single-threaded task; no atomics required.
static mut HEAP_POS: usize = 0;

/// Never-freeing bump allocator.
///
/// `dealloc` is a deliberate no-op: this is a display daemon whose allocation
/// pressure is primarily at startup (back buffer + compositor + surfaces).
/// The main loop appends to bounded buffers (history cap, chat input cap),
/// so live allocation is small per iteration.
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
            // SAFETY: `aligned` is within [0, HEAP_SIZE) and `base` is the
            // start of the static HEAP array.
            base.add(aligned)
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Never-freeing bump allocator: dealloc is intentionally a no-op.
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

// =============================================================================
// Syscall numbers + ABI constants
// =============================================================================

/// `TaskExit (11)` — terminate the calling task.
const SYS_TASK_EXIT: u64 = 11;
/// `TaskYield (12)` — cooperatively yield the CPU.
const SYS_TASK_YIELD: u64 = 12;
/// `IpcSend (22)` — send a message on a channel.
const SYS_IPC_SEND: u64 = 22;
/// `IpcTryReceive (24)` — non-blocking IPC receive.
const SYS_IPC_TRY_RECEIVE: u64 = 24;
/// `WriteConsole (60)` — write bytes to the kernel console (COM1).
const SYS_WRITE_CONSOLE: u64 = 60;
/// `DisplayMap (79)` — map the framebuffer into the caller's address space,
/// capability-gated (ADR-0040 D2).
const SYS_DISPLAY_MAP: u64 = 79;
/// `NetLookup (102)` — look up a named IPC channel registered via
/// `NetRegister (100)`.
const SYS_NET_LOOKUP: u64 = 102;
/// `AiInvoke (80)` — single-turn inference.  ABI:
/// `(model_id_ptr, model_id_len=16, input_ptr, input_len, output_ptr,
/// output_cap) -> (rax=output_len, rdx=errno)`.
pub(crate) const SYS_AI_INVOKE: u64 = 80;
/// `TimeMonotonicNanos (50)` — get nanoseconds since boot.
/// ABI: `(0,0,0,0,0,0) -> rax = nanos`.
const SYS_TIME_MONOTONIC_NANOS: u64 = 50;

/// Deposit-window action tag for the Display capability (ADR-0040 D3).
const ACTION_TAG_DISPLAY_MAP: u32 = 7;

/// `SYSCALL_ERROR` sentinel: `u64::MAX` returned in `rax` on error.
const SYSCALL_ERROR: u64 = u64::MAX;

/// `MessageKind::Request = 1` — discriminant for FS request IPC messages.
const IPC_KIND_REQUEST: u64 = 1;

/// Retry budget for `NetLookup` of the FS service channels at startup.
///
/// The FS service registers its channels slightly after boot.  Each retry
/// issues one `task_yield()`.  200 retries is generous headroom.
const FS_LOOKUP_RETRIES: u32 = 100_000;

/// Retry budget for polling a FS reply after sending a request.
///
/// Each iteration issues one `IpcTryReceive` + one `task_yield()`.
const FS_REPLY_POLL_BUDGET: u32 = 2_000_000;

/// Retry budget for `NetLookup("ai_status")` at startup.
const AI_STATUS_LOOKUP_RETRIES: u32 = 200;

/// `ENOENT (2)` — the AI runtime service has not yet registered its channel.
///
/// `AiInvoke` returns this errno when the relay is not ready.  The chat send
/// handler retries up to [`AI_INVOKE_RETRY_BUDGET`] times (one `task_yield`
/// between each attempt) before treating it as a hard failure.
pub(crate) const ENOENT_AI: u64 = 2;

/// Maximum number of `AiInvoke` ENOENT retries before giving up.
///
/// Matches the budget used in `nexacore-aicheck-image` scaled for the interactive
/// display task (less urgent than the smoke test).
pub(crate) const AI_INVOKE_RETRY_BUDGET: u32 = 200;

/// Maximum length of the chat input buffer (bytes).
///
/// Bounds the user's prompt to a size that comfortably fits in the
/// `AI_OUT` response buffer and the single-line input display.
const CHAT_INPUT_CAP: usize = 512;

// =============================================================================
// Window layout constants (mockup initial layout, Task 7)
// =============================================================================
//
// Values are the `W` position/size map from the approved design mockup
// (`brand/design/NexaCore-OS.dc.html`).

/// Terminal window width (pixels).
pub(crate) const TERM_W: u32 = 486;
/// Terminal window height (pixels).
pub(crate) const TERM_H: u32 = 398;
/// Terminal window screen position x.
const TERM_X: i32 = 452;
/// Terminal window screen position y.
const TERM_Y: i32 = 112;

/// NexaCore Helper chat window width (pixels).
pub(crate) const CHAT_W: u32 = 376;
/// NexaCore Helper chat window height (pixels).
pub(crate) const CHAT_H: u32 = 430;
/// NexaCore Helper chat window screen position x.
const CHAT_X: i32 = 98;
/// NexaCore Helper chat window screen position y.
const CHAT_Y: i32 = 88;

/// File Manager window width (pixels).
pub(crate) const FM_W: u32 = 600;
/// File Manager window height (pixels).
pub(crate) const FM_H: u32 = 392;
/// File Manager window screen position x.
const FM_X: i32 = 250;
/// File Manager window screen position y.
const FM_Y: i32 = 150;

/// Settings window width (pixels).
pub(crate) const SET_W: u32 = 520;
/// Settings window height (pixels).
pub(crate) const SET_H: u32 = 438;
/// Settings window screen position x.
const SET_X: i32 = 360;
/// Settings window screen position y.
const SET_Y: i32 = 150;

/// System Monitor window width (pixels).
pub(crate) const MONITOR_W: u32 = 568;
/// System Monitor window height (pixels).
pub(crate) const MONITOR_H: u32 = 452;
/// System Monitor window screen position x.
const MONITOR_X: i32 = 300;
/// System Monitor window screen position y.
const MONITOR_Y: i32 = 120;

/// System Info window width (pixels).
pub(crate) const SYSINFO_W: u32 = 420;
/// System Info window height (pixels).
pub(crate) const SYSINFO_H: u32 = 320;
/// System Info window screen position x.
///
/// Placed in the lower-centre band so that, when opened at boot for the
/// marketing capture, it sits below the Terminal/Helper windows with only a
/// thin overlap on their bottom edges (their key content — the `ifconfig`
/// transcript and the conversation — lives in the upper portion and stays
/// visible).
const SYSINFO_X: i32 = 360;
/// System Info window screen position y.
const SYSINFO_Y: i32 = 470;

/// Maximum length of the file-manager status string (bytes).
const FM_STATUS_CAP: usize = 64;

/// Maximum length of the Settings endpoint buffer (bytes).
///
/// An IPv4:port string is at most 21 chars; 64 gives comfortable headroom
/// while bounding the allocation.
const SET_BUF_CAP: usize = 64;

/// Height of the AI status strip (pixels).
///
/// Since Task 7 (mockup chrome), only the NexaCore Helper window still shows
/// this strip — drawn directly below its [`nexacore_desktop_shell::frame`]
/// titlebar — the other four windows dropped it (the menu-bar pill for them
/// arrives in M2).
pub(crate) const BAR_H: u32 = 34;

/// Vertical padding within a window area.
pub(crate) const PAD: u32 = 6;

/// Interval between idle heartbeat log messages (in empty-queue poll cycles).
const EMPTY_POLL_LOG_INTERVAL: u32 = 200_000;

// =============================================================================
// Syscall stubs — full-clobber, ADR-0035
// =============================================================================

/// Issue a two-register-return syscall with ALL argument registers declared
/// as clobbered (ADR-0035 lesson).
///
/// # Safety
///
/// Pointer arguments must be valid for the duration of the call.  The caller
/// is responsible for upholding the platform ABI.
#[inline(always)]
pub(crate) unsafe fn syscall(
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
    // SAFETY: canonical Ring 3 → Ring 0 transition; caller upholds pointer
    // validity; ALL argument registers (rdi, rsi, rdx, r10, r8, r9) are
    // declared `inout(…) => _` so the compiler treats them as clobbered after
    // the syscall, preventing use-after-syscall register aliasing (ADR-0035).
    // `rcx` and `r11` are clobbered by SYSCALL per AMD64 spec.
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

// =============================================================================
// Console helpers
// =============================================================================

/// Write a UTF-8 string to the kernel console (best-effort; errors ignored).
pub(crate) fn write(msg: &str) {
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
pub(crate) fn write_hex(val: u64) {
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

/// Write a decimal `usize` to the kernel console.
pub(crate) fn write_dec(mut val: usize) {
    let mut buf = [b'0'; 20];
    let mut pos = buf.len();
    if val == 0 {
        write_bytes(b"0");
        return;
    }
    while val > 0 && pos > 0 {
        pos -= 1;
        #[allow(clippy::cast_possible_truncation, reason = "digit is 0..9")]
        let digit = (val % 10) as u8;
        buf[pos] = b'0' + digit;
        val /= 10;
    }
    write_bytes(&buf[pos..]);
}

// =============================================================================
// Task helpers
// =============================================================================

/// Cooperatively yield the CPU.
pub(crate) fn task_yield() {
    // SAFETY: TaskYield takes no arguments; full clobber set per ADR-0035.
    let _ = unsafe { syscall(SYS_TASK_YIELD, 0, 0, 0, 0, 0, 0) };
}

/// Read the monotonic nanosecond clock (nanoseconds since boot).
///
/// Wraps `TimeMonotonicNanos (50)`.  Returns 0 on error (the syscall's only
/// defined error is unreachable from Ring 3 with valid arguments).
///
/// Used to measure per-message AI latency around `AiInvoke` calls.
pub(crate) fn time_monotonic_nanos() -> u64 {
    // SAFETY: TimeMonotonicNanos takes no pointer arguments; all six argument
    // slots are zero.  The kernel returns the nanosecond count in rax.
    let (rax, _rdx) = unsafe { syscall(SYS_TIME_MONOTONIC_NANOS, 0, 0, 0, 0, 0, 0) };
    rax
}

/// Terminate the calling task with the given exit `code`.  Never returns.
pub(crate) fn exit(code: u32) -> ! {
    // SAFETY: TaskExit terminates unconditionally; `noreturn` informs compiler.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") u64::from(code),
            options(noreturn),
        );
    }
}

// =============================================================================
// IPC helpers
// =============================================================================

/// Non-blocking IPC receive: `Some(n)` bytes into `buf` on success, `None`
/// when the queue is empty.
fn sys_ipc_try_receive(channel_id: u64, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: `buf` is a valid writable slice; kernel writes at most buf.len().
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
            reason = "kernel copies at most buf.len() bytes"
        )]
        Some(rax as usize)
    }
}

/// Look up a named IPC channel via `NetLookup (102)`.
///
/// Returns `(channel_id, errno)`. `errno == 0` → success.
fn sys_net_lookup(name: &[u8]) -> (u64, u64) {
    // SAFETY: `name` is a valid byte slice for the duration of the syscall.
    unsafe {
        syscall(
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

/// Send `data` on `channel_id` with message `kind`.
///
/// Returns `true` on success.
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

// =============================================================================
// Panic handler
// =============================================================================

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    write("[nexacore-apps] PANIC\n");
    exit(1)
}

// =============================================================================
// BSS receive / send buffers
// =============================================================================

/// Maximum wire size of a single `DisplayInputEvent`.
const MAX_EVENT_BYTES: usize = 32;

/// Receive buffer for keyboard IPC messages.
static mut RECV_BUF: [u8; MAX_EVENT_BYTES] = [0u8; MAX_EVENT_BYTES];

/// Receive buffer for `ai_status` channel messages.
const MAX_STATUS_EVENT_BYTES: usize = 64;
static mut STATUS_BUF: [u8; MAX_STATUS_EVENT_BYTES] = [0u8; MAX_STATUS_EVENT_BYTES];

/// Receive buffer for FS service reply messages.
///
/// Large enough for a `FsResponse::Data { bytes: [u8; FS_MAX_INLINE_BYTES] }`
/// plus postcard overhead.  4096 bytes covers the worst-case response.
const MAX_FS_REPLY_BYTES: usize = 4096;
static mut FS_REPLY_BUF: [u8; MAX_FS_REPLY_BYTES] = [0u8; MAX_FS_REPLY_BYTES];

/// Encode buffer for outgoing FS requests.
///
/// `FsRequest::Write` with max inline data + path + offset encodes to ≤ 4096 B.
const MAX_FS_REQ_BYTES: usize = 4096;
static mut FS_REQ_BUF: [u8; MAX_FS_REQ_BYTES] = [0u8; MAX_FS_REQ_BYTES];

/// Output buffer for `AiInvoke (80)` responses (BSS, 4 KiB).
///
/// Written by the kernel relay into Ring 3 memory; read back after the
/// syscall returns.  Shared across all chat invocations (single-threaded).
pub(crate) const AI_OUT_CAP: usize = 4096;
pub(crate) static mut AI_OUT: [u8; AI_OUT_CAP] = [0u8; AI_OUT_CAP];

/// 16-byte model identifier passed to `AiInvoke`.
///
/// Matches the value used in `nexacore-aicheck-image` (the reference caller).
/// The service router does not interpret the bytes; any value proves
/// marshalling through the relay.
pub(crate) static MODEL_ID: [u8; 16] = *b"gemma4-m1-000001";

// =============================================================================
// FS service client
// =============================================================================

/// Resolved FS service channel IDs.
///
/// `0` means "not resolved" (kernel channel IDs are always > 0).
static mut FS_REQ_CH: u64 = 0;
static mut FS_REPLY_CH: u64 = 0;

/// Resolve the FS service channels at startup (bounded retry).
///
/// Attempts `NetLookup("ncfs")` and `NetLookup("ncfs-reply")` up to
/// `FS_LOOKUP_RETRIES` times each, with `task_yield()` between attempts.
/// Writes the resolved channel IDs into the BSS statics [`FS_REQ_CH`] and
/// [`FS_REPLY_CH`].  Logs success or failure for each channel.
fn resolve_fs_channels() {
    // Resolve the request channel.
    let mut req_ch: u64 = 0;
    {
        let mut attempts: u32 = 0;
        loop {
            let (ch, err) = sys_net_lookup(b"ncfs");
            if err == 0 {
                req_ch = ch;
                write("[nexacore-apps] nexacore.fs req_ch=");
                write_hex(ch);
                write("\n");
                break;
            }
            attempts = attempts.saturating_add(1);
            if attempts >= FS_LOOKUP_RETRIES {
                write("[nexacore-apps] nexacore.fs not found -- FS service unavailable\n");
                break;
            }
            task_yield();
        }
    }

    // Resolve the reply channel.
    let mut reply_ch: u64 = 0;
    if req_ch != 0 {
        let mut attempts: u32 = 0;
        loop {
            let (ch, err) = sys_net_lookup(b"ncfs-reply");
            if err == 0 {
                reply_ch = ch;
                write("[nexacore-apps] nexacore.fs-reply reply_ch=");
                write_hex(ch);
                write("\n");
                break;
            }
            attempts = attempts.saturating_add(1);
            if attempts >= FS_LOOKUP_RETRIES {
                write("[nexacore-apps] nexacore.fs-reply not found -- FS service unavailable\n");
                break;
            }
            task_yield();
        }
    }

    // SAFETY: called once at startup before the input loop; single-threaded.
    unsafe {
        *core::ptr::addr_of_mut!(FS_REQ_CH) = req_ch;
        *core::ptr::addr_of_mut!(FS_REPLY_CH) = reply_ch;
    }
}

/// Returns `true` if the FS service channels were successfully resolved.
pub(crate) fn fs_available() -> bool {
    // SAFETY: read-only access after `resolve_fs_channels` completes.
    let req = unsafe { *core::ptr::addr_of!(FS_REQ_CH) };
    let rep = unsafe { *core::ptr::addr_of!(FS_REPLY_CH) };
    req != 0 && rep != 0
}

/// Send a `FsRequest` and wait for a `FsResponse`.
///
/// Encodes `req` into the BSS send buffer, issues `IpcSend` on the request
/// channel, then polls the reply channel (bounded budget, `task_yield` between
/// attempts).  Returns `Some(response)` on success; `None` on encode failure,
/// send failure, reply timeout, or decode error.  Never panics.
pub(crate) fn fs_request(req: &FsRequest) -> Option<FsResponse> {
    // SAFETY: single-threaded; the statics are only accessed here.
    let req_ch = unsafe { *core::ptr::addr_of!(FS_REQ_CH) };
    let reply_ch = unsafe { *core::ptr::addr_of!(FS_REPLY_CH) };

    if req_ch == 0 || reply_ch == 0 {
        return None;
    }

    // Encode the request into the BSS buffer (non-allocating path).
    // SAFETY: FS_REQ_BUF is a static BSS buffer; single-threaded access.
    let encoded_len = {
        let req_buf: &mut [u8; MAX_FS_REQ_BYTES] =
            unsafe { &mut *core::ptr::addr_of_mut!(FS_REQ_BUF) };
        match nexacore_types::wire::encode_into_slice(req, req_buf) {
            Ok(n) => n,
            Err(_) => {
                write("[nexacore-apps] fs_request: encode failed\n");
                return None;
            }
        }
    };

    // Send the encoded request.
    // SAFETY: FS_REQ_BUF is valid; slice bounds checked by encoded_len.
    let sent = {
        let req_buf: &[u8; MAX_FS_REQ_BYTES] = unsafe { &*core::ptr::addr_of!(FS_REQ_BUF) };
        sys_ipc_send(req_ch, IPC_KIND_REQUEST, &req_buf[..encoded_len])
    };

    if !sent {
        write("[nexacore-apps] fs_request: IpcSend failed\n");
        return None;
    }

    // Poll the reply channel (bounded).
    let mut budget: u32 = FS_REPLY_POLL_BUDGET;
    loop {
        // SAFETY: FS_REPLY_BUF is a static BSS buffer; single-threaded.
        let reply_buf: &mut [u8; MAX_FS_REPLY_BYTES] =
            unsafe { &mut *core::ptr::addr_of_mut!(FS_REPLY_BUF) };

        match sys_ipc_try_receive(reply_ch, reply_buf) {
            Some(n) => {
                let payload = &reply_buf[..n];
                return match decode_canonical::<FsResponse>(payload) {
                    Ok(resp) => Some(resp),
                    Err(_) => {
                        write("[nexacore-apps] fs_request: decode failed\n");
                        None
                    }
                };
            }
            None => {
                if budget == 0 {
                    write("[nexacore-apps] fs_request: reply timeout\n");
                    return None;
                }
                budget = budget.saturating_sub(1);
                task_yield();
            }
        }
    }
}

// =============================================================================
// FsQuery implementation for the terminal
// =============================================================================

/// `FsQuery` implementation backed by the NCFS IPC service.
///
/// `list_dir` sends `FsRequest::ListDir` and returns the entry names on
/// `FsResponse::Listing`.  On any failure it returns an empty list so that
/// the `ls` built-in degrades gracefully rather than panicking.
struct IpcFsQuery;

impl nexacore_shell::glob::FsQuery for IpcFsQuery {
    /// List directory entries at `path` via the FS service.
    ///
    /// Returns an empty `Vec` (not an error) when the FS service is
    /// unavailable or when the path does not exist, so the shell's glob
    /// expander stays calm under a missing FS service.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // (bare-metal only — not runnable in doctests)
    /// use nexacore_shell::glob::FsQuery;
    /// let fs = IpcFsQuery;
    /// let entries = fs.list_dir("/").unwrap_or_default();
    /// ```
    fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
        if !fs_available() {
            return Ok(Vec::new());
        }
        let req = FsRequest::ListDir {
            path: String::from(path),
        };
        match fs_request(&req) {
            Some(FsResponse::Listing { names }) => Ok(names),
            _ => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Network-config service client (NCIP N6.1 — backs the Terminal's `ifconfig`)
// =============================================================================

/// Resolved network-config service channel IDs.
///
/// `0` means "not resolved" (kernel channel IDs are always > 0). Mirrors
/// [`FS_REQ_CH`]/[`FS_REPLY_CH`] exactly.
static mut NET_CONFIG_REQ_CH: u64 = 0;
static mut NET_CONFIG_REPLY_CH: u64 = 0;

/// Resolve the network-config service channels at startup (bounded retry).
///
/// Mirrors [`resolve_fs_channels`]: attempts `NetLookup("config")` and
/// `NetLookup("config_reply")` up to `FS_LOOKUP_RETRIES` times each, with
/// `task_yield()` between attempts.
fn resolve_net_config_channels() {
    let mut req_ch: u64 = 0;
    {
        let mut attempts: u32 = 0;
        loop {
            let (ch, err) = sys_net_lookup(b"config");
            if err == 0 {
                req_ch = ch;
                write("[nexacore-apps] nexacore.net.config req_ch=");
                write_hex(ch);
                write("\n");
                break;
            }
            attempts = attempts.saturating_add(1);
            if attempts >= FS_LOOKUP_RETRIES {
                write("[nexacore-apps] nexacore.net.config not found -- network service unavailable\n");
                break;
            }
            task_yield();
        }
    }

    let mut reply_ch: u64 = 0;
    if req_ch != 0 {
        let mut attempts: u32 = 0;
        loop {
            let (ch, err) = sys_net_lookup(b"config_reply");
            if err == 0 {
                reply_ch = ch;
                write("[nexacore-apps] nexacore.net.config_reply reply_ch=");
                write_hex(ch);
                write("\n");
                break;
            }
            attempts = attempts.saturating_add(1);
            if attempts >= FS_LOOKUP_RETRIES {
                write("[nexacore-apps] nexacore.net.config_reply not found -- network service unavailable\n");
                break;
            }
            task_yield();
        }
    }

    // SAFETY: called once at startup before the input loop; single-threaded.
    unsafe {
        *core::ptr::addr_of_mut!(NET_CONFIG_REQ_CH) = req_ch;
        *core::ptr::addr_of_mut!(NET_CONFIG_REPLY_CH) = reply_ch;
    }
}

/// Returns `true` if the network-config service channels were resolved.
fn net_config_available() -> bool {
    // SAFETY: read-only access after `resolve_net_config_channels` completes.
    let req = unsafe { *core::ptr::addr_of!(NET_CONFIG_REQ_CH) };
    let rep = unsafe { *core::ptr::addr_of!(NET_CONFIG_REPLY_CH) };
    req != 0 && rep != 0
}

/// Maximum encoded size of a `NetConfigRequest`/`NetConfigResponse` message.
///
/// `NetConfigResponse::Interfaces` for a handful of interfaces comfortably
/// fits in 4096 bytes (matches the FS service's buffer sizing convention).
const MAX_NET_CONFIG_BYTES: usize = 4096;
static mut NET_CONFIG_REQ_BUF: [u8; MAX_NET_CONFIG_BYTES] = [0u8; MAX_NET_CONFIG_BYTES];
static mut NET_CONFIG_REPLY_BUF: [u8; MAX_NET_CONFIG_BYTES] = [0u8; MAX_NET_CONFIG_BYTES];

/// Send a `NetConfigRequest` and wait for a `NetConfigResponse`.
///
/// Mirrors [`fs_request`] exactly: encode → `IpcSend` → bounded poll of the
/// reply channel. Returns `None` on any encode/send/timeout/decode failure —
/// never blocks indefinitely (matches the existing `ncfs` bounded-retry
/// philosophy).
fn net_config_request(req: &NetConfigRequest) -> Option<NetConfigResponse> {
    // SAFETY: single-threaded; the statics are only accessed here.
    let req_ch = unsafe { *core::ptr::addr_of!(NET_CONFIG_REQ_CH) };
    let reply_ch = unsafe { *core::ptr::addr_of!(NET_CONFIG_REPLY_CH) };

    if req_ch == 0 || reply_ch == 0 {
        return None;
    }

    // SAFETY: NET_CONFIG_REQ_BUF is a static BSS buffer; single-threaded access.
    let encoded_len = {
        let req_buf: &mut [u8; MAX_NET_CONFIG_BYTES] =
            unsafe { &mut *core::ptr::addr_of_mut!(NET_CONFIG_REQ_BUF) };
        match nexacore_types::wire::encode_into_slice(req, req_buf) {
            Ok(n) => n,
            Err(_) => {
                write("[nexacore-apps] net_config_request: encode failed\n");
                return None;
            }
        }
    };

    // SAFETY: NET_CONFIG_REQ_BUF is valid; slice bounds checked by encoded_len.
    let sent = {
        let req_buf: &[u8; MAX_NET_CONFIG_BYTES] =
            unsafe { &*core::ptr::addr_of!(NET_CONFIG_REQ_BUF) };
        sys_ipc_send(req_ch, IPC_KIND_REQUEST, &req_buf[..encoded_len])
    };

    if !sent {
        write("[nexacore-apps] net_config_request: IpcSend failed\n");
        return None;
    }

    let mut budget: u32 = FS_REPLY_POLL_BUDGET;
    loop {
        // SAFETY: NET_CONFIG_REPLY_BUF is a static BSS buffer; single-threaded.
        let reply_buf: &mut [u8; MAX_NET_CONFIG_BYTES] =
            unsafe { &mut *core::ptr::addr_of_mut!(NET_CONFIG_REPLY_BUF) };

        match sys_ipc_try_receive(reply_ch, reply_buf) {
            Some(n) => {
                let payload = &reply_buf[..n];
                return match decode_canonical::<NetConfigResponse>(payload) {
                    Ok(resp) => Some(resp),
                    Err(_) => {
                        write("[nexacore-apps] net_config_request: decode failed\n");
                        None
                    }
                };
            }
            None => {
                if budget == 0 {
                    write("[nexacore-apps] net_config_request: reply timeout\n");
                    return None;
                }
                budget = budget.saturating_sub(1);
                task_yield();
            }
        }
    }
}

/// Converts the wire [`InterfaceInfo`] into the display-oriented
/// [`InterfaceDisplay`] that `nexacore_cmd_ifconfig::format_interface`
/// consumes.
///
/// Drops `gateway`/`speed_mbps`/`rx_errors`/`tx_errors`/`rx_packets`/
/// `tx_packets` — `InterfaceDisplay` doesn't carry them (classic `ifconfig`
/// output has no gateway line either), and the errors/speed fields are
/// always `0`/unknown at the source anyway (see `handle_net_config` in
/// `omni-net-image`).
fn to_interface_display(info: &InterfaceInfo) -> InterfaceDisplay {
    InterfaceDisplay {
        name: info.name.clone(),
        mac: info.mac,
        ip: info.ip,
        netmask: info.netmask.map(nexacore_types::net::Cidr::netmask),
        link_up: info.link_up,
        rx_bytes: info.rx_bytes,
        tx_bytes: info.tx_bytes,
    }
}

/// `NetQuery` implementation backed by the network-config IPC service
/// (NCIP N6.1). Mirrors [`IpcFsQuery`] exactly.
struct IpcNetQuery;

impl nexacore_shell::netquery::NetQuery for IpcNetQuery {
    fn list_interfaces(&self) -> Result<Vec<InterfaceDisplay>, String> {
        if !net_config_available() {
            return Ok(Vec::new());
        }
        match net_config_request(&NetConfigRequest::ListInterfaces) {
            Some(NetConfigResponse::Interfaces(list)) => {
                Ok(list.iter().map(to_interface_display).collect())
            }
            Some(NetConfigResponse::Error(e)) => Err(e),
            _ => Ok(Vec::new()),
        }
    }

    fn get_interface(&self, name: &str) -> Result<InterfaceDisplay, String> {
        if !net_config_available() {
            return Err(String::from("network service unavailable"));
        }
        let req = NetConfigRequest::GetInterface {
            name: String::from(name),
        };
        match net_config_request(&req) {
            Some(NetConfigResponse::Interface(info)) => Ok(to_interface_display(&info)),
            Some(NetConfigResponse::Error(e)) => Err(e),
            _ => Err(String::from("no response from network service")),
        }
    }
}

// =============================================================================
// Window interaction constants
// =============================================================================
//
// AA typography (fonts, `ui_text`/`mono_text`, `render_status`) and the
// hardware cursor overlay (`draw_cursor`, `cursor_rect`, `shadow_padded`, …)
// moved to `crate::gfx`. Titlebar drag/hit-testing itself is no longer
// hand-rolled here (M1's `TITLEBAR_GRAB_H` strip check) — the pointer arm in
// `_start`'s input loop (Task 4) routes every pointer event through
// `nexacore_desktop_shell::router::PointerRouter`, which already knows the
// exact titlebar geometry via `frame::hit_test`.

// =============================================================================
// Wallpaper asset (WS7 desktop M2)
// =============================================================================

/// Compiled desktop wallpaper (RGB565 NXWP container, see
/// `brand/wallpapers/compiled/README.md`). ~2 MiB; decoded once at boot in
/// [`_start`] and installed via `Compositor::set_wallpaper_image`, before the
/// first `damage_all` + `present` so the very first frame shows it (rather
/// than the procedural gradient fallback).
static WALLPAPER_NXWP: &[u8] =
    include_bytes!("../../../brand/wallpapers/compiled/constellation-1280x800.nxwp");

/// Returns a short label for the window currently focused, for the menu
/// bar's left-side "focused app" text. Empty string when nothing is focused
/// (should not happen once the five windows exist, but is never a panic).
fn focused_app_name(
    focused: Option<WindowId>,
    term_win: WindowId,
    monitor_win: WindowId,
    sysinfo_win: WindowId,
    fm_win: WindowId,
    set_win: WindowId,
    chat_win: WindowId,
) -> &'static str {
    match focused {
        Some(w) if w == term_win => "Terminal",
        Some(w) if w == monitor_win => "Monitor",
        Some(w) if w == sysinfo_win => "System Info",
        Some(w) if w == fm_win => "Files",
        Some(w) if w == set_win => "Settings",
        Some(w) if w == chat_win => "NexaCore Helper",
        _ => "",
    }
}

/// Short display name for a router [`AppId`], for the menu bar's focused-app
/// label.
///
/// Mirrors [`focused_app_name`]'s `WindowId`-keyed mapping (kept there for
/// the boot label and the Tab handler, both of which key off
/// `compositor.wm`'s `WindowId`) but reads directly off the `AppId` the
/// pointer arm (Task 4) already has in hand, with no `WindowId` indirection.
fn app_display_name(app: AppId) -> &'static str {
    match app {
        AppId::Terminal => "Terminal",
        AppId::Monitor => "Monitor",
        AppId::SystemInfo => "System Info",
        AppId::Files => "Files",
        AppId::Settings => "Settings",
        AppId::Helper => "NexaCore Helper",
    }
}

/// Maps a [`nexacore_desktop_shell::dock::DockModel::standard`] tile index
/// (as returned by [`nexacore_desktop_shell::dock::tile_rects`], and thus by
/// the router's [`PointerAction::DockTile`]) to the app it launches/raises.
///
/// Standard order: `0` = Logo (launcher; inert — no window — since M3), `1` =
/// Files, `2` = Terminal, `3` = Helper, `4` = Monitor, `5` = Settings. Any
/// other index (shouldn't occur — the dock only ever holds six tiles) is
/// likewise inert.
fn dock_tile_app(index: usize) -> Option<AppId> {
    match index {
        1 => Some(AppId::Files),
        2 => Some(AppId::Terminal),
        3 => Some(AppId::Helper),
        4 => Some(AppId::Monitor),
        5 => Some(AppId::Settings),
        _ => None,
    }
}

// =============================================================================
// ELF entry point
// =============================================================================

/// ELF entry point.
///
/// Runs the TASK-23/24 five-window display daemon.  See the module-level doc for
/// the full flow (terminal REPL + system monitor + file manager + settings +
/// FS client) and exit-code table.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("[nexacore-apps] start\n");

    // ── Step 1: Read device-info from the deposit window ─────────────────────
    // SAFETY: deposit window is mapped read-only at DRIVER_CAP_DEPOSIT_VA
    // before _start runs (NCIP-013 § S5.3 step 8 / ADR-0040 D5).
    let dev_info = match unsafe { nexacore_driver_shared::device_info::read() } {
        Some(info) => info,
        None => {
            write("[nexacore-apps] no device-info in deposit window\n");
            exit(2);
        }
    };

    let input_channel_id: u64 = dev_info.bar_phys;
    let fb_width: u32 = dev_info.common_offset;
    let fb_height: u32 = dev_info.notify_offset;
    let fb_stride: u32 = dev_info.isr_offset;
    let fb_bpp: u32 = dev_info.device_offset;
    let fb_len: u32 = dev_info.mmio_len;

    write("[nexacore-apps] fb_width=");
    write_hex(u64::from(fb_width));
    write(" fb_height=");
    write_hex(u64::from(fb_height));
    write(" fb_bpp=");
    write_hex(u64::from(fb_bpp));
    write("\n");

    if fb_bpp != 4 {
        write("[nexacore-apps] fb_bpp != 4, unsupported\n");
        exit(2);
    }
    if fb_width == 0 || fb_height == 0 || fb_stride == 0 {
        write("[nexacore-apps] degenerate geometry\n");
        exit(2);
    }

    // ── Step 2: Find the Display capability token ─────────────────────────────
    // SAFETY: deposit window is mapped before _start runs (see step 1).
    let cap_bytes: &[u8] =
        match nexacore_driver_shared::caps::find_token(ACTION_TAG_DISPLAY_MAP, |_| true) {
            Some(b) => b,
            None => {
                write("[nexacore-apps] no Display cap token\n");
                exit(3);
            }
        };

    // ── Step 3: DisplayMap (79) ───────────────────────────────────────────────
    let fb_len_aligned: u64 = {
        let base = u64::from(fb_len);
        (base + 0xFFF) & !0xFFF
    };

    // SAFETY: cap_bytes is valid for the duration of the syscall.
    let (front_va, errno) = unsafe {
        syscall(
            SYS_DISPLAY_MAP,
            0,
            fb_len_aligned,
            0,
            cap_bytes.as_ptr() as u64,
            cap_bytes.len() as u64,
            0,
        )
    };

    if errno != 0 {
        write("[nexacore-apps] DisplayMap FAILED errno=");
        write_hex(errno);
        write("\n");
        #[allow(
            clippy::cast_possible_truncation,
            reason = "errno from kernel fits in u32"
        )]
        exit(40u32.saturating_add(errno as u32));
    }

    write("[nexacore-apps] DisplayMap OK front_va=");
    write_hex(front_va);
    write("\n");

    // Parse the brand OpenType faces before any window renders text.
    init_fonts();
    write("[nexacore-apps] brand fonts ready (Inter UI + IBM Plex Mono)\n");

    // ── Step 4: Compositor + five windows (mockup layout, Task 7) ──────────────

    let screen_pixels = (fb_width as usize).saturating_mul(fb_height as usize);
    let mut back = vec![0u32; screen_pixels];
    let mut compositor = Compositor::new(fb_width, fb_height);

    // Shell design tokens (mockup default theme) — drive the frame chrome,
    // the decoration shadow below, and every window's content colours.
    // `mut` since Milestone 6: the menu-bar Theme icon, the Launcher's
    // "Appearance" entry, and Settings' segmented control can all reassign
    // this at runtime (see `ChromeState::set_dark`'s call sites).
    let mut shell_tokens = ShellTokens::dark();

    // Depth: a soft drop shadow + rounded corners on every window, matching
    // the mockup's frame radius and shadow token (WS7-19 F3b; Task 7).
    // Bound to a local so the drag-damage repaint below (`shadow_padded`)
    // reuses this exact value via `effects::shadow_bounds` — no separate
    // pad constant that can drift out of sync with these numbers. `mut`
    // since Milestone 7: the same 3 theme-toggle call sites that already
    // rebuild `shell_tokens` (M6) also re-tint this shadow's colour and the
    // window border colour below, keeping `compositor.decoration` in sync
    // with the active theme.
    let mut decoration_shadow = Shadow {
        offset_y: 12,
        blur: 30,
        spread: 0,
        color: shell_tokens.window_shadow,
    };
    compositor.decoration = Some(WindowDecoration {
        radius: FRAME_RADIUS,
        shadow: decoration_shadow,
        border: Some(shell_tokens.border_default),
    });

    // Branded desktop wallpaper (WS7 desktop M2). Decoded once here, before
    // any window is created, so the `damage_all` + first `present` at the
    // end of this function paints it as the very first frame. On decode
    // failure the compositor's procedural gradient stays in effect.
    match nexacore_display::wallpaper::decode_nxwp(WALLPAPER_NXWP) {
        Some(img) => compositor.set_wallpaper_image(img),
        None => write("[nexacore-apps] wallpaper decode failed, gradient fallback\n"),
    }

    // NexaCore Helper chat window (mockup layout).
    let chat_pixel_count = (CHAT_W as usize).saturating_mul(CHAT_H as usize);
    let mut chat_pixels = vec![0u32; chat_pixel_count];
    let chat_surface = Surface::new(SurfaceId(4), CHAT_W, CHAT_H);
    let chat_win: WindowId = compositor.wm.create_window(
        CHAT_X,
        CHAT_Y,
        chat_surface,
        String::from("NexaCore Helper"),
    );

    // System Monitor window.
    let monitor_pixel_count = (MONITOR_W as usize).saturating_mul(MONITOR_H as usize);
    let mut monitor_pixels = vec![0u32; monitor_pixel_count];
    let monitor_surface = Surface::new(SurfaceId(1), MONITOR_W, MONITOR_H);
    let monitor_win: WindowId = compositor.wm.create_window(
        MONITOR_X,
        MONITOR_Y,
        monitor_surface,
        String::from("System Monitor"),
    );

    // File Manager window (mockup layout).
    let fm_pixel_count = (FM_W as usize).saturating_mul(FM_H as usize);
    let mut fm_pixels = vec![0u32; fm_pixel_count];
    let fm_surface = Surface::new(SurfaceId(2), FM_W, FM_H);
    let fm_win: WindowId =
        compositor
            .wm
            .create_window(FM_X, FM_Y, fm_surface, String::from("Files"));

    // Settings window (mockup layout).
    let set_pixel_count = (SET_W as usize).saturating_mul(SET_H as usize);
    let mut set_pixels = vec![0u32; set_pixel_count];
    let set_surface = Surface::new(SurfaceId(3), SET_W, SET_H);
    let set_win: WindowId =
        compositor
            .wm
            .create_window(SET_X, SET_Y, set_surface, String::from("Settings"));

    // System Info window (launcher-only — no dock tile, see `router::AppId`
    // and `shellsync`'s module docs). Hidden at boot like Files/Settings/Monitor.
    let sysinfo_pixel_count = (SYSINFO_W as usize).saturating_mul(SYSINFO_H as usize);
    let mut sysinfo_pixels = vec![0u32; sysinfo_pixel_count];
    let sysinfo_surface = Surface::new(SurfaceId(5), SYSINFO_W, SYSINFO_H);
    let sysinfo_win: WindowId = compositor.wm.create_window(
        SYSINFO_X,
        SYSINFO_Y,
        sysinfo_surface,
        String::from("System Info"),
    );

    // Terminal window — created LAST so it is focused at boot and raised to
    // the front by the WM's z-order rules, mirroring the mockup's
    // `focused:'terminal'`.
    let term_pixel_count = (TERM_W as usize).saturating_mul(TERM_H as usize);
    let mut term_pixels = vec![0u32; term_pixel_count];
    let term_surface = Surface::new(SurfaceId(0), TERM_W, TERM_H);
    let term_win: WindowId =
        compositor
            .wm
            .create_window(TERM_X, TERM_Y, term_surface, String::from("Terminal"));

    // Shell↔compositor sync (WS7 desktop parity M3, Task 3): registers the
    // five windows against the router's `AppId`s and applies the mockup's
    // boot layout (Terminal running+visible+focused; Helper running+
    // visible; Files/Settings/Monitor not-running+hidden). Hides the three
    // not-running windows on `compositor` as a side effect (see
    // `ShellSync::new`'s doc).
    let mut shell_sync = ShellSync::new(
        &mut compositor,
        term_win,
        chat_win,
        fm_win,
        monitor_win,
        set_win,
        sysinfo_win,
        decoration_shadow,
    );

    // AI status bar — the NexaCore Helper is the only window that still
    // shows this strip (Task 7 dropped it from the other four).
    let mut chat_bar = StatusBar::new();
    chat_bar.layout(Rect {
        x: 0,
        y: 0,
        w: CHAT_W,
        h: BAR_H,
    });

    // Terminal state.
    let mut term_history: Vec<String> = Vec::new();
    let mut term_input = String::new();
    let mut shell_env = {
        let mut e = nexacore_shell::env::ShellEnv::new();
        e.set("PATH", "/bin");
        e.set("HOME", "/");
        e.set("USER", "root");
        e.set("HOSTNAME", "nexacore");
        e.set("SHELL", "/bin/nexacore-apps");
        e.set("TERM", "framebuffer");
        e
    };
    let mut shell_cwd = String::from("/");

    // File Manager state.
    let mut fm_cwd = String::from("/");
    let mut fm_entries: Vec<(String, bool)> = Vec::new();
    let mut fm_sel: usize = 0;
    let mut fm_status = String::new();
    let mut fm_seq: u32 = 0;

    // Settings state.
    let mut set_endpoint_buf = String::new();
    let mut set_model = String::new();
    let mut set_status = String::new();

    // Chat state (NexaCore Helper, ADR-0046).
    let mut chat_state = ChatState::new();
    let mut chat_input = String::new();

    // ── Step 5: NetLookup("ai_status") ───────────────────────────────────────
    let mut ai_status_ch: u64 = 0;
    {
        let mut attempts: u32 = 0;
        loop {
            let (ch, err) = sys_net_lookup(b"ai_status");
            if err == 0 {
                ai_status_ch = ch;
                write("[nexacore-apps] ai_status channel=");
                write_hex(ch);
                write("\n");
                break;
            }
            attempts = attempts.saturating_add(1);
            if attempts >= AI_STATUS_LOOKUP_RETRIES {
                write("[nexacore-apps] ai_status not found\n");
                break;
            }
            task_yield();
        }
    }

    // ── Step 6: FS service channels ──────────────────────────────────────────
    resolve_fs_channels();

    // ── Step 6b: Network-config service channels (NCIP N6.1) ─────────────────
    resolve_net_config_channels();

    // ── Step 8: Initial file-manager refresh ─────────────────────────────────
    fm_refresh(&fm_cwd, &mut fm_entries, &mut fm_sel, &mut fm_status);
    write("[nexacore-apps] file manager ready\n");

    // ── Step 9: Load Settings config ─────────────────────────────────────────
    settings_load(&mut set_endpoint_buf, &mut set_model, &mut set_status);
    write("[nexacore-apps] settings ready\n");

    write("[nexacore-apps] chat ready\n");

    // ── Step 9.5: Desktop chrome — menu bar + dock (WS7 desktop M2/M3) ───────
    //
    // M3 spec boot layout: only Terminal and NexaCore Helper are running at
    // boot, so their dock tiles show the sage running indicator; Files,
    // Settings, and Monitor start not-running (opened later from the dock).
    // `shell_sync.dock_model()` reads these flags from `ShellWm` (the same
    // state `ShellSync::new` just seeded), so this is exactly
    // `DockModel::standard(false, true, true, false, false)` at boot.
    let dock_model = shell_sync.dock_model();
    let mut chrome = ChromeState::new(fb_width, fb_height, dock_model);

    // ── Step 9.6: marketing-capture seeding (AI status + System Info window) ──
    //
    // Both are part of the same staged screenshot the Helper conversation and
    // Terminal `ifconfig` transcript are seeded for (Step 11b): on the Proxmox
    // capture rig no real `BackendStatusEvent` arrives (Ollama at OLLAMA_HOST is
    // not reachable), so the AI strip would otherwise sit at `Unknown`
    // ("offline") — unacceptable for an AI-native OS's hero image. Present it as
    // online (GPU · NexyAI) from the very first frame. A genuine status event,
    // should one arrive, still takes over via the `ai_status` handler in the
    // input loop (it re-applies to `chat_bar` + `chrome`).
    chat_bar.apply(BackendStatusEvent {
        backend: BackendKind::RemoteGpu,
        healthy: true,
        degraded: false,
    });
    chrome.set_ai_state(BackendState::Gpu);

    // Open the System Info window (launcher-only, hidden at boot by
    // `ShellSync::new`) so the OS identity/telemetry card is visible in the
    // capture. `open` marks it running + visible + raised + focused; it has no
    // dock tile, so `dock_model()` (already read above) is unaffected.
    shell_sync.open(AppId::SystemInfo, &mut compositor);

    // ── Step 10: Initial render of all windows ───────────────────────────────
    //
    // Mark the whole screen dirty so the first `present` blits every pixel:
    // this lays down the branded wallpaper across the full framebuffer and
    // overwrites the bootloader/kernel console text that DisplayMap handed us
    // (otherwise the damage-driven compositor only touches the window rects and
    // the stale text shows through the gaps between windows). Because the
    // whole screen is dirty, the chrome pass inside the first `present` below
    // also paints the menu bar and dock for the very first frame.
    compositor.damage_all();
    let boot_focus = compositor.wm.focused();
    chrome.set_focused_app(focused_app_name(
        boot_focus,
        term_win,
        monitor_win,
        sysinfo_win,
        fm_win,
        set_win,
        chat_win,
    ));
    render_terminal(
        &term_history,
        &term_input,
        &mut term_pixels,
        term_win,
        &shell_tokens,
        boot_focus == Some(term_win),
        None, // no pointer event has occurred yet at boot
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
        &mut chrome,
    );
    render_monitor(
        chat_bar.state(),
        uptime_minutes_now(),
        crate::sysinfo::query_sysinfo(),
        &mut monitor_pixels,
        monitor_win,
        &shell_tokens,
        boot_focus == Some(monitor_win),
        None,
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
        &mut chrome,
    );
    render_system_info(
        crate::sysinfo::query_sysinfo(),
        uptime_minutes_now(),
        &mut sysinfo_pixels,
        sysinfo_win,
        &shell_tokens,
        boot_focus == Some(sysinfo_win),
        None,
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
        &mut chrome,
    );
    render_file_manager(
        &fm_cwd,
        &fm_entries,
        fm_sel,
        &fm_status,
        &mut fm_pixels,
        fm_win,
        &shell_tokens,
        boot_focus == Some(fm_win),
        None,
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
        &mut chrome,
    );
    render_settings(
        &set_endpoint_buf,
        &set_model,
        &set_status,
        &mut set_pixels,
        set_win,
        &shell_tokens,
        boot_focus == Some(set_win),
        None,
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
        &mut chrome,
    );
    // Terminal is created last (highest z-order, focused at boot), so the
    // chat window is rendered last here only to match its call-order slot;
    // stacking itself is driven entirely by the WM's z-order, not this order.
    render_chat(
        &chat_state,
        &chat_input,
        &chat_bar,
        &mut chat_pixels,
        chat_win,
        &shell_tokens,
        boot_focus == Some(chat_win),
        None,
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
        &mut chrome,
    );

    // Cursor + interaction state: absolute cursor position (updated by
    // Pointer events) and the pointer router (Task 4), which owns the
    // previous button mask, any in-progress titlebar drag, and the current
    // hover target internally. Paint the cursor once so it is visible before
    // the first mouse move.
    #[allow(
        clippy::cast_possible_wrap,
        reason = "framebuffer dimensions are small positive pixel counts"
    )]
    let mut cursor_x: i32 = (fb_width / 2) as i32;
    #[allow(
        clippy::cast_possible_wrap,
        reason = "framebuffer dimensions are small positive pixel counts"
    )]
    let mut cursor_y: i32 = (fb_height / 2) as i32;
    let mut router = PointerRouter::new();
    draw_cursor(front_va, cursor_x, cursor_y, fb_stride, fb_width, fb_height);

    // ── Step 11: Input loop ───────────────────────────────────────────────────

    write("[nexacore-apps] entering input loop (kbd_ch=");
    write_hex(input_channel_id);
    write(")\n");

    let mut empty_count: u32 = 0;
    // Seeded to `Gpu` to match the boot-time AI-status seed above (Step 9.6),
    // so the `ai_status` handler only reacts to a genuine *change* from that
    // presented state rather than immediately re-applying it.
    let mut last_ai_state: BackendState = BackendState::Gpu;
    let fs_query = IpcFsQuery;
    let net_query = IpcNetQuery;

    // ── Step 11b: seed demo content (marketing-screenshot capture) ───────────
    //
    // `qm sendkey` (PS/2 key injection) is not consumed by this OS on the
    // Proxmox capture rig (USB HID is still WIP — see `os-screenshots/README.md`),
    // so nothing can be "typed live" during an automated screenshot capture.
    // Both windows below are seeded programmatically at boot instead.
    {
        // Terminal: run the real `ifconfig` command (not fabricated output) —
        // wait briefly for the network service to resolve a real lease before
        // running it, so the captured transcript shows genuine interface data
        // rather than "network still initializing". Bounded: never blocks
        // indefinitely if no lease ever arrives (link-down rig, etc.).
        const IFCONFIG_SEED_RETRIES: u32 = 50_000;
        let mut attempts: u32 = 0;
        loop {
            if net_query.list_interfaces().is_ok_and(|v| !v.is_empty()) {
                break;
            }
            attempts = attempts.saturating_add(1);
            if attempts >= IFCONFIG_SEED_RETRIES {
                break;
            }
            task_yield();
        }

        let seed_prompt = String::from("nexacore$ ifconfig");
        push_history(&mut term_history, seed_prompt);
        let (_exit_code, output) = nexacore_shell::repl::process_line(
            "ifconfig",
            &mut shell_env,
            &mut shell_cwd,
            &fs_query,
            &net_query,
        );
        if !output.is_empty() {
            let text = String::from_utf8_lossy(&output);
            for line in text.split('\n') {
                if !line.is_empty() {
                    push_history(&mut term_history, String::from(line));
                }
            }
        }

        // NexaCore Helper: a scripted conversation (not a live execution
        // engine — see the final assistant turn's own wording) demonstrating
        // the AI naming the real `ifconfig` command and asking to run it on
        // the user's behalf.
        chat_state.push_user("How do I check my IP address?");
        chat_state.begin_assistant();
        chat_state.append_chunk(
            "Run `ifconfig` in the Terminal \u{2014} it lists each network \
             interface with its IPv4 address and MAC. Want me to run it for you?",
        );
        chat_state.finish_assistant(BackendState::Gpu, 340);
        chat_state.push_user("Yes, go ahead.");
        chat_state.begin_assistant();
        chat_state.append_chunk(
            "Done \u{2014} see `eth0`'s IPv4 lease and MAC in the Terminal beside \
             this window. (Scripted preview \u{2014} live on-your-behalf \
             execution isn't wired in yet.)",
        );
        chat_state.finish_assistant(BackendState::Gpu, 410);
    }

    // Re-render Terminal and Helper now that the seeding block above populated
    // their state. The initial render pass (Step 10) ran *before* seeding, so
    // it painted both windows empty; the input loop below is purely
    // event-driven and — because PS/2 key injection is not consumed on the
    // capture rig — never fires a re-render on its own. Without these two calls
    // the very first (and only) presented frame, and therefore any screenshot,
    // would show empty Terminal/Helper windows. Repaint just those two here so
    // the seeded `ifconfig` transcript and scripted conversation are on screen.
    render_terminal(
        &term_history,
        &term_input,
        &mut term_pixels,
        term_win,
        &shell_tokens,
        boot_focus == Some(term_win),
        None,
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
        &mut chrome,
    );
    render_chat(
        &chat_state,
        &chat_input,
        &chat_bar,
        &mut chat_pixels,
        chat_win,
        &shell_tokens,
        boot_focus == Some(chat_win),
        None,
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
        &mut chrome,
    );

    loop {
        // ── a) Keyboard channel ───────────────────────────────────────────────
        // SAFETY: RECV_BUF is a static BSS buffer; single-threaded.
        let recv_buf: &mut [u8; MAX_EVENT_BYTES] =
            unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };

        let kbd_got_message = match sys_ipc_try_receive(input_channel_id, recv_buf) {
            Some(n) => {
                let payload = &recv_buf[..n];
                match decode_canonical::<DisplayInputEvent>(payload) {
                    Ok(ev) => match ev {
                        DisplayInputEvent::Key { code, pressed } => {
                            if pressed {
                                let dark_before = chrome.dark;
                                handle_key(
                                    code,
                                    &mut compositor,
                                    term_win,
                                    monitor_win,
                                    sysinfo_win,
                                    fm_win,
                                    set_win,
                                    chat_win,
                                    &mut term_history,
                                    &mut term_input,
                                    &mut shell_env,
                                    &mut shell_cwd,
                                    last_ai_state,
                                    &mut fm_cwd,
                                    &mut fm_entries,
                                    &mut fm_sel,
                                    &mut fm_status,
                                    &mut fm_seq,
                                    &mut set_endpoint_buf,
                                    &set_model,
                                    &mut set_status,
                                    &mut chat_state,
                                    &mut chat_input,
                                    &chat_bar,
                                    &mut term_pixels,
                                    &mut monitor_pixels,
                                    &mut sysinfo_pixels,
                                    &mut fm_pixels,
                                    &mut set_pixels,
                                    &mut chat_pixels,
                                    &shell_tokens,
                                    &mut back,
                                    front_va,
                                    fb_width,
                                    fb_height,
                                    fb_stride,
                                    &fs_query,
                                    &net_query,
                                    &mut chrome,
                                    &mut shell_sync,
                                );
                                // The Launcher's "Appearance" entry (Enter key,
                                // inside `handle_launcher_key`) is the only
                                // keyboard path that can flip `chrome.dark`.
                                // `handle_key`/`handle_launcher_key` receive
                                // `tokens: &ShellTokens` immutably, so they
                                // cannot rebuild `shell_tokens` themselves —
                                // this before/after diff catches the flip
                                // and finishes the job: rebuild the tokens,
                                // damage the whole screen, and re-render
                                // every window with the corrected palette
                                // (mirrors the Tab-handler's and the pointer
                                // arm's identical "refresh everything" block).
                                if chrome.dark != dark_before {
                                    shell_tokens = if chrome.dark {
                                        ShellTokens::dark()
                                    } else {
                                        ShellTokens::light()
                                    };
                                    decoration_shadow.color = shell_tokens.window_shadow;
                                    compositor.decoration = Some(WindowDecoration {
                                        radius: FRAME_RADIUS,
                                        shadow: decoration_shadow,
                                        border: Some(shell_tokens.border_default),
                                    });
                                    compositor.damage_all();
                                    let now_focus = compositor.wm.focused();
                                    let term_hov = chrome.frame_hover_for(AppId::Terminal);
                                    render_terminal(
                                        &term_history,
                                        &term_input,
                                        &mut term_pixels,
                                        term_win,
                                        &shell_tokens,
                                        now_focus == Some(term_win),
                                        term_hov,
                                        &mut compositor,
                                        &mut back,
                                        front_va,
                                        fb_width,
                                        fb_height,
                                        fb_stride,
                                        &mut chrome,
                                    );
                                    let monitor_hov = chrome.frame_hover_for(AppId::Monitor);
                                    render_monitor(
                                        last_ai_state,
                                        uptime_minutes_now(),
                                        crate::sysinfo::query_sysinfo(),
                                        &mut monitor_pixels,
                                        monitor_win,
                                        &shell_tokens,
                                        now_focus == Some(monitor_win),
                                        monitor_hov,
                                        &mut compositor,
                                        &mut back,
                                        front_va,
                                        fb_width,
                                        fb_height,
                                        fb_stride,
                                        &mut chrome,
                                    );
                                    let sysinfo_hov = chrome.frame_hover_for(AppId::SystemInfo);
                                    render_system_info(
                                        crate::sysinfo::query_sysinfo(),
                                        uptime_minutes_now(),
                                        &mut sysinfo_pixels,
                                        sysinfo_win,
                                        &shell_tokens,
                                        now_focus == Some(sysinfo_win),
                                        sysinfo_hov,
                                        &mut compositor,
                                        &mut back,
                                        front_va,
                                        fb_width,
                                        fb_height,
                                        fb_stride,
                                        &mut chrome,
                                    );
                                    let fm_hov = chrome.frame_hover_for(AppId::Files);
                                    render_file_manager(
                                        &fm_cwd,
                                        &fm_entries,
                                        fm_sel,
                                        &fm_status,
                                        &mut fm_pixels,
                                        fm_win,
                                        &shell_tokens,
                                        now_focus == Some(fm_win),
                                        fm_hov,
                                        &mut compositor,
                                        &mut back,
                                        front_va,
                                        fb_width,
                                        fb_height,
                                        fb_stride,
                                        &mut chrome,
                                    );
                                    let set_hov = chrome.frame_hover_for(AppId::Settings);
                                    render_settings(
                                        &set_endpoint_buf,
                                        &set_model,
                                        &set_status,
                                        &mut set_pixels,
                                        set_win,
                                        &shell_tokens,
                                        now_focus == Some(set_win),
                                        set_hov,
                                        &mut compositor,
                                        &mut back,
                                        front_va,
                                        fb_width,
                                        fb_height,
                                        fb_stride,
                                        &mut chrome,
                                    );
                                    let chat_hov = chrome.frame_hover_for(AppId::Helper);
                                    render_chat(
                                        &chat_state,
                                        &chat_input,
                                        &chat_bar,
                                        &mut chat_pixels,
                                        chat_win,
                                        &shell_tokens,
                                        now_focus == Some(chat_win),
                                        chat_hov,
                                        &mut compositor,
                                        &mut back,
                                        front_va,
                                        fb_width,
                                        fb_height,
                                        fb_stride,
                                        &mut chrome,
                                    );
                                }
                            }
                            true
                        }
                        DisplayInputEvent::Pointer { x, y, buttons } => {
                            let nx = i32::try_from(x).unwrap_or(0);
                            let ny = i32::try_from(y).unwrap_or(0);
                            // Repair the footprint the cursor is leaving.
                            compositor.damage(cursor_rect(cursor_x, cursor_y));

                            // Snapshot this frame's geometry and route the
                            // event against the shell z-priority ladder
                            // (menu bar > dock > window frame > content >
                            // desktop). `old_hover` is captured before the
                            // call so a hover-changed window can be told
                            // apart from one that never had it.
                            let windows = shell_sync.geoms(&compositor);
                            let dock_rects = dock::tile_rects(fb_height, &chrome.dock);
                            let panel = dock::panel_rect(fb_height);
                            let old_hover = router.hover();
                            let (action, hover_changed) = router.on_pointer(
                                nx,
                                ny,
                                buttons,
                                &windows,
                                &panel,
                                &dock_rects,
                                fb_width,
                            );

                            // ── Execute the resolved action ────────────────
                            match action {
                                PointerAction::DockTile(0) => {
                                    // Logo tile opens the launcher (mockup:
                                    // `openLauncher` on the dock's first
                                    // tile) instead of resolving through
                                    // `dock_tile_app` (which returns `None`
                                    // for index 0 — see its doc comment).
                                    chrome.launcher.open();
                                    compositor.damage_all();
                                }
                                PointerAction::DockTile(idx) => {
                                    if let Some(app) = dock_tile_app(idx) {
                                        shell_sync.open(app, &mut compositor);
                                        chrome.set_dock_model(shell_sync.dock_model());
                                    }
                                }
                                PointerAction::MenuBar(Some(2)) => {
                                    // The menu bar's third right-side icon is
                                    // Search (mockup: `right_icon_rects`
                                    // order mesh/volume/search/theme — see
                                    // `menubar::right_icon_rects`'s doc
                                    // comment).
                                    chrome.launcher.open();
                                    compositor.damage_all();
                                }
                                PointerAction::MenuBar(Some(3)) => {
                                    // The menu bar's fourth right-side icon
                                    // is Theme (mockup: `right_icon_rects`
                                    // order mesh/volume/search/theme — see
                                    // `menubar::right_icon_rects`'s doc
                                    // comment). `set_dark` marks the menu
                                    // strip and dock panel dirty; rebuilding
                                    // `shell_tokens` here — before the
                                    // `state_changed` block below runs this
                                    // same iteration — means every window's
                                    // re-render and every chrome repaint
                                    // from this point on uses the new
                                    // palette.
                                    chrome.set_dark(!chrome.dark);
                                    shell_tokens = if chrome.dark {
                                        ShellTokens::dark()
                                    } else {
                                        ShellTokens::light()
                                    };
                                    decoration_shadow.color = shell_tokens.window_shadow;
                                    compositor.decoration = Some(WindowDecoration {
                                        radius: FRAME_RADIUS,
                                        shadow: decoration_shadow,
                                        border: Some(shell_tokens.border_default),
                                    });
                                    compositor.damage_all();
                                }
                                PointerAction::FrameButton(app, FrameButton::Minimize) => {
                                    shell_sync.minimize(app, &mut compositor);
                                    chrome.set_dock_model(shell_sync.dock_model());
                                }
                                PointerAction::FrameButton(app, FrameButton::Maximize) => {
                                    shell_sync.toggle_maximize(
                                        app,
                                        &mut compositor,
                                        fb_width,
                                        fb_height,
                                    );
                                }
                                PointerAction::FrameButton(app, FrameButton::Close) => {
                                    shell_sync.close(app, &mut compositor);
                                    chrome.set_dock_model(shell_sync.dock_model());
                                }
                                PointerAction::BeginDrag { app, .. } => {
                                    shell_sync.focus(app, &mut compositor);
                                }
                                PointerAction::FocusContent(app, local_x, local_y) => {
                                    shell_sync.focus(app, &mut compositor);
                                    if app == AppId::Settings {
                                        let (light_rect, dark_rect) = appearance_rects();
                                        let want_dark = if dark_rect.contains_point(local_x, local_y)
                                        {
                                            Some(true)
                                        } else if light_rect.contains_point(local_x, local_y) {
                                            Some(false)
                                        } else {
                                            None
                                        };
                                        if let Some(want_dark) = want_dark {
                                            chrome.set_dark(want_dark);
                                            shell_tokens = if want_dark {
                                                ShellTokens::dark()
                                            } else {
                                                ShellTokens::light()
                                            };
                                            decoration_shadow.color = shell_tokens.window_shadow;
                                            compositor.decoration = Some(WindowDecoration {
                                                radius: FRAME_RADIUS,
                                                shadow: decoration_shadow,
                                                border: Some(shell_tokens.border_default),
                                            });
                                            compositor.damage_all();
                                        }
                                    }
                                }
                                PointerAction::MenuBar(_)
                                | PointerAction::Desktop
                                | PointerAction::None => {}
                            }

                            // Mirror ShellWm's (possibly just-changed) focus
                            // onto the menu bar's label — covers every action
                            // above, including the refocus-a-remaining-window
                            // fallout of close/minimize.
                            if let Some(app) = shell_sync.wm.focused() {
                                chrome.set_focused_app(app_display_name(app));
                            }

                            // Every action above but MenuBar/Desktop/None can
                            // change which window is visible and/or focused
                            // (dock-open, close, minimize, maximize-toggle,
                            // and focusing on a titlebar drag/content press
                            // all call into `ShellSync`, which only mutates
                            // `ShellWm`'s and the compositor's *state* —
                            // neither repaints a window's own titlebar focus
                            // accent). Re-render all five, mirroring the Tab
                            // handler's identical "focus changed, refresh
                            // every frame" rule, so the newly (un)focused
                            // window's accent is never left stale.
                            let opens_launcher = matches!(
                                action,
                                PointerAction::DockTile(0) | PointerAction::MenuBar(Some(2))
                            );
                            let toggles_theme =
                                matches!(action, PointerAction::MenuBar(Some(3)));
                            let state_changed = opens_launcher
                                || toggles_theme
                                || !matches!(
                                    action,
                                    PointerAction::MenuBar(_)
                                        | PointerAction::Desktop
                                        | PointerAction::None
                                );
                            if state_changed {
                                let now_focus = compositor.wm.focused();
                                let term_hov = chrome.frame_hover_for(AppId::Terminal);
                                render_terminal(
                                    &term_history,
                                    &term_input,
                                    &mut term_pixels,
                                    term_win,
                                    &shell_tokens,
                                    now_focus == Some(term_win),
                                    term_hov,
                                    &mut compositor,
                                    &mut back,
                                    front_va,
                                    fb_width,
                                    fb_height,
                                    fb_stride,
                                    &mut chrome,
                                );
                                let monitor_hov = chrome.frame_hover_for(AppId::Monitor);
                                render_monitor(
                                    last_ai_state,
                                    uptime_minutes_now(),
                                    crate::sysinfo::query_sysinfo(),
                                    &mut monitor_pixels,
                                    monitor_win,
                                    &shell_tokens,
                                    now_focus == Some(monitor_win),
                                    monitor_hov,
                                    &mut compositor,
                                    &mut back,
                                    front_va,
                                    fb_width,
                                    fb_height,
                                    fb_stride,
                                    &mut chrome,
                                );
                                let sysinfo_hov = chrome.frame_hover_for(AppId::SystemInfo);
                                render_system_info(
                                    crate::sysinfo::query_sysinfo(),
                                    uptime_minutes_now(),
                                    &mut sysinfo_pixels,
                                    sysinfo_win,
                                    &shell_tokens,
                                    now_focus == Some(sysinfo_win),
                                    sysinfo_hov,
                                    &mut compositor,
                                    &mut back,
                                    front_va,
                                    fb_width,
                                    fb_height,
                                    fb_stride,
                                    &mut chrome,
                                );
                                let fm_hov = chrome.frame_hover_for(AppId::Files);
                                render_file_manager(
                                    &fm_cwd,
                                    &fm_entries,
                                    fm_sel,
                                    &fm_status,
                                    &mut fm_pixels,
                                    fm_win,
                                    &shell_tokens,
                                    now_focus == Some(fm_win),
                                    fm_hov,
                                    &mut compositor,
                                    &mut back,
                                    front_va,
                                    fb_width,
                                    fb_height,
                                    fb_stride,
                                    &mut chrome,
                                );
                                let set_hov = chrome.frame_hover_for(AppId::Settings);
                                render_settings(
                                    &set_endpoint_buf,
                                    &set_model,
                                    &set_status,
                                    &mut set_pixels,
                                    set_win,
                                    &shell_tokens,
                                    now_focus == Some(set_win),
                                    set_hov,
                                    &mut compositor,
                                    &mut back,
                                    front_va,
                                    fb_width,
                                    fb_height,
                                    fb_stride,
                                    &mut chrome,
                                );
                                let chat_hov = chrome.frame_hover_for(AppId::Helper);
                                render_chat(
                                    &chat_state,
                                    &chat_input,
                                    &chat_bar,
                                    &mut chat_pixels,
                                    chat_win,
                                    &shell_tokens,
                                    now_focus == Some(chat_win),
                                    chat_hov,
                                    &mut compositor,
                                    &mut back,
                                    front_va,
                                    fb_width,
                                    fb_height,
                                    fb_stride,
                                    &mut chrome,
                                );
                            }

                            // ── Drag update ─────────────────────────────────
                            // Damage the old shadow+window footprint, move,
                            // then damage the new one — the shadow band
                            // extends past the window, so a tight
                            // window-only damage would leave a shadow trail.
                            if let Some((app, tx, ty)) = router.drag_target(nx, ny) {
                                let id = shell_sync.window_id(app);
                                if let Some(win) = compositor.wm.window(id) {
                                    compositor.damage(shadow_padded(
                                        win.screen_rect(),
                                        decoration_shadow,
                                    ));
                                }
                                let _ = compositor.move_window(id, tx, ty);
                                shell_sync.wm.set_rect(app, tx, ty);
                                if let Some(win) = compositor.wm.window(id) {
                                    compositor.damage(shadow_padded(
                                        win.screen_rect(),
                                        decoration_shadow,
                                    ));
                                }
                            }

                            // ── Hover repaint ───────────────────────────────
                            if hover_changed {
                                let new_hover = router.hover();
                                chrome.set_dock_hover(new_hover.dock_tile);
                                chrome.set_frame_hover(new_hover.frame_button);

                                // Re-render the window that lost hover and/or
                                // the one that gained it (may be the same
                                // window moving between its own buttons,
                                // two different windows, or one side empty).
                                let mut affected: Vec<AppId> = Vec::new();
                                if let Some((app, _)) = old_hover.frame_button {
                                    affected.push(app);
                                }
                                if let Some((app, _)) = new_hover.frame_button {
                                    if !affected.contains(&app) {
                                        affected.push(app);
                                    }
                                }
                                let now_focus = compositor.wm.focused();
                                for app in affected {
                                    match app {
                                        AppId::Terminal => {
                                            let hov = chrome.frame_hover_for(AppId::Terminal);
                                            render_terminal(
                                                &term_history,
                                                &term_input,
                                                &mut term_pixels,
                                                term_win,
                                                &shell_tokens,
                                                now_focus == Some(term_win),
                                                hov,
                                                &mut compositor,
                                                &mut back,
                                                front_va,
                                                fb_width,
                                                fb_height,
                                                fb_stride,
                                                &mut chrome,
                                            );
                                        }
                                        AppId::Monitor => {
                                            let hov = chrome.frame_hover_for(AppId::Monitor);
                                            render_monitor(
                                                last_ai_state,
                                                uptime_minutes_now(),
                                                crate::sysinfo::query_sysinfo(),
                                                &mut monitor_pixels,
                                                monitor_win,
                                                &shell_tokens,
                                                now_focus == Some(monitor_win),
                                                hov,
                                                &mut compositor,
                                                &mut back,
                                                front_va,
                                                fb_width,
                                                fb_height,
                                                fb_stride,
                                                &mut chrome,
                                            );
                                        }
                                        AppId::Files => {
                                            let hov = chrome.frame_hover_for(AppId::Files);
                                            render_file_manager(
                                                &fm_cwd,
                                                &fm_entries,
                                                fm_sel,
                                                &fm_status,
                                                &mut fm_pixels,
                                                fm_win,
                                                &shell_tokens,
                                                now_focus == Some(fm_win),
                                                hov,
                                                &mut compositor,
                                                &mut back,
                                                front_va,
                                                fb_width,
                                                fb_height,
                                                fb_stride,
                                                &mut chrome,
                                            );
                                        }
                                        AppId::Settings => {
                                            let hov = chrome.frame_hover_for(AppId::Settings);
                                            render_settings(
                                                &set_endpoint_buf,
                                                &set_model,
                                                &set_status,
                                                &mut set_pixels,
                                                set_win,
                                                &shell_tokens,
                                                now_focus == Some(set_win),
                                                hov,
                                                &mut compositor,
                                                &mut back,
                                                front_va,
                                                fb_width,
                                                fb_height,
                                                fb_stride,
                                                &mut chrome,
                                            );
                                        }
                                        AppId::Helper => {
                                            let hov = chrome.frame_hover_for(AppId::Helper);
                                            render_chat(
                                                &chat_state,
                                                &chat_input,
                                                &chat_bar,
                                                &mut chat_pixels,
                                                chat_win,
                                                &shell_tokens,
                                                now_focus == Some(chat_win),
                                                hov,
                                                &mut compositor,
                                                &mut back,
                                                front_va,
                                                fb_width,
                                                fb_height,
                                                fb_stride,
                                                &mut chrome,
                                            );
                                        }
                                        AppId::SystemInfo => {
                                            let hov = chrome.frame_hover_for(AppId::SystemInfo);
                                            render_system_info(
                                                crate::sysinfo::query_sysinfo(),
                                                uptime_minutes_now(),
                                                &mut sysinfo_pixels,
                                                sysinfo_win,
                                                &shell_tokens,
                                                now_focus == Some(sysinfo_win),
                                                hov,
                                                &mut compositor,
                                                &mut back,
                                                front_va,
                                                fb_width,
                                                fb_height,
                                                fb_stride,
                                                &mut chrome,
                                            );
                                        }
                                    }
                                }
                            }

                            cursor_x = nx;
                            cursor_y = ny;
                            // Recomposite the repaired/moved/hover-repainted
                            // rects, then float the cursor above them.
                            present(
                                &mut compositor,
                                &mut back,
                                front_va,
                                fb_width,
                                fb_height,
                                fb_stride,
                                &mut chrome,
                                &shell_tokens,
                            );
                            draw_cursor(
                                front_va, cursor_x, cursor_y, fb_stride, fb_width, fb_height,
                            );
                            true
                        }
                        _ => {
                            write("[nexacore-apps] unknown input event\n");
                            true
                        }
                    },
                    Err(_) => {
                        write("[nexacore-apps] input decode error\n");
                        true
                    }
                }
            }
            None => false,
        };

        // ── b) AI status channel ──────────────────────────────────────────────
        let status_got_message = if ai_status_ch != 0 {
            // SAFETY: STATUS_BUF is a static BSS buffer; single-threaded.
            let status_buf: &mut [u8; MAX_STATUS_EVENT_BYTES] =
                unsafe { &mut *core::ptr::addr_of_mut!(STATUS_BUF) };

            match sys_ipc_try_receive(ai_status_ch, status_buf) {
                Some(n) => {
                    let payload = &status_buf[..n];
                    match decode_canonical::<BackendStatusEvent>(payload) {
                        Ok(event) => {
                            // Only the NexaCore Helper still shows the AI
                            // status strip (Task 7 dropped it elsewhere).
                            chat_bar.apply(event);
                            let new_state = chat_bar.state();
                            if new_state != last_ai_state {
                                last_ai_state = new_state;
                                chrome.set_ai_state(new_state);
                                match new_state {
                                    BackendState::Gpu => {
                                        write("[nexacore-apps] status -> GPU\n");
                                    }
                                    BackendState::CpuDegraded => {
                                        write("[nexacore-apps] status -> CPU(degraded)\n");
                                    }
                                    BackendState::Unknown => {
                                        write("[nexacore-apps] status -> Unknown\n");
                                    }
                                }
                            }
                            // Re-render all five windows (focus borders and
                            // the chat's status strip may have changed).
                            let now_focus = compositor.wm.focused();
                            let term_hov = chrome.frame_hover_for(AppId::Terminal);
                            render_terminal(
                                &term_history,
                                &term_input,
                                &mut term_pixels,
                                term_win,
                                &shell_tokens,
                                now_focus == Some(term_win),
                                term_hov,
                                &mut compositor,
                                &mut back,
                                front_va,
                                fb_width,
                                fb_height,
                                fb_stride,
                                &mut chrome,
                            );
                            let monitor_hov = chrome.frame_hover_for(AppId::Monitor);
                            render_monitor(
                                new_state,
                                uptime_minutes_now(),
                                crate::sysinfo::query_sysinfo(),
                                &mut monitor_pixels,
                                monitor_win,
                                &shell_tokens,
                                now_focus == Some(monitor_win),
                                monitor_hov,
                                &mut compositor,
                                &mut back,
                                front_va,
                                fb_width,
                                fb_height,
                                fb_stride,
                                &mut chrome,
                            );
                            let sysinfo_hov = chrome.frame_hover_for(AppId::SystemInfo);
                            render_system_info(
                                crate::sysinfo::query_sysinfo(),
                                uptime_minutes_now(),
                                &mut sysinfo_pixels,
                                sysinfo_win,
                                &shell_tokens,
                                now_focus == Some(sysinfo_win),
                                sysinfo_hov,
                                &mut compositor,
                                &mut back,
                                front_va,
                                fb_width,
                                fb_height,
                                fb_stride,
                                &mut chrome,
                            );
                            let fm_hov = chrome.frame_hover_for(AppId::Files);
                            render_file_manager(
                                &fm_cwd,
                                &fm_entries,
                                fm_sel,
                                &fm_status,
                                &mut fm_pixels,
                                fm_win,
                                &shell_tokens,
                                now_focus == Some(fm_win),
                                fm_hov,
                                &mut compositor,
                                &mut back,
                                front_va,
                                fb_width,
                                fb_height,
                                fb_stride,
                                &mut chrome,
                            );
                            let set_hov = chrome.frame_hover_for(AppId::Settings);
                            render_settings(
                                &set_endpoint_buf,
                                &set_model,
                                &set_status,
                                &mut set_pixels,
                                set_win,
                                &shell_tokens,
                                now_focus == Some(set_win),
                                set_hov,
                                &mut compositor,
                                &mut back,
                                front_va,
                                fb_width,
                                fb_height,
                                fb_stride,
                                &mut chrome,
                            );
                            let chat_hov = chrome.frame_hover_for(AppId::Helper);
                            render_chat(
                                &chat_state,
                                &chat_input,
                                &chat_bar,
                                &mut chat_pixels,
                                chat_win,
                                &shell_tokens,
                                now_focus == Some(chat_win),
                                chat_hov,
                                &mut compositor,
                                &mut back,
                                front_va,
                                fb_width,
                                fb_height,
                                fb_stride,
                                &mut chrome,
                            );
                        }
                        Err(_) => {
                            // Malformed event — silently ignore (ADR-0043 D3).
                        }
                    }
                    true
                }
                None => false,
            }
        } else {
            false
        };

        // ── c) Yield and heartbeat ────────────────────────────────────────────
        if !kbd_got_message && !status_got_message {
            task_yield();
            empty_count = empty_count.saturating_add(1);
            if empty_count >= EMPTY_POLL_LOG_INTERVAL {
                empty_count = 0;
                write("[nexacore-apps] idle heartbeat\n");
            }
        } else {
            empty_count = 0;
            // A frame was presented this tick (key/status render, or a pointer
            // event); redraw the cursor so it keeps floating above the desktop.
            draw_cursor(front_va, cursor_x, cursor_y, fb_stride, fb_width, fb_height);
        }
    }
}

// =============================================================================
// Key dispatch
// =============================================================================

/// Routes one printable/control key to the launcher, exclusively, while it
/// is open (spec: "launcher open → keyboard to launcher; otherwise →
/// focused app"). Mirrors `handle_key`'s own Tab-handler shape: mutate
/// state, `damage_all` (the launcher's decision: full-screen repaint on
/// every change), then re-render everything so `present()`'s launcher-aware
/// overlay pass actually draws the new frame.
#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
fn handle_launcher_key(
    code: u8,
    compositor: &mut Compositor,
    chrome: &mut ChromeState,
    shell_sync: &mut ShellSync,
    term_win: WindowId,
    monitor_win: WindowId,
    sysinfo_win: WindowId,
    fm_win: WindowId,
    set_win: WindowId,
    chat_win: WindowId,
    term_history: &mut Vec<String>,
    term_input: &mut String,
    last_ai_state: BackendState,
    fm_cwd: &mut String,
    fm_entries: &mut Vec<(String, bool)>,
    fm_sel: &mut usize,
    fm_status: &mut String,
    set_endpoint_buf: &mut String,
    set_model: &str,
    set_status: &mut String,
    chat_state: &mut ChatState,
    chat_input: &mut String,
    chat_bar: &StatusBar,
    term_pixels: &mut [u32],
    monitor_pixels: &mut [u32],
    sysinfo_pixels: &mut [u32],
    fm_pixels: &mut [u32],
    set_pixels: &mut [u32],
    chat_pixels: &mut [u32],
    tokens: &ShellTokens,
    back: &mut [u32],
    front_va: u64,
    screen_w: u32,
    screen_h: u32,
    stride: u32,
) {
    match code {
        0x1B => {
            // Escape: close, no selection (mockup: `onLauncherKey` Escape branch).
            chrome.launcher.close();
            compositor.damage_all();
        }
        0x08 => {
            chrome.launcher.backspace();
            compositor.damage_all();
        }
        0x20..=0x7E => {
            chrome.launcher.push_char(code as char);
            compositor.damage_all();
        }
        0x0D => {
            // Enter: mirrors the mockup's `onLauncherKey` Enter branch — a
            // query with zero results asks the AI; otherwise the top result
            // is chosen. An empty query never reaches the zero-results
            // branch (search("") always returns up to 5 apps), matching the
            // mockup's own `if(q && res.length===0)` guard.
            let query = String::from(chrome.launcher.query());
            let results = chrome.launcher.results();
            if !query.trim().is_empty() && results.is_empty() {
                chrome.launcher.close();
                shell_sync.open(AppId::Helper, compositor);
                chrome.set_dock_model(shell_sync.dock_model());
                chat_send(
                    chat_state,
                    &query,
                    chat_bar,
                    chat_pixels,
                    chat_win,
                    tokens,
                    true,
                    chrome.frame_hover_for(AppId::Helper),
                    compositor,
                    back,
                    front_va,
                    screen_w,
                    screen_h,
                    stride,
                    chrome,
                );
            } else if let Some(entry) = results.first() {
                chrome.launcher.close();
                if entry.title == "Appearance" {
                    // Mirrors the mockup's `chooseResult`'s
                    // `item.setting === 'theme'` special case
                    // (`NexaCore-OS.dc.html:482`). The outer keyboard-event
                    // call site (below) detects this flip via a
                    // before/after `chrome.dark` diff and rebuilds
                    // `shell_tokens` + re-renders all five windows with the
                    // corrected palette — this function's own trailing
                    // re-render (further down) still runs once with the
                    // stale `tokens` first (a single harmless redundant
                    // repaint on this rare path).
                    chrome.set_dark(!chrome.dark);
                } else if let Some(app) = entry.app {
                    shell_sync.open(app, compositor);
                    chrome.set_dock_model(shell_sync.dock_model());
                    chrome.set_focused_app(app_display_name(app));
                }
                compositor.damage_all();
            } else {
                return;
            }
        }
        _ => return,
    }

    // Re-render every window (mirrors the Tab-handler's identical
    // "state may have changed, refresh everything" rule) so `present()`'s
    // launcher pass (open/closed) and any focus-accent change are both
    // reflected in the same frame.
    let now_focus = compositor.wm.focused();
    render_terminal(
        term_history,
        term_input,
        term_pixels,
        term_win,
        tokens,
        now_focus == Some(term_win),
        chrome.frame_hover_for(AppId::Terminal),
        compositor,
        back,
        front_va,
        screen_w,
        screen_h,
        stride,
        chrome,
    );
    render_monitor(
        last_ai_state,
        uptime_minutes_now(),
        crate::sysinfo::query_sysinfo(),
        monitor_pixels,
        monitor_win,
        tokens,
        now_focus == Some(monitor_win),
        chrome.frame_hover_for(AppId::Monitor),
        compositor,
        back,
        front_va,
        screen_w,
        screen_h,
        stride,
        chrome,
    );
    render_system_info(
        crate::sysinfo::query_sysinfo(),
        uptime_minutes_now(),
        sysinfo_pixels,
        sysinfo_win,
        tokens,
        now_focus == Some(sysinfo_win),
        chrome.frame_hover_for(AppId::SystemInfo),
        compositor,
        back,
        front_va,
        screen_w,
        screen_h,
        stride,
        chrome,
    );
    render_file_manager(
        fm_cwd,
        fm_entries,
        *fm_sel,
        fm_status,
        fm_pixels,
        fm_win,
        tokens,
        now_focus == Some(fm_win),
        chrome.frame_hover_for(AppId::Files),
        compositor,
        back,
        front_va,
        screen_w,
        screen_h,
        stride,
        chrome,
    );
    render_settings(
        set_endpoint_buf,
        set_model,
        set_status,
        set_pixels,
        set_win,
        tokens,
        now_focus == Some(set_win),
        chrome.frame_hover_for(AppId::Settings),
        compositor,
        back,
        front_va,
        screen_w,
        screen_h,
        stride,
        chrome,
    );
    render_chat(
        chat_state,
        chat_input,
        chat_bar,
        chat_pixels,
        chat_win,
        tokens,
        now_focus == Some(chat_win),
        chrome.frame_hover_for(AppId::Helper),
        compositor,
        back,
        front_va,
        screen_w,
        screen_h,
        stride,
        chrome,
    );
}

/// Dispatch a single key press to the focused application window.
///
/// **Tab (0x09)** cycles WM focus across all five windows (round-robin via
/// `compositor.wm.cycle_focus()`).  All five windows are re-rendered so
/// their frame's focus accent updates.
///
/// **Terminal focused** — printable → append to input; Backspace → pop;
/// Enter → run `process_line` + push history.
///
/// **Monitor focused** — no dedicated key handling; it is a read-only status
/// display (see `crate::apps::monitor`).
///
/// **File Manager focused** — Up/Down → move selection; Enter → descend
/// into directory; Backspace → parent; `n` → Mkdir; `f` → Create file;
/// `d` → Delete (shows `"dir not empty"` on `DirectoryNotEmpty`).
///
/// **Settings focused** — printable → append to endpoint buffer;
/// Backspace → pop; Esc → validate + save config.
///
/// **Chat focused** — printable → append to `chat_input` (capped at
/// [`CHAT_INPUT_CAP`]); Backspace → pop; Enter → [`chat_send`] (only when
/// `chat_input` is non-empty).
///
/// **Launcher open** — every key routes to [`handle_launcher_key`] instead
/// (spec: "launcher open → keyboard to launcher; otherwise → focused app").
///
/// Re-renders only the affected window(s) after each mutation.
#[allow(clippy::too_many_arguments)]
fn handle_key(
    code: u8,
    compositor: &mut Compositor,
    term_win: WindowId,
    monitor_win: WindowId,
    sysinfo_win: WindowId,
    fm_win: WindowId,
    set_win: WindowId,
    chat_win: WindowId,
    term_history: &mut Vec<String>,
    term_input: &mut String,
    shell_env: &mut nexacore_shell::env::ShellEnv,
    shell_cwd: &mut String,
    last_ai_state: BackendState,
    fm_cwd: &mut String,
    fm_entries: &mut Vec<(String, bool)>,
    fm_sel: &mut usize,
    fm_status: &mut String,
    fm_seq: &mut u32,
    set_endpoint_buf: &mut String,
    set_model: &str,
    set_status: &mut String,
    chat_state: &mut ChatState,
    chat_input: &mut String,
    chat_bar: &StatusBar,
    term_pixels: &mut [u32],
    monitor_pixels: &mut [u32],
    sysinfo_pixels: &mut [u32],
    fm_pixels: &mut [u32],
    set_pixels: &mut [u32],
    chat_pixels: &mut [u32],
    tokens: &ShellTokens,
    back: &mut [u32],
    front_va: u64,
    screen_w: u32,
    screen_h: u32,
    stride: u32,
    fs_query: &IpcFsQuery,
    net_query: &IpcNetQuery,
    chrome: &mut ChromeState,
    shell_sync: &mut ShellSync,
) {
    // Helper: which window is currently focused?
    let focused = compositor.wm.focused();
    let terminal_focused = focused == Some(term_win);
    let fm_focused = focused == Some(fm_win);
    let settings_focused = focused == Some(set_win);
    let chat_focused = focused == Some(chat_win);

    // Launcher open → keyboard goes to it exclusively; otherwise → focused
    // app (spec: "input routing"). See `handle_launcher_key`'s doc comment.
    if chrome.launcher.is_open() {
        handle_launcher_key(
            code,
            compositor,
            chrome,
            shell_sync,
            term_win,
            monitor_win,
            sysinfo_win,
            fm_win,
            set_win,
            chat_win,
            term_history,
            term_input,
            last_ai_state,
            fm_cwd,
            fm_entries,
            fm_sel,
            fm_status,
            set_endpoint_buf,
            set_model,
            set_status,
            chat_state,
            chat_input,
            chat_bar,
            term_pixels,
            monitor_pixels,
            sysinfo_pixels,
            fm_pixels,
            set_pixels,
            chat_pixels,
            tokens,
            back,
            front_va,
            screen_w,
            screen_h,
            stride,
        );
        return;
    }

    match code {
        // ── Tab: cycle focus across all five windows ──────────────────────────
        // The WM raises the newly-focused window to the front (z-order), so
        // the chat window is visible on top when it has focus.
        0x09 => {
            compositor.wm.cycle_focus();
            // Mirror the compositor's post-cycle focus into `ShellWm` so the
            // two halves of shell state never drift apart on a Tab press.
            // The returned `AppId` is intentionally unused here: the label
            // update below still goes through the existing WindowId-keyed
            // `focused_app_name` helper (unchanged from M2). `cycle_focus`
            // skips invisible windows and clears focus to `None` when none
            // are visible, so the compositor's post-cycle focus is always
            // one `ShellWm` also considers visible — see
            // `ShellSync::focus_from_compositor`'s doc for details.
            let _ = shell_sync.focus_from_compositor(compositor);
            // Focus changed — recompute per-window flags before re-rendering
            // so the new focus border/accent is drawn on the right window.
            let now_focus = compositor.wm.focused();
            let terminal_focused = now_focus == Some(term_win);
            let monitor_focused = now_focus == Some(monitor_win);
            let sysinfo_focused = now_focus == Some(sysinfo_win);
            let fm_focused = now_focus == Some(fm_win);
            let settings_focused = now_focus == Some(set_win);
            let chat_focused = now_focus == Some(chat_win);
            chrome.set_focused_app(focused_app_name(
                now_focus,
                term_win,
                monitor_win,
                sysinfo_win,
                fm_win,
                set_win,
                chat_win,
            ));
            // Re-render all six windows so focus borders update.
            let term_hov = chrome.frame_hover_for(AppId::Terminal);
            render_terminal(
                term_history,
                term_input,
                term_pixels,
                term_win,
                tokens,
                terminal_focused,
                term_hov,
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
            let monitor_hov = chrome.frame_hover_for(AppId::Monitor);
            render_monitor(
                last_ai_state,
                uptime_minutes_now(),
                crate::sysinfo::query_sysinfo(),
                monitor_pixels,
                monitor_win,
                tokens,
                monitor_focused,
                monitor_hov,
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
            let sysinfo_hov = chrome.frame_hover_for(AppId::SystemInfo);
            render_system_info(
                crate::sysinfo::query_sysinfo(),
                uptime_minutes_now(),
                sysinfo_pixels,
                sysinfo_win,
                tokens,
                sysinfo_focused,
                sysinfo_hov,
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
            let fm_hov = chrome.frame_hover_for(AppId::Files);
            render_file_manager(
                fm_cwd, fm_entries, *fm_sel, fm_status, fm_pixels, fm_win, tokens, fm_focused,
                fm_hov, compositor, back, front_va, screen_w, screen_h, stride, chrome,
            );
            let set_hov = chrome.frame_hover_for(AppId::Settings);
            render_settings(
                set_endpoint_buf,
                set_model,
                set_status,
                set_pixels,
                set_win,
                tokens,
                settings_focused,
                set_hov,
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
            let chat_hov = chrome.frame_hover_for(AppId::Helper);
            render_chat(
                chat_state,
                chat_input,
                chat_bar,
                chat_pixels,
                chat_win,
                tokens,
                chat_focused,
                chat_hov,
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }

        // ── Terminal keys ─────────────────────────────────────────────────────
        0x20..=0x7E if terminal_focused => {
            term_input.push(code as char);
            render_terminal(
                term_history,
                term_input,
                term_pixels,
                term_win,
                tokens,
                terminal_focused,
                chrome.frame_hover_for(AppId::Terminal),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        0x08 if terminal_focused => {
            term_input.pop();
            render_terminal(
                term_history,
                term_input,
                term_pixels,
                term_win,
                tokens,
                terminal_focused,
                chrome.frame_hover_for(AppId::Terminal),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        0x0D if terminal_focused => {
            let cmd = term_input.clone();
            let mut prompt_line = String::from("nexacore$ ");
            prompt_line.push_str(&cmd);
            push_history(term_history, prompt_line);

            let (exit_code, output) = nexacore_shell::repl::process_line(
                &cmd, shell_env, shell_cwd, fs_query, net_query,
            );

            write("[nexacore-apps] term: ");
            write(&cmd);
            write(" -> ");
            write_dec(exit_code.unsigned_abs() as usize);
            write("\n");

            if !output.is_empty() {
                let text = String::from_utf8_lossy(&output);
                for line in text.split('\n') {
                    if !line.is_empty() {
                        push_history(term_history, String::from(line));
                    }
                }
            }

            *term_input = String::new();
            render_terminal(
                term_history,
                term_input,
                term_pixels,
                term_win,
                tokens,
                terminal_focused,
                chrome.frame_hover_for(AppId::Terminal),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }

        // ── File Manager keys ─────────────────────────────────────────────────
        // Up arrow (0x80) — move selection up.
        0x80 if fm_focused => {
            if *fm_sel > 0 {
                *fm_sel -= 1;
            }
            render_file_manager(
                fm_cwd,
                fm_entries,
                *fm_sel,
                fm_status,
                fm_pixels,
                fm_win,
                tokens,
                fm_focused,
                chrome.frame_hover_for(AppId::Files),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // Down arrow (0x81) — move selection down.
        0x81 if fm_focused => {
            if !fm_entries.is_empty() && *fm_sel < fm_entries.len() - 1 {
                *fm_sel += 1;
            }
            render_file_manager(
                fm_cwd,
                fm_entries,
                *fm_sel,
                fm_status,
                fm_pixels,
                fm_win,
                tokens,
                fm_focused,
                chrome.frame_hover_for(AppId::Files),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // Enter — descend into selected directory.
        0x0D if fm_focused => {
            if let Some((name, is_dir)) = fm_entries.get(*fm_sel) {
                if *is_dir {
                    let new_cwd = path_join(fm_cwd, name);
                    *fm_cwd = new_cwd;
                    fm_refresh(fm_cwd, fm_entries, fm_sel, fm_status);
                }
            }
            render_file_manager(
                fm_cwd,
                fm_entries,
                *fm_sel,
                fm_status,
                fm_pixels,
                fm_win,
                tokens,
                fm_focused,
                chrome.frame_hover_for(AppId::Files),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // Backspace — go to parent directory.
        0x08 if fm_focused => {
            *fm_cwd = path_parent(fm_cwd);
            fm_refresh(fm_cwd, fm_entries, fm_sel, fm_status);
            render_file_manager(
                fm_cwd,
                fm_entries,
                *fm_sel,
                fm_status,
                fm_pixels,
                fm_win,
                tokens,
                fm_focused,
                chrome.frame_hover_for(AppId::Files),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // 'n' — create a new directory.
        b'n' if fm_focused => {
            let seq = *fm_seq;
            *fm_seq = fm_seq.saturating_add(1);
            let mut dir_name = String::from("dir");
            append_dec(&mut dir_name, seq as usize);
            let dir_path = path_join(fm_cwd, &dir_name);
            match fs_request(&FsRequest::Mkdir { path: dir_path }) {
                Some(FsResponse::Created) => {
                    let mut s = String::from("mkdir ");
                    s.push_str(&dir_name);
                    // Truncate status to cap.
                    if s.len() > FM_STATUS_CAP {
                        s.truncate(FM_STATUS_CAP);
                    }
                    *fm_status = s;
                }
                Some(FsResponse::Error(e)) => {
                    let mut s = errno_str(e);
                    if s.len() > FM_STATUS_CAP {
                        s.truncate(FM_STATUS_CAP);
                    }
                    *fm_status = s;
                }
                _ => {
                    *fm_status = String::from("mkdir failed");
                }
            }
            fm_refresh(fm_cwd, fm_entries, fm_sel, fm_status);
            render_file_manager(
                fm_cwd,
                fm_entries,
                *fm_sel,
                fm_status,
                fm_pixels,
                fm_win,
                tokens,
                fm_focused,
                chrome.frame_hover_for(AppId::Files),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // 'f' — create a new file.
        b'f' if fm_focused => {
            let seq = *fm_seq;
            *fm_seq = fm_seq.saturating_add(1);
            let mut file_name = String::from("file");
            append_dec(&mut file_name, seq as usize);
            file_name.push_str(".txt");
            let file_path = path_join(fm_cwd, &file_name);
            match fs_request(&FsRequest::Create { path: file_path }) {
                Some(FsResponse::Created) => {
                    let mut s = String::from("created ");
                    s.push_str(&file_name);
                    if s.len() > FM_STATUS_CAP {
                        s.truncate(FM_STATUS_CAP);
                    }
                    *fm_status = s;
                }
                Some(FsResponse::Error(e)) => {
                    let mut s = errno_str(e);
                    if s.len() > FM_STATUS_CAP {
                        s.truncate(FM_STATUS_CAP);
                    }
                    *fm_status = s;
                }
                _ => {
                    *fm_status = String::from("create failed");
                }
            }
            fm_refresh(fm_cwd, fm_entries, fm_sel, fm_status);
            render_file_manager(
                fm_cwd,
                fm_entries,
                *fm_sel,
                fm_status,
                fm_pixels,
                fm_win,
                tokens,
                fm_focused,
                chrome.frame_hover_for(AppId::Files),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // 'd' — delete selected entry.
        b'd' if fm_focused => {
            if let Some((name, _is_dir)) = fm_entries.get(*fm_sel).cloned() {
                let full_path = path_join(fm_cwd, &name);
                match fs_request(&FsRequest::Delete { path: full_path }) {
                    Some(FsResponse::Ok) => {
                        *fm_status = String::from("deleted");
                    }
                    Some(FsResponse::Error(FsErrno::DirectoryNotEmpty)) => {
                        *fm_status = String::from("dir not empty");
                    }
                    Some(FsResponse::Error(e)) => {
                        let mut s = errno_str(e);
                        if s.len() > FM_STATUS_CAP {
                            s.truncate(FM_STATUS_CAP);
                        }
                        *fm_status = s;
                    }
                    _ => {
                        *fm_status = String::from("delete failed");
                    }
                }
            }
            fm_refresh(fm_cwd, fm_entries, fm_sel, fm_status);
            render_file_manager(
                fm_cwd,
                fm_entries,
                *fm_sel,
                fm_status,
                fm_pixels,
                fm_win,
                tokens,
                fm_focused,
                chrome.frame_hover_for(AppId::Files),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }

        // ── Settings keys ─────────────────────────────────────────────────────
        // Printable characters: append to endpoint buffer (capped).
        0x20..=0x7E if settings_focused => {
            if set_endpoint_buf.len() < SET_BUF_CAP {
                set_endpoint_buf.push(code as char);
            }
            render_settings(
                set_endpoint_buf,
                set_model,
                set_status,
                set_pixels,
                set_win,
                tokens,
                settings_focused,
                chrome.frame_hover_for(AppId::Settings),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // Backspace: pop from endpoint buffer.
        0x08 if settings_focused => {
            set_endpoint_buf.pop();
            render_settings(
                set_endpoint_buf,
                set_model,
                set_status,
                set_pixels,
                set_win,
                tokens,
                settings_focused,
                chrome.frame_hover_for(AppId::Settings),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // Esc: validate + save.
        0x1B if settings_focused => {
            settings_save(set_endpoint_buf, set_model, set_status);
            render_settings(
                set_endpoint_buf,
                set_model,
                set_status,
                set_pixels,
                set_win,
                tokens,
                settings_focused,
                chrome.frame_hover_for(AppId::Settings),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }

        // ── Chat keys (NexaCore Helper, ADR-0046) ────────────────────────────────
        // Printable: append to chat_input (capped at CHAT_INPUT_CAP).
        0x20..=0x7E if chat_focused => {
            if chat_input.len() < CHAT_INPUT_CAP {
                chat_input.push(code as char);
            }
            render_chat(
                chat_state,
                chat_input,
                chat_bar,
                chat_pixels,
                chat_win,
                tokens,
                chat_focused,
                chrome.frame_hover_for(AppId::Helper),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // Backspace: pop last character from chat_input.
        0x08 if chat_focused => {
            chat_input.pop();
            render_chat(
                chat_state,
                chat_input,
                chat_bar,
                chat_pixels,
                chat_win,
                tokens,
                chat_focused,
                chrome.frame_hover_for(AppId::Helper),
                compositor,
                back,
                front_va,
                screen_w,
                screen_h,
                stride,
                chrome,
            );
        }
        // Enter: send the prompt (only when chat_input is non-empty).
        0x0D if chat_focused => {
            if !chat_input.is_empty() {
                // Snapshot and clear the input before the blocking call so
                // `chat_send` can pass `chat_input_empty` to render helpers
                // and we do not alias `chat_input` after the move.
                let prompt = core::mem::take(chat_input);
                chat_send(
                    chat_state,
                    &prompt,
                    chat_bar,
                    chat_pixels,
                    chat_win,
                    tokens,
                    chat_focused,
                    chrome.frame_hover_for(AppId::Helper),
                    compositor,
                    back,
                    front_va,
                    screen_w,
                    screen_h,
                    stride,
                    chrome,
                );
                // Re-render with the now-empty input line.
                render_chat(
                    chat_state,
                    chat_input,
                    chat_bar,
                    chat_pixels,
                    chat_win,
                    tokens,
                    chat_focused,
                    chrome.frame_hover_for(AppId::Helper),
                    compositor,
                    back,
                    front_va,
                    screen_w,
                    screen_h,
                    stride,
                    chrome,
                );
            }
        }

        // ── Fall-through for unhandled codes ─────────────────────────────────
        // This arm also catches 0x20..=0x7E and 0x08/0x0D/0x1B when NO window
        // is focused (corner case at startup), and any other byte code.
        other => {
            write("[nexacore-apps] key ");
            write_hex(u64::from(other));
            write(" (no-op)\n");
        }
    }
}

/// Append the decimal representation of `val` to `s`.
pub(crate) fn append_dec(s: &mut String, mut val: usize) {
    if val == 0 {
        s.push('0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut pos = digits.len();
    while val > 0 && pos > 0 {
        pos -= 1;
        #[allow(clippy::cast_possible_truncation, reason = "digit is 0..9")]
        let d = (val % 10) as u8;
        digits[pos] = b'0' + d;
        val /= 10;
    }
    for &b in &digits[pos..] {
        s.push(b as char);
    }
}
