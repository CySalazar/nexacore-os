//! TASK-21 (DE-C6) Ring 3 `nexacore-ui` demo image with AI-backend status bar
//! (ADR-0043, closes M3).
//!
//! Extends the TASK-20 widget-UI demo (ADR-0042) with a **system status bar**
//! that shows the live AI backend state.  The status bar is rendered in a
//! reserved strip at the **top** of the window; the widget UI tree occupies the
//! area below it.
//!
//! The status bar is fed by the `ai_status` IPC channel that the runtime image
//! registers via `NetRegister (100)`.  This image looks it up at startup via
//! `NetLookup (102)` and drains it each iteration of the input loop.
//!
//! A `no_std + no_main` ELF the kernel spawns to exercise the full userspace
//! widget pipeline on the real framebuffer (VM-103 acceptance artifact).
//! Builds on the TASK-19 compositor template (`crates/nexacore-display-image`) and
//! replaces the three solid-colour test windows with a single window rendered by
//! the `nexacore-ui` widget toolkit.
//!
//! ## Daemon flow
//!
//! ```text
//! _start()
//!     1. Read VirtioDeviceInfo from the deposit window (ADR-0040 D3):
//!          bar_phys      → input_channel_id  (u64 IPC channel)
//!          common_offset → fb_width           (pixels)
//!          notify_offset → fb_height          (pixels)
//!          isr_offset    → fb_stride          (pixels / row)
//!          device_offset → fb_bpp             (bytes / pixel)
//!          mmio_len      → fb_len             (total bytes, page-aligned)
//!        Missing info → exit(2).  Require bpp == 4 → exit(2) if not.
//!
//!     2. Find the Display capability token (action tag 7).  Missing → exit(3).
//!
//!     3. DisplayMap(offset=0, len=fb_len_page_rounded, flags=0, cap) →
//!        (front_va, errno).  errno ≠ 0 → log + exit(40 + errno).
//!
//!     4. Allocate 32 MiB heap back buffer (Vec<u32>).  Construct Compositor.
//!        Create one widget window (700×460 at screen position 120,90).
//!        Allocate a 700×460 pixel surface buffer (Vec<u32>).
//!        Build Theme::nexacore() and the initial widget tree from local state:
//!          Container{Vertical}:
//!            Label   "NexaCore OS — nexacore-ui demo"
//!            TextInput{id:1, text: input_text, cursor: input_text.len()}
//!            Button{id:2, text: "Submit"}
//!            Label   status_text
//!        StatusBar::new() laid out in the top 34-pixel strip of the window.
//!        Render → commit_surface → present().
//!        Log "[nexacore-ui-demo] ready — widget UI presented".
//!
//!     5. NetLookup("ai_status"): bounded retry (200 × task_yield).
//!        On success: log channel id, set status_channel_id.
//!        On failure after all retries: log unavailable, status_channel_id = 0.
//!
//!     6. Input loop (perpetual):
//!          a. Drain keyboard channel:
//!               Printable (0x20..=0x7E) → push char to input_text → rebuild tree → render + present
//!               Backspace (0x08)        → pop char from input_text → rebuild tree → render + present
//!               Enter (0x0D)            → status = "submitted: <input>" → rebuild → render + present
//!               Tab (0x09)              → no-op (no visual focus cycle in this image)
//!               other key               → log key code, no repaint
//!               pointer event           → log coords
//!          b. Drain ai_status channel (if resolved):
//!               Some(n) → decode_canonical::<BackendStatusEvent> →
//!                 Ok(event) → bar.apply(event); re-render + present (log on state change)
//!                 Err(_)   → silently ignore (malformed event guard — ADR-0043 D3)
//!          c. task_yield() only when BOTH channels were empty this iteration.
//!          (never exits; perpetual daemon)
//! ```
//!
//! ## Status bar layout
//!
//! The window (`WIN_W × WIN_H`) is divided into:
//! - `y ∈ [0, BAR_H)` — status bar strip (full width, `BAR_H = 34` pixels).
//! - `y ∈ [BAR_H, WIN_H)` — widget content area (padded by `theme.padding`).
//!
//! The bar is rendered AFTER the widget tree each frame so it appears on top.
//!
//! ## Widget tree rebuild model
//!
//! The application keeps `input_text: String` and `status_text: String` as
//! mutable local state.  Every time these change the full widget tree is rebuilt
//! from those locals via `build_tree(input_text, status_text)` — a pure
//! constructor that allocates a new `Widget::Container`.  This avoids the need
//! to navigate or mutate the existing tree and keeps the render path a simple
//! call sequence: `build_tree → layout → render → bar.render → commit_surface → present`.
//!
//! ## Exit codes
//!
//! | Code  | Meaning |
//! |-------|---------|
//! | `0`   | Unreachable in normal operation (daemon loops indefinitely) |
//! | `1`   | Panic handler invoked |
//! | `2`   | No device-info / degenerate geometry / bpp != 4 |
//! | `3`   | No Display capability token in the deposit window |
//! | `40+` | DisplayMap syscall failed; `code - 40` is the raw kernel errno |
//! | `50`  | Canvas construction failed (internal invariant violation) |
//!
//! ## Heap note
//!
//! A 32 MiB never-freeing bump allocator backs the `alloc` crate.  Covers:
//! back buffer 1280×800 ≈ 4 MiB, one 700×460 window surface ≈ 1.3 MiB,
//! compositor internals, and the per-render String + Vec allocations for the
//! widget tree.  The bump design avoids cumulative fragmentation in a daemon
//! that rebuilds the tree on every key event.  At scale=2 the tree is small
//! (~200 bytes) so allocations per render are bounded and modest.

#![no_std]
#![no_main]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::{string::String, vec};
use core::panic::PanicInfo;

use nexacore_display::{
    DisplayError,
    compositor::Compositor,
    geometry::Rect,
    surface::{Surface, SurfaceId, WindowId},
};
use nexacore_types::{
    ai::BackendStatusEvent, display_channel::DisplayInputEvent, wire::decode_canonical,
};
use nexacore_ui::{
    canvas::Canvas,
    layout::Direction,
    status_bar::{BackendState, StatusBar},
    theme::Theme,
    widget::{Widget, WidgetId},
};

// =============================================================================
// Bump allocator (32 MiB static heap)
// =============================================================================

/// Size of the static heap backing the bump allocator (32 MiB).
///
/// Covers: back buffer 1280×800×4 ≈ 4 MiB, one 700×460 surface ≈ 1.3 MiB,
/// compositor Vec internals and damage-region allocations, widget tree allocs
/// per render (bounded by theme.spacing + text lengths), with generous
/// headroom.  32 MiB avoids the cumulative-bump-exhaustion class of bug for a
/// long-running display daemon that rebuilds the tree on every keystroke.
const HEAP_SIZE: usize = 32 * 1024 * 1024;

/// Backing storage for the bump allocator (BSS).
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// Current bump cursor (byte offset into [`HEAP`]).
///
/// Single-threaded task; no atomics required.  Accessed only through
/// `addr_of_mut!` to avoid forming references to `static mut`.
static mut HEAP_POS: usize = 0;

/// Never-freeing bump allocator.
///
/// Provides the `alloc` crate's `GlobalAlloc` contract with a static arena.
/// `dealloc` is a deliberate no-op: this is a display daemon — allocation
/// pressure comes primarily from the initial compositor setup; the main loop
/// rebuilds a small widget tree on each keystroke (bounded allocation).
struct BumpAllocator;

// SAFETY: single-threaded Ring 3 task; allocation is a bump on a static arena;
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
            // SAFETY: `aligned` is within [0, HEAP_SIZE) and `base` is the
            // start of the static HEAP array.
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
// Syscall numbers + ABI constants
// =============================================================================

/// `TaskExit (11)` — terminate the calling task.
const SYS_TASK_EXIT: u64 = 11;
/// `TaskYield (12)` — cooperatively yield the CPU.
const SYS_TASK_YIELD: u64 = 12;
/// `IpcTryReceive (24)` — non-blocking IPC receive.
const SYS_IPC_TRY_RECEIVE: u64 = 24;
/// `WriteConsole (60)` — write bytes to the kernel console (COM1).
const SYS_WRITE_CONSOLE: u64 = 60;
/// `DisplayMap (79)` — map the framebuffer into the caller's address space,
/// capability-gated (ADR-0040 D2).
///
/// ABI: `rdi=offset` (4 KiB-aligned), `rsi=len` (4 KiB-aligned,
/// `offset+len ≤ fb_len`), `rdx=flags` (=0), `r10=cap_ptr`, `r8=cap_len` →
/// `rax=user_va`, `rdx=errno`.
const SYS_DISPLAY_MAP: u64 = 79;
/// `NetLookup (102)` — look up a named IPC channel registered via `NetRegister (100)`.
///
/// ABI: `rdi=name_ptr`, `rsi=name_len` → `rax=channel_id`, `rdx=errno`.
/// `errno == 0` means the channel was found; any non-zero value means it has
/// not been registered yet (transient) or does not exist (permanent).
/// The runtime registers `ai_status` slightly after boot; callers must use a
/// bounded retry loop with `task_yield()` between attempts (ADR-0043 D1).
const SYS_NET_LOOKUP: u64 = 102;

/// Deposit-window action tag for the Display capability (ADR-0040 D3).
/// Must match `ACTION_TAG_DISPLAY_MAP` in the kernel's `cap_deposit.rs`.
const ACTION_TAG_DISPLAY_MAP: u32 = 7;

/// `SYSCALL_ERROR` sentinel: `u64::MAX` returned in `rax` by single-value
/// syscalls on error (e.g. `IpcTryReceive` returning empty / on error).
const SYSCALL_ERROR: u64 = u64::MAX;

/// Number of empty-queue polls before the loop body logs a periodic heartbeat.
/// 200_000 iterations at one `task_yield` per iteration is several seconds
/// on a lightly loaded VM; the display daemon does NOT exit, it just logs.
const EMPTY_POLL_LOG_INTERVAL: u32 = 200_000;

/// Maximum number of characters the TextInput accumulates.
///
/// Bounds the status-line length and prevents bump-heap exhaustion from
/// a runaway key sequence.  At scale=2 this is 30 × 16 px = 480 px of text,
/// which fits inside the 700 px window with padding.
const MAX_INPUT_LEN: usize = 30;

/// Widget window geometry: width in pixels.
const WIN_W: u32 = 700;
/// Widget window geometry: height in pixels.
const WIN_H: u32 = 460;
/// Widget window position: x offset on screen.
const WIN_X: i32 = 120;
/// Widget window position: y offset on screen.
const WIN_Y: i32 = 90;

/// Height of the status bar strip at the top of the window (pixels).
///
/// The status bar occupies `y ∈ [0, BAR_H)` of the window surface.
/// The widget content area starts at `y = BAR_H` and extends to `WIN_H`.
const BAR_H: u32 = 34;

/// Maximum retry count for `NetLookup("ai_status")` at startup.
///
/// The runtime image registers the `ai_status` channel slightly after boot.
/// Each retry issues one `task_yield()` before the next attempt.  200 yields
/// is generous headroom for any scheduler tick budget.
const AI_STATUS_LOOKUP_RETRIES: u32 = 200;

// =============================================================================
// Syscall stubs — full-clobber, ADR-0035
// =============================================================================

/// Issue a two-register-return syscall with ALL argument registers declared
/// as clobbered (ADR-0035 lesson).
///
/// The kernel's syscall entry shuffles `rdi/rsi/rdx/r10/r8/r9` and returns
/// `(rax, rdx)` WITHOUT restoring any argument register.  A minimal stub
/// that only clobbers `rcx/r11` lets the compiler keep live values in the
/// argument registers across a `TaskYield`, which is the exact systemic bug
/// documented in ADR-0035.  The generic 6-argument form is used for ALL
/// syscalls — including `TaskYield` — to guarantee the full clobber set
/// regardless of the number of arguments actually consumed by the syscall.
///
/// # Safety
///
/// Pointer arguments must be valid for the duration of the call.  The caller
/// is responsible for upholding the platform ABI.
#[inline(always)]
unsafe fn syscall(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> (u64, u64) {
    let rax: u64;
    let rdx: u64;
    // SAFETY: canonical Ring 3 → Ring 0 transition; caller upholds pointer
    // validity; ALL argument registers (rdi, rsi, rdx, r10, r8, r9) are
    // declared `inout(…) => _` so the compiler treats them as clobbered after
    // the syscall, preventing the use-after-syscall register aliasing documented
    // in ADR-0035.  `rcx` and `r11` are clobbered by SYSCALL per the AMD64
    // specification; `nostack` holds because the kernel does not touch our stack.
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

/// Write a UTF-8 string to the kernel console (best-effort; errors are silently
/// ignored — a console write failing must never abort the compositor).
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
/// Used for printing numeric diagnostics (VAs, errno values, geometry fields)
/// in contexts where formatting infrastructure is unavailable.
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

/// Writes a static description of a [`DisplayError`] to the kernel console.
///
/// Each variant maps to a short, fixed ASCII string that identifies the failure.
fn write_display_error(e: &DisplayError) {
    match e {
        DisplayError::InvalidSize => write("InvalidSize"),
        DisplayError::UnknownWindow(id) => {
            write("UnknownWindow(");
            write_hex(u64::from(id.0));
            write(")");
        }
        DisplayError::BackBufferTooSmall => write("BackBufferTooSmall"),
        // Non-exhaustive: emit a generic label for future variants.
        _ => write("DisplayError(unknown)"),
    }
}

// =============================================================================
// Task helpers
// =============================================================================

/// Cooperatively yield the CPU to the next runnable task.
///
/// Uses the full-clobber stub (ADR-0035): the kernel's syscall entry shuffles
/// all argument registers; a minimal stub would allow the compiler to keep live
/// values in registers the kernel just destroyed.
fn task_yield() {
    // SAFETY: TaskYield takes no arguments; all zeros for unused slots.
    // Full clobber set is declared by the generic stub (ADR-0035).
    let _ = unsafe { syscall(SYS_TASK_YIELD, 0, 0, 0, 0, 0, 0) };
}

/// Terminate the calling task with the given exit `code`.  Never returns.
fn exit(code: u32) -> ! {
    // SAFETY: TaskExit terminates the task unconditionally; `noreturn` informs
    // the compiler this path diverges.
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
// IPC helper
// =============================================================================

/// Non-blocking IPC receive: returns `Some(n)` bytes written into `buf` on
/// success, `None` when the queue is empty.
///
/// Corresponds to `IpcTryReceive (24)`.  A return of `None` means "no message
/// available right now"; the caller should `task_yield()` and retry.
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
        // SAFETY: rax is the byte count written by the kernel; it is bounded
        // by buf.len() which fits in usize on x86_64.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "kernel copies at most buf.len() ≤ usize::MAX bytes"
        )]
        Some(rax as usize)
    }
}

/// Look up a named IPC channel by name via `NetLookup (102)`.
///
/// Returns `(channel_id, errno)`.  `errno == 0` indicates a successful
/// lookup; any non-zero value means the channel has not been registered yet
/// or does not exist.
///
/// The caller must use a bounded retry loop when looking up channels
/// registered by peer tasks that start slightly later (e.g. `ai_status`).
///
/// # Example
///
/// ```ignore
/// // The runtime registers "ai_status" slightly after boot; retry.
/// let (chan, errno) = sys_net_lookup(b"ai_status");
/// if errno == 0 {
///     // chan is the IPC channel id
/// }
/// ```
fn sys_net_lookup(name: &[u8]) -> (u64, u64) {
    // SAFETY: `name` is a valid byte slice for the duration of the syscall.
    // The kernel reads `name_len` bytes from `name_ptr` to resolve the name.
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

// =============================================================================
// Panic handler
// =============================================================================

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    write("[nexacore-ui-demo] PANIC\n");
    exit(1)
}

// =============================================================================
// BSS receive buffers
// =============================================================================

/// Maximum wire size of a single `DisplayInputEvent` (conservative bound).
const MAX_EVENT_BYTES: usize = 32;

/// Receive buffer for IPC messages from the input channel.
///
/// Declared as `static mut` so it lives in BSS, not on the 4 KiB user stack.
/// Accessed only from `_start` (single-threaded) via `addr_of_mut!`.
static mut RECV_BUF: [u8; MAX_EVENT_BYTES] = [0u8; MAX_EVENT_BYTES];

/// Maximum wire size of a single `BackendStatusEvent`.
///
/// `BackendStatusEvent` serialises to 3 bytes under postcard (1-byte
/// discriminant for `BackendKind`, 1-byte bool `healthy`, 1-byte bool
/// `degraded`).  64 bytes is generous headroom for any future extension of
/// the type without modifying this image (ADR-0043 D1).
const MAX_STATUS_EVENT_BYTES: usize = 64;

/// Receive buffer for IPC messages from the `ai_status` channel.
///
/// Kept in BSS (static) rather than on the 4 KiB user stack to ensure
/// availability throughout the daemon lifetime regardless of stack pressure.
/// Accessed only from `_start` (single-threaded) via `addr_of_mut!`.
static mut STATUS_BUF: [u8; MAX_STATUS_EVENT_BYTES] = [0u8; MAX_STATUS_EVENT_BYTES];

// =============================================================================
// Present helper
// =============================================================================

/// Composites the back buffer and blits the dirty rects to the framebuffer.
///
/// Each dirty `Rect` is copied row-by-row from the back buffer (which is
/// `screen_w` pixels wide, no padding) to the framebuffer front at
/// `front_va + (y * stride + x) * 4`.  The stride accounts for the hardware
/// scanline pitch (which may be wider than the logical pixel width).
///
/// # Safety
///
/// `front_va` must be the kernel-assigned framebuffer mapping VA returned by
/// `DisplayMap`, valid and writable for at least `stride * screen_h * 4` bytes.
fn present(
    compositor: &mut Compositor,
    back: &mut [u32],
    front_va: u64,
    screen_w: u32,
    screen_h: u32,
    stride: u32,
) {
    let dirty = match compositor.composite(back) {
        Ok(d) => d,
        Err(e) => {
            write("[nexacore-ui-demo] composite error: ");
            write_display_error(&e);
            write("\n");
            return;
        }
    };

    let n = dirty.len();
    let screen_w_usize = screen_w as usize;
    let screen_h_usize = screen_h as usize;
    let stride_usize = stride as usize;

    for dr in &dirty {
        #[allow(clippy::cast_sign_loss, reason = "compositor ensures x,y >= 0")]
        let x0 = (dr.x as u32) as usize;
        #[allow(clippy::cast_sign_loss, reason = "compositor ensures x,y >= 0")]
        let y0 = (dr.y as u32) as usize;
        let x1 = (x0 + dr.w as usize).min(screen_w_usize);
        let y1 = (y0 + dr.h as usize).min(screen_h_usize);

        let mut y = y0;
        while y < y1 {
            let back_row_start = y * screen_w_usize + x0;
            let back_row_end = y * screen_w_usize + x1;
            let front_row_start = y * stride_usize + x0;
            let px_count = x1.saturating_sub(x0);
            if px_count == 0 {
                y += 1;
                continue;
            }
            let Some(src_slice) = back.get(back_row_start..back_row_end) else {
                y += 1;
                continue;
            };
            // SAFETY: front_va is the kernel-assigned framebuffer VA, valid
            // for stride * screen_h * 4 bytes.  front_row_start + px_count
            // ≤ stride * screen_h (x1 ≤ screen_w ≤ stride, y < screen_h).
            // write_volatile prevents the compiler from eliding stores
            // (the GPU scanout hardware reads directly from this mapping).
            unsafe {
                let dst_base: *mut u32 = (front_va as *mut u32).add(front_row_start);
                let mut i = 0usize;
                while i < px_count {
                    // SAFETY: i < px_count ≤ stride (fits in the mapping).
                    core::ptr::write_volatile(dst_base.add(i), src_slice[i]);
                    i += 1;
                }
            }
            y += 1;
        }
    }

    write("[nexacore-ui-demo] composited ");
    write_hex(n as u64);
    write(" dirty rects\n");
}

// =============================================================================
// Widget tree constructor
// =============================================================================

/// Builds the widget tree for the demo window from mutable local state.
///
/// Returns a fresh `Widget::Container{Vertical}` containing:
/// 1. A title `Label` with the NexaCore OS demo header.
/// 2. A `TextInput{id:1}` showing the current `input_text` and cursor at end.
/// 3. A `Button{id:2}` labelled "Submit".
/// 4. A `Label` showing `status_text`.
///
/// The tree is rebuilt on every mutation of `input_text` or `status_text`
/// (the "rebuild-tree-from-locals" model).  Each call allocates a small,
/// bounded set of `String` and `Vec` values on the bump heap.
///
/// # Widget ids
///
/// - `WidgetId(1)` — `TextInput` (keyboard target in this demo).
/// - `WidgetId(2)` — `Button` "Submit" (activated by Enter key in this demo).
fn build_tree(input_text: &str, status_text: &str) -> Widget {
    let zero = Rect {
        x: 0,
        y: 0,
        w: 0,
        h: 0,
    };

    Widget::Container {
        direction: Direction::Vertical,
        children: alloc::vec![
            // Title label — brand heading text.
            Widget::Label {
                text: String::from("NexaCore OS -- nexacore-ui demo"),
                rect: zero,
            },
            // Text input field — echoes typed characters.
            Widget::TextInput {
                id: WidgetId(1),
                text: String::from(input_text),
                // Cursor at end of text (codepoint count = char count for ASCII).
                cursor: input_text.chars().count(),
                rect: zero,
            },
            // Submit button — activated by Enter in the input loop.
            Widget::Button {
                id: WidgetId(2),
                text: String::from("Submit"),
                rect: zero,
            },
            // Status label — shows "type something, then Enter" or submission.
            Widget::Label {
                text: String::from(status_text),
                rect: zero,
            },
        ],
        rect: zero,
    }
}

// =============================================================================
// Render helper
// =============================================================================

/// Renders the widget tree and the AI status bar into `win_pixels`, commits to
/// the compositor, and presents the result.
///
/// The window surface is divided into two vertical regions:
/// - `y ∈ [0, BAR_H)` — AI status bar strip (always-visible, full width).
/// - `y ∈ [BAR_H, WIN_H)` — widget content area (padded by `theme.padding`).
///
/// Drawing order within the canvas:
/// 1. `canvas.fill(theme.bg_surface)` — fills the entire window surface.
/// 2. `tree.layout(content_rect, theme)` — assigns concrete rects to the
///    widget tree within the content area below the bar.
/// 3. `tree.render(&mut canvas, theme)` — paints widgets into the canvas.
/// 4. `bar.render(&mut canvas, theme)` — paints the status bar on top
///    of the bar strip (step 4 is last so the bar is never occluded by widgets).
/// 5. `commit_surface` + `present()` — compositor + blit.
///
/// On `Canvas::new` failure (should never happen if `win_pixels.len() == w*h`),
/// logs and exits with code 50; the last frame remains on screen.
///
/// # Parameters
///
/// * `tree`       — widget tree to layout and render (mutated in place for rects).
/// * `bar`        — AI status bar widget to render in the top strip.
/// * `win_pixels` — pixel buffer for the window surface, `w * h` u32 pixels.
/// * `w`, `h`    — window dimensions in pixels.
/// * `win_id`    — compositor `WindowId` for this window.
/// * `theme`     — brand theme (colours + spacing).
/// * `compositor`, `back`, `front_va`, `screen_w`, `screen_h`, `stride` —
///   passed through to `present()`.
#[allow(clippy::too_many_arguments)]
fn render_ui(
    tree: &mut Widget,
    bar: &StatusBar,
    win_pixels: &mut [u32],
    w: u32,
    h: u32,
    win_id: WindowId,
    theme: &Theme,
    compositor: &mut Compositor,
    back: &mut [u32],
    front_va: u64,
    screen_w: u32,
    screen_h: u32,
    stride: u32,
) {
    // Steps 1–4: paint widget tree then status bar into the canvas.
    {
        let mut canvas = match Canvas::new(win_pixels, w, h) {
            Ok(c) => c,
            Err(_) => {
                // Internal invariant violation: the buffer was allocated as w*h.
                // Log and bail without touching the compositor.
                write("[nexacore-ui-demo] Canvas::new failed -- invariant violation\n");
                exit(50);
            }
        };

        // Step 1: Brand surface background: petrol fills the entire window.
        canvas.fill(theme.bg_surface);

        // Step 2–3: Layout and render the widget tree in the content area.
        // The content area is the window below the status bar strip, inset by
        // the brand padding on all sides.
        let padding = theme.padding;
        // BAR_H is always < WIN_H; the saturating_sub is defensive.
        let content_y_start = BAR_H.saturating_add(padding);
        let content_h = h.saturating_sub(BAR_H).saturating_sub(2 * padding);
        #[allow(clippy::cast_possible_wrap, reason = "padding fits in i32")]
        let content_rect = Rect {
            x: padding as i32,
            y: content_y_start as i32,
            w: w.saturating_sub(2 * padding),
            h: content_h,
        };
        tree.layout(content_rect, theme);

        // Render all widgets into the canvas.
        tree.render(&mut canvas, theme);

        // Step 4: Render the status bar on top of the bar strip.
        // Rendered AFTER the widget tree so it is never occluded.
        bar.render(&mut canvas, theme);
    }
    // Canvas borrow dropped here; win_pixels is free for commit_surface.

    // Step 5: commit the window pixel buffer to the compositor.
    if let Err(e) = compositor.commit_surface(win_id, win_pixels, &[]) {
        write("[nexacore-ui-demo] commit_surface failed: ");
        write_display_error(&e);
        write("\n");
    }

    // Step 6: composite + blit to hardware.
    present(compositor, back, front_va, screen_w, screen_h, stride);
}

// =============================================================================
// ELF entry point
// =============================================================================

/// ELF entry point.
///
/// Runs the TASK-21 widget-UI + AI status bar demo daemon.  See the
/// module-level doc for the full flow and exit-code table.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("[nexacore-ui-demo] start\n");

    // ── Step 1: Read device-info from the deposit window ─────────────────────
    //
    // Fields are overloaded to carry display parameters (ADR-0040 D3):
    //   bar_phys       → input_channel_id
    //   common_offset  → fb_width  (pixels)
    //   notify_offset  → fb_height (pixels)
    //   isr_offset     → fb_stride (pixels / row)
    //   device_offset  → fb_bpp    (bytes / pixel)
    //   mmio_len       → fb_len    (total bytes, page-rounded)
    //
    // SAFETY: `device_info::read()` requires that the deposit window is mapped
    // read-only at `DRIVER_CAP_DEPOSIT_VA` before `_start` runs.  Guaranteed
    // by NCIP-013 § S5.3 step 8 / ADR-0040 D5.
    let dev_info = match unsafe { nexacore_driver_shared::device_info::read() } {
        Some(info) => info,
        None => {
            write("[nexacore-ui-demo] no device-info in deposit window\n");
            exit(2);
        }
    };

    let input_channel_id: u64 = dev_info.bar_phys;
    let fb_width: u32 = dev_info.common_offset;
    let fb_height: u32 = dev_info.notify_offset;
    let fb_stride: u32 = dev_info.isr_offset;
    let fb_bpp: u32 = dev_info.device_offset;
    let fb_len: u32 = dev_info.mmio_len;

    write("[nexacore-ui-demo] fb_width=");
    write_hex(u64::from(fb_width));
    write(" fb_height=");
    write_hex(u64::from(fb_height));
    write(" fb_stride=");
    write_hex(u64::from(fb_stride));
    write(" fb_bpp=");
    write_hex(u64::from(fb_bpp));
    write("\n");

    if fb_bpp != 4 {
        write("[nexacore-ui-demo] fb_bpp != 4, unsupported\n");
        exit(2);
    }

    // ── Step 2: Find the Display capability token ─────────────────────────────
    //
    // SAFETY: deposit window is mapped before _start runs (see step 1).
    let cap_bytes: &[u8] =
        match nexacore_driver_shared::caps::find_token(ACTION_TAG_DISPLAY_MAP, |_| true) {
            Some(b) => b,
            None => {
                write("[nexacore-ui-demo] no Display cap token in deposit window\n");
                exit(3);
            }
        };

    write("[nexacore-ui-demo] Display cap found, len=");
    write_hex(cap_bytes.len() as u64);
    write("\n");

    // ── Step 3: DisplayMap (79) ───────────────────────────────────────────────
    let fb_len_aligned: u64 = {
        let base = u64::from(fb_len);
        (base + 0xFFF) & !0xFFF
    };

    // SAFETY: cap_bytes is a valid slice from the deposit window for the
    // duration of the syscall.
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
        write("[nexacore-ui-demo] DisplayMap FAILED errno=");
        write_hex(errno);
        write("\n");
        #[allow(
            clippy::cast_possible_truncation,
            reason = "errno from the kernel fits in u32"
        )]
        exit(40u32.saturating_add(errno as u32));
    }

    write("[nexacore-ui-demo] DisplayMap OK front_va=");
    write_hex(front_va);
    write("\n");

    if fb_width == 0 || fb_height == 0 || fb_stride == 0 {
        write("[nexacore-ui-demo] degenerate geometry, exiting\n");
        exit(2);
    }

    // ── Step 4: Back buffer + Compositor + widget window ─────────────────────

    // Allocate the ARGB back buffer.
    let screen_pixels = (fb_width as usize).saturating_mul(fb_height as usize);
    let mut back = vec![0u32; screen_pixels];

    // Construct compositor.
    let mut compositor = Compositor::new(fb_width, fb_height);

    // Allocate the window pixel buffer (owned, passed to commit_surface each render).
    let win_pixel_count = (WIN_W as usize).saturating_mul(WIN_H as usize);
    let mut win_pixels = vec![0u32; win_pixel_count];

    // Create the single widget window in the compositor.
    let surface = Surface::new(SurfaceId(0), WIN_W, WIN_H);
    let win_id: WindowId =
        compositor
            .wm
            .create_window(WIN_X, WIN_Y, surface, String::from("nexacore-ui demo"));

    // Build the brand theme.
    let theme = Theme::nexacore();

    // Build initial application state.
    let mut input_text = String::new();
    let mut status_text = String::from("type something, then Enter");

    // Build and lay out the AI status bar in the top strip of the window.
    let mut bar = StatusBar::new();
    bar.layout(Rect {
        x: 0,
        y: 0,
        w: WIN_W,
        h: BAR_H,
    });

    // Build the initial widget tree and render everything.
    let mut tree = build_tree(&input_text, &status_text);

    render_ui(
        &mut tree,
        &bar,
        &mut win_pixels,
        WIN_W,
        WIN_H,
        win_id,
        &theme,
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
    );

    write("[nexacore-ui-demo] ready -- widget UI presented\n");

    // ── Step 5: NetLookup("ai_status") — bounded retry ───────────────────────
    //
    // The runtime image registers the `ai_status` channel slightly after boot.
    // Retry up to AI_STATUS_LOOKUP_RETRIES times with a task_yield() between
    // each attempt.  On success, capture the channel id.  On failure after all
    // retries, proceed without the status channel (the bar stays in Unknown /
    // "AI: status unavailable").
    //
    // sentinel: status_channel_id = 0 means "not resolved" (channel IDs issued
    // by the kernel are always > 0, so 0 is a safe sentinel value).
    let mut status_channel_id: u64 = 0;
    {
        let mut attempts: u32 = 0;
        loop {
            let (chan, err) = sys_net_lookup(b"ai_status");
            if err == 0 {
                status_channel_id = chan;
                write("[nexacore-ui-demo] ai_status channel=");
                write_hex(chan);
                write("\n");
                break;
            }
            attempts = attempts.saturating_add(1);
            if attempts >= AI_STATUS_LOOKUP_RETRIES {
                write("[nexacore-ui-demo] ai_status not found -- status bar will show 'unavailable'\n");
                break;
            }
            task_yield();
        }
    }

    // ── Step 6: Input loop ────────────────────────────────────────────────────
    //
    // Perpetual.  Each iteration:
    //   a) Drains the keyboard input channel (highest priority).
    //   b) Drains the ai_status channel (if resolved).
    //   c) task_yield() only when BOTH channels were empty this iteration.

    write("[nexacore-ui-demo] entering input loop (channel=");
    write_hex(input_channel_id);
    write(")...\n");

    let mut empty_count: u32 = 0;
    // Track last-applied BackendState to log only on transitions (avoid
    // spamming the console with duplicate state messages).
    let mut last_state: BackendState = BackendState::Unknown;

    loop {
        // ── a) Keyboard channel ───────────────────────────────────────────────
        // SAFETY: RECV_BUF is a static BSS buffer; we hold the only reference
        // here (single-threaded).
        let recv_buf: &mut [u8; MAX_EVENT_BYTES] =
            unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };

        let kbd_got_message = match sys_ipc_try_receive(input_channel_id, recv_buf) {
            Some(n) => {
                let payload = &recv_buf[..n];
                match decode_canonical::<DisplayInputEvent>(payload) {
                    Ok(ev) => match ev {
                        DisplayInputEvent::Key { code, pressed } => {
                            if !pressed {
                                // Ignore key-release events; act only on press.
                            } else {
                                match code {
                                    // Printable ASCII: append to input_text.
                                    0x20..=0x7E => {
                                        if input_text.len() < MAX_INPUT_LEN {
                                            // code is already u8 (DisplayInputEvent::Key.code);
                                            // printable ASCII range 0x20..=0x7E maps to valid char.
                                            input_text.push(code as char);
                                        }

                                        write("[nexacore-ui-demo] input_text len=");
                                        write_hex(input_text.len() as u64);
                                        write("\n");

                                        tree = build_tree(&input_text, &status_text);
                                        render_ui(
                                            &mut tree,
                                            &bar,
                                            &mut win_pixels,
                                            WIN_W,
                                            WIN_H,
                                            win_id,
                                            &theme,
                                            &mut compositor,
                                            &mut back,
                                            front_va,
                                            fb_width,
                                            fb_height,
                                            fb_stride,
                                        );
                                    }

                                    // Backspace (0x08): remove last character.
                                    0x08 => {
                                        input_text.pop();

                                        write("[nexacore-ui-demo] input_text len=");
                                        write_hex(input_text.len() as u64);
                                        write("\n");

                                        tree = build_tree(&input_text, &status_text);
                                        render_ui(
                                            &mut tree,
                                            &bar,
                                            &mut win_pixels,
                                            WIN_W,
                                            WIN_H,
                                            win_id,
                                            &theme,
                                            &mut compositor,
                                            &mut back,
                                            front_va,
                                            fb_width,
                                            fb_height,
                                            fb_stride,
                                        );
                                    }

                                    // Enter (0x0D): set status and rebuild tree.
                                    0x0D => {
                                        // Build "submitted: <text>" bounded to a safe length.
                                        status_text = {
                                            let mut s = String::from("submitted: ");
                                            // Append up to MAX_INPUT_LEN chars to keep
                                            // the status label within the window width.
                                            for ch in input_text.chars().take(MAX_INPUT_LEN) {
                                                s.push(ch);
                                            }
                                            s
                                        };

                                        write("[nexacore-ui-demo] submitted: ");
                                        write(input_text.as_str());
                                        write("\n");

                                        tree = build_tree(&input_text, &status_text);
                                        render_ui(
                                            &mut tree,
                                            &bar,
                                            &mut win_pixels,
                                            WIN_W,
                                            WIN_H,
                                            win_id,
                                            &theme,
                                            &mut compositor,
                                            &mut back,
                                            front_va,
                                            fb_width,
                                            fb_height,
                                            fb_stride,
                                        );
                                    }

                                    // Tab (0x09): no visual focus cycle in this image.
                                    0x09 => {
                                        // Tab is acknowledged but produces no repaint.
                                        write("[nexacore-ui-demo] tab key (no-op)\n");
                                    }

                                    // Any other key: log, no repaint.
                                    other => {
                                        write("[nexacore-ui-demo] key ");
                                        write_hex(u64::from(other));
                                        write(" (no-op)\n");
                                    }
                                }
                            }
                        }

                        DisplayInputEvent::Pointer { x, y, buttons } => {
                            // Pointer events: dispatch_click to identify hit widget.
                            // In this image there is no pointer-driven action
                            // (the VM input pump forwards keyboard only), but we
                            // log the hit test result for diagnostic purposes.
                            let hit = tree.dispatch_click((x as i32, y as i32));
                            write("[nexacore-ui-demo] pointer x=");
                            write_hex(u64::from(x));
                            write(" y=");
                            write_hex(u64::from(y));
                            write(" buttons=");
                            write_hex(u64::from(buttons));
                            if let Some(id) = hit {
                                write(" hit=");
                                write_hex(u64::from(id.0));
                            } else {
                                write(" hit=none");
                            }
                            write("\n");
                        }

                        // Non-exhaustive: log unknown variants without decoding.
                        _ => {
                            write("[nexacore-ui-demo] unknown input event variant\n");
                        }
                    },
                    Err(_) => {
                        write("[nexacore-ui-demo] input event decode error (n=");
                        write_hex(n as u64);
                        write(")\n");
                    }
                }
                true
            }
            None => false,
        };

        // ── b) AI status channel (only if resolved) ───────────────────────────
        // Drain one message per iteration.  On a successful decode, apply the
        // event to the bar and re-render.  On a decode error, silently drop the
        // message — a malformed event must never crash or corrupt the bar
        // (ADR-0043 D3).
        let status_got_message = if status_channel_id != 0 {
            // SAFETY: STATUS_BUF is a static BSS buffer; we hold the only
            // reference here (single-threaded).
            let status_buf: &mut [u8; MAX_STATUS_EVENT_BYTES] =
                unsafe { &mut *core::ptr::addr_of_mut!(STATUS_BUF) };

            match sys_ipc_try_receive(status_channel_id, status_buf) {
                Some(n) => {
                    let payload = &status_buf[..n];
                    match decode_canonical::<BackendStatusEvent>(payload) {
                        Ok(event) => {
                            bar.apply(event);
                            let new_state = bar.state();
                            // Log only on a genuine state transition.
                            if new_state != last_state {
                                last_state = new_state;
                                match new_state {
                                    BackendState::Gpu => {
                                        write("[nexacore-ui-demo] status -> GPU\n");
                                    }
                                    BackendState::CpuDegraded => {
                                        write("[nexacore-ui-demo] status -> CPU(degraded)\n");
                                    }
                                    BackendState::Unknown => {
                                        write("[nexacore-ui-demo] status -> Unknown\n");
                                    }
                                }
                            }
                            // Re-render with the updated bar state.
                            render_ui(
                                &mut tree,
                                &bar,
                                &mut win_pixels,
                                WIN_W,
                                WIN_H,
                                win_id,
                                &theme,
                                &mut compositor,
                                &mut back,
                                front_va,
                                fb_width,
                                fb_height,
                                fb_stride,
                            );
                        }
                        Err(_) => {
                            // Malformed / unanticipated event: silently ignore.
                            // The "decode error guard" (ADR-0043 D3) — the bar
                            // state is NOT changed; no panic, no log spam.
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
        // Only yield when both channels were empty this iteration to avoid
        // introducing latency on the keyboard path while still being
        // cooperative with the scheduler.
        if !kbd_got_message && !status_got_message {
            task_yield();
            empty_count = empty_count.saturating_add(1);

            if empty_count >= EMPTY_POLL_LOG_INTERVAL {
                empty_count = 0;
                write("[nexacore-ui-demo] idle heartbeat\n");
            }
        } else {
            // Reset the idle counter whenever we process any message.
            empty_count = 0;
        }
    }
}
