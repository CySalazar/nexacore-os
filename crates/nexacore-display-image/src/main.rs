//! TASK-19 (DE-C2/DE-C3) Ring 3 compositor + window manager bootable image
//! (ADR-0041).
//!
//! A `no_std + no_main` ELF the kernel spawns to exercise the full userspace
//! compositor pipeline on the real framebuffer (VM-103 acceptance artifact).
//! This image is the TASK-19 counterpart of `nexacore-display-probe` (TASK-18).
//!
//! ## Daemon flow
//!
//! ```text
//! _start()
//!     1. Read VirtioDeviceInfo from the deposit window (ADR-0040 D3 overloaded
//!        fields):
//!          bar_phys      → input_channel_id  (u64 IPC channel)
//!          common_offset → fb_width           (pixels)
//!          notify_offset → fb_height          (pixels)
//!          isr_offset    → fb_stride          (pixels / row)
//!          device_offset → fb_bpp             (bytes / pixel)
//!          mmio_len      → fb_len             (total bytes, page-aligned)
//!        Missing info → exit(2).  Require bpp == 4 → exit if not.
//!
//!     2. Find the Display capability token (action tag 7).  Missing → exit(3).
//!
//!     3. DisplayMap(offset=0, len=fb_len_page_rounded, flags=0, cap) →
//!        (front_va, errno).  errno ≠ 0 → log + exit(40 + errno).
//!
//!     4. Allocate 32 MiB heap back buffer (Vec<u32>).  Construct Compositor.
//!        Create three overlapping test windows:
//!          A  (100,100) 400×300  fill 0xFF3060C0 (blue) + dark top bar 24px
//!          B  (300,250) 400×300  fill 0xFF40A060 (green) + dark top bar
//!          C  (520,150) 400×300  fill 0xFFC06040 (orange) + dark top bar
//!        commit_surface each window with full-window damage.
//!        set_focus(window A).  present() → composites + blits to framebuffer.
//!
//!     5. Input loop (perpetual):
//!          Tab (0x09) → cycle_focus() + present()
//!          'c' (0x63) → destroy(focused) + present()
//!          other key  → log("[nexacore-display] key {code} -> focused {id}")
//!          empty queue → task_yield(); after 200k empty polls → keep looping
//! ```
//!
//! ## Exit codes
//!
//! | Code  | Meaning |
//! |-------|---------|
//! | `0`   | Unreachable in normal operation (daemon loops indefinitely) |
//! | `1`   | Panic handler invoked |
//! | `2`   | No device-info section in the deposit window |
//! | `3`   | No Display capability token in the deposit window |
//! | `40+` | DisplayMap syscall failed; `code - 40` is the raw kernel errno |
//!
//! ## Heap note
//!
//! A 32 MiB never-freeing bump allocator backs the `alloc` crate.  32 MiB
//! comfortably covers the 1280×800 back buffer (~4 MiB at 32 bpp), three
//! 400×300 window surfaces (~1.4 MiB each), compositor internals and Vec
//! overhead, with headroom to spare.  The bump design avoids cumulative
//! fragmentation that would affect a display daemon running indefinitely.

#![no_std]
#![no_main]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::{string::String, vec};
use core::panic::PanicInfo;

use nexacore_display::{
    DisplayError,
    compositor::Compositor,
    surface::{Surface, SurfaceId, WindowId},
};
use nexacore_types::{display_channel::DisplayInputEvent, wire::decode_canonical};

// =============================================================================
// Bump allocator (32 MiB static heap)
// =============================================================================

/// Size of the static heap backing the bump allocator (32 MiB).
///
/// Covers: back buffer 1280×800×4 ≈ 4 MiB, three 400×300 surfaces ≈ 1.4 MiB
/// each, compositor Vec internals and damage-region allocations, with generous
/// headroom.  32 MiB avoids the cumulative-bump-exhaustion class of bug for a
/// long-running display daemon.
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
/// is designed to avoid per-frame heap allocation.
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
/// Used for diagnostic logging without needing `ToString` in scope (which
/// would require the `std` `ToString` blanket impl, unavailable in `no_std`).
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

// =============================================================================
// Panic handler
// =============================================================================

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    write("[nexacore-display] PANIC\n");
    exit(1)
}

// =============================================================================
// BSS receive buffer
// =============================================================================

/// Maximum wire size of a single `DisplayInputEvent` (conservative bound from
/// `nexacore_types::display_channel::MAX_EVENT_BYTES`).
const MAX_EVENT_BYTES: usize = 32;

/// Receive buffer for IPC messages from the input channel.
///
/// Declared as `static mut` so it lives in BSS, not on the 4 KiB user stack.
/// Accessed only from `_start` (single-threaded) via `addr_of_mut!`.
static mut RECV_BUF: [u8; MAX_EVENT_BYTES] = [0u8; MAX_EVENT_BYTES];

// =============================================================================
// Window pixel helpers
// =============================================================================

/// Fills the pixel slice for a window of `w × h` pixels.
///
/// The top `title_bar_h` rows are filled with `bar_color`; the remaining rows
/// are filled with `fill_color`.  This gives each test window a visually
/// distinct title bar that makes the z-order and focus border visible on the
/// serial-captured framebuffer.
///
/// # Panics
///
/// Does not panic.  `title_bar_h` is clamped to `h` so it can never exceed
/// the pixel slice length.
fn fill_window_pixels(
    pixels: &mut [u32],
    w: u32,
    h: u32,
    fill_color: u32,
    bar_color: u32,
    title_bar_h: u32,
) {
    // Clamp title_bar_h so it never exceeds h even for tiny windows.
    let bar_rows = title_bar_h.min(h) as usize;
    let w_usize = w as usize;
    let h_usize = h as usize;
    let total = w_usize.saturating_mul(h_usize);

    if pixels.len() < total {
        // Safety guard: should never happen if caller allocates correctly, but
        // we must not panic or go out of bounds.
        return;
    }

    // Paint title bar rows.
    let bar_end = bar_rows.saturating_mul(w_usize).min(total);
    for p in pixels[..bar_end].iter_mut() {
        *p = bar_color;
    }
    // Paint body rows.
    for p in pixels[bar_end..total].iter_mut() {
        *p = fill_color;
    }
}

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
///
/// # Parameters
///
/// * `compositor` — mutable borrow of the compositor; calls `composite()`.
/// * `back`       — back buffer, exactly `screen_w * screen_h` `u32` pixels.
/// * `front_va`   — user VA of the mapped framebuffer front buffer.
/// * `screen_w`   — logical screen width in pixels.
/// * `screen_h`   — logical screen height in pixels.
/// * `stride`     — framebuffer scanline pitch in **pixels** (≥ screen_w).
///
/// Logs the number of dirty rects composited.  On `composite` error (should
/// only happen if the back buffer is too small, which we guard at setup),
/// logs and returns.
fn present(
    compositor: &mut Compositor,
    back: &mut [u32],
    front_va: u64,
    screen_w: u32,
    screen_h: u32,
    stride: u32,
) {
    // Composite the back buffer; collect dirty rects.
    let dirty = match compositor.composite(back) {
        Ok(d) => d,
        Err(e) => {
            write("[nexacore-display] composite error: ");
            write_display_error(&e);
            write("\n");
            return;
        }
    };

    let n = dirty.len();

    // Blit each dirty rect from back to front.
    let screen_w_usize = screen_w as usize;
    let screen_h_usize = screen_h as usize;
    let stride_usize = stride as usize;

    for dr in &dirty {
        // Clamp the rect to the screen bounds before blitting.
        // Both .x and .y are >= 0 (the compositor guarantees this after
        // clamping all damage to the screen).  The casts are safe.
        #[allow(clippy::cast_sign_loss, reason = "compositor ensures x,y >= 0")]
        let x0 = (dr.x as u32) as usize;
        #[allow(clippy::cast_sign_loss, reason = "compositor ensures x,y >= 0")]
        let y0 = (dr.y as u32) as usize;
        let x1 = (x0 + dr.w as usize).min(screen_w_usize);
        let y1 = (y0 + dr.h as usize).min(screen_h_usize);

        // Copy row by row.
        let mut y = y0;
        while y < y1 {
            // Back-buffer row offset: back uses screen_w (no padding).
            let back_row_start = y * screen_w_usize + x0;
            let back_row_end = y * screen_w_usize + x1;

            // Front-buffer row offset: front uses stride (hardware pitch).
            let front_row_start = y * stride_usize + x0;

            // Number of pixels to copy in this row.
            let px_count = x1.saturating_sub(x0);
            if px_count == 0 {
                y += 1;
                continue;
            }

            // Source slice from back buffer — bounds-checked.
            let Some(src_slice) = back.get(back_row_start..back_row_end) else {
                y += 1;
                continue;
            };

            // Destination: raw pointer into the front-buffer mapping.
            // Each pixel is u32 (4 bytes); the front VA is byte-addressed.
            // SAFETY: front_va is the kernel-assigned framebuffer VA, valid
            // for stride * screen_h * 4 bytes.  front_row_start + px_count
            // ≤ stride * screen_h (x1 ≤ screen_w ≤ stride, y < screen_h).
            // We use write_volatile so the compiler cannot elide the stores
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

    write("[nexacore-display] composited ");
    write_hex(n as u64);
    write(" dirty rects\n");
}

// =============================================================================
// ELF entry point
// =============================================================================

/// ELF entry point.
///
/// Runs the TASK-19 compositor daemon.  See the module-level doc for the full
/// flow and exit-code table.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("[nexacore-display] start\n");

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
    // by NCIP-013 § S5.3 step 8 / ADR-0040 D5 (kernel maps before spawning).
    let dev_info = match unsafe { nexacore_driver_shared::device_info::read() } {
        Some(info) => info,
        None => {
            write("[nexacore-display] no device-info in deposit window\n");
            exit(2);
        }
    };

    let input_channel_id: u64 = dev_info.bar_phys;
    let fb_width: u32 = dev_info.common_offset;
    let fb_height: u32 = dev_info.notify_offset;
    let fb_stride: u32 = dev_info.isr_offset;
    let fb_bpp: u32 = dev_info.device_offset;
    let fb_len: u32 = dev_info.mmio_len;

    write("[nexacore-display] input_channel_id=");
    write_hex(input_channel_id);
    write(" fb_width=");
    write_hex(u64::from(fb_width));
    write(" fb_height=");
    write_hex(u64::from(fb_height));
    write(" fb_stride=");
    write_hex(u64::from(fb_stride));
    write(" fb_bpp=");
    write_hex(u64::from(fb_bpp));
    write(" fb_len=");
    write_hex(u64::from(fb_len));
    write("\n");

    if fb_bpp != 4 {
        write("[nexacore-display] fb_bpp != 4, unsupported; exiting\n");
        exit(2);
    }

    // ── Step 2: Find the Display capability token ─────────────────────────────
    //
    // SAFETY: see step 1 — deposit window is mapped before _start runs.
    let cap_bytes: &[u8] = match nexacore_driver_shared::caps::find_token(
        ACTION_TAG_DISPLAY_MAP,
        |_| true, // accept the first Display token
    ) {
        Some(b) => b,
        None => {
            write("[nexacore-display] no Display cap token in deposit window\n");
            exit(3);
        }
    };

    write("[nexacore-display] Display cap found, len=");
    write_hex(cap_bytes.len() as u64);
    write("\n");

    // ── Step 3: DisplayMap (79) ───────────────────────────────────────────────
    //
    // Page-round fb_len up to the next 4 KiB boundary so the `len` argument
    // satisfies the kernel's alignment requirement (ADR-0040 D2).
    let fb_len_aligned: u64 = {
        let base = u64::from(fb_len);
        (base + 0xFFF) & !0xFFF
    };

    // SAFETY: cap_bytes is a valid slice from the deposit window for the
    // duration of the syscall.  offset=0, flags=0 are scalar.
    let (front_va, errno) = unsafe {
        syscall(
            SYS_DISPLAY_MAP,
            0,                         // rdi = offset (0 = map from start)
            fb_len_aligned,            // rsi = len (page-rounded)
            0,                         // rdx = flags (reserved, must be 0)
            cap_bytes.as_ptr() as u64, // r10 = cap_ptr
            cap_bytes.len() as u64,    // r8  = cap_len
            0,                         // r9  = unused
        )
    };

    if errno != 0 {
        write("[nexacore-display] DisplayMap FAILED errno=");
        write_hex(errno);
        write("\n");
        // Exit code 40 + errno (errno fits in u32 for all known kernel codes).
        #[allow(
            clippy::cast_possible_truncation,
            reason = "errno from the kernel fits in u32; POSIX codes are at most a few hundred"
        )]
        exit(40u32.saturating_add(errno as u32));
    }

    write("[nexacore-display] DisplayMap OK front_va=");
    write_hex(front_va);
    write("\n");

    // Guard against degenerate geometry.
    if fb_width == 0 || fb_height == 0 || fb_stride == 0 {
        write("[nexacore-display] degenerate geometry, exiting\n");
        exit(2);
    }

    // ── Step 4: Back buffer + Compositor + test windows ──────────────────────

    // Allocate the ARGB back buffer; compositor writes here during composite().
    let screen_pixels = (fb_width as usize).saturating_mul(fb_height as usize);
    let mut back = vec![0u32; screen_pixels];

    // Construct compositor.
    let mut compositor = Compositor::new(fb_width, fb_height);

    // Window A: blue  fill  (100,100) 400×300
    //   body fill 0xFF3060C0, title bar 0xFF1A3870 (darker shade), bar height 24
    let win_a_w: u32 = 400;
    let win_a_h: u32 = 300;
    {
        let surface_a = Surface::new(SurfaceId(0), win_a_w, win_a_h);
        let id_a = compositor
            .wm
            .create_window(100, 100, surface_a, String::from("Window A"));
        let mut pixels_a = vec![0u32; (win_a_w * win_a_h) as usize];
        fill_window_pixels(
            &mut pixels_a,
            win_a_w,
            win_a_h,
            0xFF3060C0, // blue body
            0xFF1A3870, // darker blue title bar
            24,
        );
        if let Err(e) = compositor.commit_surface(id_a, &pixels_a, &[]) {
            write("[nexacore-display] commit_surface A failed: ");
            write_display_error(&e);
            write("\n");
        }
    }
    // Snapshot id_a: it was the first window created, so its WindowId is 0.
    let id_a = WindowId(0);

    // Window B: green fill  (300,250) 400×300
    //   body fill 0xFF40A060, title bar 0xFF205030
    let win_b_w: u32 = 400;
    let win_b_h: u32 = 300;
    {
        let surface_b = Surface::new(SurfaceId(1), win_b_w, win_b_h);
        let id_b = compositor
            .wm
            .create_window(300, 250, surface_b, String::from("Window B"));
        let mut pixels_b = vec![0u32; (win_b_w * win_b_h) as usize];
        fill_window_pixels(
            &mut pixels_b,
            win_b_w,
            win_b_h,
            0xFF40A060, // green body
            0xFF205030, // darker green title bar
            24,
        );
        if let Err(e) = compositor.commit_surface(id_b, &pixels_b, &[]) {
            write("[nexacore-display] commit_surface B failed: ");
            write_display_error(&e);
            write("\n");
        }
    }

    // Window C: orange fill (520,150) 400×300
    //   body fill 0xFFC06040, title bar 0xFF703020
    let win_c_w: u32 = 400;
    let win_c_h: u32 = 300;
    {
        let surface_c = Surface::new(SurfaceId(2), win_c_w, win_c_h);
        let id_c = compositor
            .wm
            .create_window(520, 150, surface_c, String::from("Window C"));
        let mut pixels_c = vec![0u32; (win_c_w * win_c_h) as usize];
        fill_window_pixels(
            &mut pixels_c,
            win_c_w,
            win_c_h,
            0xFFC06040, // orange body
            0xFF703020, // darker orange title bar
            24,
        );
        if let Err(e) = compositor.commit_surface(id_c, &pixels_c, &[]) {
            write("[nexacore-display] commit_surface C failed: ");
            write_display_error(&e);
            write("\n");
        }
    }

    // Focus window A (the initial target; windows B and C are above in z-order
    // after creation, so we explicitly set focus to A for the acceptance test).
    if let Err(e) = compositor.set_focus(id_a) {
        write("[nexacore-display] set_focus A failed: ");
        write_display_error(&e);
        write("\n");
    }

    // Initial composite + blit: 3 windows appear on screen with A focused.
    present(
        &mut compositor,
        &mut back,
        front_va,
        fb_width,
        fb_height,
        fb_stride,
    );
    write("[nexacore-display] initial frame presented (3 windows, focus=A)\n");

    // ── Step 5: Input loop ────────────────────────────────────────────────────
    //
    // The display daemon never exits.  It drains the input channel and reacts:
    //   Tab (0x09) → cycle_focus() + present()
    //   'c' (0x63) → destroy(focused) + present()
    //   other key  → log code + focused id
    //   empty      → task_yield(); log heartbeat every EMPTY_POLL_LOG_INTERVAL

    write("[nexacore-display] entering input loop (channel=");
    write_hex(input_channel_id);
    write(")...\n");

    let mut empty_count: u32 = 0;

    loop {
        // SAFETY: RECV_BUF is a static BSS buffer; we hold the only reference
        // here (single-threaded).
        let recv_buf: &mut [u8; MAX_EVENT_BYTES] =
            unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };

        match sys_ipc_try_receive(input_channel_id, recv_buf) {
            Some(n) => {
                // Reset idle counter on any message.
                empty_count = 0;

                let payload = &recv_buf[..n];
                match decode_canonical::<DisplayInputEvent>(payload) {
                    Ok(ev) => match ev {
                        DisplayInputEvent::Key { code, pressed } => {
                            if !pressed {
                                // Ignore key-release events; act only on press.
                                continue;
                            }
                            match code {
                                // Tab (0x09): cycle focus + repaint.
                                0x09 => {
                                    compositor.cycle_focus();
                                    present(
                                        &mut compositor,
                                        &mut back,
                                        front_va,
                                        fb_width,
                                        fb_height,
                                        fb_stride,
                                    );
                                    let focused_id = compositor.wm.focused();
                                    write("[nexacore-display] focus -> ");
                                    if let Some(id) = focused_id {
                                        write_hex(u64::from(id.0));
                                    } else {
                                        write("none");
                                    }
                                    write("\n");
                                }
                                // 'c' (0x63): destroy focused window + repaint.
                                0x63 => {
                                    if let Some(fid) = compositor.wm.focused() {
                                        match compositor.destroy(fid) {
                                            Ok(()) => {
                                                present(
                                                    &mut compositor,
                                                    &mut back,
                                                    front_va,
                                                    fb_width,
                                                    fb_height,
                                                    fb_stride,
                                                );
                                                write("[nexacore-display] closed window, recomposed\n");
                                            }
                                            Err(e) => {
                                                write("[nexacore-display] destroy failed: ");
                                                write_display_error(&e);
                                                write("\n");
                                            }
                                        }
                                    } else {
                                        write("[nexacore-display] 'c' pressed but no focused window\n");
                                    }
                                }
                                // Any other key: route to focused window (log).
                                other => {
                                    let focused_id = compositor.wm.focused();
                                    write("[nexacore-display] key ");
                                    write_hex(u64::from(other));
                                    write(" -> focused ");
                                    if let Some(id) = focused_id {
                                        write_hex(u64::from(id.0));
                                    } else {
                                        write("none");
                                    }
                                    write("\n");
                                }
                            }
                        }
                        DisplayInputEvent::Pointer { x, y, buttons } => {
                            // Pointer events are logged but not acted on in
                            // this acceptance image; full pointer dispatch is
                            // a TASK-20 follow-up.
                            write("[nexacore-display] pointer x=");
                            write_hex(u64::from(x));
                            write(" y=");
                            write_hex(u64::from(y));
                            write(" buttons=");
                            write_hex(u64::from(buttons));
                            write("\n");
                        }
                        // Non-exhaustive: log unknown variants without
                        // decoding their fields so new variants don't break.
                        _ => {
                            write("[nexacore-display] unknown input event variant\n");
                        }
                    },
                    Err(_) => {
                        write("[nexacore-display] input event decode error (n=");
                        write_hex(n as u64);
                        write(")\n");
                    }
                }
            }
            None => {
                // Queue empty: yield and track.
                task_yield();
                empty_count = empty_count.saturating_add(1);

                // Log a heartbeat every EMPTY_POLL_LOG_INTERVAL iterations to
                // confirm the daemon is alive without flooding the console.
                if empty_count >= EMPTY_POLL_LOG_INTERVAL {
                    empty_count = 0;
                    write("[nexacore-display] idle heartbeat\n");
                }
            }
        }
    }
}
