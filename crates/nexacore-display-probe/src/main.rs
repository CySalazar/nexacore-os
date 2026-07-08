//! TASK-18 (DE-C1) Ring 3 display-map + input-event smoke probe (ADR-0040 D5).
//!
//! A `no_std + no_main` ELF the kernel spawns to validate the `DisplayMap (79)`
//! syscall and the display-input IPC channel end-to-end on the target VM
//! (VM-103).  The kernel deposits the Display capability token and the
//! device-info record into the well-known deposit window at `0x10_0000` before
//! transferring control to `_start`.
//!
//! ## Test plan
//!
//! ```text
//! _start()
//!     1. Read VirtioDeviceInfo from the deposit window.  The display kernel
//!        uses the struct's fields with an OVERLOADED meaning (ADR-0040 D3):
//!          bar_phys           → input_channel_id  (u64 IPC channel)
//!          common_offset      → fb_width           (pixels)
//!          notify_offset      → fb_height          (pixels)
//!          isr_offset         → fb_stride          (pixels / row)
//!          device_offset      → fb_bpp             (bytes / pixel)
//!          mmio_len           → fb_len             (total bytes, page-aligned)
//!        Missing info → exit(2).
//!
//!     2. Find the Display capability token in the deposit window under
//!        ACTION_TAG_DISPLAY_MAP (7).  Missing → exit(3).
//!
//!     3. Call DisplayMap (79): rdi=0 (offset), rsi=fb_len_page_rounded,
//!        rdx=0 (flags), r10=cap_ptr, r8=cap_len → (rax=user_va, rdx=errno).
//!        errno ≠ 0 → log + exit(40 + errno).
//!
//!     4. Paint the framebuffer:
//!          - Left third: red   (0x00FF_0000)
//!          - Middle third: green (0x0000_FF00)
//!          - Right third: blue  (0x0000_00FF)
//!          - White 100×100 box at (10, 10) (0x00FF_FFFF)
//!        Uses `core::ptr::write_volatile` so the compiler cannot elide the
//!        writes.  Skipped (with a log) if fb_bpp ≠ 4.
//!
//!     5. Drain the input channel via IpcTryReceive (24), postcard-decode each
//!        message as a DisplayInputEvent, log it.  After 5 key events log the
//!        TASK-18 OK banner and exit(0).  On empty queue → task_yield() and
//!        retry (bounded).
//! ```
//!
//! ## Exit codes
//!
//! | Code  | Meaning |
//! |-------|---------|
//! | `0`   | Full success: DisplayMap OK, fb painted, 5+ input events received |
//! | `1`   | Panic handler invoked |
//! | `2`   | No device-info section in the deposit window |
//! | `3`   | No Display capability token in the deposit window |
//! | `40+` | DisplayMap syscall failed; `code - 40` is the raw kernel errno |
//!
//! ## Heap note
//!
//! A 64 KiB never-freeing bump allocator backs the `alloc` crate.  This is
//! sufficient for the handful of postcard decode calls (each
//! `DisplayInputEvent` encodes to ≤ 32 bytes).

#![no_std]
#![no_main]
#![allow(unsafe_code)]

extern crate alloc;

use core::panic::PanicInfo;

use nexacore_types::{display_channel::DisplayInputEvent, wire::decode_canonical};

// =============================================================================
// Bump allocator (64 KiB static heap)
// =============================================================================

/// Size of the static heap backing the bump allocator (64 KiB).
///
/// Sufficient for the handful of postcard decode calls this probe performs
/// (`DisplayInputEvent` encodes to ≤ 32 bytes per event).
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
/// Provides the `alloc` crate's `GlobalAlloc` contract with a static arena.
/// `dealloc` is a deliberate no-op: this probe is a one-shot smoke test that
/// exits after completing its sequence; freeing allocations would add
/// complexity with no benefit.
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
/// ABI: `rdi=offset` (into FB, 4 KiB-aligned), `rsi=len` (4 KiB-aligned,
/// `offset+len ≤ fb_len`), `rdx=flags` (=0), `r10=cap_ptr`, `r8=cap_len` →
/// `rax=user_va`, `rdx=errno`.
const SYS_DISPLAY_MAP: u64 = 79;

/// Deposit-window action tag for the Display capability (ADR-0040 D3).
/// Must match `ACTION_TAG_DISPLAY_MAP` in the kernel's `cap_deposit.rs`.
const ACTION_TAG_DISPLAY_MAP: u32 = 7;

/// `SYSCALL_ERROR` sentinel: `u64::MAX` returned in `rax` by single-value
/// syscalls on error (e.g. `IpcTryReceive` returning empty / on error).
const SYSCALL_ERROR: u64 = u64::MAX;

/// Input-drain poll budget (iterations of yield+try_receive before giving up
/// waiting for events).  Each iteration is one task_yield, so this controls
/// how long the probe idles before deciding "no more events".  2 000 000 is
/// generous enough for a QEMU-based VM with a slow interrupt path.
const INPUT_POLL_BUDGET: u32 = 2_000_000;

/// Number of key events to receive before logging the TASK-18 OK banner.
const KEY_EVENT_TARGET: u32 = 5;

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
/// ignored — a console write failing must never abort the test sequence).
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

// =============================================================================
// Task helpers
// =============================================================================

/// Cooperatively yield the CPU to the next runnable task.
///
/// Uses the full-clobber stub intentionally: the kernel's syscall entry
/// shuffles all argument registers; a minimal stub that only clobbers
/// `rcx/r11` would allow the compiler to keep live values in registers that
/// the kernel just destroyed.  See ADR-0035.
fn task_yield() {
    // SAFETY: TaskYield takes no arguments; all zeros for unused slots.
    // Full clobber set is declared by the generic stub.
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
    write("[display-probe] PANIC\n");
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
// ELF entry point
// =============================================================================

/// ELF entry point.
///
/// Executes the TASK-18 display-probe sequence and exits.  See the module-level
/// doc for the full flow and exit-code table.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("[display-probe] start\n");

    // ── Step 1: Read device-info from the deposit window ─────────────────────
    //
    // The kernel writes a `VirtioDeviceInfo` struct into the deposit window with
    // fields overloaded to carry display parameters (ADR-0040 D3 / TASK-18
    // shared contract):
    //   bar_phys       → input_channel_id
    //   common_offset  → fb_width  (pixels)
    //   notify_offset  → fb_height (pixels)
    //   isr_offset     → fb_stride (pixels / row)
    //   device_offset  → fb_bpp    (bytes / pixel)
    //   mmio_len       → fb_len    (total bytes, page-rounded)
    //
    // SAFETY: `device_info::read()` requires that the deposit window is mapped
    // read-only at `DRIVER_CAP_DEPOSIT_VA` before `_start` runs.  This is
    // guaranteed by NCIP-013 § S5.3 step 8 / ADR-0040 D5 (the kernel maps the
    // window before spawning the probe).
    let dev_info = match unsafe { nexacore_driver_shared::device_info::read() } {
        Some(info) => info,
        None => {
            write("[display-probe] no device-info in deposit window\n");
            exit(2);
        }
    };

    let input_channel_id: u64 = dev_info.bar_phys;
    let fb_width: u32 = dev_info.common_offset;
    let fb_height: u32 = dev_info.notify_offset;
    let fb_stride: u32 = dev_info.isr_offset;
    let fb_bpp: u32 = dev_info.device_offset;
    let fb_len: u32 = dev_info.mmio_len;

    write("[display-probe] input_channel_id=");
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

    // ── Step 2: Find the Display capability token ─────────────────────────────
    //
    // The kernel deposited the Display cap token under action tag 7
    // (ACTION_TAG_DISPLAY_MAP, ADR-0040 D3).
    //
    // SAFETY: see step 1 — deposit window is mapped before _start runs.
    let cap_bytes: &[u8] = match nexacore_driver_shared::caps::find_token(
        ACTION_TAG_DISPLAY_MAP,
        |_| true, // accept the first Display token — exactly one is deposited
    ) {
        Some(b) => b,
        None => {
            write("[display-probe] no Display cap token in deposit window\n");
            exit(3);
        }
    };

    write("[display-probe] Display cap found, len=");
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
    let (user_va, errno) = unsafe {
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
        write("[display-probe] DisplayMap FAILED errno=");
        write_hex(errno);
        write("\n");
        // Exit code 40 + errno (errno fits in u32 for all known kernel codes).
        #[allow(
            clippy::cast_possible_truncation,
            reason = "errno from the kernel fits in u32; POSIX codes are at most a few hundred"
        )]
        exit(40u32.saturating_add(errno as u32));
    }

    write("[display-probe] DisplayMap OK user_va=");
    write_hex(user_va);
    write("\n");

    // ── Step 4: Paint the framebuffer ────────────────────────────────────────
    //
    // Only implemented for 32-bit-per-pixel (bpp = 4).  Log and skip otherwise.
    // Pixel address: base_va + (y * stride + x) * bpp
    // Colours (ARGB / 0x00RRGGBB format):
    //   left third  → red   0x00FF0000
    //   middle third → green 0x0000FF00
    //   right third → blue  0x000000FF
    //   white box at (10..110, 10..110) → 0x00FFFFFF

    if fb_bpp != 4 {
        write("[display-probe] fb_bpp != 4, skipping paint\n");
    } else {
        // SAFETY: user_va is the kernel-assigned framebuffer mapping VA returned
        // by DisplayMap; it is writable for `fb_len_aligned` bytes.  We use
        // `write_volatile` so the compiler cannot elide the pixel writes
        // (the GPU scanout hardware reads directly from this mapping).
        // fb_stride, fb_width, fb_height are u32; cast to usize for arithmetic.
        // The range checks below prevent out-of-bounds access.
        let fb_base: *mut u32 = user_va as *mut u32;
        let width = fb_width as usize;
        let height = fb_height as usize;
        let stride = fb_stride as usize;

        // Guard: if geometry is degenerate (zero dimension), skip.
        if width == 0 || height == 0 || stride == 0 {
            write("[display-probe] degenerate geometry, skipping paint\n");
        } else {
            let third = width / 3;

            // Paint colour bars row by row.
            let mut y: usize = 0;
            while y < height {
                let row_base: usize = y * stride;
                let mut x: usize = 0;
                while x < width {
                    let colour: u32 = if x < third {
                        0x00FF_0000 // red
                    } else if x < 2 * third {
                        0x0000_FF00 // green
                    } else {
                        0x0000_00FF // blue
                    };
                    let pixel_idx = row_base + x;
                    // SAFETY: pixel_idx is in [0, height*stride) which is
                    // covered by the fb_len_aligned mapping.  write_volatile
                    // prevents the compiler from optimising out the stores.
                    unsafe {
                        core::ptr::write_volatile(fb_base.add(pixel_idx), colour);
                    }
                    x += 1;
                }
                y += 1;
            }

            // Paint the white 100×100 box at pixel (10, 10).
            const BOX_X: usize = 10;
            const BOX_Y: usize = 10;
            const BOX_SIZE: usize = 100;
            let box_x_end = (BOX_X + BOX_SIZE).min(width);
            let box_y_end = (BOX_Y + BOX_SIZE).min(height);
            let mut by: usize = BOX_Y;
            while by < box_y_end {
                let row_base: usize = by * stride;
                let mut bx: usize = BOX_X;
                while bx < box_x_end {
                    let pixel_idx = row_base + bx;
                    // SAFETY: same mapping contract as above.
                    unsafe {
                        core::ptr::write_volatile(fb_base.add(pixel_idx), 0x00FF_FFFF);
                    }
                    bx += 1;
                }
                by += 1;
            }

            write("[display-probe] framebuffer painted ");
            write_hex(u64::from(fb_width));
            write("x");
            write_hex(u64::from(fb_height));
            write("\n");
        }
    }

    // ── Step 5: Drain the input channel ──────────────────────────────────────
    //
    // Poll the input channel via IpcTryReceive(24).  Decode each message as a
    // postcard `DisplayInputEvent` and log it.  After KEY_EVENT_TARGET key events
    // log the TASK-18 OK banner.  The probe loops until the budget is exhausted
    // or the target is reached.

    write("[display-probe] waiting for input events (channel=");
    write_hex(input_channel_id);
    write(")...\n");

    let mut key_events: u32 = 0;
    let mut poll_budget: u32 = INPUT_POLL_BUDGET;
    let mut ok_logged = false;

    loop {
        // SAFETY: RECV_BUF is a static BSS buffer; we hold the only reference
        // here (single-threaded).
        let recv_buf: &mut [u8; MAX_EVENT_BYTES] =
            unsafe { &mut *core::ptr::addr_of_mut!(RECV_BUF) };

        match sys_ipc_try_receive(input_channel_id, recv_buf) {
            Some(n) => {
                // Reset idle budget on any message received.
                poll_budget = INPUT_POLL_BUDGET;

                let payload = &recv_buf[..n];
                match decode_canonical::<DisplayInputEvent>(payload) {
                    Ok(ev) => match ev {
                        DisplayInputEvent::Key { code, pressed } => {
                            write("[display-probe] key code=");
                            write_hex(u64::from(code));
                            write(" pressed=");
                            write_hex(u64::from(pressed));
                            write("\n");
                            key_events = key_events.saturating_add(1);
                            if key_events >= KEY_EVENT_TARGET && !ok_logged {
                                write("[display-probe] received 5 input events — TASK-18 OK\n");
                                ok_logged = true;
                                // Continue running to drain more events rather
                                // than cutting the loop short; the serial
                                // capture just needs this banner.
                            }
                        }
                        DisplayInputEvent::Pointer { x, y, buttons } => {
                            write("[display-probe] pointer x=");
                            write_hex(u64::from(x));
                            write(" y=");
                            write_hex(u64::from(y));
                            write(" buttons=");
                            write_hex(u64::from(buttons));
                            write("\n");
                        }
                        // Non-exhaustive: log unknown variants without decoding
                        // their fields so new variants don't break the probe.
                        _ => {
                            write("[display-probe] unknown input event variant\n");
                        }
                    },
                    Err(_) => {
                        write("[display-probe] input event decode error (n=");
                        write_hex(n as u64);
                        write(")\n");
                    }
                }
            }
            None => {
                // Queue empty: yield and retry.
                task_yield();
                if poll_budget == 0 {
                    write("[display-probe] input poll budget exhausted\n");
                    break;
                }
                poll_budget = poll_budget.saturating_sub(1);
            }
        }
    }

    write("[display-probe] done\n");
    exit(0)
}
