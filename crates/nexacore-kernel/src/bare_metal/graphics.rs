//! GOP/UEFI linear framebuffer abstraction.
//!
//! Provides pixel-level rendering on a raw linear framebuffer supplied by
//! the bootloader via UEFI Graphics Output Protocol. All operations use
//! `write_volatile` to prevent the compiler from eliding or reordering
//! stores to this memory-mapped region.
//!
//! ## Color model
//!
//! All public colour constants and function parameters use packed 32-bit
//! ARGB: `0xAA_RR_GG_BB`. Alpha is ignored for display (the GOP
//! framebuffer is opaque); it is present so callers can use standard
//! 32-bit colour literals directly.
//!
//! ## Safety
//!
//! The [`FrameBuffer`] struct wraps a raw pointer. Its constructor is
//! `unsafe`; thereafter all methods are safe (bounds-checked). The kernel
//! bootstrap ensures the pointer is valid for the duration of `kmain`.

#![allow(unsafe_code)]

use core::ptr;

// =============================================================================
// Pixel format
// =============================================================================

/// UEFI/GOP pixel format of the framebuffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// Pixels stored as R, G, B[, padding] — red byte first.
    Rgb,
    /// Pixels stored as B, G, R[, padding] — blue byte first.
    Bgr,
    /// Single grayscale byte per pixel (rare on UEFI).
    U8,
    /// Unsupported format; writes are silently discarded.
    Other,
}

// =============================================================================
// FrameBuffer
// =============================================================================

/// Kernel-owned view into the GOP linear framebuffer.
///
/// Created once in `kernel_entry` from the bootloader's `FrameBuffer` and
/// passed to `kmain`. The pixel stride (in *pixels*, not bytes) accounts
/// for any row padding the firmware inserted.
pub struct FrameBuffer {
    ptr: *mut u8,
    /// Framebuffer width in pixels.
    pub width: u32,
    /// Framebuffer height in pixels.
    pub height: u32,
    bytes_per_px: u32,
    /// Row stride in **pixels** (≥ width; may include padding columns).
    stride: u32,
    format: PixelFormat,
}

// SAFETY: The framebuffer pointer is exclusively owned by the kernel for
// the duration of `kmain`. No other code aliases it after `kernel_entry`
// hands off the `FrameBuffer` value. Single-CPU at v1.0; no `Sync` hazard.
unsafe impl Send for FrameBuffer {}

impl FrameBuffer {
    /// Construct a [`FrameBuffer`] from raw bootloader-provided values.
    ///
    /// # Safety
    ///
    /// The caller MUST ensure:
    /// - `ptr` points to a mapped, writable memory region of at least
    ///   `stride * height * bytes_per_px` bytes.
    /// - The region is exclusively owned by the kernel from this point on.
    /// - `bytes_per_px` matches the actual pixel format (1, 3, or 4).
    /// - `stride ≥ width`.
    #[must_use]
    pub const unsafe fn new(
        ptr: *mut u8,
        width: u32,
        height: u32,
        bytes_per_px: u32,
        stride: u32,
        format: PixelFormat,
    ) -> Self {
        Self {
            ptr,
            width,
            height,
            bytes_per_px,
            stride,
            format,
        }
    }

    // -------------------------------------------------------------------------
    // Public accessors for kmain's framebuffer-phys walk (ADR-0040 D1)
    // -------------------------------------------------------------------------

    /// Raw kernel virtual address pointer of the framebuffer base.
    ///
    /// Used by `kmain` to walk the active page tables and resolve the
    /// physical base address for [`FramebufferInfo`]. The pointer is the
    /// same one supplied to [`FrameBuffer::new`] by the bootloader.
    #[must_use]
    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Bytes per pixel (e.g. 4 for RGB/BGRx).
    ///
    /// Equal to `bytes_per_px` supplied to [`FrameBuffer::new`].
    #[must_use]
    pub fn bytes_per_px(&self) -> u32 {
        self.bytes_per_px
    }

    /// Row stride in **pixels** (≥ width; may include padding columns).
    ///
    /// Equal to `stride` supplied to [`FrameBuffer::new`].
    #[must_use]
    pub fn stride(&self) -> u32 {
        self.stride
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Byte offset of pixel `(x, y)` in the framebuffer.
    #[inline]
    fn byte_offset(&self, x: u32, y: u32) -> usize {
        (y * self.stride + x) as usize * self.bytes_per_px as usize
    }

    /// Write a 32-bit ARGB colour as native framebuffer bytes at the given
    /// byte offset. Does NOT bounds-check; callers must ensure `offset` is
    /// valid.
    #[inline]
    unsafe fn write_argb_at(&self, offset: usize, argb: u32) {
        let r = ((argb >> 16) & 0xFF) as u8;
        let g = ((argb >> 8) & 0xFF) as u8;
        let b = (argb & 0xFF) as u8;
        // SAFETY: caller ensures offset is within the framebuffer bounds.
        let base = unsafe { self.ptr.add(offset) };

        match self.format {
            PixelFormat::Rgb => match self.bytes_per_px {
                3 => unsafe {
                    ptr::write_volatile(base, r);
                    ptr::write_volatile(base.add(1), g);
                    ptr::write_volatile(base.add(2), b);
                },
                4 => unsafe {
                    ptr::write_volatile(base, r);
                    ptr::write_volatile(base.add(1), g);
                    ptr::write_volatile(base.add(2), b);
                    ptr::write_volatile(base.add(3), 0xFF);
                },
                _ => {}
            },
            PixelFormat::Bgr => match self.bytes_per_px {
                3 => unsafe {
                    ptr::write_volatile(base, b);
                    ptr::write_volatile(base.add(1), g);
                    ptr::write_volatile(base.add(2), r);
                },
                4 => unsafe {
                    ptr::write_volatile(base, b);
                    ptr::write_volatile(base.add(1), g);
                    ptr::write_volatile(base.add(2), r);
                    ptr::write_volatile(base.add(3), 0xFF);
                },
                _ => {}
            },
            PixelFormat::U8 => {
                #[allow(
                    clippy::integer_division,
                    reason = "ITU-R BT.601 luma; integer truncation in 0..=255 range is intended"
                )]
                let gray = (u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000;
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "weighted sum / 1000 always fits u8"
                )]
                unsafe {
                    ptr::write_volatile(base, gray as u8);
                }
            }
            PixelFormat::Other => {}
        }
    }

    // -------------------------------------------------------------------------
    // Public drawing API
    // -------------------------------------------------------------------------

    /// Write a single pixel at `(x, y)`. Out-of-bounds coordinates are
    /// silently ignored.
    pub fn write_pixel(&self, x: u32, y: u32, argb: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        // SAFETY: `byte_offset` is bounded by `stride * height * bpp`;
        // the constructor contract guarantees the buffer is that large.
        unsafe { self.write_argb_at(self.byte_offset(x, y), argb) }
    }

    /// Fill the entire framebuffer with `argb`.
    pub fn clear(&self, argb: u32) {
        self.draw_rect_filled(0, 0, self.width, self.height, argb);
    }

    /// Fill an axis-aligned rectangle. Coordinates are clamped to the
    /// framebuffer bounds; `x1`/`y1` are exclusive.
    pub fn draw_rect_filled(&self, x0: u32, y0: u32, x1: u32, y1: u32, argb: u32) {
        let x_start = x0.min(x1).min(self.width);
        let x_end = x0.max(x1).min(self.width);
        let y_start = y0.min(y1).min(self.height);
        let y_end = y0.max(y1).min(self.height);
        for y in y_start..y_end {
            for x in x_start..x_end {
                // SAFETY: x < width, y < height — guaranteed by clamping above.
                unsafe { self.write_argb_at(self.byte_offset(x, y), argb) }
            }
        }
    }

    /// Draw a 1-pixel-tall horizontal line from `x0` to `x1` (exclusive)
    /// at row `y`. Clamped to bounds.
    pub fn draw_hline(&self, x0: u32, x1: u32, y: u32, argb: u32) {
        if y >= self.height {
            return;
        }
        let x_start = x0.min(x1).min(self.width);
        let x_end = x0.max(x1).min(self.width);
        for x in x_start..x_end {
            // SAFETY: x < width, y < height.
            unsafe { self.write_argb_at(self.byte_offset(x, y), argb) }
        }
    }

    /// Draw a 1-pixel-wide vertical line from `y0` to `y1` (exclusive)
    /// at column `x`. Clamped to bounds.
    pub fn draw_vline(&self, x: u32, y0: u32, y1: u32, argb: u32) {
        if x >= self.width {
            return;
        }
        let y_start = y0.min(y1).min(self.height);
        let y_end = y0.max(y1).min(self.height);
        for y in y_start..y_end {
            // SAFETY: x < width, y < height — guaranteed by clamping above.
            unsafe { self.write_argb_at(self.byte_offset(x, y), argb) }
        }
    }

    /// Draw a 1-pixel-wide rectangle outline. `x1`/`y1` are exclusive.
    /// Clamped to framebuffer bounds.
    pub fn draw_rect_outline(&self, x0: u32, y0: u32, x1: u32, y1: u32, argb: u32) {
        self.draw_hline(x0, x1, y0, argb);
        self.draw_hline(x0, x1, y1.saturating_sub(1), argb);
        self.draw_vline(x0, y0, y1, argb);
        self.draw_vline(x1.saturating_sub(1), y0, y1, argb);
    }

    /// Save the raw framebuffer bytes for a 16×16 block at `(cx, cy)`.
    ///
    /// `buf` receives up to 4 raw bytes per pixel in row-major order
    /// (`buf[(row * 16 + col) * 4 ..]`). Out-of-bounds pixels are saved
    /// as all-zero bytes. Used by the software cursor to restore the
    /// underlying pixels when the cursor moves.
    #[allow(
        clippy::indexing_slicing,
        reason = "buf_off + 4 <= 16*16*4 = 1024 = buf.len() by row/col bounds"
    )]
    pub fn save_16x16(&self, cx: u32, cy: u32, buf: &mut [u8; 1024]) {
        let bpp = self.bytes_per_px as usize;
        for row in 0_u32..16 {
            for col in 0_u32..16 {
                let buf_off = (row * 16 + col) as usize * 4;
                let x = cx.saturating_add(col);
                let y = cy.saturating_add(row);
                if x < self.width && y < self.height {
                    let src_off = self.byte_offset(x, y);
                    for b in 0..bpp.min(4) {
                        // SAFETY: byte_offset + b is within the allocated
                        // framebuffer region (bounds-checked above).
                        buf[buf_off + b] = unsafe { self.ptr.add(src_off + b).read_volatile() };
                    }
                    for b in bpp..4 {
                        buf[buf_off + b] = 0;
                    }
                } else {
                    buf[buf_off..buf_off + 4].fill(0);
                }
            }
        }
    }

    /// Restore a 16×16 block previously saved with `save_16x16`.
    ///
    /// Out-of-bounds pixels are silently skipped.
    #[allow(
        clippy::indexing_slicing,
        reason = "buf_off + 4 <= 16*16*4 = 1024 = buf.len() by row/col bounds"
    )]
    pub fn restore_16x16(&self, cx: u32, cy: u32, buf: &[u8; 1024]) {
        let bpp = self.bytes_per_px as usize;
        for row in 0_u32..16 {
            for col in 0_u32..16 {
                let buf_off = (row * 16 + col) as usize * 4;
                let x = cx.saturating_add(col);
                let y = cy.saturating_add(row);
                if x < self.width && y < self.height {
                    let dst_off = self.byte_offset(x, y);
                    for b in 0..bpp.min(4) {
                        // SAFETY: same bounds guarantee as save_16x16.
                        unsafe {
                            self.ptr.add(dst_off + b).write_volatile(buf[buf_off + b]);
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// =============================================================================
// FramebufferInfo — physical layout discovered at boot
// =============================================================================

/// Physical base address and display geometry of the GOP linear framebuffer,
/// resolved once at boot by walking the active page tables
/// (`PageMapper::translate`).
///
/// Exposed as a kernel global so the `DisplayMap (79)` handler can validate
/// a compositor's sub-window request and build the physical address without
/// trusting any user-supplied argument for the physical base.
///
/// Produced by [`set_framebuffer_info`]; consumed via [`framebuffer_info`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramebufferInfo {
    /// Physical base of the linear framebuffer (page-aligned).
    pub phys_base: u64,
    /// Total byte length of the framebuffer (`height * stride * bpp`,
    /// rounded up to the next 4 KiB boundary). This is the maximum `len`
    /// a `DisplayMap` request may ask for.
    pub len: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Row stride in **pixels** (≥ width; may include padding columns,
    /// matching the [`FrameBuffer::stride`] definition).
    pub stride: u32,
    /// Bytes per pixel (e.g. 4 for RGB/BGRx).
    pub bpp: u32,
}

/// Kernel-global `Option<FramebufferInfo>` set once at boot.
///
/// `None` until [`set_framebuffer_info`] is called. On bare-metal, written
/// exactly once before any Ring-3 task can issue `DisplayMap`.
///
/// # Invariant
///
/// Single-CPU at Phase 1; no concurrent writers. Access is guarded by the
/// boot sequencing (set before LAPIC enables preemption of user tasks).
static mut FRAMEBUFFER_INFO: Option<FramebufferInfo> = None;

/// Store the resolved [`FramebufferInfo`] in the kernel global.
///
/// # Safety
///
/// MUST be called at most once, on a single CPU, before LAPIC preemption
/// begins (i.e. during the boot sequence in `kmain` after `PageMapper` is
/// constructed but before the scheduler is activated). Writing to a
/// `static mut` is safe here because the single-CPU boot path guarantees
/// no concurrent access.
///
/// # Example
///
/// ```rust,ignore
/// // Called in kmain once the page mapper is live:
/// unsafe {
///     bare_metal::graphics::set_framebuffer_info(FramebufferInfo { .. });
/// }
/// ```
pub unsafe fn set_framebuffer_info(info: FramebufferInfo) {
    // SAFETY: single-CPU boot path; exclusive write before any concurrent
    // reader can be scheduled. Caller upholds the at-most-once invariant.
    unsafe {
        FRAMEBUFFER_INFO = Some(info);
    }
}

/// Returns a reference to the [`FramebufferInfo`] resolved at boot, or
/// `None` if the framebuffer was absent or the page-table walk failed.
///
/// # Example
///
/// ```rust,ignore
/// if let Some(fb) = bare_metal::graphics::framebuffer_info() {
///     let phys = fb.phys_base;
/// }
/// ```
#[must_use]
pub fn framebuffer_info() -> Option<&'static FramebufferInfo> {
    // SAFETY: `FRAMEBUFFER_INFO` is written at most once (in `set_framebuffer_info`)
    // before any Ring-3 task is dispatched; subsequent reads are immutable
    // references with no aliased writers. `addr_of!` is used instead of a
    // direct reference to avoid the Rust-2024 `static_mut_refs` lint.
    unsafe { (*core::ptr::addr_of!(FRAMEBUFFER_INFO)).as_ref() }
}

// =============================================================================
// ARGB colour palette (matches the visual theme of the VGA text banner)
// =============================================================================

/// Opaque black — `0xFF_00_00_00`.
pub const BLACK: u32 = 0xFF_00_00_00;
/// Opaque white — `0xFF_FF_FF_FF`.
pub const WHITE: u32 = 0xFF_FF_FF_FF;
/// Bright cyan — `0xFF_00_D4_FF` (analogue of VGA `LIGHT_CYAN`).
pub const LIGHT_CYAN: u32 = 0xFF_00_D4_FF;
/// Medium cyan — `0xFF_00_9A_C4` (analogue of VGA `CYAN`).
pub const CYAN: u32 = 0xFF_00_9A_C4;
/// Bright yellow — `0xFF_FF_FF_00` (countdown timer; matches VGA `YELLOW`).
pub const YELLOW: u32 = 0xFF_FF_FF_00;
/// Very dark navy background — `0xFF_00_08_18`.
pub const DARK_NAVY: u32 = 0xFF_00_08_18;
/// Dark gray — `0xFF_30_30_30` (progress bar background).
pub const DARK_GRAY: u32 = 0xFF_30_30_30;
