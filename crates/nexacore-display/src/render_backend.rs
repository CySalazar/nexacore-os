//! Rendering-backend abstraction (WS7-01.1) and the CPU software fallback
//! (WS7-01.11).
//!
//! The compositor (WS7-01) is written against the [`RenderBackend`] trait so
//! that the same scene-graph, damage, effect and present logic drives either a
//! GPU backend (virtio-gpu first, then Vulkan/KMS — the live device path lands
//! rig-side, WS7-01.2) or the pure-CPU [`SoftwareBackend`] in this module.
//! Picking between them is [`select_backend`]: GPU when the hardware advertises
//! the capabilities the compositor needs, otherwise a guaranteed software
//! fallback so a desktop always renders (ADR-0041 D1: the crate stays
//! allocation-light and framebuffer-agnostic — the software backend owns its
//! own pixel buffer and the bootable image copies the dirty rects to the mapped
//! framebuffer).
//!
//! Every operation is bounds-checked: a destination rect is clipped to the
//! surface before any pixel is touched, and writes go through
//! [`slice::get_mut`] — never raw indexing, never `unsafe`.
//!
//! # `no_std`
//!
//! Uses only `alloc::vec::Vec`; the colour math is integer straight-alpha
//! `over` in the encoded ARGB8888 domain (the gamma-correct linear-light path
//! lives in [`crate::color`] and is selected by the compositor when fidelity
//! matters).

// Pixel indices are computed from `u32` width/height bounded by the surface
// size; the casts to `usize`/`i64` are width-bounded and the alpha math is
// `0..=255`. Justified at module scope to keep the hot pixel loops readable.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::integer_division
)]

use alloc::{vec, vec::Vec};

use crate::geometry::Rect;

/// What a backend can do in hardware, so the compositor can offload effects
/// when supported and fall back to CPU implementations otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// Hardware gaussian blur behind surfaces (translucency/vibrancy, WS7-01.6).
    pub hardware_blur: bool,
    /// Hardware soft drop shadows (WS7-01.7).
    pub hardware_shadow: bool,
    /// Hardware rounded-corner clipping of surfaces (WS7-01.8).
    pub hardware_rounded_clip: bool,
    /// Largest texture/resource edge the backend accepts, in pixels.
    pub max_texture_dim: u32,
}

impl BackendCapabilities {
    /// Capabilities of the pure-CPU [`SoftwareBackend`]: no hardware offload,
    /// but every effect is still available on the CPU. `max_texture_dim` is the
    /// largest square the software path will composite without overflow.
    #[must_use]
    pub const fn software() -> Self {
        Self {
            hardware_blur: false,
            hardware_shadow: false,
            hardware_rounded_clip: false,
            max_texture_dim: 16_384,
        }
    }
}

/// Which backend a [`RenderBackend`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// GPU-accelerated (virtio-gpu / Vulkan / KMS). The live path is rig-side.
    Gpu,
    /// Pure-CPU software compositing — the always-available fallback.
    Software,
}

/// Choose a backend, preferring the GPU when it can serve the desktop.
///
/// The GPU is chosen when it is present *and* advertises at least the texture
/// size the desktop needs, otherwise software so a desktop always composites
/// (WS7-01.1 / WS7-01.11). `needed_dim` is the largest surface edge the
/// compositor must handle (usually the screen's longest side).
///
/// # Example
///
/// ```
/// use nexacore_display::render_backend::{BackendCapabilities, BackendKind, select_backend};
///
/// let gpu = BackendCapabilities {
///     hardware_blur: true,
///     hardware_shadow: true,
///     hardware_rounded_clip: true,
///     max_texture_dim: 8192,
/// };
/// assert_eq!(select_backend(true, gpu, 3840), BackendKind::Gpu);
/// // GPU present but can't fit the screen → software.
/// assert_eq!(select_backend(true, gpu, 16_000), BackendKind::Software);
/// // No GPU → software.
/// assert_eq!(select_backend(false, gpu, 1920), BackendKind::Software);
/// ```
#[must_use]
pub fn select_backend(
    gpu_available: bool,
    gpu: BackendCapabilities,
    needed_dim: u32,
) -> BackendKind {
    if gpu_available && gpu.max_texture_dim >= needed_dim {
        BackendKind::Gpu
    } else {
        BackendKind::Software
    }
}

/// The operations the compositor issues against a render target. Both the GPU
/// backend (rig) and [`SoftwareBackend`] implement this; the compositor never
/// names a concrete backend.
pub trait RenderBackend {
    /// Which concrete backend this is.
    fn kind(&self) -> BackendKind;
    /// Hardware capabilities, so the compositor can offload or fall back.
    fn capabilities(&self) -> BackendCapabilities;
    /// Target size in pixels (`width`, `height`).
    fn surface_size(&self) -> (u32, u32);
    /// Fill the whole target with an opaque `0xAARRGGBB` colour.
    fn clear(&mut self, color: u32);
    /// Fill `rect` (clipped to the target) with an opaque colour.
    fn fill_rect(&mut self, rect: Rect, color: u32);
    /// Alpha-blend `color` (its high byte is the source alpha) over `rect`,
    /// clipped to the target.
    fn blend_rect(&mut self, rect: Rect, color: u32);
    /// Copy a `src_w * src_h` pixel block to `(dst_x, dst_y)`, clipped to the
    /// target. Pixels are opaque-copied. A mismatched `src` length is ignored.
    fn blit(&mut self, dst_x: i32, dst_y: i32, src: &[u32], src_w: u32, src_h: u32);
}

/// Straight-alpha `src over dst` in the encoded ARGB8888 domain.
///
/// `a` is the source alpha (`0..=255`). Result alpha is forced opaque (the
/// framebuffer has no alpha channel). Integer-only; the gamma-correct
/// linear-light variant is [`crate::color::blend_over_linear`].
#[must_use]
fn over(dst: u32, src: u32, a: u32) -> u32 {
    if a == 0 {
        return dst;
    }
    if a == 255 {
        return 0xFF00_0000 | (src & 0x00FF_FFFF);
    }
    let inv = 255 - a;
    let sr = (src >> 16) & 0xFF;
    let sg = (src >> 8) & 0xFF;
    let sb = src & 0xFF;
    let dr = (dst >> 16) & 0xFF;
    let dg = (dst >> 8) & 0xFF;
    let db = dst & 0xFF;
    // Rounded integer blend: (s*a + d*(255-a) + 127) / 255.
    let r = (sr * a + dr * inv + 127) / 255;
    let g = (sg * a + dg * inv + 127) / 255;
    let b = (sb * a + db * inv + 127) / 255;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

/// Pure-CPU compositing target (WS7-01.11). Owns an ARGB8888 pixel buffer; the
/// bootable image copies the listed dirty rects to the mapped framebuffer.
#[derive(Debug, Clone)]
pub struct SoftwareBackend {
    buf: Vec<u32>,
    w: u32,
    h: u32,
}

impl SoftwareBackend {
    /// Allocate a `w * h` software target (cleared to opaque black).
    #[must_use]
    pub fn new(w: u32, h: u32) -> Self {
        let len = (w as usize).saturating_mul(h as usize);
        Self {
            buf: vec![0xFF00_0000; len],
            w,
            h,
        }
    }

    /// The composited pixels, row-major, `w * h` long.
    #[must_use]
    pub fn buffer(&self) -> &[u32] {
        &self.buf
    }

    /// Read one pixel, or `None` if out of bounds.
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.w || y >= self.h {
            return None;
        }
        let idx = (y as usize) * (self.w as usize) + (x as usize);
        self.buf.get(idx).copied()
    }

    /// Clip `rect` to the target, returning the integer pixel span
    /// `(x0, y0, x1, y1)` (exclusive ends) or `None` if empty.
    fn clip(&self, rect: Rect) -> Option<(u32, u32, u32, u32)> {
        let screen = Rect {
            x: 0,
            y: 0,
            w: self.w,
            h: self.h,
        };
        let c = rect.intersect(&screen)?;
        if c.w == 0 || c.h == 0 {
            return None;
        }
        let x0 = c.x.max(0) as u32;
        let y0 = c.y.max(0) as u32;
        let x1 = x0.saturating_add(c.w).min(self.w);
        let y1 = y0.saturating_add(c.h).min(self.h);
        if x0 >= x1 || y0 >= y1 {
            None
        } else {
            Some((x0, y0, x1, y1))
        }
    }

    /// Apply `f` to every pixel in the clipped span via `get_mut` (no indexing).
    fn for_each_pixel(&mut self, rect: Rect, mut f: impl FnMut(u32) -> u32) {
        let Some((x0, y0, x1, y1)) = self.clip(rect) else {
            return;
        };
        let stride = self.w as usize;
        for y in y0..y1 {
            let row = (y as usize) * stride;
            for x in x0..x1 {
                if let Some(p) = self.buf.get_mut(row + x as usize) {
                    *p = f(*p);
                }
            }
        }
    }
}

impl RenderBackend for SoftwareBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Software
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::software()
    }

    fn surface_size(&self) -> (u32, u32) {
        (self.w, self.h)
    }

    fn clear(&mut self, color: u32) {
        let c = 0xFF00_0000 | (color & 0x00FF_FFFF);
        for p in &mut self.buf {
            *p = c;
        }
    }

    fn fill_rect(&mut self, rect: Rect, color: u32) {
        let c = 0xFF00_0000 | (color & 0x00FF_FFFF);
        self.for_each_pixel(rect, |_| c);
    }

    fn blend_rect(&mut self, rect: Rect, color: u32) {
        let a = (color >> 24) & 0xFF;
        self.for_each_pixel(rect, |dst| over(dst, color, a));
    }

    fn blit(&mut self, dst_x: i32, dst_y: i32, src: &[u32], src_w: u32, src_h: u32) {
        if src.len() != (src_w as usize).saturating_mul(src_h as usize) {
            return;
        }
        let dst_rect = Rect {
            x: dst_x,
            y: dst_y,
            w: src_w,
            h: src_h,
        };
        let Some((x0, y0, x1, y1)) = self.clip(dst_rect) else {
            return;
        };
        let stride = self.w as usize;
        for y in y0..y1 {
            // Source row, accounting for top clipping.
            let sy = (y as i64 - dst_y as i64) as usize;
            let drow = (y as usize) * stride;
            let srow = sy * (src_w as usize);
            for x in x0..x1 {
                let sx = (x as i64 - dst_x as i64) as usize;
                if let (Some(s), Some(d)) =
                    (src.get(srow + sx), self.buf.get_mut(drow + x as usize))
                {
                    *d = 0xFF00_0000 | (*s & 0x00FF_FFFF);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_prefers_gpu_when_capable() {
        let gpu = BackendCapabilities {
            hardware_blur: true,
            hardware_shadow: true,
            hardware_rounded_clip: true,
            max_texture_dim: 8192,
        };
        assert_eq!(select_backend(true, gpu, 3840), BackendKind::Gpu);
        assert_eq!(select_backend(true, gpu, 9000), BackendKind::Software);
        assert_eq!(select_backend(false, gpu, 100), BackendKind::Software);
    }

    #[test]
    fn software_backend_reports_software() {
        let b = SoftwareBackend::new(8, 4);
        assert_eq!(b.kind(), BackendKind::Software);
        assert_eq!(b.surface_size(), (8, 4));
        assert!(!b.capabilities().hardware_blur);
    }

    #[test]
    fn fill_rect_is_clipped_and_opaque() {
        let mut b = SoftwareBackend::new(4, 4);
        // A rect straddling the right/bottom edge must clip, not panic or wrap.
        b.fill_rect(
            Rect {
                x: 2,
                y: 2,
                w: 100,
                h: 100,
            },
            0x00FF_0000,
        );
        assert_eq!(b.pixel(3, 3), Some(0xFFFF_0000));
        assert_eq!(b.pixel(0, 0), Some(0xFF00_0000)); // untouched
        assert_eq!(b.pixel(4, 4), None); // out of bounds
    }

    #[test]
    fn negative_origin_rect_clips_to_zero() {
        let mut b = SoftwareBackend::new(4, 4);
        b.fill_rect(
            Rect {
                x: -2,
                y: -2,
                w: 4,
                h: 4,
            },
            0x0000_FF00,
        );
        // Only the (0,0)..(2,2) quadrant is inside.
        assert_eq!(b.pixel(0, 0), Some(0xFF00_FF00));
        assert_eq!(b.pixel(1, 1), Some(0xFF00_FF00));
        assert_eq!(b.pixel(2, 2), Some(0xFF00_0000));
    }

    #[test]
    fn blend_rect_does_alpha_over() {
        let mut b = SoftwareBackend::new(2, 2);
        b.clear(0x0000_0000); // opaque black
        // 50% white over black ≈ mid grey.
        b.blend_rect(
            Rect {
                x: 0,
                y: 0,
                w: 2,
                h: 2,
            },
            0x80FF_FFFF,
        );
        let px = b.pixel(0, 0).unwrap();
        let r = (px >> 16) & 0xFF;
        assert!((0x7E..=0x82).contains(&r), "got {r:#x}");
        assert_eq!(px >> 24, 0xFF, "result stays opaque");
    }

    #[test]
    fn blit_copies_clipped_block() {
        let mut b = SoftwareBackend::new(4, 4);
        let src = [0x00AA_BBCC_u32; 4]; // 2x2
        b.blit(3, 3, &src, 2, 2); // only (3,3) lands inside
        assert_eq!(b.pixel(3, 3), Some(0xFFAA_BBCC));
        assert_eq!(b.pixel(2, 2), Some(0xFF00_0000));
    }

    #[test]
    fn blit_rejects_mismatched_source_len() {
        let mut b = SoftwareBackend::new(4, 4);
        let src = [0x00FF_FFFF_u32; 3]; // claims 2x2 = 4 but is 3
        b.blit(0, 0, &src, 2, 2);
        assert_eq!(b.pixel(0, 0), Some(0xFF00_0000)); // untouched
    }
}
