//! `HiDPI` / Retina scaling (WS7-04).
//!
//! Crisp UI on high-density panels is part of macOS-grade quality. This module
//! is the `no_std + alloc`, host-testable scaling core the compositor owns and
//! propagates to the toolkit ([`crate::color`] handles the color stage; this
//! one handles the density stage):
//!
//! * [`ScaleFactor`] — a per-output logical→device pixel ratio, produced by the
//!   compositor and consumed by `nexacore-ui` (WS7-04.1). Carries the typography
//!   bridge [`ScaleFactor::device_px_per_em`] so WS7-03 glyph rendering picks up
//!   the density (WS7-04.5).
//! * [`scale_nearest`] — integer nearest-neighbor upscale (200% / 300%), the
//!   crisp path for integer scale factors (WS7-04.3).
//! * [`resample_bilinear`] — quality bilinear resample for fractional factors
//!   (e.g. 150%), the compositor's fractional-scaling path (WS7-04.4).
//!
//! Pixels are the compositor's `0xAA_RR_GG_BB` ARGB8888 `u32`
//! ([`crate::surface::Surface`]); channels are resampled independently
//! (straight alpha).

// Scaling is inherently floating-point and quantizes back to 8-bit channels and
// integer pixel counts; the casts are bounded and the indices are computed into
// pre-sized buffers.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::integer_division,
    // Exact float comparisons are intentional here: integer-factor detection
    // and exact-value test assertions over representable values.
    clippy::float_cmp
)]

use alloc::vec::Vec;

use libm::floorf;

use crate::color::Rgba8;

// =============================================================================
// ScaleFactor
// =============================================================================

/// A per-output device scale factor: the ratio of device pixels to logical
/// pixels (`2.0` for a classic Retina panel, `1.5` for a 150% fractional
/// display). Always finite and strictly positive.
///
/// The compositor derives one per output and propagates it to the toolkit
/// (WS7-04.1); widgets lay out in logical pixels and the factor maps them to
/// device pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScaleFactor(f32);

impl ScaleFactor {
    /// The identity factor (`1.0`, a standard-density output).
    pub const ONE: Self = Self(1.0);

    /// Build a factor from a raw ratio, or `None` if it is not finite and > 0.
    #[must_use]
    pub fn new(ratio: f32) -> Option<Self> {
        (ratio.is_finite() && ratio > 0.0).then_some(Self(ratio))
    }

    /// Build an integer factor (`n` clamped to at least `1`).
    #[must_use]
    pub fn integer(n: u32) -> Self {
        Self(n.max(1) as f32)
    }

    /// The raw ratio.
    #[must_use]
    pub fn value(self) -> f32 {
        self.0
    }

    /// Map a logical-pixel length to device pixels.
    #[must_use]
    pub fn to_device(self, logical: f32) -> f32 {
        logical * self.0
    }

    /// Map a device-pixel length back to logical pixels.
    #[must_use]
    pub fn to_logical(self, device: f32) -> f32 {
        device / self.0
    }

    /// Round a logical-pixel count to the nearest whole device-pixel count.
    #[must_use]
    pub fn scale_length(self, logical_px: u32) -> u32 {
        (logical_px as f32 * self.0 + 0.5) as u32
    }

    /// `true` if the factor is a whole number (eligible for the crisp integer
    /// [`scale_nearest`] path rather than fractional resampling).
    #[must_use]
    pub fn is_integer(self) -> bool {
        floorf(self.0) == self.0
    }

    /// The nearest whole-number factor (at least `1`).
    #[must_use]
    pub fn nearest_integer(self) -> u32 {
        (self.0 + 0.5) as u32
    }

    /// Scale a logical `px_per_em` to the device `px_per_em` for glyph
    /// rasterization, so WS7-03 typography renders at panel density
    /// (WS7-04.5). Feed the result to [`crate::raster::rasterize`].
    #[must_use]
    pub fn device_px_per_em(self, logical_px_per_em: f32) -> f32 {
        logical_px_per_em * self.0
    }
}

// =============================================================================
// Integer nearest-neighbor scaling (WS7-04.3)
// =============================================================================

/// Integer nearest-neighbor upscale of an ARGB8888 buffer by `factor` (clamped
/// to ≥ 1): every source pixel becomes a `factor × factor` block.
///
/// This is the crisp path for integer scale factors (200% / 300%): no
/// resampling, so hard edges stay hard.
///
/// # Errors / `None`
///
/// Returns `None` if `src.len() != src_w * src_h`, or if the scaled dimensions
/// overflow `u32` / `usize`.
#[must_use]
pub fn scale_nearest(src: &[u32], src_w: u32, src_h: u32, factor: u32) -> Option<Vec<u32>> {
    let factor = factor.max(1);
    let expected = (src_w as usize).checked_mul(src_h as usize)?;
    if src.len() != expected {
        return None;
    }
    let dst_w = src_w.checked_mul(factor)?;
    let dst_h = src_h.checked_mul(factor)?;
    let cap = (dst_w as usize).checked_mul(dst_h as usize)?;
    let mut out = Vec::with_capacity(cap);
    // Build each source row scaled horizontally (each pixel repeated `factor`
    // times), then emit that row `factor` times — pure iteration, no indexing.
    for src_row in src.chunks_exact(src_w as usize) {
        let mut scaled_row = Vec::with_capacity(dst_w as usize);
        for &px in src_row {
            for _ in 0..factor {
                scaled_row.push(px);
            }
        }
        for _ in 0..factor {
            out.extend_from_slice(&scaled_row);
        }
    }
    Some(out)
}

// =============================================================================
// Fractional bilinear resampling (WS7-04.4)
// =============================================================================

/// Sample channel array `[a, r, g, b]` (as `f32`) at integer `(x, y)`.
#[inline]
fn sample(src: &[u32], src_w: u32, x: u32, y: u32) -> [f32; 4] {
    // The index is pre-validated by the caller (x ≤ src_w-1, y ≤ src_h-1, and
    // src.len() == src_w*src_h), so `get` always hits; the `0` fallback only
    // guards against a logic error rather than indexing-panicking.
    let idx = (y as usize) * (src_w as usize) + (x as usize);
    let p = Rgba8::from_argb(src.get(idx).copied().unwrap_or(0));
    [
        f32::from(p.a),
        f32::from(p.r),
        f32::from(p.g),
        f32::from(p.b),
    ]
}

/// Linear interpolation between two channel arrays.
#[inline]
fn lerp4(a: [f32; 4], b: [f32; 4], t: f32) -> [f32; 4] {
    [
        a[0] + (b[0] - a[0]) * t,
        a[1] + (b[1] - a[1]) * t,
        a[2] + (b[2] - a[2]) * t,
        a[3] + (b[3] - a[3]) * t,
    ]
}

/// Quality **bilinear** resample of an ARGB8888 buffer to `dst_w × dst_h`.
///
/// Each destination pixel center is mapped back into the source grid and the
/// four neighboring texels are blended per channel (straight alpha). This is
/// the compositor's fractional-scaling path (e.g. 150%); for whole factors
/// prefer the crisp [`scale_nearest`].
///
/// # Errors / `None`
///
/// Returns `None` if any dimension is `0`, if `src.len() != src_w * src_h`, or
/// if `dst_w * dst_h` overflows `usize`.
#[must_use]
pub fn resample_bilinear(
    src: &[u32],
    src_w: u32,
    src_h: u32,
    dst_w: u32,
    dst_h: u32,
) -> Option<Vec<u32>> {
    if src_w == 0 || src_h == 0 || dst_w == 0 || dst_h == 0 {
        return None;
    }
    if src.len() != (src_w as usize).checked_mul(src_h as usize)? {
        return None;
    }
    let cap = (dst_w as usize).checked_mul(dst_h as usize)?;
    let mut out = Vec::with_capacity(cap);

    let x_ratio = src_w as f32 / dst_w as f32;
    let y_ratio = src_h as f32 / dst_h as f32;
    let max_x = src_w - 1;
    let max_y = src_h - 1;

    for dy in 0..dst_h {
        let fy = (((dy as f32) + 0.5) * y_ratio - 0.5).max(0.0);
        let y0 = floorf(fy);
        let wy = fy - y0;
        let y0 = (y0 as u32).min(max_y);
        let y1 = (y0 + 1).min(max_y);
        for dx in 0..dst_w {
            let fx = (((dx as f32) + 0.5) * x_ratio - 0.5).max(0.0);
            let x0 = floorf(fx);
            let wx = fx - x0;
            let x0 = (x0 as u32).min(max_x);
            let x1 = (x0 + 1).min(max_x);

            let top = lerp4(sample(src, src_w, x0, y0), sample(src, src_w, x1, y0), wx);
            let bot = lerp4(sample(src, src_w, x0, y1), sample(src, src_w, x1, y1), wx);
            let c = lerp4(top, bot, wy);
            out.push(
                Rgba8 {
                    a: (c[0] + 0.5) as u8,
                    r: (c[1] + 0.5) as u8,
                    g: (c[2] + 0.5) as u8,
                    b: (c[3] + 0.5) as u8,
                }
                .to_argb(),
            );
        }
    }
    Some(out)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{
        font::{Outline, Point},
        raster::rasterize,
    };

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() <= 1e-4
    }

    // ---- ScaleFactor --------------------------------------------------------

    #[test]
    fn scale_factor_validates_and_maps() {
        assert!(ScaleFactor::new(0.0).is_none());
        assert!(ScaleFactor::new(-2.0).is_none());
        assert!(ScaleFactor::new(f32::NAN).is_none());
        let two = ScaleFactor::new(2.0).unwrap();
        assert!(approx(two.to_device(10.0), 20.0));
        assert!(approx(two.to_logical(20.0), 10.0));
        assert_eq!(two.scale_length(13), 26);
        assert!(two.is_integer());
        assert_eq!(two.nearest_integer(), 2);
        assert_eq!(ScaleFactor::integer(3).value(), 3.0);
        assert_eq!(ScaleFactor::ONE.value(), 1.0);
    }

    #[test]
    fn fractional_factor_rounds_and_is_not_integer() {
        let f = ScaleFactor::new(1.5).unwrap();
        assert!(!f.is_integer());
        assert_eq!(f.nearest_integer(), 2);
        assert_eq!(f.scale_length(10), 15);
        assert_eq!(f.scale_length(11), 17); // 16.5 -> 17
    }

    #[test]
    fn device_px_per_em_scales_typography() {
        let two = ScaleFactor::integer(2);
        assert!(approx(two.device_px_per_em(16.0), 32.0));
    }

    // ---- Integer nearest scaling (WS7-04.3) ---------------------------------

    #[test]
    fn scale_nearest_doubles_each_pixel() {
        // 2x2 source ⇒ 4x4 with each pixel as a 2x2 block.
        let src = [
            0xFF_FF_00_00u32,
            0xFF_00_FF_00,
            0xFF_00_00_FF,
            0xFF_FF_FF_FF,
        ];
        let out = scale_nearest(&src, 2, 2, 2).unwrap();
        assert_eq!(out.len(), 16);
        // Top-left 2x2 block is all red.
        assert_eq!(out[0], 0xFF_FF_00_00);
        assert_eq!(out[1], 0xFF_FF_00_00);
        assert_eq!(out[4], 0xFF_FF_00_00);
        assert_eq!(out[5], 0xFF_FF_00_00);
        // Top-right block is green.
        assert_eq!(out[2], 0xFF_00_FF_00);
        assert_eq!(out[3], 0xFF_00_FF_00);
        // Bottom-right corner is white.
        assert_eq!(out[15], 0xFF_FF_FF_FF);
    }

    #[test]
    fn scale_nearest_factor_one_is_identity() {
        let src = [1u32, 2, 3, 4, 5, 6];
        assert_eq!(scale_nearest(&src, 3, 2, 1).unwrap(), src.to_vec());
    }

    #[test]
    fn scale_nearest_rejects_wrong_length() {
        assert!(scale_nearest(&[0u32; 3], 2, 2, 2).is_none());
    }

    // ---- Fractional bilinear resampling (WS7-04.4) --------------------------

    #[test]
    fn resample_same_size_is_identity() {
        let src = [
            0xFF_10_20_30u32,
            0xFF_40_50_60,
            0xFF_70_80_90,
            0xFF_A0_B0_C0,
        ];
        let out = resample_bilinear(&src, 2, 2, 2, 2).unwrap();
        assert_eq!(out, src.to_vec());
    }

    #[test]
    fn resample_upscale_interpolates_between_neighbors() {
        // 2x1 source: black | white. Upscaling to 4x1 must yield intermediate
        // greys (bilinear), not a hard step.
        let src = [0xFF_00_00_00u32, 0xFF_FF_FF_FF];
        let out = resample_bilinear(&src, 2, 1, 4, 1).unwrap();
        assert_eq!(out.len(), 4);
        let g = |p: u32| Rgba8::from_argb(p).r;
        // Monotonically non-decreasing from black to white.
        assert!(g(out[0]) <= g(out[1]));
        assert!(g(out[1]) <= g(out[2]));
        assert!(g(out[2]) <= g(out[3]));
        // At least one interior pixel is a genuine grey (interpolated).
        assert!((1..=254).contains(&g(out[1])) || (1..=254).contains(&g(out[2])));
    }

    #[test]
    fn resample_rejects_zero_and_bad_length() {
        assert!(resample_bilinear(&[0u32; 4], 2, 2, 0, 2).is_none());
        assert!(resample_bilinear(&[0u32; 3], 2, 2, 4, 4).is_none());
    }

    // ---- Typography at HiDPI (WS7-04.5) -------------------------------------

    #[test]
    fn rasterizing_at_device_px_per_em_scales_glyph_bitmap() {
        // A 600x600 unit square (full em box).
        fn on(x: i16, y: i16) -> Point {
            Point {
                x,
                y,
                on_curve: true,
            }
        }
        let square = Outline {
            contours: vec![vec![on(0, 0), on(600, 0), on(600, 600), on(0, 600)]],
            advance: 600,
            x_min: 0,
            y_min: 0,
            x_max: 600,
            y_max: 600,
        };
        let upem = 1000u16;
        let logical = 20.0f32;
        let one = ScaleFactor::ONE;
        let two = ScaleFactor::integer(2);

        let small = rasterize(&square, upem, one.device_px_per_em(logical));
        let large = rasterize(&square, upem, two.device_px_per_em(logical));

        assert!(!small.is_empty() && !large.is_empty());
        // At 2x the device px_per_em, the bitmap is ~twice as tall/wide.
        assert!(
            large.height >= small.height * 2 - 1 && large.height <= small.height * 2 + 1,
            "small.h={} large.h={}",
            small.height,
            large.height
        );
        assert!(
            large.width >= small.width * 2 - 1 && large.width <= small.width * 2 + 1,
            "small.w={} large.w={}",
            small.width,
            large.width
        );
    }
}
