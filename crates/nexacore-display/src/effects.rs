//! Compositor surface effects: gaussian background blur (WS7-01.6), soft drop
//! shadows (WS7-01.7) and rounded-corner clipping (WS7-01.8).
//!
//! Everything here is pure geometry / coverage math over the compositor's
//! `0xAARRGGBB` pixels, so it is fully host-testable before the GPU shader path
//! lands (rig). A capable GPU backend ([`crate::render_backend::BackendCapabilities`])
//! offloads these; on the software backend they run on the CPU.
//!
//! The shadow and material parameters mirror the WS7-00 HIG elevation/material
//! tokens (`nexacore-ui::tokens`) by value — this crate sits *below* `nexacore-ui`
//! in the dependency graph, so the engine is parameterised by raw numbers and
//! the binding to the named tokens happens in the UI layer.

// Coverage/alpha math is `0..=255`; blur kernels are fixed-point. The casts are
// range-bounded and the float path (gaussian weights, corner anti-aliasing
// distance) uses `libm` to stay `no_std`.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::float_arithmetic,
    clippy::integer_division,
    clippy::many_single_char_names
)]

use alloc::vec::Vec;

use crate::geometry::Rect;

// ===========================================================================
// Blur (WS7-01.6)
// ===========================================================================

/// Fixed-point scale for blur kernel weights (weights sum to this).
pub const KERNEL_SCALE: u32 = 4096;

/// Build a normalised 1-D gaussian blur kernel for `radius` (px).
///
/// Returns `2*radius + 1` weights summing to [`KERNEL_SCALE`] (fixed-point, so
/// the convolution is integer). `sigma = radius / 2`, the standard "visually
/// matches a `radius`-px blur" choice. `radius == 0` yields the identity kernel
/// `[KERNEL_SCALE]`.
#[must_use]
pub fn gaussian_kernel_1d(radius: u32) -> Vec<u16> {
    if radius == 0 {
        return alloc::vec![KERNEL_SCALE as u16];
    }
    let sigma = (radius as f32) / 2.0;
    let two_sigma_sq = 2.0 * sigma * sigma;
    let n = (radius * 2 + 1) as usize;
    let mut raw = Vec::with_capacity(n);
    let mut sum = 0.0f32;
    for i in 0..n {
        let x = i as f32 - radius as f32;
        let w = libm::expf(-(x * x) / two_sigma_sq);
        raw.push(w);
        sum += w;
    }
    // Normalise to KERNEL_SCALE, then fix rounding drift on the centre tap so
    // the weights sum to exactly KERNEL_SCALE (energy-preserving).
    let mut weights: Vec<u16> = raw
        .iter()
        .map(|&w| ((w / sum) * KERNEL_SCALE as f32 + 0.5) as u16)
        .collect();
    let total: u32 = weights.iter().map(|&w| u32::from(w)).sum();
    if let Some(centre) = weights.get_mut(radius as usize) {
        let drift = KERNEL_SCALE as i32 - total as i32;
        *centre = (i32::from(*centre) + drift).max(0) as u16;
    }
    weights
}

/// The three box-blur pass widths that approximate a gaussian of the given
/// `radius` (Wells' three-box approximation).
///
/// Running three successive box blurs of these widths is visually close to a
/// true gaussian but costs O(1) per pixel per pass — the technique a software
/// backend uses for large-radius vibrancy blurs.
#[must_use]
pub fn box_blur_sizes(radius: u32) -> [u32; 3] {
    if radius == 0 {
        return [1, 1, 1];
    }
    // Ideal box width for n=3 passes: w = sqrt(12*sigma^2/n + 1).
    let sigma = (radius as f32) / 2.0;
    let n = 3.0f32;
    let w_ideal = libm::sqrtf(12.0 * sigma * sigma / n + 1.0);
    let mut wl = libm::floorf(w_ideal) as u32;
    if wl % 2 == 0 {
        wl = wl.saturating_sub(1);
    }
    let wl = wl.max(1);
    let wu = wl + 2;
    // Number of lower-width passes m, rounded.
    let m_ideal =
        (12.0 * sigma * sigma - (n * (wl as f32) * (wl as f32)) - 4.0 * n * (wl as f32) - 3.0 * n)
            / (-4.0 * (wl as f32) - 4.0);
    let m = libm::roundf(m_ideal) as i32;
    [
        if 0 < m { wl } else { wu },
        if 1 < m { wl } else { wu },
        if 2 < m { wl } else { wu },
    ]
}

/// Convolve a 1-D coverage signal with `kernel` (edges clamped), returning a new
/// signal of the same length. Used to soften shadow penumbra and as the
/// separable building block of a full 2-D blur.
#[must_use]
pub fn convolve_1d(samples: &[u8], kernel: &[u16]) -> Vec<u8> {
    let n = samples.len();
    let klen = kernel.len();
    if n == 0 || klen == 0 {
        return Vec::new();
    }
    let half = (klen / 2) as i64;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut acc: u32 = 0;
        for (k, &w) in kernel.iter().enumerate() {
            let idx = (i as i64 + k as i64 - half).clamp(0, n as i64 - 1) as usize;
            let s = samples.get(idx).copied().unwrap_or(0);
            acc += u32::from(s) * u32::from(w);
        }
        out.push((acc / KERNEL_SCALE).min(255) as u8);
    }
    out
}

// ===========================================================================
// Shadows (WS7-01.7) — mirrors nexacore-ui::tokens::{Shadow, Elevation}
// ===========================================================================

/// A soft drop shadow (mirrors the WS7-00 `tokens::Shadow`): vertical offset,
/// gaussian blur radius and spread (px), and an `0xAARRGGBB` colour whose alpha
/// byte carries the shadow opacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shadow {
    /// Vertical offset in px (positive falls downward).
    pub offset_y: i16,
    /// Gaussian blur radius in px.
    pub blur: u16,
    /// Spread in px (grows/shrinks the casting rect before blurring).
    pub spread: i16,
    /// Shadow colour, `0xAARRGGBB` (alpha = peak opacity).
    pub color: u32,
}

/// One elevation level (mirrors the WS7-00 `tokens::Elevation`): a primary
/// shadow plus an optional tight contact shadow used by higher levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elevation {
    /// Primary drop shadow.
    pub primary: Shadow,
    /// Optional tight ambient/contact shadow.
    pub contact: Option<Shadow>,
}

/// The "core" rect a shadow casts from: `window` grown by `spread` and shifted
/// down by `offset_y`. The visible shadow extends [`Shadow::blur`] px beyond
/// this on every side.
#[must_use]
pub fn shadow_core(window: Rect, s: Shadow) -> Rect {
    let spread = i64::from(s.spread);
    let x = i64::from(window.x) - spread;
    let y = i64::from(window.y) - spread + i64::from(s.offset_y);
    let w = i64::from(window.w) + 2 * spread;
    let h = i64::from(window.h) + 2 * spread;
    Rect {
        x: x as i32,
        y: y as i32,
        w: w.max(0) as u32,
        h: h.max(0) as u32,
    }
}

/// The full bounding rect the shadow can touch (core grown by the blur radius).
#[must_use]
pub fn shadow_bounds(window: Rect, s: Shadow) -> Rect {
    let core = shadow_core(window, s);
    let b = i64::from(s.blur);
    Rect {
        x: (i64::from(core.x) - b) as i32,
        y: (i64::from(core.y) - b) as i32,
        w: (i64::from(core.w) + 2 * b) as u32,
        h: (i64::from(core.h) + 2 * b) as u32,
    }
}

/// Shadow alpha (`0..=255`) at screen pixel `(px, py)`.
///
/// Full inside the core rect, falling off smoothly to `0` across the blur band
/// (euclidean edge distance, gaussian-shaped falloff). Returns `0` outside the
/// blurred bounds. The base opacity is the shadow colour's alpha byte.
#[must_use]
pub fn shadow_alpha_at(window: Rect, s: Shadow, px: i32, py: i32) -> u8 {
    let base = (s.color >> 24) & 0xFF;
    if base == 0 {
        return 0;
    }
    let core = shadow_core(window, s);
    if core.w == 0 || core.h == 0 {
        return 0;
    }
    // Euclidean distance from the point to the core rect (0 if inside).
    let dx = clamp_outside(px, core.x, core.x.saturating_add(core.w as i32));
    let dy = clamp_outside(py, core.y, core.y.saturating_add(core.h as i32));
    if dx == 0 && dy == 0 {
        return base as u8;
    }
    let blur = f32::from(s.blur).max(1.0);
    let d = libm::sqrtf((dx * dx + dy * dy) as f32);
    if d >= blur {
        return 0;
    }
    // Gaussian-shaped penumbra: exp(-(d/sigma)^2 / 2), sigma = blur/2.
    let sigma = blur / 2.0;
    let falloff = libm::expf(-(d * d) / (2.0 * sigma * sigma));
    ((base as f32) * falloff + 0.5) as u8
}

/// Signed distance component of `p` outside the half-open interval `[lo, hi)`
/// (0 when inside). Returned as `i64` to feed the squared-distance sum.
fn clamp_outside(p: i32, lo: i32, hi: i32) -> i64 {
    if p < lo {
        i64::from(lo - p)
    } else if p >= hi {
        i64::from(p - hi + 1)
    } else {
        0
    }
}

// ===========================================================================
// Rounded corners (WS7-01.8)
// ===========================================================================

/// A rectangle with uniformly rounded corners (mirrors WS7-00 `tokens::radius`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundedRect {
    /// The bounding rectangle.
    pub rect: Rect,
    /// Corner radius in px, clamped to half the shorter side.
    pub radius: u32,
}

impl RoundedRect {
    /// Build a rounded rect, clamping `radius` to half the shorter side.
    #[must_use]
    pub fn new(rect: Rect, radius: u32) -> Self {
        let max_r = rect.w.min(rect.h) / 2;
        Self {
            rect,
            radius: radius.min(max_r),
        }
    }

    /// Coverage (`0..=255`) of pixel `(px, py)` by the rounded rect: `255`
    /// inside, `0` outside, anti-aliased across a 1-px band on the corner arcs.
    #[must_use]
    pub fn coverage_at(&self, px: i32, py: i32) -> u8 {
        let r = &self.rect;
        let right = r.x.saturating_add(r.w as i32);
        let bottom = r.y.saturating_add(r.h as i32);
        if px < r.x || px >= right || py < r.y || py >= bottom {
            return 0;
        }
        let rad = self.radius as i32;
        if rad == 0 {
            return 255;
        }
        // Corner circle centre nearest this pixel.
        let cx = if px < r.x + rad {
            r.x + rad
        } else if px >= right - rad {
            right - rad - 1
        } else {
            // In the straight middle band → fully covered.
            return 255;
        };
        let cy = if py < r.y + rad {
            r.y + rad
        } else if py >= bottom - rad {
            bottom - rad - 1
        } else {
            return 255;
        };
        let dx = (px - cx) as f32;
        let dy = (py - cy) as f32;
        let dist = libm::sqrtf(dx * dx + dy * dy);
        let radf = rad as f32;
        if dist <= radf - 1.0 {
            255
        } else if dist >= radf {
            0
        } else {
            // 1-px anti-aliased edge.
            (255.0 * (radf - dist) + 0.5) as u8
        }
    }

    /// The fully-covered horizontal span `[x0, x1)` at row `y`, or `None` if the
    /// row is entirely outside (or only AA fringe). Used for fast per-row
    /// clipping of opaque interiors.
    #[must_use]
    pub fn row_span(&self, y: i32) -> Option<(i32, i32)> {
        let r = &self.rect;
        let right = r.x.saturating_add(r.w as i32);
        let bottom = r.y.saturating_add(r.h as i32);
        if y < r.y || y >= bottom {
            return None;
        }
        let rad = self.radius as i32;
        if rad == 0 {
            return Some((r.x, right));
        }
        // How far the rounded corner cuts into this row.
        let inset = if y < r.y + rad {
            corner_inset(rad, (r.y + rad) - y)
        } else if y >= bottom - rad {
            corner_inset(rad, y - (bottom - rad - 1))
        } else {
            0
        };
        let x0 = r.x + inset;
        let x1 = right - inset;
        if x0 < x1 { Some((x0, x1)) } else { None }
    }
}

/// Horizontal inset of a quarter-circle of radius `rad` at vertical distance
/// `dy` from the circle centre: `rad - floor(sqrt(rad^2 - dy^2))`.
fn corner_inset(rad: i32, dy: i32) -> i32 {
    let dy = dy.clamp(0, rad);
    let inner = ((rad * rad) - (dy * dy)).max(0) as f32;
    rad - libm::floorf(libm::sqrtf(inner)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win() -> Rect {
        Rect {
            x: 100,
            y: 100,
            w: 200,
            h: 150,
        }
    }

    #[test]
    fn gaussian_kernel_is_symmetric_and_normalised() {
        let k = gaussian_kernel_1d(4);
        assert_eq!(k.len(), 9);
        let sum: u32 = k.iter().map(|&w| u32::from(w)).sum();
        assert_eq!(sum, KERNEL_SCALE, "energy-preserving");
        // Symmetric and peaked at the centre.
        assert_eq!(k.first(), k.last());
        assert!(k[4] > k[0], "centre tap is the largest");
    }

    #[test]
    fn radius_zero_kernel_is_identity() {
        let k = gaussian_kernel_1d(0);
        assert_eq!(k, alloc::vec![KERNEL_SCALE as u16]);
    }

    #[test]
    fn convolve_blurs_a_step_edge() {
        // Sharp step 0…0,255…255 → midpoint should become intermediate.
        let mut sig = alloc::vec![0u8; 8];
        for s in sig.iter_mut().skip(4) {
            *s = 255;
        }
        let k = gaussian_kernel_1d(2);
        let out = convolve_1d(&sig, &k);
        assert_eq!(out.len(), 8);
        assert!(out[3] > 0 && out[3] < 255, "edge softened: {}", out[3]);
        assert!(out[4] > out[3], "monotone across the edge");
        assert_eq!(out[0], 0, "far interior unchanged");
    }

    #[test]
    fn box_blur_sizes_are_odd_and_three() {
        let s = box_blur_sizes(10);
        assert_eq!(s.len(), 3);
        assert!(s.iter().all(|&w| w % 2 == 1), "box widths odd for symmetry");
    }

    #[test]
    fn shadow_core_offsets_down_and_spreads() {
        let s = Shadow {
            offset_y: 8,
            blur: 24,
            spread: -2,
            color: 0x1F00_0000,
        };
        let core = shadow_core(win(), s);
        // Spread -2 shrinks by 2 each side; offset_y shifts down 8.
        assert_eq!(core.x, 102);
        assert_eq!(core.y, 100 - (-2) + 8); // 110
        assert_eq!(core.w, 196);
    }

    #[test]
    fn shadow_bounds_grows_by_blur() {
        let s = Shadow {
            offset_y: 0,
            blur: 10,
            spread: 0,
            color: 0xFF00_0000,
        };
        let b = shadow_bounds(win(), s);
        assert_eq!(b.x, 90);
        assert_eq!(b.w, 200 + 20);
    }

    #[test]
    fn shadow_alpha_full_inside_zero_far_out() {
        let s = Shadow {
            offset_y: 0,
            blur: 16,
            spread: 0,
            color: 0x8000_0000, // base alpha 128
        };
        // Centre of the window is inside the core → full base alpha.
        assert_eq!(shadow_alpha_at(win(), s, 200, 175), 128);
        // Far outside the blur band → 0.
        assert_eq!(shadow_alpha_at(win(), s, 400, 175), 0);
        // Just outside the edge → partial, less than base.
        let edge = shadow_alpha_at(win(), s, 300 + 4, 175);
        assert!(edge > 0 && edge < 128, "penumbra falloff: {edge}");
    }

    #[test]
    fn rounded_rect_clamps_radius() {
        let rr = RoundedRect::new(
            Rect {
                x: 0,
                y: 0,
                w: 20,
                h: 10,
            },
            100,
        );
        assert_eq!(rr.radius, 5, "clamped to half the shorter side");
    }

    #[test]
    fn rounded_corner_coverage() {
        let rr = RoundedRect::new(
            Rect {
                x: 0,
                y: 0,
                w: 100,
                h: 100,
            },
            16,
        );
        // Centre is fully covered.
        assert_eq!(rr.coverage_at(50, 50), 255);
        // The extreme corner pixel (0,0) is outside the arc → 0.
        assert_eq!(rr.coverage_at(0, 0), 0);
        // A point well inside the straight edge band is covered.
        assert_eq!(rr.coverage_at(50, 0), 255);
        // Outside the rect entirely → 0.
        assert_eq!(rr.coverage_at(-1, 50), 0);
    }

    #[test]
    fn rounded_row_span_narrows_at_top() {
        let rr = RoundedRect::new(
            Rect {
                x: 0,
                y: 0,
                w: 100,
                h: 100,
            },
            20,
        );
        let top = rr.row_span(0).unwrap();
        let mid = rr.row_span(50).unwrap();
        let top_w = top.1 - top.0;
        let mid_w = mid.1 - mid.0;
        assert!(top_w < mid_w, "top row is inset by the corners");
        assert_eq!(mid, (0, 100), "middle row spans full width");
        assert!(rr.row_span(200).is_none(), "row outside the rect");
    }
}
