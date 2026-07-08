//! Glyph outline rasterizer with grayscale anti-aliasing (WS7-03.2 / WS7-03.4).
//!
//! Consumes a font [`Outline`] (design units, Y-up; from [`crate::font`]) and
//! produces a [`GlyphBitmap`]: an 8-bit **coverage** (alpha) map plus placement
//! bearings. Quadratic Bézier segments (off-curve points, with the `TrueType`
//! implied-midpoint rule) are flattened to line segments; the closed contours
//! are then filled with the **non-zero winding** rule. Coverage is computed by
//! `NxN` supersampling per pixel, which yields grayscale anti-aliasing for free
//! (the fraction of covered sub-samples becomes the pixel's alpha).
//!
//! [`rasterize_lcd`] additionally produces **subpixel (LCD) anti-aliasing**
//! (WS7-03.5): it samples coverage at 3× horizontal resolution (one column per
//! R/G/B stripe of an RGB panel) and runs a 5-tap FIR color-balancing filter to
//! suppress color fringing, yielding an independent alpha per channel.
//!
//! [`rasterize_subpixel`] renders a glyph translated by a fractional pen
//! position (WS7-03.7), redistributing coverage across the pixel grid so glyphs
//! land on exact sub-pixel positions for even spacing.
//!
//! `no_std + alloc`. Hinting (WS7-03.3) and the GPU glyph atlas (WS7-03.9) build
//! on these coverage maps.

// A rasterizer is inherently floating-point and casts between pixel indices and
// device coordinates; coverage is an integer quantization. All buffer writes go
// through sequential `Vec::push` (no indexing), so these are safe.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::integer_division
)]

use alloc::vec::Vec;

use crate::font::Outline;

/// Sub-samples per axis (`NxN`) for anti-aliasing. 4 → 16 samples/pixel, so
/// coverage is quantized to 1/16 steps, and `count * 255 / 16` is exact.
const SS: usize = 4;
const SS_SQ: usize = SS * SS;
/// Flattening steps per quadratic Bézier segment.
const BEZIER_STEPS: usize = 8;

/// Sub-pixel columns per output pixel for LCD rendering: one per R, G, B stripe.
const LCD_SUBPX: usize = 3;
/// 5-tap FIR color-balancing filter for LCD subpixel AA (`FreeType` default
/// weights). The taps sum to `256`, so a convex combination of `0..=255`
/// sub-pixel coverages stays in `0..=255` after a `>> 8` normalize.
const LCD_FILTER: [u32; 5] = [8, 77, 86, 77, 8];

/// A rasterized glyph: an 8-bit coverage (alpha) bitmap, row-major, Y-down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlyphBitmap {
    /// Width in pixels.
    pub width: usize,
    /// Height in pixels.
    pub height: usize,
    /// `width * height` coverage values, `0..=255` (alpha), top-left origin.
    pub coverage: Vec<u8>,
    /// X bearing: device-space x of the bitmap's left edge, from the pen origin.
    pub left: i32,
    /// Y bearing: device-space y of the bitmap's top edge above the baseline.
    pub top: i32,
}

impl GlyphBitmap {
    /// An empty bitmap (e.g. for a whitespace glyph).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            width: 0,
            height: 0,
            coverage: Vec::new(),
            left: 0,
            top: 0,
        }
    }

    /// `true` if the bitmap has no pixels.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

#[derive(Clone, Copy)]
struct Edge {
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
}

#[derive(Clone, Copy)]
struct V {
    x: f32,
    y: f32,
    on: bool,
}

fn midpoint(a: V, b: V) -> V {
    V {
        x: (a.x + b.x) * 0.5,
        y: (a.y + b.y) * 0.5,
        on: true,
    }
}

/// Flattened outline plus its device-space placement, shared by [`rasterize`]
/// and [`rasterize_lcd`].
struct Prepared {
    /// Flattened line edges in device space (Y-up).
    edges: Vec<Edge>,
    /// Device-space x of the bitmap's left edge (pixel-aligned).
    ox: f32,
    /// Device-space y of the bitmap's top edge (pixel-aligned, Y-up).
    y_top: f32,
    /// Bitmap width in pixels.
    width: usize,
    /// Bitmap height in pixels.
    height: usize,
    /// Top bearing: device-space y of the top edge above the baseline.
    top: i32,
}

/// Flattens `outline` to edges and computes its pixel bounding box, or returns
/// `None` for an empty outline / non-positive / non-finite scale.
///
/// `x_offset` translates the outline horizontally in device pixels before the
/// (pixel-aligned) bounding box is computed, which is how subpixel glyph
/// positioning (WS7-03.7) is realised: a fractional pen position shifts the
/// sampling grid relative to the outline, so the anti-aliased coverage reflects
/// the true sub-pixel placement. `x_offset == 0.0` leaves geometry untouched
/// (adding `0.0` to a finite `f32` is exact), so the non-positioned paths stay
/// bit-identical.
fn prepare(
    outline: &Outline,
    units_per_em: u16,
    px_per_em: f32,
    x_offset: f32,
) -> Option<Prepared> {
    prepare_mapped(outline, units_per_em, px_per_em, x_offset, |y| y)
}

/// Like [`prepare`], but also remaps each edge's device-space `y` through
/// `remap` — used for vertical grid-fitting / hinting (WS7-03.3).
fn prepare_mapped(
    outline: &Outline,
    units_per_em: u16,
    px_per_em: f32,
    x_offset: f32,
    remap: impl Fn(f32) -> f32,
) -> Option<Prepared> {
    // Reject empty outlines and any non-positive or non-finite scale. Testing
    // `!is_finite()` first also discards NaN (which would slip past `<= 0.0`).
    if outline.contours.is_empty()
        || units_per_em == 0
        || !px_per_em.is_finite()
        || px_per_em <= 0.0
        || !x_offset.is_finite()
    {
        return None;
    }
    let scale = px_per_em / f32::from(units_per_em);

    // Flatten every contour to scaled line segments (device space, Y-up).
    let mut edges: Vec<Edge> = Vec::new();
    for contour in &outline.contours {
        flatten_contour(contour, scale, &mut edges);
    }
    if edges.is_empty() {
        return None;
    }

    // Apply the subpixel horizontal offset and the (hinting) vertical remap.
    // Both are bit-exact no-ops on the default paths (x_offset 0.0, identity
    // map_y), so unhinted rasterization is unchanged.
    for e in &mut edges {
        e.x0 += x_offset;
        e.x1 += x_offset;
        e.y0 = remap(e.y0);
        e.y1 = remap(e.y1);
    }

    // Device-space bounding box of the flattened outline.
    let mut min_x = f32::INFINITY;
    let mut min_y = f32::INFINITY;
    let mut max_x = f32::NEG_INFINITY;
    let mut max_y = f32::NEG_INFINITY;
    for e in &edges {
        min_x = min_x.min(e.x0).min(e.x1);
        min_y = min_y.min(e.y0).min(e.y1);
        max_x = max_x.max(e.x0).max(e.x1);
        max_y = max_y.max(e.y0).max(e.y1);
    }

    let ox = libm_floor(min_x);
    let oy = libm_floor(min_y);
    let width = (libm_ceil(max_x) - ox) as usize;
    let height = (libm_ceil(max_y) - oy) as usize;
    if width == 0 || height == 0 {
        return None;
    }

    Some(Prepared {
        edges,
        ox,
        y_top: oy + height as f32,
        width,
        height,
        top: libm_ceil(max_y) as i32,
    })
}

/// Rasterizes `outline` at `px_per_em` pixels per em, given the font's
/// `units_per_em`, into a grayscale coverage bitmap.
///
/// Returns [`GlyphBitmap::empty`] for an empty outline or a non-positive size.
#[must_use]
pub fn rasterize(outline: &Outline, units_per_em: u16, px_per_em: f32) -> GlyphBitmap {
    rasterize_subpixel(outline, units_per_em, px_per_em, 0.0)
}

/// Rasterizes `outline` translated by a fractional `x_offset` (device pixels),
/// for subpixel glyph positioning (WS7-03.7).
///
/// The integer part of `x_offset` simply shifts the bitmap's [`GlyphBitmap::left`]
/// bearing; the fractional part redistributes anti-aliased coverage across the
/// pixel grid, so glyphs land on exact sub-pixel pen positions. With
/// `x_offset == 0.0` the result is bit-identical to [`rasterize`].
///
/// Returns [`GlyphBitmap::empty`] for an empty outline or a non-positive size.
#[must_use]
pub fn rasterize_subpixel(
    outline: &Outline,
    units_per_em: u16,
    px_per_em: f32,
    x_offset: f32,
) -> GlyphBitmap {
    let Some(p) = prepare(outline, units_per_em, px_per_em, x_offset) else {
        return GlyphBitmap::empty();
    };
    fill(&p)
}

/// Rasterizes `outline` with vertical grid-fitting (hinting, WS7-03.3) applied
/// through `hinter`, sharpening horizontal features at small sizes.
///
/// With an identity hinter ([`crate::hint::Hinter::is_identity`]) the result is
/// bit-identical to [`rasterize`]. Returns [`GlyphBitmap::empty`] for an empty
/// outline or a non-positive size.
#[must_use]
pub fn rasterize_hinted(
    outline: &Outline,
    units_per_em: u16,
    px_per_em: f32,
    hinter: &crate::hint::Hinter,
) -> GlyphBitmap {
    let Some(p) = prepare_mapped(outline, units_per_em, px_per_em, 0.0, |y| hinter.remap_y(y))
    else {
        return GlyphBitmap::empty();
    };
    fill(&p)
}

/// Samples a prepared outline into a grayscale coverage bitmap using `NxN`
/// supersampling with the non-zero winding rule.
fn fill(p: &Prepared) -> GlyphBitmap {
    let inv_ss = 1.0 / SS as f32;
    let mut coverage = Vec::with_capacity(p.width * p.height);
    for row in 0..p.height {
        for col in 0..p.width {
            let mut hits = 0usize;
            for sy in 0..SS {
                let py = p.y_top - row as f32 - (sy as f32 + 0.5) * inv_ss;
                for sx in 0..SS {
                    let px = p.ox + col as f32 + (sx as f32 + 0.5) * inv_ss;
                    if winding_at(&p.edges, px, py) != 0 {
                        hits += 1;
                    }
                }
            }
            coverage.push((hits * 255 / SS_SQ) as u8);
        }
    }
    GlyphBitmap {
        width: p.width,
        height: p.height,
        coverage,
        left: p.ox as i32,
        top: p.top,
    }
}

/// A rasterized glyph with subpixel (LCD) anti-aliasing: an independent 8-bit
/// coverage per R, G, B stripe, interleaved row-major (`R, G, B, R, G, B, …`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcdGlyphBitmap {
    /// Width in (whole) pixels.
    pub width: usize,
    /// Height in pixels.
    pub height: usize,
    /// `width * height * 3` coverage values: three (R, G, B) per pixel.
    pub coverage: Vec<u8>,
    /// X bearing: device-space x of the bitmap's left edge, from the pen origin.
    pub left: i32,
    /// Y bearing: device-space y of the bitmap's top edge above the baseline.
    pub top: i32,
}

impl LcdGlyphBitmap {
    /// An empty bitmap (e.g. for a whitespace glyph).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            width: 0,
            height: 0,
            coverage: Vec::new(),
            left: 0,
            top: 0,
        }
    }

    /// `true` if the bitmap has no pixels.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// The `[R, G, B]` coverage triple at `(col, row)`; zeros if out of bounds.
    #[must_use]
    pub fn rgb(&self, col: usize, row: usize) -> [u8; 3] {
        let base = (row * self.width + col) * LCD_SUBPX;
        [
            self.coverage.get(base).copied().unwrap_or(0),
            self.coverage.get(base + 1).copied().unwrap_or(0),
            self.coverage.get(base + 2).copied().unwrap_or(0),
        ]
    }
}

/// Rasterizes `outline` with subpixel (LCD) anti-aliasing for a horizontal-RGB
/// panel.
///
/// Coverage is sampled at 3× horizontal resolution (one column per R/G/B stripe)
/// and color-balanced with a 5-tap FIR filter (`LCD_FILTER`).
///
/// Returns [`LcdGlyphBitmap::empty`] for an empty outline or a non-positive size.
#[must_use]
pub fn rasterize_lcd(outline: &Outline, units_per_em: u16, px_per_em: f32) -> LcdGlyphBitmap {
    let Some(p) = prepare(outline, units_per_em, px_per_em, 0.0) else {
        return LcdGlyphBitmap::empty();
    };

    // Stage 1: coverage at 1/3-pixel horizontal resolution (one value per
    // sub-pixel column), vertical AA via the same NxN supersampling.
    let sub_cols = p.width * LCD_SUBPX;
    let inv_ss = 1.0 / SS as f32;
    let inv_sub = 1.0 / LCD_SUBPX as f32;
    let mut sub = Vec::with_capacity(sub_cols * p.height);
    for row in 0..p.height {
        for scol in 0..sub_cols {
            let mut hits = 0usize;
            for sy in 0..SS {
                let py = p.y_top - row as f32 - (sy as f32 + 0.5) * inv_ss;
                for sx in 0..SS {
                    // x spans the 1/3-px-wide sub-pixel column `scol`.
                    let px = p.ox + (scol as f32 + (sx as f32 + 0.5) * inv_ss) * inv_sub;
                    if winding_at(&p.edges, px, py) != 0 {
                        hits += 1;
                    }
                }
            }
            sub.push((hits * 255 / SS_SQ) as u8);
        }
    }

    // Stage 2: per channel, convolve the FIR filter over neighbouring sub-pixel
    // columns (out-of-range neighbours count as zero coverage).
    let mut coverage = Vec::with_capacity(p.width * p.height * LCD_SUBPX);
    for row in 0..p.height {
        let base = row * sub_cols;
        for col in 0..p.width {
            for ch in 0..LCD_SUBPX {
                let center = (col * LCD_SUBPX + ch) as isize;
                let mut acc = 0u32;
                for (k, &weight) in LCD_FILTER.iter().enumerate() {
                    let idx = center + k as isize - 2;
                    if idx >= 0 && (idx as usize) < sub_cols {
                        let s = sub.get(base + idx as usize).copied().unwrap_or(0);
                        acc += weight * u32::from(s);
                    }
                }
                coverage.push(((acc + 128) >> 8) as u8);
            }
        }
    }

    LcdGlyphBitmap {
        width: p.width,
        height: p.height,
        coverage,
        left: p.ox as i32,
        top: p.top,
    }
}

/// Non-zero winding number of point `(px, py)` against the flattened edges.
fn winding_at(edges: &[Edge], px: f32, py: f32) -> i32 {
    let mut w = 0;
    for e in edges {
        if e.y0 <= py {
            if e.y1 > py && cross(e, px, py) > 0.0 {
                w += 1;
            }
        } else if e.y1 <= py && cross(e, px, py) < 0.0 {
            w -= 1;
        }
    }
    w
}

/// Signed area of the triangle (edge.start, edge.end, point) — left/right test.
fn cross(e: &Edge, px: f32, py: f32) -> f32 {
    (e.x1 - e.x0) * (py - e.y0) - (e.y1 - e.y0) * (px - e.x0)
}

// Every index into `pts` below is provably in bounds: `i` comes from
// `position()` (so `i < n`), `n - 1` and `0` are valid because we returned
// early unless `n >= 2`, and `(begin + k) % n` is reduced modulo `n`.
#[allow(
    clippy::indexing_slicing,
    reason = "all indices into pts are bounded by n; see comment above"
)]
fn flatten_contour(contour: &[crate::font::Point], scale: f32, out: &mut Vec<Edge>) {
    if contour.len() < 2 {
        return;
    }
    let pts: Vec<V> = contour
        .iter()
        .map(|p| V {
            x: f32::from(p.x) * scale,
            y: f32::from(p.y) * scale,
            on: p.on_curve,
        })
        .collect();
    let n = pts.len();

    // Choose an on-curve starting point (synthesize the midpoint when a contour
    // begins and ends off-curve, per the TrueType implied-point rule).
    let (start, begin) = pts
        .iter()
        .position(|p| p.on)
        .map_or_else(|| (midpoint(pts[n - 1], pts[0]), 0), |i| (pts[i], i));

    let mut cur = start;
    let mut pending: Option<V> = None;
    for k in 1..=n {
        let p = pts[(begin + k) % n];
        if p.on {
            match pending.take() {
                Some(c) => push_quad(out, cur, c, p),
                None => push_line(out, cur, p),
            }
            cur = p;
        } else if let Some(c) = pending.take() {
            // Two consecutive off-curve points imply an on-curve midpoint.
            let mid = midpoint(c, p);
            push_quad(out, cur, c, mid);
            cur = mid;
            pending = Some(p);
        } else {
            pending = Some(p);
        }
    }
    if let Some(c) = pending.take() {
        push_quad(out, cur, c, start);
    }
}

fn push_line(out: &mut Vec<Edge>, a: V, b: V) {
    if (a.x - b.x).abs() > f32::EPSILON || (a.y - b.y).abs() > f32::EPSILON {
        out.push(Edge {
            x0: a.x,
            y0: a.y,
            x1: b.x,
            y1: b.y,
        });
    }
}

fn push_quad(out: &mut Vec<Edge>, p0: V, c: V, p1: V) {
    let mut prev = p0;
    for i in 1..=BEZIER_STEPS {
        let t = i as f32 / BEZIER_STEPS as f32;
        let mt = 1.0 - t;
        let x = mt * mt * p0.x + 2.0 * mt * t * c.x + t * t * p1.x;
        let y = mt * mt * p0.y + 2.0 * mt * t * c.y + t * t * p1.y;
        let next = V { x, y, on: true };
        push_line(out, prev, next);
        prev = next;
    }
}

// Minimal floor/ceil for `f32` (avoids depending on libm in this no_std crate;
// inputs here are small, finite glyph coordinates).
fn libm_floor(x: f32) -> f32 {
    let t = x as i64 as f32;
    if t > x { t - 1.0 } else { t }
}
fn libm_ceil(x: f32) -> f32 {
    let t = x as i64 as f32;
    if t < x { t + 1.0 } else { t }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::font::Point;

    fn on(x: i16, y: i16) -> Point {
        Point {
            x,
            y,
            on_curve: true,
        }
    }
    fn off(x: i16, y: i16) -> Point {
        Point {
            x,
            y,
            on_curve: false,
        }
    }

    fn outline(contour: Vec<Point>) -> Outline {
        Outline {
            contours: alloc::vec![contour],
            advance: 0,
            x_min: 0,
            y_min: 0,
            x_max: 64,
            y_max: 64,
        }
    }

    fn cov(bmp: &GlyphBitmap, col: usize, row: usize) -> u8 {
        bmp.coverage[row * bmp.width + col]
    }

    #[test]
    fn empty_outline_is_empty_bitmap() {
        let o = Outline {
            contours: Vec::new(),
            advance: 0,
            x_min: 0,
            y_min: 0,
            x_max: 0,
            y_max: 0,
        };
        assert!(rasterize(&o, 64, 64.0).is_empty());
    }

    #[test]
    fn square_is_fully_covered() {
        // 64x64 square at scale 1 (units_per_em = px_per_em = 64).
        let sq = outline(alloc::vec![on(0, 0), on(64, 0), on(64, 64), on(0, 64)]);
        let b = rasterize(&sq, 64, 64.0);
        assert_eq!((b.width, b.height), (64, 64));
        // Interior is solid; the square fills its whole bbox.
        assert_eq!(cov(&b, 32, 32), 255);
        assert_eq!(cov(&b, 5, 5), 255);
        // Total coverage ≈ area (64*64).
        let area: usize = b.coverage.iter().map(|&c| c as usize).sum::<usize>() / 255;
        assert!((area as i32 - 64 * 64).abs() <= 130, "area {area}");
    }

    #[test]
    fn triangle_fills_below_diagonal_with_aa_edge() {
        // Right triangle (0,0),(64,0),(0,64); hypotenuse x + y = 64.
        let tri = outline(alloc::vec![on(0, 0), on(64, 0), on(0, 64)]);
        let b = rasterize(&tri, 64, 64.0);
        assert_eq!((b.width, b.height), (64, 64));
        // Clearly inside (near the right-angle corner): solid.
        assert_eq!(cov(&b, 3, 60), 255); // x≈3, y≈3  (row 60 → low y)
        // Clearly outside (top-right beyond the hypotenuse): empty.
        assert_eq!(cov(&b, 60, 2), 0); // x≈60, y≈61 → x+y≈121
        // The hypotenuse produces partial-coverage anti-aliased pixels.
        assert!(
            b.coverage.iter().any(|&c| c > 0 && c < 255),
            "expected AA edge pixels"
        );
        // Area ≈ half the square.
        let area: usize = b.coverage.iter().map(|&c| c as usize).sum::<usize>() / 255;
        assert!((area as i32 - 64 * 64 / 2).abs() <= 130, "area {area}");
    }

    #[test]
    fn quadratic_curve_contour_rasterizes_nonempty() {
        // on(0,0) -> [off control (64,0)] -> on(64,64), closed back to start.
        let curved = outline(alloc::vec![on(0, 0), off(64, 0), on(64, 64)]);
        let b = rasterize(&curved, 64, 64.0);
        assert!(!b.is_empty());
        assert!(
            b.coverage.iter().any(|&c| c == 255),
            "curve interior should fill"
        );
        assert!(
            b.coverage.iter().any(|&c| c == 0),
            "curve leaves uncovered area"
        );
    }

    #[test]
    fn scaling_halves_the_bitmap() {
        let sq = outline(alloc::vec![on(0, 0), on(64, 0), on(64, 64), on(0, 64)]);
        let b = rasterize(&sq, 64, 32.0); // half size
        assert_eq!((b.width, b.height), (32, 32));
    }

    #[test]
    fn subpixel_zero_offset_matches_rasterize() {
        let sq = outline(alloc::vec![on(0, 0), on(64, 0), on(64, 64), on(0, 64)]);
        let plain = rasterize(&sq, 64, 64.0);
        let shifted = rasterize_subpixel(&sq, 64, 64.0, 0.0);
        assert_eq!(plain, shifted, "x_offset 0.0 must be bit-identical");
    }

    #[test]
    fn subpixel_integer_offset_only_moves_the_bearing() {
        // A whole-pixel shift translates the bitmap without changing coverage.
        let sq = outline(alloc::vec![on(0, 0), on(64, 0), on(64, 64), on(0, 64)]);
        let base = rasterize(&sq, 64, 64.0);
        let moved = rasterize_subpixel(&sq, 64, 64.0, 1.0);
        assert_eq!((moved.width, moved.height), (base.width, base.height));
        assert_eq!(moved.left, base.left + 1);
        assert_eq!(moved.coverage, base.coverage);
    }

    #[test]
    fn subpixel_half_offset_splits_edge_coverage() {
        // The pixel-aligned square is sharp (no horizontal AA). Shifting it by
        // half a pixel must spill coverage into one extra column and soften the
        // two vertical edges to partial coverage.
        let sq = outline(alloc::vec![on(0, 0), on(64, 0), on(64, 64), on(0, 64)]);
        let sharp = rasterize(&sq, 64, 64.0);
        assert_eq!(cov(&sharp, 0, 32), 255); // sharp left edge: fully covered

        let half = rasterize_subpixel(&sq, 64, 64.0, 0.5);
        assert_eq!(half.height, 64);
        assert_eq!(half.width, 65, "half-pixel shift widens the bitmap by one");
        // Leftmost column now only half-covered horizontally.
        let left_edge = cov(&half, 0, 32);
        assert!(0 < left_edge && left_edge < 255, "left edge {left_edge}");
        // Rightmost column likewise partial.
        let right_edge = cov(&half, 64, 32);
        assert!(
            0 < right_edge && right_edge < 255,
            "right edge {right_edge}"
        );
        // Interior stays solid.
        assert_eq!(cov(&half, 32, 32), 255);
    }

    #[test]
    fn subpixel_non_finite_offset_is_empty() {
        let sq = outline(alloc::vec![on(0, 0), on(64, 0), on(64, 64), on(0, 64)]);
        assert!(rasterize_subpixel(&sq, 64, 64.0, f32::NAN).is_empty());
    }

    #[test]
    fn lcd_empty_outline_is_empty() {
        let o = Outline {
            contours: Vec::new(),
            advance: 0,
            x_min: 0,
            y_min: 0,
            x_max: 0,
            y_max: 0,
        };
        assert!(rasterize_lcd(&o, 64, 64.0).is_empty());
    }

    #[test]
    fn lcd_has_three_channels_and_opaque_interior() {
        let sq = outline(alloc::vec![on(0, 0), on(64, 0), on(64, 64), on(0, 64)]);
        let b = rasterize_lcd(&sq, 64, 64.0);
        assert_eq!((b.width, b.height), (64, 64));
        // One (R, G, B) triple per pixel.
        assert_eq!(b.coverage.len(), b.width * b.height * 3);
        // Deep interior: every channel fully opaque (filter taps sum to 256).
        assert_eq!(b.rgb(32, 32), [255, 255, 255]);
    }

    #[test]
    fn lcd_diagonal_edge_shows_subpixel_color_fringing() {
        // A diagonal hypotenuse crosses pixels at sub-pixel offsets, so the R
        // (left) and B (right) stripes of an edge pixel see different coverage.
        let tri = outline(alloc::vec![on(0, 0), on(64, 0), on(0, 64)]);
        let b = rasterize_lcd(&tri, 64, 64.0);
        assert_eq!((b.width, b.height), (64, 64));
        // Solid interior corner stays neutral on all channels.
        assert_eq!(b.rgb(3, 60), [255, 255, 255]);
        // Somewhere on the slanted edge, the red and blue stripes differ —
        // exactly the subpixel resolution grayscale AA cannot express.
        let fringed = (0..b.height).any(|row| {
            (0..b.width).any(|col| {
                let [r, _g, blue] = b.rgb(col, row);
                r != blue
            })
        });
        assert!(
            fringed,
            "expected per-channel subpixel coverage on the edge"
        );
    }

    #[test]
    fn hinted_with_identity_matches_rasterize() {
        let sq = outline(alloc::vec![on(0, 0), on(64, 0), on(64, 64), on(0, 64)]);
        // Baseline-only zones -> identity hinter.
        let id = crate::hint::Hinter::new(64, 16.0, &[]);
        assert!(id.is_identity());
        assert_eq!(
            rasterize_hinted(&sq, 64, 16.0, &id),
            rasterize(&sq, 64, 16.0)
        );
    }

    #[test]
    fn hinted_snaps_top_edge_and_changes_coverage() {
        // A 650-unit box at 10px lands its top edge at device y 6.5; a zone at
        // 650 snaps it to 7.0, sharpening the top row.
        let box650 = outline(alloc::vec![on(0, 0), on(650, 0), on(650, 650), on(0, 650)]);
        let unhinted = rasterize(&box650, 1000, 10.0);
        let h = crate::hint::Hinter::new(1000, 10.0, &[650]);
        assert!(!h.is_identity());
        let hinted = rasterize_hinted(&box650, 1000, 10.0, &h);
        assert!(!hinted.is_empty());
        assert_eq!(
            (hinted.width, hinted.height),
            (unhinted.width, unhinted.height)
        );
        assert_ne!(
            hinted.coverage, unhinted.coverage,
            "hinting should sharpen the top edge"
        );
    }
}
