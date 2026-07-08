//! Glyph grid-fitting (light autohinting) for small sizes (WS7-03.3).
//!
//! At small pixel sizes the dominant cause of blurry text is horizontal
//! features — the baseline, x-height, cap-height, and the tops/bottoms of
//! stems — falling *between* pixel rows, so their anti-aliased coverage smears
//! across two rows instead of landing crisply on one. Hinting fixes this by
//! snapping those reference positions to the pixel grid.
//!
//! This module implements **vertical grid-fitting against alignment zones**
//! (the same idea as a `FreeType` autohinter's blue zones), which is the safe,
//! high-impact core of small-size hinting:
//!
//! * The caller supplies *alignment zones* — design-unit Y positions that
//!   should sit on a pixel boundary (baseline 0 is always included; typical
//!   extras are x-height, cap-height, ascender, descender, taken from the
//!   font's vertical metrics).
//! * [`Hinter::new`] scales each zone to device space and snaps it to the
//!   nearest pixel, yielding a per-zone vertical delta.
//! * [`Hinter::remap_y`] applies those deltas to any device-space Y by
//!   piecewise-linear interpolation between zones (and translation beyond the
//!   outermost zones), an order-preserving remap that does not distort glyph
//!   curves between zones. [`crate::raster::rasterize_hinted`] feeds it into the
//!   rasterizer.
//!
//! Out of scope (deliberately): horizontal-stem hinting and the `TrueType`
//! bytecode instruction interpreter (`fpgm`/`prep`/`glyf` programs). The latter
//! is a large stack machine whose visual benefit is validated on the rig
//! (WS7-03.10), not host-side; this autohint needs no font instructions.
//!
//! `no_std + alloc`, dep-free.

// Grid-fitting is inherently floating-point; the floor cast is bounded by small,
// finite device coordinates.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use alloc::vec::Vec;

/// A vertical grid-fitter built for one font scale and a set of alignment zones.
///
/// Construct with [`Hinter::new`]; apply with [`Hinter::remap_y`] (directly) or
/// [`crate::raster::rasterize_hinted`] (end to end).
#[derive(Debug, Clone)]
pub struct Hinter {
    /// `(device_y, delta)` control points sorted by `device_y`, where `delta`
    /// is the shift that lands `device_y` on the pixel grid.
    controls: Vec<(f32, f32)>,
}

impl Hinter {
    /// Builds a hinter for `px_per_em` (given the font's `units_per_em`) that
    /// snaps each design-unit zone in `zones` to the pixel grid.
    ///
    /// The baseline (design Y `0`) is always an alignment zone. A degenerate
    /// scale (`units_per_em == 0`, or a non-finite/non-positive `px_per_em`)
    /// yields an identity hinter (`remap_y` returns its input unchanged).
    #[must_use]
    pub fn new(units_per_em: u16, px_per_em: f32, zones: &[i16]) -> Self {
        let mut controls = Vec::with_capacity(zones.len() + 1);
        if units_per_em != 0 && px_per_em.is_finite() && px_per_em > 0.0 {
            let scale = px_per_em / f32::from(units_per_em);
            for &z in core::iter::once(&0_i16).chain(zones) {
                let device_y = f32::from(z) * scale;
                controls.push((device_y, round_f32(device_y) - device_y));
            }
            controls.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));
        }
        Self { controls }
    }

    /// `true` if this hinter leaves every coordinate unchanged.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.controls.iter().all(|&(_, delta)| delta == 0.0)
    }

    /// Remaps a device-space `y` so the alignment zones land on the pixel grid.
    ///
    /// Between two zones the shift is linearly interpolated; beyond the outermost
    /// zones it is translated by the nearest zone's shift. The result is
    /// monotonic in `y` for well-separated zones, so contour ordering is kept.
    #[must_use]
    pub fn remap_y(&self, y: f32) -> f32 {
        let Some(&first) = self.controls.first() else {
            return y;
        };
        let last = *self.controls.last().unwrap_or(&first);
        if y <= first.0 {
            return y + first.1;
        }
        if y >= last.0 {
            return y + last.1;
        }
        for w in self.controls.windows(2) {
            if let [lo, hi] = w {
                if y >= lo.0 && y <= hi.0 {
                    let span = hi.0 - lo.0;
                    let t = if span > f32::EPSILON {
                        (y - lo.0) / span
                    } else {
                        0.0
                    };
                    return y + lo.1 + (hi.1 - lo.1) * t;
                }
            }
        }
        y
    }
}

/// Rounds `x` to the nearest integer (ties toward `+∞`), without `std`/`libm`.
fn round_f32(x: f32) -> f32 {
    floor_f32(x + 0.5)
}

/// Floor of `x` for the small finite device coordinates used here.
fn floor_f32(x: f32) -> f32 {
    let t = x as i64 as f32;
    if t > x { t - 1.0 } else { t }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_zones_is_identity() {
        // Baseline only -> delta 0 everywhere.
        let h = Hinter::new(1000, 10.0, &[]);
        assert!(h.is_identity());
        for &y in &[-3.2_f32, 0.0, 1.7, 9.9] {
            assert!((h.remap_y(y) - y).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn degenerate_scale_is_identity() {
        assert!(Hinter::new(0, 10.0, &[500]).is_identity());
        assert!(Hinter::new(1000, f32::NAN, &[500]).is_identity());
        assert!(Hinter::new(1000, -4.0, &[500]).is_identity());
    }

    #[test]
    fn zone_snaps_to_pixel_grid() {
        // units 1000, ppem 10 -> scale 0.01. x-height 550 -> device 5.5 -> snap 6.
        let h = Hinter::new(1000, 10.0, &[550]);
        assert!(!h.is_identity());
        // Baseline stays put.
        assert!((h.remap_y(0.0) - 0.0).abs() < 1e-4);
        // The zone itself lands exactly on the grid.
        assert!(
            (h.remap_y(5.5) - 6.0).abs() < 1e-4,
            "got {}",
            h.remap_y(5.5)
        );
        // Halfway between baseline and the zone, the +0.5 shift is half applied.
        assert!(
            (h.remap_y(2.75) - 3.0).abs() < 1e-4,
            "got {}",
            h.remap_y(2.75)
        );
    }

    #[test]
    fn translates_beyond_outermost_zone() {
        // x-height 550 -> 5.5 -> snap 6 (delta +0.5). Above it, translate by +0.5.
        let h = Hinter::new(1000, 10.0, &[550]);
        assert!(
            (h.remap_y(8.0) - 8.5).abs() < 1e-4,
            "got {}",
            h.remap_y(8.0)
        );
        // Below the baseline, translate by the baseline delta (0).
        assert!((h.remap_y(-2.0) - -2.0).abs() < 1e-4);
    }

    #[test]
    fn remap_is_monotonic() {
        // Two zones (x-height, cap-height) at a small size.
        let h = Hinter::new(1000, 12.0, &[520, 700]);
        let mut prev = f32::NEG_INFINITY;
        // Step in tenths of a pixel from -4.0 to 12.0 using an integer counter
        // (avoids a float loop condition).
        for i in -40_i16..=120 {
            let y = f32::from(i) * 0.1;
            let mapped = h.remap_y(y);
            assert!(mapped >= prev, "non-monotonic at y={y}: {mapped} < {prev}");
            prev = mapped;
        }
    }
}
