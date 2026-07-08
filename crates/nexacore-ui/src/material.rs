//! Translucency materials and sidebar vibrancy rendering (WS7-05.5 / .6).
//!
//! The [`crate::tokens::Material`] tokens (HIG §8) declare *what* a material is
//! — a backdrop blur radius plus a tint whose alpha sets its strength. This
//! module renders one: it blurs a backdrop and composites the tint over it
//! ([`render_material`], WS7-05.5), and adds the sidebar **vibrancy** variant
//! that mixes a context tint into the material before compositing
//! ([`render_vibrancy`], WS7-05.6).
//!
//! `no_std + alloc`, pure integer/compositing math over the compositor's
//! `0xAA_RR_GG_BB` ARGB8888 `u32` pixels. The gamma-correct *over* operator is
//! reused from `nexacore_display::color`.

// Channel averages divide a bounded sum and narrow back to `u8`; window indices
// are computed into a pre-sized buffer.
#![allow(clippy::cast_possible_truncation, clippy::integer_division)]

use alloc::vec::Vec;

use nexacore_display::color::{Rgba8, blend_over_linear};

use crate::tokens::Material;

/// Separable box blur of an ARGB8888 backdrop with the given `radius` (in px).
///
/// A box blur is a fast, visually-adequate stand-in for a Gaussian backdrop
/// blur (three box passes approximate a Gaussian; the compositor may upgrade
/// the kernel). `radius == 0` returns the input unchanged. Channels are
/// averaged independently (straight alpha); edges clamp.
///
/// # Errors / `None`
///
/// Returns `None` if `src.len() != width * height`.
#[must_use]
pub fn box_blur(src: &[u32], width: u32, height: u32, radius: u16) -> Option<Vec<u32>> {
    if src.len() != (width as usize).checked_mul(height as usize)? {
        return None;
    }
    if radius == 0 || width == 0 || height == 0 {
        return Some(src.to_vec());
    }
    let horizontal = blur_axis(src, width, height, radius, Axis::Horizontal);
    Some(blur_axis(
        &horizontal,
        width,
        height,
        radius,
        Axis::Vertical,
    ))
}

/// Which axis a 1-D blur pass runs along.
#[derive(Clone, Copy)]
enum Axis {
    Horizontal,
    Vertical,
}

/// One separable blur pass averaging a `2*radius+1` window along `axis`.
fn blur_axis(src: &[u32], width: u32, height: u32, radius: u16, axis: Axis) -> Vec<u32> {
    let w = width as usize;
    let h = height as usize;
    let r = radius as usize;
    let mut out = src.to_vec();
    let (outer, inner) = match axis {
        Axis::Horizontal => (h, w),
        Axis::Vertical => (w, h),
    };
    for o in 0..outer {
        for i in 0..inner {
            let (mut sa, mut sr, mut sg, mut sb) = (0u32, 0u32, 0u32, 0u32);
            let mut count = 0u32;
            let lo = i.saturating_sub(r);
            let hi = (i + r).min(inner - 1);
            for k in lo..=hi {
                let idx = match axis {
                    Axis::Horizontal => o * w + k,
                    Axis::Vertical => k * w + o,
                };
                let p = Rgba8::from_argb(src.get(idx).copied().unwrap_or(0));
                sa += u32::from(p.a);
                sr += u32::from(p.r);
                sg += u32::from(p.g);
                sb += u32::from(p.b);
                count += 1;
            }
            let avg = Rgba8 {
                a: (sa / count) as u8,
                r: (sr / count) as u8,
                g: (sg / count) as u8,
                b: (sb / count) as u8,
            };
            let idx = match axis {
                Axis::Horizontal => o * w + i,
                Axis::Vertical => i * w + o,
            };
            if let Some(slot) = out.get_mut(idx) {
                *slot = avg.to_argb();
            }
        }
    }
    out
}

/// Composite an `0xAA_RR_GG_BB` tint over each pixel of `backdrop` (gamma-correct
/// *over*).
fn tint_over(backdrop: &[u32], tint: u32) -> Vec<u32> {
    backdrop
        .iter()
        .map(|&bg| blend_over_linear(tint, bg))
        .collect()
}

/// Render a translucency [`Material`] over `backdrop` (WS7-05.5).
///
/// Blurs the backdrop by `material.blur` then composites `material.tint` over
/// it, yielding the surface the toolkit draws beneath translucent chrome
/// (popovers, menus, toolbars).
///
/// # Errors / `None`
///
/// Returns `None` if `backdrop.len() != width * height`.
#[must_use]
pub fn render_material(
    backdrop: &[u32],
    width: u32,
    height: u32,
    material: Material,
) -> Option<Vec<u32>> {
    let blurred = box_blur(backdrop, width, height, material.blur)?;
    Some(tint_over(&blurred, material.tint))
}

/// Render sidebar **vibrancy** over `backdrop` (WS7-05.6).
///
/// Like [`render_material`] but the base material tint is first blended with a
/// `context_tint` (the dominant color behind the sidebar) so the surface picks
/// up its surroundings — the "vibrancy" effect — before compositing over the
/// blurred backdrop.
///
/// # Errors / `None`
///
/// Returns `None` if `backdrop.len() != width * height`.
#[must_use]
pub fn render_vibrancy(
    backdrop: &[u32],
    width: u32,
    height: u32,
    material: Material,
    context_tint: u32,
) -> Option<Vec<u32>> {
    let blurred = box_blur(backdrop, width, height, material.blur)?;
    // Mix the contextual tint into the material tint, then composite.
    let vibrant_tint = blend_over_linear(context_tint, material.tint);
    Some(tint_over(&blurred, vibrant_tint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::material;

    #[test]
    fn box_blur_zero_radius_is_identity() {
        let src = [
            0xFF_00_00_00u32,
            0xFF_FF_FF_FF,
            0xFF_FF_FF_FF,
            0xFF_00_00_00,
        ];
        assert_eq!(box_blur(&src, 2, 2, 0).unwrap(), src.to_vec());
    }

    #[test]
    fn box_blur_averages_neighbors() {
        // 2x1: black | white, radius 1 ⇒ both pixels become the average grey.
        let src = [0xFF_00_00_00u32, 0xFF_FF_FF_FF];
        let out = box_blur(&src, 2, 1, 1).unwrap();
        let g0 = Rgba8::from_argb(out[0]).r;
        let g1 = Rgba8::from_argb(out[1]).r;
        assert_eq!(g0, g1, "uniform after blur");
        assert!((120..=135).contains(&g0), "grey ~127, got {g0}");
    }

    #[test]
    fn box_blur_rejects_bad_length() {
        assert!(box_blur(&[0u32; 3], 2, 2, 1).is_none());
    }

    #[test]
    fn render_material_blurs_and_tints() {
        let backdrop = [0xFF_00_00_00u32; 4];
        let out = render_material(&backdrop, 2, 2, material::REGULAR).unwrap();
        assert_eq!(out.len(), 4);
        // REGULAR tint is a translucent near-white over black ⇒ result lightens.
        let lit = Rgba8::from_argb(out[0]);
        assert!(
            lit.r > 0 && lit.g > 0 && lit.b > 0,
            "tint must lighten: {lit:?}"
        );
    }

    #[test]
    fn render_material_scrim_has_no_blur_but_dims() {
        // SCRIM has blur 0 (identity backdrop) and a dark tint ⇒ dims a white
        // backdrop.
        let backdrop = [0xFF_FF_FF_FFu32; 4];
        let out = render_material(&backdrop, 2, 2, material::SCRIM).unwrap();
        let dimmed = Rgba8::from_argb(out[0]);
        assert!(dimmed.r < 0xFF, "scrim must dim: {dimmed:?}");
    }

    #[test]
    fn render_vibrancy_picks_up_context_tint() {
        // A strong red context tint must push the vibrant surface redder than
        // the plain material over the same backdrop.
        let backdrop = [0xFF_40_40_40u32; 4];
        let plain = render_material(&backdrop, 2, 2, material::THICK).unwrap();
        let context = 0x80_FF_00_00u32; // 50% red
        let vibrant = render_vibrancy(&backdrop, 2, 2, material::THICK, context).unwrap();
        let p = Rgba8::from_argb(plain[0]);
        let v = Rgba8::from_argb(vibrant[0]);
        assert!(
            v.r > p.r,
            "vibrancy should be redder: plain={p:?} vibrant={v:?}"
        );
    }

    #[test]
    fn render_material_rejects_bad_length() {
        assert!(render_material(&[0u32; 3], 2, 2, material::THIN).is_none());
    }
}
