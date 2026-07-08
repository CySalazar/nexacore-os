//! Branded desktop wallpaper (WS7-19.7).
//!
//! The desktop backdrop is a smooth top-to-bottom gradient from deep petrol to
//! the charcoal-900 dark canvas — the brand's "civic dusk". The fade is
//! interpolated in **linear light** (via [`crate::color`]) so it is
//! perceptually even rather than bunching in the midtones as a naive sRGB lerp
//! would. A large monogram is drawn over this backdrop by the desktop image
//! using the AA text engine; this module owns only the gradient fill.

#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "per-row gradient interpolation is inherently floating-point over small screen dimensions"
)]

use crate::{
    color::{Rgba8, linear_to_srgb, srgb_to_linear, u8_to_unit, unit_to_u8},
    tokens,
};

/// Linear-light RGB triple.
type Lin = [f32; 3];

fn to_linear(argb: u32) -> Lin {
    let c = Rgba8::from_argb(argb);
    [
        srgb_to_linear(u8_to_unit(c.r)),
        srgb_to_linear(u8_to_unit(c.g)),
        srgb_to_linear(u8_to_unit(c.b)),
    ]
}

fn from_linear(l: Lin) -> u32 {
    Rgba8 {
        r: unit_to_u8(linear_to_srgb(l[0])),
        g: unit_to_u8(linear_to_srgb(l[1])),
        b: unit_to_u8(linear_to_srgb(l[2])),
        a: 0xFF,
    }
    .to_argb()
}

/// Renders the branded desktop backdrop into `pixels` (row-major `w * h` ARGB).
///
/// A vertical gradient from deep petrol at the top to the charcoal-900 canvas at
/// the bottom, interpolated in linear light. Writes exactly `w * h` pixels;
/// indices beyond `pixels.len()` are skipped (never writes out of bounds).
pub fn render_gradient(pixels: &mut [u32], w: u32, h: u32) {
    render_gradient_between(pixels, w, h, tokens::PETROL_800, tokens::CHARCOAL_900);
}

/// Like [`render_gradient`] but with explicit `top`/`bottom` endpoint colours,
/// for previews and tests.
pub fn render_gradient_between(pixels: &mut [u32], w: u32, h: u32, top: u32, bottom: u32) {
    if w == 0 || h == 0 {
        return;
    }
    for y in 0..h {
        let color = gradient_between_at(y, h, top, bottom);
        let row = (y as usize) * (w as usize);
        for x in 0..(w as usize) {
            if let Some(px) = pixels.get_mut(row + x) {
                *px = color;
            }
        }
    }
}

/// The default branded backdrop colour at screen row `y` of an `h`-row screen.
///
/// This is the per-row value of [`render_gradient`]'s petrol-800 → charcoal-900
/// vertical fade. It lets a damage-driven compositor repaint an arbitrary dirty
/// rect with the wallpaper (each row is a uniform colour) without materialising
/// the whole buffer.
#[must_use]
pub fn gradient_at(y: u32, h: u32) -> u32 {
    gradient_between_at(y, h, tokens::PETROL_800, tokens::CHARCOAL_900)
}

/// Row colour of the `top`→`bottom` linear-light vertical gradient at row `y` of
/// an `h`-row screen. `y` is clamped to the last row.
fn gradient_between_at(y: u32, h: u32, top: u32, bottom: u32) -> u32 {
    if h == 0 {
        return bottom;
    }
    let tl = to_linear(top);
    let bl = to_linear(bottom);
    let span = (h - 1).max(1) as f32;
    let t = if h == 1 {
        0.0
    } else {
        y.min(h - 1) as f32 / span
    };
    from_linear([
        tl[0] + (bl[0] - tl[0]) * t,
        tl[1] + (bl[1] - tl[1]) * t,
        tl[2] + (bl[2] - tl[2]) * t,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red(argb: u32) -> i32 {
        ((argb >> 16) & 0xFF) as i32
    }
    fn green(argb: u32) -> i32 {
        ((argb >> 8) & 0xFF) as i32
    }

    #[test]
    fn endpoints_match_top_and_bottom_within_rounding() {
        let (w, h) = (3u32, 16u32);
        let mut buf = alloc::vec![0u32; (w * h) as usize];
        render_gradient(&mut buf, w, h);
        // Top row ~ petrol-800, bottom row ~ charcoal-900 (±2 per channel for
        // the sRGB<->linear round trip).
        let top = buf[0];
        let bottom = buf[(w * (h - 1)) as usize];
        assert!(
            (red(top) - red(tokens::PETROL_800)).abs() <= 2,
            "top red off"
        );
        assert!(
            (red(bottom) - red(tokens::CHARCOAL_900)).abs() <= 2,
            "bottom red off"
        );
        assert_ne!(top, bottom, "gradient endpoints must differ");
    }

    #[test]
    fn each_row_is_uniform_and_petrol_leans_green() {
        let (w, h) = (4u32, 8u32);
        let mut buf = alloc::vec![0u32; (w * h) as usize];
        render_gradient(&mut buf, w, h);
        // Every pixel in a row is identical (pure vertical gradient).
        for y in 0..h as usize {
            let base = buf[y * w as usize];
            for x in 0..w as usize {
                assert_eq!(buf[y * w as usize + x], base, "row {y} not uniform");
            }
        }
        // Petrol is a teal: near the top, green exceeds red.
        assert!(green(buf[0]) > red(buf[0]), "petrol top should lean green");
    }

    #[test]
    fn zero_dimensions_are_a_noop() {
        let mut buf = alloc::vec![0xDEAD_BEEFu32; 4];
        render_gradient(&mut buf, 0, 4);
        render_gradient(&mut buf, 4, 0);
        assert!(buf.iter().all(|&p| p == 0xDEAD_BEEF));
    }
}

/// A decoded ARGB wallpaper image (alpha always 0xFF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WallpaperImage {
    /// Width in pixels.
    pub w: u32,
    /// Height in pixels.
    pub h: u32,
    /// Row-major ARGB pixels, exactly `w * h` entries.
    pub pixels: alloc::vec::Vec<u32>,
}

/// Parses an `NXWP` v1 RGB565 container (see `brand/wallpapers/compiled/README.md`).
///
/// Layout: magic `NXWP` · version u8 (=1) · format u8 (=1, RGB565 LE) ·
/// w u16 LE · h u16 LE · payload `w*h*2` bytes. Returns `None` on any
/// malformed input — the caller falls back to the procedural gradient.
#[must_use]
#[allow(
    clippy::many_single_char_names,
    reason = "w/h/r/g/b mirror the RGB565 field names and WallpaperImage's own w/h fields; more verbose names would obscure the bit-twiddling"
)]
pub fn decode_nxwp(bytes: &[u8]) -> Option<WallpaperImage> {
    // Fixed-size destructure (no indexing) so a truncated buffer is rejected
    // by `get`/`try_into` rather than by a panicking index.
    let header: [u8; 10] = bytes.get(..10)?.try_into().ok()?;
    let [n0, n1, n2, n3, version, format, wl, wh, hl, hh] = header;
    if [n0, n1, n2, n3] != *b"NXWP" || version != 1 || format != 1 {
        return None;
    }
    let w = u32::from(u16::from_le_bytes([wl, wh]));
    let h = u32::from(u16::from_le_bytes([hl, hh]));
    if w == 0 || h == 0 {
        return None;
    }
    let count = (w as usize).checked_mul(h as usize)?;
    let payload = bytes.get(10..10_usize.checked_add(count.checked_mul(2)?)?)?;
    let mut pixels = alloc::vec::Vec::with_capacity(count);
    for chunk in payload.chunks_exact(2) {
        let &[lo, hi] = chunk else {
            continue; // unreachable: chunks_exact(2) always yields length-2 slices
        };
        let v = u16::from_le_bytes([lo, hi]);
        let r5 = u32::from(v >> 11) & 0x1F;
        let g6 = u32::from(v >> 5) & 0x3F;
        let b5 = u32::from(v) & 0x1F;
        // Bit-replicating expansion (0x1F -> 0xFF exactly).
        let r = (r5 << 3) | (r5 >> 2);
        let g = (g6 << 2) | (g6 >> 4);
        let b = (b5 << 3) | (b5 >> 2);
        pixels.push(0xFF00_0000 | (r << 16) | (g << 8) | b);
    }
    Some(WallpaperImage { w, h, pixels })
}

#[cfg(test)]
mod nxwp_tests {
    use super::{WallpaperImage, decode_nxwp};

    /// Builds a tiny 2x2 NXWP container: red, green / blue, white.
    fn tiny() -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![b'N', b'X', b'W', b'P', 1, 1, 2, 0, 2, 0];
        for px in [0xF800u16, 0x07E0, 0x001F, 0xFFFF] {
            v.push((px & 0xFF) as u8);
            v.push((px >> 8) as u8);
        }
        v
    }

    #[test]
    fn decodes_dimensions_and_expands_rgb565() {
        let img: WallpaperImage = decode_nxwp(&tiny()).expect("valid container");
        assert_eq!((img.w, img.h), (2, 2));
        assert_eq!(img.pixels.len(), 4);
        assert_eq!(img.pixels[0], 0xFFFF_0000, "pure red expands to full red");
        assert_eq!(img.pixels[3], 0xFFFF_FFFF, "white expands losslessly");
        // Green channel: 0x07E0 = all 6 bits set -> 255.
        assert_eq!(img.pixels[1], 0xFF00_FF00);
        assert_eq!(img.pixels[2], 0xFF00_00FF);
    }

    #[test]
    fn rejects_bad_magic_version_and_short_payload() {
        let mut bad_magic = tiny();
        bad_magic[0] = b'X';
        assert!(decode_nxwp(&bad_magic).is_none());
        let mut bad_version = tiny();
        bad_version[4] = 9;
        assert!(decode_nxwp(&bad_version).is_none());
        let short = &tiny()[..12];
        assert!(decode_nxwp(short).is_none());
        assert!(decode_nxwp(&[]).is_none());
    }
}
