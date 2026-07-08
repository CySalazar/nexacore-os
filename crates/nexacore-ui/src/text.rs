//! UTF-8-aware text measurement and rasterization via `font8x8`.
//!
//! This module is the canonical text rendering surface for `nexacore-ui`.  It
//! bridges Unicode codepoints → `font8x8` 8×8 glyphs → [`crate::canvas::Canvas`]
//! pixel output.
//!
//! ## UTF-8 boundary
//!
//! All measurement and rendering iterate `str::chars()` (Unicode scalar
//! values), **not** raw bytes.  A multibyte character such as `é` (U+00E9,
//! two UTF-8 bytes) counts as **one** glyph for width purposes:
//!
//! ```
//! use nexacore_ui::text::measure_text;
//! // "café" is 4 codepoints, 5 UTF-8 bytes.
//! let (w, _h) = measure_text("café", 1);
//! assert_eq!(w, 4 * 8); // 4 glyphs, not 5 bytes
//! ```
//!
//! ## Out-of-range codepoints
//!
//! `font8x8` covers ASCII 0x00–0x7F.  Codepoints outside that range (accented
//! characters, emoji, CJK, …) fall back to a visible "unknown box" glyph so
//! that text never renders as a blank gap (ADR-0042 D2).
//!
//! ## TrueType-ready API shape
//!
//! The `draw_text` signature is shaped so a future `TrueType` rasterizer can
//! drop in behind it without changing callers (ADR-0042 D2).

use font8x8::legacy::BASIC_LEGACY;
use nexacore_display::{font::Font, raster};

use crate::canvas::Canvas;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Width of one glyph in pixels (font8x8 native cell width).
pub const GLYPH_W: u32 = 8;

/// Height of one glyph in pixels (font8x8 native cell height).
pub const GLYPH_H: u32 = 8;

// ---------------------------------------------------------------------------
// Fallback glyph
// ---------------------------------------------------------------------------

/// A visible 8×8 "unknown box" glyph used for codepoints outside ASCII.
///
/// The pattern is a filled rectangle border — clearly visible on any
/// background, unambiguously a placeholder.
const FALLBACK_GLYPH: [u8; 8] = [
    0xFF, // ████████
    0x81, // █      █
    0x81, // █      █
    0x81, // █      █
    0x81, // █      █
    0x81, // █      █
    0x81, // █      █
    0xFF, // ████████
];

// ---------------------------------------------------------------------------
// Glyph lookup
// ---------------------------------------------------------------------------

/// Returns a reference to the 8×8 `font8x8` glyph for `ch`.
///
/// Characters in the printable ASCII range (0x00–0x7F) are mapped directly
/// from `font8x8::legacy::BASIC_LEGACY`.  All other codepoints (accented
/// characters, emoji, CJK, …) fall back to `FALLBACK_GLYPH` — a visible
/// "unknown box" so the text region is never silently blank.
///
/// # Example
///
/// ```
/// use nexacore_ui::text::glyph_for;
///
/// // ASCII characters return the real glyph.
/// let g = glyph_for('A');
/// assert_ne!(*g, [0u8; 8]); // not blank
///
/// // Non-ASCII falls back to the unknown-box.
/// let fallback = glyph_for('é');
/// assert_ne!(*fallback, [0u8; 8]); // also not blank
/// ```
#[allow(clippy::indexing_slicing)]
pub fn glyph_for(ch: char) -> &'static [u8; 8] {
    let code = ch as u32;
    // BASIC_LEGACY has exactly 128 entries (indices 0x00–0x7F).
    if (code as usize) < BASIC_LEGACY.len() {
        // cast is safe: code < 128
        &BASIC_LEGACY[code as usize]
    } else {
        &FALLBACK_GLYPH
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// Returns the pixel dimensions `(width, height)` of `s` rendered at `scale`.
///
/// Width is `n_chars * GLYPH_W * scale` where `n_chars` is the number of
/// Unicode scalar values (codepoints) in `s`, **not** the byte length.
/// Height is `GLYPH_H * scale`.
///
/// A `scale` of 0 is treated as 1.
///
/// # Examples
///
/// ```
/// use nexacore_ui::text::measure_text;
///
/// // 4 codepoints, 5 UTF-8 bytes — width is 4 glyphs wide.
/// let (w, h) = measure_text("café", 1);
/// assert_eq!(w, 4 * 8);
/// assert_eq!(h, 8);
///
/// // scale 2.
/// let (w2, h2) = measure_text("hello", 2);
/// assert_eq!(w2, 5 * 8 * 2);
/// assert_eq!(h2, 8 * 2);
///
/// // Empty string.
/// assert_eq!(measure_text("", 1).0, 0);
///
/// // Emoji counts as one glyph (fallback).
/// let (we, _) = measure_text("x🦀", 1);
/// assert_eq!(we, 2 * 8);
/// ```
#[must_use]
pub fn measure_text(s: &str, scale: u32) -> (u32, u32) {
    let scale = scale.max(1);
    // Count codepoints, not bytes.  Saturate at u32::MAX for pathological
    // inputs; in practice widget text never approaches that length.
    let n = u32::try_from(s.chars().count()).unwrap_or(u32::MAX);
    (
        n.saturating_mul(GLYPH_W).saturating_mul(scale),
        GLYPH_H.saturating_mul(scale),
    )
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Draws `s` onto `canvas` at position `(x, y)` in `color` at `scale`.
///
/// Each Unicode scalar value in `s` is looked up via [`glyph_for`] and
/// stamped with [`Canvas::blit_glyph`], advancing `x` by `GLYPH_W * scale`
/// per codepoint.
///
/// Glyphs that would start entirely past the right canvas edge are skipped;
/// glyphs that overlap the left/top edge are still passed to `blit_glyph`,
/// which clips them internally.  No glyph write ever leaves the canvas buffer.
///
/// Returns the total advance width in pixels (`n_codepoints * GLYPH_W * scale`),
/// which matches the value returned by [`measure_text`] on the same string and
/// scale.
///
/// A `scale` of 0 is treated as 1.
///
/// # Example
///
/// ```
/// use nexacore_ui::{canvas::Canvas, color::CHARCOAL, text::draw_text};
///
/// let mut buf = vec![0u32; 64 * 16];
/// let mut c = Canvas::new(&mut buf, 64, 16).unwrap();
/// let w = draw_text(&mut c, 0, 0, "HI", CHARCOAL, 1);
/// assert_eq!(w, 2 * 8);
/// // Some pixels should be set.
/// assert!(buf.iter().any(|&p| p == CHARCOAL));
/// ```
pub fn draw_text(canvas: &mut Canvas<'_>, x: i32, y: i32, s: &str, color: u32, scale: u32) -> u32 {
    let scale = scale.max(1);
    // GLYPH_W * scale <= 8 * u32::MAX; in practice these values are small.
    #[allow(clippy::cast_possible_wrap)]
    let glyph_advance = (GLYPH_W * scale) as i32;
    #[allow(clippy::cast_possible_wrap)]
    let canvas_w = canvas.width() as i32;

    let mut cursor_x = x;

    for ch in s.chars() {
        // Skip glyphs that start entirely past the right edge — and since all
        // subsequent glyphs will be even further right, stop iterating early.
        if cursor_x >= canvas_w {
            break;
        }
        let glyph = *glyph_for(ch);
        canvas.blit_glyph(cursor_x, y, glyph, color, scale);
        cursor_x += glyph_advance;
    }

    // The total advance is always n_codepoints * GLYPH_W * scale, regardless
    // of how many were actually drawn (matches measure_text semantics).
    let n_total = u32::try_from(s.chars().count()).unwrap_or(u32::MAX);
    n_total.saturating_mul(GLYPH_W).saturating_mul(scale)
}

// ---------------------------------------------------------------------------
// Anti-aliased rendering (WS7-19.4) — proportional text via the font engine
// ---------------------------------------------------------------------------

/// Returns the advance width in pixels of `s` rendered with `font` at pixel
/// size `px_per_em`, summing each glyph's scaled horizontal advance.
///
/// This is the AA counterpart to [`measure_text`]; it is proportional (glyph
/// widths differ) rather than a fixed cell width. Unknown codepoints fall back
/// to glyph 0 (`.notdef`), whose advance still contributes.
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_arithmetic,
    reason = "font metrics are small positive values; sub-pixel advance rounding is acceptable"
)]
pub fn measure_text_aa(s: &str, font: &Font<'_>, px_per_em: f32) -> i32 {
    let upem = f32::from(font.units_per_em().max(1));
    let scale = px_per_em / upem;
    let mut advance = 0.0f32;
    for ch in s.chars() {
        let gid = font.glyph_index(ch).unwrap_or(0);
        advance += f32::from(font.advance_width(gid)) * scale;
    }
    advance as i32
}

/// Draws `s` with **anti-aliased proportional glyphs** from `font`.
///
/// The text baseline sits at `(x, baseline_y)` and is painted in `color`. Each
/// glyph is decoded (`glyf`, including composites) and rasterized to AA coverage
/// by [`nexacore_display::raster`], then composited via [`Canvas::blit_coverage`].
/// Unknown codepoints render `.notdef`.
///
/// Returns the total advance width in pixels. This is the replacement for the
/// `font8x8` [`draw_text`] on the branded desktop path; the bitmap path remains
/// for contexts without a loaded font.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_arithmetic,
    reason = "font metrics are small positive values; sub-pixel positioning is acceptable"
)]
pub fn draw_text_aa(
    canvas: &mut Canvas<'_>,
    x: i32,
    baseline_y: i32,
    s: &str,
    font: &Font<'_>,
    px_per_em: f32,
    color: u32,
) -> i32 {
    let upem = font.units_per_em().max(1);
    let scale = px_per_em / f32::from(upem);
    let mut pen_x = x as f32;
    for ch in s.chars() {
        let gid = font.glyph_index(ch).unwrap_or(0);
        let Ok(outline) = font.glyph_outline(gid) else {
            continue;
        };
        let bmp = raster::rasterize(&outline, upem, px_per_em);
        if !bmp.is_empty() {
            // `left`/`top` are device-space bearings from the pen origin and
            // baseline respectively (top edge is `baseline_y - top`).
            let gx = pen_x as i32 + bmp.left;
            let gy = baseline_y - bmp.top;
            canvas.blit_coverage(
                gx,
                gy,
                &bmp.coverage,
                bmp.width as u32,
                bmp.height as u32,
                color,
            );
        }
        pen_x += f32::from(outline.advance) * scale;
    }
    pen_x as i32 - x
}

#[cfg(test)]
mod aa_text_tests {
    use nexacore_display::font::Font;

    use super::{draw_text_aa, measure_text_aa};
    use crate::canvas::Canvas;

    const INK: u32 = 0xFF14_171A; // charcoal-900 on a light canvas
    const BG: u32 = 0xFFF4_EBD0; // cream

    #[test]
    fn measure_is_positive_and_grows_with_length() {
        let font = Font::parse(nexacore_fonts::BRAND_UI).unwrap();
        let one = measure_text_aa("A", &font, 24.0);
        let many = measure_text_aa("AAAA", &font, 24.0);
        assert!(one > 0, "single glyph advance must be positive");
        assert!(many > one * 3, "four glyphs must be much wider than one");
    }

    #[test]
    fn draw_lays_down_ink_and_advances() {
        let font = Font::parse(nexacore_fonts::BRAND_UI).unwrap();
        let mut buf = alloc::vec![BG; 200 * 40];
        let advance = {
            let mut c = Canvas::new(&mut buf, 200, 40).unwrap();
            // Baseline near the bottom of the box so ascenders fit.
            draw_text_aa(&mut c, 4, 30, "Agé", &font, 24.0, INK)
        };
        assert!(advance > 0, "advance must be positive");
        // Some pixels changed from the cream background toward the ink colour.
        assert!(
            buf.iter().any(|&p| p != BG),
            "AA text produced no ink on the canvas"
        );
    }
}
