//! Bitmap font renderer for the GOP framebuffer.
//!
//! Wraps `font8x8::legacy::BASIC_LEGACY` — a 128-entry array of 8 × 8
//! monospace glyphs for ASCII 0x00–0x7F. The array is always available
//! without enabling extra crate features and requires no allocation.
//!
//! ## Bit order
//!
//! Each row is a byte where **bit 0 (LSB) is the leftmost pixel**.
//! Column `col` (0 = leftmost) is lit when `(row_byte >> col) & 1 == 1`.
//!
//! ## Scaling
//!
//! `render_str_scaled` expands each source pixel to a `scale × scale`
//! block. Scale 1 gives the native 8 × 8 cell; scale 4 gives 32 × 32,
//! suitable for title text at 1024 × 768.

use font8x8::legacy::BASIC_LEGACY;

use super::graphics::FrameBuffer;

// =============================================================================
// Internal glyph lookup
// =============================================================================

/// Return the 8 × 8 glyph for the given ASCII byte.
///
/// Characters outside 0x00–0x7F (and control chars) fall back to a blank
/// cell so the renderer never panics on non-ASCII input.
#[inline]
#[allow(
    clippy::indexing_slicing,
    reason = "ch < BASIC_LEGACY.len() guarded; ASCII space (0x20) always in range"
)]
fn glyph(ch: u8) -> &'static [u8; 8] {
    if (ch as usize) < BASIC_LEGACY.len() {
        &BASIC_LEGACY[ch as usize]
    } else {
        &BASIC_LEGACY[b' ' as usize]
    }
}

// =============================================================================
// Core rendering
// =============================================================================

/// Render a single ASCII byte at pixel position `(x, y)` at 1 × 1 scale.
pub fn render_char(fb: &FrameBuffer, x: u32, y: u32, ch: u8, fg: u32, bg: u32) {
    render_char_scaled(fb, x, y, ch, fg, bg, 1);
}

/// Render a single ASCII byte at `(x, y)` with each source pixel expanded
/// to a `scale × scale` block. `scale = 0` is treated as `1`.
pub fn render_char_scaled(fb: &FrameBuffer, x: u32, y: u32, ch: u8, fg: u32, bg: u32, scale: u32) {
    let scale = scale.max(1);
    let data = glyph(ch);

    for (row, &row_byte) in data.iter().enumerate() {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "row index is 0..=7, always fits u32"
        )]
        let py = y + row as u32 * scale;
        for col in 0u32..8 {
            let px = x + col * scale;
            let color = if (row_byte >> col) & 1 != 0 { fg } else { bg };
            if scale == 1 {
                fb.write_pixel(px, py, color);
            } else {
                fb.draw_rect_filled(px, py, px + scale, py + scale, color);
            }
        }
    }
}

/// Render an ASCII string starting at `(x, y)` at 1 × 1 scale.
///
/// Stops at the right edge of the framebuffer; no automatic line-wrapping.
pub fn render_str(fb: &FrameBuffer, x: u32, y: u32, s: &str, fg: u32, bg: u32) {
    render_str_scaled(fb, x, y, s, fg, bg, 1);
}

/// Render an ASCII string starting at `(x, y)` with `scale × scale` pixels.
///
/// Stops when the next character would start past `fb.width`.
pub fn render_str_scaled(fb: &FrameBuffer, x: u32, y: u32, s: &str, fg: u32, bg: u32, scale: u32) {
    let scale = scale.max(1);
    let glyph_w = 8 * scale;
    let mut cursor_x = x;

    for b in s.bytes() {
        if cursor_x.saturating_add(glyph_w) > fb.width {
            break;
        }
        render_char_scaled(fb, cursor_x, y, b, fg, bg, scale);
        cursor_x = cursor_x.saturating_add(glyph_w);
    }
}

// =============================================================================
// Number rendering helpers
// =============================================================================

/// Render a `usize` as decimal digits at `(x, y)` with the given scale.
pub fn render_usize_scaled(
    fb: &FrameBuffer,
    x: u32,
    y: u32,
    mut n: usize,
    fg: u32,
    bg: u32,
    scale: u32,
) {
    if n == 0 {
        render_char_scaled(fb, x, y, b'0', fg, bg, scale);
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "n % 10 is always 0..=9, fits u8"
        )]
        #[allow(
            clippy::indexing_slicing,
            reason = "i is decremented from buf.len() within while n>0; bounded"
        )]
        {
            buf[i] = b'0' + (n % 10) as u8;
        }
        n /= 10;
    }
    #[allow(clippy::indexing_slicing, reason = "i is bounded by buf.len() above")]
    let digits = core::str::from_utf8(&buf[i..]).unwrap_or("?");
    render_str_scaled(fb, x, y, digits, fg, bg, scale);
}

/// Width in pixels of `n` rendered as decimal at the given scale.
#[must_use]
pub fn digit_width(mut n: usize, scale: u32) -> u32 {
    if n == 0 {
        return 8 * scale.max(1);
    }
    let mut count = 0u32;
    while n > 0 {
        count += 1;
        n /= 10;
    }
    count * 8 * scale.max(1)
}
