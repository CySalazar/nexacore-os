//! Borrowed ARGB pixel-buffer canvas for widget rendering.
//!
//! [`Canvas`] wraps a caller-owned `&mut [u32]` slice and exposes a set of
//! bounds-checked drawing primitives.  Every write is guarded by a
//! `pixels.get_mut(idx)` call — there is **no `unsafe` code** in this module.
//!
//! ## Pixel format
//!
//! Pixels are stored row-major in `0xAARRGGBB` ARGB format.  The index of
//! pixel `(x, y)` is `y * width + x`.  The slice length must equal
//! `width * height` pixels; [`Canvas::new`] enforces this at construction time.
//!
//! ## Example
//!
//! ```
//! use nexacore_display::geometry::Rect;
//! use nexacore_ui::{canvas::Canvas, color::PETROL};
//!
//! let mut pixels = vec![0u32; 64 * 64];
//! let mut c = Canvas::new(&mut pixels, 64, 64).expect("valid dimensions");
//! c.fill(PETROL);
//! assert_eq!(c.width(), 64);
//! assert_eq!(c.height(), 64);
//! ```

use nexacore_display::{
    effects::{RoundedRect, Shadow, shadow_alpha_at, shadow_bounds},
    geometry::Rect,
};

/// Alpha-over composite: paint straight-alpha source `src` (its RGB) over an
/// opaque destination `dst` by `coverage` (`0` keeps `dst`, `255` replaces it).
///
/// This is the single over-operator every anti-aliased Canvas primitive routes
/// through (rounded rects, shadows, AA glyph coverage). Blending is
/// **gamma-correct**: it runs in linear light via
/// [`nexacore_display::color::blend_over_linear`] (sRGB → linear → over → sRGB),
/// so anti-aliased edges and translucent fills have the correct perceived
/// brightness (WS7-19.5) instead of the too-dark result of naive sRGB mixing.
#[must_use]
fn composite(dst: u32, src: u32, coverage: u8) -> u32 {
    if coverage == 0 {
        return dst;
    }
    if coverage == 0xFF {
        return 0xFF00_0000 | (src & 0x00FF_FFFF);
    }
    // Give the source colour the coverage as its alpha, then blend over the
    // (opaque) destination in linear light.
    let src_argb = (u32::from(coverage) << 24) | (src & 0x00FF_FFFF);
    nexacore_display::color::blend_over_linear(src_argb, dst)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by [`Canvas::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanvasError {
    /// The supplied pixel slice does not have the expected length
    /// (`width * height` pixels).
    InvalidSize,
}

impl core::fmt::Display for CanvasError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSize => write!(
                f,
                "nexacore-ui canvas: pixel slice length does not match width * height"
            ),
        }
    }
}

impl core::error::Error for CanvasError {}

// ---------------------------------------------------------------------------
// Canvas
// ---------------------------------------------------------------------------

/// A borrowed, bounds-checked ARGB pixel canvas.
///
/// All drawing primitives operate on `self.pixels` through `get_mut` so that
/// out-of-bounds coordinates are silently ignored — they never panic and never
/// write outside the buffer.
pub struct Canvas<'a> {
    /// Mutable reference to the caller-owned pixel buffer.
    pixels: &'a mut [u32],
    /// Width of the canvas in pixels.
    width: u32,
    /// Height of the canvas in pixels.
    height: u32,
}

impl<'a> Canvas<'a> {
    /// Creates a new [`Canvas`] backed by `pixels`.
    ///
    /// Returns [`CanvasError::InvalidSize`] if `pixels.len() != width * height`.
    /// Both `width` and `height` may be zero (an empty canvas accepts all
    /// drawing calls as no-ops).
    ///
    /// # Errors
    ///
    /// Returns [`CanvasError::InvalidSize`] when `pixels.len()` does not equal
    /// `width as usize * height as usize`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::canvas::{Canvas, CanvasError};
    ///
    /// // Correct size.
    /// let mut buf = vec![0u32; 16 * 16];
    /// let c = Canvas::new(&mut buf, 16, 16);
    /// assert!(c.is_ok());
    ///
    /// // Wrong size.
    /// let mut buf2 = vec![0u32; 10];
    /// assert!(Canvas::new(&mut buf2, 16, 16).is_err());
    /// ```
    pub fn new(pixels: &'a mut [u32], width: u32, height: u32) -> Result<Self, CanvasError> {
        let expected = (width as usize).saturating_mul(height as usize);
        if pixels.len() != expected {
            return Err(CanvasError::InvalidSize);
        }
        Ok(Self {
            pixels,
            width,
            height,
        })
    }

    /// Returns the canvas width in pixels.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::canvas::Canvas;
    /// let mut buf = vec![0u32; 10 * 20];
    /// let c = Canvas::new(&mut buf, 10, 20).unwrap();
    /// assert_eq!(c.width(), 10);
    /// ```
    #[inline]
    #[must_use]
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Returns the canvas height in pixels.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::canvas::Canvas;
    /// let mut buf = vec![0u32; 10 * 20];
    /// let c = Canvas::new(&mut buf, 10, 20).unwrap();
    /// assert_eq!(c.height(), 20);
    /// ```
    #[inline]
    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Fills the entire canvas with `color`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::{canvas::Canvas, color::CREAM};
    ///
    /// let mut buf = vec![0u32; 4 * 4];
    /// let mut c = Canvas::new(&mut buf, 4, 4).unwrap();
    /// c.fill(CREAM);
    /// assert!(buf.iter().all(|&p| p == CREAM));
    /// ```
    pub fn fill(&mut self, color: u32) {
        self.pixels.fill(color);
    }

    /// Fills the pixels that fall within `rect` with `color`.
    ///
    /// Coordinates outside the canvas bounds are silently clipped — this
    /// method never panics and never writes outside the buffer.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::{
    ///     canvas::Canvas,
    ///     color::{CREAM, PETROL},
    /// };
    ///
    /// let mut buf = vec![CREAM; 8 * 8];
    /// let mut c = Canvas::new(&mut buf, 8, 8).unwrap();
    /// let r = Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 4,
    ///     h: 4,
    /// };
    /// c.fill_rect(&r, PETROL);
    /// // Top-left 4x4 block is petrol; rest is cream.
    /// assert_eq!(buf[0], PETROL);
    /// assert_eq!(buf[4], CREAM);
    /// assert_eq!(buf[8 * 4], CREAM);
    /// ```
    pub fn fill_rect(&mut self, rect: &Rect, color: u32) {
        // Clamp rect to canvas bounds before iterating.
        let canvas_rect = Rect {
            x: 0,
            y: 0,
            w: self.width,
            h: self.height,
        };
        let Some(clipped) = rect.clamp_to(&canvas_rect) else {
            return;
        };

        // clipped.x / .y are non-negative because canvas_rect starts at 0,
        // so the sign-loss casts to u32 are safe.
        #[allow(clippy::cast_sign_loss)]
        let x0 = clipped.x as u32;
        #[allow(clippy::cast_sign_loss)]
        let y0 = clipped.y as u32;
        let x1 = x0.saturating_add(clipped.w);
        let y1 = y0.saturating_add(clipped.h);

        for row in y0..y1 {
            for col in x0..x1 {
                let idx = (row as usize) * (self.width as usize) + (col as usize);
                if let Some(px) = self.pixels.get_mut(idx) {
                    *px = color;
                }
            }
        }
    }

    /// Sets a single pixel at `(x, y)` to `color`.
    ///
    /// If `(x, y)` is outside the canvas, the call is a no-op.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::{canvas::Canvas, color::BRICK};
    ///
    /// let mut buf = vec![0u32; 4 * 4];
    /// {
    ///     let mut c = Canvas::new(&mut buf, 4, 4).unwrap();
    ///     c.put_pixel(1, 2, BRICK);
    ///     // Out-of-bounds is a no-op.
    ///     c.put_pixel(100, 100, BRICK);
    /// }
    /// // Pixel at row 2, col 1 (index 2*4+1 = 9).
    /// assert_eq!(buf[9], BRICK);
    /// ```
    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x < self.width && y < self.height {
            let idx = (y as usize) * (self.width as usize) + (x as usize);
            if let Some(px) = self.pixels.get_mut(idx) {
                *px = color;
            }
        }
    }

    /// Draws one 8×8 `font8x8` glyph at `(x, y)`, integer-scaled by `scale`.
    ///
    /// The `glyph` parameter is an 8-byte row array where
    /// **bit 0 (LSB) of each byte is the leftmost pixel of that row**.
    ///
    /// Each lit source pixel is expanded to a `scale × scale` block of
    /// `color`.  Pixels that fall outside the canvas are silently skipped.
    ///
    /// A `scale` of 0 is treated as 1.
    ///
    /// Negative `x` or `y` values cause the glyph to be partially or fully
    /// off-canvas; pixels in the visible portion are still drawn.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::{canvas::Canvas, color::CHARCOAL, text::glyph_for};
    ///
    /// let mut buf = vec![0u32; 16 * 16];
    /// let mut c = Canvas::new(&mut buf, 16, 16).unwrap();
    /// let g = glyph_for('A');
    /// c.blit_glyph(0, 0, *g, CHARCOAL, 1);
    /// // At least one pixel should be set (A is not blank).
    /// assert!(buf.iter().any(|&p| p == CHARCOAL));
    /// ```
    pub fn blit_glyph(&mut self, x: i32, y: i32, glyph: [u8; 8], color: u32, scale: u32) {
        let scale = scale.max(1);

        for (row, &row_byte) in glyph.iter().enumerate() {
            for col in 0u32..8 {
                // Check whether the source pixel is lit.
                if (row_byte >> col) & 1 == 0 {
                    continue;
                }
                // Compute the top-left corner of the scaled block.
                // col * scale <= 7 * u32::MAX which fits in u64; the cast to
                // i32 is annotated as potentially wrapping but is bounded by
                // practical canvas sizes.
                #[allow(clippy::cast_possible_wrap)]
                let bx = x + (col * scale) as i32;
                // row < 8 (u8 iterator) — safe to cast to u32.
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let by = y + (row as u32 * scale) as i32;

                // Paint the scale×scale block.
                for dy in 0..scale {
                    for dx in 0..scale {
                        #[allow(clippy::cast_possible_wrap)]
                        let px = bx + dx as i32;
                        #[allow(clippy::cast_possible_wrap)]
                        let py = by + dy as i32;
                        // Bounds check: skip if outside canvas.
                        if px < 0 || py < 0 {
                            continue;
                        }
                        #[allow(clippy::cast_sign_loss)]
                        let px = px as u32;
                        #[allow(clippy::cast_sign_loss)]
                        let py = py as u32;
                        if px >= self.width || py >= self.height {
                            continue;
                        }
                        let idx = (py as usize) * (self.width as usize) + (px as usize);
                        if let Some(pixel) = self.pixels.get_mut(idx) {
                            *pixel = color;
                        }
                    }
                }
            }
        }
    }

    /// Draws a rectangular border of `thickness` pixels inside `rect`.
    ///
    /// The border is drawn as four filled strips (top, bottom, left, right),
    /// each `thickness` pixels wide/tall.  If `thickness` is 0 or the rect is
    /// empty the call is a no-op.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::{
    ///     canvas::Canvas,
    ///     color::{CREAM, PETROL_700},
    /// };
    ///
    /// let mut buf = vec![CREAM; 20 * 20];
    /// let mut c = Canvas::new(&mut buf, 20, 20).unwrap();
    /// let r = Rect {
    ///     x: 2,
    ///     y: 2,
    ///     w: 16,
    ///     h: 16,
    /// };
    /// c.draw_rect_border(&r, PETROL_700, 2);
    /// // Corner pixel (2,2) should be border colour.
    /// assert_eq!(buf[2 * 20 + 2], PETROL_700);
    /// // Interior pixel well inside the border should still be CREAM.
    /// assert_eq!(buf[10 * 20 + 10], CREAM);
    /// ```
    pub fn draw_rect_border(&mut self, rect: &Rect, color: u32, thickness: u32) {
        if thickness == 0 || rect.is_empty() {
            return;
        }
        // Top strip.
        self.fill_rect(
            &Rect {
                x: rect.x,
                y: rect.y,
                w: rect.w,
                h: thickness.min(rect.h),
            },
            color,
        );
        // Bottom strip.
        #[allow(clippy::cast_possible_wrap)]
        let bottom_y = rect.y + (rect.h.saturating_sub(thickness)) as i32;
        self.fill_rect(
            &Rect {
                x: rect.x,
                y: bottom_y,
                w: rect.w,
                h: thickness.min(rect.h),
            },
            color,
        );
        // Left strip.
        self.fill_rect(
            &Rect {
                x: rect.x,
                y: rect.y,
                w: thickness.min(rect.w),
                h: rect.h,
            },
            color,
        );
        // Right strip.
        #[allow(clippy::cast_possible_wrap)]
        let right_x = rect.x + (rect.w.saturating_sub(thickness)) as i32;
        self.fill_rect(
            &Rect {
                x: right_x,
                y: rect.y,
                w: thickness.min(rect.w),
                h: rect.h,
            },
            color,
        );
    }

    /// Alpha-blends `color` onto pixel `(x, y)` by `coverage` (`0`..=`255`),
    /// the anti-aliased over-operator. Out-of-bounds pixels are skipped.
    pub fn blend_pixel(&mut self, x: i32, y: i32, color: u32, coverage: u8) {
        if x < 0 || y < 0 {
            return;
        }
        #[allow(clippy::cast_sign_loss)]
        let (ux, uy) = (x as u32, y as u32);
        if ux >= self.width || uy >= self.height {
            return;
        }
        let idx = (uy as usize) * (self.width as usize) + (ux as usize);
        if let Some(px) = self.pixels.get_mut(idx) {
            *px = composite(*px, color, coverage);
        }
    }

    /// Fills a rounded rectangle with anti-aliased corners in `color`
    /// (elevation surfaces, cards, buttons). `radius` is clamped to half the
    /// shorter side. Corner pixels get partial coverage; the interior is solid.
    pub fn fill_rounded_rect(&mut self, rect: &Rect, radius: u32, color: u32) {
        if rect.is_empty() {
            return;
        }
        let rr = RoundedRect::new(*rect, radius);
        #[allow(clippy::cast_possible_wrap)]
        let (x1, y1) = (rect.x + rect.w as i32, rect.y + rect.h as i32);
        for py in rect.y..y1 {
            for px in rect.x..x1 {
                let cov = rr.coverage_at(px, py);
                if cov != 0 {
                    self.blend_pixel(px, py, color, cov);
                }
            }
        }
    }

    /// Paints a soft drop shadow cast by `window`, per `shadow` (offset, blur,
    /// spread, colour). Call this before painting the surface so the surface
    /// sits over its shadow. The shadow's peak opacity is the colour's alpha.
    pub fn draw_shadow(&mut self, window: &Rect, shadow: Shadow) {
        let bounds = shadow_bounds(*window, shadow);
        if bounds.is_empty() {
            return;
        }
        #[allow(clippy::cast_possible_wrap)]
        let (x1, y1) = (bounds.x + bounds.w as i32, bounds.y + bounds.h as i32);
        for py in bounds.y..y1 {
            for px in bounds.x..x1 {
                let a = shadow_alpha_at(*window, shadow, px, py);
                if a != 0 {
                    self.blend_pixel(px, py, shadow.color, a);
                }
            }
        }
    }

    /// Blits an anti-aliased coverage bitmap (`w * h`, row-major, `0..=255`
    /// alpha) in `color`, top-left at `(x, y)`. This is how AA text glyphs
    /// rasterized by the font engine (`nexacore_display::raster`) reach the
    /// Canvas. Coverage entries beyond the slice are treated as `0`.
    pub fn blit_coverage(&mut self, x: i32, y: i32, coverage: &[u8], w: u32, h: u32, color: u32) {
        for row in 0..h {
            for col in 0..w {
                let idx = (row as usize) * (w as usize) + (col as usize);
                let cov = coverage.get(idx).copied().unwrap_or(0);
                if cov != 0 {
                    #[allow(clippy::cast_possible_wrap)]
                    self.blend_pixel(x + col as i32, y + row as i32, color, cov);
                }
            }
        }
    }
}

#[cfg(test)]
mod aa_tests {
    use nexacore_display::{effects::Shadow, geometry::Rect};

    use super::{Canvas, composite};

    const BLACK: u32 = 0xFF00_0000;
    const WHITE: u32 = 0xFFFF_FFFF;

    fn channel(argb: u32, shift: u32) -> u32 {
        (argb >> shift) & 0xFF
    }

    #[test]
    fn composite_blends_toward_source() {
        // Half coverage of white over black, blended in LINEAR light: the
        // linear midpoint (0.5) maps back to sRGB ~188, not the naive 128 —
        // that brighter value is the whole point of gamma-correct blending.
        let mid = composite(BLACK, WHITE, 128);
        assert_eq!(channel(mid, 24), 0xFF, "result must stay opaque");
        for shift in [0, 8, 16] {
            let c = channel(mid, shift);
            assert!(
                (180..=195).contains(&c),
                "channel {shift} = {c}, want ~188 (linear)"
            );
        }
        // Extremes are exact.
        assert_eq!(composite(BLACK, WHITE, 0), BLACK);
        assert_eq!(composite(BLACK, WHITE, 255), WHITE);
    }

    #[test]
    fn fill_rounded_rect_solid_center_clipped_corner() {
        let mut buf = alloc::vec![BLACK; 20 * 20];
        {
            let mut c = Canvas::new(&mut buf, 20, 20).unwrap();
            c.fill_rounded_rect(
                &Rect {
                    x: 0,
                    y: 0,
                    w: 20,
                    h: 20,
                },
                8,
                WHITE,
            );
        }
        // Center is fully inside -> solid white.
        assert_eq!(buf[10 * 20 + 10], WHITE);
        // The extreme corner is outside the rounded corner -> untouched bg.
        assert_eq!(buf[0], BLACK);
    }

    #[test]
    fn draw_shadow_darkens_core_leaves_far_pixels() {
        let mut buf = alloc::vec![WHITE; 30 * 30];
        let window = Rect {
            x: 10,
            y: 10,
            w: 10,
            h: 10,
        };
        {
            let mut c = Canvas::new(&mut buf, 30, 30).unwrap();
            c.draw_shadow(
                &window,
                Shadow {
                    offset_y: 0,
                    blur: 4,
                    spread: 0,
                    color: 0x8000_0000,
                },
            );
        }
        // A pixel inside the shadow core is darkened below white.
        let core = buf[15 * 30 + 15];
        assert!(
            channel(core, 16) < 200,
            "core red {} not darkened",
            channel(core, 16)
        );
        // A far-corner pixel outside the shadow bounds is untouched.
        assert_eq!(buf[29 * 30 + 29], WHITE);
    }

    #[test]
    fn blit_coverage_maps_alpha_to_ink() {
        let mut buf = alloc::vec![BLACK; 4];
        // Row of 4: full, none, full, mid.
        let cov = [255u8, 0, 255, 128];
        {
            let mut c = Canvas::new(&mut buf, 4, 1).unwrap();
            c.blit_coverage(0, 0, &cov, 4, 1, WHITE);
        }
        assert_eq!(buf[0], WHITE); // full coverage
        assert_eq!(buf[1], BLACK); // zero coverage keeps bg
        assert_eq!(buf[2], WHITE);
        assert!(
            (180..=195).contains(&channel(buf[3], 0)),
            "mid ~188 (linear)"
        );
    }
}
