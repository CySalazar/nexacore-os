//! Software cursor — 16×16 arrow bitmap with pixel save/restore.
//!
//! The cursor is rendered by:
//! 1. Saving the raw framebuffer bytes underneath it (`[u8; 1024]`).
//! 2. Blitting the bitmap, skipping fully-transparent pixels (alpha = 0).
//!
//! Erasing the cursor restores the saved bytes exactly, preventing visual
//! artefacts. The hotspot is at the top-left corner of the 16×16 block.

use super::graphics::FrameBuffer;

// =============================================================================
// Cursor bitmap
// =============================================================================

const T: u32 = 0x00_00_00_00; // transparent
const B: u32 = 0xFF_00_00_00; // black
const W: u32 = 0xFF_FF_FF_FF; // white

/// 16×16 arrow cursor bitmap, row-major ARGB. Hotspot at column 0, row 0.
#[rustfmt::skip]
const CURSOR_BITMAP: [u32; 256] = [
    // Row 0
    W, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,
    // Row 1
    W, W, T, T, T, T, T, T, T, T, T, T, T, T, T, T,
    // Row 2
    W, B, W, T, T, T, T, T, T, T, T, T, T, T, T, T,
    // Row 3
    W, B, B, W, T, T, T, T, T, T, T, T, T, T, T, T,
    // Row 4
    W, B, B, B, W, T, T, T, T, T, T, T, T, T, T, T,
    // Row 5
    W, B, B, B, B, W, T, T, T, T, T, T, T, T, T, T,
    // Row 6
    W, B, B, B, B, B, W, T, T, T, T, T, T, T, T, T,
    // Row 7
    W, B, B, B, B, B, B, W, T, T, T, T, T, T, T, T,
    // Row 8
    W, B, B, B, W, W, T, T, T, T, T, T, T, T, T, T,
    // Row 9
    W, B, W, T, W, B, W, T, T, T, T, T, T, T, T, T,
    // Row 10
    W, W, T, T, T, W, B, W, T, T, T, T, T, T, T, T,
    // Row 11
    T, T, T, T, T, T, W, B, W, T, T, T, T, T, T, T,
    // Row 12
    T, T, T, T, T, T, T, W, W, T, T, T, T, T, T, T,
    // Row 13
    T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,
    // Row 14
    T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,
    // Row 15
    T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T,
];

// =============================================================================
// Internal rendering
// =============================================================================

/// Blit the cursor bitmap at `(cx, cy)`. Transparent pixels are skipped.
fn draw_cursor(fb: &FrameBuffer, cx: u32, cy: u32) {
    for row in 0_u32..16 {
        for col in 0_u32..16 {
            #[allow(clippy::indexing_slicing)]
            let pixel = CURSOR_BITMAP[(row * 16 + col) as usize];
            if pixel == T {
                continue;
            }
            fb.write_pixel(cx.saturating_add(col), cy.saturating_add(row), pixel);
        }
    }
}

// =============================================================================
// Cursor
// =============================================================================

/// Software cursor — tracks the current hotspot and the pixels it covers.
///
/// Before drawing anything that might overlap the cursor area (e.g. a taskbar
/// update or a window redraw), call [`hide`](Cursor::hide) to restore the
/// underlying pixels, then call [`show`](Cursor::show) afterwards to
/// re-save and re-blit.
pub struct Cursor {
    /// Hotspot X coordinate (left edge of the 16×16 bitmap).
    pub cx: u32,
    /// Hotspot Y coordinate (top edge of the 16×16 bitmap).
    pub cy: u32,
    /// Raw framebuffer bytes saved from beneath the cursor (up to 4 B/px × 256 px).
    saved: [u8; 1024],
}

impl Cursor {
    /// Create a cursor at `(cx, cy)`, saving the underlying pixels and blitting
    /// the arrow bitmap.
    pub fn new(fb: &FrameBuffer, cx: u32, cy: u32) -> Self {
        let mut saved = [0u8; 1024];
        fb.save_16x16(cx, cy, &mut saved);
        draw_cursor(fb, cx, cy);
        Self { cx, cy, saved }
    }

    /// Restore the pixels saved when the cursor was last placed, erasing it
    /// visually without touching the rest of the framebuffer.
    pub fn hide(&self, fb: &FrameBuffer) {
        fb.restore_16x16(self.cx, self.cy, &self.saved);
    }

    /// Save the pixels currently beneath the cursor and blit the arrow.
    ///
    /// Call this after any operation that may have redrawn the area under
    /// the cursor (e.g. taskbar clock updates), so that a subsequent
    /// [`hide`](Cursor::hide) restores the correct background.
    pub fn show(&mut self, fb: &FrameBuffer) {
        fb.save_16x16(self.cx, self.cy, &mut self.saved);
        draw_cursor(fb, self.cx, self.cy);
    }

    /// Move the cursor by `(dx, dy)` pixels, clamped to the framebuffer bounds.
    ///
    /// Erases the cursor at the old position, updates the hotspot, then saves
    /// the background and draws at the new position.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "framebuffer dims < i32::MAX; clamp keeps result in u32 range"
    )]
    pub fn move_by(&mut self, fb: &FrameBuffer, dx: i32, dy: i32) {
        self.hide(fb);
        self.cx = (self.cx as i32 + dx).clamp(0, fb.width as i32 - 1) as u32;
        self.cy = (self.cy as i32 + dy).clamp(0, fb.height as i32 - 1) as u32;
        fb.save_16x16(self.cx, self.cy, &mut self.saved);
        draw_cursor(fb, self.cx, self.cy);
    }

    /// Move the cursor to absolute pixel position `(x, y)`, clamped to the
    /// framebuffer bounds.
    ///
    /// Used by the `VirtIO` tablet driver, which delivers absolute coordinates
    /// already scaled into framebuffer pixel space.
    pub fn move_to(&mut self, fb: &FrameBuffer, x: u32, y: u32) {
        self.hide(fb);
        self.cx = x.min(fb.width.saturating_sub(1));
        self.cy = y.min(fb.height.saturating_sub(1));
        fb.save_16x16(self.cx, self.cy, &mut self.saved);
        draw_cursor(fb, self.cx, self.cy);
    }
}
