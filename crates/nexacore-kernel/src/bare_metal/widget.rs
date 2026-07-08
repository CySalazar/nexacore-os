//! Minimal widget toolkit — Label and Button for kernel-mode windows.
//!
//! Positions are relative to a window's content area (top-left of the area
//! below the title bar). The caller computes the absolute origin and passes
//! it to each draw function.
//!
//! No heap allocation: every widget is a plain struct suitable for `const`.

use super::{font, graphics, graphics::FrameBuffer};

// =============================================================================
// Label
// =============================================================================

/// A static text label positioned within a window's content area.
pub struct Label {
    /// Horizontal offset from the content area's left edge, in pixels.
    pub rel_x: u32,
    /// Vertical offset from the content area's top edge, in pixels.
    pub rel_y: u32,
    /// Text to display (ASCII, 8×8 font).
    pub text: &'static str,
    /// Foreground colour (32-bit ARGB).
    pub fg: u32,
}

/// Draw a label at `(content_x + label.rel_x, content_y + label.rel_y)`.
pub fn draw_label(fb: &FrameBuffer, content_x: u32, content_y: u32, label: &Label, bg: u32) {
    font::render_str(
        fb,
        content_x + label.rel_x,
        content_y + label.rel_y,
        label.text,
        label.fg,
        bg,
    );
}

// =============================================================================
// Button
// =============================================================================

/// A labelled push-button positioned within a window's content area.
///
/// The button has no persistent focus state — callers pass `focused` to
/// [`draw_button`] to control the visual appearance.
pub struct Button {
    /// Horizontal offset from the content area's left edge, in pixels.
    pub rel_x: u32,
    /// Vertical offset from the content area's top edge, in pixels.
    pub rel_y: u32,
    /// Button width in pixels.
    pub width: u32,
    /// Button height in pixels.
    pub height: u32,
    /// Button label text (ASCII, 8×8 font, centred).
    pub label: &'static str,
}

/// Draw a button inside the given content area.
///
/// - Normal (`focused = false`): `DARK_GRAY` fill, `WHITE` text, no border.
/// - Highlighted (`focused = true`): `CYAN` fill, `DARK_NAVY` text + border.
pub fn draw_button(fb: &FrameBuffer, content_x: u32, content_y: u32, btn: &Button, focused: bool) {
    let x0 = content_x + btn.rel_x;
    let y0 = content_y + btn.rel_y;
    let x1 = x0 + btn.width;
    let y1 = y0 + btn.height;

    let (fill, text_fg) = if focused {
        (graphics::CYAN, graphics::DARK_NAVY)
    } else {
        (graphics::DARK_GRAY, graphics::WHITE)
    };

    fb.draw_rect_filled(x0, y0, x1, y1, fill);

    if focused {
        fb.draw_rect_outline(x0, y0, x1, y1, graphics::DARK_NAVY);
    }

    // Centre label horizontally and vertically within the button.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "button label length fits u32 for any realistic UI"
    )]
    let label_w = btn.label.len() as u32 * 8;
    #[allow(
        clippy::integer_division,
        reason = "integer pixel coords; truncation in label centering is intentional"
    )]
    let tx = x0 + btn.width.saturating_sub(label_w) / 2;
    #[allow(
        clippy::integer_division,
        reason = "integer pixel coords; truncation in label centering is intentional"
    )]
    let ty = y0 + btn.height.saturating_sub(8) / 2;
    font::render_str(fb, tx, ty, btn.label, text_fg, fill);
}

// =============================================================================
// Hit testing
// =============================================================================

/// Return `true` if point `(px, py)` falls inside the button's rendered rect.
pub fn button_hit_test(btn: &Button, content_x: u32, content_y: u32, px: u32, py: u32) -> bool {
    let x0 = content_x + btn.rel_x;
    let y0 = content_y + btn.rel_y;
    px >= x0 && px < x0 + btn.width && py >= y0 && py < y0 + btn.height
}
