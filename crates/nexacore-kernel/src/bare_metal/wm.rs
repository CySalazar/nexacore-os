//! Minimal kernel-mode window manager for the M2 graphical desktop.
//!
//! Manages a static pool of up to 8 [`Window`] slots (no heap allocation).
//! Each window is a decorated rectangle with a title bar and optional focus
//! highlight. A [`WindowManager`] tracks focus state and handles Tab-cycling.
//!
//! The taskbar is a fixed 28-pixel strip at the bottom of the framebuffer,
//! showing the NexaCore OS label on the left and the RTC clock in the centre.
//! Shutdown is exclusively user-driven via the "Power Off" button in the
//! System Info window — no auto-off timer.

use super::{font, graphics, graphics::FrameBuffer};

// =============================================================================
// Layout constants
// =============================================================================

/// Height of the window title bar in pixels.
pub const TITLEBAR_H: u32 = 20;

/// Height of the taskbar strip at the bottom of the screen.
pub const TASKBAR_H: u32 = 28;

// Taskbar partition widths (in pixels from the left edge).
const TASKBAR_LABEL_END: u32 = 90;

// =============================================================================
// Window
// =============================================================================

/// A rectangular window with a title bar and a solid content area.
///
/// Coordinates are in framebuffer pixels (top-left origin).
/// `x1 = x + width`, `y1 = y + height` (exclusive).
pub struct Window {
    /// Left edge.
    pub x: u32,
    /// Top edge.
    pub y: u32,
    /// Width in pixels (including title bar and borders).
    pub width: u32,
    /// Height in pixels (including title bar and borders).
    pub height: u32,
    /// Title displayed in the title bar.
    pub title: &'static str,
    /// Background colour of the content area (32-bit ARGB).
    pub bg_color: u32,
}

impl Window {
    /// A zero-sized placeholder used when an index slot is empty.
    pub const DEFAULT: Self = Self {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
        title: "",
        bg_color: graphics::DARK_NAVY,
    };
}

// =============================================================================
// WindowManager
// =============================================================================

/// Static-pool window manager — holds up to 8 windows with no heap allocation.
pub struct WindowManager {
    windows: [Option<Window>; 8],
    count: usize,
    /// Index of the currently focused window.
    pub focused_idx: usize,
}

impl WindowManager {
    /// Create an empty window manager with no windows and focus on slot 0.
    #[allow(
        clippy::new_without_default,
        reason = "const fn enables construction in static context; Default cannot be const"
    )]
    pub const fn new() -> Self {
        Self {
            windows: [None, None, None, None, None, None, None, None],
            count: 0,
            focused_idx: 0,
        }
    }

    /// Add a window. Returns `true` on success, `false` if the pool is full.
    pub fn add(&mut self, window: Window) -> bool {
        if self.count >= 8 {
            return false;
        }
        #[allow(
            clippy::indexing_slicing,
            reason = "self.count < 8 guaranteed by guard above"
        )]
        {
            self.windows[self.count] = Some(window);
        }
        self.count += 1;
        true
    }

    /// Return a reference to window at `idx`, or `None` if the slot is empty.
    pub fn get(&self, idx: usize) -> Option<&Window> {
        if idx >= 8 {
            return None;
        }
        #[allow(clippy::indexing_slicing, reason = "idx < 8 guaranteed by guard above")]
        {
            self.windows[idx].as_ref()
        }
    }

    /// Draw all windows. The focused window gets a cyan border; others get
    /// dark-gray borders.
    pub fn draw_all(&self, fb: &FrameBuffer) {
        for (i, slot) in self.windows.iter().enumerate() {
            if let Some(w) = slot {
                draw_window(fb, w, i == self.focused_idx);
            }
        }
    }

    /// If `(px, py)` falls inside any window's title bar, shift focus to that
    /// window and redraw the two affected borders. Returns `true` if focus
    /// changed.
    #[allow(
        clippy::indexing_slicing,
        reason = "i < self.count <= 8 and self.focused_idx < 8 by invariants"
    )]
    pub fn click_hit_test(&mut self, fb: &FrameBuffer, px: u32, py: u32) -> bool {
        let mut hit = None;
        for i in 0..self.count {
            if let Some(w) = &self.windows[i] {
                if px >= w.x && px < w.x + w.width && py >= w.y && py < w.y + TITLEBAR_H {
                    hit = Some(i);
                    break;
                }
            }
        }
        if let Some(idx) = hit {
            if idx != self.focused_idx {
                if let Some(w) = &self.windows[self.focused_idx] {
                    fb.draw_rect_outline(
                        w.x,
                        w.y,
                        w.x + w.width,
                        w.y + w.height,
                        graphics::DARK_GRAY,
                    );
                }
                self.focused_idx = idx;
                if let Some(w) = &self.windows[self.focused_idx] {
                    fb.draw_rect_outline(w.x, w.y, w.x + w.width, w.y + w.height, graphics::CYAN);
                }
                return true;
            }
        }
        false
    }

    /// Rotate focus to the next window and redraw only the two affected borders.
    #[allow(
        clippy::indexing_slicing,
        reason = "self.focused_idx < self.count <= 8 by invariants"
    )]
    pub fn tab_focus(&mut self, fb: &FrameBuffer) {
        if self.count == 0 {
            return;
        }
        // Redraw old border as unfocused.
        if let Some(w) = &self.windows[self.focused_idx] {
            fb.draw_rect_outline(w.x, w.y, w.x + w.width, w.y + w.height, graphics::DARK_GRAY);
        }
        self.focused_idx = (self.focused_idx + 1) % self.count;
        // Redraw new border as focused.
        if let Some(w) = &self.windows[self.focused_idx] {
            fb.draw_rect_outline(w.x, w.y, w.x + w.width, w.y + w.height, graphics::CYAN);
        }
    }
}

// =============================================================================
// Drawing helpers
// =============================================================================

/// Render a single window: title bar, content area, and 1-pixel border.
///
/// - Title bar: `DARK_NAVY` background, title text in `LIGHT_CYAN`.
/// - Border: `CYAN` when `focused`, `DARK_GRAY` otherwise.
/// - Content area: `window.bg_color`.
pub fn draw_window(fb: &FrameBuffer, window: &Window, focused: bool) {
    if window.width == 0 || window.height == 0 {
        return;
    }
    let x1 = window.x + window.width;
    let y1 = window.y + window.height;
    let title_bottom = window.y + TITLEBAR_H;

    // Title bar background.
    fb.draw_rect_filled(window.x, window.y, x1, title_bottom, graphics::DARK_NAVY);
    // Title text (left-padded 6 px, vertically centred in title bar).
    #[allow(
        clippy::integer_division,
        reason = "integer pixel coords; truncation in vertical centering is intentional"
    )]
    let title_y = window.y + (TITLEBAR_H.saturating_sub(8)) / 2;
    font::render_str(
        fb,
        window.x + 6,
        title_y,
        window.title,
        graphics::LIGHT_CYAN,
        graphics::DARK_NAVY,
    );

    // Content area.
    if window.height > TITLEBAR_H {
        fb.draw_rect_filled(window.x, title_bottom, x1, y1, window.bg_color);
    }

    // Border (drawn last so it sits on top of the fill).
    let border = if focused {
        graphics::CYAN
    } else {
        graphics::DARK_GRAY
    };
    fb.draw_rect_outline(window.x, window.y, x1, y1, border);
}

// =============================================================================
// Taskbar
// =============================================================================

/// Draw the full taskbar strip at the bottom of the framebuffer.
///
/// Layout: `[NexaCore OS | HH:MM:SS ]`. The right portion of the strip is left
/// blank — shutdown is exclusively triggered by the "Power Off" button in the
/// System Info window.
pub fn draw_taskbar(fb: &FrameBuffer) {
    let y0 = fb.height.saturating_sub(TASKBAR_H);

    // Background + top separator.
    fb.draw_rect_filled(0, y0, fb.width, fb.height, graphics::DARK_NAVY);
    fb.draw_hline(0, fb.width, y0, graphics::CYAN);

    // "NexaCore OS" label.
    font::render_str(
        fb,
        8,
        y0 + 10,
        "NexaCore OS",
        graphics::LIGHT_CYAN,
        graphics::DARK_NAVY,
    );

    // Divider after label.
    fb.draw_vline(
        TASKBAR_LABEL_END,
        y0 + 4,
        fb.height.saturating_sub(4),
        graphics::DARK_GRAY,
    );
}

/// Display a "Powering off…" overlay centred in the taskbar.
pub fn show_poweroff_overlay(fb: &FrameBuffer) {
    let y0 = fb.height.saturating_sub(TASKBAR_H);
    fb.draw_rect_filled(0, y0 + 1, fb.width, fb.height, graphics::DARK_NAVY);
    font::render_str(
        fb,
        8,
        y0 + 10,
        "Powering off...",
        graphics::YELLOW,
        graphics::DARK_NAVY,
    );
}

/// Display a "Rebooting…" overlay centred in the taskbar.
pub fn show_reboot_overlay(fb: &FrameBuffer) {
    let y0 = fb.height.saturating_sub(TASKBAR_H);
    fb.draw_rect_filled(0, y0 + 1, fb.width, fb.height, graphics::DARK_NAVY);
    font::render_str(
        fb,
        8,
        y0 + 10,
        "Rebooting...",
        graphics::YELLOW,
        graphics::DARK_NAVY,
    );
}
