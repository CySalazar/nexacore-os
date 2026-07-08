//! Window type: the unit of window-manager management.
//!
//! A [`Window`] binds a [`Surface`] (pixel buffer) to a screen position,
//! z-order, visibility flag, and title.  The [`crate::wm::WindowManager`]
//! owns all windows.
//!
//! # `no_std` compatibility
//!
//! Depends only on `alloc::string::String`; no `std` API is required.

use alloc::string::String;

use crate::{
    geometry::Rect,
    surface::{Surface, WindowId},
};

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------

/// A single on-screen window owned by the [`crate::wm::WindowManager`].
///
/// Each window holds one [`Surface`] (the pixel content) and the screen
/// coordinates at which it is composited.  The `z` field determines paint
/// order: higher `z` means painted later (on top of lower-`z` windows).
///
/// # Example
///
/// ```
/// use nexacore_display::{
///     geometry::Rect,
///     surface::{Surface, SurfaceId, WindowId},
///     window::Window,
/// };
///
/// let surface = Surface::new(SurfaceId(0), 200, 100);
/// let win = Window {
///     id: WindowId(1),
///     x: 50,
///     y: 50,
///     z: 0,
///     surface,
///     visible: true,
///     title: String::from("my window"),
/// };
/// let r = win.screen_rect();
/// assert_eq!(
///     r,
///     Rect {
///         x: 50,
///         y: 50,
///         w: 200,
///         h: 100
///     }
/// );
/// ```
#[derive(Debug, Clone)]
pub struct Window {
    /// Unique identifier for this window.
    pub id: WindowId,
    /// Horizontal screen position of the top-left corner (signed, may be
    /// negative for off-screen windows).
    pub x: i32,
    /// Vertical screen position of the top-left corner (signed, may be
    /// negative for off-screen windows).
    pub y: i32,
    /// Paint order: higher `z` is drawn on top.  Assigned and managed by
    /// the [`crate::wm::WindowManager`].
    pub z: i32,
    /// Pixel content for this window.
    pub surface: Surface,
    /// Whether this window should be included in compositing.
    pub visible: bool,
    /// Human-readable title (shown in the focus border or a future title bar).
    pub title: String,
}

impl Window {
    /// Returns the screen rectangle occupied by this window.
    ///
    /// The rectangle's position is `(self.x, self.y)` and its size is the
    /// surface's `(width, height)`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{
    ///     geometry::Rect,
    ///     surface::{Surface, SurfaceId, WindowId},
    ///     window::Window,
    /// };
    ///
    /// let w = Window {
    ///     id: WindowId(0),
    ///     x: -10,
    ///     y: 5,
    ///     z: 0,
    ///     surface: Surface::new(SurfaceId(0), 80, 40),
    ///     visible: true,
    ///     title: String::new(),
    /// };
    /// assert_eq!(
    ///     w.screen_rect(),
    ///     Rect {
    ///         x: -10,
    ///         y: 5,
    ///         w: 80,
    ///         h: 40
    ///     }
    /// );
    /// ```
    #[must_use]
    pub fn screen_rect(&self) -> Rect {
        Rect {
            x: self.x,
            y: self.y,
            w: self.surface.width,
            h: self.surface.height,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::SurfaceId;

    fn make_window(id: u32, x: i32, y: i32, w: u32, h: u32) -> Window {
        Window {
            id: WindowId(id),
            x,
            y,
            z: 0,
            surface: Surface::new(SurfaceId(id), w, h),
            visible: true,
            title: String::new(),
        }
    }

    #[test]
    fn screen_rect_matches_position_and_size() {
        let win = make_window(0, 10, 20, 100, 50);
        assert_eq!(
            win.screen_rect(),
            Rect {
                x: 10,
                y: 20,
                w: 100,
                h: 50
            }
        );
    }

    #[test]
    fn screen_rect_negative_origin() {
        let win = make_window(1, -30, -15, 200, 100);
        let r = win.screen_rect();
        assert_eq!(r.x, -30);
        assert_eq!(r.y, -15);
        assert_eq!(r.w, 200);
        assert_eq!(r.h, 100);
    }

    #[test]
    fn screen_rect_zero_size() {
        let win = make_window(2, 0, 0, 0, 0);
        assert!(win.screen_rect().is_empty());
    }
}
