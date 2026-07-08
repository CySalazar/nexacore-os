//! Input routing to guest windows (WS9-03.8).
//!
//! Host pointer and keyboard events arrive in host-desktop coordinates and must
//! be delivered to the right guest window, in that window's local coordinate
//! space. The [`InputRouter`] holds the host geometry of each mapped window
//! (fed from the [`super::bridge::HostSurfaceDesc`] the bridge produces),
//! **hit-tests** the topmost window under the pointer, **translates**
//! coordinates to window-local, tracks **keyboard focus** (click-to-focus), and
//! emits the [`super::agent::HostToGuest`] message the guest agent expects.
//!
//! Coordinate translation assumes a window's host surface maps 1:1 to its
//! local space with the local origin at the surface's top-left — the case the
//! guest compositor guarantees for on-screen, interactive windows.

use std::collections::BTreeMap;

use super::{
    Point, Rect,
    agent::{HostToGuest, WindowId},
};

/// Linux `BTN_LEFT` — the primary button that transfers focus on press.
pub const BTN_LEFT: u32 = 0x110;

/// Host geometry of one mapped window, used for hit-testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowGeom {
    dest: Rect,
    z: u32,
}

/// The result of routing a host input event to a guest window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedInput {
    /// The window the event was delivered to.
    pub target: WindowId,
    /// The message to send to the guest agent.
    pub message: HostToGuest,
    /// Set when this event moved keyboard focus to a new window; the desktop
    /// layer should raise it and issue the paired focus in/out.
    pub focus_change: Option<WindowId>,
}

/// Routes host input to guest windows, tracking geometry and focus.
#[derive(Debug, Clone, Default)]
pub struct InputRouter {
    windows: BTreeMap<WindowId, WindowGeom>,
    focus: Option<WindowId>,
    last_pointer: Point,
}

impl InputRouter {
    /// An empty router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a window's host geometry (from its surface description).
    pub fn upsert_window(&mut self, id: WindowId, dest: Rect, z: u32) {
        self.windows.insert(id, WindowGeom { dest, z });
    }

    /// Remove a window; clears focus if it held it.
    pub fn remove_window(&mut self, id: WindowId) {
        self.windows.remove(&id);
        if self.focus == Some(id) {
            self.focus = None;
        }
    }

    /// The currently focused window, if any.
    #[must_use]
    pub fn focus(&self) -> Option<WindowId> {
        self.focus
    }

    /// The topmost window containing `p` (highest `z` wins), if any.
    #[must_use]
    pub fn hit_test(&self, p: Point) -> Option<WindowId> {
        self.windows
            .iter()
            .filter(|(_, g)| g.dest.contains(p))
            .max_by_key(|(_, g)| g.z)
            .map(|(id, _)| *id)
    }

    /// Route pointer motion. Returns `None` if the pointer is not over any
    /// guest window (the host handles it). Motion never changes focus.
    pub fn route_motion(&mut self, p: Point) -> Option<RoutedInput> {
        self.last_pointer = p;
        let id = self.hit_test(p)?;
        let dest = self.windows.get(&id)?.dest;
        let (x, y) = window_local(p, dest);
        Some(RoutedInput {
            target: id,
            message: HostToGuest::PointerMotion { id, x, y },
            focus_change: None,
        })
    }

    /// Route a pointer button. A primary-button **press** transfers focus to
    /// the window under the pointer. Returns `None` if no window is hit.
    pub fn route_button(&mut self, button: u32, pressed: bool) -> Option<RoutedInput> {
        let id = self.hit_test(self.last_pointer)?;
        let focus_change = if pressed && button == BTN_LEFT && self.focus != Some(id) {
            self.focus = Some(id);
            Some(id)
        } else {
            None
        };
        Some(RoutedInput {
            target: id,
            message: HostToGuest::PointerButton {
                id,
                button,
                pressed,
            },
            focus_change,
        })
    }

    /// Route a discrete scroll to the window under the pointer.
    pub fn route_scroll(&self, dx: i32, dy: i32) -> Option<RoutedInput> {
        let id = self.hit_test(self.last_pointer)?;
        Some(RoutedInput {
            target: id,
            message: HostToGuest::PointerScroll { id, dx, dy },
            focus_change: None,
        })
    }

    /// Route a key to the focused window. Returns `None` if nothing is focused.
    pub fn route_key(&self, keycode: u32, pressed: bool) -> Option<RoutedInput> {
        let id = self.focus?;
        Some(RoutedInput {
            target: id,
            message: HostToGuest::Key {
                id,
                keycode,
                pressed,
            },
            focus_change: None,
        })
    }

    /// Explicitly set keyboard focus (e.g. via the task switcher). Returns the
    /// focus change if it differs from the current focus and the window exists.
    pub fn set_focus(&mut self, id: WindowId) -> Option<WindowId> {
        if self.windows.contains_key(&id) && self.focus != Some(id) {
            self.focus = Some(id);
            Some(id)
        } else {
            None
        }
    }
}

/// Translate a host-desktop point to window-local coordinates.
fn window_local(p: Point, dest: Rect) -> (i32, i32) {
    (p.x.saturating_sub(dest.x), p.y.saturating_sub(dest.y))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn router() -> InputRouter {
        let mut r = InputRouter::new();
        // Two overlapping windows; window 2 is on top (higher z).
        r.upsert_window(WindowId(1), Rect::new(0, 0, 200, 200), 0);
        r.upsert_window(WindowId(2), Rect::new(100, 100, 200, 200), 1);
        r
    }

    #[test]
    fn hit_test_prefers_topmost() {
        let r = router();
        // Overlap region belongs to the higher-z window.
        assert_eq!(r.hit_test(Point::new(150, 150)), Some(WindowId(2)));
        // Non-overlap region of the bottom window.
        assert_eq!(r.hit_test(Point::new(50, 50)), Some(WindowId(1)));
        // Empty desktop.
        assert_eq!(r.hit_test(Point::new(999, 999)), None);
    }

    #[test]
    fn motion_translates_to_window_local() {
        let mut r = router();
        let out = r.route_motion(Point::new(150, 160)).unwrap();
        assert_eq!(out.target, WindowId(2));
        // Local = point - dest.origin (100,100) = (50,60).
        assert_eq!(
            out.message,
            HostToGuest::PointerMotion {
                id: WindowId(2),
                x: 50,
                y: 60,
            }
        );
        assert!(out.focus_change.is_none());
    }

    #[test]
    fn motion_off_window_is_none() {
        let mut r = router();
        assert!(r.route_motion(Point::new(999, 999)).is_none());
    }

    #[test]
    fn primary_press_transfers_focus() {
        let mut r = router();
        r.route_motion(Point::new(150, 150)); // over window 2
        let out = r.route_button(BTN_LEFT, true).unwrap();
        assert_eq!(out.focus_change, Some(WindowId(2)));
        assert_eq!(r.focus(), Some(WindowId(2)));
        // Re-pressing the same window does not re-fire a focus change.
        let again = r.route_button(BTN_LEFT, true).unwrap();
        assert!(again.focus_change.is_none());
    }

    #[test]
    fn keys_go_to_focused_window() {
        let mut r = router();
        assert!(r.route_key(30, true).is_none()); // nothing focused yet
        r.route_motion(Point::new(50, 50)); // over window 1
        r.route_button(BTN_LEFT, true);
        let out = r.route_key(30, true).unwrap();
        assert_eq!(
            out.message,
            HostToGuest::Key {
                id: WindowId(1),
                keycode: 30,
                pressed: true,
            }
        );
    }

    #[test]
    fn removing_focused_window_clears_focus() {
        let mut r = router();
        r.route_motion(Point::new(50, 50));
        r.route_button(BTN_LEFT, true);
        assert_eq!(r.focus(), Some(WindowId(1)));
        r.remove_window(WindowId(1));
        assert_eq!(r.focus(), None);
    }
}
