//! Window manager: lifecycle, z-order, focus, and input routing.
//!
//! [`WindowManager`] is the authority over all live windows.  It handles:
//!
//! * **Lifecycle** — [`WindowManager::create_window`] allocates a new window
//!   and gives it the next z-order position; [`WindowManager::destroy`] removes
//!   it and re-focuses the topmost remaining window if it was focused.
//! * **Z-order** — [`WindowManager::raise`] moves a window to the top;
//!   [`WindowManager::windows_bottom_to_top`] provides the paint-order iterator
//!   the compositor uses.
//! * **Focus** — exactly one window is focused at a time (or none if there are
//!   no windows).  [`WindowManager::set_focus`] changes focus; [`WindowManager::cycle_focus`]
//!   implements Tab-style rotation.
//! * **Input routing** — [`WindowManager::route_input`] returns the window that
//!   should receive a [`DisplayInputEvent`]: keyboard events go to the focused
//!   window only; pointer events are routed by hit-test.
//!
//! The `WindowManager` itself does not track damage; callers (the [`crate::compositor::Compositor`])
//! observe the return values of mutating operations and record the affected
//! screen rects in a [`crate::geometry::DamageRegion`].
//!
//! # `no_std` compatibility
//!
//! Uses `alloc::vec::Vec` and `alloc::string::String`; no `std` API is required.

use alloc::{string::String, vec::Vec};

use nexacore_types::display_channel::DisplayInputEvent;

use crate::{
    DisplayError,
    geometry::Rect,
    surface::{Surface, WindowId},
    window::Window,
};

// ---------------------------------------------------------------------------
// WindowManager
// ---------------------------------------------------------------------------

/// Central manager for all live windows.
///
/// Owns the list of [`Window`]s, the focus state, and the z-order counter.
/// All coordinates passed to mutating methods are clamped to the configured
/// `screen` rectangle before being applied (ADR-0041 D4).
///
/// # Example
///
/// ```
/// use nexacore_display::{
///     geometry::Rect,
///     surface::{Surface, SurfaceId, WindowId},
///     wm::WindowManager,
/// };
///
/// let screen = Rect {
///     x: 0,
///     y: 0,
///     w: 1920,
///     h: 1080,
/// };
/// let mut wm = WindowManager::new(screen);
/// let surface = Surface::new(SurfaceId(0), 300, 200);
/// let id = wm.create_window(100, 100, surface, String::from("hello"));
/// assert_eq!(wm.focused(), Some(id));
/// ```
pub struct WindowManager {
    /// All live windows, in creation order (z-order is a field inside each).
    windows: Vec<Window>,
    /// The currently focused window, or `None` if there are no windows.
    focus: Option<WindowId>,
    /// Monotonically increasing counter used to assign unique `WindowId`s.
    next_id: u32,
    /// Monotonically increasing counter used to assign z-order values.
    /// Each `raise` and `create` bumps this and uses the new value.
    next_z: i32,
    /// Screen bounds used for clamping window positions.
    screen: Rect,
}

impl WindowManager {
    /// Creates a new, empty [`WindowManager`] for the given `screen` bounds.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{geometry::Rect, wm::WindowManager};
    /// let wm = WindowManager::new(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 1920,
    ///     h: 1080,
    /// });
    /// assert!(wm.focused().is_none());
    /// ```
    #[must_use]
    pub fn new(screen: Rect) -> Self {
        Self {
            windows: Vec::new(),
            focus: None,
            next_id: 0,
            next_z: 0,
            screen,
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Creates a new window at `(x, y)` with the given `surface` and `title`.
    ///
    /// The window is created at the top of the z-order and immediately
    /// receives focus.  Its position is clamped to the screen bounds.
    ///
    /// Returns the [`WindowId`] of the new window.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{
    ///     geometry::Rect,
    ///     surface::{Surface, SurfaceId},
    ///     wm::WindowManager,
    /// };
    ///
    /// let mut wm = WindowManager::new(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 800,
    ///     h: 600,
    /// });
    /// let id = wm.create_window(
    ///     50,
    ///     50,
    ///     Surface::new(SurfaceId(0), 100, 80),
    ///     String::from("test"),
    /// );
    /// assert_eq!(wm.focused(), Some(id));
    /// ```
    pub fn create_window(&mut self, x: i32, y: i32, surface: Surface, title: String) -> WindowId {
        let id = WindowId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);

        // Bump z counter so this window is on top of all existing ones.
        self.next_z = self.next_z.wrapping_add(1);
        let z = self.next_z;

        let (cx, cy) = self.clamp_position(x, y);

        self.windows.push(Window {
            id,
            x: cx,
            y: cy,
            z,
            surface,
            visible: true,
            title,
        });

        // New window gets immediate focus.
        self.focus = Some(id);
        id
    }

    /// Destroys the window identified by `id`.
    ///
    /// If the window was focused, focus transfers to the window with the
    /// highest z-order among the remaining windows (i.e. the topmost visible
    /// window), or becomes `None` if no windows remain.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError::UnknownWindow`] if `id` is not found.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{
    ///     geometry::Rect,
    ///     surface::{Surface, SurfaceId},
    ///     wm::WindowManager,
    /// };
    ///
    /// let mut wm = WindowManager::new(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 800,
    ///     h: 600,
    /// });
    /// let id = wm.create_window(0, 0, Surface::new(SurfaceId(0), 50, 50), String::new());
    /// wm.destroy(id).unwrap();
    /// assert!(wm.focused().is_none());
    /// ```
    pub fn destroy(&mut self, id: WindowId) -> Result<(), DisplayError> {
        let pos = self
            .windows
            .iter()
            .position(|w| w.id == id)
            .ok_or(DisplayError::UnknownWindow(id))?;

        self.windows.remove(pos);

        // If the destroyed window was focused, pick the new topmost window.
        if self.focus == Some(id) {
            self.focus = self.windows.iter().max_by_key(|w| w.z).map(|w| w.id);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Geometry
    // -----------------------------------------------------------------------

    /// Moves window `id` to `(x, y)`, clamped to the screen bounds.
    ///
    /// Returns the old [`Rect`] of the window (before the move) so the caller
    /// can damage both the old and new positions.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError::UnknownWindow`] if `id` is not found.
    pub fn move_to(&mut self, id: WindowId, x: i32, y: i32) -> Result<Rect, DisplayError> {
        let win = self
            .windows
            .iter_mut()
            .find(|w| w.id == id)
            .ok_or(DisplayError::UnknownWindow(id))?;

        let old_rect = win.screen_rect();
        let (cx, cy) = clamp_pos_to_screen(x, y, &self.screen);
        win.x = cx;
        win.y = cy;
        Ok(old_rect)
    }

    // -----------------------------------------------------------------------
    // Z-order
    // -----------------------------------------------------------------------

    /// Raises window `id` to the top of the z-order.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError::UnknownWindow`] if `id` is not found.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{
    ///     geometry::Rect,
    ///     surface::{Surface, SurfaceId},
    ///     wm::WindowManager,
    /// };
    ///
    /// let mut wm = WindowManager::new(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 800,
    ///     h: 600,
    /// });
    /// let a = wm.create_window(0, 0, Surface::new(SurfaceId(0), 50, 50), String::new());
    /// let b = wm.create_window(0, 0, Surface::new(SurfaceId(1), 50, 50), String::new());
    /// // b is on top. Raise a.
    /// wm.raise(a).unwrap();
    /// let top = wm.windows_bottom_to_top().last().unwrap();
    /// assert_eq!(top.id, a);
    /// ```
    pub fn raise(&mut self, id: WindowId) -> Result<(), DisplayError> {
        // Verify the window exists.
        let _ = self
            .windows
            .iter()
            .find(|w| w.id == id)
            .ok_or(DisplayError::UnknownWindow(id))?;

        self.next_z = self.next_z.wrapping_add(1);
        let new_z = self.next_z;

        if let Some(win) = self.windows.iter_mut().find(|w| w.id == id) {
            win.z = new_z;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Focus
    // -----------------------------------------------------------------------

    /// Sets the focused window to `id`.
    ///
    /// Returns `(old_focus, new_focus)` so the caller can damage both the
    /// previously focused window (to redraw without a focus border) and the
    /// newly focused one (to draw a focus border).
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError::UnknownWindow`] if `id` is not found.
    pub fn set_focus(
        &mut self,
        id: WindowId,
    ) -> Result<(Option<WindowId>, WindowId), DisplayError> {
        // Verify the target window exists.
        let _ = self
            .windows
            .iter()
            .find(|w| w.id == id)
            .ok_or(DisplayError::UnknownWindow(id))?;

        let old_focus = self.focus;
        self.focus = Some(id);
        Ok((old_focus, id))
    }

    /// Cycles focus to the next **visible** window in z-order (Tab-key
    /// semantics).
    ///
    /// Only windows with `visible == true` are eligible: invisible windows
    /// (e.g. windows created hidden, such as Files/Editor/Settings before
    /// they are shown) must never receive compositor focus, since the shell's
    /// focus tracking silently no-ops on a non-visible window and Tab-cycling
    /// onto one would desync compositor focus from shell-tracked focus.
    ///
    /// Windows are cycled in ascending z-order among the visible set:
    ///
    /// - If there is currently a focused *visible* window, focus moves to the
    ///   next visible window above it in z-order, wrapping to the
    ///   bottom-most visible window when the topmost visible window is
    ///   reached.
    /// - If there is no current focus, **or** the currently focused window is
    ///   not visible (e.g. it was hidden after being focused, or no longer
    ///   exists), this is treated the same as "no current focus": focus lands
    ///   on the bottom-most visible window.
    /// - If there is exactly one visible window, focus lands on (or stays on)
    ///   it, regardless of what was previously focused.
    /// - If there are **no** visible windows, this returns `None` and also
    ///   clears `self.focus` to `None`. A stale `Some(hidden_id)` would leave
    ///   input routing pointing at a window that can never legitimately
    ///   receive focus again until it is shown and explicitly re-focused;
    ///   `None` is the safer state (callers already treat "no focus" as
    ///   dropping key events in [`WindowManager::route_input`]).
    ///
    /// Returns the new [`WindowId`] that received focus, or `None` if no
    /// visible windows are present.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{
    ///     geometry::Rect,
    ///     surface::{Surface, SurfaceId},
    ///     wm::WindowManager,
    /// };
    ///
    /// let mut wm = WindowManager::new(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 800,
    ///     h: 600,
    /// });
    /// let a = wm.create_window(0, 0, Surface::new(SurfaceId(0), 50, 50), String::new());
    /// let b = wm.create_window(10, 10, Surface::new(SurfaceId(1), 50, 50), String::new());
    /// // b was just created and is focused; cycle should land on a.
    /// let new_focus = wm.cycle_focus();
    /// assert!(new_focus.is_some());
    /// assert_ne!(new_focus, Some(b));
    /// ```
    pub fn cycle_focus(&mut self) -> Option<WindowId> {
        // Collect *visible* window IDs sorted by z ascending.  Invisible
        // windows are never eligible for focus (see doc comment above).
        let mut by_z: Vec<(i32, WindowId)> = self
            .windows
            .iter()
            .filter(|w| w.visible)
            .map(|w| (w.z, w.id))
            .collect();
        by_z.sort_unstable_by_key(|&(z, _)| z);

        if by_z.is_empty() {
            // No visible window can hold focus. Clear a possibly-stale
            // focus rather than leaving it pointing at a hidden window.
            self.focus = None;
            return None;
        }

        if by_z.len() == 1 {
            // Exactly one visible window: cycling always lands on it, even
            // if the previous focus was `None` or a since-hidden window.
            let only = by_z.first().map(|&(_, id)| id);
            self.focus = only;
            return only;
        }

        let len = by_z.len();
        // Use `.get()` everywhere to avoid clippy::indexing_slicing.  `len > 0`
        // is guaranteed by the `is_empty()` guard above.
        // Use `map_or_else` to avoid clippy::option_if_let_else.
        let new_id = self.focus.map_or_else(
            || {
                // No current focus: focus the bottom-most visible window.
                by_z.first().map(|&(_, id)| id)
            },
            |focused_id| {
                // Find the index of the currently focused window among the
                // *visible* ones and pick the next one, wrapping around. If
                // `focused_id` isn't found here (it's hidden, or no longer
                // exists), fall back to the bottom-most visible window —
                // same treatment as "no current focus".
                let pos = by_z.iter().position(|&(_, id)| id == focused_id);
                pos.map_or_else(
                    || by_z.first().map(|&(_, id)| id),
                    |i| by_z.get((i + 1) % len).map(|&(_, id)| id),
                )
            },
        );

        self.focus = new_id;
        self.focus
    }

    /// Returns the currently focused [`WindowId`], or `None`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{geometry::Rect, wm::WindowManager};
    /// let wm = WindowManager::new(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 100,
    ///     h: 100,
    /// });
    /// assert_eq!(wm.focused(), None);
    /// ```
    #[must_use]
    pub fn focused(&self) -> Option<WindowId> {
        self.focus
    }

    // -----------------------------------------------------------------------
    // Hit-test and input routing
    // -----------------------------------------------------------------------

    /// Returns the topmost visible window whose screen rect contains `(px, py)`.
    ///
    /// "Topmost" means the highest `z` value.  Returns `None` if no visible
    /// window covers the point (pointer is on empty desktop).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{
    ///     geometry::Rect,
    ///     surface::{Surface, SurfaceId},
    ///     wm::WindowManager,
    /// };
    ///
    /// let mut wm = WindowManager::new(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 800,
    ///     h: 600,
    /// });
    /// let id = wm.create_window(10, 10, Surface::new(SurfaceId(0), 100, 100), String::new());
    /// assert_eq!(wm.hit_test(50, 50), Some(id));
    /// assert_eq!(wm.hit_test(5, 5), None); // outside the window
    /// ```
    #[must_use]
    pub fn hit_test(&self, px: i32, py: i32) -> Option<WindowId> {
        // Walk windows in descending z order; first hit wins.
        self.windows
            .iter()
            .filter(|w| w.visible)
            .max_by_key(|w| w.z)
            .and_then(|_| {
                // Manual iteration: we need to find the topmost hit, not just
                // the topmost window.
                self.windows
                    .iter()
                    .filter(|w| w.visible && w.screen_rect().contains_point(px, py))
                    .max_by_key(|w| w.z)
                    .map(|w| w.id)
            })
    }

    /// Routes `ev` to the appropriate window and returns its [`WindowId`].
    ///
    /// Routing rules (ADR-0041 D3):
    /// - [`DisplayInputEvent::Key`] → the currently focused window, or `None`
    ///   if there is no focused window.  Keys **never** reach an unfocused
    ///   window.
    /// - [`DisplayInputEvent::Pointer`] → `hit_test(x, y)`; `None` if the
    ///   point is on empty desktop.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{
    ///     geometry::Rect,
    ///     surface::{Surface, SurfaceId},
    ///     wm::WindowManager,
    /// };
    /// use nexacore_types::display_channel::DisplayInputEvent;
    ///
    /// let mut wm = WindowManager::new(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 800,
    ///     h: 600,
    /// });
    /// let id = wm.create_window(0, 0, Surface::new(SurfaceId(0), 200, 200), String::new());
    /// let routed = wm.route_input(&DisplayInputEvent::Key {
    ///     code: b'a',
    ///     pressed: true,
    /// });
    /// assert_eq!(routed, Some(id));
    /// ```
    #[must_use]
    pub fn route_input(&self, ev: &DisplayInputEvent) -> Option<WindowId> {
        // Only pointer events require special routing; everything else (Key
        // and any future non_exhaustive variants) goes to the focused window.
        if let DisplayInputEvent::Pointer { x, y, .. } = ev {
            // Pointer coordinates are u32; convert to i32 for the hit-test.
            // Values > i32::MAX are treated as i32::MAX (far off-screen for
            // any practical resolution).
            let px = i32::try_from(*x).unwrap_or(i32::MAX);
            let py = i32::try_from(*y).unwrap_or(i32::MAX);
            self.hit_test(px, py)
        } else {
            // Key events (and future non_exhaustive variants) go to the focused
            // window only — keys NEVER reach an unfocused window (ADR-0041 D3).
            self.focus
        }
    }

    // -----------------------------------------------------------------------
    // Iteration
    // -----------------------------------------------------------------------

    /// Returns an iterator over all windows in ascending z-order (bottom to top).
    ///
    /// The compositor uses this order for back-to-front painting.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{
    ///     geometry::Rect,
    ///     surface::{Surface, SurfaceId},
    ///     wm::WindowManager,
    /// };
    ///
    /// let mut wm = WindowManager::new(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 800,
    ///     h: 600,
    /// });
    /// let a = wm.create_window(0, 0, Surface::new(SurfaceId(0), 10, 10), String::new());
    /// let b = wm.create_window(5, 5, Surface::new(SurfaceId(1), 10, 10), String::new());
    /// let ids: Vec<_> = wm.windows_bottom_to_top().map(|w| w.id).collect();
    /// // a was created first with lower z; b was created second with higher z.
    /// assert_eq!(ids[0], a);
    /// assert_eq!(ids[1], b);
    /// ```
    pub fn windows_bottom_to_top(&self) -> impl Iterator<Item = &Window> {
        // Collect references pre-sorted by z ascending.  Sorting by reference
        // avoids holding mutable indices alongside the slice, and removing the
        // index layer removes the indexing_slicing lint sites.
        let mut ordered: Vec<&Window> = self.windows.iter().collect();
        ordered.sort_unstable_by_key(|w| w.z);
        ordered.into_iter()
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Returns a shared reference to the window with `id`, or `None`.
    #[must_use]
    pub fn window(&self, id: WindowId) -> Option<&Window> {
        self.windows.iter().find(|w| w.id == id)
    }

    /// Returns an exclusive reference to the window with `id`, or `None`.
    pub fn window_mut(&mut self, id: WindowId) -> Option<&mut Window> {
        self.windows.iter_mut().find(|w| w.id == id)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Clamps a window's top-left corner to the screen bounds.
    ///
    /// A window is allowed to be partially off-screen (e.g. dragged to the
    /// edge), but its origin must remain within the screen so that at least
    /// one pixel is reachable.  We clamp `x` to `[screen.x, screen.right()-1]`
    /// and similarly for `y`.  The surface dimensions are not consulted here;
    /// the origin alone is clamped so a window can always be dragged back on
    /// screen regardless of size.
    fn clamp_position(&self, x: i32, y: i32) -> (i32, i32) {
        clamp_pos_to_screen(x, y, &self.screen)
    }
}

/// Clamps a window origin to keep the window's top-left inside the screen.
fn clamp_pos_to_screen(x: i32, y: i32, screen: &Rect) -> (i32, i32) {
    // Allow the top-left to sit anywhere within the screen rectangle.
    // The right/bottom of the screen is exclusive, so valid x is
    // [screen.x, screen.right() - 1].
    //
    // The `.min(i64::from(i32::MAX))` guard ensures the cast from i64 to i32
    // is safe: we have proved the value fits because we clamped it to the
    // i32 range before casting.
    let x_max_i64 = (screen.right() - 1).min(i64::from(i32::MAX));
    let y_max_i64 = (screen.bottom() - 1).min(i64::from(i32::MAX));
    // The cast is safe: both values are ≤ i32::MAX after the `.min()` above.
    #[allow(clippy::cast_possible_truncation)]
    let x_max = x_max_i64 as i32;
    #[allow(clippy::cast_possible_truncation)]
    let y_max = y_max_i64 as i32;
    let cx = x.max(screen.x).min(x_max);
    let cy = y.max(screen.y).min(y_max);
    (cx, cy)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use nexacore_types::display_channel::DisplayInputEvent;

    use super::*;
    use crate::surface::SurfaceId;

    fn screen() -> Rect {
        Rect {
            x: 0,
            y: 0,
            w: 800,
            h: 600,
        }
    }

    fn make_surface(id: u32, w: u32, h: u32) -> Surface {
        Surface::new(SurfaceId(id), w, h)
    }

    fn add_window(wm: &mut WindowManager, x: i32, y: i32, w: u32, h: u32) -> WindowId {
        // window count in tests ≪ u32::MAX.
        #[allow(clippy::cast_possible_truncation)]
        let sid = wm.windows.len() as u32;
        wm.create_window(x, y, make_surface(sid, w, h), String::new())
    }

    // --- Lifecycle ---

    #[test]
    fn create_and_destroy() {
        let mut wm = WindowManager::new(screen());
        let id = add_window(&mut wm, 0, 0, 50, 50);
        assert_eq!(wm.focused(), Some(id));
        wm.destroy(id).unwrap();
        assert_eq!(wm.focused(), None);
    }

    #[test]
    fn destroy_unknown_returns_error() {
        let mut wm = WindowManager::new(screen());
        assert!(matches!(
            wm.destroy(WindowId(999)),
            Err(DisplayError::UnknownWindow(_))
        ));
    }

    #[test]
    fn destroy_focused_window_focuses_next_topmost() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 50, 50); // z=1
        let b = add_window(&mut wm, 10, 10, 50, 50); // z=2, focused
        wm.destroy(b).unwrap();
        // After b is gone, a should be focused (it's the only one left).
        assert_eq!(wm.focused(), Some(a));
    }

    // --- Z-order and raise ---

    #[test]
    fn raise_makes_window_topmost() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 50, 50);
        let _b = add_window(&mut wm, 10, 10, 50, 50);
        // b is on top. Raise a.
        wm.raise(a).unwrap();
        let top = wm.windows_bottom_to_top().last().unwrap();
        assert_eq!(top.id, a);
    }

    #[test]
    fn windows_bottom_to_top_order() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 10, 10); // z=1
        let b = add_window(&mut wm, 5, 5, 10, 10); // z=2
        let c = add_window(&mut wm, 0, 5, 10, 10); // z=3
        let ids: Vec<_> = wm.windows_bottom_to_top().map(|w| w.id).collect();
        assert_eq!(ids, vec![a, b, c]);
    }

    // --- Focus ---

    #[test]
    fn set_focus_changes_focus() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 50, 50);
        let b = add_window(&mut wm, 10, 10, 50, 50);
        // b is focused after creation. Switch to a.
        let (old, new) = wm.set_focus(a).unwrap();
        assert_eq!(old, Some(b));
        assert_eq!(new, a);
        assert_eq!(wm.focused(), Some(a));
    }

    #[test]
    fn cycle_focus_wraps() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 50, 50); // z=1
        let b = add_window(&mut wm, 10, 10, 50, 50); // z=2, focused
        // Cycle: b (z=2, current) → next in z ascending = a? No:
        // sorted by z ascending: [a(z=1), b(z=2)].  Current=b(idx=1).
        // next = (1+1)%2 = 0 → a.
        let nf = wm.cycle_focus();
        assert_eq!(nf, Some(a));
        // Cycle again from a: (0+1)%2 = 1 → b.
        let nf2 = wm.cycle_focus();
        assert_eq!(nf2, Some(b));
    }

    #[test]
    fn cycle_focus_skips_hidden_middle_window() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 50, 50); // z=1, bottom
        let b = add_window(&mut wm, 10, 10, 50, 50); // z=2, middle -> hidden
        let c = add_window(&mut wm, 20, 20, 50, 50); // z=3, top
        wm.window_mut(b).unwrap().visible = false;
        // Start the cycle from a known point: focus on the bottom window.
        wm.set_focus(a).unwrap();
        let nf = wm.cycle_focus();
        // a -> should skip hidden b and land on c.
        assert_eq!(nf, Some(c));
        assert_ne!(nf, Some(b));
        let nf2 = wm.cycle_focus();
        // c -> wraps back to a, still skipping b.
        assert_eq!(nf2, Some(a));
        assert_ne!(nf2, Some(b));
    }

    #[test]
    fn cycle_focus_all_hidden_except_one_always_returns_it() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 50, 50);
        let b = add_window(&mut wm, 10, 10, 50, 50);
        let c = add_window(&mut wm, 20, 20, 50, 50);
        wm.window_mut(a).unwrap().visible = false;
        wm.window_mut(b).unwrap().visible = false;
        // c remains visible.
        assert_eq!(wm.cycle_focus(), Some(c));
        assert_eq!(wm.cycle_focus(), Some(c));
        assert_eq!(wm.cycle_focus(), Some(c));
    }

    #[test]
    fn cycle_focus_zero_visible_returns_none_and_clears_focus() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 50, 50);
        let b = add_window(&mut wm, 10, 10, 50, 50);
        wm.window_mut(a).unwrap().visible = false;
        wm.window_mut(b).unwrap().visible = false;
        assert_eq!(wm.cycle_focus(), None);
        assert_eq!(wm.focused(), None);
    }

    #[test]
    fn cycle_focus_current_focus_becomes_hidden_lands_on_visible() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 50, 50);
        let b = add_window(&mut wm, 10, 10, 50, 50);
        // b is focused after creation. Hide it while it's still focused.
        assert_eq!(wm.focused(), Some(b));
        wm.window_mut(b).unwrap().visible = false;
        let nf = wm.cycle_focus();
        assert_eq!(nf, Some(a));
        assert_ne!(nf, Some(b));

        // Now hide everything: must return None, and focus must be cleared.
        wm.window_mut(a).unwrap().visible = false;
        assert_eq!(wm.cycle_focus(), None);
        assert_eq!(wm.focused(), None);
    }

    // --- Hit-test ---

    #[test]
    fn hit_test_inside_window() {
        let mut wm = WindowManager::new(screen());
        let id = add_window(&mut wm, 10, 10, 100, 100);
        assert_eq!(wm.hit_test(50, 50), Some(id));
        assert_eq!(wm.hit_test(10, 10), Some(id));
        assert_eq!(wm.hit_test(109, 109), Some(id));
    }

    #[test]
    fn hit_test_outside_all_windows_is_none() {
        let mut wm = WindowManager::new(screen());
        add_window(&mut wm, 10, 10, 50, 50);
        assert_eq!(wm.hit_test(5, 5), None);
        assert_eq!(wm.hit_test(200, 200), None);
    }

    #[test]
    fn hit_test_overlapping_returns_topmost() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 100, 100); // z=1
        let b = add_window(&mut wm, 50, 50, 100, 100); // z=2, on top
        // In the overlap region [50,50..100,100], b should win.
        assert_eq!(wm.hit_test(60, 60), Some(b));
        // Outside b but inside a.
        assert_eq!(wm.hit_test(10, 10), Some(a));
    }

    // --- Input routing ---

    #[test]
    fn key_routes_to_focused_window() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 50, 50);
        let b = add_window(&mut wm, 10, 10, 50, 50);
        // b is focused after creation.
        let ev = DisplayInputEvent::Key {
            code: b'x',
            pressed: true,
        };
        assert_eq!(wm.route_input(&ev), Some(b));
        // Switch focus to a.
        wm.set_focus(a).unwrap();
        assert_eq!(wm.route_input(&ev), Some(a));
    }

    #[test]
    fn key_never_routes_to_unfocused() {
        let mut wm = WindowManager::new(screen());
        let a = add_window(&mut wm, 0, 0, 200, 200);
        let b = add_window(&mut wm, 0, 0, 200, 200);
        wm.set_focus(a).unwrap();
        let ev = DisplayInputEvent::Key {
            code: b'q',
            pressed: true,
        };
        let routed = wm.route_input(&ev);
        assert_eq!(routed, Some(a));
        assert_ne!(routed, Some(b));
    }

    #[test]
    fn key_routes_to_none_when_no_focus() {
        let wm = WindowManager::new(screen());
        let ev = DisplayInputEvent::Key {
            code: b'a',
            pressed: true,
        };
        assert_eq!(wm.route_input(&ev), None);
    }

    #[test]
    fn pointer_routes_by_hit_test() {
        let mut wm = WindowManager::new(screen());
        let id = add_window(&mut wm, 10, 10, 100, 100);
        let ev = DisplayInputEvent::Pointer {
            x: 50,
            y: 50,
            buttons: 0,
        };
        assert_eq!(wm.route_input(&ev), Some(id));
    }

    #[test]
    fn pointer_on_empty_desktop_is_none() {
        let mut wm = WindowManager::new(screen());
        add_window(&mut wm, 10, 10, 50, 50);
        let ev = DisplayInputEvent::Pointer {
            x: 700,
            y: 500,
            buttons: 0,
        };
        assert_eq!(wm.route_input(&ev), None);
    }

    // --- move_to clamp ---

    #[test]
    fn move_to_clamps_to_screen() {
        let mut wm = WindowManager::new(screen());
        let id = add_window(&mut wm, 0, 0, 50, 50);
        // Try to move far outside.
        wm.move_to(id, -10_000, -10_000).unwrap();
        let win = wm.window(id).unwrap();
        // Must be clamped to screen.x, screen.y.
        assert!(win.x >= 0);
        assert!(win.y >= 0);
    }
}
