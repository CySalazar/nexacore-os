//! Pointer router: pure, host-testable pointer-event resolution.
//!
//! Resolves one absolute pointer event per call against the shell's
//! z-priority ladder — menu bar, then dock panel, then window frame, then
//! window content, then the desktop wallpaper — and tracks the small bit of
//! state that must survive between events: an in-progress titlebar drag, the
//! previous button mask (to detect a press *edge* rather than "held"), and
//! the current hover target (for chrome repaint decisions). It has no
//! knowledge of the compositor or any canvas; callers supply window/dock/
//! menu-bar geometry each call and act on the returned [`PointerAction`].

use nexacore_display::geometry::Rect;

use crate::{
    frame::{self, FrameButton, FrameHit},
    menubar::{self, MENUBAR_H},
};

/// Identifies one of the six desktop apps for routing purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppId {
    /// The terminal emulator.
    Terminal,
    /// The NexaCore Helper assistant.
    Helper,
    /// The file manager.
    Files,
    /// The system monitor.
    Monitor,
    /// The settings / control-centre app.
    Settings,
    /// The System Info window (launcher-only — no dock tile).
    SystemInfo,
}

/// One window's routing geometry, supplied by the caller each event.
#[derive(Debug, Clone, Copy)]
pub struct WindowGeom {
    /// Which app the window belongs to.
    pub app: AppId,
    /// Screen rect (compositor coordinates).
    pub rect: Rect,
    /// Z value (higher = on top).
    pub z: i32,
    /// Whether the window is currently visible.
    pub visible: bool,
}

/// What the pointer is hovering, for chrome feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HoverState {
    /// Index into the dock model's tiles, when over a dock tile.
    pub dock_tile: Option<usize>,
    /// A titlebar button of a visible window.
    pub frame_button: Option<(AppId, FrameButton)>,
}

/// The router's verdict for one pointer event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerAction {
    /// Nothing to do (no press edge, no hover change).
    None,
    /// Press on a menu-bar element (consumed; inert in M3). The index mirrors
    /// [`menubar::right_icon_rects`] order; `None` = elsewhere on the bar.
    MenuBar(Option<usize>),
    /// Press on dock tile `index` of the supplied dock model.
    DockTile(usize),
    /// Press on a titlebar button of the given app's window.
    FrameButton(AppId, FrameButton),
    /// Press in a titlebar drag zone: begin dragging that window.
    /// `grab` = pointer offset from the window origin.
    BeginDrag {
        /// The app whose window is being dragged.
        app: AppId,
        /// Pointer offset from the window's left edge at press time.
        grab_x: i32,
        /// Pointer offset from the window's top edge at press time.
        grab_y: i32,
    },
    /// Press inside window content: focus it (the caller forwards the event
    /// to the app if it wants). The two `i32`s are the press position in
    /// window-relative coordinates — the same origin as the window's own
    /// render canvas (`(0,0)` = window's top-left, `y` includes the
    /// titlebar band) — so a caller can hit-test its own in-content controls
    /// without the router knowing anything about app-specific layout.
    FocusContent(AppId, i32, i32),
    /// Press on the desktop (wallpaper): clear/keep focus, nothing else.
    Desktop,
}

/// Pointer router: resolves pointer events against shell z-priority
/// (menu bar > dock > window frame > window content > desktop) and tracks
/// drag + hover state between events.
///
/// A dock-panel press that lands inside [`panel rect`](Self::on_pointer)
/// but misses every tile is still consumed by the panel: it returns
/// [`PointerAction::None`] rather than falling through to a window
/// underneath. The panel itself has no action to report in M3, but the
/// z-priority ladder still stops there — windows never receive a press that
/// visually landed on the dock.
#[derive(Debug, Default)]
pub struct PointerRouter {
    drag: Option<(AppId, i32, i32)>,
    prev_buttons: u8,
    hover: HoverState,
}

impl PointerRouter {
    /// Creates a router with no drag in progress, no buttons held, and empty
    /// hover.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current hover state (for chrome rendering).
    #[must_use]
    pub fn hover(&self) -> HoverState {
        self.hover
    }

    /// Whether a drag is in progress.
    #[must_use]
    pub fn dragging(&self) -> Option<AppId> {
        self.drag.map(|(app, ..)| app)
    }

    /// Processes one absolute pointer event. `windows` may be in any order;
    /// the router picks the topmost visible window containing the point.
    /// `dock_rects` are the dock tile rects in model order (screen coords);
    /// `screen_w` sizes the menu bar. Returns the action for a left-press
    /// edge, and separately whether hover changed (drives chrome repaints).
    #[allow(
        clippy::too_many_arguments,
        reason = "interface fixed by the task brief: one absolute pointer event plus the \
                  per-frame geometry snapshot it must be routed against"
    )]
    pub fn on_pointer(
        &mut self,
        x: i32,
        y: i32,
        buttons: u8,
        windows: &[WindowGeom],
        dock_panel: &Rect,
        dock_rects: &[Rect],
        screen_w: u32,
    ) -> (PointerAction, bool) {
        let new_hover = compute_hover(x, y, windows, dock_panel, dock_rects);
        let hover_changed = new_hover != self.hover;
        self.hover = new_hover;

        let pressed = buttons & 1 != 0;
        let was_pressed = self.prev_buttons & 1 != 0;
        self.prev_buttons = buttons;

        if !pressed {
            // Release: a drag in progress ends here, wherever the release
            // lands (even on top of chrome) — see rule 3 in the brief.
            if was_pressed {
                self.drag = None;
            }
            return (PointerAction::None, hover_changed);
        }
        if was_pressed {
            // Button already held: this is not a new press edge.
            return (PointerAction::None, hover_changed);
        }

        let action = self.press_action(x, y, windows, dock_panel, dock_rects, screen_w);
        (action, hover_changed)
    }

    /// Resolves a left-press *edge* against the shell z-priority ladder.
    /// Only called once `on_pointer` has confirmed this is a rising edge.
    fn press_action(
        &mut self,
        x: i32,
        y: i32,
        windows: &[WindowGeom],
        dock_panel: &Rect,
        dock_rects: &[Rect],
        screen_w: u32,
    ) -> PointerAction {
        #[allow(
            clippy::cast_possible_wrap,
            reason = "MENUBAR_H is a small positive pixel metric"
        )]
        if y < MENUBAR_H as i32 {
            return PointerAction::MenuBar(menu_icon_at(screen_w, x, y));
        }
        if dock_panel.contains_point(x, y) {
            // The panel consumes the press even off-tile; it never falls
            // through to a window underneath (see the struct doc comment).
            return dock_tile_at(dock_rects, x, y)
                .map_or(PointerAction::None, PointerAction::DockTile);
        }
        let Some(win) = topmost_window(windows, x, y) else {
            return PointerAction::Desktop;
        };
        let local_x = x - win.rect.x;
        let local_y = y - win.rect.y;
        match frame::hit_test(win.rect.w, local_x, local_y) {
            FrameHit::Button(b) => PointerAction::FrameButton(win.app, b),
            FrameHit::Drag => {
                self.drag = Some((win.app, local_x, local_y));
                PointerAction::BeginDrag {
                    app: win.app,
                    grab_x: local_x,
                    grab_y: local_y,
                }
            }
            FrameHit::Content => PointerAction::FocusContent(win.app, local_x, local_y),
        }
    }

    /// Drag update: while the left button is held with an active drag,
    /// returns the new window origin for the dragged app (y clamped ≥ 0).
    #[must_use]
    pub fn drag_target(&self, x: i32, y: i32) -> Option<(AppId, i32, i32)> {
        let (app, grab_x, grab_y) = self.drag?;
        if self.prev_buttons & 1 == 0 {
            return None;
        }
        Some((app, x - grab_x, (y - grab_y).max(0)))
    }
}

/// Computes the hover target for `(x, y)`, following the same z-priority
/// ladder as [`PointerRouter::press_action`]: menu bar, then dock panel
/// (stopping there even off-tile), then the topmost visible window's frame,
/// else empty.
fn compute_hover(
    x: i32,
    y: i32,
    windows: &[WindowGeom],
    dock_panel: &Rect,
    dock_rects: &[Rect],
) -> HoverState {
    #[allow(
        clippy::cast_possible_wrap,
        reason = "MENUBAR_H is a small positive pixel metric"
    )]
    if y < MENUBAR_H as i32 {
        return HoverState::default();
    }
    if dock_panel.contains_point(x, y) {
        return HoverState {
            dock_tile: dock_tile_at(dock_rects, x, y),
            frame_button: None,
        };
    }
    if let Some(win) = topmost_window(windows, x, y) {
        let local_x = x - win.rect.x;
        let local_y = y - win.rect.y;
        if let FrameHit::Button(b) = frame::hit_test(win.rect.w, local_x, local_y) {
            return HoverState {
                dock_tile: None,
                frame_button: Some((win.app, b)),
            };
        }
    }
    HoverState::default()
}

/// The index of the dock tile rect containing `(x, y)`, if any.
fn dock_tile_at(dock_rects: &[Rect], x: i32, y: i32) -> Option<usize> {
    dock_rects.iter().position(|r| r.contains_point(x, y))
}

/// The index (in [`menubar::right_icon_rects`] order) of the right-side menu
/// bar icon containing `(x, y)`, if any.
fn menu_icon_at(screen_w: u32, x: i32, y: i32) -> Option<usize> {
    menubar::right_icon_rects(screen_w)
        .iter()
        .position(|r| r.contains_point(x, y))
}

/// The topmost (highest `z`) visible window containing `(x, y)`, if any.
fn topmost_window(windows: &[WindowGeom], x: i32, y: i32) -> Option<WindowGeom> {
    windows
        .iter()
        .filter(|w| w.visible && w.rect.contains_point(x, y))
        .max_by_key(|w| w.z)
        .copied()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::cast_possible_wrap,
    reason = "test literals and lookups over small, known-shape fixtures; halving small \
              positive pixel metrics to find a rect centre truncates harmlessly"
)]
mod tests {
    use super::*;
    use crate::dock::{self, DockModel};

    /// A titlebar-width window matching `frame.rs`'s own geometry fixture, so
    /// the exact pixel offsets in `frame::geometry_tests` (drag at
    /// window-local (20, 20), content at window-local (20, 42)) apply here
    /// unchanged.
    const WIN_W: u32 = 486;
    const WIN_H: u32 = 300;
    const SCREEN_W: u32 = 1280;
    const SCREEN_H: u32 = 800;

    fn window(app: AppId, x: i32, y: i32, z: i32, visible: bool) -> WindowGeom {
        WindowGeom {
            app,
            rect: Rect {
                x,
                y,
                w: WIN_W,
                h: WIN_H,
            },
            z,
            visible,
        }
    }

    fn dock_fixture() -> (Rect, alloc::vec::Vec<Rect>) {
        let model = DockModel::standard(true, true, true, true, true);
        let panel = dock::panel_rect(SCREEN_H);
        let rects = dock::tile_rects(SCREEN_H, &model);
        (panel, rects)
    }

    fn empty_windows() -> [WindowGeom; 0] {
        []
    }

    // --- Priority order ----------------------------------------------------

    #[test]
    fn menu_bar_wins_over_a_window_beneath_it() {
        let mut r = PointerRouter::new();
        let windows = [window(AppId::Terminal, 0, 0, 0, true)];
        let (panel, rects) = dock_fixture();
        let (action, _) = r.on_pointer(50, 20, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::MenuBar(None));
    }

    #[test]
    fn dock_panel_wins_over_a_window_overlapping_it() {
        let mut r = PointerRouter::new();
        // Window (0,0,486×300) under the dock; the Logo tile (rects[0]) sits at
        // y≈230..278 on an 800px screen (inside the window) and genuinely collides.
        let windows = [window(AppId::Files, 0, 0, 0, true)];
        let (panel, rects) = dock_fixture();
        let tile = rects[0]; // Logo tile, not rects[2] which sits below window
        let (px, py) = (tile.x + 5, tile.y + 5);
        let (action, _) = r.on_pointer(px, py, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::DockTile(0));
        // If dock-priority check were missing, the point would hit the window
        // and return FocusContent instead; the assertion proves the dock wins.
    }

    #[test]
    fn dock_panel_press_missing_every_tile_is_consumed_not_passed_through() {
        let mut r = PointerRouter::new();
        // Full-screen window under the dock, so a "None" result here can only
        // be explained by panel consumption, not simply "nothing was there".
        let windows = [window(AppId::Files, 0, 0, 0, true)];
        let (panel, rects) = dock_fixture();
        // A point inside the panel's padding, above the first tile.
        let (px, py) = (panel.x + 5, panel.y + 2);
        assert!(!rects.iter().any(|t| t.contains_point(px, py)));
        let (action, _) = r.on_pointer(px, py, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::None);
    }

    #[test]
    fn topmost_of_two_overlapping_windows_wins() {
        let mut r = PointerRouter::new();
        let low = window(AppId::Files, 100, 100, 0, true);
        let high = window(AppId::Monitor, 100, 100, 5, true);
        let windows = [low, high];
        let (panel, rects) = dock_fixture();
        // Content point (below the shared titlebar) inside both rects.
        // Window origin (100,100); press at (150,200) → window-local (50,100).
        let (action, _) = r.on_pointer(150, 200, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::FocusContent(AppId::Monitor, 50, 100));
    }

    #[test]
    fn hidden_windows_are_skipped() {
        let mut r = PointerRouter::new();
        let windows = [window(AppId::Terminal, 100, 100, 0, false)];
        let (panel, rects) = dock_fixture();
        let (action, _) = r.on_pointer(150, 200, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::Desktop);
    }

    // --- FrameHit mapping (real frame geometry) ----------------------------

    #[test]
    fn frame_button_press_maps_to_frame_button_action() {
        let mut r = PointerRouter::new();
        let win = window(AppId::Terminal, 100, 100, 0, true);
        let windows = [win];
        let (panel, rects) = dock_fixture();
        let close = frame::button_rect(WIN_W, FrameButton::Close);
        let (px, py) = (
            100 + close.x + close.w as i32 / 2,
            100 + close.y + close.h as i32 / 2,
        );
        let (action, _) = r.on_pointer(px, py, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(
            action,
            PointerAction::FrameButton(AppId::Terminal, FrameButton::Close)
        );

        let min = frame::button_rect(WIN_W, FrameButton::Minimize);
        let (px, py) = (
            100 + min.x + min.w as i32 / 2,
            100 + min.y + min.h as i32 / 2,
        );
        let (action, _) = r.on_pointer(px, py, 0, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::None, "release edge, no press");
        let (action, _) = r.on_pointer(px, py, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(
            action,
            PointerAction::FrameButton(AppId::Terminal, FrameButton::Minimize)
        );
    }

    #[test]
    fn drag_zone_press_begins_a_drag() {
        let mut r = PointerRouter::new();
        let win = window(AppId::Monitor, 100, 100, 0, true);
        let windows = [win];
        let (panel, rects) = dock_fixture();
        // window-local (20, 20) is `Drag` per frame::geometry_tests.
        let (action, _) = r.on_pointer(120, 120, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(
            action,
            PointerAction::BeginDrag {
                app: AppId::Monitor,
                grab_x: 20,
                grab_y: 20,
            }
        );
        assert_eq!(r.dragging(), Some(AppId::Monitor));
    }

    #[test]
    fn content_press_focuses_content() {
        let mut r = PointerRouter::new();
        let win = window(AppId::Files, 100, 100, 0, true);
        let windows = [win];
        let (panel, rects) = dock_fixture();
        // window-local (20, 42) is `Content` per frame::geometry_tests.
        let (action, _) = r.on_pointer(120, 142, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::FocusContent(AppId::Files, 20, 42));
    }

    #[test]
    fn press_outside_any_window_is_desktop() {
        let mut r = PointerRouter::new();
        let windows = empty_windows();
        let (panel, rects) = dock_fixture();
        let (action, _) = r.on_pointer(900, 500, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::Desktop);
    }

    #[test]
    fn menu_bar_icon_index_matches_right_icon_rects() {
        let mut r = PointerRouter::new();
        let windows = empty_windows();
        let (panel, rects) = dock_fixture();
        let icons = menubar::right_icon_rects(SCREEN_W);
        let mesh = icons[0];
        let (px, py) = (mesh.x + 2, mesh.y + 2);
        let (action, _) = r.on_pointer(px, py, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::MenuBar(Some(0)));
    }

    // --- Drag begin / target / end cycle, with y-clamp ---------------------

    #[test]
    fn drag_begin_target_end_cycle_clamps_y_at_zero() {
        let mut r = PointerRouter::new();
        let win = window(AppId::Helper, 100, 100, 0, true);
        let windows = [win];
        let (panel, rects) = dock_fixture();

        // Begin: window-local (20, 20) => grab offset (20, 20).
        let (action, _) = r.on_pointer(120, 120, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(
            action,
            PointerAction::BeginDrag {
                app: AppId::Helper,
                grab_x: 20,
                grab_y: 20,
            }
        );

        // Hold + move: target follows pointer minus the grab offset.
        let (action, _) = r.on_pointer(200, 180, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::None, "held, not a new press");
        assert_eq!(r.drag_target(200, 180), Some((AppId::Helper, 180, 160)));

        // Move so the unclamped y would go negative: clamp to 0.
        assert_eq!(r.drag_target(200, 5), Some((AppId::Helper, 180, 0)));

        // Release: drag state clears even though the release point lands on
        // chrome (the frame's close button) rather than empty desktop.
        let close = frame::button_rect(WIN_W, FrameButton::Close);
        let (rx, ry) = (100 + close.x + 1, 100 + close.y + 1);
        let (action, _) = r.on_pointer(rx, ry, 0, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::None);
        assert_eq!(r.dragging(), None);
        assert_eq!(r.drag_target(200, 180), None);
    }

    // --- Hover transitions ---------------------------------------------------

    #[test]
    fn hover_transitions_none_to_dock_to_frame_button_to_none() {
        let mut r = PointerRouter::new();
        let win = window(AppId::Settings, 100, 100, 0, true);
        let windows = [win];
        let (panel, rects) = dock_fixture();

        // none -> dock tile 1
        let tile = rects[1];
        let (_, changed) = r.on_pointer(
            tile.x + 5,
            tile.y + 5,
            0,
            &windows,
            &panel,
            &rects,
            SCREEN_W,
        );
        assert!(changed);
        assert_eq!(
            r.hover(),
            HoverState {
                dock_tile: Some(1),
                frame_button: None
            }
        );

        // same tile again -> unchanged
        let (_, changed) = r.on_pointer(
            tile.x + 6,
            tile.y + 6,
            0,
            &windows,
            &panel,
            &rects,
            SCREEN_W,
        );
        assert!(!changed, "still over the same tile");

        // dock tile -> frame button
        let close = frame::button_rect(WIN_W, FrameButton::Close);
        let (px, py) = (
            100 + close.x + close.w as i32 / 2,
            100 + close.y + close.h as i32 / 2,
        );
        let (_, changed) = r.on_pointer(px, py, 0, &windows, &panel, &rects, SCREEN_W);
        assert!(changed);
        assert_eq!(
            r.hover(),
            HoverState {
                dock_tile: None,
                frame_button: Some((AppId::Settings, FrameButton::Close)),
            }
        );

        // frame button -> none (desktop, far from everything)
        let (_, changed) = r.on_pointer(900, 500, 0, &windows, &panel, &rects, SCREEN_W);
        assert!(changed);
        assert_eq!(r.hover(), HoverState::default());
    }

    #[test]
    fn hovering_the_titlebar_drag_zone_or_content_reports_no_frame_button() {
        let mut r = PointerRouter::new();
        let win = window(AppId::Terminal, 100, 100, 0, true);
        let windows = [win];
        let (panel, rects) = dock_fixture();
        // window-local (20, 20): Drag zone, not a button.
        let (_, _) = r.on_pointer(120, 120, 0, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(r.hover(), HoverState::default());
        // window-local (20, 42): Content, not a button.
        let (_, _) = r.on_pointer(120, 142, 0, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(r.hover(), HoverState::default());
    }

    #[test]
    fn occluded_frame_button_does_not_hover() {
        let mut r = PointerRouter::new();
        // Two overlapping windows: the lower window's close button is spatially
        // under the upper window's content area. When we hover at the lower
        // window's button position, the upper window occludes it — the button
        // must not report as hovering.
        let low = window(AppId::Files, 100, 200, 0, true);
        let close_btn = frame::button_rect(WIN_W, FrameButton::Close);
        // Lower window's close button at screen coords (100 + close_btn.x, 200 + close_btn.y).
        let btn_screen_x = 100 + close_btn.x;
        let btn_screen_y = 200 + close_btn.y;

        // Upper window positioned to cover the lower window's button area.
        // Its content region starts at (400, 100 + 42) = (400, 142) and extends
        // to (400 + 486, 100 + 300) = (886, 400).
        // The lower window's button is at screen (btn_screen_x, btn_screen_y).
        // Verify the button is inside the upper window's content area.
        let high = window(AppId::Monitor, 400, 100, 1, true);
        let windows = [low, high];
        let (panel, rects) = dock_fixture();

        // Pointer at the lower window's close button position (no button press).
        let (_, _) = r.on_pointer(
            btn_screen_x,
            btn_screen_y,
            0,
            &windows,
            &panel,
            &rects,
            SCREEN_W,
        );

        // The upper window's content occludes the lower window's button:
        // hover().frame_button must be None (or could belong to upper window,
        // but upper's content doesn't have buttons). The key is that the lower
        // window's button must NOT be reported.
        let hover = r.hover();
        assert_eq!(hover.frame_button, None, "occluded button must not hover");
    }

    // --- Press-edge single-fire ---------------------------------------------

    #[test]
    fn press_action_fires_once_while_button_stays_held() {
        let mut r = PointerRouter::new();
        let windows = empty_windows();
        let (panel, rects) = dock_fixture();

        let (action, _) = r.on_pointer(900, 500, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::Desktop, "rising edge fires");

        let (action, _) = r.on_pointer(900, 500, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::None, "still held: no re-fire");

        let (action, _) = r.on_pointer(900, 500, 0, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(action, PointerAction::None, "release produces no action");

        let (action, _) = r.on_pointer(900, 500, 1, &windows, &panel, &rects, SCREEN_W);
        assert_eq!(
            action,
            PointerAction::Desktop,
            "new press after release fires again"
        );
    }
}
