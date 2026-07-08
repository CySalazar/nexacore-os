//! Window-manager polish: snap, tiling, workspaces, switcher, overview (WS7-12).
//!
//! The base [`WindowManager`](crate::wm::WindowManager) (WS7-01) creates, moves,
//! stacks and focuses windows. Daily use wants more: edge **snapping** and
//! half/quarter **tiling** with drop zones, virtual-desktop **workspaces**,
//! an Alt-Tab **app switcher**, and an Exposé-style **overview** — all with
//! animations driven by the compositor's vsync.
//!
//! Every construct here is pure geometry or a small state machine over value
//! types, so it is fully host-tested. The animations use
//! [`animation::SpringState`](crate::animation::SpringState) and are stepped
//! once per composited frame with [`vsync_dt_seconds`]; wiring them to the live
//! present loop, and the the test VM fluid-animation check, is WS7-12.8 (rig).

#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::integer_division
)]

use alloc::{collections::BTreeMap, vec::Vec};

use crate::{
    animation::{Spring, SpringState},
    geometry::Rect,
    surface::WindowId,
};

// -----------------------------------------------------------------------------
// WS7-12.1 — edge snapping
// -----------------------------------------------------------------------------

/// Snap a window to the screen edges it is within `threshold` pixels of.
///
/// Each axis is handled independently: a left/right edge closer than
/// `threshold` to the corresponding screen edge is aligned to it (keeping the
/// window size); ditto top/bottom. If a window is close to both left and right
/// (a window wider than the screen minus slack), the left edge wins.
#[must_use]
pub fn snap_to_edges(window: Rect, screen: Rect, threshold: u32) -> Rect {
    let t = i64::from(threshold);
    let mut x = window.x;
    let mut y = window.y;

    if (i64::from(window.x) - i64::from(screen.x)).abs() <= t {
        x = screen.x;
    } else if (window.right() - screen.right()).abs() <= t {
        x = i32::try_from(screen.right() - i64::from(window.w)).unwrap_or(window.x);
    }

    if (i64::from(window.y) - i64::from(screen.y)).abs() <= t {
        y = screen.y;
    } else if (window.bottom() - screen.bottom()).abs() <= t {
        y = i32::try_from(screen.bottom() - i64::from(window.h)).unwrap_or(window.y);
    }

    Rect {
        x,
        y,
        w: window.w,
        h: window.h,
    }
}

// -----------------------------------------------------------------------------
// WS7-12.2 — half / quarter tiling with drop zones
// -----------------------------------------------------------------------------

/// A tiling target: which region of the screen a dropped window fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileZone {
    /// Left half.
    LeftHalf,
    /// Right half.
    RightHalf,
    /// Top half.
    TopHalf,
    /// Bottom half.
    BottomHalf,
    /// Top-left quarter.
    TopLeft,
    /// Top-right quarter.
    TopRight,
    /// Bottom-left quarter.
    BottomLeft,
    /// Bottom-right quarter.
    BottomRight,
    /// Full screen.
    Maximize,
}

impl TileZone {
    /// The screen rectangle this zone fills.
    #[must_use]
    pub fn rect(self, screen: Rect) -> Rect {
        let half_w = screen.w / 2;
        let half_h = screen.h / 2;
        let mid_x = screen.x + half_w as i32;
        let mid_y = screen.y + half_h as i32;
        // Right/bottom halves absorb the odd pixel so two halves tile exactly.
        let rem_w = screen.w - half_w;
        let rem_h = screen.h - half_h;
        match self {
            Self::LeftHalf => Rect {
                x: screen.x,
                y: screen.y,
                w: half_w,
                h: screen.h,
            },
            Self::RightHalf => Rect {
                x: mid_x,
                y: screen.y,
                w: rem_w,
                h: screen.h,
            },
            Self::TopHalf => Rect {
                x: screen.x,
                y: screen.y,
                w: screen.w,
                h: half_h,
            },
            Self::BottomHalf => Rect {
                x: screen.x,
                y: mid_y,
                w: screen.w,
                h: rem_h,
            },
            Self::TopLeft => Rect {
                x: screen.x,
                y: screen.y,
                w: half_w,
                h: half_h,
            },
            Self::TopRight => Rect {
                x: mid_x,
                y: screen.y,
                w: rem_w,
                h: half_h,
            },
            Self::BottomLeft => Rect {
                x: screen.x,
                y: mid_y,
                w: half_w,
                h: rem_h,
            },
            Self::BottomRight => Rect {
                x: mid_x,
                y: mid_y,
                w: rem_w,
                h: rem_h,
            },
            Self::Maximize => screen,
        }
    }
}

/// Resolve a drag-drop point to a tiling zone, or `None` if it is in the
/// screen's interior (a free-floating drop).
///
/// `margin` is the hot-zone thickness at each edge. Corners (within `margin` of
/// two edges) tile to a quarter; a drop in the top-edge centre maximizes; a
/// drop near one edge tiles to that half.
#[must_use]
pub fn zone_for_drop(px: i32, py: i32, screen: Rect, margin: u32) -> Option<TileZone> {
    if !screen.contains_point(px, py) {
        return None;
    }
    let m = i64::from(margin);
    let near_left = i64::from(px) - i64::from(screen.x) < m;
    let near_right = screen.right() - i64::from(px) <= m;
    let near_top = i64::from(py) - i64::from(screen.y) < m;
    let near_bottom = screen.bottom() - i64::from(py) <= m;

    match (near_left, near_right, near_top, near_bottom) {
        (true, _, true, _) => Some(TileZone::TopLeft),
        (_, true, true, _) => Some(TileZone::TopRight),
        (true, _, _, true) => Some(TileZone::BottomLeft),
        (_, true, _, true) => Some(TileZone::BottomRight),
        (true, _, _, _) => Some(TileZone::LeftHalf),
        (_, true, _, _) => Some(TileZone::RightHalf),
        (_, _, true, _) => Some(TileZone::Maximize),
        (_, _, _, true) => Some(TileZone::BottomHalf),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// WS7-12.3 — workspaces (virtual desktops)
// -----------------------------------------------------------------------------

/// A set of virtual desktops with per-window assignment.
#[derive(Debug, Clone)]
pub struct WorkspaceSet {
    count: usize,
    active: usize,
    assignment: BTreeMap<WindowId, usize>,
}

impl WorkspaceSet {
    /// A workspace set with `count` desktops (clamped to ≥ 1), starting on
    /// workspace 0.
    #[must_use]
    pub fn new(count: usize) -> Self {
        Self {
            count: count.max(1),
            active: 0,
            assignment: BTreeMap::new(),
        }
    }

    /// Number of workspaces.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// The active workspace index.
    #[must_use]
    pub fn active(&self) -> usize {
        self.active
    }

    /// Assign a window to a workspace. Returns `false` if `ws` is out of range.
    pub fn assign(&mut self, id: WindowId, ws: usize) -> bool {
        if ws >= self.count {
            return false;
        }
        self.assignment.insert(id, ws);
        true
    }

    /// Remove a window's assignment (e.g. on destroy).
    pub fn remove(&mut self, id: WindowId) {
        self.assignment.remove(&id);
    }

    /// The workspace a window is on (defaults to 0 if unassigned).
    #[must_use]
    pub fn workspace_of(&self, id: WindowId) -> usize {
        self.assignment.get(&id).copied().unwrap_or(0)
    }

    /// The windows assigned to `ws`, in id order.
    #[must_use]
    pub fn windows_on(&self, ws: usize) -> Vec<WindowId> {
        self.assignment
            .iter()
            .filter(|(_, w)| **w == ws)
            .map(|(&id, _)| id)
            .collect()
    }

    /// The windows on the active workspace.
    #[must_use]
    pub fn active_windows(&self) -> Vec<WindowId> {
        self.windows_on(self.active)
    }

    /// Switch the active workspace. Returns `false` if `ws` is out of range or
    /// already active.
    pub fn switch(&mut self, ws: usize) -> bool {
        if ws >= self.count || ws == self.active {
            return false;
        }
        self.active = ws;
        true
    }
}

// -----------------------------------------------------------------------------
// WS7-12.4 / .7 — workspace transition animation (vsync-driven)
// -----------------------------------------------------------------------------

/// Direction a workspace switch slides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlideDirection {
    /// New workspace enters from the right (moving to a higher index).
    Left,
    /// New workspace enters from the left (moving to a lower index).
    Right,
}

/// A critically-damped slide animation for a workspace switch.
///
/// Progress runs `0.0 → 1.0`; multiply by the screen width to get the scroll
/// offset. Step it once per composited frame with [`vsync_dt_seconds`].
#[derive(Debug, Clone)]
pub struct WorkspaceTransition {
    progress: SpringState,
    spring: Spring,
    direction: SlideDirection,
    active: bool,
}

impl Default for WorkspaceTransition {
    fn default() -> Self {
        Self {
            progress: SpringState::at(1.0),
            spring: Spring::critically_damped(180.0, 1.0),
            direction: SlideDirection::Left,
            active: false,
        }
    }
}

impl WorkspaceTransition {
    /// An idle transition (settled, no animation in flight).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin a slide in `direction`. Progress resets to 0 and targets 1.
    pub fn begin(&mut self, direction: SlideDirection) {
        self.direction = direction;
        self.progress = SpringState::at(0.0);
        self.progress.set_target(1.0);
        self.active = true;
    }

    /// Advance the animation by `dt` seconds (one vsync). Returns whether the
    /// transition is still running.
    pub fn tick(&mut self, dt: f32) -> bool {
        if !self.active {
            return false;
        }
        self.progress.step(self.spring, dt);
        if self.progress.settled(0.001, 0.001) {
            self.progress.snap_to_target();
            self.active = false;
        }
        self.active
    }

    /// Current progress in `0.0..=1.0`.
    #[must_use]
    pub fn progress(&self) -> f32 {
        self.progress.value
    }

    /// The horizontal scroll offset in pixels for a screen `width`.
    #[must_use]
    pub fn offset_px(&self, width: u32) -> f32 {
        let p = self.progress();
        let d = match self.direction {
            SlideDirection::Left => 1.0 - p,
            SlideDirection::Right => p - 1.0,
        };
        d * width as f32
    }

    /// Whether a slide is in flight.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }
}

/// The frame delta (seconds) for a given refresh rate — the `dt` WM animations
/// step with, so every animation is locked to the compositor's vsync (WS7-12.7).
#[must_use]
pub fn vsync_dt_seconds(refresh_hz: u16) -> f32 {
    if refresh_hz == 0 {
        return 0.0;
    }
    1.0 / f32::from(refresh_hz)
}

// -----------------------------------------------------------------------------
// WS7-12.5 — Alt-Tab app switcher (MRU)
// -----------------------------------------------------------------------------

/// An overlay app-switcher cycling windows in most-recently-used order.
#[derive(Debug, Clone, Default)]
pub struct AppSwitcher {
    /// Most-recently-used first.
    order: Vec<WindowId>,
    open: bool,
    index: usize,
}

impl AppSwitcher {
    /// An empty, closed switcher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Promote a window to most-recently-used (call on focus).
    pub fn touch(&mut self, id: WindowId) {
        self.order.retain(|&w| w != id);
        self.order.insert(0, id);
    }

    /// Drop a window (e.g. on destroy).
    pub fn remove(&mut self, id: WindowId) {
        self.order.retain(|&w| w != id);
        if self.index >= self.order.len() {
            self.index = 0;
        }
    }

    /// The MRU order (front = most recent).
    #[must_use]
    pub fn order(&self) -> &[WindowId] {
        &self.order
    }

    /// Whether the overlay is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Open the overlay. Selection starts on the previous window (index 1) so a
    /// tap-and-release Alt-Tab flips to the last-used window.
    pub fn open(&mut self) {
        self.open = true;
        self.index = usize::from(self.order.len() > 1);
    }

    /// Advance selection to the next (older) window, wrapping.
    pub fn next(&mut self) {
        if self.open && !self.order.is_empty() {
            self.index = (self.index + 1) % self.order.len();
        }
    }

    /// Move selection to the previous (newer) window, wrapping.
    pub fn prev(&mut self) {
        if self.open && !self.order.is_empty() {
            self.index = (self.index + self.order.len() - 1) % self.order.len();
        }
    }

    /// The currently highlighted window.
    #[must_use]
    pub fn selected(&self) -> Option<WindowId> {
        self.order.get(self.index).copied()
    }

    /// Close the overlay and commit the selection: the chosen window becomes
    /// most-recently-used and is returned.
    pub fn commit(&mut self) -> Option<WindowId> {
        self.open = false;
        let chosen = self.selected();
        if let Some(id) = chosen {
            self.touch(id);
            self.index = 0;
        }
        chosen
    }

    /// Close the overlay without changing the MRU order.
    pub fn cancel(&mut self) {
        self.open = false;
        self.index = 0;
    }
}

// -----------------------------------------------------------------------------
// WS7-12.6 — Exposé / Mission-Control grid overview
// -----------------------------------------------------------------------------

/// The number of columns for an `n`-cell grid: the smallest `c` with `c² ≥ n`.
#[must_use]
fn columns_for(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut c = 1usize;
    while c * c < n {
        c += 1;
    }
    c
}

/// Lay out `count` window thumbnails in a centred, gap-separated grid filling
/// `screen` (Exposé/Mission-Control). Returns one rectangle per window in
/// row-major order.
#[must_use]
pub fn grid_layout(count: usize, screen: Rect, gap: u32) -> Vec<Rect> {
    if count == 0 {
        return Vec::new();
    }
    let cols = columns_for(count);
    let rows = count.div_ceil(cols);
    let gap_px = i64::from(gap);

    let cell_w = ((i64::from(screen.w) - (cols as i64 + 1) * gap_px) / cols as i64).max(1);
    let cell_h = ((i64::from(screen.h) - (rows as i64 + 1) * gap_px) / rows as i64).max(1);
    let cw = cell_w as u32;
    let ch = cell_h as u32;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let row = (i / cols) as i64;
        let col = (i % cols) as i64;
        let cell_x = i64::from(screen.x) + gap_px + col * (cell_w + gap_px);
        let cell_y = i64::from(screen.y) + gap_px + row * (cell_h + gap_px);
        out.push(Rect {
            x: i32::try_from(cell_x).unwrap_or(screen.x),
            y: i32::try_from(cell_y).unwrap_or(screen.y),
            w: cw,
            h: ch,
        });
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp
)]
mod tests {
    use alloc::vec;

    use super::*;

    const SCREEN: Rect = Rect {
        x: 0,
        y: 0,
        w: 1920,
        h: 1080,
    };

    #[test]
    fn snap_aligns_near_edges() {
        // 8 px from the left, 5 px from the top → both snap.
        let w = Rect {
            x: 8,
            y: 5,
            w: 400,
            h: 300,
        };
        let snapped = snap_to_edges(w, SCREEN, 10);
        assert_eq!(
            snapped,
            Rect {
                x: 0,
                y: 0,
                w: 400,
                h: 300
            }
        );
    }

    #[test]
    fn snap_aligns_right_edge() {
        // right edge at 1915, 5 px from screen right (1920) → snap right.
        let w = Rect {
            x: 1515,
            y: 100,
            w: 400,
            h: 300,
        };
        let snapped = snap_to_edges(w, SCREEN, 10);
        assert_eq!(snapped.x, 1520); // 1920 - 400
    }

    #[test]
    fn snap_leaves_interior_windows() {
        let w = Rect {
            x: 500,
            y: 400,
            w: 400,
            h: 300,
        };
        assert_eq!(snap_to_edges(w, SCREEN, 10), w);
    }

    #[test]
    fn tile_halves_tile_exactly() {
        let l = TileZone::LeftHalf.rect(SCREEN);
        let r = TileZone::RightHalf.rect(SCREEN);
        assert_eq!(
            l,
            Rect {
                x: 0,
                y: 0,
                w: 960,
                h: 1080
            }
        );
        assert_eq!(
            r,
            Rect {
                x: 960,
                y: 0,
                w: 960,
                h: 1080
            }
        );
        // No gap, no overlap: they cover the full width.
        assert_eq!(l.w + r.w, SCREEN.w);
    }

    #[test]
    fn drop_zones_map_corners_and_edges() {
        assert_eq!(zone_for_drop(5, 5, SCREEN, 20), Some(TileZone::TopLeft));
        assert_eq!(
            zone_for_drop(1915, 1075, SCREEN, 20),
            Some(TileZone::BottomRight)
        );
        assert_eq!(zone_for_drop(5, 500, SCREEN, 20), Some(TileZone::LeftHalf));
        assert_eq!(zone_for_drop(960, 5, SCREEN, 20), Some(TileZone::Maximize));
        assert_eq!(zone_for_drop(960, 540, SCREEN, 20), None); // interior
    }

    #[test]
    fn workspaces_assign_and_switch() {
        let mut ws = WorkspaceSet::new(4);
        assert!(ws.assign(WindowId(1), 0));
        assert!(ws.assign(WindowId(2), 2));
        assert!(!ws.assign(WindowId(3), 9)); // out of range
        assert_eq!(ws.windows_on(0), vec![WindowId(1)]);
        assert_eq!(ws.active_windows(), vec![WindowId(1)]);
        assert!(ws.switch(2));
        assert_eq!(ws.active(), 2);
        assert_eq!(ws.active_windows(), vec![WindowId(2)]);
        assert!(!ws.switch(2)); // already active
    }

    #[test]
    fn transition_settles_under_vsync() {
        let mut t = WorkspaceTransition::new();
        t.begin(SlideDirection::Left);
        assert!(t.is_active());
        let dt = vsync_dt_seconds(60);
        let mut frames = 0;
        while t.tick(dt) && frames < 1000 {
            frames += 1;
        }
        assert!(!t.is_active());
        assert!((t.progress() - 1.0).abs() < 0.01);
        assert!((t.offset_px(1920)).abs() < 1.0);
        assert!(frames > 0 && frames < 1000);
    }

    #[test]
    fn vsync_dt_matches_refresh() {
        assert!((vsync_dt_seconds(60) - 1.0 / 60.0).abs() < 1e-6);
        assert_eq!(vsync_dt_seconds(0), 0.0);
    }

    #[test]
    fn switcher_alt_tab_flips_to_last_used() {
        let mut s = AppSwitcher::new();
        s.touch(WindowId(1));
        s.touch(WindowId(2));
        s.touch(WindowId(3)); // MRU: [3, 2, 1]
        s.open();
        assert_eq!(s.selected(), Some(WindowId(2))); // previous window
        let committed = s.commit();
        assert_eq!(committed, Some(WindowId(2)));
        assert_eq!(s.order(), &[WindowId(2), WindowId(3), WindowId(1)]);
    }

    #[test]
    fn switcher_cycles_and_wraps() {
        let mut s = AppSwitcher::new();
        s.touch(WindowId(1));
        s.touch(WindowId(2));
        s.open(); // MRU [2,1], index 1 → WindowId(1)
        s.next(); // wraps to index 0 → WindowId(2)
        assert_eq!(s.selected(), Some(WindowId(2)));
        s.prev(); // back to index 1
        assert_eq!(s.selected(), Some(WindowId(1)));
    }

    #[test]
    fn grid_layout_is_gap_separated_and_ordered() {
        let rects = grid_layout(4, SCREEN, 20);
        assert_eq!(rects.len(), 4);
        // 4 cells → 2x2 grid.
        assert_eq!(rects[0].x, 20);
        assert_eq!(rects[0].y, 20);
        // Second cell is to the right of the first with a gap.
        assert!(rects[1].x > rects[0].x + rects[0].w as i32);
        // Third cell starts a new row.
        assert!(rects[2].y > rects[0].y + rects[0].h as i32);
    }

    #[test]
    fn grid_layout_empty_is_empty() {
        assert!(grid_layout(0, SCREEN, 20).is_empty());
    }
}
