//! Shell window-state machine: running/minimized/maximized bookkeeping and
//! focus, decoupled from the compositor (the caller mirrors changes into
//! `nexacore-display` via `move_window`/`set_focus`/damage).

use alloc::vec::Vec;

use nexacore_display::geometry::Rect;

/// Maximized-window margins and floors (mockup `toggleMax`).
const MAX_X: i32 = 90;
const MAX_Y: i32 = 44;
const MAX_W_MARGIN: u32 = 104;
const MAX_H_MARGIN: u32 = 62;
const MAX_W_FLOOR: u32 = 560;
const MAX_H_FLOOR: u32 = 360;

/// One window's shell-visible state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinState {
    /// Current screen rect.
    pub rect: Rect,
    /// Pre-maximize rect; `Some` while maximized.
    pub restore: Option<Rect>,
    /// Whether the app is running (window exists on screen or in the dock).
    pub running: bool,
    /// Whether the window is minimized (hidden but running).
    pub minimized: bool,
}

/// Window-state registry keyed by an app identifier `K`.
#[derive(Debug, Default)]
pub struct ShellWm<K: Copy + Eq> {
    entries: Vec<(K, WinState)>,
    focused: Option<K>,
}

impl<K: Copy + Eq> ShellWm<K> {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            focused: None,
        }
    }

    /// Registers a window; the first `running` insert takes focus.
    pub fn insert(&mut self, key: K, rect: Rect, running: bool) {
        self.entries.push((
            key,
            WinState {
                rect,
                restore: None,
                running,
                minimized: false,
            },
        ));
        if running && self.focused.is_none() {
            self.focused = Some(key);
        }
    }

    fn get_mut(&mut self, key: K) -> Option<&mut WinState> {
        self.entries
            .iter_mut()
            .find(|(k, _)| *k == key)
            .map(|(_, s)| s)
    }

    /// The state of `key`, if registered.
    #[must_use]
    pub fn state(&self, key: K) -> Option<&WinState> {
        self.entries.iter().find(|(k, _)| *k == key).map(|(_, s)| s)
    }

    /// `running && !minimized`.
    #[must_use]
    pub fn is_visible(&self, key: K) -> bool {
        self.state(key).is_some_and(|s| s.running && !s.minimized)
    }

    /// The focused window, if any is visible.
    #[must_use]
    pub fn focused(&self) -> Option<K> {
        self.focused
    }

    /// Focuses `key` if it is visible.
    pub fn focus(&mut self, key: K) {
        if self.is_visible(key) {
            self.focused = Some(key);
        }
    }

    /// Opens (or un-minimizes) and focuses `key`.
    pub fn open(&mut self, key: K) {
        if let Some(s) = self.get_mut(key) {
            s.running = true;
            s.minimized = false;
            self.focused = Some(key);
        }
    }

    /// Closes `key` and refocuses the first remaining visible window.
    pub fn close(&mut self, key: K) {
        if let Some(s) = self.get_mut(key) {
            s.running = false;
            s.restore = None;
        }
        self.refocus_from(key);
    }

    /// Minimizes `key` and refocuses the first remaining visible window.
    pub fn minimize(&mut self, key: K) {
        if let Some(s) = self.get_mut(key) {
            s.minimized = true;
        }
        self.refocus_from(key);
    }

    fn refocus_from(&mut self, key: K) {
        if self.focused == Some(key) {
            self.focused = self
                .entries
                .iter()
                .find(|(k, s)| *k != key && s.running && !s.minimized)
                .map(|(k, _)| *k);
        }
    }

    /// Toggles maximize with the mockup's margins/floors, saving/restoring
    /// the previous rect.
    pub fn toggle_maximize(&mut self, key: K, screen_w: u32, screen_h: u32) {
        if let Some(s) = self.get_mut(key) {
            if let Some(prev) = s.restore.take() {
                s.rect = prev;
            } else {
                s.restore = Some(s.rect);
                s.rect = Rect {
                    x: MAX_X,
                    y: MAX_Y,
                    w: screen_w.saturating_sub(MAX_W_MARGIN).max(MAX_W_FLOOR),
                    h: screen_h.saturating_sub(MAX_H_MARGIN).max(MAX_H_FLOOR),
                };
            }
        }
        self.focus(key);
    }

    /// Moves `key`'s window (drag); y is clamped to ≥ 0 as in the mockup.
    pub fn set_rect(&mut self, key: K, x: i32, y: i32) {
        if let Some(s) = self.get_mut(key) {
            s.rect.x = x;
            s.rect.y = y.max(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use nexacore_display::geometry::Rect;

    use super::ShellWm;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum App {
        Term,
        Files,
    }

    fn wm() -> ShellWm<App> {
        let mut wm = ShellWm::new();
        wm.insert(
            App::Term,
            Rect {
                x: 452,
                y: 112,
                w: 486,
                h: 398,
            },
            true,
        );
        wm.insert(
            App::Files,
            Rect {
                x: 250,
                y: 150,
                w: 600,
                h: 392,
            },
            false,
        );
        wm
    }

    #[test]
    fn open_focuses_and_makes_visible() {
        let mut wm = wm();
        assert!(!wm.is_visible(App::Files));
        wm.open(App::Files);
        assert!(wm.is_visible(App::Files));
        assert_eq!(wm.focused(), Some(App::Files));
    }

    #[test]
    fn close_refocuses_a_remaining_visible_window() {
        let mut wm = wm();
        wm.open(App::Files);
        wm.close(App::Files);
        assert!(!wm.is_visible(App::Files));
        assert_eq!(wm.focused(), Some(App::Term));
    }

    #[test]
    fn maximize_saves_and_restores_the_rect() {
        let mut wm = wm();
        let before = wm.state(App::Term).unwrap().rect;
        wm.toggle_maximize(App::Term, 1280, 800);
        let maxi = wm.state(App::Term).unwrap().rect;
        assert_eq!((maxi.x, maxi.y), (90, 44));
        assert_eq!(maxi.w, 1280 - 104);
        assert_eq!(maxi.h, 800 - 62);
        wm.toggle_maximize(App::Term, 1280, 800);
        assert_eq!(wm.state(App::Term).unwrap().rect, before);
    }

    #[test]
    fn small_screens_get_floor_sizes_when_maximized() {
        let mut wm = wm();
        wm.toggle_maximize(App::Term, 600, 400);
        let maxi = wm.state(App::Term).unwrap().rect;
        assert_eq!(maxi.w, 560);
        assert_eq!(maxi.h, 360);
    }
}
