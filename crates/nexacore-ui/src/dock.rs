//! Dock / taskbar model with running-app indicators (WS7-14.6/.7).
//!
//! The dock shows pinned apps (always) plus any running-but-unpinned app, each
//! carrying a running indicator (window count) and an attention flag. The model
//! is pure state — pin/unpin and launch/stop transitions keep the dock in sync
//! with the window manager; rendering the icons is downstream UI.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use nexacore_display::{geometry::Rect, tokens};

use crate::{
    canvas::Canvas,
    text::{draw_text, measure_text},
    theme::Theme,
};

/// One dock item: a pinned and/or running app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockApp {
    /// Application id (matches [`crate::launcher::AppEntry::id`]).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Whether the app is pinned (shown even when not running).
    pub pinned: bool,
    /// Whether the app is currently running.
    pub running: bool,
    /// Number of open windows (the running indicator).
    pub windows: u32,
    /// Whether the app requests user attention.
    pub attention: bool,
}

impl DockApp {
    fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            pinned: false,
            running: false,
            windows: 0,
            attention: false,
        }
    }

    /// Whether this item should still occupy a dock slot.
    fn is_live(&self) -> bool {
        self.pinned || self.running
    }
}

/// The dock / taskbar (WS7-14.6/.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dock {
    items: Vec<DockApp>,
}

impl Dock {
    /// An empty dock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn index_of(&self, id: &str) -> Option<usize> {
        self.items.iter().position(|a| a.id == id)
    }

    /// The index of `id`, creating a fresh (unpinned, not-running) item if absent.
    fn ensure(&mut self, id: &str, name: &str) -> usize {
        if let Some(i) = self.index_of(id) {
            i
        } else {
            self.items.push(DockApp::new(id, name));
            self.items.len() - 1
        }
    }

    /// Drop an item if it is neither pinned nor running.
    fn prune(&mut self, id: &str) {
        if let Some(i) = self.index_of(id) {
            if self.items.get(i).is_some_and(|a| !a.is_live()) {
                self.items.remove(i);
            }
        }
    }

    /// Pin an app (creating its item if absent).
    pub fn pin(&mut self, id: &str, name: &str) {
        let i = self.ensure(id, name);
        if let Some(app) = self.items.get_mut(i) {
            app.pinned = true;
        }
    }

    /// Unpin an app; if it is not running it leaves the dock.
    pub fn unpin(&mut self, id: &str) {
        if let Some(i) = self.index_of(id) {
            if let Some(app) = self.items.get_mut(i) {
                app.pinned = false;
            }
            self.prune(id);
        }
    }

    /// Mark an app running with `windows` open windows (creating its item if a
    /// running-but-unpinned app appears).
    pub fn mark_running(&mut self, id: &str, name: &str, windows: u32) {
        let i = self.ensure(id, name);
        if let Some(app) = self.items.get_mut(i) {
            app.running = true;
            app.windows = windows;
        }
    }

    /// Mark an app stopped; if it is not pinned it leaves the dock.
    pub fn mark_stopped(&mut self, id: &str) {
        if let Some(i) = self.index_of(id) {
            if let Some(app) = self.items.get_mut(i) {
                app.running = false;
                app.windows = 0;
                app.attention = false;
            }
            self.prune(id);
        }
    }

    /// Set an app's attention flag (no-op if the app is not in the dock).
    pub fn set_attention(&mut self, id: &str, on: bool) {
        if let Some(i) = self.index_of(id) {
            if let Some(app) = self.items.get_mut(i) {
                app.attention = on;
            }
        }
    }

    /// The visible dock items: pinned apps first (in pin order), then any
    /// running-but-unpinned apps (in launch order).
    #[must_use]
    pub fn visible(&self) -> Vec<&DockApp> {
        let pinned = self.items.iter().filter(|a| a.pinned);
        let running_unpinned = self.items.iter().filter(|a| a.running && !a.pinned);
        pinned.chain(running_unpinned).collect()
    }

    /// Renders the dock as a **branded elevated bar** inside `bar_rect`
    /// (WS7-19.6).
    ///
    /// A rounded dark-material panel with a soft drop shadow, sized to the
    /// visible apps, is centred horizontally near the bottom of `bar_rect`.
    /// Each app gets a rounded petrol tile bearing its initial as a monogram;
    /// a running app (open windows) shows a sage indicator dot, and an app
    /// requesting attention is tinted brick. Nothing is drawn for an empty dock.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::integer_division,
        reason = "dock geometry uses small positive pixel values; centring halves are exact"
    )]
    pub fn render(&self, canvas: &mut Canvas<'_>, theme: &Theme, bar_rect: &Rect) {
        const TILE: u32 = 44;
        const GAP: u32 = 8;

        let apps = self.visible();
        if apps.is_empty() {
            return;
        }
        let pad = theme.padding;
        let n = u32::try_from(apps.len()).unwrap_or(u32::MAX);

        let panel_w = n * TILE + n.saturating_sub(1) * GAP + 2 * pad;
        let panel_h = TILE + 2 * pad;
        let panel_x = bar_rect.x + (bar_rect.w.saturating_sub(panel_w) / 2) as i32;
        let panel_y = bar_rect.y + bar_rect.h.saturating_sub(panel_h) as i32;
        let panel = Rect {
            x: panel_x,
            y: panel_y,
            w: panel_w,
            h: panel_h,
        };

        // Elevated dark-material panel.
        canvas.draw_shadow(&panel, theme.elevation);
        canvas.fill_rounded_rect(&panel, theme.radius, tokens::SURFACE_DARK);

        // App tiles, left to right.
        let ty = panel_y + pad as i32;
        let mut tx = panel_x + pad as i32;
        for app in &apps {
            let tile = Rect {
                x: tx,
                y: ty,
                w: TILE,
                h: TILE,
            };
            let tile_color = if app.attention {
                tokens::BRICK_500
            } else {
                tokens::PETROL_500
            };
            canvas.fill_rounded_rect(&tile, theme.radius, tile_color);

            // Monogram: the app initial, upper-cased, centred (font8x8 path).
            if let Some(ch) = app.name.chars().next() {
                let mono: String = ch.to_uppercase().collect();
                let (gw, gh) = measure_text(&mono, theme.text_scale);
                let mx = tx + (TILE.saturating_sub(gw) / 2) as i32;
                let my = ty + (TILE.saturating_sub(gh) / 2) as i32;
                draw_text(
                    canvas,
                    mx,
                    my,
                    &mono,
                    tokens::TEXT_ON_DARK,
                    theme.text_scale,
                );
            }

            // Running indicator: a sage dot centred just inside the tile bottom.
            if app.running && app.windows > 0 {
                let dot = Rect {
                    x: tx + (TILE / 2) as i32 - 2,
                    y: ty + TILE as i32 - 4,
                    w: 4,
                    h: 3,
                };
                canvas.fill_rounded_rect(&dot, 1, tokens::SAGE_500);
            }

            tx += (TILE + GAP) as i32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BG: u32 = 0xFF14_171A; // desktop canvas

    #[test]
    fn render_empty_dock_draws_nothing() {
        let dock = Dock::new();
        let mut buf = alloc::vec![BG; 200 * 80];
        {
            let mut c = Canvas::new(&mut buf, 200, 80).unwrap();
            dock.render(
                &mut c,
                &Theme::nexacore(),
                &Rect {
                    x: 0,
                    y: 0,
                    w: 200,
                    h: 80,
                },
            );
        }
        assert!(
            buf.iter().all(|&p| p == BG),
            "empty dock must paint nothing"
        );
    }

    #[test]
    fn render_draws_panel_and_running_indicator() {
        let mut dock = Dock::new();
        dock.pin("org.nexacore.editor", "Text Editor");
        dock.mark_running("org.nexacore.editor", "Text Editor", 2);
        let mut buf = alloc::vec![BG; 200 * 80];
        {
            let mut c = Canvas::new(&mut buf, 200, 80).unwrap();
            dock.render(
                &mut c,
                &Theme::nexacore(),
                &Rect {
                    x: 0,
                    y: 0,
                    w: 200,
                    h: 80,
                },
            );
        }
        // The panel + tile paint over the background.
        assert!(buf.iter().any(|&p| p != BG), "dock rendered no pixels");
        // A petrol tile pixel exists (the app tile).
        assert!(
            buf.iter().any(|&p| p == tokens::PETROL_500),
            "no petrol tile drawn"
        );
        // The running indicator lays down a sage pixel.
        assert!(
            buf.iter().any(|&p| p == tokens::SAGE_500),
            "no sage running indicator drawn"
        );
    }

    #[test]
    fn pinned_apps_are_always_visible() {
        let mut dock = Dock::new();
        dock.pin("org.nexacore.editor", "Text Editor");
        assert_eq!(dock.visible().len(), 1);
        assert!(!dock.visible()[0].running);
        // Running toggles the indicator without changing visibility.
        dock.mark_running("org.nexacore.editor", "Text Editor", 2);
        assert_eq!(dock.visible()[0].windows, 2);
        assert!(dock.visible()[0].running);
        dock.mark_stopped("org.nexacore.editor");
        // Still visible (pinned), no longer running.
        assert_eq!(dock.visible().len(), 1);
        assert!(!dock.visible()[0].running);
    }

    #[test]
    fn unpinned_running_app_appears_then_leaves_on_stop() {
        let mut dock = Dock::new();
        dock.mark_running("org.nexacore.calc", "Calculator", 1);
        assert_eq!(dock.visible().len(), 1);
        dock.mark_stopped("org.nexacore.calc");
        assert!(dock.visible().is_empty()); // not pinned → removed
    }

    #[test]
    fn unpinning_a_running_app_keeps_it_until_stopped() {
        let mut dock = Dock::new();
        dock.pin("org.nexacore.term", "Terminal");
        dock.mark_running("org.nexacore.term", "Terminal", 1);
        dock.unpin("org.nexacore.term");
        // Still running → stays, now as an unpinned running item.
        let vis = dock.visible();
        assert_eq!(vis.len(), 1);
        assert!(vis[0].running && !vis[0].pinned);
        dock.mark_stopped("org.nexacore.term");
        assert!(dock.visible().is_empty());
    }

    #[test]
    fn pinned_first_then_running_unpinned() {
        let mut dock = Dock::new();
        dock.mark_running("b.running", "B", 1); // unpinned running
        dock.pin("a.pinned", "A"); // pinned, added later
        let vis = dock.visible();
        assert_eq!(vis[0].id, "a.pinned"); // pinned first despite later insert
        assert_eq!(vis[1].id, "b.running");
    }

    #[test]
    fn attention_flag_tracks() {
        let mut dock = Dock::new();
        dock.pin("x", "X");
        dock.set_attention("x", true);
        assert!(dock.visible()[0].attention);
        dock.set_attention("missing", true); // no-op, no panic
    }
}
