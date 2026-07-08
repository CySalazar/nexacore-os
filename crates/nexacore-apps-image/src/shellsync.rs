//! Shell ↔ compositor synchronisation (WS7 desktop parity M3, Task 3).
//!
//! [`ShellSync`] maps [`AppId`]s (the router's app identifiers) to
//! compositor [`WindowId`]s and executes shell actions (open/close/minimize/
//! maximize-toggle/focus) by mutating both halves of the shell's window
//! state in lockstep:
//!
//! * [`ShellWm`] — the authoritative running/minimized/maximized state and
//!   restore-rect bookkeeping, decoupled from the compositor (M1).
//! * [`Compositor`] — the actual on-screen window: `visible`, z-order,
//!   focus, and damage.
//!
//! Every mutating method here is the single place that touches both, so a
//! caller (`_start`'s dock-click / titlebar-button handling, wired up in
//! Task 4) never has to remember to update one after the other.
//!
//! ## Boot layout (spec)
//!
//! [`ShellSync::new`] applies the design mockup's initial state: Terminal is
//! running + visible + focused; NexaCore Helper is running + visible; Files,
//! Settings, and the System Monitor start not-running and hidden until the
//! user opens them from the dock (see the `crate::gfx`/`main` module docs
//! for the full M2 desktop-chrome context).
//!
//! ## Maximize is position-only (M3 limitation)
//!
//! See the `// LIMIT (M7):` comment on [`ShellSync::toggle_maximize`].
//!
//! ## Keyboard (Tab) compatibility
//!
//! [`ShellSync::focus_from_compositor`] is called from the Tab key's
//! `cycle_focus` handler in `main.rs` so `ShellWm`'s focus never drifts from
//! the compositor's after a Tab press. `cycle_focus` skips invisible windows
//! and clears focus to `None` when none are visible, so the two halves of
//! shell state stay in sync on every Tab press.

use alloc::vec::Vec;

use nexacore_desktop_shell::{
    dock::DockModel,
    router::{AppId, WindowGeom},
    wm::ShellWm,
};
use nexacore_display::{
    compositor::Compositor, effects::Shadow, geometry::Rect, surface::WindowId, window::Window,
};

use crate::gfx::shadow_padded;

/// Maps router [`AppId`]s to compositor [`WindowId`]s and executes shell
/// actions, keeping [`ShellWm`] and the [`Compositor`] in sync. See the
/// module doc for the overall design.
///
/// # Deviation from the task brief's illustrative shape
///
/// The brief sketches the id mapping as `ids: [(AppId, WindowId); 5]`. This
/// implementation instead uses six named fields plus an exhaustive `match`
/// in [`ShellSync::window_id`]. Both are `pub(crate)`-private representation
/// details (only [`ShellSync::wm`] and the methods are part of the surface
/// Task 4 depends on), but the named-field/`match` shape makes
/// `window_id` a *total* function — every `AppId` variant has a field, so
/// there is no "not found" case requiring an `.unwrap()`/panic or a
/// fabricated fallback `WindowId`, which the workspace's no-`unwrap`/
/// no-panic rule for non-test code forbids handling any other way. Behaviour
/// is identical to the array shape; only the private encoding differs.
pub(crate) struct ShellSync {
    /// Source of truth for running/minimized/maximized state and rects.
    pub wm: ShellWm<AppId>,
    /// Compositor window backing the Terminal app.
    term: WindowId,
    /// Compositor window backing the NexaCore Helper chat app.
    helper: WindowId,
    /// Compositor window backing the File Manager app.
    files: WindowId,
    /// Compositor window backing the System Monitor app.
    monitor: WindowId,
    /// Compositor window backing the Settings app.
    settings: WindowId,
    /// Compositor window backing the System Info app (launcher-only, no
    /// dock tile).
    system_info: WindowId,
    /// The desktop's window decoration shadow (same value as `main.rs`'s
    /// `decoration_shadow` local), used to pad every lifecycle damage rect
    /// below so the shadow band a window paints outside its tight rect is
    /// always repainted too — see [`ShellSync::hide`]'s doc for why a tight
    /// rect alone leaves a stale shadow trail.
    decoration_shadow: Shadow,
}

/// The six router [`AppId`] variants, in a fixed enumeration order reused
/// by [`ShellSync::geoms`] and [`ShellSync::focus_from_compositor`].
const APPS: [AppId; 6] = [
    AppId::Terminal,
    AppId::Helper,
    AppId::Files,
    AppId::Monitor,
    AppId::Settings,
    AppId::SystemInfo,
];

#[allow(
    dead_code,
    reason = "public surface consumed by Task 4 (dock clicks / titlebar buttons wired into \
              _start's pointer arm); Task 3's scope only wires ShellSync::new + \
              focus_from_compositor + dock_model, so open/close/minimize/toggle_maximize/focus/ \
              geoms (and the private helpers they alone call) are unused until then"
)]
impl ShellSync {
    /// Builds the shell↔compositor mapping from the six window IDs created
    /// in `_start`, and applies the M3 spec's initial boot layout (see the
    /// module doc).
    ///
    /// Reads each window's current rect straight off `comp` (rather than
    /// duplicating `main.rs`'s layout constants here), so `ShellWm`'s
    /// initial rects can never drift from what the compositor actually
    /// created. Hides the three not-running windows on `comp`
    /// (`visible = false`) and damages their screen rects, so the first
    /// `present` clears their footprint to the wallpaper instead of leaving
    /// whatever their initial render committed to the surface visible.
    pub fn new(
        comp: &mut Compositor,
        term: WindowId,
        helper: WindowId,
        files: WindowId,
        monitor: WindowId,
        settings: WindowId,
        system_info: WindowId,
        decoration_shadow: Shadow,
    ) -> Self {
        fn rect_of(comp: &Compositor, id: WindowId) -> Rect {
            comp.wm.window(id).map(Window::screen_rect).unwrap_or(Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            })
        }

        let mut wm = ShellWm::new();
        wm.insert(AppId::Terminal, rect_of(comp, term), true);
        wm.insert(AppId::Helper, rect_of(comp, helper), true);
        wm.insert(AppId::Files, rect_of(comp, files), false);
        wm.insert(AppId::Monitor, rect_of(comp, monitor), false);
        wm.insert(AppId::Settings, rect_of(comp, settings), false);
        wm.insert(AppId::SystemInfo, rect_of(comp, system_info), false);
        // `insert`'s "first running entry takes focus" rule already focuses
        // Terminal (the first `running: true` insert above); this is just
        // belt-and-braces against that rule ever changing.
        wm.focus(AppId::Terminal);

        for id in [files, monitor, settings, system_info] {
            let vacated = comp.wm.window_mut(id).map(|win| {
                win.visible = false;
                win.screen_rect()
            });
            if let Some(r) = vacated {
                comp.damage(r);
            }
        }

        Self {
            wm,
            term,
            helper,
            files,
            monitor,
            settings,
            system_info,
            decoration_shadow,
        }
    }

    /// The compositor [`WindowId`] backing `app`'s window. Total: every
    /// `AppId` variant maps to a field, so this never fails.
    #[must_use]
    pub fn window_id(&self, app: AppId) -> WindowId {
        match app {
            AppId::Terminal => self.term,
            AppId::Helper => self.helper,
            AppId::Files => self.files,
            AppId::Monitor => self.monitor,
            AppId::Settings => self.settings,
            AppId::SystemInfo => self.system_info,
        }
    }

    /// Snapshots every app's current rect/z/visibility from `comp` into
    /// [`WindowGeom`]s, for the pointer router (Task 4) to route against.
    /// An app whose window is somehow missing from `comp` (never happens in
    /// practice — all six are created once in `_start` and never
    /// destroyed) is silently omitted rather than substituting a fabricated
    /// rect.
    #[must_use]
    pub fn geoms(&self, comp: &Compositor) -> Vec<WindowGeom> {
        let mut out = Vec::with_capacity(APPS.len());
        for app in APPS {
            if let Some(win) = comp.wm.window(self.window_id(app)) {
                out.push(WindowGeom {
                    app,
                    rect: win.screen_rect(),
                    z: win.z,
                    visible: win.visible,
                });
            }
        }
        out
    }

    /// Dock-click "open": marks `app` running + focused in [`ShellWm`],
    /// shows its window, raises it to the top of the z-order, and focuses
    /// it on the compositor. `raise` and `set_focus` each already damage the
    /// window's tight rect, but that leaves the shadow band the decoration
    /// paints outside the tight rect uncomposited (the area was showing
    /// bare wallpaper while the window was hidden); the explicit
    /// shadow-padded damage below covers that band too.
    pub fn open(&mut self, app: AppId, comp: &mut Compositor) {
        self.wm.open(app);
        let id = self.window_id(app);
        if let Some(win) = comp.wm.window_mut(id) {
            win.visible = true;
        }
        if let Some(win) = comp.wm.window(id) {
            comp.damage(shadow_padded(win.screen_rect(), self.decoration_shadow));
        }
        let _ = comp.raise(id);
        let _ = comp.set_focus(id);
    }

    /// Close button: hides `app`'s window, marks it not-running in
    /// [`ShellWm`] (which also refocuses the first remaining visible window
    /// per its own policy), and mirrors the new focus onto the compositor.
    pub fn close(&mut self, app: AppId, comp: &mut Compositor) {
        self.wm.close(app);
        self.hide(app, comp);
        self.sync_focus_to_compositor(comp);
    }

    /// Minimize button: hides `app`'s window; the app stays running (only
    /// `minimized` flips in [`ShellWm`]), which refocuses the first
    /// remaining visible window per its own policy.
    pub fn minimize(&mut self, app: AppId, comp: &mut Compositor) {
        self.wm.minimize(app);
        self.hide(app, comp);
        self.sync_focus_to_compositor(comp);
    }

    /// Maximize toggle: [`ShellWm::toggle_maximize`] computes/stores the
    /// mockup's maximize rect (or restores the pre-maximize one) and
    /// refocuses `app`; this method re-positions the compositor window to
    /// match — it never resizes it.
    //
    // LIMIT (M7): window surfaces are fixed-size, allocated once in
    // `_start`; a true maximize needs surface reallocation plus the owning
    // app re-rendering its content at the new size, neither of which this
    // sync layer can do on the app's behalf. `ShellWm`'s rect stays
    // authoritative for *position* (and for restoring it on the second
    // toggle), but the window's on-screen *size* never changes here. M7
    // polish should decide whether per-app relayout is worth implementing,
    // or whether maximize-resize should simply be dropped from the design.
    pub fn toggle_maximize(
        &mut self,
        app: AppId,
        comp: &mut Compositor,
        screen_w: u32,
        screen_h: u32,
    ) {
        self.wm.toggle_maximize(app, screen_w, screen_h);
        let id = self.window_id(app);
        // Damage the old shadow+window footprint, move, then damage the new
        // one — the shadow band extends past the window, so a tight
        // window-only damage would leave a shadow trail (mirrors the drag
        // handler in `main.rs`).
        if let Some(win) = comp.wm.window(id) {
            comp.damage(shadow_padded(win.screen_rect(), self.decoration_shadow));
        }
        if let Some(state) = self.wm.state(app) {
            let _ = comp.move_window(id, state.rect.x, state.rect.y);
        }
        if let Some(win) = comp.wm.window(id) {
            comp.damage(shadow_padded(win.screen_rect(), self.decoration_shadow));
        }
        let _ = comp.set_focus(id);
    }

    /// Focuses `app`: raises + focuses its window on the compositor and
    /// mirrors the change into [`ShellWm`].
    pub fn focus(&mut self, app: AppId, comp: &mut Compositor) {
        self.wm.focus(app);
        let id = self.window_id(app);
        let _ = comp.raise(id);
        let _ = comp.set_focus(id);
    }

    /// Keyboard-Tab compatibility: reads the compositor's current focus
    /// (already advanced by `compositor.wm.cycle_focus()` in the Tab key
    /// handler) and mirrors it into [`ShellWm`], so Tab-cycling keeps both
    /// halves of the shell state in sync. Returns the newly-focused
    /// [`AppId`] so the caller can also update the menu bar's focused-app
    /// label. Returns `None` if the compositor has no focused window, or
    /// its focused window doesn't map to any of the six known apps
    /// (neither should happen with six permanent windows, but this stays
    /// defensive rather than panicking).
    ///
    /// `nexacore_display::wm::WindowManager::cycle_focus` skips invisible
    /// windows when picking the next focus target, and clears focus to
    /// `None` if no visible window remains, so the compositor's focused
    /// window (if any) is always one `ShellWm` also considers visible — the
    /// two halves of shell state stay in sync on every Tab press.
    pub fn focus_from_compositor(&mut self, comp: &Compositor) -> Option<AppId> {
        let focused_id = comp.wm.focused()?;
        let app = APPS
            .into_iter()
            .find(|&a| self.window_id(a) == focused_id)?;
        self.wm.focus(app);
        Some(app)
    }

    /// The dock's tile running-flags, read from [`ShellWm`]'s authoritative
    /// state (not the compositor's `visible` flag — a minimized-but-running
    /// app must still show as running in the dock).
    #[must_use]
    pub fn dock_model(&self) -> DockModel {
        DockModel::standard(
            self.is_running(AppId::Files),
            self.is_running(AppId::Terminal),
            self.is_running(AppId::Helper),
            self.is_running(AppId::Monitor),
            self.is_running(AppId::Settings),
        )
    }

    /// Hides `app`'s compositor window (`visible = false`) and damages its
    /// vacated rect, padded by the decoration shadow. Shared by
    /// [`ShellSync::close`] and [`ShellSync::minimize`], which both hide the
    /// window but differ only in the `ShellWm` transition (not-running vs.
    /// running-but-minimized).
    ///
    /// A tight-rect-only damage would leave the shadow band the decoration
    /// painted outside the window's rect uncomposited, so it keeps showing
    /// on screen as a stale dark ring after the window vanishes — the same
    /// failure mode the drag handler in `main.rs` already guards against.
    fn hide(&self, app: AppId, comp: &mut Compositor) {
        let id = self.window_id(app);
        let vacated = comp.wm.window_mut(id).map(|win| {
            win.visible = false;
            win.screen_rect()
        });
        if let Some(r) = vacated {
            comp.damage(shadow_padded(r, self.decoration_shadow));
        }
    }

    /// Mirrors [`ShellWm`]'s current focus (if any) onto the compositor.
    /// Used after [`ShellSync::close`]/[`ShellSync::minimize`] refocus a
    /// remaining visible window per `ShellWm`'s own policy.
    fn sync_focus_to_compositor(&self, comp: &mut Compositor) {
        if let Some(app) = self.wm.focused() {
            let id = self.window_id(app);
            let _ = comp.set_focus(id);
        }
    }

    /// `true` if `app` is currently running in [`ShellWm`] (regardless of
    /// minimized state).
    fn is_running(&self, app: AppId) -> bool {
        self.wm.state(app).is_some_and(|s| s.running)
    }
}
