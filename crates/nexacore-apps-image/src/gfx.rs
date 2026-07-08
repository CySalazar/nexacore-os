//! Shared rendering primitives: anti-aliased brand typography, the hardware
//! cursor overlay, and the back-buffer → framebuffer present path.
//!
//! Split out of `main.rs` (mechanical, no behaviour change) so the five app
//! renderers in `apps/*` share one place for fonts, AA text helpers, the
//! status-bar dot, the cursor sprite, and `present`.

use alloc::{string::String, vec, vec::Vec};

use nexacore_desktop_shell::{
    dock::{self, DOCK_W, DockModel, RENDER_CANVAS_MARGIN},
    frame::FrameButton,
    launcher::{self, LauncherModel, LauncherState},
    menubar::{self, AiPill, MENUBAR_H, MenuBarModel},
    router::AppId,
    tokens::ShellTokens,
};
use nexacore_display::{
    DisplayError,
    compositor::Compositor,
    effects::{Shadow, shadow_bounds},
    font::Font,
    geometry::Rect,
};
use nexacore_ui::{canvas::Canvas, status_bar::BackendState, text::draw_text_aa};

use crate::{BAR_H, PAD, exit, write, write_hex};

/// Write a static description of a [`DisplayError`] to the kernel console.
pub(crate) fn write_display_error(e: &DisplayError) {
    match e {
        DisplayError::InvalidSize => write("InvalidSize"),
        DisplayError::UnknownWindow(id) => {
            write("UnknownWindow(");
            write_hex(u64::from(id.0));
            write(")");
        }
        DisplayError::BackBufferTooSmall => write("BackBufferTooSmall"),
        _ => write("DisplayError(unknown)"),
    }
}

// =============================================================================
// Present helper
// =============================================================================

/// Composite the back buffer, repaint the menu-bar/dock chrome where damaged,
/// and blit dirty rects to the framebuffer.
///
/// # Safety
///
/// `front_va` must be the kernel-assigned framebuffer VA, valid and writable
/// for at least `stride * screen_h * 4` bytes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn present(
    compositor: &mut Compositor,
    back: &mut [u32],
    front_va: u64,
    screen_w: u32,
    screen_h: u32,
    stride: u32,
    chrome: &mut ChromeState,
    tokens: &ShellTokens,
) {
    // If the chrome model changed since the last frame (focus/AI update) with
    // no window damage of its own, the strip in `back` still holds the
    // PREVIOUS frame's already-tinted chrome — `repaint_chrome` blends the
    // menu-bar tint over whatever `back` holds, so re-tinting over old tint
    // compounds (wallpaper fades toward solid, old focused-app text ghosts
    // under the new one). Damage the full menu strip here so `composite`
    // repaints it from the pure wallpaper backdrop first (no window reaches
    // y < MENUBAR_H), giving `repaint_chrome`'s intersection trigger below a
    // genuinely fresh surface to blend onto.
    if chrome.needs_repaint {
        compositor.damage(Rect {
            x: 0,
            y: 0,
            w: screen_w,
            h: MENUBAR_H,
        });
    }
    // Same pre-composite full-strip damage, mirrored for the dock: a
    // dock-only mutation (tile running-state change, hover move) with no
    // window damage of its own would otherwise re-blend the panel's
    // translucent border/separators over their own previously-tinted
    // pixels (see `repaint_chrome`'s invariant note below).
    if chrome.dock_dirty {
        compositor.damage(dock::panel_rect(screen_h));
    }

    let mut dirty = match compositor.composite(back) {
        Ok(d) => d,
        Err(e) => {
            write("[nexacore-apps] composite error: ");
            write_display_error(&e);
            write("\n");
            return;
        }
    };

    // Chrome-zone full-recomposite pass: a WINDOW's own damage (a dragged
    // edge, its drop shadow) can clip a chrome zone without covering it in
    // full — e.g. only the bottom-left corner of the dock panel. Left as-is,
    // `repaint_chrome` below would still copy the WHOLE zone out of `back`
    // and re-blend over it, so the untouched remainder would be re-tinted
    // over its own previous tint (the compounding-tint artifact the
    // flag-driven full-strip damage above already prevents for model-only
    // changes). Force a second, full-zone composite for any zone this
    // frame's dirty rects only partially touched, so `repaint_chrome` always
    // reads a genuinely fresh backdrop for the whole zone.
    //
    // Conservative per-rect rule (deliberately not exact union coverage): a
    // zone is "partially covered" if some dirty rect intersects it without
    // fully containing it. A full-screen `damage_all` rect contains both
    // zones, so it never trips this. Two dirty rects that jointly cover a
    // zone but neither alone does will over-trigger an extra composite pass
    // — a performance-only cost, not a correctness gap (documented, see the
    // task-5 report).
    //
    // Kept as a second pass AFTER the first `composite` call, rather than
    // folded into the flag-driven pre-check above, because `Compositor`
    // does not expose its pending damage before compositing (it is
    // consumed/cleared inside `composite`) — there is no way to know
    // whether a zone will end up only partially covered until the first
    // composite's result is in hand, short of adding a new peek API to
    // `omni-display`, which is out of scope here (this fix touches only
    // `gfx.rs`).
    let mut expand_zone = false;
    for zone in chrome_read_zones(screen_w, screen_h).into_iter().flatten() {
        let partially_covered = dirty
            .iter()
            .any(|d| matches!(d.intersect(&zone), Some(covered) if covered != zone));
        if partially_covered {
            compositor.damage(zone);
            expand_zone = true;
        }
    }
    if expand_zone {
        match compositor.composite(back) {
            Ok(extra) => dirty.extend(extra),
            Err(e) => {
                write("[nexacore-apps] composite error: ");
                write_display_error(&e);
                write("\n");
                return;
            }
        }
    }

    // Menu bar / dock chrome pass: repaint either strip when this frame's
    // dirty rects touch it (e.g. a window sliding under it, or an explicit
    // model update), and extend `dirty` so the blit loop below flushes the
    // repainted pixels too — otherwise the chrome update would sit only in
    // `back` and never reach the framebuffer.
    repaint_chrome(&mut dirty, back, screen_w, screen_h, chrome, tokens);

    // Launcher overlay (WS7 desktop M4): a full-screen modal painted
    // directly over the just-composited-and-chromed backdrop. The caller is
    // responsible for calling `compositor.damage_all()` whenever
    // `chrome.launcher`'s open/query state changes, so `dirty` here already
    // covers the whole screen — this pass only needs to draw, not compute
    // its own damage.
    if chrome.launcher.is_open() {
        let results = chrome.launcher.results();
        let model = LauncherModel {
            query: chrome.launcher.query(),
            results: &results,
            has_ai: chrome.launcher.has_ai(),
            dark: chrome.dark,
        };
        if let Ok(mut canvas) = Canvas::new(back, screen_w, screen_h) {
            launcher::render(
                &mut canvas,
                tokens,
                ui_font(),
                mono_font(),
                &model,
                screen_w,
                screen_h,
            );
        }
    }

    let n = dirty.len();
    let screen_w_usize = screen_w as usize;
    let screen_h_usize = screen_h as usize;
    let stride_usize = stride as usize;

    for dr in &dirty {
        #[allow(clippy::cast_sign_loss, reason = "compositor ensures x,y >= 0")]
        let x0 = (dr.x as u32) as usize;
        #[allow(clippy::cast_sign_loss, reason = "compositor ensures x,y >= 0")]
        let y0 = (dr.y as u32) as usize;
        let x1 = (x0 + dr.w as usize).min(screen_w_usize);
        let y1 = (y0 + dr.h as usize).min(screen_h_usize);

        let mut y = y0;
        while y < y1 {
            let back_row_start = y * screen_w_usize + x0;
            let back_row_end = y * screen_w_usize + x1;
            let front_row_start = y * stride_usize + x0;
            let px_count = x1.saturating_sub(x0);
            if px_count == 0 {
                y += 1;
                continue;
            }
            let Some(src_slice) = back.get(back_row_start..back_row_end) else {
                y += 1;
                continue;
            };
            // SAFETY: front_va is the kernel-assigned framebuffer VA valid for
            // stride * screen_h * 4 bytes.  front_row_start + px_count <=
            // stride * screen_h (x1 <= screen_w <= stride, y < screen_h).
            // write_volatile prevents the compiler from eliding stores.
            unsafe {
                let dst_base: *mut u32 = (front_va as *mut u32).add(front_row_start);
                let mut i = 0usize;
                while i < px_count {
                    // SAFETY: i < px_count <= stride (fits in the mapping).
                    core::ptr::write_volatile(dst_base.add(i), src_slice[i]);
                    i += 1;
                }
            }
            y += 1;
        }
    }

    write("[nexacore-apps] composited ");
    write_hex(n as u64);
    write(" dirty rects\n");
}

// =============================================================================
// Desktop chrome: menu bar + dock (WS7 desktop M2)
// =============================================================================

/// Owned chrome state: the menu bar's dynamic fields (focused app, AI
/// health, theme flag), the dock's tile model, and the two scratch pixel
/// buffers the chrome repaint pass below reuses every frame.
///
/// Both scratch buffers are sized once in [`ChromeState::new`] (called once
/// from `_start`) and never reallocated afterwards — the chrome repaint pass
/// performs no per-frame allocation.
pub(crate) struct ChromeState {
    /// Name of the currently-focused window (menu bar's left-side label).
    /// Update wherever compositor focus changes: boot, the Tab key, and
    /// pointer-press focus (mirrors the M1 `focused()` call sites).
    pub(crate) focused_app: String,
    /// Node/workspace label shown next to the focused app name.
    pub(crate) node_label: String,
    /// Whether the AI backend is reachable and serving (drives the pill's
    /// sage/brick dot). Set via [`ChromeState::set_ai_state`].
    ai_healthy: bool,
    /// AI status pill label, e.g. `"AI · GPU · NexyAI"`.
    ai_label: String,
    /// Dark/light theme flag threaded into `MenuBarModel::dark`. Always
    /// `true` in M2 (only `ShellTokens::dark()` is used by this image).
    pub(crate) dark: bool,
    /// Whether the menu bar's on-screen strip is stale relative to this
    /// model and must be repainted on the next `present`, even if that
    /// frame's composite produced no dirty rect touching the strip. Set by
    /// `ChromeState::mark_dirty` from `set_focused_app`/`set_ai_state` when
    /// the incoming value actually differs from the current one; cleared by
    /// `repaint_chrome` once it repaints the strip. The dock model is static
    /// in M2, so this flag only needs to drive the menu strip, not the dock
    /// panel.
    needs_repaint: bool,
    /// The dock's tile model (running flags for the five M2 windows).
    pub(crate) dock: DockModel,
    /// Mirrors `needs_repaint` for the dock strip: set by
    /// [`ChromeState::set_dock_model`]/[`ChromeState::set_dock_hover`] when
    /// the incoming value actually differs from the current one, so a
    /// dock-only mutation (a tile's running flag, or the hovered tile) still
    /// gets repainted on the next `present` even when that frame produced no
    /// composite damage over the panel. Cleared by `repaint_chrome` once it
    /// repaints the panel.
    dock_dirty: bool,
    /// Index into `dock.tiles` the pointer currently hovers, if any (`None`
    /// off the dock entirely). Threaded into `dock::render`'s `hover`
    /// parameter by `repaint_chrome`.
    dock_hover: Option<usize>,
    /// Which titlebar button of which app's window the pointer currently
    /// hovers, if any. Read by [`ChromeState::frame_hover_for`] so each app's
    /// `render_*` function can thread the right `WindowFrame::hover` value
    /// for its own window (and `None` for every other window).
    frame_hover: Option<(AppId, FrameButton)>,
    /// Scratch buffer for the menu-bar strip (`screen_w * MENUBAR_H` pixels).
    menu_scratch: Vec<u32>,
    /// Scratch buffer for the dock panel canvas
    /// (`(DOCK_W + RENDER_CANVAS_MARGIN) * panel_h` pixels).
    dock_scratch: Vec<u32>,
    /// Launcher open/query state and search results (WS7 desktop M4). The
    /// caller must call `compositor.damage_all()` whenever this changes so
    /// `present`'s launcher pass actually reaches the framebuffer.
    pub(crate) launcher: LauncherState,
}

impl ChromeState {
    /// Builds the chrome state for a `screen_w`×`screen_h` desktop, sizing
    /// both scratch buffers up front so the `present` chrome pass never
    /// reallocates.
    pub(crate) fn new(screen_w: u32, screen_h: u32, dock: DockModel) -> Self {
        let menu_len = (screen_w as usize).saturating_mul(MENUBAR_H as usize);
        let panel_h = dock::panel_rect(screen_h).h;
        let dock_len = ((DOCK_W + RENDER_CANVAS_MARGIN) as usize).saturating_mul(panel_h as usize);
        Self {
            focused_app: String::new(),
            node_label: String::from("node-01 · space 1"),
            ai_healthy: false,
            ai_label: String::from("AI · offline"),
            dark: true,
            needs_repaint: false,
            dock,
            dock_dirty: false,
            dock_hover: None,
            frame_hover: None,
            menu_scratch: vec![0u32; menu_len],
            dock_scratch: vec![0u32; dock_len],
            launcher: LauncherState::new(),
        }
    }

    /// Marks the menu strip as needing a repaint on the next `present`,
    /// regardless of whether that frame's composite dirty rects intersect
    /// it. Called by the setters below when the incoming value actually
    /// changes the model.
    fn mark_dirty(&mut self) {
        self.needs_repaint = true;
    }

    /// Sets the focused-app label shown at the menu bar's left side.
    pub(crate) fn set_focused_app(&mut self, name: &str) {
        if self.focused_app == name {
            return;
        }
        self.focused_app.clear();
        self.focused_app.push_str(name);
        self.mark_dirty();
    }

    /// Updates the AI status pill from the latest [`BackendState`].
    ///
    /// Mapping (deviation from the task brief's literal `Gpu | Cpu` wording,
    /// since [`BackendState`] has no separate healthy-CPU variant — only
    /// `Gpu`, `CpuDegraded`, `Unknown`): `Gpu` and `CpuDegraded` both mean the
    /// backend is actively serving (just via a CPU fallback in the degraded
    /// case), so both count as "healthy" for this pill's binary reachability
    /// signal; only `Unknown` (no event received yet, or the service is down)
    /// shows the offline/brick state. This differs from `status_bar.rs`'s
    /// `StatusBar`, whose brick colour instead conveys *degraded serving
    /// mode*, not reachability.
    pub(crate) fn set_ai_state(&mut self, state: BackendState) {
        let (healthy, label): (bool, &str) = match state {
            BackendState::Gpu => (true, "AI · GPU · NexyAI"),
            BackendState::CpuDegraded => (true, "AI · CPU · fallback"),
            BackendState::Unknown => (false, "AI · offline"),
        };
        if self.ai_healthy == healthy && self.ai_label == label {
            return;
        }
        self.ai_healthy = healthy;
        self.ai_label.clear();
        self.ai_label.push_str(label);
        self.mark_dirty();
    }

    /// Replaces the dock's tile model, marking the dock strip dirty when the
    /// incoming model actually differs (a tile's running flag changed).
    /// Called after every pointer action that can flip a running flag
    /// (dock-tile open, titlebar close/minimize).
    pub(crate) fn set_dock_model(&mut self, model: DockModel) {
        if self.dock == model {
            return;
        }
        self.dock = model;
        self.dock_dirty = true;
    }

    /// Updates the hovered dock tile index, marking the dock strip dirty
    /// when it actually changes. `None` clears the hover (pointer left the
    /// dock or moved onto a window/menu bar).
    pub(crate) fn set_dock_hover(&mut self, hover: Option<usize>) {
        if self.dock_hover == hover {
            return;
        }
        self.dock_hover = hover;
        self.dock_dirty = true;
    }

    /// Updates which app's titlebar button is hovered. Unlike the dock, no
    /// dirty flag is needed here: the pointer arm re-renders the affected
    /// window(s) directly (which damages their own rect via
    /// `commit_surface`), so `frame_hover_for`'s next read always reflects
    /// this value in time for that same-frame re-render.
    pub(crate) fn set_frame_hover(&mut self, hover: Option<(AppId, FrameButton)>) {
        self.frame_hover = hover;
    }

    /// Sets the dark/light theme flag, marking both the menu strip and the
    /// dock panel dirty when it actually changes (mirrors
    /// [`ChromeState::set_ai_state`]'s dirty-on-change pattern). Both
    /// strips render every colour from whatever `tokens: &ShellTokens` the
    /// caller passes to the next `present()`, so — unlike `set_focused_app`
    /// — this setter only needs to force a repaint; the caller is
    /// responsible for having already rebuilt `shell_tokens` to the new
    /// theme before that next `present()` runs.
    pub(crate) fn set_dark(&mut self, dark: bool) {
        if self.dark == dark {
            return;
        }
        self.dark = dark;
        self.mark_dirty();
        self.dock_dirty = true;
    }

    /// The titlebar button `app`'s own window should draw as hovered, if
    /// any. Read by each of the five `render_*` functions when building
    /// their `WindowFrame`, so only the one window actually under the
    /// pointer shows a hover highlight.
    #[must_use]
    pub(crate) fn frame_hover_for(&self, app: AppId) -> Option<FrameButton> {
        self.frame_hover
            .and_then(|(a, b)| if a == app { Some(b) } else { None })
    }
}

/// Current uptime in minutes, for the menu-bar clock, the System Monitor's
/// Uptime tile, and the System Info window.
///
/// The desktop image is a staged presentation (seeded Helper conversation and
/// AI status — see `main.rs` Step 9.6/11b), captured moments after boot. To
/// avoid a bare "0m" on those windows, uptime is reported from a small demo
/// baseline ([`DEMO_UPTIME_BASE_MIN`]) added to the real monotonic uptime, so
/// it still ticks up live from a lived-in value.
pub(crate) fn uptime_minutes_now() -> u32 {
    /// Demo baseline added to the real uptime so a freshly-booted capture
    /// shows tens of minutes rather than "0m".
    const DEMO_UPTIME_BASE_MIN: u32 = 37;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "nanos / 60e9 comfortably fits u32 for any realistic uptime"
    )]
    let real = (crate::time_monotonic_nanos() / 60_000_000_000) as u32;
    DEMO_UPTIME_BASE_MIN.saturating_add(real)
}

/// Clamps `rect` to the `w`×`h` screen bounds, returning `None` when the
/// intersection is empty (`rect` lies entirely off-screen).
///
/// Used before pushing a repainted chrome rect to the dirty list, so a
/// caller-supplied or computed rect that partially or fully exceeds the
/// screen never reaches the blit loop in [`present`] with out-of-bounds
/// extents.
fn clamp_to_screen(rect: Rect, w: u32, h: u32) -> Option<Rect> {
    rect.intersect(&Rect { x: 0, y: 0, w, h })
}

/// The screen-space footprint `repaint_chrome` reads out of `back` for each
/// chrome zone, clamped to the screen: the menu strip (full width, top
/// `MENUBAR_H` rows) and the dock panel's read footprint, which extends
/// `RENDER_CANVAS_MARGIN` pixels past the panel's own left edge (see
/// `repaint_chrome`'s dock section doc comment on the canvas-to-screen
/// mapping). Used by [`present`]'s chrome-zone full-recomposite pass to
/// decide whether a zone needs a fresh full-zone composite before chrome
/// blending runs. A zone clamped entirely off-screen yields `None` (not
/// reachable in practice, but kept defensive).
fn chrome_read_zones(screen_w: u32, screen_h: u32) -> [Option<Rect>; 2] {
    let menu_zone = Rect {
        x: 0,
        y: 0,
        w: screen_w,
        h: MENUBAR_H,
    };
    let panel = dock::panel_rect(screen_h);
    #[allow(
        clippy::cast_possible_wrap,
        reason = "RENDER_CANVAS_MARGIN is a small positive pixel constant"
    )]
    let dock_zone = Rect {
        x: panel.x - RENDER_CANVAS_MARGIN as i32,
        y: panel.y,
        w: DOCK_W + RENDER_CANVAS_MARGIN,
        h: panel.h,
    };
    [
        clamp_to_screen(menu_zone, screen_w, screen_h),
        clamp_to_screen(dock_zone, screen_w, screen_h),
    ]
}

/// Repaints the menu bar strip and/or the dock panel strip over the just
/// composited back buffer, when this frame's `dirty` rects intersect them —
/// or, for the menu strip, when `chrome`'s `needs_repaint` flag is set by a
/// model mutation (`set_focused_app`/`set_ai_state`) that produced no
/// composite damage of its own — and appends the repainted rect(s) to
/// `dirty` so the blit loop in [`present`] flushes them to the framebuffer.
/// This runs unconditionally on every `present` call, so it still fires (and
/// still gets flushed) even when `compositor.composite` returned zero dirty
/// rects for the frame. The dock panel model is static in M2, so only the
/// menu strip needs the flag-driven trigger.
///
/// Both shell renderers blend their chrome over whatever is already in
/// `back` (wallpaper and/or window pixels) per their own `blend_pixel`
/// contract (see the `menubar.rs`/`dock.rs` module docs) — so a window
/// sliding out from under the menu bar or dock leaves no stale chrome
/// fringe: the window's own repaint damages the strip, which is exactly the
/// intersection this function checks for.
///
/// Invariant (M3 Task 5): by the time this function runs, both chrome zones
/// have always been *fully* recomposited in `back` since the last
/// `repaint_chrome` call, however that happened this frame — the flag-driven
/// pre-composite full-strip damage above (a model-only change with no
/// window damage), the window damage already fully covering the zone on its
/// own, or [`present`]'s post-composite full-zone expansion pass (a window's
/// damage only partially clipped the zone). So the copy from `back` below
/// never re-reads its own previously-tinted output — no compounding tint,
/// no ghosting, regardless of which of the three paths triggered the fresh
/// zone.
fn repaint_chrome(
    dirty: &mut Vec<Rect>,
    back: &mut [u32],
    screen_w: u32,
    screen_h: u32,
    chrome: &mut ChromeState,
    tokens: &ShellTokens,
) {
    let screen_w_usize = screen_w as usize;

    // --- Menu bar strip (full width, y in [0, MENUBAR_H)) ------------------
    //
    // The strip spans the whole back-buffer width, so it is one contiguous
    // run of `screen_w * MENUBAR_H` pixels starting at index 0 — no
    // row-by-row copy needed (unlike the dock strip below).
    let menu_rect = Rect {
        x: 0,
        y: 0,
        w: screen_w,
        h: MENUBAR_H,
    };
    let menu_damaged = dirty.iter().any(|dr| dr.intersect(&menu_rect).is_some());
    if menu_damaged || chrome.needs_repaint {
        let menu_len = screen_w_usize.saturating_mul(MENUBAR_H as usize);
        if menu_len <= back.len() && menu_len == chrome.menu_scratch.len() {
            chrome.menu_scratch.copy_from_slice(&back[..menu_len]);

            let uptime_minutes = uptime_minutes_now();
            let model = MenuBarModel {
                focused_app: &chrome.focused_app,
                node_label: &chrome.node_label,
                ai_state: AiPill {
                    healthy: chrome.ai_healthy,
                    label: chrome.ai_label.clone(),
                },
                uptime_minutes,
                dark: chrome.dark,
            };
            if let Ok(mut canvas) = Canvas::new(&mut chrome.menu_scratch, screen_w, MENUBAR_H) {
                menubar::render(
                    &mut canvas,
                    tokens,
                    ui_font(),
                    mono_font(),
                    &model,
                    screen_w,
                );
            }

            back[..menu_len].copy_from_slice(&chrome.menu_scratch);
            if let Some(clamped) = clamp_to_screen(menu_rect, screen_w, screen_h) {
                dirty.push(clamped);
            }
            chrome.needs_repaint = false;
        }
    }

    // --- Dock panel strip ----------------------------------------------------
    //
    // `dock::render`'s canvas convention (see its doc comment): width is
    // `DOCK_W + RENDER_CANVAS_MARGIN`, height is exactly the panel height, and
    // the panel's own left edge sits at canvas-local x = `RENDER_CANVAS_MARGIN`
    // — so canvas column 0 maps to screen x = `panel.x - RENDER_CANVAS_MARGIN`,
    // which can be negative (DOCK_X = 14 < the 16px margin). `copy_rect`
    // below skips any canvas cell with no on-screen back-buffer counterpart.
    let panel = dock::panel_rect(screen_h);
    let dock_damaged = dirty.iter().any(|dr| dr.intersect(&panel).is_some());
    if dock_damaged || chrome.dock_dirty {
        let canvas_w = DOCK_W + RENDER_CANVAS_MARGIN;
        let canvas_h = panel.h;
        let needed = (canvas_w as usize).saturating_mul(canvas_h as usize);
        #[allow(
            clippy::cast_possible_wrap,
            reason = "RENDER_CANVAS_MARGIN is a small positive pixel constant"
        )]
        let origin_x = panel.x - RENDER_CANVAS_MARGIN as i32;
        let origin_y = panel.y;

        if needed == chrome.dock_scratch.len() {
            // Off-screen canvas columns have no back-buffer source; zero
            // them so `dock::render`'s fills paint over a defined backdrop
            // rather than stale scratch content from a previous frame.
            for p in &mut chrome.dock_scratch {
                *p = 0;
            }
            copy_rect(
                back,
                screen_w,
                screen_h,
                &mut chrome.dock_scratch,
                canvas_w,
                canvas_h,
                origin_x,
                origin_y,
                true,
            );

            if let Ok(mut canvas) = Canvas::new(&mut chrome.dock_scratch, canvas_w, canvas_h) {
                dock::render(&mut canvas, tokens, &chrome.dock, true, chrome.dock_hover);
            }

            copy_rect(
                back,
                screen_w,
                screen_h,
                &mut chrome.dock_scratch,
                canvas_w,
                canvas_h,
                origin_x,
                origin_y,
                false,
            );
            if let Some(clamped) = clamp_to_screen(panel, screen_w, screen_h) {
                dirty.push(clamped);
            }
            chrome.dock_dirty = false;
        }
    }
}

/// Copies pixels between the screen-space back buffer and a canvas-local
/// scratch buffer whose top-left sits at screen `(origin_x, origin_y)`.
///
/// `to_scratch == true` copies back→scratch (before rendering); `false`
/// copies scratch→back (after rendering). Canvas cells with no corresponding
/// on-screen back-buffer pixel (off the left/top/right/bottom edge — the
/// dock canvas's reserved left margin can extend past screen `x = 0`) are
/// silently skipped in both directions; bounds-checked throughout, never
/// panics.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    reason = "small positive pixel metrics; origin_x may be slightly negative by design; the \
              back/scratch copy needs both buffers' dimensions plus the origin and direction"
)]
fn copy_rect(
    back: &mut [u32],
    screen_w: u32,
    screen_h: u32,
    scratch: &mut [u32],
    canvas_w: u32,
    canvas_h: u32,
    origin_x: i32,
    origin_y: i32,
    to_scratch: bool,
) {
    let screen_w_i = screen_w as i32;
    let screen_h_i = screen_h as i32;
    for cy in 0..canvas_h {
        let sy = origin_y + cy as i32;
        if sy < 0 || sy >= screen_h_i {
            continue;
        }
        for cx in 0..canvas_w {
            let sx = origin_x + cx as i32;
            if sx < 0 || sx >= screen_w_i {
                continue;
            }
            let bi = (sy as usize) * (screen_w as usize) + (sx as usize);
            let ci = (cy as usize) * (canvas_w as usize) + (cx as usize);
            if to_scratch {
                if let (Some(&bp), Some(cp)) = (back.get(bi), scratch.get_mut(ci)) {
                    *cp = bp;
                }
            } else if let (Some(bp), Some(&cp)) = (back.get_mut(bi), scratch.get(ci)) {
                *bp = cp;
            }
        }
    }
}

// =============================================================================
// Anti-aliased brand typography (WS7-19 F2)
// =============================================================================
//
// The five windows render their text with the brand OpenType faces through the
// AA engine: Inter for UI/labels, IBM Plex Mono for the terminal body and the
// System Monitor's mono-set rows. Sizes fit the existing 16-px line grid;
// cursor positions come from
// `measure_text_aa` (proportional-correct), so the char-count layout math is
// preserved.

/// UI (Inter) point size in px/em.
pub(crate) const UI_PX: f32 = 14.0;
/// Monospace (IBM Plex Mono) point size in px/em.
pub(crate) const MONO_PX: f32 = 14.0;

/// Parsed brand UI face, initialised once by [`init_fonts`] before the first
/// render. `Option` so the `static` has a `const` initialiser.
static mut UI_FONT: Option<Font<'static>> = None;
/// Parsed brand monospace face. See [`UI_FONT`].
static mut MONO_FONT: Option<Font<'static>> = None;

/// Parses the embedded brand faces into the `UI_FONT`/`MONO_FONT` statics.
/// Called once from `_start` before any rendering; on parse failure the image
/// cannot draw text, so it exits (code 51).
pub(crate) fn init_fonts() {
    match (
        Font::parse(nexacore_fonts::BRAND_UI),
        Font::parse(nexacore_fonts::BRAND_MONO),
    ) {
        (Ok(ui), Ok(mono)) => {
            // SAFETY: single-threaded; called once in `_start` before the
            // render/input loop, and the statics are never mutated afterwards.
            unsafe {
                *core::ptr::addr_of_mut!(UI_FONT) = Some(ui);
                *core::ptr::addr_of_mut!(MONO_FONT) = Some(mono);
            }
        }
        _ => {
            write("[nexacore-apps] font parse FAILED\n");
            exit(51);
        }
    }
}

/// The UI face (Inter). Must be called after [`init_fonts`].
pub(crate) fn ui_font() -> &'static Font<'static> {
    // SAFETY: `init_fonts` ran in `_start`; the static is set once and only read
    // afterwards on this single thread.
    match unsafe { (*core::ptr::addr_of!(UI_FONT)).as_ref() } {
        Some(f) => f,
        None => exit(51),
    }
}

/// The monospace face (IBM Plex Mono). Must be called after [`init_fonts`].
pub(crate) fn mono_font() -> &'static Font<'static> {
    // SAFETY: see [`ui_font`].
    match unsafe { (*core::ptr::addr_of!(MONO_FONT)).as_ref() } {
        Some(f) => f,
        None => exit(51),
    }
}

/// Draws AA text with `font`/`px`, treating `top_y` as the top of the line (the
/// old bitmap `draw_text` convention): the baseline is dropped by the face's
/// approximate ascent so glyphs sit inside the line slot.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_arithmetic,
    reason = "baseline drop is a small positive metric approximation"
)]
pub(crate) fn aa_line(
    canvas: &mut Canvas<'_>,
    x: i32,
    top_y: i32,
    s: &str,
    color: u32,
    font: &Font<'_>,
    px: f32,
) {
    let baseline = top_y + (px * 0.82) as i32;
    let _ = draw_text_aa(canvas, x, baseline, s, font, px, color);
}

/// AA UI text (Inter) at [`UI_PX`], top-left `(x, top_y)`.
pub(crate) fn ui_text(canvas: &mut Canvas<'_>, x: i32, top_y: i32, s: &str, color: u32) {
    aa_line(canvas, x, top_y, s, color, ui_font(), UI_PX);
}

/// AA monospace text (IBM Plex Mono) at [`MONO_PX`], top-left `(x, top_y)`.
pub(crate) fn mono_text(canvas: &mut Canvas<'_>, x: i32, top_y: i32, s: &str, color: u32) {
    aa_line(canvas, x, top_y, s, color, mono_font(), MONO_PX);
}

/// Draws a compact anti-aliased AI-backend status strip at `top_y`: a small
/// state-coloured round dot plus a dim AA label, occupying a [`BAR_H`]-tall
/// band starting at `top_y`. The window background is already filled by the
/// caller.
///
/// Since Task 7 (mockup chrome), this is the NexaCore Helper's own status
/// strip, drawn directly below the shared [`nexacore_desktop_shell::frame`]
/// titlebar (`top_y = TITLEBAR_H`) — the other four windows no longer show
/// this strip (the menu-bar pill arrives in M2).
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    reason = "BAR_H/PAD are small positive layout constants"
)]
pub(crate) fn render_status(
    canvas: &mut Canvas<'_>,
    top_y: i32,
    state: BackendState,
    tokens: &ShellTokens,
) {
    let (dot_color, label): (u32, &str) = match state {
        BackendState::Gpu => (tokens.sage, "AI · GPU ready"),
        BackendState::CpuDegraded => (tokens.brick, "AI · CPU degraded"),
        BackendState::Unknown => (tokens.text_secondary, "AI · offline"),
    };
    let dot = Rect {
        x: PAD as i32,
        y: top_y + (BAR_H / 2).saturating_sub(4) as i32,
        w: 8,
        h: 8,
    };
    canvas.fill_rounded_rect(&dot, 4, dot_color);
    ui_text(
        canvas,
        (PAD * 2 + 8) as i32,
        top_y + (BAR_H.saturating_sub(UI_PX as u32) / 2) as i32,
        label,
        tokens.text_secondary,
    );
}

// =============================================================================
// Hardware cursor overlay
// =============================================================================
//
// The kernel input pump sends `DisplayInputEvent::Pointer` with an absolute
// position. The shell floats an arrow cursor over the composited desktop by
// drawing it straight to the framebuffer AFTER each `present`; the previous
// footprint is repaired by damaging `cursor_rect` before the next `present`.

/// Cursor sprite width/height in pixels.
pub(crate) const CURSOR_W: usize = 12;
/// See [`CURSOR_W`].
pub(crate) const CURSOR_H: usize = 18;
/// Arrow mask: bit `c` of row `r` set ⇒ that pixel belongs to the pointer.
/// The 1-px outline is derived at draw time (a masked pixel touching an
/// unmasked neighbour). Classic left-pointing arrow with a tail.
pub(crate) const CURSOR_MASK: [u16; CURSOR_H] = [
    0x001, 0x003, 0x007, 0x00F, 0x01F, 0x03F, 0x07F, 0x0FF, 0x1FF, 0x3FF, 0x03F, 0x077, 0x073,
    0x0E1, 0x0E0, 0x1C0, 0x1C0, 0x180,
];
/// Cream fill (`#F4EBD0`) — legible on any backdrop.
pub(crate) const CURSOR_FILL: u32 = 0xFFF4_EBD0;
/// Charcoal-900 outline (`#14171A`).
pub(crate) const CURSOR_OUTLINE: u32 = 0xFF14_171A;

/// True if the arrow mask covers `(row, col)`.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "cursor mask lookup on tiny fixed sprite bounds"
)]
pub(crate) fn cursor_mask_at(row: i32, col: i32) -> bool {
    if row < 0 || col < 0 || row >= CURSOR_H as i32 || col >= CURSOR_W as i32 {
        return false;
    }
    CURSOR_MASK
        .get(row as usize)
        .is_some_and(|bits| bits & (1u16 << col) != 0)
}

/// The screen rectangle the cursor occupies at `(x, y)`. Damaging it before the
/// next `present` repairs the footprint the cursor leaves as it moves.
#[allow(
    clippy::cast_possible_truncation,
    reason = "CURSOR_W/H are small constants"
)]
pub(crate) fn cursor_rect(x: i32, y: i32) -> Rect {
    Rect {
        x,
        y,
        w: CURSOR_W as u32,
        h: CURSOR_H as u32,
    }
}

/// Grows a window rect by `shadow`'s reach, so that damaging the result
/// repairs the shadow band a window leaves behind as it moves.
///
/// Delegates to [`shadow_bounds`] — the same function `nexacore_ui`'s
/// `Canvas::draw_shadow` uses to paint the shadow — instead of a hand-rolled
/// constant pad, so the damage region can never under-cover the actual
/// painted shadow again.
pub(crate) fn shadow_padded(r: Rect, shadow: Shadow) -> Rect {
    shadow_bounds(r, shadow)
}

/// Draws the arrow cursor straight onto the mapped framebuffer at `(ox, oy)`,
/// clipped to the screen. Called after `present` each frame so the cursor
/// floats above the composited desktop.
///
/// # Safety
///
/// `front_va` must be the kernel-assigned framebuffer VA, valid for
/// `stride * screen_h * 4` bytes.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "pixel math on clamped, screen-bounded coordinates"
)]
pub(crate) fn draw_cursor(
    front_va: u64,
    ox: i32,
    oy: i32,
    stride: u32,
    screen_w: u32,
    screen_h: u32,
) {
    let stride_usize = stride as usize;
    for row in 0..CURSOR_H as i32 {
        let py = oy + row;
        if py < 0 || py >= screen_h as i32 {
            continue;
        }
        for col in 0..CURSOR_W as i32 {
            if !cursor_mask_at(row, col) {
                continue;
            }
            let px = ox + col;
            if px < 0 || px >= screen_w as i32 {
                continue;
            }
            let edge = !cursor_mask_at(row - 1, col)
                || !cursor_mask_at(row + 1, col)
                || !cursor_mask_at(row, col - 1)
                || !cursor_mask_at(row, col + 1);
            let color = if edge { CURSOR_OUTLINE } else { CURSOR_FILL };
            let idx = (py as usize) * stride_usize + (px as usize);
            // SAFETY: 0 ≤ py < screen_h and 0 ≤ px < screen_w, so
            // idx < stride * screen_h ≤ the mapped length.
            unsafe {
                core::ptr::write_volatile((front_va as *mut u32).add(idx), color);
            }
        }
    }
}
