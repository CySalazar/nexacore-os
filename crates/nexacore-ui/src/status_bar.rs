//! AI-backend status bar widget (ADR-0043, TASK-21, DE-C6).
//!
//! [`StatusBar`] is an always-visible, full-width strip that shows the live
//! AI backend state:
//!
//! | [`BackendState`] | Indicator colour | Label |
//! |-----------------|-----------------|-------|
//! | [`BackendState::Gpu`] | [`crate::color::SAGE`] | `"AI: GPU  127.0.0.1  NexyAI"` |
//! | [`BackendState::CpuDegraded`] | [`crate::color::BRICK`] | `"AI: CPU (degraded - Ollama unreachable)"` |
//! | [`BackendState::Unknown`] | [`crate::color::MUTED`] | `"AI: status unavailable"` |
//!
//! The widget is updated by calling [`StatusBar::apply`] with a
//! [`BackendStatusEvent`] received from the runtime's `ai_status` IPC
//! channel.  The event's `backend` and `degraded` fields determine the
//! state mapping:
//!
//! - `RemoteGpu` and `!degraded` → [`BackendState::Gpu`]
//! - anything else (degraded flag OR `LocalCpu`) → [`BackendState::CpuDegraded`]
//!
//! Malformed / unanticipated events are **never** produced by this widget:
//! `apply` takes a well-typed [`BackendStatusEvent`] (the decode guard lives
//! in the display image, not here). The widget simply maps the well-typed
//! fields above; no additional validation is needed.
//!
//! ## Layout
//!
//! Call [`StatusBar::layout`] with the full-width [`nexacore_display::geometry::Rect`]
//! you want the bar to occupy before calling [`StatusBar::render`].
//!
//! ## Rendering
//!
//! [`StatusBar::render`] draws:
//!
//! 1. A background fill of `theme.bg_surface` over the whole bar rect.
//! 2. A square indicator box `(bar_h - 8)` pixels on each side, at `x =
//!    theme.padding`, vertically centred.  Coloured by state.
//! 3. The label string, in `theme.text` at `theme.text_scale`, to the right
//!    of the indicator box, also vertically centred.
//!
//! ## `no_std` note
//!
//! This module uses only `core` — no `alloc` is required.
//!
//! ## Quick start
//!
//! ```
//! use nexacore_display::geometry::Rect;
//! use nexacore_types::ai::{BackendKind, BackendStatusEvent};
//! use nexacore_ui::{
//!     canvas::Canvas,
//!     status_bar::{BackendState, StatusBar},
//!     theme::Theme,
//! };
//!
//! let mut bar = StatusBar::new();
//! assert_eq!(bar.state(), BackendState::Unknown);
//!
//! // Lay out the bar in a 640-pixel wide, 28-pixel tall strip.
//! bar.layout(Rect {
//!     x: 0,
//!     y: 0,
//!     w: 640,
//!     h: 28,
//! });
//!
//! // Update from a healthy GPU event.
//! bar.apply(BackendStatusEvent {
//!     backend: BackendKind::RemoteGpu,
//!     healthy: true,
//!     degraded: false,
//! });
//! assert_eq!(bar.state(), BackendState::Gpu);
//!
//! // Render into a pixel buffer.
//! let mut pixels = vec![0u32; 640 * 28];
//! let mut canvas = Canvas::new(&mut pixels, 640, 28).expect("valid");
//! bar.render(&mut canvas, &Theme::nexacore());
//! ```

use nexacore_display::geometry::Rect;
use nexacore_types::ai::{BackendKind, BackendStatusEvent};

use crate::{
    canvas::Canvas,
    color::{BRICK, MUTED, SAGE},
    text::draw_text,
    theme::Theme,
};

// ---------------------------------------------------------------------------
// Static endpoint / model brand constants (ADR-0043 D3)
// ---------------------------------------------------------------------------

// These constants define the remote Ollama endpoint served by the
// runtime image.  They are embedded in `LABEL_GPU` so the display image
// does not need to duplicate them, and are `pub` so `nexacore-ui-demo-image`
// can reference them for its own probe registration.

/// Ollama host used by the runtime image (`RemoteGpu` endpoint).
pub const OLLAMA_HOST: &str = "127.0.0.1";

/// Display name for the AI model shown in the UI.
///
/// This is a **UI label only** — the actual Ollama model tag used in the
/// wire request body (`"gemma4:latest"`) lives in `nexacore-runtime`'s
/// provider config and is intentionally untouched by this constant. Do not
/// propagate this name into `nexacore-runtime`; doing so would break real
/// inference (no Ollama model is literally named `NexyAI`).
pub const OLLAMA_MODEL: &str = "NexyAI";

// Pre-built label strings (static, no alloc needed).
/// Label shown when the AI backend is serving via the remote GPU.
const LABEL_GPU: &str = "AI: GPU  127.0.0.1  NexyAI";

/// Label shown when the AI backend has fallen back to local CPU (degraded).
const LABEL_CPU_DEGRADED: &str = "AI: CPU (degraded - Ollama unreachable)";

/// Label shown before any status event has been received.
const LABEL_UNKNOWN: &str = "AI: status unavailable";

// ---------------------------------------------------------------------------
// BackendState
// ---------------------------------------------------------------------------

/// The AI backend the [`StatusBar`] last observed.
///
/// The initial value before any [`BackendStatusEvent`] arrives is
/// [`BackendState::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendState {
    /// The remote GPU (Ollama) is healthy and serving requests.
    Gpu,
    /// The backend is degraded — either `LocalCpu` is active, or the remote
    /// GPU reported `degraded: true`.
    CpuDegraded,
    /// No status event has been received yet.
    Unknown,
}

// ---------------------------------------------------------------------------
// StatusBar
// ---------------------------------------------------------------------------

/// An always-visible system status bar showing the live AI backend
/// (ADR-0043, DE-C6).
///
/// Renders a coloured state indicator box plus label text:
///
/// - `Gpu` → sage indicator + GPU label
/// - `CpuDegraded` → brick indicator + degraded label
/// - `Unknown` → muted-grey indicator + unavailable label
///
/// ## Lifecycle
///
/// 1. `let mut bar = StatusBar::new();`
/// 2. `bar.layout(strip_rect);` — must be called before `render`.
/// 3. Per incoming [`BackendStatusEvent`]: `bar.apply(event);`
/// 4. Per frame: `bar.render(&mut canvas, &theme);`
pub struct StatusBar {
    /// Current backend state (drives indicator colour and label).
    state: BackendState,
    /// The screen rectangle this bar occupies, set by [`StatusBar::layout`].
    rect: Rect,
}

impl StatusBar {
    /// Creates a new [`StatusBar`] with [`BackendState::Unknown`] and a
    /// zero-sized rect at the origin.
    ///
    /// Call [`StatusBar::layout`] before [`StatusBar::render`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::status_bar::{BackendState, StatusBar};
    ///
    /// let bar = StatusBar::new();
    /// assert_eq!(bar.state(), BackendState::Unknown);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: BackendState::Unknown,
            rect: Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
        }
    }

    /// Returns the current [`BackendState`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::status_bar::{BackendState, StatusBar};
    ///
    /// let bar = StatusBar::new();
    /// assert_eq!(bar.state(), BackendState::Unknown);
    /// ```
    #[must_use]
    #[inline]
    pub fn state(&self) -> BackendState {
        self.state
    }

    /// Updates the bar state from a backend status event.
    ///
    /// ## State-mapping rules
    ///
    /// | `event.backend` | `event.degraded` | New [`BackendState`] |
    /// |-----------------|-----------------|---------------------|
    /// | `RemoteGpu` | `false` | [`BackendState::Gpu`] |
    /// | `RemoteGpu` | `true` | [`BackendState::CpuDegraded`] |
    /// | `LocalCpu` | `false` | [`BackendState::CpuDegraded`] |
    /// | `LocalCpu` | `true` | [`BackendState::CpuDegraded`] |
    ///
    /// The `healthy` field is not used for the visual state — the bar shows
    /// the backend that is *currently serving* (`degraded` qualifies whether
    /// it is doing so under duress), not the connectivity probe result.
    ///
    /// This method is **total**: it accepts every combination of `backend`
    /// and `degraded` without error.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_types::ai::{BackendKind, BackendStatusEvent};
    /// use nexacore_ui::status_bar::{BackendState, StatusBar};
    ///
    /// let mut bar = StatusBar::new();
    ///
    /// bar.apply(BackendStatusEvent {
    ///     backend: BackendKind::RemoteGpu,
    ///     healthy: true,
    ///     degraded: false,
    /// });
    /// assert_eq!(bar.state(), BackendState::Gpu);
    ///
    /// bar.apply(BackendStatusEvent {
    ///     backend: BackendKind::LocalCpu,
    ///     healthy: true,
    ///     degraded: true,
    /// });
    /// assert_eq!(bar.state(), BackendState::CpuDegraded);
    ///
    /// bar.apply(BackendStatusEvent {
    ///     backend: BackendKind::RemoteGpu,
    ///     healthy: false,
    ///     degraded: false,
    /// });
    /// assert_eq!(bar.state(), BackendState::Gpu);
    ///
    /// // A RemoteGpu event with degraded:true -> CpuDegraded (degraded flag wins).
    /// bar.apply(BackendStatusEvent {
    ///     backend: BackendKind::RemoteGpu,
    ///     healthy: true,
    ///     degraded: true,
    /// });
    /// assert_eq!(bar.state(), BackendState::CpuDegraded);
    /// ```
    pub fn apply(&mut self, event: BackendStatusEvent) {
        self.state = state_from_event(event);
    }

    /// Lays the bar out within `bounds`, reserving the full rectangle.
    ///
    /// `bounds` is typically a full-width strip (e.g. 28 px tall) at the
    /// top of the screen.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::status_bar::StatusBar;
    ///
    /// let mut bar = StatusBar::new();
    /// let strip = Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 640,
    ///     h: 28,
    /// };
    /// bar.layout(strip);
    /// assert_eq!(bar.rect(), strip);
    /// ```
    pub fn layout(&mut self, bounds: Rect) {
        self.rect = bounds;
    }

    /// Returns the bar's current laid-out rectangle.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::status_bar::StatusBar;
    ///
    /// let mut bar = StatusBar::new();
    /// let r = Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 800,
    ///     h: 28,
    /// };
    /// bar.layout(r);
    /// assert_eq!(bar.rect(), r);
    /// ```
    #[must_use]
    #[inline]
    pub fn rect(&self) -> Rect {
        self.rect
    }

    /// Renders the status bar into `canvas` using `theme`.
    ///
    /// Drawing order:
    ///
    /// 1. Fill the bar rect with `theme.bg_surface`.
    /// 2. Draw a square indicator box `(bar_h - 8)` px on each side at
    ///    `x = theme.padding`, vertically centred.  The colour is:
    ///    - [`BackendState::Gpu`] → [`crate::color::SAGE`]
    ///    - [`BackendState::CpuDegraded`] → [`crate::color::BRICK`]
    ///    - [`BackendState::Unknown`] → [`crate::color::MUTED`]
    /// 3. Render the label string in `theme.text` at `theme.text_scale`,
    ///    vertically centred, with its left edge at
    ///    `theme.padding * 2 + indicator_size`.
    ///
    /// All drawing is bounds-checked internally by [`Canvas`] — calls with
    /// a rect that is entirely or partially off-canvas are safe and produce
    /// no out-of-bounds writes.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// use nexacore_ui::{canvas::Canvas, status_bar::StatusBar, theme::Theme};
    ///
    /// let mut bar = StatusBar::new();
    /// bar.layout(Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 640,
    ///     h: 28,
    /// });
    ///
    /// let mut pixels = vec![0u32; 640 * 28];
    /// let mut canvas = Canvas::new(&mut pixels, 640, 28).expect("valid");
    /// bar.render(&mut canvas, &Theme::nexacore()); // must not panic
    /// ```
    pub fn render(&self, canvas: &mut Canvas<'_>, theme: &Theme) {
        // 1. Background fill.
        canvas.fill_rect(&self.rect, theme.bg_surface);

        let bar_h = self.rect.h;

        // Indicator box size: bar_h minus 8-px top/bottom margin,
        // minimum 1 to stay visible.
        let ind_size = bar_h.saturating_sub(8).max(1);

        // Vertical centre offset of the indicator within the bar.
        // Integer division by 2 is intentional: we centre in whole pixels.
        #[allow(clippy::integer_division)]
        let v_offset = bar_h.saturating_sub(ind_size) / 2;

        let ind_color = indicator_color(self.state);

        // 2. Indicator box.
        #[allow(clippy::cast_possible_wrap)]
        let ind_x = self.rect.x + theme.padding as i32;
        #[allow(clippy::cast_possible_wrap)]
        let ind_y = self.rect.y + v_offset as i32;

        let ind_rect = Rect {
            x: ind_x,
            y: ind_y,
            w: ind_size,
            h: ind_size,
        };
        canvas.fill_rect(&ind_rect, ind_color);

        // 3. Label text.
        // Text is vertically centred: text_h = GLYPH_H * text_scale.
        let text_h = crate::text::GLYPH_H.saturating_mul(theme.text_scale);
        // Integer division by 2 is intentional: we centre in whole pixels.
        #[allow(clippy::integer_division)]
        let text_v_offset = bar_h.saturating_sub(text_h) / 2;

        // Left edge of text: padding + indicator + padding.
        #[allow(clippy::cast_possible_wrap)]
        let text_x = ind_x + ind_size as i32 + theme.padding as i32;
        #[allow(clippy::cast_possible_wrap)]
        let text_y = self.rect.y + text_v_offset as i32;

        draw_text(
            canvas,
            text_x,
            text_y,
            label_for(self.state),
            theme.text,
            theme.text_scale,
        );
    }
}

impl Default for StatusBar {
    /// Equivalent to [`StatusBar::new`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::status_bar::{BackendState, StatusBar};
    ///
    /// let bar = StatusBar::default();
    /// assert_eq!(bar.state(), BackendState::Unknown);
    /// ```
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Maps a [`BackendStatusEvent`] to a [`BackendState`].
///
/// Rule: `RemoteGpu && !degraded` → `Gpu`; anything else → `CpuDegraded`.
/// The `healthy` field is intentionally not used here — it reflects the
/// connectivity-probe result, whereas `state` reflects what the bar should
/// display to the user about the serving mode.
///
/// Takes by value: `BackendStatusEvent` is `Copy` and 3 bytes wide, so
/// pass-by-value avoids an unnecessary indirection.
fn state_from_event(event: BackendStatusEvent) -> BackendState {
    match event.backend {
        BackendKind::RemoteGpu if !event.degraded => BackendState::Gpu,
        _ => BackendState::CpuDegraded,
    }
}

/// Returns the ARGB indicator colour for `state`.
fn indicator_color(state: BackendState) -> u32 {
    match state {
        BackendState::Gpu => SAGE,
        BackendState::CpuDegraded => BRICK,
        BackendState::Unknown => MUTED,
    }
}

/// Returns the static label string for `state`.
fn label_for(state: BackendState) -> &'static str {
    match state {
        BackendState::Gpu => LABEL_GPU,
        BackendState::CpuDegraded => LABEL_CPU_DEGRADED,
        BackendState::Unknown => LABEL_UNKNOWN,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use nexacore_display::geometry::Rect;
    use nexacore_types::ai::{BackendKind, BackendStatusEvent};

    use super::{BackendState, StatusBar};
    use crate::{
        canvas::Canvas,
        color::{BRICK, MUTED, SAGE},
        theme::Theme,
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn gpu_event(degraded: bool) -> BackendStatusEvent {
        BackendStatusEvent {
            backend: BackendKind::RemoteGpu,
            healthy: true,
            degraded,
        }
    }

    fn cpu_event(degraded: bool) -> BackendStatusEvent {
        BackendStatusEvent {
            backend: BackendKind::LocalCpu,
            healthy: true,
            degraded,
        }
    }

    /// The canonical bar rect for render tests.
    fn bar_rect() -> Rect {
        Rect {
            x: 0,
            y: 0,
            w: 256,
            h: 28,
        }
    }

    /// Build a canvas backed by a `&mut [u32]` slice of the given dimensions.
    fn make_canvas(pixels: &mut [u32], w: u32, h: u32) -> Canvas<'_> {
        Canvas::new(pixels, w, h).expect("valid dimensions")
    }

    // -----------------------------------------------------------------------
    // Transition tests: Gpu -> CpuDegraded -> Gpu
    // -----------------------------------------------------------------------

    #[test]
    fn transitions_gpu_cpu_gpu() {
        let mut bar = StatusBar::new();
        assert_eq!(
            bar.state(),
            BackendState::Unknown,
            "initial state is Unknown"
        );

        // RemoteGpu && !degraded -> Gpu
        bar.apply(gpu_event(false));
        assert_eq!(bar.state(), BackendState::Gpu, "RemoteGpu/healthy -> Gpu");

        // LocalCpu && degraded -> CpuDegraded
        bar.apply(cpu_event(true));
        assert_eq!(
            bar.state(),
            BackendState::CpuDegraded,
            "LocalCpu/degraded -> CpuDegraded"
        );

        // Back to Gpu
        bar.apply(gpu_event(false));
        assert_eq!(bar.state(), BackendState::Gpu, "RemoteGpu/!degraded -> Gpu");
    }

    #[test]
    fn degraded_flag_wins_over_remote_gpu() {
        // A RemoteGpu event with degraded:true must produce CpuDegraded.
        let mut bar = StatusBar::new();
        bar.apply(gpu_event(true));
        assert_eq!(
            bar.state(),
            BackendState::CpuDegraded,
            "RemoteGpu with degraded:true -> CpuDegraded"
        );
    }

    #[test]
    fn all_four_event_combinations() {
        // Cover every combination: backend x degraded.
        let combinations = [
            (BackendKind::RemoteGpu, false, BackendState::Gpu),
            (BackendKind::RemoteGpu, true, BackendState::CpuDegraded),
            (BackendKind::LocalCpu, false, BackendState::CpuDegraded),
            (BackendKind::LocalCpu, true, BackendState::CpuDegraded),
        ];

        for (backend, degraded, expected) in combinations {
            let mut bar = StatusBar::new();
            bar.apply(BackendStatusEvent {
                backend,
                healthy: true,
                degraded,
            });
            assert_eq!(
                bar.state(),
                expected,
                "backend={backend:?} degraded={degraded} -> {expected:?}"
            );
        }
    }

    #[test]
    fn apply_never_panics_with_all_field_combinations() {
        // Feed all 2x2x2 = 8 field combinations; confirm totality.
        let mut bar = StatusBar::new();
        for backend in [BackendKind::RemoteGpu, BackendKind::LocalCpu] {
            for healthy in [false, true] {
                for degraded in [false, true] {
                    bar.apply(BackendStatusEvent {
                        backend,
                        healthy,
                        degraded,
                    });
                }
            }
        }
        // Must reach here without panicking.
        // The final state is whatever the last event produced; we just
        // verify no panic occurred.
        let _ = bar.state();
    }

    // -----------------------------------------------------------------------
    // Render tests: indicator pixel colour reflects state
    // -----------------------------------------------------------------------

    /// Returns the pixel at the centre of the indicator box.
    ///
    /// With the default theme (`padding = 8`) and a 28-px bar height the
    /// indicator is `bar_h - 8 = 20` px square, top-left at
    /// `(padding, (bar_h - ind_size)/2) = (8, 4)`.
    /// The centre pixel is at `(8 + 20/2, 4 + 20/2) = (18, 14)`.
    #[allow(clippy::integer_division)]
    fn indicator_center_pixel(pixels: &[u32], w: u32) -> u32 {
        let theme = Theme::nexacore();
        let bar_h: u32 = 28;
        let ind_size = bar_h.saturating_sub(8).max(1); // 20
        let v_offset = bar_h.saturating_sub(ind_size) / 2; // 4
        let ind_x = theme.padding; // 8
        let ind_y = v_offset; // 4
        let cx = ind_x + ind_size / 2; // 18
        let cy = ind_y + ind_size / 2; // 14
        pixels[(cy as usize) * (w as usize) + (cx as usize)]
    }

    #[test]
    fn render_gpu_indicator_is_sage() {
        let mut bar = StatusBar::new();
        bar.layout(bar_rect());
        bar.apply(gpu_event(false));

        let (w, h) = (256u32, 28u32);
        let mut pixels = alloc::vec![0u32; (w * h) as usize];
        {
            let mut canvas = make_canvas(&mut pixels, w, h);
            bar.render(&mut canvas, &Theme::nexacore());
        }

        assert_eq!(
            indicator_center_pixel(&pixels, w),
            SAGE,
            "Gpu state: indicator pixel must be SAGE"
        );
    }

    #[test]
    fn render_cpu_degraded_indicator_is_brick() {
        let mut bar = StatusBar::new();
        bar.layout(bar_rect());
        bar.apply(cpu_event(true));

        let (w, h) = (256u32, 28u32);
        let mut pixels = alloc::vec![0u32; (w * h) as usize];
        {
            let mut canvas = make_canvas(&mut pixels, w, h);
            bar.render(&mut canvas, &Theme::nexacore());
        }

        assert_eq!(
            indicator_center_pixel(&pixels, w),
            BRICK,
            "CpuDegraded state: indicator pixel must be BRICK"
        );
    }

    #[test]
    fn render_unknown_indicator_is_muted() {
        let mut bar = StatusBar::new();
        bar.layout(bar_rect());
        // Do NOT apply any event — state stays Unknown.

        let (w, h) = (256u32, 28u32);
        let mut pixels = alloc::vec![0u32; (w * h) as usize];
        {
            let mut canvas = make_canvas(&mut pixels, w, h);
            bar.render(&mut canvas, &Theme::nexacore());
        }

        assert_eq!(
            indicator_center_pixel(&pixels, w),
            MUTED,
            "Unknown state: indicator pixel must be MUTED"
        );
    }

    // -----------------------------------------------------------------------
    // Robustness: render with rect partly off-canvas does not panic
    // -----------------------------------------------------------------------

    #[test]
    fn render_rect_partly_off_canvas_does_not_panic() {
        let mut bar = StatusBar::new();
        // Lay out a rect that is partly outside the canvas (canvas is 32x8;
        // the bar starts at x=20, so it overflows the right edge).
        bar.layout(Rect {
            x: 20,
            y: 0,
            w: 640,
            h: 28,
        });
        bar.apply(gpu_event(false));

        let (w, h) = (32u32, 8u32);
        let mut pixels = alloc::vec![0u32; (w * h) as usize];
        let mut canvas = make_canvas(&mut pixels, w, h);
        bar.render(&mut canvas, &Theme::nexacore()); // must not panic
        assert_eq!(pixels.len(), (w * h) as usize, "buffer length unchanged");
    }

    #[test]
    fn render_zero_size_rect_does_not_panic() {
        let mut bar = StatusBar::new();
        bar.layout(Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        });

        let (w, h) = (64u32, 16u32);
        let mut pixels = alloc::vec![0u32; (w * h) as usize];
        let mut canvas = make_canvas(&mut pixels, w, h);
        bar.render(&mut canvas, &Theme::nexacore()); // must not panic
    }

    // -----------------------------------------------------------------------
    // State-machine: rapid successive apply calls
    // -----------------------------------------------------------------------

    #[test]
    fn rapid_apply_last_event_wins() {
        let mut bar = StatusBar::new();
        for _ in 0..100 {
            bar.apply(gpu_event(false));
            bar.apply(cpu_event(true));
        }
        assert_eq!(bar.state(), BackendState::CpuDegraded);
        bar.apply(gpu_event(false));
        assert_eq!(bar.state(), BackendState::Gpu);
    }
}
