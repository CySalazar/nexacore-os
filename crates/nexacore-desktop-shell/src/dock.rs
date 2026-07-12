//! Vertical dock rendering (mockup parity).
//!
//! The mockup's dock: a 64px-wide translucent glass panel pinned 14px from
//! the left edge, holding the launcher (brand-mark) tile, four app tiles,
//! a `Settings` tile, and two hairline separators splitting the launcher
//! from the app group and the app group from `Settings`. Running apps get a
//! sage indicator bar bleeding out of the tile's left edge.
//!
//! ## Layout formula (`PANEL_H`, [`tile_rects`])
//!
//! The panel's height is a fixed function of the *standard* dock content —
//! 6 tiles + 2 separators + 7 inter-slot gaps + top/bottom padding — **not**
//! of the actual screen height; [`panel_rect`] only uses `screen_h` to
//! vertically centre that fixed-height panel (the mockup pins the panel at
//! `y = 120` on an 820px-tall screen with a taller, hand-picked box height;
//! centring a content-derived height generalizes that to arbitrary screen
//! sizes, per the task brief). [`tile_rects`] walks `model.tiles` and places
//! a separator immediately before a [`TileGlyph::Files`] or
//! [`TileGlyph::Settings`] tile (unless it is the first tile), which
//! reproduces the mockup's fixed ordering for [`DockModel::standard`] while
//! degrading gracefully (no separators at all) for ad-hoc models such as the
//! single-tile one used by this module's `running_indicator` test.
//!
//! ## Coordinate convention (screen vs. canvas-local)
//!
//! [`panel_rect`] and [`tile_rects`] return **screen coordinates** (the
//! panel's `x` starts at [`DOCK_X`]); callers map those onto whatever
//! desktop-sized backdrop buffer they maintain. [`render`], by contrast,
//! draws into a small canvas the caller allocates just for the dock strip;
//! see its doc comment for the exact canvas-local convention.
//!
//! ## Blend contract and the rounded-rect approximation
//!
//! Same `Canvas::blend_pixel` contract documented in `menubar.rs`: coverage
//! carries the alpha, `color`'s own alpha byte is ignored. Non-rounded
//! translucent fills (the 1px panel border, the 34×1 separators) are drawn
//! with a per-pixel blend loop passing the real alpha as `coverage`, exactly
//! like `menubar.rs`'s chrome tint. Rounded translucent fills (the panel
//! background, the tile backgrounds) instead use
//! [`Canvas::fill_rounded_rect`], which forces full coverage in the
//! interior — so they are pre-blended by hand to an **opaque** approximate
//! colour, over a representative dark backdrop, the same trade-off
//! `menubar.rs` documents for its AI-health pill background.

use alloc::vec::Vec;

use nexacore_display::geometry::Rect;
use nexacore_ui::canvas::Canvas;

use crate::{
    stroke::{draw_brand_mark, stroke_circle, stroke_line},
    tokens::ShellTokens,
};

/// Dock panel's left edge, screen coordinates (mockup: 14px from the left).
pub const DOCK_X: i32 = 14;
/// Dock panel width (mockup: 64px).
pub const DOCK_W: u32 = 64;
/// One tile's side length (mockup: 48×48).
pub const TILE: u32 = 48;
/// Tile corner radius (mockup: 14px).
pub const TILE_RADIUS: u32 = 14;
/// Panel corner radius (mockup: 20px).
pub const PANEL_RADIUS: u32 = 20;

/// Vertical padding above the first slot and below the last (mockup:
/// `padding: 9px 8px`, the `9px` component).
const PAD_V: u32 = 9;
/// Gap between every pair of adjacent slots — tile-to-tile,
/// tile-to-separator, or separator-to-tile (mockup: `gap: 7px`).
const GAP: u32 = 7;
/// Separator width, centred in the panel (mockup: `width:34px`).
const SEP_W: u32 = 34;
/// Separator height (mockup: `height:1px`).
const SEP_H: u32 = 1;
/// A tile's horizontal offset from the panel's left edge, centring `TILE`
/// inside `DOCK_W`.
#[allow(
    clippy::integer_division,
    reason = "exact halving of an even pixel gap (64-48=16); no fractional remainder is lost"
)]
const TILE_X_OFFSET: u32 = (DOCK_W - TILE) / 2;

/// Standard dock content: launcher + 4 app tiles + settings tile.
const STD_TILE_COUNT: u32 = 6;
/// Standard dock content: one separator before `Files`, one before
/// `Settings`.
const STD_SEP_COUNT: u32 = 2;
/// Standard dock content: 8 slots (6 tiles + 2 separators) ⇒ 7 gaps between
/// them.
const STD_GAP_COUNT: u32 = 7;
/// Fixed panel content height for the standard dock: `6*48 + 2*1 + 7*7`.
const PANEL_CONTENT_H: u32 = STD_TILE_COUNT * TILE + STD_SEP_COUNT * SEP_H + STD_GAP_COUNT * GAP;
/// Fixed panel height, content plus top/bottom padding.
const PANEL_H: u32 = PANEL_CONTENT_H + 2 * PAD_V;

/// Left margin `render`'s canvas reserves ahead of the panel's own left edge.
///
/// So the running-indicator bar (drawn at `tile.x − 6`, 3px wide) has room to
/// paint without being clipped by the canvas bounds. Part of [`render`]'s
/// canvas convention (see its doc comment for the full convention) and
/// exported so callers outside this crate that need to size a scratch buffer
/// for that canvas (e.g. `omni-apps-image`'s chrome repaint pass) share this
/// single value instead of hand-mirroring it.
pub const RENDER_CANVAS_MARGIN: u32 = 16;

/// Horizontal nudge applied to a hovered tile's content (mockup: `tileEnter`
/// sets `transform: translateX(5px)` on the tile element).
///
/// In the mockup the transform is applied to the whole tile `<div>`, and a
/// CSS transform moves absolutely-positioned children along with it — so the
/// running-indicator span (`position:absolute; left:-6px` inside the tile,
/// mockup lines 288–293) shifts right together with the tile background and
/// glyph. [`render`] reproduces that: everything drawn for the hovered tile —
/// rounded-rect background, glyph, and running indicator — moves by this
/// amount.
///
/// Clipping note: the nudge stays inside [`render`]'s canvas in both of its
/// conventions. With `panel_local == true` the canvas is `DOCK_W +
/// RENDER_CANVAS_MARGIN = 80`px wide and the nudged tile spans `x = 29..77`;
/// with `panel_local == false` it spans `13..61` of the 64px panel. The
/// nudged indicator's left edge (`tile.x + 5 − 6`) also stays ≥ 0 in both.
/// No clamping is needed.
const HOVER_NUDGE_X: i32 = 5;

// --- Colours -------------------------------------------------------------

/// Stroke-glyph colour (mockup: `color:#F4EBD0`, cream).
const GLYPH_COLOR: u32 = 0xFFF4_EBD0;
/// Panel background, pre-blended to opaque: `rgba(18,22,25,0.92)` over a
/// representative dark backdrop (`ShellTokens::dark().bg_canvas`,
/// `#14171A`) → `18*0.92+20*0.08=18.16`, `22*0.92+23*0.08=22.08`,
/// `25*0.92+26*0.08=25.08` ⇒ `#121619` (the source colour barely moves at
/// 92% alpha over a similarly-dark backdrop).
const PANEL_BG_PREBLEND: u32 = 0xFF12_1619;
/// Tile background, pre-blended to opaque: `rgba(244,235,208,0.09)` over the
/// panel background above (`#121619`) → `244*0.09+18*0.91=38.34`,
/// `235*0.09+22*0.91=41.17`, `208*0.09+25*0.91=41.47` ⇒ `#262929`.
const TILE_BG_PREBLEND: u32 = 0xFF26_2929;
/// Hovered tile background, pre-blended to opaque the same way as
/// [`TILE_BG_PREBLEND`] but at the mockup's hover alpha step
/// (`rgba(244,235,208,0.17)`, `tileEnter` in the mockup script) over the same
/// panel background (`#121619`) → `244*0.17+18*0.83=56.42`,
/// `235*0.17+22*0.83=58.21`, `208*0.17+25*0.83=56.11` ⇒ `#383A38`.
const TILE_BG_HOVER_PREBLEND: u32 = 0xFF38_3A38;
/// Border/separator RGB (mockup: `rgba(255,255,255,...)`, white); alpha is
/// carried by the paired `..._COV` below, per the `blend_pixel` contract.
const WHITE_RGB: u32 = 0x00FF_FFFF;
/// Panel border coverage (`rgba(...,0.10)`, `round(0.10 * 255)`).
const BORDER_COV: u8 = 26;
/// Separator coverage (`rgba(...,0.11)`, `round(0.11 * 255)`).
const SEP_COV: u8 = 28;

/// Which glyph a dock tile draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileGlyph {
    /// The brand mark (opens the launcher).
    Logo,
    /// Folder glyph (Files app).
    Files,
    /// Terminal window glyph.
    Terminal,
    /// Assistant/person glyph (NexaCore Helper).
    Helper,
    /// Concentric-rings glyph (system monitor).
    Monitor,
    /// Control-center building glyph (settings).
    Settings,
}

/// One dock slot: a glyph, its running state, and a display title (used for
/// tooltips/accessibility by callers; unused by [`render`] itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DockTile {
    /// Which glyph this tile draws.
    pub glyph: TileGlyph,
    /// Whether the app is currently running (draws the sage indicator bar).
    pub running: bool,
    /// Human-readable title (tooltip text).
    pub title: &'static str,
}

/// Everything the dock needs to lay out and render one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockModel {
    /// Tiles in top-to-bottom order. Separators are not modelled explicitly;
    /// [`tile_rects`] and [`render`] insert one before a [`TileGlyph::Files`]
    /// or [`TileGlyph::Settings`] tile that isn't first, reproducing the
    /// mockup's fixed ordering for [`DockModel::standard`].
    pub tiles: Vec<DockTile>,
}

impl DockModel {
    /// Builds the standard dock: launcher, `Files`, `Terminal`, `Helper`,
    /// `Monitor`, `Settings`, in the mockup's fixed order, with each app
    /// tile's running state supplied by the caller (the launcher tile is
    /// never "running").
    #[must_use]
    #[allow(
        clippy::fn_params_excessive_bools,
        reason = "interface fixed by the task brief: one running flag per app tile, in mockup order"
    )]
    pub fn standard(
        files_running: bool,
        terminal_running: bool,
        helper_running: bool,
        monitor_running: bool,
        settings_running: bool,
    ) -> Self {
        Self {
            tiles: alloc::vec![
                DockTile {
                    glyph: TileGlyph::Logo,
                    running: false,
                    title: "NexaCore menu & search",
                },
                DockTile {
                    glyph: TileGlyph::Files,
                    running: files_running,
                    title: "Files",
                },
                DockTile {
                    glyph: TileGlyph::Terminal,
                    running: terminal_running,
                    title: "Terminal",
                },
                DockTile {
                    glyph: TileGlyph::Helper,
                    running: helper_running,
                    title: "NexaCore Helper",
                },
                DockTile {
                    glyph: TileGlyph::Monitor,
                    running: monitor_running,
                    title: "System Monitor",
                },
                DockTile {
                    glyph: TileGlyph::Settings,
                    running: settings_running,
                    title: "Control Center",
                },
            ],
        }
    }
}

/// Whether a separator is drawn immediately before a tile of this glyph
/// (when it isn't the very first tile) — see the module doc comment.
fn separator_before(glyph: TileGlyph) -> bool {
    matches!(glyph, TileGlyph::Files | TileGlyph::Settings)
}

/// The tile rects and separator y-positions for `tiles`, laid out top to
/// bottom starting at `(panel_x, panel_y)` in whatever coordinate space the
/// caller supplies (screen for [`tile_rects`], canvas-local for [`render`]).
#[allow(
    clippy::cast_possible_wrap,
    reason = "small positive pixel metrics accumulated into an i32 cursor"
)]
fn layout(panel_x: i32, panel_y: i32, tiles: &[DockTile]) -> (Vec<Rect>, Vec<i32>) {
    let tile_x = panel_x + TILE_X_OFFSET as i32;
    let mut y = panel_y + PAD_V as i32;
    let mut rects = Vec::with_capacity(tiles.len());
    let mut separators = Vec::new();
    for (i, tile) in tiles.iter().enumerate() {
        if i > 0 {
            y += GAP as i32;
            if separator_before(tile.glyph) {
                separators.push(y);
                y += SEP_H as i32 + GAP as i32;
            }
        }
        rects.push(Rect {
            x: tile_x,
            y,
            w: TILE,
            h: TILE,
        });
        y += TILE as i32;
    }
    (rects, separators)
}

/// The dock panel's rect in screen coordinates.
///
/// `x = `[`DOCK_X`]`, width `[`DOCK_W`], a fixed height derived from the
/// standard dock's content (see the module doc comment), vertically centred
/// on a `screen_h`-tall screen.
#[must_use]
#[allow(
    clippy::cast_possible_wrap,
    clippy::integer_division,
    reason = "screen_h is a small positive pixel metric; centring by floor-division is the \
              intended behaviour (matches the test's own free/2 floor-division)"
)]
pub fn panel_rect(screen_h: u32) -> Rect {
    let y = (screen_h as i32 - PANEL_H as i32) / 2;
    Rect {
        x: DOCK_X,
        y,
        w: DOCK_W,
        h: PANEL_H,
    }
}

/// One 48×48 rect per tile in `model.tiles`, in screen coordinates.
///
/// Centred inside the [`panel_rect`] for `screen_h`, top to bottom in
/// `model.tiles` order. Separator slots are not returned (`rects.len() ==
/// model.tiles.len()`), only their vertical footprint.
#[must_use]
pub fn tile_rects(screen_h: u32, model: &DockModel) -> Vec<Rect> {
    let panel = panel_rect(screen_h);
    layout(panel.x, panel.y, &model.tiles).0
}

/// Draws the 1px translucent border around `panel`'s straight edges.
///
/// This ignores `panel`'s rounded corners (a straight rectangle outline
/// rather than one following [`PANEL_RADIUS`]) — the same "flat approximation
/// of a rounded translucent edge" trade-off documented at the top of this
/// module for the panel/tile fills, applied here to a stroke instead of a
/// fill.
#[allow(clippy::cast_possible_wrap, reason = "small positive pixel metrics")]
fn draw_panel_border(canvas: &mut Canvas<'_>, panel: &Rect) {
    let x0 = panel.x;
    let x1 = panel.x + panel.w as i32 - 1;
    let y0 = panel.y;
    let y1 = panel.y + panel.h as i32 - 1;
    let mut x = x0;
    while x <= x1 {
        canvas.blend_pixel(x, y0, WHITE_RGB, BORDER_COV);
        canvas.blend_pixel(x, y1, WHITE_RGB, BORDER_COV);
        x += 1;
    }
    let mut y = y0;
    while y <= y1 {
        canvas.blend_pixel(x0, y, WHITE_RGB, BORDER_COV);
        canvas.blend_pixel(x1, y, WHITE_RGB, BORDER_COV);
        y += 1;
    }
}

/// Draws one 34×1 translucent separator, horizontally centred in the panel,
/// at local row `y`.
#[allow(
    clippy::cast_possible_wrap,
    clippy::integer_division,
    reason = "small positive pixel metrics; exact halving of an even gap (64-34=30)"
)]
fn draw_separator(canvas: &mut Canvas<'_>, panel_x: i32, y: i32) {
    let x0 = panel_x + ((DOCK_W - SEP_W) / 2) as i32;
    let x1 = x0 + SEP_W as i32;
    let mut x = x0;
    while x < x1 {
        canvas.blend_pixel(x, y, WHITE_RGB, SEP_COV);
        x += 1;
    }
}

/// Draws the sage running-indicator: a round-capped 3px-wide, 16px-tall bar
/// (`stroke_line`'s round caps give the "dot-capped bar" look from the
/// brief without a separate `fill_dot` call) at the tile's left edge minus
/// 6px, vertically centred on the tile.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry; distance-field stroking is float-based"
)]
fn draw_running_indicator(canvas: &mut Canvas<'_>, tile: &Rect, color: u32) {
    let cx = tile.x as f32 - 4.5; // bar left edge at tile.x-6, width 3 ⇒ centre at tile.x-4.5
    let cy = tile.y as f32 + TILE as f32 * 0.5;
    stroke_line(canvas, cx, cy - 6.5, cx, cy + 6.5, 3.0, color);
}

/// Draws the folder glyph (Files) as a closed 5-segment outline: three plain
/// sides (left, bottom, right) and a two-segment top that steps up into a
/// tab, tracing a simplification of the mockup's rounded-tab folder path.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry; distance-field stroking is float-based"
)]
fn draw_files_glyph(canvas: &mut Canvas<'_>, cx: f32, cy: f32) {
    let x0 = cx - 9.5;
    let x1 = cx + 9.5;
    let y_top = cy - 2.0;
    let y_bottom = cy + 7.0;
    let peak = (cx - 3.0, cy - 6.5);
    stroke_line(canvas, x1, y_top, peak.0, peak.1, 1.5, GLYPH_COLOR);
    stroke_line(canvas, peak.0, peak.1, x0, y_top, 1.5, GLYPH_COLOR);
    stroke_line(canvas, x0, y_top, x0, y_bottom, 1.5, GLYPH_COLOR);
    stroke_line(canvas, x0, y_bottom, x1, y_bottom, 1.5, GLYPH_COLOR);
    stroke_line(canvas, x1, y_bottom, x1, y_top, 1.5, GLYPH_COLOR);
}

/// Draws the terminal glyph: an 18×15 rect border, a right-pointing chevron
/// prompt, and an underscore cursor.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry; distance-field stroking is float-based"
)]
fn draw_terminal_glyph(canvas: &mut Canvas<'_>, cx: f32, cy: f32) {
    let x0 = cx - 9.0;
    let x1 = cx + 9.0;
    let y0 = cy - 7.5;
    let y1 = cy + 7.5;
    stroke_line(canvas, x0, y0, x1, y0, 1.6, GLYPH_COLOR);
    stroke_line(canvas, x1, y0, x1, y1, 1.6, GLYPH_COLOR);
    stroke_line(canvas, x1, y1, x0, y1, 1.6, GLYPH_COLOR);
    stroke_line(canvas, x0, y1, x0, y0, 1.6, GLYPH_COLOR);
    // Chevron prompt.
    stroke_line(canvas, cx - 4.0, cy - 2.0, cx - 1.0, cy, 1.4, GLYPH_COLOR);
    stroke_line(canvas, cx - 1.0, cy, cx - 4.0, cy + 2.0, 1.4, GLYPH_COLOR);
    // Underscore cursor.
    stroke_line(
        canvas,
        cx - 1.0,
        cy + 4.0,
        cx + 5.0,
        cy + 4.0,
        1.4,
        GLYPH_COLOR,
    );
}

/// Draws the helper (assistant) glyph: a circular head with a small "+"
/// badge, and shoulders approximated by an open three-segment trapezoid.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry; distance-field stroking is float-based"
)]
fn draw_helper_glyph(canvas: &mut Canvas<'_>, cx: f32, cy: f32) {
    let head_cy = cy - 3.0;
    stroke_circle(canvas, cx, head_cy, 4.5, 1.5, GLYPH_COLOR);
    // Plus badge on the head.
    stroke_line(
        canvas,
        cx - 2.0,
        head_cy,
        cx + 2.0,
        head_cy,
        1.3,
        GLYPH_COLOR,
    );
    stroke_line(
        canvas,
        cx,
        head_cy - 2.0,
        cx,
        head_cy + 2.0,
        1.3,
        GLYPH_COLOR,
    );
    // Shoulders: open trapezoid (left diagonal, top, right diagonal).
    stroke_line(
        canvas,
        cx - 10.0,
        cy + 9.0,
        cx - 7.0,
        cy + 2.0,
        1.5,
        GLYPH_COLOR,
    );
    stroke_line(
        canvas,
        cx - 7.0,
        cy + 2.0,
        cx + 7.0,
        cy + 2.0,
        1.5,
        GLYPH_COLOR,
    );
    stroke_line(
        canvas,
        cx + 7.0,
        cy + 2.0,
        cx + 10.0,
        cy + 9.0,
        1.5,
        GLYPH_COLOR,
    );
}

/// Draws the monitor glyph: three concentric rings (radii 9, 5.5, 2).
#[allow(
    clippy::float_arithmetic,
    reason = "small glyph geometry; distance-field stroking is float-based"
)]
fn draw_monitor_glyph(canvas: &mut Canvas<'_>, cx: f32, cy: f32) {
    stroke_circle(canvas, cx, cy, 9.0, 1.5, GLYPH_COLOR);
    stroke_circle(canvas, cx, cy, 5.5, 1.5, GLYPH_COLOR);
    stroke_circle(canvas, cx, cy, 2.0, 1.5, GLYPH_COLOR);
}

/// Draws the settings ("control centre") glyph: a two-segment roof
/// triangle, top and bottom horizontals, and four evenly spaced verticals
/// standing in for the mockup's building-with-columns icon.
#[allow(
    clippy::float_arithmetic,
    reason = "small glyph geometry; distance-field stroking is float-based"
)]
fn draw_settings_glyph(canvas: &mut Canvas<'_>, cx: f32, cy: f32) {
    let apex = (cx, cy - 9.0);
    let base_left = (cx - 9.0, cy - 4.0);
    let base_right = (cx + 9.0, cy - 4.0);
    let bottom_y = cy + 7.0;
    stroke_line(
        canvas,
        apex.0,
        apex.1,
        base_left.0,
        base_left.1,
        1.5,
        GLYPH_COLOR,
    );
    stroke_line(
        canvas,
        apex.0,
        apex.1,
        base_right.0,
        base_right.1,
        1.5,
        GLYPH_COLOR,
    );
    stroke_line(
        canvas,
        base_left.0,
        base_left.1,
        base_right.0,
        base_right.1,
        1.5,
        GLYPH_COLOR,
    );
    stroke_line(
        canvas,
        cx - 9.0,
        bottom_y,
        cx + 9.0,
        bottom_y,
        1.5,
        GLYPH_COLOR,
    );
    for x in [cx - 9.0, cx - 3.0, cx + 3.0, cx + 9.0] {
        stroke_line(canvas, x, base_left.1, x, bottom_y, 1.5, GLYPH_COLOR);
    }
}

/// Draws one dock tile glyph, centred in `r` (any square-ish size — the
/// centre is derived from `r`'s own dimensions, not a fixed tile size, so
/// this is also reused by `launcher.rs` for 32×32 result-row icons).
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry; distance-field stroking is float-based"
)]
pub(crate) fn draw_glyph(
    canvas: &mut Canvas<'_>,
    tokens: &ShellTokens,
    glyph: TileGlyph,
    r: &Rect,
) {
    let cx = r.x as f32 + r.w as f32 * 0.5;
    let cy = r.y as f32 + r.h as f32 * 0.5;
    match glyph {
        // Dock logo is hardcoded `#F4EBD0` (cream) in the mockup because the
        // dock panel is always dark, theme-invariant.
        TileGlyph::Logo => draw_brand_mark(canvas, cx, cy, 1.0, GLYPH_COLOR, tokens.brick),
        TileGlyph::Files => draw_files_glyph(canvas, cx, cy),
        TileGlyph::Terminal => draw_terminal_glyph(canvas, cx, cy),
        TileGlyph::Helper => draw_helper_glyph(canvas, cx, cy),
        TileGlyph::Monitor => draw_monitor_glyph(canvas, cx, cy),
        TileGlyph::Settings => draw_settings_glyph(canvas, cx, cy),
    }
}

/// Renders the dock panel and all its tiles into `canvas`.
///
/// ## Canvas convention
///
/// `canvas` holds the backdrop strip for the dock (same blend-over contract
/// as the menu bar): its width is the panel width ([`DOCK_W`]) plus a
/// [`RENDER_CANVAS_MARGIN`]-px left margin when `panel_local` is `true`, and its
/// height is exactly the panel height. All drawing is in canvas-local
/// coordinates: with `panel_local == true` the panel's left edge sits at
/// canvas `x = 16` (not `0`), reserving room for the running-indicator bar
/// that paints at `tile.x − 6`. With `panel_local == false` there is no
/// reserved margin and the panel's left edge sits at canvas `x = 0` (the
/// caller is responsible for giving the canvas enough left padding itself,
/// or accepting that the indicator clips at the canvas edge). This is
/// unlike [`panel_rect`]/[`tile_rects`], which return **screen**
/// coordinates — the caller maps between the two when copying the backdrop
/// into (and the result back out of) this canvas.
///
/// ## Hover
///
/// `hover` is an index into `model.tiles` (the same indexing the pointer
/// router's `HoverState::dock_tile` uses). The hovered tile draws with the
/// stepped-up `TILE_BG_HOVER_PREBLEND` fill and its whole content —
/// background, glyph, and running indicator — nudged `HOVER_NUDGE_X`px
/// right, matching the mockup's `tileEnter` behaviour (see the constants'
/// doc comments). An out-of-range index simply hovers nothing.
#[allow(clippy::cast_possible_wrap, reason = "small positive pixel metrics")]
pub fn render(
    canvas: &mut Canvas<'_>,
    tokens: &ShellTokens,
    model: &DockModel,
    panel_local: bool,
    hover: Option<usize>,
) {
    let margin = if panel_local {
        RENDER_CANVAS_MARGIN as i32
    } else {
        0
    };
    let panel = Rect {
        x: margin,
        y: 0,
        w: DOCK_W,
        h: canvas.height(),
    };
    canvas.fill_rounded_rect(&panel, PANEL_RADIUS, PANEL_BG_PREBLEND);
    draw_panel_border(canvas, &panel);

    let (rects, separators) = layout(margin, 0, &model.tiles);
    for sep_y in separators {
        draw_separator(canvas, margin, sep_y);
    }
    for (i, (tile, r)) in model.tiles.iter().zip(rects.iter()).enumerate() {
        let hovered = hover == Some(i);
        let draw_rect = if hovered {
            Rect {
                x: r.x + HOVER_NUDGE_X,
                ..*r
            }
        } else {
            *r
        };
        let fill = if hovered {
            TILE_BG_HOVER_PREBLEND
        } else {
            TILE_BG_PREBLEND
        };
        canvas.fill_rounded_rect(&draw_rect, TILE_RADIUS, fill);
        if tile.running {
            draw_running_indicator(canvas, &draw_rect, tokens.sage);
        }
        draw_glyph(canvas, tokens, tile.glyph, &draw_rect);
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::integer_division,
    reason = "test literals are small positive pixel metrics, verbatim from the task brief; \
              scanned coordinates are non-negative canvas-local pixels"
)]
mod tests {
    use nexacore_ui::canvas::Canvas;

    use super::*;
    use crate::tokens::ShellTokens;

    #[test]
    fn standard_model_lists_six_tiles_in_mockup_order() {
        let m = DockModel::standard(false, true, true, false, false);
        let glyphs: alloc::vec::Vec<_> = m.tiles.iter().map(|t| t.glyph).collect();
        assert_eq!(
            glyphs,
            [
                TileGlyph::Logo,
                TileGlyph::Files,
                TileGlyph::Terminal,
                TileGlyph::Helper,
                TileGlyph::Monitor,
                TileGlyph::Settings
            ]
        );
        assert!(m.tiles[2].running && m.tiles[3].running);
        assert!(!m.tiles[1].running);
    }

    #[test]
    fn draw_glyph_centres_on_the_rects_own_size_not_a_hardcoded_tile() {
        // A 32×32 rect at (100, 100): centre must be (116, 116), not the
        // 48×48-tile centre (124, 124) the old hardcoded calc would have used.
        let buf = alloc::vec![0u32; 300 * 300];
        let tokens = ShellTokens::dark();
        let small = Rect {
            x: 100,
            y: 100,
            w: 32,
            h: 32,
        };
        let big = Rect {
            x: 100,
            y: 100,
            w: 48,
            h: 48,
        };
        let mut small_buf = buf.clone();
        {
            let mut c = Canvas::new(&mut small_buf, 300, 300).unwrap();
            draw_glyph(&mut c, &tokens, TileGlyph::Settings, &small);
        }
        let mut big_buf = buf.clone();
        {
            let mut c = Canvas::new(&mut big_buf, 300, 300).unwrap();
            draw_glyph(&mut c, &tokens, TileGlyph::Settings, &big);
        }
        // Different centres draw non-identical pixel sets for the same glyph.
        assert_ne!(small_buf, big_buf);
        // The 48×48 case must still match the pre-refactor behaviour exactly:
        // rendering into a rect whose w/h equal TILE is bit-identical to the
        // original hardcoded-TILE centre calc (48/2 == TILE/2).
        let mut tile_buf = buf;
        {
            let mut c = Canvas::new(&mut tile_buf, 300, 300).unwrap();
            let tile_rect = Rect {
                x: 100,
                y: 100,
                w: TILE,
                h: TILE,
            };
            draw_glyph(&mut c, &tokens, TileGlyph::Settings, &tile_rect);
        }
        assert_eq!(
            big_buf, tile_buf,
            "TILE-sized rect behaves identically to before"
        );
    }

    #[test]
    fn panel_is_left_anchored_and_vertically_centred() {
        let p = panel_rect(800);
        assert_eq!(p.x, DOCK_X);
        assert_eq!(p.w, DOCK_W);
        let free = 800 - p.h;
        assert!(
            (i64::from(p.y) - i64::from(free / 2)).abs() <= 1,
            "vertically centred"
        );
    }

    #[test]
    fn tile_rects_are_48px_and_inside_the_panel() {
        let m = DockModel::standard(true, true, true, true, true);
        let p = panel_rect(800);
        let rects = tile_rects(800, &m);
        assert_eq!(rects.len(), m.tiles.len());
        for r in &rects {
            assert_eq!((r.w, r.h), (TILE, TILE));
            assert!(r.x >= p.x && r.y >= p.y && r.y + r.h as i32 <= p.y + p.h as i32);
        }
        assert!(rects[0].y < rects[5].y, "top-to-bottom order");
    }

    #[test]
    fn running_indicator_appears_only_for_running_tiles() {
        let t = ShellTokens::dark();
        let render_with = |running: bool| {
            let m = DockModel {
                tiles: alloc::vec![DockTile {
                    glyph: TileGlyph::Terminal,
                    running,
                    title: "Terminal"
                }],
            };
            let p = panel_rect(200);
            let mut buf = alloc::vec![0xFF20_2020u32; (p.w as usize + 16) * p.h as usize];
            {
                let mut c = Canvas::new(&mut buf, p.w + 16, p.h).unwrap();
                render(&mut c, &t, &m, true, None);
            }
            buf
        };
        let with = render_with(true);
        let without = render_with(false);
        let sage = t.sage;
        assert!(
            with.iter().filter(|&&p| p == sage).count()
                > without.iter().filter(|&&p| p == sage).count()
        );
    }

    #[test]
    fn hovered_tile_lays_brighter_pixels_and_shifts_glyph_ink() {
        let t = ShellTokens::dark();
        let m = DockModel {
            tiles: alloc::vec![DockTile {
                glyph: TileGlyph::Terminal,
                running: false,
                title: "Terminal"
            }],
        };
        let p = panel_rect(200);
        let canvas_w = p.w + RENDER_CANVAS_MARGIN;
        let render_with = |hover: Option<usize>| {
            let mut buf = alloc::vec![0xFF20_2020u32; canvas_w as usize * p.h as usize];
            {
                let mut c = Canvas::new(&mut buf, canvas_w, p.h).unwrap();
                render(&mut c, &t, &m, true, hover);
            }
            buf
        };
        let unhovered = render_with(None);
        let hovered = render_with(Some(0));

        // Hovered variant lays the brighter (0.17-alpha) tile fill somewhere;
        // the unhovered variant never does.
        assert!(
            hovered.iter().any(|&p| p == TILE_BG_HOVER_PREBLEND),
            "hovered render contains the stepped-up tile fill"
        );
        assert!(
            !unhovered.iter().any(|&p| p == TILE_BG_HOVER_PREBLEND),
            "unhovered render never contains the stepped-up tile fill"
        );

        // Glyph ink's leftmost x, within the tile's row band, shifts exactly
        // +5px right when hovered (mockup `translateX(5px)`).
        let (rects, _) = layout(RENDER_CANVAS_MARGIN as i32, 0, &m.tiles);
        let r = rects[0];
        let min_glyph_x = |buf: &alloc::vec::Vec<u32>| -> Option<i32> {
            let mut min_x: Option<i32> = None;
            for y in r.y..(r.y + r.h as i32) {
                for x in 0..canvas_w as i32 {
                    let idx = y as usize * canvas_w as usize + x as usize;
                    if buf[idx] == GLYPH_COLOR {
                        min_x = Some(min_x.map_or(x, |cur| cur.min(x)));
                    }
                }
            }
            min_x
        };
        let base = min_glyph_x(&unhovered).expect("glyph ink drawn in unhovered render");
        let shifted = min_glyph_x(&hovered).expect("glyph ink drawn in hovered render");
        assert_eq!(
            shifted - base,
            5,
            "glyph ink shifts +5px right when hovered"
        );
    }
}
