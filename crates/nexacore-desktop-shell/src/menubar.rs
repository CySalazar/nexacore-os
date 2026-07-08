//! Menu bar rendering (mockup parity).
//!
//! The mockup's menu bar: 34px tall, a translucent chrome tint over whatever
//! backdrop is behind it (desktop wallpaper or a window strip), the brand
//! hexagon logo and focused-app name at the left, a node label, and on the
//! right an AI-health pill, four icon slots (mesh/volume/search/theme), an
//! uptime clock, and an avatar disc.
//!
//! ## `Canvas::blend_pixel` alpha contract (verified at `omni-ui/src/canvas.rs:423`)
//!
//! `blend_pixel(x, y, color, coverage)` **ignores `color`'s own alpha byte**:
//! internally it rebuilds the source alpha entirely from the `coverage: u8`
//! parameter (`composite` masks `color` down to `0x00FF_FFFF` and ORs in
//! `coverage << 24`). So a translucent tint cannot be expressed as an ARGB
//! colour with a meaningful alpha channel — it must be passed as an **opaque
//! RGB** value paired with `coverage` set to the intended alpha byte (e.g. a
//! 0.64-alpha tint is `coverage = 163`, not a `0xA3______` colour). The tint
//! pass below follows that contract explicitly.

use core::f32::consts::FRAC_1_SQRT_2;

use alloc::{format, string::String};

use nexacore_display::{font::Font, geometry::Rect};
use nexacore_ui::{
    canvas::Canvas,
    text::{draw_text_aa, measure_text_aa},
};

use crate::{
    stroke::{draw_brand_mark, fill_dot, stroke_circle, stroke_crescent, stroke_line},
    tokens::ShellTokens,
};

/// Menu bar height in pixels (mockup: 34px).
pub const MENUBAR_H: u32 = 34;

// --- Chrome tint (see module-level `blend_pixel` contract note) ------------

/// Dark-theme tint RGB (`rgb(18,21,24)`); alpha is carried by `..._COV`.
const TINT_DARK_RGB: u32 = 0x0012_1518;
/// Dark-theme tint coverage (`0.64` alpha, `round(0.64 * 255)`).
const TINT_DARK_COV: u8 = 163;
/// Light-theme tint RGB (`rgb(250,245,230)`); alpha is carried by `..._COV`.
const TINT_LIGHT_RGB: u32 = 0x00FA_F5E6;
/// Light-theme tint coverage (`0.72` alpha, `round(0.72 * 255)`).
const TINT_LIGHT_COV: u8 = 184;
/// Dark-theme bottom hairline RGB (`rgba(255,255,255,0.07)`).
const HAIRLINE_DARK_RGB: u32 = 0x00FF_FFFF;
/// Light-theme bottom hairline RGB (`rgba(0,0,0,0.07)`).
const HAIRLINE_LIGHT_RGB: u32 = 0x0000_0000;
/// Hairline coverage (`0.07` alpha, `round(0.07 * 255)`), both themes.
const HAIRLINE_COV: u8 = 18;

// --- Logo --------------------------------------------------------------

/// Logo slot's left edge (mockup: `x = 12..38`).
const LOGO_X: i32 = 12;
/// Logo slot side length (mockup: 26×26).
const LOGO_SIZE: i32 = 26;

// --- Focused app name / separator / node label --------------------------

/// Focused app name text size in px.
const APP_NAME_PX: f32 = 13.0;
/// Gap between the logo slot's right edge and the app name.
const APP_NAME_GAP: i32 = 5;
/// Gap between the app name and the separator hairline.
const SEP_GAP_BEFORE: i32 = 8;
/// Separator hairline width.
const SEP_W: i32 = 1;
/// Separator hairline height.
const SEP_H: i32 = 14;
/// Gap between the separator and the node label.
const SEP_GAP_AFTER: i32 = 6;
/// Node label text size in px.
const NODE_LABEL_PX: f32 = 11.0;

// --- Right side: avatar, clock, icons, AI pill --------------------------

/// Distance from the bar's right edge to the avatar disc.
const RIGHT_MARGIN: i32 = 12;
/// Avatar disc diameter.
const AVATAR_D: i32 = 22;
/// Avatar initial letter text size in px.
const AVATAR_LETTER_PX: f32 = 11.0;
/// Avatar initial letter colour (brand cream, literal per mockup — used on
/// the petrol disc in both themes).
const AVATAR_LETTER_COLOR: u32 = 0xFFF4_EBD0;
/// Gap between adjacent right-side clusters (avatar/clock/icons/pill).
const CLUSTER_GAP: i32 = 12;
/// Clock text size in px.
const CLOCK_PX: f32 = 12.0;
/// Fixed width reserved for the clock slot. Not measured from the actual
/// uptime text: [`right_icon_rects`] must be geometry-only (no model), so the
/// icon cluster's anchor cannot depend on rendered clock content. Comfortably
/// fits `"up NNNh 59m"` (real-world uptimes); a text overflowing this is
/// simply right-aligned further left rather than clipped.
const CLOCK_RESERVED_W: i32 = 62;
/// Icon slot side length (mesh/volume/search/theme).
const ICON_SIZE: u32 = 26;
/// Gap between adjacent icon slots.
const ICON_GAP: i32 = 6;
/// AI pill height.
const PILL_H: u32 = 22;
/// AI pill corner radius.
const PILL_R: u32 = 11;
/// AI pill status-dot diameter.
const PILL_DOT_D: f32 = 7.0;
/// AI pill label text size in px.
const PILL_LABEL_PX: f32 = 11.0;
/// Reserved width inside the pill before the label (status dot + padding),
/// per the brief's `pill width = 26 + measure_text_aa(label, ...)`.
const PILL_LEAD: i32 = 26;
/// Gap between the pill's right edge and the icon cluster's left edge.
const PILL_GAP: i32 = 10;
/// Minimum breathing room used by the small-width clamp checks.
const MIN_GAP: i32 = 16;
/// AI pill background, pre-blended to opaque (`rgba(244,235,208,0.10)` over
/// the dark tinted bar) — same "pre-blend translucent chrome over a
/// representative backdrop" convention as `tokens.rs`'s `btn_group_bg`,
/// since [`Canvas::fill_rounded_rect`] paints its solid interior at full
/// coverage (see the `blend_pixel` contract note above).
const PILL_BG_DARK: u32 = 0xFF29_2D2F;
/// AI pill background, pre-blended to opaque, light theme.
const PILL_BG_LIGHT: u32 = 0xFFF1_ECDD;

/// Three mesh-icon dot offsets from the icon centre (triangle, radius 6),
/// precomputed so drawing needs no runtime trig.
const MESH_OFFSETS: [(f32, f32); 3] = [(0.0, -6.0), (-5.196_2, 3.0), (5.196_2, 3.0)];
/// Eight compass unit directions for the theme icon's sun rays.
const RAY_DIRS: [(f32, f32); 8] = [
    (0.0, -1.0),
    (FRAC_1_SQRT_2, -FRAC_1_SQRT_2),
    (1.0, 0.0),
    (FRAC_1_SQRT_2, FRAC_1_SQRT_2),
    (0.0, 1.0),
    (-FRAC_1_SQRT_2, FRAC_1_SQRT_2),
    (-1.0, 0.0),
    (-FRAC_1_SQRT_2, -FRAC_1_SQRT_2),
];

/// AI-backend health pill: a short status label with a colour-coded dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiPill {
    /// Whether the AI backend is reachable and healthy (sage dot) or not
    /// (brick dot).
    pub healthy: bool,
    /// Status label, e.g. `"AI · GPU · NexyAI"`.
    pub label: String,
}

/// Everything the menu bar needs to render one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuBarModel<'a> {
    /// Name of the currently-focused app.
    pub focused_app: &'a str,
    /// Node/workspace label, e.g. `"node-01 · space 1"`.
    pub node_label: &'a str,
    /// AI backend health pill.
    pub ai_state: AiPill,
    /// System uptime in minutes, formatted by [`format_uptime`].
    pub uptime_minutes: u32,
    /// Whether the shell is in dark mode (drives tint/pill colours and the
    /// theme icon glyph).
    pub dark: bool,
}

/// Formats an uptime duration for the menu-bar clock, e.g. `"up 4h 12m"` for
/// 252 minutes, or `"up 0m"` when `minutes < 60` (hours are omitted, not
/// shown as `0h`).
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "whole hours/minutes-of-hour split; fractional remainder is meaningless here"
)]
pub fn format_uptime(minutes: u32) -> String {
    let hours = minutes / 60;
    let mins = minutes % 60;
    if hours == 0 {
        format!("up {mins}m")
    } else {
        format!("up {hours}h {mins}m")
    }
}

/// The four right-side 26×26 icon hit rects — mesh, volume, search, theme,
/// left to right — anchored to the bar's fixed right-side reserve (avatar and
/// clock slot).
///
/// This is deliberately geometry-only (no [`MenuBarModel`]): the clock's
/// actual text length must never move the icon cluster, so hit rects stay
/// stable regardless of the rendered uptime string.
#[must_use]
#[allow(
    clippy::cast_possible_wrap,
    clippy::integer_division,
    reason = "small positive pixel metrics; halving a small height truncates harmlessly"
)]
pub fn right_icon_rects(width: u32) -> [Rect; 4] {
    let right_edge = width as i32 - RIGHT_MARGIN;
    let avatar_left = right_edge - AVATAR_D;
    let clock_right = avatar_left - CLUSTER_GAP;
    let clock_left = clock_right - CLOCK_RESERVED_W;
    let icons_right = clock_left - CLUSTER_GAP;
    let y = (MENUBAR_H as i32 - ICON_SIZE as i32) / 2;
    let theme_x = icons_right - ICON_SIZE as i32;
    let search_x = theme_x - ICON_GAP - ICON_SIZE as i32;
    let volume_x = search_x - ICON_GAP - ICON_SIZE as i32;
    let mesh_x = volume_x - ICON_GAP - ICON_SIZE as i32;
    [
        Rect {
            x: mesh_x,
            y,
            w: ICON_SIZE,
            h: ICON_SIZE,
        },
        Rect {
            x: volume_x,
            y,
            w: ICON_SIZE,
            h: ICON_SIZE,
        },
        Rect {
            x: search_x,
            y,
            w: ICON_SIZE,
            h: ICON_SIZE,
        },
        Rect {
            x: theme_x,
            y,
            w: ICON_SIZE,
            h: ICON_SIZE,
        },
    ]
}

/// Which right-side icon glyph belongs in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IconKind {
    /// Node mesh: three dots joined to the centre by spokes.
    Mesh,
    /// Volume: a speaker body plus a fanned sound wave.
    Volume,
    /// Search: a magnifying glass.
    Search,
    /// Theme: a sun disc with rays in dark mode, a crescent moon in light
    /// mode (dark-mode toggle).
    Theme,
}

/// Draws one stroke-built icon glyph centred in `r`, in `color`.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry; distance-field stroking is float-based throughout"
)]
fn draw_icon_glyph(canvas: &mut Canvas<'_>, r: &Rect, kind: IconKind, color: u32, dark: bool) {
    let cx = r.x as f32 + r.w as f32 * 0.5;
    let cy = r.y as f32 + r.h as f32 * 0.5;
    match kind {
        IconKind::Mesh => {
            for (dx, dy) in MESH_OFFSETS {
                stroke_line(canvas, cx, cy, cx + dx, cy + dy, 1.4, color);
                fill_dot(canvas, cx + dx, cy + dy, 3.0, color);
            }
        }
        IconKind::Volume => {
            // Speaker body: back edge, two flared sides, front cap.
            stroke_line(canvas, cx - 7.0, cy - 2.0, cx - 7.0, cy + 2.0, 1.4, color);
            stroke_line(canvas, cx - 7.0, cy - 2.0, cx - 1.0, cy - 5.0, 1.4, color);
            stroke_line(canvas, cx - 7.0, cy + 2.0, cx - 1.0, cy + 5.0, 1.4, color);
            stroke_line(canvas, cx - 1.0, cy - 5.0, cx - 1.0, cy + 5.0, 1.4, color);
            // Sound wave: three short fanned segments, standing in for an arc.
            stroke_line(canvas, cx + 2.0, cy - 3.5, cx + 4.2, cy - 2.3, 1.2, color);
            stroke_line(canvas, cx + 2.5, cy, cx + 4.9, cy, 1.2, color);
            stroke_line(canvas, cx + 2.0, cy + 3.5, cx + 4.2, cy + 2.3, 1.2, color);
        }
        IconKind::Search => {
            stroke_circle(canvas, cx - 1.0, cy - 1.0, 6.0, 1.4, color);
            stroke_line(canvas, cx + 3.2, cy + 3.2, cx + 6.5, cy + 6.5, 1.6, color);
        }
        IconKind::Theme if dark => {
            fill_dot(canvas, cx, cy, 8.0, color);
            for (dx, dy) in RAY_DIRS {
                stroke_line(
                    canvas,
                    cx + dx * 5.0,
                    cy + dy * 5.0,
                    cx + dx * 7.5,
                    cy + dy * 7.5,
                    1.4,
                    color,
                );
            }
        }
        IconKind::Theme => {
            // Light theme: crescent moon (mockup: `themeIcon`,
            // `NexaCore-OS.dc.html:598-600`).
            stroke_crescent(canvas, cx, cy, 6.5, 3.0, -2.5, 5.5, 1.4, color);
        }
    }
}

/// Alpha-blends the chrome tint (and bottom hairline) over every pixel of
/// the bar. Per the `blend_pixel` contract documented at the top of this
/// module, the tint colour is passed as opaque RGB with its alpha expressed
/// through `coverage`.
fn tint_bar(canvas: &mut Canvas<'_>, dark: bool) {
    let (rgb, cov) = if dark {
        (TINT_DARK_RGB, TINT_DARK_COV)
    } else {
        (TINT_LIGHT_RGB, TINT_LIGHT_COV)
    };
    let w = canvas.width();
    let h = canvas.height();
    let mut y = 0;
    while y < h {
        let mut x = 0;
        while x < w {
            #[allow(clippy::cast_possible_wrap, reason = "small positive pixel metrics")]
            canvas.blend_pixel(x as i32, y as i32, rgb, cov);
            x += 1;
        }
        y += 1;
    }
    let hairline_rgb = if dark {
        HAIRLINE_DARK_RGB
    } else {
        HAIRLINE_LIGHT_RGB
    };
    if h > 0 {
        let last_row = h - 1;
        let mut x = 0;
        while x < w {
            #[allow(clippy::cast_possible_wrap, reason = "small positive pixel metrics")]
            canvas.blend_pixel(x as i32, last_row as i32, hairline_rgb, HAIRLINE_COV);
            x += 1;
        }
    }
}

/// Draws the hexagon brand logo in the 26×26 slot at [`LOGO_X`].
///
/// Delegates to the shared [`draw_brand_mark`] helper (also used by the
/// dock's launcher tile) at `scale == 1.0`, reproducing this slot's original
/// geometry exactly.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry; LOGO_X/LOGO_SIZE are tiny pixel constants"
)]
fn draw_logo(canvas: &mut Canvas<'_>, tokens: &ShellTokens, bar_cy: f32) {
    let cx = LOGO_X as f32 + LOGO_SIZE as f32 * 0.5;
    draw_brand_mark(canvas, cx, bar_cy, 1.0, tokens.petrol, tokens.brick);
}

/// Renders the full 34px menu bar into `canvas`.
///
/// `canvas`'s pixels already hold the backdrop strip (the caller copies it
/// from the back buffer); this first alpha-blends the chrome tint over the
/// whole strip, then draws the logo, focused app name, node label, and the
/// right-side avatar/clock/icons/AI-pill cluster. At small `width`s the AI
/// pill is dropped first, then the node label, rather than overlapping.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::float_arithmetic,
    clippy::integer_division,
    clippy::too_many_lines,
    reason = "small positive pixel metrics and glyph geometry; the menu bar paints the \
              tint, logo, text clusters, and right-side content in one pass by design"
)]
pub fn render(
    canvas: &mut Canvas<'_>,
    tokens: &ShellTokens,
    ui_font: &Font<'_>,
    mono_font: &Font<'_>,
    model: &MenuBarModel<'_>,
    width: u32,
) {
    tint_bar(canvas, model.dark);

    let bar_cy = MENUBAR_H as f32 * 0.5;
    draw_logo(canvas, tokens, bar_cy);

    // Focused app name — baseline-centred, same formula as `frame.rs`.
    let name_baseline = (bar_cy + APP_NAME_PX * 0.36) as i32;
    let name_x = LOGO_X + LOGO_SIZE + APP_NAME_GAP;
    let name_w = draw_text_aa(
        canvas,
        name_x,
        name_baseline,
        model.focused_app,
        ui_font,
        APP_NAME_PX,
        tokens.text_primary,
    );
    let left_cursor = name_x + name_w;

    // Right-side geometry is fixed and content-independent; reuse it as the
    // single source of truth shared with hit-testing.
    let [mesh_r, volume_r, search_r, theme_r] = right_icon_rects(width);
    let icons_left = mesh_r.x;

    // AI pill: drop first when it would collide with the app name.
    let label_w = measure_text_aa(&model.ai_state.label, mono_font, PILL_LABEL_PX);
    let pill_w = (PILL_LEAD + label_w).max(0);
    let pill_right = icons_left - PILL_GAP;
    let pill_left = pill_right - pill_w;
    let draw_pill = pill_left > left_cursor + MIN_GAP;

    // Node label: drop next when it would collide with whichever right-side
    // content starts first (the pill if kept, else the icon cluster).
    let content_right_bound = (if draw_pill { pill_left } else { icons_left }) - SEP_GAP_BEFORE;
    let sep_x = left_cursor + SEP_GAP_BEFORE;
    let node_x = sep_x + SEP_W + SEP_GAP_AFTER;
    let node_label_w = measure_text_aa(model.node_label, mono_font, NODE_LABEL_PX);
    let draw_node = node_x + node_label_w < content_right_bound;

    if draw_node {
        canvas.fill_rect(
            &Rect {
                x: sep_x,
                y: (MENUBAR_H as i32 - SEP_H) / 2,
                w: SEP_W as u32,
                h: SEP_H as u32,
            },
            tokens.border_soft,
        );
        let node_baseline = (bar_cy + NODE_LABEL_PX * 0.36) as i32;
        let _ = draw_text_aa(
            canvas,
            node_x,
            node_baseline,
            model.node_label,
            mono_font,
            NODE_LABEL_PX,
            tokens.text_tertiary,
        );
    }

    // --- Right side: avatar, clock, icons, AI pill ---
    let right_edge = width as i32 - RIGHT_MARGIN;
    let avatar_left = right_edge - AVATAR_D;
    let avatar_cx = avatar_left as f32 + AVATAR_D as f32 * 0.5;
    fill_dot(canvas, avatar_cx, bar_cy, AVATAR_D as f32, tokens.petrol);
    let letter_w = measure_text_aa("S", ui_font, AVATAR_LETTER_PX);
    let letter_baseline = (bar_cy + AVATAR_LETTER_PX * 0.36) as i32;
    let letter_x = (avatar_cx - letter_w as f32 * 0.5) as i32;
    let _ = draw_text_aa(
        canvas,
        letter_x,
        letter_baseline,
        "S",
        ui_font,
        AVATAR_LETTER_PX,
        AVATAR_LETTER_COLOR,
    );

    let clock_str = format_uptime(model.uptime_minutes);
    let clock_right = avatar_left - CLUSTER_GAP;
    let clock_w = measure_text_aa(&clock_str, mono_font, CLOCK_PX);
    let clock_x = clock_right - clock_w;
    let clock_baseline = (bar_cy + CLOCK_PX * 0.36) as i32;
    let _ = draw_text_aa(
        canvas,
        clock_x,
        clock_baseline,
        &clock_str,
        mono_font,
        CLOCK_PX,
        tokens.text_primary,
    );

    for (r, kind) in [mesh_r, volume_r, search_r, theme_r].into_iter().zip([
        IconKind::Mesh,
        IconKind::Volume,
        IconKind::Search,
        IconKind::Theme,
    ]) {
        draw_icon_glyph(canvas, &r, kind, tokens.text_secondary, model.dark);
    }

    if draw_pill {
        let pill_rect = Rect {
            x: pill_left,
            y: (MENUBAR_H as i32 - PILL_H as i32) / 2,
            w: pill_w as u32,
            h: PILL_H,
        };
        let pill_bg = if model.dark {
            PILL_BG_DARK
        } else {
            PILL_BG_LIGHT
        };
        canvas.fill_rounded_rect(&pill_rect, PILL_R, pill_bg);
        let dot_color = if model.ai_state.healthy {
            tokens.sage
        } else {
            tokens.brick
        };
        let dot_cx = pill_left as f32 + 13.0;
        fill_dot(canvas, dot_cx, bar_cy, PILL_DOT_D, dot_color);
        let label_x = pill_left + PILL_LEAD;
        let label_baseline = (bar_cy + PILL_LABEL_PX * 0.36) as i32;
        let _ = draw_text_aa(
            canvas,
            label_x,
            label_baseline,
            &model.ai_state.label,
            mono_font,
            PILL_LABEL_PX,
            tokens.text_primary,
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_wrap,
    clippy::integer_division,
    reason = "test literals are small positive pixel metrics"
)]
mod tests {
    use nexacore_display::font::Font;
    use nexacore_ui::canvas::Canvas;

    use super::*;
    use crate::tokens::ShellTokens;

    const W: u32 = 640;

    fn render_bar(healthy: bool) -> alloc::vec::Vec<u32> {
        render_bar_themed(healthy, true)
    }

    fn render_bar_themed(healthy: bool, dark: bool) -> alloc::vec::Vec<u32> {
        let t = ShellTokens::dark();
        let ui = Font::parse(nexacore_fonts::BRAND_UI).unwrap();
        let mono = Font::parse(nexacore_fonts::BRAND_MONO).unwrap();
        // Backdrop: a recognizable mid-grey the tint must blend over.
        let mut buf = alloc::vec![0xFF55_5555u32; (W * MENUBAR_H) as usize];
        {
            let mut c = Canvas::new(&mut buf, W, MENUBAR_H).unwrap();
            let model = MenuBarModel {
                focused_app: "Terminal",
                node_label: "node-01 · space 1",
                ai_state: AiPill {
                    healthy,
                    label: alloc::string::String::from("AI · GPU · NexyAI"),
                },
                uptime_minutes: 252,
                dark,
            };
            render(&mut c, &t, &ui, &mono, &model, W);
        }
        buf
    }

    #[test]
    fn theme_icon_swaps_glyph_shape_between_dark_and_light() {
        let dark_buf = render_bar_themed(true, true);
        let light_buf = render_bar_themed(true, false);
        let theme_r = right_icon_rects(W)[3];
        #[allow(clippy::cast_sign_loss)]
        let cx = (theme_r.x + theme_r.w as i32 / 2) as usize;
        #[allow(clippy::cast_sign_loss)]
        let cy = (theme_r.y + theme_r.h as i32 / 2) as usize;
        let center_idx = cy * (W as usize) + cx;
        let ink = ShellTokens::dark().text_secondary;
        assert_eq!(
            dark_buf[center_idx], ink,
            "dark theme: sun disc fully covers the icon's exact centre"
        );
        assert_ne!(
            light_buf[center_idx], ink,
            "light theme: crescent's carve-out leaves the exact centre untouched"
        );
    }

    #[test]
    fn tints_backdrop_and_draws_brand_dot() {
        let buf = render_bar(true);
        // The chrome tint must have changed the raw backdrop everywhere.
        assert!(
            buf.iter().filter(|&&p| p == 0xFF55_5555).count() < (W as usize),
            "bar is tinted"
        );
        // The logo's brick centre dot is present.
        let brick = ShellTokens::dark().brick;
        assert!(
            buf.iter().any(|&p| p == brick),
            "brick mission-anchor dot drawn"
        );
    }

    #[test]
    fn ai_pill_reflects_backend_health() {
        let ok = render_bar(true);
        let sage = ShellTokens::dark().sage;
        assert!(ok.iter().any(|&p| p == sage), "healthy pill dot is sage");
        let down = render_bar(false);
        let brick = ShellTokens::dark().brick;
        // Unhealthy pill dot is brick; count must exceed the logo dot's pixels alone.
        let brick_ok = ok.iter().filter(|&&p| p == brick).count();
        let brick_down = down.iter().filter(|&&p| p == brick).count();
        assert!(
            brick_down > brick_ok,
            "unhealthy state adds a brick status dot"
        );
    }

    #[test]
    fn right_icons_sit_before_the_clock() {
        let rects = right_icon_rects(W);
        assert_eq!(rects.len(), 4);
        for r in &rects {
            assert_eq!(r.w, 26);
            assert_eq!(r.h, 26);
            assert!(r.x > (W / 2) as i32, "icons live on the right half");
        }
        assert!(rects[0].x < rects[3].x, "left-to-right order");
    }

    #[test]
    fn format_uptime_matches_the_brief_examples() {
        assert_eq!(format_uptime(0), "up 0m");
        assert_eq!(format_uptime(59), "up 59m");
        assert_eq!(format_uptime(252), "up 4h 12m");
        assert_eq!(format_uptime(1500), "up 25h 0m");
    }

    #[test]
    fn narrow_widths_clamp_instead_of_overlapping() {
        // Must not panic (no index/arithmetic overflow) at a width too small
        // to fit every element; the pill and/or node label are dropped.
        const NARROW: u32 = 360;
        let t = ShellTokens::dark();
        let ui = Font::parse(nexacore_fonts::BRAND_UI).unwrap();
        let mono = Font::parse(nexacore_fonts::BRAND_MONO).unwrap();
        let mut buf = alloc::vec![0xFF55_5555u32; (NARROW * MENUBAR_H) as usize];
        let model = MenuBarModel {
            focused_app: "Terminal",
            node_label: "node-01 · space 1",
            ai_state: AiPill {
                healthy: true,
                label: alloc::string::String::from("AI · GPU · NexyAI"),
            },
            uptime_minutes: 1500,
            dark: false,
        };
        let mut c = Canvas::new(&mut buf, NARROW, MENUBAR_H).unwrap();
        render(&mut c, &t, &ui, &mono, &model, NARROW);
        // Rendering something is still expected (e.g. the logo).
        let brick = ShellTokens::dark().brick;
        assert!(
            buf.iter().any(|&p| p == brick),
            "logo still drawn at narrow widths"
        );
    }

    /// Self-review: at ordinary widths (640, 1280) every optional element —
    /// node label and AI pill — must fit without the running-x clamp
    /// dropping it, and the left-side content must end strictly before the
    /// right-side content begins (mirrors the arithmetic in `render`,
    /// without duplicating its drawing).
    #[test]
    fn standard_widths_fit_pill_and_node_label_without_overlap() {
        let ui = Font::parse(nexacore_fonts::BRAND_UI).unwrap();
        let mono = Font::parse(nexacore_fonts::BRAND_MONO).unwrap();
        for width in [640i32, 1280] {
            #[allow(
                clippy::cast_sign_loss,
                reason = "test literals are small positive widths"
            )]
            let [mesh_r, ..] = right_icon_rects(width as u32);
            let icons_left = mesh_r.x;

            let name_x = LOGO_X + LOGO_SIZE + APP_NAME_GAP;
            let name_w = measure_text_aa("Terminal", &ui, APP_NAME_PX);
            let left_cursor = name_x + name_w;

            let label_w = measure_text_aa("AI · GPU · NexyAI", &mono, PILL_LABEL_PX);
            let pill_w = (PILL_LEAD + label_w).max(0);
            let pill_left = (icons_left - PILL_GAP) - pill_w;
            assert!(
                pill_left > left_cursor + MIN_GAP,
                "width {width}: AI pill would be dropped (pill_left {pill_left} <= {})",
                left_cursor + MIN_GAP
            );

            let content_right_bound = pill_left - SEP_GAP_BEFORE;
            let sep_x = left_cursor + SEP_GAP_BEFORE;
            let node_x = sep_x + SEP_W + SEP_GAP_AFTER;
            let node_label_w = measure_text_aa("node-01 · space 1", &mono, NODE_LABEL_PX);
            assert!(
                node_x + node_label_w < content_right_bound,
                "width {width}: node label would be dropped ({} >= {content_right_bound})",
                node_x + node_label_w
            );
        }
    }
}
