//! Launcher: fuzzy search over a static app/setting/file index, plus the
//! open/query state machine (mockup parity,
//! `docs/superpowers/specs/2026-07-05-desktop-shell-design.md` Milestone 4).
//!
//! Mirrors the mockup's `INDEX`/`fuzzy`/`results`
//! (`brand/design/NexaCore-OS.dc.html:360-374,501-525`) exactly on the
//! scoring algorithm and index content; see the M4 plan
//! (`docs/superpowers/plans/2026-07-06-desktop-shell-m4.md`) for the
//! "Plan-level decisions" on the few entries that intentionally have no
//! `app` target yet.

use alloc::{string::String, vec::Vec};

use nexacore_display::{font::Font, geometry::Rect};
use nexacore_ui::{
    canvas::Canvas,
    text::{draw_text_aa, measure_text_aa},
};

use crate::{
    dock::{self, TileGlyph},
    router::AppId,
    stroke::{stroke_circle, stroke_line},
    tokens::ShellTokens,
};

/// Which category a launcher result belongs to (mockup: `r.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// An application (`"APP"`).
    App,
    /// A setting/preference (`"SET"`).
    Setting,
    /// A file (`"FILE"`).
    File,
}

/// One entry in the static launcher index (mockup: `this.INDEX`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LauncherEntry {
    /// Result title, e.g. `"Terminal"`.
    pub title: &'static str,
    /// Result subtitle, e.g. `"shell"`.
    pub sub: &'static str,
    /// Category badge.
    pub kind: EntryKind,
    /// Extra fuzzy-searchable keywords (mockup: `it.kw`).
    pub keywords: &'static str,
    /// The app this result opens, if any. `None` for entries the mockup
    /// itself leaves inert (`app:null`) or that need an app this codebase
    /// doesn't have yet (see the plan's "Plan-level decisions").
    pub app: Option<AppId>,
}

/// The 14-entry static index (mockup: `this.INDEX`, extended with `System
/// Info` — WS7 desktop M8, launcher-only, no dock tile).
///
/// `brand/design/NexaCore-OS.dc.html:360-374`. `Text Editor` (mockup:
/// `app:null`) and `Appearance` (theme toggle, Milestone 6) get `app: None`
/// here — see the M4/M5 plans' "Plan-level decisions".
pub static INDEX: [LauncherEntry; 14] = [
    LauncherEntry {
        title: "Terminal",
        sub: "shell",
        kind: EntryKind::App,
        keywords: "shell console cli",
        app: Some(AppId::Terminal),
    },
    LauncherEntry {
        title: "NexaCore Helper",
        sub: "Local AI assistant",
        kind: EntryKind::App,
        keywords: "ai chat assistant ollama",
        app: Some(AppId::Helper),
    },
    LauncherEntry {
        title: "Files",
        sub: "Documents and mesh",
        kind: EntryKind::App,
        keywords: "finder documents browser",
        app: Some(AppId::Files),
    },
    LauncherEntry {
        title: "System Monitor",
        sub: "Mesh · nodes · attestation",
        kind: EntryKind::App,
        keywords: "activity processes network",
        app: Some(AppId::Monitor),
    },
    LauncherEntry {
        title: "Control Center",
        sub: "Settings",
        kind: EntryKind::App,
        keywords: "preferences settings",
        app: Some(AppId::Settings),
    },
    LauncherEntry {
        title: "Text Editor",
        sub: "text",
        kind: EntryKind::App,
        keywords: "notes write code",
        app: None,
    },
    LauncherEntry {
        title: "Appearance",
        sub: "Light / dark",
        kind: EntryKind::Setting,
        keywords: "theme color dark light",
        app: None,
    },
    LauncherEntry {
        title: "Network & Mesh",
        sub: "3 attested peers",
        kind: EntryKind::Setting,
        keywords: "wifi peer connection",
        app: Some(AppId::Monitor),
    },
    LauncherEntry {
        title: "AI Backend",
        sub: "GPU · NexyAI",
        kind: EntryKind::Setting,
        keywords: "model ollama inference",
        app: Some(AppId::Settings),
    },
    LauncherEntry {
        title: "Privacy · Local-first",
        sub: "Fail-close, no cloud",
        kind: EntryKind::Setting,
        keywords: "security encryption",
        app: Some(AppId::Settings),
    },
    LauncherEntry {
        title: "README.md",
        sub: "~/Documents",
        kind: EntryKind::File,
        keywords: "document text",
        app: Some(AppId::Files),
    },
    LauncherEntry {
        title: "mesh-peers.toml",
        sub: "~/Documents",
        kind: EntryKind::File,
        keywords: "configuration nodes",
        app: Some(AppId::Files),
    },
    LauncherEntry {
        title: "kernel.log",
        sub: "~/var/log",
        kind: EntryKind::File,
        keywords: "system log",
        app: Some(AppId::Files),
    },
    LauncherEntry {
        title: "System Info",
        sub: "NexaCore OS · build info",
        kind: EntryKind::App,
        keywords: "version build cpu memory about",
        app: Some(AppId::SystemInfo),
    },
];

/// Ports the mockup's `fuzzy(q, t)` scoring exactly.
///
/// `+2` per matched character (an in-order, case-insensitive ASCII
/// subsequence match), `+5` when a match continues immediately after the
/// previous one, `+8` when a match sits at `text`'s start or right after one
/// of `" -_./"`, and a final `- text.len() / 4` length penalty. `None` if
/// `query` is not a subsequence of `text`. ASCII-only case-folding (the
/// index and expected queries are ASCII Italian; documented scope limit,
/// not a hidden Unicode bug).
#[must_use]
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    reason = "index/length arithmetic over small UI strings (index entries, typed queries); the \
              final `/ 4` length penalty is an intentional floor-divide, not a precision bug"
)]
pub fn fuzzy(query: &str, text: &str) -> Option<i32> {
    let q: Vec<u8> = query.bytes().map(|b| b.to_ascii_lowercase()).collect();
    let t: Vec<u8> = text.bytes().collect();
    let mut qi = 0usize;
    let mut score: i32 = 0;
    let mut prev: i32 = -2;
    for (i, &tb) in t.iter().enumerate() {
        let Some(&qb) = q.get(qi) else {
            break;
        };
        if tb.to_ascii_lowercase() == qb {
            score += 2;
            let i_i32 = i as i32;
            if prev == i_i32 - 1 {
                score += 5;
            }
            let at_boundary = i == 0
                || t.get(i - 1)
                    .is_some_and(|p| matches!(p, b' ' | b'-' | b'_' | b'.' | b'/'));
            if at_boundary {
                score += 8;
            }
            prev = i_i32;
            qi += 1;
        }
    }
    if qi == q.len() {
        Some(score - (t.len() as i32) / 4)
    } else {
        None
    }
}

/// Ports the mockup's `results()`.
///
/// Empty query → first 5 [`EntryKind::App`] entries in index order;
/// otherwise every entry is scored by
/// `max(fuzzy(query, title), fuzzy(query, keywords) - 6)` (kept only if at
/// least one side matched), sorted by score descending then title length
/// ascending, top 6.
#[must_use]
pub fn search(query: &str) -> Vec<&'static LauncherEntry> {
    let query = query.trim();
    if query.is_empty() {
        return INDEX
            .iter()
            .filter(|e| e.kind == EntryKind::App)
            .take(5)
            .collect();
    }
    let mut hits: Vec<(&'static LauncherEntry, i32)> = Vec::new();
    for entry in &INDEX {
        let title_score = fuzzy(query, entry.title);
        let kw_score = fuzzy(query, entry.keywords);
        let best = match (title_score, kw_score) {
            (None, None) => None,
            (Some(t), None) => Some(t),
            (None, Some(k)) => Some(k - 6),
            (Some(t), Some(k)) => Some(t.max(k - 6)),
        };
        if let Some(score) = best {
            hits.push((entry, score));
        }
    }
    hits.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.title.len().cmp(&b.0.title.len()))
    });
    hits.into_iter().take(6).map(|(e, _)| e).collect()
}

/// Launcher open/query state machine (mockup: `launcherOpen`/`query` state).
#[derive(Debug, Default)]
pub struct LauncherState {
    open: bool,
    query: String,
}

impl LauncherState {
    /// A closed launcher with an empty query.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the launcher is currently open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// The current query text.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Opens the launcher and clears the query (mockup: `openLauncher`).
    pub fn open(&mut self) {
        self.open = true;
        self.query.clear();
    }

    /// Closes the launcher (mockup: `closeLauncher`).
    pub fn close(&mut self) {
        self.open = false;
    }

    /// Appends one character to the query, only while open.
    pub fn push_char(&mut self, c: char) {
        if self.open {
            self.query.push(c);
        }
    }

    /// Removes the last character of the query, only while open.
    pub fn backspace(&mut self) {
        if self.open {
            self.query.pop();
        }
    }

    /// Current search results for `self.query()`.
    #[must_use]
    pub fn results(&self) -> Vec<&'static LauncherEntry> {
        search(&self.query)
    }

    /// Whether the "Ask NexaCore Helper" row should show (mockup:
    /// `launcher.hasAi`: a non-empty, non-whitespace-only query).
    #[must_use]
    pub fn has_ai(&self) -> bool {
        !self.query.trim().is_empty()
    }
}

// =============================================================================
// Rendering (mockup parity: full-screen scrim + centred panel)
// =============================================================================
//
// ## Blend contract
//
// Same `Canvas::blend_pixel` contract as `menubar.rs`/`dock.rs`: the scrim
// (a flat full-screen tint) is drawn with real per-pixel alpha via
// `blend_pixel`, since it sits over whatever the compositor already
// rendered (wallpaper and/or windows). The panel's rounded background
// instead uses `Canvas::fill_rounded_rect`, which forces full coverage in
// the interior — so, like `dock.rs`'s panel background, it is pre-blended
// by hand to an opaque approximation over a representative dark backdrop
// (the panel only ever sits over the just-applied scrim, which is close to
// uniform, so the approximation error is small).

/// Fixed panel width (mockup: `min(640px, 92vw)`; at this codebase's
/// 1280×800 target, 640px always wins).
pub const PANEL_W: u32 = 640;
/// Panel top offset (mockup: `padding-top:118px` on the scrim).
const PANEL_TOP: i32 = 118;
/// Panel corner radius (mockup: `border-radius:16px`).
const PANEL_RADIUS: u32 = 16;
/// Header row height (search icon + input + `esc` badge).
const HEADER_H: u32 = 54;
/// "Ask NexaCore Helper" row height.
const AI_ROW_H: u32 = 56;
/// Category heading label row height.
const HEADING_H: u32 = 24;
/// One result row's height.
const ROW_H: u32 = 52;
/// Body padding (mockup: `padding:8px` on the scrollable body).
const BODY_PAD: u32 = 8;
/// Result icon square side (mockup: `32px`).
const ICON_SIZE: u32 = 32;
/// Row horizontal padding (mockup: `padding:9px 12px`, the `12px`).
const ROW_PAD_X: i32 = 12;
/// Body max height (mockup: `max-height:52vh`; ≈ 52% of an 800px screen).
const MAX_BODY_H: u32 = 416;

// --- Colours (mockup `:root`/`[data-theme="dark"]` custom properties;
// blended per the `Canvas::blend_pixel` contract documented above) --------

/// Scrim RGB, dark theme (`rgba(0,0,0,0.44)`); alpha via [`SCRIM_DARK_COV`].
const SCRIM_DARK_RGB: u32 = 0x0000_0000;
/// `round(0.44 * 255)`.
const SCRIM_DARK_COV: u8 = 112;
/// Scrim RGB, light theme (`rgba(24,24,20,0.26)`).
const SCRIM_LIGHT_RGB: u32 = 0x0018_1814;
/// `round(0.26 * 255)`.
const SCRIM_LIGHT_COV: u8 = 66;
/// Panel background, dark theme, pre-blended to opaque:
/// `rgba(24,28,31,0.88)` over `ShellTokens::dark().bg_canvas` (`#14171A`)
/// → `24*.88+20*.12≈24`, `28*.88+23*.12≈27`, `31*.88+26*.12≈30` ⇒ `#181B1E`.
const PANEL_BG_DARK: u32 = 0xFF18_1B1E;
/// Panel background, light theme, pre-blended to opaque:
/// `rgba(252,250,244,0.90)` over `ShellTokens::light().bg_canvas` (`#F4EBD0`)
/// → `252*.9+244*.1≈251`, `250*.9+235*.1≈249`, `244*.9+208*.1≈240` ⇒ `#FBF9F0`.
const PANEL_BG_LIGHT: u32 = 0xFFFB_F9F0;
/// Panel border RGB, dark theme (`rgba(255,255,255,0.08)`); alpha via
/// [`BORDER_DARK_COV`].
const BORDER_DARK_RGB: u32 = 0x00FF_FFFF;
/// `round(0.08 * 255)`.
const BORDER_DARK_COV: u8 = 20;
/// Panel border RGB, light theme (`rgba(31,36,33,0.10)`).
const BORDER_LIGHT_RGB: u32 = 0x001F_2421;
/// `round(0.10 * 255)`.
const BORDER_LIGHT_COV: u8 = 26;
/// Result-icon square background, dark theme, pre-blended to opaque:
/// `rgba(244,235,208,0.10)` over [`PANEL_BG_DARK`] (`#181B1E`)
/// → `244*.1+24*.9≈46`, `235*.1+27*.9≈48`, `208*.1+30*.9≈48` ⇒ `#2E3030`.
const TILE_BG_DARK: u32 = 0xFF2E_3030;
/// Result-icon square background, light theme, pre-blended to opaque:
/// `rgba(15,76,92,0.07)` over [`PANEL_BG_LIGHT`] (`#FBF9F0`)
/// → `15*.07+251*.93≈234`, `76*.07+249*.93≈237`, `92*.07+240*.93≈230` ⇒ `#EAEDE6`.
const TILE_BG_LIGHT: u32 = 0xFFEA_EDE6;

/// Everything the launcher overlay needs to render one frame.
#[derive(Debug, Clone, Copy)]
pub struct LauncherModel<'a> {
    /// Current query text (mockup: `launcher.query`).
    pub query: &'a str,
    /// Current results (mockup: `launcher.results`), already computed by
    /// the caller (typically [`LauncherState::results`]) so this module
    /// stays a pure render function over borrowed data.
    pub results: &'a [&'static LauncherEntry],
    /// Whether to show the "Ask NexaCore Helper" row.
    pub has_ai: bool,
    /// Dark/light theme flag (mirrors `MenuBarModel::dark`).
    pub dark: bool,
}

/// The launcher panel's rect for `screen_w`, sized to fit `model`'s content
/// (mockup: the scrim's `padding-top:118px` plus the panel's own
/// `max-height:52vh` scrollable body).
#[must_use]
#[allow(
    clippy::cast_possible_wrap,
    clippy::integer_division,
    reason = "screen_w is a small positive pixel metric; centring by floor-division is intended"
)]
pub fn panel_rect(screen_w: u32, model: &LauncherModel<'_>) -> Rect {
    let ai = if model.has_ai { AI_ROW_H } else { 0 };
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the launcher shows at most 6 results; well within u32 range"
    )]
    let rows = ROW_H.saturating_mul(model.results.len() as u32);
    let body = (BODY_PAD * 2 + ai + HEADING_H + rows).min(MAX_BODY_H);
    Rect {
        x: (screen_w as i32 - PANEL_W as i32) / 2,
        y: PANEL_TOP,
        w: PANEL_W,
        h: HEADER_H + body,
    }
}

/// Draws the generic fallback glyph for an entry with no dock-icon app
/// (mockup parity gap; see the M4 plan's "Plan-level decisions").
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::integer_division,
    reason = "small glyph geometry; small positive pixel metrics"
)]
fn draw_kind_glyph(canvas: &mut Canvas<'_>, tokens: &ShellTokens, kind: EntryKind, r: &Rect) {
    let cx = r.x as f32 + r.w as f32 * 0.5;
    let cy = r.y as f32 + r.h as f32 * 0.5;
    match kind {
        EntryKind::App => stroke_circle(canvas, cx, cy, 6.0, 1.4, tokens.text_accent),
        EntryKind::Setting => {
            stroke_circle(canvas, cx, cy, 6.0, 1.4, tokens.text_accent);
            stroke_line(canvas, cx - 2.0, cy, cx + 2.0, cy, 1.4, tokens.text_accent);
        }
        EntryKind::File => {
            let side: i32 = 12;
            let sq = Rect {
                x: r.x + (r.w as i32 - side) / 2,
                y: r.y + (r.h as i32 - side) / 2,
                w: side as u32,
                h: side as u32,
            };
            canvas.draw_rect_border(&sq, tokens.text_tertiary, 1);
        }
    }
}

/// Draws the "Text Editor" entry's pencil glyph (mockup: `✎`), built
/// from a diagonal stroke (the pencil body) plus a short angled stroke at
/// the writing tip.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry"
)]
fn draw_pencil_glyph(canvas: &mut Canvas<'_>, tokens: &ShellTokens, r: &Rect) {
    let cx = r.x as f32 + r.w as f32 * 0.5;
    let cy = r.y as f32 + r.h as f32 * 0.5;
    stroke_line(
        canvas,
        cx - 5.0,
        cy + 5.0,
        cx + 4.0,
        cy - 4.0,
        1.6,
        tokens.text_accent,
    );
    stroke_line(
        canvas,
        cx - 6.0,
        cy + 6.0,
        cx - 4.0,
        cy + 4.0,
        1.6,
        tokens.text_accent,
    );
}

/// Draws the "Appearance" (theme) entry's glyph: a circle bisected by a
/// vertical line, echoing the mockup's half-tone `◐` glyph without a
/// half-disc-fill primitive.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry"
)]
fn draw_info_entry_glyph(canvas: &mut Canvas<'_>, tokens: &ShellTokens, r: &Rect) {
    let cx = r.x as f32 + r.w as f32 * 0.5;
    let cy = r.y as f32 + r.h as f32 * 0.5;
    stroke_circle(canvas, cx, cy, 6.5, 1.3, tokens.text_accent);
    // The "i" dot (a short, thick stroke draws as a filled round dot).
    stroke_line(canvas, cx, cy - 3.2, cx, cy - 3.0, 1.8, tokens.text_accent);
    // The "i" stem.
    stroke_line(canvas, cx, cy - 0.5, cx, cy + 3.5, 1.6, tokens.text_accent);
}

/// Draws the "Appearance" (theme) entry's glyph: a circle bisected by a
/// vertical line, echoing the mockup's half-tone `◐` glyph without a
/// half-disc-fill primitive.
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "small glyph geometry"
)]
fn draw_theme_entry_glyph(canvas: &mut Canvas<'_>, tokens: &ShellTokens, r: &Rect) {
    let cx = r.x as f32 + r.w as f32 * 0.5;
    let cy = r.y as f32 + r.h as f32 * 0.5;
    stroke_circle(canvas, cx, cy, 6.0, 1.4, tokens.text_accent);
    stroke_line(canvas, cx, cy - 6.0, cx, cy + 6.0, 1.4, tokens.text_accent);
}

/// Draws one result's icon: the real dock glyph when `entry.app` maps to
/// one, a bespoke glyph for the two entries that need one, else a generic
/// per-[`EntryKind`] shape.
fn draw_entry_icon(canvas: &mut Canvas<'_>, tokens: &ShellTokens, entry: &LauncherEntry, r: &Rect) {
    let tile_glyph = match entry.app {
        Some(AppId::Terminal) => Some(TileGlyph::Terminal),
        Some(AppId::Helper) => Some(TileGlyph::Helper),
        Some(AppId::Files) => Some(TileGlyph::Files),
        Some(AppId::Settings) => Some(TileGlyph::Settings),
        Some(AppId::Monitor) => Some(TileGlyph::Monitor),
        Some(AppId::SystemInfo) | None => None,
    };
    match tile_glyph {
        Some(g) => dock::draw_glyph(canvas, tokens, g, r),
        None => match entry.title {
            "Text Editor" => draw_pencil_glyph(canvas, tokens, r),
            "Appearance" => draw_theme_entry_glyph(canvas, tokens, r),
            "System Info" => draw_info_entry_glyph(canvas, tokens, r),
            _ => draw_kind_glyph(canvas, tokens, entry.kind, r),
        },
    }
}

/// Category badge text (mockup: `r.kind`).
fn kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::App => "APP",
        EntryKind::Setting => "SET",
        EntryKind::File => "FILE",
    }
}

/// Renders the full-screen launcher overlay (scrim + centred panel).
///
/// `canvas` must already hold the composited backdrop (wallpaper and/or
/// windows) — every fill here blends over it per the `blend_pixel` contract
/// documented at the top of this section, except the panel's own rounded
/// background, which is a pre-blended opaque approximation.
#[allow(
    clippy::too_many_arguments,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::float_arithmetic,
    clippy::integer_division,
    clippy::too_many_lines,
    reason = "small positive pixel metrics and glyph geometry; the launcher paints the scrim, \
              panel, header, AI row, heading and result rows in one pass by design"
)]
pub fn render(
    canvas: &mut Canvas<'_>,
    tokens: &ShellTokens,
    ui_font: &Font<'_>,
    mono_font: &Font<'_>,
    model: &LauncherModel<'_>,
    screen_w: u32,
    screen_h: u32,
) {
    let (scrim_rgb, scrim_cov) = if model.dark {
        (SCRIM_DARK_RGB, SCRIM_DARK_COV)
    } else {
        (SCRIM_LIGHT_RGB, SCRIM_LIGHT_COV)
    };
    let mut y = 0;
    while y < screen_h {
        let mut x = 0;
        while x < screen_w {
            canvas.blend_pixel(x as i32, y as i32, scrim_rgb, scrim_cov);
            x += 1;
        }
        y += 1;
    }

    let panel = panel_rect(screen_w, model);
    let panel_bg = if model.dark {
        PANEL_BG_DARK
    } else {
        PANEL_BG_LIGHT
    };
    canvas.fill_rounded_rect(&panel, PANEL_RADIUS, panel_bg);
    let (border_rgb, border_cov) = if model.dark {
        (BORDER_DARK_RGB, BORDER_DARK_COV)
    } else {
        (BORDER_LIGHT_RGB, BORDER_LIGHT_COV)
    };
    // 1px straight outline (ignores the rounded corners — same simplification
    // dock.rs documents for its own panel border).
    for px in panel.x..(panel.x + panel.w as i32) {
        canvas.blend_pixel(px, panel.y, border_rgb, border_cov);
        canvas.blend_pixel(px, panel.y + panel.h as i32 - 1, border_rgb, border_cov);
    }
    for py in panel.y..(panel.y + panel.h as i32) {
        canvas.blend_pixel(panel.x, py, border_rgb, border_cov);
        canvas.blend_pixel(panel.x + panel.w as i32 - 1, py, border_rgb, border_cov);
    }

    // --- Header: search icon + query/placeholder + esc badge ---------------
    let header_cy = panel.y as f32 + HEADER_H as f32 * 0.5;
    stroke_circle(
        canvas,
        panel.x as f32 + 27.0,
        header_cy - 1.0,
        6.0,
        1.4,
        tokens.text_tertiary,
    );
    stroke_line(
        canvas,
        panel.x as f32 + 31.2,
        header_cy + 3.2,
        panel.x as f32 + 34.5,
        header_cy + 6.5,
        1.6,
        tokens.text_tertiary,
    );
    let text_x = panel.x + 46;
    let baseline = (header_cy + 18.0 * 0.36) as i32;
    if model.query.is_empty() {
        let _ = draw_text_aa(
            canvas,
            text_x,
            baseline,
            "Search apps, files, settings…",
            ui_font,
            18.0,
            tokens.text_tertiary,
        );
    } else {
        let mut shown = String::from(model.query);
        shown.push('_');
        let _ = draw_text_aa(
            canvas,
            text_x,
            baseline,
            &shown,
            ui_font,
            18.0,
            tokens.text_primary,
        );
    }
    let esc_w = measure_text_aa("esc", mono_font, 10.5);
    let esc_pad = 6;
    let esc_rect = Rect {
        x: panel.x + panel.w as i32 - esc_w - esc_pad * 2 - 18,
        y: panel.y + (HEADER_H as i32 - 20) / 2,
        w: (esc_w + esc_pad * 2) as u32,
        h: 20,
    };
    canvas.draw_rect_border(&esc_rect, tokens.border_default, 1);
    let _ = draw_text_aa(
        canvas,
        esc_rect.x + esc_pad,
        (header_cy + 10.5 * 0.36) as i32,
        "esc",
        mono_font,
        10.5,
        tokens.text_tertiary,
    );

    // --- Body ----------------------------------------------------------------
    let mut cursor_y = panel.y + HEADER_H as i32 + BODY_PAD as i32;

    if model.has_ai {
        let row = Rect {
            x: panel.x + BODY_PAD as i32,
            y: cursor_y,
            w: panel.w - BODY_PAD * 2,
            h: AI_ROW_H,
        };
        let icon = Rect {
            x: row.x + 12,
            y: row.y + (AI_ROW_H as i32 - 34) / 2,
            w: 34,
            h: 34,
        };
        canvas.fill_rounded_rect(&icon, 9, tokens.petrol);
        dock::draw_glyph(canvas, tokens, TileGlyph::Helper, &icon);
        let text_x = icon.x + icon.w as i32 + 13;
        let title_baseline = row.y + AI_ROW_H as i32 / 2 - 2;
        let _ = draw_text_aa(
            canvas,
            text_x,
            title_baseline,
            "Ask NexaCore Helper",
            ui_font,
            13.5,
            tokens.text_primary,
        );
        let mut sub = String::from("\"");
        sub.push_str(model.query);
        sub.push_str("\" — run locally on the node");
        let _ = draw_text_aa(
            canvas,
            text_x,
            title_baseline + 15,
            &sub,
            ui_font,
            12.0,
            tokens.text_secondary,
        );
        cursor_y += AI_ROW_H as i32;
    }

    let heading = if model.query.trim().is_empty() {
        "APP"
    } else {
        "RESULTS"
    };
    let _ = draw_text_aa(
        canvas,
        panel.x + 12 + BODY_PAD as i32,
        cursor_y + 14,
        heading,
        ui_font,
        10.5,
        tokens.text_tertiary,
    );
    cursor_y += HEADING_H as i32;

    for entry in model.results {
        let row = Rect {
            x: panel.x + BODY_PAD as i32,
            y: cursor_y,
            w: panel.w - BODY_PAD * 2,
            h: ROW_H,
        };
        let icon = Rect {
            x: row.x + ROW_PAD_X,
            y: row.y + (ROW_H as i32 - ICON_SIZE as i32) / 2,
            w: ICON_SIZE,
            h: ICON_SIZE,
        };
        let tile_bg = if model.dark {
            TILE_BG_DARK
        } else {
            TILE_BG_LIGHT
        };
        canvas.fill_rounded_rect(&icon, 8, tile_bg);
        draw_entry_icon(canvas, tokens, entry, &icon);

        let text_x = icon.x + icon.w as i32 + 13;
        let title_baseline = row.y + ROW_H as i32 / 2 - 2;
        let _ = draw_text_aa(
            canvas,
            text_x,
            title_baseline,
            entry.title,
            ui_font,
            13.5,
            tokens.text_primary,
        );
        let _ = draw_text_aa(
            canvas,
            text_x,
            title_baseline + 15,
            entry.sub,
            ui_font,
            11.5,
            tokens.text_tertiary,
        );

        let label = kind_label(entry.kind);
        let label_w = measure_text_aa(label, mono_font, 10.0);
        let badge_pad = 7;
        let badge_rect = Rect {
            x: row.x + row.w as i32 - label_w - badge_pad * 2,
            y: row.y + (ROW_H as i32 - 18) / 2,
            w: (label_w + badge_pad * 2) as u32,
            h: 18,
        };
        canvas.draw_rect_border(&badge_rect, tokens.border_default, 1);
        let _ = draw_text_aa(
            canvas,
            badge_rect.x + badge_pad,
            row.y + ROW_H as i32 / 2 + 3,
            label,
            mono_font,
            10.0,
            tokens.text_tertiary,
        );

        cursor_y += ROW_H as i32;
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test literals and lookups over small, known-shape fixtures"
)]
mod tests {
    use super::*;

    // --- fuzzy -------------------------------------------------------------

    #[test]
    fn fuzzy_matches_in_order_subsequence_case_insensitively() {
        assert!(fuzzy("trm", "Terminal").is_some());
        assert!(fuzzy("tls", "settings").is_none(), "not a subsequence");
    }

    #[test]
    fn fuzzy_rewards_consecutive_and_word_start_matches() {
        // "term" is a fully-consecutive, word-start match in "Terminal";
        // "trm" is the same characters but scattered and mid-word for two of
        // the three — it must score strictly lower.
        let consecutive = fuzzy("term", "Terminal").unwrap();
        let scattered = fuzzy("trm", "Terminal").unwrap();
        assert!(consecutive > scattered);
    }

    #[test]
    fn fuzzy_applies_the_length_penalty() {
        // Same query, same score-earning matches, longer haystack: the
        // longer text scores lower purely from `- text.len() / 4`.
        let short = fuzzy("ab", "ab").unwrap();
        let long = fuzzy("ab", "ab______________").unwrap();
        assert!(long < short);
    }

    // --- search --------------------------------------------------------------

    #[test]
    fn empty_query_returns_first_five_apps_in_index_order() {
        let r = search("");
        assert_eq!(r.len(), 5);
        assert!(r.iter().all(|e| e.kind == EntryKind::App));
        assert_eq!(r[0].title, "Terminal");
        assert_eq!(r[1].title, "NexaCore Helper");
        assert_eq!(r[2].title, "Files");
        assert_eq!(r[3].title, "System Monitor");
        assert_eq!(r[4].title, "Control Center");
    }

    #[test]
    fn search_matches_title_and_keywords() {
        let r = search("shell");
        assert!(
            r.iter().any(|e| e.title == "Terminal"),
            "matched via keyword \"shell\""
        );
    }

    #[test]
    fn search_ranks_a_title_match_above_an_unrelated_keyword_hit() {
        let r = search("term");
        assert_eq!(r.first().map(|e| e.title), Some("Terminal"));
    }

    #[test]
    fn search_caps_results_at_six() {
        // A query that fuzzy-matches broadly (single common ASCII letter);
        // the index has 13 entries, so this exercises the take(6) cap.
        let r = search("e");
        assert!(r.len() <= 6);
    }

    #[test]
    fn search_finds_nothing_for_a_query_with_no_subsequence_match() {
        assert!(search("zzzzz").is_empty());
    }

    #[test]
    fn index_placeholders_have_no_app_target() {
        let editor = INDEX.iter().find(|e| e.title == "Text Editor").unwrap();
        assert_eq!(editor.app, None);
        let theme = INDEX.iter().find(|e| e.title == "Appearance").unwrap();
        assert_eq!(theme.app, None);
    }

    #[test]
    fn monitor_and_mesh_entries_open_the_monitor_app() {
        let monitor = INDEX.iter().find(|e| e.title == "System Monitor").unwrap();
        assert_eq!(monitor.app, Some(AppId::Monitor));
        let mesh = INDEX.iter().find(|e| e.title == "Network & Mesh").unwrap();
        assert_eq!(mesh.app, Some(AppId::Monitor));
    }

    #[test]
    fn aspetto_entry_is_a_theme_setting_with_no_app_target() {
        // `main.rs`'s launcher Enter-key handler matches this entry by
        // `title == "Appearance"` to toggle the runtime theme (Milestone 6) —
        // this test locks the exact title string and the `Setting`/`None`
        // shape that match depends on. If this ever fails, update the
        // `main.rs` match alongside whatever changed here.
        let aspetto = INDEX
            .iter()
            .find(|e| e.title == "Appearance")
            .expect("INDEX must contain an Appearance entry");
        assert_eq!(aspetto.kind, EntryKind::Setting);
        assert_eq!(aspetto.app, None);
    }

    // --- LauncherState -------------------------------------------------------

    #[test]
    fn open_clears_the_query_and_close_leaves_it() {
        let mut s = LauncherState::new();
        assert!(!s.is_open());
        s.push_char('x'); // no-op while closed
        assert_eq!(s.query(), "");
        s.open();
        assert!(s.is_open());
        s.push_char('a');
        s.push_char('b');
        assert_eq!(s.query(), "ab");
        s.close();
        assert!(!s.is_open());
        assert_eq!(s.query(), "ab", "close() does not clear; open() does");
        s.open();
        assert_eq!(s.query(), "", "re-opening clears the previous query");
    }

    #[test]
    fn backspace_pops_one_character_and_is_a_no_op_while_closed() {
        let mut s = LauncherState::new();
        s.open();
        s.push_char('a');
        s.push_char('b');
        s.backspace();
        assert_eq!(s.query(), "a");
        s.close();
        s.backspace();
        assert_eq!(s.query(), "a", "no-op while closed");
    }

    #[test]
    fn has_ai_is_false_for_empty_or_whitespace_only_query() {
        let mut s = LauncherState::new();
        s.open();
        assert!(!s.has_ai());
        s.push_char(' ');
        assert!(!s.has_ai());
        s.push_char('q');
        assert!(s.has_ai());
    }

    #[test]
    fn results_delegates_to_search() {
        let mut s = LauncherState::new();
        s.open();
        s.push_char('t');
        s.push_char('e');
        s.push_char('r');
        s.push_char('m');
        assert_eq!(s.results(), search("term"));
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test-only Font::parse/Canvas::new over known-good assets"
)]
mod render_tests {
    use nexacore_display::font::Font;
    use nexacore_ui::canvas::Canvas;

    use super::*;
    use crate::tokens::ShellTokens;

    const W: u32 = 1280;
    const H: u32 = 800;

    fn render_overlay(query: &str) -> Vec<u32> {
        let tokens = ShellTokens::dark();
        let ui = Font::parse(nexacore_fonts::BRAND_UI).unwrap();
        let mono = Font::parse(nexacore_fonts::BRAND_MONO).unwrap();
        // Recognizable backdrop the scrim/panel must visibly change.
        let mut buf = alloc::vec![0xFF55_5555u32; (W * H) as usize];
        let results = search(query);
        let model = LauncherModel {
            query,
            results: &results,
            has_ai: !query.trim().is_empty(),
            dark: true,
        };
        {
            let mut c = Canvas::new(&mut buf, W, H).unwrap();
            render(&mut c, &tokens, &ui, &mono, &model, W, H);
        }
        buf
    }

    #[test]
    fn monitor_entry_reuses_the_real_dock_glyph_not_the_generic_fallback() {
        let tokens = ShellTokens::dark();
        let r = Rect {
            x: 10,
            y: 10,
            w: ICON_SIZE,
            h: ICON_SIZE,
        };
        let monitor_entry = INDEX.iter().find(|e| e.title == "System Monitor").unwrap();
        let placeholder_entry = INDEX.iter().find(|e| e.title == "Appearance").unwrap();

        let mut monitor_buf = alloc::vec![0u32; 40 * 40];
        {
            let mut c = Canvas::new(&mut monitor_buf, 40, 40).unwrap();
            draw_entry_icon(&mut c, &tokens, monitor_entry, &r);
        }
        let mut dock_buf = alloc::vec![0u32; 40 * 40];
        {
            let mut c = Canvas::new(&mut dock_buf, 40, 40).unwrap();
            dock::draw_glyph(&mut c, &tokens, TileGlyph::Monitor, &r);
        }
        assert_eq!(
            monitor_buf, dock_buf,
            "a Monitor-app result must draw the exact dock concentric-rings glyph"
        );

        let mut placeholder_buf = alloc::vec![0u32; 40 * 40];
        {
            let mut c = Canvas::new(&mut placeholder_buf, 40, 40).unwrap();
            draw_entry_icon(&mut c, &tokens, placeholder_entry, &r);
        }
        assert_ne!(
            monitor_buf, placeholder_buf,
            "an app-less entry must not draw the same pixels as the dock glyph"
        );
    }

    #[test]
    fn editor_and_aspetto_entries_get_bespoke_glyphs_not_the_generic_fallback() {
        let editor = INDEX.iter().find(|e| e.title == "Text Editor").unwrap();
        let aspetto = INDEX.iter().find(|e| e.title == "Appearance").unwrap();
        let tokens = ShellTokens::dark();
        let r = Rect {
            x: 0,
            y: 0,
            w: ICON_SIZE,
            h: ICON_SIZE,
        };

        let mut editor_buf = alloc::vec![0xFF10_1010u32; (ICON_SIZE * ICON_SIZE) as usize];
        let mut generic_app_buf = editor_buf.clone();
        {
            let mut c = Canvas::new(&mut editor_buf, ICON_SIZE, ICON_SIZE).unwrap();
            draw_entry_icon(&mut c, &tokens, editor, &r);
        }
        {
            // `EntryKind::App`'s generic fallback ring, for comparison — any
            // OTHER `App`-kind entry with a real `app` never reaches this
            // path, so build the ring directly.
            let mut c = Canvas::new(&mut generic_app_buf, ICON_SIZE, ICON_SIZE).unwrap();
            draw_kind_glyph(&mut c, &tokens, EntryKind::App, &r);
        }
        assert_ne!(
            editor_buf, generic_app_buf,
            "Text Editor must draw its own pencil glyph, not the generic App ring"
        );

        let mut aspetto_buf = alloc::vec![0xFF10_1010u32; (ICON_SIZE * ICON_SIZE) as usize];
        let mut generic_setting_buf = aspetto_buf.clone();
        {
            let mut c = Canvas::new(&mut aspetto_buf, ICON_SIZE, ICON_SIZE).unwrap();
            draw_entry_icon(&mut c, &tokens, aspetto, &r);
        }
        {
            let mut c = Canvas::new(&mut generic_setting_buf, ICON_SIZE, ICON_SIZE).unwrap();
            draw_kind_glyph(&mut c, &tokens, EntryKind::Setting, &r);
        }
        assert_ne!(
            aspetto_buf, generic_setting_buf,
            "Appearance must draw its own bisected-circle glyph, not the generic Setting ring+bar"
        );
    }

    #[test]
    fn scrim_darkens_the_whole_backdrop() {
        let buf = render_overlay("");
        assert!(
            buf.iter().all(|&p| p != 0xFF55_5555),
            "every pixel must be touched by the scrim blend"
        );
    }

    #[test]
    fn panel_area_differs_from_the_scrim_only_backdrop() {
        let empty_query = render_overlay("zzzzznomatch");
        let with_results = render_overlay("term");
        // Different result counts must paint different pixels somewhere
        // inside the panel's row area (the row-count-dependent panel height
        // and row contents differ).
        assert_ne!(empty_query, with_results);
    }

    #[test]
    fn does_not_panic_at_a_narrow_or_short_screen() {
        const NW: u32 = 320;
        const NH: u32 = 200;
        let tokens = ShellTokens::dark();
        let ui = Font::parse(nexacore_fonts::BRAND_UI).unwrap();
        let mono = Font::parse(nexacore_fonts::BRAND_MONO).unwrap();
        let mut buf = alloc::vec![0u32; (NW * NH) as usize];
        let results = search("");
        let model = LauncherModel {
            query: "",
            results: &results,
            has_ai: false,
            dark: true,
        };
        let mut c = Canvas::new(&mut buf, NW, NH).unwrap();
        render(&mut c, &tokens, &ui, &mono, &model, NW, NH);
    }
}
