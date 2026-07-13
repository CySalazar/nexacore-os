//! System Info window: static build provenance + live CPU/RAM/uptime.
//!
//! Rendering only, no persistence. Launcher-only (no dock tile, see
//! `router::AppId::SystemInfo` and the `shellsync` module doc) — reachable
//! only via the Launcher's "System Info" entry.
//!
//! Every rendered string here is a hand-written literal ("NexaCore OS",
//! "System Info", card labels) — never derived from `CARGO_PKG_NAME` (which
//! would resolve to the crate's internal package name), so no internal
//! "omni" naming ever leaks into this window.

use alloc::{format, string::String};

use nexacore_desktop_shell::{
    frame::{FrameButton, FrameVariant, TITLEBAR_H, WindowFrame},
    tokens::ShellTokens,
};
use nexacore_display::{compositor::Compositor, geometry::Rect, surface::WindowId};
use nexacore_ui::canvas::Canvas;

use crate::gfx::{ChromeState, mono_text, present, ui_font, ui_text, write_display_error};
use crate::{PAD, SYSINFO_H, SYSINFO_W, exit, sysinfo::SysInfo, write};

/// User-facing product version shown in the identity card.
///
/// Deliberately NOT `env!("CARGO_PKG_VERSION")`: this image crate's Cargo
/// version tracks the workspace crate version, whereas the shipped product
/// carries its own user-facing release string. Single source of truth for
/// the value shown here; keep it in sync with the GitHub release tag and
/// `nexacoreos.com` (the site's "Current build" line).
const PRODUCT_VERSION: &str = "0.3.0-alpha.2";

/// Outer margin and inter-card gap (mirrors `apps::monitor`'s layout unit).
const CARD_GAP: i32 = 12;
/// Identity card ("NexaCore OS" + version + build date) height.
const IDENTITY_CARD_H: i32 = 88;
/// Hardware tile row height (CPU / Memory / Uptime).
const TILE_ROW_H: i32 = 80;
/// Card/tile corner radius.
const CARD_RADIUS: u32 = 10;

/// Formats an uptime in minutes as `"{h}h {m}m"` — duplicated from
/// `apps::monitor::format_uptime_short` (small, self-contained helper; see
/// that module's own doc for why this codebase prefers a owned copy over
/// cross-module coupling for an 8-line function).
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "whole hours/minutes-of-hour split; fractional remainder is meaningless here"
)]
fn format_uptime_short(minutes: u32) -> String {
    let hours = minutes / 60;
    let mins = minutes % 60;
    if hours == 0 {
        format!("{mins}m")
    } else {
        format!("{hours}h {mins}m")
    }
}

/// Draws a bordered rounded-rect card background at `rect`.
fn card_bg(canvas: &mut Canvas<'_>, tokens: &ShellTokens, rect: &Rect) {
    canvas.fill_rounded_rect(rect, CARD_RADIUS, tokens.bg_surface_2);
}

/// Render the System Info window into `pixels` and commit + present.
///
/// `sysinfo` is the `SysInfo (114)` syscall's result (`None` falls back to
/// an "N/A" placeholder, mirroring `apps::monitor`). The version is the
/// user-facing [`PRODUCT_VERSION`]; the build date comes from a
/// `build.rs`-injected `env!()` value.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_system_info(
    sysinfo: Option<SysInfo>,
    uptime_minutes: u32,
    pixels: &mut [u32],
    win_id: WindowId,
    tokens: &ShellTokens,
    focused: bool,
    hover: Option<FrameButton>,
    compositor: &mut Compositor,
    back: &mut [u32],
    front_va: u64,
    screen_w: u32,
    screen_h: u32,
    stride: u32,
    chrome: &mut ChromeState,
) {
    {
        let mut canvas = match Canvas::new(pixels, SYSINFO_W, SYSINFO_H) {
            Ok(c) => c,
            Err(_) => {
                write("[nexacore-apps] system_info: Canvas::new failed\n");
                exit(51);
            }
        };

        canvas.fill(tokens.bg_surface);

        let frame = WindowFrame {
            title: "System Info",
            focused,
            hover,
            variant: FrameVariant::Standard,
        };
        frame.render(&mut canvas, tokens, ui_font(), SYSINFO_W);

        #[allow(
            clippy::cast_possible_wrap,
            reason = "PAD/TITLEBAR_H/SYSINFO_W/SYSINFO_H are small positive pixel metrics"
        )]
        let content_x = PAD as i32;
        #[allow(clippy::cast_possible_wrap, reason = "small positive pixel metric")]
        let content_top = (TITLEBAR_H + PAD) as i32;
        #[allow(clippy::cast_possible_wrap, reason = "small positive pixel metric")]
        let content_w = SYSINFO_W as i32 - 2 * content_x;

        // --- Identity card: NexaCore OS name + real build provenance ---------
        let mut y = content_top;
        let identity_rect = Rect {
            x: content_x,
            y,
            w: content_w as u32,
            h: IDENTITY_CARD_H as u32,
        };
        card_bg(&mut canvas, tokens, &identity_rect);
        ui_text(
            &mut canvas,
            identity_rect.x + PAD as i32,
            identity_rect.y + PAD as i32,
            "NexaCore OS",
            tokens.text_primary,
        );
        let version_line = format!("v{PRODUCT_VERSION}");
        mono_text(
            &mut canvas,
            identity_rect.x + PAD as i32,
            identity_rect.y + PAD as i32 + 20,
            &version_line,
            tokens.text_secondary,
        );
        let built_line = format!("built {}", env!("NEXACORE_BUILD_DATE"));
        mono_text(
            &mut canvas,
            identity_rect.x + PAD as i32,
            identity_rect.y + PAD as i32 + 38,
            &built_line,
            tokens.text_tertiary,
        );
        y += IDENTITY_CARD_H + CARD_GAP;

        // --- Hardware tiles: CPU / Memory / Uptime ----------------------------
        let tile_w = (content_w - 2 * CARD_GAP) / 3;
        let tiles: [(&str, String); 3] = [
            (
                "CPU",
                sysinfo.map_or_else(
                    || String::from("N/A"),
                    |s| {
                        format!(
                            "{} core{}",
                            s.cpu_count,
                            if s.cpu_count == 1 { "" } else { "s" }
                        )
                    },
                ),
            ),
            (
                "Memory",
                sysinfo.map_or_else(
                    || String::from("N/A"),
                    |s| {
                        format!(
                            "{}/{} MiB",
                            s.total_mib.saturating_sub(s.free_mib),
                            s.total_mib
                        )
                    },
                ),
            ),
            ("Uptime", format_uptime_short(uptime_minutes)),
        ];
        for (i, (label, value)) in tiles.iter().enumerate() {
            let tile_x = content_x + (i as i32) * (tile_w + CARD_GAP);
            let tile_rect = Rect {
                x: tile_x,
                y,
                w: tile_w as u32,
                h: TILE_ROW_H as u32,
            };
            canvas.draw_rect_border(&tile_rect, tokens.border_default, 1);
            mono_text(
                &mut canvas,
                tile_rect.x + PAD as i32,
                tile_rect.y + PAD as i32,
                label,
                tokens.text_tertiary,
            );
            ui_text(
                &mut canvas,
                tile_rect.x + PAD as i32,
                tile_rect.y + PAD as i32 + 22,
                value,
                tokens.text_primary,
            );
        }
    }

    if let Err(e) = compositor.commit_surface(win_id, pixels, &[]) {
        write("[nexacore-apps] system_info: commit_surface failed: ");
        write_display_error(&e);
        write("\n");
    }
    present(
        compositor, back, front_va, screen_w, screen_h, stride, chrome, tokens,
    );
}
