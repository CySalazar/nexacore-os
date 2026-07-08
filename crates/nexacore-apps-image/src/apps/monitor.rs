//! System Monitor window: rendering only, no persistence.
//!
//! Replaces the placeholder Editor window (which occupied this dock/launcher
//! slot from M1 but was never reachable) as of WS7 desktop-shell M5. See
//! `docs/superpowers/plans/2026-07-06-desktop-shell-m5.md` for the full
//! rationale. CPU/Memory are now live (the `SysInfo (114)` syscall, see
//! `crate::sysinfo`); the Mesh/TEE Attestation cards remain static
//! placeholders — no host-reachable IPC surface exists in
//! `omni-apps-image` for either of those two data sources yet.

use alloc::{format, string::String};

use nexacore_desktop_shell::{
    frame::{FrameButton, FrameVariant, WindowFrame, TITLEBAR_H},
    tokens::ShellTokens,
};
use nexacore_display::{compositor::Compositor, geometry::Rect, surface::WindowId};
use nexacore_ui::{
    canvas::Canvas,
    status_bar::{BackendState, OLLAMA_HOST, OLLAMA_MODEL},
};

use crate::gfx::{mono_text, present, ui_font, ui_text, write_display_error, ChromeState};
use crate::{exit, write, MONITOR_H, MONITOR_W, PAD};

/// Outer margin and inter-card gap (this window's own layout unit — not a
/// pixel-for-pixel translation of the mockup's CSS grid, which has no fixed
/// row heights to copy; see the M5 plan's "Plan-level decisions").
const CARD_GAP: i32 = 12;
/// Row 1 ("AI Backend") card height.
const BACKEND_CARD_H: i32 = 64;
/// Row 2 (Mesh / TEE Attestation) card height.
const HALF_CARD_H: i32 = 120;
/// Row 3 (CPU / Memory / Uptime) tile height.
const TILE_ROW_H: i32 = 80;
/// Card/tile corner radius.
const CARD_RADIUS: u32 = 10;

/// Formats an uptime in minutes as `"{h}h {m}m"` (hours omitted below 60
/// minutes, e.g. `"0m"`/`"59m"`/`"4h 12m"`) — the same hour/minute split as
/// `nexacore_desktop_shell::menubar::format_uptime`, without its `"up "`
/// prefix (the Monitor tile's own label already says `"Uptime"`).
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

/// The "AI Backend" card's badge fill colour and label for `state`, reusing
/// the same three health colours the menu-bar pill and Helper status strip
/// already use (see `gfx::ChromeState::set_ai_state`).
fn backend_badge(tokens: &ShellTokens, state: BackendState) -> (u32, &'static str) {
    match state {
        BackendState::Gpu => (tokens.sage, "HEALTHY"),
        BackendState::CpuDegraded => (tokens.warning, "CPU FALLBACK"),
        BackendState::Unknown => (tokens.brick, "OFFLINE"),
    }
}

/// Draws a bordered rounded-rect card background at `rect`.
fn card_bg(canvas: &mut Canvas<'_>, tokens: &ShellTokens, rect: &Rect) {
    canvas.fill_rounded_rect(rect, CARD_RADIUS, tokens.bg_surface_2);
}

/// Render the System Monitor window into `pixels` and commit + present.
///
/// `ai_state` and `uptime_minutes` are live inputs computed by every call
/// site before this is called; `sysinfo` is the `SysInfo (114)` syscall's
/// result (`None` falls back to the previous "N/A" placeholder). Mesh/TEE
/// remain static placeholders — see the module doc.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn render_monitor(
    ai_state: BackendState,
    uptime_minutes: u32,
    sysinfo: Option<crate::sysinfo::SysInfo>,
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
        let mut canvas = match Canvas::new(pixels, MONITOR_W, MONITOR_H) {
            Ok(c) => c,
            Err(_) => {
                write("[nexacore-apps] monitor: Canvas::new failed\n");
                exit(50);
            }
        };

        canvas.fill(tokens.bg_surface);

        let frame = WindowFrame {
            title: "System Monitor",
            focused,
            hover,
            variant: FrameVariant::Standard,
        };
        frame.render(&mut canvas, tokens, ui_font(), MONITOR_W);

        #[allow(
            clippy::cast_possible_wrap,
            reason = "PAD/TITLEBAR_H/MONITOR_W/MONITOR_H are small positive pixel metrics"
        )]
        let content_x = PAD as i32;
        #[allow(clippy::cast_possible_wrap, reason = "small positive pixel metric")]
        let content_top = (TITLEBAR_H + PAD) as i32;
        #[allow(clippy::cast_possible_wrap, reason = "small positive pixel metric")]
        let content_w = MONITOR_W as i32 - 2 * content_x;

        // --- Row 1: AI Backend ------------------------------------------------
        let mut y = content_top;
        let backend_rect = Rect {
            x: content_x,
            y,
            w: content_w as u32,
            h: BACKEND_CARD_H as u32,
        };
        card_bg(&mut canvas, tokens, &backend_rect);
        ui_text(
            &mut canvas,
            backend_rect.x + PAD as i32,
            backend_rect.y + PAD as i32,
            "AI Backend -- GPU",
            tokens.text_primary,
        );
        let subtitle = format!("{OLLAMA_HOST} · {OLLAMA_MODEL}");
        mono_text(
            &mut canvas,
            backend_rect.x + PAD as i32,
            backend_rect.y + PAD as i32 + 18,
            &subtitle,
            tokens.text_secondary,
        );
        let (badge_bg, badge_label) = backend_badge(tokens, ai_state);
        let badge_w: u32 = 90;
        let badge_h: u32 = 22;
        let badge_rect = Rect {
            x: backend_rect.x + backend_rect.w as i32 - badge_w as i32 - PAD as i32,
            y: backend_rect.y + (BACKEND_CARD_H - badge_h as i32) / 2,
            w: badge_w,
            h: badge_h,
        };
        canvas.fill_rounded_rect(&badge_rect, badge_h / 2, badge_bg);
        mono_text(
            &mut canvas,
            badge_rect.x + 10,
            badge_rect.y + 6,
            badge_label,
            tokens.bg_surface,
        );
        y += BACKEND_CARD_H + CARD_GAP;

        // --- Row 2: Mesh | TEE Attestation ------------------------------------
        // PLACEHOLDER (M5): no host-reachable mesh-peer or TEE-attestation IPC
        // surface exists in `omni-apps-image` yet (see the M5 plan's
        // "Plan-level decisions"). Values mirror the design mockup's own
        // literal example data, which is itself static (not live-bound).
        let half_w = (content_w - CARD_GAP) / 2;
        let mesh_rect = Rect {
            x: content_x,
            y,
            w: half_w as u32,
            h: HALF_CARD_H as u32,
        };
        card_bg(&mut canvas, tokens, &mesh_rect);
        ui_text(
            &mut canvas,
            mesh_rect.x + PAD as i32,
            mesh_rect.y + PAD as i32,
            "Mesh · 3 peers",
            tokens.text_primary,
        );
        for (i, row) in ["node-01   1.2 ms", "node-02   3.4 ms", "node-03   4.1 ms"]
            .iter()
            .enumerate()
        {
            mono_text(
                &mut canvas,
                mesh_rect.x + PAD as i32,
                mesh_rect.y + PAD as i32 + 22 + (i as i32) * 18,
                row,
                tokens.text_secondary,
            );
        }

        let tee_rect = Rect {
            x: content_x + half_w + CARD_GAP,
            y,
            w: half_w as u32,
            h: HALF_CARD_H as u32,
        };
        card_bg(&mut canvas, tokens, &tee_rect);
        ui_text(
            &mut canvas,
            tee_rect.x + PAD as i32,
            tee_rect.y + PAD as i32,
            "TEE Attestation",
            tokens.text_primary,
        );
        for (i, row) in [
            "status     verified",
            "measure    0x9f3a...c2e1",
            "quote      SEV-SNP",
        ]
        .iter()
        .enumerate()
        {
            mono_text(
                &mut canvas,
                tee_rect.x + PAD as i32,
                tee_rect.y + PAD as i32 + 22 + (i as i32) * 18,
                row,
                tokens.text_secondary,
            );
        }
        y += HALF_CARD_H + CARD_GAP;

        // --- Row 3: CPU / Memory / Uptime tiles -------------------------------
        let tile_w = (content_w - 2 * CARD_GAP) / 3;
        let tiles: [(&str, String); 3] = [
            // Live: SysInfo (114) reports the enabled logical-CPU count
            // (not an instantaneous load percentage — no per-core
            // utilization sampling exists in the kernel yet).
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
            // Live: SysInfo (114) reports free/total physical RAM from the
            // kernel's frame allocator.
            (
                "Memory",
                sysinfo.map_or_else(
                    || String::from("N/A"),
                    |s| format!("{}/{} MiB", s.total_mib.saturating_sub(s.free_mib), s.total_mib),
                ),
            ),
            // Live: reuses the same uptime source as the menu-bar clock.
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
        write("[nexacore-apps] monitor: commit_surface failed: ");
        write_display_error(&e);
        write("\n");
    }
    present(
        compositor, back, front_va, screen_w, screen_h, stride, chrome, tokens,
    );
}
