//! Settings window: rendering + AI-endpoint config load/save.
//!
//! Split out of `main.rs` (mechanical, no behaviour change).

use alloc::string::String;

use nexacore_desktop_shell::{
    frame::{FrameButton, FrameVariant, WindowFrame, TITLEBAR_H},
    tokens::ShellTokens,
};
use nexacore_display::{compositor::Compositor, geometry::Rect, surface::WindowId};
use nexacore_types::{
    config::{AiEndpointConfig, AI_CONFIG_PATH},
    fs_service::{FsErrno, FsRequest, FsResponse},
    wire::{decode_canonical, encode_canonical},
};
use nexacore_ui::{canvas::Canvas, text::GLYPH_H};

use crate::gfx::{mono_text, present, ui_font, ui_text, write_display_error, ChromeState};
use crate::{append_dec, exit, fs_available, fs_request, write, PAD, SET_H, SET_W};

// =============================================================================
// Settings logic
// =============================================================================

/// Load the AI config from NCFS into `endpoint_buf` and `model`.
///
/// On absent or corrupt config, falls back to [`AiEndpointConfig::default`]
/// and sets `status` to `"using defaults"`.  Never panics.
pub(crate) fn settings_load(endpoint_buf: &mut String, model: &mut String, status: &mut String) {
    if !fs_available() {
        let def = AiEndpointConfig::default();
        *endpoint_buf = build_endpoint_buf(&def.host, def.port);
        *model = def.model.clone();
        *status = String::from("FS unavailable — using defaults");
        return;
    }

    let read_resp = fs_request(&FsRequest::Read {
        path: String::from(AI_CONFIG_PATH),
        offset: 0,
        len: 3072,
    });

    let cfg = match read_resp {
        Some(FsResponse::Data { bytes }) => match decode_canonical::<AiEndpointConfig>(&bytes) {
            Ok(c) => {
                write("[nexacore-apps] settings: loaded config from FS\n");
                c
            }
            Err(_) => {
                write("[nexacore-apps] settings: corrupt config — using defaults\n");
                *status = String::from("corrupt config — using defaults");
                AiEndpointConfig::default()
            }
        },
        Some(FsResponse::Error(FsErrno::NotFound)) | None => {
            write("[nexacore-apps] settings: config absent — using defaults\n");
            *status = String::from("using defaults");
            AiEndpointConfig::default()
        }
        _ => {
            write("[nexacore-apps] settings: config read failed — using defaults\n");
            *status = String::from("using defaults");
            AiEndpointConfig::default()
        }
    };

    *endpoint_buf = build_endpoint_buf(&cfg.host, cfg.port);
    *model = cfg.model.clone();
}

/// Build the `"host:port"` display string from separate components.
pub(crate) fn build_endpoint_buf(host: &str, port: u16) -> String {
    let mut s = String::from(host);
    s.push(':');
    append_dec(&mut s, port as usize);
    s
}

/// Validate, and if valid persist, the AI config from `endpoint_buf`.
///
/// Parses `endpoint_buf` as `"host:port"` (split on the last `':'`).  Calls
/// [`AiEndpointConfig::validate`]; on failure sets `status` to
/// `"invalid endpoint"` and does NOT write.  On success: `Mkdir /config`
/// (idempotent), `Write`, `Sync`.
pub(crate) fn settings_save(endpoint_buf: &str, model: &str, status: &mut String) {
    // Parse "host:port" — split on the LAST colon so IPv6 (future) still works.
    let split_pos = match endpoint_buf.rfind(':') {
        Some(p) => p,
        None => {
            *status = String::from("invalid endpoint");
            write("[nexacore-apps] settings: invalid endpoint rejected (no colon)\n");
            return;
        }
    };

    let host = &endpoint_buf[..split_pos];
    let port_str = &endpoint_buf[split_pos + 1..];

    let port: u16 = {
        let mut val: u32 = 0;
        let mut ok = !port_str.is_empty();
        for b in port_str.bytes() {
            if !b.is_ascii_digit() {
                ok = false;
                break;
            }
            val = val * 10 + u32::from(b - b'0');
            if val > 65535 {
                ok = false;
                break;
            }
        }
        if !ok {
            *status = String::from("invalid endpoint");
            write("[nexacore-apps] settings: invalid endpoint rejected (bad port)\n");
            return;
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "val <= 65535 enforced by the loop above"
        )]
        {
            val as u16
        }
    };

    let cfg = AiEndpointConfig {
        host: String::from(host),
        port,
        model: String::from(model),
    };

    // Validate before any write.
    if let Err(_e) = cfg.validate() {
        *status = String::from("invalid endpoint");
        write("[nexacore-apps] settings: invalid endpoint rejected\n");
        return;
    }

    // Encode the config.
    let encoded = match encode_canonical(&cfg) {
        Ok(b) => b,
        Err(_) => {
            *status = String::from("encode error");
            write("[nexacore-apps] settings: encode failed\n");
            return;
        }
    };

    if !fs_available() {
        *status = String::from("FS unavailable — not saved");
        write("[nexacore-apps] settings: FS not available, save skipped\n");
        return;
    }

    // `AI_CONFIG_PATH` is root-level (the nexacore-fs on-disk format flattens
    // nested paths on remount — ADR-0045), so no directory is created here.

    // Truncate-write the config file.
    let write_resp = fs_request(&FsRequest::Write {
        path: String::from(AI_CONFIG_PATH),
        offset: 0,
        data: encoded,
    });
    match write_resp {
        Some(FsResponse::Ok) => {}
        Some(FsResponse::Error(_)) | None => {
            *status = String::from("write failed");
            write("[nexacore-apps] settings: write failed\n");
            return;
        }
        _ => {}
    }

    // Sync for durability.
    let sync_resp = fs_request(&FsRequest::Sync);
    match sync_resp {
        Some(FsResponse::Ok) => {}
        Some(FsResponse::Error(_)) | None => {
            *status = String::from("sync failed");
            write("[nexacore-apps] settings: sync failed\n");
            return;
        }
        _ => {}
    }

    // Success.
    write("[nexacore-apps] settings: saved ");
    write(host);
    write(":");
    write(port_str);
    write("\n");

    // Build "saved host:port — reboot to apply" status message.
    let mut s = String::from("saved ");
    s.push_str(host);
    s.push(':');
    s.push_str(port_str);
    s.push_str(" -- reboot to apply");
    *status = s;
}

// =============================================================================
// Settings rendering
// =============================================================================

/// Layout constants for the Appearance (theme) section added below the
/// existing hint line in Milestone 6. `ROW_H` matches `render_settings`'s
/// own local `line_h` (`GLYPH_H * 2`) so the two never drift apart; the
/// three `APPEARANCE_*` constants replay the exact same running-`y`
/// arithmetic `render_settings` already does for the title/endpoint/
/// model/hint rows above them, so `appearance_rects` (called both by
/// `render_settings` and by `main.rs`'s pointer-content handler) always
/// agrees with where the section is actually drawn.
#[allow(
    clippy::cast_possible_wrap,
    reason = "TITLEBAR_H/PAD/GLYPH_H are small positive pixel constants"
)]
const ROW_H: i32 = (GLYPH_H * 2) as i32;
#[allow(
    clippy::cast_possible_wrap,
    reason = "TITLEBAR_H/PAD/GLYPH_H are small positive pixel constants"
)]
const APPEARANCE_HEADER_Y: i32 =
    (TITLEBAR_H + PAD) as i32 + ROW_H + PAD as i32 + ROW_H + ROW_H + ROW_H + PAD as i32;
const APPEARANCE_SUB_Y: i32 = APPEARANCE_HEADER_Y + ROW_H;
const APPEARANCE_SEG_Y: i32 = APPEARANCE_SUB_Y + ROW_H + PAD as i32;
/// Segmented-control button size (mouse-clickable Light/Dark toggle).
const SEG_BTN_W: u32 = 96;
const SEG_BTN_H: u32 = 28;

/// Window-relative hit-rects for the Appearance segmented control's two
/// buttons, `(light_rect, dark_rect)`. Same coordinate space as this
/// window's own render canvas and as `PointerAction::FocusContent`'s
/// `(x, y)` — used both to draw the buttons (`render_settings`) and to
/// hit-test a content press against them (`main.rs`).
#[must_use]
pub(crate) fn appearance_rects() -> (Rect, Rect) {
    let light = Rect {
        x: PAD as i32,
        y: APPEARANCE_SEG_Y,
        w: SEG_BTN_W,
        h: SEG_BTN_H,
    };
    let dark = Rect {
        x: PAD as i32 + SEG_BTN_W as i32,
        y: APPEARANCE_SEG_Y,
        w: SEG_BTN_W,
        h: SEG_BTN_H,
    };
    (light, dark)
}

/// Render the Settings window into `pixels` and commit + present.
///
/// Layout within `SET_W × SET_H`:
/// - `y ∈ [0, TITLEBAR_H)` — the shell frame's titlebar (Standard variant).
/// - Title: `"Settings — AI backend"`.
/// - `"endpoint: <set_endpoint_buf>_"` — the editable buffer with a cursor.
/// - `"model: <set_model>"` — the current model name (read-only in v1).
/// - Hint line: `"[type host:port, Esc=save]"`.
/// - Status line: operation feedback (last save result or error).
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_settings(
    endpoint_buf: &str,
    model: &str,
    set_status: &str,
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
        let mut canvas = match Canvas::new(pixels, SET_W, SET_H) {
            Ok(c) => c,
            Err(_) => {
                write("[nexacore-apps] settings: Canvas::new failed\n");
                exit(50);
            }
        };

        canvas.fill(tokens.bg_surface);

        // Shell frame: 42px titlebar, Standard variant.
        let frame = WindowFrame {
            title: "Control Center",
            focused,
            hover,
            variant: FrameVariant::Standard,
        };
        frame.render(&mut canvas, tokens, ui_font(), SET_W);

        let line_h = (GLYPH_H * 2) as i32;
        let mut y = (TITLEBAR_H + PAD) as i32;

        // Title.
        ui_text(
            &mut canvas,
            PAD as i32,
            y,
            "Settings -- AI backend",
            tokens.text_primary,
        );
        y += line_h + PAD as i32;

        // Endpoint buffer with trailing cursor underscore.
        let mut ep_line = String::from("endpoint: ");
        ep_line.push_str(endpoint_buf);
        ep_line.push('_');
        ui_text(&mut canvas, PAD as i32, y, &ep_line, tokens.text_primary);
        y += line_h;

        // Model (read-only in v1).
        let mut model_line = String::from("model: ");
        model_line.push_str(model);
        ui_text(
            &mut canvas,
            PAD as i32,
            y,
            &model_line,
            tokens.text_secondary,
        );
        y += line_h;

        // Hint.
        ui_text(
            &mut canvas,
            PAD as i32,
            y,
            "[type host:port, Esc=save]",
            tokens.text_primary,
        );

        // Appearance (theme) section (WS7 desktop M6): a Light/Dark segmented
        // control. Mouse-clickable via `appearance_rects`' rects, which
        // `main.rs`'s `PointerAction::FocusContent(AppId::Settings, x, y)`
        // handler hit-tests against directly.
        ui_text(
            &mut canvas,
            PAD as i32,
            APPEARANCE_HEADER_Y,
            "Appearance",
            tokens.text_primary,
        );
        mono_text(
            &mut canvas,
            PAD as i32,
            APPEARANCE_SUB_Y,
            "System theme",
            tokens.text_tertiary,
        );
        let (light_rect, dark_rect) = appearance_rects();
        let (light_bg, light_fg) = if chrome.dark {
            (tokens.bg_surface_2, tokens.text_secondary)
        } else {
            (tokens.sage, tokens.bg_surface)
        };
        let (dark_bg, dark_fg) = if chrome.dark {
            (tokens.sage, tokens.bg_surface)
        } else {
            (tokens.bg_surface_2, tokens.text_secondary)
        };
        canvas.fill_rounded_rect(&light_rect, 6, light_bg);
        canvas.fill_rounded_rect(&dark_rect, 6, dark_bg);
        canvas.draw_rect_border(&light_rect, tokens.border_default, 1);
        canvas.draw_rect_border(&dark_rect, tokens.border_default, 1);
        mono_text(
            &mut canvas,
            light_rect.x + 14,
            light_rect.y + 10,
            "Light",
            light_fg,
        );
        mono_text(
            &mut canvas,
            dark_rect.x + 18,
            dark_rect.y + 10,
            "Dark",
            dark_fg,
        );

        // Status line at bottom.
        let status_y = (SET_H as i32) - line_h;
        if !set_status.is_empty() {
            ui_text(&mut canvas, PAD as i32, status_y, set_status, tokens.sage);
        }
    }

    if let Err(e) = compositor.commit_surface(win_id, pixels, &[]) {
        write("[nexacore-apps] settings: commit_surface failed: ");
        write_display_error(&e);
        write("\n");
    }
    present(
        compositor, back, front_va, screen_w, screen_h, stride, chrome, tokens,
    );
}
