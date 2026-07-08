//! Terminal window: rendering + scrolling history.
//!
//! Split out of `main.rs` (mechanical, no behaviour change).

use alloc::string::String;
use alloc::vec::Vec;

use nexacore_desktop_shell::{
    frame::{FrameButton, FrameVariant, WindowFrame, TITLEBAR_H},
    tokens::ShellTokens,
};
use nexacore_display::{compositor::Compositor, surface::WindowId};
use nexacore_ui::{
    canvas::Canvas,
    text::{measure_text_aa, GLYPH_H},
};

use crate::gfx::{
    mono_font, mono_text, present, ui_font, write_display_error, ChromeState, MONO_PX,
};
use crate::{exit, write, PAD, TERM_H, TERM_W};

/// Height of the prompt/input line at the bottom of the terminal (pixels).
pub(crate) const PROMPT_LINE_H: u32 = GLYPH_H * 2;

/// Number of visible history lines in the terminal window.
///
/// Task 7: the content area now starts below the shell frame's titlebar
/// (`TITLEBAR_H = 42`) rather than the old AI status bar (`BAR_H = 34`).
pub(crate) const TERM_VISIBLE_LINES: u32 = {
    let content_h = TERM_H - TITLEBAR_H - PAD * 2 - PROMPT_LINE_H;
    content_h / (GLYPH_H * 2)
};

/// Maximum entries in the terminal history `Vec<String>` before truncation.
///
/// Keeps bump-heap growth bounded per session.  Older lines are dropped
/// from the front when the cap is exceeded.
pub(crate) const TERM_HISTORY_CAP: usize = 200;

// =============================================================================
// Terminal rendering
// =============================================================================

/// Render the terminal window into `pixels` and commit + present.
///
/// Layout (top-to-bottom within `TERM_W × TERM_H`):
/// - `y ∈ [0, TITLEBAR_H)` — the shell frame's titlebar (Terminal variant).
/// - `y ∈ [TITLEBAR_H, TERM_H - PROMPT_LINE_H)` — scrolling history lines.
/// - `y ∈ [TERM_H - PROMPT_LINE_H, TERM_H)` — prompt + current input.
///
/// The most recent `TERM_VISIBLE_LINES` history entries are displayed;
/// older entries scroll off upward.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_terminal(
    history: &[String],
    input: &str,
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
    // Inner scope so that `canvas` (which borrows `pixels`) is dropped
    // before `commit_surface` needs exclusive access to `pixels`.
    {
        let mut canvas = match Canvas::new(pixels, TERM_W, TERM_H) {
            Ok(c) => c,
            Err(_) => {
                write("[nexacore-apps] terminal: Canvas::new failed\n");
                exit(50);
            }
        };

        // Background: the terminal's always-dark content surface.
        canvas.fill(tokens.term_bg);

        // Shell frame: 42px titlebar, Terminal variant (dark titlebar shares
        // `term_bg` by design — separation comes from the frame's bottom
        // hairline, not a colour difference; see ShellTokens docs).
        let frame = WindowFrame {
            title: "Terminal",
            focused,
            hover,
            variant: FrameVariant::Terminal,
        };
        frame.render(&mut canvas, tokens, ui_font(), TERM_W);

        // History lines — most recent `TERM_VISIBLE_LINES` from the end.
        let vis = TERM_VISIBLE_LINES as usize;
        let start = if history.len() > vis {
            history.len() - vis
        } else {
            0
        };
        let visible = &history[start..];

        let mut y = (TITLEBAR_H + PAD) as i32;
        for line in visible {
            mono_text(&mut canvas, PAD as i32, y, line, tokens.text_primary);
            y += (GLYPH_H * 2) as i32;
        }

        // Prompt + current input at the bottom.
        let prompt_y = (TERM_H - PROMPT_LINE_H) as i32;
        let mut prompt_str = String::from("nexacore$ ");
        prompt_str.push_str(input);
        mono_text(&mut canvas, PAD as i32, prompt_y, &prompt_str, tokens.sage);

        // Caret after the input — positioned by the measured prompt width.
        let cursor_x = PAD as i32 + measure_text_aa(&prompt_str, mono_font(), MONO_PX);
        mono_text(&mut canvas, cursor_x, prompt_y, "_", tokens.sage);
        // canvas borrow of `pixels` ends here.
    }

    if let Err(e) = compositor.commit_surface(win_id, pixels, &[]) {
        write("[nexacore-apps] terminal: commit_surface failed: ");
        write_display_error(&e);
        write("\n");
    }
    present(
        compositor, back, front_va, screen_w, screen_h, stride, chrome, tokens,
    );
}

// =============================================================================
// History helper
// =============================================================================

/// Push a line into the history buffer, capping at [`TERM_HISTORY_CAP`].
///
/// When the cap is reached, the oldest entry is removed from the front to
/// keep the bump-heap growth bounded over a long session.
pub(crate) fn push_history(history: &mut Vec<String>, line: String) {
    history.push(line);
    // Drain oldest entries when over cap.
    while history.len() > TERM_HISTORY_CAP {
        history.remove(0);
    }
}
