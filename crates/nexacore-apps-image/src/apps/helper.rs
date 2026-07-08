//! NexaCore Helper chat window: rendering + `AiInvoke` send flow.
//!
//! Split out of `main.rs` (mechanical, no behaviour change).

use alloc::{format, string::String, vec::Vec};

use nexacore_desktop_shell::{
    frame::{FrameButton, FrameVariant, TITLEBAR_H, WindowFrame},
    tokens::ShellTokens,
};
use nexacore_display::{compositor::Compositor, geometry::Rect, surface::WindowId};
use nexacore_ui::{
    canvas::Canvas,
    chat::{ChatRole, ChatState},
    status_bar::{BackendState, StatusBar},
    text::measure_text_aa,
};

use crate::gfx::{
    ChromeState, UI_PX, present, render_status, ui_font, ui_text, write_display_error,
};
use crate::{
    AI_INVOKE_RETRY_BUDGET, AI_OUT, AI_OUT_CAP, BAR_H, CHAT_H, CHAT_W, ENOENT_AI, MODEL_ID, PAD,
    SYS_AI_INVOKE, exit, syscall, task_yield, time_monotonic_nanos, write, write_dec, write_hex,
};

/// Number of characters revealed per progressive-reveal step (ADR-0046 §D3).
///
/// After each step the chat window is re-rendered and `task_yield` is called,
/// producing a streaming visual for the user.
const CHAT_CHUNK_SIZE: usize = 24;

// =============================================================================
// Chat rendering
// =============================================================================

/// One laid-out chat message, ready to draw as a messaging-style bubble.
struct Bubble {
    /// `true` for the user's turns (right-aligned, accent fill); `false` for
    /// the assistant (left-aligned, neutral fill).
    is_user: bool,
    /// Assistant caption shown above the bubble ("NexyAI" / "NexyAI · Nms");
    /// `None` for user turns.
    caption: Option<String>,
    /// Word-wrapped body lines.
    lines: Vec<String>,
    /// Bubble box width in pixels (hugs the widest wrapped line).
    w: i32,
    /// Bubble box height in pixels.
    h: i32,
    /// Total vertical space this message occupies (caption + bubble + gap).
    block_h: i32,
}

/// Word-wraps `text` so each line's measured pixel width stays within
/// `max_px`, breaking on spaces. A single word wider than `max_px` is left on
/// its own line (its bubble simply grows / the window clips it — chat words
/// are short in practice). `measure` returns the pixel advance of a candidate
/// line so wrapping tracks the real proportional font, not a char estimate.
fn wrap_to_px(text: &str, max_px: i32, measure: impl Fn(&str) -> i32) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        let candidate = if cur.is_empty() {
            String::from(word)
        } else {
            format!("{cur} {word}")
        };
        if cur.is_empty() || measure(&candidate) <= max_px {
            cur = candidate;
        } else {
            lines.push(core::mem::take(&mut cur));
            cur = String::from(word);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// Render the NexaCore Helper chat window into `pixels` and commit + present.
///
/// Layout within `CHAT_W × CHAT_H`:
/// - `y ∈ [0, TITLEBAR_H)` — the shell frame's titlebar (Standard variant).
/// - `y ∈ [TITLEBAR_H, TITLEBAR_H + BAR_H)` — the AI status strip (the
///   mockup's `LOCALE · GPU · …` strip; this is the only window that still
///   shows it — the other four windows dropped it in Task 7).
/// - `y = TITLEBAR_H + BAR_H + PAD` — title: `"NexaCore Helper"`.
/// - `y ∈ [TITLEBAR_H + BAR_H + PAD + line_h, CHAT_H - line_h * 2)` — chat
///   history lines from `state.render_lines(cols, max_visible_lines)`.
/// - `y = CHAT_H - line_h * 2` — separator hint: `"[Enter=send  Backspace=del]"`.
/// - `y = CHAT_H - line_h` — input line: `"> <chat_input>_"`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_chat(
    state: &ChatState,
    chat_input: &str,
    bar: &StatusBar,
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
        let mut canvas = match Canvas::new(pixels, CHAT_W, CHAT_H) {
            Ok(c) => c,
            Err(_) => {
                write("[nexacore-apps] chat: Canvas::new failed\n");
                exit(50);
            }
        };

        canvas.fill(tokens.bg_surface);

        // Shell frame: 42px titlebar, Standard variant.
        let frame = WindowFrame {
            title: "NexaCore Helper",
            focused,
            hover,
            variant: FrameVariant::Standard,
        };
        frame.render(&mut canvas, tokens, ui_font(), CHAT_W);

        // AI status strip directly below the titlebar (mockup's status row).
        render_status(&mut canvas, TITLEBAR_H as i32, bar.state(), tokens);

        // ── Conversation: messaging-style bubbles ────────────────────────────
        // The titlebar already names the window ("NexaCore Helper"), so there
        // is no separate title line — the room goes to the conversation.
        // Distinction is carried the way messaging apps do it: the user's turns
        // sit on the right in an accent (petrol) bubble; the assistant's sit on
        // the left in a neutral bubble under a small "NexyAI" caption.
        let line_h: i32 = 18;
        let content_x = PAD as i32;
        let content_w = (CHAT_W - PAD * 2) as i32;
        let content_start_y = (TITLEBAR_H + BAR_H + PAD) as i32;
        // Reserve the bottom two lines for the hint + input row.
        let content_end_y = (CHAT_H as i32) - line_h * 2 - (PAD as i32);
        let avail = content_end_y - content_start_y;

        const BUBBLE_RADIUS: u32 = 10;
        const BUBBLE_HPAD: i32 = 10;
        const BUBBLE_VPAD: i32 = 7;
        const BUBBLE_GAP: i32 = 10;
        const CAPTION_H: i32 = 17;
        let max_bubble_w = content_w * 78 / 100;
        let inner_max = (max_bubble_w - 2 * BUBBLE_HPAD).max(1);

        // Lay each message out: wrap to the max bubble width, then hug the
        // widest wrapped line so short replies get small bubbles.
        let mut bubbles: Vec<Bubble> = Vec::new();
        for msg in state.messages() {
            let is_user = matches!(msg.role, ChatRole::User);
            let lines = wrap_to_px(&msg.text, inner_max, |s| {
                measure_text_aa(s, ui_font(), UI_PX)
            });
            let text_w = lines
                .iter()
                .map(|l| measure_text_aa(l, ui_font(), UI_PX))
                .max()
                .unwrap_or(0);
            // `.min().max()` (not `clamp`) so a pathologically small window can
            // never trip `clamp`'s min>max panic — the crate forbids panics.
            let w = (text_w + 2 * BUBBLE_HPAD)
                .min(max_bubble_w)
                .max(2 * BUBBLE_HPAD + 8);
            let n = i32::try_from(lines.len().max(1)).unwrap_or(1);
            let h = n * line_h + 2 * BUBBLE_VPAD;
            let caption = if is_user {
                None
            } else {
                Some(match msg.latency_ms {
                    Some(ms) => format!("NexyAI \u{00B7} {ms}ms"),
                    None => String::from("NexyAI"),
                })
            };
            let cap_h = if caption.is_some() { CAPTION_H } else { 0 };
            let block_h = cap_h + h + BUBBLE_GAP;
            bubbles.push(Bubble {
                is_user,
                caption,
                lines,
                w,
                h,
                block_h,
            });
        }

        // Show the most recent messages that fit (chat scrolled to the bottom):
        // walk from the newest backwards until the height budget is spent.
        let mut start = 0usize;
        let mut acc = 0i32;
        for (i, b) in bubbles.iter().enumerate().rev() {
            acc += b.block_h;
            if acc > avail {
                start = i + 1;
                break;
            }
        }
        if !bubbles.is_empty() {
            // Always keep at least the newest message on screen.
            start = start.min(bubbles.len() - 1);
        }

        let mut y = content_start_y;
        for b in bubbles.iter().skip(start) {
            if y >= content_end_y {
                break;
            }
            let bubble_x = if b.is_user {
                content_x + content_w - b.w
            } else {
                content_x
            };
            // Caption above the bubble (assistant only), aligned to its edge.
            if let Some(cap) = &b.caption {
                ui_text(&mut canvas, bubble_x, y, cap, tokens.text_tertiary);
                y += CAPTION_H;
            }
            // Bubble background: accent for the user, neutral for the assistant.
            let fill = if b.is_user {
                tokens.petrol
            } else {
                tokens.bg_surface_2
            };
            canvas.fill_rounded_rect(
                &Rect {
                    x: bubble_x,
                    y,
                    w: b.w as u32,
                    h: b.h as u32,
                },
                BUBBLE_RADIUS,
                fill,
            );
            // Body text inside the bubble.
            let tx = bubble_x + BUBBLE_HPAD;
            let mut ty = y + BUBBLE_VPAD;
            for line in &b.lines {
                ui_text(&mut canvas, tx, ty, line, tokens.text_primary);
                ty += line_h;
            }
            y += b.h + BUBBLE_GAP;
        }

        // Hint line.
        let hint_y = (CHAT_H as i32) - line_h * 2 - (PAD as i32);
        ui_text(
            &mut canvas,
            content_x,
            hint_y,
            "Enter to send \u{00B7} Tab to switch windows",
            tokens.text_secondary,
        );

        // Input line with cursor.
        let input_y = (CHAT_H as i32) - line_h;
        let mut input_line = String::from("> ");
        input_line.push_str(chat_input);
        input_line.push('_');
        ui_text(&mut canvas, content_x, input_y, &input_line, tokens.sage);
        // canvas borrow of `pixels` ends here.
    }

    if let Err(e) = compositor.commit_surface(win_id, pixels, &[]) {
        write("[nexacore-apps] chat: commit_surface failed: ");
        write_display_error(&e);
        write("\n");
    }
    present(
        compositor, back, front_va, screen_w, screen_h, stride, chrome, tokens,
    );
}

// =============================================================================
// Chat send flow (AiInvoke + progressive reveal)
// =============================================================================

/// Execute the full send flow for one chat turn (ADR-0046 §D2/D3/D4).
///
/// Steps:
/// 1. `push_user(prompt)` — append the user turn to `state`; re-render
///    immediately so the user sees their message.
/// 2. `TimeMonotonicNanos` — capture `t0`.
/// 3. `AiInvoke(80)` — blocking relay call (retries `ENOENT` up to
///    `AI_INVOKE_RETRY_BUDGET` times); writes answer into `AI_OUT`.
/// 4. `latency_ms` — `(TimeMonotonicNanos - t0) / 1_000_000`.
/// 5. `begin_assistant()` then progressive reveal: append `CHAT_CHUNK_SIZE`
///    chars at a time via `append_chunk`, re-rendering + `task_yield` between
///    steps (streaming visual).
/// 6. `finish_assistant(bar.state(), latency_ms)` — stamp the badge.
///
/// On `ENOENT` budget exhaustion or any non-zero errno the answer is replaced
/// with `"[error: AI service unavailable]"` and `finish_assistant` is still
/// called so the turn is properly closed.
///
/// # Safety
///
/// Accesses the `AI_OUT` BSS buffer through `addr_of_mut!`; single-threaded,
/// no aliasing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn chat_send(
    state: &mut ChatState,
    prompt: &str,
    bar: &StatusBar,
    pixels: &mut [u32],
    chat_win: WindowId,
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
    // Step 1 — append user turn and render immediately.
    state.push_user(prompt);
    let chat_input_empty = String::new(); // show cleared input during inference
    render_chat(
        state,
        &chat_input_empty,
        bar,
        pixels,
        chat_win,
        tokens,
        focused,
        hover,
        compositor,
        back,
        front_va,
        screen_w,
        screen_h,
        stride,
        chrome,
    );

    write("[nexacore-apps] chat: prompt sent (");
    write_dec(prompt.len());
    write(" chars)\n");

    // Step 2 — capture t0.
    let t0 = time_monotonic_nanos();

    // Step 3 — AiInvoke with ENOENT retry.
    let mut attempts: u32 = 0;
    let invoke_result: Result<usize, ()> = loop {
        // SAFETY: MODEL_ID and prompt are valid slices for the syscall duration.
        // AI_OUT is a BSS static buffer; `addr_of_mut!` gives a raw pointer
        // without creating a reference, satisfying the aliasing rules while the
        // kernel writes into the buffer.
        let (rax, rdx) = unsafe {
            syscall(
                SYS_AI_INVOKE,
                MODEL_ID.as_ptr() as u64,
                MODEL_ID.len() as u64,
                prompt.as_ptr() as u64,
                prompt.len() as u64,
                core::ptr::addr_of_mut!(AI_OUT) as u64,
                AI_OUT_CAP as u64,
            )
        };

        if rdx == ENOENT_AI {
            attempts = attempts.saturating_add(1);
            if attempts >= AI_INVOKE_RETRY_BUDGET {
                write("[nexacore-apps] chat: AI service unavailable (ENOENT budget)\n");
                break Err(());
            }
            task_yield();
            continue;
        }

        if rdx != 0 {
            write("[nexacore-apps] chat: AiInvoke errno=");
            write_hex(rdx);
            write("\n");
            break Err(());
        }

        // Truncate out_len to AI_OUT_CAP defensively.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "kernel bounds output_len to AI_OUT_CAP = 4096"
        )]
        let out_len = (rax as usize).min(AI_OUT_CAP);
        break Ok(out_len);
    };

    // Step 4 — latency.
    let t1 = time_monotonic_nanos();
    #[allow(
        clippy::cast_possible_truncation,
        reason = "latency fits in u32 (ms since boot mod 2^32 is fine)"
    )]
    let latency_ms = ((t1.saturating_sub(t0)) / 1_000_000) as u32;

    // Build the answer string (or error message).
    let answer: &str = match invoke_result {
        Ok(out_len) => {
            // SAFETY: single-threaded; out_len <= AI_OUT_CAP; AI_OUT was written
            // by the kernel during AiInvoke and is now safe to read back.
            let bytes = unsafe { &(*core::ptr::addr_of!(AI_OUT))[..out_len] };
            core::str::from_utf8(bytes).unwrap_or("<non-utf8>")
        }
        Err(()) => "[error: AI service unavailable]",
    };

    write("[nexacore-apps] chat: answer ");
    write_dec(answer.len());
    write(" chars, latency=");
    write_dec(latency_ms as usize);
    write("ms, badge=");
    match bar.state() {
        BackendState::Gpu => write("GPU"),
        BackendState::CpuDegraded => write("CPU"),
        BackendState::Unknown => write("Unknown"),
    }
    write("\n");

    // Step 5 — progressive reveal via append_chunk.
    state.begin_assistant();
    render_chat(
        state,
        &chat_input_empty,
        bar,
        pixels,
        chat_win,
        tokens,
        focused,
        hover,
        compositor,
        back,
        front_va,
        screen_w,
        screen_h,
        stride,
        chrome,
    );

    // Reveal the answer in chunks of CHAT_CHUNK_SIZE characters.
    // We iterate over char boundaries to avoid splitting multi-byte codepoints.
    let mut offset: usize = 0;
    while offset < answer.len() {
        // Find the end of the next chunk at a char boundary.
        let remaining = &answer[offset..];
        let chunk_end = {
            let mut byte_end = 0usize;
            for (char_count, c) in remaining.chars().enumerate() {
                if char_count >= CHAT_CHUNK_SIZE {
                    break;
                }
                byte_end += c.len_utf8();
            }
            byte_end
        };
        if chunk_end == 0 {
            break; // no progress — guard against pathological input
        }
        let chunk = &remaining[..chunk_end];
        offset += chunk_end;

        state.append_chunk(chunk);
        render_chat(
            state,
            &chat_input_empty,
            bar,
            pixels,
            chat_win,
            tokens,
            focused,
            hover,
            compositor,
            back,
            front_va,
            screen_w,
            screen_h,
            stride,
            chrome,
        );
        task_yield();
    }

    // Step 6 — stamp the badge and close the assistant turn.
    state.finish_assistant(bar.state(), latency_ms);
    render_chat(
        state,
        &chat_input_empty,
        bar,
        pixels,
        chat_win,
        tokens,
        focused,
        hover,
        compositor,
        back,
        front_va,
        screen_w,
        screen_h,
        stride,
        chrome,
    );
}
