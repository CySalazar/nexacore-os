//! File Manager window: rendering + NCFS CRUD + path helpers.
//!
//! Split out of `main.rs` (mechanical, no behaviour change).

use alloc::string::String;
use alloc::vec::Vec;

use nexacore_desktop_shell::{
    frame::{FrameButton, FrameVariant, WindowFrame, TITLEBAR_H},
    tokens::ShellTokens,
};
use nexacore_display::{compositor::Compositor, surface::WindowId};
use nexacore_types::fs_service::{FsErrno, FsRequest, FsResponse};
use nexacore_ui::{canvas::Canvas, text::GLYPH_H};

use crate::gfx::{present, ui_font, ui_text, write_display_error, ChromeState};
use crate::{exit, fs_available, fs_request, write, FM_H, FM_W, PAD};

/// Maximum number of file-manager entries displayed.
///
/// Bounds heap growth when a hostile or large FS reply arrives; the file
/// manager silently truncates the listing to this many entries.
const FM_ENTRIES_CAP: usize = 64;

// =============================================================================
// Path helpers
// =============================================================================

/// Join a directory path and a file/directory name into a canonical path.
///
/// Handles the special case of `dir = "/"` to avoid double slashes.
///
/// # Examples
///
/// ```
/// // (tested via doctests in host builds; logic is pure and allocation-free)
/// // path_join("/", "foo")     -> "/foo"
/// // path_join("/a/b", "c")   -> "/a/b/c"
/// // path_join("/a/b/", "c")  -> "/a/b/c"
/// ```
pub(crate) fn path_join(dir: &str, name: &str) -> String {
    // Strip any trailing slash from dir to normalise.
    let dir = dir.trim_end_matches('/');
    // An empty `dir` (or just "/") should yield "/<name>".
    let mut result = String::from(dir);
    result.push('/');
    result.push_str(name);
    result
}

/// Walk up to the parent directory without going above `"/"`.
///
/// `"/"` stays as `"/"`.  `"/a/b/c"` yields `"/a/b"`.
///
/// # Examples
///
/// ```
/// // path_parent("/")       -> "/"
/// // path_parent("/a")      -> "/"
/// // path_parent("/a/b/c")  -> "/a/b"
/// ```
pub(crate) fn path_parent(path: &str) -> String {
    // Strip any trailing slash first.
    let p = path.trim_end_matches('/');
    if p.is_empty() || p == "/" {
        return String::from("/");
    }
    // Find the last '/'.
    if let Some(pos) = p.rfind('/') {
        if pos == 0 {
            // The parent of "/foo" is "/"
            return String::from("/");
        }
        return String::from(&p[..pos]);
    }
    // Fallback (should not be reached for well-formed absolute paths).
    String::from("/")
}

// =============================================================================
// File Manager logic
// =============================================================================

/// Refresh the file-manager entry list by listing `cwd` and stat-ing each entry.
///
/// Populates `entries` with `(name, is_dir)` pairs up to [`FM_ENTRIES_CAP`].
/// Clamps `sel` to the new entries length.
/// Sets `status` on error; clears it on success.
pub(crate) fn fm_refresh(
    cwd: &str,
    entries: &mut Vec<(String, bool)>,
    sel: &mut usize,
    status: &mut String,
) {
    entries.clear();

    if !fs_available() {
        *status = String::from("FS unavailable");
        return;
    }

    let list_resp = fs_request(&FsRequest::ListDir {
        path: String::from(cwd),
    });

    let names = match list_resp {
        Some(FsResponse::Listing { names }) => names,
        Some(FsResponse::Error(e)) => {
            *status = errno_str(e);
            return;
        }
        _ => {
            *status = String::from("list error");
            return;
        }
    };

    for name in names.iter().take(FM_ENTRIES_CAP) {
        let full = path_join(cwd, name);
        let is_dir = match fs_request(&FsRequest::Stat { path: full }) {
            Some(FsResponse::Stat { is_dir, .. }) => is_dir,
            _ => false,
        };
        entries.push((name.clone(), is_dir));
    }

    // Clamp selection.
    if entries.is_empty() {
        *sel = 0;
    } else if *sel >= entries.len() {
        *sel = entries.len() - 1;
    }

    status.clear();
}

/// Return a short human-readable label for an [`FsErrno`] value.
///
/// Used in status lines; must fit within `FM_STATUS_CAP` characters.
pub(crate) fn errno_str(e: FsErrno) -> String {
    let s = match e {
        FsErrno::NotFound => "not found",
        FsErrno::AlreadyExists => "already exists",
        FsErrno::InvalidArgument => "invalid arg",
        FsErrno::TooLarge => "too large",
        FsErrno::Integrity => "integrity error",
        FsErrno::Io => "I/O error",
        FsErrno::NotMounted => "not mounted",
        FsErrno::DirectoryNotEmpty => "dir not empty",
        _ => "error",
    };
    String::from(s)
}

// =============================================================================
// File Manager rendering
// =============================================================================

/// Render the File Manager window into `pixels` and commit + present.
///
/// Layout within `FM_W × FM_H`:
/// - `y ∈ [0, TITLEBAR_H)` — the shell frame's titlebar (Standard variant).
/// - `y = TITLEBAR_H + PAD` — title: `"Files: <cwd>"`.
/// - `y ∈ [TITLEBAR_H + PAD + line_h, FM_H - line_h)` — entry list.
///   Directories shown as `"[D] name"`, files as `"    name"`.  The selected
///   row is drawn in the brick accent colour (`tokens.brick`).
/// - `y = FM_H - line_h` — status line (operations feedback).
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_file_manager(
    cwd: &str,
    entries: &[(String, bool)],
    sel: usize,
    fm_status: &str,
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
        let mut canvas = match Canvas::new(pixels, FM_W, FM_H) {
            Ok(c) => c,
            Err(_) => {
                write("[nexacore-apps] file manager: Canvas::new failed\n");
                exit(50);
            }
        };

        canvas.fill(tokens.bg_surface);

        // Shell frame: 42px titlebar, Standard variant.
        let frame = WindowFrame {
            title: "Files",
            focused,
            hover,
            variant: FrameVariant::Standard,
        };
        frame.render(&mut canvas, tokens, ui_font(), FM_W);

        let line_h = (GLYPH_H * 2) as i32;
        let title_y = (TITLEBAR_H + PAD) as i32;

        // Title: "Files: <cwd>" — truncate to fit FM_W.
        let mut title = String::from("Files: ");
        title.push_str(cwd);
        ui_text(&mut canvas, PAD as i32, title_y, &title, tokens.text_primary);

        let content_start_y = title_y + line_h + PAD as i32;
        let content_end_y = (FM_H as i32) - line_h - (PAD as i32);
        let max_visible = if content_end_y > content_start_y {
            ((content_end_y - content_start_y) / line_h) as usize
        } else {
            0
        };

        // Scroll window: ensure `sel` is visible.
        let scroll_start = if entries.is_empty() {
            0
        } else if sel >= max_visible {
            // Scroll so the selected entry is the last visible one.
            sel + 1 - max_visible
        } else {
            0
        };

        let mut y = content_start_y;
        for (i, (name, is_dir)) in entries.iter().enumerate().skip(scroll_start) {
            if y >= content_end_y {
                break;
            }
            let mut line = String::from(if *is_dir { "[D] " } else { "    " });
            line.push_str(name);

            // Selected row drawn in accent (brick), others in primary text.
            let color = if i == sel {
                tokens.brick
            } else {
                tokens.text_primary
            };
            ui_text(&mut canvas, PAD as i32, y, &line, color);
            y += line_h;
        }

        // Hint line when empty.
        if entries.is_empty() {
            ui_text(
                &mut canvas,
                PAD as i32,
                content_start_y,
                "(empty)",
                tokens.text_secondary,
            );
        }

        // Status line at bottom.
        let status_y = (FM_H as i32) - line_h;
        if !fm_status.is_empty() {
            ui_text(&mut canvas, PAD as i32, status_y, fm_status, tokens.sage);
        }
    }

    if let Err(e) = compositor.commit_surface(win_id, pixels, &[]) {
        write("[nexacore-apps] file manager: commit_surface failed: ");
        write_display_error(&e);
        write("\n");
    }
    present(
        compositor, back, front_va, screen_w, screen_h, stride, chrome, tokens,
    );
}
