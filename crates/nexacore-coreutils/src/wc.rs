//! `wc` — count lines, words, bytes, and characters (WS8-10.4).
//!
//! [`count`] computes all four metrics for a text payload:
//!
//! - **lines** (`-l`): the number of `\n` bytes (a final line without a trailing
//!   newline is *not* counted, exactly as GNU `wc`).
//! - **words** (`-w`): the number of whitespace-separated tokens.
//! - **chars** (`-m`): the number of Unicode scalar values.
//! - **bytes** (`-c`): the number of bytes.
//!
//! [`WcFlags`] selects which metrics to render; with no flags set the classic
//! default (lines, words, bytes) is shown. [`wc_files`] counts each file read
//! through the [`fs::FileSystem`](crate::fs) seam and appends a `total` row when
//! more than one file is given.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::fs::{FileSystem, FsError};

/// The four counts `wc` can report for one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WcCounts {
    /// Number of newline bytes.
    pub lines: usize,
    /// Number of whitespace-separated words.
    pub words: usize,
    /// Number of Unicode scalar values.
    pub chars: usize,
    /// Number of bytes.
    pub bytes: usize,
}

impl WcCounts {
    /// Sum two count sets component-wise (used to build the `total` row).
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        Self {
            lines: self.lines.saturating_add(other.lines),
            words: self.words.saturating_add(other.words),
            chars: self.chars.saturating_add(other.chars),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }
}

/// Which metrics [`format_counts`] renders, and in which fixed order.
///
/// The render order is always lines, words, chars, bytes — independent of the
/// order flags were requested in, matching GNU `wc`. The four booleans mirror
/// `wc`'s `-l`/`-w`/`-m`/`-c` switches directly, so the `struct_excessive_bools`
/// lint is allowed rather than obscuring that mapping behind an enum.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WcFlags {
    /// Render the line count (`-l`).
    pub lines: bool,
    /// Render the word count (`-w`).
    pub words: bool,
    /// Render the character count (`-m`).
    pub chars: bool,
    /// Render the byte count (`-c`).
    pub bytes: bool,
}

impl Default for WcFlags {
    /// The classic default with no flags: lines, words, and bytes.
    fn default() -> Self {
        Self {
            lines: true,
            words: true,
            chars: false,
            bytes: true,
        }
    }
}

impl WcFlags {
    /// All flags off — a base for building an explicit selection.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            lines: false,
            words: false,
            chars: false,
            bytes: false,
        }
    }

    /// Whether no metric is selected (in which case the default set applies).
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.lines && !self.words && !self.chars && !self.bytes
    }

    /// Resolve to an effective selection: if nothing is set, use the default.
    #[must_use]
    pub fn effective(self) -> Self {
        if self.is_empty() {
            Self::default()
        } else {
            self
        }
    }
}

/// Count all four metrics for `input`.
#[must_use]
pub fn count(input: &str) -> WcCounts {
    let lines = input.bytes().filter(|&b| b == b'\n').count();
    let words = input.split_whitespace().count();
    let chars = input.chars().count();
    let bytes = input.len();
    WcCounts {
        lines,
        words,
        chars,
        bytes,
    }
}

/// Count all four metrics for a raw byte payload.
///
/// Byte and line counts are exact; word and character counts are computed over
/// the payload decoded as UTF-8 with [`String::from_utf8_lossy`], so invalid
/// bytes are treated as replacement characters rather than causing a failure.
#[must_use]
pub fn count_bytes(input: &[u8]) -> WcCounts {
    let text = String::from_utf8_lossy(input);
    // Line/word/char metrics come from the decoded text (newline bytes survive
    // lossy decoding unchanged, so the line count stays exact); the byte count
    // is taken from the raw payload, which may differ when bytes are invalid.
    let mut counts = count(&text);
    counts.bytes = input.len();
    counts
}

/// Format `counts` per `flags`, appending `label` when present.
///
/// Fields are emitted in the fixed order lines, words, chars, bytes, separated
/// by a single space; `label` (a filename, or `total`) follows after a space.
#[must_use]
pub fn format_counts(counts: &WcCounts, flags: WcFlags, label: Option<&str>) -> String {
    let flags = flags.effective();
    let mut fields: Vec<String> = Vec::new();
    if flags.lines {
        fields.push(counts.lines.to_string());
    }
    if flags.words {
        fields.push(counts.words.to_string());
    }
    if flags.chars {
        fields.push(counts.chars.to_string());
    }
    if flags.bytes {
        fields.push(counts.bytes.to_string());
    }
    let mut out = fields.join(" ");
    if let Some(name) = label {
        out.push(' ');
        out.push_str(name);
    }
    out
}

/// Count `input` and format it in one step (single, unlabeled input).
#[must_use]
pub fn wc(input: &str, flags: WcFlags) -> String {
    format_counts(&count(input), flags, None)
}

/// Count every file in `paths` through the seam, one formatted row per file,
/// plus a trailing `total` row when more than one file is given.
///
/// # Errors
///
/// Propagates the first [`FsError`] encountered while reading a path.
pub fn wc_files<F: FileSystem>(
    fs: &F,
    paths: &[&str],
    flags: WcFlags,
) -> Result<Vec<String>, FsError> {
    let mut rows: Vec<String> = Vec::new();
    let mut total = WcCounts::default();
    for path in paths {
        let bytes = fs.read(path)?;
        let counts = count_bytes(&bytes);
        total = total.combine(counts);
        rows.push(format_counts(&counts, flags, Some(path)));
    }
    if paths.len() > 1 {
        rows.push(format_counts(&total, flags, Some("total")));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    #[test]
    fn counts_all_metrics() {
        let c = count("hello world\nsecond line\n");
        assert_eq!(c.lines, 2);
        assert_eq!(c.words, 4);
        assert_eq!(c.bytes, 24);
        assert_eq!(c.chars, 24);
    }

    #[test]
    fn final_line_without_newline_not_counted() {
        let c = count("a\nb");
        assert_eq!(c.lines, 1);
        assert_eq!(c.words, 2);
    }

    #[test]
    fn empty_input_is_all_zero() {
        assert_eq!(count(""), WcCounts::default());
    }

    #[test]
    fn multibyte_chars_differ_from_bytes() {
        // "é" is one scalar, two bytes.
        let c = count("é\n");
        assert_eq!(c.chars, 2); // 'é' + '\n'
        assert_eq!(c.bytes, 3);
        assert_eq!(c.lines, 1);
    }

    #[test]
    fn words_collapse_runs_of_whitespace() {
        let c = count("  a\t\tb   c  ");
        assert_eq!(c.words, 3);
    }

    #[test]
    fn default_flags_render_lines_words_bytes() {
        let c = count("a b\n");
        assert_eq!(format_counts(&c, WcFlags::default(), None), "1 2 4");
    }

    #[test]
    fn empty_flags_fall_back_to_default() {
        let c = count("a b\n");
        assert_eq!(format_counts(&c, WcFlags::none(), None), "1 2 4");
    }

    #[test]
    fn single_flag_renders_one_field() {
        let c = count("a b c\n");
        let only_lines = WcFlags {
            lines: true,
            ..WcFlags::none()
        };
        assert_eq!(format_counts(&c, only_lines, None), "1");
    }

    #[test]
    fn chars_flag_renders_char_count() {
        let c = count("é\n");
        let only_chars = WcFlags {
            chars: true,
            ..WcFlags::none()
        };
        assert_eq!(format_counts(&c, only_chars, None), "2");
    }

    #[test]
    fn fixed_field_order_independent_of_request() {
        let c = count("a b\n");
        // Request bytes and lines; output still orders lines before bytes.
        let flags = WcFlags {
            lines: true,
            bytes: true,
            ..WcFlags::none()
        };
        assert_eq!(format_counts(&c, flags, None), "1 4");
    }

    #[test]
    fn label_is_appended() {
        let c = count("a\n");
        assert_eq!(
            format_counts(&c, WcFlags::default(), Some("/f.txt")),
            "1 1 2 /f.txt"
        );
    }

    #[test]
    fn wc_files_single_file_no_total() {
        let fs = MemFs::new().with_text_file("/a.txt", "one two\n");
        let rows = wc_files(&fs, &["/a.txt"], WcFlags::default()).unwrap();
        assert_eq!(rows, ["1 2 8 /a.txt"]);
    }

    #[test]
    fn wc_files_multi_adds_total() {
        let fs = MemFs::new()
            .with_text_file("/a.txt", "a\n")
            .with_text_file("/b.txt", "b b\n");
        let rows = wc_files(&fs, &["/a.txt", "/b.txt"], WcFlags::default()).unwrap();
        assert_eq!(rows, ["1 1 2 /a.txt", "1 2 4 /b.txt", "2 3 6 total"]);
    }

    #[test]
    fn wc_files_missing_propagates_error() {
        let fs = MemFs::new().with_text_file("/a.txt", "a\n");
        assert_eq!(
            wc_files(&fs, &["/a.txt", "/nope"], WcFlags::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn count_bytes_matches_count_for_utf8() {
        let text = "héllo\nworld\n";
        assert_eq!(count_bytes(text.as_bytes()), count(text));
    }
}
