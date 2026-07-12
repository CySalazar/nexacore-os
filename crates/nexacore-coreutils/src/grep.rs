//! `grep` — select lines matching a pattern (WS8-10.4).
//!
//! Matching is **fixed-string** (literal substring) by default, with the
//! classic flags:
//!
//! - `-i` ([`GrepOptions::ignore_case`]): ASCII/Unicode case-insensitive match.
//! - `-v` ([`GrepOptions::invert`]): keep lines that do *not* match.
//! - `-n` ([`GrepOptions::line_number`]): prefix each line with its 1-based number.
//! - `-c` ([`GrepOptions::count_only`]): emit only the count of matching lines.
//! - `-w` ([`GrepOptions::word`]): match only whole words (the occurrence must be
//!   bounded by non-word characters, where a word character is alphanumeric or
//!   `_`).
//!
//! ## Regex is a library-gated seam, not hand-rolled here
//!
//! Only literal matching lives in this module. Regular-expression matching plugs
//! in behind the very same seam the editor's search uses — the
//! `nexacore-text` crate's `Matcher` trait, whose `LiteralMatcher` this mirrors.
//! A regex engine is deliberately *not* vendored: the workspace has no vetted
//! `no_std` regex crate yet, and this crate is dependency-free by charter. When
//! one is admitted it slots in as another `Matcher` implementation rather than a
//! bespoke engine grown inside `grep`.
//!
//! ## Files through the seam
//!
//! [`grep_files`] runs the same matcher over files read through the
//! [`fs::FileSystem`](crate::fs) seam, prefixing each output line with the
//! filename when more than one file is searched (GNU `grep` behaviour).

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::{
    fs::{FileSystem, FsError},
    split_lines,
};

/// Options controlling [`grep`].
///
/// The five independent boolean flags mirror `grep`'s own command-line switches
/// one-to-one; collapsing them into an enum or bitset would only obscure that
/// direct correspondence, so the `struct_excessive_bools` lint is allowed here.
/// `Copy` is intentionally *not* derived, keeping the crate's "options passed by
/// `&reference`" convention idiomatic for this small struct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrepOptions {
    /// `-i`: case-insensitive matching.
    pub ignore_case: bool,
    /// `-v`: invert the match (keep non-matching lines).
    pub invert: bool,
    /// `-n`: prefix each emitted line with its 1-based line number.
    pub line_number: bool,
    /// `-c`: emit only a count of matching lines.
    pub count_only: bool,
    /// `-w`: match whole words only.
    pub word: bool,
}

/// Whether a single `line` matches `pattern` under `opts` (before inversion).
///
/// An empty pattern matches every line (as GNU `grep` does).
#[must_use]
pub fn line_matches(pattern: &str, line: &str, opts: &GrepOptions) -> bool {
    let raw = if opts.ignore_case {
        contains_ci(line, pattern, opts.word)
    } else {
        contains(line, pattern, opts.word)
    };
    raw ^ opts.invert
}

/// Case-sensitive containment, optionally word-bounded.
fn contains(hay: &str, needle: &str, word: bool) -> bool {
    if needle.is_empty() {
        return true;
    }
    if word {
        contains_word(hay, needle)
    } else {
        hay.contains(needle)
    }
}

/// Case-insensitive containment, optionally word-bounded.
///
/// Both sides are folded to lowercase first. Word-boundary tests are then made
/// against the folded haystack, which is internally consistent because both the
/// occurrence and its neighbouring characters live in the same folded string.
fn contains_ci(hay: &str, needle: &str, word: bool) -> bool {
    if needle.is_empty() {
        return true;
    }
    let hay_lc = hay.to_lowercase();
    let needle_lc = needle.to_lowercase();
    if word {
        contains_word(&hay_lc, &needle_lc)
    } else {
        hay_lc.contains(&needle_lc)
    }
}

/// Whether `needle` occurs in `hay` bounded on both sides by non-word
/// characters (string edges count as boundaries).
fn contains_word(hay: &str, needle: &str) -> bool {
    for (start, matched) in hay.match_indices(needle) {
        let before = hay.get(..start).and_then(|s| s.chars().next_back());
        let after_start = start.saturating_add(matched.len());
        let after = hay.get(after_start..).and_then(|s| s.chars().next());
        let left_ok = before.is_none_or(|c| !is_word_char(c));
        let right_ok = after.is_none_or(|c| !is_word_char(c));
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

/// Whether `c` is a word character (alphanumeric or underscore).
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Return the matching lines as `(1-based line number, line text)` pairs.
///
/// Inversion, case-folding, and word-boundary rules from `opts` are applied;
/// output formatting (`-n`, `-c`) is *not* — that is [`grep`]'s job.
#[must_use]
pub fn grep_matches(pattern: &str, input: &str, opts: &GrepOptions) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    for (idx, line) in split_lines(input).into_iter().enumerate() {
        if line_matches(pattern, line, opts) {
            out.push((idx.saturating_add(1), line.to_string()));
        }
    }
    out
}

/// Run `grep` over `input`, formatting output lines per `opts`.
///
/// With `-c` the result is a single element holding the match count. Otherwise
/// each matching line is rendered, prefixed with `N:` when `-n` is set.
#[must_use]
pub fn grep(pattern: &str, input: &str, opts: &GrepOptions) -> Vec<String> {
    let matches = grep_matches(pattern, input, opts);
    if opts.count_only {
        return vec![matches.len().to_string()];
    }
    matches
        .into_iter()
        .map(|(num, line)| format_line(None, num, &line, opts))
        .collect()
}

/// Format one output line, optionally prefixed by a filename and/or line number.
fn format_line(file: Option<&str>, num: usize, line: &str, opts: &GrepOptions) -> String {
    let mut out = String::new();
    if let Some(name) = file {
        out.push_str(name);
        out.push(':');
    }
    if opts.line_number {
        out.push_str(&num.to_string());
        out.push(':');
    }
    out.push_str(line);
    out
}

/// Run `grep` over every file in `paths`, read through the seam.
///
/// When more than one path is given, each output line (and each `-c` count line)
/// is prefixed with `path:`. For `-c` the prefix is `path:count`.
///
/// # Errors
///
/// Propagates the first [`FsError`] encountered while reading a path (including
/// [`FsError::InvalidData`] for non-UTF-8 files).
pub fn grep_files<F: FileSystem>(
    pattern: &str,
    fs: &F,
    paths: &[&str],
    opts: &GrepOptions,
) -> Result<Vec<String>, FsError> {
    let multi = paths.len() > 1;
    let mut out: Vec<String> = Vec::new();
    for path in paths {
        let text = fs.read_to_string(path)?;
        let matches = grep_matches(pattern, &text, opts);
        if opts.count_only {
            let mut row = String::new();
            if multi {
                row.push_str(path);
                row.push(':');
            }
            row.push_str(&matches.len().to_string());
            out.push(row);
        } else {
            for (num, line) in matches {
                let prefix = if multi { Some(*path) } else { None };
                out.push(format_line(prefix, num, &line, opts));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    const TEXT: &str = "alpha\nBeta\ngamma\nbeta test\ndelta\n";

    #[test]
    fn plain_substring_match() {
        let out = grep("beta", TEXT, &GrepOptions::default());
        assert_eq!(out, ["beta test"]);
    }

    #[test]
    fn ignore_case_matches_both() {
        let opts = GrepOptions {
            ignore_case: true,
            ..GrepOptions::default()
        };
        let out = grep("beta", TEXT, &opts);
        assert_eq!(out, ["Beta", "beta test"]);
    }

    #[test]
    fn invert_keeps_non_matching() {
        let opts = GrepOptions {
            invert: true,
            ..GrepOptions::default()
        };
        let out = grep("beta", TEXT, &opts);
        assert_eq!(out, ["alpha", "Beta", "gamma", "delta"]);
    }

    #[test]
    fn line_numbers_are_one_based() {
        let opts = GrepOptions {
            line_number: true,
            ..GrepOptions::default()
        };
        let out = grep("gamma", TEXT, &opts);
        assert_eq!(out, ["3:gamma"]);
    }

    #[test]
    fn count_only_reports_number() {
        let opts = GrepOptions {
            ignore_case: true,
            count_only: true,
            ..GrepOptions::default()
        };
        let out = grep("beta", TEXT, &opts);
        assert_eq!(out, ["2"]);
    }

    #[test]
    fn word_match_requires_boundaries() {
        // "beta" as a whole word: "Beta" (case differs) is excluded without -i,
        // "beta test" matches, but "betaform" would not.
        let text = "beta\nbetaform\nmy beta.\n";
        let opts = GrepOptions {
            word: true,
            ..GrepOptions::default()
        };
        let out = grep("beta", text, &opts);
        assert_eq!(out, ["beta", "my beta."]);
    }

    #[test]
    fn word_match_with_ignore_case() {
        let text = "BETA\nbetaform\n";
        let opts = GrepOptions {
            word: true,
            ignore_case: true,
            ..GrepOptions::default()
        };
        let out = grep("beta", text, &opts);
        assert_eq!(out, ["BETA"]);
    }

    #[test]
    fn empty_pattern_matches_all_lines() {
        let out = grep("", "a\nb\n", &GrepOptions::default());
        assert_eq!(out, ["a", "b"]);
    }

    #[test]
    fn no_match_yields_empty() {
        let out = grep("zzz", TEXT, &GrepOptions::default());
        assert!(out.is_empty());
    }

    #[test]
    fn count_only_with_no_match_is_zero() {
        let opts = GrepOptions {
            count_only: true,
            ..GrepOptions::default()
        };
        assert_eq!(grep("zzz", TEXT, &opts), ["0"]);
    }

    #[test]
    fn grep_over_single_file_has_no_prefix() {
        let fs = MemFs::new().with_text_file("/a.txt", "foo\nbar\nfoobar\n");
        let out = grep_files("foo", &fs, &["/a.txt"], &GrepOptions::default()).unwrap();
        assert_eq!(out, ["foo", "foobar"]);
    }

    #[test]
    fn grep_over_multiple_files_prefixes_filename() {
        let fs = MemFs::new()
            .with_text_file("/a.txt", "foo\nbar\n")
            .with_text_file("/b.txt", "baz\nfoo\n");
        let out = grep_files("foo", &fs, &["/a.txt", "/b.txt"], &GrepOptions::default()).unwrap();
        assert_eq!(out, ["/a.txt:foo", "/b.txt:foo"]);
    }

    #[test]
    fn grep_files_line_number_and_filename() {
        let fs = MemFs::new()
            .with_text_file("/a.txt", "x\nfoo\n")
            .with_text_file("/b.txt", "foo\n");
        let opts = GrepOptions {
            line_number: true,
            ..GrepOptions::default()
        };
        let out = grep_files("foo", &fs, &["/a.txt", "/b.txt"], &opts).unwrap();
        assert_eq!(out, ["/a.txt:2:foo", "/b.txt:1:foo"]);
    }

    #[test]
    fn grep_files_count_with_prefix() {
        let fs = MemFs::new()
            .with_text_file("/a.txt", "foo\nfoo\n")
            .with_text_file("/b.txt", "bar\n");
        let opts = GrepOptions {
            count_only: true,
            ..GrepOptions::default()
        };
        let out = grep_files("foo", &fs, &["/a.txt", "/b.txt"], &opts).unwrap();
        assert_eq!(out, ["/a.txt:2", "/b.txt:0"]);
    }

    #[test]
    fn grep_files_missing_is_not_found() {
        let fs = MemFs::new().with_text_file("/a.txt", "foo\n");
        assert_eq!(
            grep_files("foo", &fs, &["/a.txt", "/nope"], &GrepOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn grep_files_non_utf8_is_invalid_data() {
        let fs = MemFs::new().with_file("/x", &[0xFF, 0xFE]);
        assert_eq!(
            grep_files("foo", &fs, &["/x"], &GrepOptions::default()),
            Err(FsError::InvalidData)
        );
    }
}
