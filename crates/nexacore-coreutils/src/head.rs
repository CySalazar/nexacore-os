//! `head` — emit the first part of a stream or file (WS8-10.4).
//!
//! Two modes, mirroring the real tool:
//!
//! - **Lines** (`-n N`, default 10): the first `N` newline-terminated lines.
//! - **Bytes** (`-c N`): the first `N` bytes.
//!
//! Both modes operate on a raw byte payload so they are UTF-8-safe by
//! construction: a `\n` is always a single byte and can never be part of a
//! multibyte scalar, so line counting over bytes is exact. Byte mode may cut a
//! multibyte scalar in half (exactly as GNU `head -c` does); the [`head_str`]
//! convenience therefore renders any such truncated tail with the Unicode
//! replacement character rather than failing.
//!
//! Multiple inputs are supported through the [`fs::FileSystem`](crate::fs)
//! seam: [`head_files`] prefixes each file's output with a `==> path <==`
//! banner when more than one file is given, exactly like GNU `head`.

use alloc::{string::String, vec::Vec};

use crate::fs::{FileSystem, FsError};

/// The default number of lines emitted when no count is given.
pub const DEFAULT_LINES: usize = 10;

/// Whether [`head`] takes a leading count of lines or of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadMode {
    /// `-n N`: keep the first `N` lines.
    Lines(usize),
    /// `-c N`: keep the first `N` bytes.
    Bytes(usize),
}

/// Options controlling [`head`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadOptions {
    /// The leading count and its unit.
    pub mode: HeadMode,
}

impl Default for HeadOptions {
    fn default() -> Self {
        Self {
            mode: HeadMode::Lines(DEFAULT_LINES),
        }
    }
}

impl HeadOptions {
    /// Line-count options (`-n N`).
    #[must_use]
    pub const fn lines(count: usize) -> Self {
        Self {
            mode: HeadMode::Lines(count),
        }
    }

    /// Byte-count options (`-c N`).
    #[must_use]
    pub const fn bytes(count: usize) -> Self {
        Self {
            mode: HeadMode::Bytes(count),
        }
    }
}

/// Apply `head` to a raw byte payload, returning the selected leading bytes.
#[must_use]
pub fn head(input: &[u8], opts: &HeadOptions) -> Vec<u8> {
    match opts.mode {
        HeadMode::Bytes(n) => input.iter().copied().take(n).collect(),
        HeadMode::Lines(n) => head_lines_bytes(input, n),
    }
}

/// Keep the bytes up to and including the `n`th newline (or all of `input` if it
/// holds fewer than `n` lines).
fn head_lines_bytes(input: &[u8], n: usize) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let mut out: Vec<u8> = Vec::new();
    let mut seen = 0usize;
    for &b in input {
        out.push(b);
        if b == b'\n' {
            seen = seen.saturating_add(1);
            if seen == n {
                break;
            }
        }
    }
    out
}

/// Apply `head` to text, returning a `String`.
///
/// In byte mode a truncated multibyte tail is rendered lossily (with the U+FFFD
/// replacement character); in line mode the result is always exact.
#[must_use]
pub fn head_str(input: &str, opts: &HeadOptions) -> String {
    let bytes = head(input.as_bytes(), opts);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Read `path` through the seam and apply `head` to its bytes.
///
/// # Errors
///
/// Propagates any [`FsError`] from reading `path` (missing, directory, symlink,
/// or non-absolute path).
pub fn head_file<F: FileSystem>(
    fs: &F,
    path: &str,
    opts: &HeadOptions,
) -> Result<Vec<u8>, FsError> {
    let bytes = fs.read(path)?;
    Ok(head(&bytes, opts))
}

/// Apply `head` to every file in `paths`, formatting a combined string.
///
/// With a single path the file's `head` output is returned verbatim. With two
/// or more, each block is introduced by a `==> path <==` banner and blocks are
/// separated by a blank line, matching GNU `head`. Byte payloads are rendered
/// with [`String::from_utf8_lossy`].
///
/// # Errors
///
/// Propagates the first [`FsError`] encountered while reading a path.
pub fn head_files<F: FileSystem>(
    fs: &F,
    paths: &[&str],
    opts: &HeadOptions,
) -> Result<String, FsError> {
    let multi = paths.len() > 1;
    let mut out = String::new();
    for (idx, path) in paths.iter().enumerate() {
        let bytes = head_file(fs, path, opts)?;
        if multi {
            if idx > 0 {
                out.push('\n');
            }
            out.push_str("==> ");
            out.push_str(path);
            out.push_str(" <==\n");
        }
        out.push_str(&String::from_utf8_lossy(&bytes));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    #[test]
    fn default_takes_first_ten_lines() {
        let input = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n";
        let out = head_str(input, &HeadOptions::default());
        assert_eq!(out, "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n");
    }

    #[test]
    fn fewer_lines_than_requested_returns_all() {
        let out = head_str("a\nb\n", &HeadOptions::lines(10));
        assert_eq!(out, "a\nb\n");
    }

    #[test]
    fn lines_without_trailing_newline() {
        let out = head_str("a\nb\nc", &HeadOptions::lines(2));
        assert_eq!(out, "a\nb\n");
    }

    #[test]
    fn zero_lines_yields_empty() {
        assert_eq!(head_str("a\nb\n", &HeadOptions::lines(0)), "");
    }

    #[test]
    fn byte_mode_takes_first_n_bytes() {
        assert_eq!(head_str("abcdef", &HeadOptions::bytes(3)), "abc");
    }

    #[test]
    fn byte_mode_beyond_length_returns_all() {
        assert_eq!(head_str("ab", &HeadOptions::bytes(10)), "ab");
    }

    #[test]
    fn byte_mode_is_byte_exact() {
        // Five ASCII bytes then a 2-byte scalar; -c 6 cuts the scalar in half,
        // which renders as a single replacement character.
        let out = head(b"hello\xc3\xa9", &HeadOptions::bytes(6));
        assert_eq!(out, b"hello\xc3");
    }

    #[test]
    fn head_file_reads_through_seam() {
        let fs = MemFs::new().with_text_file("/a.txt", "one\ntwo\nthree\n");
        let out = head_file(&fs, "/a.txt", &HeadOptions::lines(2)).unwrap();
        assert_eq!(out, b"one\ntwo\n");
    }

    #[test]
    fn head_file_missing_is_not_found() {
        let fs = MemFs::new();
        assert_eq!(
            head_file(&fs, "/nope", &HeadOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn head_file_directory_errors() {
        let fs = MemFs::new().with_dir("/d");
        assert_eq!(
            head_file(&fs, "/d", &HeadOptions::default()),
            Err(FsError::IsADirectory)
        );
    }

    #[test]
    fn single_file_has_no_banner() {
        let fs = MemFs::new().with_text_file("/a.txt", "x\ny\n");
        let out = head_files(&fs, &["/a.txt"], &HeadOptions::lines(1)).unwrap();
        assert_eq!(out, "x\n");
    }

    #[test]
    fn multiple_files_get_banners_and_blank_line() {
        let fs = MemFs::new()
            .with_text_file("/a.txt", "a1\na2\n")
            .with_text_file("/b.txt", "b1\nb2\n");
        let out = head_files(&fs, &["/a.txt", "/b.txt"], &HeadOptions::lines(1)).unwrap();
        assert_eq!(out, "==> /a.txt <==\na1\n\n==> /b.txt <==\nb1\n");
    }

    #[test]
    fn multiple_files_propagate_first_error() {
        let fs = MemFs::new().with_text_file("/a.txt", "a\n");
        assert_eq!(
            head_files(&fs, &["/a.txt", "/nope"], &HeadOptions::default()),
            Err(FsError::NotFound)
        );
    }
}
