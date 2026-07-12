//! `tail` — emit the last part of a stream or file (WS8-10.4).
//!
//! Two modes, mirroring the real tool:
//!
//! - **Lines** (`-n N`, default 10): the last `N` lines. A single trailing
//!   newline terminates the final line rather than introducing an empty one, so
//!   `tail -n 1` of `"a\nb\n"` is `"b\n"`.
//! - **Bytes** (`-c N`): the last `N` bytes.
//!
//! As with [`head`](crate::head), both modes work on a raw byte payload and are
//! therefore UTF-8-safe for line counting (`\n` is a single byte). Byte mode may
//! cut a multibyte scalar; [`tail_str`] renders any such head lossily.
//!
//! ## Out of scope
//!
//! `tail -f` (follow) is intentionally **not** implemented here. Following a
//! growing file requires a live, side-effecting event loop against the kernel
//! VFS; this crate is pure, synchronous, `no_std` logic over an in-memory
//! payload and has no notion of time or of a file that changes underneath it.
//! Follow belongs in the shell/VFS layer that drives this core, not in the core.

use alloc::{string::String, vec::Vec};

use crate::fs::{FileSystem, FsError};

/// The default number of lines emitted when no count is given.
pub const DEFAULT_LINES: usize = 10;

/// Whether [`tail`] takes a trailing count of lines or of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailMode {
    /// `-n N`: keep the last `N` lines.
    Lines(usize),
    /// `-c N`: keep the last `N` bytes.
    Bytes(usize),
}

/// Options controlling [`tail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailOptions {
    /// The trailing count and its unit.
    pub mode: TailMode,
}

impl Default for TailOptions {
    fn default() -> Self {
        Self {
            mode: TailMode::Lines(DEFAULT_LINES),
        }
    }
}

impl TailOptions {
    /// Line-count options (`-n N`).
    #[must_use]
    pub const fn lines(count: usize) -> Self {
        Self {
            mode: TailMode::Lines(count),
        }
    }

    /// Byte-count options (`-c N`).
    #[must_use]
    pub const fn bytes(count: usize) -> Self {
        Self {
            mode: TailMode::Bytes(count),
        }
    }
}

/// Apply `tail` to a raw byte payload, returning the selected trailing bytes.
#[must_use]
pub fn tail(input: &[u8], opts: &TailOptions) -> Vec<u8> {
    match opts.mode {
        TailMode::Bytes(n) => tail_bytes(input, n),
        TailMode::Lines(n) => tail_lines_bytes(input, n),
    }
}

/// Keep the last `n` bytes, preserving their original order.
fn tail_bytes(input: &[u8], n: usize) -> Vec<u8> {
    let mut collected: Vec<u8> = input.iter().rev().take(n).copied().collect();
    collected.reverse();
    collected
}

/// Keep the last `n` lines of `input`.
///
/// Scans from the end counting line separators, ignoring one final trailing
/// newline (which terminates the last line rather than separating a new one).
/// When `input` holds `n` lines or fewer, all of it is returned.
fn tail_lines_bytes(input: &[u8], n: usize) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let len = input.len();
    let mut newlines = 0usize;
    let mut cut: Option<usize> = None;
    for (rev_i, &b) in input.iter().rev().enumerate() {
        if b == b'\n' {
            // A newline that is the very last byte only terminates the final
            // line; it does not separate an additional kept line.
            if rev_i == 0 {
                continue;
            }
            newlines = newlines.saturating_add(1);
            if newlines == n {
                // Absolute position of this separator; the kept region starts
                // right after it. `len - 1 - rev_i` is the forward index.
                let pos = len.saturating_sub(1).saturating_sub(rev_i);
                cut = Some(pos.saturating_add(1));
                break;
            }
        }
    }
    cut.map_or_else(
        || input.to_vec(),
        |start| input.iter().skip(start).copied().collect(),
    )
}

/// Apply `tail` to text, returning a `String`.
///
/// In byte mode a truncated multibyte head is rendered lossily (with the U+FFFD
/// replacement character); in line mode the result is always exact.
#[must_use]
pub fn tail_str(input: &str, opts: &TailOptions) -> String {
    let bytes = tail(input.as_bytes(), opts);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Read `path` through the seam and apply `tail` to its bytes.
///
/// # Errors
///
/// Propagates any [`FsError`] from reading `path`.
pub fn tail_file<F: FileSystem>(
    fs: &F,
    path: &str,
    opts: &TailOptions,
) -> Result<Vec<u8>, FsError> {
    let bytes = fs.read(path)?;
    Ok(tail(&bytes, opts))
}

/// Apply `tail` to every file in `paths`, formatting a combined string.
///
/// Banner and blank-line behaviour matches [`head_files`](crate::head::head_files):
/// a single file is verbatim, multiple files get `==> path <==` banners.
///
/// # Errors
///
/// Propagates the first [`FsError`] encountered while reading a path.
pub fn tail_files<F: FileSystem>(
    fs: &F,
    paths: &[&str],
    opts: &TailOptions,
) -> Result<String, FsError> {
    let multi = paths.len() > 1;
    let mut out = String::new();
    for (idx, path) in paths.iter().enumerate() {
        let bytes = tail_file(fs, path, opts)?;
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
    fn default_takes_last_ten_lines() {
        let input = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n";
        let out = tail_str(input, &TailOptions::default());
        assert_eq!(out, "3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n");
    }

    #[test]
    fn last_two_lines_with_trailing_newline() {
        assert_eq!(tail_str("a\nb\nc\n", &TailOptions::lines(2)), "b\nc\n");
    }

    #[test]
    fn last_two_lines_without_trailing_newline() {
        assert_eq!(tail_str("a\nb\nc", &TailOptions::lines(2)), "b\nc");
    }

    #[test]
    fn fewer_lines_than_requested_returns_all() {
        assert_eq!(tail_str("a\nb\n", &TailOptions::lines(10)), "a\nb\n");
    }

    #[test]
    fn zero_lines_yields_empty() {
        assert_eq!(tail_str("a\nb\n", &TailOptions::lines(0)), "");
    }

    #[test]
    fn single_line_no_newline() {
        assert_eq!(tail_str("only", &TailOptions::lines(3)), "only");
    }

    #[test]
    fn byte_mode_takes_last_n_bytes() {
        assert_eq!(tail_str("abcdef", &TailOptions::bytes(3)), "def");
    }

    #[test]
    fn byte_mode_beyond_length_returns_all() {
        assert_eq!(tail_str("ab", &TailOptions::bytes(10)), "ab");
    }

    #[test]
    fn byte_mode_is_byte_exact() {
        // Trailing 2-byte scalar preceded by ASCII; -c 1 keeps only the second
        // continuation byte, an invalid lead which renders as replacement.
        let out = tail(b"x\xc3\xa9", &TailOptions::bytes(1));
        assert_eq!(out, b"\xa9");
    }

    #[test]
    fn tail_file_reads_through_seam() {
        let fs = MemFs::new().with_text_file("/a.txt", "one\ntwo\nthree\n");
        let out = tail_file(&fs, "/a.txt", &TailOptions::lines(2)).unwrap();
        assert_eq!(out, b"two\nthree\n");
    }

    #[test]
    fn tail_file_missing_is_not_found() {
        let fs = MemFs::new();
        assert_eq!(
            tail_file(&fs, "/nope", &TailOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn multiple_files_get_banners() {
        let fs = MemFs::new()
            .with_text_file("/a.txt", "a1\na2\n")
            .with_text_file("/b.txt", "b1\nb2\n");
        let out = tail_files(&fs, &["/a.txt", "/b.txt"], &TailOptions::lines(1)).unwrap();
        assert_eq!(out, "==> /a.txt <==\na2\n\n==> /b.txt <==\nb2\n");
    }

    #[test]
    fn multiple_files_propagate_first_error() {
        let fs = MemFs::new().with_text_file("/a.txt", "a\n");
        assert_eq!(
            tail_files(&fs, &["/nope", "/a.txt"], &TailOptions::default()),
            Err(FsError::NotFound)
        );
    }
}
