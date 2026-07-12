//! `ls` — list directory contents over the [`FileSystem`] seam (WS8-10.1).
//!
//! Supported flags:
//!
//! | Flag | Meaning |
//! |------|---------|
//! | (none) / `-1` | One entry name per line (no TTY column packing here) |
//! | `-a` | Include entries whose name begins with `.` |
//! | `-l` | Long format: `<kind><caps> <len> <name>` (symlinks show `-> target`) |
//!
//! The output is a `Vec<String>` of ready-to-print lines: no colors, no
//! terminal-width probing. Entries are sorted by name (the seam already returns
//! them sorted; `ls` keeps that contract explicit). Listing a **file** yields a
//! single line for that file, matching how `ls FILE` behaves.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    fs::{DirEntry, FileKind, FileSystem, FsError, Metadata},
    path,
};

/// Options controlling [`ls`], mirroring the `ls` command flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LsOptions {
    /// `-a`: include dotfiles (names beginning with `.`).
    pub all: bool,
    /// `-l`: long format with kind, capabilities, and length columns.
    pub long: bool,
    /// `-1`: force one entry per line. This is already the default here (there
    /// is no column packing), so it is accepted for parity and is a no-op.
    pub one_per_line: bool,
}

/// Parse `ls`-style flags (e.g. `["-l", "-a"]` or a bundled `["-la"]`).
///
/// # Errors
///
/// Returns [`CoreError::InvalidArgument`](crate::CoreError::InvalidArgument) for
/// any unrecognised flag or non-flag argument.
pub fn parse_args<I, S>(args: I) -> Result<LsOptions, crate::CoreError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut opts = LsOptions::default();
    for arg in args {
        let arg = arg.as_ref();
        let Some(flags) = arg.strip_prefix('-') else {
            return Err(crate::CoreError::InvalidArgument);
        };
        if flags.is_empty() {
            return Err(crate::CoreError::InvalidArgument);
        }
        for ch in flags.chars() {
            match ch {
                'a' => opts.all = true,
                'l' => opts.long = true,
                '1' => opts.one_per_line = true,
                _ => return Err(crate::CoreError::InvalidArgument),
            }
        }
    }
    Ok(opts)
}

/// List `path` over `fs`, returning one formatted line per entry.
///
/// # Errors
///
/// Propagates [`FsError`] from the seam: [`FsError::NotFound`] for a missing
/// path, [`FsError::InvalidPath`] for a non-absolute path, etc.
pub fn ls<F: FileSystem>(fs: &F, path: &str, opts: &LsOptions) -> Result<Vec<String>, FsError> {
    let meta = fs.metadata(path)?;

    // `ls FILE` (or a symlink) lists just that one entry.
    if meta.kind != FileKind::Dir {
        let name = path::file_name(path).unwrap_or_else(|| path.to_string());
        let entry = DirEntry {
            name,
            metadata: meta,
        };
        return Ok(render(&[entry], opts));
    }

    let mut entries = fs.read_dir(path)?;
    if !opts.all {
        entries.retain(|e| !e.name.starts_with('.'));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(render(&entries, opts))
}

/// Render `entries` into printable lines under `opts`.
fn render(entries: &[DirEntry], opts: &LsOptions) -> Vec<String> {
    if !opts.long {
        return entries.iter().map(|e| e.name.clone()).collect();
    }

    // Long format: right-align the length column to the widest length string.
    let mut width = 0usize;
    for entry in entries {
        let digits = decimal_len(entry.metadata.len);
        if digits > width {
            width = digits;
        }
    }

    let mut lines: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        lines.push(long_line(entry, width));
    }
    lines
}

/// Format one long-format line: `<kind><caps> <padded-len> <name>`.
fn long_line(entry: &DirEntry, width: usize) -> String {
    let kind = kind_char(entry.metadata.kind);
    let caps = entry.metadata.capabilities.as_rwx();
    let len_str = pad_left(entry.metadata.len, width);
    let mut line = String::new();
    line.push(kind);
    line.push_str(&caps);
    line.push(' ');
    line.push_str(&len_str);
    line.push(' ');
    line.push_str(&entry.name);
    if entry.metadata.kind == FileKind::Symlink {
        // The seam does not expose the target through DirEntry; annotate the
        // kind so the long line still reads as a link.
        line.push_str(" -> (symlink)");
    }
    line
}

/// The leading type character used by `ls -l`.
const fn kind_char(kind: FileKind) -> char {
    match kind {
        FileKind::File => '-',
        FileKind::Dir => 'd',
        FileKind::Symlink => 'l',
    }
}

/// Number of decimal digits in `value` (at least 1). No integer division is
/// used: the value is formatted and its byte length taken.
fn decimal_len(value: u64) -> usize {
    format!("{value}").len()
}

/// Left-pad the decimal form of `value` with spaces to at least `width`.
fn pad_left(value: u64, width: usize) -> String {
    let s = format!("{value}");
    let mut out = String::new();
    let mut pad = width.saturating_sub(s.len());
    while pad > 0 {
        out.push(' ');
        pad -= 1;
    }
    out.push_str(&s);
    out
}

/// Length in bytes of an entry's metadata payload — re-exported convenience for
/// callers formatting their own columns.
#[must_use]
pub fn entry_len(meta: &Metadata) -> u64 {
    meta.len
}

/// Build a single-entry listing line for `name` with `meta` (used by callers
/// that already hold metadata). Provided for symmetry with [`ls`].
#[must_use]
pub fn format_entries(entries: &[DirEntry], opts: &LsOptions) -> Vec<String> {
    render(entries, opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    fn fs() -> MemFs {
        MemFs::new()
            .with_text_file("/d/beta.txt", "hello")
            .with_text_file("/d/alpha.txt", "hi")
            .with_text_file("/d/.hidden", "secret")
            .with_dir("/d/sub")
            .with_symlink("/d/link", "/d/alpha.txt")
    }

    #[test]
    fn plain_lists_sorted_visible_names() {
        let out = ls(&fs(), "/d", &LsOptions::default()).unwrap();
        assert_eq!(out, ["alpha.txt", "beta.txt", "link", "sub"]);
    }

    #[test]
    fn all_includes_dotfiles() {
        let opts = LsOptions {
            all: true,
            ..LsOptions::default()
        };
        let out = ls(&fs(), "/d", &opts).unwrap();
        assert_eq!(out, [".hidden", "alpha.txt", "beta.txt", "link", "sub"]);
    }

    #[test]
    fn one_per_line_is_same_as_plain() {
        let plain = ls(&fs(), "/d", &LsOptions::default()).unwrap();
        let one = ls(
            &fs(),
            "/d",
            &LsOptions {
                one_per_line: true,
                ..LsOptions::default()
            },
        )
        .unwrap();
        assert_eq!(plain, one);
    }

    #[test]
    fn long_format_columns() {
        let opts = LsOptions {
            long: true,
            ..LsOptions::default()
        };
        let out = ls(&fs(), "/d", &opts).unwrap();
        // alpha.txt: file, rw-, len 2 ("hi"); beta.txt: len 5 ("hello"); link is
        // a symlink whose len is its target-string length (12 → 2 digits), so
        // the length column width is 2.
        assert_eq!(out[0], "-rw-  2 alpha.txt");
        assert_eq!(out[1], "-rw-  5 beta.txt");
        assert_eq!(out[2], "lrwx 12 link -> (symlink)");
        assert_eq!(out[3], "drwx  0 sub");
    }

    #[test]
    fn long_format_pads_len_column() {
        let big = MemFs::new()
            .with_file("/big", &[0u8; 100])
            .with_text_file("/small", "x");
        let opts = LsOptions {
            long: true,
            ..LsOptions::default()
        };
        let out = ls(&big, "/", &opts).unwrap();
        // width 3 (from "100"); "small" length 1 padded to "  1".
        assert_eq!(out[0], "-rw- 100 big");
        assert_eq!(out[1], "-rw-   1 small");
    }

    #[test]
    fn listing_a_single_file() {
        let out = ls(&fs(), "/d/alpha.txt", &LsOptions::default()).unwrap();
        assert_eq!(out, ["alpha.txt"]);
    }

    #[test]
    fn missing_path_errors() {
        assert_eq!(
            ls(&fs(), "/nope", &LsOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn relative_path_errors() {
        assert_eq!(
            ls(&fs(), "d", &LsOptions::default()),
            Err(FsError::InvalidPath)
        );
    }

    #[test]
    fn parse_bundled_flags() {
        assert_eq!(
            parse_args(["-la"]).unwrap(),
            LsOptions {
                all: true,
                long: true,
                one_per_line: false,
            }
        );
    }

    #[test]
    fn parse_rejects_unknown() {
        assert_eq!(parse_args(["-z"]), Err(crate::CoreError::InvalidArgument));
    }

    #[test]
    fn entry_len_and_format_entries_helpers() {
        let entries = [DirEntry {
            name: String::from("x"),
            metadata: Metadata {
                kind: FileKind::File,
                len: 7,
                capabilities: crate::fs::Capabilities::read_write(),
            },
        }];
        assert_eq!(entry_len(&entries[0].metadata), 7);
        assert_eq!(format_entries(&entries, &LsOptions::default()), ["x"]);
    }
}
