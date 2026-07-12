//! `du` — recursive disk usage over the [`FileSystem`] seam (WS8-10.3).
//!
//! Walks a directory subtree through the [`FileSystem`] and sums the byte length
//! of every file it contains, reporting a cumulative total per directory. Like
//! [`tree`](crate::tree) the walk is **depth-guarded** ([`DuOptions::max_depth`])
//! so a pathological layout can never spin forever; symlinks are treated as
//! leaves and never followed, which also rules out link cycles.
//!
//! ## Flags
//!
//! | Flag | Meaning |
//! |------|---------|
//! | (none) | One line per directory (its subtree total), deepest first, root last |
//! | `-a` | Also emit one line per file (`--all`) |
//! | `-s` | Emit only the grand total for the argument (`--summarize`) |
//! | `-h` | Human-readable sizes (`1.5K`, `15M`), integer math only |
//!
//! ## Integer-only human sizes
//!
//! [`human_size`] scales bytes by powers of 1024 (`K`, `M`, `G`, …) using only
//! [`u64::div_euclid`] / [`u64::rem_euclid`] — no `/`/`%` operator and no
//! floating point. Below 1024 the raw byte count is printed with no suffix. From
//! `1024` up, a single fractional digit is shown while the scaled value is below
//! `10` (`1.5K`); larger values are truncated to a whole number (`15M`).
//!
//! ## Depth guard vs. totals
//!
//! `max_depth` caps traversal exactly as [`tree`](crate::tree) caps listing:
//! subtrees deeper than the cap are neither listed **nor summed**. With the
//! default cap of [`DEFAULT_MAX_DEPTH`] this only matters for pathologically deep
//! layouts; callers that need a partial report set a smaller cap deliberately.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    CoreError,
    fs::{FileKind, FileSystem, FsError},
    path,
};

/// The default recursion cap for [`du`] when a caller does not set one. Mirrors
/// [`tree`](crate::tree::DEFAULT_MAX_DEPTH).
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Options controlling [`du`], mirroring the `du` command flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuOptions {
    /// Maximum depth to descend below the argument (the argument is depth 0).
    /// Subtrees deeper than this are neither listed nor summed. Guards against
    /// runaway recursion.
    pub max_depth: usize,
    /// `-s`: emit only the grand total for the argument, nothing else.
    pub summary: bool,
    /// `-a`: also emit one line per file, not just per directory.
    pub all: bool,
    /// `-h`: format sizes human-readably (integer math, see [`human_size`]).
    pub human: bool,
}

impl Default for DuOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            summary: false,
            all: false,
            human: false,
        }
    }
}

/// Parse `du`-style flags (e.g. `["-s", "-h"]` or a bundled `["-sh"]`).
///
/// Recognises `-s`, `-a`, `-h`, and bundled short flags. `-s` and `-a` are
/// mutually exclusive in GNU `du`; here `-s` simply wins (it suppresses the
/// per-entry lines `-a` would add).
///
/// # Errors
///
/// [`CoreError::InvalidArgument`] for any unrecognised flag or non-flag token.
pub fn parse_args<I, S>(args: I) -> Result<DuOptions, CoreError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut opts = DuOptions::default();
    for arg in args {
        let arg = arg.as_ref();
        let Some(flags) = arg.strip_prefix('-') else {
            return Err(CoreError::InvalidArgument);
        };
        if flags.is_empty() {
            return Err(CoreError::InvalidArgument);
        }
        for ch in flags.chars() {
            match ch {
                's' => opts.summary = true,
                'a' => opts.all = true,
                'h' => opts.human = true,
                _ => return Err(CoreError::InvalidArgument),
            }
        }
    }
    Ok(opts)
}

/// One `du` report row: the cumulative byte size of an entry and its path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuEntry {
    /// Cumulative size in bytes (a file's length, or a directory's subtree sum).
    pub size: u64,
    /// The normalized absolute path of the entry.
    pub path: String,
}

/// Compute disk usage for the subtree rooted at `path`.
///
/// Returns the report rows in `du` order: within each directory, `-a` file rows
/// (when enabled) come first, then each subdirectory's total, and the directory's
/// own total comes after its contents — so the argument's total is the **last**
/// row. With [`DuOptions::summary`] the result is a single row: the argument's
/// grand total.
///
/// A file argument yields a single row for that file.
///
/// # Errors
///
/// [`FsError::NotFound`] for a missing path, [`FsError::InvalidPath`] for a
/// non-absolute path, plus any seam error while reading a directory.
pub fn du<F: FileSystem>(fs: &F, path: &str, opts: &DuOptions) -> Result<Vec<DuEntry>, FsError> {
    let meta = fs.metadata(path)?;
    let root = path::normalize(path);
    let mut out: Vec<DuEntry> = Vec::new();
    match meta.kind {
        FileKind::File | FileKind::Symlink => {
            out.push(DuEntry {
                size: meta.len,
                path: root,
            });
        }
        FileKind::Dir => {
            let total = walk(fs, &root, 0, opts, &mut out)?;
            if opts.summary {
                out.clear();
            }
            out.push(DuEntry {
                size: total,
                path: root,
            });
        }
    }
    Ok(out)
}

/// Recursive worker: sum `dir`'s subtree, pushing child rows in `du` order.
///
/// Returns the cumulative byte total of `dir`. The caller is responsible for
/// pushing `dir`'s own row; `walk` only pushes rows for `dir`'s contents.
fn walk<F: FileSystem>(
    fs: &F,
    dir: &str,
    depth: usize,
    opts: &DuOptions,
    out: &mut Vec<DuEntry>,
) -> Result<u64, FsError> {
    let entries = fs.read_dir(dir)?;
    let mut total: u64 = 0;
    for entry in entries {
        let child = path::join(dir, &entry.name);
        match entry.metadata.kind {
            FileKind::Dir => {
                // Depth-guard the descent exactly as `tree` guards its listing.
                if depth < opts.max_depth {
                    let sub = walk(fs, &child, depth.saturating_add(1), opts, out)?;
                    total = total.saturating_add(sub);
                    if !opts.summary {
                        out.push(DuEntry {
                            size: sub,
                            path: child,
                        });
                    }
                }
            }
            FileKind::File | FileKind::Symlink => {
                total = total.saturating_add(entry.metadata.len);
                if opts.all && !opts.summary {
                    out.push(DuEntry {
                        size: entry.metadata.len,
                        path: child,
                    });
                }
            }
        }
    }
    Ok(total)
}

/// Format `du` rows into ready-to-print lines: `<size>\t<path>`.
///
/// With `human` the size column is rendered by [`human_size`]; otherwise it is
/// the raw byte count.
#[must_use]
pub fn format_rows(rows: &[DuEntry], human: bool) -> Vec<String> {
    rows.iter()
        .map(|row| {
            let size = if human {
                human_size(row.size)
            } else {
                row.size.to_string()
            };
            format!("{size}\t{path}", path = row.path)
        })
        .collect()
}

/// Compute and format disk usage in one step.
///
/// # Errors
///
/// Propagates [`du`] errors.
pub fn du_lines<F: FileSystem>(
    fs: &F,
    path: &str,
    opts: &DuOptions,
) -> Result<Vec<String>, FsError> {
    let rows = du(fs, path, opts)?;
    Ok(format_rows(&rows, opts.human))
}

/// The unit suffixes for [`human_size`], indexed by power of 1024.
const UNITS: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];

/// Render a byte count human-readably using integer math only.
///
/// Scales by powers of 1024. Below `1024` the raw count is printed with no
/// suffix (`512`). From `1024` up, one fractional digit is shown while the
/// scaled value is under `10` (`1.5K`); larger values are truncated to a whole
/// number (`15M`). Uses only [`u64::div_euclid`] / [`u64::rem_euclid`]: no
/// `/`/`%` operator, no floating point.
#[must_use]
pub fn human_size(bytes: u64) -> String {
    let mut idx: usize = 0;
    let mut divisor: u64 = 1;
    while idx + 1 < UNITS.len() && bytes.div_euclid(divisor) >= 1024 {
        divisor = divisor.saturating_mul(1024);
        idx = idx.saturating_add(1);
    }
    let unit = UNITS.get(idx).copied().unwrap_or("");
    if idx == 0 {
        // Below 1024: exact byte count, no suffix.
        return bytes.to_string();
    }
    let whole = bytes.div_euclid(divisor);
    if whole < 10 {
        let remainder = bytes.rem_euclid(divisor);
        let tenths = remainder.saturating_mul(10).div_euclid(divisor);
        if tenths > 0 {
            return format!("{whole}.{tenths}{unit}");
        }
    }
    format!("{whole}{unit}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    fn fs() -> MemFs {
        MemFs::new()
            .with_text_file("/root/a.txt", "10bytes---") // 10 bytes
            .with_text_file("/root/sub/b.txt", "twenty-bytes-exactly") // 20 bytes
            .with_text_file("/root/sub/deep/c.txt", "thirty-bytes-exactly-for-a-test") // 31 bytes
    }

    #[test]
    fn default_lists_dirs_post_order_root_last() {
        let rows = du(&fs(), "/root", &DuOptions::default()).unwrap();
        assert_eq!(
            rows,
            [
                DuEntry {
                    size: 31,
                    path: "/root/sub/deep".to_string()
                },
                DuEntry {
                    size: 51,
                    path: "/root/sub".to_string()
                },
                DuEntry {
                    size: 61,
                    path: "/root".to_string()
                },
            ]
        );
    }

    #[test]
    fn all_also_lists_files() {
        let opts = DuOptions {
            all: true,
            ..DuOptions::default()
        };
        let rows = du(&fs(), "/root", &opts).unwrap();
        let paths: Vec<&str> = rows.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/root/a.txt",
                "/root/sub/b.txt",
                "/root/sub/deep/c.txt",
                "/root/sub/deep",
                "/root/sub",
                "/root",
            ]
        );
    }

    #[test]
    fn summary_reports_only_the_total() {
        let opts = DuOptions {
            summary: true,
            ..DuOptions::default()
        };
        let rows = du(&fs(), "/root", &opts).unwrap();
        assert_eq!(
            rows,
            [DuEntry {
                size: 61,
                path: "/root".to_string()
            }]
        );
    }

    #[test]
    fn depth_guard_stops_descent_and_sum() {
        // max_depth 1: descend into `/root/sub` (depth 1) but not `/root/sub/deep`.
        let opts = DuOptions {
            max_depth: 1,
            ..DuOptions::default()
        };
        let rows = du(&fs(), "/root", &opts).unwrap();
        // `deep` is neither listed nor summed, so `sub` is only its own 20 bytes.
        assert_eq!(
            rows,
            [
                DuEntry {
                    size: 20,
                    path: "/root/sub".to_string()
                },
                DuEntry {
                    size: 30,
                    path: "/root".to_string()
                },
            ]
        );
    }

    #[test]
    fn depth_zero_sums_only_direct_files() {
        let opts = DuOptions {
            max_depth: 0,
            ..DuOptions::default()
        };
        let rows = du(&fs(), "/root", &opts).unwrap();
        assert_eq!(
            rows,
            [DuEntry {
                size: 10,
                path: "/root".to_string()
            }]
        );
    }

    #[test]
    fn file_argument_reports_the_file() {
        let rows = du(&fs(), "/root/a.txt", &DuOptions::default()).unwrap();
        assert_eq!(
            rows,
            [DuEntry {
                size: 10,
                path: "/root/a.txt".to_string()
            }]
        );
    }

    #[test]
    fn missing_path_is_not_found() {
        assert_eq!(
            du(&fs(), "/nope", &DuOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn relative_path_is_invalid() {
        assert_eq!(
            du(&fs(), "root", &DuOptions::default()),
            Err(FsError::InvalidPath)
        );
    }

    #[test]
    fn format_rows_uses_tab_and_raw_size() {
        let rows = [DuEntry {
            size: 61,
            path: "/root".to_string(),
        }];
        assert_eq!(format_rows(&rows, false), ["61\t/root"]);
    }

    #[test]
    fn du_lines_end_to_end_human() {
        let opts = DuOptions {
            summary: true,
            human: true,
            ..DuOptions::default()
        };
        let lines = du_lines(&fs(), "/root", &opts).unwrap();
        assert_eq!(lines, ["61\t/root"]);
    }

    #[test]
    fn human_size_below_kilo_is_raw() {
        assert_eq!(human_size(0), "0");
        assert_eq!(human_size(512), "512");
        assert_eq!(human_size(1023), "1023");
    }

    #[test]
    fn human_size_one_fraction_digit_under_ten() {
        assert_eq!(human_size(1024), "1K");
        assert_eq!(human_size(1536), "1.5K"); // 1.5 * 1024
        assert_eq!(human_size(2560), "2.5K");
    }

    #[test]
    fn human_size_truncates_at_ten_and_above() {
        assert_eq!(human_size(15 * 1024), "15K");
        assert_eq!(human_size(15 * 1024 + 512), "15K"); // fraction dropped >= 10
    }

    #[test]
    fn human_size_scales_through_units() {
        assert_eq!(human_size(1024 * 1024), "1M");
        assert_eq!(human_size(1024 * 1024 * 1024), "1G");
        assert_eq!(
            human_size(3 * 1024 * 1024 * 1024 + 512 * 1024 * 1024),
            "3.5G"
        );
    }

    #[test]
    fn parse_args_bundled_and_separate() {
        assert_eq!(
            parse_args(["-sh"]).unwrap(),
            DuOptions {
                summary: true,
                human: true,
                ..DuOptions::default()
            }
        );
        assert_eq!(
            parse_args(["-a", "-h"]).unwrap(),
            DuOptions {
                all: true,
                human: true,
                ..DuOptions::default()
            }
        );
    }

    #[test]
    fn parse_args_rejects_unknown_and_nonflag() {
        assert_eq!(parse_args(["-z"]), Err(CoreError::InvalidArgument));
        assert_eq!(parse_args(["root"]), Err(CoreError::InvalidArgument));
        assert_eq!(parse_args(["-"]), Err(CoreError::InvalidArgument));
    }
}
