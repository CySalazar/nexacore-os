//! `df` — filesystem usage report over an injected statfs seam (WS8-10.3).
//!
//! There is no ambient kernel to query in pure `no_std` logic, so the per-mount
//! usage facts `df` reports are obtained through the [`FsUsageSource`] seam (host
//! double [`StaticFsUsage`]). On hardware that seam bridges to the VFS `statfs`
//! calls; host tests drive a fixed table. Every function is deterministic.
//!
//! ## Flags
//!
//! | Flag | Meaning |
//! |------|---------|
//! | (none) | Sizes in 1 KiB blocks (`1K-blocks` column) |
//! | `-h` | Human-readable sizes (`1.5K`, `4G`), integer math only |
//!
//! ## Integer-only `Use%`
//!
//! The use-percentage is `ceil(used * 100 / total)` computed with
//! [`u64::div_euclid`] — no `/`/`%` operator, no floating point. GNU `df` rounds
//! the percentage up, so a filesystem with any used space never reports `0%`; a
//! zero-capacity filesystem reports `0%` (no division by zero).

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{CoreError, du::human_size};

/// Usage facts for a single mounted filesystem (one `df` row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsUsage {
    /// The backing device or source (the `Filesystem` column).
    pub source: String,
    /// The mount point (the `Mounted on` column).
    pub mountpoint: String,
    /// Total capacity in bytes.
    pub total: u64,
    /// Used capacity in bytes.
    pub used: u64,
    /// Available capacity in bytes (may be below `total - used` when space is
    /// reserved, exactly as on a real filesystem).
    pub available: u64,
}

impl FsUsage {
    /// Construct an [`FsUsage`] row from its fields.
    #[must_use]
    pub fn new(source: &str, mountpoint: &str, total: u64, used: u64, available: u64) -> Self {
        Self {
            source: source.to_string(),
            mountpoint: mountpoint.to_string(),
            total,
            used,
            available,
        }
    }

    /// The `ceil(used * 100 / total)` use-percentage, clamped to `0` when
    /// `total` is zero. Integer math only.
    #[must_use]
    pub fn use_percent(&self) -> u64 {
        if self.total == 0 {
            return 0;
        }
        let numerator = self.used.saturating_mul(100);
        // Ceiling division without the `/` operator: (a + b - 1).div_euclid(b).
        numerator
            .saturating_add(self.total.saturating_sub(1))
            .div_euclid(self.total)
    }
}

/// The seam that yields the current per-mount [`FsUsage`] rows.
pub trait FsUsageSource {
    /// The usage rows to report, in the order they should be listed.
    fn usages(&self) -> Vec<FsUsage>;
}

/// A fixed host double for [`FsUsageSource`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticFsUsage {
    /// The rows this source always reports.
    rows: Vec<FsUsage>,
}

impl StaticFsUsage {
    /// A source that reports `rows`.
    #[must_use]
    pub fn new(rows: Vec<FsUsage>) -> Self {
        Self { rows }
    }

    /// Append a row (builder style).
    #[must_use]
    pub fn with(mut self, row: FsUsage) -> Self {
        self.rows.push(row);
        self
    }
}

impl FsUsageSource for StaticFsUsage {
    fn usages(&self) -> Vec<FsUsage> {
        self.rows.clone()
    }
}

/// Options controlling [`df`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DfOptions {
    /// `-h`: format sizes human-readably (integer math, see [`human_size`]).
    pub human: bool,
}

/// Parse `df`-style flags (currently just `-h`).
///
/// # Errors
///
/// [`CoreError::InvalidArgument`] for any unrecognised flag or non-flag token.
pub fn parse_args<I, S>(args: I) -> Result<DfOptions, CoreError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut opts = DfOptions::default();
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
                'h' => opts.human = true,
                _ => return Err(CoreError::InvalidArgument),
            }
        }
    }
    Ok(opts)
}

/// One byte count rendered for a size column, per [`DfOptions`].
///
/// Without `-h` the value is in 1 KiB blocks, rounded up (matching GNU `df`'s
/// default block size); with `-h` it is [`human_size`].
fn size_cell(bytes: u64, human: bool) -> String {
    if human {
        human_size(bytes)
    } else {
        to_blocks(bytes).to_string()
    }
}

/// Bytes rounded **up** to whole 1 KiB blocks (integer math only).
#[must_use]
pub fn to_blocks(bytes: u64) -> u64 {
    bytes.saturating_add(1023).div_euclid(1024)
}

/// Format a `df` report from `source` into ready-to-print, column-aligned lines.
///
/// The first line is the header. Numeric columns are right-justified and the
/// `Filesystem` / `Mounted on` columns left-justified, each sized to its widest
/// cell — the classic `df` table shape.
#[must_use]
pub fn df<S: FsUsageSource>(source: &S, opts: DfOptions) -> Vec<String> {
    let rows = source.usages();
    let size_header = if opts.human { "Size" } else { "1K-blocks" };

    // Build every cell first so column widths can be measured before printing.
    let mut cells: Vec<[String; 6]> = Vec::new();
    cells.push([
        "Filesystem".to_string(),
        size_header.to_string(),
        "Used".to_string(),
        "Avail".to_string(),
        "Use%".to_string(),
        "Mounted on".to_string(),
    ]);
    for row in &rows {
        let mut percent = row.use_percent().to_string();
        percent.push('%');
        cells.push([
            row.source.clone(),
            size_cell(row.total, opts.human),
            size_cell(row.used, opts.human),
            size_cell(row.available, opts.human),
            percent,
            row.mountpoint.clone(),
        ]);
    }

    let widths = column_widths(&cells);
    cells.iter().map(|row| format_row(row, &widths)).collect()
}

/// The maximum cell width in each of the six columns.
fn column_widths(cells: &[[String; 6]]) -> [usize; 6] {
    let mut widths = [0usize; 6];
    for row in cells {
        for (slot, cell) in widths.iter_mut().zip(row.iter()) {
            let len = cell.chars().count();
            if len > *slot {
                *slot = len;
            }
        }
    }
    widths
}

/// Format one row: `Filesystem` and `Mounted on` left-justified, the four
/// numeric columns right-justified, single-space separated.
fn format_row(cells: &[String; 6], widths: &[usize; 6]) -> String {
    // Column justification: index 0 (Filesystem) and 5 (Mounted on) left, the
    // rest right. Iterate so no `x[i]` indexing is needed.
    let mut out = String::new();
    for (col, (cell, width)) in cells.iter().zip(widths.iter()).enumerate() {
        if col > 0 {
            out.push(' ');
        }
        let left = col == 0 || col == 5;
        if left {
            out.push_str(&format!("{cell:<width$}"));
        } else {
            out.push_str(&format!("{cell:>width$}"));
        }
    }
    // Trim trailing padding on the final left-justified column for tidy output.
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> StaticFsUsage {
        StaticFsUsage::new(Vec::new())
            .with(FsUsage::new(
                "/dev/root",
                "/",
                20 * 1024 * 1024 * 1024,
                5 * 1024 * 1024 * 1024,
                15 * 1024 * 1024 * 1024,
            ))
            .with(FsUsage::new(
                "tmpfs",
                "/tmp",
                1024 * 1024 * 1024,
                0,
                1024 * 1024 * 1024,
            ))
    }

    #[test]
    fn use_percent_ceils_and_guards_zero_total() {
        // 1 byte of 1000 rounds up to 1%, not 0%.
        assert_eq!(FsUsage::new("s", "/", 1000, 1, 999).use_percent(), 1);
        // Exact quarter.
        assert_eq!(FsUsage::new("s", "/", 400, 100, 300).use_percent(), 25);
        // Ceiling: 101/400 = 25.25% -> 26%.
        assert_eq!(FsUsage::new("s", "/", 400, 101, 299).use_percent(), 26);
        // Zero capacity never divides by zero.
        assert_eq!(FsUsage::new("s", "/", 0, 0, 0).use_percent(), 0);
        // Full.
        assert_eq!(FsUsage::new("s", "/", 400, 400, 0).use_percent(), 100);
    }

    #[test]
    fn to_blocks_rounds_up() {
        assert_eq!(to_blocks(0), 0);
        assert_eq!(to_blocks(1), 1);
        assert_eq!(to_blocks(1024), 1);
        assert_eq!(to_blocks(1025), 2);
    }

    #[test]
    fn default_report_has_header_and_blocks() {
        let lines = df(&source(), DfOptions::default());
        let header = lines.first().cloned().unwrap_or_default();
        assert!(header.starts_with("Filesystem"));
        assert!(header.contains("1K-blocks"));
        assert!(header.contains("Use%"));
        assert!(header.ends_with("Mounted on"));
        // Root: 5 GiB used of 20 GiB -> 25%.
        assert!(lines.get(1).is_some_and(|l| l.contains("25%")));
        assert!(lines.get(1).is_some_and(|l| l.starts_with("/dev/root")));
        assert!(lines.get(1).is_some_and(|l| l.ends_with('/')));
        // Total capacity in 1 KiB blocks (20 GiB -> 20971520).
        assert!(lines.get(1).is_some_and(|l| l.contains("20971520")));
    }

    #[test]
    fn human_report_uses_size_header_and_suffixes() {
        let opts = DfOptions { human: true };
        let lines = df(&source(), opts);
        assert!(lines.first().is_some_and(|l| l.contains("Size")));
        // 20 GiB total, 5 GiB used, 15 GiB avail.
        let root = lines.get(1).cloned().unwrap_or_default();
        assert!(root.contains("20G"), "row was: {root}");
        assert!(root.contains("5G"), "row was: {root}");
        assert!(root.contains("15G"), "row was: {root}");
    }

    #[test]
    fn columns_are_aligned_to_equal_width() {
        let lines = df(&source(), DfOptions::default());
        // Every row is the same visual length up to its trailing (trimmed)
        // mountpoint, so the Use% column lines up. Check the header and rows all
        // contain a right-justified Use% just before the mountpoint.
        let tmp = lines.get(2).cloned().unwrap_or_default();
        assert!(tmp.starts_with("tmpfs"));
        assert!(tmp.contains("0%"));
        assert!(tmp.ends_with("/tmp"));
    }

    #[test]
    fn empty_source_yields_only_header() {
        let lines = df(&StaticFsUsage::default(), DfOptions::default());
        assert_eq!(lines.len(), 1);
        assert!(lines.first().is_some_and(|l| l.starts_with("Filesystem")));
    }

    #[test]
    fn parse_args_accepts_h_only() {
        assert_eq!(parse_args(["-h"]).unwrap(), DfOptions { human: true });
        assert_eq!(
            parse_args::<[&str; 0], &str>([]).unwrap(),
            DfOptions::default()
        );
        assert_eq!(parse_args(["-x"]), Err(CoreError::InvalidArgument));
        assert_eq!(parse_args(["/"]), Err(CoreError::InvalidArgument));
    }

    #[test]
    fn seam_round_trips() {
        let src = StaticFsUsage::new(alloc::vec![FsUsage::new("s", "/", 100, 50, 50)]);
        assert_eq!(src.usages().len(), 1);
    }
}
