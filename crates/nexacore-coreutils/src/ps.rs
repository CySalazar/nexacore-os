//! `ps` — tabular process listing over the [`ProcessSource`] seam (WS8-10.8).
//!
//! Renders the process table from the [`process`](crate::process) seam as an
//! aligned column table with a header row. Columns are selectable `-o`-style;
//! the default set is `PID PPID STAT %CPU RSS COMMAND`.
//!
//! ## Flags
//!
//! | Flag | Meaning |
//! |------|---------|
//! | `-e` / `-a` | Select every process. Accepted for parity: this host-testable half has no controlling-terminal concept, so it already lists every process the seam returns; the flag is therefore a no-op. |
//! | `-o LIST` | Choose the columns and their order (comma-separated names). |
//!
//! Recognised column names: `pid`, `ppid`, `stat`/`state`, `pcpu`/`%cpu`,
//! `rss`/`mem`, `comm`/`cmd`/`command`.
//!
//! ## Integer `%CPU` and `RSS`
//!
//! `%CPU` is rendered from [`cpu_permille`](crate::process::ProcessInfo::cpu_permille)
//! by [`format_percent`] with integer `div_euclid`/`rem_euclid` (no floats).
//! `RSS` is resident bytes rounded up to whole KiB via
//! [`to_blocks`], matching `ps`'s KiB RSS column.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    CoreError,
    df::to_blocks,
    process::{ProcessInfo, ProcessSource},
};

/// A selectable `ps` output column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsColumn {
    /// Process id (`pid`).
    Pid,
    /// Parent process id (`ppid`).
    Ppid,
    /// Owning principal id (`uid`/`owner`).
    Owner,
    /// Single-letter scheduling state (`stat`).
    State,
    /// CPU usage percentage (`%cpu`).
    Cpu,
    /// Resident set size in KiB (`rss`).
    Rss,
    /// Command name (`comm`).
    Command,
}

impl PsColumn {
    /// The header label for this column.
    #[must_use]
    pub const fn header(self) -> &'static str {
        match self {
            Self::Pid => "PID",
            Self::Ppid => "PPID",
            Self::Owner => "UID",
            Self::State => "STAT",
            Self::Cpu => "%CPU",
            Self::Rss => "RSS",
            Self::Command => "COMMAND",
        }
    }

    /// Whether this column is numeric (right-justified). The command column is
    /// the only left-justified one.
    #[must_use]
    pub const fn is_numeric(self) -> bool {
        !matches!(self, Self::Command)
    }

    /// Render this column's cell for `proc`.
    #[must_use]
    pub fn cell(self, proc: &ProcessInfo) -> String {
        match self {
            Self::Pid => proc.pid.to_string(),
            Self::Ppid => proc.ppid.to_string(),
            Self::Owner => proc.owner.to_string(),
            Self::State => proc.state.code().to_string(),
            Self::Cpu => format_percent(proc.cpu_permille),
            Self::Rss => to_blocks(proc.mem_bytes).to_string(),
            Self::Command => proc.name.clone(),
        }
    }

    /// Parse a single column name (case-insensitive).
    fn parse(name: &str) -> Result<Self, CoreError> {
        // Lower-case without allocating a String per char class: match on a
        // lowercased copy so `%CPU` and `pcpu` both resolve.
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "pid" => Ok(Self::Pid),
            "ppid" => Ok(Self::Ppid),
            "uid" | "owner" => Ok(Self::Owner),
            "stat" | "state" => Ok(Self::State),
            "pcpu" | "%cpu" | "cpu" => Ok(Self::Cpu),
            "rss" | "mem" => Ok(Self::Rss),
            "comm" | "cmd" | "command" => Ok(Self::Command),
            _ => Err(CoreError::InvalidArgument),
        }
    }
}

/// The default column set: `PID PPID STAT %CPU RSS COMMAND`.
#[must_use]
pub fn default_columns() -> Vec<PsColumn> {
    alloc::vec![
        PsColumn::Pid,
        PsColumn::Ppid,
        PsColumn::State,
        PsColumn::Cpu,
        PsColumn::Rss,
        PsColumn::Command,
    ]
}

/// Options controlling [`ps`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PsOptions {
    /// `-e`/`-a`: list every process. A parity no-op here (see the module docs).
    pub all: bool,
    /// The columns to render, in order. Empty means [`default_columns`].
    pub columns: Vec<PsColumn>,
}

/// Parse `ps`-style arguments: `-e`, `-a`, and `-o col,col,…`.
///
/// `-o` may be given as `-o pid,comm` (two tokens) or `-opid,comm` (one). A
/// second `-o` replaces the column list.
///
/// # Errors
///
/// [`CoreError::InvalidArgument`] for an unknown flag or column name;
/// [`CoreError::MissingValue`] if `-o` has no column list.
pub fn parse_args<I, S>(args: I) -> Result<PsOptions, CoreError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut opts = PsOptions::default();
    let mut want_columns = false;
    for arg in args {
        let arg = arg.as_ref();
        if want_columns {
            opts.columns = parse_column_list(arg)?;
            want_columns = false;
            continue;
        }
        let Some(flags) = arg.strip_prefix('-') else {
            return Err(CoreError::InvalidArgument);
        };
        if flags.is_empty() {
            return Err(CoreError::InvalidArgument);
        }
        // `-o` consumes the rest of the token as the list, or the next token.
        if let Some(rest) = flags.strip_prefix('o') {
            if rest.is_empty() {
                want_columns = true;
            } else {
                opts.columns = parse_column_list(rest)?;
            }
            continue;
        }
        for ch in flags.chars() {
            match ch {
                'e' | 'a' => opts.all = true,
                _ => return Err(CoreError::InvalidArgument),
            }
        }
    }
    if want_columns {
        return Err(CoreError::MissingValue);
    }
    Ok(opts)
}

/// Parse a comma-separated column list into [`PsColumn`]s (rejecting an empty
/// list or an empty element).
fn parse_column_list(list: &str) -> Result<Vec<PsColumn>, CoreError> {
    if list.is_empty() {
        return Err(CoreError::InvalidArgument);
    }
    let mut columns = Vec::new();
    for name in list.split(',') {
        if name.is_empty() {
            return Err(CoreError::InvalidArgument);
        }
        columns.push(PsColumn::parse(name)?);
    }
    Ok(columns)
}

/// Render `procs` as an aligned column table (header + one row each).
///
/// Numeric columns are right-justified, the command column left-justified, each
/// sized to its widest cell. This is the shared renderer `top` reuses.
#[must_use]
pub fn render_table(procs: &[ProcessInfo], columns: &[PsColumn]) -> Vec<String> {
    let effective = if columns.is_empty() {
        default_columns()
    } else {
        columns.to_vec()
    };

    // Build every cell (header first) so widths can be measured before printing.
    let mut rows: Vec<Vec<String>> = Vec::new();
    rows.push(effective.iter().map(|c| c.header().to_string()).collect());
    for proc in procs {
        rows.push(effective.iter().map(|c| c.cell(proc)).collect());
    }

    let widths = column_widths(&rows, effective.len());
    rows.iter()
        .map(|row| format_row(row, &widths, &effective))
        .collect()
}

/// List processes from `source` per `opts`.
#[must_use]
pub fn ps<S: ProcessSource>(source: &S, opts: &PsOptions) -> Vec<String> {
    let procs = source.processes();
    render_table(&procs, &opts.columns)
}

/// The maximum cell width in each of `count` columns.
fn column_widths(rows: &[Vec<String>], count: usize) -> Vec<usize> {
    let mut widths = alloc::vec![0usize; count];
    for row in rows {
        for (slot, cell) in widths.iter_mut().zip(row.iter()) {
            let len = cell.chars().count();
            if len > *slot {
                *slot = len;
            }
        }
    }
    widths
}

/// Format one table row with per-column justification and single-space gaps.
fn format_row(cells: &[String], widths: &[usize], columns: &[PsColumn]) -> String {
    let mut out = String::new();
    for (idx, (cell, width)) in cells.iter().zip(widths.iter()).enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        // A column is left-justified iff it is non-numeric (the command column).
        let left = columns.get(idx).is_some_and(|c| !c.is_numeric());
        if left {
            out.push_str(&format!("{cell:<width$}"));
        } else {
            out.push_str(&format!("{cell:>width$}"));
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Render a permille CPU figure as a `%CPU` string (e.g. `505` -> `50.5`).
///
/// Integer math only: `permille.div_euclid(10)` gives the whole percent and
/// `permille.rem_euclid(10)` the single fractional digit — no floating point.
#[must_use]
pub fn format_percent(permille: u32) -> String {
    let whole = permille.div_euclid(10);
    let frac = permille.rem_euclid(10);
    format!("{whole}.{frac}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{ProcessState, StaticProcessSource};

    fn source() -> StaticProcessSource {
        StaticProcessSource::default()
            .with(ProcessInfo::new(
                1,
                0,
                0,
                "init",
                ProcessState::Sleeping,
                0,
                4096,
            ))
            .with(ProcessInfo::new(
                42,
                1,
                1000,
                "shell",
                ProcessState::Running,
                505,
                65536,
            ))
    }

    #[test]
    fn format_percent_integer_math() {
        assert_eq!(format_percent(0), "0.0");
        assert_eq!(format_percent(505), "50.5");
        assert_eq!(format_percent(1000), "100.0");
        assert_eq!(format_percent(7), "0.7");
    }

    #[test]
    fn default_table_has_header_and_rows() {
        let lines = ps(&source(), &PsOptions::default());
        let header = lines.first().cloned().unwrap_or_default();
        assert!(header.starts_with("PID"));
        assert!(header.contains("STAT"));
        assert!(header.contains("%CPU"));
        assert!(header.ends_with("COMMAND"));
        // shell row: pid 42, state R, 50.5% cpu, 64 KiB rss, name shell.
        let shell = lines.get(2).cloned().unwrap_or_default();
        assert!(shell.contains("42"));
        assert!(shell.contains('R'));
        assert!(shell.contains("50.5"));
        assert!(shell.ends_with("shell"));
    }

    #[test]
    fn rss_is_kib_rounded_up() {
        // 65536 bytes -> 64 KiB exactly. Column width is max(len("RSS"), len("64"))
        // = 3, so the value is right-justified in 3 columns.
        let cols = alloc::vec![PsColumn::Rss];
        let lines = render_table(&source().processes(), &cols);
        assert_eq!(lines.get(2).map(String::as_str), Some(" 64"));
    }

    #[test]
    fn column_selection_orders_and_filters() {
        let opts = parse_args(["-o", "comm,pid"]).unwrap();
        let lines = ps(&source(), &opts);
        assert_eq!(lines.first().map(String::as_str), Some("COMMAND PID"));
        // init has pid 1; row is left-justified command then right-justified pid.
        assert_eq!(lines.get(1).map(String::as_str), Some("init      1"));
    }

    #[test]
    fn bundled_dash_o_column_list() {
        let opts = parse_args(["-opid,comm"]).unwrap();
        assert_eq!(opts.columns, [PsColumn::Pid, PsColumn::Command]);
    }

    #[test]
    fn dash_e_and_a_set_all() {
        assert!(parse_args(["-e"]).unwrap().all);
        assert!(parse_args(["-a"]).unwrap().all);
        assert!(parse_args(["-ea"]).unwrap().all);
    }

    #[test]
    fn unknown_flag_or_column_is_error() {
        assert_eq!(parse_args(["-z"]), Err(CoreError::InvalidArgument));
        assert_eq!(parse_args(["-o", "bogus"]), Err(CoreError::InvalidArgument));
        assert_eq!(parse_args(["-o", ""]), Err(CoreError::InvalidArgument));
        assert_eq!(parse_args(["-o"]), Err(CoreError::MissingValue));
        assert_eq!(parse_args(["notaflag"]), Err(CoreError::InvalidArgument));
    }

    #[test]
    fn column_name_aliases_are_case_insensitive() {
        assert_eq!(
            parse_args(["-o", "PID,%CPU,State,Cmd"]).unwrap().columns,
            [
                PsColumn::Pid,
                PsColumn::Cpu,
                PsColumn::State,
                PsColumn::Command
            ]
        );
    }
}
