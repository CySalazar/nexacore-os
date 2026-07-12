//! `cut` — select fields or character ranges from each line.
//!
//! Two modes, mirroring the real tool:
//!
//! - **Fields** (`-f LIST -d DELIM`): split each line on `DELIM` (default TAB)
//!   and keep the listed 1-based fields, re-joined with `DELIM`. Lines that do
//!   not contain the delimiter are passed through unchanged (like GNU `cut`
//!   without `-s`).
//! - **Chars** (`-c LIST`): keep the listed 1-based character positions.
//!
//! `LIST` is a comma-separated list of ranges: `N` (single), `N-M` (closed),
//! `N-` (open-ended to the end of line), and `-M` (from the start). Selected
//! positions are always emitted in ascending order with duplicates merged,
//! matching `cut` semantics (the list order does not affect output order).

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{CoreError, split_lines};

/// Whether [`cut_lines`] selects delimited fields or character positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutMode {
    /// `-f`: select delimiter-separated fields.
    Fields,
    /// `-c`: select character positions.
    Chars,
}

/// A single inclusive 1-based selection range. `end == None` means "to the end
/// of the line".
type CutRange = (usize, Option<usize>);

/// Options controlling [`cut_lines`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutOptions {
    /// Field or character selection mode.
    pub mode: CutMode,
    /// Field delimiter (used only in [`CutMode::Fields`]). Default is TAB.
    pub delimiter: char,
    /// The parsed, ordered list of selection ranges.
    pub ranges: Vec<CutRange>,
}

impl CutOptions {
    /// Build field-mode options from a delimiter and a `LIST` spec.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidArgument`] / [`CoreError::InvalidNumber`] if
    /// the range list is malformed.
    pub fn fields(delimiter: char, list: &str) -> Result<Self, CoreError> {
        Ok(Self {
            mode: CutMode::Fields,
            delimiter,
            ranges: parse_ranges(list)?,
        })
    }

    /// Build char-mode options from a `LIST` spec.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidArgument`] / [`CoreError::InvalidNumber`] if
    /// the range list is malformed.
    pub fn chars(list: &str) -> Result<Self, CoreError> {
        Ok(Self {
            mode: CutMode::Chars,
            delimiter: '\t',
            ranges: parse_ranges(list)?,
        })
    }
}

/// Parse a `cut` range list such as `"1,3-5,7-"` into ordered ranges.
///
/// # Errors
///
/// Returns [`CoreError::InvalidArgument`] for structurally invalid entries
/// (empty parts, a bare `-`, a zero position, or a reversed `N-M`) and
/// [`CoreError::InvalidNumber`] when a component is not a number.
pub fn parse_ranges(list: &str) -> Result<Vec<CutRange>, CoreError> {
    if list.is_empty() {
        return Err(CoreError::InvalidArgument);
    }
    let mut ranges = Vec::new();
    for part in list.split(',') {
        ranges.push(parse_one_range(part)?);
    }
    Ok(ranges)
}

/// Parse a single range token (`N`, `N-M`, `N-`, or `-M`).
fn parse_one_range(part: &str) -> Result<CutRange, CoreError> {
    if let Some((a, b)) = part.split_once('-') {
        if a.is_empty() && b.is_empty() {
            return Err(CoreError::InvalidArgument);
        }
        let start = if a.is_empty() { 1 } else { parse_pos(a)? };
        let end = if b.is_empty() {
            None
        } else {
            Some(parse_pos(b)?)
        };
        if let Some(e) = end {
            if e < start {
                return Err(CoreError::InvalidArgument);
            }
        }
        Ok((start, end))
    } else {
        let n = parse_pos(part)?;
        Ok((n, Some(n)))
    }
}

/// Parse a 1-based position (rejecting `0` and non-numbers).
fn parse_pos(s: &str) -> Result<usize, CoreError> {
    let n = s.parse::<usize>().map_err(|_| CoreError::InvalidNumber)?;
    if n == 0 {
        Err(CoreError::InvalidArgument)
    } else {
        Ok(n)
    }
}

/// Return `true` if `pos` (1-based) is covered by any range.
fn covers(ranges: &[CutRange], pos: usize) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| pos >= start && end.is_none_or(|e| pos <= e))
}

/// Apply `cut` to every line of `input`.
#[must_use]
pub fn cut_lines(input: &str, opts: &CutOptions) -> Vec<String> {
    split_lines(input)
        .into_iter()
        .map(|line| cut_line(line, opts))
        .collect()
}

/// Apply `cut` to a single line.
fn cut_line(line: &str, opts: &CutOptions) -> String {
    match opts.mode {
        CutMode::Chars => cut_chars(line, &opts.ranges),
        CutMode::Fields => cut_fields(line, opts.delimiter, &opts.ranges),
    }
}

/// Select character positions from a line.
fn cut_chars(line: &str, ranges: &[CutRange]) -> String {
    let mut out = String::new();
    for (idx, ch) in line.chars().enumerate() {
        if covers(ranges, idx + 1) {
            out.push(ch);
        }
    }
    out
}

/// Select delimited fields from a line, re-joined with the delimiter.
fn cut_fields(line: &str, delim: char, ranges: &[CutRange]) -> String {
    if !line.contains(delim) {
        // No delimiter: pass the whole line through unchanged.
        return line.to_string();
    }
    let mut selected = Vec::new();
    for (idx, field) in line.split(delim).enumerate() {
        if covers(ranges, idx + 1) {
            selected.push(field);
        }
    }
    let sep = delim.to_string();
    selected.join(sep.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chars_single_positions() {
        let opts = CutOptions::chars("1,3").unwrap();
        let out = cut_lines("abcde\nvwxyz", &opts);
        assert_eq!(out, ["ac", "vx"]);
    }

    #[test]
    fn chars_closed_range() {
        let opts = CutOptions::chars("2-4").unwrap();
        assert_eq!(cut_lines("abcdef", &opts), ["bcd"]);
    }

    #[test]
    fn chars_open_ended() {
        let opts = CutOptions::chars("3-").unwrap();
        assert_eq!(cut_lines("abcdef", &opts), ["cdef"]);
    }

    #[test]
    fn chars_from_start() {
        let opts = CutOptions::chars("-3").unwrap();
        assert_eq!(cut_lines("abcdef", &opts), ["abc"]);
    }

    #[test]
    fn chars_ascending_regardless_of_list_order() {
        // List "3,1" still emits positions in ascending order.
        let opts = CutOptions::chars("3,1").unwrap();
        assert_eq!(cut_lines("abcde", &opts), ["ac"]);
    }

    #[test]
    fn chars_out_of_range_positions_ignored() {
        let opts = CutOptions::chars("4-9").unwrap();
        assert_eq!(cut_lines("ab", &opts), [""]);
    }

    #[test]
    fn fields_default_tab_delimiter() {
        let opts = CutOptions::fields('\t', "1,3").unwrap();
        assert_eq!(cut_lines("a\tb\tc\td", &opts), ["a\tc"]);
    }

    #[test]
    fn fields_custom_delimiter() {
        let opts = CutOptions::fields(':', "2").unwrap();
        assert_eq!(cut_lines("root:x:0:0", &opts), ["x"]);
    }

    #[test]
    fn fields_range_rejoins_with_delimiter() {
        let opts = CutOptions::fields(',', "2-3").unwrap();
        assert_eq!(cut_lines("a,b,c,d", &opts), ["b,c"]);
    }

    #[test]
    fn fields_line_without_delimiter_passes_through() {
        let opts = CutOptions::fields(',', "2").unwrap();
        assert_eq!(cut_lines("noseparator", &opts), ["noseparator"]);
    }

    #[test]
    fn multibyte_chars_counted_by_scalar() {
        let opts = CutOptions::chars("1,2").unwrap();
        assert_eq!(cut_lines("éàü", &opts), ["éà"]);
    }

    #[test]
    fn parse_rejects_zero() {
        assert_eq!(parse_ranges("0"), Err(CoreError::InvalidArgument));
    }

    #[test]
    fn parse_rejects_reversed_range() {
        assert_eq!(parse_ranges("5-2"), Err(CoreError::InvalidArgument));
    }

    #[test]
    fn parse_rejects_bare_dash() {
        assert_eq!(parse_ranges("-"), Err(CoreError::InvalidArgument));
    }

    #[test]
    fn parse_rejects_non_number() {
        assert_eq!(parse_ranges("a-b"), Err(CoreError::InvalidNumber));
    }

    #[test]
    fn parse_rejects_empty() {
        assert_eq!(parse_ranges(""), Err(CoreError::InvalidArgument));
    }
}
