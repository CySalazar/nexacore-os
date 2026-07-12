//! `diff` — line-level difference between two text streams.
//!
//! Computes a longest-common-subsequence (LCS) alignment of the two line
//! sequences and walks it into a flat change list of [`DiffOp`]s: lines only in
//! the left input are [`DiffOp::Removed`], lines only in the right are
//! [`DiffOp::Added`], and lines common to both are [`DiffOp::Context`]. The
//! ops are emitted in reading order, so [`format_diff`] can render a readable
//! `-`/`+`/space listing directly.
//!
//! The LCS table is stored as a flat `Vec<usize>` addressed by
//! `row * width + col`; all reads go through `slice::get`, so the module stays
//! free of panicking indexing and integer division.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::split_lines;

/// A single edit-script entry produced by [`diff_lines`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp {
    /// A line present in both inputs (unchanged).
    Context(String),
    /// A line present only in the right ("new") input.
    Added(String),
    /// A line present only in the left ("old") input.
    Removed(String),
}

/// Compute the line diff turning `left` into `right`.
#[must_use]
pub fn diff_lines(left: &str, right: &str) -> Vec<DiffOp> {
    let a = split_lines(left);
    let b = split_lines(right);
    let width = b.len() + 1;
    let table = lcs_table(&a, &b, width);
    backtrack(&a, &b, &table, width)
}

/// Fill the LCS length table from the bottom-right corner up.
///
/// `table[i * width + j]` holds the LCS length of `a[i..]` and `b[j..]`.
fn lcs_table(a: &[&str], b: &[&str], width: usize) -> Vec<usize> {
    let rows = a.len() + 1;
    let mut table = vec![0usize; rows * width];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            let value = if a.get(i) == b.get(j) {
                cell(&table, width, i + 1, j + 1) + 1
            } else {
                cell(&table, width, i + 1, j).max(cell(&table, width, i, j + 1))
            };
            if let Some(slot) = table.get_mut(i * width + j) {
                *slot = value;
            }
        }
    }
    table
}

/// Read `table[row * width + col]`, treating out-of-bounds as `0`.
fn cell(table: &[usize], width: usize, row: usize, col: usize) -> usize {
    table.get(row * width + col).copied().unwrap_or(0)
}

/// Walk the filled table to produce the ordered edit script.
fn backtrack(a: &[&str], b: &[&str], table: &[usize], width: usize) -> Vec<DiffOp> {
    let mut ops = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while let (Some(&la), Some(&lb)) = (a.get(i), b.get(j)) {
        if la == lb {
            ops.push(DiffOp::Context(la.to_string()));
            i += 1;
            j += 1;
        } else if cell(table, width, i + 1, j) >= cell(table, width, i, j + 1) {
            ops.push(DiffOp::Removed(la.to_string()));
            i += 1;
        } else {
            ops.push(DiffOp::Added(lb.to_string()));
            j += 1;
        }
    }
    while let Some(&la) = a.get(i) {
        ops.push(DiffOp::Removed(la.to_string()));
        i += 1;
    }
    while let Some(&lb) = b.get(j) {
        ops.push(DiffOp::Added(lb.to_string()));
        j += 1;
    }
    ops
}

/// Render an edit script as `-`/`+`/space-prefixed lines (`diff`-style).
#[must_use]
pub fn format_diff(ops: &[DiffOp]) -> Vec<String> {
    ops.iter()
        .map(|op| match op {
            DiffOp::Context(line) => alloc::format!("  {line}"),
            DiffOp::Added(line) => alloc::format!("+ {line}"),
            DiffOp::Removed(line) => alloc::format!("- {line}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_inputs_are_all_context() {
        let ops = diff_lines("a\nb\nc", "a\nb\nc");
        assert_eq!(
            ops,
            [
                DiffOp::Context("a".to_string()),
                DiffOp::Context("b".to_string()),
                DiffOp::Context("c".to_string()),
            ]
        );
    }

    #[test]
    fn added_line_in_middle() {
        let ops = diff_lines("a\nc", "a\nb\nc");
        assert_eq!(
            ops,
            [
                DiffOp::Context("a".to_string()),
                DiffOp::Added("b".to_string()),
                DiffOp::Context("c".to_string()),
            ]
        );
    }

    #[test]
    fn removed_line() {
        let ops = diff_lines("a\nb\nc", "a\nc");
        assert_eq!(
            ops,
            [
                DiffOp::Context("a".to_string()),
                DiffOp::Removed("b".to_string()),
                DiffOp::Context("c".to_string()),
            ]
        );
    }

    #[test]
    fn changed_line_is_remove_then_add() {
        let ops = diff_lines("a\nb\nc", "a\nx\nc");
        assert_eq!(
            ops,
            [
                DiffOp::Context("a".to_string()),
                DiffOp::Removed("b".to_string()),
                DiffOp::Added("x".to_string()),
                DiffOp::Context("c".to_string()),
            ]
        );
    }

    #[test]
    fn empty_left_is_all_added() {
        let ops = diff_lines("", "x\ny");
        assert_eq!(
            ops,
            [
                DiffOp::Added("x".to_string()),
                DiffOp::Added("y".to_string())
            ]
        );
    }

    #[test]
    fn empty_right_is_all_removed() {
        let ops = diff_lines("x\ny", "");
        assert_eq!(
            ops,
            [
                DiffOp::Removed("x".to_string()),
                DiffOp::Removed("y".to_string())
            ]
        );
    }

    #[test]
    fn both_empty_no_ops() {
        assert!(diff_lines("", "").is_empty());
    }

    #[test]
    fn append_at_end() {
        let ops = diff_lines("a", "a\nb");
        assert_eq!(
            ops,
            [
                DiffOp::Context("a".to_string()),
                DiffOp::Added("b".to_string())
            ]
        );
    }

    #[test]
    fn format_uses_prefixes() {
        let ops = diff_lines("a\nb", "a\nx");
        let rendered = format_diff(&ops);
        assert_eq!(rendered, ["  a", "- b", "+ x"]);
    }

    #[test]
    fn complete_replacement() {
        let ops = diff_lines("a\nb", "c\nd");
        assert_eq!(
            ops,
            [
                DiffOp::Removed("a".to_string()),
                DiffOp::Removed("b".to_string()),
                DiffOp::Added("c".to_string()),
                DiffOp::Added("d".to_string()),
            ]
        );
    }
}
