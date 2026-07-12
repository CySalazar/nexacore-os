//! `sort` — order the lines of a text stream.
//!
//! Supported flags:
//!
//! | Flag | Meaning |
//! |------|---------|
//! | (none) | Lexical (byte-wise Unicode scalar) ascending order |
//! | `-n` | Numeric: compare a leading integer key (`i64`) |
//! | `-r` | Reverse the final order |
//! | `-u` | Keep only the first of each run of equal keys |
//!
//! Numeric mode parses the longest leading `[+-]?[0-9]+` prefix of each line
//! (after leading whitespace) into an `i64`; lines without a numeric prefix
//! sort as `0`, matching GNU `sort -n`. No floating point is used, so ordering
//! is exact for integer keys.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::split_lines;

/// Options controlling [`sort_lines`], mirroring the `sort` command flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SortOptions {
    /// `-n`: compare a leading integer key instead of lexically.
    pub numeric: bool,
    /// `-r`: reverse the resulting order.
    pub reverse: bool,
    /// `-u`: drop all but the first line of each run of equal keys.
    pub unique: bool,
}

/// Parse `sort`-style flags (e.g. `["-n", "-r"]`, or a bundled `["-nru"]`).
///
/// # Errors
///
/// Returns [`CoreError::InvalidArgument`](crate::CoreError::InvalidArgument)
/// for any unrecognised flag or non-flag argument.
pub fn parse_args<I, S>(args: I) -> Result<SortOptions, crate::CoreError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut opts = SortOptions::default();
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
                'n' => opts.numeric = true,
                'r' => opts.reverse = true,
                'u' => opts.unique = true,
                _ => return Err(crate::CoreError::InvalidArgument),
            }
        }
    }
    Ok(opts)
}

/// Sort `input`'s lines according to `opts`.
#[must_use]
pub fn sort_lines(input: &str, opts: &SortOptions) -> Vec<String> {
    let mut lines = split_lines(input);

    if opts.numeric {
        lines.sort_by_key(|line| numeric_key(line));
    } else {
        lines.sort_unstable();
    }

    if opts.unique {
        if opts.numeric {
            lines.dedup_by(|a, b| numeric_key(a) == numeric_key(b));
        } else {
            lines.dedup();
        }
    }

    if opts.reverse {
        lines.reverse();
    }

    lines.into_iter().map(ToString::to_string).collect()
}

/// Extract the leading integer key of a line for numeric sorting.
///
/// Skips leading whitespace, then reads an optional sign followed by ASCII
/// digits. Anything that does not parse (empty prefix, lone sign) yields `0`.
fn numeric_key(line: &str) -> i64 {
    let trimmed = line.trim_start();
    let mut prefix = String::new();
    for (idx, ch) in trimmed.chars().enumerate() {
        let is_sign = idx == 0 && (ch == '-' || ch == '+');
        if is_sign || ch.is_ascii_digit() {
            prefix.push(ch);
        } else {
            break;
        }
    }
    prefix.parse::<i64>().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_ascending() {
        let out = sort_lines("banana\napple\ncherry", &SortOptions::default());
        assert_eq!(out, ["apple", "banana", "cherry"]);
    }

    #[test]
    fn lexical_is_bytewise_not_numeric() {
        // "10" < "9" lexically because '1' < '9'.
        let out = sort_lines("9\n10\n2", &SortOptions::default());
        assert_eq!(out, ["10", "2", "9"]);
    }

    #[test]
    fn numeric_ascending() {
        let opts = SortOptions {
            numeric: true,
            ..SortOptions::default()
        };
        let out = sort_lines("9\n10\n2", &opts);
        assert_eq!(out, ["2", "9", "10"]);
    }

    #[test]
    fn numeric_handles_signs_and_nonnumeric() {
        let opts = SortOptions {
            numeric: true,
            ..SortOptions::default()
        };
        let out = sort_lines("-5\nfoo\n3\n-1", &opts);
        // "foo" -> 0, so order: -5, -1, foo(0), 3
        assert_eq!(out, ["-5", "-1", "foo", "3"]);
    }

    #[test]
    fn numeric_with_leading_whitespace() {
        let opts = SortOptions {
            numeric: true,
            ..SortOptions::default()
        };
        let out = sort_lines("  30\n4\n 100", &opts);
        assert_eq!(out, ["4", "  30", " 100"]);
    }

    #[test]
    fn reverse_order() {
        let opts = SortOptions {
            reverse: true,
            ..SortOptions::default()
        };
        let out = sort_lines("a\nb\nc", &opts);
        assert_eq!(out, ["c", "b", "a"]);
    }

    #[test]
    fn unique_lexical() {
        let opts = SortOptions {
            unique: true,
            ..SortOptions::default()
        };
        let out = sort_lines("b\na\nb\na\nc", &opts);
        assert_eq!(out, ["a", "b", "c"]);
    }

    #[test]
    fn unique_numeric_dedups_by_key() {
        let opts = SortOptions {
            numeric: true,
            unique: true,
            ..SortOptions::default()
        };
        // "3" and " 3 " share numeric key 3; first survives.
        let out = sort_lines("3\n1\n3\n2", &opts);
        assert_eq!(out, ["1", "2", "3"]);
    }

    #[test]
    fn numeric_reverse_unique_combination() {
        let opts = SortOptions {
            numeric: true,
            reverse: true,
            unique: true,
        };
        let out = sort_lines("1\n3\n2\n3\n1", &opts);
        assert_eq!(out, ["3", "2", "1"]);
    }

    #[test]
    fn trailing_newline_does_not_add_empty_line() {
        let out = sort_lines("b\na\n", &SortOptions::default());
        assert_eq!(out, ["a", "b"]);
    }

    #[test]
    fn empty_input_yields_no_lines() {
        assert!(sort_lines("", &SortOptions::default()).is_empty());
    }

    #[test]
    fn parse_bundled_flags() {
        let opts = parse_args(["-nru"]).unwrap();
        assert_eq!(
            opts,
            SortOptions {
                numeric: true,
                reverse: true,
                unique: true
            }
        );
    }

    #[test]
    fn parse_separate_flags() {
        let opts = parse_args(["-n", "-r"]).unwrap();
        assert_eq!(
            opts,
            SortOptions {
                numeric: true,
                reverse: true,
                unique: false
            }
        );
    }

    #[test]
    fn parse_rejects_unknown_flag() {
        assert_eq!(parse_args(["-x"]), Err(crate::CoreError::InvalidArgument));
    }

    #[test]
    fn parse_rejects_bare_dash() {
        assert_eq!(parse_args(["-"]), Err(crate::CoreError::InvalidArgument));
    }

    #[test]
    fn parse_rejects_non_flag() {
        assert_eq!(
            parse_args(["file.txt"]),
            Err(crate::CoreError::InvalidArgument)
        );
    }
}
