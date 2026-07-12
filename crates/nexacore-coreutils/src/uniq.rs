//! `uniq` — collapse adjacent duplicate lines.
//!
//! `uniq` only ever compares *adjacent* lines (like the real tool), so callers
//! that want global deduplication should [`sort`](crate::sort) first.
//!
//! Supported flags:
//!
//! | Flag | Meaning |
//! |------|---------|
//! | (none) | Emit one line per run of adjacent equal lines |
//! | `-c` | Prefix each output line with its run count, as `"{count} {line}"` |
//! | `-d` | Emit only runs that repeated (count > 1) |
//! | `-u` | Emit only runs that occurred exactly once |
//!
//! `-d` and `-u` are mutually exclusive filters; if both are set nothing
//! matches (a run cannot be both repeated and unique), mirroring GNU `uniq`.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::split_lines;

/// Options controlling [`uniq_lines`], mirroring the `uniq` command flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UniqOptions {
    /// `-c`: prefix each emitted line with its run count.
    pub count: bool,
    /// `-d`: emit only runs that repeated (count > 1).
    pub only_repeated: bool,
    /// `-u`: emit only runs that occurred exactly once.
    pub only_unique: bool,
}

/// Parse `uniq`-style flags (e.g. `["-c", "-d"]` or a bundled `["-cd"]`).
///
/// # Errors
///
/// Returns [`CoreError::InvalidArgument`](crate::CoreError::InvalidArgument)
/// for any unrecognised flag or non-flag argument.
pub fn parse_args<I, S>(args: I) -> Result<UniqOptions, crate::CoreError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut opts = UniqOptions::default();
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
                'c' => opts.count = true,
                'd' => opts.only_repeated = true,
                'u' => opts.only_unique = true,
                _ => return Err(crate::CoreError::InvalidArgument),
            }
        }
    }
    Ok(opts)
}

/// Collapse adjacent duplicate lines of `input` according to `opts`.
#[must_use]
pub fn uniq_lines(input: &str, opts: &UniqOptions) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<&str> = None;
    let mut count: usize = 0;

    for line in split_lines(input) {
        match current {
            Some(prev) if prev == line => count += 1,
            _ => {
                emit(&mut out, current, count, opts);
                current = Some(line);
                count = 1;
            }
        }
    }
    emit(&mut out, current, count, opts);
    out
}

/// Push the finished run (`line` seen `count` times) to `out` if it passes the
/// `-d`/`-u` filters, formatting the count prefix when `-c` is set.
fn emit(out: &mut Vec<String>, line: Option<&str>, count: usize, opts: &UniqOptions) {
    let Some(line) = line else {
        return;
    };
    if opts.only_repeated && count < 2 {
        return;
    }
    if opts.only_unique && count != 1 {
        return;
    }
    if opts.count {
        out.push(format!("{count} {line}"));
    } else {
        out.push(line.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_adjacent_runs() {
        let out = uniq_lines("a\na\nb\na", &UniqOptions::default());
        assert_eq!(out, ["a", "b", "a"]);
    }

    #[test]
    fn non_adjacent_duplicates_survive() {
        let out = uniq_lines("a\nb\na\nb", &UniqOptions::default());
        assert_eq!(out, ["a", "b", "a", "b"]);
    }

    #[test]
    fn counts_runs() {
        let opts = UniqOptions {
            count: true,
            ..UniqOptions::default()
        };
        let out = uniq_lines("a\na\na\nb\nc\nc", &opts);
        assert_eq!(out, ["3 a", "1 b", "2 c"]);
    }

    #[test]
    fn only_repeated() {
        let opts = UniqOptions {
            only_repeated: true,
            ..UniqOptions::default()
        };
        let out = uniq_lines("a\na\nb\nc\nc", &opts);
        assert_eq!(out, ["a", "c"]);
    }

    #[test]
    fn only_unique() {
        let opts = UniqOptions {
            only_unique: true,
            ..UniqOptions::default()
        };
        let out = uniq_lines("a\na\nb\nc\nc", &opts);
        assert_eq!(out, ["b"]);
    }

    #[test]
    fn count_with_only_repeated() {
        let opts = UniqOptions {
            count: true,
            only_repeated: true,
            ..UniqOptions::default()
        };
        let out = uniq_lines("x\nx\ny", &opts);
        assert_eq!(out, ["2 x"]);
    }

    #[test]
    fn repeated_and_unique_together_match_nothing() {
        let opts = UniqOptions {
            only_repeated: true,
            only_unique: true,
            count: false,
        };
        let out = uniq_lines("a\na\nb", &opts);
        assert!(out.is_empty());
    }

    #[test]
    fn preserves_interior_empty_lines() {
        let out = uniq_lines("a\n\n\nb", &UniqOptions::default());
        assert_eq!(out, ["a", "", "b"]);
    }

    #[test]
    fn empty_input() {
        assert!(uniq_lines("", &UniqOptions::default()).is_empty());
    }

    #[test]
    fn parse_bundled() {
        let opts = parse_args(["-cd"]).unwrap();
        assert_eq!(
            opts,
            UniqOptions {
                count: true,
                only_repeated: true,
                only_unique: false
            }
        );
    }

    #[test]
    fn parse_rejects_unknown() {
        assert_eq!(parse_args(["-z"]), Err(crate::CoreError::InvalidArgument));
    }
}
