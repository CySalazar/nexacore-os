//! `xargs` — split an input stream into command-argument batches.
//!
//! Input is tokenised into arguments (by whitespace, or by a custom delimiter
//! with `-d`), then grouped into batches. With `-n N` each batch holds at most
//! `N` arguments; without it, all arguments form a single batch. An optional
//! command prefix is prepended to every batch, so the result models the argv
//! vectors `xargs` would actually execute.
//!
//! This is the pure batching logic only — no process is spawned (that seam is
//! a later subtask).

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Options controlling [`xargs_batches`], mirroring the `xargs` command flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XargsOptions {
    /// `-n`: maximum arguments per batch. `None` (or `Some(0)`) means "all in
    /// one batch".
    pub max_args: Option<usize>,
    /// `-d`: token delimiter. `None` splits on any ASCII whitespace run.
    pub delimiter: Option<char>,
    /// Fixed command + leading arguments prepended to every batch.
    pub command: Vec<String>,
}

/// Tokenise `input` into arguments, then build the argv batches.
///
/// Each returned inner vector is one command invocation: the configured
/// [`command`](XargsOptions::command) prefix followed by that batch's
/// arguments. If the input has no arguments, the result is empty (nothing to
/// run), matching `xargs --no-run-if-empty`.
#[must_use]
pub fn xargs_batches(input: &str, opts: &XargsOptions) -> Vec<Vec<String>> {
    let tokens = tokenize(input, opts.delimiter);
    if tokens.is_empty() {
        return Vec::new();
    }

    let chunk = match opts.max_args {
        Some(n) if n > 0 => n,
        _ => tokens.len(),
    };

    tokens
        .chunks(chunk)
        .map(|batch| {
            let mut argv = opts.command.clone();
            argv.extend(batch.iter().cloned());
            argv
        })
        .collect()
}

/// Split `input` into non-empty argument tokens.
fn tokenize(input: &str, delimiter: Option<char>) -> Vec<String> {
    delimiter.map_or_else(
        || input.split_whitespace().map(ToString::to_string).collect(),
        |d| {
            input
                .split(d)
                .filter(|t| !t.is_empty())
                .map(ToString::to_string)
                .collect()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn whitespace_split_single_batch() {
        let out = xargs_batches("a b  c\nd", &XargsOptions::default());
        assert_eq!(out, [s(&["a", "b", "c", "d"])]);
    }

    #[test]
    fn max_args_chunks() {
        let opts = XargsOptions {
            max_args: Some(2),
            ..XargsOptions::default()
        };
        let out = xargs_batches("a b c d e", &opts);
        assert_eq!(out, [s(&["a", "b"]), s(&["c", "d"]), s(&["e"])]);
    }

    #[test]
    fn command_prefix_prepended_to_each_batch() {
        let opts = XargsOptions {
            max_args: Some(1),
            command: s(&["echo"]),
            ..XargsOptions::default()
        };
        let out = xargs_batches("x y", &opts);
        assert_eq!(out, [s(&["echo", "x"]), s(&["echo", "y"])]);
    }

    #[test]
    fn custom_delimiter() {
        let opts = XargsOptions {
            delimiter: Some(','),
            ..XargsOptions::default()
        };
        let out = xargs_batches("a,b,c", &opts);
        assert_eq!(out, [s(&["a", "b", "c"])]);
    }

    #[test]
    fn custom_delimiter_keeps_whitespace_in_tokens() {
        let opts = XargsOptions {
            delimiter: Some(','),
            max_args: Some(1),
            ..XargsOptions::default()
        };
        let out = xargs_batches("hello world,foo", &opts);
        assert_eq!(out, [s(&["hello world"]), s(&["foo"])]);
    }

    #[test]
    fn empty_input_runs_nothing() {
        assert!(xargs_batches("   \n  ", &XargsOptions::default()).is_empty());
    }

    #[test]
    fn zero_max_args_treated_as_all() {
        let opts = XargsOptions {
            max_args: Some(0),
            ..XargsOptions::default()
        };
        let out = xargs_batches("a b c", &opts);
        assert_eq!(out, [s(&["a", "b", "c"])]);
    }

    #[test]
    fn delimiter_ignores_empty_tokens() {
        let opts = XargsOptions {
            delimiter: Some(','),
            ..XargsOptions::default()
        };
        let out = xargs_batches("a,,b,", &opts);
        assert_eq!(out, [s(&["a", "b"])]);
    }
}
