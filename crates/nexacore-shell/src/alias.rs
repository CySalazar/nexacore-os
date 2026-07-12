//! First-word alias expansion with a recursion loop-guard.
//!
//! The alias *table* lives in [`crate::env::ShellEnv`] (`set_alias` /
//! `get_alias` / `remove_alias` / `aliases`). This module contributes the
//! missing piece: expanding the first word of a command line against that
//! table, without touching quoted or non-first tokens, and terminating on
//! recursive alias chains.
//!
//! ## Rules (POSIX-flavoured)
//!
//! - Only the **first word** of the line is a candidate for expansion; every
//!   later token is copied through verbatim.
//! - If the first word is **quoted** (`'…'` or `"…"`), it is *not* an alias
//!   reference and the line is returned unchanged.
//! - After a substitution the *new* first word is re-examined, so chained
//!   aliases expand fully. A **loop-guard** tracks the set of already-expanded
//!   alias names and stops the moment a name recurs, so `a→b→c→a` and the
//!   classic self-referential `alias ls='ls --color'` both terminate.
//! - Leading whitespace is preserved.

use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

use crate::env::ShellEnv;

/// Expand the first word of `line` against the alias table in `env`.
///
/// Returns the expanded command line. See the [module docs](self) for the exact
/// rules. Non-alias, quoted, and empty first words leave the line untouched.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{alias::expand_line, env::ShellEnv};
///
/// let mut env = ShellEnv::new();
/// env.set_alias("ll", "ls -la");
/// assert_eq!(expand_line("ll /tmp", &env), "ls -la /tmp");
/// // Quoted first word is not expanded.
/// assert_eq!(expand_line("'ll'", &env), "'ll'");
/// ```
#[must_use]
pub fn expand_line(line: &str, env: &ShellEnv) -> String {
    // Preserve leading whitespace exactly; only the remainder is rewritten.
    let ws_end = line.len() - line.trim_start().len();
    let (leading, rest) = line.split_at(ws_end);

    // A quoted first word is never an alias reference.
    if rest.starts_with('\'') || rest.starts_with('"') {
        return line.to_string();
    }

    let mut current = rest.to_string();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    loop {
        // Split off the first word and the (possibly empty) remainder.
        let trimmed = current.trim_start();
        let word_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
        let (word, tail) = trimmed.split_at(word_end);

        if word.is_empty() {
            break;
        }
        // Loop-guard: stop if this alias name was already expanded.
        if seen.contains(word) {
            break;
        }
        let Some(value) = env.get_alias(word) else {
            break;
        };
        seen.insert(word.to_string());
        current = alloc::format!("{value}{tail}");
    }

    alloc::format!("{leading}{current}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_first_word() {
        let mut env = ShellEnv::new();
        env.set_alias("ll", "ls -la");
        assert_eq!(expand_line("ll", &env), "ls -la");
    }

    #[test]
    fn expands_first_word_keeps_remaining_args() {
        let mut env = ShellEnv::new();
        env.set_alias("ll", "ls -la");
        assert_eq!(expand_line("ll /tmp", &env), "ls -la /tmp");
    }

    #[test]
    fn non_alias_first_word_is_unchanged() {
        let env = ShellEnv::new();
        assert_eq!(expand_line("echo hello", &env), "echo hello");
    }

    #[test]
    fn only_first_word_is_expanded() {
        // "ls" is an alias, but as a non-first token it must NOT be expanded.
        let mut env = ShellEnv::new();
        env.set_alias("ls", "ls --color");
        env.set_alias("grep", "grep -n");
        // First word grep expands; the later "ls" token stays literal.
        assert_eq!(expand_line("grep ls", &env), "grep -n ls");
    }

    #[test]
    fn quoted_first_word_is_not_expanded_single() {
        let mut env = ShellEnv::new();
        env.set_alias("ll", "ls -la");
        assert_eq!(expand_line("'ll'", &env), "'ll'");
    }

    #[test]
    fn quoted_first_word_is_not_expanded_double() {
        let mut env = ShellEnv::new();
        env.set_alias("ll", "ls -la");
        assert_eq!(expand_line("\"ll\" foo", &env), "\"ll\" foo");
    }

    #[test]
    fn recursive_alias_chain_terminates() {
        // a -> b -> c -> a : the guard must stop when "a" recurs.
        let mut env = ShellEnv::new();
        env.set_alias("a", "b");
        env.set_alias("b", "c");
        env.set_alias("c", "a");
        // a -> b -> c -> a(seen) : stops, leaving the first word as "a".
        assert_eq!(expand_line("a", &env), "a");
    }

    #[test]
    fn self_referential_alias_terminates() {
        // The classic `alias ls='ls --color'` must expand exactly once.
        let mut env = ShellEnv::new();
        env.set_alias("ls", "ls --color");
        assert_eq!(expand_line("ls /tmp", &env), "ls --color /tmp");
    }

    #[test]
    fn multi_step_alias_expands_fully() {
        // ll -> "la -h", la -> "ls -a" : first word re-checked each step.
        let mut env = ShellEnv::new();
        env.set_alias("ll", "la -h");
        env.set_alias("la", "ls -a");
        assert_eq!(expand_line("ll /x", &env), "ls -a -h /x");
    }

    #[test]
    fn empty_line_is_unchanged() {
        let env = ShellEnv::new();
        assert_eq!(expand_line("", &env), "");
        assert_eq!(expand_line("   ", &env), "   ");
    }

    #[test]
    fn leading_whitespace_is_preserved() {
        let mut env = ShellEnv::new();
        env.set_alias("ll", "ls -la");
        assert_eq!(expand_line("  ll", &env), "  ls -la");
    }
}
