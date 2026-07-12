//! `sed`-lite — stream substitution over lines.
//!
//! ## Supported subset
//!
//! A program is one or more commands, one per line (blank lines are ignored).
//! Each command is a substitution:
//!
//! ```text
//! [ADDR]s DELIM pattern DELIM replacement DELIM [g]
//! ```
//!
//! - **`ADDR`** — an optional 1-based line number. When present, the
//!   substitution applies only to that input line; otherwise it applies to
//!   every line.
//! - **`DELIM`** — the character immediately after `s` is the field delimiter
//!   (usually `/`, but any character works, e.g. `s|a|b|`).
//! - **`pattern`** — a **literal** string to search for (this is not a regular
//!   expression). The delimiter may be included by escaping it (`\<delim>`).
//! - **`replacement`** — the literal replacement text.
//! - **`g`** — optional flag: replace every occurrence on the line instead of
//!   just the first.
//!
//! Multiple commands are applied in order to each line (the output of one feeds
//! the next), matching `sed`'s command-pipeline behaviour. An empty pattern is
//! rejected (it would either loop forever or, in real `sed`, reuse the previous
//! regex, which this literal subset does not track).

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{CoreError, split_lines};

/// A single parsed `s///` substitution command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SedCommand {
    /// Optional 1-based line address; `None` means "every line".
    pub address: Option<usize>,
    /// Literal search string (never empty).
    pub pattern: String,
    /// Literal replacement string.
    pub replacement: String,
    /// `g` flag: replace all occurrences on the line.
    pub global: bool,
}

impl SedCommand {
    /// Return `true` if this command applies to line number `nr` (1-based).
    #[must_use]
    pub fn applies_to(&self, nr: usize) -> bool {
        self.address.is_none_or(|addr| addr == nr)
    }

    /// Apply the substitution to a single line of text.
    #[must_use]
    pub fn apply_to_line(&self, line: &str) -> String {
        if self.global {
            line.replace(&self.pattern, &self.replacement)
        } else {
            replace_first(line, &self.pattern, &self.replacement)
        }
    }
}

/// A parsed `sed` program: an ordered list of substitution commands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SedProgram {
    /// The commands, applied in order to each input line.
    pub commands: Vec<SedCommand>,
}

impl SedProgram {
    /// Parse a `sed` script (commands separated by newlines).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidProgram`] if any command is malformed
    /// (bad address, missing `s`, unterminated field, empty pattern, or an
    /// unknown flag).
    pub fn parse(script: &str) -> Result<Self, CoreError> {
        let mut commands = Vec::new();
        for raw in script.split('\n') {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            commands.push(parse_command(line)?);
        }
        Ok(Self { commands })
    }

    /// Apply the whole program to `input`, returning the transformed lines.
    #[must_use]
    pub fn apply(&self, input: &str) -> Vec<String> {
        split_lines(input)
            .into_iter()
            .enumerate()
            .map(|(idx, line)| {
                let nr = idx + 1;
                let mut current = line.to_string();
                for cmd in &self.commands {
                    if cmd.applies_to(nr) {
                        current = cmd.apply_to_line(&current);
                    }
                }
                current
            })
            .collect()
    }
}

/// Parse a single substitution command line.
fn parse_command(cmd: &str) -> Result<SedCommand, CoreError> {
    let mut chars = cmd.chars().peekable();

    // Optional leading 1-based line address.
    let mut addr = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            addr.push(c);
            chars.next();
        } else {
            break;
        }
    }
    let address = if addr.is_empty() {
        None
    } else {
        let n = addr
            .parse::<usize>()
            .map_err(|_| CoreError::InvalidProgram)?;
        if n == 0 {
            return Err(CoreError::InvalidProgram);
        }
        Some(n)
    };

    if chars.next() != Some('s') {
        return Err(CoreError::InvalidProgram);
    }
    let delim = chars.next().ok_or(CoreError::InvalidProgram)?;

    let pattern = scan_field(&mut chars, delim)?;
    let replacement = scan_field(&mut chars, delim)?;
    let flags: String = chars.collect();
    let global = parse_flags(&flags)?;

    if pattern.is_empty() {
        return Err(CoreError::InvalidProgram);
    }
    Ok(SedCommand {
        address,
        pattern,
        replacement,
        global,
    })
}

/// Read characters up to (and consuming) the next unescaped `delim`.
///
/// `\<delim>` yields a literal delimiter; any other `\x` is preserved verbatim.
/// Reaching the end of input without a closing delimiter is an error.
fn scan_field(
    chars: &mut core::iter::Peekable<core::str::Chars<'_>>,
    delim: char,
) -> Result<String, CoreError> {
    let mut field = String::new();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next) if next == delim => field.push(delim),
                Some(next) => {
                    field.push('\\');
                    field.push(next);
                }
                None => return Err(CoreError::InvalidProgram),
            }
        } else if c == delim {
            return Ok(field);
        } else {
            field.push(c);
        }
    }
    Err(CoreError::InvalidProgram)
}

/// Parse the trailing flag string; only `g` is recognised.
fn parse_flags(flags: &str) -> Result<bool, CoreError> {
    let mut global = false;
    for ch in flags.chars() {
        match ch {
            'g' => global = true,
            _ => return Err(CoreError::InvalidProgram),
        }
    }
    Ok(global)
}

/// Replace the first literal occurrence of `pat` in `haystack` with `rep`.
fn replace_first(haystack: &str, pat: &str, rep: &str) -> String {
    haystack.find(pat).map_or_else(
        || haystack.to_string(),
        |idx| {
            let mut out = String::new();
            out.push_str(haystack.get(..idx).unwrap_or(""));
            out.push_str(rep);
            out.push_str(haystack.get(idx + pat.len()..).unwrap_or(""));
            out
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(script: &str, input: &str) -> Vec<String> {
        SedProgram::parse(script).unwrap().apply(input)
    }

    #[test]
    fn substitutes_first_occurrence() {
        assert_eq!(run("s/a/X/", "aaa\nbab"), ["Xaa", "bXb"]);
    }

    #[test]
    fn global_flag_replaces_all() {
        assert_eq!(run("s/a/X/g", "aaa\nbab"), ["XXX", "bXb"]);
    }

    #[test]
    fn line_address_restricts() {
        assert_eq!(run("2s/x/Y/", "x\nx\nx"), ["x", "Y", "x"]);
    }

    #[test]
    fn custom_delimiter() {
        assert_eq!(run("s|/usr|/opt|", "/usr/bin"), ["/opt/bin"]);
    }

    #[test]
    fn escaped_delimiter_in_pattern() {
        // Match a literal slash, replace with a dash.
        assert_eq!(run("s/a\\/b/a-b/", "a/b"), ["a-b"]);
    }

    #[test]
    fn multi_command_pipeline() {
        // First s/a/b/ then s/b/c/ applied in order: "a" -> "b" -> "c".
        assert_eq!(run("s/a/b/\ns/b/c/", "a"), ["c"]);
    }

    #[test]
    fn no_match_leaves_line_unchanged() {
        assert_eq!(run("s/z/Q/", "abc"), ["abc"]);
    }

    #[test]
    fn replacement_can_be_empty() {
        assert_eq!(run("s/foo//g", "foofoo bar"), [" bar"]);
    }

    #[test]
    fn blank_lines_in_script_ignored() {
        assert_eq!(run("\n\ns/a/b/\n", "a"), ["b"]);
    }

    #[test]
    fn empty_pattern_rejected() {
        assert_eq!(SedProgram::parse("s//x/"), Err(CoreError::InvalidProgram));
    }

    #[test]
    fn unterminated_command_rejected() {
        assert_eq!(SedProgram::parse("s/a/b"), Err(CoreError::InvalidProgram));
    }

    #[test]
    fn unknown_flag_rejected() {
        assert_eq!(SedProgram::parse("s/a/b/z"), Err(CoreError::InvalidProgram));
    }

    #[test]
    fn zero_address_rejected() {
        assert_eq!(SedProgram::parse("0s/a/b/"), Err(CoreError::InvalidProgram));
    }

    #[test]
    fn missing_s_command_rejected() {
        assert_eq!(SedProgram::parse("d/a/b/"), Err(CoreError::InvalidProgram));
    }
}
