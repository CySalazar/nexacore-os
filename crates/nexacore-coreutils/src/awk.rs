//! `awk`-lite — field extraction and a minimal `print` action.
//!
//! ## Supported subset
//!
//! A program is a single action of the form `{ print ARG, ARG, ... }`:
//!
//! - **`$0`** — the whole current record (line).
//! - **`$N`** — the `N`-th field (1-based); out-of-range fields render empty.
//! - **`NR`** — the current record number (1-based).
//! - **`NF`** — the number of fields in the current record.
//! - **`"literal"`** — a double-quoted string literal, emitted verbatim.
//! - **`{ print }`** (no args) is shorthand for `{ print $0 }`.
//!
//! Arguments are separated by commas and joined on output with a single space
//! (the default `OFS`). The field separator defaults to runs of whitespace;
//! `-F C` (passed as `field_sep`) splits on the single character `C` instead.
//!
//! Not supported (out of scope for the lite subset): patterns/conditions,
//! `BEGIN`/`END` blocks, multiple statements, variables, arithmetic, and
//! regular-expression field separators.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{CoreError, split_lines};

/// One argument of a `print` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwkArg {
    /// `$0`: the entire record.
    WholeRecord,
    /// `$N`: the `N`-th field (1-based).
    Field(usize),
    /// `NR`: the current record number.
    RecordNumber,
    /// `NF`: the number of fields in the record.
    FieldCount,
    /// A string literal.
    Literal(String),
}

/// A parsed `awk`-lite program: a field separator plus a `print` argument list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwkProgram {
    /// Field separator: `None` splits on whitespace runs, `Some(c)` on `c`.
    pub field_sep: Option<char>,
    /// The ordered arguments of the `print` action.
    pub print_args: Vec<AwkArg>,
}

impl AwkProgram {
    /// Parse a `{ print ... }` program with an optional field separator.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidProgram`] if the program is not a
    /// `{ print ... }` block, has an empty argument, an unterminated string, or
    /// an unrecognised argument token.
    pub fn parse(program: &str, field_sep: Option<char>) -> Result<Self, CoreError> {
        let body = program
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .ok_or(CoreError::InvalidProgram)?
            .trim();

        let rest = body
            .strip_prefix("print")
            .ok_or(CoreError::InvalidProgram)?
            .trim();
        let print_args = if rest.is_empty() {
            alloc::vec![AwkArg::WholeRecord]
        } else {
            parse_args(rest)?
        };
        Ok(Self {
            field_sep,
            print_args,
        })
    }

    /// Apply the program to every record (line) of `input`.
    #[must_use]
    pub fn apply(&self, input: &str) -> Vec<String> {
        split_lines(input)
            .into_iter()
            .enumerate()
            .map(|(idx, line)| self.render(line, idx + 1))
            .collect()
    }

    /// Render one record given its 1-based record number.
    fn render(&self, line: &str, nr: usize) -> String {
        let fields = self.split_fields(line);
        let parts: Vec<String> = self
            .print_args
            .iter()
            .map(|arg| eval_arg(arg, line, &fields, nr))
            .collect();
        parts.join(" ")
    }

    /// Split a record into fields according to the configured separator.
    fn split_fields<'a>(&self, line: &'a str) -> Vec<&'a str> {
        self.field_sep.map_or_else(
            || line.split_whitespace().collect(),
            |sep| line.split(sep).collect(),
        )
    }
}

/// Evaluate a single `print` argument against the current record.
fn eval_arg(arg: &AwkArg, line: &str, fields: &[&str], nr: usize) -> String {
    match arg {
        AwkArg::WholeRecord => line.to_string(),
        AwkArg::Field(n) => fields
            .get(n.saturating_sub(1))
            .map_or_else(String::new, ToString::to_string),
        AwkArg::RecordNumber => nr.to_string(),
        AwkArg::FieldCount => fields.len().to_string(),
        AwkArg::Literal(text) => text.clone(),
    }
}

/// Split the argument list on commas (respecting quotes) and classify each.
fn parse_args(rest: &str) -> Result<Vec<AwkArg>, CoreError> {
    let mut args = Vec::new();
    for token in split_on_commas(rest)? {
        args.push(classify(token.trim())?);
    }
    Ok(args)
}

/// Split on top-level commas, keeping quoted commas inside their string.
fn split_on_commas(input: &str) -> Result<Vec<String>, CoreError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                tokens.push(core::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if in_quotes {
        return Err(CoreError::InvalidProgram);
    }
    tokens.push(current);
    Ok(tokens)
}

/// Classify a single trimmed argument token into an [`AwkArg`].
fn classify(token: &str) -> Result<AwkArg, CoreError> {
    if token.is_empty() {
        return Err(CoreError::InvalidProgram);
    }
    if token == "NR" {
        return Ok(AwkArg::RecordNumber);
    }
    if token == "NF" {
        return Ok(AwkArg::FieldCount);
    }
    if let Some(inner) = token.strip_prefix('"') {
        let literal = inner.strip_suffix('"').ok_or(CoreError::InvalidProgram)?;
        return Ok(AwkArg::Literal(literal.to_string()));
    }
    if let Some(num) = token.strip_prefix('$') {
        let n = num
            .parse::<usize>()
            .map_err(|_| CoreError::InvalidProgram)?;
        return Ok(if n == 0 {
            AwkArg::WholeRecord
        } else {
            AwkArg::Field(n)
        });
    }
    Err(CoreError::InvalidProgram)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(program: &str, sep: Option<char>, input: &str) -> Vec<String> {
        AwkProgram::parse(program, sep).unwrap().apply(input)
    }

    #[test]
    fn print_whole_record_default() {
        assert_eq!(run("{print}", None, "hello\nworld"), ["hello", "world"]);
    }

    #[test]
    fn print_explicit_field() {
        assert_eq!(run("{print $2}", None, "a b c"), ["b"]);
    }

    #[test]
    fn print_multiple_fields_joined_by_space() {
        assert_eq!(run("{print $1, $3}", None, "a b c"), ["a c"]);
    }

    #[test]
    fn whitespace_runs_collapse() {
        assert_eq!(run("{print $2}", None, "a    b"), ["b"]);
    }

    #[test]
    fn custom_field_separator() {
        assert_eq!(run("{print $1, $3}", Some(':'), "root:x:0:0"), ["root 0"]);
    }

    #[test]
    fn nr_and_nf() {
        assert_eq!(run("{print NR, NF}", None, "a b\nc d e"), ["1 2", "2 3"]);
    }

    #[test]
    fn field_zero_is_whole_record() {
        assert_eq!(run("{print $0}", None, "a b c"), ["a b c"]);
    }

    #[test]
    fn out_of_range_field_is_empty() {
        assert_eq!(run("{print $5}", None, "a b"), [""]);
    }

    #[test]
    fn string_literal() {
        assert_eq!(run("{print \"row\", NR}", None, "x\ny"), ["row 1", "row 2"]);
    }

    #[test]
    fn literal_with_comma_inside_quotes() {
        assert_eq!(run("{print \"a,b\"}", None, "x"), ["a,b"]);
    }

    #[test]
    fn separator_split_keeps_empty_fields() {
        // Colon split of "a::b" yields 3 fields; field 2 is empty.
        assert_eq!(run("{print NF, $2}", Some(':'), "a::b"), ["3 "]);
    }

    #[test]
    fn missing_braces_rejected() {
        assert_eq!(
            AwkProgram::parse("print $1", None),
            Err(CoreError::InvalidProgram)
        );
    }

    #[test]
    fn missing_print_rejected() {
        assert_eq!(
            AwkProgram::parse("{ $1 }", None),
            Err(CoreError::InvalidProgram)
        );
    }

    #[test]
    fn unterminated_string_rejected() {
        assert_eq!(
            AwkProgram::parse("{print \"oops}", None),
            Err(CoreError::InvalidProgram)
        );
    }

    #[test]
    fn unknown_token_rejected() {
        assert_eq!(
            AwkProgram::parse("{print foo}", None),
            Err(CoreError::InvalidProgram)
        );
    }

    #[test]
    fn trailing_comma_rejected() {
        assert_eq!(
            AwkProgram::parse("{print $1,}", None),
            Err(CoreError::InvalidProgram)
        );
    }
}
