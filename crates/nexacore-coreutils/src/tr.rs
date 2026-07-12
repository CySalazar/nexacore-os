//! `tr` — translate, delete, or squeeze characters.
//!
//! Modes, mirroring the real tool:
//!
//! - `tr SET1 SET2` — translate each character in `SET1` to the character at
//!   the same position in `SET2`. If `SET2` is shorter, its last character is
//!   reused for the remaining `SET1` positions (GNU behaviour).
//! - `tr -d SET1` — delete every character in `SET1`.
//! - `tr -s SET1` — squeeze runs of the same character in `SET1` to one.
//! - `tr -s SET1 SET2` — translate, then squeeze using `SET2`.
//! - `tr -d -s SET1 SET2` — delete `SET1`, then squeeze `SET2`.
//!
//! Set syntax supports literal characters, `a-z` ranges, and the backslash
//! escapes `\n`, `\t`, `\r`, `\\`, and `\-` (a literal dash).

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::CoreError;

/// Options controlling [`tr`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrOptions {
    /// `-d`: delete characters in `set1` instead of translating.
    pub delete: bool,
    /// `-s`: squeeze adjacent repeats in the squeeze set.
    pub squeeze: bool,
    /// The expanded first character set.
    pub set1: Vec<char>,
    /// The expanded second character set (may be empty).
    pub set2: Vec<char>,
}

impl TrOptions {
    /// Build options from raw set specs, expanding ranges and escapes.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidRange`] for a reversed range (`z-a`) and
    /// [`CoreError::InvalidArgument`] for a dangling escape.
    pub fn new(delete: bool, squeeze: bool, set1: &str, set2: &str) -> Result<Self, CoreError> {
        Ok(Self {
            delete,
            squeeze,
            set1: expand_set(set1)?,
            set2: expand_set(set2)?,
        })
    }
}

/// Expand a `tr` set specification into an explicit character vector.
///
/// # Errors
///
/// Returns [`CoreError::InvalidRange`] if a range's end precedes its start, and
/// [`CoreError::InvalidArgument`] for a trailing backslash with no escapee.
pub fn expand_set(spec: &str) -> Result<Vec<char>, CoreError> {
    let tokens = tokenize(spec)?;
    expand_ranges(&tokens)
}

/// A resolved set token: the character plus whether it came from an escape
/// (an escaped `-` must never start a range).
type Token = (char, bool);

/// Resolve backslash escapes into `(char, escaped)` tokens.
fn tokenize(spec: &str) -> Result<Vec<Token>, CoreError> {
    let mut tokens = Vec::new();
    let mut chars = spec.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let Some(next) = chars.next() else {
                return Err(CoreError::InvalidArgument);
            };
            let mapped = match next {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                other => other,
            };
            tokens.push((mapped, true));
        } else {
            tokens.push((c, false));
        }
    }
    Ok(tokens)
}

/// Expand `a-z` style ranges within a resolved token stream.
fn expand_ranges(tokens: &[Token]) -> Result<Vec<char>, CoreError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(&(start, _)) = tokens.get(i) {
        let dash = tokens.get(i + 1);
        let end = tokens.get(i + 2);
        if let (Some(&('-', false)), Some(&(stop, _))) = (dash, end) {
            if stop < start {
                return Err(CoreError::InvalidRange);
            }
            for cp in u32::from(start)..=u32::from(stop) {
                if let Some(ch) = char::from_u32(cp) {
                    out.push(ch);
                }
            }
            i += 3;
        } else {
            out.push(start);
            i += 1;
        }
    }
    Ok(out)
}

/// Apply `tr` to the whole input string.
#[must_use]
pub fn tr(input: &str, opts: &TrOptions) -> String {
    let transformed = if opts.delete {
        delete_chars(input, &opts.set1)
    } else if opts.set2.is_empty() {
        input.to_string()
    } else {
        translate(input, &opts.set1, &opts.set2)
    };

    if opts.squeeze {
        let squeeze_set = if opts.set2.is_empty() {
            &opts.set1
        } else {
            &opts.set2
        };
        squeeze_chars(&transformed, squeeze_set)
    } else {
        transformed
    }
}

/// Translate every character of `set1` to the aligned character of `set2`.
fn translate(input: &str, set1: &[char], set2: &[char]) -> String {
    let last = set2.len().saturating_sub(1);
    let mut out = String::new();
    for ch in input.chars() {
        match set1.iter().position(|&c| c == ch) {
            Some(pos) => match set2.get(pos.min(last)) {
                Some(&mapped) => out.push(mapped),
                None => out.push(ch),
            },
            None => out.push(ch),
        }
    }
    out
}

/// Delete every character that appears in `set`.
fn delete_chars(input: &str, set: &[char]) -> String {
    input.chars().filter(|ch| !set.contains(ch)).collect()
}

/// Squeeze adjacent repeats of any character in `set` down to one.
fn squeeze_chars(input: &str, set: &[char]) -> String {
    let mut out = String::new();
    let mut prev: Option<char> = None;
    for ch in input.chars() {
        if prev == Some(ch) && set.contains(&ch) {
            continue;
        }
        out.push(ch);
        prev = Some(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(delete: bool, squeeze: bool, s1: &str, s2: &str) -> TrOptions {
        TrOptions::new(delete, squeeze, s1, s2).unwrap()
    }

    #[test]
    fn translate_one_to_one() {
        assert_eq!(tr("hello", &opts(false, false, "el", "ip")), "hippo");
    }

    #[test]
    fn translate_case_via_range() {
        assert_eq!(tr("Hello", &opts(false, false, "a-z", "A-Z")), "HELLO");
    }

    #[test]
    fn translate_shorter_set2_reuses_last() {
        // set1 = abc, set2 = x -> all map to 'x'.
        assert_eq!(tr("abc", &opts(false, false, "abc", "x")), "xxx");
    }

    #[test]
    fn delete_chars_removes() {
        assert_eq!(tr("hello world", &opts(true, false, "lo", "")), "he wrd");
    }

    #[test]
    fn delete_range() {
        assert_eq!(tr("a1b2c3", &opts(true, false, "0-9", "")), "abc");
    }

    #[test]
    fn squeeze_only() {
        assert_eq!(tr("aaabbbccc", &opts(false, true, "abc", "")), "abc");
    }

    #[test]
    fn squeeze_specific_char_only() {
        // Only squeeze spaces; letters keep their runs.
        assert_eq!(tr("a   b    c", &opts(false, true, " ", "")), "a b c");
    }

    #[test]
    fn translate_then_squeeze() {
        // Translate a->x, then squeeze x.
        assert_eq!(tr("aaa", &opts(false, true, "a", "x")), "x");
    }

    #[test]
    fn delete_then_squeeze() {
        // Delete 'x', squeeze 'a'.
        let o = opts(true, true, "x", "a");
        assert_eq!(tr("axaxaa", &o), "a");
    }

    #[test]
    fn escapes_expand() {
        // Translate newline to space.
        assert_eq!(tr("a\nb", &opts(false, false, "\\n", " ")), "a b");
    }

    #[test]
    fn literal_dash_via_escape() {
        let set = expand_set("a\\-c").unwrap();
        assert_eq!(set, ['a', '-', 'c']);
    }

    #[test]
    fn range_expands_inclusive() {
        assert_eq!(expand_set("a-e").unwrap(), ['a', 'b', 'c', 'd', 'e']);
    }

    #[test]
    fn reversed_range_rejected() {
        assert_eq!(expand_set("z-a"), Err(CoreError::InvalidRange));
    }

    #[test]
    fn trailing_backslash_rejected() {
        assert_eq!(expand_set("abc\\"), Err(CoreError::InvalidArgument));
    }

    #[test]
    fn untranslated_chars_pass_through() {
        assert_eq!(tr("abcdef", &opts(false, false, "a", "z")), "zbcdef");
    }
}
