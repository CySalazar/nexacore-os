//! Find & replace (WS8-08.5).
//!
//! [`find_all`] and [`replace_all`] work against any [`Matcher`]. The bundled
//! [`LiteralMatcher`] does literal / ASCII-case-insensitive / whole-word
//! matching; a regex engine plugs in behind the same trait (the engine is
//! library-gated — the workspace has no `no_std` regex crate vetted yet).

use alloc::{string::String, vec::Vec};

/// A byte range `[start, end)` of a match in the haystack.
pub type Match = (usize, usize);

/// Finds the next match at or after a byte offset.
pub trait Matcher {
    /// The next match starting at or after `start`, or `None`. Returned offsets
    /// must be UTF-8 character boundaries.
    fn find_from(&self, haystack: &str, start: usize) -> Option<Match>;
}

/// A literal substring matcher with optional ASCII case-insensitivity and
/// whole-word constraint.
#[derive(Debug, Clone)]
pub struct LiteralMatcher {
    needle: String,
    case_insensitive: bool,
    whole_word: bool,
}

impl LiteralMatcher {
    /// A case-sensitive literal matcher for `needle`.
    #[must_use]
    pub fn new(needle: &str) -> Self {
        Self {
            needle: String::from(needle),
            case_insensitive: false,
            whole_word: false,
        }
    }

    /// Set ASCII case-insensitivity.
    #[must_use]
    pub fn case_insensitive(mut self, on: bool) -> Self {
        self.case_insensitive = on;
        self
    }

    /// Require the match to be bounded by non-word characters.
    #[must_use]
    pub fn whole_word(mut self, on: bool) -> Self {
        self.whole_word = on;
        self
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether `[start, end)` is bounded by non-word bytes (or the text edges).
fn is_whole_word(hay: &[u8], start: usize, end: usize) -> bool {
    let before_ok = start == 0 || hay.get(start - 1).is_none_or(|&b| !is_word_byte(b));
    let after_ok = hay.get(end).is_none_or(|&b| !is_word_byte(b));
    before_ok && after_ok
}

impl Matcher for LiteralMatcher {
    fn find_from(&self, haystack: &str, start: usize) -> Option<Match> {
        let hay = haystack.as_bytes();
        let needle = self.needle.as_bytes();
        if needle.is_empty() || start > hay.len() {
            return None;
        }
        let mut i = start;
        while i + needle.len() <= hay.len() {
            let end = i + needle.len();
            // Only consider matches on character boundaries so replacements
            // never split a UTF-8 sequence.
            if haystack.is_char_boundary(i) && haystack.is_char_boundary(end) {
                let window = hay.get(i..end).unwrap_or(&[]);
                let hit = if self.case_insensitive {
                    window.eq_ignore_ascii_case(needle)
                } else {
                    window == needle
                };
                if hit && (!self.whole_word || is_whole_word(hay, i, end)) {
                    return Some((i, end));
                }
            }
            i += 1;
        }
        None
    }
}

/// All non-overlapping matches of `matcher` in `haystack`, left to right.
#[must_use]
pub fn find_all<M: Matcher>(haystack: &str, matcher: &M) -> Vec<Match> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some((s, e)) = matcher.find_from(haystack, pos) {
        out.push((s, e));
        // Advance past the match; guard against a zero-width match looping.
        pos = if e > s { e } else { e + 1 };
    }
    out
}

/// Replace every non-overlapping match with `replacement`.
#[must_use]
pub fn replace_all<M: Matcher>(haystack: &str, matcher: &M, replacement: &str) -> String {
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0usize;
    for (s, e) in find_all(haystack, matcher) {
        if s < last {
            continue; // defensive: skip overlaps
        }
        out.push_str(haystack.get(last..s).unwrap_or(""));
        out.push_str(replacement);
        last = e;
    }
    out.push_str(haystack.get(last..).unwrap_or(""));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_finds_all_occurrences() {
        let m = LiteralMatcher::new("ab");
        assert_eq!(find_all("abXabYab", &m), [(0, 2), (3, 5), (6, 8)]);
        assert!(find_all("nope", &m).is_empty());
    }

    #[test]
    fn case_insensitive_matches() {
        let m = LiteralMatcher::new("todo").case_insensitive(true);
        assert_eq!(find_all("TODO todo ToDo", &m), [(0, 4), (5, 9), (10, 14)]);
        // Case-sensitive default does not.
        assert!(find_all("TODO", &LiteralMatcher::new("todo")).is_empty());
    }

    #[test]
    fn whole_word_respects_boundaries() {
        let m = LiteralMatcher::new("cat").whole_word(true);
        // "cat" matches standalone but not inside "category" or "scat".
        assert_eq!(find_all("cat category scat cat.", &m), [(0, 3), (18, 21)]);
    }

    #[test]
    fn replace_all_substitutes() {
        let m = LiteralMatcher::new("foo");
        assert_eq!(replace_all("foo bar foo", &m, "baz"), "baz bar baz");
        // No match leaves the text unchanged.
        assert_eq!(replace_all("bar", &m, "baz"), "bar");
    }

    #[test]
    fn matching_is_utf8_safe() {
        // The needle bytes must land on char boundaries; a search that would
        // split "é" (2 bytes) finds nothing spurious.
        let m = LiteralMatcher::new("\u{00A9}"); // © is 0xC2 0xA9
        let hay = "a\u{00A9}b"; // a © b
        assert_eq!(find_all(hay, &m), [(1, 3)]);
        assert_eq!(replace_all(hay, &m, "(c)"), "a(c)b");
    }
}
