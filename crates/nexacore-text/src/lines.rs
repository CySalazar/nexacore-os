//! Line index for gutter line numbers and a minimap sampler (WS8-08.7).

use alloc::vec::Vec;

/// A map from line number to byte offset, over a snapshot of the document.
///
/// Line breaks are `\n`, `\r\n`, or a lone `\r`. A trailing line break yields a
/// final empty line, as editors display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineIndex {
    starts: Vec<usize>,
    len: usize,
}

impl LineIndex {
    /// Build the index for `text`.
    #[must_use]
    pub fn build(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut starts = Vec::new();
        starts.push(0);
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes.get(i) {
                Some(b'\n') => {
                    i += 1;
                    starts.push(i);
                }
                Some(b'\r') => {
                    i += if bytes.get(i + 1) == Some(&b'\n') {
                        2
                    } else {
                        1
                    };
                    starts.push(i);
                }
                _ => i += 1,
            }
        }
        Self {
            starts,
            len: bytes.len(),
        }
    }

    /// The number of lines.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.starts.len()
    }

    /// The byte offset where line `n` (0-based) starts.
    #[must_use]
    pub fn line_start(&self, n: usize) -> Option<usize> {
        self.starts.get(n).copied()
    }

    /// The `[start, end)` byte range of line `n`, including its terminator.
    #[must_use]
    pub fn line_range(&self, n: usize) -> Option<(usize, usize)> {
        let start = self.line_start(n)?;
        let end = self.starts.get(n + 1).copied().unwrap_or(self.len);
        Some((start, end))
    }

    /// The line number containing byte `offset` (clamped to the last line).
    #[must_use]
    pub fn line_of_offset(&self, offset: usize) -> usize {
        // The largest line whose start is <= offset.
        match self.starts.binary_search(&offset) {
            Ok(exact) => exact,
            Err(next) => next.saturating_sub(1),
        }
    }

    /// Sample up to `target_rows` evenly spaced line numbers for a minimap of
    /// that height. Fewer lines than rows returns them all.
    #[must_use]
    #[allow(
        clippy::integer_division,
        reason = "even minimap sampling maps row r to line r*n/target"
    )]
    pub fn minimap_rows(&self, target_rows: usize) -> Vec<usize> {
        let n = self.line_count();
        if target_rows == 0 || n == 0 {
            return Vec::new();
        }
        if n <= target_rows {
            return (0..n).collect();
        }
        (0..target_rows).map(|r| r * n / target_rows).collect()
    }
}

/// Free-function convenience wrapper for [`LineIndex::minimap_rows`].
#[must_use]
pub fn minimap_rows(text: &str, target_rows: usize) -> Vec<usize> {
    LineIndex::build(text).minimap_rows(target_rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_lines_and_ranges() {
        let idx = LineIndex::build("one\ntwo\nthree");
        assert_eq!(idx.line_count(), 3);
        assert_eq!(idx.line_start(1), Some(4));
        assert_eq!(idx.line_range(0), Some((0, 4))); // "one\n"
        assert_eq!(idx.line_range(2), Some((8, 13))); // "three"
        assert_eq!(idx.line_range(9), None);
    }

    #[test]
    fn trailing_newline_makes_an_empty_final_line() {
        let idx = LineIndex::build("a\n");
        assert_eq!(idx.line_count(), 2);
        assert_eq!(idx.line_range(1), Some((2, 2)));
    }

    #[test]
    fn handles_crlf_and_lone_cr() {
        let idx = LineIndex::build("a\r\nb\rc");
        assert_eq!(idx.line_count(), 3);
        assert_eq!(idx.line_start(1), Some(3)); // after "a\r\n"
        assert_eq!(idx.line_start(2), Some(5)); // after "b\r"
    }

    #[test]
    fn maps_offset_to_line() {
        let idx = LineIndex::build("one\ntwo\nthree");
        assert_eq!(idx.line_of_offset(0), 0);
        assert_eq!(idx.line_of_offset(3), 0);
        assert_eq!(idx.line_of_offset(4), 1);
        assert_eq!(idx.line_of_offset(12), 2);
    }

    #[test]
    fn minimap_samples_evenly_and_clamps() {
        // 10 lines into 4 rows: evenly spaced starts.
        let text = "l0\nl1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9";
        let rows = minimap_rows(text, 4);
        assert_eq!(rows, [0, 2, 5, 7]);
        // Fewer lines than rows returns them all.
        assert_eq!(minimap_rows("a\nb", 8), [0, 1]);
        assert!(minimap_rows("", 0).is_empty());
    }
}
