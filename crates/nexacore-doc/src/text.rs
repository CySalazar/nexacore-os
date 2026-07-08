//! Text layout + hit-testing (WS8-04.4).
//!
//! Selecting text in a rendered page needs the glyph positions, which only the
//! PDF text engine knows. That extraction is library-gated behind
//! [`TextExtractor`]; the resulting [`TextLayout`] is a flat run of positioned
//! glyphs in reading order, over which this module provides caret hit-testing
//! and word/line boundary queries — the host-testable half that drives
//! selection ([`crate::selection`]).

use alloc::{string::String, vec::Vec};

/// An axis-aligned rectangle in page pixels (origin top-left).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    /// Left edge.
    pub x: i32,
    /// Top edge.
    pub y: i32,
    /// Width.
    pub w: u32,
    /// Height.
    pub h: u32,
}

impl Rect {
    /// X of the horizontal centre.
    #[must_use]
    pub const fn center_x(&self) -> i32 {
        self.x + (self.w / 2) as i32
    }

    /// Y of the vertical centre.
    #[must_use]
    pub const fn center_y(&self) -> i32 {
        self.y + (self.h / 2) as i32
    }

    /// Whether `(px, py)` lies inside the rectangle.
    #[must_use]
    pub const fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && px < self.x + self.w as i32 && py >= self.y && py < self.y + self.h as i32
    }
}

/// One glyph with its bounding box in page pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositionedGlyph {
    /// The Unicode scalar this glyph renders.
    pub ch: char,
    /// Bounding box in page pixels.
    pub rect: Rect,
}

/// Why text extraction failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtractError {
    /// The page index does not exist.
    NoSuchPage,
    /// The page has no extractable text layer (e.g. a scanned image).
    NoTextLayer,
}

/// A page's glyphs in reading order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TextLayout {
    /// Positioned glyphs, in reading order.
    pub glyphs: Vec<PositionedGlyph>,
}

impl TextLayout {
    /// Build from a glyph run.
    #[must_use]
    pub fn new(glyphs: Vec<PositionedGlyph>) -> Self {
        Self { glyphs }
    }

    /// Number of glyphs (also the maximum caret position).
    #[must_use]
    pub fn len(&self) -> usize {
        self.glyphs.len()
    }

    /// Whether the page has no glyphs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.glyphs.is_empty()
    }

    /// The full page text in reading order.
    #[must_use]
    pub fn text(&self) -> String {
        self.glyphs.iter().map(|g| g.ch).collect()
    }

    /// Text covered by the caret range `[start, end)` (clamped + ordered).
    #[must_use]
    pub fn range_text(&self, start: usize, end: usize) -> String {
        let lo = start.min(end).min(self.len());
        let hi = start.max(end).min(self.len());
        self.glyphs
            .get(lo..hi)
            .map(|s| s.iter().map(|g| g.ch).collect())
            .unwrap_or_default()
    }

    /// The glyph whose box contains `(px, py)`, if any.
    #[must_use]
    pub fn glyph_at(&self, px: i32, py: i32) -> Option<usize> {
        self.glyphs.iter().position(|g| g.rect.contains(px, py))
    }

    /// The caret position (`0..=len`) nearest `(px, py)`.
    ///
    /// Picks the glyph minimising the squared distance from the point to the
    /// glyph centre, then resolves to the caret before or after that glyph
    /// depending on which horizontal half the point falls in. Empty layouts
    /// return caret 0.
    #[must_use]
    pub fn caret_at(&self, px: i32, py: i32) -> usize {
        let mut best: Option<(usize, i64)> = None;
        for (i, g) in self.glyphs.iter().enumerate() {
            let dx = i64::from(px - g.rect.center_x());
            let dy = i64::from(py - g.rect.center_y());
            let d2 = dx * dx + dy * dy;
            if best.is_none_or(|(_, bd)| d2 < bd) {
                best = Some((i, d2));
            }
        }
        match best {
            None => 0,
            Some((i, _)) => {
                let after = self.glyphs.get(i).is_some_and(|g| px >= g.rect.center_x());
                if after { i + 1 } else { i }
            }
        }
    }

    /// Word boundaries (caret positions) around the glyph at caret `caret`.
    ///
    /// A word is a maximal run of alphanumeric glyphs. If the caret is not on a
    /// word glyph, returns `(caret, caret)` (an empty range).
    #[must_use]
    pub fn word_bounds(&self, caret: usize) -> (usize, usize) {
        let len = self.len();
        if len == 0 {
            return (0, 0);
        }
        // The glyph "under" the caret is the one at `caret` (caret sits to its
        // left); clamp to the last glyph for an end-caret.
        let idx = caret.min(len - 1);
        let is_word = |i: usize| self.glyphs.get(i).is_some_and(|g| g.ch.is_alphanumeric());
        if !is_word(idx) {
            return (caret, caret);
        }
        let mut start = idx;
        while start > 0 && is_word(start - 1) {
            start -= 1;
        }
        let mut end = idx + 1;
        while end < len && is_word(end) {
            end += 1;
        }
        (start, end)
    }

    /// Line boundaries (caret positions) for the line containing the glyph at
    /// caret `caret`. Glyphs are on the same line when their boxes share a
    /// vertical overlap with the anchor glyph.
    #[must_use]
    pub fn line_bounds(&self, caret: usize) -> (usize, usize) {
        let len = self.len();
        if len == 0 {
            return (0, 0);
        }
        let idx = caret.min(len - 1);
        let Some(anchor) = self.glyphs.get(idx) else {
            return (caret, caret);
        };
        let same_line = |i: usize| {
            self.glyphs.get(i).is_some_and(|g| {
                // Vertical overlap between g.rect and anchor.rect.
                let a_top = anchor.rect.y;
                let a_bot = anchor.rect.y + anchor.rect.h as i32;
                let g_top = g.rect.y;
                let g_bot = g.rect.y + g.rect.h as i32;
                g_top < a_bot && a_top < g_bot
            })
        };
        let mut start = idx;
        while start > 0 && same_line(start - 1) {
            start -= 1;
        }
        let mut end = idx + 1;
        while end < len && same_line(end) {
            end += 1;
        }
        (start, end)
    }
}

/// The library-gated seam that extracts a page's text layout from the document
/// bytes. The real implementation drives the vetted PDF text engine; tests use
/// a mock.
pub trait TextExtractor {
    /// Extract the [`TextLayout`] of page `index` from `doc`.
    ///
    /// # Errors
    ///
    /// [`ExtractError`] when the page does not exist or has no text layer.
    fn extract(&self, doc: &[u8], index: usize) -> Result<TextLayout, ExtractError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lay out "Hi  yo" as two words on one row of 10×16 glyph cells, with a
    /// double space (gap) between them. Caret positions: H0 i1 (sp) (sp) y4 o5.
    fn two_words() -> TextLayout {
        let cell = |i: i32, ch: char| PositionedGlyph {
            ch,
            rect: Rect {
                x: i * 10,
                y: 0,
                w: 10,
                h: 16,
            },
        };
        TextLayout::new(alloc::vec![
            cell(0, 'H'),
            cell(1, 'i'),
            cell(2, ' '),
            cell(3, ' '),
            cell(4, 'y'),
            cell(5, 'o'),
        ])
    }

    #[test]
    fn text_and_range_text() {
        let l = two_words();
        assert_eq!(l.text(), "Hi  yo");
        assert_eq!(l.range_text(0, 2), "Hi");
        assert_eq!(l.range_text(4, 6), "yo");
        // Reversed + out-of-range are normalised + clamped.
        assert_eq!(l.range_text(6, 4), "yo");
        assert_eq!(l.range_text(4, 99), "yo");
    }

    #[test]
    fn caret_at_resolves_to_nearest_side() {
        let l = two_words();
        // Far left → caret 0.
        assert_eq!(l.caret_at(-100, 8), 0);
        // Left half of glyph 0 (centre x = 5) → caret 0.
        assert_eq!(l.caret_at(2, 8), 0);
        // Right half of glyph 0 → caret 1.
        assert_eq!(l.caret_at(8, 8), 1);
        // Far right → caret after last glyph (6).
        assert_eq!(l.caret_at(1000, 8), 6);
    }

    #[test]
    fn glyph_at_is_box_exact() {
        let l = two_words();
        assert_eq!(l.glyph_at(5, 8), Some(0));
        assert_eq!(l.glyph_at(45, 8), Some(4));
        assert_eq!(l.glyph_at(5, 100), None); // below the row
    }

    #[test]
    fn word_bounds_span_alphanumeric_run() {
        let l = two_words();
        // Caret 0 is on 'H' → word [0,2) = "Hi".
        assert_eq!(l.word_bounds(0), (0, 2));
        // Caret 1 is on 'i' → still "Hi".
        assert_eq!(l.word_bounds(1), (0, 2));
        // Caret 2 is on a space → empty range at the caret.
        assert_eq!(l.word_bounds(2), (2, 2));
        // Caret 4 is on 'y' → "yo".
        assert_eq!(l.word_bounds(4), (4, 6));
        assert_eq!(l.range_text(l.word_bounds(4).0, l.word_bounds(4).1), "yo");
    }

    #[test]
    fn line_bounds_group_by_vertical_overlap() {
        // Two rows: row0 y=0..16, row1 y=20..36.
        let g = |x: i32, y: i32, ch: char| PositionedGlyph {
            ch,
            rect: Rect { x, y, w: 10, h: 16 },
        };
        let l = TextLayout::new(alloc::vec![
            g(0, 0, 'a'),
            g(10, 0, 'b'),
            g(0, 20, 'c'),
            g(10, 20, 'd'),
        ]);
        assert_eq!(l.line_bounds(0), (0, 2)); // "ab"
        assert_eq!(l.line_bounds(2), (2, 4)); // "cd"
    }

    struct MockExtractor;
    impl TextExtractor for MockExtractor {
        fn extract(&self, doc: &[u8], index: usize) -> Result<TextLayout, ExtractError> {
            if index >= 1 {
                return Err(ExtractError::NoSuchPage);
            }
            if doc.is_empty() {
                return Err(ExtractError::NoTextLayer);
            }
            Ok(two_words())
        }
    }

    #[test]
    fn extractor_seam_round_trips() {
        assert_eq!(MockExtractor.extract(b"pdf", 0).unwrap().text(), "Hi  yo");
        assert_eq!(
            MockExtractor.extract(b"pdf", 1),
            Err(ExtractError::NoSuchPage)
        );
        assert_eq!(
            MockExtractor.extract(b"", 0),
            Err(ExtractError::NoTextLayer)
        );
    }
}
