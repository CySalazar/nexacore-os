//! Text selection + clipboard copy (WS8-04.5).
//!
//! A [`Selection`] is a pair of caret positions (anchor + focus) into a
//! [`crate::text::TextLayout`]. Dragging moves `focus`; the selected text is
//! the glyph run between the ordered endpoints. Copying goes through the
//! library-gated [`Clipboard`] seam so the host tests never touch a real
//! system clipboard.

use alloc::string::String;

use crate::text::TextLayout;

/// A text selection over caret positions (`0..=layout.len()`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    /// Where the selection started (fixed end).
    pub anchor: usize,
    /// Where the selection currently ends (moving end).
    pub focus: usize,
}

impl Selection {
    /// A collapsed selection (caret) at `pos`.
    #[must_use]
    pub const fn caret(pos: usize) -> Self {
        Self {
            anchor: pos,
            focus: pos,
        }
    }

    /// Start a selection anchored at `pos`.
    #[must_use]
    pub const fn new(anchor: usize, focus: usize) -> Self {
        Self { anchor, focus }
    }

    /// Move the focus end (e.g. while dragging), keeping the anchor.
    pub fn extend_to(&mut self, focus: usize) {
        self.focus = focus;
    }

    /// The ordered `(start, end)` caret range.
    #[must_use]
    pub fn range(&self) -> (usize, usize) {
        (self.anchor.min(self.focus), self.anchor.max(self.focus))
    }

    /// Whether nothing is selected (anchor == focus).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchor == self.focus
    }

    /// Number of glyphs selected.
    #[must_use]
    pub fn len(&self) -> usize {
        let (s, e) = self.range();
        e - s
    }

    /// Expand the selection to whole words at both ends (double-click + drag).
    pub fn snap_to_words(&mut self, layout: &TextLayout) {
        let (s, e) = self.range();
        let (ws, _) = layout.word_bounds(s);
        // For the end, use the word that the caret just before `e` belongs to.
        let end_probe = e.saturating_sub(1);
        let (_, we) = layout.word_bounds(end_probe);
        self.anchor = ws;
        self.focus = we.max(ws);
    }

    /// The selected text from `layout`.
    #[must_use]
    pub fn selected_text(&self, layout: &TextLayout) -> String {
        let (s, e) = self.range();
        layout.range_text(s, e)
    }
}

/// The clipboard seam. The real desktop clipboard lives in `nexacore-ui`; tests
/// use an in-memory implementation.
pub trait Clipboard {
    /// Replace the clipboard contents with `text`.
    fn set_text(&mut self, text: &str);
}

/// Copy the current selection's text into `clipboard`. Returns the copied
/// string (empty if the selection is collapsed).
pub fn copy_selection<C: Clipboard>(
    selection: &Selection,
    layout: &TextLayout,
    clipboard: &mut C,
) -> String {
    let text = selection.selected_text(layout);
    clipboard.set_text(&text);
    text
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::text::{PositionedGlyph, Rect, TextLayout};

    fn layout() -> TextLayout {
        let cell = |i: i32, ch: char| PositionedGlyph {
            ch,
            rect: Rect {
                x: i * 10,
                y: 0,
                w: 10,
                h: 16,
            },
        };
        // "Hello world"
        TextLayout::new(
            "Hello world"
                .chars()
                .enumerate()
                .map(|(i, c)| cell(i as i32, c))
                .collect(),
        )
    }

    struct MemClipboard {
        contents: String,
    }
    impl Clipboard for MemClipboard {
        fn set_text(&mut self, text: &str) {
            self.contents = text.to_string();
        }
    }

    #[test]
    fn range_is_ordered_regardless_of_drag_direction() {
        let mut s = Selection::new(7, 2);
        assert_eq!(s.range(), (2, 7));
        assert_eq!(s.len(), 5);
        s.extend_to(11);
        assert_eq!(s.range(), (7, 11));
    }

    #[test]
    fn selected_text_matches_range() {
        let l = layout();
        let s = Selection::new(0, 5);
        assert_eq!(s.selected_text(&l), "Hello");
        let s2 = Selection::new(6, 11);
        assert_eq!(s2.selected_text(&l), "world");
    }

    #[test]
    fn snap_to_words_expands_partial_selection() {
        let l = layout();
        // Select "ell" (carets 1..4) → snaps to "Hello" (0..5).
        let mut s = Selection::new(1, 4);
        s.snap_to_words(&l);
        assert_eq!(s.range(), (0, 5));
        assert_eq!(s.selected_text(&l), "Hello");
    }

    #[test]
    fn copy_writes_selection_to_clipboard() {
        let l = layout();
        let s = Selection::new(6, 11);
        let mut clip = MemClipboard {
            contents: String::new(),
        };
        let copied = copy_selection(&s, &l, &mut clip);
        assert_eq!(copied, "world");
        assert_eq!(clip.contents, "world");
    }

    #[test]
    fn collapsed_selection_copies_empty() {
        let l = layout();
        let s = Selection::caret(3);
        assert!(s.is_empty());
        let mut clip = MemClipboard {
            contents: "stale".to_string(),
        };
        assert_eq!(copy_selection(&s, &l, &mut clip), "");
        assert_eq!(clip.contents, "");
    }
}
