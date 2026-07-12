//! Client-side text editing: cut / copy / paste against the clipboard
//! (WS7-08.3).
//!
//! [`crate::clipboard`] is the *service* — it stores offers and serves per-MIME
//! requests. This module is the *client* side a text widget uses: a
//! [`TextBuffer`] holds editable content with a caret and an optional selection,
//! and [`TextBuffer::copy`] / [`TextBuffer::cut`] / [`TextBuffer::paste`] move
//! text between the buffer and a [`ClipboardService`]. Copy offers the selected
//! text; cut offers it and removes it; paste replaces the selection (or inserts
//! at the caret) with the clipboard's text. Pure logic, `no_std + alloc` —
//! host-testable with no widget or IPC dependency.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::clipboard::{ClipboardContent, ClipboardService, Selection};

/// An editable text buffer with a caret and an optional selection.
///
/// Positions are **character** indices (not byte offsets), so multi-byte UTF-8
/// graphemes behave correctly. The caret sits in `[0, len]`; a selection spans
/// the ordered range between the caret and the anchor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextBuffer {
    chars: Vec<char>,
    cursor: usize,
    anchor: Option<usize>,
}

impl TextBuffer {
    /// An empty buffer with the caret at the start.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A buffer initialised with `text`, caret at the end, no selection.
    #[must_use]
    pub fn from_text(text: &str) -> Self {
        let chars: Vec<char> = text.chars().collect();
        let cursor = chars.len();
        Self {
            chars,
            cursor,
            anchor: None,
        }
    }

    /// The full content as a `String`.
    #[must_use]
    pub fn text(&self) -> String {
        self.chars.iter().collect()
    }

    /// Length in characters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// Caret position (character index).
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Move the caret to `pos` (clamped) and drop any selection.
    pub fn set_cursor(&mut self, pos: usize) {
        self.cursor = pos.min(self.chars.len());
        self.anchor = None;
    }

    /// Select the range `[start, end)` (order-independent); the caret ends at
    /// `end`. Both bounds are clamped to the buffer length.
    pub fn select_range(&mut self, start: usize, end: usize) {
        let len = self.chars.len();
        self.anchor = Some(start.min(len));
        self.cursor = end.min(len);
    }

    /// The ordered selection bounds `(lo, hi)`, or `None` when nothing is
    /// selected (no anchor, or an empty range).
    #[must_use]
    pub fn selection(&self) -> Option<(usize, usize)> {
        let anchor = self.anchor?;
        let (lo, hi) = if anchor <= self.cursor {
            (anchor, self.cursor)
        } else {
            (self.cursor, anchor)
        };
        (lo < hi).then_some((lo, hi))
    }

    /// The selected text, if any.
    #[must_use]
    pub fn selected_text(&self) -> Option<String> {
        let (lo, hi) = self.selection()?;
        Some(self.chars.get(lo..hi)?.iter().collect())
    }

    /// Delete the current selection, placing the caret at its start. Returns
    /// `true` if anything was removed.
    pub fn delete_selection(&mut self) -> bool {
        let Some((lo, hi)) = self.selection() else {
            return false;
        };
        self.chars.drain(lo..hi);
        self.cursor = lo;
        self.anchor = None;
        true
    }

    /// Insert `text` at the caret, replacing any active selection first. The
    /// caret ends just after the inserted text.
    pub fn insert_str(&mut self, text: &str) {
        self.delete_selection();
        let at = self.cursor.min(self.chars.len());
        let inserted: Vec<char> = text.chars().collect();
        let n = inserted.len();
        self.chars.splice(at..at, inserted);
        self.cursor = at + n;
        self.anchor = None;
    }

    // --- Clipboard client operations (WS7-08.3) ------------------------------

    /// Copy the selection onto `selection` of `svc`. Returns `true` if there was
    /// a selection to copy (the buffer is left unchanged).
    pub fn copy(&self, svc: &mut ClipboardService, selection: Selection) -> bool {
        let Some(text) = self.selected_text() else {
            return false;
        };
        svc.offer(selection, ClipboardContent::text(&text));
        true
    }

    /// Cut the selection: copy it onto `svc`, then delete it from the buffer.
    /// Returns `true` if there was a selection.
    pub fn cut(&mut self, svc: &mut ClipboardService, selection: Selection) -> bool {
        if !self.copy(svc, selection) {
            return false;
        }
        self.delete_selection();
        true
    }

    /// Paste the `text/plain` content of `selection` at the caret, replacing any
    /// active selection. Returns `true` if the clipboard held text.
    pub fn paste(&mut self, svc: &ClipboardService, selection: Selection) -> bool {
        let Some(text) = svc.request_text(selection) else {
            return false;
        };
        let owned = text.to_string();
        self.insert_str(&owned);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_text_places_caret_at_end() {
        let buf = TextBuffer::from_text("hello");
        assert_eq!(buf.text(), "hello");
        assert_eq!(buf.cursor(), 5);
        assert!(buf.selection().is_none());
    }

    #[test]
    fn select_range_is_order_independent() {
        let mut buf = TextBuffer::from_text("hello world");
        buf.select_range(6, 11);
        assert_eq!(buf.selected_text().as_deref(), Some("world"));
        buf.select_range(11, 6); // reversed
        assert_eq!(buf.selected_text().as_deref(), Some("world"));
    }

    #[test]
    fn copy_offers_selection_without_mutating_buffer() {
        let mut svc = ClipboardService::new();
        let mut buf = TextBuffer::from_text("hello world");
        buf.select_range(0, 5);
        assert!(buf.copy(&mut svc, Selection::Clipboard));
        assert_eq!(svc.request_text(Selection::Clipboard), Some("hello"));
        assert_eq!(buf.text(), "hello world", "copy does not change the buffer");
    }

    #[test]
    fn copy_without_selection_is_noop() {
        let mut svc = ClipboardService::new();
        let buf = TextBuffer::from_text("hello");
        assert!(!buf.copy(&mut svc, Selection::Clipboard));
        assert!(!svc.has_content(Selection::Clipboard));
    }

    #[test]
    fn cut_copies_then_removes_selection() {
        let mut svc = ClipboardService::new();
        let mut buf = TextBuffer::from_text("hello world");
        buf.select_range(5, 11); // " world"
        assert!(buf.cut(&mut svc, Selection::Clipboard));
        assert_eq!(svc.request_text(Selection::Clipboard), Some(" world"));
        assert_eq!(buf.text(), "hello");
        assert_eq!(buf.cursor(), 5);
        assert!(buf.selection().is_none());
    }

    #[test]
    fn paste_inserts_at_caret() {
        let mut svc = ClipboardService::new();
        svc.offer(Selection::Clipboard, ClipboardContent::text("XYZ"));
        let mut buf = TextBuffer::from_text("hello");
        buf.set_cursor(2);
        assert!(buf.paste(&svc, Selection::Clipboard));
        assert_eq!(buf.text(), "heXYZllo");
        assert_eq!(buf.cursor(), 5);
    }

    #[test]
    fn paste_replaces_active_selection() {
        let mut svc = ClipboardService::new();
        svc.offer(Selection::Clipboard, ClipboardContent::text("brave"));
        let mut buf = TextBuffer::from_text("hello world");
        buf.select_range(0, 5); // "hello"
        assert!(buf.paste(&svc, Selection::Clipboard));
        assert_eq!(buf.text(), "brave world");
    }

    #[test]
    fn paste_empty_clipboard_is_noop() {
        let svc = ClipboardService::new();
        let mut buf = TextBuffer::from_text("hi");
        assert!(!buf.paste(&svc, Selection::Clipboard));
        assert_eq!(buf.text(), "hi");
    }

    #[test]
    fn copy_paste_roundtrip_across_primary_and_clipboard() {
        let mut svc = ClipboardService::new();
        let mut source = TextBuffer::from_text("copy me");
        source.select_range(0, 4); // "copy"
        source.copy(&mut svc, Selection::Primary);

        let mut dest = TextBuffer::from_text("");
        assert!(dest.paste(&svc, Selection::Primary));
        assert_eq!(dest.text(), "copy");
        // The explicit clipboard was never touched.
        assert!(!dest.paste(&svc, Selection::Clipboard));
    }

    #[test]
    fn multibyte_selection_uses_char_indices() {
        let mut svc = ClipboardService::new();
        let mut buf = TextBuffer::from_text("café☕end");
        // chars: c a f é ☕ e n d  → select "é☕" = indices 3..5
        buf.select_range(3, 5);
        assert_eq!(buf.selected_text().as_deref(), Some("é☕"));
        assert!(buf.cut(&mut svc, Selection::Clipboard));
        assert_eq!(buf.text(), "cafend");
        assert_eq!(svc.request_text(Selection::Clipboard), Some("é☕"));
    }

    #[test]
    fn insert_str_replaces_selection() {
        let mut buf = TextBuffer::from_text("hello");
        buf.select_range(0, 5);
        buf.insert_str("bye");
        assert_eq!(buf.text(), "bye");
        assert_eq!(buf.cursor(), 3);
    }
}
