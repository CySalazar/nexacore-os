//! Smart clipboard copy / cut / paste (WS8-08.10).
//!
//! Editor-side cut / copy / paste over a selection, integrating a system
//! clipboard (WS7-08). Because `nexacore-text` stays dependency-free, the system
//! clipboard is reached through a *local* seam, the [`Clipboard`] trait: the
//! production implementation is wired elsewhere (to the WS7-08 clipboard
//! service), while host tests pass an in-memory double.
//!
//! All three operations validate the selection against the text (fail-closed:
//! out-of-range or non-boundary selections return a typed [`ClipboardError`],
//! never a panic or an index) and — like [`crate::ai_actions`] and
//! [`crate::snippet`] — compute a [`Replacement`] the caller splices into the
//! [`crate::buffer::PieceTable`]. They never mutate the buffer themselves.
//!
//! - [`copy`] writes the selected substring to the clipboard.
//! - [`cut`] writes the selection to the clipboard and returns a [`Replacement`]
//!   that deletes it.
//! - [`paste`] returns a [`Replacement`] that overwrites the selection (or, when
//!   the selection is empty, inserts at the caret) with the clipboard contents.
//!
//! ## Smart rule: trailing-newline trim on paste
//!
//! [`paste`] applies one documented "smart" transform: it strips **at most one**
//! trailing line terminator (`\r\n`, `\n`, or `\r`) from the clipboard contents
//! before inserting. Copying a whole line (e.g. via a line-select shortcut)
//! captures its terminating newline; pasting that verbatim mid-line would shove
//! the following text onto a new line. Trimming a single trailing break makes
//! "copy a line, paste it inline" behave the way users expect, while leaving
//! interior newlines — and any second trailing blank line — intact. Copy and cut
//! store the selection verbatim; the smart rule is a paste-time concern only.

use alloc::string::String;

pub use crate::ai_actions::Replacement;

/// A system clipboard the editor can read from and write to.
///
/// This is the local, dependency-free seam. The real implementation is injected
/// by higher layers (which own the WS7-08 clipboard service); host tests pass an
/// in-memory double. `write` takes `&self` because a clipboard is shared,
/// interior-mutable state.
pub trait Clipboard {
    /// The current clipboard contents, or `None` if the clipboard is empty.
    fn read(&self) -> Option<String>;
    /// Replace the clipboard contents with `text`.
    fn write(&self, text: &str);
}

/// Why a clipboard operation could not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardError {
    /// The selection was empty, so there is nothing to copy or cut.
    EmptySelection,
    /// The selection range was out of bounds or not on UTF-8 char boundaries.
    OutOfRange,
    /// A paste was requested but the clipboard was empty.
    EmptyClipboard,
}

/// Validate `[start, end)` against `text` and return the slice it names.
///
/// The empty range is *allowed* here (it is a valid caret position); callers
/// that require a non-empty selection check for that themselves.
fn checked_slice(text: &str, start: usize, end: usize) -> Result<&str, ClipboardError> {
    if start > end || end > text.len() {
        return Err(ClipboardError::OutOfRange);
    }
    if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return Err(ClipboardError::OutOfRange);
    }
    text.get(start..end).ok_or(ClipboardError::OutOfRange)
}

/// Strip at most one trailing line terminator (`\r\n`, `\n`, or `\r`).
fn trim_one_trailing_newline(text: &str) -> &str {
    // `\r\n` is checked first so the pair is treated as a single terminator.
    text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .or_else(|| text.strip_suffix('\r'))
        .unwrap_or(text)
}

/// Write the selected substring of `text` to `clipboard`.
///
/// The buffer is not touched. The `selection` is a `[start, end)` byte range.
///
/// # Errors
/// - [`ClipboardError::OutOfRange`] if `start > end`, `end` exceeds `text`, or
///   either endpoint is not a UTF-8 character boundary.
/// - [`ClipboardError::EmptySelection`] if the range is valid but empty.
pub fn copy<C: Clipboard + ?Sized>(
    clipboard: &C,
    text: &str,
    selection: (usize, usize),
) -> Result<(), ClipboardError> {
    let (start, end) = selection;
    let slice = checked_slice(text, start, end)?;
    if slice.is_empty() {
        return Err(ClipboardError::EmptySelection);
    }
    clipboard.write(slice);
    Ok(())
}

/// Write the selection to `clipboard` and return the [`Replacement`] that
/// deletes it.
///
/// The buffer is not touched; the returned replacement is empty text over the
/// selection range, which the caller applies to remove the cut text.
///
/// # Errors
/// - [`ClipboardError::OutOfRange`] if `start > end`, `end` exceeds `text`, or
///   either endpoint is not a UTF-8 character boundary.
/// - [`ClipboardError::EmptySelection`] if the range is valid but empty.
pub fn cut<C: Clipboard + ?Sized>(
    clipboard: &C,
    text: &str,
    selection: (usize, usize),
) -> Result<Replacement, ClipboardError> {
    let (start, end) = selection;
    let slice = checked_slice(text, start, end)?;
    if slice.is_empty() {
        return Err(ClipboardError::EmptySelection);
    }
    clipboard.write(slice);
    Ok(Replacement {
        text: String::new(),
        range: (start, end),
    })
}

/// Return the [`Replacement`] that pastes the clipboard contents over the
/// selection (or inserts them at the caret when the selection is empty).
///
/// The buffer is not touched. The clipboard contents are passed through the
/// smart trailing-newline trim documented on this module before being placed
/// into the replacement. An empty selection is a valid insertion point, so it is
/// *not* rejected here.
///
/// # Errors
/// - [`ClipboardError::OutOfRange`] if `start > end`, `end` exceeds `text`, or
///   either endpoint is not a UTF-8 character boundary.
/// - [`ClipboardError::EmptyClipboard`] if the clipboard holds no text.
pub fn paste<C: Clipboard + ?Sized>(
    clipboard: &C,
    text: &str,
    selection: (usize, usize),
) -> Result<Replacement, ClipboardError> {
    let (start, end) = selection;
    // Validate the target range even though an empty selection is allowed.
    let _ = checked_slice(text, start, end)?;
    let contents = clipboard.read().ok_or(ClipboardError::EmptyClipboard)?;
    let trimmed = trim_one_trailing_newline(&contents);
    Ok(Replacement {
        text: String::from(trimmed),
        range: (start, end),
    })
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use core::cell::RefCell;

    use super::*;

    /// An in-memory clipboard double with interior mutability.
    struct MemClipboard {
        slot: RefCell<Option<String>>,
    }

    impl MemClipboard {
        fn empty() -> Self {
            Self {
                slot: RefCell::new(None),
            }
        }

        fn with(text: &str) -> Self {
            Self {
                slot: RefCell::new(Some(text.to_string())),
            }
        }

        fn contents(&self) -> Option<String> {
            self.slot.borrow().clone()
        }
    }

    impl Clipboard for MemClipboard {
        fn read(&self) -> Option<String> {
            self.slot.borrow().clone()
        }

        fn write(&self, text: &str) {
            *self.slot.borrow_mut() = Some(text.to_string());
        }
    }

    #[test]
    fn copy_writes_the_selection() {
        let cb = MemClipboard::empty();
        copy(&cb, "hello world", (6, 11)).unwrap();
        assert_eq!(cb.contents(), Some("world".to_string()));
    }

    #[test]
    fn copy_empty_selection_is_rejected() {
        let cb = MemClipboard::empty();
        let err = copy(&cb, "hello", (2, 2)).unwrap_err();
        assert_eq!(err, ClipboardError::EmptySelection);
        assert_eq!(cb.contents(), None);
    }

    #[test]
    fn copy_out_of_range_is_rejected() {
        let cb = MemClipboard::empty();
        assert_eq!(
            copy(&cb, "hello", (0, 99)).unwrap_err(),
            ClipboardError::OutOfRange
        );
        assert_eq!(
            copy(&cb, "hello", (4, 1)).unwrap_err(),
            ClipboardError::OutOfRange
        );
    }

    #[test]
    fn copy_respects_char_boundaries() {
        let cb = MemClipboard::empty();
        // "café" — offset 4 splits the two-byte 'é' (3..5).
        let err = copy(&cb, "café", (0, 4)).unwrap_err();
        assert_eq!(err, ClipboardError::OutOfRange);
        // A boundary-aligned multi-byte selection copies fine.
        copy(&cb, "café", (0, 5)).unwrap();
        assert_eq!(cb.contents(), Some("café".to_string()));
    }

    #[test]
    fn cut_writes_and_returns_deleting_replacement() {
        let cb = MemClipboard::empty();
        let repl = cut(&cb, "hello world", (0, 6)).unwrap();
        assert_eq!(cb.contents(), Some("hello ".to_string()));
        assert_eq!(repl.text, "");
        assert_eq!(repl.range, (0, 6));
    }

    #[test]
    fn cut_empty_selection_is_rejected() {
        let cb = MemClipboard::empty();
        let err = cut(&cb, "hello", (3, 3)).unwrap_err();
        assert_eq!(err, ClipboardError::EmptySelection);
        assert_eq!(cb.contents(), None);
    }

    #[test]
    fn paste_overwrites_selection() {
        let cb = MemClipboard::with("NEW");
        let repl = paste(&cb, "hello world", (0, 5)).unwrap();
        assert_eq!(repl.text, "NEW");
        assert_eq!(repl.range, (0, 5));
    }

    #[test]
    fn paste_into_empty_selection_is_an_insertion() {
        let cb = MemClipboard::with("X");
        let repl = paste(&cb, "ab", (1, 1)).unwrap();
        assert_eq!(repl.text, "X");
        assert_eq!(repl.range, (1, 1));
    }

    #[test]
    fn paste_from_empty_clipboard_is_rejected() {
        let cb = MemClipboard::empty();
        let err = paste(&cb, "hello", (0, 0)).unwrap_err();
        assert_eq!(err, ClipboardError::EmptyClipboard);
    }

    #[test]
    fn paste_out_of_range_is_rejected() {
        let cb = MemClipboard::with("X");
        assert_eq!(
            paste(&cb, "hello", (0, 99)).unwrap_err(),
            ClipboardError::OutOfRange
        );
    }

    #[test]
    fn smart_paste_trims_one_trailing_newline() {
        // A single "\n" is trimmed.
        let cb = MemClipboard::with("line\n");
        assert_eq!(paste(&cb, "", (0, 0)).unwrap().text, "line");
        // A "\r\n" pair is trimmed as one terminator.
        let cb = MemClipboard::with("line\r\n");
        assert_eq!(paste(&cb, "", (0, 0)).unwrap().text, "line");
        // A lone "\r" is trimmed.
        let cb = MemClipboard::with("line\r");
        assert_eq!(paste(&cb, "", (0, 0)).unwrap().text, "line");
    }

    #[test]
    fn smart_paste_trims_only_one_and_keeps_interior_newlines() {
        // Only the last terminator goes; a preceding blank line survives.
        let cb = MemClipboard::with("a\nb\n\n");
        assert_eq!(paste(&cb, "", (0, 0)).unwrap().text, "a\nb\n");
        // Interior newlines are untouched when there is no trailing one.
        let cb = MemClipboard::with("a\nb");
        assert_eq!(paste(&cb, "", (0, 0)).unwrap().text, "a\nb");
    }

    #[test]
    fn works_through_a_trait_object() {
        let cb = MemClipboard::with("PATCH");
        let clipboard: &dyn Clipboard = &cb;
        let repl = paste(clipboard, "hello", (1, 4)).unwrap();
        assert_eq!(repl.text, "PATCH");
        assert_eq!(repl.range, (1, 4));
    }
}
