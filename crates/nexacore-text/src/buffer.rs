//! A piece-table text buffer (WS8-08.1).
//!
//! A piece table keeps the loaded file in an immutable **original** buffer and
//! all inserted text in an append-only **add** buffer; the document is an
//! ordered list of *pieces*, each a `(source, start, len)` slice into one of
//! those buffers. Editing only rewrites the small piece list — the loaded
//! content is never copied — so opening and editing a hundreds-of-MB file is
//! cheap. This is the classic editor structure (used by VS Code's model), here
//! operating on UTF-8 bytes with edits constrained to character boundaries.

use alloc::{string::String, vec::Vec};

use crate::TextError;

/// Which backing buffer a [`Piece`] slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The immutable loaded-file buffer.
    Original,
    /// The append-only edit buffer.
    Add,
}

/// A contiguous run of bytes in one backing buffer.
#[derive(Debug, Clone, Copy)]
struct Piece {
    source: Source,
    start: usize,
    len: usize,
}

/// A piece-table text buffer over UTF-8 bytes.
#[derive(Debug, Clone)]
pub struct PieceTable {
    original: String,
    add: String,
    pieces: Vec<Piece>,
    len: usize,
}

impl PieceTable {
    /// A buffer initialised with `original` as the loaded content.
    #[must_use]
    pub fn new(original: &str) -> Self {
        let len = original.len();
        let mut pieces = Vec::new();
        if len > 0 {
            pieces.push(Piece {
                source: Source::Original,
                start: 0,
                len,
            });
        }
        Self {
            original: String::from(original),
            add: String::new(),
            pieces,
            len,
        }
    }

    /// The document length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the document is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes a piece slices.
    fn piece_bytes(&self, piece: &Piece) -> &str {
        let src = match piece.source {
            Source::Original => &self.original,
            Source::Add => &self.add,
        };
        src.get(piece.start..piece.start + piece.len).unwrap_or("")
    }

    /// Materialise the whole document.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::with_capacity(self.len);
        for piece in &self.pieces {
            out.push_str(self.piece_bytes(piece));
        }
        out
    }

    /// Materialise a byte range `[start, end)` of the document.
    ///
    /// # Errors
    /// [`TextError::OutOfBounds`] if the range exceeds the document.
    pub fn slice(&self, start: usize, end: usize) -> Result<String, TextError> {
        if start > end || end > self.len {
            return Err(TextError::OutOfBounds);
        }
        let mut out = String::with_capacity(end - start);
        let mut pos = 0usize;
        for piece in &self.pieces {
            let piece_end = pos + piece.len;
            if piece_end > start && pos < end {
                let s = start.max(pos) - pos;
                let e = end.min(piece_end) - pos;
                if let Some(chunk) = self.piece_bytes(piece).get(s..e) {
                    out.push_str(chunk);
                }
            }
            pos = piece_end;
            if pos >= end {
                break;
            }
        }
        Ok(out)
    }

    /// The byte at logical offset `pos`, if any.
    fn byte_at(&self, pos: usize) -> Option<u8> {
        let mut acc = 0usize;
        for piece in &self.pieces {
            if pos < acc + piece.len {
                let local = pos - acc;
                return self.piece_bytes(piece).as_bytes().get(local).copied();
            }
            acc += piece.len;
        }
        None
    }

    /// Whether `pos` is a valid character boundary (or the end of the buffer).
    fn is_char_boundary(&self, pos: usize) -> bool {
        if pos == 0 || pos == self.len {
            return true;
        }
        // A byte is a boundary iff it is not a UTF-8 continuation byte (0b10xxxxxx).
        self.byte_at(pos).is_some_and(|b| (b & 0xC0) != 0x80)
    }

    /// Split the piece list so `pos` lands on a piece boundary, returning the
    /// index of the piece that starts at `pos` (or `pieces.len()` at the end).
    fn split_at(&mut self, pos: usize) -> usize {
        let mut acc = 0usize;
        let mut idx = 0usize;
        while idx < self.pieces.len() {
            let plen = self.pieces.get(idx).map_or(0, |p| p.len);
            if pos == acc {
                return idx;
            }
            if pos < acc + plen {
                // Split piece `idx` at internal offset `k`.
                let k = pos - acc;
                if let Some(&piece) = self.pieces.get(idx) {
                    let left = Piece {
                        source: piece.source,
                        start: piece.start,
                        len: k,
                    };
                    let right = Piece {
                        source: piece.source,
                        start: piece.start + k,
                        len: piece.len - k,
                    };
                    if let Some(slot) = self.pieces.get_mut(idx) {
                        *slot = left;
                    }
                    self.pieces.insert(idx + 1, right);
                }
                return idx + 1;
            }
            acc += plen;
            idx += 1;
        }
        self.pieces.len()
    }

    /// Insert `text` at byte offset `pos`.
    ///
    /// # Errors
    /// [`TextError::OutOfBounds`] if `pos > len`; [`TextError::NotCharBoundary`]
    /// if `pos` splits a UTF-8 sequence.
    pub fn insert(&mut self, pos: usize, text: &str) -> Result<(), TextError> {
        if pos > self.len {
            return Err(TextError::OutOfBounds);
        }
        if !self.is_char_boundary(pos) {
            return Err(TextError::NotCharBoundary);
        }
        if text.is_empty() {
            return Ok(());
        }
        let idx = self.split_at(pos);
        let start = self.add.len();
        self.add.push_str(text);
        self.pieces.insert(
            idx,
            Piece {
                source: Source::Add,
                start,
                len: text.len(),
            },
        );
        self.len += text.len();
        Ok(())
    }

    /// Delete the byte range `[pos, pos + len)`.
    ///
    /// # Errors
    /// [`TextError::OutOfBounds`] if the range exceeds the document;
    /// [`TextError::NotCharBoundary`] if either end splits a UTF-8 sequence.
    pub fn delete(&mut self, pos: usize, len: usize) -> Result<(), TextError> {
        let end = pos.checked_add(len).ok_or(TextError::OutOfBounds)?;
        if end > self.len {
            return Err(TextError::OutOfBounds);
        }
        if !self.is_char_boundary(pos) || !self.is_char_boundary(end) {
            return Err(TextError::NotCharBoundary);
        }
        if len == 0 {
            return Ok(());
        }
        let start_idx = self.split_at(pos);
        let end_idx = self.split_at(end);
        self.pieces.drain(start_idx..end_idx);
        self.len -= len;
        Ok(())
    }

    /// Replace the byte range `[pos, pos + len)` with `text` in one step.
    ///
    /// # Errors
    /// As [`PieceTable::delete`] then [`PieceTable::insert`].
    pub fn replace(&mut self, pos: usize, len: usize, text: &str) -> Result<(), TextError> {
        self.delete(pos, len)?;
        self.insert(pos, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_buffer_round_trips() {
        let pt = PieceTable::new("hello world");
        assert_eq!(pt.len(), 11);
        assert!(!pt.is_empty());
        assert_eq!(pt.text(), "hello world");
        assert!(PieceTable::new("").is_empty());
    }

    #[test]
    fn insert_at_start_middle_end() {
        let mut pt = PieceTable::new("bd");
        pt.insert(1, "c").unwrap();
        pt.insert(0, "a").unwrap();
        pt.insert(pt.len(), "e").unwrap();
        assert_eq!(pt.text(), "abcde");
        assert_eq!(pt.len(), 5);
    }

    #[test]
    fn delete_spanning_multiple_pieces() {
        let mut pt = PieceTable::new("The quick brown fox");
        pt.insert(3, " VERY").unwrap(); // "The VERY quick brown fox"
        assert_eq!(pt.text(), "The VERY quick brown fox");
        // Delete " VERY quick" (offsets 3..14).
        pt.delete(3, 11).unwrap();
        assert_eq!(pt.text(), "The brown fox");
    }

    #[test]
    fn replace_range() {
        let mut pt = PieceTable::new("color and flavor");
        // Replace "color" (0..5) with "colour".
        pt.replace(0, 5, "colour").unwrap();
        assert_eq!(pt.text(), "colour and flavor");
    }

    #[test]
    fn slice_returns_substring() {
        let mut pt = PieceTable::new("abcdef");
        pt.insert(3, "XYZ").unwrap(); // abcXYZdef
        assert_eq!(pt.slice(2, 7).unwrap(), "cXYZd");
        assert_eq!(pt.slice(0, pt.len()).unwrap(), "abcXYZdef");
        assert_eq!(pt.slice(5, 3).err(), Some(TextError::OutOfBounds));
    }

    #[test]
    fn rejects_out_of_bounds_and_non_boundary() {
        let mut pt = PieceTable::new("café"); // 'é' is 2 bytes → len 5
        assert_eq!(pt.len(), 5);
        assert_eq!(pt.insert(9, "x").err(), Some(TextError::OutOfBounds));
        // Offset 4 is inside the 'é' sequence (byte 3..5).
        assert_eq!(pt.insert(4, "x").err(), Some(TextError::NotCharBoundary));
        // A valid boundary insert works and keeps valid UTF-8.
        pt.insert(3, "z").unwrap();
        assert_eq!(pt.text(), "cafzé");
    }

    #[test]
    fn many_edits_stay_consistent() {
        let mut pt = PieceTable::new("0123456789");
        pt.insert(5, "[mid]").unwrap();
        pt.delete(0, 2).unwrap();
        pt.insert(pt.len(), "!").unwrap();
        pt.replace(0, 1, "A").unwrap();
        // "0123456789" -> "01234[mid]56789" -> "234[mid]56789" ->
        // "234[mid]56789!" -> "A34[mid]56789!"
        assert_eq!(pt.text(), "A34[mid]56789!");
        assert_eq!(pt.len(), pt.text().len());
    }
}
