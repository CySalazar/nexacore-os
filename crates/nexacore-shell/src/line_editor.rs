//! Interactive line editor with cursor movement, history, and ANSI rendering.
//!
//! This module provides [`crate::line_editor::LineEditor`], the line-editing layer consumed by the
//! REPL. It accepts raw byte input, maps byte sequences to [`crate::line_editor::EditAction`]
//! values via [`crate::line_editor::map_key`], and maintains a character buffer with a logical
//! cursor position.
//!
//! ## Key bindings
//!
//! | Byte sequence | Action |
//! |---|---|
//! | Printable ASCII / UTF-8 | [`crate::line_editor::EditAction::Insert`] |
//! | `\x7f` or `\x08` | [`crate::line_editor::EditAction::Backspace`] |
//! | `\x1b[A` | [`crate::line_editor::EditAction::HistoryUp`] |
//! | `\x1b[B` | [`crate::line_editor::EditAction::HistoryDown`] |
//! | `\x1b[C` | [`crate::line_editor::EditAction::MoveRight`] |
//! | `\x1b[D` | [`crate::line_editor::EditAction::MoveLeft`] |
//! | `\x1b[H` or `\x1b[1~` | [`crate::line_editor::EditAction::Home`] |
//! | `\x1b[F` or `\x1b[4~` | [`crate::line_editor::EditAction::End`] |
//! | `\x1b[3~` | [`crate::line_editor::EditAction::Delete`] |
//! | `\x03` | [`crate::line_editor::EditAction::Interrupt`] |
//! | `\x04` | [`crate::line_editor::EditAction::Eof`] |
//! | `\x09` | [`crate::line_editor::EditAction::Complete`] |
//! | `\x0c` | [`crate::line_editor::EditAction::ClearScreen`] |
//! | `\r` or `\n` | [`crate::line_editor::EditAction::Submit`] |
//!
//! ## Rendering
//!
//! [`crate::line_editor::LineEditor::render_line`] produces a sequence of ANSI bytes that:
//! 1. Moves the cursor to column 0 (`\r`).
//! 2. Erases from cursor to end of line (`\x1b[K`).
//! 3. Writes the prompt.
//! 4. Writes the buffer content.
//! 5. Repositions the cursor at the logical cursor position.
//!
//! This approach avoids tracking the previous line's length and is safe for
//! terminals that support ANSI escape sequences (VT100+).

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, format, string::String, vec::Vec};

// ── LineResult ────────────────────────────────────────────────────────────────

/// Result returned by [`LineEditor::apply_action`].
///
/// Indicates whether editing is ongoing, complete, or terminated.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::line_editor::{EditAction, LineEditor, LineResult};
///
/// let mut ed = LineEditor::new();
/// assert_eq!(
///     ed.apply_action(EditAction::Insert('h')),
///     LineResult::Continue
/// );
/// assert_eq!(
///     ed.apply_action(EditAction::Insert('i')),
///     LineResult::Continue
/// );
/// assert_eq!(
///     ed.apply_action(EditAction::Submit),
///     LineResult::Line("hi".into())
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineResult {
    /// Continue editing — no complete line yet.
    Continue,
    /// A complete line was submitted (Enter pressed). The inner `String` is
    /// the buffer content at the time of submission.
    Line(String),
    /// User pressed Ctrl+C — interrupt signal.
    Interrupt,
    /// User pressed Ctrl+D on an empty buffer — end of file.
    Eof,
}

// ── EditAction ────────────────────────────────────────────────────────────────

/// An action derived from raw terminal input.
///
/// The mapping from raw bytes to actions is performed by [`map_key`].
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::line_editor::{EditAction, map_key};
///
/// assert_eq!(map_key(b"\x1b[A"), EditAction::HistoryUp);
/// assert_eq!(map_key(b"\r"), EditAction::Submit);
/// assert_eq!(map_key(b"a"), EditAction::Insert('a'));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditAction {
    /// Insert a character at the current cursor position.
    Insert(char),
    /// Delete the character immediately before the cursor (Backspace).
    Backspace,
    /// Delete the character at the cursor position (Delete / Forward-delete).
    Delete,
    /// Move cursor one character to the left.
    MoveLeft,
    /// Move cursor one character to the right.
    MoveRight,
    /// Move cursor to the start of the line (Home).
    Home,
    /// Move cursor to the end of the line (End).
    End,
    /// Navigate history one entry backwards (older).
    HistoryUp,
    /// Navigate history one entry forwards (newer).
    HistoryDown,
    /// Request tab completion.
    Complete,
    /// Submit the current line (Enter / Return).
    Submit,
    /// Ctrl+C — interrupt the current line.
    Interrupt,
    /// Ctrl+D — EOF if buffer is empty, otherwise acts as Delete.
    Eof,
    /// Ctrl+L — clear the screen and redraw.
    ClearScreen,
    /// An unrecognised byte sequence.
    Unknown,
}

// ── map_key ───────────────────────────────────────────────────────────────────

/// Map a raw byte sequence to an [`EditAction`].
///
/// This function handles single-byte control codes and multi-byte ANSI escape
/// sequences. It is designed to process one complete key press at a time; the
/// caller (typically a raw-mode terminal loop) is responsible for buffering
/// bytes until a complete sequence is available.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::line_editor::{EditAction, map_key};
///
/// // ANSI arrow keys.
/// assert_eq!(map_key(b"\x1b[A"), EditAction::HistoryUp);
/// assert_eq!(map_key(b"\x1b[B"), EditAction::HistoryDown);
/// assert_eq!(map_key(b"\x1b[C"), EditAction::MoveRight);
/// assert_eq!(map_key(b"\x1b[D"), EditAction::MoveLeft);
///
/// // Control characters.
/// assert_eq!(map_key(b"\x03"), EditAction::Interrupt);
/// assert_eq!(map_key(b"\x04"), EditAction::Eof);
/// assert_eq!(map_key(b"\x09"), EditAction::Complete);
/// assert_eq!(map_key(b"\r"), EditAction::Submit);
/// assert_eq!(map_key(b"\n"), EditAction::Submit);
///
/// // Printable character.
/// assert_eq!(map_key(b"a"), EditAction::Insert('a'));
///
/// // Unknown escape sequence.
/// assert_eq!(map_key(b"\x1b[Z"), EditAction::Unknown);
/// ```
pub fn map_key(raw: &[u8]) -> EditAction {
    match raw {
        // ── Submit ────────────────────────────────────────────────────────────
        b"\r" | b"\n" => EditAction::Submit,

        // ── Control characters ────────────────────────────────────────────────
        [0x03] => EditAction::Interrupt,
        [0x04] => EditAction::Eof,
        [0x08 | 0x7f] => EditAction::Backspace,
        [0x09] => EditAction::Complete,
        [0x0c] => EditAction::ClearScreen,

        // ── ANSI escape sequences ─────────────────────────────────────────────
        // Arrow keys: \x1b[A / \x1b[B / \x1b[C / \x1b[D
        b"\x1b[A" => EditAction::HistoryUp,
        b"\x1b[B" => EditAction::HistoryDown,
        b"\x1b[C" => EditAction::MoveRight,
        b"\x1b[D" => EditAction::MoveLeft,

        // Home: \x1b[H or \x1b[1~
        b"\x1b[H" | b"\x1b[1~" => EditAction::Home,

        // End: \x1b[F or \x1b[4~
        b"\x1b[F" | b"\x1b[4~" => EditAction::End,

        // Delete (forward): \x1b[3~
        b"\x1b[3~" => EditAction::Delete,

        // ── Unknown escape sequence ───────────────────────────────────────────
        [0x1b, ..] => EditAction::Unknown,

        // ── Printable character (single-byte ASCII or multi-byte UTF-8) ───────
        bytes => {
            // Attempt to decode the bytes as a UTF-8 string. If decoding
            // succeeds and the result is a single codepoint that is not a
            // control character, emit Insert.
            if let Ok(s) = core::str::from_utf8(bytes) {
                let mut chars = s.chars();
                if let Some(ch) = chars.next() {
                    if chars.next().is_none() && !ch.is_control() {
                        return EditAction::Insert(ch);
                    }
                }
            }
            EditAction::Unknown
        }
    }
}

// ── LineEditor ────────────────────────────────────────────────────────────────

/// Interactive line editor with cursor movement, history navigation, and ANSI
/// rendering.
///
/// The editor stores the current input as a `Vec<char>` to handle multi-byte
/// Unicode characters correctly. All cursor positions are measured in
/// characters (codepoints), not bytes.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::line_editor::{EditAction, LineEditor, LineResult};
///
/// let mut ed = LineEditor::new();
/// ed.apply_action(EditAction::Insert('h'));
/// ed.apply_action(EditAction::Insert('i'));
/// assert_eq!(ed.buffer_str(), "hi");
/// assert_eq!(ed.cursor(), 2);
/// ```
#[derive(Debug)]
pub struct LineEditor {
    /// The current input buffer as a sequence of Unicode codepoints.
    buffer: Vec<char>,
    /// Logical cursor position — the index of the character that would be
    /// pushed right by the next [`EditAction::Insert`].
    /// Invariant: `0 <= cursor <= buffer.len()`.
    cursor: usize,
    /// Command history. Entry `history[0]` is the oldest command.
    history: Vec<String>,
    /// Index into `history` when navigating. `None` means "current input".
    history_index: Option<usize>,
    /// Snapshot of the buffer before history navigation began, so that
    /// pressing Down past the end restores what the user was typing.
    saved_buffer: Option<String>,
    /// Maximum number of history entries to retain.
    max_history: usize,
}

impl LineEditor {
    /// Create a new [`LineEditor`] with a history limit of 1000 entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::line_editor::LineEditor;
    ///
    /// let ed = LineEditor::new();
    /// assert_eq!(ed.buffer_str(), "");
    /// assert_eq!(ed.cursor(), 0);
    /// assert!(ed.history().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            cursor: 0,
            history: Vec::new(),
            history_index: None,
            saved_buffer: None,
            max_history: 1000,
        }
    }

    /// Apply an [`EditAction`] to the current buffer state.
    ///
    /// Returns a [`LineResult`] indicating whether editing continues, a line
    /// was submitted, or the session was interrupted / terminated.
    ///
    /// # Behaviour by action
    ///
    /// | Action | Effect |
    /// |---|---|
    /// | `Insert(c)` | Inserts `c` at cursor, advances cursor. |
    /// | `Backspace` | Removes char before cursor; no-op at position 0. |
    /// | `Delete` | Removes char at cursor; no-op at end of buffer. |
    /// | `MoveLeft` | Decrements cursor; no-op at 0. |
    /// | `MoveRight` | Increments cursor; no-op at end. |
    /// | `Home` | Sets cursor to 0. |
    /// | `End` | Sets cursor to `buffer.len()`. |
    /// | `HistoryUp` | Loads the previous history entry. |
    /// | `HistoryDown` | Loads the next history entry or restores saved buffer. |
    /// | `Submit` | Returns `LineResult::Line(buffer)` and calls `reset`. |
    /// | `Interrupt` | Returns `LineResult::Interrupt`. |
    /// | `Eof` | Returns `Eof` if buffer empty, otherwise acts as `Delete`. |
    /// | `ClearScreen` | Returns `Continue` (caller renders clear sequence). |
    /// | `Complete` | Returns `Continue` (caller drives completion). |
    /// | `Unknown` | Returns `Continue`. |
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::line_editor::{EditAction, LineEditor, LineResult};
    ///
    /// let mut ed = LineEditor::new();
    /// ed.apply_action(EditAction::Insert('a'));
    /// ed.apply_action(EditAction::Insert('b'));
    /// assert_eq!(ed.apply_action(EditAction::Backspace), LineResult::Continue);
    /// assert_eq!(ed.buffer_str(), "a");
    /// ```
    pub fn apply_action(&mut self, action: EditAction) -> LineResult {
        match action {
            EditAction::Insert(c) => {
                self.buffer.insert(self.cursor, c);
                self.cursor += 1;
                LineResult::Continue
            }

            EditAction::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.buffer.remove(self.cursor);
                }
                LineResult::Continue
            }

            EditAction::Delete => {
                if self.cursor < self.buffer.len() {
                    self.buffer.remove(self.cursor);
                }
                LineResult::Continue
            }

            EditAction::MoveLeft => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
                LineResult::Continue
            }

            EditAction::MoveRight => {
                if self.cursor < self.buffer.len() {
                    self.cursor += 1;
                }
                LineResult::Continue
            }

            EditAction::Home => {
                self.cursor = 0;
                LineResult::Continue
            }

            EditAction::End => {
                self.cursor = self.buffer.len();
                LineResult::Continue
            }

            EditAction::HistoryUp => {
                self.navigate_history_up();
                LineResult::Continue
            }

            EditAction::HistoryDown => {
                self.navigate_history_down();
                LineResult::Continue
            }

            EditAction::Submit => {
                let line = self.buffer_str();
                self.reset();
                LineResult::Line(line)
            }

            EditAction::Interrupt => LineResult::Interrupt,

            EditAction::Eof => {
                if self.buffer.is_empty() {
                    LineResult::Eof
                } else {
                    // Delete the character at cursor position (forward delete).
                    if self.cursor < self.buffer.len() {
                        self.buffer.remove(self.cursor);
                    }
                    LineResult::Continue
                }
            }

            // ClearScreen, Complete, and Unknown do not modify buffer state;
            // the REPL handles any display or completion logic they require.
            EditAction::ClearScreen | EditAction::Complete | EditAction::Unknown => {
                LineResult::Continue
            }
        }
    }

    /// Render the current line as a sequence of ANSI bytes.
    ///
    /// The produced sequence:
    /// 1. `\r` — carriage return to column 0.
    /// 2. `\x1b[K` — erase from cursor to end of line.
    /// 3. The prompt string (as UTF-8 bytes).
    /// 4. The buffer content (as UTF-8 bytes).
    /// 5. `\x1b[{n}D` — move cursor left by `(buffer.len() - cursor)` columns
    ///    (only emitted when cursor is not at the end of the line).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::line_editor::LineEditor;
    ///
    /// let mut ed = LineEditor::new();
    /// let bytes = ed.render_line("$ ");
    /// // Should start with carriage return and erase-to-EOL.
    /// assert!(bytes.starts_with(b"\r\x1b[K"));
    /// // Should contain the prompt.
    /// assert!(bytes.windows(2).any(|w| w == b"$ "));
    /// ```
    pub fn render_line(&self, prompt: &str) -> Vec<u8> {
        let mut out = Vec::new();

        // Move to column 0 and erase to end of line.
        out.extend_from_slice(b"\r\x1b[K");

        // Write the prompt.
        out.extend_from_slice(prompt.as_bytes());

        // Write the buffer content.
        let buf_str: String = self.buffer.iter().collect();
        out.extend_from_slice(buf_str.as_bytes());

        // Reposition cursor if it is not at the end.
        let chars_after_cursor = self.buffer.len() - self.cursor;
        if chars_after_cursor > 0 {
            // Emit ESC[nD to move left by n columns.
            let move_left = format!("\x1b[{chars_after_cursor}D");
            out.extend_from_slice(move_left.as_bytes());
        }

        out
    }

    /// Return the current buffer content as a `String`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::line_editor::{EditAction, LineEditor};
    ///
    /// let mut ed = LineEditor::new();
    /// ed.apply_action(EditAction::Insert('h'));
    /// ed.apply_action(EditAction::Insert('i'));
    /// assert_eq!(ed.buffer_str(), "hi");
    /// ```
    #[must_use]
    pub fn buffer_str(&self) -> String {
        self.buffer.iter().collect()
    }

    /// Push a completed line into the history ring.
    ///
    /// Empty strings are not stored. If the new entry is identical to the
    /// most recent history entry, it is also skipped (deduplication).
    ///
    /// When the history exceeds [`max_history`](LineEditor::new) entries, the
    /// oldest entry is evicted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::line_editor::LineEditor;
    ///
    /// let mut ed = LineEditor::new();
    /// ed.push_history("ls -la");
    /// ed.push_history("echo hello");
    /// assert_eq!(ed.history().len(), 2);
    /// ```
    pub fn push_history(&mut self, line: &str) {
        if line.is_empty() {
            return;
        }
        // Skip duplicates of the most recent entry.
        if self.history.last().map(String::as_str) == Some(line) {
            return;
        }
        self.history.push(line.to_owned());
        // Evict oldest if over the limit.
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    /// Return a reference to the history buffer (oldest first).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::line_editor::LineEditor;
    ///
    /// let mut ed = LineEditor::new();
    /// assert!(ed.history().is_empty());
    /// ed.push_history("pwd");
    /// assert_eq!(ed.history(), &["pwd"]);
    /// ```
    #[must_use]
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Reset the editor for a new input line.
    ///
    /// Clears the buffer, sets cursor to 0, and cancels any active history
    /// navigation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::line_editor::{EditAction, LineEditor};
    ///
    /// let mut ed = LineEditor::new();
    /// ed.apply_action(EditAction::Insert('x'));
    /// ed.reset();
    /// assert_eq!(ed.buffer_str(), "");
    /// assert_eq!(ed.cursor(), 0);
    /// ```
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
        self.history_index = None;
        self.saved_buffer = None;
    }

    /// Replace the buffer with `content` and move the cursor to the end.
    ///
    /// Used by the tab-completion engine to insert a completed token.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::line_editor::LineEditor;
    ///
    /// let mut ed = LineEditor::new();
    /// ed.set_buffer("hello world");
    /// assert_eq!(ed.buffer_str(), "hello world");
    /// assert_eq!(ed.cursor(), 11);
    /// ```
    pub fn set_buffer(&mut self, content: &str) {
        self.buffer = content.chars().collect();
        self.cursor = self.buffer.len();
    }

    /// Return the current cursor position (character index, 0-based).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::line_editor::{EditAction, LineEditor};
    ///
    /// let mut ed = LineEditor::new();
    /// assert_eq!(ed.cursor(), 0);
    /// ed.apply_action(EditAction::Insert('a'));
    /// assert_eq!(ed.cursor(), 1);
    /// ```
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Move one step back through history (toward older entries).
    ///
    /// On the first call (no active navigation), saves the current buffer so it
    /// can be restored when the user presses Down past the end of history.
    fn navigate_history_up(&mut self) {
        if self.history.is_empty() {
            return;
        }

        let new_index = match self.history_index {
            None => {
                // Save current buffer before entering history navigation.
                self.saved_buffer = Some(self.buffer_str());
                self.history.len() - 1
            }
            Some(0) => {
                // Already at the oldest entry; no-op.
                return;
            }
            Some(i) => i - 1,
        };

        self.history_index = Some(new_index);
        // SAFETY: `new_index` is derived from `self.history.len() - 1` or a
        // prior index decremented by 1, both of which are within bounds because
        // we checked `self.history.is_empty()` and `Some(0)` before arriving here.
        if let Some(entry) = self.history.get(new_index).cloned() {
            self.set_buffer(&entry);
        }
    }

    /// Move one step forward through history (toward newer entries).
    ///
    /// When the user navigates past the most recent history entry, the saved
    /// buffer (from before navigation began) is restored.
    fn navigate_history_down(&mut self) {
        let Some(idx) = self.history_index else {
            // Not in history navigation; nothing to do.
            return;
        };

        if idx + 1 < self.history.len() {
            let new_index = idx + 1;
            self.history_index = Some(new_index);
            // SAFETY: `new_index` is `idx + 1` and we checked `idx + 1 < self.history.len()`.
            if let Some(entry) = self.history.get(new_index).cloned() {
                self.set_buffer(&entry);
            }
        } else {
            // Past the newest entry — restore the pre-navigation buffer.
            self.history_index = None;
            let saved = self.saved_buffer.take().unwrap_or_default();
            self.set_buffer(&saved);
        }
    }
}

impl Default for LineEditor {
    /// Create a default [`LineEditor`] identical to [`LineEditor::new`].
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── map_key ───────────────────────────────────────────────────────────────

    #[test]
    fn map_key_arrow_up() {
        assert_eq!(map_key(b"\x1b[A"), EditAction::HistoryUp);
    }

    #[test]
    fn map_key_arrow_down() {
        assert_eq!(map_key(b"\x1b[B"), EditAction::HistoryDown);
    }

    #[test]
    fn map_key_arrow_right() {
        assert_eq!(map_key(b"\x1b[C"), EditAction::MoveRight);
    }

    #[test]
    fn map_key_arrow_left() {
        assert_eq!(map_key(b"\x1b[D"), EditAction::MoveLeft);
    }

    #[test]
    fn map_key_home_h() {
        assert_eq!(map_key(b"\x1b[H"), EditAction::Home);
    }

    #[test]
    fn map_key_home_tilde() {
        assert_eq!(map_key(b"\x1b[1~"), EditAction::Home);
    }

    #[test]
    fn map_key_end_f() {
        assert_eq!(map_key(b"\x1b[F"), EditAction::End);
    }

    #[test]
    fn map_key_end_tilde() {
        assert_eq!(map_key(b"\x1b[4~"), EditAction::End);
    }

    #[test]
    fn map_key_delete_forward() {
        assert_eq!(map_key(b"\x1b[3~"), EditAction::Delete);
    }

    #[test]
    fn map_key_backspace_del() {
        assert_eq!(map_key(&[0x7f]), EditAction::Backspace);
    }

    #[test]
    fn map_key_backspace_bs() {
        assert_eq!(map_key(&[0x08]), EditAction::Backspace);
    }

    #[test]
    fn map_key_ctrl_c() {
        assert_eq!(map_key(&[0x03]), EditAction::Interrupt);
    }

    #[test]
    fn map_key_ctrl_d() {
        assert_eq!(map_key(&[0x04]), EditAction::Eof);
    }

    #[test]
    fn map_key_tab() {
        assert_eq!(map_key(&[0x09]), EditAction::Complete);
    }

    #[test]
    fn map_key_ctrl_l() {
        assert_eq!(map_key(&[0x0c]), EditAction::ClearScreen);
    }

    #[test]
    fn map_key_enter_cr() {
        assert_eq!(map_key(b"\r"), EditAction::Submit);
    }

    #[test]
    fn map_key_enter_lf() {
        assert_eq!(map_key(b"\n"), EditAction::Submit);
    }

    #[test]
    fn map_key_regular_char() {
        assert_eq!(map_key(b"a"), EditAction::Insert('a'));
        assert_eq!(map_key(b"Z"), EditAction::Insert('Z'));
        assert_eq!(map_key(b"5"), EditAction::Insert('5'));
        assert_eq!(map_key(b" "), EditAction::Insert(' '));
    }

    #[test]
    fn map_key_unknown_escape() {
        assert_eq!(map_key(b"\x1b[Z"), EditAction::Unknown);
        assert_eq!(map_key(b"\x1b"), EditAction::Unknown);
    }

    // ── LineEditor: insert & buffer ───────────────────────────────────────────

    #[test]
    fn insert_single_char() {
        let mut ed = LineEditor::new();
        assert_eq!(
            ed.apply_action(EditAction::Insert('x')),
            LineResult::Continue
        );
        assert_eq!(ed.buffer_str(), "x");
        assert_eq!(ed.cursor(), 1);
    }

    #[test]
    fn insert_multiple_chars() {
        let mut ed = LineEditor::new();
        for c in "hello".chars() {
            ed.apply_action(EditAction::Insert(c));
        }
        assert_eq!(ed.buffer_str(), "hello");
        assert_eq!(ed.cursor(), 5);
    }

    #[test]
    fn insert_at_middle_position() {
        let mut ed = LineEditor::new();
        ed.set_buffer("ac");
        ed.apply_action(EditAction::MoveLeft); // cursor at 1
        ed.apply_action(EditAction::Insert('b'));
        assert_eq!(ed.buffer_str(), "abc");
        assert_eq!(ed.cursor(), 2);
    }

    #[test]
    fn insert_at_start() {
        let mut ed = LineEditor::new();
        ed.set_buffer("bc");
        ed.apply_action(EditAction::Home);
        ed.apply_action(EditAction::Insert('a'));
        assert_eq!(ed.buffer_str(), "abc");
        assert_eq!(ed.cursor(), 1);
    }

    // ── Backspace ─────────────────────────────────────────────────────────────

    #[test]
    fn backspace_at_start_is_noop() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::Home);
        let result = ed.apply_action(EditAction::Backspace);
        assert_eq!(result, LineResult::Continue);
        assert_eq!(ed.buffer_str(), "abc");
        assert_eq!(ed.cursor(), 0);
    }

    #[test]
    fn backspace_at_end_removes_last_char() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::Backspace);
        assert_eq!(ed.buffer_str(), "ab");
        assert_eq!(ed.cursor(), 2);
    }

    #[test]
    fn backspace_in_middle() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::MoveLeft); // cursor at 2
        ed.apply_action(EditAction::Backspace);
        assert_eq!(ed.buffer_str(), "ac");
        assert_eq!(ed.cursor(), 1);
    }

    #[test]
    fn backspace_on_empty_buffer_is_noop() {
        let mut ed = LineEditor::new();
        assert_eq!(ed.apply_action(EditAction::Backspace), LineResult::Continue);
        assert_eq!(ed.buffer_str(), "");
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    #[test]
    fn delete_at_end_is_noop() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        assert_eq!(ed.apply_action(EditAction::Delete), LineResult::Continue);
        assert_eq!(ed.buffer_str(), "abc");
        assert_eq!(ed.cursor(), 3);
    }

    #[test]
    fn delete_in_middle() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::Home);
        ed.apply_action(EditAction::MoveRight); // cursor at 1
        ed.apply_action(EditAction::Delete);
        assert_eq!(ed.buffer_str(), "ac");
        assert_eq!(ed.cursor(), 1);
    }

    #[test]
    fn delete_at_start() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::Home);
        ed.apply_action(EditAction::Delete);
        assert_eq!(ed.buffer_str(), "bc");
        assert_eq!(ed.cursor(), 0);
    }

    // ── Movement ──────────────────────────────────────────────────────────────

    #[test]
    fn move_left_decrements_cursor() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::MoveLeft);
        assert_eq!(ed.cursor(), 2);
    }

    #[test]
    fn move_left_at_zero_is_noop() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::Home);
        assert_eq!(ed.apply_action(EditAction::MoveLeft), LineResult::Continue);
        assert_eq!(ed.cursor(), 0);
    }

    #[test]
    fn move_right_increments_cursor() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::Home);
        ed.apply_action(EditAction::MoveRight);
        assert_eq!(ed.cursor(), 1);
    }

    #[test]
    fn move_right_at_end_is_noop() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        assert_eq!(ed.apply_action(EditAction::MoveRight), LineResult::Continue);
        assert_eq!(ed.cursor(), 3);
    }

    #[test]
    fn home_moves_cursor_to_zero() {
        let mut ed = LineEditor::new();
        ed.set_buffer("hello");
        ed.apply_action(EditAction::Home);
        assert_eq!(ed.cursor(), 0);
    }

    #[test]
    fn end_moves_cursor_to_end() {
        let mut ed = LineEditor::new();
        ed.set_buffer("hello");
        ed.apply_action(EditAction::Home);
        ed.apply_action(EditAction::End);
        assert_eq!(ed.cursor(), 5);
    }

    // ── Submit ────────────────────────────────────────────────────────────────

    #[test]
    fn submit_returns_line_and_resets() {
        let mut ed = LineEditor::new();
        ed.set_buffer("ls -la");
        let result = ed.apply_action(EditAction::Submit);
        assert_eq!(result, LineResult::Line("ls -la".to_string()));
        assert_eq!(ed.buffer_str(), "");
        assert_eq!(ed.cursor(), 0);
    }

    #[test]
    fn submit_empty_buffer_returns_empty_string() {
        let mut ed = LineEditor::new();
        let result = ed.apply_action(EditAction::Submit);
        assert_eq!(result, LineResult::Line(String::new()));
    }

    // ── Interrupt / Eof ───────────────────────────────────────────────────────

    #[test]
    fn ctrl_c_returns_interrupt() {
        let mut ed = LineEditor::new();
        ed.set_buffer("partial input");
        assert_eq!(
            ed.apply_action(EditAction::Interrupt),
            LineResult::Interrupt
        );
    }

    #[test]
    fn ctrl_d_on_empty_returns_eof() {
        let mut ed = LineEditor::new();
        assert_eq!(ed.apply_action(EditAction::Eof), LineResult::Eof);
    }

    #[test]
    fn ctrl_d_on_nonempty_acts_as_delete() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::Home); // cursor at 0
        let result = ed.apply_action(EditAction::Eof);
        assert_eq!(result, LineResult::Continue);
        assert_eq!(ed.buffer_str(), "bc");
        assert_eq!(ed.cursor(), 0);
    }

    // ── History ───────────────────────────────────────────────────────────────

    #[test]
    fn push_history_adds_entry() {
        let mut ed = LineEditor::new();
        ed.push_history("ls");
        assert_eq!(ed.history(), &["ls".to_string()]);
    }

    #[test]
    fn push_history_empty_string_is_ignored() {
        let mut ed = LineEditor::new();
        ed.push_history("");
        assert!(ed.history().is_empty());
    }

    #[test]
    fn push_history_duplicate_is_skipped() {
        let mut ed = LineEditor::new();
        ed.push_history("ls");
        ed.push_history("ls");
        assert_eq!(ed.history().len(), 1);
    }

    #[test]
    fn push_history_different_entries_both_stored() {
        let mut ed = LineEditor::new();
        ed.push_history("ls");
        ed.push_history("pwd");
        assert_eq!(ed.history().len(), 2);
    }

    #[test]
    fn history_up_loads_most_recent_entry() {
        let mut ed = LineEditor::new();
        ed.push_history("cmd1");
        ed.push_history("cmd2");
        ed.apply_action(EditAction::HistoryUp);
        assert_eq!(ed.buffer_str(), "cmd2");
    }

    #[test]
    fn history_up_twice_loads_older_entry() {
        let mut ed = LineEditor::new();
        ed.push_history("cmd1");
        ed.push_history("cmd2");
        ed.apply_action(EditAction::HistoryUp);
        ed.apply_action(EditAction::HistoryUp);
        assert_eq!(ed.buffer_str(), "cmd1");
    }

    #[test]
    fn history_up_at_oldest_is_noop() {
        let mut ed = LineEditor::new();
        ed.push_history("only");
        ed.apply_action(EditAction::HistoryUp);
        ed.apply_action(EditAction::HistoryUp); // no-op
        assert_eq!(ed.buffer_str(), "only");
    }

    #[test]
    fn history_down_after_up_returns_to_current() {
        let mut ed = LineEditor::new();
        ed.push_history("cmd1");
        ed.push_history("cmd2");
        ed.set_buffer("partial");
        ed.apply_action(EditAction::HistoryUp); // loads cmd2
        ed.apply_action(EditAction::HistoryDown); // back to saved
        assert_eq!(ed.buffer_str(), "partial");
    }

    #[test]
    fn history_down_without_navigation_is_noop() {
        let mut ed = LineEditor::new();
        ed.set_buffer("current");
        ed.apply_action(EditAction::HistoryDown); // no-op
        assert_eq!(ed.buffer_str(), "current");
    }

    #[test]
    fn history_saves_and_restores_current_buffer() {
        let mut ed = LineEditor::new();
        ed.push_history("old_cmd");
        ed.set_buffer("typing...");
        ed.apply_action(EditAction::HistoryUp);
        assert_eq!(ed.buffer_str(), "old_cmd");
        ed.apply_action(EditAction::HistoryDown);
        assert_eq!(ed.buffer_str(), "typing...");
    }

    #[test]
    fn history_max_size_is_respected() {
        let mut ed = LineEditor::new();
        // Force a small max to test eviction.
        ed.max_history = 3;
        ed.push_history("a");
        ed.push_history("b");
        ed.push_history("c");
        ed.push_history("d"); // evicts "a"
        assert_eq!(ed.history().len(), 3);
        assert!(!ed.history().contains(&"a".to_string()));
        assert!(ed.history().contains(&"d".to_string()));
    }

    // ── render_line ───────────────────────────────────────────────────────────

    #[test]
    fn render_line_starts_with_cr_and_erase() {
        let ed = LineEditor::new();
        let bytes = ed.render_line("$ ");
        assert!(bytes.starts_with(b"\r\x1b[K"));
    }

    #[test]
    fn render_line_contains_prompt() {
        let ed = LineEditor::new();
        let bytes = ed.render_line("nexacore> ");
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("nexacore> "));
    }

    #[test]
    fn render_line_contains_buffer_content() {
        let mut ed = LineEditor::new();
        ed.set_buffer("ls -la");
        let bytes = ed.render_line("$ ");
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("ls -la"));
    }

    #[test]
    fn render_line_cursor_at_end_no_reposition() {
        // When cursor is at end, no ESC[nD sequence should be emitted.
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        let bytes = ed.render_line("");
        // Find if any ESC[nD sequence is present after the content.
        let s = String::from_utf8_lossy(&bytes);
        // The buffer "abc" has cursor at 3 = len, so no move-left needed.
        assert!(!s.contains("\x1b[3D"));
    }

    #[test]
    fn render_line_cursor_in_middle_emits_reposition() {
        let mut ed = LineEditor::new();
        ed.set_buffer("abc");
        ed.apply_action(EditAction::Home); // cursor at 0
        let bytes = ed.render_line("");
        let s = String::from_utf8_lossy(&bytes);
        // 3 chars after cursor → ESC[3D
        assert!(s.contains("\x1b[3D"));
    }

    // ── set_buffer / reset ────────────────────────────────────────────────────

    #[test]
    fn set_buffer_updates_content_and_cursor() {
        let mut ed = LineEditor::new();
        ed.set_buffer("hello");
        assert_eq!(ed.buffer_str(), "hello");
        assert_eq!(ed.cursor(), 5);
    }

    #[test]
    fn reset_clears_buffer_and_cursor() {
        let mut ed = LineEditor::new();
        ed.set_buffer("something");
        ed.reset();
        assert_eq!(ed.buffer_str(), "");
        assert_eq!(ed.cursor(), 0);
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_buffer_all_movement_ops_are_noop() {
        let mut ed = LineEditor::new();
        ed.apply_action(EditAction::MoveLeft);
        ed.apply_action(EditAction::MoveRight);
        ed.apply_action(EditAction::Home);
        ed.apply_action(EditAction::End);
        assert_eq!(ed.buffer_str(), "");
        assert_eq!(ed.cursor(), 0);
    }

    #[test]
    fn multiple_inserts_then_backspaces_reaches_empty() {
        let mut ed = LineEditor::new();
        for c in "abcde".chars() {
            ed.apply_action(EditAction::Insert(c));
        }
        for _ in 0..5 {
            ed.apply_action(EditAction::Backspace);
        }
        assert_eq!(ed.buffer_str(), "");
        assert_eq!(ed.cursor(), 0);
    }

    #[test]
    fn history_up_empty_history_is_noop() {
        let mut ed = LineEditor::new();
        ed.set_buffer("current");
        ed.apply_action(EditAction::HistoryUp);
        assert_eq!(ed.buffer_str(), "current");
    }
}
