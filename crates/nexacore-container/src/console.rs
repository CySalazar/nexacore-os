//! Guest console output capture for container serial I/O.
//!
//! The guest kernel writes to the first serial UART (COM1, I/O port `0x3F8`)
//! for early-boot and kernel-log output. The [`KvmEngine`] run loop intercepts
//! [`crate::hypervisor::VcpuExit::IoOut`] exits on port `0x3F8` and forwards
//! the bytes to a [`ConsoleOutput`] instance stored per-container.
//!
//! ## Design
//!
//! [`ConsoleOutput`] is an append-only byte buffer with helper methods for
//! UTF-8 extraction and line splitting. It is intentionally simple:
//!
//! - No maximum size limit in v0.1 (size is bounded by the guest kernel log
//!   verbosity, which is small for micro-VM guests; a configurable cap is a
//!   follow-up).
//! - Non-UTF-8 bytes are replaced with the Unicode replacement character
//!   `U+FFFD` by [`ConsoleOutput::drain`] and [`ConsoleOutput::lines`] so
//!   callers always receive valid `String` values.
//! - [`ConsoleOutput`] is `Send` because the engine stores it inside a
//!   `Mutex<HashMap<…>>` and accesses it under the lock.
//!
//! [`KvmEngine`]: crate::engine::KvmEngine

/// Captures guest serial console output (port `0x3F8` I/O writes).
///
/// The engine's run loop calls [`ConsoleOutput::write_byte`] for every byte
/// the guest writes to the COM1 serial port. Callers retrieve the accumulated
/// output via [`ConsoleOutput::drain`] (consuming) or inspect it via
/// [`ConsoleOutput::lines`] (non-consuming).
///
/// ## Example
///
/// ```rust
/// use nexacore_container::console::ConsoleOutput;
///
/// let mut out = ConsoleOutput::new();
/// for b in b"hello\nworld\n" {
///     out.write_byte(*b);
/// }
///
/// assert_eq!(out.lines(), vec!["hello", "world"]);
/// let text = out.drain();
/// assert_eq!(text, "hello\nworld\n");
/// // After drain the buffer is empty.
/// assert_eq!(out.drain(), "");
/// ```
#[derive(Debug, Default)]
pub struct ConsoleOutput {
    /// Raw byte buffer. Accumulated by `write_byte`; consumed by `drain`.
    buf: Vec<u8>,
}

impl ConsoleOutput {
    /// Create a new, empty console output buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::console::ConsoleOutput;
    /// let out = ConsoleOutput::new();
    /// assert_eq!(out.lines(), Vec::<String>::new());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append a single byte to the internal buffer.
    ///
    /// This method is called by the engine once per byte received from the
    /// guest's serial port. It is intentionally `O(1)` so that high-volume
    /// kernel log output does not stall the run loop.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::console::ConsoleOutput;
    ///
    /// let mut out = ConsoleOutput::new();
    /// out.write_byte(b'A');
    /// out.write_byte(b'\n');
    /// assert_eq!(out.lines(), vec!["A"]);
    /// ```
    pub fn write_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    /// Drain all buffered output and return it as a `String`.
    ///
    /// After this call the internal buffer is empty. Non-UTF-8 bytes are
    /// replaced with `U+FFFD` (Unicode replacement character) rather than
    /// returning an error, because guest kernel serial output can include
    /// binary escape sequences.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::console::ConsoleOutput;
    ///
    /// let mut out = ConsoleOutput::new();
    /// for b in b"hello\n" {
    ///     out.write_byte(*b);
    /// }
    /// let s = out.drain();
    /// assert_eq!(s, "hello\n");
    /// assert_eq!(out.drain(), ""); // buffer is now empty
    /// ```
    pub fn drain(&mut self) -> String {
        let bytes = std::mem::take(&mut self.buf);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Return a snapshot of the buffered output split into lines.
    ///
    /// Unlike [`Self::drain`], this method does **not** consume the buffer.
    /// Empty trailing lines (e.g., from a trailing `\n`) are excluded by the
    /// `filter` on the iterator.
    ///
    /// Non-UTF-8 bytes are replaced with `U+FFFD` as in [`Self::drain`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::console::ConsoleOutput;
    ///
    /// let mut out = ConsoleOutput::new();
    /// for b in b"line1\nline2\n" {
    ///     out.write_byte(*b);
    /// }
    /// let lines = out.lines();
    /// assert_eq!(lines, vec!["line1", "line2"]);
    /// // Buffer is unchanged.
    /// assert_eq!(out.lines().len(), 2);
    /// ```
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let s = String::from_utf8_lossy(&self.buf);
        s.lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Return the accumulated bytes without consuming or clearing the buffer.
    ///
    /// This method is used by the engine to produce the console text without
    /// requiring a mutable reference (unlike [`ConsoleOutput::drain`]).
    /// Non-UTF-8 bytes are not filtered here; callers should pass the result
    /// through [`String::from_utf8_lossy`] if they need a `String`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::console::ConsoleOutput;
    ///
    /// let mut out = ConsoleOutput::new();
    /// out.write_byte(b'X');
    /// assert_eq!(out.as_bytes(), b"X");
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Returns `true` if no bytes have been buffered yet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::console::ConsoleOutput;
    ///
    /// let out = ConsoleOutput::new();
    /// assert!(out.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns the number of bytes currently buffered.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::console::ConsoleOutput;
    ///
    /// let mut out = ConsoleOutput::new();
    /// out.write_byte(b'x');
    /// assert_eq!(out.len(), 1);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let out = ConsoleOutput::new();
        assert!(out.is_empty());
        assert_eq!(out.len(), 0);
        assert_eq!(out.lines(), Vec::<String>::new());
    }

    #[test]
    fn write_byte_accumulates() {
        let mut out = ConsoleOutput::new();
        out.write_byte(b'a');
        out.write_byte(b'b');
        assert_eq!(out.len(), 2);
        assert!(!out.is_empty());
    }

    #[test]
    fn drain_returns_content_and_clears_buffer() {
        let mut out = ConsoleOutput::new();
        for b in b"hello\n" {
            out.write_byte(*b);
        }
        let s = out.drain();
        assert_eq!(s, "hello\n");
        assert!(out.is_empty());
        assert_eq!(out.drain(), "");
    }

    #[test]
    fn lines_splits_on_newlines() {
        let mut out = ConsoleOutput::new();
        for b in b"first\nsecond\nthird\n" {
            out.write_byte(*b);
        }
        assert_eq!(out.lines(), vec!["first", "second", "third"]);
    }

    #[test]
    fn lines_does_not_consume_buffer() {
        let mut out = ConsoleOutput::new();
        for b in b"hello\n" {
            out.write_byte(*b);
        }
        let _ = out.lines();
        assert!(!out.is_empty(), "lines() must not consume the buffer");
    }

    #[test]
    fn lines_excludes_empty_trailing_line() {
        let mut out = ConsoleOutput::new();
        for b in b"a\nb\n" {
            out.write_byte(*b);
        }
        // Trailing newline must not produce an empty entry.
        let lines = out.lines();
        assert_eq!(lines, vec!["a", "b"]);
        assert!(!lines.iter().any(String::is_empty));
    }

    #[test]
    fn drain_handles_non_utf8_gracefully() {
        let mut out = ConsoleOutput::new();
        // 0xFF is never valid UTF-8.
        out.write_byte(0xFF);
        let s = out.drain();
        // Should contain the replacement character, not panic.
        assert!(s.contains('\u{FFFD}'));
    }

    #[test]
    fn mock_serial_hello_scenario() {
        // Mirrors what the engine does when MockHypervisor emits IoOut.
        let mut out = ConsoleOutput::new();
        for b in b"hello\n" {
            out.write_byte(*b);
        }
        assert!(out.lines().iter().any(|l| l.contains("hello")));
        let drained = out.drain();
        assert!(drained.contains("hello"));
    }
}
