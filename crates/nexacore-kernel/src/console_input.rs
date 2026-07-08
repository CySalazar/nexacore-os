//! Kernel console input ring buffer.
//!
//! Accumulates bytes from the PS/2 keyboard IRQ handler (or serial
//! input). The `ReadConsole` syscall drains this buffer line-by-line.
//!
//! ## Design
//!
//! The buffer is a fixed-capacity ring backed by
//! [`alloc::collections::VecDeque<u8>`]. When the buffer is full, the
//! **oldest** byte is silently evicted to prevent the IRQ handler from
//! blocking. This matches the behaviour of classic Unix tty buffers.
//!
//! **Thread-safety:** `ConsoleInputBuffer` is not `Sync`. In the kernel the
//! IRQ path and the syscall path must coordinate via a spinlock or by
//! masking the keyboard IRQ around buffer operations.

use alloc::{collections::VecDeque, vec::Vec};

/// Maximum capacity of the console input ring buffer, in bytes.
///
/// 4 KiB is the traditional tty input buffer size. Raising this constant
/// widens the per-buffer allocation without changing the ABI.
pub const CONSOLE_INPUT_CAPACITY: usize = 4096;

/// Ring buffer for keyboard / serial console input.
///
/// Bytes are pushed by the IRQ handler via [`push_byte`](Self::push_byte)
/// and consumed by the `ReadConsole` syscall via
/// [`read_bytes`](Self::read_bytes).
///
/// ## Examples
///
/// ```
/// use nexacore_kernel::console_input::ConsoleInputBuffer;
/// let mut buf = ConsoleInputBuffer::new();
/// buf.push_byte(b'O');
/// buf.push_byte(b'K');
/// let bytes = buf.read_bytes(2, false);
/// assert_eq!(bytes, b"OK");
/// ```
#[derive(Debug)]
pub struct ConsoleInputBuffer {
    buffer: VecDeque<u8>,
    capacity: usize,
}

impl ConsoleInputBuffer {
    /// Create a new empty console input buffer with the default
    /// [`CONSOLE_INPUT_CAPACITY`].
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::console_input::ConsoleInputBuffer;
    /// let buf = ConsoleInputBuffer::new();
    /// assert!(buf.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::with_capacity(CONSOLE_INPUT_CAPACITY),
            capacity: CONSOLE_INPUT_CAPACITY,
        }
    }

    /// Push a byte from the keyboard IRQ handler.
    ///
    /// If the buffer is full, the oldest byte is silently dropped to
    /// make room. This prevents an unresponsive reader from blocking
    /// the IRQ handler.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::console_input::ConsoleInputBuffer;
    /// let mut buf = ConsoleInputBuffer::new();
    /// buf.push_byte(b'A');
    /// assert_eq!(buf.len(), 1);
    /// ```
    pub fn push_byte(&mut self, byte: u8) {
        if self.buffer.len() >= self.capacity {
            let _ = self.buffer.pop_front();
        }
        self.buffer.push_back(byte);
    }

    /// Read up to `max_len` bytes from the buffer.
    ///
    /// ## Modes
    ///
    /// - **Raw** (`line_buffered = false`): returns up to `max_len` bytes
    ///   regardless of content.
    /// - **Line-buffered** (`line_buffered = true`): returns bytes up to and
    ///   including the first `'\n'` byte, capped at `max_len`. If no `'\n'`
    ///   is present, returns **all available bytes** (bounded by `max_len`),
    ///   so a partial line is never silently lost.
    ///
    /// Returns an empty `Vec` when the buffer is empty or `max_len == 0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::console_input::ConsoleInputBuffer;
    /// let mut buf = ConsoleInputBuffer::new();
    /// buf.push_byte(b'h');
    /// buf.push_byte(b'i');
    /// buf.push_byte(b'\n');
    /// buf.push_byte(b'x');
    /// // Line-buffered: reads up to and including '\n'.
    /// let line = buf.read_bytes(64, true);
    /// assert_eq!(line, b"hi\n");
    /// // Raw: reads remaining byte.
    /// let rest = buf.read_bytes(64, false);
    /// assert_eq!(rest, b"x");
    /// ```
    pub fn read_bytes(&mut self, max_len: usize, line_buffered: bool) -> Vec<u8> {
        if max_len == 0 || self.buffer.is_empty() {
            return Vec::new();
        }

        let available = self.buffer.len().min(max_len);

        let to_drain = if line_buffered {
            // Find first '\n' within the affordable window.
            // map_or: if newline found include it (+1); otherwise return all available.
            self.buffer
                .iter()
                .take(available)
                .position(|&b| b == b'\n')
                .map_or(available, |pos| pos + 1)
        } else {
            available
        };

        self.buffer.drain(..to_drain).collect()
    }

    /// Check whether a complete line (ending with `\n`) is available.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::console_input::ConsoleInputBuffer;
    /// let mut buf = ConsoleInputBuffer::new();
    /// assert!(!buf.has_line());
    /// buf.push_byte(b'\n');
    /// assert!(buf.has_line());
    /// ```
    #[must_use]
    pub fn has_line(&self) -> bool {
        self.buffer.contains(&b'\n')
    }

    /// Returns `true` if the buffer contains no bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::console_input::ConsoleInputBuffer;
    /// let buf = ConsoleInputBuffer::new();
    /// assert!(buf.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns the number of bytes currently buffered.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_kernel::console_input::ConsoleInputBuffer;
    /// let mut buf = ConsoleInputBuffer::new();
    /// buf.push_byte(b'Z');
    /// assert_eq!(buf.len(), 1);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for ConsoleInputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_buffer_is_empty() {
        let buf = ConsoleInputBuffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert!(!buf.has_line());
    }

    #[test]
    fn push_byte_accumulates() {
        let mut buf = ConsoleInputBuffer::new();
        buf.push_byte(b'h');
        buf.push_byte(b'i');
        assert_eq!(buf.len(), 2);
        assert!(!buf.is_empty());
    }

    #[test]
    fn read_bytes_raw_drains() {
        let mut buf = ConsoleInputBuffer::new();
        for &b in b"hello" {
            buf.push_byte(b);
        }
        let data = buf.read_bytes(3, false);
        assert_eq!(data, b"hel");
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn line_buffered_reads_up_to_newline() {
        let mut buf = ConsoleInputBuffer::new();
        for &b in b"hello\nworld" {
            buf.push_byte(b);
        }
        assert!(buf.has_line());
        let line = buf.read_bytes(100, true);
        assert_eq!(line, b"hello\n");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn has_line_detects_newline() {
        let mut buf = ConsoleInputBuffer::new();
        assert!(!buf.has_line());
        buf.push_byte(b'x');
        assert!(!buf.has_line());
        buf.push_byte(b'\n');
        assert!(buf.has_line());
    }

    #[test]
    fn overflow_drops_oldest() {
        let mut buf = ConsoleInputBuffer {
            buffer: VecDeque::with_capacity(4),
            capacity: 4,
        };
        for &b in b"ABCDE" {
            buf.push_byte(b);
        }
        assert_eq!(buf.len(), 4);
        let data = buf.read_bytes(10, false);
        // 'A' (oldest) was evicted; remaining bytes are B, C, D, E.
        assert_eq!(data, b"BCDE");
    }

    #[test]
    fn empty_read_returns_empty() {
        let mut buf = ConsoleInputBuffer::new();
        assert!(buf.read_bytes(10, false).is_empty());
        assert!(buf.read_bytes(10, true).is_empty());
    }

    #[test]
    fn multiple_lines_buffered() {
        let mut buf = ConsoleInputBuffer::new();
        for &b in b"line1\nline2\nline3\n" {
            buf.push_byte(b);
        }
        let l1 = buf.read_bytes(100, true);
        assert_eq!(l1, b"line1\n");
        let l2 = buf.read_bytes(100, true);
        assert_eq!(l2, b"line2\n");
        let l3 = buf.read_bytes(100, true);
        assert_eq!(l3, b"line3\n");
        assert!(buf.is_empty());
    }

    #[test]
    fn utf8_multibyte_accumulation() {
        let mut buf = ConsoleInputBuffer::new();
        // U+00E9 "é" in UTF-8: 0xC3 0xA9.
        buf.push_byte(0xC3);
        buf.push_byte(0xA9);
        buf.push_byte(b'\n');
        let data = buf.read_bytes(100, true);
        assert_eq!(data, &[0xC3, 0xA9, b'\n']);
    }

    #[test]
    fn read_bytes_max_len_zero_returns_empty() {
        let mut buf = ConsoleInputBuffer::new();
        buf.push_byte(b'a');
        assert!(buf.read_bytes(0, false).is_empty());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn line_buffered_no_newline_returns_all_available() {
        // Per spec: "or all available if no \n".
        let mut buf = ConsoleInputBuffer::new();
        for &b in b"no-newline" {
            buf.push_byte(b);
        }
        assert!(!buf.has_line());
        let data = buf.read_bytes(64, true);
        assert_eq!(data, b"no-newline");
        assert!(buf.is_empty());
    }

    #[test]
    fn line_buffered_max_len_caps_output() {
        let mut buf = ConsoleInputBuffer::new();
        for &b in b"hello\n" {
            buf.push_byte(b);
        }
        // max_len = 3 caps within the line.
        let data = buf.read_bytes(3, true);
        assert_eq!(data, b"hel");
        assert_eq!(buf.len(), 3);
    }
}
