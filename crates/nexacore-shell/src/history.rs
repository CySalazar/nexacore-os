//! Bounded command-history ring buffer.
//!
//! [`crate::history::History`] stores the most recent command lines in a fixed-capacity
//! circular buffer. When full, the oldest entry is evicted (ring wraparound).
//! It supports:
//!
//! - **Append** with optional deduplication of *consecutive* duplicates.
//! - **Index lookup** by logical position (`0` = oldest live entry).
//! - **Navigation** via [`crate::history::History::prev`] / [`crate::history::History::next`], the model that
//!   backs up-arrow / down-arrow recall: `prev` walks toward older entries and
//!   clamps at the oldest; `next` walks back toward the newest and returns
//!   `None` once it steps past it (back to the "current input" line).
//!
//! Unlike the `Vec`-based scratch history inside
//! [`crate::line_editor::LineEditor`], this is a true bounded ring: eviction is
//! O(1) and the logical order is preserved across arbitrarily many pushes.

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// A bounded, fixed-capacity command history implemented as a ring buffer.
#[derive(Debug, Clone)]
pub struct History {
    /// Backing storage used as a circular buffer.
    buf: Vec<String>,
    /// Index of the oldest entry within `buf`.
    start: usize,
    /// Number of live entries currently stored (`0..=capacity`).
    len: usize,
    /// Maximum number of entries retained before wraparound eviction.
    cap: usize,
    /// When `true`, a push equal to the newest entry is ignored.
    dedup: bool,
    /// Navigation cursor: logical index being viewed, or `None` for "current".
    cursor: Option<usize>,
}

impl History {
    /// Create a new history with the given capacity and consecutive-duplicate
    /// deduplication enabled.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_dedup(capacity, true)
    }

    /// Create a new history with an explicit dedup policy.
    #[must_use]
    pub fn with_dedup(capacity: usize, dedup: bool) -> Self {
        let cap = capacity.max(1);
        Self {
            buf: Vec::new(),
            start: 0,
            len: 0,
            cap,
            dedup,
            cursor: None,
        }
    }

    /// Number of entries currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return `true` when the history holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The maximum number of entries this history can hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Append `entry` to the history and reset navigation.
    ///
    /// Empty entries are ignored. When deduplication is enabled, an entry equal
    /// to the current newest entry is ignored. When the buffer is full the
    /// oldest entry is overwritten (ring wraparound).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::history::History;
    ///
    /// let mut h = History::new(2);
    /// h.push("a");
    /// h.push("b");
    /// h.push("c"); // evicts "a"
    /// assert_eq!(h.get(0), Some("b"));
    /// assert_eq!(h.get(1), Some("c"));
    /// ```
    pub fn push(&mut self, entry: &str) {
        // Navigation always resets on a new command, regardless of whether the
        // entry is ultimately stored.
        self.cursor = None;

        if entry.is_empty() {
            return;
        }
        if self.dedup && self.newest() == Some(entry) {
            return;
        }

        if self.len < self.cap {
            // Room to grow: place at the next slot after the current tail.
            let slot = (self.start + self.len) % self.cap;
            if let Some(existing) = self.buf.get_mut(slot) {
                *existing = entry.to_string();
            } else {
                self.buf.push(entry.to_string());
            }
            self.len += 1;
        } else {
            // Full: overwrite the oldest and advance the window.
            if let Some(oldest) = self.buf.get_mut(self.start) {
                *oldest = entry.to_string();
            }
            self.start = (self.start + 1) % self.cap;
        }
    }

    /// Look up an entry by logical index, where `0` is the oldest live entry
    /// and `len() - 1` is the newest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::history::History;
    ///
    /// let mut h = History::new(10);
    /// h.push("first");
    /// h.push("second");
    /// assert_eq!(h.get(0), Some("first"));
    /// assert_eq!(h.get(1), Some("second"));
    /// assert_eq!(h.get(2), None);
    /// ```
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&str> {
        if index >= self.len {
            return None;
        }
        let slot = (self.start + index) % self.cap;
        self.buf.get(slot).map(String::as_str)
    }

    /// The newest stored entry, or `None` when empty.
    #[must_use]
    fn newest(&self) -> Option<&str> {
        if self.len == 0 {
            None
        } else {
            self.get(self.len - 1)
        }
    }

    /// Navigate one entry towards older commands (up-arrow).
    ///
    /// The first call returns the newest entry; subsequent calls walk toward
    /// the oldest and clamp there. Returns `None` only when the history is
    /// empty.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::history::History;
    ///
    /// let mut h = History::new(10);
    /// h.push("old");
    /// h.push("new");
    /// assert_eq!(h.prev(), Some("new"));
    /// assert_eq!(h.prev(), Some("old"));
    /// assert_eq!(h.prev(), Some("old")); // clamps at oldest
    /// ```
    pub fn prev(&mut self) -> Option<&str> {
        if self.len == 0 {
            return None;
        }
        let idx = match self.cursor {
            None => self.len - 1,
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.cursor = Some(idx);
        self.get(idx)
    }

    /// Navigate one entry towards newer commands (down-arrow).
    ///
    /// Returns the next-newer entry, or `None` once navigation steps past the
    /// newest entry (returning to the pre-navigation "current input"). Also
    /// returns `None` when no navigation is in progress.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::history::History;
    ///
    /// let mut h = History::new(10);
    /// h.push("a");
    /// h.push("b");
    /// h.prev(); // "b"
    /// h.prev(); // "a"
    /// assert_eq!(h.next(), Some("b"));
    /// assert_eq!(h.next(), None); // past the newest -> current input
    /// ```
    #[allow(
        clippy::should_implement_trait,
        reason = "prev/next are the natural up/down-arrow history navigation pair, not an Iterator"
    )]
    pub fn next(&mut self) -> Option<&str> {
        let idx = self.cursor?;
        if idx + 1 < self.len {
            let new_idx = idx + 1;
            self.cursor = Some(new_idx);
            self.get(new_idx)
        } else {
            // Stepped past the newest entry: back to current input.
            self.cursor = None;
            None
        }
    }

    /// Reset navigation so the next [`prev`](Self::prev) starts at the newest.
    pub fn reset_navigation(&mut self) {
        self.cursor = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let h = History::new(10);
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert_eq!(h.capacity(), 10);
    }

    #[test]
    fn push_appends_in_order() {
        let mut h = History::new(10);
        h.push("a");
        h.push("b");
        h.push("c");
        assert_eq!(h.len(), 3);
        assert_eq!(h.get(0), Some("a"));
        assert_eq!(h.get(1), Some("b"));
        assert_eq!(h.get(2), Some("c"));
        assert_eq!(h.get(3), None);
    }

    #[test]
    fn push_skips_empty() {
        let mut h = History::new(10);
        h.push("");
        assert!(h.is_empty());
    }

    #[test]
    fn dedup_skips_consecutive_duplicates() {
        let mut h = History::new(10);
        h.push("ls");
        h.push("ls");
        assert_eq!(h.len(), 1);
        // Non-consecutive duplicates are kept.
        h.push("pwd");
        h.push("ls");
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn dedup_disabled_keeps_consecutive_duplicates() {
        let mut h = History::with_dedup(10, false);
        h.push("ls");
        h.push("ls");
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn ring_wraparound_evicts_oldest() {
        let mut h = History::new(3);
        h.push("a");
        h.push("b");
        h.push("c");
        h.push("d"); // evicts "a"
        h.push("e"); // evicts "b"
        assert_eq!(h.len(), 3);
        assert_eq!(h.get(0), Some("c"));
        assert_eq!(h.get(1), Some("d"));
        assert_eq!(h.get(2), Some("e"));
    }

    #[test]
    fn ring_wraparound_preserves_logical_order_after_many_pushes() {
        let mut h = History::new(3);
        for cmd in ["c1", "c2", "c3", "c4", "c5", "c6", "c7"] {
            h.push(cmd);
        }
        // Only the last three survive, oldest-first.
        assert_eq!(h.get(0), Some("c5"));
        assert_eq!(h.get(1), Some("c6"));
        assert_eq!(h.get(2), Some("c7"));
    }

    #[test]
    fn prev_walks_from_newest_to_oldest_then_clamps() {
        let mut h = History::new(10);
        h.push("a");
        h.push("b");
        h.push("c");
        assert_eq!(h.prev(), Some("c"));
        assert_eq!(h.prev(), Some("b"));
        assert_eq!(h.prev(), Some("a"));
        // Clamp at oldest.
        assert_eq!(h.prev(), Some("a"));
    }

    #[test]
    fn next_walks_back_towards_newest_then_none() {
        let mut h = History::new(10);
        h.push("a");
        h.push("b");
        h.push("c");
        h.prev(); // c
        h.prev(); // b
        h.prev(); // a
        assert_eq!(h.next(), Some("b"));
        assert_eq!(h.next(), Some("c"));
        // Past the newest returns to "current input" (None).
        assert_eq!(h.next(), None);
        assert_eq!(h.next(), None);
    }

    #[test]
    fn prev_on_empty_is_none() {
        let mut h = History::new(10);
        assert_eq!(h.prev(), None);
    }

    #[test]
    fn next_without_navigation_is_none() {
        let mut h = History::new(10);
        h.push("a");
        assert_eq!(h.next(), None);
    }

    #[test]
    fn push_resets_navigation() {
        let mut h = History::new(10);
        h.push("a");
        h.push("b");
        assert_eq!(h.prev(), Some("b"));
        // A new push should reset the cursor back to "newest" for next prev().
        h.push("c");
        assert_eq!(h.prev(), Some("c"));
    }

    #[test]
    fn navigation_after_wraparound_is_consistent() {
        let mut h = History::new(2);
        h.push("a");
        h.push("b");
        h.push("c"); // evicts a -> holds [b, c]
        assert_eq!(h.prev(), Some("c"));
        assert_eq!(h.prev(), Some("b"));
        assert_eq!(h.prev(), Some("b")); // clamp
    }
}
