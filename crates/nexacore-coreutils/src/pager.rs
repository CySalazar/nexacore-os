//! `less` / `more` — pager viewport logic.
//!
//! A [`Pager`] holds an owned set of lines plus a viewport defined by a `top`
//! line index and a `page_size` (viewport height). It is a pure state machine:
//! it performs no terminal I/O and reads no input events — a front-end drives
//! it by calling the navigation methods and rendering [`Pager::view`].
//!
//! Navigation mirrors the classic pagers:
//!
//! - line scrolling ([`Pager::scroll_down`] / [`Pager::scroll_up`]),
//! - page scrolling ([`Pager::page_down`] / [`Pager::page_up`]),
//! - jump to start / end ([`Pager::jump_to_top`] / [`Pager::jump_to_bottom`]),
//! - forward search ([`Pager::search_forward`]).
//!
//! The viewport is always clamped so the top never scrolls past the last full
//! page: `top` stays within `0..=max_top` where `max_top = line_count -
//! page_size` (saturating). All arithmetic is integer add/subtract with
//! saturation — no division, no panics.

use alloc::{string::String, vec::Vec};

use crate::split_lines;

/// A scrollable, searchable viewport over a fixed set of lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pager {
    /// The full set of lines being paged.
    lines: Vec<String>,
    /// Index of the first visible line.
    top: usize,
    /// Number of lines visible at once (always >= 1).
    page_size: usize,
}

impl Pager {
    /// Create a pager over `lines` with the given viewport height.
    ///
    /// `page_size` is clamped to a minimum of `1` so a viewport always shows at
    /// least one line.
    #[must_use]
    pub fn new(lines: Vec<String>, page_size: usize) -> Self {
        Self {
            lines,
            top: 0,
            page_size: page_size.max(1),
        }
    }

    /// Create a pager by splitting `input` into lines (see
    /// [`split_lines`]).
    #[must_use]
    pub fn from_text(input: &str, page_size: usize) -> Self {
        let lines = split_lines(input).into_iter().map(String::from).collect();
        Self::new(lines, page_size)
    }

    /// The currently visible slice of lines (at most `page_size` long).
    #[must_use]
    pub fn view(&self) -> &[String] {
        let end = self
            .top
            .saturating_add(self.page_size)
            .min(self.lines.len());
        self.lines.get(self.top..end).unwrap_or(&[])
    }

    /// Index of the first visible line.
    #[must_use]
    pub const fn top(&self) -> usize {
        self.top
    }

    /// The viewport height.
    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Total number of lines held by the pager.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// The largest valid value of `top`: `line_count - page_size`, saturating
    /// to `0` when everything fits on one screen.
    #[must_use]
    pub fn max_top(&self) -> usize {
        self.lines.len().saturating_sub(self.page_size)
    }

    /// `true` when the viewport is at the very top.
    #[must_use]
    pub const fn at_top(&self) -> bool {
        self.top == 0
    }

    /// `true` when the viewport is at the last full page.
    #[must_use]
    pub fn at_bottom(&self) -> bool {
        self.top == self.max_top()
    }

    /// Scroll down by `n` lines, clamping at the bottom.
    pub fn scroll_down(&mut self, n: usize) {
        self.top = self.top.saturating_add(n).min(self.max_top());
    }

    /// Scroll up by `n` lines, clamping at the top.
    pub fn scroll_up(&mut self, n: usize) {
        self.top = self.top.saturating_sub(n);
    }

    /// Scroll down by one full page.
    pub fn page_down(&mut self) {
        self.scroll_down(self.page_size);
    }

    /// Scroll up by one full page.
    pub fn page_up(&mut self) {
        self.scroll_up(self.page_size);
    }

    /// Jump to the first line.
    pub fn jump_to_top(&mut self) {
        self.top = 0;
    }

    /// Jump to the last full page.
    pub fn jump_to_bottom(&mut self) {
        self.top = self.max_top();
    }

    /// Change the viewport height (e.g. on a terminal resize), re-clamping the
    /// current `top`. `page_size` is floored at `1`.
    pub fn resize(&mut self, page_size: usize) {
        self.page_size = page_size.max(1);
        self.top = self.top.min(self.max_top());
    }

    /// Search forward from just below the current top for the first line
    /// containing `needle`.
    ///
    /// On a hit the viewport scrolls so the matched line is visible (its index
    /// becomes the new `top`, clamped to [`max_top`](Self::max_top)) and the
    /// matched absolute line index is returned. On a miss (or an empty needle)
    /// the viewport is left unchanged and `None` is returned.
    pub fn search_forward(&mut self, needle: &str) -> Option<usize> {
        if needle.is_empty() {
            return None;
        }
        let start = self.top.saturating_add(1);
        for (index, line) in self.lines.iter().enumerate().skip(start) {
            if line.contains(needle) {
                self.top = index.min(self.max_top());
                return Some(index);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pager(n: usize, page: usize) -> Pager {
        let lines = (0..n).map(|i| alloc::format!("line{i}")).collect();
        Pager::new(lines, page)
    }

    fn view_of(p: &Pager) -> Vec<&str> {
        p.view().iter().map(String::as_str).collect()
    }

    #[test]
    fn initial_view_is_first_page() {
        let p = pager(10, 3);
        assert_eq!(view_of(&p), ["line0", "line1", "line2"]);
        assert!(p.at_top());
    }

    #[test]
    fn page_size_floored_at_one() {
        let p = pager(5, 0);
        assert_eq!(p.page_size(), 1);
        assert_eq!(view_of(&p), ["line0"]);
    }

    #[test]
    fn scroll_down_moves_viewport() {
        let mut p = pager(10, 3);
        p.scroll_down(2);
        assert_eq!(p.top(), 2);
        assert_eq!(view_of(&p), ["line2", "line3", "line4"]);
    }

    #[test]
    fn scroll_down_clamps_at_bottom() {
        let mut p = pager(5, 3);
        p.scroll_down(100);
        assert_eq!(p.top(), 2); // max_top = 5 - 3
        assert!(p.at_bottom());
        assert_eq!(view_of(&p), ["line2", "line3", "line4"]);
    }

    #[test]
    fn scroll_up_saturates_at_top() {
        let mut p = pager(10, 3);
        p.scroll_down(4);
        p.scroll_up(100);
        assert_eq!(p.top(), 0);
    }

    #[test]
    fn page_down_and_up() {
        let mut p = pager(10, 3);
        p.page_down();
        assert_eq!(p.top(), 3);
        p.page_down();
        assert_eq!(p.top(), 6);
        p.page_up();
        assert_eq!(p.top(), 3);
    }

    #[test]
    fn jump_to_top_and_bottom() {
        let mut p = pager(10, 4);
        p.jump_to_bottom();
        assert_eq!(p.top(), 6); // 10 - 4
        p.jump_to_top();
        assert_eq!(p.top(), 0);
    }

    #[test]
    fn short_content_has_zero_max_top() {
        let p = pager(2, 5);
        assert_eq!(p.max_top(), 0);
        assert!(p.at_top());
        assert!(p.at_bottom());
        assert_eq!(view_of(&p), ["line0", "line1"]);
    }

    #[test]
    fn search_forward_finds_below_top() {
        let mut p = Pager::from_text("alpha\nbeta\ngamma\nbeta\ndelta", 2);
        let hit = p.search_forward("beta");
        assert_eq!(hit, Some(1));
        assert_eq!(p.top(), 1);
    }

    #[test]
    fn search_forward_skips_current_top_line() {
        // "beta" is on line 1 (the top after the first search); searching again
        // must find the *next* occurrence at line 3, not the current one.
        let mut p = Pager::from_text("alpha\nbeta\ngamma\nbeta\ndelta", 2);
        assert_eq!(p.search_forward("beta"), Some(1));
        assert_eq!(p.search_forward("beta"), Some(3));
    }

    #[test]
    fn search_forward_clamps_top_to_max() {
        let mut p = Pager::from_text("a\nb\nc\nd\ntarget", 2);
        let hit = p.search_forward("target");
        assert_eq!(hit, Some(4));
        assert_eq!(p.top(), p.max_top()); // 5 - 2 = 3, matched line still visible
        assert_eq!(p.top(), 3);
    }

    #[test]
    fn search_forward_miss_leaves_viewport() {
        let mut p = pager(10, 3);
        p.scroll_down(2);
        assert_eq!(p.search_forward("nope"), None);
        assert_eq!(p.top(), 2);
    }

    #[test]
    fn empty_needle_is_no_op() {
        let mut p = pager(10, 3);
        p.scroll_down(2);
        assert_eq!(p.search_forward(""), None);
        assert_eq!(p.top(), 2);
    }

    #[test]
    fn resize_reclamps_top() {
        let mut p = pager(10, 3);
        p.jump_to_bottom();
        assert_eq!(p.top(), 7);
        p.resize(6);
        assert_eq!(p.page_size(), 6);
        assert_eq!(p.top(), 4); // clamped to 10 - 6
    }

    #[test]
    fn empty_pager_view_is_empty() {
        let p = Pager::from_text("", 5);
        assert_eq!(p.line_count(), 0);
        assert!(p.view().is_empty());
    }
}
