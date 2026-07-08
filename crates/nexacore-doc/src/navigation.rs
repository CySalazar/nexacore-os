//! Multi-page navigation (WS8-04.3) — continuous scroll + thumbnails.
//!
//! [`ContinuousLayout`] stacks the pages vertically (each at its already-scaled
//! pixel height, separated by a gap) and answers the queries a scroll view
//! needs: total content height, which pages intersect the viewport, which page
//! contains a given offset, and the scroll offset that brings a page to the
//! top. [`ThumbnailStrip`] is the side-rail model.

use alloc::vec::Vec;

/// A page that intersects the current viewport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisiblePage {
    /// Zero-based page index.
    pub index: usize,
    /// Y of the page top **relative to the viewport top**. Negative when the
    /// page starts above the viewport (scrolled partway through it).
    pub y_top: i32,
    /// On-screen page height in pixels.
    pub height: u32,
}

/// Vertical stack of pages with a fixed gap between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContinuousLayout {
    /// Already-scaled page heights, in document order.
    heights: Vec<u32>,
    /// Gap between consecutive pages, in pixels.
    gap: u32,
}

impl ContinuousLayout {
    /// Build a layout from per-page on-screen heights and an inter-page gap.
    #[must_use]
    pub fn new(heights: Vec<u32>, gap: u32) -> Self {
        Self { heights, gap }
    }

    /// Number of pages.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.heights.len()
    }

    /// Absolute Y of page `index`'s top within the content (0 for page 0), or
    /// `None` if out of range.
    #[must_use]
    pub fn page_top(&self, index: usize) -> Option<u64> {
        if index >= self.heights.len() {
            return None;
        }
        let mut y: u64 = 0;
        for h in self.heights.iter().take(index) {
            y = y
                .saturating_add(u64::from(*h))
                .saturating_add(u64::from(self.gap));
        }
        Some(y)
    }

    /// Total content height (sum of page heights + inter-page gaps).
    #[must_use]
    pub fn total_height(&self) -> u64 {
        if self.heights.is_empty() {
            return 0;
        }
        let pages: u64 = self.heights.iter().map(|h| u64::from(*h)).sum();
        let gaps = u64::from(self.gap).saturating_mul((self.heights.len() as u64) - 1);
        pages.saturating_add(gaps)
    }

    /// The page index containing absolute content offset `y`, or `None` if `y`
    /// falls in a gap or past the end. The first matching page wins.
    #[must_use]
    pub fn page_at(&self, y: u64) -> Option<usize> {
        let mut top: u64 = 0;
        for (i, h) in self.heights.iter().enumerate() {
            let bottom = top.saturating_add(u64::from(*h));
            if y >= top && y < bottom {
                return Some(i);
            }
            top = bottom.saturating_add(u64::from(self.gap));
        }
        None
    }

    /// The pages intersecting `[scroll_y, scroll_y + viewport_h)`, each with its
    /// top relative to the viewport. Pages are returned in document order.
    #[must_use]
    pub fn visible_pages(&self, scroll_y: u64, viewport_h: u32) -> Vec<VisiblePage> {
        let view_bottom = scroll_y.saturating_add(u64::from(viewport_h));
        let mut out = Vec::new();
        let mut top: u64 = 0;
        for (i, h) in self.heights.iter().enumerate() {
            let bottom = top.saturating_add(u64::from(*h));
            // Intersect [top, bottom) with [scroll_y, view_bottom).
            if bottom > scroll_y && top < view_bottom {
                // y_top relative to viewport = top - scroll_y (may be negative).
                let rel =
                    i64::try_from(top).unwrap_or(i64::MAX) - i64::try_from(scroll_y).unwrap_or(0);
                out.push(VisiblePage {
                    index: i,
                    y_top: i32::try_from(rel).unwrap_or(if rel < 0 { i32::MIN } else { i32::MAX }),
                    height: *h,
                });
            }
            if top >= view_bottom {
                break;
            }
            top = bottom.saturating_add(u64::from(self.gap));
        }
        out
    }

    /// Scroll offset that places page `index`'s top at the viewport top.
    #[must_use]
    pub fn scroll_to_page(&self, index: usize) -> Option<u64> {
        self.page_top(index)
    }
}

/// A thumbnail side-rail: `count` thumbnails of uniform height, one selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThumbnailStrip {
    count: usize,
    selected: usize,
    thumb_height: u32,
    gap: u32,
}

impl ThumbnailStrip {
    /// New strip over `count` pages; selection starts at page 0.
    #[must_use]
    pub fn new(count: usize, thumb_height: u32, gap: u32) -> Self {
        Self {
            count,
            selected: 0,
            thumb_height,
            gap,
        }
    }

    /// Currently selected page index.
    #[must_use]
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Select page `index`, clamped to `0..count`. Returns the new selection.
    pub fn select(&mut self, index: usize) -> usize {
        if self.count == 0 {
            self.selected = 0;
        } else {
            self.selected = index.min(self.count - 1);
        }
        self.selected
    }

    /// Move the selection by `delta` (saturating at both ends).
    pub fn step(&mut self, delta: i32) -> usize {
        let cur = self.selected as i64;
        let next = (cur + i64::from(delta)).max(0);
        self.select(usize::try_from(next).unwrap_or(0))
    }

    /// Absolute Y of thumbnail `index`'s top within the strip, or `None` if out
    /// of range.
    #[must_use]
    pub fn thumb_top(&self, index: usize) -> Option<u64> {
        if index >= self.count {
            return None;
        }
        Some((u64::from(self.thumb_height).saturating_add(u64::from(self.gap))) * index as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> ContinuousLayout {
        // 3 pages 100px tall, 10px gap.
        ContinuousLayout::new(alloc::vec![100, 100, 100], 10)
    }

    #[test]
    fn total_height_sums_pages_and_gaps() {
        // 3*100 + 2*10 = 320.
        assert_eq!(layout().total_height(), 320);
    }

    #[test]
    fn page_tops_account_for_gaps() {
        let l = layout();
        assert_eq!(l.page_top(0), Some(0));
        assert_eq!(l.page_top(1), Some(110));
        assert_eq!(l.page_top(2), Some(220));
        assert_eq!(l.page_top(3), None);
    }

    #[test]
    fn page_at_offset_handles_pages_and_gaps() {
        let l = layout();
        assert_eq!(l.page_at(0), Some(0));
        assert_eq!(l.page_at(99), Some(0));
        assert_eq!(l.page_at(105), None); // in the gap [100,110)
        assert_eq!(l.page_at(110), Some(1));
        assert_eq!(l.page_at(1000), None); // past end
    }

    #[test]
    fn visible_pages_reports_partial_pages_with_relative_tops() {
        let l = layout();
        // Scroll to y=50, viewport 120 tall → sees [50,170): page0 (top -50),
        // page1 (top 60).
        let v = l.visible_pages(50, 120);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].index, 0);
        assert_eq!(v[0].y_top, -50);
        assert_eq!(v[1].index, 1);
        assert_eq!(v[1].y_top, 60);
    }

    #[test]
    fn scroll_to_page_returns_page_top() {
        assert_eq!(layout().scroll_to_page(2), Some(220));
    }

    #[test]
    fn thumbnail_selection_clamps_and_steps() {
        let mut t = ThumbnailStrip::new(4, 80, 8);
        assert_eq!(t.selected(), 0);
        assert_eq!(t.select(2), 2);
        assert_eq!(t.select(99), 3); // clamp to last
        assert_eq!(t.step(-1), 2);
        assert_eq!(t.step(-99), 0); // saturate at 0
        assert_eq!(t.thumb_top(1), Some(88));
        assert_eq!(t.thumb_top(4), None);
    }
}
