//! Page rendering + cache (WS8-04.2).
//!
//! The actual PDF→pixels rasterization is the vetted, library-gated
//! [`PdfRasterizer`] (re-exported from `nexacore-print`, where the print
//! pipeline already drives it). This module adds the viewer-side concern: a
//! bounded **render cache** keyed by `(page index, dpi)` so scrolling back to a
//! page — or re-rendering at the same zoom — does not re-run the rasterizer.

use alloc::vec::Vec;

pub use nexacore_print::{
    pwg::ColorSpace,
    render::{PdfRasterizer, RasterPage, RenderError},
};

/// Cache key: page index + the dpi it was rasterized at (zoom maps to dpi).
type Key = (usize, u32);

struct CacheEntry {
    key: Key,
    page: RasterPage,
}

/// A bounded most-recently-used cache of rasterized pages.
///
/// Capacity is the maximum number of `(page, dpi)` renders kept; the
/// least-recently-used entry is evicted when full. Capacity is clamped to at
/// least 1.
pub struct PageCache {
    entries: Vec<CacheEntry>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

impl PageCache {
    /// New cache holding up to `capacity` rendered pages (min 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity: capacity.max(1),
            hits: 0,
            misses: 0,
        }
    }

    /// Number of cached renders.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Cache hits / misses since construction (diagnostics + tests).
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    /// Whether `(index, dpi)` is currently cached.
    #[must_use]
    pub fn contains(&self, index: usize, dpi: u32) -> bool {
        self.entries.iter().any(|e| e.key == (index, dpi))
    }

    /// Drop all cached renders (e.g. on document close).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return the rasterized page for `(index, dpi)`, rendering it through
    /// `rasterizer` on a miss and caching the result (evicting the LRU entry
    /// when full). A hit moves the entry to most-recently-used.
    ///
    /// # Errors
    ///
    /// Propagates the rasterizer's [`RenderError`] (the cache is unchanged on
    /// error).
    pub fn render<R: PdfRasterizer>(
        &mut self,
        rasterizer: &R,
        pdf: &[u8],
        index: usize,
        dpi: u32,
        color_space: ColorSpace,
    ) -> Result<&RasterPage, RenderError> {
        let key = (index, dpi);
        if let Some(pos) = self.entries.iter().position(|e| e.key == key) {
            self.hits += 1;
            // Promote to most-recently-used (move to the back).
            let entry = self.entries.remove(pos);
            self.entries.push(entry);
        } else {
            let page = rasterizer.rasterize(pdf, index, dpi, color_space)?;
            self.misses += 1;
            if self.entries.len() >= self.capacity && !self.entries.is_empty() {
                // Evict least-recently-used (front).
                self.entries.remove(0);
            }
            self.entries.push(CacheEntry { key, page });
        }
        // The just-touched entry is at the back.
        self.entries
            .last()
            .map(|e| &e.page)
            .ok_or(RenderError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use nexacore_print::pwg::PageGeometry;

    use super::*;

    /// Counts how many times `rasterize` ran, to prove the cache short-circuits.
    struct CountingRasterizer {
        calls: core::cell::Cell<u32>,
        pages: usize,
    }
    impl PdfRasterizer for CountingRasterizer {
        fn page_count(&self, _pdf: &[u8]) -> usize {
            self.pages
        }
        fn rasterize(
            &self,
            _pdf: &[u8],
            index: usize,
            dpi: u32,
            color_space: ColorSpace,
        ) -> Result<RasterPage, RenderError> {
            if index >= self.pages {
                return Err(RenderError::NoSuchPage);
            }
            self.calls.set(self.calls.get() + 1);
            let geometry = PageGeometry {
                width: 2,
                height: 2,
                bits_per_color: 8,
                color_space,
                dpi,
            };
            let len = geometry.bytes_per_line() as usize * geometry.height as usize;
            Ok(RasterPage {
                geometry,
                data: alloc::vec![0xCD; len],
            })
        }
    }

    fn rasterizer(pages: usize) -> CountingRasterizer {
        CountingRasterizer {
            calls: core::cell::Cell::new(0),
            pages,
        }
    }

    #[test]
    fn second_render_of_same_key_is_a_cache_hit() {
        let r = rasterizer(3);
        let mut cache = PageCache::new(4);
        cache.render(&r, b"pdf", 0, 150, ColorSpace::Srgb).unwrap();
        cache.render(&r, b"pdf", 0, 150, ColorSpace::Srgb).unwrap();
        assert_eq!(r.calls.get(), 1, "second render must hit the cache");
        assert_eq!(cache.stats(), (1, 1));
    }

    #[test]
    fn different_dpi_is_a_distinct_entry() {
        let r = rasterizer(3);
        let mut cache = PageCache::new(4);
        cache.render(&r, b"pdf", 0, 150, ColorSpace::Srgb).unwrap();
        cache.render(&r, b"pdf", 0, 300, ColorSpace::Srgb).unwrap();
        assert_eq!(r.calls.get(), 2);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn lru_eviction_when_capacity_exceeded() {
        let r = rasterizer(5);
        let mut cache = PageCache::new(2);
        cache.render(&r, b"pdf", 0, 150, ColorSpace::Srgb).unwrap(); // [0]
        cache.render(&r, b"pdf", 1, 150, ColorSpace::Srgb).unwrap(); // [0,1]
        cache.render(&r, b"pdf", 2, 150, ColorSpace::Srgb).unwrap(); // evict 0 → [1,2]
        assert!(!cache.contains(0, 150));
        assert!(cache.contains(1, 150));
        assert!(cache.contains(2, 150));
        // Re-rendering page 0 is a miss again (it was evicted).
        cache.render(&r, b"pdf", 0, 150, ColorSpace::Srgb).unwrap();
        assert_eq!(r.calls.get(), 4);
    }

    #[test]
    fn hit_promotes_entry_so_it_survives_eviction() {
        let r = rasterizer(5);
        let mut cache = PageCache::new(2);
        cache.render(&r, b"pdf", 0, 150, ColorSpace::Srgb).unwrap(); // [0]
        cache.render(&r, b"pdf", 1, 150, ColorSpace::Srgb).unwrap(); // [0,1]
        cache.render(&r, b"pdf", 0, 150, ColorSpace::Srgb).unwrap(); // hit → [1,0]
        cache.render(&r, b"pdf", 2, 150, ColorSpace::Srgb).unwrap(); // evict 1 → [0,2]
        assert!(cache.contains(0, 150), "recently-used page 0 survives");
        assert!(!cache.contains(1, 150), "page 1 was LRU and evicted");
    }

    #[test]
    fn render_error_leaves_cache_unchanged() {
        let r = rasterizer(1);
        let mut cache = PageCache::new(4);
        assert_eq!(
            cache.render(&r, b"pdf", 9, 150, ColorSpace::Srgb).err(),
            Some(RenderError::NoSuchPage)
        );
        assert!(cache.is_empty());
    }
}
