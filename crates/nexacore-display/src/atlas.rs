//! GPU glyph atlas cache (WS7-03.9).
//!
//! The compositor rasterizes a glyph once, then caches its coverage bitmap in a
//! single large GPU texture (the *atlas*) so subsequent frames blit from the
//! texture instead of re-rasterizing. This module is the **host-testable core**
//! of that cache:
//!
//! * [`AtlasAllocator`] — a shelf (row) packer that places glyph rectangles into
//!   a fixed-size texture; glyphs are short and wide, so packing them into rows
//!   of similar height wastes little space.
//! * [`GlyphAtlas`] — a [`GlyphKey`] → [`AtlasRect`] cache layered on the
//!   allocator. On a miss it allocates a slot and uploads the bitmap through the
//!   [`AtlasUpload`] trait; on a hit it returns the cached rectangle and uploads
//!   nothing.
//!
//! The actual GPU texture write lives behind [`AtlasUpload`], so the packing and
//! caching logic is fully deterministic and host-verifiable with a mock
//! uploader — no GPU or `unsafe` is involved here.
//!
//! `no_std + alloc` (uses [`alloc::collections::BTreeMap`] and `Vec`).

// usize bitmap dimensions are narrowed to the u32 texel coordinates the GPU
// uses; glyph bitmaps are far smaller than u32::MAX, so the cast cannot lose
// data in practice.
#![allow(clippy::cast_possible_truncation)]

use alloc::{collections::BTreeMap, vec::Vec};

use crate::raster::GlyphBitmap;

/// Texels of padding reserved around every packed glyph, so bilinear sampling of
/// one glyph never bleeds coverage from its neighbour.
const PADDING: u32 = 1;

/// A rectangular placement inside the atlas texture, in texels (top-left origin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtlasRect {
    /// X texel of the rectangle's left edge.
    pub x: u32,
    /// Y texel of the rectangle's top edge.
    pub y: u32,
    /// Width in texels.
    pub width: u32,
    /// Height in texels.
    pub height: u32,
}

impl AtlasRect {
    /// A zero-area rectangle (used for whitespace glyphs that occupy no texels).
    const ZERO: Self = Self {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    };

    /// `true` if `self` and `other` share any interior texel.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        let x_overlap = self.x < other.x + other.width && other.x < self.x + self.width;
        let y_overlap = self.y < other.y + other.height && other.y < self.y + self.height;
        x_overlap && y_overlap && self.width != 0 && self.height != 0
    }
}

/// Identifies a cached glyph: a glyph index at a quantized pixel size and a
/// subpixel-position variant.
///
/// `px_per_em` is the size rounded to whole pixels and `subpixel` selects the
/// fractional-position phase (WS7-03.7), so the same glyph rendered at different
/// sub-pixel offsets occupies distinct cache slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GlyphKey {
    /// Glyph index within the font.
    pub glyph_id: u16,
    /// Pixel size, rounded to whole pixels.
    pub px_per_em: u16,
    /// Subpixel-position phase (0 when not subpixel-positioned).
    pub subpixel: u8,
}

/// One packed row of the atlas: glyphs of comparable height share a shelf.
#[derive(Debug, Clone, Copy)]
struct Shelf {
    /// Y texel of the shelf's top edge.
    top: u32,
    /// Shelf height in texels (the tallest glyph placed so far).
    height: u32,
    /// Next free X texel within the shelf.
    x: u32,
}

/// A shelf (row) packer placing glyph rectangles into a fixed-size texture.
///
/// A glyph is placed in the first existing shelf that is tall enough and has
/// horizontal room; otherwise a new shelf is opened below the last one. When no
/// shelf fits and no vertical room remains, [`AtlasAllocator::alloc`] returns
/// `None` and the caller should [`AtlasAllocator::clear`] (or evict) and retry.
#[derive(Debug, Clone)]
pub struct AtlasAllocator {
    width: u32,
    height: u32,
    shelves: Vec<Shelf>,
    /// Y texel just below the last shelf — where the next new shelf starts.
    bottom: u32,
}

impl AtlasAllocator {
    /// Creates an allocator for a `width` × `height` texel atlas.
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            shelves: Vec::new(),
            bottom: 0,
        }
    }

    /// Atlas width in texels.
    #[must_use]
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Atlas height in texels.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Reserves a `w` × `h` rectangle (plus padding), or `None` if the atlas is
    /// full. A zero-area request yields `AtlasRect::ZERO`.
    pub fn alloc(&mut self, w: u32, h: u32) -> Option<AtlasRect> {
        if w == 0 || h == 0 {
            return Some(AtlasRect::ZERO);
        }
        let pw = w + PADDING;
        let ph = h + PADDING;
        if pw > self.width {
            return None;
        }

        // First existing shelf that is tall enough and still has room.
        for shelf in &mut self.shelves {
            if h <= shelf.height && shelf.x + pw <= self.width {
                let rect = AtlasRect {
                    x: shelf.x,
                    y: shelf.top,
                    width: w,
                    height: h,
                };
                shelf.x += pw;
                return Some(rect);
            }
        }

        // Otherwise open a new shelf below the last one if it fits vertically.
        if self.bottom + ph <= self.height {
            let top = self.bottom;
            self.shelves.push(Shelf {
                top,
                height: h,
                x: pw,
            });
            self.bottom += ph;
            return Some(AtlasRect {
                x: 0,
                y: top,
                width: w,
                height: h,
            });
        }

        None
    }

    /// Frees every shelf, returning the atlas to its empty state.
    pub fn clear(&mut self) {
        self.shelves.clear();
        self.bottom = 0;
    }
}

/// Uploads a rasterized glyph's coverage into the GPU atlas texture.
///
/// This is the single effectful seam of the atlas: implementors copy
/// `bitmap.coverage` into the texture region described by `rect`. The cache
/// itself never touches the GPU, which keeps its logic host-testable.
pub trait AtlasUpload {
    /// Writes `bitmap`'s coverage into the atlas texture at `rect`.
    fn upload(&mut self, rect: AtlasRect, bitmap: &GlyphBitmap);
}

/// A glyph cache mapping [`GlyphKey`]s to packed [`AtlasRect`]s.
///
/// On a miss the glyph is allocated a slot and uploaded once; on a hit the
/// cached rectangle is returned and nothing is re-uploaded.
#[derive(Debug, Clone)]
pub struct GlyphAtlas {
    alloc: AtlasAllocator,
    map: BTreeMap<GlyphKey, AtlasRect>,
}

impl GlyphAtlas {
    /// Creates a glyph cache backed by a `width` × `height` texel atlas.
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            alloc: AtlasAllocator::new(width, height),
            map: BTreeMap::new(),
        }
    }

    /// Number of distinct glyphs currently cached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if no glyph is cached yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// `true` if `key` is already cached.
    #[must_use]
    pub fn contains(&self, key: GlyphKey) -> bool {
        self.map.contains_key(&key)
    }

    /// The cached rectangle for `key`, if present.
    #[must_use]
    pub fn get(&self, key: GlyphKey) -> Option<AtlasRect> {
        self.map.get(&key).copied()
    }

    /// Returns the atlas rectangle for `key`, allocating and uploading `bitmap`
    /// on a cache miss.
    ///
    /// Returns `None` only when the glyph does not fit and the atlas is full;
    /// the caller should [`GlyphAtlas::clear`] (or evict) and retry. An empty
    /// `bitmap` (whitespace) is cached as `AtlasRect::ZERO` without an upload.
    pub fn get_or_insert<U: AtlasUpload>(
        &mut self,
        key: GlyphKey,
        bitmap: &GlyphBitmap,
        uploader: &mut U,
    ) -> Option<AtlasRect> {
        if let Some(&rect) = self.map.get(&key) {
            return Some(rect);
        }
        if bitmap.is_empty() {
            self.map.insert(key, AtlasRect::ZERO);
            return Some(AtlasRect::ZERO);
        }
        let rect = self
            .alloc
            .alloc(bitmap.width as u32, bitmap.height as u32)?;
        uploader.upload(rect, bitmap);
        self.map.insert(key, rect);
        Some(rect)
    }

    /// Evicts every cached glyph and frees the atlas.
    pub fn clear(&mut self) {
        self.alloc.clear();
        self.map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock uploader that records every `(rect, width, height)` it is asked to
    /// write, so tests can assert exactly which glyphs hit the "GPU".
    struct RecordingUploader {
        uploads: Vec<(AtlasRect, usize, usize)>,
    }

    impl RecordingUploader {
        fn new() -> Self {
            Self {
                uploads: Vec::new(),
            }
        }
    }

    impl AtlasUpload for RecordingUploader {
        fn upload(&mut self, rect: AtlasRect, bitmap: &GlyphBitmap) {
            self.uploads.push((rect, bitmap.width, bitmap.height));
        }
    }

    fn bmp(w: usize, h: usize) -> GlyphBitmap {
        GlyphBitmap {
            width: w,
            height: h,
            coverage: alloc::vec![255u8; w * h],
            left: 0,
            top: 0,
        }
    }

    fn key(glyph_id: u16) -> GlyphKey {
        GlyphKey {
            glyph_id,
            px_per_em: 16,
            subpixel: 0,
        }
    }

    #[test]
    fn rects_stay_in_bounds_and_never_overlap() {
        let mut a = AtlasAllocator::new(64, 64);
        let mut rects = Vec::new();
        for _ in 0..12 {
            if let Some(r) = a.alloc(10, 10) {
                assert!(r.x + r.width <= a.width());
                assert!(r.y + r.height <= a.height());
                rects.push(r);
            }
        }
        assert!(rects.len() >= 2);
        for (i, ri) in rects.iter().enumerate() {
            for rj in &rects[i + 1..] {
                assert!(!ri.overlaps(rj), "overlap between {ri:?} and {rj:?}");
            }
        }
    }

    #[test]
    fn equal_height_glyphs_share_a_shelf() {
        let mut a = AtlasAllocator::new(64, 64);
        let r0 = a.alloc(10, 10).unwrap();
        let r1 = a.alloc(10, 10).unwrap();
        assert_eq!(r0.y, r1.y, "same-height glyphs should share a shelf row");
        assert!(r1.x >= r0.x + r0.width);
    }

    #[test]
    fn new_shelf_opens_when_row_is_full() {
        // Width 20 fits one padded 10px glyph per row (11 + 11 > 20).
        let mut a = AtlasAllocator::new(20, 64);
        let r0 = a.alloc(10, 10).unwrap();
        let r1 = a.alloc(10, 10).unwrap();
        assert_eq!(r0.y, 0);
        assert!(
            r1.y >= r0.y + r0.height,
            "second glyph should start a new row"
        );
    }

    #[test]
    fn zero_area_request_is_zero_rect() {
        let mut a = AtlasAllocator::new(32, 32);
        assert_eq!(a.alloc(0, 8), Some(AtlasRect::ZERO));
        assert_eq!(a.alloc(8, 0), Some(AtlasRect::ZERO));
    }

    #[test]
    fn too_wide_glyph_does_not_fit() {
        let mut a = AtlasAllocator::new(16, 64);
        assert_eq!(a.alloc(20, 8), None);
    }

    #[test]
    fn cache_hit_does_not_reupload() {
        let mut atlas = GlyphAtlas::new(128, 128);
        let mut up = RecordingUploader::new();
        let g = bmp(12, 16);

        let r0 = atlas.get_or_insert(key(7), &g, &mut up).unwrap();
        let r1 = atlas.get_or_insert(key(7), &g, &mut up).unwrap();
        assert_eq!(r0, r1, "same key returns the same rect");
        assert_eq!(up.uploads.len(), 1, "second lookup must be a cache hit");
        assert_eq!(atlas.len(), 1);
        assert!(atlas.contains(key(7)));
    }

    #[test]
    fn distinct_keys_get_distinct_uploads() {
        let mut atlas = GlyphAtlas::new(128, 128);
        let mut up = RecordingUploader::new();
        let r0 = atlas.get_or_insert(key(1), &bmp(10, 10), &mut up).unwrap();
        let r1 = atlas.get_or_insert(key(2), &bmp(10, 10), &mut up).unwrap();
        assert_ne!(r0, r1);
        assert_eq!(up.uploads.len(), 2);
        assert_eq!(atlas.len(), 2);
    }

    #[test]
    fn empty_glyph_is_cached_without_upload() {
        let mut atlas = GlyphAtlas::new(64, 64);
        let mut up = RecordingUploader::new();
        let r = atlas
            .get_or_insert(key(3), &GlyphBitmap::empty(), &mut up)
            .unwrap();
        assert_eq!(r, AtlasRect::ZERO);
        assert!(up.uploads.is_empty(), "whitespace must not touch the GPU");
        assert!(atlas.contains(key(3)));
    }

    #[test]
    fn full_atlas_returns_none_then_clear_recovers() {
        // Width 20 holds one padded 10px glyph per row (11 + 11 > 20); height 22
        // holds exactly two such rows (11 + 11 = 22), so the third glyph fails.
        let mut atlas = GlyphAtlas::new(20, 22);
        let mut up = RecordingUploader::new();
        assert!(atlas.get_or_insert(key(1), &bmp(10, 10), &mut up).is_some());
        assert!(atlas.get_or_insert(key(2), &bmp(10, 10), &mut up).is_some());
        assert!(
            atlas.get_or_insert(key(3), &bmp(10, 10), &mut up).is_none(),
            "third glyph must not fit"
        );
        atlas.clear();
        assert!(atlas.is_empty());
        assert!(
            atlas.get_or_insert(key(3), &bmp(10, 10), &mut up).is_some(),
            "clear() must free the atlas"
        );
    }
}
