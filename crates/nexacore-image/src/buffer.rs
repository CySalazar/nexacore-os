//! [`ImageBuffer`] — an RGBA8 pixel buffer with bounds-checked editing
//! (WS8-03.4 crop, WS8-03.5 rotate/flip).
//!
//! The buffer is the decoded, format-independent representation every edit
//! operates on. All access is `.get()`-checked (no raw indexing), and every
//! transform returns a fresh buffer, so an edit can never corrupt out-of-bounds
//! memory.

use alloc::{vec, vec::Vec};

use crate::{ImageError, Result};

/// Bytes per pixel (RGBA8).
pub const CHANNELS: usize = 4;

/// An RGBA8 image: `width * height` pixels, 4 bytes each, row-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageBuffer {
    width: u32,
    height: u32,
    /// Row-major RGBA8; length is always `width * height * 4`.
    pixels: Vec<u8>,
}

impl ImageBuffer {
    /// Create a transparent (all-zero) image of `width × height`.
    ///
    /// # Errors
    ///
    /// [`ImageError::EmptyImage`] if either dimension is zero.
    pub fn new(width: u32, height: u32) -> Result<Self> {
        Self::filled(width, height, [0, 0, 0, 0])
    }

    /// Create an image of `width × height` filled with `rgba`.
    ///
    /// # Errors
    ///
    /// [`ImageError::EmptyImage`] if either dimension is zero.
    pub fn filled(width: u32, height: u32, rgba: [u8; 4]) -> Result<Self> {
        if width == 0 || height == 0 {
            return Err(ImageError::EmptyImage);
        }
        let count = width as usize * height as usize;
        let mut pixels = Vec::with_capacity(count * CHANNELS);
        for _ in 0..count {
            pixels.extend_from_slice(&rgba);
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    /// Wrap existing RGBA8 bytes as an image.
    ///
    /// # Errors
    ///
    /// - [`ImageError::EmptyImage`] if either dimension is zero.
    /// - [`ImageError::BadBufferLength`] if `pixels.len() != width*height*4`.
    pub fn from_rgba(width: u32, height: u32, pixels: Vec<u8>) -> Result<Self> {
        if width == 0 || height == 0 {
            return Err(ImageError::EmptyImage);
        }
        if pixels.len() != width as usize * height as usize * CHANNELS {
            return Err(ImageError::BadBufferLength);
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    /// Image width in pixels.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Image height in pixels.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// The raw RGBA8 bytes.
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Consume the buffer, returning the raw RGBA8 bytes.
    #[must_use]
    pub fn into_pixels(self) -> Vec<u8> {
        self.pixels
    }

    /// Byte offset of pixel `(x, y)`, or `None` if out of bounds.
    fn offset(&self, x: u32, y: u32) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        Some((y as usize * self.width as usize + x as usize) * CHANNELS)
    }

    /// The RGBA value at `(x, y)`, or `None` if out of bounds.
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<[u8; 4]> {
        let off = self.offset(x, y)?;
        self.pixels.get(off..off + CHANNELS)?.try_into().ok()
    }

    /// Set the RGBA value at `(x, y)`. Out-of-bounds writes are ignored.
    pub fn set_pixel(&mut self, x: u32, y: u32, rgba: [u8; 4]) {
        if let Some(off) = self.offset(x, y) {
            if let Some(slice) = self.pixels.get_mut(off..off + CHANNELS) {
                slice.copy_from_slice(&rgba);
            }
        }
    }

    /// Crop the rectangle `(x, y, w, h)` into a new image (WS8-03.4).
    ///
    /// # Errors
    ///
    /// - [`ImageError::EmptyImage`] if `w == 0` or `h == 0`.
    /// - [`ImageError::OutOfBounds`] if the rectangle exceeds the image.
    pub fn crop(&self, x: u32, y: u32, w: u32, h: u32) -> Result<Self> {
        if w == 0 || h == 0 {
            return Err(ImageError::EmptyImage);
        }
        // `checked_add` guards against u32 overflow on the far edge.
        let x_end = x.checked_add(w).ok_or(ImageError::OutOfBounds)?;
        let y_end = y.checked_add(h).ok_or(ImageError::OutOfBounds)?;
        if x_end > self.width || y_end > self.height {
            return Err(ImageError::OutOfBounds);
        }
        let mut out = Vec::with_capacity(w as usize * h as usize * CHANNELS);
        for row in y..y_end {
            let row_start = (row as usize * self.width as usize + x as usize) * CHANNELS;
            let row_end = row_start + w as usize * CHANNELS;
            // `offset` math is bounds-checked above, so the slice always exists;
            // `.get()` keeps the access panic-free regardless.
            if let Some(slice) = self.pixels.get(row_start..row_end) {
                out.extend_from_slice(slice);
            }
        }
        Self::from_rgba(w, h, out)
    }

    /// A new image rotated 90° clockwise (WS8-03.5).
    #[must_use]
    pub fn rotate90(&self) -> Self {
        let (w, h) = (self.width, self.height);
        let mut out = vec![0u8; self.pixels.len()];
        let new_w = h;
        for y in 0..h {
            for x in 0..w {
                if let Some(px) = self.pixel(x, y) {
                    // (x, y) -> (h-1-y, x) in the rotated (h × w) image.
                    let nx = h - 1 - y;
                    let ny = x;
                    let off = (ny as usize * new_w as usize + nx as usize) * CHANNELS;
                    if let Some(slot) = out.get_mut(off..off + CHANNELS) {
                        slot.copy_from_slice(&px);
                    }
                }
            }
        }
        Self {
            width: h,
            height: w,
            pixels: out,
        }
    }

    /// A new image rotated 180°.
    #[must_use]
    pub fn rotate180(&self) -> Self {
        self.rotate90().rotate90()
    }

    /// A new image rotated 270° clockwise (90° counter-clockwise).
    #[must_use]
    pub fn rotate270(&self) -> Self {
        self.rotate90().rotate90().rotate90()
    }

    /// A new image mirrored left-to-right (WS8-03.5).
    #[must_use]
    pub fn flip_horizontal(&self) -> Self {
        let mut out = self.clone();
        for y in 0..self.height {
            for x in 0..self.width {
                if let Some(px) = self.pixel(self.width - 1 - x, y) {
                    out.set_pixel(x, y, px);
                }
            }
        }
        out
    }

    /// A new image mirrored top-to-bottom (WS8-03.5).
    #[must_use]
    pub fn flip_vertical(&self) -> Self {
        let mut out = self.clone();
        for y in 0..self.height {
            for x in 0..self.width {
                if let Some(px) = self.pixel(x, self.height - 1 - y) {
                    out.set_pixel(x, y, px);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2×2 image with four distinct corner colors for transform checks.
    fn quad() -> ImageBuffer {
        // (0,0)=red (1,0)=green / (0,1)=blue (1,1)=white
        let pixels = alloc::vec![
            255, 0, 0, 255, 0, 255, 0, 255, // row 0
            0, 0, 255, 255, 255, 255, 255, 255, // row 1
        ];
        ImageBuffer::from_rgba(2, 2, pixels).unwrap()
    }

    #[test]
    fn from_rgba_validates_length() {
        assert_eq!(
            ImageBuffer::from_rgba(2, 2, alloc::vec![0; 8]).unwrap_err(),
            ImageError::BadBufferLength
        );
        assert!(ImageBuffer::from_rgba(2, 2, alloc::vec![0; 16]).is_ok());
    }

    #[test]
    fn empty_dimensions_rejected() {
        assert_eq!(ImageBuffer::new(0, 4).unwrap_err(), ImageError::EmptyImage);
        assert_eq!(ImageBuffer::new(4, 0).unwrap_err(), ImageError::EmptyImage);
    }

    #[test]
    fn pixel_get_set_is_bounds_checked() {
        let mut img = ImageBuffer::new(3, 2).unwrap();
        assert_eq!(img.pixel(0, 0), Some([0, 0, 0, 0]));
        assert_eq!(img.pixel(3, 0), None);
        img.set_pixel(2, 1, [1, 2, 3, 4]);
        assert_eq!(img.pixel(2, 1), Some([1, 2, 3, 4]));
        // Out-of-bounds write is a silent no-op (no panic, no corruption).
        img.set_pixel(99, 99, [9, 9, 9, 9]);
        assert_eq!(img.pixel(2, 1), Some([1, 2, 3, 4]));
    }

    #[test]
    fn crop_extracts_region() {
        let img = quad();
        let c = img.crop(1, 0, 1, 2).unwrap();
        assert_eq!((c.width(), c.height()), (1, 2));
        assert_eq!(c.pixel(0, 0), Some([0, 255, 0, 255])); // green
        assert_eq!(c.pixel(0, 1), Some([255, 255, 255, 255])); // white
    }

    #[test]
    fn crop_rejects_out_of_bounds() {
        let img = quad();
        assert_eq!(img.crop(1, 1, 2, 2).unwrap_err(), ImageError::OutOfBounds);
        assert_eq!(img.crop(0, 0, 0, 1).unwrap_err(), ImageError::EmptyImage);
    }

    #[test]
    fn rotate90_moves_corners_clockwise() {
        let r = quad().rotate90();
        assert_eq!((r.width(), r.height()), (2, 2));
        // top-left of the rotated image is the original bottom-left (blue).
        assert_eq!(r.pixel(0, 0), Some([0, 0, 255, 255]));
        // top-right is the original top-left (red).
        assert_eq!(r.pixel(1, 0), Some([255, 0, 0, 255]));
    }

    #[test]
    fn four_rotations_are_identity() {
        let img = quad();
        let back = img.rotate90().rotate90().rotate90().rotate90();
        assert_eq!(back, img);
    }

    #[test]
    fn rotate180_matches_double_rotate90() {
        let img = quad();
        assert_eq!(img.rotate180(), img.rotate90().rotate90());
    }

    #[test]
    fn rotate90_on_non_square_swaps_dimensions() {
        let img = ImageBuffer::new(4, 2).unwrap();
        let r = img.rotate90();
        assert_eq!((r.width(), r.height()), (2, 4));
    }

    #[test]
    fn flip_horizontal_mirrors_columns() {
        let f = quad().flip_horizontal();
        assert_eq!(f.pixel(0, 0), Some([0, 255, 0, 255])); // was top-right green
        assert_eq!(f.pixel(1, 0), Some([255, 0, 0, 255])); // was top-left red
    }

    #[test]
    fn flip_vertical_mirrors_rows() {
        let f = quad().flip_vertical();
        assert_eq!(f.pixel(0, 0), Some([0, 0, 255, 255])); // was bottom-left blue
        assert_eq!(f.pixel(0, 1), Some([255, 0, 0, 255])); // was top-left red
    }

    #[test]
    fn double_flip_is_identity() {
        let img = quad();
        assert_eq!(img.flip_horizontal().flip_horizontal(), img);
        assert_eq!(img.flip_vertical().flip_vertical(), img);
    }
}
