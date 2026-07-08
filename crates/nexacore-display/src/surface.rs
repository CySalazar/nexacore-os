//! Surface types: per-window ARGB pixel buffer.
//!
//! A [`Surface`] holds the pixel content for one window.  The compositor
//! blits from it into the back buffer during [`crate::compositor::Compositor::composite`].
//!
//! # Security invariant
//!
//! [`Surface::commit`] validates that the supplied pixel slice has exactly
//! `width * height` elements.  Any other length is rejected with
//! [`crate::DisplayError::InvalidSize`] **before** any pixels are written.
//! This prevents a malicious or buggy client from causing an out-of-bounds
//! write by supplying a buffer of the wrong size (ADR-0041 D4).
//!
//! # `no_std` compatibility
//!
//! Depends only on `alloc::vec::Vec`; no `std` API is required.

use alloc::{vec, vec::Vec};

use crate::DisplayError;

// ---------------------------------------------------------------------------
// Newtypes
// ---------------------------------------------------------------------------

/// A unique identifier for a [`Surface`].
///
/// Wraps a `u32` counter; the compositor assigns these sequentially.
/// `Copy + Eq + Hash + Ord` so surfaces can be stored in collections.
///
/// # Example
///
/// ```
/// use nexacore_display::surface::SurfaceId;
/// let id = SurfaceId(1);
/// assert_eq!(id, SurfaceId(1));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SurfaceId(pub u32);

/// A unique identifier for a [`crate::window::Window`].
///
/// Wraps a `u32` counter; the [`crate::wm::WindowManager`] assigns these
/// sequentially.  `Copy + Eq + Hash + Ord` so windows can be stored in
/// ordered collections.
///
/// # Example
///
/// ```
/// use nexacore_display::surface::WindowId;
/// let id = WindowId(42);
/// assert_eq!(id, WindowId(42));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WindowId(pub u32);

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

/// Per-window ARGB pixel buffer.
///
/// Each window owns one `Surface`.  The client commits new pixel content via
/// [`Surface::commit`], which replaces the entire pixel buffer atomically
/// after validating the length.  The compositor reads pixels via
/// [`Surface::pixel`] or the full slice via [`Surface::pixels`].
///
/// Pixels are stored in `0xAARRGGBB` format (most-significant byte = alpha).
///
/// # Example
///
/// ```
/// use nexacore_display::surface::{Surface, SurfaceId};
///
/// let mut s = Surface::new(SurfaceId(1), 2, 2);
/// let pixels = [0xFFFF0000u32, 0xFF00FF00, 0xFF0000FF, 0xFFFFFFFF];
/// s.commit(&pixels).expect("correct length");
/// assert_eq!(s.pixel(0, 0), Some(0xFFFF0000));
/// assert_eq!(s.pixel(1, 1), Some(0xFFFFFFFF));
/// assert_eq!(s.pixel(2, 0), None); // out of bounds
/// ```
#[derive(Debug, Clone)]
pub struct Surface {
    /// Identifier assigned by the [`crate::wm::WindowManager`].
    pub id: SurfaceId,
    /// Width of the surface in pixels.
    pub width: u32,
    /// Height of the surface in pixels.
    pub height: u32,
    /// Raw pixel data, row-major, `0xAARRGGBB`.  Length == `width * height`.
    pixels: Vec<u32>,
}

impl Surface {
    /// Creates a new surface with all pixels zeroed (transparent black).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::surface::{Surface, SurfaceId};
    /// let s = Surface::new(SurfaceId(0), 4, 4);
    /// assert_eq!(s.pixels().len(), 16);
    /// assert!(s.pixels().iter().all(|&p| p == 0));
    /// ```
    #[must_use]
    pub fn new(id: SurfaceId, w: u32, h: u32) -> Self {
        let len = (w as usize).saturating_mul(h as usize);
        Self {
            id,
            width: w,
            height: h,
            pixels: vec![0u32; len],
        }
    }

    /// Replaces the pixel buffer with `pixels`.
    ///
    /// The supplied slice must have exactly `width * height` elements.  Any
    /// other length is rejected immediately — no partial write occurs.
    ///
    /// # Errors
    ///
    /// Returns [`DisplayError::InvalidSize`] if
    /// `pixels.len() != (width * height) as usize`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::{
    ///     DisplayError,
    ///     surface::{Surface, SurfaceId},
    /// };
    ///
    /// let mut s = Surface::new(SurfaceId(1), 2, 2);
    /// // Wrong length → error, pixels unchanged.
    /// assert!(matches!(
    ///     s.commit(&[0u32; 3]),
    ///     Err(DisplayError::InvalidSize)
    /// ));
    /// // Correct length → success.
    /// s.commit(&[0xFFFF0000u32; 4]).expect("correct length");
    /// ```
    pub fn commit(&mut self, pixels: &[u32]) -> Result<(), DisplayError> {
        let expected = (self.width as usize).saturating_mul(self.height as usize);
        if pixels.len() != expected {
            return Err(DisplayError::InvalidSize);
        }
        self.pixels.copy_from_slice(pixels);
        Ok(())
    }

    /// Returns the pixel at `(x, y)`, or `None` if out of bounds.
    ///
    /// Coordinates are zero-based; `x` must be `< width` and `y` must be
    /// `< height`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::surface::{Surface, SurfaceId};
    /// let mut s = Surface::new(SurfaceId(0), 3, 3);
    /// s.commit(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    /// assert_eq!(s.pixel(2, 1), Some(6)); // row 1, col 2
    /// assert_eq!(s.pixel(3, 0), None); // out of bounds
    /// ```
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.width || y >= self.height {
            return None;
        }
        // x < width and y < height, so index = y * width + x < width * height
        // = pixels.len().  The multiplication cannot overflow because both
        // values are u32 and we compute into usize (which is 64-bit on all
        // supported targets).
        let idx = (y as usize) * (self.width as usize) + (x as usize);
        self.pixels.get(idx).copied()
    }

    /// Returns a shared slice of all pixels, in row-major order.
    ///
    /// The length is always `width * height`.
    #[must_use]
    pub fn pixels(&self) -> &[u32] {
        &self.pixels
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_surface_is_zeroed() {
        let s = Surface::new(SurfaceId(0), 4, 4);
        assert_eq!(s.pixels().len(), 16);
        assert!(s.pixels().iter().all(|&p| p == 0));
    }

    #[test]
    fn commit_correct_length_succeeds() {
        let mut s = Surface::new(SurfaceId(1), 2, 3);
        assert!(s.commit(&[0u32; 6]).is_ok());
    }

    #[test]
    fn commit_wrong_length_is_error() {
        let mut s = Surface::new(SurfaceId(1), 2, 3);
        assert!(matches!(
            s.commit(&[0u32; 5]),
            Err(DisplayError::InvalidSize)
        ));
        assert!(matches!(
            s.commit(&[0u32; 7]),
            Err(DisplayError::InvalidSize)
        ));
        // Original buffer unchanged (still zero).
        assert!(s.pixels().iter().all(|&p| p == 0));
    }

    #[test]
    fn commit_zero_sized_surface() {
        let mut s = Surface::new(SurfaceId(0), 0, 100);
        // A zero-width surface requires an empty slice.
        assert!(s.commit(&[]).is_ok());
        assert!(matches!(s.commit(&[1u32]), Err(DisplayError::InvalidSize)));
    }

    #[test]
    fn pixel_returns_correct_value() {
        let mut s = Surface::new(SurfaceId(2), 3, 2);
        let data: Vec<u32> = (0..6).collect();
        s.commit(&data).unwrap();
        assert_eq!(s.pixel(0, 0), Some(0));
        assert_eq!(s.pixel(2, 0), Some(2));
        assert_eq!(s.pixel(0, 1), Some(3));
        assert_eq!(s.pixel(2, 1), Some(5));
    }

    #[test]
    fn pixel_out_of_bounds_is_none() {
        let s = Surface::new(SurfaceId(0), 5, 5);
        assert_eq!(s.pixel(5, 0), None);
        assert_eq!(s.pixel(0, 5), None);
        assert_eq!(s.pixel(u32::MAX, u32::MAX), None);
    }

    #[test]
    fn surface_id_ordering() {
        assert!(SurfaceId(0) < SurfaceId(1));
        assert_eq!(SurfaceId(5), SurfaceId(5));
    }

    #[test]
    fn window_id_ordering() {
        assert!(WindowId(0) < WindowId(1));
        assert_ne!(WindowId(1), WindowId(2));
    }

    #[test]
    fn surface_name_in_string_context() {
        // Ensure SurfaceId/WindowId can be used with format! in test code.
        let id = SurfaceId(7);
        assert_eq!(alloc::format!("{id:?}"), "SurfaceId(7)");
    }
}
