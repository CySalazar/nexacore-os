//! Pointer cursors: bitmaps, hotspots, and frame animation (WS7-05.3 / .4).
//!
//! A [`Cursor`] is an ARGB8888 image plus a *hotspot* — the pixel that tracks
//! the pointer position (the tip of an arrow, the center of a crosshair). An
//! [`AnimatedCursor`] is a looping sequence of frames with per-frame timing
//! (the spinning "busy" cursor). `no_std + alloc`; the compositor blits the
//! frame returned by [`AnimatedCursor::frame_at`] at the pointer location,
//! offset by the hotspot.

use alloc::vec::Vec;

/// A pointer cursor image with its hotspot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    width: u32,
    height: u32,
    hotspot_x: u32,
    hotspot_y: u32,
    pixels: Vec<u32>,
}

impl Cursor {
    /// Build a cursor from an ARGB8888 `pixels` buffer (row-major, `width ×
    /// height`).
    ///
    /// # Errors / `None`
    ///
    /// Returns `None` if `pixels.len() != width * height`, if either dimension
    /// is `0`, or if the hotspot lies outside the image.
    #[must_use]
    pub fn new(
        width: u32,
        height: u32,
        hotspot_x: u32,
        hotspot_y: u32,
        pixels: Vec<u32>,
    ) -> Option<Self> {
        if width == 0 || height == 0 {
            return None;
        }
        let expected = (width as usize).checked_mul(height as usize)?;
        if pixels.len() != expected || hotspot_x >= width || hotspot_y >= height {
            return None;
        }
        Some(Self {
            width,
            height,
            hotspot_x,
            hotspot_y,
            pixels,
        })
    }

    /// Image width in pixels.
    #[must_use]
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Image height in pixels.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Hotspot column (the pixel aligned to the pointer position).
    #[must_use]
    pub fn hotspot_x(&self) -> u32 {
        self.hotspot_x
    }

    /// Hotspot row.
    #[must_use]
    pub fn hotspot_y(&self) -> u32 {
        self.hotspot_y
    }

    /// The ARGB8888 pixel buffer (row-major).
    #[must_use]
    pub fn pixels(&self) -> &[u32] {
        &self.pixels
    }

    /// The ARGB8888 pixel at `(x, y)`, or `None` if out of bounds.
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let idx = (y as usize) * (self.width as usize) + (x as usize);
        self.pixels.get(idx).copied()
    }
}

/// One animation frame: a cursor image and how long to display it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorFrame {
    /// The frame image.
    pub cursor: Cursor,
    /// How long this frame is shown, in milliseconds (must be > 0).
    pub duration_ms: u32,
}

/// A looping animated cursor: a non-empty sequence of timed frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnimatedCursor {
    frames: Vec<CursorFrame>,
    total_ms: u32,
}

impl AnimatedCursor {
    /// Build an animated cursor from `frames`.
    ///
    /// # Errors / `None`
    ///
    /// Returns `None` if `frames` is empty, if any frame has `duration_ms == 0`,
    /// or if the total duration overflows `u32`.
    #[must_use]
    pub fn new(frames: Vec<CursorFrame>) -> Option<Self> {
        if frames.is_empty() {
            return None;
        }
        let mut total_ms: u32 = 0;
        for f in &frames {
            if f.duration_ms == 0 {
                return None;
            }
            total_ms = total_ms.checked_add(f.duration_ms)?;
        }
        Some(Self { frames, total_ms })
    }

    /// Total loop duration in milliseconds.
    #[must_use]
    pub fn total_duration_ms(&self) -> u32 {
        self.total_ms
    }

    /// Number of frames.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// The cursor to display at `time_ms` since the animation started; the
    /// sequence loops, so any time maps to a frame.
    #[must_use]
    pub fn frame_at(&self, time_ms: u32) -> &Cursor {
        let mut t = time_ms % self.total_ms;
        for f in &self.frames {
            if t < f.duration_ms {
                return &f.cursor;
            }
            t -= f.duration_ms;
        }
        // Defensive fall-through: the loop above always returns because
        // `t < total_ms == sum of durations`. `frames` is non-empty (enforced
        // by `new`), so `len - 1` is a valid index — no panic, no runtime hit.
        #[allow(clippy::indexing_slicing)]
        &self.frames[self.frames.len() - 1].cursor
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn solid(w: u32, h: u32, hx: u32, hy: u32, color: u32) -> Cursor {
        Cursor::new(w, h, hx, hy, vec![color; (w * h) as usize]).unwrap()
    }

    #[test]
    fn cursor_validates_length_and_hotspot() {
        assert!(Cursor::new(2, 2, 0, 0, vec![0; 4]).is_some());
        assert!(Cursor::new(2, 2, 0, 0, vec![0; 3]).is_none()); // wrong length
        assert!(Cursor::new(2, 2, 2, 0, vec![0; 4]).is_none()); // hotspot x oob
        assert!(Cursor::new(0, 2, 0, 0, vec![]).is_none()); // zero dim
    }

    #[test]
    fn cursor_pixel_access() {
        let pixels = vec![
            0xFF_00_00_00u32,
            0xFF_11_11_11,
            0xFF_22_22_22,
            0xFF_33_33_33,
        ];
        let c = Cursor::new(2, 2, 1, 1, pixels).unwrap();
        assert_eq!(c.pixel(0, 0), Some(0xFF_00_00_00));
        assert_eq!(c.pixel(1, 1), Some(0xFF_33_33_33));
        assert_eq!(c.pixel(2, 0), None);
        assert_eq!(c.hotspot_x(), 1);
        assert_eq!(c.hotspot_y(), 1);
    }

    #[test]
    fn animated_cursor_rejects_empty_and_zero_duration() {
        assert!(AnimatedCursor::new(vec![]).is_none());
        let bad = vec![CursorFrame {
            cursor: solid(1, 1, 0, 0, 0xFF_FF_FF_FF),
            duration_ms: 0,
        }];
        assert!(AnimatedCursor::new(bad).is_none());
    }

    #[test]
    fn animated_cursor_frame_at_loops() {
        let a = solid(1, 1, 0, 0, 0xFF_AA_00_00);
        let b = solid(1, 1, 0, 0, 0xFF_00_BB_00);
        let anim = AnimatedCursor::new(vec![
            CursorFrame {
                cursor: a.clone(),
                duration_ms: 100,
            },
            CursorFrame {
                cursor: b.clone(),
                duration_ms: 200,
            },
        ])
        .unwrap();
        assert_eq!(anim.total_duration_ms(), 300);
        assert_eq!(anim.frame_count(), 2);
        // Within frame A.
        assert_eq!(anim.frame_at(0), &a);
        assert_eq!(anim.frame_at(99), &a);
        // Within frame B.
        assert_eq!(anim.frame_at(100), &b);
        assert_eq!(anim.frame_at(299), &b);
        // Loops back to A.
        assert_eq!(anim.frame_at(300), &a);
        assert_eq!(anim.frame_at(401), &b);
    }
}
