//! Axis-aligned rectangle types and damage-tracking for the compositor.
//!
//! This module provides two primitives used throughout `nexacore-display`:
//!
//! * [`Rect`] — an axis-aligned rectangle with a signed origin (so a window
//!   partially off the top-left edge is representable) and unsigned dimensions.
//!   All geometry arithmetic uses `i64` intermediates for the right/bottom
//!   edges to avoid overflow on extreme inputs from untrusted clients.
//!
//! * [`DamageRegion`] — a bounded set of dirty screen rectangles.  The
//!   compositor accumulates damage as windows move, resize, or receive new
//!   pixel content, and [`crate::compositor::Compositor::composite`] repaints only those areas.
//!   The set is capped at [`MAX_DAMAGE_RECTS`] entries; once the cap would be
//!   exceeded the entire set is collapsed to its bounding box so that a flood
//!   of tiny client damage rects cannot exhaust memory or degrade performance
//!   unboundedly (ADR-0041 D2).
//!
//! # `no_std` compatibility
//!
//! Both types use only `alloc::vec::Vec`; no `std` API is required.

use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Rect
// ---------------------------------------------------------------------------

/// An axis-aligned rectangle with a signed origin and unsigned dimensions.
///
/// The origin `(x, y)` may be negative so that windows whose top-left corner
/// is partially off the left or top edge of the screen are representable.
/// `w` and `h` are unsigned: a rectangle with `w == 0` or `h == 0` is
/// considered *empty* (see [`Rect::is_empty`]).
///
/// All right/bottom edge computations use `i64` to prevent overflow when
/// client-supplied values are near `i32::MIN` or `i32::MAX`.
///
/// # Example
///
/// ```
/// use nexacore_display::geometry::Rect;
///
/// let r = Rect {
///     x: 10,
///     y: 20,
///     w: 100,
///     h: 50,
/// };
/// assert_eq!(r.right(), 110);
/// assert_eq!(r.bottom(), 70);
/// assert!(r.contains_point(10, 20));
/// assert!(!r.contains_point(110, 20)); // right edge is exclusive
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rect {
    /// Horizontal offset of the left edge, in pixels. May be negative.
    pub x: i32,
    /// Vertical offset of the top edge, in pixels. May be negative.
    pub y: i32,
    /// Width in pixels. Zero means the rectangle is empty.
    pub w: u32,
    /// Height in pixels. Zero means the rectangle is empty.
    pub h: u32,
}

impl Rect {
    /// Returns the exclusive right edge (`x + w`) as `i64`.
    ///
    /// Using `i64` prevents overflow when `x` is near `i32::MAX` or `w` is
    /// large.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// assert_eq!(
    ///     Rect {
    ///         x: i32::MAX,
    ///         y: 0,
    ///         w: 1,
    ///         h: 1
    ///     }
    ///     .right(),
    ///     i32::MAX as i64 + 1
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn right(&self) -> i64 {
        i64::from(self.x) + i64::from(self.w)
    }

    /// Returns the exclusive bottom edge (`y + h`) as `i64`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// assert_eq!(
    ///     Rect {
    ///         x: 0,
    ///         y: i32::MAX,
    ///         w: 1,
    ///         h: 1
    ///     }
    ///     .bottom(),
    ///     i32::MAX as i64 + 1
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn bottom(&self) -> i64 {
        i64::from(self.y) + i64::from(self.h)
    }

    /// Returns `true` if the rectangle has zero area (`w == 0` or `h == 0`).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// assert!(
    ///     Rect {
    ///         x: 0,
    ///         y: 0,
    ///         w: 0,
    ///         h: 10
    ///     }
    ///     .is_empty()
    /// );
    /// assert!(
    ///     !Rect {
    ///         x: 0,
    ///         y: 0,
    ///         w: 1,
    ///         h: 1
    ///     }
    ///     .is_empty()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.w == 0 || self.h == 0
    }

    /// Returns the area in pixels (`w as u64 * h as u64`).
    ///
    /// Using `u64` avoids overflow for large rectangles (e.g. 4096×4096 =
    /// 16 777 216, which fits in `u32`, but a pathological 65535×65535 would
    /// not).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// assert_eq!(
    ///     Rect {
    ///         x: 0,
    ///         y: 0,
    ///         w: 1920,
    ///         h: 1080
    ///     }
    ///     .area(),
    ///     2_073_600
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn area(&self) -> u64 {
        u64::from(self.w) * u64::from(self.h)
    }

    /// Returns `true` if `(px, py)` lies strictly inside the rectangle.
    ///
    /// The rectangle is half-open: `x <= px < x + w` and `y <= py < y + h`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// let r = Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 10,
    ///     h: 10,
    /// };
    /// assert!(r.contains_point(0, 0));
    /// assert!(r.contains_point(9, 9));
    /// assert!(!r.contains_point(10, 0)); // right edge exclusive
    /// assert!(!r.contains_point(0, 10)); // bottom edge exclusive
    /// ```
    #[inline]
    #[must_use]
    pub fn contains_point(&self, px: i32, py: i32) -> bool {
        let point_x = i64::from(px);
        let point_y = i64::from(py);
        point_x >= i64::from(self.x)
            && point_x < self.right()
            && point_y >= i64::from(self.y)
            && point_y < self.bottom()
    }

    /// Returns the intersection of `self` and `other`, or `None` if they do
    /// not overlap (including the case where the intersection would be empty).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// let a = Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 10,
    ///     h: 10,
    /// };
    /// let b = Rect {
    ///     x: 5,
    ///     y: 5,
    ///     w: 10,
    ///     h: 10,
    /// };
    /// let i = a.intersect(&b).unwrap();
    /// assert_eq!(
    ///     i,
    ///     Rect {
    ///         x: 5,
    ///         y: 5,
    ///         w: 5,
    ///         h: 5
    ///     }
    /// );
    ///
    /// let c = Rect {
    ///     x: 20,
    ///     y: 20,
    ///     w: 5,
    ///     h: 5,
    /// };
    /// assert!(a.intersect(&c).is_none());
    /// ```
    #[must_use]
    // Casts are safe by construction:
    // * `x0 = max(self.x, other.x)` is in [i32::MIN, i32::MAX] so `x0 as i32` is exact.
    // * `x1 - x0 > 0` (checked above) so the subtraction is positive → sign-loss cast to u64 is safe.
    // * `.min(u64::from(u32::MAX))` bounds the value to [0, u32::MAX] → the u64→u32 cast is exact.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let x0 = i64::from(self.x).max(i64::from(other.x));
        let y0 = i64::from(self.y).max(i64::from(other.y));
        let x1 = self.right().min(other.right());
        let y1 = self.bottom().min(other.bottom());
        if x1 <= x0 || y1 <= y0 {
            return None;
        }
        // x0 is in [i32::MIN, i32::MAX] because it is max(self.x, other.x).
        // The difference (x1 - x0) > 0, so the i64 → u64 cast is safe.
        // The `.min(u32::MAX as u64)` clamp ensures the u64 → u32 cast is exact.
        let w = (x1 - x0) as u64;
        let h = (y1 - y0) as u64;
        Some(Self {
            x: x0 as i32,
            y: y0 as i32,
            w: w.min(u64::from(u32::MAX)) as u32,
            h: h.min(u64::from(u32::MAX)) as u32,
        })
    }

    /// Returns the smallest rectangle that contains both `self` and `other`.
    ///
    /// Empty rectangles are handled: if both are empty the result is a zero
    /// rect at the origin.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// let a = Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 5,
    ///     h: 5,
    /// };
    /// let b = Rect {
    ///     x: 8,
    ///     y: 8,
    ///     w: 5,
    ///     h: 5,
    /// };
    /// let u = a.union(&b);
    /// assert_eq!(
    ///     u,
    ///     Rect {
    ///         x: 0,
    ///         y: 0,
    ///         w: 13,
    ///         h: 13
    ///     }
    /// );
    /// ```
    #[must_use]
    // Casts follow the same reasoning as `intersect`: x0 = min(self.x, other.x)
    // is in [i32::MIN, i32::MAX]; differences are positive (non-empty guards
    // are checked before entry) → i64→u64 sign-loss is safe; u32::MAX clamp
    // makes the u64→u32 exact.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    pub fn union(&self, other: &Self) -> Self {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        let x0 = i64::from(self.x).min(i64::from(other.x));
        let y0 = i64::from(self.y).min(i64::from(other.y));
        let x1 = self.right().max(other.right());
        let y1 = self.bottom().max(other.bottom());
        // Both non-empty, so x1 > x0 and y1 > y0: differences are positive.
        let w = ((x1 - x0) as u64).min(u64::from(u32::MAX)) as u32;
        let h = ((y1 - y0) as u64).min(u64::from(u32::MAX)) as u32;
        Self {
            x: x0 as i32,
            y: y0 as i32,
            w,
            h,
        }
    }

    /// Returns `self` clamped to `bounds` (i.e. `self.intersect(bounds)`).
    ///
    /// Returns `None` if `self` and `bounds` do not overlap, meaning the
    /// rectangle is entirely outside `bounds` and no visible area remains.
    ///
    /// This is the primary defence-in-depth call for client-supplied rects:
    /// any rect that extends past the screen or surface boundary is silently
    /// reduced to its visible portion — it never becomes an out-of-bounds
    /// index (ADR-0041 D4).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_display::geometry::Rect;
    /// let screen = Rect {
    ///     x: 0,
    ///     y: 0,
    ///     w: 1920,
    ///     h: 1080,
    /// };
    /// // Malicious client rect far outside the screen.
    /// let evil = Rect {
    ///     x: -1000,
    ///     y: -1000,
    ///     w: 100_000,
    ///     h: 100_000,
    /// };
    /// let clamped = evil.clamp_to(&screen).unwrap();
    /// assert_eq!(clamped, screen);
    ///
    /// // Entirely outside — returns None, never an out-of-bounds write.
    /// let outside = Rect {
    ///     x: 2000,
    ///     y: 0,
    ///     w: 10,
    ///     h: 10,
    /// };
    /// assert!(outside.clamp_to(&screen).is_none());
    /// ```
    #[must_use]
    pub fn clamp_to(&self, bounds: &Self) -> Option<Self> {
        self.intersect(bounds)
    }
}

// ---------------------------------------------------------------------------
// DamageRegion
// ---------------------------------------------------------------------------

/// Maximum number of dirty rectangles stored before the set is coalesced.
///
/// When a [`DamageRegion`] would grow beyond this limit, all rectangles are
/// collapsed to their bounding box so that a malicious or misbehaving client
/// flooding tiny damage rects cannot cause unbounded memory growth
/// (ADR-0041 D2).
pub const MAX_DAMAGE_RECTS: usize = 16;

/// A bounded set of dirty screen rectangles, accumulated between frames.
///
/// The compositor adds to the region whenever a surface is committed, a
/// window is moved/raised/destroyed, or focus changes.  [`crate::compositor::Compositor::composite`]
/// consumes the region by repainting only the dirty areas, then calls
/// [`DamageRegion::clear`].
///
/// # Overflow protection
///
/// Once the internal vector would exceed [`MAX_DAMAGE_RECTS`] entries, all
/// current rects plus the new one are merged into a single bounding box.
/// This keeps memory usage `O(1)` regardless of client behaviour.
///
/// # Example
///
/// ```
/// use nexacore_display::geometry::{DamageRegion, Rect};
///
/// let mut d = DamageRegion::new();
/// d.add(Rect {
///     x: 0,
///     y: 0,
///     w: 10,
///     h: 10,
/// });
/// d.add(Rect {
///     x: 5,
///     y: 5,
///     w: 10,
///     h: 10,
/// });
/// assert_eq!(d.iter().count(), 2);
/// d.clear();
/// assert!(d.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct DamageRegion {
    /// The accumulated set of dirty rectangles.
    rects: Vec<Rect>,
}

impl DamageRegion {
    /// Creates a new, empty [`DamageRegion`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            // Pre-allocate the maximum number of entries so the vector never
            // reallocates during normal compositor operation.
            rects: Vec::with_capacity(MAX_DAMAGE_RECTS),
        }
    }

    /// Adds a dirty rectangle to the region.
    ///
    /// Empty rectangles are silently discarded (they contribute no visible
    /// damage).  If adding `r` would push the count past [`MAX_DAMAGE_RECTS`],
    /// the entire set (including `r`) is collapsed to its bounding box before
    /// the new entry is stored — so the stored count never exceeds
    /// `MAX_DAMAGE_RECTS`.
    pub fn add(&mut self, r: Rect) {
        // Empty rects carry no damage; discarding them keeps the count tight.
        if r.is_empty() {
            return;
        }

        if self.rects.len() < MAX_DAMAGE_RECTS {
            self.rects.push(r);
        } else {
            // Coalesce: compute bounding box of everything currently stored
            // plus the incoming rect, then replace the whole set with that
            // single bounding box.
            let bbox = self
                .rects
                .iter()
                .copied()
                .fold(r, |acc, cur| acc.union(&cur));
            self.rects.clear();
            // bbox is guaranteed non-empty because r was non-empty.
            self.rects.push(bbox);
        }
    }

    /// Removes all dirty rectangles from the region.
    pub fn clear(&mut self) {
        self.rects.clear();
    }

    /// Returns an iterator over the current dirty rectangles.
    pub fn iter(&self) -> impl Iterator<Item = &Rect> {
        self.rects.iter()
    }

    /// Returns `true` if no dirty rectangles are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rects.is_empty()
    }

    /// Clamps all tracked rectangles to `screen`, dropping any that are
    /// entirely outside the screen bounds.
    ///
    /// Called before each `composite` pass to ensure no rect in the region
    /// ever produces an out-of-bounds framebuffer index.
    pub fn clamp_all_to(&mut self, screen: &Rect) {
        // Retain only rects that have a non-empty intersection with the screen,
        // replacing each with its clamped form.
        self.rects.retain_mut(|r| {
            // Keep the rect only if it has a non-empty intersection with the
            // screen; replace it with the clamped version in that case.
            // `is_some_and` cannot be used here because we need the side-effect
            // of updating `*r`; the `if let` form is the clearest equivalent.
            #[allow(clippy::option_if_let_else)]
            if let Some(clamped) = r.clamp_to(screen) {
                *r = clamped;
                true
            } else {
                false
            }
        });
    }
}

impl Default for DamageRegion {
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

    // --- Rect basics ---

    #[test]
    fn rect_right_bottom_no_overflow() {
        let r = Rect {
            x: i32::MAX,
            y: i32::MAX,
            w: 1,
            h: 1,
        };
        assert_eq!(r.right(), i64::from(i32::MAX) + 1);
        assert_eq!(r.bottom(), i64::from(i32::MAX) + 1);
    }

    #[test]
    fn rect_is_empty() {
        assert!(
            Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 10
            }
            .is_empty()
        );
        assert!(
            Rect {
                x: 0,
                y: 0,
                w: 10,
                h: 0
            }
            .is_empty()
        );
        assert!(
            !Rect {
                x: 0,
                y: 0,
                w: 1,
                h: 1
            }
            .is_empty()
        );
    }

    #[test]
    fn rect_contains_point_boundary() {
        let r = Rect {
            x: 5,
            y: 5,
            w: 10,
            h: 10,
        };
        assert!(r.contains_point(5, 5)); // top-left inclusive
        assert!(r.contains_point(14, 14)); // bottom-right of inclusive range
        assert!(!r.contains_point(15, 5)); // right edge exclusive
        assert!(!r.contains_point(5, 15)); // bottom edge exclusive
        assert!(!r.contains_point(4, 5)); // left of rect
    }

    #[test]
    fn rect_intersect_overlapping() {
        let a = Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        };
        let b = Rect {
            x: 5,
            y: 5,
            w: 10,
            h: 10,
        };
        assert_eq!(
            a.intersect(&b),
            Some(Rect {
                x: 5,
                y: 5,
                w: 5,
                h: 5
            })
        );
    }

    #[test]
    fn rect_intersect_disjoint() {
        let a = Rect {
            x: 0,
            y: 0,
            w: 5,
            h: 5,
        };
        let b = Rect {
            x: 10,
            y: 0,
            w: 5,
            h: 5,
        };
        assert!(a.intersect(&b).is_none());
    }

    #[test]
    fn rect_intersect_touching_edge_is_empty() {
        // Touching but not overlapping: right edge of a == left edge of b.
        let a = Rect {
            x: 0,
            y: 0,
            w: 5,
            h: 5,
        };
        let b = Rect {
            x: 5,
            y: 0,
            w: 5,
            h: 5,
        };
        assert!(a.intersect(&b).is_none());
    }

    #[test]
    fn rect_union_non_overlapping() {
        let a = Rect {
            x: 0,
            y: 0,
            w: 5,
            h: 5,
        };
        let b = Rect {
            x: 8,
            y: 8,
            w: 5,
            h: 5,
        };
        assert_eq!(
            a.union(&b),
            Rect {
                x: 0,
                y: 0,
                w: 13,
                h: 13
            }
        );
    }

    #[test]
    fn rect_union_with_empty() {
        let a = Rect {
            x: 3,
            y: 4,
            w: 10,
            h: 10,
        };
        let empty = Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        };
        assert_eq!(a.union(&empty), a);
        assert_eq!(empty.union(&a), a);
    }

    #[test]
    fn rect_clamp_to_screen() {
        let screen = Rect {
            x: 0,
            y: 0,
            w: 1920,
            h: 1080,
        };
        // Malicious client rect.
        let evil = Rect {
            x: -1000,
            y: -1000,
            w: 100_000,
            h: 100_000,
        };
        let clamped = evil.clamp_to(&screen).unwrap();
        assert_eq!(clamped, screen);
    }

    #[test]
    fn rect_clamp_to_outside_returns_none() {
        let screen = Rect {
            x: 0,
            y: 0,
            w: 1920,
            h: 1080,
        };
        let outside = Rect {
            x: 2000,
            y: 0,
            w: 10,
            h: 10,
        };
        assert!(outside.clamp_to(&screen).is_none());
    }

    // --- DamageRegion ---

    #[test]
    fn damage_add_and_clear() {
        let mut d = DamageRegion::new();
        d.add(Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        });
        d.add(Rect {
            x: 5,
            y: 5,
            w: 10,
            h: 10,
        });
        assert_eq!(d.iter().count(), 2);
        d.clear();
        assert!(d.is_empty());
    }

    #[test]
    fn damage_empty_rect_discarded() {
        let mut d = DamageRegion::new();
        d.add(Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 10,
        });
        assert!(d.is_empty());
    }

    #[test]
    fn damage_coalesces_at_cap() {
        let mut d = DamageRegion::new();
        // Fill exactly MAX_DAMAGE_RECTS entries.
        // MAX_DAMAGE_RECTS = 16 fits in i32; cast is safe.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        for i in 0..MAX_DAMAGE_RECTS as i32 {
            d.add(Rect {
                x: i,
                y: 0,
                w: 1,
                h: 1,
            });
        }
        assert_eq!(d.iter().count(), MAX_DAMAGE_RECTS);
        // Adding one more should coalesce to a single bounding box.
        d.add(Rect {
            x: 100,
            y: 100,
            w: 1,
            h: 1,
        });
        assert_eq!(d.iter().count(), 1);
    }

    #[test]
    fn damage_clamp_all_to_screen() {
        let screen = Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 100,
        };
        let mut d = DamageRegion::new();
        d.add(Rect {
            x: -10,
            y: -10,
            w: 50,
            h: 50,
        }); // partially outside
        d.add(Rect {
            x: 200,
            y: 200,
            w: 10,
            h: 10,
        }); // entirely outside
        d.clamp_all_to(&screen);
        // Only the first rect survives (clamped); the second is dropped.
        let rects: Vec<_> = d.iter().copied().collect();
        assert_eq!(rects.len(), 1);
        let clamped = rects[0];
        // Must lie entirely within screen.
        assert!(clamped.x >= screen.x);
        assert!(clamped.y >= screen.y);
        assert!(clamped.right() <= screen.right());
        assert!(clamped.bottom() <= screen.bottom());
    }
}
