//! Smooth live window resize with incremental relayout (WS7-01.10).
//!
//! Two pieces:
//!
//! * [`resize_damage`] computes the *symmetric difference* of the old and new
//!   window rects — the strips that are newly exposed (must paint) or vacated
//!   (reveal what's behind). The overlapping interior is untouched, so a resize
//!   only repaints/relayouts its changed edges, not the whole window.
//! * [`LiveResize`] tracks the resize handle with a spring (WS7-00
//!   `spring-resize`, via [`crate::animation`]) so the window edge follows the
//!   pointer with minimal lag instead of snapping, and reports the incremental
//!   damage between frames.
//!
//! Pure geometry over [`Rect`]; `no_std`.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names
)]

use alloc::{vec, vec::Vec};

use crate::{
    animation::{Spring, SpringState},
    geometry::Rect,
};

/// Half-open edges `(x0, y0, x1, y1)` of a rect in `i64` (overflow-safe).
fn edges(r: Rect) -> (i64, i64, i64, i64) {
    (
        i64::from(r.x),
        i64::from(r.y),
        i64::from(r.x) + i64::from(r.w),
        i64::from(r.y) + i64::from(r.h),
    )
}

fn from_edges(x0: i64, y0: i64, x1: i64, y1: i64) -> Option<Rect> {
    if x1 > x0 && y1 > y0 {
        Some(Rect {
            x: x0 as i32,
            y: y0 as i32,
            w: (x1 - x0) as u32,
            h: (y1 - y0) as u32,
        })
    } else {
        None
    }
}

/// `a` minus `b`: the parts of `a` not covered by `b`, as up to four
/// non-overlapping rects (top / bottom / left / right strips). Empty when `b`
/// fully covers `a`; `[a]` when they don't intersect.
#[must_use]
pub fn rect_subtract(a: Rect, b: Rect) -> Vec<Rect> {
    let Some(i) = a.intersect(&b) else {
        return if a.w == 0 || a.h == 0 {
            Vec::new()
        } else {
            vec![a]
        };
    };
    let (ax0, ay0, ax1, ay1) = edges(a);
    let (ix0, iy0, ix1, iy1) = edges(i);
    let mut out = Vec::new();
    // Top strip (full width, above the overlap).
    out.extend(from_edges(ax0, ay0, ax1, iy0));
    // Bottom strip (full width, below the overlap).
    out.extend(from_edges(ax0, iy1, ax1, ay1));
    // Left strip (between top and bottom, left of the overlap).
    out.extend(from_edges(ax0, iy0, ix0, iy1));
    // Right strip (between top and bottom, right of the overlap).
    out.extend(from_edges(ix1, iy0, ax1, iy1));
    out
}

/// Incremental repaint regions when a window moves/resizes from `old` to `new`.
///
/// Returns the newly-covered area (`new \ old`) plus the vacated area
/// (`old \ new`); the shared interior is omitted — that is the "incremental"
/// win (WS7-01.10).
///
/// # Example
///
/// ```
/// use nexacore_display::{geometry::Rect, resize::resize_damage};
///
/// let old = Rect {
///     x: 0,
///     y: 0,
///     w: 100,
///     h: 100,
/// };
/// let new = Rect {
///     x: 0,
///     y: 0,
///     w: 140,
///     h: 130,
/// }; // grow right + down
/// let dmg = resize_damage(old, new);
/// // Two strips: the new right column and bottom row — not the whole window.
/// assert_eq!(dmg.len(), 2);
/// assert!(dmg.iter().all(|r| r.x >= 100 || r.y >= 100));
/// ```
#[must_use]
pub fn resize_damage(old: Rect, new: Rect) -> Vec<Rect> {
    let mut out = rect_subtract(new, old); // newly exposed
    out.extend(rect_subtract(old, new)); // vacated
    out
}

/// A window edge tracked smoothly toward a target rect during live resize.
///
/// Each rect component (x, y, w, h) is a spring chasing the handle's target, so
/// the window follows the pointer with a soft, non-bouncy lag. [`Self::step`]
/// advances the simulation; [`Self::take_damage`] returns the incremental
/// regions changed since the previous call.
#[derive(Debug, Clone, Copy)]
pub struct LiveResize {
    x: SpringState,
    y: SpringState,
    w: SpringState,
    h: SpringState,
    last: Rect,
    min_w: u32,
    min_h: u32,
}

impl LiveResize {
    /// Start tracking from `start`, enforcing a minimum content size.
    #[must_use]
    pub fn new(start: Rect, min_w: u32, min_h: u32) -> Self {
        Self {
            x: SpringState::at(start.x as f32),
            y: SpringState::at(start.y as f32),
            w: SpringState::at(start.w as f32),
            h: SpringState::at(start.h as f32),
            last: start,
            min_w: min_w.max(1),
            min_h: min_h.max(1),
        }
    }

    /// Point the resize at a new handle rect (e.g. the pointer dragged an edge).
    /// Width/height targets are floored at the minimum content size.
    pub fn set_target(&mut self, target: Rect) {
        self.x.set_target(target.x as f32);
        self.y.set_target(target.y as f32);
        self.w.set_target(target.w.max(self.min_w) as f32);
        self.h.set_target(target.h.max(self.min_h) as f32);
    }

    /// Advance the spring simulation by `dt` seconds and return the current rect.
    pub fn step(&mut self, spring: Spring, dt: f32) -> Rect {
        self.x.step(spring, dt);
        self.y.step(spring, dt);
        self.w.step(spring, dt);
        self.h.step(spring, dt);
        self.current()
    }

    /// The current interpolated rect (components rounded to whole pixels).
    #[must_use]
    pub fn current(&self) -> Rect {
        Rect {
            x: round_i32(self.x.value),
            y: round_i32(self.y.value),
            w: round_u32(self.w.value).max(self.min_w),
            h: round_u32(self.h.value).max(self.min_h),
        }
    }

    /// `true` once every component has settled at its target.
    #[must_use]
    pub fn settled(&self) -> bool {
        self.x.settled(0.5, 0.5)
            && self.y.settled(0.5, 0.5)
            && self.w.settled(0.5, 0.5)
            && self.h.settled(0.5, 0.5)
    }

    /// The incremental damage between the previous reported rect and the current
    /// one, advancing the internal baseline. Empty when nothing moved this step.
    pub fn take_damage(&mut self) -> Vec<Rect> {
        let cur = self.current();
        if cur == self.last {
            return Vec::new();
        }
        let dmg = resize_damage(self.last, cur);
        self.last = cur;
        dmg
    }
}

fn round_i32(v: f32) -> i32 {
    libm::roundf(v) as i32
}

fn round_u32(v: f32) -> u32 {
    if v <= 0.0 { 0 } else { libm::roundf(v) as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grow_damages_only_new_strips() {
        let old = Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 100,
        };
        let new = Rect {
            x: 0,
            y: 0,
            w: 140,
            h: 130,
        };
        let dmg = resize_damage(old, new);
        assert_eq!(dmg.len(), 2, "right column + bottom row");
        // No damaged rect intrudes into the shared 100x100 interior.
        assert!(dmg.iter().all(|r| r.x >= 100 || r.y >= 100));
        // The shared interior pixel is NOT in any damage rect.
        assert!(!dmg.iter().any(|r| r.contains_point(50, 50)));
    }

    #[test]
    fn shrink_damages_vacated_strips() {
        let old = Rect {
            x: 0,
            y: 0,
            w: 140,
            h: 130,
        };
        let new = Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 100,
        };
        let dmg = resize_damage(old, new);
        // The vacated right column and bottom row must repaint (reveal behind).
        assert!(dmg.iter().any(|r| r.contains_point(120, 50)));
        assert!(dmg.iter().any(|r| r.contains_point(50, 120)));
    }

    #[test]
    fn no_change_no_damage() {
        let r = Rect {
            x: 10,
            y: 10,
            w: 50,
            h: 50,
        };
        assert!(resize_damage(r, r).is_empty());
    }

    #[test]
    fn subtract_disjoint_returns_whole() {
        let a = Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        };
        let b = Rect {
            x: 100,
            y: 100,
            w: 10,
            h: 10,
        };
        assert_eq!(rect_subtract(a, b), vec![a]);
    }

    #[test]
    fn subtract_covering_returns_empty() {
        let a = Rect {
            x: 5,
            y: 5,
            w: 10,
            h: 10,
        };
        let b = Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 100,
        };
        assert!(rect_subtract(a, b).is_empty());
    }

    #[test]
    fn subtract_hole_returns_four_strips() {
        let a = Rect {
            x: 0,
            y: 0,
            w: 30,
            h: 30,
        };
        let b = Rect {
            x: 10,
            y: 10,
            w: 10,
            h: 10,
        }; // fully inside a
        let parts = rect_subtract(a, b);
        assert_eq!(parts.len(), 4, "top/bottom/left/right strips");
        // Total area of strips = area(a) - area(b) = 900 - 100 = 800.
        let area: u64 = parts.iter().map(crate::geometry::Rect::area).sum();
        assert_eq!(area, 800);
    }

    #[test]
    fn live_resize_tracks_toward_target_and_settles() {
        let start = Rect {
            x: 0,
            y: 0,
            w: 200,
            h: 200,
        };
        let mut lr = LiveResize::new(start, 100, 100);
        lr.set_target(Rect {
            x: 0,
            y: 0,
            w: 400,
            h: 300,
        });
        let spring = Spring::critically_damped(300.0, 1.0);
        for _ in 0..600 {
            lr.step(spring, 1.0 / 120.0);
        }
        assert!(lr.settled());
        let cur = lr.current();
        assert!((cur.w as i32 - 400).abs() <= 1, "w settled at {}", cur.w);
        assert!((cur.h as i32 - 300).abs() <= 1, "h settled at {}", cur.h);
    }

    #[test]
    fn live_resize_enforces_min_size() {
        let start = Rect {
            x: 0,
            y: 0,
            w: 200,
            h: 200,
        };
        let mut lr = LiveResize::new(start, 120, 120);
        lr.set_target(Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        });
        let spring = Spring::critically_damped(300.0, 1.0);
        for _ in 0..600 {
            lr.step(spring, 1.0 / 120.0);
        }
        let cur = lr.current();
        assert!(cur.w >= 120 && cur.h >= 120, "min size honoured: {cur:?}");
    }

    #[test]
    fn take_damage_is_incremental_then_empty() {
        let start = Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 100,
        };
        let mut lr = LiveResize::new(start, 50, 50);
        lr.set_target(Rect {
            x: 0,
            y: 0,
            w: 300,
            h: 100,
        });
        let spring = Spring::critically_damped(300.0, 1.0);
        let mut saw_damage = false;
        for _ in 0..600 {
            lr.step(spring, 1.0 / 120.0);
            if !lr.take_damage().is_empty() {
                saw_damage = true;
            }
        }
        assert!(saw_damage, "resize produced incremental damage");
        // Once settled, no further damage.
        assert!(lr.take_damage().is_empty());
    }
}
