//! Layout primitives: [`Size`] and [`Direction`].
//!
//! These types are factored out of [`crate::widget`] so that callers that only
//! need measurement can import them without pulling in the full widget tree.
//!
//! ## Example
//!
//! ```
//! use nexacore_ui::layout::{Direction, Size};
//!
//! let s = Size { w: 120, h: 32 };
//! assert_eq!(s.w, 120);
//! let d = Direction::Vertical;
//! assert!(matches!(d, Direction::Vertical));
//! ```

// ---------------------------------------------------------------------------
// Size
// ---------------------------------------------------------------------------

/// A two-dimensional pixel size.
///
/// Returned by [`crate::widget::Widget::measure`] and used during layout to
/// position children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    /// Width in pixels.
    pub w: u32,
    /// Height in pixels.
    pub h: u32,
}

// ---------------------------------------------------------------------------
// Direction
// ---------------------------------------------------------------------------

/// The stacking axis for a [`crate::widget::Widget::Container`].
///
/// `Vertical` stacks children top-to-bottom; `Horizontal` stacks them
/// left-to-right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Stack children from top to bottom.
    Vertical,
    /// Stack children from left to right.
    Horizontal,
}
