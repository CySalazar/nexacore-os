//! Linux (and Wine) application window integration — the *app bridge*.
//!
//! See `NCIP-Container-006` § 8 ("application integration") and plan task
//! **WS9-03** ("Linux app path: guest image + window integration"). The goal is
//! to run Linux GUI applications inside a container micro-VM whose individual
//! windows appear **integrated** into the NexaCore desktop — sitting next to
//! native apps — rather than as a nested *desktop-in-desktop*.
//!
//! ## Architecture
//!
//! The guest boots a minimal, Stichting-signed Linux image ([`image`]) whose
//! PID 1 is a **guest agent** running a headless Wayland compositor. Guest
//! applications connect to that compositor and render into a single guest
//! framebuffer exported over `virtio-gpu`. The agent reports each toplevel
//! window's lifecycle and geometry to the host over `virtio-vsock` using the
//! [`agent`] protocol.
//!
//! On the host, the [`bridge`] maps every guest toplevel to one NexaCore
//! compositor surface. The crucial step is [`clip`]: each host surface samples
//! **only the sub-rectangle** of the guest framebuffer that the window occupies
//! — presenting the guest's whole output as one surface is explicitly rejected
//! as a desktop-in-desktop. [`input`] routes host pointer/keyboard events back
//! to the correct guest window (with coordinate translation), and [`clipboard`]
//! / [`dnd`] / [`audio`] carry the remaining interop channels.
//!
//! ## Host-testability
//!
//! Every module here is pure logic or a state machine over value types. The
//! effects that require the live desktop runtime — attaching to the real
//! NexaCore compositor ([`bridge::CompositorSink`]), the guest kernel, and the
//! `virtio-snd` device — are expressed as **traits/seams** so the geometry,
//! protocol codecs, and state transitions are unit-tested on the host. The
//! end-to-end assertion (a Linux GUI app integrated on the test VM) is the deferred
//! rig sub-task **WS9-03.9**.

pub mod agent;
pub mod audio;
pub mod bridge;
pub mod clip;
pub mod clipboard;
pub mod dnd;
pub mod image;
pub mod input;

pub use agent::{GuestToHost, GuestWindow, GuestWindowRegistry, HostToGuest, WindowId};
pub use audio::{AudioBridge, GuestAudioStream, HostAudioRoute};
pub use bridge::{CompositorSink, HostSurfaceDesc, SurfaceId, WindowBridge};
pub use clip::WindowClip;
pub use clipboard::{ClipboardBridge, ClipboardOffer, SelectionOwner};
pub use dnd::{DragAction, DragSession, DragState};
pub use image::GuestImageManifest;
pub use input::{InputRouter, RoutedInput};

/// Errors raised across the app-bridge subsystem.
///
/// The subsystem follows the crate's **fail-closed** convention: any request
/// that references an unknown window, exceeds a resource bound, or would
/// produce a desktop-in-desktop is rejected rather than best-effort honoured.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppBridgeError {
    /// The guest image manifest is missing a required field or fails a
    /// structural invariant. The static slug names the failed check.
    #[error("invalid guest image manifest: {0}")]
    InvalidManifest(&'static str),

    /// A protocol message referenced a window id the host does not track.
    #[error("unknown guest window: {0}")]
    UnknownWindow(u64),

    /// The guest tried to map more concurrent windows than the bridge admits.
    #[error("guest exceeded the concurrent window limit")]
    TooManyWindows,

    /// A guest toplevel covers (approximately) the entire guest output and was
    /// rejected to prevent a nested desktop-in-desktop.
    #[error("window rejected as desktop-in-desktop")]
    DesktopInDesktop,

    /// A geometry lies (partly) outside the guest framebuffer or a host
    /// surface it references.
    #[error("geometry out of bounds")]
    OutOfBounds,

    /// A capability check failed at an interop boundary (clipboard / drag /
    /// audio). The slug names the boundary.
    #[error("capability denied: {0}")]
    Capability(&'static str),

    /// A malformed or out-of-sequence protocol message. The slug names the
    /// violated protocol invariant.
    #[error("app-bridge protocol violation: {0}")]
    Protocol(&'static str),

    /// A clipboard payload exceeded the negotiated maximum size.
    #[error("clipboard payload exceeds the maximum size")]
    ClipboardTooLarge,

    /// A drag was released with no target having accepted the offer.
    #[error("drag released with no accepting target")]
    NoDropTarget,
}

/// Result alias for the app-bridge subsystem.
pub type AppBridgeResult<T> = core::result::Result<T, AppBridgeError>;

// -----------------------------------------------------------------------------
// Shared integer geometry
// -----------------------------------------------------------------------------

/// A point in a signed pixel coordinate space.
///
/// Signed because host desktop coordinates can be negative (e.g. a window
/// dragged partly off the left edge, or a monitor placed left of the origin).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Point {
    /// Horizontal coordinate.
    pub x: i32,
    /// Vertical coordinate.
    pub y: i32,
}

impl Point {
    /// A point at the given coordinates.
    #[must_use]
    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

/// A non-negative pixel extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Size {
    /// Width in pixels.
    pub w: u32,
    /// Height in pixels.
    pub h: u32,
}

impl Size {
    /// A size with the given extents.
    #[must_use]
    pub const fn new(w: u32, h: u32) -> Self {
        Self { w, h }
    }

    /// Whether either extent is zero (degenerate).
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    /// Total pixel count (`w * h`), saturating on overflow.
    #[must_use]
    pub fn area(self) -> u64 {
        u64::from(self.w).saturating_mul(u64::from(self.h))
    }
}

/// An axis-aligned rectangle: a signed origin plus a non-negative extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rect {
    /// Left edge (inclusive).
    pub x: i32,
    /// Top edge (inclusive).
    pub y: i32,
    /// Width in pixels.
    pub w: u32,
    /// Height in pixels.
    pub h: u32,
}

impl Rect {
    /// A rectangle from origin and extent.
    #[must_use]
    pub const fn new(x: i32, y: i32, w: u32, h: u32) -> Self {
        Self { x, y, w, h }
    }

    /// The right edge (exclusive): `x + w`, saturating.
    #[must_use]
    pub fn right(self) -> i64 {
        i64::from(self.x) + i64::from(self.w)
    }

    /// The bottom edge (exclusive): `y + h`, saturating.
    #[must_use]
    pub fn bottom(self) -> i64 {
        i64::from(self.y) + i64::from(self.h)
    }

    /// The rectangle's extent.
    #[must_use]
    pub const fn size(self) -> Size {
        Size::new(self.w, self.h)
    }

    /// Whether the rectangle has zero area.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    /// Pixel area, saturating.
    #[must_use]
    pub fn area(self) -> u64 {
        self.size().area()
    }

    /// Whether `p` lies within the rectangle (half-open on the far edges).
    #[must_use]
    pub fn contains(self, p: Point) -> bool {
        i64::from(p.x) >= i64::from(self.x)
            && i64::from(p.x) < self.right()
            && i64::from(p.y) >= i64::from(self.y)
            && i64::from(p.y) < self.bottom()
    }

    /// The intersection of two rectangles, or `None` if they are disjoint.
    #[must_use]
    pub fn intersect(self, other: Self) -> Option<Self> {
        let x0 = self.x.max(other.x);
        let y0 = self.y.max(other.y);
        let x1 = self.right().min(other.right());
        let y1 = self.bottom().min(other.bottom());
        if x1 <= i64::from(x0) || y1 <= i64::from(y0) {
            return None;
        }
        // Widths are bounded by the operands' `u32` extents, so the
        // differences fit in `u32`.
        let w = u32::try_from(x1 - i64::from(x0)).ok()?;
        let h = u32::try_from(y1 - i64::from(y0)).ok()?;
        Some(Self::new(x0, y0, w, h))
    }

    /// Whether `self` is fully contained within `bounds`.
    #[must_use]
    pub fn is_within(self, bounds: Self) -> bool {
        i64::from(self.x) >= i64::from(bounds.x)
            && i64::from(self.y) >= i64::from(bounds.y)
            && self.right() <= bounds.right()
            && self.bottom() <= bounds.bottom()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn rect_contains_is_half_open() {
        let r = Rect::new(10, 10, 100, 50);
        assert!(r.contains(Point::new(10, 10)));
        assert!(r.contains(Point::new(109, 59)));
        // Far edges are exclusive.
        assert!(!r.contains(Point::new(110, 30)));
        assert!(!r.contains(Point::new(30, 60)));
        assert!(!r.contains(Point::new(9, 30)));
    }

    #[test]
    fn rect_intersect_overlapping() {
        let a = Rect::new(0, 0, 100, 100);
        let b = Rect::new(50, 50, 100, 100);
        assert_eq!(a.intersect(b), Some(Rect::new(50, 50, 50, 50)));
    }

    #[test]
    fn rect_intersect_disjoint_is_none() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(20, 20, 10, 10);
        assert_eq!(a.intersect(b), None);
        // Edge-touching is not overlapping (half-open).
        let c = Rect::new(10, 0, 10, 10);
        assert_eq!(a.intersect(c), None);
    }

    #[test]
    fn rect_is_within_bounds() {
        let bounds = Rect::new(0, 0, 1920, 1080);
        assert!(Rect::new(10, 10, 100, 100).is_within(bounds));
        assert!(!Rect::new(-1, 10, 100, 100).is_within(bounds));
        assert!(!Rect::new(1900, 10, 100, 100).is_within(bounds));
    }

    #[test]
    fn size_area_saturates() {
        assert_eq!(Size::new(3, 4).area(), 12);
        assert_eq!(
            Size::new(u32::MAX, u32::MAX).area(),
            u64::from(u32::MAX) * u64::from(u32::MAX)
        );
    }
}
