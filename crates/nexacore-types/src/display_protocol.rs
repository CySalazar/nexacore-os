//! Client ⇄ compositor IPC wire protocol (TASK-19, DE-C2/DE-C3).
//!
//! This module defines the canonical `postcard`-encoded message enums that
//! flow between compositor and client processes over the named IPC channel
//! [`crate::display_protocol::DISPLAY_CHANNEL_NAME`].
//!
//! ## Design (ADR-0041 D5)
//!
//! The protocol is **defined and documented now** in this TASK-19 deliverable.
//! The compositor receives [`crate::display_protocol::ClientRequest`]s and emits [`crate::display_protocol::CompositorEvent`]s.
//! Encoding is always done via [`crate::wire::encode_canonical`] /
//! [`crate::wire::decode_canonical`] (NCIP-Serde-004 — the single workspace
//! audit point for serialization).
//!
//! Multi-process clients speaking this protocol over real IPC arrive with
//! TASK-20 (`nexacore-ui`); the TASK-19 acceptance image drives three **in-process
//! test surfaces** through the identical commit/clamp path (ADR-0041 D5).
//!
//! ## Backward-compatibility
//!
//! Both enums carry `#[non_exhaustive]` so new variants may be added via PR
//! without breaking source-level `match` consumers (who must provide a `_ =>`
//! arm).  Removing or renaming a variant is a wire-breaking change requiring a
//! `DISPLAY_CHANNEL_NAME` version bump.
//!
//! ## Wire format
//!
//! The postcard `varint` discriminant is written first, followed by the
//! variant's fields.  Each message is fully self-delimiting; the size bounds
//! [`crate::display_protocol::MAX_CLIENT_REQUEST_BYTES`] and [`crate::display_protocol::MAX_COMPOSITOR_EVENT_BYTES`] are
//! conservative upper bounds including a generous slack factor.
//!
//! ## `no_std` compatibility
//!
//! This module depends only on `serde`, `alloc::vec::Vec`, and the sibling
//! [`crate::display_channel::DisplayInputEvent`] type.  No `std` API is used.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::display_channel::DisplayInputEvent;

// ---------------------------------------------------------------------------
// Channel constants
// ---------------------------------------------------------------------------

/// Registered name of the compositor IPC channel.
///
/// Clients look up this name in the kernel's channel registry to obtain the
/// channel handle.  The kernel registers the channel when it spawns the
/// compositor process.
pub const DISPLAY_CHANNEL_NAME: &str = "nexacore.display.compositor";

/// Conservative upper bound in bytes on a postcard-encoded [`ClientRequest`].
///
/// The largest realistic variant is `Commit` with [`MAX_DAMAGE_RECTS`] damage
/// rects (each `4 × 5 = 20` bytes worst-case varint) plus surface-id (`5` B)
/// = 16 × 20 + 5 = 325 B; this bound leaves generous slack.
pub const MAX_CLIENT_REQUEST_BYTES: usize = 512;

/// Conservative upper bound in bytes on a postcard-encoded [`CompositorEvent`].
///
/// The largest variant is `Input(DisplayInputEvent::Pointer)` at ~14 bytes;
/// `Configure` is ~15 bytes.  64 bytes is a comfortable upper bound.
pub const MAX_COMPOSITOR_EVENT_BYTES: usize = 64;

/// Maximum number of client damage rects per [`ClientRequest::Commit`] message.
///
/// Matches `nexacore_display::geometry::MAX_DAMAGE_RECTS` so a client cannot send
/// more rects than the compositor's damage region can hold.
pub const MAX_DAMAGE_RECTS: usize = 16;

// ---------------------------------------------------------------------------
// Wire rect
// ---------------------------------------------------------------------------

/// An axis-aligned rectangle carried in the IPC wire protocol.
///
/// This is a distinct type from `nexacore_display::geometry::Rect` to keep the
/// wire contract in `nexacore-types` (the foundational layer) independent of the
/// compositor-side representation.  The field layout is identical; callers
/// convert between the two at the protocol boundary.
///
/// # Example
///
/// ```
/// use nexacore_types::{
///     display_protocol::Rect,
///     wire::{decode_canonical, encode_canonical},
/// };
///
/// let r = Rect {
///     x: 10,
///     y: 20,
///     w: 100,
///     h: 50,
/// };
/// let bytes = encode_canonical(&r).expect("encode");
/// let back: Rect = decode_canonical(&bytes).expect("decode");
/// assert_eq!(back.x, 10);
/// assert_eq!(back.w, 100);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    /// Horizontal origin (signed; may be negative for off-screen rects).
    pub x: i32,
    /// Vertical origin (signed; may be negative for off-screen rects).
    pub y: i32,
    /// Width in pixels.
    pub w: u32,
    /// Height in pixels.
    pub h: u32,
}

// ---------------------------------------------------------------------------
// Client → compositor
// ---------------------------------------------------------------------------

/// Messages sent from a client process to the compositor.
///
/// Encoded with [`crate::wire::encode_canonical`] and sent as
/// `MessageKind::Request` on the [`DISPLAY_CHANNEL_NAME`] channel.
///
/// `#[non_exhaustive]` allows future variants (e.g. `SetTitle`, `SetCursor`)
/// to be added without breaking existing clients that match exhaustively.
///
/// # Example
///
/// ```
/// use nexacore_types::{
///     display_protocol::{ClientRequest, Rect},
///     wire::{decode_canonical, encode_canonical},
/// };
///
/// let req = ClientRequest::CreateSurface {
///     width: 800,
///     height: 600,
/// };
/// let bytes = encode_canonical(&req).expect("encode");
/// let back: ClientRequest = decode_canonical(&bytes).expect("decode");
/// assert!(matches!(
///     back,
///     ClientRequest::CreateSurface {
///         width: 800,
///         height: 600
///     }
/// ));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ClientRequest {
    /// Request the compositor to allocate a new surface of the given size.
    ///
    /// The compositor responds with [`CompositorEvent::SurfaceCreated`]
    /// carrying the assigned `surface_id`.
    CreateSurface {
        /// Width of the requested surface in pixels.
        width: u32,
        /// Height of the requested surface in pixels.
        height: u32,
    },

    /// Commit new pixel content for a surface and declare which sub-rects are
    /// dirty.
    ///
    /// The pixel data itself is transferred via a shared-memory segment
    /// registered at `CreateSurface` time (TASK-20 detail); the `damage` list
    /// tells the compositor which rects to re-read and repaint.
    ///
    /// Rects in `damage` are validated (intersected with the surface bounds,
    /// then the screen) before use — the compositor never trusts client values
    /// directly (ADR-0041 D4).
    Commit {
        /// The surface being updated (returned by a prior [`CompositorEvent::SurfaceCreated`]).
        surface_id: u32,
        /// Dirty rects in surface-local coordinates.  An empty list means the
        /// entire surface is dirty.
        ///
        /// Length is bounded by [`MAX_DAMAGE_RECTS`] at the protocol level;
        /// a client sending more rects than this is violating the protocol.
        damage: Vec<Rect>,
    },

    /// Request that the compositor destroy the surface.
    ///
    /// The compositor responds with [`CompositorEvent::Closed`].
    Destroy {
        /// The surface to destroy.
        surface_id: u32,
    },

    /// Request that the compositor move the window to `(x, y)`.
    ///
    /// Coordinates are in screen pixels.  The compositor clamps them to the
    /// screen bounds (ADR-0041 D4).
    Move {
        /// The surface whose window should move.
        surface_id: u32,
        /// New X coordinate of the window's top-left corner.
        x: i32,
        /// New Y coordinate of the window's top-left corner.
        y: i32,
    },
}

// ---------------------------------------------------------------------------
// Compositor → client
// ---------------------------------------------------------------------------

/// Events sent from the compositor to a client process.
///
/// Encoded with [`crate::wire::encode_canonical`] and delivered as
/// `MessageKind::Notification` on the [`DISPLAY_CHANNEL_NAME`] channel.
///
/// `#[non_exhaustive]` allows future events (e.g. `FocusIn`, `FocusOut`,
/// `Expose`) to be added without breaking existing clients.
///
/// # Example
///
/// ```
/// use nexacore_types::{
///     display_protocol::CompositorEvent,
///     wire::{decode_canonical, encode_canonical},
/// };
///
/// let ev = CompositorEvent::SurfaceCreated { surface_id: 42 };
/// let bytes = encode_canonical(&ev).expect("encode");
/// let back: CompositorEvent = decode_canonical(&bytes).expect("decode");
/// assert!(matches!(
///     back,
///     CompositorEvent::SurfaceCreated { surface_id: 42 }
/// ));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CompositorEvent {
    /// Acknowledgement that a [`ClientRequest::CreateSurface`] succeeded.
    ///
    /// The `surface_id` is the compositor-assigned identifier the client uses
    /// in subsequent [`ClientRequest::Commit`] / [`ClientRequest::Destroy`] /
    /// [`ClientRequest::Move`] messages.
    SurfaceCreated {
        /// Compositor-assigned surface identifier.
        surface_id: u32,
    },

    /// An input event routed to this client's focused window.
    ///
    /// Keyboard events are delivered only to the focused client (ADR-0041 D3).
    /// Pointer events are delivered to the client whose window is under the
    /// cursor (hit-test in the compositor; ADR-0041 D3).
    Input(DisplayInputEvent),

    /// Notification that a surface has been destroyed (either by the client's
    /// own [`ClientRequest::Destroy`] or by the compositor on shutdown).
    Closed {
        /// The surface that was destroyed.
        surface_id: u32,
    },

    /// The compositor is requesting a resize of the client's surface.
    ///
    /// The client should respond by allocating a new pixel buffer of the given
    /// dimensions and issuing a [`ClientRequest::Commit`].
    Configure {
        /// The surface to reconfigure.
        surface_id: u32,
        /// New width requested by the compositor.
        width: u32,
        /// New height requested by the compositor.
        height: u32,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{decode_canonical, encode_canonical};

    // --- Rect ---

    #[test]
    fn rect_round_trip() {
        let r = Rect {
            x: -5,
            y: 10,
            w: 200,
            h: 150,
        };
        let bytes = encode_canonical(&r).expect("encode");
        let back: Rect = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, r);
    }

    // --- ClientRequest ---

    #[test]
    fn client_request_create_surface_round_trip() {
        let req = ClientRequest::CreateSurface {
            width: 1920,
            height: 1080,
        };
        let bytes = encode_canonical(&req).expect("encode");
        assert!(bytes.len() <= MAX_CLIENT_REQUEST_BYTES);
        let back: ClientRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn client_request_commit_round_trip() {
        let req = ClientRequest::Commit {
            surface_id: 7,
            damage: alloc::vec![
                Rect {
                    x: 0,
                    y: 0,
                    w: 100,
                    h: 50
                },
                Rect {
                    x: 50,
                    y: 50,
                    w: 200,
                    h: 200
                },
            ],
        };
        let bytes = encode_canonical(&req).expect("encode");
        assert!(bytes.len() <= MAX_CLIENT_REQUEST_BYTES);
        let back: ClientRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn client_request_commit_max_damage_rects_fits_bound() {
        // Worst case: MAX_DAMAGE_RECTS rects with max values.
        let count = u32::try_from(MAX_DAMAGE_RECTS).expect("MAX_DAMAGE_RECTS fits u32");
        let rects: Vec<Rect> = (0..count)
            .map(|_| Rect {
                x: i32::MAX,
                y: i32::MIN,
                w: u32::MAX,
                h: u32::MAX,
            })
            .collect();
        let req = ClientRequest::Commit {
            surface_id: u32::MAX,
            damage: rects,
        };
        let bytes = encode_canonical(&req).expect("encode worst-case Commit");
        assert!(
            bytes.len() <= MAX_CLIENT_REQUEST_BYTES,
            "worst-case Commit ({} B) exceeds MAX_CLIENT_REQUEST_BYTES ({})",
            bytes.len(),
            MAX_CLIENT_REQUEST_BYTES
        );
    }

    #[test]
    fn client_request_destroy_round_trip() {
        let req = ClientRequest::Destroy { surface_id: 3 };
        let bytes = encode_canonical(&req).expect("encode");
        let back: ClientRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn client_request_move_round_trip() {
        let req = ClientRequest::Move {
            surface_id: 1,
            x: -100,
            y: 200,
        };
        let bytes = encode_canonical(&req).expect("encode");
        let back: ClientRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    // --- CompositorEvent ---

    #[test]
    fn compositor_event_surface_created_round_trip() {
        let ev = CompositorEvent::SurfaceCreated { surface_id: 42 };
        let bytes = encode_canonical(&ev).expect("encode");
        assert!(bytes.len() <= MAX_COMPOSITOR_EVENT_BYTES);
        let back: CompositorEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ev);
    }

    #[test]
    fn compositor_event_input_key_round_trip() {
        let ev = CompositorEvent::Input(DisplayInputEvent::Key {
            code: b'\t',
            pressed: true,
        });
        let bytes = encode_canonical(&ev).expect("encode");
        assert!(bytes.len() <= MAX_COMPOSITOR_EVENT_BYTES);
        let back: CompositorEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ev);
    }

    #[test]
    fn compositor_event_input_pointer_round_trip() {
        let ev = CompositorEvent::Input(DisplayInputEvent::Pointer {
            x: u32::MAX,
            y: u32::MAX,
            buttons: 0xFF,
        });
        let bytes = encode_canonical(&ev).expect("encode");
        assert!(
            bytes.len() <= MAX_COMPOSITOR_EVENT_BYTES,
            "pointer event ({} B) exceeds MAX_COMPOSITOR_EVENT_BYTES ({})",
            bytes.len(),
            MAX_COMPOSITOR_EVENT_BYTES
        );
        let back: CompositorEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ev);
    }

    #[test]
    fn compositor_event_closed_round_trip() {
        let ev = CompositorEvent::Closed { surface_id: 99 };
        let bytes = encode_canonical(&ev).expect("encode");
        let back: CompositorEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ev);
    }

    #[test]
    fn compositor_event_configure_round_trip() {
        let ev = CompositorEvent::Configure {
            surface_id: 5,
            width: 1280,
            height: 720,
        };
        let bytes = encode_canonical(&ev).expect("encode");
        assert!(bytes.len() <= MAX_COMPOSITOR_EVENT_BYTES);
        let back: CompositorEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ev);
    }
}
