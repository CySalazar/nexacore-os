//! # `nexacore-display`
//!
//! Userspace compositor and window manager for NexaCore OS (ADR-0041, TASK-19,
//! DE-C2 / DE-C3).
//!
//! ## Purpose
//!
//! This crate is the **host-testable core** of the NexaCore display subsystem.
//! It provides:
//!
//! * **[`geometry`]** — [`geometry::Rect`] (signed origin, unsigned size) and
//!   [`geometry::DamageRegion`] (bounded dirty-rect set with overflow coalescing).
//! * **[`surface`]** — [`surface::Surface`] (per-window ARGB pixel buffer),
//!   [`surface::SurfaceId`], and [`surface::WindowId`] newtypes.
//! * **[`window`]** — [`window::Window`] binding a surface to screen coordinates,
//!   z-order, and visibility.
//! * **[`wm`]** — [`wm::WindowManager`]: lifecycle, z-order, focus, and input
//!   routing (`route_input` keys to focused window, pointer to hit-test).
//! * **[`compositor`]** — [`compositor::Compositor`]: damage-driven back-to-front
//!   compositing into a caller-owned back buffer.
//!
//! ## Security invariants (ADR-0041 D4)
//!
//! * Every client-supplied pixel slice is validated for exact size before write.
//! * Every client damage rect is intersected with the surface bounds, translated
//!   to screen coords, and intersected with the screen before accumulation.
//!   An out-of-bounds rect becomes a clamped (possibly empty) rect — never an
//!   out-of-bounds framebuffer write.
//! * The compositor blit uses bounds-checked slice indexing throughout; no
//!   `unsafe` code is present in this crate.
//!
//! ## `no_std` + `alloc`
//!
//! This crate compiles for both the developer host (`x86_64-unknown-linux-gnu`)
//! and the bare-metal Ring-3 target (`x86_64-unknown-none`).  It uses
//! `alloc::{string::String, vec::Vec}` but no `std` API.
//!
//! ## Architecture reference
//!
//! See [`ADR-0041`](../../../docs/adr/0041-nexacore-display-compositor-wm.md) for
//! the full design rationale, alternatives considered, and consequences.
//!
//! The bootable `crates/nexacore-display-image` (workspace-excluded, built only for
//! `x86_64-unknown-none`) maps the framebuffer via `nexacore-usys::display`, drives
//! this compositor, and drains the `nexacore_types::display_channel` input channel.
//! That image crate is the TASK-19 verification artifact; it is NOT part of
//! this crate.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-display")]
#![no_std]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
    )
)]

// `alloc` provides `String`, `Vec`, and `Box` without `std`.
extern crate alloc;

pub mod animation;
pub mod atlas;
pub mod capture;
pub mod color;
pub mod compositor;
pub mod effects;
pub mod font;
pub mod font_stack;
pub mod geometry;
pub mod hint;
pub mod input;
pub mod kerning;
pub mod keymap;
pub mod output;
pub mod present;
pub mod raster;
pub mod render_backend;
pub mod resize;
pub mod scale;
pub mod scene;
/// Complex-text analysis for shaping (WS7-17).
///
/// Script itemization, the Unicode BiDi algorithm, and Arabic contextual joining.
pub mod shaping;
pub mod surface;
pub mod tokens;
pub mod wallpaper;
pub mod window;
pub mod wm;
pub mod wm_polish;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by `nexacore-display` operations.
///
/// All variants carry enough information to identify the failure category;
/// none carry runtime secret data (ADR-0041 security model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisplayError {
    /// A pixel slice supplied by the client does not have the expected length
    /// (`width * height` pixels).
    ///
    /// This is the primary "never trust the client" invariant:
    /// [`surface::Surface::commit`] rejects any mismatched slice before any
    /// pixel is written (ADR-0041 D4).
    InvalidSize,

    /// The referenced window does not exist in the [`wm::WindowManager`].
    UnknownWindow(surface::WindowId),

    /// The back buffer supplied to [`compositor::Compositor::composite`] is
    /// smaller than `screen_w * screen_h` pixels.
    BackBufferTooSmall,

    /// The referenced output does not exist in the
    /// [`output::OutputManager`].
    UnknownOutput(output::OutputId),

    /// A mode index is out of range for the referenced output, or the output
    /// has no modes.
    InvalidMode,

    /// An output with the same id is already registered (hotplug connect).
    DuplicateOutput(output::OutputId),
}

impl core::fmt::Display for DisplayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSize => write!(
                f,
                "display: pixel slice length does not match surface dimensions"
            ),
            Self::UnknownWindow(id) => write!(f, "display: unknown window id {}", id.0),
            Self::BackBufferTooSmall => {
                write!(f, "display: back buffer too small for screen dimensions")
            }
            Self::UnknownOutput(id) => write!(f, "display: unknown output id {}", id.0),
            Self::InvalidMode => write!(f, "display: invalid or unavailable output mode"),
            Self::DuplicateOutput(id) => {
                write!(f, "display: output id {} already registered", id.0)
            }
        }
    }
}

// `thiserror` is not used here because the Error derive would import
// `std::error::Error`; instead we implement `core::error::Error` directly,
// which is stable since Rust 1.81 and is what `thiserror` v2 uses internally
// when `default-features = false`.
impl core::error::Error for DisplayError {}
