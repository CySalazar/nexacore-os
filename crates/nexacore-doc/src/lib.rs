//! # `nexacore-doc`
//!
//! Host-testable core of the NexaCore document/PDF viewer (WS8-04).
//!
//! Like `nexacore-media` (WS8-02), `nexacore-image` (WS8-03), and
//! `nexacore-print` (WS2-13), every effect that needs a real, large, untrusted
//! library sits behind a trait so the orchestration and interaction logic stays
//! host-testable and `no_std`:
//!
//! * **[`model`]** — [`model::Document`]: the format-agnostic page model (page
//!   sizes in PDF points), opened through the library-gated
//!   [`model::DocumentBackend`] seam (WS8-04.1).
//! * **[`render`]** — re-exports the [`render::PdfRasterizer`] seam from
//!   `nexacore-print` and adds a bounded [`render::PageCache`] that memoises
//!   rasterized pages by `(index, dpi)` (WS8-04.2). The real PDF rasterizer is
//!   the vetted, library-gated implementation behind the trait.
//! * **[`navigation`]** — [`navigation::ContinuousLayout`] (continuous-scroll
//!   geometry: total height, visible-page query, page-at-offset, scroll-to-page)
//!   and [`navigation::ThumbnailStrip`] (WS8-04.3).
//! * **[`zoom`]** — [`zoom::ZoomMode`] + [`zoom::resolve_scale_permille`]: an
//!   integer-permille zoom with fit-to-width / fit-to-page (WS8-04.7).
//! * **[`text`]** — [`text::TextLayout`] (positioned glyphs, caret hit-testing,
//!   word/line boundaries), extracted through the library-gated
//!   [`text::TextExtractor`] seam (WS8-04.4).
//! * **[`selection`]** — [`selection::Selection`] over caret positions +
//!   [`selection::Clipboard`] copy (WS8-04.5).
//! * **[`print`]** — [`print::print_pages`]: the print path into
//!   `nexacore-print`'s PWG-Raster pipeline (WS8-04.6 / WS2-13).
//!
//! All geometry is integer math, so the crate is `no_std + alloc` and free of
//! any floating-point or `std` dependency. The library selection (WS8-04.1) and
//! the rasterizer/text-extractor wiring stay behind the seams above; the real
//! decode + the VM-103 end-to-end (WS8-04.8) are device-side.

#![no_std]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-doc")]
#![deny(missing_docs)]
// The viewer is geometry-heavy: u32↔usize↔i32 conversions in layout math are
// inherent and individually bounds-reasoned; raw indexing is avoided in favour
// of `.get()` / iterators.
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss, clippy::cast_lossless)]
// Integer division is the whole point of the permille-zoom / fit math (no floats
// for `no_std` determinism); each site's rounding is documented.
#![allow(clippy::integer_division)]
// Tests assert on known-good fixtures; panicking accessors surface regressions
// as failures, not silent wrong values.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
    )
)]

extern crate alloc;

pub mod model;
pub mod navigation;
pub mod print;
pub mod render;
pub mod selection;
pub mod text;
pub mod zoom;

pub use model::{Document, DocumentBackend, DocumentError, DocumentFormat, PointSize};
pub use navigation::{ContinuousLayout, ThumbnailStrip, VisiblePage};
pub use selection::{Clipboard, Selection};
pub use text::{PositionedGlyph, Rect, TextExtractor, TextLayout};
pub use zoom::{PxSize, Viewport, ZoomMode, resolve_scale_permille};
