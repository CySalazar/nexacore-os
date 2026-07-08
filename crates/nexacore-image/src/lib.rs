//! # `nexacore-image`
//!
//! Host-testable core of the NexaCore image viewer/editor (WS8-03).
//!
//! Like `nexacore-media` (WS8-02), every effect that needs a real codec library
//! sits behind a trait so the orchestration and edit logic stays host-testable:
//!
//! * **[`format`]** — magic-byte [`format::sniff_format`] + header-only
//!   dimension parsers for PNG / JPEG / WebP / AVIF ([`format::parse_info`],
//!   WS8-03.1 / WS8-03.2 at the header level).
//! * **[`buffer`]** — [`buffer::ImageBuffer`]: an RGBA8 pixel buffer with
//!   bounds-checked [`crop`](buffer::ImageBuffer::crop) (WS8-03.4) and
//!   [`rotate90`](buffer::ImageBuffer::rotate90) / `rotate180` / `rotate270` /
//!   flip (WS8-03.5).
//! * **[`viewport`]** — [`viewport::Viewport`]: an integer (permille-zoom)
//!   zoom/pan transform with image↔screen mapping and fit-to-screen (WS8-03.3).
//! * **[`annotate`]** — [`annotate::AnnotationLayer`]: a highlight / arrow /
//!   text-block annotation model with alpha compositing onto an
//!   [`buffer::ImageBuffer`] (WS8-03.6).
//! * **[`decode`]** — [`decode::ImageDecoder`] trait + [`decode::DecoderSelector`];
//!   the real pixel decode is library-gated (WS8-03.1 / WS8-03.2).
//! * **[`encode`]** — [`encode::ImageEncoder`] trait + a host round-trippable
//!   [`encode::RawCodec`] for the save path (WS8-03.7).
//!
//! All geometry is integer math so the crate is `no_std + alloc` and free of any
//! floating-point/std dependency.

#![no_std]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-image")]
#![deny(missing_docs)]
// The crate is pixel-manipulation heavy: u32↔usize↔i32 conversions in geometry
// are inherent and individually bounds-reasoned; raw indexing is avoided in
// favour of `.get()`/iterators.
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss, clippy::cast_lossless)]
// Integer division is the whole point of the permille-zoom / alpha-blend design
// (no floats for `no_std` determinism); each site's rounding is documented.
#![allow(clippy::integer_division)]
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

pub mod annotate;
pub mod buffer;
pub mod decode;
pub mod encode;
pub mod format;
pub mod viewport;

pub use crate::{
    annotate::{Annotation, AnnotationLayer, Color},
    buffer::ImageBuffer,
    decode::{DecodeError, ImageDecoder},
    encode::{EncodeError, ImageEncoder},
    format::{ImageFormat, ImageInfo, parse_info, sniff_format},
    viewport::Viewport,
};

/// Errors raised by the image core's pure operations (buffer/crop/format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageError {
    /// A pixel-buffer constructor got a byte length that does not match
    /// `width * height * 4`.
    BadBufferLength,
    /// A zero-area image (`width == 0` or `height == 0`) where one is required.
    EmptyImage,
    /// A crop/region rectangle falls outside the source image bounds.
    OutOfBounds,
    /// The byte stream is too short for the header being parsed.
    Truncated,
    /// The header bytes are present but malformed (bad magic, bad field).
    Malformed,
    /// The format is recognized but not handled by this parser/path.
    Unsupported,
}

impl core::fmt::Display for ImageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::BadBufferLength => "pixel buffer length does not match width*height*4",
            Self::EmptyImage => "image has zero width or height",
            Self::OutOfBounds => "region falls outside the image bounds",
            Self::Truncated => "byte stream too short for the header",
            Self::Malformed => "malformed image header",
            Self::Unsupported => "unsupported image format",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for ImageError {}

/// Crate result alias.
pub type Result<T> = core::result::Result<T, ImageError>;
