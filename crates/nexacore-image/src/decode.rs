//! [`ImageDecoder`] trait + [`DecoderSelector`] (WS8-03.1 / WS8-03.2).
//!
//! The real PNG/JPEG/WebP/AVIF pixel decode is **library-gated**: it lives
//! behind the [`ImageDecoder`] trait, exactly as the WS8-02 video codecs live
//! behind `VideoDecoder` and the WS5-03 ASR model behind `Transcriber`. The
//! orchestration here — sniff the format, pick a decoder that supports it,
//! produce an [`crate::buffer::ImageBuffer`] — is host-testable with a mock.

use alloc::{boxed::Box, vec::Vec};

use crate::{
    buffer::ImageBuffer,
    format::{ImageFormat, sniff_format},
};

/// Why a decode could not produce an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// No registered decoder handles the (sniffed) format.
    UnsupportedFormat,
    /// The format was not recognized from the header.
    UnknownFormat,
    /// The encoded bytes are malformed for the declared format.
    Malformed,
    /// The encoded stream ended before a full image was decoded.
    Truncated,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::UnsupportedFormat => "no decoder handles this image format",
            Self::UnknownFormat => "unrecognized image format",
            Self::Malformed => "malformed image data",
            Self::Truncated => "truncated image data",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for DecodeError {}

/// A pixel decoder for one or more [`ImageFormat`]s.
///
/// The production implementation wraps a vetted codec library and returns RGBA8
/// pixels; tests use a mock that returns a fixed buffer.
pub trait ImageDecoder {
    /// Returns `true` if this decoder can decode `format`.
    fn supports(&self, format: ImageFormat) -> bool;

    /// Decode `data` (already sniffed as `format`) into an RGBA8 image.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the bytes are malformed/truncated or the format is
    /// not handled.
    fn decode(
        &self,
        format: ImageFormat,
        data: &[u8],
    ) -> core::result::Result<ImageBuffer, DecodeError>;
}

/// Routes encoded bytes to the first registered [`ImageDecoder`] that supports
/// the sniffed format (WS8-03.1 / WS8-03.2).
#[derive(Default)]
pub struct DecoderSelector {
    decoders: Vec<Box<dyn ImageDecoder>>,
}

impl DecoderSelector {
    /// Create an empty selector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            decoders: Vec::new(),
        }
    }

    /// Register a decoder (later registrations are lower priority).
    pub fn register(&mut self, decoder: Box<dyn ImageDecoder>) {
        self.decoders.push(decoder);
    }

    /// Number of registered decoders.
    #[must_use]
    pub fn len(&self) -> usize {
        self.decoders.len()
    }

    /// Whether no decoder is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decoders.is_empty()
    }

    /// Sniff `data`, then decode it with the first decoder that supports the
    /// detected format.
    ///
    /// # Errors
    ///
    /// - [`DecodeError::UnknownFormat`] if the header matches no known format.
    /// - [`DecodeError::UnsupportedFormat`] if no registered decoder handles it.
    /// - any error the chosen decoder returns.
    pub fn decode(&self, data: &[u8]) -> core::result::Result<ImageBuffer, DecodeError> {
        let format = sniff_format(data).ok_or(DecodeError::UnknownFormat)?;
        let decoder = self
            .decoders
            .iter()
            .find(|d| d.supports(format))
            .ok_or(DecodeError::UnsupportedFormat)?;
        decoder.decode(format, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock decoder that "decodes" any PNG to a fixed 1×1 red pixel.
    struct PngMock;
    impl ImageDecoder for PngMock {
        fn supports(&self, format: ImageFormat) -> bool {
            format == ImageFormat::Png
        }
        fn decode(
            &self,
            _format: ImageFormat,
            _data: &[u8],
        ) -> core::result::Result<ImageBuffer, DecodeError> {
            ImageBuffer::filled(1, 1, [255, 0, 0, 255]).map_err(|_| DecodeError::Malformed)
        }
    }

    fn png_bytes() -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        v.extend_from_slice(&[0, 0, 0, 13]);
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&[8, 6, 0, 0, 0]);
        v
    }

    #[test]
    fn selector_routes_to_supporting_decoder() {
        let mut sel = DecoderSelector::new();
        sel.register(Box::new(PngMock));
        assert_eq!(sel.len(), 1);
        let img = sel.decode(&png_bytes()).unwrap();
        assert_eq!(img.pixel(0, 0), Some([255, 0, 0, 255]));
    }

    #[test]
    fn selector_errs_on_unknown_format() {
        let sel = DecoderSelector::new();
        assert_eq!(
            sel.decode(b"not an image").unwrap_err(),
            DecodeError::UnknownFormat
        );
    }

    #[test]
    fn selector_errs_when_no_decoder_supports() {
        // Empty selector: the PNG is recognized but nothing decodes it.
        let sel = DecoderSelector::new();
        assert_eq!(
            sel.decode(&png_bytes()).unwrap_err(),
            DecodeError::UnsupportedFormat
        );
    }
}
