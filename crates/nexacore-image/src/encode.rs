//! [`ImageEncoder`] trait + the host round-trippable [`RawCodec`] (WS8-03.7).
//!
//! Saving a real PNG/JPEG is **library-gated** (it needs DEFLATE / a JPEG
//! encoder), so it lives behind the [`ImageEncoder`] trait. To keep the
//! save/load path host-testable end-to-end, [`RawCodec`] implements a tiny
//! self-describing uncompressed container (`NCIM` magic + dimensions + RGBA8)
//! that round-trips an [`ImageBuffer`] exactly.

use alloc::vec::Vec;

use crate::{
    buffer::{CHANNELS, ImageBuffer},
    format::ImageFormat,
};

/// Why an encode could not produce bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// No registered encoder handles the requested format.
    UnsupportedFormat,
    /// The image could not be serialized (e.g. it is empty).
    BadImage,
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::UnsupportedFormat => "no encoder handles this output format",
            Self::BadImage => "image cannot be encoded",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for EncodeError {}

/// An encoder that serializes an [`ImageBuffer`] to one or more output formats.
///
/// The production implementation wraps a vetted codec library (PNG/JPEG/WebP);
/// [`RawCodec`] is the host round-trip implementation.
pub trait ImageEncoder {
    /// Returns `true` if this encoder can emit `format`.
    fn supports(&self, format: ImageFormat) -> bool;

    /// Encode `image` into `format` bytes.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] when the format is unsupported or the image is invalid.
    fn encode(
        &self,
        image: &ImageBuffer,
        format: ImageFormat,
    ) -> core::result::Result<Vec<u8>, EncodeError>;
}

/// Magic prefix of the [`RawCodec`] container.
const RAW_MAGIC: &[u8; 4] = b"NCIM";

/// A lossless, uncompressed RGBA container used to exercise the save/load path
/// host-side without a real codec library (WS8-03.7).
///
/// Layout: `"NCIM"` · width `u32` LE · height `u32` LE · RGBA8 pixels.
#[derive(Debug, Default, Clone, Copy)]
pub struct RawCodec;

impl RawCodec {
    /// Encode `image` to the raw container.
    #[must_use]
    pub fn encode_raw(image: &ImageBuffer) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + image.pixels().len());
        out.extend_from_slice(RAW_MAGIC);
        out.extend_from_slice(&image.width().to_le_bytes());
        out.extend_from_slice(&image.height().to_le_bytes());
        out.extend_from_slice(image.pixels());
        out
    }

    /// Decode a raw container produced by [`encode_raw`](Self::encode_raw).
    ///
    /// # Errors
    ///
    /// [`EncodeError::BadImage`] if the magic, dimensions, or pixel length are
    /// inconsistent.
    pub fn decode_raw(data: &[u8]) -> core::result::Result<ImageBuffer, EncodeError> {
        if data.get(..4) != Some(RAW_MAGIC.as_slice()) {
            return Err(EncodeError::BadImage);
        }
        let w_arr: [u8; 4] = data
            .get(4..8)
            .ok_or(EncodeError::BadImage)?
            .try_into()
            .map_err(|_| EncodeError::BadImage)?;
        let h_arr: [u8; 4] = data
            .get(8..12)
            .ok_or(EncodeError::BadImage)?
            .try_into()
            .map_err(|_| EncodeError::BadImage)?;
        let width = u32::from_le_bytes(w_arr);
        let height = u32::from_le_bytes(h_arr);
        let pixels = data.get(12..).ok_or(EncodeError::BadImage)?;
        if pixels.len() != width as usize * height as usize * CHANNELS {
            return Err(EncodeError::BadImage);
        }
        ImageBuffer::from_rgba(width, height, pixels.to_vec()).map_err(|_| EncodeError::BadImage)
    }
}

impl ImageEncoder for RawCodec {
    fn supports(&self, _format: ImageFormat) -> bool {
        // The raw codec is format-agnostic: it stores RGBA verbatim regardless
        // of the requested container (it is the host save/load stand-in).
        true
    }

    fn encode(
        &self,
        image: &ImageBuffer,
        _format: ImageFormat,
    ) -> core::result::Result<Vec<u8>, EncodeError> {
        Ok(Self::encode_raw(image))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_round_trips_exactly() {
        let img = ImageBuffer::filled(3, 2, [10, 20, 30, 40]).unwrap();
        let bytes = RawCodec::encode_raw(&img);
        let back = RawCodec::decode_raw(&bytes).unwrap();
        assert_eq!(back, img);
    }

    #[test]
    fn encoder_trait_round_trips() {
        let img = ImageBuffer::filled(2, 2, [1, 2, 3, 4]).unwrap();
        let codec = RawCodec;
        let bytes = codec.encode(&img, ImageFormat::Png).unwrap();
        assert_eq!(RawCodec::decode_raw(&bytes).unwrap(), img);
    }

    #[test]
    fn decode_raw_rejects_bad_magic() {
        assert_eq!(
            RawCodec::decode_raw(b"XXXX....").unwrap_err(),
            EncodeError::BadImage
        );
    }

    #[test]
    fn decode_raw_rejects_length_mismatch() {
        let mut bytes = RawCodec::encode_raw(&ImageBuffer::filled(2, 2, [0; 4]).unwrap());
        bytes.pop(); // corrupt the pixel length
        assert_eq!(
            RawCodec::decode_raw(&bytes).unwrap_err(),
            EncodeError::BadImage
        );
    }
}
