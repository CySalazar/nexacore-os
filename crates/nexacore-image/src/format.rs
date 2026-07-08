//! Format sniffing and header-only dimension parsing (WS8-03.1 / WS8-03.2).
//!
//! These parsers recover the *format and pixel dimensions* from a file header
//! without decoding any pixels — the image-app shell needs them to size the
//! viewport before the (library-gated) [`crate::decode::ImageDecoder`] runs.
//! Every read is `.get()`-checked, so a truncated or malformed header returns
//! an error instead of panicking.

use crate::{ImageError, Result};

/// A recognized still-image container format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageFormat {
    /// PNG (`\x89PNG\r\n\x1a\n`).
    Png,
    /// JPEG (`\xFF\xD8\xFF`).
    Jpeg,
    /// WebP (`RIFF....WEBP`).
    WebP,
    /// AVIF (ISO-BMFF `ftyp` with an `avif`/`avis` brand).
    Avif,
}

impl ImageFormat {
    /// A short lowercase label / extension for this format.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::WebP => "webp",
            Self::Avif => "avif",
        }
    }
}

/// Format plus pixel dimensions recovered from a header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageInfo {
    /// The detected container format.
    pub format: ImageFormat,
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
}

/// Detect the image format from the leading magic bytes (WS8-03.1 / WS8-03.2).
///
/// Returns `None` if no known signature matches.
#[must_use]
pub fn sniff_format(data: &[u8]) -> Option<ImageFormat> {
    const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if data.get(..8) == Some(&PNG_MAGIC) {
        return Some(ImageFormat::Png);
    }
    if data.get(..3) == Some(&[0xFF, 0xD8, 0xFF]) {
        return Some(ImageFormat::Jpeg);
    }
    if data.get(..4) == Some(b"RIFF") && data.get(8..12) == Some(b"WEBP") {
        return Some(ImageFormat::WebP);
    }
    // ISO-BMFF: bytes 4..8 are `ftyp`; the major brand at 8..12 names the codec.
    if data.get(4..8) == Some(b"ftyp") {
        if let Some(brand) = data.get(8..12) {
            if brand == b"avif" || brand == b"avis" {
                return Some(ImageFormat::Avif);
            }
        }
    }
    None
}

/// Parse the format and pixel dimensions from a file header (WS8-03.1 / .2).
///
/// # Errors
///
/// - [`ImageError::Unsupported`] if no known signature matches.
/// - [`ImageError::Truncated`] if the header is too short for its dimensions.
/// - [`ImageError::Malformed`] if the header fields are inconsistent.
pub fn parse_info(data: &[u8]) -> Result<ImageInfo> {
    match sniff_format(data).ok_or(ImageError::Unsupported)? {
        ImageFormat::Png => parse_png(data),
        ImageFormat::Jpeg => parse_jpeg(data),
        ImageFormat::WebP => parse_webp(data),
        ImageFormat::Avif => parse_avif(data),
    }
}

/// Read a big-endian u32 at `off`, or `None` if out of bounds.
fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

/// Read a little-endian u16 at `off`, or `None` if out of bounds.
fn le_u16(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?))
}

fn parse_png(data: &[u8]) -> Result<ImageInfo> {
    // After the 8-byte magic: IHDR chunk (len[4] "IHDR"[4] width[4] height[4]).
    // Width is at byte 16, height at byte 20 (big-endian).
    if data.get(12..16) != Some(b"IHDR") {
        return Err(ImageError::Malformed);
    }
    let width = be_u32(data, 16).ok_or(ImageError::Truncated)?;
    let height = be_u32(data, 20).ok_or(ImageError::Truncated)?;
    if width == 0 || height == 0 {
        return Err(ImageError::Malformed);
    }
    Ok(ImageInfo {
        format: ImageFormat::Png,
        width,
        height,
    })
}

fn parse_jpeg(data: &[u8]) -> Result<ImageInfo> {
    // Walk the marker segments from offset 2 until a Start-Of-Frame (SOF0..SOF3,
    // SOF5..SOF7, SOF9..SOF11, SOF13..SOF15) carries the dimensions.
    let mut i = 2usize;
    loop {
        // Each marker is 0xFF then a code; skip any 0xFF fill bytes.
        let mut marker = *data.get(i).ok_or(ImageError::Truncated)?;
        if marker != 0xFF {
            return Err(ImageError::Malformed);
        }
        let mut code = *data.get(i + 1).ok_or(ImageError::Truncated)?;
        while code == 0xFF {
            // Padding fill: advance one byte and re-read.
            i += 1;
            marker = code;
            code = *data.get(i + 1).ok_or(ImageError::Truncated)?;
        }
        let _ = marker;
        // Standalone markers (RSTn, SOI, EOI, TEM) carry no length payload.
        if code == 0xD8 || code == 0xD9 || (0xD0..=0xD7).contains(&code) || code == 0x01 {
            i += 2;
            continue;
        }
        let seg_len = le_be_u16(data, i + 2).ok_or(ImageError::Truncated)? as usize;
        if seg_len < 2 {
            return Err(ImageError::Malformed);
        }
        // SOF markers carrying frame dimensions.
        let is_sof = matches!(code,
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF);
        if is_sof {
            // Segment: marker[2] len[2] precision[1] height[2] width[2] ...
            let height = le_be_u16(data, i + 5).ok_or(ImageError::Truncated)?;
            let width = le_be_u16(data, i + 7).ok_or(ImageError::Truncated)?;
            if width == 0 || height == 0 {
                return Err(ImageError::Malformed);
            }
            return Ok(ImageInfo {
                format: ImageFormat::Jpeg,
                width: width as u32,
                height: height as u32,
            });
        }
        // Skip this segment (2-byte marker + length-counted payload).
        i = i.checked_add(2 + seg_len).ok_or(ImageError::Malformed)?;
    }
}

/// Big-endian u16 (JPEG segment lengths and dimensions are big-endian).
fn le_be_u16(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(off..off + 2)?.try_into().ok()?))
}

fn parse_webp(data: &[u8]) -> Result<ImageInfo> {
    // After "RIFF"[4] size[4] "WEBP"[4], a chunk fourcc at 12..16 selects the
    // sub-format: "VP8 " (lossy), "VP8L" (lossless), "VP8X" (extended).
    let fourcc = data.get(12..16).ok_or(ImageError::Truncated)?;
    match fourcc {
        b"VP8X" => {
            // Extended header: flags[1] reserved[3] then canvas w-1[3] h-1[3]
            // (little-endian 24-bit), starting at byte 24.
            let w = le_u24(data, 24).ok_or(ImageError::Truncated)?;
            let h = le_u24(data, 27).ok_or(ImageError::Truncated)?;
            Ok(ImageInfo {
                format: ImageFormat::WebP,
                width: w + 1,
                height: h + 1,
            })
        }
        b"VP8 " => {
            // Lossy: 16-bit width/height (14 bits used) at bytes 26/28 LE.
            let w = le_u16(data, 26).ok_or(ImageError::Truncated)?;
            let h = le_u16(data, 28).ok_or(ImageError::Truncated)?;
            Ok(ImageInfo {
                format: ImageFormat::WebP,
                width: (w & 0x3FFF) as u32,
                height: (h & 0x3FFF) as u32,
            })
        }
        b"VP8L" => {
            // Lossless: 1-byte signature (0x2F) then 14-bit w-1, 14-bit h-1
            // packed little-endian starting at byte 21.
            let bits = le_u32(data, 21).ok_or(ImageError::Truncated)?;
            let w = (bits & 0x3FFF) + 1;
            let h = ((bits >> 14) & 0x3FFF) + 1;
            Ok(ImageInfo {
                format: ImageFormat::WebP,
                width: w,
                height: h,
            })
        }
        _ => Err(ImageError::Malformed),
    }
}

/// Little-endian 24-bit value at `off`.
fn le_u24(data: &[u8], off: usize) -> Option<u32> {
    let [b0, b1, b2]: [u8; 3] = data.get(off..off + 3)?.try_into().ok()?;
    Some(u32::from(b0) | (u32::from(b1) << 8) | (u32::from(b2) << 16))
}

/// Little-endian u32 at `off`.
fn le_u32(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

fn parse_avif(data: &[u8]) -> Result<ImageInfo> {
    // ISO-BMFF: find the `ispe` (Image Spatial Extents) box, whose payload is
    // version[1] flags[3] width[4] height[4] (big-endian). Scan for the fourcc
    // rather than walking the full box tree (sufficient for header dimensions).
    let needle = b"ispe";
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if data.get(i..i + 4) == Some(needle) {
            // Box body starts after the fourcc: version+flags (4) then w,h.
            let w = be_u32(data, i + 8).ok_or(ImageError::Truncated)?;
            let h = be_u32(data, i + 12).ok_or(ImageError::Truncated)?;
            if w == 0 || h == 0 {
                return Err(ImageError::Malformed);
            }
            return Ok(ImageInfo {
                format: ImageFormat::Avif,
                width: w,
                height: h,
            });
        }
        i += 1;
    }
    Err(ImageError::Malformed)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn png_header(w: u32, h: u32) -> Vec<u8> {
        let mut v = alloc::vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        v.extend_from_slice(&[0, 0, 0, 13]); // IHDR length
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 6, 0, 0, 0]); // bit depth, color type, etc.
        v
    }

    fn jpeg_header(w: u16, h: u16) -> Vec<u8> {
        let mut v = alloc::vec![0xFF, 0xD8, 0xFF]; // SOI + start of next marker
        // APP0 (JFIF) segment: 0xFF 0xE0 len[2] payload...
        v.push(0xE0);
        v.extend_from_slice(&7u16.to_be_bytes()); // len = 7 (2 + 5 payload)
        v.extend_from_slice(b"JFIF\0"); // 5-byte payload
        // SOF0: 0xFF 0xC0 len[2] precision[1] height[2] width[2] ...
        v.extend_from_slice(&[0xFF, 0xC0]);
        v.extend_from_slice(&17u16.to_be_bytes());
        v.push(8); // precision
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 0, 3, 0x11, 0]); // components
        v
    }

    fn webp_vp8x_header(w: u32, h: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"RIFF");
        v.extend_from_slice(&0u32.to_le_bytes()); // file size (ignored)
        v.extend_from_slice(b"WEBP");
        v.extend_from_slice(b"VP8X");
        v.extend_from_slice(&10u32.to_le_bytes()); // chunk size
        v.extend_from_slice(&[0, 0, 0, 0]); // flags + reserved
        let wm1 = w - 1;
        let hm1 = h - 1;
        v.extend_from_slice(&wm1.to_le_bytes()[..3]);
        v.extend_from_slice(&hm1.to_le_bytes()[..3]);
        v
    }

    fn avif_header(w: u32, h: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0, 0, 0, 0x18]); // ftyp box size
        v.extend_from_slice(b"ftyp");
        v.extend_from_slice(b"avif");
        v.extend_from_slice(&[0; 16]); // minor + compatible brands
        // ispe box: size[4] "ispe" version+flags[4] w[4] h[4]
        v.extend_from_slice(&[0, 0, 0, 0x14]);
        v.extend_from_slice(b"ispe");
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v
    }

    #[test]
    fn sniff_recognizes_all_formats() {
        assert_eq!(sniff_format(&png_header(1, 1)), Some(ImageFormat::Png));
        assert_eq!(sniff_format(&jpeg_header(1, 1)), Some(ImageFormat::Jpeg));
        assert_eq!(
            sniff_format(&webp_vp8x_header(1, 1)),
            Some(ImageFormat::WebP)
        );
        assert_eq!(sniff_format(&avif_header(1, 1)), Some(ImageFormat::Avif));
        assert_eq!(sniff_format(b"not an image"), None);
    }

    #[test]
    fn parse_png_dimensions() {
        let info = parse_info(&png_header(1920, 1080)).unwrap();
        assert_eq!(info.format, ImageFormat::Png);
        assert_eq!((info.width, info.height), (1920, 1080));
    }

    #[test]
    fn parse_jpeg_dimensions() {
        let info = parse_info(&jpeg_header(640, 480)).unwrap();
        assert_eq!(info.format, ImageFormat::Jpeg);
        assert_eq!((info.width, info.height), (640, 480));
    }

    #[test]
    fn parse_webp_vp8x_dimensions() {
        let info = parse_info(&webp_vp8x_header(800, 600)).unwrap();
        assert_eq!(info.format, ImageFormat::WebP);
        assert_eq!((info.width, info.height), (800, 600));
    }

    #[test]
    fn parse_avif_dimensions() {
        let info = parse_info(&avif_header(256, 144)).unwrap();
        assert_eq!(info.format, ImageFormat::Avif);
        assert_eq!((info.width, info.height), (256, 144));
    }

    #[test]
    fn truncated_png_errs() {
        let mut h = png_header(10, 10);
        h.truncate(18); // cut into the height field
        assert_eq!(parse_info(&h).unwrap_err(), ImageError::Truncated);
    }

    #[test]
    fn unknown_format_errs() {
        assert_eq!(
            parse_info(b"\x00\x01\x02\x03nope").unwrap_err(),
            ImageError::Unsupported
        );
    }

    #[test]
    fn format_labels_unique() {
        let labels = [
            ImageFormat::Png.label(),
            ImageFormat::Jpeg.label(),
            ImageFormat::WebP.label(),
            ImageFormat::Avif.label(),
        ];
        for (i, a) in labels.iter().enumerate() {
            for b in labels.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}
