//! PWG-Raster page-header encoding (WS2-13.6).
//!
//! PWG Raster (PWG 5102.4) is the rasterized print format IPP Everywhere
//! printers accept: a 4-byte file sync word (`"RaS2"`) followed, per page, by a
//! fixed 1796-byte page header and then the raster rows. This module encodes the
//! sync word and the **geometry-bearing** fields of the page header (width,
//! height, bits-per-colour/-pixel, colour space, resolution, bytes-per-line) at
//! their cups-raster-v2 offsets, zero-filling the reserved fields. Byte-exact
//! interop with a physical printer is validated on the LAN (WS2-13.8); the
//! encode/decode here is host-tested for self-consistency and the geometry math.

use alloc::vec::Vec;

/// The PWG Raster file sync word (big-endian, version 2).
pub const SYNC_WORD: [u8; 4] = *b"RaS2";

/// Size of a single PWG Raster page header, in bytes (PWG 5102.4 §4).
pub const PAGE_HEADER_LEN: usize = 1796;

// cups-raster-v2 field offsets within the 1796-byte page header for the fields
// this encoder sets (the four 64-byte cups string fields occupy 0..256).
const OFF_HW_RES_X: usize = 276;
const OFF_HW_RES_Y: usize = 280;
const OFF_CUPS_WIDTH: usize = 372;
const OFF_CUPS_HEIGHT: usize = 376;
const OFF_CUPS_BITS_PER_COLOR: usize = 384;
const OFF_CUPS_BITS_PER_PIXEL: usize = 388;
const OFF_CUPS_BYTES_PER_LINE: usize = 392;
const OFF_CUPS_COLOR_SPACE: usize = 400;
const OFF_CUPS_NUM_COLORS: usize = 420;

/// The PWG/cups raster colour space of a page (the codes this encoder emits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ColorSpace {
    /// 8-bit sRGB colour (cups `CUPS_CSPACE_SRGB`).
    Srgb = 19,
    /// 8-bit grayscale (cups `CUPS_CSPACE_SGRAY`).
    Sgray = 18,
    /// 1-bit black (cups `CUPS_CSPACE_K`).
    Black = 3,
}

impl ColorSpace {
    /// Number of colour channels for this space.
    #[must_use]
    pub const fn num_colors(self) -> u32 {
        match self {
            Self::Srgb => 3,
            Self::Sgray | Self::Black => 1,
        }
    }
}

/// The geometry of one rasterized page (WS2-13.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageGeometry {
    /// Page width in pixels.
    pub width: u32,
    /// Page height in pixels.
    pub height: u32,
    /// Bits per colour channel (1 or 8).
    pub bits_per_color: u32,
    /// Colour space.
    pub color_space: ColorSpace,
    /// Render resolution in DPI (applied to both axes).
    pub dpi: u32,
}

impl PageGeometry {
    /// Bits per pixel = bits-per-colour × channels.
    #[must_use]
    pub const fn bits_per_pixel(self) -> u32 {
        self.bits_per_color * self.color_space.num_colors()
    }

    /// Bytes per raster row (ceil to a byte boundary).
    #[must_use]
    pub const fn bytes_per_line(self) -> u32 {
        (self.width * self.bits_per_pixel()).div_ceil(8)
    }

    /// Encode the 1796-byte PWG Raster page header for this geometry (WS2-13.6).
    #[must_use]
    pub fn encode_header(self) -> Vec<u8> {
        let mut h = alloc::vec![0u8; PAGE_HEADER_LEN];
        put_u32(&mut h, OFF_HW_RES_X, self.dpi);
        put_u32(&mut h, OFF_HW_RES_Y, self.dpi);
        put_u32(&mut h, OFF_CUPS_WIDTH, self.width);
        put_u32(&mut h, OFF_CUPS_HEIGHT, self.height);
        put_u32(&mut h, OFF_CUPS_BITS_PER_COLOR, self.bits_per_color);
        put_u32(&mut h, OFF_CUPS_BITS_PER_PIXEL, self.bits_per_pixel());
        put_u32(&mut h, OFF_CUPS_BYTES_PER_LINE, self.bytes_per_line());
        put_u32(&mut h, OFF_CUPS_COLOR_SPACE, self.color_space as u32);
        put_u32(&mut h, OFF_CUPS_NUM_COLORS, self.color_space.num_colors());
        h
    }

    /// Decode the geometry fields from a 1796-byte page header (inverse of
    /// [`encode_header`](Self::encode_header)).
    ///
    /// # Errors
    ///
    /// Returns `None` if the header is too short or carries an unknown colour
    /// space.
    #[must_use]
    pub fn decode_header(header: &[u8]) -> Option<Self> {
        if header.len() < PAGE_HEADER_LEN {
            return None;
        }
        let color_space = match get_u32(header, OFF_CUPS_COLOR_SPACE)? {
            19 => ColorSpace::Srgb,
            18 => ColorSpace::Sgray,
            3 => ColorSpace::Black,
            _ => return None,
        };
        Some(Self {
            width: get_u32(header, OFF_CUPS_WIDTH)?,
            height: get_u32(header, OFF_CUPS_HEIGHT)?,
            bits_per_color: get_u32(header, OFF_CUPS_BITS_PER_COLOR)?,
            color_space,
            dpi: get_u32(header, OFF_HW_RES_X)?,
        })
    }
}

/// Begin a PWG Raster stream: the file sync word followed by the first page's
/// header (WS2-13.6). Raster rows are appended by the caller.
#[must_use]
pub fn begin_page(geometry: PageGeometry) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + PAGE_HEADER_LEN);
    out.extend_from_slice(&SYNC_WORD);
    out.extend_from_slice(&geometry.encode_header());
    out
}

fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    if let Some(slot) = buf.get_mut(off..off + 4) {
        slot.copy_from_slice(&value.to_be_bytes());
    }
}

fn get_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srgb_a4_300dpi() -> PageGeometry {
        PageGeometry {
            width: 2480, // A4 @ 300 dpi
            height: 3508,
            bits_per_color: 8,
            color_space: ColorSpace::Srgb,
            dpi: 300,
        }
    }

    #[test]
    fn bits_and_bytes_per_line_math() {
        let g = srgb_a4_300dpi();
        assert_eq!(g.bits_per_pixel(), 24);
        assert_eq!(g.bytes_per_line(), 2480 * 3);
        // 1-bit black: 8 pixels per byte, ceil.
        let bw = PageGeometry {
            width: 10,
            height: 1,
            bits_per_color: 1,
            color_space: ColorSpace::Black,
            dpi: 203,
        };
        assert_eq!(bw.bits_per_pixel(), 1);
        assert_eq!(bw.bytes_per_line(), 2); // ceil(10/8)
    }

    #[test]
    fn header_is_exactly_one_header_long() {
        assert_eq!(srgb_a4_300dpi().encode_header().len(), PAGE_HEADER_LEN);
    }

    #[test]
    fn geometry_round_trips_through_the_header() {
        let g = srgb_a4_300dpi();
        let back = PageGeometry::decode_header(&g.encode_header()).unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn begin_page_starts_with_sync_word() {
        let stream = begin_page(srgb_a4_300dpi());
        assert_eq!(&stream[..4], b"RaS2");
        assert_eq!(stream.len(), 4 + PAGE_HEADER_LEN);
    }

    #[test]
    fn decode_rejects_short_header() {
        assert!(PageGeometry::decode_header(&[0u8; 100]).is_none());
    }
}
