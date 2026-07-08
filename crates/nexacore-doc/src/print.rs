//! Print path (WS8-04.6) — bridge the viewer to `nexacore-print` (WS2-13).
//!
//! Printing a document re-renders the requested pages through the same
//! [`crate::render::PdfRasterizer`] seam, then wraps each one in
//! a PWG-Raster stream via `nexacore-print`. The result is one ready-to-spool
//! byte stream per page, in the order requested — the spooler (WS2-13) takes it
//! from there.

use alloc::vec::Vec;

use nexacore_print::{
    pwg::ColorSpace,
    render::{PdfRasterizer, RenderError, pdf_page_to_pwg},
};

/// Render the given `pages` to PWG-Raster streams (one `Vec<u8>` per page) at
/// `dpi` in `color_space`, ready for the print spooler.
///
/// Pages are emitted in the order given (so a UI can print a custom selection
/// or reversed order). A print dpi of 300–600 is typical, independent of the
/// on-screen zoom.
///
/// # Errors
///
/// Propagates the first [`RenderError`] encountered (e.g. an out-of-range page);
/// no partial result is returned.
pub fn print_pages<R: PdfRasterizer>(
    rasterizer: &R,
    pdf: &[u8],
    pages: &[usize],
    dpi: u32,
    color_space: ColorSpace,
) -> Result<Vec<Vec<u8>>, RenderError> {
    let mut streams = Vec::with_capacity(pages.len());
    for &index in pages {
        streams.push(pdf_page_to_pwg(rasterizer, pdf, index, dpi, color_space)?);
    }
    Ok(streams)
}

/// Render an inclusive page range `[first, last]` to PWG-Raster streams.
///
/// # Errors
///
/// [`RenderError::NoSuchPage`] if `first > last`; otherwise propagates the
/// rasterizer error for the first failing page.
pub fn print_range<R: PdfRasterizer>(
    rasterizer: &R,
    pdf: &[u8],
    first: usize,
    last: usize,
    dpi: u32,
    color_space: ColorSpace,
) -> Result<Vec<Vec<u8>>, RenderError> {
    if first > last {
        return Err(RenderError::NoSuchPage);
    }
    let pages: Vec<usize> = (first..=last).collect();
    print_pages(rasterizer, pdf, &pages, dpi, color_space)
}

#[cfg(test)]
mod tests {
    use nexacore_print::{pwg::PageGeometry, render::RasterPage};

    use super::*;

    struct ThreePageRasterizer;
    impl PdfRasterizer for ThreePageRasterizer {
        fn page_count(&self, _pdf: &[u8]) -> usize {
            3
        }
        fn rasterize(
            &self,
            _pdf: &[u8],
            index: usize,
            dpi: u32,
            color_space: ColorSpace,
        ) -> Result<RasterPage, RenderError> {
            if index >= 3 {
                return Err(RenderError::NoSuchPage);
            }
            let geometry = PageGeometry {
                width: 2,
                height: 2,
                bits_per_color: 8,
                color_space,
                dpi,
            };
            let len = geometry.bytes_per_line() as usize * geometry.height as usize;
            Ok(RasterPage {
                geometry,
                data: alloc::vec![0x11; len],
            })
        }
    }

    #[test]
    fn print_pages_emits_one_stream_per_page_in_order() {
        let streams = print_pages(
            &ThreePageRasterizer,
            b"%PDF",
            &[2, 0],
            300,
            ColorSpace::Srgb,
        )
        .unwrap();
        assert_eq!(streams.len(), 2);
        for s in &streams {
            assert_eq!(&s[..4], b"RaS2", "each stream is a PWG-Raster page");
        }
    }

    #[test]
    fn print_range_covers_inclusive_bounds() {
        let streams =
            print_range(&ThreePageRasterizer, b"%PDF", 0, 2, 300, ColorSpace::Srgb).unwrap();
        assert_eq!(streams.len(), 3);
    }

    #[test]
    fn out_of_range_page_propagates_error() {
        assert_eq!(
            print_pages(&ThreePageRasterizer, b"%PDF", &[5], 300, ColorSpace::Srgb).err(),
            Some(RenderError::NoSuchPage)
        );
    }

    #[test]
    fn inverted_range_is_rejected() {
        assert_eq!(
            print_range(&ThreePageRasterizer, b"%PDF", 2, 1, 300, ColorSpace::Srgb).err(),
            Some(RenderError::NoSuchPage)
        );
    }
}
