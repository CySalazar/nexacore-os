//! PDF → raster rendering seam (WS2-13.5).
//!
//! Rasterizing a PDF page to pixels needs a real PDF library (a large untrusted
//! parser), so it is **library-gated** behind the [`PdfRasterizer`] trait —
//! exactly as the WS8-02 media codecs and the WS8-03 image codecs are. The print
//! pipeline drives this trait, then wraps the resulting [`RasterPage`] in a
//! PWG-Raster stream ([`crate::pwg`]); the orchestration is host-testable with a
//! mock rasterizer.

use alloc::vec::Vec;

use crate::pwg::{ColorSpace, PageGeometry};

/// One rasterized page: geometry plus the raw pixel rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RasterPage {
    /// Page geometry (used to build the PWG-Raster header).
    pub geometry: PageGeometry,
    /// Raster rows, `geometry.bytes_per_line() * height` bytes.
    pub data: Vec<u8>,
}

/// Why rasterization failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// The PDF could not be parsed.
    Malformed,
    /// The requested page index does not exist.
    NoSuchPage,
}

/// Renders a PDF page to pixels (WS2-13.5). The real implementation wraps a
/// vetted PDF library; tests use a mock.
pub trait PdfRasterizer {
    /// Number of pages in `pdf`.
    fn page_count(&self, pdf: &[u8]) -> usize;

    /// Rasterize page `index` of `pdf` at `dpi` into `color_space`.
    ///
    /// # Errors
    ///
    /// [`RenderError`] when the PDF is malformed or the page does not exist.
    fn rasterize(
        &self,
        pdf: &[u8],
        index: usize,
        dpi: u32,
        color_space: ColorSpace,
    ) -> Result<RasterPage, RenderError>;
}

/// Render a PDF page and wrap it as a PWG-Raster stream (WS2-13.5/.6).
///
/// # Errors
///
/// Propagates the rasterizer's [`RenderError`].
pub fn pdf_page_to_pwg<R: PdfRasterizer>(
    rasterizer: &R,
    pdf: &[u8],
    index: usize,
    dpi: u32,
    color_space: ColorSpace,
) -> Result<Vec<u8>, RenderError> {
    let page = rasterizer.rasterize(pdf, index, dpi, color_space)?;
    let mut stream = crate::pwg::begin_page(page.geometry);
    stream.extend_from_slice(&page.data);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock that renders any non-empty "pdf" to a 2×2 page.
    struct MockRasterizer;
    impl PdfRasterizer for MockRasterizer {
        fn page_count(&self, pdf: &[u8]) -> usize {
            usize::from(!pdf.is_empty())
        }
        fn rasterize(
            &self,
            pdf: &[u8],
            index: usize,
            dpi: u32,
            color_space: ColorSpace,
        ) -> Result<RasterPage, RenderError> {
            if pdf.is_empty() {
                return Err(RenderError::Malformed);
            }
            if index >= 1 {
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
                data: alloc::vec![0xAB; len],
            })
        }
    }

    #[test]
    fn pdf_to_pwg_prepends_header_then_pixels() {
        let stream =
            pdf_page_to_pwg(&MockRasterizer, b"%PDF-1.7", 0, 300, ColorSpace::Srgb).unwrap();
        // sync word + 1796-byte header + 2*2*3 pixel bytes.
        assert_eq!(&stream[..4], b"RaS2");
        assert_eq!(stream.len(), 4 + crate::pwg::PAGE_HEADER_LEN + 2 * 2 * 3);
    }

    #[test]
    fn empty_pdf_is_malformed() {
        assert_eq!(
            pdf_page_to_pwg(&MockRasterizer, b"", 0, 300, ColorSpace::Srgb),
            Err(RenderError::Malformed)
        );
    }

    #[test]
    fn out_of_range_page_errs() {
        assert_eq!(
            pdf_page_to_pwg(&MockRasterizer, b"%PDF", 5, 300, ColorSpace::Srgb),
            Err(RenderError::NoSuchPage)
        );
        assert_eq!(MockRasterizer.page_count(b"%PDF"), 1);
    }
}
