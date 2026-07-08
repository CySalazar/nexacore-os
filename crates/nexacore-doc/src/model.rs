//! Document model (WS8-04.1) — format-agnostic page geometry.
//!
//! The viewer targets PDF first, but the model carries only page sizes and
//! optional metadata, so a future EPUB/Office backend reuses the navigation,
//! zoom, and selection layers unchanged. The real PDF parser (a large untrusted
//! library) is gated behind [`DocumentBackend`], exactly as the rasterizer is
//! gated behind [`crate::render::PdfRasterizer`].

use alloc::{string::String, vec::Vec};

/// A page size in PDF points (1/72 inch), the canonical PDF unit. Integer
/// points are sufficient for layout; sub-point precision is irrelevant at any
/// realistic zoom and keeps the crate float-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointSize {
    /// Page width in points.
    pub width: u32,
    /// Page height in points.
    pub height: u32,
}

impl PointSize {
    /// US Letter (8.5×11 in) in points.
    pub const LETTER: Self = Self {
        width: 612,
        height: 792,
    };

    /// ISO A4 (210×297 mm) in points.
    pub const A4: Self = Self {
        width: 595,
        height: 842,
    };
}

/// The document container format. Currently only PDF, but the model is
/// format-agnostic so other backends can populate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentFormat {
    /// Portable Document Format.
    Pdf,
}

/// Why opening a document failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentError {
    /// The bytes are not a recognisable document of the expected format.
    Malformed,
    /// The document declares zero pages.
    Empty,
}

/// A parsed document: its format, per-page geometry, and optional title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// Container format.
    pub format: DocumentFormat,
    /// Per-page geometry, in document order.
    pub pages: Vec<PointSize>,
    /// Optional document title (from metadata).
    pub title: Option<String>,
}

impl Document {
    /// Build a document directly from page geometry (used by backends and
    /// tests).
    ///
    /// # Errors
    ///
    /// [`DocumentError::Empty`] if `pages` is empty — a zero-page document is
    /// not viewable.
    pub fn new(
        format: DocumentFormat,
        pages: Vec<PointSize>,
        title: Option<String>,
    ) -> Result<Self, DocumentError> {
        if pages.is_empty() {
            return Err(DocumentError::Empty);
        }
        Ok(Self {
            format,
            pages,
            title,
        })
    }

    /// Number of pages.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Geometry of page `index`, or `None` if out of range.
    #[must_use]
    pub fn page_size(&self, index: usize) -> Option<PointSize> {
        self.pages.get(index).copied()
    }

    /// Total height of all pages stacked vertically, in points (used as a
    /// fallback scroll extent before scaling).
    #[must_use]
    pub fn total_points_height(&self) -> u64 {
        self.pages.iter().map(|p| u64::from(p.height)).sum()
    }

    /// The widest page width in points (drives fit-to-width over a whole
    /// document so a single wide page does not clip).
    #[must_use]
    pub fn max_width_points(&self) -> u32 {
        self.pages.iter().map(|p| p.width).max().unwrap_or(0)
    }
}

/// The library-gated seam that turns raw document bytes into a [`Document`].
///
/// The real implementation wraps a vetted PDF library (a large untrusted
/// parser); tests and headless contexts use a mock that fabricates page
/// geometry. Keeping it a trait is the WS8-04.1 "select & vet the library"
/// boundary: the untrusted parser is isolated behind one method.
pub trait DocumentBackend {
    /// Parse `bytes` into a [`Document`].
    ///
    /// # Errors
    ///
    /// [`DocumentError`] when the bytes are malformed or describe zero pages.
    fn open(&self, bytes: &[u8]) -> Result<Document, DocumentError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_document_is_rejected() {
        assert_eq!(
            Document::new(DocumentFormat::Pdf, Vec::new(), None),
            Err(DocumentError::Empty)
        );
    }

    #[test]
    fn page_queries_are_bounds_checked() {
        let doc = Document::new(
            DocumentFormat::Pdf,
            alloc::vec![PointSize::A4, PointSize::LETTER],
            None,
        )
        .unwrap();
        assert_eq!(doc.page_count(), 2);
        assert_eq!(doc.page_size(0), Some(PointSize::A4));
        assert_eq!(doc.page_size(1), Some(PointSize::LETTER));
        assert_eq!(doc.page_size(2), None);
    }

    #[test]
    fn aggregate_geometry_is_correct() {
        let doc = Document::new(
            DocumentFormat::Pdf,
            alloc::vec![PointSize::A4, PointSize::LETTER],
            None,
        )
        .unwrap();
        assert_eq!(doc.total_points_height(), 842 + 792);
        assert_eq!(doc.max_width_points(), 612);
    }

    /// A mock backend that reads a fixed page count from the first byte.
    struct MockBackend;
    impl DocumentBackend for MockBackend {
        fn open(&self, bytes: &[u8]) -> Result<Document, DocumentError> {
            let n = *bytes.first().ok_or(DocumentError::Malformed)? as usize;
            if n == 0 {
                return Err(DocumentError::Empty);
            }
            let pages = (0..n).map(|_| PointSize::A4).collect();
            Document::new(DocumentFormat::Pdf, pages, None)
        }
    }

    #[test]
    fn backend_seam_round_trips() {
        let doc = MockBackend.open(&[3]).unwrap();
        assert_eq!(doc.page_count(), 3);
        assert_eq!(MockBackend.open(&[]), Err(DocumentError::Malformed));
        assert_eq!(MockBackend.open(&[0]), Err(DocumentError::Empty));
    }
}
