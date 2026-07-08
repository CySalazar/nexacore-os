//! System font stack with brand-first fallback (WS7-03.8).
//!
//! A *font stack* is an ordered list of font faces: the brand/primary typeface
//! first, then progressively more general system fallbacks. To render a string,
//! each character is resolved against the stack and the first face that has a
//! glyph for it wins — the CSS `font-family` fallback model. This keeps brand
//! text in the brand face while still rendering characters the brand face lacks
//! (symbols, CJK, emoji, …) from a fallback.
//!
//! The stack is decoupled from the concrete parser through the [`GlyphSource`]
//! trait (implemented here for [`crate::font::Font`]), so the fallback logic is
//! deterministic and host-testable with a mock source — no font binary needed.
//!
//! ## Integrating the brand typeface
//!
//! The brand typeface is integrated by registering it as the **first** face
//! (see [`FontStack::push`]). The brand *font binary* itself is an external,
//! licensed asset supplied at packaging time; this module provides the complete
//! integration mechanism and fallback policy around it.
//!
//! `no_std + alloc`, dep-free.

use alloc::{string::String, vec::Vec};

/// A per-face source of glyph mappings.
///
/// Decouples the stack from the concrete font parser and keeps the fallback
/// logic host-testable. Implemented for [`crate::font::Font`].
pub trait GlyphSource {
    /// Glyph id for `ch` in this face, or `None` if the face cannot render it.
    fn glyph(&self, ch: char) -> Option<u16>;
}

impl GlyphSource for crate::font::Font<'_> {
    fn glyph(&self, ch: char) -> Option<u16> {
        // A `cmap` hit of glyph 0 (`.notdef`) means "no glyph"; fall through.
        match self.glyph_index(ch) {
            None | Some(0) => None,
            other => other,
        }
    }
}

/// A resolved glyph: which face supplied it, and the glyph id within that face.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlyphMatch {
    /// Index of the face within the stack (`0` is the brand/primary face).
    pub face: usize,
    /// Glyph id within that face.
    pub glyph_id: u16,
}

/// One named face in the stack.
#[derive(Debug, Clone)]
struct Face<S> {
    name: String,
    source: S,
}

/// An ordered font stack: a brand/primary face followed by system fallbacks.
///
/// [`FontStack::resolve`] walks the faces in registration order and returns the
/// first that has a glyph for the character.
#[derive(Debug, Clone)]
pub struct FontStack<S> {
    faces: Vec<Face<S>>,
}

impl<S> Default for FontStack<S> {
    fn default() -> Self {
        Self { faces: Vec::new() }
    }
}

impl<S: GlyphSource> FontStack<S> {
    /// Creates an empty font stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a face. The first face registered is the brand/primary face;
    /// later faces are fallbacks tried in registration order.
    pub fn push(&mut self, name: &str, source: S) {
        self.faces.push(Face {
            name: String::from(name),
            source,
        });
    }

    /// Number of faces in the stack.
    #[must_use]
    pub fn len(&self) -> usize {
        self.faces.len()
    }

    /// `true` if the stack has no faces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.faces.is_empty()
    }

    /// Name of the brand/primary face, if any.
    #[must_use]
    pub fn primary(&self) -> Option<&str> {
        self.faces.first().map(|f| f.name.as_str())
    }

    /// Name of the face at `index`.
    #[must_use]
    pub fn face_name(&self, index: usize) -> Option<&str> {
        self.faces.get(index).map(|f| f.name.as_str())
    }

    /// The glyph source of the face at `index`.
    #[must_use]
    pub fn face(&self, index: usize) -> Option<&S> {
        self.faces.get(index).map(|f| &f.source)
    }

    /// Resolves `ch` to the first face that can render it (brand face first),
    /// or `None` if no face in the stack has a glyph for it.
    #[must_use]
    pub fn resolve(&self, ch: char) -> Option<GlyphMatch> {
        for (i, f) in self.faces.iter().enumerate() {
            if let Some(glyph_id) = f.source.glyph(ch) {
                return Some(GlyphMatch { face: i, glyph_id });
            }
        }
        None
    }

    /// Resolves every character of `text`, one entry per character (`None`
    /// where no face has a glyph — the caller renders `.notdef`).
    #[must_use]
    pub fn resolve_str(&self, text: &str) -> Vec<Option<GlyphMatch>> {
        text.chars().map(|c| self.resolve(c)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock face that maps a fixed set of characters to glyph ids.
    struct Mock {
        supported: &'static [(char, u16)],
    }

    impl GlyphSource for Mock {
        fn glyph(&self, ch: char) -> Option<u16> {
            self.supported
                .iter()
                .find(|(c, _)| *c == ch)
                .map(|(_, g)| *g)
        }
    }

    fn brand_then_fallback() -> FontStack<Mock> {
        let mut s = FontStack::new();
        s.push(
            "Brand",
            Mock {
                supported: &[('A', 10), ('B', 11)],
            },
        );
        s.push(
            "Fallback",
            Mock {
                supported: &[('A', 20), ('B', 21), ('Z', 29)],
            },
        );
        s
    }

    #[test]
    fn empty_stack_resolves_nothing() {
        let s: FontStack<Mock> = FontStack::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.resolve('A'), None);
        assert_eq!(s.primary(), None);
    }

    #[test]
    fn brand_face_wins_when_it_has_the_glyph() {
        let s = brand_then_fallback();
        assert_eq!(s.len(), 2);
        assert_eq!(s.primary(), Some("Brand"));
        // 'A' and 'B' exist in the brand face -> face 0.
        assert_eq!(
            s.resolve('A'),
            Some(GlyphMatch {
                face: 0,
                glyph_id: 10
            })
        );
        assert_eq!(
            s.resolve('B'),
            Some(GlyphMatch {
                face: 0,
                glyph_id: 11
            })
        );
    }

    #[test]
    fn falls_back_when_brand_lacks_the_glyph() {
        let s = brand_then_fallback();
        // 'Z' is only in the fallback face -> face 1, its glyph id.
        assert_eq!(
            s.resolve('Z'),
            Some(GlyphMatch {
                face: 1,
                glyph_id: 29
            })
        );
        // A character no face has resolves to None.
        assert_eq!(s.resolve('!'), None);
    }

    #[test]
    fn face_accessors_report_names_and_sources() {
        let s = brand_then_fallback();
        assert_eq!(s.face_name(0), Some("Brand"));
        assert_eq!(s.face_name(1), Some("Fallback"));
        assert_eq!(s.face_name(2), None);
        assert!(s.face(0).is_some());
        assert!(s.face(9).is_none());
    }

    #[test]
    fn resolve_str_maps_each_character() {
        let s = brand_then_fallback();
        let got = s.resolve_str("AZ!");
        assert_eq!(
            got,
            alloc::vec![
                Some(GlyphMatch {
                    face: 0,
                    glyph_id: 10
                }), // 'A' from brand
                Some(GlyphMatch {
                    face: 1,
                    glyph_id: 29
                }), // 'Z' from fallback
                None, // '!' unresolved
            ]
        );
    }

    #[test]
    fn font_glyph_source_uses_cmap_and_skips_notdef() {
        // Exercises `impl GlyphSource for Font` against the shared synthetic
        // font: 'A' maps to glyph 1, 'B' is unmapped.
        let bytes = crate::font::test_support::build_test_font();
        let font = crate::font::Font::parse(&bytes).unwrap();
        let mut s = FontStack::new();
        s.push("Synthetic", font);
        assert_eq!(
            s.resolve('A'),
            Some(GlyphMatch {
                face: 0,
                glyph_id: 1
            })
        );
        assert_eq!(s.resolve('B'), None);
    }
}
