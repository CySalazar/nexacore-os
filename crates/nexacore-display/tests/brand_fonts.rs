//! End-to-end validation of the font engine against the **real brand fonts**
//! (WS7-19.3): parse → cmap lookup → outline decode (including composite/
//! compound glyphs for accented Latin) → AA rasterization.
//!
//! The synthetic-font unit tests in `font.rs` prove the composite assembler is
//! numerically correct; this proves the whole pipeline works on the actual
//! Inter / IBM Plex Mono / Source Serif 4 byte payloads the desktop ships.

// Integration tests are a separate crate and do not inherit the lib's
// `cfg_attr(test, allow(...))`; a test that asserts by panicking is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use nexacore_display::{font::Font, raster};

/// Rasterizes `ch` from `bytes` at `px` em and returns the number of inked
/// (non-zero coverage) pixels. Panics if the font/glyph cannot be decoded.
fn inked_pixels(bytes: &[u8], ch: char, px: f32) -> usize {
    let font = Font::parse(bytes).expect("brand font parses as a glyf sfnt");
    let gid = font
        .glyph_index(ch)
        .unwrap_or_else(|| panic!("brand font has no glyph for {ch:?}"));
    let outline = font
        .glyph_outline(gid)
        .unwrap_or_else(|e| panic!("outline decode for {ch:?} failed: {e}"));
    let bmp = raster::rasterize(&outline, font.units_per_em(), px);
    bmp.coverage.iter().filter(|&&c| c > 0).count()
}

#[test]
fn brand_faces_parse_and_have_sane_metrics() {
    for (name, bytes) in nexacore_fonts::ALL {
        let font = Font::parse(bytes).unwrap_or_else(|e| panic!("{name}: parse failed: {e}"));
        let upem = font.units_per_em();
        assert!(
            (16..=16384).contains(&upem),
            "{name}: implausible unitsPerEm {upem}"
        );
        assert!(font.num_glyphs() > 100, "{name}: too few glyphs");
    }
}

#[test]
fn ui_face_renders_ascii_with_ink() {
    // Inter (the UI face) must render basic ASCII with real coverage.
    for ch in ['A', 'g', '7', '@'] {
        assert!(
            inked_pixels(nexacore_fonts::BRAND_UI, ch, 32.0) > 0,
            "Inter rendered no ink for {ch:?}"
        );
    }
}

#[test]
fn accented_latin_renders_across_families() {
    // Accented Latin is encoded as composite glyphs in these families; before
    // WS7-19.3 the parser rejected them. Each must now decode and rasterize
    // with ink — the end-to-end proof that composite assembly works on real
    // fonts, not just the synthetic test font.
    let faces = [
        ("Inter", nexacore_fonts::BRAND_UI),
        ("IBM Plex Mono", nexacore_fonts::BRAND_MONO),
        ("Source Serif 4", nexacore_fonts::BRAND_DISPLAY),
    ];
    for (name, bytes) in faces {
        for ch in ['é', 'à', 'ñ', 'ü'] {
            assert!(
                inked_pixels(bytes, ch, 32.0) > 0,
                "{name}: accented {ch:?} produced no ink"
            );
        }
    }
}

#[test]
fn whitespace_is_inkless_but_decodes() {
    // The space glyph decodes to an empty outline (no ink) without error.
    let font = Font::parse(nexacore_fonts::BRAND_UI).unwrap();
    let gid = font.glyph_index(' ').expect("space glyph");
    let outline = font.glyph_outline(gid).expect("space outline");
    assert!(outline.is_empty(), "space should have no contours");
}
