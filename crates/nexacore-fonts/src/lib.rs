//! # `nexacore-fonts`
//!
//! Embedded NexaCore **brand type families** as `glyf`-flavored `TrueType` byte
//! slices (WS7-19.3), for the OS text engine to render without any filesystem
//! font loading (there is no persistent FS on the live image).
//!
//! Three families, per the brand typography system
//! (`brand/typography/typography.md`):
//!
//! | Family | Role (HIG §3) | Constant(s) |
//! |---|---|---|
//! | **Inter** | UI, navigation, captions | [`INTER_REGULAR`], [`INTER_MEDIUM`], [`INTER_SEMIBOLD`] |
//! | **IBM Plex Mono** | code, terminal, status pills | [`IBM_PLEX_MONO_REGULAR`], [`IBM_PLEX_MONO_MEDIUM`] |
//! | **Source Serif 4** | display, headings, wordmark | [`SOURCE_SERIF_REGULAR`], [`SOURCE_SERIF_BOLD`], [`SOURCE_SERIF_ITALIC`] |
//!
//! [`BRAND_UI`], [`BRAND_MONO`], and [`BRAND_DISPLAY`] alias the primary render
//! weight of each family.
//!
//! All three families are **SIL Open Font License 1.1**
//! (`brand/typography/fonts/OFL-*.txt`) — redistribution and embedding are
//! permitted. The byte builds and their provenance are documented in
//! `brand/typography/fonts/README.md`.
//!
//! ## Parsing
//!
//! These are raw font bytes. Parse them with `nexacore_display::font::Font::parse`
//! (a `glyf` sfnt parser) to obtain outlines, then rasterize with
//! `nexacore_display::raster`. This crate deliberately carries no parser and no
//! dependencies — it is purely the asset payload.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-fonts")]
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

// --- Inter (UI) -------------------------------------------------------------

/// Inter Regular (400) — the primary UI text weight.
pub const INTER_REGULAR: &[u8] =
    include_bytes!("../../../brand/typography/fonts/Inter-Regular.ttf");
/// Inter Medium (500) — UI emphasis / paired-with-serif body weight.
pub const INTER_MEDIUM: &[u8] = include_bytes!("../../../brand/typography/fonts/Inter-Medium.ttf");
/// Inter `SemiBold` (600) — UI headings / strong labels.
pub const INTER_SEMIBOLD: &[u8] =
    include_bytes!("../../../brand/typography/fonts/Inter-SemiBold.ttf");

// --- IBM Plex Mono (code / terminal / status) -------------------------------

/// IBM Plex Mono Regular (400) — terminal, code, metadata, status pills.
pub const IBM_PLEX_MONO_REGULAR: &[u8] =
    include_bytes!("../../../brand/typography/fonts/IBMPlexMono-Regular.ttf");
/// IBM Plex Mono Medium (500) — emphasized monospace.
pub const IBM_PLEX_MONO_MEDIUM: &[u8] =
    include_bytes!("../../../brand/typography/fonts/IBMPlexMono-Medium.ttf");

// --- Source Serif 4 (display / headings / wordmark) -------------------------

/// Source Serif 4 Regular (400) — display and long-form serif.
pub const SOURCE_SERIF_REGULAR: &[u8] =
    include_bytes!("../../../brand/typography/fonts/SourceSerif4-Regular.ttf");
/// Source Serif 4 Bold (700) — serif headings / wordmark.
pub const SOURCE_SERIF_BOLD: &[u8] =
    include_bytes!("../../../brand/typography/fonts/SourceSerif4-Bold.ttf");
/// Source Serif 4 Italic — serif italics (Source Serif only, per the HIG).
pub const SOURCE_SERIF_ITALIC: &[u8] =
    include_bytes!("../../../brand/typography/fonts/SourceSerif4-It.ttf");

// --- Primary-weight aliases -------------------------------------------------

/// The primary UI face (Inter Regular).
pub const BRAND_UI: &[u8] = INTER_REGULAR;
/// The primary monospace face (IBM Plex Mono Regular).
pub const BRAND_MONO: &[u8] = IBM_PLEX_MONO_REGULAR;
/// The primary display/serif face (Source Serif 4 Regular).
pub const BRAND_DISPLAY: &[u8] = SOURCE_SERIF_REGULAR;

/// Every embedded face, as `(name, bytes)` — useful for building a font stack
/// or asserting integrity over the whole set.
pub const ALL: &[(&str, &[u8])] = &[
    ("Inter Regular", INTER_REGULAR),
    ("Inter Medium", INTER_MEDIUM),
    ("Inter SemiBold", INTER_SEMIBOLD),
    ("IBM Plex Mono Regular", IBM_PLEX_MONO_REGULAR),
    ("IBM Plex Mono Medium", IBM_PLEX_MONO_MEDIUM),
    ("Source Serif 4 Regular", SOURCE_SERIF_REGULAR),
    ("Source Serif 4 Bold", SOURCE_SERIF_BOLD),
    ("Source Serif 4 Italic", SOURCE_SERIF_ITALIC),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every embedded face must be a non-empty `glyf` sfnt. The sfnt version is
    /// `0x0001_0000` (`TrueType`) or the `true` tag — never `OTTO` (CFF), which
    /// the OS parser cannot render.
    #[test]
    fn all_faces_are_non_empty_glyf_sfnt() {
        for (name, bytes) in ALL {
            let tag = bytes.get(0..4).unwrap_or_default();
            let is_truetype = tag == [0x00, 0x01, 0x00, 0x00] || tag == *b"true";
            assert!(
                is_truetype,
                "{name}: not a glyf TrueType sfnt (tag {tag:02X?}); OTTO/CFF is unsupported",
            );
        }
    }

    #[test]
    fn primary_aliases_point_at_regular_weights() {
        assert_eq!(BRAND_UI.as_ptr(), INTER_REGULAR.as_ptr());
        assert_eq!(BRAND_MONO.as_ptr(), IBM_PLEX_MONO_REGULAR.as_ptr());
        assert_eq!(BRAND_DISPLAY.as_ptr(), SOURCE_SERIF_REGULAR.as_ptr());
    }
}
