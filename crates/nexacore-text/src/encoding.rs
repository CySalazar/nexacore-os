//! Encoding (BOM) and line-ending (EOL) detection and normalisation (WS8-08.6).

use alloc::string::String;

/// A detected text encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// UTF-8 with a byte-order mark (`EF BB BF`).
    Utf8Bom,
    /// UTF-8 without a BOM (the assumed default).
    Utf8,
    /// UTF-16 little-endian (`FF FE`).
    Utf16Le,
    /// UTF-16 big-endian (`FE FF`).
    Utf16Be,
}

impl Encoding {
    /// The byte length of this encoding's BOM (`0` for [`Encoding::Utf8`]).
    #[must_use]
    pub fn bom_len(self) -> usize {
        match self {
            Self::Utf8Bom => 3,
            Self::Utf16Le | Self::Utf16Be => 2,
            Self::Utf8 => 0,
        }
    }
}

/// A detected line-ending style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eol {
    /// Unix `\n`.
    Lf,
    /// Windows `\r\n`.
    Crlf,
    /// Classic-Mac `\r`.
    Cr,
    /// More than one style is present.
    Mixed,
    /// No line ending was found.
    None,
}

impl Eol {
    /// The bytes this style writes for a newline (empty for
    /// [`Eol::Mixed`]/[`Eol::None`]).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::Crlf => "\r\n",
            Self::Cr => "\r",
            Self::Mixed | Self::None => "",
        }
    }
}

/// Detect the encoding of `bytes` by sniffing its leading BOM.
#[must_use]
pub fn detect_encoding(bytes: &[u8]) -> Encoding {
    match bytes {
        [0xEF, 0xBB, 0xBF, ..] => Encoding::Utf8Bom,
        [0xFF, 0xFE, ..] => Encoding::Utf16Le,
        [0xFE, 0xFF, ..] => Encoding::Utf16Be,
        _ => Encoding::Utf8,
    }
}

/// Detect the dominant line-ending style in `text`.
///
/// Returns [`Eol::Mixed`] if more than one distinct style occurs, so the editor
/// can warn before normalising.
#[must_use]
pub fn detect_eol(text: &str) -> Eol {
    let bytes = text.as_bytes();
    let mut lf = false; // a lone '\n'
    let mut crlf = false;
    let mut cr = false; // a lone '\r'
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'\r') => {
                if bytes.get(i + 1) == Some(&b'\n') {
                    crlf = true;
                    i += 2;
                    continue;
                }
                cr = true;
            }
            Some(b'\n') => lf = true,
            _ => {}
        }
        i += 1;
    }
    match (lf, crlf, cr) {
        (false, false, false) => Eol::None,
        (true, false, false) => Eol::Lf,
        (false, true, false) => Eol::Crlf,
        (false, false, true) => Eol::Cr,
        _ => Eol::Mixed,
    }
}

/// Rewrite every line ending in `text` to `target`.
#[must_use]
pub fn normalize_eol(text: &str, target: Eol) -> String {
    let newline = match target {
        Eol::Lf => "\n",
        Eol::Crlf => "\r\n",
        Eol::Cr => "\r",
        // A no-op target leaves the text unchanged.
        Eol::Mixed | Eol::None => return String::from(text),
    };
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    // Copy the text in UTF-8-valid segments between line endings. `\r`/`\n` are
    // ASCII, so they never fall inside a multi-byte sequence and every segment
    // boundary is a valid `str` boundary.
    let mut seg_start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'\r' | b'\n') => {
                out.push_str(text.get(seg_start..i).unwrap_or(""));
                out.push_str(newline);
                if bytes.get(i) == Some(&b'\r') && bytes.get(i + 1) == Some(&b'\n') {
                    i += 1; // consume the paired '\n'
                }
                i += 1;
                seg_start = i;
            }
            _ => i += 1,
        }
    }
    out.push_str(text.get(seg_start..).unwrap_or(""));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_boms() {
        assert_eq!(detect_encoding(b"\xEF\xBB\xBFhi"), Encoding::Utf8Bom);
        assert_eq!(detect_encoding(b"\xFF\xFEh\0"), Encoding::Utf16Le);
        assert_eq!(detect_encoding(b"\xFE\xFF\0h"), Encoding::Utf16Be);
        assert_eq!(detect_encoding(b"plain"), Encoding::Utf8);
        assert_eq!(Encoding::Utf8Bom.bom_len(), 3);
        assert_eq!(Encoding::Utf8.bom_len(), 0);
    }

    #[test]
    fn detects_eol_styles() {
        assert_eq!(detect_eol("a\nb\nc"), Eol::Lf);
        assert_eq!(detect_eol("a\r\nb\r\n"), Eol::Crlf);
        assert_eq!(detect_eol("a\rb\rc"), Eol::Cr);
        assert_eq!(detect_eol("a\nb\r\nc"), Eol::Mixed);
        assert_eq!(detect_eol("single line"), Eol::None);
    }

    #[test]
    fn normalizes_mixed_to_lf_and_crlf() {
        let mixed = "a\r\nb\nc\rd";
        assert_eq!(normalize_eol(mixed, Eol::Lf), "a\nb\nc\nd");
        assert_eq!(normalize_eol(mixed, Eol::Crlf), "a\r\nb\r\nc\r\nd");
        // A no-op target is unchanged.
        assert_eq!(normalize_eol(mixed, Eol::None), mixed);
    }
}
