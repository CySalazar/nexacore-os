//! # `nexacore-cmd-wget`
//!
//! File downloader command for NexaCore OS.
//!
//! Provides URL filename extraction, range request header construction,
//! download progress formatting, and command-line argument parsing.  No I/O
//! is performed here; the caller drives the actual HTTP transfer.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`WgetConfig`] | Download session parameters |
//! | [`extract_filename_from_url`] | Derive a local filename from a URL |
//! | [`build_range_header`] | Build an HTTP `Range` header for resume support |
//! | [`format_progress`] | Format a download progress indicator |
//! | [`parse_args`] | Parse `wget [-O file] [-c] <url>` arguments |
//! | [`WgetError`] | Typed errors from [`parse_args`] |
//!
//! ## RFC references
//!
//! - RFC 7233 — HTTP Range Requests

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        clippy::indexing_slicing,
    )
)]

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
};

// =============================================================================
// WgetConfig
// =============================================================================

/// Configuration for a `wget` download session.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_wget::{WgetConfig, parse_args};
///
/// let cfg = parse_args(&["http://example.com/file.tar.gz"]).unwrap();
/// assert_eq!(cfg.url, "http://example.com/file.tar.gz");
/// assert!(!cfg.resume);
/// assert!(cfg.output_file.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgetConfig {
    /// URL to download.
    pub url: String,
    /// Override the local output filename (defaults to the URL basename).
    pub output_file: Option<String>,
    /// Resume a partial download using an HTTP `Range` header.
    pub resume: bool,
}

// =============================================================================
// Filename extraction
// =============================================================================

/// Extract the filename component from a URL.
///
/// Returns the last path segment after the final `/`, stripping any query
/// string or fragment.  Returns `None` when the URL has no meaningful path
/// component (e.g. `"http://example.com"` or `"http://example.com/"`).
///
/// # Examples
///
/// ```
/// use nexacore_cmd_wget::extract_filename_from_url;
///
/// assert_eq!(
///     extract_filename_from_url("http://example.com/files/archive.tar.gz"),
///     Some(String::from("archive.tar.gz"))
/// );
/// assert_eq!(extract_filename_from_url("http://example.com/"), None);
/// assert_eq!(extract_filename_from_url("http://example.com"), None);
/// assert_eq!(
///     extract_filename_from_url("http://example.com/file.txt?v=1"),
///     Some(String::from("file.txt"))
/// );
/// ```
#[must_use]
pub fn extract_filename_from_url(url: &str) -> Option<String> {
    // Strip the scheme + authority to isolate the path component.
    // For "http://host/path/file.txt" this yields "/path/file.txt".
    // For "http://host" (no slash after authority) this yields "" so we return None.
    let path_start = if let Some(after_scheme) = url.find("://") {
        // Find the first '/' after the authority (scheme://host).
        let authority_start = after_scheme + 3;
        let remaining = url.get(authority_start..).unwrap_or("");
        match remaining.find('/') {
            Some(pos) => authority_start + pos,
            None => return None, // No path component at all.
        }
    } else {
        // No scheme — treat as a plain path.
        0
    };

    let path = url.get(path_start..).unwrap_or("");

    // Strip query string and fragment before extracting the path segment.
    let path_clean = path
        .split('?')
        .next()
        .unwrap_or(path)
        .split('#')
        .next()
        .unwrap_or(path);

    let segment = path_clean.rsplit('/').next().unwrap_or("");
    if segment.is_empty() {
        None
    } else {
        Some(segment.to_string())
    }
}

// =============================================================================
// Range header
// =============================================================================

/// Build the value of an HTTP `Range` header to resume a download from
/// `offset` bytes.
///
/// The returned string is the header *value* only (not the `Range: ` prefix),
/// so the caller can prepend it as needed.
///
/// Conforms to RFC 7233 §2.1 — byte range specifier syntax.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_wget::build_range_header;
///
/// assert_eq!(build_range_header(0), "bytes=0-");
/// assert_eq!(build_range_header(1024), "bytes=1024-");
/// assert_eq!(build_range_header(u64::MAX), "bytes=18446744073709551615-");
/// ```
#[must_use]
pub fn build_range_header(offset: u64) -> String {
    format!("bytes={offset}-")
}

// =============================================================================
// Progress formatting
// =============================================================================

/// Format a download progress indicator.
///
/// When `total` is `Some(n)` the progress is shown as a percentage using
/// integer arithmetic.  When `total` is `None` only the downloaded byte count
/// is shown.
///
/// All arithmetic is integer-only (no `f64`) to comply with the
/// `clippy::float_arithmetic` lint.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_wget::format_progress;
///
/// // Known total.
/// let s = format_progress(512, Some(1024));
/// assert!(s.contains("512"), "got: {s}");
/// assert!(s.contains("50%"), "got: {s}");
///
/// // Unknown total.
/// let s = format_progress(2048, None);
/// assert!(s.contains("2048"), "got: {s}");
/// ```
#[must_use]
pub fn format_progress(downloaded: u64, total: Option<u64>) -> String {
    match total {
        Some(t) if t > 0 => {
            // Percentage: downloaded * 100 / total.  Integer division truncates.
            #[allow(clippy::integer_division)]
            let pct = downloaded.saturating_mul(100) / t;
            format!("{downloaded} / {t} bytes ({pct}%)")
        }
        Some(_) => format!("{downloaded} bytes (size unknown)"),
        None => format!("{downloaded} bytes downloaded"),
    }
}

// =============================================================================
// WgetError
// =============================================================================

/// Errors returned by [`parse_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WgetError {
    /// No URL was provided.
    MissingUrl,
    /// A required argument was missing after a flag.
    MissingArgument,
    /// An unrecognised flag was encountered.
    UnknownFlag,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `wget` command.
///
/// Supported flags:
///
/// | Flag | Argument | Effect |
/// |------|----------|--------|
/// | `-O` | `<file>` | Write output to `file` instead of the URL basename |
/// | `-c` | — | Resume a partial download |
///
/// The first non-flag argument is the URL to download.
///
/// # Errors
///
/// Returns a [`WgetError`] when arguments cannot be parsed.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_wget::{WgetError, parse_args};
///
/// let cfg = parse_args(&["http://example.com/file.iso"]).unwrap();
/// assert_eq!(cfg.url, "http://example.com/file.iso");
/// assert!(!cfg.resume);
///
/// let cfg = parse_args(&["-O", "out.iso", "-c", "http://example.com/file.iso"]).unwrap();
/// assert_eq!(cfg.output_file, Some(String::from("out.iso")));
/// assert!(cfg.resume);
///
/// assert_eq!(parse_args(&[]), Err(WgetError::MissingUrl));
/// ```
pub fn parse_args(args: &[&str]) -> Result<WgetConfig, WgetError> {
    let mut url: Option<String> = None;
    let mut output_file: Option<String> = None;
    let mut resume = false;
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = args.get(idx).copied().unwrap_or("");
        match arg {
            "-O" => {
                idx += 1;
                let file = args.get(idx).ok_or(WgetError::MissingArgument)?;
                output_file = Some((*file).to_string());
            }
            "-c" => resume = true,
            s if s.starts_with('-') => return Err(WgetError::UnknownFlag),
            s => url = Some(s.to_string()),
        }
        idx += 1;
    }

    let url = url.ok_or(WgetError::MissingUrl)?;
    Ok(WgetConfig {
        url,
        output_file,
        resume,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Filename extraction
    // -------------------------------------------------------------------------

    #[test]
    fn extract_filename_simple() {
        assert_eq!(
            extract_filename_from_url("http://example.com/file.tar.gz"),
            Some(String::from("file.tar.gz"))
        );
    }

    #[test]
    fn extract_filename_with_query() {
        assert_eq!(
            extract_filename_from_url("http://example.com/report.pdf?v=3"),
            Some(String::from("report.pdf"))
        );
    }

    #[test]
    fn extract_filename_trailing_slash_none() {
        assert!(extract_filename_from_url("http://example.com/").is_none());
    }

    #[test]
    fn extract_filename_no_path_none() {
        assert!(extract_filename_from_url("http://example.com").is_none());
    }

    // -------------------------------------------------------------------------
    // Range header
    // -------------------------------------------------------------------------

    #[test]
    fn range_header_from_zero() {
        assert_eq!(build_range_header(0), "bytes=0-");
    }

    #[test]
    fn range_header_from_offset() {
        assert_eq!(build_range_header(4096), "bytes=4096-");
    }

    // -------------------------------------------------------------------------
    // Progress formatting
    // -------------------------------------------------------------------------

    #[test]
    fn format_progress_with_total() {
        let s = format_progress(256, Some(1024));
        assert!(s.contains("25%"), "got: {s}");
    }

    #[test]
    fn format_progress_without_total() {
        let s = format_progress(512, None);
        assert!(s.contains("512"), "got: {s}");
        assert!(!s.contains('%'), "got: {s}");
    }

    #[test]
    fn format_progress_complete() {
        let s = format_progress(1024, Some(1024));
        assert!(s.contains("100%"), "got: {s}");
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_simple_url() {
        let cfg = parse_args(&["http://example.com/f.iso"]).unwrap();
        assert_eq!(cfg.url, "http://example.com/f.iso");
        assert!(!cfg.resume);
        assert!(cfg.output_file.is_none());
    }

    #[test]
    fn parse_args_output_and_resume() {
        let cfg = parse_args(&["-O", "out.iso", "-c", "http://example.com/f.iso"]).unwrap();
        assert_eq!(cfg.output_file, Some(String::from("out.iso")));
        assert!(cfg.resume);
    }

    #[test]
    fn parse_args_missing_url() {
        assert_eq!(parse_args(&[]), Err(WgetError::MissingUrl));
    }

    #[test]
    fn parse_args_unknown_flag() {
        assert_eq!(
            parse_args(&["-z", "http://example.com/"]),
            Err(WgetError::UnknownFlag)
        );
    }
}
