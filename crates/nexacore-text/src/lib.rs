//! # `nexacore-text`
//!
//! Host-testable core of **NexaCoreText** — NexaCore's fast plain-text editor
//! (WS8-08). It is the device-independent half of "Notepad but advanced":
//!
//! - [`buffer`] (WS8-08.1) — a [`buffer::PieceTable`] text buffer. Edits never
//!   copy the loaded file, so opening and editing hundreds-of-MB files stays
//!   cheap.
//! - [`search`] (WS8-08.5) — literal / case-insensitive / whole-word
//!   [`search::find_all`] and [`search::replace_all`], with a [`search::Matcher`]
//!   seam behind which a regex engine plugs in.
//! - [`encoding`] (WS8-08.6) — [`encoding::detect_encoding`] (BOM sniffing) and
//!   [`encoding::detect_eol`] line-ending detection + normalisation.
//! - [`lines`] (WS8-08.7) — a [`lines::LineIndex`] for gutter line numbers and a
//!   [`lines::minimap_rows`] downsampler.
//! - [`highlight`] (WS8-08.3/.4) — [`highlight::Highlighter`]s for JSON,
//!   Markdown, TOML/YAML, log files, and ncScript `.oss` (keyword set aligned to
//!   `nexacore-script`).
//!
//! Multi-tab UI (.2), syntax highlighting (.3/.4), AI actions (.8), ncScript
//! execution (.9), and clipboard (.10) are the surrounding sub-tasks.
//!
//! ## `no_std` + `alloc`
//!
//! `#![no_std]` pulling only `alloc`, dependency-free, so it builds for
//! `x86_64-unknown-none` as well as the developer host.

#![no_std]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
    )
)]

extern crate alloc;

pub mod buffer;
pub mod encoding;
pub mod highlight;
pub mod lines;
pub mod search;

/// Errors from text-buffer operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextError {
    /// A byte offset was past the end of the document.
    OutOfBounds,
    /// A byte offset fell inside a UTF-8 multi-byte sequence.
    NotCharBoundary,
}
