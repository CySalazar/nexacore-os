//! `man` - look up a manual page by name (WS8-10.10).
//!
//! Manual pages are not baked into this crate; they are served by an injected
//! [`ManSource`] seam (host double [`MapManSource`]). `man name` asks the source
//! for the page text and is **fail-closed**: an unknown page is a
//! [`ManError::NotFound`], never an empty or fabricated page.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

/// The seam that resolves a manual-page name to its text.
pub trait ManSource {
    /// The page text for `name`, or `None` if there is no such page.
    fn page(&self, name: &str) -> Option<String>;

    /// The names of all available pages, sorted. Used by `man -k`-style
    /// listings; defaults to empty for sources that cannot enumerate.
    fn names(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Why a manual-page lookup failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManError {
    /// No page exists for the requested name.
    NotFound,
}

impl core::fmt::Display for ManError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no manual entry"),
        }
    }
}

/// An in-memory [`ManSource`] host double backed by a `BTreeMap`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapManSource {
    /// `page name -> page text`.
    pages: BTreeMap<String, String>,
}

impl MapManSource {
    /// An empty page set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a page (builder style).
    #[must_use]
    pub fn with_page(mut self, name: &str, text: &str) -> Self {
        self.pages.insert(name.to_string(), text.to_string());
        self
    }
}

impl ManSource for MapManSource {
    fn page(&self, name: &str) -> Option<String> {
        self.pages.get(name).cloned()
    }

    fn names(&self) -> Vec<String> {
        self.pages.keys().cloned().collect()
    }
}

/// `man name`: fetch the page text for `name` from `source`.
///
/// # Errors
///
/// [`ManError::NotFound`] if `source` has no page for `name` (fail-closed).
pub fn man<M: ManSource>(source: &M, name: &str) -> Result<String, ManError> {
    source.page(name).ok_or(ManError::NotFound)
}

/// `man -k`: the sorted list of page names `source` can serve.
#[must_use]
pub fn list_pages<M: ManSource>(source: &M) -> Vec<String> {
    let mut names = source.names();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> MapManSource {
        MapManSource::new()
            .with_page("ls", "LS(1)\n  list directory contents")
            .with_page("cat", "CAT(1)\n  concatenate files")
    }

    #[test]
    fn known_page_is_returned() {
        assert_eq!(
            man(&source(), "ls").unwrap(),
            "LS(1)\n  list directory contents"
        );
    }

    #[test]
    fn unknown_page_is_not_found() {
        assert_eq!(man(&source(), "nope"), Err(ManError::NotFound));
    }

    #[test]
    fn empty_source_is_fail_closed() {
        let empty = MapManSource::new();
        assert_eq!(man(&empty, "ls"), Err(ManError::NotFound));
    }

    #[test]
    fn list_pages_is_sorted() {
        assert_eq!(list_pages(&source()), ["cat", "ls"]);
    }

    #[test]
    fn error_display_message() {
        use alloc::format;
        assert_eq!(format!("{}", ManError::NotFound), "no manual entry");
    }
}
