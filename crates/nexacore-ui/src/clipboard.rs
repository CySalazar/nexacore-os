//! Clipboard service: multi-format offers and per-MIME requests (WS7-08).
//!
//! A copy places a [`ClipboardContent`] — one logical payload available in one
//! or more MIME representations (e.g. `text/plain` and `text/html`, or
//! `image/png`) — on a [`Selection`]. A paste *requests* a specific MIME type
//! and receives the matching bytes, or nothing if that format is not on offer
//! ([`ClipboardService`], WS7-08.1/.2).
//!
//! Two independent selections are tracked (WS7-08.4): the explicit
//! [`Selection::Clipboard`] (Ctrl-C / Ctrl-V) and the X11-style
//! [`Selection::Primary`] (highlight-to-select, middle-click paste). Each offer
//! bumps a serial so a consumer can tell whether the offer it is reading is
//! still current.
//!
//! Pure data model, `no_std + alloc`; the IPC transport and client cut/copy/
//! paste bindings (WS7-08.3) sit on top.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// The MIME type for UTF-8 plain text.
pub const MIME_TEXT: &str = "text/plain;charset=utf-8";

/// Which selection an offer or request targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// The explicit clipboard (copy / paste).
    Clipboard,
    /// The primary selection (highlight / middle-click paste).
    Primary,
}

/// A clipboard payload in one or more MIME representations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClipboardContent {
    /// `(mime, bytes)` representations, in offer order.
    formats: Vec<(String, Vec<u8>)>,
}

impl ClipboardContent {
    /// An empty payload.
    #[must_use]
    pub fn new() -> Self {
        Self {
            formats: Vec::new(),
        }
    }

    /// A payload holding a single UTF-8 `text/plain` representation.
    #[must_use]
    pub fn text(text: &str) -> Self {
        Self::new().with_format(MIME_TEXT, text.as_bytes())
    }

    /// Add a representation (builder-style); replaces an existing one for the
    /// same MIME type.
    #[must_use]
    pub fn with_format(mut self, mime: &str, bytes: &[u8]) -> Self {
        self.add_format(mime, bytes);
        self
    }

    /// Add or replace the representation for `mime`.
    pub fn add_format(&mut self, mime: &str, bytes: &[u8]) {
        if let Some(entry) = self.formats.iter_mut().find(|(m, _)| m == mime) {
            entry.1 = bytes.to_vec();
        } else {
            self.formats.push((mime.to_string(), bytes.to_vec()));
        }
    }

    /// The MIME types this payload offers, in order.
    #[must_use]
    pub fn mime_types(&self) -> Vec<&str> {
        self.formats.iter().map(|(m, _)| m.as_str()).collect()
    }

    /// The bytes of the `mime` representation, if present.
    #[must_use]
    pub fn get(&self, mime: &str) -> Option<&[u8]> {
        self.formats
            .iter()
            .find(|(m, _)| m == mime)
            .map(|(_, b)| b.as_slice())
    }

    /// The `text/plain` representation decoded as UTF-8, if present and valid.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        self.get(MIME_TEXT)
            .and_then(|b| core::str::from_utf8(b).ok())
    }

    /// Whether the payload has no representations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.formats.is_empty()
    }
}

/// Holds the current clipboard and primary-selection offers (WS7-08.2/.4).
#[derive(Debug, Clone, Default)]
pub struct ClipboardService {
    clipboard: Option<ClipboardContent>,
    primary: Option<ClipboardContent>,
    serial: u64,
}

impl ClipboardService {
    /// An empty service (both selections cleared).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&self, selection: Selection) -> Option<&ClipboardContent> {
        match selection {
            Selection::Clipboard => self.clipboard.as_ref(),
            Selection::Primary => self.primary.as_ref(),
        }
    }

    fn slot_mut(&mut self, selection: Selection) -> &mut Option<ClipboardContent> {
        match selection {
            Selection::Clipboard => &mut self.clipboard,
            Selection::Primary => &mut self.primary,
        }
    }

    /// Place `content` on `selection`, replacing any previous offer, and return
    /// the new serial identifying this offer.
    pub fn offer(&mut self, selection: Selection, content: ClipboardContent) -> u64 {
        self.serial = self.serial.wrapping_add(1);
        *self.slot_mut(selection) = Some(content);
        self.serial
    }

    /// The MIME types currently offered on `selection` (empty if none).
    #[must_use]
    pub fn formats(&self, selection: Selection) -> Vec<&str> {
        self.slot(selection)
            .map(ClipboardContent::mime_types)
            .unwrap_or_default()
    }

    /// Request the `mime` representation of the current `selection` offer.
    #[must_use]
    pub fn request(&self, selection: Selection, mime: &str) -> Option<&[u8]> {
        self.slot(selection)?.get(mime)
    }

    /// Convenience: request the `text/plain` representation as UTF-8.
    #[must_use]
    pub fn request_text(&self, selection: Selection) -> Option<&str> {
        self.slot(selection)?.as_text()
    }

    /// Whether `selection` currently holds an offer.
    #[must_use]
    pub fn has_content(&self, selection: Selection) -> bool {
        self.slot(selection).is_some()
    }

    /// Clear the offer on `selection`.
    pub fn clear(&mut self, selection: Selection) {
        *self.slot_mut(selection) = None;
    }

    /// The serial of the most recent offer (0 before any offer).
    #[must_use]
    pub fn current_serial(&self) -> u64 {
        self.serial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_the_offered_mime_and_misses_others() {
        let mut svc = ClipboardService::new();
        let content = ClipboardContent::text("hello").with_format("text/html", b"<b>hello</b>");
        svc.offer(Selection::Clipboard, content);

        assert_eq!(svc.request_text(Selection::Clipboard), Some("hello"));
        assert_eq!(
            svc.request(Selection::Clipboard, "text/html"),
            Some(&b"<b>hello</b>"[..])
        );
        // A format that was not offered is a miss.
        assert_eq!(svc.request(Selection::Clipboard, "image/png"), None);
    }

    #[test]
    fn lists_offered_formats_in_order() {
        let content = ClipboardContent::text("x").with_format("text/html", b"<i>x</i>");
        assert_eq!(content.mime_types(), [MIME_TEXT, "text/html"]);
    }

    #[test]
    fn add_format_replaces_same_mime() {
        let mut c = ClipboardContent::text("one");
        c.add_format(MIME_TEXT, b"two");
        assert_eq!(c.as_text(), Some("two"));
        assert_eq!(c.mime_types().len(), 1); // no duplicate MIME entry
    }

    #[test]
    fn clipboard_and_primary_are_independent() {
        let mut svc = ClipboardService::new();
        svc.offer(Selection::Clipboard, ClipboardContent::text("clip"));
        svc.offer(Selection::Primary, ClipboardContent::text("prim"));
        assert_eq!(svc.request_text(Selection::Clipboard), Some("clip"));
        assert_eq!(svc.request_text(Selection::Primary), Some("prim"));
        // Clearing one leaves the other intact.
        svc.clear(Selection::Primary);
        assert!(!svc.has_content(Selection::Primary));
        assert!(svc.has_content(Selection::Clipboard));
        assert!(svc.request_text(Selection::Primary).is_none());
    }

    #[test]
    fn each_offer_bumps_the_serial() {
        let mut svc = ClipboardService::new();
        assert_eq!(svc.current_serial(), 0);
        let s1 = svc.offer(Selection::Clipboard, ClipboardContent::text("a"));
        let s2 = svc.offer(Selection::Clipboard, ClipboardContent::text("b"));
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        // The newest offer replaced the previous content.
        assert_eq!(svc.request_text(Selection::Clipboard), Some("b"));
    }

    #[test]
    fn empty_selection_reports_no_formats() {
        let svc = ClipboardService::new();
        assert!(svc.formats(Selection::Clipboard).is_empty());
        assert!(!svc.has_content(Selection::Clipboard));
        assert_eq!(svc.request_text(Selection::Clipboard), None);
    }
}
