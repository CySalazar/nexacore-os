//! Clipboard pass-through between guest and host (WS9-03.5).
//!
//! A copy on either side publishes a MIME-typed **offer**; a paste on the other
//! side requests one of the offered types, and the owning side delivers the
//! bytes lazily. The [`ClipboardBridge`] models this selection-ownership dance
//! for both directions. It is **capability-gated** (a container without the
//! clipboard grant cannot offer or receive) and **size-bounded** (deliveries
//! over the negotiated maximum are rejected), both fail-closed.

use super::{AppBridgeError, AppBridgeResult};

/// Which side currently owns the clipboard selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionOwner {
    /// No active selection.
    None,
    /// The guest copied last.
    Guest,
    /// The host copied last.
    Host,
}

/// A MIME-typed clipboard offer published by the owning side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardOffer {
    /// The MIME types the owner can provide (e.g. `text/plain;charset=utf-8`).
    pub mime_types: Vec<String>,
}

/// A pending transfer: the paste side has requested `mime`, to be pulled from
/// `from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransfer {
    /// The requested MIME type.
    pub mime: String,
    /// The side that must produce the bytes.
    pub from: SelectionOwner,
}

/// Bidirectional clipboard pass-through state machine.
#[derive(Debug, Clone)]
pub struct ClipboardBridge {
    owner: SelectionOwner,
    offer: Option<ClipboardOffer>,
    max_bytes: usize,
    permitted: bool,
}

impl ClipboardBridge {
    /// A bridge permitting deliveries up to `max_bytes`. `permitted` reflects
    /// the container's clipboard capability grant; when `false` every operation
    /// fails closed.
    #[must_use]
    pub fn new(max_bytes: usize, permitted: bool) -> Self {
        Self {
            owner: SelectionOwner::None,
            offer: None,
            max_bytes,
            permitted,
        }
    }

    /// The current selection owner.
    #[must_use]
    pub fn owner(&self) -> SelectionOwner {
        self.owner
    }

    /// The MIME types currently on offer, if any.
    #[must_use]
    pub fn offered_types(&self) -> Option<&[String]> {
        self.offer.as_ref().map(|o| o.mime_types.as_slice())
    }

    /// Publish a guest-side copy (guest becomes the selection owner).
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::Capability`] if the clipboard grant is absent;
    /// [`AppBridgeError::Protocol`] if the offer is empty.
    pub fn guest_offers(&mut self, mime_types: Vec<String>) -> AppBridgeResult<()> {
        self.publish(SelectionOwner::Guest, mime_types)
    }

    /// Publish a host-side copy (host becomes the selection owner).
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::Capability`] if the clipboard grant is absent;
    /// [`AppBridgeError::Protocol`] if the offer is empty.
    pub fn host_offers(&mut self, mime_types: Vec<String>) -> AppBridgeResult<()> {
        self.publish(SelectionOwner::Host, mime_types)
    }

    fn publish(&mut self, owner: SelectionOwner, mime_types: Vec<String>) -> AppBridgeResult<()> {
        if !self.permitted {
            return Err(AppBridgeError::Capability("clipboard"));
        }
        if mime_types.is_empty() {
            return Err(AppBridgeError::Protocol("empty clipboard offer"));
        }
        self.owner = owner;
        self.offer = Some(ClipboardOffer { mime_types });
        Ok(())
    }

    /// A paste side requests `mime`. Returns the transfer to fulfil by pulling
    /// bytes from the owning side.
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::Capability`] if the grant is absent;
    /// [`AppBridgeError::Protocol`] if there is no active selection or `mime`
    /// was not offered.
    pub fn request(&self, mime: &str) -> AppBridgeResult<PendingTransfer> {
        if !self.permitted {
            return Err(AppBridgeError::Capability("clipboard"));
        }
        let offer = self
            .offer
            .as_ref()
            .ok_or(AppBridgeError::Protocol("no active selection"))?;
        if !offer.mime_types.iter().any(|m| m == mime) {
            return Err(AppBridgeError::Protocol("mime type not offered"));
        }
        Ok(PendingTransfer {
            mime: mime.to_string(),
            from: self.owner,
        })
    }

    /// Validate a delivered payload against the size bound and pass it through.
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::ClipboardTooLarge`] if `bytes` exceeds `max_bytes`.
    pub fn deliver(&self, bytes: Vec<u8>) -> AppBridgeResult<Vec<u8>> {
        if bytes.len() > self.max_bytes {
            return Err(AppBridgeError::ClipboardTooLarge);
        }
        Ok(bytes)
    }

    /// Clear the current selection (e.g. the owning app exited).
    pub fn clear(&mut self) {
        self.owner = SelectionOwner::None;
        self.offer = None;
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn text() -> Vec<String> {
        vec!["text/plain;charset=utf-8".to_string()]
    }

    #[test]
    fn guest_copy_host_paste_round_trip() {
        let mut cb = ClipboardBridge::new(1024, true);
        cb.guest_offers(text()).unwrap();
        assert_eq!(cb.owner(), SelectionOwner::Guest);
        let req = cb.request("text/plain;charset=utf-8").unwrap();
        assert_eq!(req.from, SelectionOwner::Guest);
        let data = cb.deliver(b"hello".to_vec()).unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn without_capability_all_ops_fail_closed() {
        let mut cb = ClipboardBridge::new(1024, false);
        assert_eq!(
            cb.guest_offers(text()),
            Err(AppBridgeError::Capability("clipboard"))
        );
        assert_eq!(
            cb.request("text/plain"),
            Err(AppBridgeError::Capability("clipboard"))
        );
    }

    #[test]
    fn request_unoffered_type_is_rejected() {
        let mut cb = ClipboardBridge::new(1024, true);
        cb.host_offers(text()).unwrap();
        assert_eq!(
            cb.request("image/png"),
            Err(AppBridgeError::Protocol("mime type not offered"))
        );
    }

    #[test]
    fn request_without_selection_is_rejected() {
        let cb = ClipboardBridge::new(1024, true);
        assert_eq!(
            cb.request("text/plain"),
            Err(AppBridgeError::Protocol("no active selection"))
        );
    }

    #[test]
    fn oversized_delivery_is_rejected() {
        let cb = ClipboardBridge::new(4, true);
        assert_eq!(
            cb.deliver(vec![0u8; 5]),
            Err(AppBridgeError::ClipboardTooLarge)
        );
        assert!(cb.deliver(vec![0u8; 4]).is_ok());
    }

    #[test]
    fn empty_offer_is_rejected() {
        let mut cb = ClipboardBridge::new(1024, true);
        assert_eq!(
            cb.guest_offers(vec![]),
            Err(AppBridgeError::Protocol("empty clipboard offer"))
        );
    }

    #[test]
    fn clear_resets_ownership() {
        let mut cb = ClipboardBridge::new(1024, true);
        cb.guest_offers(text()).unwrap();
        cb.clear();
        assert_eq!(cb.owner(), SelectionOwner::None);
        assert!(cb.offered_types().is_none());
    }
}
