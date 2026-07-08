//! Drag-and-drop protocol: grab, motion, drop, and MIME negotiation (WS7-09).
//!
//! A [`DragSource`] offers a payload (a [`ClipboardContent`] of one or more MIME
//! representations) plus the actions it supports (copy / move / link). A
//! [`DropTarget`] declares which MIME types and actions it accepts. A
//! [`DndSession`] is the state machine the compositor drives: `start_drag`
//! (grab), `enter_target` / `leave_target` (motion), and `drop` — which succeeds
//! only when the source and target share a MIME type **and** an action
//! ([`DndSession::negotiate`], WS7-09.4).
//!
//! - WS7-09.1 — the session state machine + dedicated transitions.
//! - WS7-09.2 — the source role ([`DragSource`], data offered per MIME).
//! - WS7-09.3 — the target role ([`DropTarget`], accepted MIME/actions).
//! - WS7-09.4 — the MIME + action negotiation.
//!
//! Pure state, `no_std + alloc`; the drag cursor / visual feedback (WS7-09.5)
//! and file-manager / editor integration (WS7-09.6) sit on top.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::clipboard::ClipboardContent;

/// A drag-and-drop action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DndAction {
    /// Copy the data to the target.
    Copy,
    /// Move the data (source deletes it after a successful drop).
    Move,
    /// Create a link/reference at the target.
    Link,
}

/// The drag source: the offered payload and supported actions (WS7-09.2).
#[derive(Debug, Clone)]
pub struct DragSource {
    /// The payload, available in one or more MIME representations.
    pub data: ClipboardContent,
    /// Actions the source supports, in preference order.
    pub actions: Vec<DndAction>,
}

impl DragSource {
    /// A new source offering `data` with the given `actions`.
    #[must_use]
    pub fn new(data: ClipboardContent, actions: &[DndAction]) -> Self {
        Self {
            data,
            actions: actions.to_vec(),
        }
    }
}

/// The drop target: accepted MIME types and actions (WS7-09.3).
#[derive(Debug, Clone)]
pub struct DropTarget {
    /// MIME types the target can accept.
    pub accepted_mimes: Vec<String>,
    /// Actions the target permits.
    pub actions: Vec<DndAction>,
}

impl DropTarget {
    /// A new target accepting `mimes` under `actions`.
    #[must_use]
    pub fn new(mimes: &[&str], actions: &[DndAction]) -> Self {
        Self {
            accepted_mimes: mimes.iter().map(|&s| s.to_string()).collect(),
            actions: actions.to_vec(),
        }
    }
}

/// The negotiated `(mime, action)` a drop would perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DndMatch {
    /// The chosen MIME type (source-preferred, target-accepted).
    pub mime: String,
    /// The chosen action.
    pub action: DndAction,
}

/// The outcome of a successful drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropResult {
    /// The negotiated MIME type.
    pub mime: String,
    /// The negotiated action.
    pub action: DndAction,
    /// The payload bytes in the negotiated MIME representation.
    pub bytes: Vec<u8>,
}

/// The session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DndState {
    /// No drag in progress.
    Idle,
    /// A drag is in progress but the pointer is not over a drop target.
    Dragging,
    /// The pointer is over a drop target.
    OverTarget,
    /// A drop completed successfully.
    Dropped,
    /// The drag was cancelled (or a drop was rejected).
    Cancelled,
}

/// The drag-and-drop session state machine (WS7-09.1).
#[derive(Debug, Clone, Default)]
pub struct DndSession {
    source: Option<DragSource>,
    target: Option<DropTarget>,
    state: DndState,
}

impl Default for DndState {
    fn default() -> Self {
        Self::Idle
    }
}

impl DndSession {
    /// A new idle session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> DndState {
        self.state
    }

    /// Begin a drag with `source` (grab). Resets any prior target.
    pub fn start_drag(&mut self, source: DragSource) {
        self.source = Some(source);
        self.target = None;
        self.state = DndState::Dragging;
    }

    /// The pointer entered `target` (motion). No-op unless a drag is active.
    pub fn enter_target(&mut self, target: DropTarget) {
        if matches!(self.state, DndState::Dragging | DndState::OverTarget) {
            self.target = Some(target);
            self.state = DndState::OverTarget;
        }
    }

    /// The pointer left the current target (motion).
    pub fn leave_target(&mut self) {
        if self.state == DndState::OverTarget {
            self.target = None;
            self.state = DndState::Dragging;
        }
    }

    /// The `(mime, action)` a drop on the current target would perform: the
    /// first source-offered MIME the target accepts, paired with the first
    /// source action the target permits. `None` if there is no drag, no target,
    /// or no mutual MIME/action (WS7-09.4).
    #[must_use]
    pub fn negotiate(&self) -> Option<DndMatch> {
        let source = self.source.as_ref()?;
        let target = self.target.as_ref()?;
        let mime = source
            .data
            .mime_types()
            .into_iter()
            .find(|m| target.accepted_mimes.iter().any(|a| a == m))?
            .to_string();
        let action = source
            .actions
            .iter()
            .copied()
            .find(|a| target.actions.contains(a))?;
        Some(DndMatch { mime, action })
    }

    /// Perform the drop. On a successful negotiation returns the [`DropResult`]
    /// (with the payload bytes) and moves to [`DndState::Dropped`]; otherwise the
    /// drop is rejected, the session moves to [`DndState::Cancelled`], and `None`
    /// is returned.
    pub fn drop_on_target(&mut self) -> Option<DropResult> {
        let result = self.negotiate().and_then(|m| {
            let bytes = self.source.as_ref()?.data.get(&m.mime)?.to_vec();
            Some(DropResult {
                mime: m.mime,
                action: m.action,
                bytes,
            })
        });
        self.state = if result.is_some() {
            DndState::Dropped
        } else {
            DndState::Cancelled
        };
        result
    }

    /// Cancel the drag (e.g. Escape or a drop outside any target).
    pub fn cancel(&mut self) {
        self.state = DndState::Cancelled;
        self.target = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::MIME_TEXT;

    fn source() -> DragSource {
        // Offers plain text and HTML; supports copy then move.
        let data = ClipboardContent::text("drag me").with_format("text/html", b"<b>drag me</b>");
        DragSource::new(data, &[DndAction::Copy, DndAction::Move])
    }

    #[test]
    fn negotiation_picks_source_preferred_mutual_mime_and_action() {
        let mut s = DndSession::new();
        s.start_drag(source());
        // Target accepts HTML (not plain text) and only Move.
        s.enter_target(DropTarget::new(&["text/html"], &[DndAction::Move]));
        let m = s.negotiate().unwrap();
        assert_eq!(m.mime, "text/html");
        assert_eq!(m.action, DndAction::Move);
    }

    #[test]
    fn drop_returns_bytes_and_completes() {
        let mut s = DndSession::new();
        s.start_drag(source());
        s.enter_target(DropTarget::new(
            &[MIME_TEXT, "text/html"],
            &[DndAction::Copy],
        ));
        let result = s.drop_on_target().unwrap();
        // Source prefers plain text (offered first) and the target accepts it.
        assert_eq!(result.mime, MIME_TEXT);
        assert_eq!(result.action, DndAction::Copy);
        assert_eq!(result.bytes, b"drag me");
        assert_eq!(s.state(), DndState::Dropped);
    }

    #[test]
    fn no_mutual_mime_rejects_the_drop() {
        let mut s = DndSession::new();
        s.start_drag(source());
        s.enter_target(DropTarget::new(&["image/png"], &[DndAction::Copy]));
        assert_eq!(s.negotiate(), None);
        assert!(s.drop_on_target().is_none());
        assert_eq!(s.state(), DndState::Cancelled);
    }

    #[test]
    fn no_mutual_action_rejects_the_drop() {
        let mut s = DndSession::new();
        s.start_drag(source()); // copy, move
        s.enter_target(DropTarget::new(&[MIME_TEXT], &[DndAction::Link]));
        assert_eq!(s.negotiate(), None); // no shared action
    }

    #[test]
    fn motion_enter_and_leave_track_target() {
        let mut s = DndSession::new();
        s.start_drag(source());
        assert_eq!(s.state(), DndState::Dragging);
        s.enter_target(DropTarget::new(&[MIME_TEXT], &[DndAction::Copy]));
        assert_eq!(s.state(), DndState::OverTarget);
        assert!(s.negotiate().is_some());
        s.leave_target();
        assert_eq!(s.state(), DndState::Dragging);
        assert!(s.negotiate().is_none()); // no target → nothing to negotiate
    }

    #[test]
    fn cancel_ends_the_drag() {
        let mut s = DndSession::new();
        s.start_drag(source());
        s.cancel();
        assert_eq!(s.state(), DndState::Cancelled);
        assert!(s.negotiate().is_none());
    }
}
