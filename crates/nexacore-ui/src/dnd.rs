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
//! - WS7-09.5 — the drag cursor ([`DndSession::cursor`]) and ghost visual
//!   feedback ([`DndSession::feedback`]) derived from the session state.
//!
//! Pure state, `no_std + alloc`; the file-manager / editor integration
//! (WS7-09.6) sits on top.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::clipboard::{ClipboardContent, MIME_TEXT};

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

impl DndAction {
    /// The drag cursor that represents this action (WS7-09.5).
    #[must_use]
    fn drag_cursor(self) -> DragCursor {
        match self {
            Self::Copy => DragCursor::Copy,
            Self::Move => DragCursor::Move,
            Self::Link => DragCursor::Link,
        }
    }
}

/// The semantic drag cursor shown during a drag (WS7-09.5).
///
/// This is the *meaning* the compositor should render (the theme maps it to an
/// actual [`crate::cursor::Cursor`] image), not a pixel buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DragCursor {
    /// A drag is in progress but the pointer is not over a droppable target.
    Grabbing,
    /// Over a target that would copy the payload.
    Copy,
    /// Over a target that would move the payload.
    Move,
    /// Over a target that would link the payload.
    Link,
    /// Over a target that cannot accept the payload (no mutual MIME/action).
    NoDrop,
}

/// Pixel offset of the drag ghost from the pointer, so the preview trails the
/// cursor instead of hiding beneath it (WS7-09.5).
pub const GHOST_OFFSET: i32 = 12;

/// The drag ghost preview shown trailing the pointer during a drag (WS7-09.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DragFeedback {
    /// The drag cursor to display.
    pub cursor: DragCursor,
    /// Top-left x of the ghost preview.
    pub ghost_x: i32,
    /// Top-left y of the ghost preview.
    pub ghost_y: i32,
    /// Whether the current target should highlight (it would accept the drop).
    pub target_highlight: bool,
    /// A short label describing the dragged payload.
    pub label: String,
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

    /// A short label for the drag ghost: a text preview when the payload carries
    /// plain text, otherwise its primary MIME type (WS7-09.5).
    #[must_use]
    pub fn preview_label(&self) -> String {
        if let Some(bytes) = self.data.get(MIME_TEXT) {
            if let Ok(text) = core::str::from_utf8(bytes) {
                return truncate_label(text);
            }
        }
        self.data
            .mime_types()
            .first()
            .map_or_else(String::new, ToString::to_string)
    }
}

/// Truncate a label to a small number of characters, appending `…` when cut.
fn truncate_label(text: &str) -> String {
    const MAX: usize = 32;
    let mut out: String = text.chars().take(MAX).collect();
    if text.chars().count() > MAX {
        out.push('…');
    }
    out
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

    /// The drag cursor for the current state, or `None` when no drag is active
    /// (WS7-09.5).
    ///
    /// While dragging without a target the cursor is [`DragCursor::Grabbing`];
    /// over a target it reflects the negotiated action, or [`DragCursor::NoDrop`]
    /// when the target cannot accept the payload.
    #[must_use]
    pub fn cursor(&self) -> Option<DragCursor> {
        match self.state {
            DndState::Dragging => Some(DragCursor::Grabbing),
            DndState::OverTarget => Some(
                self.negotiate()
                    .map_or(DragCursor::NoDrop, |m| m.action.drag_cursor()),
            ),
            DndState::Idle | DndState::Dropped | DndState::Cancelled => None,
        }
    }

    /// The visual feedback for a drag with the pointer at `(pointer_x,
    /// pointer_y)`, or `None` when no drag is active (WS7-09.5).
    ///
    /// The ghost preview is offset from the pointer by [`GHOST_OFFSET`];
    /// `target_highlight` is set only when the pointer is over a target that
    /// would accept the drop.
    #[must_use]
    pub fn feedback(&self, pointer_x: i32, pointer_y: i32) -> Option<DragFeedback> {
        let cursor = self.cursor()?;
        let target_highlight = self.state == DndState::OverTarget && self.negotiate().is_some();
        let label = self
            .source
            .as_ref()
            .map(DragSource::preview_label)
            .unwrap_or_default();
        Some(DragFeedback {
            cursor,
            ghost_x: pointer_x.saturating_add(GHOST_OFFSET),
            ghost_y: pointer_y.saturating_add(GHOST_OFFSET),
            target_highlight,
            label,
        })
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

    // --- WS7-09.5: drag cursor + visual feedback ---------------------------

    #[test]
    fn cursor_reflects_state_and_negotiation() {
        let mut s = DndSession::new();
        assert_eq!(s.cursor(), None); // idle
        s.start_drag(source());
        assert_eq!(s.cursor(), Some(DragCursor::Grabbing)); // dragging, no target
        // Over a target that would move → Move cursor.
        s.enter_target(DropTarget::new(&["text/html"], &[DndAction::Move]));
        assert_eq!(s.cursor(), Some(DragCursor::Move));
        // Over a target that cannot accept → NoDrop.
        s.leave_target();
        s.enter_target(DropTarget::new(&["image/png"], &[DndAction::Copy]));
        assert_eq!(s.cursor(), Some(DragCursor::NoDrop));
    }

    #[test]
    fn cursor_is_none_after_drop_or_cancel() {
        let mut s = DndSession::new();
        s.start_drag(source());
        s.enter_target(DropTarget::new(&[MIME_TEXT], &[DndAction::Copy]));
        s.drop_on_target();
        assert_eq!(s.cursor(), None); // dropped
        let mut s2 = DndSession::new();
        s2.start_drag(source());
        s2.cancel();
        assert_eq!(s2.cursor(), None); // cancelled
    }

    #[test]
    fn feedback_offsets_ghost_and_highlights_accepting_target() {
        let mut s = DndSession::new();
        s.start_drag(source());
        // Dragging, no target: ghost trails the pointer, no highlight.
        let fb = s.feedback(100, 200).unwrap();
        assert_eq!(fb.cursor, DragCursor::Grabbing);
        assert_eq!(
            (fb.ghost_x, fb.ghost_y),
            (100 + GHOST_OFFSET, 200 + GHOST_OFFSET)
        );
        assert!(!fb.target_highlight);
        assert_eq!(fb.label, "drag me"); // text preview
        // Over an accepting target: highlight on.
        s.enter_target(DropTarget::new(&[MIME_TEXT], &[DndAction::Copy]));
        assert!(s.feedback(0, 0).unwrap().target_highlight);
        // Over a rejecting target: highlight off, NoDrop cursor.
        s.leave_target();
        s.enter_target(DropTarget::new(&["image/png"], &[DndAction::Copy]));
        let fb = s.feedback(0, 0).unwrap();
        assert!(!fb.target_highlight);
        assert_eq!(fb.cursor, DragCursor::NoDrop);
    }

    #[test]
    fn feedback_is_none_without_a_drag() {
        assert!(DndSession::new().feedback(10, 10).is_none());
    }

    #[test]
    fn preview_label_falls_back_to_primary_mime() {
        // A non-text payload: label is the primary MIME type.
        let data = ClipboardContent::new().with_format("image/png", &[1, 2, 3]);
        let src = DragSource::new(data, &[DndAction::Copy]);
        assert_eq!(src.preview_label(), "image/png");
    }

    #[test]
    fn preview_label_truncates_long_text() {
        let long = "x".repeat(40);
        let data = ClipboardContent::text(&long);
        let src = DragSource::new(data, &[DndAction::Copy]);
        let label = src.preview_label();
        assert!(label.ends_with('…'));
        assert_eq!(label.chars().count(), 33); // 32 chars + ellipsis
    }
}
