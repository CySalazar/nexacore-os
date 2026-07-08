//! Drag-and-drop pass-through between guest and host (WS9-03.6).
//!
//! Dragging data across the guest/host boundary is a small state machine: a
//! source **starts** a drag with a set of offered MIME types, the pointer
//! **moves** across targets, a target may **accept** with an action (copy /
//! move / link), and a **drop** completes only if a target accepted — otherwise
//! it is cancelled. The [`DragSession`] enforces that ordering fail-closed and
//! is capability-gated like the clipboard ([`super::clipboard`]).

use super::{AppBridgeError, AppBridgeResult, Point};

/// The action a drop performs, negotiated between source and target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DragAction {
    /// Copy the data to the target.
    Copy,
    /// Move the data (source deletes on success).
    Move,
    /// Create a link/reference.
    Link,
}

/// Lifecycle state of a drag session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DragState {
    /// No drag in progress.
    Idle,
    /// A drag is in progress.
    Dragging,
    /// The drag completed with an accepted drop.
    Dropped,
    /// The drag was cancelled (no accepting target, or explicit cancel).
    Cancelled,
}

/// Which side initiated the drag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DragSource {
    /// The guest started the drag.
    Guest,
    /// The host started the drag.
    Host,
}

/// A cross-boundary drag-and-drop session.
#[derive(Debug, Clone)]
pub struct DragSession {
    state: DragState,
    source: Option<DragSource>,
    mime_types: Vec<String>,
    position: Point,
    accepted: Option<DragAction>,
    permitted: bool,
}

impl DragSession {
    /// An idle session. `permitted` reflects the container's drag-and-drop
    /// capability grant; when `false`, starting a drag fails closed.
    #[must_use]
    pub fn new(permitted: bool) -> Self {
        Self {
            state: DragState::Idle,
            source: None,
            mime_types: Vec::new(),
            position: Point::new(0, 0),
            accepted: None,
            permitted,
        }
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> DragState {
        self.state
    }

    /// The offered MIME types (empty when idle).
    #[must_use]
    pub fn mime_types(&self) -> &[String] {
        &self.mime_types
    }

    /// The action the current target has accepted, if any.
    #[must_use]
    pub fn accepted_action(&self) -> Option<DragAction> {
        self.accepted
    }

    /// Begin a drag from `source` offering `mime_types`.
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::Capability`] if the grant is absent;
    /// [`AppBridgeError::Protocol`] if a drag is already in progress or the
    /// offer is empty.
    pub fn start(&mut self, source: DragSource, mime_types: Vec<String>) -> AppBridgeResult<()> {
        if !self.permitted {
            return Err(AppBridgeError::Capability("drag-and-drop"));
        }
        if self.state == DragState::Dragging {
            return Err(AppBridgeError::Protocol("drag already in progress"));
        }
        if mime_types.is_empty() {
            return Err(AppBridgeError::Protocol("empty drag offer"));
        }
        self.state = DragState::Dragging;
        self.source = Some(source);
        self.mime_types = mime_types;
        self.accepted = None;
        Ok(())
    }

    /// Update the drag pointer position. Moving over a new target clears any
    /// previously accepted action (the new target must accept afresh).
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::Protocol`] if no drag is in progress.
    pub fn motion(&mut self, position: Point) -> AppBridgeResult<()> {
        if self.state != DragState::Dragging {
            return Err(AppBridgeError::Protocol("motion without active drag"));
        }
        self.position = position;
        Ok(())
    }

    /// The current pointer position.
    #[must_use]
    pub fn position(&self) -> Point {
        self.position
    }

    /// The target under the pointer accepts the drag with `action`.
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::Protocol`] if no drag is in progress.
    pub fn target_accepts(&mut self, action: DragAction) -> AppBridgeResult<()> {
        if self.state != DragState::Dragging {
            return Err(AppBridgeError::Protocol("accept without active drag"));
        }
        self.accepted = Some(action);
        Ok(())
    }

    /// The pointer left the accepting target; the drop would now be rejected.
    pub fn target_leaves(&mut self) {
        self.accepted = None;
    }

    /// Release the drag. Completes with the accepted action, or cancels if no
    /// target accepted.
    ///
    /// # Errors
    ///
    /// [`AppBridgeError::Protocol`] if no drag is in progress;
    /// [`AppBridgeError::NoDropTarget`] if released with no accepting target
    /// (the session transitions to [`DragState::Cancelled`]).
    pub fn drop_here(&mut self) -> AppBridgeResult<DragAction> {
        if self.state != DragState::Dragging {
            return Err(AppBridgeError::Protocol("drop without active drag"));
        }
        if let Some(action) = self.accepted {
            self.state = DragState::Dropped;
            Ok(action)
        } else {
            self.state = DragState::Cancelled;
            Err(AppBridgeError::NoDropTarget)
        }
    }

    /// Cancel the drag (e.g. `Esc`).
    pub fn cancel(&mut self) {
        if self.state == DragState::Dragging {
            self.state = DragState::Cancelled;
            self.accepted = None;
        }
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

    fn uri() -> Vec<String> {
        vec!["text/uri-list".to_string()]
    }

    #[test]
    fn accepted_drop_completes_with_action() {
        let mut d = DragSession::new(true);
        d.start(DragSource::Guest, uri()).unwrap();
        d.motion(Point::new(300, 200)).unwrap();
        d.target_accepts(DragAction::Copy).unwrap();
        assert_eq!(d.drop_here().unwrap(), DragAction::Copy);
        assert_eq!(d.state(), DragState::Dropped);
    }

    #[test]
    fn drop_without_target_cancels() {
        let mut d = DragSession::new(true);
        d.start(DragSource::Host, uri()).unwrap();
        d.motion(Point::new(10, 10)).unwrap();
        assert_eq!(d.drop_here(), Err(AppBridgeError::NoDropTarget));
        assert_eq!(d.state(), DragState::Cancelled);
    }

    #[test]
    fn leaving_target_revokes_acceptance() {
        let mut d = DragSession::new(true);
        d.start(DragSource::Guest, uri()).unwrap();
        d.target_accepts(DragAction::Move).unwrap();
        d.target_leaves();
        assert_eq!(d.drop_here(), Err(AppBridgeError::NoDropTarget));
    }

    #[test]
    fn without_capability_start_fails_closed() {
        let mut d = DragSession::new(false);
        assert_eq!(
            d.start(DragSource::Guest, uri()),
            Err(AppBridgeError::Capability("drag-and-drop"))
        );
    }

    #[test]
    fn double_start_is_rejected() {
        let mut d = DragSession::new(true);
        d.start(DragSource::Guest, uri()).unwrap();
        assert_eq!(
            d.start(DragSource::Guest, uri()),
            Err(AppBridgeError::Protocol("drag already in progress"))
        );
    }

    #[test]
    fn motion_or_accept_without_drag_is_rejected() {
        let mut d = DragSession::new(true);
        assert_eq!(
            d.motion(Point::new(1, 1)),
            Err(AppBridgeError::Protocol("motion without active drag"))
        );
        assert_eq!(
            d.target_accepts(DragAction::Link),
            Err(AppBridgeError::Protocol("accept without active drag"))
        );
    }
}
