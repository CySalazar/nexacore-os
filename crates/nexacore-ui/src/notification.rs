//! Notification service: API, priority-queue daemon, and history (WS7-10).
//!
//! The host-verifiable core of the notification service:
//!
//! * [`NotificationRequest`] / [`NotificationEvent`] — the IPC API a client
//!   posts to and the daemon answers with (post / replace / dismiss / action,
//!   WS7-10.1).
//! * [`NotificationDaemon`] — keeps the *active* set ordered by priority
//!   (highest first, FIFO within a priority) for the toast stack, and moves
//!   dismissed/actioned notifications into a bounded, browsable [history]
//!   (WS7-10.2 / WS7-10.4).
//!
//! `no_std + alloc`, pure logic — the on-screen toast rendering (WS7-10.3) and
//! the tray (WS7-10.5/.6) consume this core. Cross-process IPC transport
//! (postcard wire) and disk persistence of the history are thin follow-ups; the
//! API contract and the queue/history semantics live here.
//!
//! [history]: NotificationDaemon::history

// Length prefixes are written as `u32`; the `usize`→`u32` casts are bounded by
// realistic notification counts and string lengths.
#![allow(clippy::cast_possible_truncation)]

use alloc::{string::String, vec::Vec};

use nexacore_display::{geometry::Rect, tokens};

use crate::{canvas::Canvas, text::draw_text, theme::Theme};

/// Urgency of a notification (orders the toast stack; higher shows first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Low-urgency / informational.
    Low,
    /// Default urgency.
    Normal,
    /// Time-sensitive.
    High,
    /// Critical / alert — never coalesced away.
    Critical,
}

/// An actionable button attached to a notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationAction {
    /// Stable action key the client matches on.
    pub key: String,
    /// Human-readable button label.
    pub label: String,
}

/// A notification posted by an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Client-assigned id (the key for replace / dismiss / action).
    pub id: u64,
    /// Posting application identifier.
    pub app: String,
    /// Short title.
    pub title: String,
    /// Body text.
    pub body: String,
    /// Urgency.
    pub priority: Priority,
    /// Optional action buttons.
    pub actions: Vec<NotificationAction>,
}

/// The notification-service IPC API: requests a client sends (WS7-10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationRequest {
    /// Post a new notification (or supersede one with the same id).
    Post(Notification),
    /// Replace an existing notification's content in place, keeping its slot.
    Replace(Notification),
    /// Dismiss an active notification by id.
    Dismiss(u64),
    /// Invoke one of a notification's actions by key.
    Action {
        /// Target notification id.
        id: u64,
        /// Action key to invoke.
        key: String,
    },
}

/// Events the daemon emits in response to a [`NotificationRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationEvent {
    /// A new notification became active.
    Posted(u64),
    /// An existing notification was updated in place.
    Replaced(u64),
    /// A notification was dismissed (now in history).
    Dismissed(u64),
    /// An action was invoked; the notification is moved to history.
    ActionInvoked {
        /// Notification id.
        id: u64,
        /// Invoked action key.
        key: String,
    },
    /// The request referenced an id that is not active.
    NotFound(u64),
}

/// A history record: the notification plus how it left the active set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The notification as it was when it left the active set.
    pub notification: Notification,
    /// The action key, if it was resolved by an action (vs. a plain dismiss).
    pub resolved_action: Option<String>,
}

/// The notification daemon: a priority-ordered active set plus a bounded
/// history (WS7-10.2 / WS7-10.4).
#[derive(Debug)]
pub struct NotificationDaemon {
    active: Vec<Notification>,
    history: Vec<HistoryEntry>,
    history_cap: usize,
}

impl NotificationDaemon {
    /// Create a daemon retaining up to `history_cap` past notifications
    /// (clamped to at least 1).
    #[must_use]
    pub fn new(history_cap: usize) -> Self {
        Self {
            active: Vec::new(),
            history: Vec::new(),
            history_cap: history_cap.max(1),
        }
    }

    /// Dispatch one request, returning the resulting event (WS7-10.1/.2).
    pub fn handle(&mut self, request: NotificationRequest) -> NotificationEvent {
        match request {
            NotificationRequest::Post(n) => self.post(n),
            NotificationRequest::Replace(n) => self.replace(n),
            NotificationRequest::Dismiss(id) => self.dismiss(id),
            NotificationRequest::Action { id, key } => self.action(id, &key),
        }
    }

    /// Insert `n` after all active entries of equal-or-higher priority and
    /// before the first lower-priority one (priority-desc, FIFO within a
    /// priority).
    fn insert_active(&mut self, n: Notification) {
        let idx = self
            .active
            .iter()
            .position(|e| e.priority < n.priority)
            .unwrap_or(self.active.len());
        self.active.insert(idx, n);
    }

    fn post(&mut self, n: Notification) -> NotificationEvent {
        let id = n.id;
        // A post with an existing id supersedes it (remove then re-insert by
        // the new priority).
        self.active.retain(|e| e.id != id);
        self.insert_active(n);
        NotificationEvent::Posted(id)
    }

    fn replace(&mut self, n: Notification) -> NotificationEvent {
        let id = n.id;
        if self.active.iter().any(|e| e.id == id) {
            self.active.retain(|e| e.id != id);
            self.insert_active(n);
            NotificationEvent::Replaced(id)
        } else {
            NotificationEvent::NotFound(id)
        }
    }

    fn dismiss(&mut self, id: u64) -> NotificationEvent {
        let Some(n) = self.take_active(id) else {
            return NotificationEvent::NotFound(id);
        };
        self.push_history(n, None);
        NotificationEvent::Dismissed(id)
    }

    fn action(&mut self, id: u64, key: &str) -> NotificationEvent {
        // The action must exist on the notification.
        let has_action = self
            .active
            .iter()
            .find(|e| e.id == id)
            .is_some_and(|e| e.actions.iter().any(|a| a.key == key));
        if !has_action {
            return NotificationEvent::NotFound(id);
        }
        let Some(n) = self.take_active(id) else {
            return NotificationEvent::NotFound(id);
        };
        self.push_history(n, Some(String::from(key)));
        NotificationEvent::ActionInvoked {
            id,
            key: String::from(key),
        }
    }

    /// Remove and return the active notification with `id`, if present.
    fn take_active(&mut self, id: u64) -> Option<Notification> {
        let idx = self.active.iter().position(|e| e.id == id)?;
        Some(self.active.remove(idx))
    }

    /// Append to history, evicting the oldest entries past the cap.
    fn push_history(&mut self, notification: Notification, resolved_action: Option<String>) {
        self.history.push(HistoryEntry {
            notification,
            resolved_action,
        });
        while self.history.len() > self.history_cap {
            self.history.remove(0);
        }
    }

    /// The active notifications, highest priority first (the toast stack).
    #[must_use]
    pub fn active(&self) -> &[Notification] {
        &self.active
    }

    /// The highest-priority active notification (the next toast to show), if
    /// any.
    #[must_use]
    pub fn next_toast(&self) -> Option<&Notification> {
        self.active.first()
    }

    /// The browsable history, oldest first, newest last (WS7-10.4).
    #[must_use]
    pub fn history(&self) -> &[HistoryEntry] {
        &self.history
    }

    /// Serialize the history to a portable byte blob so it can be persisted to
    /// disk (WS7-10.4). The blob is self-describing (length-prefixed,
    /// little-endian); [`import_history`](Self::import_history) restores it.
    #[must_use]
    pub fn export_history(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, self.history.len() as u32);
        for e in &self.history {
            encode_notification(&mut out, &e.notification);
            match &e.resolved_action {
                None => out.push(0),
                Some(key) => {
                    out.push(1);
                    put_str(&mut out, key);
                }
            }
        }
        out
    }

    /// Restore the history from an [`export_history`](Self::export_history)
    /// blob, replacing the current history (and re-applying the cap). Returns
    /// `false` (leaving the history untouched) if the blob is malformed.
    #[must_use]
    pub fn import_history(&mut self, bytes: &[u8]) -> bool {
        let mut r = ByteReader::new(bytes);
        let Some(count) = r.u32() else { return false };
        let mut restored = Vec::new();
        for _ in 0..count {
            let Some(notification) = decode_notification(&mut r) else {
                return false;
            };
            let resolved_action = match r.u8() {
                Some(0) => None,
                Some(1) => match r.string() {
                    Some(key) => Some(key),
                    None => return false,
                },
                _ => return false,
            };
            restored.push(HistoryEntry {
                notification,
                resolved_action,
            });
        }
        while restored.len() > self.history_cap {
            restored.remove(0);
        }
        self.history = restored;
        true
    }
}

// =============================================================================
// History persistence codec (WS7-10.4)
// =============================================================================

/// Stable discriminant for a [`Priority`] in the persistence format.
fn priority_disc(p: Priority) -> u8 {
    match p {
        Priority::Low => 0,
        Priority::Normal => 1,
        Priority::High => 2,
        Priority::Critical => 3,
    }
}

/// Inverse of [`priority_disc`].
fn disc_priority(d: u8) -> Option<Priority> {
    match d {
        0 => Some(Priority::Low),
        1 => Some(Priority::Normal),
        2 => Some(Priority::High),
        3 => Some(Priority::Critical),
        _ => None,
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

fn encode_notification(out: &mut Vec<u8>, n: &Notification) {
    put_u64(out, n.id);
    out.push(priority_disc(n.priority));
    put_str(out, &n.app);
    put_str(out, &n.title);
    put_str(out, &n.body);
    put_u32(out, n.actions.len() as u32);
    for a in &n.actions {
        put_str(out, &a.key);
        put_str(out, &a.label);
    }
}

/// A bounds-checked little-endian reader over the persistence blob.
struct ByteReader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> ByteReader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let v = self.b.get(self.i).copied()?;
        self.i += 1;
        Some(v)
    }

    fn u32(&mut self) -> Option<u32> {
        let end = self.i.checked_add(4)?;
        let arr: [u8; 4] = self.b.get(self.i..end)?.try_into().ok()?;
        self.i = end;
        Some(u32::from_le_bytes(arr))
    }

    fn u64(&mut self) -> Option<u64> {
        let end = self.i.checked_add(8)?;
        let arr: [u8; 8] = self.b.get(self.i..end)?.try_into().ok()?;
        self.i = end;
        Some(u64::from_le_bytes(arr))
    }

    fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let end = self.i.checked_add(len)?;
        let s = core::str::from_utf8(self.b.get(self.i..end)?).ok()?;
        self.i = end;
        Some(String::from(s))
    }
}

fn decode_notification(r: &mut ByteReader<'_>) -> Option<Notification> {
    let id = r.u64()?;
    let priority = disc_priority(r.u8()?)?;
    let app = r.string()?;
    let title = r.string()?;
    let body = r.string()?;
    let action_count = r.u32()?;
    let mut actions = Vec::new();
    for _ in 0..action_count {
        let key = r.string()?;
        let label = r.string()?;
        actions.push(NotificationAction { key, label });
    }
    Some(Notification {
        id,
        app,
        title,
        body,
        priority,
        actions,
    })
}

impl Notification {
    /// The accent colour for this notification's urgency: petrol for
    /// low/normal, goldenrod for high, brick for critical.
    #[must_use]
    fn accent(&self) -> u32 {
        match self.priority {
            Priority::Low | Priority::Normal => tokens::PETROL_500,
            Priority::High => tokens::STATUS_WARNING,
            Priority::Critical => tokens::BRICK_500,
        }
    }

    /// Renders this notification as a **branded toast card** inside `rect`
    /// (WS7-19.6 / WS7-10.3).
    ///
    /// An elevated rounded cream card (soft shadow) with a priority-coloured
    /// accent stripe down the left edge, the app/title in charcoal, and the body
    /// in the secondary text colour beneath it. Text uses the bitmap path; the
    /// desktop image swaps in `draw_text_aa` once a font is loaded.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "toast geometry uses small positive pixel values"
    )]
    pub fn render(&self, canvas: &mut Canvas<'_>, theme: &Theme, rect: &Rect) {
        canvas.draw_shadow(rect, theme.elevation);
        canvas.fill_rounded_rect(rect, theme.radius, tokens::CREAM_50);

        // Priority accent stripe hugging the left edge.
        let stripe = Rect {
            x: rect.x,
            y: rect.y + theme.radius as i32,
            w: 4,
            h: rect.h.saturating_sub(2 * theme.radius),
        };
        canvas.fill_rounded_rect(&stripe, 1, self.accent());

        // Title (app + title) and body, inset past the stripe.
        let inset_x = rect.x + (theme.padding + 6) as i32;
        let title_y = rect.y + theme.padding as i32;
        draw_text(
            canvas,
            inset_x,
            title_y,
            &self.title,
            tokens::CHARCOAL_800,
            theme.text_scale,
        );
        let body_y = title_y + (crate::text::GLYPH_H * theme.text_scale + theme.spacing) as i32;
        draw_text(
            canvas,
            inset_x,
            body_y,
            &self.body,
            tokens::CHARCOAL_500,
            theme.text_scale,
        );
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn note(id: u64, priority: Priority) -> Notification {
        Notification {
            id,
            app: String::from("test.app"),
            title: String::from("t"),
            body: String::from("b"),
            priority,
            actions: Vec::new(),
        }
    }

    #[test]
    fn toast_render_draws_card_with_priority_accent() {
        const BG: u32 = 0xFF14_171A;
        let critical = note(1, Priority::Critical);
        let mut buf = alloc::vec![BG; 240 * 64];
        {
            let mut c = Canvas::new(&mut buf, 240, 64).unwrap();
            critical.render(
                &mut c,
                &Theme::nexacore(),
                &Rect {
                    x: 8,
                    y: 8,
                    w: 220,
                    h: 48,
                },
            );
        }
        // A cream card body and the brick critical-accent stripe are painted.
        assert!(buf.iter().any(|&p| p == tokens::CREAM_50), "no card body");
        assert!(
            buf.iter().any(|&p| p == tokens::BRICK_500),
            "no critical accent stripe"
        );
        // Priority drives the accent colour.
        assert_eq!(note(2, Priority::Low).accent(), tokens::PETROL_500);
        assert_eq!(note(3, Priority::High).accent(), tokens::STATUS_WARNING);
    }

    fn note_with_action(id: u64, action_key: &str) -> Notification {
        Notification {
            actions: vec![NotificationAction {
                key: String::from(action_key),
                label: String::from("Do it"),
            }],
            ..note(id, Priority::Normal)
        }
    }

    #[test]
    fn post_orders_by_priority_then_fifo() {
        let mut d = NotificationDaemon::new(8);
        assert_eq!(
            d.handle(NotificationRequest::Post(note(1, Priority::Normal))),
            NotificationEvent::Posted(1)
        );
        assert_eq!(
            d.handle(NotificationRequest::Post(note(2, Priority::Low))),
            NotificationEvent::Posted(2)
        );
        assert_eq!(
            d.handle(NotificationRequest::Post(note(3, Priority::Critical))),
            NotificationEvent::Posted(3)
        );
        assert_eq!(
            d.handle(NotificationRequest::Post(note(4, Priority::Normal))),
            NotificationEvent::Posted(4)
        );
        // Critical first, then the two Normals in FIFO order, then Low.
        let ids: Vec<u64> = d.active().iter().map(|n| n.id).collect();
        assert_eq!(ids, vec![3, 1, 4, 2]);
        assert_eq!(d.next_toast().map(|n| n.id), Some(3));
    }

    #[test]
    fn post_with_same_id_supersedes() {
        let mut d = NotificationDaemon::new(8);
        d.handle(NotificationRequest::Post(note(1, Priority::Low)));
        d.handle(NotificationRequest::Post(note(1, Priority::Critical)));
        assert_eq!(d.active().len(), 1);
        assert_eq!(d.active()[0].priority, Priority::Critical);
    }

    #[test]
    fn replace_updates_in_place_or_reports_not_found() {
        let mut d = NotificationDaemon::new(8);
        d.handle(NotificationRequest::Post(note(1, Priority::Normal)));
        let mut updated = note(1, Priority::High);
        updated.title = String::from("updated");
        assert_eq!(
            d.handle(NotificationRequest::Replace(updated)),
            NotificationEvent::Replaced(1)
        );
        assert_eq!(d.active()[0].title, "updated");
        assert_eq!(d.active()[0].priority, Priority::High);
        assert_eq!(
            d.handle(NotificationRequest::Replace(note(99, Priority::Low))),
            NotificationEvent::NotFound(99)
        );
    }

    #[test]
    fn dismiss_moves_to_history() {
        let mut d = NotificationDaemon::new(8);
        d.handle(NotificationRequest::Post(note(1, Priority::Normal)));
        assert_eq!(
            d.handle(NotificationRequest::Dismiss(1)),
            NotificationEvent::Dismissed(1)
        );
        assert!(d.active().is_empty());
        assert_eq!(d.history().len(), 1);
        assert_eq!(d.history()[0].notification.id, 1);
        assert_eq!(d.history()[0].resolved_action, None);
        assert_eq!(
            d.handle(NotificationRequest::Dismiss(1)),
            NotificationEvent::NotFound(1)
        );
    }

    #[test]
    fn action_requires_known_key_and_records_it() {
        let mut d = NotificationDaemon::new(8);
        d.handle(NotificationRequest::Post(note_with_action(1, "open")));
        // Unknown key ⇒ NotFound, stays active.
        assert_eq!(
            d.handle(NotificationRequest::Action {
                id: 1,
                key: String::from("nope")
            }),
            NotificationEvent::NotFound(1)
        );
        assert_eq!(d.active().len(), 1);
        // Known key ⇒ invoked, moved to history with the action recorded.
        assert_eq!(
            d.handle(NotificationRequest::Action {
                id: 1,
                key: String::from("open")
            }),
            NotificationEvent::ActionInvoked {
                id: 1,
                key: String::from("open")
            }
        );
        assert!(d.active().is_empty());
        assert_eq!(d.history()[0].resolved_action.as_deref(), Some("open"));
    }

    #[test]
    fn history_is_bounded() {
        let mut d = NotificationDaemon::new(2);
        for id in 1..=4 {
            d.handle(NotificationRequest::Post(note(id, Priority::Normal)));
            d.handle(NotificationRequest::Dismiss(id));
        }
        // Only the two most recent survive, oldest-first.
        let ids: Vec<u64> = d.history().iter().map(|h| h.notification.id).collect();
        assert_eq!(ids, vec![3, 4]);
    }

    #[test]
    fn history_export_import_round_trips() {
        let mut d = NotificationDaemon::new(8);
        d.handle(NotificationRequest::Post(note(1, Priority::High)));
        d.handle(NotificationRequest::Dismiss(1));
        d.handle(NotificationRequest::Post(note_with_action(2, "open")));
        d.handle(NotificationRequest::Action {
            id: 2,
            key: String::from("open"),
        });
        let blob = d.export_history();

        let mut restored = NotificationDaemon::new(8);
        assert!(restored.import_history(&blob));
        assert_eq!(restored.history(), d.history());
        // The action key survived the round trip.
        assert_eq!(
            restored.history()[1].resolved_action.as_deref(),
            Some("open")
        );
    }

    #[test]
    fn import_rejects_truncated_blob_and_keeps_history() {
        let mut d = NotificationDaemon::new(8);
        d.handle(NotificationRequest::Post(note(1, Priority::Normal)));
        d.handle(NotificationRequest::Dismiss(1));
        let blob = d.export_history();

        let mut other = NotificationDaemon::new(8);
        other.handle(NotificationRequest::Post(note(9, Priority::Low)));
        other.handle(NotificationRequest::Dismiss(9));
        // A truncated blob is rejected and the existing history is untouched.
        assert!(!other.import_history(&blob[..blob.len() - 1]));
        assert_eq!(other.history().len(), 1);
        assert_eq!(other.history()[0].notification.id, 9);
    }

    #[test]
    fn import_reapplies_cap() {
        let mut src = NotificationDaemon::new(8);
        for id in 1..=4 {
            src.handle(NotificationRequest::Post(note(id, Priority::Normal)));
            src.handle(NotificationRequest::Dismiss(id));
        }
        let blob = src.export_history();
        // Importing into a cap-2 daemon keeps only the two newest.
        let mut small = NotificationDaemon::new(2);
        assert!(small.import_history(&blob));
        let ids: Vec<u64> = small.history().iter().map(|h| h.notification.id).collect();
        assert_eq!(ids, vec![3, 4]);
    }
}
