//! Display input-event channel ABI (kernel → compositor).
//!
//! This module defines the canonical input-event shape carried on the
//! display-input IPC channel per
//! [`ADR-0040`](../../../docs/adr/0040-display-map-input-channel.md)
//! (TASK-18, DE-C1). The kernel is the sole producer: it polls the PS/2
//! keyboard (and, later, the pointer) and pushes one
//! [`DisplayInputEvent`] per physical event into the channel as a
//! `MessageKind::Notification`. The Ring-3 compositor (TASK-19, or the
//! TASK-18 `nexacore-display-probe`) drains the channel via
//! `IpcTryReceive (24)` and decodes each event.
//!
//! ## Why a separate `nexacore-types` module
//!
//! Both the kernel producer and every Ring-3 consumer (probe, compositor,
//! future input-method services) need to encode/decode these events.
//! Keeping them in `nexacore-types` puts them in the foundational layer every
//! workspace member already depends on, and routes the wire shape through
//! [`crate::wire::encode_canonical`] — the single workspace audit point
//! for serialization (NCIP-Serde-004).
//!
//! ## Backward-compatibility policy
//!
//! [`DisplayInputEvent`] carries `#[non_exhaustive]` so new event kinds
//! (scroll, touch, IME composition) MAY be added via PR without breaking
//! source-level `match` consumers, which must provide a `_ =>` arm.
//!
//! ## Wire size
//!
//! The largest variant encodes to well under [`MAX_EVENT_BYTES`]; the IPC
//! layer caps payloads at 4 KiB (Phase 1), so a single event always fits
//! in one message with ample headroom.

use serde::{Deserialize, Serialize};

/// Channel-name prefix for the display-input service channel.
///
/// The kernel registers its input channel under this name so the wire
/// contract is discoverable alongside the other service channels.
pub const CHANNEL_NAME: &str = "nexacore.display.input";

/// Conservative upper bound in bytes on a postcard-encoded
/// [`DisplayInputEvent`].
///
/// The largest variant ([`DisplayInputEvent::Pointer`]) is a 1-byte
/// discriminant + two `u32`s (varint, ≤ 5 B each) + 1 byte = 12 bytes
/// worst case; this bound leaves generous slack and keeps a fixed-size
/// receive buffer trivially sufficient.
pub const MAX_EVENT_BYTES: usize = 32;

/// One input event delivered kernel → compositor over the display-input
/// channel.
///
/// Encoded with [`crate::wire::encode_canonical`] (postcard) and carried as
/// the payload of a `MessageKind::Notification` IPC message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DisplayInputEvent {
    /// A keyboard key transition.
    Key {
        /// Logical key code. Printable keys carry their ASCII byte; the
        /// kernel maps PS/2 scancodes to this stable code space (e.g.
        /// `0x1B` = Escape, `0x0D` = Enter, `0x08` = Backspace, `0x09` =
        /// Tab; the four arrows use the `0x80..=0x83` private range).
        code: u8,
        /// `true` on press (make), `false` on release (break). The Phase-1
        /// PS/2 path emits make codes only, so `pressed` is always `true`
        /// today; the field is present so the contract does not change when
        /// break-code tracking lands.
        pressed: bool,
    },
    /// A pointer (mouse/tablet) update with absolute screen coordinates.
    Pointer {
        /// Absolute X in pixels, `0..screen_width`.
        x: u32,
        /// Absolute Y in pixels, `0..screen_height`.
        y: u32,
        /// Button mask: bit 0 = left, bit 1 = right, bit 2 = middle.
        buttons: u8,
    },
}

/// Private key codes for non-printable navigation keys, chosen in the
/// `0x80..=0x83` range so they never collide with 7-bit ASCII printable
/// codes carried directly in [`DisplayInputEvent::Key::code`].
pub mod keycode {
    /// Escape (`0x1B`, standard ASCII ESC).
    pub const ESCAPE: u8 = 0x1B;
    /// Enter / Return (`0x0D`, ASCII CR).
    pub const ENTER: u8 = 0x0D;
    /// Backspace (`0x08`, ASCII BS).
    pub const BACKSPACE: u8 = 0x08;
    /// Tab (`0x09`, ASCII HT).
    pub const TAB: u8 = 0x09;
    /// Arrow Up (private range).
    pub const ARROW_UP: u8 = 0x80;
    /// Arrow Down (private range).
    pub const ARROW_DOWN: u8 = 0x81;
    /// Arrow Left (private range).
    pub const ARROW_LEFT: u8 = 0x82;
    /// Arrow Right (private range).
    pub const ARROW_RIGHT: u8 = 0x83;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{decode_canonical, encode_canonical};

    #[test]
    fn key_event_round_trips() {
        let ev = DisplayInputEvent::Key {
            code: b'a',
            pressed: true,
        };
        let bytes = encode_canonical(&ev).expect("encode");
        assert!(bytes.len() <= MAX_EVENT_BYTES);
        let back: DisplayInputEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ev);
    }

    #[test]
    fn pointer_event_round_trips() {
        let ev = DisplayInputEvent::Pointer {
            x: 1024,
            y: 768,
            buttons: 0b101,
        };
        let bytes = encode_canonical(&ev).expect("encode");
        assert!(bytes.len() <= MAX_EVENT_BYTES);
        let back: DisplayInputEvent = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ev);
    }

    #[test]
    fn max_event_bytes_bounds_worst_case() {
        // The widest variant: two u32 max values + full button mask.
        let ev = DisplayInputEvent::Pointer {
            x: u32::MAX,
            y: u32::MAX,
            buttons: 0xFF,
        };
        let bytes = encode_canonical(&ev).expect("encode");
        assert!(
            bytes.len() <= MAX_EVENT_BYTES,
            "worst-case event ({} B) must fit MAX_EVENT_BYTES ({})",
            bytes.len(),
            MAX_EVENT_BYTES
        );
    }

    #[test]
    fn navigation_keycodes_are_distinct_from_printable_ascii() {
        // The private-range arrow codes must not collide with printable
        // ASCII (0x20..=0x7E).
        for code in [
            keycode::ARROW_UP,
            keycode::ARROW_DOWN,
            keycode::ARROW_LEFT,
            keycode::ARROW_RIGHT,
        ] {
            assert!(code >= 0x80, "navigation code {code:#x} must be >= 0x80");
        }
    }
}
