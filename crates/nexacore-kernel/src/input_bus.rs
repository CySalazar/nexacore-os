//! WS2-08 — unified input event bus (PS/2 + pointer + ACPI).
//!
//! Today the PS/2 keyboard/mouse pump (`bare_metal::input`) decodes scancodes
//! in-kernel and the desktop has no path for ACPI system keys (power, lid,
//! brightness). This module defines the **one normalized event format** every
//! input source funnels into — [`crate::input_bus::UnifiedInputEvent`] — plus the *pure*
//! normalizers that turn raw PS/2 scancodes and ACPI device notifications into
//! it, and the routing that splits the stream into the display-input channel
//! (keys/pointer) versus the power-management path (system events).
//!
//! The normalizers are pure functions (no port I/O, no statics), so the
//! bare-metal pump and the ACPI GPE handler become thin shells that read a
//! register and call into the host-tested decode here. As a bonus the PS/2
//! normalizer decodes **break codes** into key-*release* events — the existing
//! in-kernel `decode` discards key-up, which this lifts (the
//! `DisplayInputEvent::Key::pressed` contract was reserved for exactly this).

use nexacore_types::display_channel::{DisplayInputEvent, keycode};

/// Where a unified input event originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSource {
    /// PS/2 keyboard (i8042 keyboard port).
    Ps2Keyboard,
    /// PS/2 mouse (i8042 aux port).
    Ps2Mouse,
    /// USB-HID device.
    Usb,
    /// ACPI fixed/general-purpose event (power button, lid, video keys).
    Acpi,
}

/// A system-level input event (not a keystroke or pointer move) raised by ACPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    /// The power button was pressed (request orderly shutdown → ACPI S5).
    PowerButton,
    /// The lid was opened.
    LidOpened,
    /// The lid was closed.
    LidClosed,
    /// Display brightness up.
    BrightnessUp,
    /// Display brightness down.
    BrightnessDown,
}

/// The payload of a unified input event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPayload {
    /// A keyboard key transition. `code` uses the
    /// `nexacore_types::display_channel::keycode` space; `pressed` is `true`
    /// on make, `false` on break.
    Key {
        /// Logical key code (ASCII for printables, the `keycode` private range
        /// for navigation/control keys).
        code: u8,
        /// `true` on press (make), `false` on release (break).
        pressed: bool,
    },
    /// A pointer update in absolute screen coordinates.
    Pointer {
        /// Absolute X in pixels.
        x: u32,
        /// Absolute Y in pixels.
        y: u32,
        /// Button mask: bit 0 = left, bit 1 = right, bit 2 = middle.
        buttons: u8,
    },
    /// A system-level (ACPI) event.
    System(SystemEvent),
}

/// One event on the unified input bus: a source tag plus a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnifiedInputEvent {
    /// The source that produced this event.
    pub source: InputSource,
    /// The event payload.
    pub payload: InputPayload,
}

impl UnifiedInputEvent {
    /// A keyboard event.
    #[must_use]
    pub const fn key(source: InputSource, code: u8, pressed: bool) -> Self {
        Self {
            source,
            payload: InputPayload::Key { code, pressed },
        }
    }

    /// A pointer event.
    #[must_use]
    pub const fn pointer(source: InputSource, x: u32, y: u32, buttons: u8) -> Self {
        Self {
            source,
            payload: InputPayload::Pointer { x, y, buttons },
        }
    }

    /// A system (ACPI) event.
    #[must_use]
    pub const fn system(event: SystemEvent) -> Self {
        Self {
            source: InputSource::Acpi,
            payload: InputPayload::System(event),
        }
    }

    /// Project to a [`DisplayInputEvent`] for the keys/pointer subset, or
    /// `None` for a system event (which routes to power-management instead).
    ///
    /// Key *release* events (`pressed == false`) still map — the display
    /// channel carries the `pressed` flag — so the compositor sees both edges.
    #[must_use]
    pub fn to_display(self) -> Option<DisplayInputEvent> {
        match self.payload {
            InputPayload::Key { code, pressed } => Some(DisplayInputEvent::Key { code, pressed }),
            InputPayload::Pointer { x, y, buttons } => {
                Some(DisplayInputEvent::Pointer { x, y, buttons })
            }
            InputPayload::System(_) => None,
        }
    }
}

/// Where a unified event is dispatched after normalization (WS2-08.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputRoute {
    /// Forward to the compositor over the display-input channel.
    Display(DisplayInputEvent),
    /// Hand to the power-management subsystem (e.g. power button → ACPI S5).
    Power(SystemEvent),
}

/// Route a unified event to its destination.
#[must_use]
pub fn route(event: UnifiedInputEvent) -> InputRoute {
    match event.payload {
        InputPayload::System(sys) => InputRoute::Power(sys),
        InputPayload::Key { code, pressed } => {
            InputRoute::Display(DisplayInputEvent::Key { code, pressed })
        }
        InputPayload::Pointer { x, y, buttons } => {
            InputRoute::Display(DisplayInputEvent::Pointer { x, y, buttons })
        }
    }
}

// =============================================================================
// PS/2 scancode normalization (Set 1) — WS2-08.2
// =============================================================================

/// The PS/2 extended-prefix scancode (`0xE0`).
pub const PS2_EXTENDED_PREFIX: u8 = 0xE0;

/// Outcome of decoding a single PS/2 Set-1 scancode byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2Decode {
    /// The byte was the `0xE0` prefix; the *next* byte should be decoded with
    /// `extended = true`.
    ExtendedPrefix,
    /// A decoded keyboard event.
    Event(UnifiedInputEvent),
    /// A recognized-but-unmapped byte (no event emitted).
    Ignored,
}

/// Map a Set-1 base scancode (bit 7 cleared) to its unshifted ASCII byte, for
/// the standard US QWERTY alphanumeric rows. Returns `None` for non-printable
/// or unmapped codes.
const fn set1_ascii(base: u8) -> Option<u8> {
    let c = match base {
        0x02 => b'1',
        0x03 => b'2',
        0x04 => b'3',
        0x05 => b'4',
        0x06 => b'5',
        0x07 => b'6',
        0x08 => b'7',
        0x09 => b'8',
        0x0A => b'9',
        0x0B => b'0',
        0x10 => b'q',
        0x11 => b'w',
        0x12 => b'e',
        0x13 => b'r',
        0x14 => b't',
        0x15 => b'y',
        0x16 => b'u',
        0x17 => b'i',
        0x18 => b'o',
        0x19 => b'p',
        0x1E => b'a',
        0x1F => b's',
        0x20 => b'd',
        0x21 => b'f',
        0x22 => b'g',
        0x23 => b'h',
        0x24 => b'j',
        0x25 => b'k',
        0x26 => b'l',
        0x2C => b'z',
        0x2D => b'x',
        0x2E => b'c',
        0x2F => b'v',
        0x30 => b'b',
        0x31 => b'n',
        0x32 => b'm',
        0x39 => b' ',
        _ => return None,
    };
    Some(c)
}

/// Normalize one PS/2 Set-1 scancode byte into a [`Ps2Decode`].
///
/// `extended` is the caller's running state — `true` iff the previous byte was
/// [`PS2_EXTENDED_PREFIX`]. The caller flips its state to `true` on
/// [`Ps2Decode::ExtendedPrefix`] and back to `false` after the following byte.
///
/// Make codes (bit 7 clear) yield `pressed = true`; break codes (bit 7 set)
/// yield `pressed = false` for the same key — so key-up is no longer dropped.
#[must_use]
pub fn normalize_ps2_scancode(scancode: u8, extended: bool) -> Ps2Decode {
    if scancode == PS2_EXTENDED_PREFIX {
        return Ps2Decode::ExtendedPrefix;
    }
    let pressed = scancode & 0x80 == 0;
    let base = scancode & 0x7F;

    let code = if extended {
        // Extended codes are the dedicated arrow cluster.
        match base {
            0x48 => keycode::ARROW_UP,
            0x50 => keycode::ARROW_DOWN,
            0x4B => keycode::ARROW_LEFT,
            0x4D => keycode::ARROW_RIGHT,
            _ => return Ps2Decode::Ignored,
        }
    } else {
        match base {
            0x01 => keycode::ESCAPE,
            0x1C => keycode::ENTER,
            0x0E => keycode::BACKSPACE,
            0x0F => keycode::TAB,
            other => match set1_ascii(other) {
                Some(ascii) => ascii,
                None => return Ps2Decode::Ignored,
            },
        }
    };

    Ps2Decode::Event(UnifiedInputEvent::key(
        InputSource::Ps2Keyboard,
        code,
        pressed,
    ))
}

// =============================================================================
// ACPI event normalization — WS2-08.3/.4/.5
// =============================================================================

/// An ACPI device class that raises input-relevant notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiDevice {
    /// Control-method power button (`PNP0C0C`).
    PowerButton,
    /// Lid switch (`PNP0C0D`).
    Lid,
    /// ACPI video / display adapter (brightness hotkeys).
    Video,
}

/// ACPI `Notify` value for a status change on the power-button / lid devices.
pub const ACPI_NOTIFY_STATUS_CHANGE: u8 = 0x80;
/// ACPI video-extension `Notify` for "increase brightness".
pub const ACPI_NOTIFY_BRIGHTNESS_UP: u8 = 0x86;
/// ACPI video-extension `Notify` for "decrease brightness".
pub const ACPI_NOTIFY_BRIGHTNESS_DOWN: u8 = 0x87;

/// Normalize an ACPI `Notify(device, code)` into a [`SystemEvent`].
///
/// For the lid device the `Notify(0x80)` only signals "status changed"; the
/// handler must read `_LID` and pass the resulting open/closed state as
/// `lid_open` (ignored for the other devices). Returns `None` for an
/// unrecognized `(device, code)` pair.
#[must_use]
pub fn normalize_acpi_notify(device: AcpiDevice, code: u8, lid_open: bool) -> Option<SystemEvent> {
    match device {
        AcpiDevice::PowerButton if code == ACPI_NOTIFY_STATUS_CHANGE => {
            Some(SystemEvent::PowerButton)
        }
        AcpiDevice::Lid if code == ACPI_NOTIFY_STATUS_CHANGE => Some(if lid_open {
            SystemEvent::LidOpened
        } else {
            SystemEvent::LidClosed
        }),
        AcpiDevice::Video if code == ACPI_NOTIFY_BRIGHTNESS_UP => Some(SystemEvent::BrightnessUp),
        AcpiDevice::Video if code == ACPI_NOTIFY_BRIGHTNESS_DOWN => {
            Some(SystemEvent::BrightnessDown)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps2_make_code_decodes_to_press() {
        // 0x1E = 'a' make.
        assert_eq!(
            normalize_ps2_scancode(0x1E, false),
            Ps2Decode::Event(UnifiedInputEvent::key(InputSource::Ps2Keyboard, b'a', true))
        );
    }

    #[test]
    fn ps2_break_code_decodes_to_release() {
        // 0x9E = 0x1E | 0x80 = 'a' break → release (key-up no longer dropped).
        assert_eq!(
            normalize_ps2_scancode(0x9E, false),
            Ps2Decode::Event(UnifiedInputEvent::key(
                InputSource::Ps2Keyboard,
                b'a',
                false
            ))
        );
    }

    #[test]
    fn ps2_control_keys_use_keycode_space() {
        for (sc, code) in [
            (0x01, keycode::ESCAPE),
            (0x1C, keycode::ENTER),
            (0x0E, keycode::BACKSPACE),
            (0x0F, keycode::TAB),
            (0x39, b' '),
        ] {
            assert_eq!(
                normalize_ps2_scancode(sc, false),
                Ps2Decode::Event(UnifiedInputEvent::key(InputSource::Ps2Keyboard, code, true))
            );
        }
    }

    #[test]
    fn ps2_extended_prefix_then_arrow() {
        assert_eq!(
            normalize_ps2_scancode(PS2_EXTENDED_PREFIX, false),
            Ps2Decode::ExtendedPrefix
        );
        // After the prefix, 0x48 is Arrow Up (not numpad-8).
        assert_eq!(
            normalize_ps2_scancode(0x48, true),
            Ps2Decode::Event(UnifiedInputEvent::key(
                InputSource::Ps2Keyboard,
                keycode::ARROW_UP,
                true
            ))
        );
        // Without the prefix, 0x48 is unmapped (numpad, not handled here).
        assert_eq!(normalize_ps2_scancode(0x48, false), Ps2Decode::Ignored);
    }

    #[test]
    fn ps2_unmapped_scancode_is_ignored() {
        assert_eq!(normalize_ps2_scancode(0x7E, false), Ps2Decode::Ignored);
    }

    #[test]
    fn acpi_power_button_normalizes() {
        assert_eq!(
            normalize_acpi_notify(AcpiDevice::PowerButton, ACPI_NOTIFY_STATUS_CHANGE, false),
            Some(SystemEvent::PowerButton)
        );
    }

    #[test]
    fn acpi_lid_uses_read_state() {
        assert_eq!(
            normalize_acpi_notify(AcpiDevice::Lid, ACPI_NOTIFY_STATUS_CHANGE, true),
            Some(SystemEvent::LidOpened)
        );
        assert_eq!(
            normalize_acpi_notify(AcpiDevice::Lid, ACPI_NOTIFY_STATUS_CHANGE, false),
            Some(SystemEvent::LidClosed)
        );
    }

    #[test]
    fn acpi_brightness_keys_normalize() {
        assert_eq!(
            normalize_acpi_notify(AcpiDevice::Video, ACPI_NOTIFY_BRIGHTNESS_UP, false),
            Some(SystemEvent::BrightnessUp)
        );
        assert_eq!(
            normalize_acpi_notify(AcpiDevice::Video, ACPI_NOTIFY_BRIGHTNESS_DOWN, false),
            Some(SystemEvent::BrightnessDown)
        );
    }

    #[test]
    fn acpi_unknown_pair_is_none() {
        assert_eq!(
            normalize_acpi_notify(AcpiDevice::PowerButton, 0x01, false),
            None
        );
        assert_eq!(normalize_acpi_notify(AcpiDevice::Video, 0x99, false), None);
    }

    #[test]
    fn keys_route_to_display_system_routes_to_power() {
        let key = UnifiedInputEvent::key(InputSource::Ps2Keyboard, b'a', true);
        assert_eq!(
            route(key),
            InputRoute::Display(DisplayInputEvent::Key {
                code: b'a',
                pressed: true
            })
        );
        let ptr = UnifiedInputEvent::pointer(InputSource::Ps2Mouse, 10, 20, 0b1);
        assert_eq!(
            route(ptr),
            InputRoute::Display(DisplayInputEvent::Pointer {
                x: 10,
                y: 20,
                buttons: 0b1
            })
        );
        let pw = UnifiedInputEvent::system(SystemEvent::PowerButton);
        assert_eq!(route(pw), InputRoute::Power(SystemEvent::PowerButton));
    }

    #[test]
    fn system_event_has_no_display_projection() {
        let pw = UnifiedInputEvent::system(SystemEvent::LidClosed);
        assert_eq!(pw.to_display(), None);
    }
}
