//! USB HID boot-protocol driver logic.
//!
//! Implements DE-E3 (ADR-0049): HID Boot-Protocol keyboard and mouse report
//! parsing, consecutive-report key-event diffing, and HID Usage ID → display
//! keycode mapping.
//!
//! ## Boot protocol
//!
//! After `SET_PROTOCOL(boot)` and `SET_IDLE(0)` on EP0, the device sends
//! 8-byte keyboard reports (or 3-byte mouse reports) on the interrupt-IN
//! endpoint whenever the state changes.
//!
//! ### Keyboard report layout (USB HID Spec 1.11 § B.1 Table B-1)
//!
//! ```text
//! Byte 0: Modifier keys (see modifier bits below)
//! Byte 1: Reserved (always 0x00)
//! Bytes 2–7: Keycode slots (up to 6 simultaneous keys)
//! ```
//!
//! ### Mouse report layout (USB HID Spec 1.11 § B.2 Table B-2)
//!
//! ```text
//! Byte 0: Button mask (bit 0 = left, 1 = right, 2 = middle)
//! Byte 1: X displacement (signed i8)
//! Byte 2: Y displacement (signed i8)
//! ```
//!
//! ## Security posture
//!
//! All data comes from an untrusted USB device. Every parse function is
//! explicitly length-checked before any field access; malformed or too-short
//! reports yield typed errors, never panics or over-reads.  The `0x01`
//! rollover keycode is treated as a phantom state and rejected.
//!
//! ## References
//!
//! - USB HID Specification 1.11, Appendix B — Boot Interface Descriptors.
//! - USB HID Usage Tables 1.2, Section 10 — Keyboard/Keypad Page.
//! - `nexacore_types::display_channel::keycode` — target keycode space.

extern crate alloc;
use alloc::vec::Vec;

// =============================================================================
// Error type
// =============================================================================

/// Errors returned by HID report parsing functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HidError {
    /// The input slice is shorter than the minimum required for this report
    /// type.
    ///
    /// Keyboard reports require at least 8 bytes; mouse reports require at
    /// least 3 bytes.
    TooShort,
    /// All six keycode slots contain `0x01` (Keyboard Error Roll Over),
    /// indicating a phantom key state that must be ignored.
    RolloverPhantom,
    /// A HID report descriptor is malformed (a short item's data runs past the
    /// end, or an unsupported long item was encountered).
    MalformedDescriptor,
    /// The report descriptor declares no Generic Desktop `X`/`Y` usage pair —
    /// the device is not a pointer (WS7-06).
    NoPointerUsages,
    /// A report's id prefix byte does not match the pointer layout's report
    /// id; the report belongs to a different report type and should be
    /// skipped (WS7-06).
    ReportIdMismatch,
}

// =============================================================================
// Keyboard report
// =============================================================================

/// Minimum byte length of a USB HID boot-protocol keyboard report.
pub const KEYBOARD_REPORT_MIN_LEN: usize = 8;

/// A parsed USB HID boot-protocol keyboard report.
///
/// The report covers the modifier byte and the six simultaneous keycode slots
/// as defined in USB HID Specification 1.11 Appendix B.1 Table B-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidBootKeyboardReport {
    /// Modifier key bitmask.
    ///
    /// Bit assignments (USB HID Usage Tables 1.2 § 10):
    /// - Bit 0: Left Ctrl
    /// - Bit 1: Left Shift
    /// - Bit 2: Left Alt
    /// - Bit 3: Left GUI
    /// - Bit 4: Right Ctrl
    /// - Bit 5: Right Shift
    /// - Bit 6: Right Alt
    /// - Bit 7: Right GUI
    pub modifier: u8,
    /// Up to six simultaneous keycodes (HID Usage IDs, Keyboard/Keypad page).
    ///
    /// Unused slots are filled with `0x00`. A slot value of `0x01` in ALL six
    /// slots signals keyboard rollover (phantom state) and is rejected by
    /// [`parse_keyboard_report`].
    pub keycodes: [u8; 6],
}

/// Parse a USB HID boot-protocol keyboard report.
///
/// `data` must be at least [`KEYBOARD_REPORT_MIN_LEN`] (8) bytes.
/// Byte 0 is the modifier, byte 1 is reserved (ignored), bytes 2–7 are the
/// six keycode slots.
///
/// # Errors
///
/// - [`HidError::TooShort`] when `data.len() < 8`.
/// - [`HidError::RolloverPhantom`] when all six keycode bytes are `0x01`
///   (keyboard error roll-over phantom state).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::hid::parse_keyboard_report;
///
/// // Shift + 'a' (usage 0x04) pressed.
/// let report = [0x02u8, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
/// let r = parse_keyboard_report(&report).unwrap();
/// assert_eq!(r.modifier, 0x02); // Left Shift
/// assert_eq!(r.keycodes[0], 0x04);
/// ```
pub fn parse_keyboard_report(data: &[u8]) -> Result<HidBootKeyboardReport, HidError> {
    if data.len() < KEYBOARD_REPORT_MIN_LEN {
        return Err(HidError::TooShort);
    }
    // byte 0: modifier (guaranteed by len >= 8 check above).
    let modifier = *data.first().ok_or(HidError::TooShort)?;
    // byte 1: reserved — ignore.
    // bytes 2..=7: keycode slots.
    let mut keycodes = [0u8; 6];
    for (i, slot) in keycodes.iter_mut().enumerate() {
        *slot = *data.get(2 + i).ok_or(HidError::TooShort)?;
    }
    // Reject rollover phantom: all six slots == 0x01.
    if keycodes.iter().all(|&k| k == 0x01) {
        return Err(HidError::RolloverPhantom);
    }
    Ok(HidBootKeyboardReport { modifier, keycodes })
}

// =============================================================================
// Mouse report
// =============================================================================

/// Minimum byte length of a USB HID boot-protocol mouse report.
pub const MOUSE_REPORT_MIN_LEN: usize = 3;

/// A parsed USB HID boot-protocol mouse report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidBootMouseReport {
    /// Button mask: bit 0 = left, bit 1 = right, bit 2 = middle.
    pub buttons: u8,
    /// Signed X displacement since the last report.
    pub dx: i8,
    /// Signed Y displacement since the last report.
    pub dy: i8,
}

/// Parse a USB HID boot-protocol mouse report.
///
/// `data` must be at least [`MOUSE_REPORT_MIN_LEN`] (3) bytes.
/// Byte 0 is the button mask, byte 1 is the signed X delta, byte 2 is the
/// signed Y delta.
///
/// # Errors
///
/// - [`HidError::TooShort`] when `data.len() < 3`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::hid::parse_mouse_report;
///
/// // Left button pressed, dx=+5, dy=-3.
/// let report = [0x01u8, 5, (-3i8) as u8];
/// let r = parse_mouse_report(&report).unwrap();
/// assert_eq!(r.buttons, 0x01);
/// assert_eq!(r.dx, 5);
/// assert_eq!(r.dy, -3);
/// ```
pub fn parse_mouse_report(data: &[u8]) -> Result<HidBootMouseReport, HidError> {
    if data.len() < MOUSE_REPORT_MIN_LEN {
        return Err(HidError::TooShort);
    }
    let buttons = *data.first().ok_or(HidError::TooShort)?;
    // Interpret the displacement bytes as signed i8.
    // The USB HID spec defines these as two's-complement signed 8-bit values;
    // `i8::from_ne_bytes` is the idiomatic wrapping reinterpretation.
    let dx = i8::from_ne_bytes([*data.get(1).ok_or(HidError::TooShort)?]);
    let dy = i8::from_ne_bytes([*data.get(2).ok_or(HidError::TooShort)?]);
    Ok(HidBootMouseReport { buttons, dx, dy })
}

// =============================================================================
// Key event
// =============================================================================

/// A key-transition event produced by [`HidKeyboardState::update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// Display keycode.
    ///
    /// Printable keys carry their ASCII byte; non-printable keys use the
    /// constants defined in `nexacore_types::display_channel::keycode` (e.g.
    /// Escape = `0x1B`, Enter = `0x0D`, arrow keys = `0x80..=0x83`).
    pub code: u8,
    /// `true` on key press (make), `false` on key release (break).
    pub pressed: bool,
}

// =============================================================================
// Keyboard state tracker
// =============================================================================

/// Modifier key bit positions in the modifier byte.
///
/// Any non-zero modifier mask means at least one modifier is currently held.
const MOD_LEFT_SHIFT: u8 = 1 << 1;
const MOD_RIGHT_SHIFT: u8 = 1 << 5;

/// Modifier keycode constants used by [`HidKeyboardState`].
///
/// These are synthetic display codes assigned to modifier keys so the image
/// layer can forward them as `Key` events if needed. They live in the
/// `0x90..=0x97` range — above the `0x80..=0x83` arrow range.
const KEYCODE_LEFT_CTRL: u8 = 0x90;
const KEYCODE_LEFT_SHIFT: u8 = 0x91;
const KEYCODE_LEFT_ALT: u8 = 0x92;
const KEYCODE_LEFT_GUI: u8 = 0x93;
const KEYCODE_RIGHT_CTRL: u8 = 0x94;
const KEYCODE_RIGHT_SHIFT: u8 = 0x95;
const KEYCODE_RIGHT_ALT: u8 = 0x96;
const KEYCODE_RIGHT_GUI: u8 = 0x97;

/// Consecutive-report keyboard state tracker.
///
/// Holds the previous keyboard report and diffs it against the next one to
/// produce per-key press and release events.  This matches the approach used
/// by low-level HID drivers on all major operating systems.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::hid::{HidBootKeyboardReport, HidKeyboardState};
///
/// let mut state = HidKeyboardState::default();
/// // 'a' (usage 0x04) pressed.
/// let r1 = HidBootKeyboardReport {
///     modifier: 0,
///     keycodes: [0x04, 0, 0, 0, 0, 0],
/// };
/// let events = state.update(r1);
/// assert_eq!(events.len(), 1);
/// assert!(events[0].pressed);
/// // 'a' released.
/// let r2 = HidBootKeyboardReport {
///     modifier: 0,
///     keycodes: [0; 6],
/// };
/// let events2 = state.update(r2);
/// assert_eq!(events2.len(), 1);
/// assert!(!events2[0].pressed);
/// ```
#[derive(Debug, Default)]
pub struct HidKeyboardState {
    /// The most recent keyboard report (used as the baseline for the next
    /// diff).
    prev: Option<HidBootKeyboardReport>,
}

impl HidKeyboardState {
    /// Construct a new, empty state (no keys previously seen as pressed).
    #[must_use]
    pub fn new() -> Self {
        Self { prev: None }
    }

    /// Diff `report` against the previous report and return key-transition
    /// events.
    ///
    /// Emits `pressed = true` for keycodes that appear in `report` but not in
    /// the previous report.  Emits `pressed = false` for keycodes that were in
    /// the previous report but are absent from `report`.  Zero-valued keycode
    /// slots (`0x00`) are ignored (no key assigned).
    ///
    /// Modifier-byte changes are also diffed bit-by-bit: each modifier bit
    /// that transitions 0→1 produces a press event with a modifier keycode
    /// (`0x90..=0x97`); 1→0 produces a release event.
    ///
    /// The returned `Vec` is ordered: modifier events first (bit 0 through 7),
    /// then regular keycodes (slot 0 through 5), press/release events
    /// interleaved by order-of-detection.
    pub fn update(&mut self, report: HidBootKeyboardReport) -> Vec<KeyEvent> {
        let mut buf = [KeyEvent {
            code: 0,
            pressed: false,
        }; MAX_KEY_EVENTS_PER_REPORT];
        let n = self.update_into(report, &mut buf);
        buf.get(..n).unwrap_or(&[]).to_vec()
    }

    /// Allocation-free variant of [`HidKeyboardState::update`] for heap-less
    /// driver images (WS7-06): writes the key-transition events into `out`
    /// and returns how many were written.
    ///
    /// Events beyond `out.len()` are dropped; sizing `out` with
    /// [`MAX_KEY_EVENTS_PER_REPORT`] guarantees no event is ever lost.
    pub fn update_into(&mut self, report: HidBootKeyboardReport, out: &mut [KeyEvent]) -> usize {
        let mut n = 0usize;
        let push = |slot: Option<&mut KeyEvent>, ev: KeyEvent, n: &mut usize| {
            if let Some(s) = slot {
                *s = ev;
                *n += 1;
            }
        };
        let prev_modifier = self.prev.map_or(0u8, |p| p.modifier);
        let prev_keycodes = self.prev.map_or([0u8; 6], |p| p.keycodes);

        // Diff modifier bits.
        // Detect whether shift is held in the new report for usage→keycode mapping.
        let shift =
            (report.modifier & MOD_LEFT_SHIFT) != 0 || (report.modifier & MOD_RIGHT_SHIFT) != 0;

        let modifier_codes: [u8; 8] = [
            KEYCODE_LEFT_CTRL,
            KEYCODE_LEFT_SHIFT,
            KEYCODE_LEFT_ALT,
            KEYCODE_LEFT_GUI,
            KEYCODE_RIGHT_CTRL,
            KEYCODE_RIGHT_SHIFT,
            KEYCODE_RIGHT_ALT,
            KEYCODE_RIGHT_GUI,
        ];
        for (bit, &mod_code) in modifier_codes.iter().enumerate() {
            let was = (prev_modifier >> bit) & 1;
            let now = (report.modifier >> bit) & 1;
            if was == 0 && now == 1 {
                push(
                    out.get_mut(n),
                    KeyEvent {
                        code: mod_code,
                        pressed: true,
                    },
                    &mut n,
                );
            } else if was == 1 && now == 0 {
                push(
                    out.get_mut(n),
                    KeyEvent {
                        code: mod_code,
                        pressed: false,
                    },
                    &mut n,
                );
            }
        }

        // Key press: in new report but not in previous.
        for i in 0..6usize {
            let code = *report.keycodes.get(i).unwrap_or(&0);
            if code == 0 {
                continue;
            }
            let already_held = prev_keycodes.contains(&code);
            if !already_held {
                if let Some(display_code) = usage_to_keycode(code, shift) {
                    push(
                        out.get_mut(n),
                        KeyEvent {
                            code: display_code,
                            pressed: true,
                        },
                        &mut n,
                    );
                }
            }
        }

        // Key release: in previous report but not in new.
        for i in 0..6usize {
            let code = *prev_keycodes.get(i).unwrap_or(&0);
            if code == 0 {
                continue;
            }
            let still_held = report.keycodes.contains(&code);
            if !still_held {
                // Use shift=false for release events: the shift state at time
                // of release is used, but the keycode emitted should match the
                // press event.  For simplicity we re-derive with the NEW
                // report's shift state (release without shift).
                if let Some(display_code) = usage_to_keycode(code, false) {
                    push(
                        out.get_mut(n),
                        KeyEvent {
                            code: display_code,
                            pressed: false,
                        },
                        &mut n,
                    );
                }
            }
        }

        self.prev = Some(report);
        n
    }
}

/// Maximum number of key events a single boot-keyboard report diff can
/// produce: 8 modifier transitions + 6 presses + 6 releases (WS7-06).
pub const MAX_KEY_EVENTS_PER_REPORT: usize = 20;

// =============================================================================
// HID Usage ID → display keycode mapping
// =============================================================================

/// Map a HID Keyboard/Keypad page Usage ID to the display keycode.
///
/// Returns `Some(code)` for recognised keycodes; `None` for Usage IDs that
/// have no mapping in the current display keycode space (e.g. function keys,
/// media keys).
///
/// `shift` controls capitalisation for letter keys and the alternate symbols
/// on number/symbol keys.
///
/// The target display keycode space is defined by
/// `nexacore_types::display_channel::keycode`:
/// - Printable ASCII (`0x20..=0x7E`) for letters, digits, symbols.
/// - `0x1B` Escape, `0x0D` Enter, `0x08` Backspace, `0x09` Tab.
/// - `0x80` Arrow Up, `0x81` Arrow Down, `0x82` Arrow Left, `0x83` Arrow Right.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::hid::usage_to_keycode;
///
/// assert_eq!(usage_to_keycode(0x04, false), Some(b'a')); // 'a' unshifted
/// assert_eq!(usage_to_keycode(0x04, true), Some(b'A')); // 'A' shifted
/// assert_eq!(usage_to_keycode(0x28, false), Some(0x0D)); // Enter
/// assert_eq!(usage_to_keycode(0x29, false), Some(0x1B)); // Escape
/// assert_eq!(usage_to_keycode(0x4F, false), Some(0x83)); // Arrow Right
/// assert_eq!(usage_to_keycode(0x52, false), Some(0x80)); // Arrow Up
/// ```
// The keycode mapping table is inherently large. Splitting it into helper
// functions would create artificial indirection with no safety benefit; a
// single exhaustive match is the most readable and auditable form.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn usage_to_keycode(usage: u8, shift: bool) -> Option<u8> {
    match usage {
        // Letters a-z / A-Z: HID Usage 0x04 = 'a', 0x1D = 'z'.
        0x04..=0x1D => {
            let letter_idx = usage - 0x04;
            if shift {
                Some(b'A' + letter_idx)
            } else {
                Some(b'a' + letter_idx)
            }
        }
        // Digits: HID Usage 0x1E = '1' through 0x26 = '9', 0x27 = '0'.
        0x1E..=0x26 => {
            let digit = usage - 0x1D; // 0x1E-0x1D = 1 → '1'
            if shift {
                // Shifted number row symbols.
                Some(match digit {
                    1 => b'!',
                    2 => b'@',
                    3 => b'#',
                    4 => b'$',
                    5 => b'%',
                    6 => b'^',
                    7 => b'&',
                    8 => b'*',
                    9 => b'(',
                    _ => return None,
                })
            } else {
                Some(b'0' + digit)
            }
        }
        0x27 => {
            // '0' key (HID 0x27).
            if shift { Some(b')') } else { Some(b'0') }
        }
        // Enter.
        0x28 => Some(0x0D),
        // Escape.
        0x29 => Some(0x1B),
        // Backspace.
        0x2A => Some(0x08),
        // Tab.
        0x2B => Some(0x09),
        // Space.
        0x2C => Some(0x20),
        // Minus / Underscore.
        0x2D => {
            if shift {
                Some(b'_')
            } else {
                Some(b'-')
            }
        }
        // Equals / Plus.
        0x2E => {
            if shift {
                Some(b'+')
            } else {
                Some(b'=')
            }
        }
        // Left bracket / Left brace.
        0x2F => {
            if shift {
                Some(b'{')
            } else {
                Some(b'[')
            }
        }
        // Right bracket / Right brace.
        0x30 => {
            if shift {
                Some(b'}')
            } else {
                Some(b']')
            }
        }
        // Backslash / Pipe.
        0x31 => {
            if shift {
                Some(b'|')
            } else {
                Some(b'\\')
            }
        }
        // Semicolon / Colon.
        0x33 => {
            if shift {
                Some(b':')
            } else {
                Some(b';')
            }
        }
        // Quote / Double-quote.
        0x34 => {
            if shift {
                Some(b'"')
            } else {
                Some(b'\'')
            }
        }
        // Grave accent / Tilde.
        0x35 => {
            if shift {
                Some(b'~')
            } else {
                Some(b'`')
            }
        }
        // Comma / Less-than.
        0x36 => {
            if shift {
                Some(b'<')
            } else {
                Some(b',')
            }
        }
        // Period / Greater-than.
        0x37 => {
            if shift {
                Some(b'>')
            } else {
                Some(b'.')
            }
        }
        // Slash / Question mark.
        0x38 => {
            if shift {
                Some(b'?')
            } else {
                Some(b'/')
            }
        }
        // Arrow Right (HID 0x4F → display 0x83).
        0x4F => Some(0x83),
        // Arrow Left (HID 0x50 → display 0x82).
        0x50 => Some(0x82),
        // Arrow Down (HID 0x51 → display 0x81).
        0x51 => Some(0x81),
        // Arrow Up (HID 0x52 → display 0x80).
        0x52 => Some(0x80),
        // All other usages have no mapping in the current keycode space.
        _ => None,
    }
}

// =============================================================================
// Report-descriptor parser (WS2-05.1)
// =============================================================================

/// The `bType` of a HID short item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    /// Main item (Input/Output/Feature/Collection/End Collection).
    Main,
    /// Global item (usage page, report size/count, logical range, report id, …).
    Global,
    /// Local item (usage, usage minimum/maximum, …).
    Local,
}

/// A single decoded HID short item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidItem {
    /// The item type (`bType`).
    pub item_type: ItemType,
    /// The item tag (`bTag`).
    pub tag: u8,
    /// The item's data, zero-extended from its `bSize` bytes (little-endian).
    pub data: u32,
    /// The item's data size in bytes (0, 1, 2, or 4).
    pub size: u8,
}

impl HidItem {
    /// The data reinterpreted as a sign-extended integer for its byte width.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "reinterpret the width-masked item data as signed"
    )]
    pub fn data_signed(self) -> i32 {
        match self.size {
            1 => i32::from(self.data as u8 as i8),
            2 => i32::from(self.data as u16 as i16),
            4 => self.data as i32,
            _ => 0,
        }
    }
}

/// Which kind of main item produced a report field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Device-to-host data (`Input`).
    Input,
    /// Host-to-device data (`Output`).
    Output,
    /// Bidirectional configuration data (`Feature`).
    Feature,
}

/// `Constant` main-item flag (bit 0) — a padding/reserved field.
pub const FIELD_CONSTANT: u32 = 1 << 0;
/// `Variable` main-item flag (bit 1) — each field is its own value (vs an array).
pub const FIELD_VARIABLE: u32 = 1 << 1;
/// `Relative` main-item flag (bit 2) — deltas rather than absolute values.
pub const FIELD_RELATIVE: u32 = 1 << 2;

/// One report field described by a Main Input/Output/Feature item, with the
/// global/local item state in force when it was declared (WS2-05.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportField {
    /// The report id in force (0 if none was declared).
    pub report_id: u8,
    /// The usage page in force.
    pub usage_page: u16,
    /// The local usages accumulated for this field.
    pub usages: Vec<u32>,
    /// Bits per field.
    pub report_size: u32,
    /// Number of fields.
    pub report_count: u32,
    /// Logical minimum in force.
    pub logical_min: i32,
    /// Logical maximum in force.
    pub logical_max: i32,
    /// Input / Output / Feature.
    pub kind: FieldKind,
    /// The main item's flag bits (see [`FIELD_CONSTANT`] etc.).
    pub flags: u32,
}

/// Decode the HID short-item stream of a report descriptor (WS2-05.1).
///
/// Long items (prefix `0xFE`) are unsupported and rejected.
///
/// # Errors
/// [`HidError::MalformedDescriptor`] if an item's data runs past the end of the
/// descriptor or a long item is present.
pub fn parse_items(desc: &[u8]) -> Result<Vec<HidItem>, HidError> {
    let mut items = Vec::new();
    let mut i = 0usize;
    while let Some(res) = next_item(desc, &mut i) {
        items.push(res?);
    }
    Ok(items)
}

/// Decode the short item at `*cursor`, advancing the cursor (WS7-06).
///
/// The allocation-free core of [`parse_items`], shared with
/// [`extract_pointer_layout`] so heap-less driver images can stream the item
/// sequence directly. Returns `None` at the end of the descriptor;
/// `Some(Err(_))` on a malformed or long (`0xFE`) item.
fn next_item(desc: &[u8], cursor: &mut usize) -> Option<Result<HidItem, HidError>> {
    let prefix = *desc.get(*cursor)?;
    if prefix == 0xFE {
        // Long item: unsupported.
        return Some(Err(HidError::MalformedDescriptor));
    }
    let size_code = prefix & 0b11;
    let size = if size_code == 3 { 4 } else { size_code };
    let type_code = (prefix >> 2) & 0b11;
    let tag = prefix >> 4;
    let item_type = match type_code {
        0 => ItemType::Main,
        1 => ItemType::Global,
        2 => ItemType::Local,
        _ => return Some(Err(HidError::MalformedDescriptor)),
    };
    let data_start = *cursor + 1;
    let data_end = data_start + size as usize;
    let Some(bytes) = desc.get(data_start..data_end) else {
        return Some(Err(HidError::MalformedDescriptor));
    };
    let mut data = 0u32;
    for (shift, b) in bytes.iter().enumerate() {
        data |= u32::from(*b) << (8 * shift);
    }
    *cursor = data_end;
    Some(Ok(HidItem {
        item_type,
        tag,
        data,
        size,
    }))
}

/// Mutable global-item state carried across the descriptor walk.
#[derive(Default, Clone)]
struct GlobalState {
    usage_page: u16,
    logical_min: i32,
    logical_max: i32,
    report_size: u32,
    report_count: u32,
    report_id: u8,
}

/// Parse a HID report descriptor into its report fields (WS2-05.1).
///
/// Walks the short-item stream tracking global item state (usage page, report
/// size/count, logical range, report id) and local usages, emitting a
/// [`ReportField`] for each Main Input/Output/Feature item and clearing local
/// state afterward (per the HID spec).
///
/// # Errors
/// [`HidError::MalformedDescriptor`] if the item stream cannot be decoded.
#[allow(
    clippy::cast_possible_truncation,
    reason = "global items narrow their data to the field width (u16 page, u8 id)"
)]
pub fn parse_report_descriptor(desc: &[u8]) -> Result<Vec<ReportField>, HidError> {
    let items = parse_items(desc)?;
    let mut global = GlobalState::default();
    let mut usages: Vec<u32> = Vec::new();
    let mut fields = Vec::new();
    for item in items {
        match item.item_type {
            ItemType::Global => match item.tag {
                0x0 => global.usage_page = item.data as u16,
                0x1 => global.logical_min = item.data_signed(),
                0x2 => global.logical_max = item.data_signed(),
                0x7 => global.report_size = item.data,
                0x8 => global.report_id = item.data as u8,
                0x9 => global.report_count = item.data,
                _ => {}
            },
            ItemType::Local => {
                // Usage (0x0), Usage Minimum (0x1), Usage Maximum (0x2) all
                // contribute usage values; other local items are ignored here.
                if item.tag <= 0x2 {
                    usages.push(item.data);
                }
            }
            ItemType::Main => {
                let kind = match item.tag {
                    0x8 => Some(FieldKind::Input),
                    0x9 => Some(FieldKind::Output),
                    0xB => Some(FieldKind::Feature),
                    _ => None, // Collection / End Collection: no field
                };
                if let Some(kind) = kind {
                    fields.push(ReportField {
                        report_id: global.report_id,
                        usage_page: global.usage_page,
                        usages: usages.clone(),
                        report_size: global.report_size,
                        report_count: global.report_count,
                        logical_min: global.logical_min,
                        logical_max: global.logical_max,
                        kind,
                        flags: item.data,
                    });
                }
                // Local state resets after every main item.
                usages.clear();
            }
        }
    }
    Ok(fields)
}

// =============================================================================
// Generic pointer-report decoder (WS7-06 — absolute tablets / report protocol)
// =============================================================================

/// Usage Page `Generic Desktop` (HID Usage Tables § 4).
const USAGE_PAGE_GENERIC_DESKTOP: u16 = 0x01;
/// Usage Page `Button` (HID Usage Tables § 12).
const USAGE_PAGE_BUTTON: u16 = 0x09;
/// Generic Desktop usage `X` (HID Usage Tables § 4).
const USAGE_X: u32 = 0x30;
/// Generic Desktop usage `Y` (HID Usage Tables § 4).
const USAGE_Y: u32 = 0x31;

/// A pointer sample decoded from a HID *report-protocol* input report.
///
/// Produced by [`decode_pointer_report`] for devices whose report descriptor
/// declares Generic Desktop `X`/`Y` usages — e.g. the QEMU `usb-tablet`
/// (absolute coordinates in `0..=0x7FFF`) or a report-protocol mouse
/// (relative deltas). `relative` distinguishes the two: when `false`, `x`/`y`
/// are absolute within `[x_min, x_max]`/`[y_min, y_max]` and can be mapped to
/// the screen with [`scale_absolute_to_screen`]; when `true` they are deltas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerSample {
    /// Decoded X value (absolute position or relative delta).
    pub x: i32,
    /// Decoded Y value (absolute position or relative delta).
    pub y: i32,
    /// Logical minimum declared for the X field.
    pub x_min: i32,
    /// Logical maximum declared for the X field.
    pub x_max: i32,
    /// Logical minimum declared for the Y field.
    pub y_min: i32,
    /// Logical maximum declared for the Y field.
    pub y_max: i32,
    /// Button bitmask in declaration order: bit 0 = first declared button
    /// (left), bit 1 = second (right), bit 2 = third (middle) — the
    /// `DisplayInputEvent::Pointer` convention.
    pub buttons: u8,
    /// `true` when the X/Y main item carried the `Relative` flag (deltas),
    /// `false` for absolute devices such as tablets.
    pub relative: bool,
}

/// Extract `width` bits starting at absolute bit offset `bit_off` from a
/// little-endian HID report, LSB first. `None` if the field runs past `data`.
fn extract_bits(data: &[u8], bit_off: usize, width: u32) -> Option<u32> {
    let mut value: u32 = 0;
    for i in 0..width as usize {
        let bit = bit_off.checked_add(i)?;
        let byte = *data.get(bit >> 3)?;
        if (byte >> (bit & 7)) & 1 != 0 {
            value |= 1u32 << i;
        }
    }
    Some(value)
}

/// Sign-extend a `width`-bit raw field value to `i32`.
fn sign_extend(raw: u32, width: u32) -> i32 {
    if width == 0 || width >= 32 {
        #[allow(
            clippy::cast_possible_wrap,
            reason = "a full 32-bit field is reinterpreted as its two's-complement value"
        )]
        return raw as i32;
    }
    let sign_bit = 1u32 << (width - 1);
    #[allow(
        clippy::cast_possible_wrap,
        reason = "two's-complement reinterpretation after explicit sign extension"
    )]
    if raw & sign_bit != 0 {
        (raw | !(sign_bit | (sign_bit - 1))) as i32
    } else {
        raw as i32
    }
}

/// Compact, allocation-free pointer-report layout extracted straight from a
/// report descriptor (WS7-06).
///
/// The driver image is heap-less, so instead of materialising every
/// [`ReportField`] it extracts ONCE (at device-setup time) the bit positions
/// of the three things an input pump needs — buttons, X, Y — and then decodes
/// each interrupt-IN report against this fixed layout with
/// [`decode_pointer_report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerLayout {
    /// Report id of the X/Y fields (0 = the device declares no report ids,
    /// so reports carry no id prefix byte).
    pub report_id: u8,
    /// Absolute bit offset of the first button bit (including the id prefix
    /// byte when `report_id != 0`); `u32::MAX` when no buttons matched.
    pub buttons_bit: u32,
    /// Number of declared button bits captured (0..=8), in declaration
    /// order: bit 0 = left, 1 = right, 2 = middle.
    pub buttons_count: u8,
    /// Absolute bit offset of the X field.
    pub x_bit: u32,
    /// Bit width of the X field (1..=32).
    pub x_width: u8,
    /// Logical minimum declared for X.
    pub x_min: i32,
    /// Logical maximum declared for X.
    pub x_max: i32,
    /// Absolute bit offset of the Y field.
    pub y_bit: u32,
    /// Bit width of the Y field (1..=32).
    pub y_width: u8,
    /// Logical minimum declared for Y.
    pub y_min: i32,
    /// Logical maximum declared for Y.
    pub y_max: i32,
    /// `true` when the X/Y main item carried the `Relative` flag.
    pub relative: bool,
}

/// Maximum local usages tracked per main item during layout extraction.
///
/// X/Y appear among the first usages of their main item on every real
/// pointer device; usages beyond this window are treated like a repeated
/// last usage (HID 1.11 § 6.2.2.8) and cannot introduce new X/Y matches.
const LAYOUT_MAX_USAGES: usize = 8;

/// Extract the pointer layout from a raw HID report descriptor without
/// allocating (WS7-06).
///
/// Streams the short-item sequence tracking global/local item state and a
/// running bit offset per report id (the offset starts at 8 when report ids
/// are in use, accounting for the id prefix byte). Captures the FIRST
/// matching Button run and Generic Desktop `X`/`Y` usages; `Output`/
/// `Feature` items live in separate report spaces and do not advance the
/// input bit offset.
///
/// # Errors
///
/// - [`HidError::MalformedDescriptor`] if the item stream cannot be decoded
///   or a matched field's width is 0 or exceeds 32 bits.
/// - [`HidError::NoPointerUsages`] if no `X`/`Y` pair is declared (the
///   device is not a pointer).
#[allow(
    clippy::cast_possible_truncation,
    reason = "global items narrow their data to the field width (u16 page, u8 id)"
)]
#[allow(
    clippy::too_many_lines,
    reason = "one linear pass over the item stream; splitting the state \
              machine into helpers would obscure the offset bookkeeping"
)]
pub fn extract_pointer_layout(desc: &[u8]) -> Result<PointerLayout, HidError> {
    #[derive(Clone, Copy)]
    struct Axis {
        bit: u32,
        width: u32,
        min: i32,
        max: i32,
        relative: bool,
        id: u8,
    }

    let mut global = GlobalState::default();
    let mut usages = [0u32; LAYOUT_MAX_USAGES];
    let mut usage_len: usize = 0;
    let mut uses_ids = false;
    let mut bit_off: u32 = 0;
    let mut buttons: Option<(u32, u8, u8)> = None; // (bit, count, id)
    let mut x: Option<Axis> = None;
    let mut y: Option<Axis> = None;

    // Stream the item sequence WITHOUT parse_items: the driver image is
    // heap-less (`PanicOnAlloc`), so no `Vec` may be built here.
    let mut cursor = 0usize;
    while let Some(res) = next_item(desc, &mut cursor) {
        let item = res?;
        match item.item_type {
            ItemType::Global => match item.tag {
                0x0 => global.usage_page = item.data as u16,
                0x1 => global.logical_min = item.data_signed(),
                0x2 => global.logical_max = item.data_signed(),
                0x7 => global.report_size = item.data,
                0x8 => {
                    global.report_id = item.data as u8;
                    uses_ids = true;
                    // Each report id opens its own bit space, prefixed by
                    // the id byte (HID 1.11 § 8.1).
                    bit_off = 8;
                }
                0x9 => global.report_count = item.data,
                _ => {}
            },
            ItemType::Local => {
                if item.tag <= 0x2 {
                    if let Some(slot) = usages.get_mut(usage_len) {
                        *slot = item.data;
                        usage_len += 1;
                    }
                }
            }
            ItemType::Main => {
                // Only Input items (tag 0x8) consume input-report bits.
                if item.tag == 0x8 {
                    let width = global.report_size;
                    let count = global.report_count;
                    let is_constant = item.data & FIELD_CONSTANT != 0;
                    if !is_constant {
                        if width == 0 || width > 32 {
                            return Err(HidError::MalformedDescriptor);
                        }
                        match global.usage_page {
                            USAGE_PAGE_BUTTON => {
                                if buttons.is_none() {
                                    #[allow(
                                        clippy::cast_possible_truncation,
                                        reason = "button count is capped at 8"
                                    )]
                                    let captured = count.min(8) as u8;
                                    buttons = Some((bit_off, captured, global.report_id));
                                }
                            }
                            USAGE_PAGE_GENERIC_DESKTOP => {
                                for slot in 0..count {
                                    // A shorter usage list repeats its last
                                    // usage (HID 1.11 § 6.2.2.8).
                                    let idx = (slot as usize).min(usage_len.saturating_sub(1));
                                    let usage = usages.get(idx).copied().unwrap_or(0);
                                    let usage = if usage_len == 0 { 0 } else { usage };
                                    let axis = Axis {
                                        bit: bit_off.saturating_add(slot.saturating_mul(width)),
                                        width,
                                        min: global.logical_min,
                                        max: global.logical_max,
                                        relative: item.data & FIELD_RELATIVE != 0,
                                        id: global.report_id,
                                    };
                                    if usage == USAGE_X && x.is_none() {
                                        x = Some(axis);
                                    } else if usage == USAGE_Y && y.is_none() {
                                        y = Some(axis);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    bit_off = bit_off.saturating_add(width.saturating_mul(count));
                }
                // Local state resets after every main item (per the HID spec).
                usage_len = 0;
            }
        }
    }

    let (Some(x), Some(y)) = (x, y) else {
        return Err(HidError::NoPointerUsages);
    };
    if x.id != y.id {
        return Err(HidError::NoPointerUsages);
    }
    let (buttons_bit, buttons_count) = match buttons {
        Some((bit, count, id)) if id == x.id => (bit, count),
        _ => (u32::MAX, 0),
    };
    #[allow(
        clippy::cast_possible_truncation,
        reason = "widths are validated to 1..=32 above"
    )]
    Ok(PointerLayout {
        report_id: if uses_ids { x.id } else { 0 },
        buttons_bit,
        buttons_count,
        x_bit: x.bit,
        x_width: x.width as u8,
        x_min: x.min,
        x_max: x.max,
        y_bit: y.bit,
        y_width: y.width as u8,
        y_min: y.min,
        y_max: y.max,
        relative: x.relative,
    })
}

/// Decode one interrupt-IN report against a [`PointerLayout`] (WS7-06).
///
/// Allocation-free: extracts the button bits and the X/Y values (sign-
/// extended when the logical minimum is negative) at the layout's fixed bit
/// positions.
///
/// # Errors
///
/// - [`HidError::TooShort`] if a field runs past the end of `data`.
/// - [`HidError::ReportIdMismatch`] if the layout expects a report id prefix
///   and `data[0]` carries a different id (the report belongs to another
///   report type and must simply be skipped).
pub fn decode_pointer_report(
    layout: &PointerLayout,
    data: &[u8],
) -> Result<PointerSample, HidError> {
    if layout.report_id != 0 {
        let id = *data.first().ok_or(HidError::TooShort)?;
        if id != layout.report_id {
            return Err(HidError::ReportIdMismatch);
        }
    }

    let mut buttons: u8 = 0;
    if layout.buttons_bit != u32::MAX {
        for k in 0..u32::from(layout.buttons_count) {
            let bit = layout.buttons_bit.saturating_add(k) as usize;
            let raw = extract_bits(data, bit, 1).ok_or(HidError::TooShort)?;
            if raw != 0 {
                buttons |= 1 << k;
            }
        }
    }

    let decode_axis = |bit: u32, width: u8, min: i32| -> Result<i32, HidError> {
        let raw = extract_bits(data, bit as usize, u32::from(width)).ok_or(HidError::TooShort)?;
        if min < 0 {
            Ok(sign_extend(raw, u32::from(width)))
        } else {
            #[allow(
                clippy::cast_possible_wrap,
                reason = "unsigned pointer ranges fit i32 in practice (16-bit \
                          tablets); the logical range guards scaling"
            )]
            Ok(raw as i32)
        }
    };

    Ok(PointerSample {
        x: decode_axis(layout.x_bit, layout.x_width, layout.x_min)?,
        y: decode_axis(layout.y_bit, layout.y_width, layout.y_min)?,
        x_min: layout.x_min,
        x_max: layout.x_max,
        y_min: layout.y_min,
        y_max: layout.y_max,
        buttons,
        relative: layout.relative,
    })
}

/// Map an absolute HID value in `[logical_min, logical_max]` to a screen
/// coordinate in `[0, screen_extent - 1]` (WS7-06).
///
/// Out-of-range values clamp to the nearest edge; a degenerate logical range
/// or a zero-sized screen yields 0. All arithmetic is `i64` so extreme
/// logical ranges cannot overflow.
#[must_use]
pub fn scale_absolute_to_screen(
    value: i32,
    logical_min: i32,
    logical_max: i32,
    screen_extent: u32,
) -> u32 {
    if screen_extent == 0 {
        return 0;
    }
    let span = i64::from(logical_max) - i64::from(logical_min);
    if span <= 0 {
        return 0;
    }
    let offset = (i64::from(value) - i64::from(logical_min)).clamp(0, span);
    #[allow(
        clippy::integer_division,
        reason = "intentional integer scaling: the sub-pixel remainder is \
                  meaningless for a screen coordinate"
    )]
    let scaled = offset * (i64::from(screen_extent) - 1) / span;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "scaled is clamped to [0, screen_extent-1], which fits u32"
    )]
    {
        scaled as u32
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::indexing_slicing,
    clippy::needless_collect,
    clippy::manual_is_ascii_check
)]
mod tests {
    use super::*;

    // -- parse_keyboard_report -----------------------------------------------

    #[test]
    fn keyboard_report_happy_path() {
        let data = [0x02u8, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let r = parse_keyboard_report(&data).unwrap();
        assert_eq!(r.modifier, 0x02); // Left Shift
        assert_eq!(r.keycodes[0], 0x04);
        assert_eq!(r.keycodes[1], 0x00);
    }

    #[test]
    fn keyboard_report_no_keys() {
        let data = [0x00u8; 8];
        let r = parse_keyboard_report(&data).unwrap();
        assert_eq!(r.modifier, 0x00);
        assert_eq!(r.keycodes, [0u8; 6]);
    }

    #[test]
    fn keyboard_report_too_short_rejects() {
        assert_eq!(parse_keyboard_report(&[0u8; 7]), Err(HidError::TooShort));
        assert_eq!(parse_keyboard_report(&[]), Err(HidError::TooShort));
    }

    #[test]
    fn keyboard_report_rollover_phantom_rejects() {
        // All six keycode slots = 0x01 = rollover error phantom.
        let data = [0x00u8, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01];
        assert_eq!(parse_keyboard_report(&data), Err(HidError::RolloverPhantom));
    }

    #[test]
    fn keyboard_report_partial_rollover_not_rejected() {
        // Only five slots are 0x01 — NOT all six, so not a phantom.
        let data = [0x00u8, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x04];
        let r = parse_keyboard_report(&data).unwrap();
        assert_eq!(r.keycodes[5], 0x04);
    }

    #[test]
    fn keyboard_report_exact_length_ok() {
        // Exactly 8 bytes must succeed.
        let data = [0x00u8; 8];
        assert!(parse_keyboard_report(&data).is_ok());
    }

    #[test]
    fn keyboard_report_longer_than_8_ok() {
        // Reports longer than 8 bytes are valid (extra bytes ignored).
        let data = [0x00u8; 12];
        assert!(parse_keyboard_report(&data).is_ok());
    }

    // -- parse_mouse_report -------------------------------------------------

    #[test]
    fn mouse_report_happy_path() {
        let data = [0x01u8, 5, (-3i8) as u8];
        let r = parse_mouse_report(&data).unwrap();
        assert_eq!(r.buttons, 0x01);
        assert_eq!(r.dx, 5);
        assert_eq!(r.dy, -3);
    }

    #[test]
    fn mouse_report_too_short_rejects() {
        assert_eq!(parse_mouse_report(&[0u8; 2]), Err(HidError::TooShort));
        assert_eq!(parse_mouse_report(&[]), Err(HidError::TooShort));
    }

    #[test]
    fn mouse_report_exact_length_ok() {
        assert!(parse_mouse_report(&[0u8; 3]).is_ok());
    }

    #[test]
    fn mouse_report_negative_deltas() {
        let data = [0x00u8, (-10i8) as u8, (-20i8) as u8];
        let r = parse_mouse_report(&data).unwrap();
        assert_eq!(r.dx, -10);
        assert_eq!(r.dy, -20);
    }

    // -- HidKeyboardState key-down/up diffing --------------------------------

    fn make_report(modifier: u8, keycodes: [u8; 6]) -> HidBootKeyboardReport {
        HidBootKeyboardReport { modifier, keycodes }
    }

    #[test]
    fn key_press_single() {
        let mut state = HidKeyboardState::new();
        let r = make_report(0, [0x04, 0, 0, 0, 0, 0]); // 'a' pressed
        let events = state.update(r);
        // One key-down event for 'a'.
        let downs: Vec<_> = events.iter().filter(|e| e.pressed).collect();
        assert_eq!(downs.len(), 1);
        assert_eq!(downs[0].code, b'a');
    }

    #[test]
    fn key_release_single() {
        let mut state = HidKeyboardState::new();
        let r1 = make_report(0, [0x04, 0, 0, 0, 0, 0]); // 'a' down
        state.update(r1);
        let r2 = make_report(0, [0; 6]); // 'a' released
        let events = state.update(r2);
        let ups: Vec<_> = events.iter().filter(|e| !e.pressed).collect();
        assert_eq!(ups.len(), 1);
        assert_eq!(ups[0].code, b'a');
    }

    #[test]
    fn key_held_produces_no_repeat_event() {
        let mut state = HidKeyboardState::new();
        let r = make_report(0, [0x04, 0, 0, 0, 0, 0]);
        state.update(r);
        let events = state.update(r); // same report again
        // No new events for a held key.
        assert!(events.is_empty(), "held key must not repeat");
    }

    #[test]
    fn multi_key_press_and_release() {
        let mut state = HidKeyboardState::new();
        // Press 'a' (0x04) and 'b' (0x05) simultaneously.
        let r1 = make_report(0, [0x04, 0x05, 0, 0, 0, 0]);
        let ev1 = state.update(r1);
        let downs: Vec<u8> = ev1.iter().filter(|e| e.pressed).map(|e| e.code).collect();
        assert!(downs.contains(&b'a'), "a should be down");
        assert!(downs.contains(&b'b'), "b should be down");

        // Release 'a', keep 'b'.
        let r2 = make_report(0, [0x05, 0, 0, 0, 0, 0]);
        let ev2 = state.update(r2);
        let ups: Vec<u8> = ev2.iter().filter(|e| !e.pressed).map(|e| e.code).collect();
        assert!(ups.contains(&b'a'), "a should be released");
        let new_downs: Vec<u8> = ev2.iter().filter(|e| e.pressed).map(|e| e.code).collect();
        assert!(!new_downs.contains(&b'b'), "b still held, no new down");
    }

    #[test]
    fn modifier_key_events_emitted() {
        let mut state = HidKeyboardState::new();
        // Press Left Shift (bit 1 of modifier byte).
        let r1 = make_report(0x02, [0; 6]);
        let ev1 = state.update(r1);
        let shift_down = ev1
            .iter()
            .any(|e| e.code == KEYCODE_LEFT_SHIFT && e.pressed);
        assert!(shift_down, "Left Shift press event expected");

        // Release Left Shift.
        let r2 = make_report(0x00, [0; 6]);
        let ev2 = state.update(r2);
        let shift_up = ev2
            .iter()
            .any(|e| e.code == KEYCODE_LEFT_SHIFT && !e.pressed);
        assert!(shift_up, "Left Shift release event expected");
    }

    #[test]
    fn shift_affects_keycode_mapping() {
        let mut state = HidKeyboardState::new();
        // Press 'a' with Left Shift held.
        let r = make_report(0x02, [0x04, 0, 0, 0, 0, 0]);
        let events = state.update(r);
        let key_events: Vec<_> = events
            .iter()
            .filter(|e| e.pressed && (e.code == b'A' || e.code == b'a'))
            .collect();
        assert_eq!(key_events.len(), 1, "one key event for 'a'/'A'");
        assert_eq!(key_events[0].code, b'A', "should be uppercase with Shift");
    }

    // -- usage_to_keycode ---------------------------------------------------

    #[test]
    fn letter_unshifted() {
        assert_eq!(usage_to_keycode(0x04, false), Some(b'a'));
        assert_eq!(usage_to_keycode(0x1D, false), Some(b'z'));
    }

    #[test]
    fn letter_shifted() {
        assert_eq!(usage_to_keycode(0x04, true), Some(b'A'));
        assert_eq!(usage_to_keycode(0x1D, true), Some(b'Z'));
    }

    #[test]
    fn digits_unshifted() {
        // HID 0x1E = '1', 0x27 = '0'.
        assert_eq!(usage_to_keycode(0x1E, false), Some(b'1'));
        assert_eq!(usage_to_keycode(0x27, false), Some(b'0'));
        assert_eq!(usage_to_keycode(0x26, false), Some(b'9'));
    }

    #[test]
    fn digits_shifted_symbols() {
        assert_eq!(usage_to_keycode(0x1E, true), Some(b'!'));
        assert_eq!(usage_to_keycode(0x1F, true), Some(b'@'));
        assert_eq!(usage_to_keycode(0x27, true), Some(b')'));
    }

    #[test]
    fn control_keys() {
        assert_eq!(usage_to_keycode(0x28, false), Some(0x0D)); // Enter
        assert_eq!(usage_to_keycode(0x29, false), Some(0x1B)); // Escape
        assert_eq!(usage_to_keycode(0x2A, false), Some(0x08)); // Backspace
        assert_eq!(usage_to_keycode(0x2B, false), Some(0x09)); // Tab
        assert_eq!(usage_to_keycode(0x2C, false), Some(0x20)); // Space
    }

    #[test]
    fn arrow_keys() {
        // HID 0x4F = Right → display 0x83.
        assert_eq!(usage_to_keycode(0x4F, false), Some(0x83));
        // HID 0x50 = Left → display 0x82.
        assert_eq!(usage_to_keycode(0x50, false), Some(0x82));
        // HID 0x51 = Down → display 0x81.
        assert_eq!(usage_to_keycode(0x51, false), Some(0x81));
        // HID 0x52 = Up → display 0x80.
        assert_eq!(usage_to_keycode(0x52, false), Some(0x80));
    }

    #[test]
    fn symbol_keys() {
        assert_eq!(usage_to_keycode(0x2D, false), Some(b'-'));
        assert_eq!(usage_to_keycode(0x2D, true), Some(b'_'));
        assert_eq!(usage_to_keycode(0x2E, false), Some(b'='));
        assert_eq!(usage_to_keycode(0x2E, true), Some(b'+'));
        assert_eq!(usage_to_keycode(0x36, false), Some(b','));
        assert_eq!(usage_to_keycode(0x36, true), Some(b'<'));
        assert_eq!(usage_to_keycode(0x37, false), Some(b'.'));
        assert_eq!(usage_to_keycode(0x37, true), Some(b'>'));
        assert_eq!(usage_to_keycode(0x38, false), Some(b'/'));
        assert_eq!(usage_to_keycode(0x38, true), Some(b'?'));
    }

    #[test]
    fn unknown_usage_returns_none() {
        // Function keys (0x3A = F1), media keys, etc. have no mapping.
        assert_eq!(usage_to_keycode(0x00, false), None);
        assert_eq!(usage_to_keycode(0x3A, false), None); // F1
        assert_eq!(usage_to_keycode(0xFF, false), None);
    }

    #[test]
    fn all_letter_usages_produce_ascii_range() {
        for usage in 0x04u8..=0x1Du8 {
            let lower = usage_to_keycode(usage, false).unwrap();
            let upper = usage_to_keycode(usage, true).unwrap();
            assert!(
                (b'a'..=b'z').contains(&lower),
                "usage {usage:#x} lower={lower:#x}"
            );
            assert!(
                (b'A'..=b'Z').contains(&upper),
                "usage {usage:#x} upper={upper:#x}"
            );
        }
    }

    // --- Report-descriptor parser (WS2-05.1) --------------------------------

    /// The canonical USB HID boot-keyboard report descriptor (HID 1.11 App. B.1).
    const BOOT_KEYBOARD_DESC: &[u8] = &[
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x06, // Usage (Keyboard)
        0xA1, 0x01, // Collection (Application)
        0x05, 0x07, //   Usage Page (Key Codes)
        0x19, 0xE0, //   Usage Minimum (224)
        0x29, 0xE7, //   Usage Maximum (231)
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x01, //   Logical Maximum (1)
        0x75, 0x01, //   Report Size (1)
        0x95, 0x08, //   Report Count (8)
        0x81, 0x02, //   Input (Data, Variable, Absolute) — modifiers
        0x95, 0x01, //   Report Count (1)
        0x75, 0x08, //   Report Size (8)
        0x81, 0x01, //   Input (Constant) — reserved byte
        0x95, 0x06, //   Report Count (6)
        0x75, 0x08, //   Report Size (8)
        0x15, 0x00, //   Logical Minimum (0)
        0x25, 0x65, //   Logical Maximum (101)
        0x05, 0x07, //   Usage Page (Key Codes)
        0x19, 0x00, //   Usage Minimum (0)
        0x29, 0x65, //   Usage Maximum (101)
        0x81, 0x00, //   Input (Data, Array) — keycodes
        0xC0, // End Collection
    ];

    #[test]
    fn parse_items_decodes_a_short_item() {
        let items = parse_items(&[0x05, 0x01]).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item_type, ItemType::Global);
        assert_eq!(items[0].tag, 0x0); // Usage Page
        assert_eq!(items[0].data, 1);
        assert_eq!(items[0].size, 1);
    }

    #[test]
    fn malformed_items_are_rejected() {
        // Declares a 2-byte payload but only one byte follows.
        assert_eq!(
            parse_items(&[0x06, 0x01]),
            Err(HidError::MalformedDescriptor)
        );
        // Long items are unsupported.
        assert_eq!(
            parse_items(&[0xFE, 0x00]),
            Err(HidError::MalformedDescriptor)
        );
    }

    #[test]
    fn boot_keyboard_descriptor_yields_three_input_fields() {
        let fields = parse_report_descriptor(BOOT_KEYBOARD_DESC).unwrap();
        assert_eq!(fields.len(), 3);

        // Field 0: the modifier bitmap — 8 × 1-bit variable inputs.
        let modifiers = &fields[0];
        assert_eq!(modifiers.kind, FieldKind::Input);
        assert_eq!(modifiers.usage_page, 0x07);
        assert_eq!(modifiers.report_size, 1);
        assert_eq!(modifiers.report_count, 8);
        assert_eq!(modifiers.logical_max, 1);
        assert_ne!(modifiers.flags & FIELD_VARIABLE, 0);
        assert_eq!(modifiers.usages, alloc::vec![0xE0, 0xE7]); // usage min/max

        // Field 1: the reserved constant byte.
        let reserved = &fields[1];
        assert_eq!(reserved.report_size, 8);
        assert_eq!(reserved.report_count, 1);
        assert_ne!(reserved.flags & FIELD_CONSTANT, 0);
        assert!(reserved.usages.is_empty()); // local state was cleared

        // Field 2: the six keycode slots — an array (not variable).
        let keys = &fields[2];
        assert_eq!(keys.report_count, 6);
        assert_eq!(keys.report_size, 8);
        assert_eq!(keys.logical_max, 101);
        assert_eq!(keys.flags & FIELD_VARIABLE, 0); // array
        assert_eq!(keys.usages, alloc::vec![0x00, 0x65]);
    }

    #[test]
    fn logical_minimum_sign_extends() {
        // Logical Minimum (-127) encoded as a single 0x81 byte.
        let desc = &[
            0x75, 0x08, // Report Size (8)
            0x95, 0x01, // Report Count (1)
            0x15, 0x81, // Logical Minimum (-127)
            0x25, 0x7F, // Logical Maximum (127)
            0x81, 0x06, // Input (Data, Variable, Relative)
        ];
        let fields = parse_report_descriptor(desc).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].logical_min, -127);
        assert_eq!(fields[0].logical_max, 127);
        assert_ne!(fields[0].flags & FIELD_RELATIVE, 0);
    }

    // --- Pointer-report decoder (WS7-06) -------------------------------------

    /// An absolute-tablet report descriptor with the QEMU `usb-tablet` layout:
    /// 3 button bits + 5 pad bits, then 16-bit absolute X and Y in
    /// `0..=0x7FFF`, then an 8-bit relative wheel. Report: 6 bytes.
    const ABS_TABLET_DESC: &[u8] = &[
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x02, // Usage (Mouse)
        0xA1, 0x01, // Collection (Application)
        0x09, 0x01, //   Usage (Pointer)
        0xA1, 0x00, //   Collection (Physical)
        0x05, 0x09, //     Usage Page (Button)
        0x19, 0x01, //     Usage Minimum (1)
        0x29, 0x03, //     Usage Maximum (3)
        0x15, 0x00, //     Logical Minimum (0)
        0x25, 0x01, //     Logical Maximum (1)
        0x95, 0x03, //     Report Count (3)
        0x75, 0x01, //     Report Size (1)
        0x81, 0x02, //     Input (Data, Variable, Absolute) — buttons
        0x95, 0x01, //     Report Count (1)
        0x75, 0x05, //     Report Size (5)
        0x81, 0x01, //     Input (Constant) — padding
        0x05, 0x01, //     Usage Page (Generic Desktop)
        0x09, 0x30, //     Usage (X)
        0x09, 0x31, //     Usage (Y)
        0x15, 0x00, //     Logical Minimum (0)
        0x26, 0xFF, 0x7F, //     Logical Maximum (0x7FFF)
        0x75, 0x10, //     Report Size (16)
        0x95, 0x02, //     Report Count (2)
        0x81, 0x02, //     Input (Data, Variable, Absolute) — X, Y
        0x09, 0x38, //     Usage (Wheel)
        0x15, 0x81, //     Logical Minimum (-127)
        0x25, 0x7F, //     Logical Maximum (127)
        0x75, 0x08, //     Report Size (8)
        0x95, 0x01, //     Report Count (1)
        0x81, 0x06, //     Input (Data, Variable, Relative) — wheel
        0xC0, //   End Collection
        0xC0, // End Collection
    ];

    #[test]
    fn tablet_layout_captures_buttons_and_absolute_xy() {
        let l = extract_pointer_layout(ABS_TABLET_DESC).unwrap();
        assert_eq!(l.report_id, 0);
        assert_eq!(l.buttons_bit, 0);
        assert_eq!(l.buttons_count, 3);
        assert_eq!(l.x_bit, 8); // 3 button bits + 5 pad bits
        assert_eq!(l.x_width, 16);
        assert_eq!((l.x_min, l.x_max), (0, 0x7FFF));
        assert_eq!(l.y_bit, 24);
        assert_eq!(l.y_width, 16);
        assert_eq!((l.y_min, l.y_max), (0, 0x7FFF));
        assert!(!l.relative);
    }

    #[test]
    fn tablet_report_decodes_absolute_xy_and_buttons() {
        let l = extract_pointer_layout(ABS_TABLET_DESC).unwrap();
        // buttons=left+middle (0b101), X=0x4000, Y=0x1234, wheel=0.
        let report = [0b0000_0101u8, 0x00, 0x40, 0x34, 0x12, 0x00];
        let s = decode_pointer_report(&l, &report).unwrap();
        assert_eq!(s.x, 0x4000);
        assert_eq!(s.y, 0x1234);
        assert_eq!(s.x_min, 0);
        assert_eq!(s.x_max, 0x7FFF);
        assert_eq!(s.y_min, 0);
        assert_eq!(s.y_max, 0x7FFF);
        assert_eq!(s.buttons, 0b101); // left + middle
        assert!(!s.relative);
    }

    #[test]
    fn tablet_report_extremes_cover_the_full_logical_range() {
        let l = extract_pointer_layout(ABS_TABLET_DESC).unwrap();
        let min = decode_pointer_report(&l, &[0, 0x00, 0x00, 0x00, 0x00, 0]).unwrap();
        assert_eq!((min.x, min.y), (0, 0));
        let max = decode_pointer_report(&l, &[0, 0xFF, 0x7F, 0xFF, 0x7F, 0]).unwrap();
        assert_eq!((max.x, max.y), (0x7FFF, 0x7FFF));
    }

    #[test]
    fn tablet_report_too_short_rejects() {
        let l = extract_pointer_layout(ABS_TABLET_DESC).unwrap();
        assert_eq!(
            decode_pointer_report(&l, &[0u8, 0x00, 0x40]),
            Err(HidError::TooShort)
        );
    }

    #[test]
    fn relative_mouse_report_sign_extends_deltas() {
        // A report-protocol mouse: 3 buttons + 5 pad, X/Y 8-bit relative.
        let desc = &[
            0x05, 0x09, // Usage Page (Button)
            0x19, 0x01, 0x29, 0x03, // Usage Min/Max (1..3)
            0x15, 0x00, 0x25, 0x01, // Logical 0..1
            0x95, 0x03, 0x75, 0x01, // Count 3, Size 1
            0x81, 0x02, // Input (Data, Variable)
            0x95, 0x01, 0x75, 0x05, // Count 1, Size 5
            0x81, 0x01, // Input (Constant) — pad
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x30, 0x09, 0x31, // Usage X, Y
            0x15, 0x81, 0x25, 0x7F, // Logical -127..127
            0x75, 0x08, 0x95, 0x02, // Size 8, Count 2
            0x81, 0x06, // Input (Data, Variable, Relative)
        ];
        let l = extract_pointer_layout(desc).unwrap();
        assert!(l.relative);
        // dx = -2 (0xFE), dy = +5, right button held.
        let s = decode_pointer_report(&l, &[0b010, 0xFE, 0x05]).unwrap();
        assert_eq!(s.x, -2);
        assert_eq!(s.y, 5);
        assert_eq!(s.buttons, 0b010);
        assert!(s.relative);
    }

    #[test]
    fn report_id_prefix_selects_the_matching_fields() {
        // Two reports: id 1 = one 8-bit GD X/Y pair; id 2 = something else.
        let desc = &[
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x85, 0x01, // Report ID (1)
            0x09, 0x30, 0x09, 0x31, // Usage X, Y
            0x15, 0x00, 0x25, 0x7F, // Logical 0..127
            0x75, 0x08, 0x95, 0x02, // Size 8, Count 2
            0x81, 0x02, // Input
            0x85, 0x02, // Report ID (2)
            0x09, 0x38, // Usage (Wheel)
            0x75, 0x08, 0x95, 0x01, // Size 8, Count 1
            0x81, 0x06, // Input (Relative)
        ];
        let l = extract_pointer_layout(desc).unwrap();
        assert_eq!(l.report_id, 1);
        assert_eq!(l.x_bit, 8); // after the id prefix byte
        // Report for id 1: [id, x, y].
        let s = decode_pointer_report(&l, &[0x01, 60, 70]).unwrap();
        assert_eq!((s.x, s.y), (60, 70));
        // A report for id 2 must be skipped, not decoded.
        assert_eq!(
            decode_pointer_report(&l, &[0x02, 5]),
            Err(HidError::ReportIdMismatch)
        );
    }

    #[test]
    fn layout_extraction_rejects_non_pointer_descriptors() {
        // The boot keyboard descriptor has no X/Y usages.
        assert_eq!(
            extract_pointer_layout(BOOT_KEYBOARD_DESC),
            Err(HidError::NoPointerUsages)
        );
    }

    #[test]
    fn layout_extraction_rejects_oversized_field_widths() {
        // A GD X/Y input field with a 33-bit width is malformed.
        let desc = &[
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x30, 0x09, 0x31, // Usage X, Y
            0x15, 0x00, 0x25, 0x7F, // Logical 0..127
            0x75, 0x21, // Report Size (33)
            0x95, 0x02, // Report Count (2)
            0x81, 0x02, // Input
        ];
        assert_eq!(
            extract_pointer_layout(desc),
            Err(HidError::MalformedDescriptor)
        );
    }

    // --- scale_absolute_to_screen (WS7-06) ------------------------------------

    #[test]
    fn scaling_maps_logical_range_onto_screen_extent() {
        // 0..0x7FFF onto a 1280-pixel-wide screen.
        assert_eq!(scale_absolute_to_screen(0, 0, 0x7FFF, 1280), 0);
        assert_eq!(scale_absolute_to_screen(0x7FFF, 0, 0x7FFF, 1280), 1279);
        // Midpoint lands mid-screen (integer division).
        let mid = scale_absolute_to_screen(0x4000, 0, 0x7FFF, 1280);
        assert!((639..=640).contains(&mid), "mid = {mid}");
    }

    #[test]
    fn scaling_clamps_out_of_range_values() {
        assert_eq!(scale_absolute_to_screen(-50, 0, 100, 800), 0);
        assert_eq!(scale_absolute_to_screen(500, 0, 100, 800), 799);
    }

    #[test]
    fn scaling_degenerate_inputs_yield_zero() {
        assert_eq!(scale_absolute_to_screen(10, 0, 100, 0), 0); // no screen
        assert_eq!(scale_absolute_to_screen(10, 100, 100, 800), 0); // empty range
        assert_eq!(scale_absolute_to_screen(10, 200, 100, 800), 0); // inverted
    }

    #[test]
    fn sign_extend_handles_edge_widths() {
        assert_eq!(sign_extend(0xFE, 8), -2);
        assert_eq!(sign_extend(0x7F, 8), 127);
        assert_eq!(sign_extend(0b1, 1), -1);
        assert_eq!(sign_extend(0xFFFF_FFFF, 32), -1);
    }
}
