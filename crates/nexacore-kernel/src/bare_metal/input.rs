//! PS/2 keyboard and mouse input via i8042 controller (polling, no IDT).
//!
//! ## Keyboard
//!
//! Reads Scancode Set 1 as translated by the QEMU/VirtualBox i8042 emulation
//! (translation is enabled by default on both platforms). Make codes (bit 7
//! clear) are decoded into [`Key`] values; break codes (bit 7 set) are
//! discarded. Extended two-byte sequences (0xE0 prefix) are tracked with a
//! module-level atomic flag so dedicated arrow keys are handled correctly.
//!
//! ## Mouse
//!
//! The PS/2 aux port (mouse) is initialised by [`ps2_mouse_init`], which
//! enables the auxiliary device and sends the "enable streaming" command
//! (`0xF4`). Mouse data is then available via [`ps2_mouse_poll`], which
//! returns a [`MouseEvent`] when a complete 3-byte packet is assembled.
//!
//! Status register bit 5 (`AUXB`) distinguishes keyboard bytes (bit 5 = 0)
//! from mouse bytes (bit 5 = 1), so the two pollers never consume each
//! other's data. Call [`ps2_mouse_poll`] before [`ps2_poll`] each loop
//! iteration to drain mouse bytes promptly.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use super::arch;

const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;

/// Set when the previous scancode was the 0xE0 extended prefix.
static EXTENDED: AtomicBool = AtomicBool::new(false);

/// Index of the next byte to fill in the 3-byte mouse packet (0, 1, or 2).
static MOUSE_IDX: AtomicU8 = AtomicU8::new(0);
/// Accumulator for the current in-flight 3-byte PS/2 mouse packet.
static MOUSE_PKT: [AtomicU8; 3] = [AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0)];

/// A decoded keyboard event (key-down only; key-up events are discarded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// A printable ASCII character (byte value).
    Char(u8),
    /// Escape key (`0x01` make code).
    Escape,
    /// Enter / Return key (`0x1C` make code).
    Enter,
    /// Backspace key (`0x0E` make code).
    Backspace,
    /// Tab key (`0x0F` make code).
    Tab,
    /// Cursor-up (dedicated arrow key `0xE0 0x48`, or numpad-8 `0x48`).
    ArrowUp,
    /// Cursor-down (dedicated arrow key `0xE0 0x50`, or numpad-2 `0x50`).
    ArrowDown,
    /// Cursor-left (dedicated arrow key `0xE0 0x4B`, or numpad-4 `0x4B`).
    ArrowLeft,
    /// Cursor-right (dedicated arrow key `0xE0 0x4D`, or numpad-6 `0x4D`).
    ArrowRight,
}

/// A decoded PS/2 mouse packet.
#[derive(Clone, Copy, Debug)]
pub struct MouseEvent {
    /// Signed horizontal delta (right = positive).
    pub dx: i32,
    /// Signed vertical delta (down = positive; PS/2 y-axis is inverted).
    pub dy: i32,
    /// Button mask: bit 0 = left button, bit 1 = right, bit 2 = middle.
    pub buttons: u8,
}

/// Poll the PS/2 keyboard port once.
///
/// Returns `Some(Key)` if a recognized make code is available in the i8042
/// output buffer; returns `None` if the buffer is empty, the byte is a break
/// code, the scancode is not in the lookup table, or the byte belongs to the
/// mouse (status bit 5 set).
///
/// Non-blocking: reads at most two I/O ports and returns immediately.
pub fn ps2_poll() -> Option<Key> {
    // SAFETY: ports 0x60/0x64 are the PS/2 data and status registers.
    let status = unsafe { arch::inb(PS2_STATUS) };
    // Bit 0: output buffer full. Bit 5 (AUXB): byte is from the aux (mouse) port.
    // Skip mouse bytes — ps2_mouse_poll() owns those.
    if status & 0x01 == 0 || status & 0x20 != 0 {
        return None;
    }
    let sc = unsafe { arch::inb(PS2_DATA) };
    decode(sc)
}

/// Initialise the PS/2 keyboard port.
///
/// Enables the first (keyboard) port at the i8042 (`0xAE`) and asks the
/// keyboard to enable scanning (`0xF4`), draining the ACK. A UEFI boot can
/// leave the port disabled (no legacy BIOS keyboard setup ran), which would
/// starve [`ps2_poll`]; calling this makes keyboard polling reliable regardless
/// of firmware state. Safe to call if no keyboard is connected.
pub fn ps2_keyboard_init() {
    // SAFETY: ports 0x60/0x64 are the PS/2 data/command registers.
    unsafe {
        wait_input_ready();
        arch::outb(PS2_STATUS, 0xAE); // enable first (keyboard) port
        wait_input_ready();
        arch::outb(PS2_DATA, 0xF4); // keyboard: enable scanning
        // Drain the ACK (0xFA) the keyboard sends back.
        for _ in 0..65_536u32 {
            if arch::inb(PS2_STATUS) & 0x01 != 0 {
                let _ = arch::inb(PS2_DATA);
                break;
            }
        }
    }
}

/// Initialise the PS/2 auxiliary (mouse) port.
///
/// Sends the enable-auxiliary-device command (`0xA8`), routes the
/// "enable streaming" command (`0xF4`) to the mouse via the controller, and
/// drains the ACK byte. Safe to call if no mouse is connected.
pub fn ps2_mouse_init() {
    // SAFETY: ports 0x60/0x64 are the PS/2 data/command registers.
    unsafe {
        wait_input_ready();
        arch::outb(PS2_STATUS, 0xA8); // enable auxiliary device
        wait_input_ready();
        arch::outb(PS2_STATUS, 0xD4); // route next byte to mouse
        wait_input_ready();
        arch::outb(PS2_DATA, 0xF4); // enable streaming
        // Drain the ACK (0xFA) the mouse sends back.
        for _ in 0..65_536u32 {
            if arch::inb(PS2_STATUS) & 0x01 != 0 {
                let _ = arch::inb(PS2_DATA);
                break;
            }
        }
    }
}

/// Poll the PS/2 mouse port once.
///
/// Assembles 3-byte packets from bytes marked as aux-device bytes (status
/// bit 5 = 1). Returns a [`MouseEvent`] when a complete, valid packet is
/// ready; returns `None` otherwise.
///
/// Call this **before** [`ps2_poll`] each loop iteration so that mouse bytes
/// are drained before the keyboard poller runs.
pub fn ps2_mouse_poll() -> Option<MouseEvent> {
    loop {
        // SAFETY: ports 0x60/0x64 are the PS/2 data and status registers.
        let status = unsafe { arch::inb(PS2_STATUS) };
        // Require OBF (bit 0) and AUXB (bit 5) to both be set.
        if status & 0x21 != 0x21 {
            return None;
        }
        let byte = unsafe { arch::inb(PS2_DATA) };

        let idx = MOUSE_IDX.load(Ordering::Relaxed) as usize;
        #[allow(
            clippy::indexing_slicing,
            reason = "MOUSE_IDX always wraps mod 3 below; idx < MOUSE_PKT.len() = 3"
        )]
        MOUSE_PKT[idx].store(byte, Ordering::Relaxed);
        let next = (idx + 1) % 3;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "(idx + 1) % 3 ∈ {0,1,2} always fits u8"
        )]
        MOUSE_IDX.store(next as u8, Ordering::Relaxed);

        if next != 0 {
            // Packet not yet complete — keep draining.
            continue;
        }

        // Full 3-byte packet received.
        let flags = MOUSE_PKT[0].load(Ordering::Relaxed);
        // Bit 3 is the always-1 sync bit; if clear the packet is misaligned.
        if flags & 0x08 == 0 {
            return None;
        }
        let raw_x = MOUSE_PKT[1].load(Ordering::Relaxed);
        let raw_y = MOUSE_PKT[2].load(Ordering::Relaxed);
        let dx = ps2_signed(flags & 0x10 != 0, raw_x);
        // PS/2 y+ = up, screen y+ = down — negate dy.
        let dy = -ps2_signed(flags & 0x20 != 0, raw_y);
        return Some(MouseEvent {
            dx,
            dy,
            buttons: flags & 0x07,
        });
    }
}

fn wait_input_ready() {
    for _ in 0..65_536u32 {
        // SAFETY: port 0x64 is the PS/2 status register.
        if unsafe { arch::inb(PS2_STATUS) } & 0x02 == 0 {
            return;
        }
    }
}

fn ps2_signed(sign_bit: bool, raw: u8) -> i32 {
    if sign_bit {
        i32::from(raw) - 256
    } else {
        i32::from(raw)
    }
}

fn decode(sc: u8) -> Option<Key> {
    // 0xE0 = extended prefix; set flag and wait for the actual scancode.
    if sc == 0xE0 {
        EXTENDED.store(true, Ordering::Relaxed);
        return None;
    }

    let extended = EXTENDED.swap(false, Ordering::Relaxed);

    // Bit 7 set = break (key-up) code — discard.
    if sc & 0x80 != 0 {
        return None;
    }

    if extended {
        return match sc {
            0x48 => Some(Key::ArrowUp),
            0x50 => Some(Key::ArrowDown),
            0x4B => Some(Key::ArrowLeft),
            0x4D => Some(Key::ArrowRight),
            _ => None,
        };
    }

    match sc {
        0x01 => Some(Key::Escape),
        0x02 => Some(Key::Char(b'1')),
        0x03 => Some(Key::Char(b'2')),
        0x04 => Some(Key::Char(b'3')),
        0x05 => Some(Key::Char(b'4')),
        0x06 => Some(Key::Char(b'5')),
        0x07 => Some(Key::Char(b'6')),
        0x08 => Some(Key::Char(b'7')),
        0x09 => Some(Key::Char(b'8')),
        0x0A => Some(Key::Char(b'9')),
        0x0B => Some(Key::Char(b'0')),
        0x0C => Some(Key::Char(b'-')),
        0x0D => Some(Key::Char(b'=')),
        0x0E => Some(Key::Backspace),
        0x0F => Some(Key::Tab),
        0x10 => Some(Key::Char(b'q')),
        0x11 => Some(Key::Char(b'w')),
        0x12 => Some(Key::Char(b'e')),
        0x13 => Some(Key::Char(b'r')),
        0x14 => Some(Key::Char(b't')),
        0x15 => Some(Key::Char(b'y')),
        0x16 => Some(Key::Char(b'u')),
        0x17 => Some(Key::Char(b'i')),
        0x18 => Some(Key::Char(b'o')),
        0x19 => Some(Key::Char(b'p')),
        0x1A => Some(Key::Char(b'[')),
        0x1B => Some(Key::Char(b']')),
        0x1C => Some(Key::Enter),
        0x1E => Some(Key::Char(b'a')),
        0x1F => Some(Key::Char(b's')),
        0x20 => Some(Key::Char(b'd')),
        0x21 => Some(Key::Char(b'f')),
        0x22 => Some(Key::Char(b'g')),
        0x23 => Some(Key::Char(b'h')),
        0x24 => Some(Key::Char(b'j')),
        0x25 => Some(Key::Char(b'k')),
        0x26 => Some(Key::Char(b'l')),
        0x27 => Some(Key::Char(b';')),
        0x28 => Some(Key::Char(b'\'')),
        0x2C => Some(Key::Char(b'z')),
        0x2D => Some(Key::Char(b'x')),
        0x2E => Some(Key::Char(b'c')),
        0x2F => Some(Key::Char(b'v')),
        0x30 => Some(Key::Char(b'b')),
        0x31 => Some(Key::Char(b'n')),
        0x32 => Some(Key::Char(b'm')),
        0x33 => Some(Key::Char(b',')),
        0x34 => Some(Key::Char(b'.')),
        0x35 => Some(Key::Char(b'/')),
        0x39 => Some(Key::Char(b' ')),
        // Numpad arrows (no 0xE0 prefix, NumLock-independent on some firmware).
        0x48 => Some(Key::ArrowUp),
        0x50 => Some(Key::ArrowDown),
        0x4B => Some(Key::ArrowLeft),
        0x4D => Some(Key::ArrowRight),
        _ => None,
    }
}
