//! VGA text-mode writer — 80 × 25, colour attribute byte, CP437 charset.
//!
//! Physical address `0xB8000` is the start of the VGA text buffer.
//! `bootloader` v0.9 (BIOS path) identity-maps the first GiB of
//! physical memory, so the virtual address equals the physical address.
//! All writes use `write_volatile` to prevent the compiler from
//! eliding or reordering stores to this memory-mapped I/O region.

#![allow(unsafe_code)]

const COLS: usize = 80;
const ROWS: usize = 25;

/// VGA 4-bit colour: black.
pub const BLACK: u8 = 0x0;
/// VGA 4-bit colour: dark cyan.
pub const CYAN: u8 = 0x3;
/// VGA 4-bit colour: bright cyan.
pub const LIGHT_CYAN: u8 = 0xB;
/// VGA 4-bit colour: bright white.
pub const WHITE: u8 = 0xF;
/// VGA 4-bit colour: bright yellow.
pub const YELLOW: u8 = 0xE;

#[inline]
const fn attr(fg: u8, bg: u8) -> u8 {
    (bg << 4) | fg
}

// Return a pointer to the character byte of cell (row, col).
#[inline]
fn cell_ptr(row: usize, col: usize) -> *mut u8 {
    let offset = (row * COLS + col) * 2;
    // SAFETY: caller ensures row < ROWS, col < COLS.
    (0xB8000_usize + offset) as *mut u8
}

/// Fill every cell with a space in the given colours.
pub fn clear(fg: u8, bg: u8) {
    let a = attr(fg, bg);
    for r in 0..ROWS {
        for c in 0..COLS {
            let p = cell_ptr(r, c);
            // SAFETY: p is within the 80×25 VGA buffer.
            unsafe {
                core::ptr::write_volatile(p, b' ');
                core::ptr::write_volatile(p.add(1), a);
            }
        }
    }
}

/// Write `bytes` starting at `(row, col)` with the given colours.
/// Silently stops at the right edge of the screen.
pub fn write_at(row: usize, col: usize, bytes: &[u8], fg: u8, bg: u8) {
    let a = attr(fg, bg);
    for (i, &b) in bytes.iter().enumerate() {
        let c = col + i;
        if c >= COLS || row >= ROWS {
            break;
        }
        let p = cell_ptr(row, c);
        // SAFETY: bounds checked above.
        unsafe {
            core::ptr::write_volatile(p, b);
            core::ptr::write_volatile(p.add(1), a);
        }
    }
}

/// Write `n` as decimal digits starting at `(row, col)`.
pub fn write_usize_at(row: usize, col: usize, mut n: usize, fg: u8, bg: u8) {
    if n == 0 {
        write_at(row, col, b"0", fg, bg);
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        #[allow(
            clippy::cast_possible_truncation,
            clippy::indexing_slicing,
            reason = "n % 10 is 0..=9; i is bounded by buf.len()"
        )]
        {
            buf[i] = b'0' + (n % 10) as u8;
        }
        n /= 10;
    }
    #[allow(clippy::indexing_slicing, reason = "i is bounded by buf.len() above")]
    write_at(row, col, &buf[i..], fg, bg);
}
