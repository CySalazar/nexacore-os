//! Brand palette constants as packed `u32` ARGB values (`0xAARRGGBB`).
//!
//! These are the short, widget-facing names for the most-used brand hues. They
//! are **re-exported from the single canonical source of truth**,
//! [`nexacore_display::tokens`] (WS7-19.1) — the compositor and the design-token
//! module (`crate::tokens::color`) resolve to the same definitions, so the
//! brand ramp is defined exactly once for the whole graphics stack.
//!
//! ## Usage
//!
//! ```
//! use nexacore_ui::color::PETROL;
//! // Opaque petrol — 0xFF prefix means fully opaque.
//! assert_eq!(PETROL >> 24, 0xFF);
//! assert_eq!(PETROL & 0x00FF_FFFF, 0x0F4C5C);
//! ```
//!
//! ## ARGB encoding
//!
//! ```text
//! Bits 31–24: alpha (0xFF = fully opaque, 0x00 = fully transparent)
//! Bits 23–16: red
//! Bits 15–8:  green
//! Bits  7–0:  blue
//! ```

// Canonical five-hue system + the two petrol shades the default theme uses,
// re-exported (aliased to their short names) from the source of truth.
pub use nexacore_display::tokens::{
    BRICK_500 as BRICK, CHARCOAL_800 as CHARCOAL, CREAM_300 as CREAM, PETROL_300,
    PETROL_500 as PETROL, PETROL_700, SAGE_500 as SAGE,
};

/// Muted grey `#6B6B6B` — the AI status bar's "unknown" indicator.
///
/// Role: status indicator when the AI backend state has not yet been
/// established (ADR-0043, TASK-21, DE-C6). Deliberately outside the brand
/// palette — neutral enough to convey neither success nor failure — so it
/// stays local rather than in the brand token source.
pub const MUTED: u32 = 0xFF6B_6B6B;
