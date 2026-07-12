//! # `nexacore-ui`
//!
//! Brand-themed GUI toolkit for NexaCore OS (ADR-0042, TASK-20, DE-C4/DE-C5).
//!
//! ## Purpose
//!
//! This crate provides the **host-testable core** of the NexaCore desktop GUI:
//!
//! * **[`color`]** — brand palette constants as `u32` ARGB values.
//! * **[`canvas`]** — [`canvas::Canvas`]: a borrowed, bounds-checked ARGB
//!   pixel buffer with fill, rect, glyph, and border primitives.
//! * **[`text`]** — UTF-8-aware text measurement ([`text::measure_text`]) and
//!   rendering ([`text::draw_text`]) via `font8x8` 8×8 monospace glyphs.
//! * **[`theme`]** — [`theme::Theme`]: brand palette + spacing parameters;
//!   [`theme::Theme::nexacore`] is the canonical NexaCore OS look-and-feel.
//! * **[`layout`]** — [`layout::Size`] and [`layout::Direction`] used by the
//!   widget tree.
//! * **[`widget`]** — [`widget::Widget`]: a retained widget tree
//!   (`Label`, `Button`, `TextInput`, `List`, `Container`) with
//!   `measure → layout → render → dispatch_click` pipeline.
//!
//! ## Architecture reference
//!
//! See [`ADR-0042`](../../../docs/adr/0042-nexacore-ui-toolkit-text.md) for the
//! full design rationale (decoupled `Canvas`, UTF-8 measurement at codepoint
//! granularity, retained widget tree, brand theme, `TrueType` follow-up).
//!
//! ## `no_std` + `alloc`
//!
//! This crate compiles for both the developer host (`x86_64-unknown-linux-gnu`)
//! and the bare-metal Ring-3 target (`x86_64-unknown-none`).  It uses
//! `alloc::{string::String, vec::Vec}` but no `std` API.
//!
//! ## Quick start
//!
//! ```
//! use nexacore_ui::{
//!     canvas::Canvas,
//!     color::{CHARCOAL, CREAM},
//!     text::draw_text,
//!     theme::Theme,
//! };
//!
//! // Allocate a 320×240 pixel buffer.
//! let mut pixels = vec![0u32; 320 * 240];
//! let mut canvas = Canvas::new(&mut pixels, 320, 240).expect("valid dimensions");
//!
//! // Clear to the brand canvas colour.
//! canvas.fill(CREAM);
//!
//! // Draw a greeting.
//! draw_text(&mut canvas, 8, 8, "NexaCore OS", CHARCOAL, 2);
//! ```
//!
//! ## Bootable demo image
//!
//! The `crates/nexacore-ui-demo-image` (workspace-excluded, ADR-0042 D6) drives
//! this crate from a Ring-3 bare-metal context: it maps the framebuffer via
//! `nexacore-usys::display`, creates an `nexacore-display` surface, renders an
//! `nexacore-ui` widget tree into a [`canvas::Canvas`], and commits the result.
//! That image crate is the TASK-20 VM-103 verification artifact; it is NOT
//! part of this crate.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-ui")]
#![no_std]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
        clippy::float_arithmetic,
    )
)]

// `alloc` provides `String`, `Vec`, and `Box` without `std`.
extern crate alloc;

/// Accessibility layer (WS7-16).
///
/// A11y tree, focus/keyboard navigation, screen reader, high contrast, and
/// global text scaling.
pub mod a11y;
pub mod ai_actions;
pub mod canvas;
pub mod chat;
pub mod chrome;
pub mod clipboard;
pub mod color;
pub mod cursor;
pub mod display_settings;
pub mod dnd;
pub mod dock;
pub mod edit;
pub mod i18n;
pub mod icon;
pub mod launcher;
pub mod layout;
pub mod material;
pub mod notification;
pub mod scale;
pub mod session;
pub mod settings;
pub mod shortcuts;
pub mod status_bar;
pub mod text;
pub mod theme;
pub mod theming;
pub mod toast;
pub mod tokens;
pub mod tray;
pub mod widget;

#[cfg(test)]
mod tests;
