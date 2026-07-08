//! # `nexacore-desktop-shell`
//!
//! Desktop shell layer for NexaCore OS: the design-mockup window chrome,
//! shell design tokens (dark/light), and a compositor-agnostic window-state
//! machine. Sits between `nexacore-ui` (toolkit) and the apps image.
//!
//! Reference mockup: `brand/design/NexaCore-OS.dc.html`.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-desktop-shell")]
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

extern crate alloc;

pub mod dock;
pub mod frame;
pub mod launcher;
pub mod menubar;
pub mod router;
pub mod stroke;
pub mod tokens;
pub mod wm;
