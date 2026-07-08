//! Architecture-specific kernel intrinsics.
//!
//! At v0.2 the kernel targets `x86_64-unknown-none`. The intrinsics
//! exposed here are the minimum surface required by the K3 panic
//! handler (interrupt disable + halt forever) and the early console
//! (port I/O for the 16550 UART on COM1).
//!
//! For non-x86 hosts (e.g., the maintainer's `aarch64-apple-darwin`
//! workstation), the private `non_x86_64` sibling module provides
//! no-op stubs so that `cargo build --workspace --all-features` and
//! the host integration tests at `tests/heap.rs` and
//! `tests/panic_record.rs` still compile. The stubs never execute in
//! the bare-metal binary because the binary is cross-built to
//! `x86_64-unknown-none` (and the `x86_64` private sibling is the
//! active variant there).

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;

#[cfg(not(target_arch = "x86_64"))]
mod non_x86_64;
#[cfg(not(target_arch = "x86_64"))]
pub use self::non_x86_64::*;
