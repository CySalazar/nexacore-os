//! Pre-`kmain` console facade.
//!
//! Forwards into [`nexacore_kernel::bare_metal::early_console`] which
//! talks to the 16550 UART at COM1. Kept as a separate module here
//! so the kernel-runner's `main.rs` reads cleanly and the boot
//! handshake banner is a single audit point.

use nexacore_kernel::bare_metal::early_console;

/// Print the K4 boot banner over COM1 — the canonical "first byte"
/// indicating the kernel has reached `kernel_entry` and the early
/// console is operational.
///
/// Distinct from `kmain`'s banner (which carries kernel version +
/// memory-region count) because this writes BEFORE the heap is
/// initialised — proving that the panic-path / early-console pair
/// works without allocator support, which is the K3 invariant.
pub fn announce_boot() {
    early_console::write_str("\n[NexaCore OS] kernel-runner: entry_point reached.\n");
    early_console::write_str("[NexaCore OS] early console (COM1) is live.\n");
    early_console::write_str("[NexaCore OS] proceeding to heap init + kmain.\n");
}
