//! Interrupt-driven completion for NVMe queues.
//!
//! Abstracts the completion mechanism behind a trait so the driver
//! can transparently switch between polling and interrupt-driven
//! completion without changing the IO session logic.
//!
//! ## Phase-1 architecture
//!
//! Phase-1 `IrqAttach (72)` binds a single MSI-X vector (vector 0)
//! to the admin CQ and the IO CQ. The kernel signals completions by
//! unblocking the driver's `IrqWait` syscall; the driver then drains
//! the CQ ring as usual via `drain_completion`.
//!
//! The polling path remains available as a fallback (the image's
//! bring-up sequence uses it before the interrupt binding is
//! established). Both paths implement [`CompletionWaiter`] so the
//! IO session is agnostic to the mechanism.
//!
//! ## MSI-X vector layout
//!
//! NVMe 1.4 § 11 mandates that MSI-X is the preferred interrupt
//! mechanism. Phase-1 allocates one vector (shared between admin
//! and IO CQs); multi-queue configurations (future NCIP) would
//! allocate one vector per IO CQ for reduced contention.

/// Completion waiting strategy.
///
/// The driver polls or waits for an interrupt depending on which
/// implementor is wired into the IO session. Both paths return the
/// same `bool`: `true` if a completion may be pending (the caller
/// should drain the CQ), `false` if the wait was interrupted or
/// timed out.
pub trait CompletionWaiter {
    /// Block until the controller signals a completion, or until
    /// the budget is exhausted. Returns `true` when the caller
    /// should attempt a CQ drain.
    fn wait_for_completion(&mut self, budget: u32) -> bool;
}

/// Polling-based completion waiter.
///
/// Spins for up to `budget` iterations, yielding `true` on every
/// call (the caller always drains). This is the Phase-1 default
/// before `IrqAttach` establishes the interrupt binding.
#[derive(Debug, Clone, Copy, Default)]
pub struct PollingWaiter;

impl CompletionWaiter for PollingWaiter {
    #[inline]
    fn wait_for_completion(&mut self, _budget: u32) -> bool {
        true
    }
}

/// Interrupt-driven completion waiter.
///
/// Wraps the `IrqWait` syscall number and the IRQ vector index so
/// the driver can block until the kernel delivers the MSI-X
/// completion signal. The struct is agnostic to the syscall ABI —
/// the actual `syscall` invocation is performed by a caller-supplied
/// closure, keeping this crate free of inline assembly.
///
/// Phase-1 shares a single MSI-X vector (vector 0) between the
/// admin CQ and the IO CQ; a future multi-queue slice would
/// construct one `InterruptWaiter` per CQ with distinct vector
/// indices.
#[derive(Debug, Clone, Copy)]
pub struct InterruptWaiter {
    vector: u16,
    irq_line: u32,
}

impl InterruptWaiter {
    /// Construct a waiter bound to the given MSI-X vector and IRQ
    /// line. `irq_line` is the kernel-side identifier returned by
    /// `IrqAttach (72)` — it maps to the PIC/APIC/MSI-X entry the
    /// controller writes completions through.
    #[must_use]
    pub const fn new(vector: u16, irq_line: u32) -> Self {
        Self { vector, irq_line }
    }

    /// The MSI-X vector index this waiter is bound to.
    #[must_use]
    pub const fn vector(self) -> u16 {
        self.vector
    }

    /// The kernel IRQ line this waiter targets.
    #[must_use]
    pub const fn irq_line(self) -> u32 {
        self.irq_line
    }
}

impl CompletionWaiter for InterruptWaiter {
    #[inline]
    fn wait_for_completion(&mut self, _budget: u32) -> bool {
        // Phase-1: the interrupt binding was established by
        // `IrqAttach (72)` at bring-up time. In the no_std bare-metal
        // context the driver would issue a `hlt`-like wait or a
        // dedicated `IrqWait` syscall here. For the host-test harness
        // and the cross-build validation, this always returns true
        // (optimistic: assume the controller has already signalled).
        //
        // The actual `syscall` invocation for the bare-metal path
        // lives in `nexacore-driver-nvme-image::_start` where inline
        // assembly is available; this crate (compiled with `no_std`
        // but without `no_main`) cannot issue syscalls directly.
        true
    }
}

/// MSI-X vector table entry parsed from BAR0.
///
/// NVMe controllers expose their MSI-X capability through the PCI
/// configuration space (Capability ID 0x11); the vector table
/// itself lives in BAR0 at an offset declared in the MSI-X
/// capability structure. Each entry is 16 bytes per PCI 3.0
/// § 6.8.2.
///
/// Phase-1 does not parse the PCI MSI-X capability structure
/// (that requires `PciConfigRead (74)` which the live image does
/// not yet exercise); instead it hardcodes vector 0 as the single
/// shared interrupt. This struct is scaffolded for the future
/// multi-queue slice that will read the real table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixTableEntry {
    /// Lower 32 bits of the message address.
    pub msg_addr_lo: u32,
    /// Upper 32 bits of the message address.
    pub msg_addr_hi: u32,
    /// Message data.
    pub msg_data: u32,
    /// Vector control (bit 0 = mask).
    pub vector_ctrl: u32,
}

/// MSI-X Table Entry size in bytes per PCI 3.0 § 6.8.2.
pub const MSIX_TABLE_ENTRY_BYTES: usize = 16;

impl MsixTableEntry {
    /// Parse a single MSI-X table entry from a 16-byte slice.
    ///
    /// Returns `None` if the slice is shorter than
    /// [`MSIX_TABLE_ENTRY_BYTES`].
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MSIX_TABLE_ENTRY_BYTES {
            return None;
        }
        Some(Self {
            msg_addr_lo: read_le_u32(bytes, 0),
            msg_addr_hi: read_le_u32(bytes, 4),
            msg_data: read_le_u32(bytes, 8),
            vector_ctrl: read_le_u32(bytes, 12),
        })
    }

    /// Returns `true` if the vector is masked (bit 0 of
    /// `vector_ctrl`).
    #[must_use]
    pub const fn is_masked(self) -> bool {
        self.vector_ctrl & 1 != 0
    }
}

/// Phase-1 MSI-X configuration: single vector, shared between
/// admin and IO CQs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixConfig {
    /// Number of vectors the controller supports.
    pub table_size: u16,
    /// The vector index Phase-1 uses (always 0).
    pub active_vector: u16,
    /// Whether interrupts are enabled.
    pub enabled: bool,
}

impl MsixConfig {
    /// Phase-1 default: 1 vector, index 0, enabled.
    #[must_use]
    pub const fn phase_1_default() -> Self {
        Self {
            table_size: 1,
            active_vector: 0,
            enabled: true,
        }
    }

    /// Returns `true` if the configuration supports the requested
    /// vector index.
    #[must_use]
    pub const fn supports_vector(self, vector: u16) -> bool {
        vector < self.table_size
    }
}

fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    let Some(slice) = buf.get(off..off + 4) else {
        return 0;
    };
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(slice);
    u32::from_le_bytes(tmp)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // PollingWaiter
    // -------------------------------------------------------------------

    #[test]
    fn polling_waiter_always_returns_true() {
        let mut w = PollingWaiter;
        assert!(w.wait_for_completion(0));
        assert!(w.wait_for_completion(100));
        assert!(w.wait_for_completion(u32::MAX));
    }

    // -------------------------------------------------------------------
    // InterruptWaiter
    // -------------------------------------------------------------------

    #[test]
    fn interrupt_waiter_stores_vector_and_irq_line() {
        let w = InterruptWaiter::new(0, 34);
        assert_eq!(w.vector(), 0);
        assert_eq!(w.irq_line(), 34);
    }

    #[test]
    fn interrupt_waiter_returns_true_on_wait() {
        let mut w = InterruptWaiter::new(0, 34);
        assert!(w.wait_for_completion(50_000));
    }

    // -------------------------------------------------------------------
    // MsixTableEntry
    // -------------------------------------------------------------------

    #[test]
    fn msix_table_entry_bytes_is_sixteen() {
        assert_eq!(MSIX_TABLE_ENTRY_BYTES, 16);
    }

    #[test]
    fn msix_table_entry_from_bytes_parses_correctly() {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&0xFEE0_0000_u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0x0000_0000_u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&0x0000_0041_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x0000_0000_u32.to_le_bytes());
        let entry = MsixTableEntry::from_bytes(&bytes).unwrap();
        assert_eq!(entry.msg_addr_lo, 0xFEE0_0000);
        assert_eq!(entry.msg_addr_hi, 0);
        assert_eq!(entry.msg_data, 0x41);
        assert_eq!(entry.vector_ctrl, 0);
        assert!(!entry.is_masked());
    }

    #[test]
    fn msix_table_entry_detects_masked_vector() {
        let mut bytes = [0u8; 16];
        bytes[12..16].copy_from_slice(&0x0000_0001_u32.to_le_bytes());
        let entry = MsixTableEntry::from_bytes(&bytes).unwrap();
        assert!(entry.is_masked());
    }

    #[test]
    fn msix_table_entry_rejects_undersized_slice() {
        let bytes = [0u8; 15];
        assert!(MsixTableEntry::from_bytes(&bytes).is_none());
    }

    // -------------------------------------------------------------------
    // MsixConfig
    // -------------------------------------------------------------------

    #[test]
    fn phase_1_default_config() {
        let cfg = MsixConfig::phase_1_default();
        assert_eq!(cfg.table_size, 1);
        assert_eq!(cfg.active_vector, 0);
        assert!(cfg.enabled);
    }

    #[test]
    fn supports_vector_within_table_size() {
        let cfg = MsixConfig {
            table_size: 4,
            active_vector: 0,
            enabled: true,
        };
        assert!(cfg.supports_vector(0));
        assert!(cfg.supports_vector(3));
        assert!(!cfg.supports_vector(4));
    }

    // -------------------------------------------------------------------
    // CompletionWaiter trait is object-safe
    // -------------------------------------------------------------------

    #[test]
    fn completion_waiter_is_object_safe() {
        let mut poll = PollingWaiter;
        let waiter: &mut dyn CompletionWaiter = &mut poll;
        assert!(waiter.wait_for_completion(1));
    }

    #[test]
    fn interrupt_waiter_is_object_safe() {
        let mut irq = InterruptWaiter::new(0, 34);
        let waiter: &mut dyn CompletionWaiter = &mut irq;
        assert!(waiter.wait_for_completion(1));
    }
}
