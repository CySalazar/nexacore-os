//! MB14.d — Inter-processor interrupt helpers.
//!
//! Builds on the pure-function ICR encoders from [`super::mp`] and the
//! live LAPIC `ICR_HI`/`ICR_LO` writer in [`super::lapic::lapic_send_ipi`]
//! to expose two broadcast primitives that the kernel uses for cross-CPU
//! coordination:
//!
//! - [`send_to_all_except_self`]: Fixed-delivery IPI to every other CPU
//!   using the `AllExcludingSelf` shorthand. Selected by the TLB
//!   shootdown driver (vector [`super::tlb_shootdown::TLB_SHOOTDOWN_VECTOR`]
//!   `= 0xFD`) and reusable by future MB14.e cross-CPU primitives.
//! - [`send_to_apic_id`]: Fixed-delivery IPI to a specific physical APIC
//!   ID. Used in BSP-side smoke tests and by future per-CPU directed
//!   work-stealing.
//!
//! Both helpers reuse [`super::mp::encode_icr_xapic`] so the ICR bit
//! layout stays pinned by the host-side encoder tests in `mp::tests::*`
//! — a regression in this layer would surface as a test failure in CI
//! rather than a triple-faulted AP on real silicon.
//!
//! ## Why this lives outside `mp`
//!
//! The `mp` module is the MADT-walk + INIT-SIPI orchestrator: its scope
//! ends at "every enabled AP is parked on a kernel stack." General-purpose
//! IPIs are a different concern (cross-AS TLB shootdown, future
//! work-stealing wake-ups, future user-IPC fast-path) so they live in
//! their own module to keep `mp` focused and to keep the cross-CPU
//! primitives easy to discover.

#![allow(
    unsafe_code,
    reason = "thin layer over `lapic_send_ipi` (already #![allow(unsafe_code)])"
)]

use super::mp::{
    IcrCommand, IcrDeliveryMode, IcrDestinationMode, IcrDestinationShorthand, IcrLevel,
    IcrTriggerMode, encode_icr_xapic,
};

/// Build the canonical Fixed-delivery, edge-triggered, assert-level
/// broadcast IPI command targeting every CPU except the issuer.
///
/// Reusable from host tests so MB14.d's wire-level invariants stay
/// pinned alongside the existing `mp::encode_icr_*` tests.
#[must_use]
pub const fn broadcast_all_except_self(vector: u8) -> IcrCommand {
    IcrCommand {
        vector,
        delivery_mode: IcrDeliveryMode::Fixed,
        destination_mode: IcrDestinationMode::Physical,
        level: IcrLevel::Assert,
        trigger_mode: IcrTriggerMode::Edge,
        shorthand: IcrDestinationShorthand::AllExcludingSelf,
        destination_apic_id: 0,
    }
}

/// Build the canonical Fixed-delivery, edge-triggered, assert-level IPI
/// command targeting one specific physical APIC ID.
#[must_use]
pub const fn fixed_to_apic_id(vector: u8, apic_id: u32) -> IcrCommand {
    IcrCommand {
        vector,
        delivery_mode: IcrDeliveryMode::Fixed,
        destination_mode: IcrDestinationMode::Physical,
        level: IcrLevel::Assert,
        trigger_mode: IcrTriggerMode::Edge,
        shorthand: IcrDestinationShorthand::NoShorthand,
        destination_apic_id: apic_id,
    }
}

/// Send a Fixed-delivery IPI at `vector` to every CPU except the issuer
/// using the LAPIC `AllExcludingSelf` shorthand.
///
/// Returns `false` if [`super::lapic::lapic_init`] has not yet
/// succeeded (LAPIC MMIO unmapped); the call is a no-op in that case.
/// Returns `true` after the ICR write sequence has been issued. The
/// caller is responsible for any post-send ack-poll: this helper only
/// guarantees that the ICR has been latched onto the APIC bus.
#[must_use]
pub fn send_to_all_except_self(vector: u8) -> bool {
    let (low, high) = encode_icr_xapic(broadcast_all_except_self(vector));
    super::lapic::lapic_send_ipi(low, high)
}

/// Send a Fixed-delivery IPI at `vector` to one specific physical APIC ID.
///
/// Same return semantics as [`send_to_all_except_self`].
#[must_use]
pub fn send_to_apic_id(vector: u8, apic_id: u32) -> bool {
    let (low, high) = encode_icr_xapic(fixed_to_apic_id(vector, apic_id));
    super::lapic::lapic_send_ipi(low, high)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_all_except_self_encodes_shorthand_bits() {
        let cmd = broadcast_all_except_self(0xFD);
        let (low, high) = encode_icr_xapic(cmd);
        // Vector
        assert_eq!(low & 0xFF, 0xFD);
        // Delivery mode = Fixed (000)
        assert_eq!((low >> 8) & 0b111, 0b000, "Fixed delivery");
        // Destination mode = Physical (0)
        assert_eq!((low >> 11) & 1, 0, "physical destination");
        // Level = Assert (1)
        assert_eq!((low >> 14) & 1, 1, "level assert");
        // Trigger = Edge (0)
        assert_eq!((low >> 15) & 1, 0, "edge trigger");
        // Shorthand = AllExcludingSelf (0b11)
        assert_eq!((low >> 18) & 0b11, 0b11, "AllExcludingSelf shorthand");
        // High dword carries no destination when shorthand is set.
        assert_eq!(high, 0, "shorthand IPI ignores destination field");
    }

    #[test]
    fn fixed_to_apic_id_encodes_destination_in_high() {
        let cmd = fixed_to_apic_id(0xFD, 3);
        let (low, high) = encode_icr_xapic(cmd);
        // Same delivery / level / trigger / shorthand fields as Fixed
        // broadcast, just with the destination field populated.
        assert_eq!(low & 0xFF, 0xFD);
        assert_eq!((low >> 8) & 0b111, 0b000);
        assert_eq!((low >> 18) & 0b11, 0b00, "NoShorthand for directed IPI");
        // xAPIC destination lives in the top byte of the high dword.
        assert_eq!(high, 0x0300_0000, "APIC ID 3 in xAPIC dest byte");
    }

    #[test]
    fn vector_byte_is_passed_through_unchanged() {
        for v in [0u8, 0x20, 0x80, 0xFD, 0xFE, 0xFF] {
            let (low, _) = encode_icr_xapic(broadcast_all_except_self(v));
            assert_eq!(low & 0xFF, u32::from(v));
        }
    }

    #[test]
    fn fixed_to_apic_id_truncates_high_bits_under_xapic() {
        // xAPIC ICR_HI byte is only 8 bits — IDs above 0xFF wrap by
        // construction of `encode_icr_xapic`. Pin the behaviour so the
        // future x2APIC switch (MB14.f) becomes a deliberate API change
        // rather than a silent fix.
        let (_, high) = encode_icr_xapic(fixed_to_apic_id(0xFD, 0x1234_5678));
        assert_eq!(high, 0x7800_0000);
    }
}
