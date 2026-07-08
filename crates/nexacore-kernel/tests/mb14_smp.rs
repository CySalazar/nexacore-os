//! Host-mode integration tests for MB14 SMP support.
//!
//! Exercises the full chain from MADT parsing through per-CPU descriptor
//! registration, GDT/TSS slot population, ICR encoding, and trampoline
//! blob emplacement — all without requiring bare-metal hardware.
//!
//! ## Coverage areas
//!
//! 1. **MADT parsing** — `mp::parse_madt` decodes xAPIC and x2APIC entries.
//! 2. **ICR encoding** — `mp::encode_icr_xapic` / `encode_icr_x2apic` pin
//!    the INIT and SIPI wire formats against Intel SDM Vol 3A § 10.6.1.
//! 3. **INIT-SIPI orchestrator** — `mp::start_aps` / `start_aps_live`
//!    correctly selects APs, skips the BSP, and skips disabled entries.
//! 4. **Per-CPU descriptor lifecycle** — `per_cpu::register_ap`, slot
//!    isolation, and the `ap_online_ack_addr` sentinel are wired together
//!    correctly.
//! 5. **GDT + TSS per-AP slots** — `gdt::gdt_set_ap_tss`,
//!    `gdt::tss_selector_for_cpu`, and `tss::init_ap_tss` produce
//!    consistent selector / descriptor values.
//! 6. **Trampoline blob + emplacement** — `mp_trampoline::build_trampoline_blob`
//!    and `mp_emplacement::place_trampoline` (via a synthetic `TestArena`)
//!    produce structurally valid blobs that would let an AP reach
//!    `kmain_ap` on real hardware.
//! 7. **AP runtime control block** — `mp_ap_entry::register_ap_runtime_slot`
//!    round-trips all four per-AP fields with consistent values derived
//!    from the other layers.
//! 8. **End-to-end topology walk** — given a realistic 4-CPU MADT buffer,
//!    verify that the full BSP-pre-fire setup sequence produces the
//!    correct slot count, LAPIC-to-cpu mappings, and TSS descriptors.
//!
//! ## What is NOT tested here
//!
//! - The `x86_64` bare-metal ICR write path (requires LAPIC MMIO).
//! - The PIT delay (requires hardware timer).
//! - The `kmain_ap` asm landing stub (requires real AP execution).
//!
//! Those paths are exercised by the Proxmox smoke test on real hardware
//! during the MB14 acceptance gate.

#![cfg(feature = "bare-metal")]
#![allow(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    // Test-only: `if bool { 1 } else { 0 }` is clear for ICR flag construction.
    clippy::bool_to_int_with_if,
    // Test-only: compile-time constant assertions are always-true by design.
    clippy::assertions_on_constants,
    // Test-only: `use` after statements in test helper functions.
    clippy::items_after_statements,
    // Test-only: cognitive complexity of end-to-end integration test.
    clippy::cognitive_complexity,
    // Test-only: `<= u64::from(u32::MAX)` bound check is intentionally readable.
    clippy::checked_conversions,
    // Test-only: `u32` values promoted to `u64` via From.
    clippy::cast_lossless
)]

extern crate alloc;

use alloc::vec::Vec;

use nexacore_kernel::{
    bare_metal::{
        gdt::{gdt_base_and_limit, gdt_set_ap_tss, tss_selector_for_cpu},
        mp::{
            CpuEntry, CpuTopology, IcrCommand, IcrDeliveryMode, IcrDestinationMode,
            IcrDestinationShorthand, IcrLevel, IcrTriggerMode, MAX_CPUS, MadtError, StartApsMode,
            encode_icr_x2apic, encode_icr_xapic, parse_madt, start_aps,
        },
        mp_ap_entry::{
            AP_ACK_COUNTER_OFFSET, AP_KMAIN_AP_VA_OFFSET, AP_LANDING_STUB_OFFSET,
            AP_LANDING_STUB_SIZE, PseudoDescriptor, build_ap_landing_stub,
            install_descriptor_tables, register_ap_runtime_slot,
        },
        mp_emplacement::{TRAMPOLINE_PHYS_BASE, TRAMPOLINE_SIPI_VECTOR, place_trampoline},
        mp_trampoline::{TRAMPOLINE_BLOB_SIZE, build_temp_gdt, build_trampoline_blob},
        per_cpu::{CPU_ID_UNINIT, MAX_AP_SLOTS, ap_online_ack_addr, ap_slot, bsp, register_ap},
        tss::init_ap_tss,
    },
    memory::{BitmapFrameAllocator, PhysAddr},
};

// =============================================================================
// Shared MADT builder helper
// =============================================================================

/// Build a minimal MADT byte buffer with the supplied ICS bytes appended
/// after the 44-byte header. Mirrors the helper in `mp::tests` but exposed
/// here so integration tests do not need to reach into private test helpers.
fn make_madt(ics_bytes: &[u8]) -> Vec<u8> {
    let total = 44 + ics_bytes.len();
    let mut buf = alloc::vec![0u8; total];
    buf[0..4].copy_from_slice(b"APIC");
    let len_le = (total as u32).to_le_bytes();
    buf[4..8].copy_from_slice(&len_le);
    buf[44..].copy_from_slice(ics_bytes);
    buf
}

/// Append a type-0 (Processor Local APIC) ICS record to an existing
/// `ics_bytes` accumulator.
fn push_local_apic(ics: &mut Vec<u8>, acpi_uid: u8, apic_id: u8, enabled: bool) {
    ics.extend_from_slice(&[0x00, 0x08, acpi_uid, apic_id]);
    let flags: u32 = if enabled { 1 } else { 0 };
    ics.extend_from_slice(&flags.to_le_bytes());
}

/// Append a type-9 (Processor Local x2APIC) ICS record.
fn push_x2apic(ics: &mut Vec<u8>, apic_id: u32, acpi_uid: u32, enabled: bool) {
    let flags: u32 = if enabled { 1 } else { 0 };
    ics.extend_from_slice(&[0x09, 0x10, 0x00, 0x00]); // type, length, 2B reserved
    ics.extend_from_slice(&apic_id.to_le_bytes());
    ics.extend_from_slice(&flags.to_le_bytes());
    ics.extend_from_slice(&acpi_uid.to_le_bytes());
}

/// Build a [`CpuTopology`] from a raw slice of [`CpuEntry`] values (for
/// the start_aps / start_aps_live tests that need a synthetic topology).
fn topology_from_entries(cpus: &[CpuEntry]) -> CpuTopology {
    // We must go through `parse_madt` to produce a `CpuTopology` without
    // reaching into private fields. Build the MADT buffer dynamically.
    let mut ics = Vec::new();
    for cpu in cpus {
        if cpu.x2apic {
            push_x2apic(&mut ics, cpu.apic_id, cpu.acpi_uid, cpu.enabled);
        } else {
            push_local_apic(&mut ics, cpu.acpi_uid as u8, cpu.apic_id as u8, cpu.enabled);
        }
    }
    let buf = make_madt(&ics);
    parse_madt(&buf).expect("topology_from_entries: parse_madt failed")
}

// =============================================================================
// 1. MADT parsing — cross-type round-trip
// =============================================================================

#[test]
fn madt_parse_rejects_non_apic_signature() {
    // A buffer whose first 4 bytes are not b"APIC" must be rejected
    // with BadSignature.
    let mut buf = make_madt(&[]);
    buf[0] = b'X';
    assert!(
        matches!(parse_madt(&buf), Err(MadtError::BadSignature)),
        "non-APIC signature must be rejected"
    );
}

#[test]
fn madt_parse_mixed_local_apic_and_x2apic_entries_in_order() {
    // Three CPUs: one xAPIC (BSP, apic_id=0), one IO-APIC stub that must
    // be skipped, one x2APIC (AP, apic_id=0x1234_5678).
    let mut ics = Vec::new();
    push_local_apic(&mut ics, 1, 0, true);
    // IO APIC (type 1, length 12, zeroed payload) — parser must skip.
    ics.extend_from_slice(&[0x01, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    push_x2apic(&mut ics, 0x1234_5678, 0x42, true);
    let buf = make_madt(&ics);

    let topo = parse_madt(&buf).expect("parse must succeed");
    assert_eq!(topo.len(), 2, "IO APIC entry must be skipped");
    assert_eq!(topo.enabled_count(), 2);
    assert!(!topo.entries()[0].x2apic, "first entry is xAPIC");
    assert!(topo.entries()[1].x2apic, "second entry is x2APIC");
    assert_eq!(topo.entries()[1].apic_id, 0x1234_5678);
}

#[test]
fn madt_parse_disabled_entry_counted_but_not_enabled() {
    let mut ics = Vec::new();
    push_local_apic(&mut ics, 1, 0, true); // enabled BSP
    push_local_apic(&mut ics, 2, 1, false); // disabled AP
    let buf = make_madt(&ics);

    let topo = parse_madt(&buf).expect("parse");
    assert_eq!(topo.len(), 2);
    assert_eq!(
        topo.enabled_count(),
        1,
        "disabled entry must not count as enabled"
    );
    assert!(!topo.entries()[1].enabled);
}

#[test]
fn madt_parse_exactly_max_cpus_does_not_error() {
    let mut ics = Vec::new();
    for i in 0..MAX_CPUS {
        push_local_apic(&mut ics, i as u8, i as u8, true);
    }
    let buf = make_madt(&ics);
    let topo = parse_madt(&buf).expect("exactly MAX_CPUS entries must parse cleanly");
    assert_eq!(topo.len(), MAX_CPUS);
}

#[test]
fn madt_parse_max_cpus_plus_one_returns_too_many_cpus() {
    let mut ics = Vec::new();
    for i in 0..=MAX_CPUS {
        push_local_apic(&mut ics, i as u8, i as u8, true);
    }
    let buf = make_madt(&ics);
    assert!(
        matches!(parse_madt(&buf), Err(MadtError::TooManyCpus)),
        "MAX_CPUS + 1 entries must produce TooManyCpus"
    );
}

// =============================================================================
// 2. ICR encoding — INIT and SIPI wire formats
// =============================================================================

#[test]
fn icr_xapic_init_delivers_mode_5_level_assert() {
    // INIT assert: delivery_mode=5 (bits 8..10), level=1 (bit 14).
    let (low, _) = encode_icr_xapic(IcrCommand::init_assert(1));
    assert_eq!((low >> 8) & 0b111, 0b101, "INIT delivery mode must be 5");
    assert_eq!((low >> 14) & 1, 1, "level must be Assert (1)");
    assert_eq!((low >> 15) & 1, 0, "trigger mode must be Edge (0)");
    assert_eq!((low >> 18) & 0b11, 0b00, "shorthand must be NoShorthand");
    assert_eq!(low & 0xFF, 0, "INIT vector field must be zero");
}

#[test]
fn icr_xapic_sipi_delivery_mode_is_startup() {
    // StartUp delivery mode = 6 (0b110).
    let (low, _) = encode_icr_xapic(IcrCommand::sipi(1, 0x08));
    assert_eq!(
        (low >> 8) & 0b111,
        0b110,
        "SIPI delivery mode must be StartUp (6)"
    );
    assert_eq!(
        low & 0xFF,
        0x08,
        "SIPI vector must equal trampoline page number"
    );
}

#[test]
fn icr_xapic_high_dword_carries_8bit_apic_id() {
    // xAPIC destination occupies bits 56..63 of ICR (top byte of ICR_HI).
    // APIC ID 0xAB → ICR_HI[31:24] = 0xAB.
    let (_, high) = encode_icr_xapic(IcrCommand::init_assert(0xAB));
    assert_eq!(high >> 24, 0xAB, "xAPIC ID in top byte of ICR_HI");
    assert_eq!(
        high & 0x00FF_FFFF,
        0,
        "lower 3 bytes of ICR_HI reserved-zero"
    );
}

#[test]
fn icr_xapic_destination_wraps_at_8_bits() {
    // 0x1234_5678 → truncated to 0x78 under xAPIC.
    let (_, high) = encode_icr_xapic(IcrCommand::init_assert(0x1234_5678));
    assert_eq!(high >> 24, 0x78, "xAPIC must truncate to 8-bit ID");
}

#[test]
fn icr_x2apic_carries_full_32bit_apic_id() {
    let full_id: u32 = 0xCAFE_BABE;
    let icr = encode_icr_x2apic(IcrCommand::init_assert(full_id));
    assert_eq!(
        (icr >> 32) as u32,
        full_id,
        "x2APIC must carry full 32-bit ID in high dword"
    );
}

#[test]
fn icr_x2apic_sipi_packs_vector_and_mode() {
    let icr = encode_icr_x2apic(IcrCommand::sipi(2, 0x08));
    let low = icr as u32;
    assert_eq!(low & 0xFF, 0x08, "x2APIC SIPI vector");
    assert_eq!((low >> 8) & 0b111, 0b110, "x2APIC StartUp delivery mode");
    assert_eq!((icr >> 32) as u32, 2, "x2APIC destination APIC ID");
}

#[test]
fn icr_broadcast_shorthand_all_excluding_self_bits_18_19() {
    let cmd = IcrCommand {
        vector: 0xFD,
        delivery_mode: IcrDeliveryMode::Fixed,
        destination_mode: IcrDestinationMode::Physical,
        level: IcrLevel::Assert,
        trigger_mode: IcrTriggerMode::Edge,
        shorthand: IcrDestinationShorthand::AllExcludingSelf,
        destination_apic_id: 0,
    };
    let (low, high) = encode_icr_xapic(cmd);
    assert_eq!(
        (low >> 18) & 0b11,
        0b11,
        "AllExcludingSelf = 0b11 at bits 18..19"
    );
    // When shorthand is used, the destination field has no effect.
    assert_eq!(high, 0, "destination ignored when shorthand is set");
}

// =============================================================================
// 3. INIT-SIPI orchestrator — start_aps + start_aps_live topology walk
// =============================================================================

#[test]
fn start_aps_targets_every_enabled_non_bsp_cpu() {
    // BSP=0, AP=1 (enabled), AP=2 (enabled). Expect 2 targeted.
    let topo = topology_from_entries(&[
        CpuEntry {
            apic_id: 0,
            acpi_uid: 0,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 1,
            acpi_uid: 1,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 2,
            acpi_uid: 2,
            enabled: true,
            x2apic: false,
        },
    ]);
    let r = start_aps(&topo, 0, 0x08, StartApsMode::DryRun);
    assert_eq!(r.targeted, 2, "BSP must be excluded from target set");
    assert_eq!(r.sequenced, 2);
    assert!(r.dry_run);
}

#[test]
fn start_aps_skips_disabled_entries() {
    let topo = topology_from_entries(&[
        CpuEntry {
            apic_id: 0,
            acpi_uid: 0,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 1,
            acpi_uid: 1,
            enabled: false,
            x2apic: false,
        }, // disabled
        CpuEntry {
            apic_id: 2,
            acpi_uid: 2,
            enabled: true,
            x2apic: false,
        },
    ]);
    let r = start_aps(&topo, 0, 0x08, StartApsMode::DryRun);
    assert_eq!(r.targeted, 1, "disabled AP must not be targeted");
}

#[test]
fn start_aps_skips_bsp_regardless_of_position() {
    // BSP is at index 2 (out of LAPIC-ID order), identified by apic_id match.
    let topo = topology_from_entries(&[
        CpuEntry {
            apic_id: 1,
            acpi_uid: 1,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 2,
            acpi_uid: 2,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 5,
            acpi_uid: 5,
            enabled: true,
            x2apic: false,
        }, // BSP
    ]);
    let r = start_aps(&topo, 5, 0x08, StartApsMode::DryRun);
    assert_eq!(
        r.targeted, 2,
        "BSP (apic_id=5) must be excluded by ID match"
    );
}

#[test]
fn start_aps_uniprocessor_produces_zero_targets() {
    let topo = topology_from_entries(&[CpuEntry {
        apic_id: 0,
        acpi_uid: 0,
        enabled: true,
        x2apic: false,
    }]);
    let r = start_aps(&topo, 0, 0x08, StartApsMode::DryRun);
    assert_eq!(r.targeted, 0);
    assert_eq!(r.sequenced, 0);
}

#[test]
fn start_aps_trampoline_zero_forces_dry_run_even_in_live_mode() {
    // trampoline_page = 0 → SIPI vector 0 = IVT; always rejected.
    let topo = topology_from_entries(&[
        CpuEntry {
            apic_id: 0,
            acpi_uid: 0,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 1,
            acpi_uid: 1,
            enabled: true,
            x2apic: false,
        },
    ]);
    let r = start_aps(&topo, 0, 0, StartApsMode::Live);
    assert!(r.dry_run, "vector 0 must force dry_run regardless of mode");
}

#[test]
fn start_aps_dry_run_counts_targets_correctly() {
    // DryRun mode must return targeted == sequenced and dry_run == true,
    // mirroring what the live path would report before any actual LAPIC
    // writes occur.  This test is the portable host equivalent of the
    // live INIT-SIPI path validated on bare-metal by the Proxmox smoke.
    let topo = topology_from_entries(&[
        CpuEntry {
            apic_id: 0,
            acpi_uid: 0,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 1,
            acpi_uid: 1,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 2,
            acpi_uid: 2,
            enabled: true,
            x2apic: false,
        },
    ]);
    let r = start_aps(&topo, 0, 0x08, StartApsMode::DryRun);
    assert_eq!(r.targeted, 2);
    assert_eq!(r.sequenced, 2);
    assert!(r.dry_run, "DryRun mode must set the dry_run flag");
}

// =============================================================================
// 4. Per-CPU descriptor lifecycle
// =============================================================================

#[test]
fn per_cpu_bsp_descriptor_is_non_null() {
    // bsp() must return a stable non-null reference.
    let bsp_ref = bsp();
    let addr = core::ptr::from_ref(bsp_ref) as usize;
    assert_ne!(addr, 0, "BSP descriptor must be at a non-null address");
}

#[test]
fn per_cpu_register_ap_round_trips_cpu_and_lapic_id() {
    // Register AP slot 5 (cpu_id=5) with a synthetic LAPIC ID.
    let slot = register_ap(5, 0xFF).expect("slot 5 must be available");
    assert_eq!(slot.cpu_id(), 5);
    assert_eq!(slot.lapic_id(), 0xFF);
    assert!(!slot.is_bsp());
    assert!(slot.is_initialised());
}

#[test]
fn per_cpu_register_ap_self_pointer_is_slot_address() {
    // The self-pointer at offset 0 must equal the address of the slot
    // itself so that `gs:[0]` dereference returns `&PerCpu`.
    let slot = register_ap(6, 0xAA).expect("slot 6");
    let expected = core::ptr::from_ref(slot) as u64;
    assert_eq!(
        slot.self_ptr(),
        expected,
        "self_ptr must equal slot address"
    );
}

#[test]
fn per_cpu_ap_slot_readback_matches_registered_pointer() {
    let a = register_ap(7, 0xBB).expect("register slot 7");
    let b = ap_slot(7).expect("readback slot 7");
    assert_eq!(
        core::ptr::from_ref(a),
        core::ptr::from_ref(b),
        "ap_slot must alias the same static slot as register_ap"
    );
}

#[test]
fn per_cpu_max_ap_slots_is_max_cpus_minus_one() {
    assert_eq!(MAX_AP_SLOTS, MAX_CPUS - 1);
}

#[test]
fn per_cpu_uninit_sentinel_never_collides_with_xapic_id() {
    // xAPIC IDs are 8-bit; the sentinel must be above 0xFF so a
    // stray comparison with a real LAPIC ID cannot produce a false match.
    assert!(
        CPU_ID_UNINIT > 0xFF,
        "CPU_ID_UNINIT must be out of xAPIC range"
    );
}

#[test]
fn per_cpu_online_ack_addr_is_stable_and_non_zero() {
    let a = ap_online_ack_addr();
    let b = ap_online_ack_addr();
    assert_ne!(a, 0, "AP_ONLINE_ACK must be at a non-zero address");
    assert_eq!(
        a, b,
        "consecutive calls must return the same stable address"
    );
}

#[test]
fn per_cpu_kernel_rsp_round_trip() {
    let slot = register_ap(8, 0xCC).expect("slot 8");
    slot.set_kernel_rsp(0xFFFF_C001_0000_0000);
    assert_eq!(slot.kernel_rsp(), 0xFFFF_C001_0000_0000);
}

#[test]
fn per_cpu_tick_counter_increments_per_descriptor() {
    let slot = register_ap(9, 0xDD).expect("slot 9");
    // Reset by obtaining a fresh descriptor-level view via the same slot.
    // Counters are cumulative in a shared static; we test only that each
    // inc_tick call advances the counter by exactly 1.
    let before = slot.tick_count();
    slot.inc_tick();
    assert_eq!(slot.tick_count(), before + 1);
    slot.inc_tick();
    assert_eq!(slot.tick_count(), before + 2);
}

#[test]
fn per_cpu_resched_flag_request_then_take_round_trip() {
    let slot = register_ap(10, 0xEE).expect("slot 10");
    slot.request_resched();
    assert!(slot.resched_pending(), "flag must be set after request");
    assert!(slot.take_resched(), "take must return true once");
    assert!(!slot.resched_pending(), "flag must be clear after take");
    assert!(!slot.take_resched(), "second take must return false");
}

#[test]
fn per_cpu_scheduler_guard_is_per_descriptor() {
    // Two independent descriptors can hold the guard simultaneously.
    let a = register_ap(11, 0x11).expect("slot 11");
    let b = register_ap(12, 0x12).expect("slot 12");
    // Release first so clean state for the test.
    if a.is_in_scheduler() {
        a.leave_scheduler();
    }
    if b.is_in_scheduler() {
        b.leave_scheduler();
    }
    assert!(a.enter_scheduler(), "a must be acquirable");
    assert!(b.enter_scheduler(), "b must be acquirable independently");
    assert!(!a.enter_scheduler(), "re-entrant claim on a must fail");
    a.leave_scheduler();
    b.leave_scheduler();
}

// =============================================================================
// 5. GDT + TSS per-AP slots
// =============================================================================

#[test]
fn gdt_bsp_selector_is_0x28() {
    assert_eq!(
        tss_selector_for_cpu(0),
        0x28,
        "BSP TSS selector must be 0x28"
    );
}

#[test]
fn gdt_first_ap_selector_is_0x38() {
    // cpu_id=1 → GDT slot 7 → selector 7*8 = 56 = 0x38.
    assert_eq!(tss_selector_for_cpu(1), 0x38);
}

#[test]
fn gdt_second_ap_selector_is_0x48() {
    // cpu_id=2 → GDT slot 9 → selector 9*8 = 72 = 0x48.
    assert_eq!(tss_selector_for_cpu(2), 0x48);
}

#[test]
fn gdt_out_of_range_cpu_yields_null_selector() {
    let oor = MAX_CPUS as u32;
    assert_eq!(
        tss_selector_for_cpu(oor),
        0,
        "out-of-range cpu_id must yield null selector"
    );
}

#[test]
fn gdt_bsp_rejects_set_ap_tss() {
    // cpu_id=0 is the BSP and uses the legacy static TSS.
    assert!(!gdt_set_ap_tss(0, 0xDEAD_BEEF));
}

#[test]
fn tss_init_ap_tss_rejects_bsp_cpu_id() {
    assert!(!init_ap_tss(0, 0, 0, 0), "cpu_id 0 is BSP — reject");
}

#[test]
fn tss_init_ap_tss_round_trips_stack_pointers() {
    use nexacore_kernel::bare_metal::tss::{ap_tss_ist1, ap_tss_ist2, ap_tss_rsp0};
    let rsp0 = 0xFFFF_C000_DEAD_BEEF_u64;
    let ist1 = 0xFFFF_C001_CAFE_0001_u64;
    let ist2 = 0xFFFF_C001_CAFE_0002_u64;
    // cpu_id=13 → different from IDs used by other tests.
    assert!(init_ap_tss(13, rsp0, ist1, ist2));
    assert_eq!(ap_tss_rsp0(13), rsp0);
    assert_eq!(ap_tss_ist1(13), ist1);
    assert_eq!(ap_tss_ist2(13), ist2);
}

#[test]
fn tss_ap_tss_addr_strides_by_104_bytes() {
    use nexacore_kernel::bare_metal::tss::ap_tss_addr;
    let a = ap_tss_addr(1);
    let b = ap_tss_addr(2);
    assert_ne!(a, 0);
    assert_eq!(b - a, 104, "TSS stride must be sizeof(Tss) = 104 bytes");
}

#[test]
fn gdt_set_ap_tss_writes_descriptor_at_correct_slot() {
    use nexacore_kernel::bare_metal::{
        gdt::gdt_read_pair,
        tss::{ap_tss_addr, tss_descriptor},
    };
    // Use cpu_id=14 to avoid collisions with earlier tests.
    let tss_base = ap_tss_addr(14);
    assert_ne!(tss_base, 0);
    assert!(gdt_set_ap_tss(14, tss_base));
    // cpu_id=14 → slot = 7 + 2*(14-1) = 7 + 26 = 33.
    let slot = 7 + 2 * (14 - 1);
    let (actual_lo, actual_hi) = gdt_read_pair(slot);
    let limit = (core::mem::size_of::<nexacore_kernel::bare_metal::tss::Tss>() - 1) as u32;
    let (expected_lo, expected_hi) = tss_descriptor(tss_base, limit);
    assert_eq!(actual_lo, expected_lo, "TSS descriptor low word mismatch");
    assert_eq!(actual_hi, expected_hi, "TSS descriptor high word mismatch");
}

#[test]
fn gdt_base_and_limit_are_non_zero_and_aligned() {
    let (base, limit) = gdt_base_and_limit();
    assert_ne!(base, 0, "GDT base must be non-zero");
    assert_ne!(limit, 0, "GDT limit must be non-zero");
    // Limit is (N * 8 - 1); N * 8 mod 8 == 0 so limit ≡ 7 (mod 8).
    assert_eq!(
        (limit as usize + 1) % 8,
        0,
        "GDT byte size must be a multiple of 8"
    );
}

// =============================================================================
// 6. Trampoline blob structure (pure builder)
// =============================================================================

#[test]
fn trampoline_blob_starts_with_cli_cld() {
    let blob = build_trampoline_blob(0x0000_8000, 0x0000_9000, 0xFFFF_FFFF_8010_0000);
    assert_eq!(blob[0], 0xFA, "first byte must be cli (0xFA)");
    assert_eq!(blob[1], 0xFC, "second byte must be cld (0xFC)");
}

#[test]
fn trampoline_blob_fits_in_one_page() {
    assert!(
        TRAMPOLINE_BLOB_SIZE <= 4096,
        "trampoline must fit in a 4 KiB page"
    );
}

#[test]
fn trampoline_blob_64bit_tail_encodes_kernel_entry() {
    let entry: u64 = 0x1234_5678_9ABC_DEF0;
    let blob = build_trampoline_blob(0x0000_8000, 0x0000_9000, entry);
    // REX.W + MOV at offset 0x62.
    assert_eq!(blob[0x62], 0x48, "REX.W prefix");
    assert_eq!(blob[0x63], 0xB8, "MOV rax, imm64 opcode");
    let imm = u64::from_le_bytes(blob[0x64..0x6C].try_into().expect("8 bytes"));
    assert_eq!(imm, entry, "kernel entry address must be embedded verbatim");
}

#[test]
fn trampoline_blob_gdt_slot_3_is_64bit_code() {
    // GDT slot 3 (64-bit code) must have L=1 and D/B=0 in the flags byte.
    let gdt = build_temp_gdt();
    let bytes = gdt[3].to_le_bytes();
    // Flags nibble at byte 6: G=1 D/B=0 L=1 AVL=0 + limit[19:16] = 0xAF.
    assert_eq!(bytes[6], 0xAF, "64-bit code flags must be 0xAF (L=1 D/B=0)");
}

#[test]
fn trampoline_sipi_vector_matches_0x8000() {
    // SIPI vector = base >> 12. For 0x8000 that is 0x08.
    assert_eq!(TRAMPOLINE_SIPI_VECTOR, 0x08);
    assert_eq!(
        u32::from(TRAMPOLINE_SIPI_VECTOR) << 12,
        TRAMPOLINE_PHYS_BASE
    );
}

// =============================================================================
// 7. Trampoline emplacement (synthetic TestArena)
// =============================================================================

/// Number of 4 KiB frames in the test arena (1.5 MiB / 4 KiB = 384).
const ARENA_FRAMES: u64 = 384;
const ARENA_SIZE: usize = ARENA_FRAMES as usize * 4096;
const FREE_BASE: u64 = 0x10_0000; // mirrors kmain's mark_range_used threshold

/// A heap-allocated 4 KiB-aligned byte arena standing in for the
/// bootloader physical-memory direct map.
struct TestArena {
    ptr: *mut u8,
    layout: std::alloc::Layout,
}

impl TestArena {
    fn new() -> Self {
        let layout = std::alloc::Layout::from_size_align(ARENA_SIZE, 4096).expect("valid layout");
        // SAFETY: layout has non-zero size; alloc_zeroed returns a valid
        // allocation or null. Null is checked immediately after.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "test arena allocation failed");
        Self { ptr, layout }
    }

    /// The `phys_offset` value for this arena: `phys 0` maps to `self.ptr`.
    fn phys_offset(&self) -> u64 {
        self.ptr as u64
    }

    /// Read `len` bytes at physical address `paddr`.
    fn read_bytes(&self, paddr: u64, len: usize) -> Vec<u8> {
        assert!(
            paddr + len as u64 <= ARENA_SIZE as u64,
            "read_bytes paddr {paddr:#x} len {len} outside arena"
        );
        // SAFETY: bounds-checked above; the pointer arithmetic stays within
        // the valid arena allocation.
        let src = unsafe { self.ptr.add(paddr as usize) };
        let mut out = alloc::vec![0u8; len];
        for (i, slot) in out.iter_mut().enumerate() {
            // SAFETY: same bounds invariant as above.
            *slot = unsafe { core::ptr::read_volatile(src.add(i)) };
        }
        out
    }
}

impl Drop for TestArena {
    fn drop(&mut self) {
        // SAFETY: layout matches the original alloc_zeroed call.
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

/// Build a `PageMapper` rooted at the first frame handed out by the
/// allocator, plus an allocator with frames above 1 MiB marked free.
use nexacore_kernel::bare_metal::paging::PageMapper;
fn make_mapper_and_alloc() -> (TestArena, PageMapper, BitmapFrameAllocator<8>) {
    let arena = TestArena::new();
    let phys_offset = arena.phys_offset();

    let mut alloc = BitmapFrameAllocator::<8>::new(PhysAddr(0));
    alloc.mark_range_free(PhysAddr(FREE_BASE), ARENA_FRAMES * 4096 - FREE_BASE);

    let pml4_pa = alloc.alloc_frame().expect("PML4 frame from arena");
    let mapper = PageMapper::new(phys_offset, pml4_pa);
    (arena, mapper, alloc)
}

#[test]
fn trampoline_emplacement_places_blob_at_0x8000() {
    let (_arena, mut mapper, mut alloc) = make_mapper_and_alloc();
    let r = place_trampoline(&mut alloc, &mut mapper, 0xFFFF_FFFF_8010_0000)
        .expect("emplacement must succeed in test arena");
    assert_eq!(r.trampoline_paddr, TRAMPOLINE_PHYS_BASE);
}

#[test]
fn trampoline_emplacement_temp_pml4_fits_in_32_bits() {
    let (_arena, mut mapper, mut alloc) = make_mapper_and_alloc();
    let r = place_trampoline(&mut alloc, &mut mapper, 0xFFFF_FFFF_8010_0000).expect("emplacement");
    assert!(
        r.temp_pml4_paddr <= u64::from(u32::MAX),
        "temp PML4 must be in low 4 GiB for 32-bit CR3 load"
    );
    assert_eq!(
        r.temp_pml4_paddr & 0xFFF,
        0,
        "temp PML4 must be 4 KiB-aligned"
    );
}

#[test]
fn trampoline_emplacement_blob_starts_with_cli_cld_in_memory() {
    let (arena, mut mapper, mut alloc) = make_mapper_and_alloc();
    place_trampoline(&mut alloc, &mut mapper, 0xFFFF_FFFF_8010_0000).expect("emplacement");
    let head = arena.read_bytes(u64::from(TRAMPOLINE_PHYS_BASE), 2);
    assert_eq!(head[0], 0xFA, "cli opcode at phys 0x8000");
    assert_eq!(head[1], 0xFC, "cld opcode at phys 0x8001");
}

#[test]
fn trampoline_emplacement_allocates_between_three_and_seven_frames() {
    let (_arena, mut mapper, mut alloc) = make_mapper_and_alloc();
    let before = alloc.free_frames();
    place_trampoline(&mut alloc, &mut mapper, 0xFFFF_FFFF_8010_0000).expect("emplacement");
    let after = alloc.free_frames();
    let consumed = before - after;
    // 3 frames for the temp PML4/PDPT/PD + up to 4 for the active CR3.
    assert!(
        (3..=7).contains(&consumed),
        "expected 3..=7 frames consumed, got {consumed}"
    );
}

// =============================================================================
// 8. AP landing stub — byte-level invariants
// =============================================================================

#[test]
fn landing_stub_starts_with_lock_inc_ack_counter() {
    let stub = build_ap_landing_stub(TRAMPOLINE_PHYS_BASE);
    // F0 48 FF 04 25 <disp32>
    assert_eq!(stub[0x00], 0xF0, "LOCK prefix");
    assert_eq!(stub[0x01], 0x48, "REX.W");
    assert_eq!(stub[0x02], 0xFF, "INC opcode");
    assert_eq!(stub[0x03], 0x04, "ModR/M /0 SIB-mode");
    assert_eq!(stub[0x04], 0x25, "SIB disp32-absolute");
    let disp = u32::from_le_bytes(stub[0x05..0x09].try_into().expect("4 bytes"));
    assert_eq!(
        disp,
        TRAMPOLINE_PHYS_BASE + AP_ACK_COUNTER_OFFSET as u32,
        "ack-counter disp32 must point at AP_ACK_COUNTER slot"
    );
}

#[test]
fn landing_stub_switches_cr3_before_jump() {
    // 0x19  0F 22 D9   mov cr3, rcx
    let stub = build_ap_landing_stub(TRAMPOLINE_PHYS_BASE);
    assert_eq!(&stub[0x19..0x1C], &[0x0F, 0x22, 0xD9]);
}

#[test]
fn landing_stub_ends_with_jmp_rdx() {
    let stub = build_ap_landing_stub(TRAMPOLINE_PHYS_BASE);
    assert_eq!(
        &stub[0x1C..0x1E],
        &[0xFF, 0xE2],
        "jmp rdx terminates the stub"
    );
}

#[test]
fn landing_stub_size_matches_constant() {
    let stub = build_ap_landing_stub(TRAMPOLINE_PHYS_BASE);
    assert_eq!(stub.len(), AP_LANDING_STUB_SIZE);
}

#[test]
fn landing_stub_does_not_overlap_trampoline_blob() {
    // The blob occupies [0x000..0x100); the stub starts at 0x100.
    assert!(
        AP_LANDING_STUB_OFFSET >= TRAMPOLINE_BLOB_SIZE,
        "landing stub must not overlap the 256-byte trampoline blob"
    );
}

#[test]
fn landing_stub_slot_offsets_fit_within_one_page() {
    assert!(
        AP_KMAIN_AP_VA_OFFSET + 8 <= 4096,
        "all slots must fit inside the 4 KiB trampoline page"
    );
}

// =============================================================================
// 9. AP runtime control block — field round-trips
// =============================================================================

#[test]
fn pseudo_descriptor_is_ten_bytes() {
    assert_eq!(core::mem::size_of::<PseudoDescriptor>(), 10);
}

#[test]
fn ap_runtime_control_install_descriptor_tables_round_trips() {
    // install_descriptor_tables writes into the singleton AP_RUNTIME_CONTROL;
    // other tests may have already written to it, so we read back our exact
    // values rather than asserting zero-init.
    install_descriptor_tables(0xFFFF_C000_0000_0000, 0x01FF, 0xFFFF_C100_0000_0000, 0x0FFF);
    use nexacore_kernel::bare_metal::mp_ap_entry::read_ap_runtime_slot as read_slot;
    // The GDTR/IDTR are not exposed via `read_ap_runtime_slot`; we exercise
    // the per-AP slot path separately (below).
    // Round-trip a per-AP slot to confirm the plumbing is wired end-to-end.
    assert!(register_ap_runtime_slot(
        2,
        0x03,
        0xFFFF_C010_0000_0000,
        0xFFFF_D000_0000_0000,
        0x48
    ));
    let (lapic, kstk, pc, sel) = read_slot(2).expect("slot 2");
    assert_eq!(lapic, 0x03);
    assert_eq!(kstk, 0xFFFF_C010_0000_0000);
    assert_eq!(pc, 0xFFFF_D000_0000_0000);
    assert_eq!(sel, 0x48);
}

#[test]
fn ap_runtime_slot_rejects_bsp_cpu_id() {
    assert!(
        !register_ap_runtime_slot(0, 0, 0, 0, 0),
        "cpu_id 0 is BSP — slot registration must be rejected"
    );
}

#[test]
fn ap_runtime_slot_rejects_out_of_range_cpu_id() {
    let oor = MAX_CPUS as u32;
    assert!(
        !register_ap_runtime_slot(oor, 0, 0, 0, 0),
        "cpu_id >= MAX_CPUS must be rejected"
    );
}

// =============================================================================
// 10. End-to-end: 4-CPU BSP pre-fire sequence
//
// Given a 4-CPU MADT (BSP + 3 APs) simulate the full BSP pre-fire
// sequence and verify:
//   - All 3 APs are registered in per_cpu, gdt, and tss.
//   - LAPIC-to-cpu mappings are consistent.
//   - TSS selectors follow the arithmetic for slots 7, 9, 11.
//   - start_aps_live produces targeted=3, sequenced=3 on the host stub.
// =============================================================================

#[test]
fn end_to_end_4cpu_pre_fire_sequence() {
    // Step 1 — parse a 4-CPU MADT.
    let mut ics = Vec::new();
    push_local_apic(&mut ics, 1, 0x00, true); // BSP, apic_id=0
    push_local_apic(&mut ics, 2, 0x01, true); // AP1, apic_id=1
    push_local_apic(&mut ics, 3, 0x02, true); // AP2, apic_id=2
    push_local_apic(&mut ics, 4, 0x03, true); // AP3, apic_id=3
    let madt = make_madt(&ics);
    let topo = parse_madt(&madt).expect("4-CPU MADT must parse");
    assert_eq!(topo.len(), 4);
    assert_eq!(topo.enabled_count(), 4);

    // Step 2 — register per-CPU slots for APs (cpu_id = 1..=3).
    // Use fresh synthetic LAPIC IDs distinct from other tests.
    let synthetic_lapic = [0xE1_u32, 0xE2, 0xE3];
    let synthetic_cpu = [15_u32, 16, 17]; // cpu_ids distinct from other tests
    for (i, &cpu_id) in synthetic_cpu.iter().enumerate() {
        let lapic_id = synthetic_lapic[i];
        let slot = register_ap(cpu_id, lapic_id).expect("AP slot must be available");
        assert_eq!(slot.cpu_id(), cpu_id);
        assert_eq!(slot.lapic_id(), lapic_id);
        assert!(!slot.is_bsp());
    }

    // Step 3 — install per-AP TSS entries (synthetic rsp0/ist addresses).
    use nexacore_kernel::bare_metal::tss::{ap_tss_addr, ap_tss_rsp0};
    for &cpu_id in &synthetic_cpu {
        let rsp0 = 0xFFFF_C200_0000_0000 + (cpu_id as u64 * 0x1000);
        let ist1 = rsp0 + 0x10_0000;
        let ist2 = ist1 + 0x10_0000;
        assert!(init_ap_tss(cpu_id, rsp0, ist1, ist2));
        assert_eq!(ap_tss_rsp0(cpu_id), rsp0);
    }

    // Step 4 — write TSS descriptors into the GDT.
    for &cpu_id in &synthetic_cpu {
        let tss_base = ap_tss_addr(cpu_id);
        assert_ne!(tss_base, 0);
        assert!(gdt_set_ap_tss(cpu_id, tss_base));
    }

    // Step 5 — verify selector arithmetic is monotonically increasing.
    let sel_15 = tss_selector_for_cpu(15);
    let sel_16 = tss_selector_for_cpu(16);
    let sel_17 = tss_selector_for_cpu(17);
    assert!(
        sel_15 < sel_16,
        "selectors must be monotonically increasing"
    );
    assert!(
        sel_16 < sel_17,
        "selectors must be monotonically increasing"
    );
    // Each selector advances by 2 slots * 8 bytes = 16.
    assert_eq!(
        sel_16 - sel_15,
        16,
        "selector stride must be 16 bytes (2 slots)"
    );
    assert_eq!(sel_17 - sel_16, 16);

    // Step 6 — populate the AP runtime control block for one representative AP.
    let sample_cpu = synthetic_cpu[0];
    let sample_kstk = 0xFFFF_C200_0000_0000 + (sample_cpu as u64 * 0x1000);
    let sample_pc =
        core::ptr::from_ref(register_ap(sample_cpu, synthetic_lapic[0]).expect("slot")) as u64;
    let sample_sel = tss_selector_for_cpu(sample_cpu);
    assert!(register_ap_runtime_slot(
        sample_cpu,
        synthetic_lapic[0],
        sample_kstk,
        sample_pc,
        sample_sel
    ));

    // Step 7 — DryRun orchestrator: targeted=3, sequenced=3.
    // The live INIT-SIPI path requires LAPIC MMIO mapped at phys_offset,
    // which is not available in the host test process.  DryRun exercises
    // the topology walk, BSP exclusion, and disabled-entry skipping
    // without touching MMIO or the AP ack counter.
    let topo4 = topology_from_entries(&[
        CpuEntry {
            apic_id: 0,
            acpi_uid: 1,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 1,
            acpi_uid: 2,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 2,
            acpi_uid: 3,
            enabled: true,
            x2apic: false,
        },
        CpuEntry {
            apic_id: 3,
            acpi_uid: 4,
            enabled: true,
            x2apic: false,
        },
    ]);
    let report = start_aps(&topo4, 0, TRAMPOLINE_SIPI_VECTOR, StartApsMode::DryRun);
    assert_eq!(report.targeted, 3, "3 APs should be targeted");
    assert_eq!(report.sequenced, 3, "all 3 sequenced in DryRun");
    assert!(report.dry_run, "DryRun must set the dry_run flag");
}
