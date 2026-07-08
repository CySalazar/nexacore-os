# ADR-0017: e1000e Live Bring-Up (P6.7.9.c / TASK-006)

**Date:** 2026-05-24  
**Status:** Accepted  
**Deciders:** cySalazar  

## Context

TASK-006 requires wiring the e1000e 13-step bring-up FSM with real
MMIO register operations, validated in QEMU. This is the third and
final live driver bring-up in Wave 3 (after virtio-net and NVMe),
and the first bare-metal-only driver (e1000e exposes a full 128 KiB
CSR window, unlike virtio-net's I/O port path).

## Decision

### Kernel-side bring-up (preferred for Phase 1)

The e1000e live bring-up is performed directly in kernel context via
`driver_loader.rs::e1000e_live_bringup()`, following the same pattern
established by the NVMe bring-up (ADR-0016). The function:

1. Maps 32 pages (128 KiB) of BAR0 into a fixed kernel VA
2. Performs volatile MMIO reads/writes for each of the 13 FSM steps
3. Reports progress on the serial console

### Why kernel-side instead of user-space image

The user-space image (`nexacore-driver-e1000e-image`) requires the full
DriverLoad path (capability deposit, spawn_from_elf, MmioMap syscall
handler returning a mapped VA). While the image code is production-ready
and compiles for `x86_64-unknown-none`, the kernel's DriverLoad
mechanism does not yet support 128 KiB BAR mappings in the user-space
page table (only the 4 KiB probe ELF mapping is wired). The kernel-side
approach validates the hardware interaction without requiring the full
user-space DriverLoad chain.

### PHY/MDIC handling

QEMU's e1000e model does not fully implement the MDIC register
(auto-negotiation has no meaningful effect on an emulated link). The
driver treats MDIC timeout as non-fatal on QEMU; production drivers
on real silicon MUST verify auto-negotiation completion.

## Alternatives Considered

1. **User-space image via DriverLoad** — Requires extending the page
   mapper to handle 32-page BAR mappings in user space. Deferred to
   Phase 2.
2. **Skip e1000e, validate only via unit tests** — Rejected; the
   development plan requires live MMIO proof per NCIP-015 § S5.1.

## Consequences

- Wave 3 is complete (all three driver families validated live)
- The e1000e user-space image is ready for production use once
  DriverLoad supports large BAR mappings (Phase 2)
- Risk R4 (no physical e1000e hardware) is documented and accepted
