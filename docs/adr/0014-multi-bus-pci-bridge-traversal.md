# ADR-0014: Multi-Bus PCI Scan with Bridge Traversal (P6.7.9-pre.9)

**Status:** Accepted  
**Date:** 2026-05-24  
**Decision-makers:** cySalazar  
**Context:** P6.7.9-pre.9 — extend PCI enumeration from single-bus to full topology discovery

## Context

P6.7.9-pre.8 introduced a PCI bus 0 scanner that discovers devices on
the root bus only.  Real hardware and advanced virtualised platforms
(multi-socket servers, PCIe switches, SR-IOV) place devices behind
PCI-to-PCI bridges on secondary buses that bus-0-only enumeration
cannot reach.

TASK-004 (virtio-net live bring-up) and TASK-005 (NVMe live bring-up)
will benefit from discovering devices regardless of their bus placement.

## Decision

Implement recursive multi-bus PCI enumeration via PCI-to-PCI bridge
traversal in `bare_metal/pci_scan.rs`:

1. **Bridge detection:** When a device's class code is `0x06` (Bridge
   Device), subclass is `0x04` (PCI-to-PCI), and its header type's low
   7 bits equal `0x01` (Type 1 header), it is a PCI-to-PCI bridge.

2. **Secondary bus discovery:** Read the bridge's configuration register
   at offset `0x18` (Bus Numbers register, Type 1 header).  Bits `[15:8]`
   contain the secondary bus number — the bus on the downstream side.

3. **Recursive scan:** After recording the bridge device, recursively
   enumerate the secondary bus.  Each bridge found on that bus triggers
   another level of recursion.

4. **Depth limit:** Cap recursion at 8 levels (`MAX_BRIDGE_DEPTH`).
   Physical PCI topologies rarely exceed 3-4 levels; 8 provides margin
   while preventing infinite loops on misconfigured bridge chains.

5. **Multi-root-complex support:** Before scanning, check if device
   `(0,0,0)` is multi-function.  If so, treat each function as a
   separate root complex and scan buses 0-7 independently (QEMU/KVM
   multi-socket emulation exposes this pattern).

6. **Capacity increase:** `MAX_DISCOVERED` raised from 32 to 64 to
   accommodate devices across multiple buses.

## Alternatives Considered

- **Flat bus iteration (0..255):** Simple but O(256 × 32 × 8) = 65536
  config reads even on empty buses.  Bridge traversal only visits
  populated buses — typical topology touches 1-3 buses total.

- **ACPI MCFG-based ECAM enumeration:** The correct long-term approach
  for PCIe, but requires ACPI table parsing and MMIO-based config access.
  Deferred to Phase 2 when the ACPI subsystem is fully operational.

## Consequences

- The driver loader now calls `scan_all_buses()` and logs bus count,
  bridge count, and per-device bus number.
- `PciDevice` gains a `header_type` field and an `is_pci_bridge()` method.
- `ScanResult` gains `buses_scanned()`, `bridges_found()`, and
  `find_by_class()` accessors.
- The legacy `scan_bus_0()` entry point is preserved as a thin wrapper
  around `scan_all_buses()` for backward compatibility.
- On the Proxmox test VM (single-bus Q35 topology), behaviour is identical
  to pre.8 — bus 0 is scanned, no bridges are found, same device set.
- 6 new unit tests added; workspace total rises from 1707 to 1713.
