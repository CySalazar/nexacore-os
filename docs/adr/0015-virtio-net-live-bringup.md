# ADR-0015: virtio-net Live Bring-Up via Legacy I/O Ports (P6.7.9-pre.10)

**Status:** Accepted  
**Date:** 2026-05-24  
**Decision-makers:** cySalazar  
**Context:** P6.7.9-pre.10 / TASK-004 — first live interaction with the virtio-net hardware

## Context

P6.7.9-pre.9 introduced multi-bus PCI scanning which discovered the
virtio-net device (1AF4:1000, transitional) on bus 06 behind PCIe
bridges on the Proxmox test VM.  TASK-004 requires demonstrating live
device initialization.

The transitional virtio-net device (device ID 0x1000) exposes a
legacy I/O port interface via BAR0 per virtio 1.0 § 4.1.  BAR0 on
the Proxmox VM is `0x00006081` (I/O space, port base `0x6080`).

## Decision

Perform the full virtio-net bring-up sequence via legacy I/O ports
directly from Ring 0 in the driver loader, before spawning the
capability probe ELF.  The sequence follows virtio 1.0 §§ 3.1–3.2:

1. **Reset** — write 0 to device_status (offset 0x12), read back 0.
2. **Acknowledge** — write `ACKNOWLEDGE` (0x01).
3. **Driver** — write `ACKNOWLEDGE | DRIVER` (0x03).
4. **Feature negotiation** — read device_features (offset 0x00),
   write back as driver_features (accept all).
5. **Features OK** — write `ACKNOWLEDGE | DRIVER | FEATURES_OK` (0x0B),
   read back and verify `FEATURES_OK` bit retained.
6. **Read MAC** — read 6 bytes from offset 0x14.
7. **Driver OK** — write full status with `DRIVER_OK` (0x0F); device
   is live.

PCI Command register updated to enable I/O Space + Memory Space +
Bus Master (`cmd | 0x0007`) via new `enable_device_full()`.

## Alternatives Considered

- **Modern virtio PCI transport (BAR4 MMIO):** Requires PCI capability
  list parsing to locate the Common Config structure within a memory
  BAR.  More complex; deferred to a follow-up when the driver image
  owns the bring-up.

- **Ring 3 driver image bring-up:** The ideal long-term approach, but
  requires I/O port syscalls (`IoPortRead`/`IoPortWrite`) or the modern
  MMIO transport.  This pre-step proves the device is accessible and
  responsive before wiring the user-space path.

## Consequences

- Serial log now shows the complete virtio-net bring-up sequence with
  status register readings, device features, and MAC address.
- `pci_scan.rs` gains `bar_is_io()`, `bar_io_base()`, and
  `enable_device_full()` for I/O BAR handling.
- The driver loader finds virtio-net by exact vendor+device ID
  (1AF4:1000 or 1AF4:1041) across all buses, not just the first
  VirtIO device on bus 0.
- 2 new unit tests; workspace total rises from 1713 to 1715.
