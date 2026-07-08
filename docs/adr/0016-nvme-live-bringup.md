# ADR-0016: NVMe Live Bring-Up via MMIO (P6.7.9-pre.11)

**Status:** Accepted  
**Date:** 2026-05-24  
**Decision-makers:** cySalazar  
**Context:** P6.7.9-pre.11 / TASK-005 — first live interaction with NVMe hardware

## Context

TASK-005 requires demonstrating live NVMe controller initialization
on the Proxmox test VM.  The VM was extended with a QEMU NVMe device
(`-device nvme,serial=NexaCore-NVME0`) backed by an 8 MiB raw disk image.

NVMe uses MMIO (BAR0) rather than I/O ports.  The kernel's physical
memory direct-map (`phys_offset + bar0_phys`) provides Ring 0 access
to the controller registers.

## Decision

Perform the NVMe bring-up sequence directly from Ring 0 in the
driver loader via volatile MMIO reads/writes through the direct-map.
The sequence follows NVMe 1.4 § 3.1:

1. **Read CAP** — identify controller capabilities (MQES, timeout).
2. **Read VS** — identify NVMe version.
3. **Read CSTS** — check initial controller status.
4. **Disable** — clear `CC.EN`, poll `CSTS.RDY = 0`.
5. **Program CC** — set `IOSQES = 6` (64B), `IOCQES = 4` (16B),
   `MPS = 0` (4 KiB pages), `CSS = 0`, `AMS = 0`.
6. **Enable** — set `CC.EN`, poll `CSTS.RDY = 1` with `CFS` tripwire.
7. **Verify** — read final `CSTS` confirming `RDY=1`, `CFS=0`.

The driver loader finds the NVMe device by PCI class+subclass
(01:08) via `find_by_class()` — works regardless of vendor ID.

## Alternatives Considered

- **Ring 3 driver image with MmioMap syscall:** The production path,
  already implemented in `nexacore-driver-nvme-image` (P6.7.10 series).
  The Ring 0 approach here proves hardware access works before
  involving the full driver framework.

## Consequences

- Serial log shows NVMe controller CAP, VS, disable/enable cycle
  with poll counts, and final CSTS.
- the Proxmox test VM config extended with NVMe device (QEMU `-device
  nvme`); the 8 MiB test disk is ephemeral at `/tmp/nvme-test.img`.
- Same architectural pattern as ADR-0015 (virtio-net): kernel-side
  hardware validation before full driver-image wiring.
