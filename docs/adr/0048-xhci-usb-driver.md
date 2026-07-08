# ADR-0048: xHCI Driver + USB Enumeration from Ring 3 (TASK-26, DE-E1+E2)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-26
**Refs:** PLAN.md TASK-26 (DE-E1+E2, M5), ADR-0036/0037 (NVMe driver, the
template), ADR-0027/0028 (IOMMU domains, TASK-07), ADR-0035 (full-clobber
syscall ABI), `crates/nexacore-driver-nvme*`, `crates/nexacore-kernel/src/bare_metal/
driver_loader.rs`, `crates/nexacore-driver-shared`

## Context

The Live USB (M5) and any real desktop need USB input/storage, which requires an
**xHCI** (USB 3.x host controller) driver. There is none yet (no `nexacore-driver-
xhci`, no USB types). This ADR covers DE-E1 (controller bring-up) + DE-E2 (hub /
device enumeration); USB **class** drivers (HID keyboard/mouse, mass storage)
are TASK-27.

The NVMe driver is the proven template (recon, file:line-cited):
- **Boot-spawn, not signed `DriverLoad`.** `driver_loader.rs` scans PCI
  (`find_by_class(class, subclass)`), enables the device (IOSE+MSE+BME), then
  `ProcessControlBlock::spawn_from_elf` (the image from initramfs) +
  `cap_deposit::deposit_for_driver` mints MMIO/DMA/IRQ tokens at the well-known
  deposit VA `0x0010_0000`. The signed-manifest `DriverLoad(73)` route (Ed25519,
  `KNOWN_ISSUERS`) is the FUTURE userspace path; the kernel boot-spawn trusts
  initramfs. xHCI follows the boot-spawn path.
- **Image pattern** (`nexacore-driver-nvme-image`): `_start` →
  `nexacore_driver_shared::caps::find_token(ACTION_TAG_MMIO_MAP/DMA_MAP, ..)` →
  `MmioMap(70)` (BAR → user VA) → `DmaMap(71)` (dual-address: CPU IOVA + device
  phys) per ring/buffer page → bring up controller → service/idle loop.
  `PanicOnAlloc` global allocator (stack-only; rings/buffers live in the DMA
  arena). Full-clobber `syscall5` stub (ADR-0035).
- **Rings**: `SqRing`/`CqRing` pure-state math (capacity, tail/head, phase/cycle
  bit toggled on wrap); `MmioBackend` trait for doorbell/register writes;
  device-written data is UNTRUSTED and bounds-checked.

## Decisions

### D1 — Two crates, mirroring NVMe

- `crates/nexacore-driver-xhci/` — host-testable `no_std` lib (the unit-test
  surface): register definitions, TRB types + Command/Event/Transfer ring state,
  DCBAA + slot/endpoint context layout, USB descriptor parsing, and the
  enumeration state machine. Pure logic + a `MmioBackend`-style seam so it tests
  on the host without hardware.
- `crates/nexacore-driver-xhci-image/` — the Ring-3 ELF: `_start` brings the
  controller up over live MMIO/DMA, runs enumeration, logs the enumerated
  device's VID/PID, then idles. `PanicOnAlloc`, full-clobber syscalls.

### D2 — Kernel boot-spawn (same authority path as NVMe)

`driver_loader.rs` gains an xHCI block: `find_by_class(XHCI_CLASS=0x0C,
XHCI_SUBCLASS=0x03)` (prog_if `0x30`), enable the device, `spawn_driver_and_
deposit` with caps scoped to **the xHCI BAR** (MMIO), a **DMA window** (rings +
contexts + buffers, e.g. the `0x0100_0000_0000` arena), and the **MSI-X IRQ**.
A `manifest.toml` is added for parity with NVMe / the future signed path, but is
not consulted at boot-spawn. The image is added to `build-shell-initramfs.sh`
ENTRIES and the root `Cargo.toml` workspace (image excluded from host tests).

### D3 — Controller bring-up sequence (xHCI §4.2)

Over the mapped BAR (Capability regs → `CAPLENGTH`/`HCSPARAMS1`/`HCCPARAMS1`/
`DBOFF`/`RTSOFF`; Operational at +CAPLENGTH; Runtime at +RTSOFF; Doorbells at
+DBOFF): (1) wait `USBSTS.CNR`=0; (2) `USBCMD.HCRST`=1, poll until clear +
`USBSTS.CNR`=0; (3) program `CONFIG.MaxSlotsEn` from `HCSPARAMS1`; (4) allocate
+ set **DCBAAP** (Device Context Base Address Array); (5) allocate the **Command
Ring**, set **CRCR** (with RCS cycle bit); (6) allocate the **Event Ring** +
**ERST**, program interrupter 0 (`ERSTSZ`/`ERSTBA`/`ERDP`, `IMAN.IE`); (7)
`USBCMD.R/S`=1 (run), poll `USBSTS.HCH`=0. All register widths/volatile per spec.

### D4 — Rings + contexts in the DMA arena (16-byte TRBs, cycle bit)

TRBs are 16 bytes. Command Ring (driver-produced, device-consumed, a Link TRB
wraps it), Event Ring (device-produced; the driver tracks the **cycle bit**, a
phase toggle identical to NVMe's CQ phase, and advances **ERDP**), and per-
endpoint Transfer Rings. DCBAA + 32/64-byte slot/endpoint contexts (size per
`HCCPARAMS1.CSZ`) live in DMA pages. Each is a separate `DmaMap` page (device
phys for the controller, CPU IOVA for the driver), all inside the granted IOMMU
window — no DMA outside it.

### D5 — Enumeration state machine (xHCI §4.3, USB §9)

Per powered root-hub port (count from `HCSPARAMS1.MaxPorts`): (1) detect
connect (`PORTSC.CCS`); (2) reset (`PORTSC.PR`, wait `PRC`); (3) **Enable Slot**
command → slot id; (4) build the slot+EP0 context (route/speed/port), allocate
EP0's Transfer Ring, set DCBAA[slot]; (5) **Address Device** command (issues the
USB `SET_ADDRESS`); (6) **GET_DESCRIPTOR(Device)** as a control transfer on EP0
(SETUP/DATA/STATUS TRBs) → read the 18-byte device descriptor → **log
idVendor/idProduct**; (7) GET_DESCRIPTOR(Configuration) for the config/interface/
endpoint descriptors (feeds TASK-27 class drivers). External-hub topology
(multi-tier) is minimal/deferred; root-hub ports are the TASK-26 acceptance.

### D6 — Descriptor parsing is untrusted-input-hardened (security)

Every descriptor (device/config/interface/endpoint) and every event/transfer
TRB the device writes is parsed with explicit length + `bLength`/`wTotalLength`
bounds checks; a malformed/short/over-long descriptor returns a typed `Err`
(never a panic, never an over-read), exactly the discipline the acceptance names
("descriptor malformati → errore"). Unknown descriptor types are skipped by
their `bLength`. The enumeration state machine has per-step timeouts so a silent
device cannot hang the driver.

### D7 — Allocator + isolation

`PanicOnAlloc` (stack-only) like NVMe — all rings/contexts/buffers live in the
DMA arena, sized at compile time. DMA is confined to the granted IOMMU window;
MMIO is confined to the granted BAR (the kernel cap scopes enforce both). No
heap, so no allocator-OOM class of bug (cf. TASK-24).

### D8 — TASK-26 scope boundary

In scope: controller bring-up, root-hub port enumeration, address assignment,
device + configuration descriptor read (VID/PID logged). Out of scope (TASK-27):
class drivers (HID, mass storage), bulk/interrupt transfer endpoints, and a
USB-device **service channel** in `nexacore-types` (enumeration logs to the console
for TASK-26; a `usb` channel module lands when a class driver needs it).

## Alternatives considered

- **Signed `DriverLoad(73)` at boot** — deferred: the kernel boot-spawn (NVMe's
  path) is what works today; signing is the future userspace-init route.
- **One mega-crate** — rejected: the lib/image split is what makes the rings +
  descriptor parsing + state machine host-testable (the unit acceptance), as
  NVMe proved.
- **Full external-hub topology now** — deferred: root-hub enumeration meets the
  acceptance; multi-tier hubs are a follow-up.
- **A USB service channel + class drivers now** — that is TASK-27; TASK-26 stops
  at enumeration + descriptor logging.

## Consequences

- New `nexacore-driver-xhci` (host-tested: TRB/ring layout, descriptor parsing incl.
  malformed → error, enumeration state machine) + `nexacore-driver-xhci-image`.
- `driver_loader.rs` xHCI boot-spawn block + `pci_scan` xHCI class constants;
  `build-shell-initramfs.sh` + root `Cargo.toml` updated; a `manifest.toml`.
- the test VM: add a `qemu-xhci` controller + a `usb-kbd` test device; the controller
  initializes and the device is enumerated with its VID/PID in the serial log,
  `Page Fault = 0` (verbatim capture).
- External-hub topology, USB class drivers + a `usb` service channel, and the
  signed `DriverLoad` path are tracked follow-ups (TASK-27+).

## Verification appendix — TASK-26 CLOSED (2026-06-08)

Implemented in two phases (Phase 1 host-testable lib `nexacore-driver-xhci`, 164
tests; Phase 2 Ring-3 image `nexacore-driver-xhci-image` + kernel boot-spawn — agent
team), then hardware-brought-up + debugged in-session. **VERIFIED on the test VM**
(a `qemu-xhci` controller + a `usb-kbd` test device), `Page Fault = 0`.

Host tests: `nexacore-driver-xhci` 164 (120 unit + 44 doctests) — TRB encode/decode
+ cycle bit, ring wrap/Link-TRB/cycle-toggle + event-ring cycle-gated dequeue,
descriptor parsing happy-path + malformed (too short / bad bLength / wrong type /
truncated / over-long → typed `Err`, no panic), and the enumeration state machine
(full PortReset→EnableSlot→AddressDevice→GetDeviceDescriptor→Enumerated + timeout
/ failure paths).

the test VM (verbatim serial):

```
[driver-loader] xhci MMIO scope phys=0000384000004000 len=10000 dma=hi+32KiB
[driver-loader] xhci spawned  task_id=7
[driver-loader] xhci iommu domain attached  did=7
[xhci] CAPLENGTH=0x40 MaxSlots=0x40 MaxPorts=0x08 CSZ=32
[xhci] CNR cleared
[xhci] HCRST complete
[xhci] Event Ring + ERST programmed
[xhci] controller running (HCH=0)
[xhci] device on port 0x05 PORTSC=0x00020ee1
[xhci] port reset complete port=0x05
[xhci] Enable Slot submitted
[xhci] Address Device submitted slot=0x01
[xhci] GET_DESCRIPTOR submitted slot=0x01
[xhci] enumerated device VID=0x0627 PID=0x0001 slot=0x01
```

`VID=0x0627 PID=0x0001` is the QEMU USB Keyboard — the device is correctly
enumerated (DE-E2), on a fully brought-up controller (DE-E1), zero #PF.

### Bring-up findings (xHCI gotchas, all fixed in-session)

1. **Event TRB type constants swapped.** The lib had Port-Status=33 /
   Command-Completion=34 / Transfer=35; the xHCI spec (Table 6-91) is
   Transfer=**32**, Command-Completion=**33**, Port-Status=**34**. The driver
   consumed a Port Status Change Event as a (zero-code) Command Completion →
   `Enable Slot` "failed" with code 0. Fixed the constants + the asserting test.
2. **Port Status Change Events interleave.** The port reset queues a Port Status
   Change Event ahead of the command completion; the image's event loop now
   drains those (they are not command/transfer completions) so the `Enumerator`
   only sees the events it expects.
3. **Setup Stage TRB length (the hard one).** The `setup_stage_trb` set the TRB
   Transfer Length to wLength (18); per xHCI §6.4.1.2.1 a Setup Stage TRB with
   IDT=1 carries the always-8-byte setup packet, so the length field MUST be 8.
   With 18, qemu-xhci **silently rejected the entire control TD — no Transfer
   Event at all** (EP0 was Running, dequeue ptr + cycle matched; the malformed
   length was the only fault). Localised by dumping USBSTS + the output EP0
   context EP-State + the EP0 dequeue pointer + the posted SETUP cycle bit, all
   of which were correct — isolating the fault to the SETUP TRB contents. Fixed
   to a fixed length of 8.

External-hub topology, USB class drivers (HID/storage) + a `usb` service
channel, MSI-X interrupts (vs the cooperative event-ring poll), and the signed
`DriverLoad` path are tracked follow-ups (TASK-27+).
