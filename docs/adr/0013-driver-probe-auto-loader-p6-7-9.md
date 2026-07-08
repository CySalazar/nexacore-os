# ADR-0013: DEV-ONLY Driver Probe Auto-Loader (P6.7.9-pre.8)

**Status:** Accepted  
**Date:** 2026-05-24  
**Decision-makers:** cySalazar  
**Context:** P6.7.9.a — first driver to exercise the full syscall path (capability deposit + MmioMap/DmaMap/IrqAttach)

## Context

Phase 1 milestone P6.7.9 requires live driver bring-up: a Ring 3
user-space process that discovers capability tokens deposited by the
kernel and issues MmioMap (70) / DmaMap (71) / IrqAttach (72) syscalls
against real PCI device resources.

The infrastructure is fully implemented:
- `DriverLoad (73)` syscall handler (decode pack, verify manifest, spawn ELF, deposit tokens)
- `MmioMap / DmaMap / IrqAttach` syscall handlers (scope verification, page-table install)
- `nexacore-driver-shared` SDK (deposit window parser)
- `cap_deposit.rs` (token minting and deposit encoding)
- `nexacore-driver-pack` build tool (NexaCore-Pack v1 blob builder)

What is missing is the **glue**: PCI bus enumeration, device discovery,
and a boot-time trigger that loads the first driver.

## Decision

### 1. PCI bus scanner (`bare_metal/pci_scan.rs`)

Add a Type 1 configuration space scanner using the existing CF8/CFC
I/O port helpers in `arch/x86_64.rs`. Phase 1 scans bus 0 only
(32 devices × 8 functions). Returns `ScanResult` with discovered
vendor/device IDs, BAR addresses, and interrupt lines.

### 2. DEV-ONLY auto-loader (`bare_metal/driver_loader.rs`)

A kernel-internal auto-loader that runs in `kmain` after IOMMU init
and before the desktop. It:
1. Scans PCI bus 0 for devices.
2. Spawns a hand-crafted probe ELF (248 bytes, same pattern as
   `userprobe_mb12.rs`) that reads the deposit window, finds the
   MmioMap token, and issues the MmioMap syscall.
3. Deposits capability tokens (MmioMap, DmaMap, IrqAttach) with
   scopes matching the discovered PCI device's BAR address.
4. The probe process runs when the LAPIC timer preempts kmain into
   the scheduler dispatch loop.

### 3. KNOWN_ISSUERS populated with DEV-ONLY key

The Ed25519 verifying key derived from `DRIVER_CAP_ISSUER_SEED`
(the fixed `0xCAFEBABE` pattern) is added to the `KNOWN_ISSUERS`
table so `verify_manifest` passes for DEV-ONLY driver packs.

## Alternatives considered

1. **Embed the actual `nexacore-driver-net-virtio-image` ELF**: Requires
   a two-step build (driver image first, then kernel) and
   `include_bytes!` with build.rs cfg detection. More realistic but
   adds build-chain fragility. Deferred to TASK-004 follow-up.

2. **User-space init process**: A proper init process that calls
   DriverLoad for each driver. Architecturally correct but requires
   a new crate, IPC scaffolding, and a bootable init ELF. Planned
   for Phase 2.

3. **Skip the probe and test via `nexacore-driver-pack` + `DriverLoad`
   from kmain**: Would exercise the full DriverLoad ceremony but
   requires constructing the pack in kernel memory, which duplicates
   the offline `nexacore-driver-pack` tool's logic.

## Consequences

- The PCI scanner is reusable for all subsequent driver bring-up
  (NVMe, e1000e).
- The auto-loader pattern validates the complete
  spawn → deposit → MmioMap path in a controlled boot-time sequence.
- KNOWN_ISSUERS is no longer empty; `phase1_table_is_empty` test is
  replaced with `dev_only_issuer_is_present`.
- Exit sentinel codes from the probe (0, 10, 40+e) provide
  unambiguous triage via the serial console.
