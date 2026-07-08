# ADR-0024: M0 NIC Datapath — Ring 3 virtio-net Driver Is Canonical

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar
**Refs:** PLAN.md TASK-04, todo-desktop.md CHECKPOINT 15/18/20 (anomaly #2), CHECKPOINT 23

## Context

`nexacore-net` resolves the interface `virtio0` at startup
(`[nexacore-net] virtio0 present at startup` on every the test VM boot), but the
CHECKPOINT 15/18/20 audits "found no non-test registrant" for it in the
kernel, leaving the M0 NIC datapath formally undecided between:

(a) the in-kernel legacy-I/O bring-up that already runs at boot
    (`[virtio-net] RESET → ACK → DRIVER → FEAT → READY` serial lines), or
(b) the Ring 3 driver process with kernel-deposited capability tokens.

TASK-05 (M0 E2E to Ollama) must know which path carries frames.

## Root cause of the `virtio0` registration (anomaly #2 — resolved)

The earlier audits searched **kernel** sources only. The registrant is in
**userspace**, reached via syscall — the full chain, with exact locations:

1. **Registrant:** `crates/nexacore-driver-net-virtio-image/src/main.rs:1616-1624`
   — Step 8 of the driver image's `_start`: `net_register(IFACE_NAME, …)` with
   `IFACE_NAME = b"virtio0"` (`main.rs:302` region), passing its freshly
   created `cmd_ch` + `evt_ch` and the device MAC. This call already existed
   at CHECKPOINT 20 (`c807769`: then `main.rs:269`/`645`).
2. **Syscall entry:** `NetRegister (100)` handler,
   `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs:3338` →
   `net_registry_mut().register(iface_name, channel_id, event_channel_id,
   mac, caller)` — the **only** mutable registration site in the kernel
   (verified by grep over all `net_registry_mut()` callers; the others are
   `unregister` and `clear_for_owner`).
3. **Registry:** `crates/nexacore-kernel/src/services/net.rs:293` (`register`),
   exact-match lookup at `:378` (`lookup_interface`).
4. **Spawn site:** `crates/nexacore-kernel/src/lib.rs:1688-1767` — kmain spawns
   `/bin/nexacore-driver-net-virtio` (initramfs) at `System` priority AFTER the
   DEV probe loader and BEFORE `nexacore-net`, depositing its
   `MmioMap`/`DmaMap`/`IrqAttach` capability tokens
   (`boot_load_virtio_net_image`, `driver_loader.rs:669` region).

The in-kernel `virtio_net_live_bringup` (`driver_loader.rs:879`) registers
**nothing**: it enables the PCI command bits (IOSE+MSE+BME), walks the legacy
I/O status dance, and reads the MAC — then the Ring 3 driver **resets and
re-initialises** the same device through its modern-MMIO capability mappings
and owns the virtqueues from that point on.

## Decision

**The Ring 3 virtio-net driver image is the canonical M0 NIC datapath**
(option (b)'s process model). Frames flow:

```
netcheck (Ring 3) → NET syscalls → kernel 2-channel relay → nexacore-net (Ring 3)
   → cmd_ch/evt_ch IPC → nexacore-driver-net-virtio (Ring 3) → virtqueues → wire
```

This is not aspirational — the M0 TCP handshake to `127.0.0.1:11434`
already runs through this chain (verified on the test VM, CP21/CP22 captures).

Consequences for the in-kernel bring-up:

- `virtio_net_live_bringup` is declared **non-datapath**: its load-bearing
  effects are PCI enable (IOSE+MSE+BME — the Ring 3 driver has no PCI-config
  capability) and boot diagnostics (BAR/feature dumps). Its legacy status
  dance (`DRIVER_OK` via I/O ports) is redundant — the Ring 3 driver resets
  the device immediately after — and is kept only because removing it now
  would churn the verified M0 boot before TASK-05 closes. It is slated for
  reduction to PCI-enable + dump when NCIP-026 WI-7 moves bus-master gating
  to IOMMU domain attach (TASK-07).

Loading mechanism (the second half of option (b)):

- For M0, the driver continues to load via **boot-spawn + capability
  deposit** from the initramfs. The initramfs is embedded in the kernel
  image via `include_bytes!` — the binary sits in the same trust and
  measurement domain as the kernel itself, so a signed manifest adds no
  authenticity the embedding does not already provide. Capability tokens
  are already signed with the per-boot secret issuer key (NCIP-026 WI-6)
  and pinned at use (WI-3).
- **Signed `DriverLoad (73)` becomes mandatory the moment any driver binary
  is loaded from outside the embedded initramfs** — i.e. from mutable
  storage at M2 (TASK-15 root-from-disk) and for every new driver that
  follows the TASK-26 pattern (xHCI: "manifest firmato, `DriverLoad(73)`").
  The syscall path, `tools/nexacore-driver-pack`, and the deposit-window
  verification (P6.7.8.9) already exist; the migration is wiring, not new
  machinery, and is deliberately NOT done in TASK-04 to keep the datapath
  stable for TASK-05 (see PLAN.md deviation log 2026-06-06).

## Alternatives Considered

- **(a) In-kernel datapath:** rejected. It contradicts the microkernel
  architecture and NCIP-026's posture (drivers in Ring 3 with confined
  capabilities, R2 DMA confinement via WI-7), would put frame processing in
  Ring 0, and would discard the working, hardware-verified Ring 3 chain.
- **(b) with immediate `DriverLoad (73)` migration:** rejected *for this
  task* on risk sequencing: it changes the loader of the exact component
  TASK-05's E2E proof depends on, while providing no additional authenticity
  for an initramfs-embedded binary (same trust domain as the kernel). The
  migration point is bound above instead of left open.
- **Removing `virtio_net_live_bringup` now:** rejected — its PCI-enable is
  load-bearing for the Ring 3 driver's DMA (BME), and the WI-7 IOMMU work
  (TASK-07) is the natural place to re-home bus-master gating.

## Consequences

- TASK-05 builds on the existing chain unchanged: no loader churn, no
  registration collision (single registrant, single registration site).
- The `[virtio-net] … READY status=0F` serial lines must be read as
  *diagnostics of a transient init that the Ring 3 driver supersedes*, not
  as the datapath — documented at the function site.
- A future failure to spawn the driver image degrades exactly as designed:
  `nexacore-net` reports `virtio0 not yet registered; will retry in service
  loop` and the boot continues.
