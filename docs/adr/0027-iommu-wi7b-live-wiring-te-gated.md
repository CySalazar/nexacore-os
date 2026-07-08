# ADR-0027: IOMMU Live Wiring with TE Operator-Gated (WI-7b step 2)

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar (operator gate on `GCMD.TE` stands — ADR-0026, PLAN TASK-07 deviation log)
**Refs:** PLAN.md TASK-07, NCIP-026 WI-7b, ADR-0024 (M0 datapath), ADR-0026 (WI-7a SLPT builder),
`bare_metal/iommu/{vtd.rs,mod.rs}`, `bare_metal/{driver_loader.rs,syscall_entry.rs}`

## Context

WI-7a (ADR-0026) delivered a host-tested VT-d second-level page-table (SLPT)
builder but deliberately left it **unwired**: `VtdBackend::map` kept recording
`(iova→phys)` tuples in a `Vec`, the M0 drivers' deposit-path spawn performed
no IOMMU binding at all, and `GCMD.TE` stayed off. WI-7b step 1 then read
`CAP.SAGAW` from the live unit on the test VM (`sagaw=6` → highest AGAW 48-bit /
4-level), confirming the width every context entry and SLPT build must use.

The remaining gap to a safe TE flip was the wiring itself:

1. `DmaMap (71)` never built SLPT entries — a TE flip would fault every
   legitimate DMA window (empty trees).
2. The M0 drivers (virtio-net; ADR-0024) spawn via
   `boot_load_virtio_net_image` → `spawn_driver_and_deposit`, **not** via
   `DriverLoad (73)` — so they got no domain, no attach, no context entry.
3. The `DriverLoad` path **auto-flipped TE** after the first successful
   context-entry install (P6.7.9-pre.11 behaviour) — a landmine: any future
   `DriverLoad` call would have raised TE outside the operator-gated session.
4. `enable_translation` wrote `GCMD = TE` alone. GCMD mixes one-shot command
   bits with level-sensitive **enable** bits; per Intel VT-d rev 4.1 § 11.4.4
   software must preserve the enable bits on every GCMD write. A
   spec-conforming implementation (QEMU `intel-iommu` included) interprets
   `TE`-only as "TE := 1 **and QIE := 0**" — silently disabling the
   invalidation queue at the exact moment translation starts, after which
   every queued invalidation times out.
5. `IommuBackend::flush` was a no-op — but QEMU advertises `CAP.CM = 1`
   (caching mode), under which even not-present → present SLPT transitions
   must be invalidated once TE is up.
6. `DomainPageTables::release` freed only the root frame; with the builder
   wired, intermediate SLPT tables would leak on driver teardown.

ADR-0026 had rejected "wire now" with the rationale *zero functional gain
until TE is raised*. That trade-off inverted once WI-7b started: the
operator-gated TE session becomes drastically safer if every wiring change is
already landed, hardware-exercised (with TE off) and M0-verified, leaving the
session a single-bit flip plus the §S9.1 tests.

## Decision

Land the full live wiring now, with translation enable **excluded by
construction**:

1. **`VtdBackend::{map_with_src, unmap_with_src}`** — the `dma_map`-facing
   surface. With a provisioned domain root they build/clear the real SLPT via
   the WI-7a walker (`map_range_slpt` / `unmap_4k_slpt`), allocating
   intermediates from a threaded `FrameSource`; without one they degrade to
   the legacy bookkeeping-only behaviour. Width = live `CAP.SAGAW`, fallback
   `Bits48Level4` (same default as the device-entry install — AGAW and tree
   depth cannot disagree). A failed build records no bookkeeping entry.
2. **`iommu_map_window` / `iommu_unmap_window`** (mod.rs) — vendor dispatch:
   Intel routes to the SLPT path; AMD-Vi/passthrough stay bookkeeping-only
   (no AMD substrate in the test loop — ADR-0026). `DmaMap (71)` and
   `tear_down_dma_mappings` now call these with a `KernelFrameSource`.
3. **Boot deposit-path IOMMU bind** (`bind_driver_iommu_domain` in
   `driver_loader.rs`) — mirror of the `DriverLoad` bind block:
   `install_domain` → per-BDF `attach_device` (+ `pcb.bound_pci_devices` for
   teardown) → `provision_domain_pt` → live VT-d context-entry / AMD-Vi DTE
   install sized to live SAGAW. `boot_load_virtio_net_image` now declares the
   scanned BDF as `Resource::PciDevice`, so the M0 virtio-net driver gets the
   full binding at every boot. No-PCI spawns (DEV-ONLY probe) skip the block.
4. **TE flip behind cargo feature `iommu-te` (default OFF).** The
   `DriverLoad` auto-flip is compiled out unless the operator builds with the
   feature; with it off, a log line (`TE gated off (iommu-te)`) makes the
   held gate observable in hardware captures. The boot deposit path contains
   **no** TE call at all.
5. **`enable_translation` writes `GCMD = TE | QIE`** — preserving the
   queued-invalidation enable per § 11.4.4 (fixes the latent QIE-drop).
6. **Live `flush`** — submits a per-domain IOTLB invalidate descriptor
   through the invalidation queue when the unit is activated (the
   `phys_offset` is cached at `activate_hardware`; the trait signature is
   unchanged). Host/dormant backends keep the no-op.
7. **`release_domain_pt` frees the whole subtree** (`free_slpt_subtree`)
   before the registry releases the root — closes the intermediate-table
   leak. Leaf targets (the driver's DMA buffer frames) are never freed by
   the walk; they belong to `tear_down_dma_mappings`.

With TE off, all of this is behaviourally inert for the devices (hardware
stays in passthrough) while being **live-exercised**: every boot now writes
real root/context entries, pumps context-cache + IOTLB invalidation
descriptors through the queue, and populates per-domain SLPTs on `DmaMap` —
all observable on the test VM serial with the M0 smoke unchanged.

## Alternatives Considered

- **Keep everything for the TE session (status quo of ADR-0026):** maximises
  the blast radius of the riskiest session — wiring bugs (context-entry
  encoding, IQ interaction, frame accounting) would surface only with TE up,
  i.e. as a bricked M0. Rejected: land and hardware-verify everything
  reversible first; leave only the irreversible bit for the gated session.
- **Runtime kill-switch instead of a cargo feature:** no kernel cmdline
  infrastructure exists, and a runtime flag would put the policy decision in
  mutable state. A compile-time feature is auditable in the build hash and
  cannot be toggled by a compromised component.
- **Flip TE automatically once per-domain SLPTs are populated:** rejected —
  per the operator's explicit gating decision (PLAN TASK-07 deviation,
  2026-06-06) and NCIP-026 §S9.1, which requires the negative DMA test in the
  same session as the flip.
- **Wire AMD-Vi I/O page tables too:** still no AMD hardware/emulation in
  the loop; the entry layout differs (Next-Level field). Deferred unchanged
  from ADR-0026.
- **Per-unmap subtree reaping instead of wholesale free at release:**
  refcount bookkeeping per level for no Phase-1 benefit; the domain root
  release is the natural quarantine point. Unchanged from ADR-0026.

## Consequences

- The operator-gated WI-7b session shrinks to: build with `iommu-te`, boot,
  run §S9.1 negative (out-of-window DMA → fault report, system stable) and
  positive (virtio-net + NVMe confined, M0 + NVMe IO re-verified) tests.
- Two latent hardware bugs are fixed **before** they could brick that
  session: the GCMD QIE-drop (§ 11.4.4) and the missing CM=1 invalidations.
- `DmaMap` now allocates SLPT intermediate frames per driver process
  (bounded: ≤ 3 intermediates per 512-page subtree at 4-level); they are
  returned wholesale at driver teardown via `free_slpt_subtree`.
- Boot logs gain `[driver-loader] virtio-net iommu domain attached did=…`
  and `… iommu ctx-entry installed (TE off)` lines — the hardware capture
  proves the wiring runs and the gate holds (`translation enabled` grep = 0).
- The `iommu-te` feature is the single, auditable switch for the most
  dangerous bit in the kernel; CI never enables it.
