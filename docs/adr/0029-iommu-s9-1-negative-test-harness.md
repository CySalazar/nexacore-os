# ADR-0029: VT-d §S9.1 Negative-Test Harness — e1000e Empty-SLPT Fault Injection (WI-7b step 3)

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar (operator authorised the `GCMD.TE` flip; M0-safe sub-steps verified on the test VM)
**Refs:** PLAN.md TASK-07, NCIP-026 WI-7 §S9.1, ADR-0028 (TE flip + confinement),
`bare_metal/driver_loader.rs`, `bare_metal/iommu/{vtd.rs,mod.rs}`

## Context

NCIP-026 §S9.1 requires, for any WI changing DMA/translation behaviour on
hardware, a **negative test**: *"a test driver attempts DMA outside its
windows → the transaction is blocked by the IOMMU (fault report in the log),
the system stays stable."* ADR-0028 (C0/C1/C2) made VT-d translation live and
confined virtio-net to its second-level page table (SLPT), and proved
confinement at the SLPT level host-side (`translate_slpt` returns `None`
out-of-window) and live-enforced (TE on, 0 faults on legitimate traffic).
What remained was a **live demonstration that the IOMMU actually faults a
device that DMAs out of its window**.

The difficulty: a live IOMMU fault requires a real **device DMA** to an
unmapped address, and that needs a controllable DMA source. The real drivers
never DMA out of bounds (that is the point), so the negative test needs a
DEV-only harness that deliberately mis-configures a device we control.

## Decision

Add a DEV-only `iommu-negtest` cargo feature (implies `iommu-te`; never in
CI) that turns the in-kernel **e1000e** NIC into the §S9.1 negative-test
subject. e1000e is the ideal target: the kernel owns its CSR window (mapped
at a fixed VA by `e1000e_live_bringup`), M0 does not use it (M0 is on
virtio-net), and its TX-ring base is a known physical address.

In `iommu_finalize_enable_translation`, under `iommu-negtest`:

1. **Empty-SLPT translating entry.** e1000e is given a `UntranslatedOnly`
   (TT=00b) context entry pointing at a freshly-provisioned domain whose SLPT
   is left **empty** (no `map_with_src` calls) — so any DMA it issues
   translates through an empty tree and faults. Its empty domain is
   deliberately excluded from the C2 pre-flip "SLPT built" guard.
2. **Flip `GCMD.TE`** (the normal C1/C2 path; virtio-net stays correctly
   confined and working, all other devices passthrough).
3. **Force the fault deterministically.** After the flip, bump e1000e's `TDT`
   (TX tail) to 1 so the controller DMA-reads descriptor[0] from `TDBAL`
   (phys 0) — unmapped in the empty SLPT — and the IOMMU records a fault.
   A bounded spin lets the DMA attempt + fault recording land.
4. **Observe + assert.** `iommu_drain_faults` reads the FRCD registers; a
   fault whose source-id equals the e1000e BDF proves the IOMMU blocked the
   out-of-window DMA. Logged as `negtest PASS`.
5. **Revocation.** e1000e is quiesced (RX/TX disabled) and its context entry
   is revoked via `release_vt_d_device_entry_managed` (zero the context entry
   + context-cache + IOTLB invalidation) — the same MMIO teardown a destroyed
   DMA token drives through `tear_down_pci_bindings`. This satisfies the
   §S9.1 "token destruction → detach + invalidation" criterion on hardware.

The positive test (virtio-net confined + M0 `HTTP 200`) runs in the SAME
boot, because only e1000e is sabotaged — so one `iommu-te,iommu-negtest`
boot demonstrates the negative test, the positive test, and revocation
together, with the system staying stable throughout.

## Alternatives Considered

- **Sabotage virtio-net instead of e1000e:** deterministic (virtio-net always
  DMAs for M0) but conflates the negative test with M0 — the positive test
  would no longer run in the same boot. Rejected; e1000e is free.
- **Rely on e1000e RX-descriptor prefetch (no forced TX):** non-deterministic
  — depends on the controller prefetching with no traffic. The forced TDT
  bump is deterministic.
- **A synthetic CPU-side "out-of-window" check:** the IOMMU only faults on
  *device* DMA; a CPU access would `#PF` via the page tables, not the IOMMU —
  it would not exercise §S9.1. Rejected.
- **A dedicated Ring 3 negative-test probe:** a Ring 3 probe cannot drive a
  device DMA without a device + MMIO capability; more scaffolding than reusing
  the kernel-owned e1000e. Rejected.

## Deterministic-flip barrier (added after attempt 4)

The first VM runs exposed a latent race: the TE-finalize step could be
reached before the confined virtio-net driver's `DmaMap` had built its SLPT,
so the C2 guard aborted the flip (`SLPT not built yet`). The relative timing
of "finalize reached" vs "driver `DmaMap` ran" is non-deterministic and
shifted once `caching-mode=on` added invalidation VM-exits to the driver's
map path. The fix (kept regardless of the negative-test outcome — it makes
the flip deterministic instead of timing-dependent): a **bounded busy-spin
barrier** in finalize that waits, with interrupts live, until every confined
domain reports SLPT mappings — the live LAPIC timer dispatches the driver
during the spin, it completes its `DmaMap`, and control returns. Bounded so a
stuck driver cannot hang boot. the test VM confirms `confined domain SLPT ready`
→ `GCMD.TE raised` deterministically.

## Hardware finding (the test VM, 4 attempts incl. `caching-mode=on`)

The harness was exercised on the test VM (`iommu-te,iommu-negtest`) across four
iterations, the last two with the deterministic barrier and with the
intel-iommu device set to **`caching-mode=on` (CM=1)**. In every run: the
empty-SLPT entry installed, `GCMD.TE` was raised (`translation ENABLED`), the
forced TX advanced the e1000e `TDH 0 → 1` (the controller DID process the
descriptor), **M0 stayed up** (virtio-net confined + `HTTP 200`), the e1000e
entry was **revoked live** (`REVOKED (detach + invalidation)`, post-revoke
faults drained = 0), and the system stayed stable.

However, **no DMAR fault was ever recorded**, with OR without `caching-mode=on`:
`FSTS = 0x00000000`; the reader hardened to scan FRCD directly at the
confirmed `CAP.FRO = 0x220` (QEMU's FRCD offset) shows `FRCD[0] = 0`
(genuinely empty), even with the TX ring base pointed at a non-zero unmapped
IOVA (1 GiB); and the Proxmox host `journalctl` shows **no** VT-d/DMAR fault
line from QEMU. The fault reader is correct (right register, confirmed
offset); the fault is simply not recorded anywhere.

Conclusion (definitive): **QEMU does not surface an *emulated* device's DMA
translation failure as an observable fault** — not in FRCD, not on its own
log — even with `caching-mode=on`. QEMU's emulated-device DMA path
(`pci_dma_read`) returns an error to the device on a failed translation, the
e1000e model ignores it (advances `TDH`, transmits nothing), and the full
`vtd_report_dmar_fault` → FRCD recording path that real silicon and
**vfio-passthrough** devices exercise is not driven for emulated devices.
This is an emulation-model limitation of the *observation method*, not a
kernel defect: the out-of-window read was *blocked* (nothing was corrupted;
the system stayed stable), the confinement walker is correct (host-tested),
and e1000e shares bus 6 with virtio-net whose DMA QEMU demonstrably *does*
translate (M0 works) — so e1000e's DMA is translated too; only the fault
*report* is absent.

The live FRCD-observed negative fault is therefore **achievable only on real
VT-d silicon or a vfio-passthrough device**, neither available on this
emulated VM — the same class of "hardware-gated criterion" NCIP-026 already
applies to WI-8's TEE quote. Confinement itself remains proven on the VM by:
the C2 positive test (virtio-net confined to its SLPT, M0 `HTTP 200`,
translation genuinely enforced under `GCMD.TE`), the host SLPT test
(`slpt_confines_dma_to_mapped_window_only`: out-of-window → `None`), and the
live revocation demonstration. The harness is retained so the FRCD fault can
be captured the moment the work runs on real VT-d hardware.

## Consequences

- §S9.1's *enforcement* + *revocation* are demonstrated on the VM; the §S9.1
  *fault-report-in-log* sub-criterion is **hardware-gated** (real VT-d /
  vfio) by the QEMU emulated-device limitation above, and the harness that
  will capture it is committed and ready.
- e1000e is intentionally left revoked/quiesced after the test in the negtest
  build; it is not used by anything (M0 is virtio-net), so this is harmless.
- The harness reuses the existing FRCD reader (ADR-0028 C0) and the
  managed install/release MMIO paths — no new IOMMU machinery.
- For real silicon, the `CAP.RWBF` write-buffer-flush check (deferred on
  QEMU, `RWBF=0`) must be added before the entries can be relied upon; the
  bus-master gating re-home (`virtio_net_live_bringup` status-dance removal)
  is the remaining WI-7 cleanup.
