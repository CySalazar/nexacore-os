# ADR-0028: VT-d TE Flip — Identity-Confined Driver + Passthrough Baseline (WI-7b step 3)

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar (operator authorised the `GCMD.TE` flip accepting M0 risk; M0-safe sub-steps each verified on the test VM)
**Reviewers:** tee-specialist agent (VT-d rev 4.1 spec review — verdict REJECT-as-was, design below incorporates every finding)
**Refs:** PLAN.md TASK-07, NCIP-026 WI-7b, ADR-0024 (M0 datapath), ADR-0026 (SLPT builder), ADR-0027 (live wiring TE-off),
`bare_metal/iommu/{vtd.rs,mod.rs}`, `bare_metal/{driver_loader.rs,syscall_entry.rs}`, `process.rs`

## Context

WI-7b step 2 (ADR-0027) landed the full live SLPT wiring with `GCMD.TE`
**off**. Raising TE is the last, highest-risk action: the moment translation
is enabled, the VT-d unit evaluates the root + context tables for **every**
DMA request, and any device without a present context entry is blocked and
faulted. A tee-specialist review of the as-was code (VT-d rev 4.1) returned
**REJECT** with a 100 % M0-brick probability on flip, for these reasons:

1. **CRITICAL — SLPT keyed on the wrong address.** `dma_map` built the SLPT
   `iova_base → phys_base`, but the driver programs the returned `phys_base`
   into its virtqueue descriptors (ADR-0024) — the device emits `phys_base`,
   not `iova_base`. On TE, the IOMMU walks the SLPT for `phys_base`, finds
   nothing, and faults every virtio-net DMA.
2. **HIGH — no passthrough baseline.** Only virtio-net had a context entry.
   The in-kernel virtio-tablet (bus 0, DMAs continuously), e1000e (live
   RX/TX rings), NVMe, virtio-blk and the USB controllers had none → all
   blocked the instant TE flips.
3. **HIGH — wrong translation type.** The confined entry used
   `UntranslatedAndTranslated` (TT=01b), which requires the device to issue
   ATS-translated requests and the unit to advertise device-IOTLB
   (`ECAP.DT`). QEMU `intel-iommu` advertises neither and virtio-net never
   uses ATS.
4. **HIGH — no fault visibility.** No code read the Fault Recording
   Registers, so the §S9.1 negative test could not prove a blocked DMA was
   observed and a mis-flip would hang silently.
5. **MEDIUM — `CAP.RWBF` unchecked.** Harmless on QEMU (`RWBF=0`) but would
   brick real silicon that requires a write-buffer flush before relying on
   table writes.

## Decision

Adopt the specialist's **C0 → C1 → C2** decomposition, each step verified on
the test VM, with the flip gated behind the `iommu-te` cargo feature (ADR-0027).

### C0 — M0-safe substrate, TE still off (this commit)

1. **Identity `phys_base → phys_base` SLPT** (finding 1). `dma_map` keys the
   IOMMU window on `phys_base` (the address the device emits); `DmaMapping`
   gains a `phys_base` field so teardown clears the SLPT at the same address.
   Confinement holds — only the driver's own frames become reachable. With
   TE off this is inert (the device bypasses the SLPT), so M0 is unchanged
   by construction and re-verified on the test VM.
2. **`UntranslatedOnly` (TT=00b)** for the confined virtio-net (finding 3).
   00b routes *all* of the device's DMA through the SLPT — exactly the
   confinement intended — without requiring ATS/`ECAP.DT`. Correct for any
   device that does not itself issue ATS requests (our case unconditionally).
3. **DMAR fault-status reader** (finding 4). `cap_fault_recording_offset`
   (`CAP.FRO`), `cap_num_fault_recording` (`CAP.NFR`), FSTS/FRCD decoders,
   `FaultRecord` + `decode_fault_record`, and the live
   `VtdBackend::drain_faults` / `iommu_drain_faults` that walk the FRCD
   registers, decode each recorded fault (source-id, reason, r/w, address),
   RW1C-clear them, and return the records. Read-only + RW1C — never changes
   translation, safe on every boot. 11 new host tests.

### C1 — passthrough baseline + the flip (DONE 2026-06-06, the test VM verified)

4. **Passthrough context entries for every other DMA-capable device**
   (finding 2): scan every function on every bus, install a `Passthrough`
   (TT=10b) context entry with `slpt_phys = 0` and `AW = highest CAP.SAGAW`
   (hard-assert `Some`, never the silent `Bits48Level4` fallback — finding 6)
   for each BDF except the confined virtio-net. A passthrough entry leaves
   the device identity-addressing when TE is on, so the flip is behaviourally
   equivalent to TE-off for those devices — which makes C1 a true test of
   *device-enumeration completeness*.
5. **Flip `GCMD.TE`** (behind `iommu-te`) once every context entry is
   installed, in a dedicated boot-finalisation step after all in-kernel
   bring-up. First land C1 with virtio-net ALSO on passthrough (proves the
   flip mechanism + enumeration), soak the FRCD reader for a clean run, then
   C2 switches virtio-net to its translating (TT=00b) entry.

### C2 — confine virtio-net (DONE 2026-06-06, the test VM verified) + §S9.1 tests

6. virtio-net keeps its translating context entry + identity SLPT; run the
   §S9.1 negative test (out-of-window DMA → FRCD fault report, system
   stable) and the positive test (virtio-net + NVMe confined, M0 re-verified)
   plus DMA-token-destruction revocation.

### Cross-cutting (deferred to C1 where consumed)

- `CAP.RWBF` decoder + `GCMD.WBF` before relying on table writes when set
  (finding 5) — unnecessary on QEMU (`RWBF=0`) but required for real silicon.
- GCMD enable-bit mask tracking (todo P11.3) so a future `IRE` raise does
  not drop `TE|QIE`.

## Alternatives Considered

- **Flip TE in one shot with only virtio-net confined** (the as-was path):
  rejected by the spec review — 100 % brick (findings 1+2). The C0→C1→C2
  staging isolates each failure mode behind a hardware checkpoint.
- **Change the driver ABI to program `iova_base` into descriptors** instead
  of identity-mapping `phys_base`: larger blast radius (touches the proven
  M0 driver image and the `DmaMap` return contract) for no confinement gain
  over the identity map. Rejected — keep the driver byte-identical.
- **TT=01b with device-IOTLB**: would need QEMU `intel-iommu,device-iotlb=on`
  and ATS negotiation in the driver — scope creep with no Phase-1 benefit.
- **No passthrough baseline; install translating entries for every device**:
  every in-kernel driver (tablet, e1000e, NVMe) would need a provisioned
  domain + SLPT covering its DMA windows — far more code and risk than a
  passthrough identity entry, for devices we are not yet confining.

## Hardware verification (the test VM)

- **C0 (TE off):** `vt-d activated`, `sagaw=6 levels=4`, identity SLPT built
  (`DmaMap errno=0`), `translation enabled` = 0, HTTP 200, PF = 0, REPL.
- **C1 (TE on, all-passthrough):** `iommu_finalize_enable_translation` ran a
  fresh PCI scan and installed passthrough context entries —
  `passthrough installed=28 skipped=1 failed=0` (skipped = the confined
  virtio-net, whose entry `bind` installed); `GCMD.TE raised — translation
  ENABLED` (GSTS.TES mirror observed); `0 DMAR faults post-flip`. With TE
  genuinely enforcing, e1000e live bring-up, the virtio-tablet, and the full
  M0 datapath all kept working through their passthrough entries:
  `M0 E2E COMPLETE: HTTP 200` ran AFTER the flip (finalize logged before the
  netcheck HTTP exchange), virtio-net TX frames flowed through the IOMMU, PF
  = 0, no panic, REPL reached. This proves the flip mechanism and that the
  device enumeration is complete (every DMA-capable device has a context
  entry; nothing faults).

- **C2 (TE on, virtio-net confined):** `bind` switched to `UntranslatedOnly`
  (TT=00b) for virtio-net, so its DMA routes through its identity
  `phys→phys` SLPT. A pre-flip guard (`iommu_domain_has_mappings`) refuses
  the flip until the confined domain's SLPT is built by the driver's
  `DmaMap` — making the flip safe regardless of `DmaMap` timing. the test VM
  (`iommu-te`): `passthrough installed=28 skipped=1 failed=0`, `GCMD.TE
  raised — translation ENABLED`, `0 DMAR faults post-flip`, and
  `M0 E2E COMPLETE: HTTP 200` with virtio-net's DMA going THROUGH its SLPT
  (genuinely confined to its own windows), PF = 0, REPL reached. Host-side
  §S9.1 confinement is proven by `slpt_confines_dma_to_mapped_window_only`
  (the SLPT resolves inside the window and returns None for the pages just
  before/after). The live device-fault §S9.1 negative test (a device DMAs
  out-of-window → FRCD fault) and the HW token-revocation test are the final
  residual (a dedicated DEV harness — the real drivers never DMA out-of-bounds
  or exit at boot).

## Consequences

- C0 is provably M0-safe (TE off; the only live-path change, the identity
  SLPT key, is bypassed while TE is off) and is committed + hardware-verified
  before any flip stacks on top.
- The fault reader exists before the flip, so C1/C2 can observe a mis-flip
  (or the §S9.1 fault) instead of hanging silently.
- `DmaMapping` grows one `u64`; the bookkeeping and teardown stay symmetric
  on `phys_base`.
- The flip remains operator-gated behind `iommu-te`; CI never enables it.
- The passthrough baseline (C1) means the TE flip confines ONLY virtio-net
  for now; tablet/e1000e/NVMe/USB stay identity-passing until each grows its
  own translating domain in a later WI (tracked, not in scope here).
