# ADR-0026: VT-d Second-Level Page-Table Builder (WI-7a, no TE flip)

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar (operator-scoped: "WI-7a now, substrate, no TE")
**Refs:** PLAN.md TASK-07, NCIP-026 WI-7, ADR-0024 (M0 datapath),
`bare_metal/iommu/{vtd.rs,pt_alloc.rs,kernel_frame_source.rs}`

## Context

NCIP-026 WI-7 (R2: DMA confinement) requires that each Ring 3 driver with a
DMA capability runs inside a dedicated IOMMU domain whose second-level page
table (SLPT) only maps its own windows, with `GCMD.TE` (VT-d Translation
Enable) raised so the hardware actually enforces it.

The substrate from P6.7.9-pre.* is extensive (vtd.rs context-entry/SLPTE
encoders, domain allocator, per-bus context tables, `activate_hardware`
raising SRTP+QIE, `enable_translation` flipping TE, managed device-entry
install). But it has one load-bearing gap: **`VtdBackend::map` only records
a `(domain, iova→phys)` tuple in a `Vec`** (`vtd.rs:1936`) — it never builds
the hardware-walkable multi-level page-table tree. The per-domain root frame
(`pt_alloc::DomainPageTables::provision`) is allocated zero-filled and stays
empty.

Consequence: raising `GCMD.TE` today would make the IOMMU walk an **empty**
SLPT root for every attached device → **every legitimate DMA faults** →
virtio-net and NVMe die → the just-verified M0 (HTTP 200 to Ollama) and NVMe
IO break. The M0 drivers additionally load via the deposit path
(`boot_load_virtio_net_image`), not the `DriverLoad(73)` syscall that hosts
the existing attach+TE logic, so TE is never raised at M0 boot today.

WI-7 is therefore intrinsically multi-session and the TE flip is the
highest-risk single change in the whole plan. The operator scoped this
iteration to **WI-7a: the host-testable substrate completion only, no TE
flip**, with WI-7b (live wiring + TE + hardware negative/positive tests)
deferred to an explicit operator-gated session.

## Decision

Implement a **real VT-d second-level page-table builder**, host-tested,
**not yet wired into the live `dma_map` path** and with **`GCMD.TE` left
off**.

1. **`FrameSource` gains entry access** (`pt_alloc.rs`): two methods,
   `read_entry(table_phys, index) -> u64` and `write_entry(table_phys,
   index, value)`, alongside the existing `alloc_zeroed_frame`/`free_frame`.
   The trait already abstracts "the frames the IOMMU page tables live in",
   so reading/writing entries in those frames belongs there. `KernelFrameSource`
   backs them with direct-map volatile read/write (bare-metal) / no-op
   (host, never called live). `MockFrameSource` backs them with a
   deterministic `BTreeMap<phys, [u64;512]>` so host tests verify tree
   structure without dereferencing real memory.

2. **VT-d SLPT walker** (`vtd.rs`): `slpt_index`, `map_4k_slpt`,
   `map_range_slpt`, `unmap_4k_slpt`, `translate_slpt`. The walk descends
   the `AddressWidth::levels()` (2..5) levels, faulting in missing
   intermediate tables from the `FrameSource`, and writes the leaf SL-PTE.
   Intermediate and leaf entries share the R/W + 4-KiB-output-address bit
   layout (VT-d § 9.6 — leaf vs intermediate is a function of level, not a
   bit, for 4-KiB pages; PS is only set for large-page leaves we never
   emit), so "present" is `R|W set` at every level. `AddressWidth` (not a
   raw level count) is the parameter, so an invalid level is unrepresentable.

3. **Scope guards:** the builder is `pub` (it is the API WI-7b will call)
   and fully exercised by tests, so no dead-code. It is **not** called from
   `dma_map` or the deposit-path spawn in this change. `GCMD.TE` stays off.
   M0 is therefore unchanged by construction and re-verified on the test VM.

## Alternatives Considered

- **Wire the builder into `dma_map` now (still no TE):** would make
  `dma_map` allocate SLPT frames per mapping immediately. Harmless with TE
  off (passthrough), but it changes the live frame-allocation behaviour of
  the exact path M0 depends on, for zero functional gain until TE is raised.
  Rejected — keep the live path byte-identical until WI-7b raises TE in one
  coordinated, hardware-verified step.
- **Put entry read/write on a separate `SlptMemory` trait:** cleaner
  separation, but the builder needs alloc AND entry access from the same
  object; two traits on `KernelFrameSource` would force two `&mut` borrows
  of one value at the call site. One trait avoids the borrow conflict.
- **Reap empty intermediate subtrees on `unmap`:** correct long-term, but
  adds refcount bookkeeping per level. Phase 1 frees the whole subtree
  wholesale when the domain root is released on driver teardown (the
  existing `iommu_release_domain_pt` path), so per-unmap reaping is deferred.
- **Build the AMD-Vi I/O page table too:** AMD-Vi uses a different entry
  layout (Next-Level field) and is not exercised on the test VM (`vendor=intel`).
  Deferred to when an AMD substrate is in the test loop.

## Consequences

- WI-7b is massively de-risked: the linchpin (a correct, tested SLPT
  builder) exists, so WI-7b is wiring + the TE flip + the negative-test
  driver, not new page-table algorithms.
- The change is provably M0-safe: nothing in the live datapath calls the
  builder and TE stays off. Re-verified on the test VM (M0 HTTP 200 intact).
- `FrameSource` implementors must now provide entry access; only two exist
  (`KernelFrameSource`, `MockFrameSource`), both updated.
- WI-7b carries an explicit hardware risk (a wrong map/AGAW faults all DMA);
  it is operator-gated, not part of this change.
