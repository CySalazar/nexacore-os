# ADR-0011: NVMe driver image bring-up IO path architecture

## Metadata

- **ID:** ADR-0011
- **Data:** 2026-05-23
- **Stato:** accepted
- **Sostituisce:** N/A
- **Sostituito da:** N/A

---

## Contesto

TASK-005 (NVMe live driver bring-up, P6.7.9.b) requires the Ring-3
`nexacore-driver-nvme-image` to execute the full NVMe 1.4 bring-up sequence
end-to-end via real syscalls against the kernel's driver framework
(NCIP-Driver-Framework-013 + NCIP-Driver-NVMe-014 SS S6).

The image runs under `PanicOnAlloc` (no heap allocator) because the
Phase-1 kernel does not yet expose a user-space heap service. This
constraint forces all admin and IO command encoding, submission, and
completion polling to be alloc-free. The existing `AdminSession` and
`IoSession` helpers in the `nexacore-driver-nvme` library allocate
`Vec<u8>` for SQ/CQ data pages, making them unusable from the image.

The decision concerns how the image composes the existing library
primitives (`encode_identify`, `encode_create_io_cq`, `encode_read`,
etc.) with the raw DMA arena slices the kernel provides via
`DmaMap (71)`.

---

## Decisione

**Sintesi:** the image uses `AdminQueuePair` directly (bypassing
`AdminSession` / `IoSession`) against `&mut [u8]` / `&[u8]` slices
constructed from the DMA arena IOVAs, with a deterministic IOVA layout.

### IOVA arena layout (Phase-1, static)

| Offset  | Size  | Purpose                        |
|---------|-------|--------------------------------|
| `0x0000`| 4 KiB | Admin SQ data page             |
| `0x1000`| 4 KiB | Admin CQ data page             |
| `0x2000`| 4 KiB | Identify Controller response   |
| `0x3000`| 4 KiB | Active Namespace List response |
| `0x4000`| 4 KiB | Identify Namespace response    |
| `0x5000`| 4 KiB | IO CQ data page                |
| `0x6000`| 4 KiB | IO SQ data page                |
| `0x7000`| 4 KiB | IO read/write data buffer      |
| `0x8000`| 4 KiB | Discard Range Descriptor       |

All IOVAs are 4 KiB-aligned by construction. Phase-1 IOMMU passthrough
means `user_va == iova`, so the image reads/writes DMA pages directly
through reinterpreted pointers.

### Admin command sequence (5 admin commands via admin QP)

1. `Identify(Controller)` — CID 1, response at `0x2000`
2. `Identify(ActiveNsList)` — CID 2, response at `0x3000`
3. `Identify(Namespace { nsid })` — CID 3, response at `0x4000`
4. `Create IO Completion Queue` — CID 4, CQ at `0x5000`
5. `Create IO Submission Queue` — CID 5, SQ at `0x6000`

### IO command sequence (4 IO commands via IO QP, qid=1)

1. `NVM Read(LBA 0, 1 sector)` — CID 1, data at `0x7000`
2. `NVM Write(LBA 0, 1 sector)` — CID 2, data at `0x7000`
3. `NVM Flush` — CID 3
4. `NVM Dataset Management (Discard, LBA 0, 1 sector)` — CID 4,
   Range Descriptor at `0x8000`

### Pre-disable validation (CAP + VS registers)

Before disabling the controller, the image reads:
- `CAP.DSTRD` — must be 0 (4-byte doorbell stride)
- `CAP.MQES` — must be >= 63 (support 64 entries)
- `CAP.MPSMIN` — must be 0 (support 4 KiB pages)
- `VS.major` — must be >= 1 (NVMe 1.0+)

---

## Alternative Considerate

### Alternativa A: extend `AdminSession` / `IoSession` with a `no_alloc` mode

- **Descrizione:** add a generic parameter or trait bound that lets
  the session operate on borrowed slices instead of owned `Vec<u8>`.
- **Pro:** single code path for both the host harness and the live image.
- **Contro:** the session owns the SQ/CQ data pages today; changing
  this requires a non-trivial refactor of the `AdminSession` API and
  breaks all existing host-side tests that rely on the `Vec` ownership
  pattern. The refactor would be premature — Phase-2 may introduce a
  user-space heap that makes the `Vec` path viable for the live image.
- **Motivo di esclusione:** excessive coupling risk for Phase-1;
  the direct `AdminQueuePair` approach is simpler and equally correct.

### Alternativa B: embed a bump allocator in the image

- **Descrizione:** replace `PanicOnAlloc` with a fixed-size bump
  allocator backed by a page in the DMA arena.
- **Pro:** `AdminSession` and `IoSession` become usable unchanged.
- **Contro:** introduces a non-trivial allocator into a security-critical
  Ring-3 binary; the bump allocator's `dealloc` is a no-op, leaking
  memory across the session lifetime. Unnecessary when the total memory
  footprint is < 36 KiB (9 pages).
- **Motivo di esclusione:** violates the "minimize moving parts in
  security-critical paths" principle from NCIP-013 SS R1.

---

## Conseguenze

### Positive

- The image is alloc-free: zero heap allocations, zero deallocation
  bugs, zero OOM paths.
- Every sentinel exit code is unique and triage-friendly on the
  serial log.
- The IOVA layout is deterministic and audit-friendly (no runtime
  allocation decisions).
- 90 host-side composition tests exercise the full admin + IO
  command sequence without requiring QEMU.

### Negative

- The image duplicates the admin-command poll loop pattern 9 times
  (one per admin/IO command). This is intentional — the alloc-free
  constraint precludes a generic polling helper that returns a
  type-erased result, and the per-command sentinels require distinct
  exit codes.
- Adding a new admin or IO command requires extending the IOVA layout
  and the CID counter manually.

### Rischi

- Phase-1 IOMMU passthrough (`iova == user_va`) means a compromised
  driver can read/write any frame the kernel allocated. TASK-010
  (VT-d / AMD-Vi IOMMU backends) closes this gap.
- The static IOVA layout assumes a single NVMe controller. Multi-
  controller support requires a per-controller arena offset scheme.

---

## Note di Implementazione

Delivered across P6.7.10-pre.1 through P6.7.10-pre.41 (41 sub-slices
on branch `main`). The image's `_start` function is 23 sequential
steps (4.1 through 4.23 + steps 5-6) in a single linear function
body, matching the NVMe 1.4 SS 3.1 bring-up flowchart.

---

## Riferimenti

- NCIP-Driver-NVMe-014 SS S6 (bring-up sequence)
- NCIP-Driver-Framework-013 SS S2 (MmioMap/DmaMap/IrqAttach)
- `crates/nexacore-driver-nvme-image/src/main.rs` (implementation)
- `crates/nexacore-driver-nvme/src/queue.rs` (composition tests)
- `crates/nexacore-driver-nvme/src/controller_regs.rs` (CAP/VS extractors)
- ADR-0005 (MB12 IPC message passing)
- ADR-0006 (MB13 nexacore-capability integration)
