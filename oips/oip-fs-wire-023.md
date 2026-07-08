---
ncip: 23
title: NCFS On-Disk Format v1 — Superblock, Inode B+-Tree, CoW Block Allocator, AEAD Integrity
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-24
updated: 2026-05-24
requires:
  - 14
  - 18
supersedes: ~
superseded-by: ~
discussion: ~
license: CC0-1.0
---

# NCIP-FS-Wire-023 — NCFS On-Disk Format v1

> **TASK-15 status (2026-06-08, ADR-0037):** the on-disk format is mounted
> from a real NVMe disk for the first time, by the Ring 3 `nexacore-fsd`
> daemon over the TASK-14 BLK service, with reboot persistence verified on
> the test VM. Because `OnDiskVolume::mount` is whole-volume-`&[u8]`-backed,
> the boot-mounted root volume is currently capped at **128 blocks
> (512 KiB)** to bound the per-block `BlkRequest` round-trips at boot. A
> lazy `read_block`/`write_block` block-device trait (mount/sync on demand
> instead of whole-volume) is the planned refactor that lifts this cap;
> until then 128 blocks is the documented root-volume size.

> **Erratum and hardening note (2026-06-12, ADR-0051):** the shipped
> implementation now writes **superblock `version = 2`**, an erratum-level
> encoding revision within this NCIP's layout. Changes: (a) inode records
> store the **full absolute path** instead of the basename — the v1 encoding
> silently flattened nested directory hierarchies on mount and collided
> same-named files in different directories; (b) serialisation **fails
> closed** with `FsError::MetadataOverflow` when a metadata region (bitmap,
> inode table, integrity tags — one 4 KiB block each) would overflow, where
> it previously truncated silently; (c) version-1 images are rejected at
> mount per this NCIP's own Backwards Compatibility rule (no silent
> reinterpretation). Known format-level limits acknowledged: no atomic
> commit / CoW root (the §S3 "atomic 8-byte pointer update" does not cover
> the multi-block superblock+bitmap+inode-table transaction), max file
> ~1 GiB via §S2 double-indirect pointers vs. the 8 EiB frozen in
> NCIP-FS-018 §S1.1, 95-byte names vs. 255-byte NFC, and no capability
> fingerprint field in the §S2 inode despite NCIP-FS-018 §S1. These are
> resolved structurally by **`NCIP-FS-Wire-027` (Draft)**, which supersedes
> this NCIP upon its activation.

## Abstract

This NCIP defines the on-disk format for NCFS v1, the native filesystem
of NexaCore OS. The format comprises four structural layers: a **Superblock**
identifying the volume and tracking free-space metadata, an **Inode
B+-tree** mapping file/directory metadata to block pointers, a
**Copy-on-Write (CoW) block allocator** ensuring crash consistency
without a journal, and per-block **AEAD integrity tags** providing
tamper evidence for all stored data.

## Motivation

### M1. NCFS needs an on-disk format to persist AI models

The Phase 2 AI Runtime Service loads models via `ModelRegistry::load_from_bytes`.
Today, model bytes arrive from test fixtures. Production deployment requires
models to be stored on NVMe media and loaded via the BLK channel. The on-disk
format is the bridge between raw NVMe blocks and the structured file abstraction
that `ModelRegistry` expects.

### M2. Integrity at the block level prevents silent corruption

AI model weights are high-value data: a single flipped bit can cause
catastrophic inference errors with no obvious error signal. AEAD tags per
block provide tamper evidence (accidental corruption) and tamper resistance
(adversarial modification of model weights on disk).

### M3. CoW allocation enables crash-safe writes without journaling

A traditional journal doubles write amplification. Copy-on-Write semantics
achieve crash consistency by never overwriting live data: new blocks are
written to free space, the inode pointer is atomically updated, and old
blocks are freed. If the system crashes mid-write, either the old or new
state is valid — never a torn intermediate.

## Specification

### S1. Superblock (Block 0)

The superblock occupies the first 4 KiB block of the volume.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | `magic` | `b"OMNIFS01"` — format identifier |
| 8 | 4 | `version` | Format version (1 for this NCIP) |
| 12 | 4 | `block_size` | Block size in bytes (MUST be 4096) |
| 16 | 8 | `total_blocks` | Total number of blocks on the volume |
| 24 | 8 | `free_blocks` | Number of unallocated blocks |
| 32 | 8 | `inode_count` | Total number of allocated inodes |
| 40 | 8 | `root_inode` | Inode number of the root directory |
| 48 | 8 | `created_at` | Volume creation timestamp (NexaCore HAL epoch) |
| 56 | 8 | `aead_key_id` | Key identifier for block-level AEAD tags |

Bytes 64–4095 are reserved (zeroed). The superblock is written during
`mkfs` and updated on every metadata-modifying operation.

### S2. Inode structure

Each inode occupies 256 bytes and contains:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | `inode_number` | Unique inode identifier |
| 8 | 1 | `file_type` | 0 = regular file, 1 = directory |
| 9 | 7 | _reserved_ | Padding (zeroed) |
| 16 | 8 | `size` | File size in bytes |
| 24 | 4 | `block_count` | Number of allocated blocks |
| 28 | 4 | _reserved_ | Padding |
| 32 | 8 | `created` | Creation timestamp |
| 40 | 8 | `modified` | Last-modified timestamp |
| 48 | 8×12 | `direct_blocks` | 12 direct block pointers |
| 144 | 8 | `indirect_block` | Single-indirect block pointer |
| 152 | 8 | `double_indirect` | Double-indirect block pointer |
| 160 | 96 | `name` | UTF-8 file name (null-padded, max 95 chars) |

Maximum file size with direct blocks only: 12 × 4096 = 48 KiB.
With single indirect (512 entries × 4096): ~2 MiB.
With double indirect: ~1 GiB. Sufficient for Phase 2 model files.

### S3. CoW block allocator

Block allocation follows Copy-on-Write semantics:

1. **Write**: allocate a new block from the free list, write data to it,
   update the inode to point to the new block, free the old block.
2. **Free list**: a bitmap stored in blocks 1–N (one bit per data block).
   Block 0 is the superblock; bitmap blocks start at block 1.
3. **Atomic pointer update**: the inode's block pointer is updated in a
   single 8-byte write, which is atomic on NVMe (per NVM Express spec
   §4.2 — writes ≤ atomic write unit are guaranteed atomic).

### S4. AEAD integrity tags

Every data block has an associated 16-byte AEAD tag stored in a
dedicated integrity region:

- Tag computation: `AEAD-Encrypt(key, nonce=block_number, data=block_data)`
- Phase 2 stub: tags are zeroed (no real encryption key available).
- Phase 3+: tags are computed using the TEE-sealed key identified by
  `superblock.aead_key_id`.

Verification is mandatory on read: if the computed tag does not match
the stored tag, the read returns `FsError::IntegrityViolation`.

## Rationale

### R1. Why B+-tree for inodes, not a flat table

A flat inode table (ext4-style) wastes space when the filesystem has few
files (common for AI model storage — tens of large files). A B+-tree
grows proportionally to the number of files and provides O(log n) lookup
by inode number. For the Phase 2 in-memory implementation, `BTreeMap` is
used directly.

### R2. Why CoW instead of a journal

CoW avoids the 2× write amplification of journaling and naturally
produces snapshots (the old blocks remain valid until freed). This aligns
with NexaCore OS's undo/rollback philosophy (NCIP-007 §6) — a filesystem-level
rollback is simply "revert the inode pointer to the previous block set."

## Backwards Compatibility

N/A — v1 is the first NCFS on-disk format; there is no prior layout to remain
compatible with. Forward-compatibility across future format revisions is gated
by the superblock magic (`b"OMNIFS01"`) and `version` field (§ Specification): a
reader rejects a volume whose magic/version it does not understand, so a later
format revision is a new magic/version, never a silent reinterpretation.

## Test Cases

- **T1.** Format a volume with `InMemoryFs::format(1024)` → superblock
  magic is `b"OMNIFS01"`, version is 1, root inode exists.
- **T2.** Create a file, write 8 KiB, read back → data matches.
- **T3.** Write at offset 4096, read at offset 0 → first block is zero,
  second block has the written data.
- **T4.** Delete a file → `free_blocks` increases, `stat` returns `NotFound`.
- **T5.** Block integrity tag computation and verification (stub: zeroed tags).
- **T6.** End-to-end: format → create → write → stat → read → delete → verify free.

## Reference Implementation

The format is exercised by the `InMemoryFs` reference implementation in the
`nexacore-fs` crate (`format` / create / write / read / `stat` / delete), validated
by the § Test Cases T1–T6 above. The native on-disk NCFS host that persists
this layout to a block device is delivered phased per `NCIP-FS-018`.

## Security Considerations

- AEAD tags are mandatory; a volume without tags is considered corrupted.
- The AEAD key MUST be TEE-sealed; compromise of the key voids integrity.
- CoW semantics mean deleted data remains on disk until the block is
  reused; secure deletion requires block zeroing (Phase 3).

## Privacy Considerations

- File names in inodes may contain PII; encryption-at-rest (via
  `nexacore-tokenization`) is recommended for user-data volumes.

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
