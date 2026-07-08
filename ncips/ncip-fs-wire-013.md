---
ncip: 13
title: NCFS On-Disk Format (FS-Wire) — v3 Superblock, Inodes, Extents, Integrity
track: Standards Track
status: Review
authors: [hello@nexacoreos.com]
created: 2026-07-02
license: CC0-1.0
---

## Abstract

This NCIP specifies the **on-disk wire format** of NCFS v3, the NexaCore native
filesystem: the block device abstraction, the dual-slot A/B superblock with a
keyed self-MAC, the 256-byte inode with inline extents, the extent + allocation
map for reflink/copy-on-write, the directory encoding, the keyed-BLAKE3 Merkle
integrity tree, and the per-volume XChaCha20-Poly1305 block confidentiality
layer. It freezes these byte layouts and the crash-consistent commit protocol as
a testable contract so any tool (`mkfs`, mount, fsck, migration) reproduces
byte-identical structures.

## Motivation

A confidential-by-design OS needs a filesystem whose integrity and
confidentiality are structural, not bolted on. v0–v2 (`docs/…`, ADR-0037) capped
volumes at a fixed block count and lacked authenticated encryption. v3 removes
the size cap, adds authenticated encryption per block, O(1) snapshots, and a
Merkle read-path integrity check. For these guarantees to survive a crash and to
be verifiable independently of the writer, the exact bytes on disk and the commit
ordering must be frozen. This NCIP is that freeze; it also serves as the concrete
realisation of the previously-unwritten "FS-Wire" specification referenced by the
storage workstream.

## Specification

### Block device

Storage is a `BlockDevice`: a lazily-addressed array of fixed-size blocks with
`read`/`write`/`flush`/`commit_root`. There is no whole-volume block cap (the
v0–v2 128-block limit is removed).

### Superblock (dual A/B slots)

The superblock is `SuperblockV3`, magic `NCFSV3\0\0` (8 bytes). Two copies are
kept in slots A and B; the active slot is chosen by `generation & 1`
(`slot_for_generation`). Each superblock carries a **BLAKE3-keyed self-MAC**
(`MacKey`); `mount` selects the highest-generation slot whose MAC verifies, so a
torn write of the newest slot cleanly falls back to the previous generation.
`commit(dev, sb, key)` writes the inactive slot then updates the root, giving
crash consistency: a crash mid-commit keeps the previous good generation.

### Inodes and extents

An inode is `InodeV3`, exactly `INODE_SIZE = 256` bytes, with the capability
fingerprint pinned at a fixed offset, a `key_epoch`, and `INLINE_EXTENTS = 4`
inline extents. An `Extent` is `EXTENT_LEN = 24` bytes; `map_logical(extents,
logical)` resolves a logical block to a physical block. The root inode is
`ROOT_INODE = 1`. The `AllocMap` holds a per-block refcount enabling reflink and
copy-on-write: `alloc`/`incref`/`decref`, with `is_shared` (refcount > 1)
triggering copy-on-write on the next write.

### Directories

A directory is encoded as a sequence of entries (name + inode number), with an
NFC-normalisation check behind an `NfcCheck` seam. The entry stream is terminated
by an **inode-0 terminator**: decoding stops at the first zero-inode entry, so a
zero-padded tail block does not produce spurious entries.

### Integrity (keyed-BLAKE3 Merkle tree)

Block integrity uses a keyed-BLAKE3 Merkle tree: `leaf_hash(key, block)`,
`node_hash(key, left, right)`, `merkle_root(key, leaves)` /
`root_over_blocks`, with `merkle_proof(key, leaves, index)` and verification for
the read path. Keying the tree binds the integrity proof to the volume key so an
attacker cannot forge a consistent tree for substituted blocks.

### Confidentiality (per-volume AEAD)

Data blocks are sealed with XChaCha20-Poly1305. `seal_block`/`open_block` bind
associated data `(generation, block, key_epoch)`. The nonce is deterministic —
`block_nonce(generation, block)` — which is misuse-resistant here because a
`(generation, block)` pair names exactly one plaintext version (a rewrite bumps
the generation). A BLAKE3-keyed key hierarchy derives per-volume and per-epoch
keys (`derive_volume_key`/`derive_epoch_key`); `key_epoch` provides
crypto-erasure. The master key's sealing to the platform TEE is the caller's
responsibility (WS10).

### mkfs and snapshots

`format(dev, keys)` writes superblock slots A and B, the allocation map, an empty
root directory, and the Merkle root, committing generation 1; `format` →
`mount` round-trips. `SnapshotTable::take` records the current root in O(1);
`clone_from` produces a writable clone that shares blocks copy-on-write; `retain`
adjusts refcounts so shared blocks survive until every referencing snapshot is
deleted.

## Rationale

The A/B superblock with a MAC-verified highest-valid-generation mount is the
simplest structure that is atomic against a torn superblock write without a
journal. Deterministic nonces avoid a per-write RNG on the hot path while staying
misuse-safe because the generation counter versions every block. Keying the
Merkle tree (rather than a plain hash tree) is what makes integrity resistant to
substitution under a known volume. The inode-0 directory terminator fixes a real
decoding bug where zero-padded blocks yielded phantom entries.

## Backwards Compatibility

v0–v2 on-disk structures (`ondisk.rs`, `InMemoryFs`) are retained alongside v3 to
support the v2→v3 migration path (WS3-01.16). v3 is a new format version
identified by its magic and superblock; it does not attempt in-place
compatibility with v2 layouts.

## Test Cases

Host unit tests in `crates/nexacore-fs/src/v3/` cover: superblock A/B slot selection
and crash-keeps-previous-generation; inode 256-byte byte-exact encode/decode with
the pinned fingerprint offset; extent map/alloc-map refcount (reflink/CoW share);
directory encode/decode including the inode-0 terminator (no phantom entries);
Merkle root/proof/verify and corruption detection; `seal_block`/`open_block`
round-trip with AAD binding; `format`→`mount` round-trip; and snapshot
`take`/`clone_from`/`retain` refcount behaviour.

## Reference Implementation

`crates/nexacore-fs/src/v3/` — modules `blockdev`, `superblock`, `inode`, `extent`,
`dirent`, `merkle`, `block_crypto`, `mkfs`, `snapshot` (package
`nexacore-fs`). Plan tasks WS3-01.1–.10. The crash-consistency torture harness,
ZSTD extents, fuzzing, and the v2→v3 migration are follow-ups (WS3-01.11–.17).

## Security Considerations

Integrity is keyed (BLAKE3-MAC superblock, keyed-BLAKE3 Merkle tree) so an
attacker with block-device access cannot forge a self-consistent tampered
volume without the key. Confidentiality is authenticated encryption
(XChaCha20-Poly1305) with AAD binding block position and epoch, so blocks cannot
be relocated or replayed across epochs. `key_epoch` enables crypto-erasure.
Deterministic nonces are safe only under the "one plaintext per
`(generation, block)`" invariant this format enforces; implementations MUST bump
the generation on rewrite. The master key MUST be sealed to the platform TEE by
the caller (WS10); this format assumes it is provided already unsealed.

## Privacy Considerations

Per-volume encryption means at-rest data — including filenames and directory
structure carried in encrypted data blocks — is confidential without the volume
key. `key_epoch`-based crypto-erasure provides a privacy-preserving deletion
primitive: rotating the epoch renders prior-epoch blocks unrecoverable without
overwriting them. The format carries no user-identifying metadata beyond what the
filesystem contents themselves contain.

## Copyright

This document is placed in the public domain under CC0-1.0.
