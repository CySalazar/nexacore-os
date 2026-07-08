# ADR-0051: NCFS Hardening Pass — Fail-Closed Serialisation, Path-Preserving Encoding v2, Wire-027/Review-Gate-028 Direction

**Status:** Accepted
**Date:** 2026-06-12
**Deciders:** operator-approved remediation plan (filesystem audit of 2026-06-12)
**Refs:** NCIP-FS-018 (§S1.1 frozen parameters, SC1, SC7, PC1, PC3),
NCIP-FS-Wire-023 (+ 2026-06-12 erratum note), NCIP-FS-Wire-027 (Draft),
NCIP-Review-Gate-028 (Draft), ADR-0037 (root mount persistence),
`docs/ncfs-compliance-matrix.md`

## Context

A comparative audit of NCFS against mainstream filesystems (ext4, XFS,
Btrfs, ZFS, NTFS, FAT32, exFAT, APFS), conducted 2026-06-12 against both the
implementation and the full NCIP-FS-018 specification, found five weakness
classes:

1. **Silent metadata truncation (data loss).** `sync_to_bytes` copied the
   bitmap, the serialised inode table, and the integrity tags into one
   4 KiB block each with `.min(BLOCK_SIZE)`, and `write_integrity_tags`
   `break`-ed when full — volumes past any limit serialised *without error*,
   losing metadata.
2. **Nested paths did not survive a mount.** Inode records stored only the
   basename; `deserialize_inodes` rebuilt every path as `/<basename>`,
   flattening hierarchies and colliding same-named files in different
   directories. Latent (not documented in any ADR/NCIP) because the deployed
   root volume only held `/test.txt`.
3. **The v1 format contradicts NCIP-FS-018.** No CoW root / atomic commit
   (the "no journal, no fsck" rationale has no mechanism); max file ~1 GiB
   vs the frozen 8 EiB; 95-byte names vs 255-byte NFC; the mandated 32-byte
   capability fingerprint is absent from the Wire-023 inode.
4. **The AEAD scheme violates SC7.** Plain ChaCha20-Poly1305 with
   nonce = block number reuses nonces when CoW reallocates freed block
   numbers — harmless with the all-zero Phase-2 stub key, fatal with a real
   one.
5. **Governance.** NCIP-FS-018 and Wire-023 each went Draft→Active same-day
   on a single 100%-weight ballot; permanent artifacts (on-disk formats,
   crypto selections) had no independent-review requirement.

## Decisions

### D1 — Fail closed on metadata overflow (shipped)

`OnDiskVolume::sync_to_bytes` now returns
`Result<Vec<u8>, FsError>` and rejects with the new
`FsError::MetadataOverflow` when the bitmap (> 4096 B, i.e.
`total_blocks > MAX_V1_TOTAL_BLOCKS` = 32 768), the serialised inode table
(> 4096 B), or the integrity tags (> 170 entries) would not fit their
single block. Additionally, `create_file` / `create_directory` /
`write_file` carry **operation-time guards** (exact projected sizes,
checked before any allocation) so the volume can never reach an
unserialisable state; a rejected operation leaves the volume untouched.
`FsService::sync_ondisk_to_bytes` propagates the error; `nexacore-fsd` logs
`sync_to_bytes FAILED: metadata overflow — sync aborted` and aborts the
sync, leaving the previous on-disk image intact. Silent truncation is
forbidden permanently (`write_integrity_tags`' bound is now defence in
depth, unreachable from the public API).

### D2 — Path-preserving inode encoding; on-disk version 1 → 2 (shipped)

Inode records now serialise the **full absolute path** (the record from
which `path_map` is rebuilt at mount); the in-memory `name` is derived as
the basename. Nested hierarchies and same-basename files round-trip
exactly. Because this changes the byte encoding, `NEXACORE_FS_VERSION` is
bumped **1 → 2** and version-1 images are rejected at mount — fail closed,
per Wire-023's own "new version, never silent reinterpretation" rule.
Operational consequence accepted: a v1 image still carries the `OMNIFS01`
magic, so `nexacore-fsd` takes the ADR-0037 D3 **hard-error path** (logs
`mount FAILED (integrity/parse) — NOT overwriting`, exit 5) — it does NOT
reformat, by design (a recognised-magic volume may hold real data). The
the test VM test image is tmpfs-backed: a host reboot clears it (the
absent-magic fallback then formats fresh v2), or the operator zeroes
`/tmp/nvme-test.img` manually. One-time migration step, documented in
the development plan WS3-01. Wire-023 carries a dated erratum note recording the v2
encoding.

### D3 — NCIP-FS-Wire-027 (Draft): the structural fix

The format-level defects (no atomic commit, single-block metadata caps,
name-in-inode, missing fingerprint, SC7 violation, no snapshots) are not
patchable inside the v1 layout. NCIP-FS-Wire-027 specifies format v3: dual
superblock A/B with generation numbers and a MAC'd root pointer (commit =
one atomic 4 KiB write; mount = highest valid generation; "no fsck"
becomes true), CoW metadata objects (all single-block caps removed),
extent-based mapping (2⁶³ B files, reconciling §S1.1), directory objects
with 255-byte NFC entries, the 32-byte capability fingerprint at inode
offset 40, a Merkle integrity tree rooted in the committed superblock,
mandatory XChaCha20-Poly1305 (or AES-256-GCM-SIV per NCIP-Crypto-002) with
nonces derived from `(generation, physical_block)` — unrepeatable by the
commit rule — a BLAKE3-KDF key hierarchy off the TEE-sealed master key
with domain separation, and `key_epoch` for cryptographic erasure (PC3).
Snapshots are retained roots (O(1)). It supersedes Wire-023 on activation.

### D4 — NCIP-Review-Gate-028 (Draft): independent review before format/crypto freezes

Amending NCIP-Process-001 directly would itself violate the process
(governance changes require an NCIP, §3.4). NCIP-028 therefore adds, via the
proper channel, an activation precondition for Standards Track NCIPs that
define on-disk/wire formats or select cryptographic primitives: at least
one documented independent technical review (non-author; crypto reviews
require demonstrable crypto competence), recorded under `docs/audits/` and
in the NCIP's amendment history. Fast-track and single-voter ballots remain
valid for everything else. Wire-027 §S9 additionally self-imposes:
cryptographer review (SC1), a write-prefix crash-consistency harness
passing on QEMU + the test VM, recorded BLAKE3-vs-Poly1305 benchmarks, and a
mount/parse fuzz corpus — all before Active.

### D5 — Compliance matrix as a living document

`docs/ncfs-compliance-matrix.md` records, for every NCIP-FS-018 §S1.1
parameter: specified vs wire format vs implementation vs tests. Update
rule: any PR touching `crates/nexacore-fs` or `ncips/ncip-fs-*` updates the
matrix in the same change. The spec-vs-reality gap stays explicit instead
of being rediscovered by audits.

### D6 — Implementation sequencing (the development plan WS3-01)

Order is dependency-driven: (1) lazy block-device trait
(`read_block`/`write_block`/`flush`/`commit_root`) replacing whole-volume
`&[u8]` mounting — lifts the ADR-0037 128-block cap and is the substrate
for (2) the dual-superblock commit, then (3) CoW metadata objects /
extents / directories, then (4) real keys + AEAD via TEE keystore, then
(5) snapshots. No work on higher features (send/receive, resize) before
the atomic commit exists — anything built on the v1 sync model is rework.

## Alternatives considered

- **Keep version 1 and accept both encodings at mount** — rejected: a v1
  image misparses as v2 (paths without leading `/`), which is exactly the
  "silent reinterpretation" Wire-023 forbids. Fail closed instead.
- **Reject sub-directory creation until v3** (instead of the v2 path
  encoding) — rejected: regresses shipped functionality (TASK-23 directory
  CRUD) and leaves the editor/file-manager unable to use folders.
- **Enforce capacity only in `sync_to_bytes`** (no operation-time guards) —
  rejected: an over-full volume would accept writes it can never persist;
  failing at the write site gives the caller an actionable error and an
  unchanged volume.
- **Patch a root pointer into Wire-023 as another erratum** — rejected: an
  atomic-commit mechanism is a new format, not an erratum; smuggling it in
  without the §S9 review gates is the anti-pattern NCIP-028 exists to stop.
- **Amend NCIP-Process-001 in place for the review gate** — rejected:
  governance changes must themselves go through an NCIP (Process-001 §3.4).

## Consequences

- `nexacore-fs`: +6 unit tests (118 total in-crate: hardening module covers
  nested paths, basename collisions, all three overflow guards, the
  guard-constant pin, and v1-image rejection); all 112 unit + 82 doctests
  green; clippy clean; `nexacore-fsd-image` checks clean for
  `x86_64-unknown-none`; `nexacore-runtime` (dependent) unaffected, suite
  green.
- Public API: `sync_to_bytes` and `sync_ondisk_to_bytes` are now fallible
  (pre-1.0 crate; the only external consumer, `nexacore-fsd-image`, updated in
  the same change). New public `MAX_V1_TOTAL_BLOCKS` and
  `FsError::MetadataOverflow` (enum is `#[non_exhaustive]`).
- On-disk: version-2 volumes only. The existing v1 boot-counter image on
  the test VM hits the D3 hard-error path (no silent reformat); it is cleared
  by the next host reboot (tmpfs) or by manually zeroing
  `/tmp/nvme-test.img`, after which the absent-magic fallback formats a
  fresh v2 volume.
- Registry: NCIP index gains 027 (Standards Track, Draft) and 028 (Process,
  Draft); Wire-023 carries the erratum note; FS-018 carries the
  reconciliation amendment row. `scripts/lint-ncips.py`: 0 errors across 31
  files.
- The documented-limits posture is restored: every known gap is now either
  fixed in code, specified in a Draft NCIP with activation gates, or listed
  in the compliance matrix. No silent caps remain.
