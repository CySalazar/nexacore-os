# NCFS Compliance Matrix — NCIP-FS-018 §S1.1 vs. reality

> **Purpose.** NCIP-FS-018 §S1.1 freezes the quantitative parameters of
> NCFS. This matrix records, for every frozen parameter, what the
> **active wire format** specifies, what the **implementation**
> (`crates/nexacore-fs`) does today, and whether a **test** pins the behaviour.
> It exists so the gap between specification and reality is always explicit
> — never discovered by an audit again (see ADR-0051).
>
> **Update rule.** Any PR that changes `crates/nexacore-fs`, `ncips/ncip-fs-*`,
> or the NCFS sections of the docs MUST update this file in the same
> change. Stale rows are treated as documentation bugs.
>
> Last updated: **2026-06-12** (ADR-0051 hardening pass; NCIP-FS-Wire-027
> and NCIP-Review-Gate-028 filed as Draft; Wire-027 amended with the
> §S2.1 policy object — per-volume adaptive profiles under an invariant
> floor).

Legend: ✅ conforms · 🟡 partial / stopgap · ❌ not implemented ·
✔ by-design exclusion honoured. "Wire" = active on-disk format
(NCIP-FS-Wire-023, encoding v2 erratum) unless noted; NCIP-FS-Wire-027
(Draft) is the reconciliation target.

| §S1.1 parameter (frozen) | Specified | Wire format (023 v2) | Implementation (`nexacore-fs`) | Status | Tested |
|---|---|---|---|---|---|
| Logical block size | 4 KiB fixed | 4 KiB | 4 KiB (`BLOCK_SIZE`, asserted vs `nexacore_types::blk`) | ✅ | yes |
| Max volume size | 2⁷⁶ B (64 ZiB) | 128 MiB (1-block bitmap, `MAX_V1_TOTAL_BLOCKS` = 32 768 blocks) | same; **fail-closed** above (`MetadataOverflow`); deployed root = 512 KiB (ADR-0037) | 🟡 | `sync_rejects_bitmap_larger_than_one_block` |
| Max file size | 2⁶³ B (8 EiB) | ~1 GiB by §S2 layout (027 → 2⁶³ via extents) | direct pointers only; bounded by 1-block inode table AND 170-entry tag region (~680 KiB tagged data/volume); fail-closed | 🟡 | `write_file_rejects_integrity_region_overflow` |
| Max files per volume | Unbounded (dynamic) | 1-block inode table (027 → unbounded CoW objects) | a few dozen (path-length dependent); **fail-closed** (`MetadataOverflow`) | 🟡 | `create_file_rejects_inode_table_overflow_…` |
| Max filename length | 255 B UTF-8 **NFC** | 023 §S2: 95 B, no normalisation (027 → 255 B NFC dir entries) | name = basename of path; no NFC normalisation | ❌ | no |
| Max path length | 4096 B | 4096 B (`MAX_PATH_LEN`) | enforced (`PathTooLong`) | ✅ | yes |
| Nested directory persistence | implied by namespace model | **v1 encoding lost it**; v2 erratum stores full paths | full paths round-trip across mount | ✅ (since v2) | `nested_directory_hierarchy_survives_remount`, `same_basename_in_two_directories_does_not_collide` |
| Integrity primitive | BLAKE3-keyed MAC 256-bit (default; NCIP-Crypto-002 binds) | ChaCha20-Poly1305 16-B tag per block | implemented, **all-zero stub key** → detects accidental corruption only, forgeable | 🟡 | tamper tests in `lib.rs` |
| Integrity verification on read | Mandatory, non-disablable | mandatory | every `read_file` verifies; `IntegrityViolation` on mismatch | ✅ (with stub-key caveat) | yes |
| Confidentiality (encryption at rest) | Mandatory per-volume, metadata included (PC1) | absent in 023 (027 §S7: mandatory XChaCha20-Poly1305) | **absent — data and names in plaintext** | ❌ | n/a |
| Nonce-misuse resistance (SC7) | required | 023 scheme violates it under CoW realloc (027: `(generation, block)` derivation) | stub key makes it moot today; scheme must not ship with a real key | ❌ | `nonce uniqueness` property is 027 §T5 |
| Capability fingerprint (32 B/inode) | required (§S1) | **absent from 023 inode** (027 §S4: offset 40) | absent | ❌ | n/a |
| Crash consistency / atomic commit | CoW root, "fsck: none" | **no root pointer in 023** — in-place metadata; (027 §S1: dual superblock + generation) | whole-volume rewrite on sync; `fsck()` exists and is needed | ❌ | 027 §T1 harness is the gate |
| Hard links | NOT supported (by design) | absent | absent | ✔ | n/a |
| Symbolic links | Supported | absent (027 §S4 type 2) | absent | ❌ | n/a |
| Reflinks / clones | Supported | absent (027 §S3/§S8) | absent | ❌ | n/a |
| Extended attributes | Supported, capability-tagged | absent | absent | ❌ | n/a |
| Compression | Opt-in ZSTD, default OFF | absent | absent | ❌ | n/a |
| Deduplication | NOT supported in v1 (by design) | absent | absent | ✔ | n/a |
| Multi-device | NOT supported in v1 (by design) | absent | absent (single BLK channel) | ✔ | n/a |
| Snapshots | O(1), atomic, unlimited | no mechanism in 023 (027 §S8: retained roots) | absent | ❌ | 027 §T7 |
| Clones (writable snapshots) | Supported | absent | absent | ❌ | n/a |
| `fsck` requirement | None (CoW root recovery) | 023 needs it (no root); `fsck()` shipped | 4-check `fsck()` implemented | 🟡 (inverted: present because needed) | yes |
| TRIM / discard | On CoW retirement, 24 h window | absent | absent | ❌ | n/a |
| Online resize (grow) | Supported | absent | absent | ❌ | n/a |
| Online resize (shrink) | Supported (scrub-and-relocate) | absent | absent | ❌ | n/a |
| Send / receive | Supported | absent (027 §S8: verifiable streams) | absent | ❌ | n/a |
| Cryptographic erasure (PC3) | Required | absent (027 §S7: `key_epoch`) | absent | ❌ | 027 §T6 |

## Adaptive profiles (Wire-027 §S2.1 — beyond §S1.1)

| Aspect | Specified | Implementation | Status | Tested |
|---|---|---|---|---|
| Policy object (CoW, commit-root-referenced) + `profile_id` in superblock | Wire-027 §S2.1 (Draft) | absent | ❌ | 027 §T8 |
| Named per-volume profiles (`interactive`/`gaming`/`server`/`high-assurance`/`archive`) | Wire-027 §S2.1; semantics deferred to `NCIP-FS-Profiles-NNN` (not yet filed) | absent | ❌ | n/a |
| Invariant floor (schema cannot express weakening of integrity/encryption/commit/capability) | Wire-027 §S2.1, normative | absent | ❌ | 027 §T8 schema test |
| Session overlays (runtime-only) / enterprise pinning / `fs:policy` capability | Wire-027 §S2.1; plan WS3-09 | absent | ❌ | 027 §T8 |
| AI auto-adaptation (secp telemetry → recommend → consent → apply) | NCIP-Agent-Arch-022 §S6.1/§S6.3 + NCIP-Helper-007 autonomy levels; plan WS16-07 | absent | ❌ | n/a |

## Operations surface (informative)

Implemented and tested: `create_file`, `write_file` (CoW, read-modify-write,
sparse), `read_file` (tag-verified, short reads), `delete_file`,
`create_directory`, `delete_directory` (empty-only, root-protected),
`stat_file`, `list_directory`, `exists`, `fsck`, `format`, `mount`
(fail-closed on magic/version/truncation), `sync_to_bytes` (fail-closed on
metadata overflow). **Absent:** `rename`, `truncate`, permissions/ownership,
timestamps (HAL `Clock` pending — fields are zero).

## Remediation path

1. **Shipped 2026-06-12 (ADR-0051):** fail-closed serialisation
   (`FsError::MetadataOverflow` + operation-time guards), path-preserving
   inode records (encoding v2, version bump 1→2, fail-closed for v1
   images), daemon surfaces sync failure on serial.
2. **NCIP-FS-Wire-027 (Draft):** dual-superblock CoW root commit, extents
   (8 EiB), directory objects (255 B NFC), capability fingerprint,
   Merkle-rooted integrity, mandatory AEAD with safe nonces, key epochs,
   snapshots, §S2.1 policy object (adaptive profiles under an invariant
   floor). Supersedes 023 on activation.
3. **NCIP-Review-Gate-028 (Draft):** no format/crypto NCIP activates without
   documented independent review; Wire-027 additionally gates on
   cryptographer review, crash-consistency harness, benchmarks, fuzzing
   (027 §S9).
4. **Implementation sequencing:** the development plan WS3-01 (block-device trait
   first, then commit, then objects, then crypto).
