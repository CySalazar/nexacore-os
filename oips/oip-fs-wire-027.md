---
ncip: 27
title: NCFS On-Disk Format v3 — CoW Root Commit, Extents, Directory Objects, Merkle Integrity, Authenticated Encryption
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-06-12
updated: 2026-06-12
requires:
  - 2
  - 14
  - 18
supersedes: 23
superseded-by: ~
discussion: ~
license: CC0-1.0
---

# NCIP-FS-Wire-027 — NCFS On-Disk Format v3

> **Status note (filing, 2026-06-12):** this NCIP is filed as `Draft` and
> intentionally NOT fast-tracked. Per the §S9 activation gates below (and the
> independent-review gate of `NCIP-Review-Gate-028`), it MUST NOT
> transition to `Active` before a documented independent technical review, a
> cryptographer review of §S6–§S7, passing crash-consistency results from the
> §T1 harness, and the §S9.3 benchmark numbers are attached. Freezing an
> on-disk format without contradictory review is the failure mode this NCIP
> exists to prevent.

## Abstract

This NCIP specifies NCFS on-disk format **v3**, superseding the v1 format of
`NCIP-FS-Wire-023` (and its v2 encoding erratum). Version 3 closes the gap
between the architectural promises frozen in `NCIP-FS-018` §S1.1 and what the
v1 format can actually deliver. Five structural changes: (1) a **dual
superblock with generation numbers and a copy-on-write root pointer**, making
every commit atomic and making "mount the latest valid root" the real — not
aspirational — recovery model; (2) **extent-based file mapping**, lifting the
maximum file size from ~1 GiB (v1 double-indirect pointers) to the 2⁶³ bytes
frozen in NCIP-018 §S1.1; (3) **directory objects with real entries**
(255-byte UTF-8 NFC names), replacing basename-in-inode storage; (4) a
**Merkle-structured integrity tree** whose root lives in the committed
superblock, giving whole-volume authenticated state; (5) **mandatory
authenticated encryption** with a nonce-misuse-safe scheme derived from
`(generation, block_number)` and a TEE-rooted key hierarchy with epochs for
cryptographic erasure. The inode gains the 32-byte capability fingerprint
field that NCIP-018 §S1 mandates and v1 omitted. Snapshots become a retained
root pointer — O(1), as promised. A reserved per-volume **policy object**
(§S2.1) makes context-adaptive profiles (home, gaming, server,
high-assurance) first-class and CoW-versioned, under a normative "invariant
floor": profiles tune policy, but can never express a weakening of
integrity, confidentiality, or commit atomicity.

## Motivation

### M1. The v1 format does not implement the consistency model NCIP-018 promises

`NCIP-FS-018` rationalises "no journal, no fsck" with CoW-root atomicity
("mount latest valid root"). The v1 format of `NCIP-FS-Wire-023` has **no root
pointer and no CoW metadata tree**: superblock, bitmap, and inode table are
fixed regions updated in place. The claimed atomicity (a single 8-byte inode
pointer write) does not cover the multi-block, non-atomic
superblock+bitmap+inode-table transaction. Structurally, v1 is ext2 with CoW
data blocks. The crash-consistency guarantee that justifies the entire
no-journal design exists in neither the spec nor the implementation. v3 makes
it real.

### M2. Metadata capacity and silent truncation

The v1 layout reserves exactly one 4 KiB block each for bitmap, inode table,
and integrity tags. The original implementation silently truncated these
regions on overflow — losing metadata without an error. The implementation
now fails closed (`FsError::MetadataOverflow`, encoding v2 erratum), but the
single-block limits themselves (128 MiB volume, ~25 inodes, 170 tagged
blocks) are format-level and need a format-level fix: CoW metadata objects of
unbounded size (§S2).

### M3. Nested directory hierarchies did not survive a mount

v1 inodes stored only the basename; mount reconstructed every path as
`/<basename>`, silently flattening hierarchies and colliding same-named files
in different directories. The encoding-v2 erratum stores full paths as a
stopgap; the structural fix is real directory objects (§S5) in which an
entry, not the inode, owns the name.

### M4. The frozen §S1.1 parameters are unreachable in v1

NCIP-018 §S1.1 freezes 8 EiB max file and 255-byte NFC names, and forbids the
wire-format NCIP from changing them. The v1 inode (12 direct + 1 indirect +
1 double-indirect, 95-byte name field) caps files at ~1 GiB and names at
95 bytes. v1 also omits the 32-byte capability fingerprint that NCIP-018 §S1
mandates on every inode. v3 reconciles the wire format with the frozen
parameters instead of quietly contradicting them.

### M5. The v1 AEAD scheme violates NCIP-018 SC7 under CoW reallocation

NCIP-018 SC7 requires a nonce-misuse-resistant AEAD. The v1 scheme
(ChaCha20-Poly1305, nonce = block number, single long-lived key) reuses
nonces structurally: CoW frees blocks and the allocator reuses their numbers
for different plaintext. Harmless while the key is the all-zero Phase-2 stub;
fatal the day real encryption ships. v3 fixes the nonce derivation and the
key hierarchy before any real key exists, so the unsafe scheme is never
deployed.

## Specification

Normative keywords per RFC 2119. The logical block size remains **4 KiB
fixed** (NCIP-018 §S1.1, unchanged). The superblock magic remains
`b"OMNIFS01"`; the `version` field is **3**. Readers MUST reject any
magic/version they do not implement (no silent reinterpretation).

### S1. Dual superblock and atomic commit

- Two superblock slots: **SB-A at block 0** and **SB-B at the last block** of
  the volume. Each contains: magic, version, `generation: u64`,
  `root_object: u64` (block address of the commit root), `total_blocks`,
  `key_epoch: u64`, `aead_key_id`, `profile_id: u32` (§S2.1), `created_at`,
  flags, and a 32-byte **self-MAC** (keyed BLAKE3 over the superblock bytes)
  that authenticates the slot.
- A **commit** proceeds: (1) write all new data and metadata objects to free
  blocks (never overwriting live blocks of the current generation); (2) write
  the integrity-tree nodes up to a new root (§S6); (3) write the alternate
  superblock slot with `generation + 1`, the new `root_object`, and a valid
  self-MAC. Step 3 is a single 4 KiB block write — the NVMe atomic write unit
  (NCIP-Driver-NVMe-014) — and is the commit point.
- **Mount** reads both slots, discards any slot whose self-MAC or
  magic/version fails, and mounts the valid slot with the **highest
  generation**. A crash at any point leaves at least one valid slot: before
  step 3 the old generation is intact; after step 3 the new one is. There is
  no torn intermediate by construction.
- Blocks freed by generation N MUST NOT be reallocated before generation
  N+1 commits, and MUST be TRIM-eligible only after the configured retention
  window (NCIP-018 §S1.1 TRIM row).
- `fsck` is therefore not required for recovery (the NCIP-018 model becomes
  true); `nexacore-fs-verify` remains as an audit tool.

### S2. CoW metadata objects

All metadata are **objects**: sequences of 4 KiB blocks referenced (directly
or via the extent structure of §S3) from the commit root. The commit root
references: the **allocator object** (free-space bitmap, multi-block, sized
⌈total_blocks/32768⌉ blocks), the **inode tree object** (B+-tree keyed by
inode number, 256-byte records), the **root directory object** (§S5), the
**integrity tree root** (§S6), and the **policy object** (§S2.1). Updating
any metadata block follows the same CoW rule as data: write a new block,
re-point the parent, never touch the live generation. This removes every
single-block metadata cap of v1 (volume size, inode count, tagged-block
count become bounded only by volume capacity, per NCIP-018 §S1.1 "unbounded
files per volume" and 64 ZiB volume).

### S2.1. Policy object — per-volume adaptive profiles

Each volume carries a **policy object**: a CoW metadata object holding the
volume's **profile** — the set of context-adaptive parameters (commit
cadence and batching, extent-allocation policy, compression defaults,
snapshot/retention and TRIM windows, scrub scheduling, cache/writeback
sizing, chaff policy per NCIP-018 SC6, key-unlock UX class). A `profile_id:
u32` field in the superblock identifies the named preset (e.g.
`interactive`, `gaming`, `server`, `high-assurance`, `archive`) for
mount-time and UI display; the policy object holds the parameter vector.

**Invariant floor (normative).** Profiles tune *policy*, never *protocol*.
The policy-object schema MUST NOT be able to express: disabling integrity
verification, disabling confidentiality, weakening the §S1 commit
protocol, bypassing capability binding, or re-enabling silently-truncating
behaviour. This is a schema-level guarantee (no such fields exist), not a
runtime check — a compromised agent cannot *request* a floor violation.
Consequently the §S1 crash-consistency argument and the §T1 harness cover
every profile without a configuration matrix: profiles change scheduling
and layout policy only.

**Atomicity, audit, revert.** A profile change is a normal CoW commit:
atomic, versioned, and revertible like any other write; each change
carries an audit record (requesting agent, autonomy level, telemetry
justification). Transient **session overlays** (e.g. cache boost during a
fullscreen game) are runtime-only and MUST NOT be persisted to the policy
object. Enterprise deployments MAY **pin** the policy object (a pinned
flag makes further profile commits require an explicit administrative
capability), disabling or bounding automatic adaptation.

**Semantics deferred.** This NCIP reserves the on-disk structure only. The
profile parameter semantics, the local-only telemetry schema exported by
the FS service, the workload-classification and hysteresis rules, and the
mapping of profile dimensions to user-autonomy levels are specified in a
follow-up NCIP (`NCIP-FS-Profiles-NNN`), integrating the Security &
Performance Agent's monitoring/optimization mandate
(`NCIP-Agent-Arch-022` §S6.1/§S6.3) and the NCIP-Helper-007 autonomy levels.
Security-relevant dimensions (chaff, key policy, compliance retention)
MUST NOT be auto-adapted without explicit consent.

### S3. Extent-based file mapping

- An **extent** is `(logical_block: u64, physical_block: u64, length: u32)`
  — 20 bytes packed, covering up to 2³² consecutive blocks (16 TiB) per
  extent.
- Each inode embeds **4 inline extents** (covering small files without
  indirection) plus one `extent_tree: u64` pointer to a B+-tree of extents
  for larger files. Maximum file size is bounded by the signed 64-bit size
  accumulator: **2⁶³ bytes**, matching NCIP-018 §S1.1.
- Sparse files: absent logical ranges read as zeros (unchanged semantics).
- Reflinks (NCIP-018 §S1.1) are extent-tree nodes shared between inodes with
  per-extent refcounts in the allocator object; hard links remain
  unsupported by design.

### S4. Inode record v3 (256 bytes, fixed)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `inode_number` |
| 8 | 1 | `file_type` (0 file, 1 directory, 2 symlink) |
| 9 | 7 | reserved (zeroed) |
| 16 | 8 | `size` |
| 24 | 8 | `created` |
| 32 | 8 | `modified` |
| 40 | 32 | **`capability_fingerprint`** (NCIP-018 §S1, BLAKE3-256 of the canonical NexaCoreCapability) |
| 72 | 8 | `key_epoch` (encryption epoch for cryptographic erasure, §S7) |
| 80 | 8 | `flags` (compression, chaff policy, reserved bits) |
| 88 | 80 | 4 × inline extent (20 bytes each) |
| 168 | 8 | `extent_tree` (0 = none) |
| 176 | 80 | reserved (zeroed) |

**The inode carries no name.** Names live exclusively in directory entries
(§S5). Timestamps are HAL-epoch seconds and MUST be populated once the HAL
`Clock` lands (zero remains the explicit "unknown" sentinel, not a stub
convention).

### S5. Directory objects

A directory's data blocks contain a packed sequence of entries:

```
entry := inode_number(8) | entry_len(2) | name_len(2) | name(≤255, UTF-8 NFC)
```

- `name_len` ≤ **255 bytes**, UTF-8, **NFC-normalised at create time**
  (NCIP-018 §S1.1; rejects Unicode-confusable path attacks). Writers MUST
  reject non-NFC names; readers MUST treat byte-identical names as the only
  equality.
- Path resolution walks directory objects from the root directory; the v1/v2
  flat `path_map` disappears from the format (it MAY remain an in-memory
  cache).
- Symlinks (§S4 type 2) store the target path as the file content, resolved
  at lookup with the target's own capability check (NCIP-018 §S1.1).

### S6. Merkle integrity tree

- Every allocated block (data AND metadata) has a tag. Default primitive
  per NCIP-018 §S1.1: **keyed BLAKE3, 256-bit output**, key from the §S7
  hierarchy. (If `NCIP-Crypto-002` is amended to select a different MAC, that
  amendment binds here without re-opening this NCIP.)
- Tags are stored in a **Merkle tree**: leaves are per-block tags, internal
  nodes are keyed BLAKE3 over their children, and the **root digest is a
  field of the committed superblock slot** (§S1). Verification on read is
  mandatory and non-disablable (volumes with verification disabled MUST NOT
  mount — NCIP-018 §S1.1).
- Consequences: (a) a single root comparison authenticates the entire volume
  state at mount; (b) snapshot send/receive streams are verifiable against
  the snapshot's root digest; (c) the BLAKE3 tree mode aligns with the CoW
  structure, so a commit recomputes only the path from changed leaves to the
  root.

### S7. Authenticated encryption and key hierarchy

- **Confidentiality is mandatory per volume** (NCIP-018 §S1.1): all data
  blocks and all metadata objects (directory entries included — file names
  are PII, NCIP-018 PC1) are encrypted. Plaintext volumes are not mountable.
- **AEAD: XChaCha20-Poly1305** (192-bit nonce) as the default proposal;
  AES-256-GCM-SIV is the acceptable alternative where AES hardware is
  attested. Final binding selection follows `NCIP-Crypto-002`; both satisfy
  NCIP-018 SC7. Plain ChaCha20-Poly1305 with deterministic block-number
  nonces (the v1 scheme) is **forbidden**: CoW reallocation reuses block
  numbers and therefore nonces.
- **Nonce derivation**: `nonce = BLAKE3-derive(key=nonce_subkey, input =
  generation(8) || physical_block(8))` truncated to 192 bits. A
  `(generation, block)` pair is written at most once by the §S1 commit rule,
  so nonces never repeat under a given key; the 192-bit space additionally
  tolerates random fallback.
- **Key hierarchy**: TEE-sealed **volume master key** (identified by
  `aead_key_id`, never on disk) → BLAKE3-KDF → subkeys with distinct
  domain-separation contexts: `data-enc`, `meta-enc`, `integrity-mac`,
  `nonce`, `sb-mac`. Each subkey derivation includes the **`key_epoch`**.
- **Cryptographic erasure** (NCIP-018 PC3): revoking the master key erases
  the volume; bumping `key_epoch` (per volume, and per inode via the §S4
  field) erases the keys of prior-epoch content once its blocks are retired
  — the GDPR Article 17 mechanism, wired to the Helper deletion UI.

### S8. Snapshots, clones, send/receive

- A **snapshot** is a retained `(generation, root_object, integrity_root)`
  triple recorded in a snapshot table object referenced by the commit root.
  Creation is a single commit — **O(1), atomic, unlimited count** (NCIP-018
  §S1.1). Blocks referenced by any retained snapshot are exempt from
  reallocation and TRIM.
- A **clone** is a snapshot root copied as the base of a new writable inode
  tree; divergence is per-block via the §S3 refcounts.
- **Send/receive**: the delta between two snapshots is the set of blocks
  reachable from the newer root and not the older; the stream carries the
  blocks plus the integrity-tree path to the new root, making the stream
  verifiable end-to-end.

### S9. Activation gates (normative for this NCIP's own lifecycle)

This NCIP MUST NOT transition to `Active`, and the v3 format MUST NOT be
frozen, before ALL of the following are attached to the NCIP as dated
amendments:

1. **Independent technical review** — at least one documented review by a
   reviewer who is not an author of this NCIP (per `NCIP-Review-Gate-028`,
   the independent-review gate for on-disk-format and cryptographic NCIPs).
   The review MUST cover §S1 commit semantics and §S7 nonce/key design at
   minimum.
2. **Cryptographer review** of §S6–§S7 (the engagement template at
   `docs/audits/cryptographer-engagement-template.md`), per NCIP-018 SC1.
3. **Crash-consistency harness results**: the §T1 write-prefix harness
   passing on QEMU and on the Proxmox test VM (every prefix of every recorded
   commit sequence mounts to a valid generation).
4. **Benchmarks**: keyed-BLAKE3 vs Poly1305 tag throughput on 4 KiB blocks,
   and end-to-end read-path overhead of mandatory verification, measured on
   the reference targets; numbers recorded in the NCIP, not adjectives.
5. **Fuzzing**: a mount/parse fuzz corpus with no memory-safety findings
   (panics acceptable, per the driver-isolation model).

### S10. Migration from v1/v2 volumes

Readers of version 3 MUST reject version 1/2 volumes (and vice versa).
Migration is **one-way copy**: mount the old volume read-only with the v1/v2
reader, copy into a freshly formatted v3 volume, verify, then retire the old
volume. In-place conversion is forbidden (consistent with NCIP-018 §S9's
no-in-place-conversion policy). The 128-block root volume of ADR-0037 makes
this a sub-second operation in practice.

## Rationale

### Why dual superblock + generation instead of a journal

A journal doubles write amplification on the very writes it protects and
adds a replay path that needs its own correctness argument. The dual-slot
commit makes the *existing* CoW write path atomic with exactly one extra
block write per commit, and the recovery path ("pick highest valid
generation") is the mount path — no separate replay code to get wrong. This
is the mechanism ZFS (überblock ring) and modern CoW designs use; v1's
in-place metadata was the anomaly.

### Why extents instead of more indirect levels

A third indirection level would reach large files but keeps O(file-size)
metadata and per-block pointer chasing. Extents make contiguous files (the
dominant case for AI model weights, this filesystem's primary workload)
nearly metadata-free, align with the frozen 8 EiB ceiling, and are the
proven design of XFS/Btrfs/APFS. Inline extents keep small files cheap.

### Why names move to directory entries

A name-in-inode design forces exactly the basename/path ambiguity that
produced the v1 flattening bug, caps name length by inode geometry, and
makes hard-link-like aliasing impossible to even express. Entries owning
names is the universal design for a reason; it also lets two directories
hold equal names without inode-level collision by construction.

### Why a Merkle tree instead of a flat tag region

A flat region authenticates blocks individually but not the *set* — an
attacker with disk access can roll back individual blocks together with
their tags. Rooting the tag tree in the MAC'd, generation-numbered
superblock authenticates the whole volume state and gives verifiable
send/receive for free. BLAKE3's native tree mode was selected in NCIP-018
§S1.1 partly for this alignment.

### Why profiles are an on-disk CoW object and not mount options

Mount-option tunables are how filesystems accumulate untestable
configuration matrices and silently-weakened guarantees (ext4
`data=writeback` being the canonical foot-gun). Making the profile a CoW
object gives three properties mount options cannot: the configuration is
part of the committed, integrity-protected volume state (it cannot drift
from what the volume actually was at a generation); changes are atomic,
audited, and revertible like data; and the invariant floor is enforced by
the schema rather than by operator discipline. Per-volume granularity
(via the NCIP-018 §S8 capability mount model) replaces the global mode
switch: a machine holds a `gaming` volume and an `interactive` volume
simultaneously, and adaptation — automatic or suggested, per the
NCIP-Helper-007 autonomy levels — moves one volume at a time with
hysteresis, never the whole system at once.

### Why XChaCha20-Poly1305 over AES-GCM-SIV as default

Both satisfy SC7. XChaCha20-Poly1305 is constant-time in software on every
target (no AES-NI dependency — relevant for a microkernel that must not
trust unattested hardware acceleration), is already in the project's
RustCrypto `no_std` dependency set, and its 192-bit nonce makes the derived
scheme robust even under derivation-context mistakes. GCM-SIV's two-pass
structure also costs more on the write path. The final word stays with
NCIP-Crypto-002, as NCIP-018 already established.

### Reconciliation with NCIP-018 §S1.1 (the point of this NCIP)

| §S1.1 frozen parameter | v1 (Wire-023) | v3 (this NCIP) |
|---|---|---|
| Max file 2⁶³ B | ~1 GiB | 2⁶³ B (§S3) |
| Max volume 2⁷⁶ B | 128 MiB (1-block bitmap) | bounded by 64-bit addressing (§S2) |
| Names 255 B NFC | 95 B, no normalisation | 255 B NFC (§S5) |
| Files per volume unbounded | ~25 (1-block table) | unbounded (§S2) |
| Capability fingerprint per inode | absent | 32-byte field (§S4) |
| Snapshots O(1) atomic | no mechanism | retained roots (§S8) |
| Integrity mandatory | tags, flat, stub key | Merkle-rooted, keyed (§S6) |
| Confidentiality mandatory | absent | mandatory AEAD (§S7) |
| Nonce-misuse resistance (SC7) | violated under realloc | (generation, block) scheme (§S7) |
| No fsck needed (CoW root) | false (no root) | true (§S1) |

## Backwards Compatibility

v3 supersedes `NCIP-FS-Wire-023` upon activation; until then Wire-023 remains
the Active format and carries an erratum note pointing here. Version 1/2
volumes fail closed under a v3 reader (magic/version gate, §S10) and are
migrated by one-way copy. No deployed volume outlives a host reboot today
(ADR-0037: tmpfs-backed test image), so the practical migration surface is
nil; the gate exists for correctness, not convenience.

## Test Cases

- **T1 (crash consistency, gating)**: record the block-write sequence of N
  randomized commit workloads; for EVERY prefix of every sequence, mounting
  the prefix image MUST yield a valid volume at either the pre-commit or
  post-commit generation — never an error, never a mix. Run on QEMU and
  the Proxmox test VM (the ADR-0037 BLK path).
- **T2 (hierarchy)**: nested directories, same basename in sibling
  directories, 255-byte NFC names, non-NFC rejection — all across remount.
- **T3 (extents)**: a sparse 1 TiB-logical file with three extents
  round-trips; reads in holes return zeros; reflink shares extents with
  refcount accounting.
- **T4 (integrity)**: any single tampered byte — data block, directory
  block, inode block, integrity node, superblock — is detected at read or
  mount; per-block rollback with matching old tag is detected via the root.
- **T5 (nonce uniqueness)**: property test that no `(key_epoch, generation,
  physical_block)` triple repeats across a recorded multi-commit history.
- **T6 (erasure)**: after `key_epoch` bump and block retirement, prior
  content is unrecoverable from the raw image with the current master key.
- **T7 (snapshots)**: snapshot creation cost is O(1) in blocks written;
  reads from a retained snapshot are stable while the head diverges.
- **T8 (profiles)**: a profile change commits atomically and is revertible
  by generation rollback; the §T1 harness passes identically under every
  named profile; a schema-level test proves the policy object cannot
  encode any invariant-floor violation (no such field deserialises); a
  pinned policy object rejects profile commits lacking the administrative
  capability.

## Reference Implementation

Phased in `crates/nexacore-fs`, sequenced per ADR-0051: (1) the lazy
block-device trait (`read_block`/`write_block`/`flush`/`commit_root`)
replaces whole-volume `&[u8]` mounting (lifts the ADR-0037 128-block cap);
(2) §S1 dual-superblock commit on that trait; (3) §S2–§S5 objects; (4)
§S6–§S7 crypto integration behind the `nexacore-crypto`/TEE keystore; (5) §S8
snapshots. The v2-encoding hardening already shipped (fail-closed
serialisation, path-preserving records, `MetadataOverflow` guards) keeps the
current implementation safe while v3 lands.

## Security Considerations

- **SC1 — rollback at volume granularity**: an offline attacker can replay
  an entire older image (both slots, consistent root). Detection requires an
  external freshness anchor; binding the latest generation/root digest to a
  TEE monotonic counter is specified as a SHOULD for TEE-equipped nodes and
  recorded as the residual risk elsewhere. Per-block rollback is defeated by
  §S6.
- **SC2 — superblock MAC key**: the `sb-mac` subkey derives from the
  TEE-sealed master key; an attacker without the key can forge neither slot
  MACs nor integrity roots. Loss of the TEE seal voids integrity AND
  confidentiality — unchanged trust model from NCIP-018 SC1.
- **SC3 — CoW write-pattern side channel**: NCIP-018 SC6's chaff-block
  requirement binds here; the §S4 `flags` field reserves the per-inode chaff
  policy bits. The precise chaff schedule remains with the cryptographer
  review (§S9.2).
- **SC4 — key separation**: distinct KDF contexts (§S7) ensure a compromise
  of one subkey class (e.g., a side-channel on the MAC path) does not yield
  the encryption keys.
- **SC5 — review gates**: §S9 makes the reviews and the crash harness
  normative preconditions of activation; skipping them is a process
  violation, not a judgment call.

## Privacy Considerations

- **PC1**: directory entries (file names) are inside encrypted metadata
  objects (§S7) — an offline image yields no tree enumeration, satisfying
  NCIP-018 PC1 (which v1 did not: names sat in plaintext inodes).
- **PC2**: the VolumeId derivation (NCIP-018 §S8) is unchanged; nothing in
  v3 adds user-linkable identifiers to the on-disk format. Generation
  numbers are monotonic but carry no wall-clock or identity data;
  `created_at` remains HAL-epoch.
- **PC3**: `key_epoch` (§S7) is the concrete GDPR Article 17 mechanism at
  both volume and inode granularity.

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
