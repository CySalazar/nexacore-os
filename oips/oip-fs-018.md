---
ncip: 18
title: Filesystem direction for NexaCore OS — native NCFS as primary, foreign filesystems as read-only compatibility services
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-22
updated: 2026-05-22
activated: 2026-05-22
requires:
  - 13
  - 14
  - 6
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

# NCIP-FS-018 — Filesystem direction for NexaCore OS

## Abstract

This NCIP closes the open architectural question in
[`docs/02-architecture.md`](../docs/02-architecture.md) § "Open architectural
questions" line 252 — *"Filesystem: native NexaCore FS vs. existing options (ZFS
port, ext4 via compatibility)"* — and `docs/planning/2026-05-21-development-the development plan`
**Risk R12**.

The decision: NexaCore OS commits to **a purpose-built native filesystem named
`NCFS`** as the **single canonical persistent filesystem** of the platform.
Foreign filesystems (ext4, NTFS, FAT/exFAT, …) are **explicitly NOT** ported as
primary storage; they are admitted only as **read-only compatibility user-space
services** behind the BLK channel of [`NCIP-Driver-NVMe-014`](./oip-driver-nvme-014.md),
mounted under a dedicated `READONLY_COMPAT_FS` capability, gated to migration
and import workflows, and shipped no earlier than **Phase 3**.

A **port of ZFS** is **rejected** for NexaCore OS v0.x and v1.x for three
non-overlapping reasons (license incompatibility with Apache-2.0 for tight
integration, port effort blowing the Phase 2 timeline, and absence of
capability-binding primitives in ZFS metadata). The decision is revisitable
in v2.x if `zfs-rs` or an equivalent Rust-native, capability-aware fork reaches
production maturity.

This NCIP picks the **direction**. The **on-disk wire format** of `NCFS` —
inode layout, B+-tree / log-structured tree choice, integrity-tag positioning,
capability-binding encoding — is **deferred to a follow-up NCIP** (`NCIP-FS-Wire-NNN`,
to be filed at the start of Phase 2). Locking the wire format requires
prerequisite design work (the `nexacore-crypto` AEAD selection and the per-volume
key-derivation contract) that is not in scope for this NCIP.

The companion crate `crates/nexacore-fs` — currently scaffolded as a stub by
`TASK-011` in the 2026-05-21 development plan — is re-scoped from "stub-only
skeleton" to **"NCFS v0 host"** at Phase 2 entry.

---

## Motivation

### M1. The decision blocks Phase 2 and is currently parked

`docs/02-architecture.md:252` still lists the filesystem direction as an open
question. The 2026-05-21 development plan tracks this as **Risk R12** (Medium
probability / Medium impact) and forces `TASK-011` into a stub-only posture:
`crates/nexacore-fs` is scaffolded only to register the BLK channel and return
`FsResponse::NotImplemented` for every request. A real filesystem cannot be
implemented until this NCIP picks a direction.

`docs/06-roadmap.md` Phase 2 (months 18–30) deliverables include:

- **AI Runtime Service** — needs persistent model weights on disk.
- **Encrypted-by-default data types** (`EncryptedString`, `MaskedSSN`, …) —
  needs a filesystem that participates in the capability + encryption stack
  rather than being orthogonal to it.
- **Tokenization service** — needs a per-user token vault with
  unlinkability properties, which is a filesystem-level concern as much as a
  service-level one.

A filesystem chosen reactively at Phase 2 entry — when the AI Runtime team is
already blocked — is the worst-case schedule outcome. Filing this NCIP now,
during the MB14 → v0.3.0-alpha.1 closure window, lets the Phase 2 wave open
with a known target and a real `crates/nexacore-fs` to grow into.

### M2. The capability model needs to extend to the filesystem

NexaCore OS's distinguishing property — relative to Linux, macOS, Windows — is
**capability-bound I/O at every layer**:

- Drivers carry signed capability tokens ([`NCIP-Driver-Framework-013`](./oip-driver-framework-013.md) § S2).
- IPC channels are capability-gated.
- Memory regions are capability-protected (per-process CR3, MB11; NexaCoreCapability,
  MB13).
- Containers ([`NCIP-Container-006`](./oip-container-006.md)) execute behind
  capability-bound virtio backends.

A filesystem that does not natively participate in this model — ZFS, ext4,
NTFS, btrfs, bcachefs — would become the **first capability-orthogonal layer
in the platform**: every file access would have to be wrapped in an external
capability check that the filesystem itself does not enforce, leaving a
permanent ambient-authority gap inside the FS service. This is the same class
of mistake the project explicitly avoids by not implementing POSIX in the
kernel (resolved by [`NCIP-Container-006`](./oip-container-006.md)).

A native filesystem can encode capability binding directly into inode metadata,
making every read/write require a capability proof that the filesystem
verifies — closing the gap structurally rather than papering over it with a
service-level shim.

### M3. The threat model demands integrity by default

[`docs/04a-threat-model.md`](../docs/04a-threat-model.md) lists adversary
classes that include "compromised driver" (A4) and "offline disk extraction"
(implicit in A1 "physical access"). A filesystem without **end-to-end content
integrity** — i.e., authenticated checksums covering both data and metadata —
allows a compromised driver below it or an offline attacker above it to
silently corrupt or substitute file contents. ext4 (metadata-only journaling),
NTFS (no end-to-end integrity), FAT (no integrity at all) fail this test by
construction. ZFS and NCFS-native pass it; bcachefs passes it; btrfs passes
it modulo well-known corner-case bugs in RAID5/6.

A read-only compat driver (ext4 / NTFS) can be admitted **because the integrity
of the foreign volume is the user's responsibility, not NexaCore's** — the user
opted to mount an external Windows or Linux disk. The threat model accepts
this with a documented capability scope. A primary filesystem with no
integrity guarantee is not acceptable.

### M4. License hygiene matters

The NexaCore OS codebase is **Apache-2.0**. Tight integration with CDDL-licensed
code (the historical ZFS license) is legally fraught: CDDL §3.4 imposes
per-file source-disclosure obligations on derivative works, which creates
legal friction when combining with permissive-licensed codebases.
The two licenses' obligations have been held to be incompatible
for static linking by every major Linux distribution (Debian's position since
2006, Fedora's since 2007). Even a user-space FS service that consumes ZFS as
a library would land NexaCore OS in a region of license uncertainty that no
project of this scale can afford in v0.x.

A native filesystem under NexaCore OS's own Apache-2.0 license has no such concerns.

### M5. The Wine-in-container architecture removes the NTFS compatibility argument

The standard argument for NTFS support — "users want to run their Windows
apps and Windows apps expect NTFS" — is **already addressed** by
[`NCIP-Container-006`](./oip-container-006.md): Windows applications run inside
`nexacore/linux-wine:N-stable` micro-VM containers, against a virtual disk image
exposed via virtio-blk. The guest sees whatever filesystem the image was
formatted with (typically ext4 or NTFS inside the image, transparently); the
host NexaCore OS sees only the opaque image file in NCFS.

The remaining NTFS use case is **mounting an external Windows disk for
data migration**. This is a legitimate but secondary need that fits the
read-only compat-driver model.

---

## Specification

### S1. Native filesystem — `NCFS`

NexaCore OS **MUST** ship a single canonical persistent filesystem named **`NCFS`**.
`NCFS` **MUST** be implemented in Rust, live as a **user-space service**
behind the BLK channel of [`NCIP-Driver-NVMe-014`](./oip-driver-nvme-014.md)
(channel name `nexacore.svc.fs.<volN>`), and follow the user-space-driver
architecture of [`NCIP-Driver-Framework-013`](./oip-driver-framework-013.md).
Crate: `crates/nexacore-fs` (`no_std + alloc`, workspace member).

`NCFS` **MUST** be **copy-on-write (CoW)** at the block level.

`NCFS` **MUST** provide **end-to-end content integrity**: every block (data
and metadata) **MUST** be covered by an authenticated integrity tag rooted in
a per-volume key derived from the volume's capability token. The integrity
algorithm **MUST** be the AEAD primitive selected by `nexacore-crypto` v0.1
(BLAKE3-keyed or AES-GCM-SIV, per a follow-up NCIP). Verification **MUST** be
mandatory on every read; volumes with verification disabled **MUST NOT** be
mountable.

`NCFS` **MUST** support **per-volume confidentiality**: file contents are
encrypted-at-rest under a key derived from the per-volume key. The derivation
**MUST** allow the user to revoke a volume key without rewriting the underlying
storage (cryptographic erasure).

`NCFS` **MUST** support **snapshots**: a snapshot is a CoW root pointer
captured atomically, takes O(log N) time, and consumes incremental space
proportional to subsequent divergence.

`NCFS` capability binding: every inode **MUST** carry a capability fingerprint
(32 bytes) identifying the NexaCoreCapability under which the inode was created.
Read and write operations **MUST** verify that the capability presented by the
caller derives from or matches this fingerprint, per the NexaCoreCapability
attenuation rules (MB13).

`NCFS` **MUST NOT** expose a POSIX ABI surface. The FS service exposes typed
operations over its IPC channel (`Open`, `Read`, `Write`, `Stat`, `List`,
`Snapshot`, `Mount`, `Unmount`). POSIX semantics, if needed by guest Linux
applications, live inside the guest of an `nexacore-container` per
[`NCIP-Container-006`](./oip-container-006.md), against a virtual disk image
that NCFS serves as an opaque blob.

### S1.1. Quantitative parameters (frozen by this NCIP)

The following parameters are normative for NCFS v0, v1, and v2. Any change
**MUST** be filed as an amendment to this NCIP or as a new NCIP that supersedes
the specific parameter; the on-disk wire format NCIP (`NCIP-FS-Wire-NNN`)
**MUST NOT** modify these values.

| Parameter | Value | Rationale |
|---|---|---|
| **Logical block size** | **4 KiB, fixed** | Matches CPU page size (x86_64), NVMe LBA (typical), and PRP transfer model alignment required by [`NCIP-Driver-NVMe-014`](./oip-driver-nvme-014.md) § S4. Variable block size (ZFS-style) is explicitly rejected to keep the CoW + integrity invariants tractable in v1. |
| **Maximum volume size** | **2⁷⁶ bytes (64 ZiB)** | Determined by 64-bit block offsets × 4 KiB blocks. Practical limit is the BLK channel addressable space, smaller in v0–v1. |
| **Maximum file size** | **2⁶³ bytes (8 EiB)** | Determined by 48-bit extent length × 4 KiB blocks × signed 64-bit file-size accumulator. |
| **Maximum files per volume** | **Unbounded** (dynamic inode allocation in the CoW tree, limited only by available volume capacity) | Avoids the static-inode-count problem of ext4 that forces `mkfs`-time allocation decisions. |
| **Maximum filename length** | **255 bytes, UTF-8, NFC-normalized** | Matches POSIX/Linux convention. NFC normalization mandatory to defeat Unicode-confusable path attacks. |
| **Maximum path length** | **4096 bytes** | Matches Linux `PATH_MAX`; compatible with guest Linux applications in `nexacore-container`. |
| **Integrity primitive (default)** | **BLAKE3-keyed MAC, 256-bit output** | Final selection deferred to [`NCIP-Crypto-002`](./oip-crypto-002.md). Default proposal selected for (a) ≈6–10× speed advantage over SHA-256 on modern CPUs (SIMD parallelization), (b) built-in keyed mode (no separate HMAC construction), (c) tree-structured Merkle-friendly mode that aligns with the CoW B+-tree. |
| **Confidentiality primitive (default)** | **AEAD with strict nonce-misuse resistance** (AES-256-GCM-SIV or XChaCha20-Poly1305) | Final selection deferred to [`NCIP-Crypto-002`](./oip-crypto-002.md). The nonce-misuse-resistance requirement is non-negotiable per §SC7. Plain AES-GCM (non-SIV) is excluded. |
| **Capability fingerprint length** | **32 bytes** (256-bit) | Computed as BLAKE3-256 of the canonical serialization of the NexaCoreCapability (canonicalization rules in `NexaCoreCapability v1`, to stabilize during MB13 follow-up). |
| **Integrity verification on read** | **Mandatory, non-disablable** | Volumes with verification disabled **MUST NOT** be mountable. |
| **Confidentiality on write** | **Mandatory per-volume** | Plaintext-on-disk volumes are not supported. |
| **Hard links** | **NOT SUPPORTED** | Hard links create N "owners" for a single inode; under capability binding this either (a) requires multi-fingerprint inodes (increases ambient authority), (b) breaks the one-cap-per-inode invariant, or (c) carves an ambient-authority island out of the FS — all three rejected. Reflinks (CoW clones) provide the same effective benefit (multiple paths sharing data without duplication) with single-fingerprint clarity. |
| **Symbolic links** | **Supported** | Symlinks are explicit indirection visible to the caller, do not break capability binding (the target's capability is checked at resolve time), and are necessary for the migration flow (§S9). |
| **Reflinks (`copy_file_range`-style clones)** | **Supported** | Free in CoW; replaces hard-link use cases. |
| **Extended attributes** | **Supported**, capability-tagged | xattr namespaces themselves carry a capability fingerprint; setting `security.*` xattrs requires a specific capability per inode. |
| **Compression** | **Opt-in per-file, ZSTD only, default OFF** | ZSTD chosen as the single supported algorithm (no algorithm matrix). Default off because the project's primary target workload (AI Runtime model weights, encrypted user data) is poorly compressible. Compression interacts non-trivially with the AEAD layer; the interaction order **MUST** be `compress → encrypt → integrity-tag` (CRIME/BREACH considerations apply, but the per-volume nonce-misuse-resistant AEAD blocks the standard attack path). |
| **Deduplication** | **NOT SUPPORTED in v1** | Reasoning: in-line dedup is RAM-heavy (ZFS DDT consumes 1–5 GB RAM per TB of data) and correctness-fragile. The NCFS v1 budget cannot absorb the implementation + audit cost. Revisitable in v2 if a credible design emerges; not rejected forever. |
| **Multi-device support in v1** | **NOT SUPPORTED** — single device per volume | Local mirroring, striping, RAID-Z-equivalent parity all out of scope for v1. |
| **Redundancy in v2** | **Mesh-replicated volumes only** | Volume-level redundancy delivered through NCFS v2's mesh-replication protocol (cross-node CoW root sync per `NCIP-FS-Mesh-NNN`), not through a v1 RAID layer. Users who need single-host redundancy in the meantime can use device-mapper or LVM raid at the block layer below the BLK channel, treating NCFS as a single-device consumer. |
| **Snapshots** | **O(1) creation, atomic, unlimited count** | A snapshot is a new immutable CoW root pointer captured atomically via a single 8-byte aligned-write commit; subsequent divergence allocates only the changed blocks. |
| **Clones (writable snapshots)** | **Supported** | A clone is a snapshot promoted to writable; share/divergence accounting is per-block. |
| **`fsck` requirement** | **None** | CoW root atomicity makes "mount latest valid root" the recovery model. A separate user tool `nexacore-fs-verify` walks the tree and verifies integrity tags + capability bindings on demand or on a configurable schedule; it is an audit tool, not a recovery requirement. |
| **TRIM/discard** | **Supported on CoW retirement** | Old block ranges are issued as TRIM to the underlying NVMe device after a configurable retention window (default: 24 h, to allow rollback to a recent root). |
| **Online resize (grow)** | **Supported** | Free in CoW: the new capacity is added to the free-block pool atomically. |
| **Online resize (shrink)** | **Supported** with prerequisite scrub-and-relocate pass | A shrink operation evacuates blocks above the new size into the lower region before shrinking the device map; the operation is journalled and resumable across crashes. |
| **Send / receive (snapshot diff)** | **Supported** | Snapshot deltas are streamed over the FS IPC channel; the wire format of the delta stream is specified in `NCIP-FS-Wire-NNN`. |

### S2. Phased delivery of `NCFS`

`NCFS` **MUST** be delivered in three phases aligned with the roadmap:

| Phase | Target | Scope |
|---|---|---|
| **v0** | Phase 2 entry (≈ month 18) | In-memory only, CoW semantics, capability binding, integrity tags. Sufficient for AI Runtime model weights and transient state. No on-disk format yet. |
| **v1** | Phase 3 entry (≈ month 30) | Persistent on-disk format frozen (subject to **`NCIP-FS-Wire-NNN`** follow-up NCIP). Snapshots. Single-node only. NVMe backend via BLK channel. |
| **v2** | Phase 4+ | Mesh-replicated volumes (cross-node CoW root sync over the mesh protocol). Multi-writer reconciliation per [`NCIP-Process-001`](./oip-process-001.md)-tracked design. |

Each phase entry **MUST** be opened by its own NCIP and **MUST NOT** start
implementation until that NCIP is `Active`.

### S3. BLK channel contract reuse

`NCFS` **MUST** consume the BLK channel contract from
[`NCIP-Driver-NVMe-014`](./oip-driver-nvme-014.md) § S6 unchanged. No new
storage-driver-side ABI is introduced by this NCIP.

### S4. Compatibility filesystem services

NexaCore OS **MAY** ship additional filesystem services that expose **foreign
filesystems** under a **read-only** posture for migration and import workflows.

Each foreign filesystem **MUST** be a separate user-space service, with its
own signed manifest per [`NCIP-Driver-Framework-013`](./oip-driver-framework-013.md),
loaded under a dedicated **`READONLY_COMPAT_FS`** capability defined in
`nexacore-capability` (per the MB13 capability model). This capability:

- **MUST NOT** be derivable to a writable-FS capability.
- **MUST** be revocable per-mount by the user via the Helper UI.
- **MUST** be denied by default; the user **MUST** explicitly grant it for each
  mount operation.
- **MUST** be logged in the audit trail (`docs/audits/`) every time it is
  exercised, with the foreign volume's identifier and mount duration.

Write support for foreign filesystems is **OUT OF SCOPE** for v0.x, v1.x, and
v2.x of NexaCore OS. Users who need to write to a foreign filesystem **MUST** do
so from inside an `nexacore-container` mounting the volume as a virtio-blk device
to a guest Linux that owns the relevant FS driver — preserving the NexaCore host's
posture that foreign FS code never has write authority on the host.

### S5. ext4 read-only compatibility — `nexacore-fs-compat-ext4`

NexaCore OS **MAY** ship `nexacore-fs-compat-ext4` (crate `crates/nexacore-fs-compat-ext4`)
as a read-only ext4 driver, scheduled **no earlier than Phase 3** and gated on
prior delivery of `NCFS v1`.

The implementation **MUST** be a Rust-native parser (no FFI to e2fsprogs). The
reference baseline is the existing `ext4-view` crate family on crates.io; a
fork or rewrite under Apache-2.0 is acceptable. Static linking to GPL-2.0 code
is not (license-incompatibility with Apache-2.0).

`nexacore-fs-compat-ext4` **MUST** support extents (post-2.6.30 ext4), 64-bit
features, large files. It **MAY** omit support for journal replay (the driver
**MUST** refuse to mount an ext4 volume with a dirty journal, displaying a
Helper UI prompt directing the user to run `e2fsck` from a guest Linux
container first).

### S6. NTFS read-only compatibility — `nexacore-fs-compat-ntfs`

NexaCore OS **MAY** ship `nexacore-fs-compat-ntfs` (crate `crates/nexacore-fs-compat-ntfs`)
as a read-only NTFS driver, scheduled **no earlier than Phase 3**, optional,
and **lower priority than `nexacore-fs-compat-ext4`**.

The implementation **MUST** be a Rust-native parser. The reference baseline is
the existing `ntfs` crate on crates.io (MIT/Apache-2.0, no FFI, no Microsoft
code). The driver **MUST** support NTFS 3.1 (Windows XP through Windows 11),
**MUST NOT** support Volume Shadow Copy Service (VSS) write integration,
**MUST NOT** expose Alternate Data Streams (ADS) (see *Rationale* below for
why; they are exfiltration vectors).

A reference baseline of partial Microsoft-published documentation
(Microsoft Open Specifications, `[MS-FSCC]`) covers enough of the format for
read-only access. The driver **MUST NOT** rely on reverse-engineered behaviour
that diverges from the published spec.

The driver **MUST NOT** be enabled by default in stock NexaCore OS builds. The user
**MUST** opt in explicitly via Helper UI (per
[`NCIP-Helper-007`](./oip-helper-007.md)), with the consent dialog citing the
read-only posture and the residual patent risk acknowledged in *Security
Considerations* below.

### S7. FAT, exFAT, btrfs, bcachefs, APFS, HFS+

All other foreign filesystems are **OUT OF SCOPE** for v0.x, v1.x, and v2.x of
NexaCore OS. A future NCIP may admit any of them via the same read-only
compat-service pattern (S4) if user demand justifies the engineering cost.

In particular, **bcachefs** is a serious candidate for a future v3.x re-evaluation
of the primary-FS decision; the Rust port `bcachefs-rs` does not yet exist at
the maturity required. **btrfs** is not pursued due to known historical
RAID5/6 reliability concerns and the project's preference for an FS designed
around capability binding from day one. Both are explicitly **not rejected
forever** — only deferred.

### S8. Mount, namespace, and discovery model

NexaCore OS **MUST** expose filesystems through a **per-volume capability mount
model**, not a global namespace (no `/mnt/`, no drive letters). Each mounted
filesystem is identified by:

- A **VolumeId** (32-byte, derived from the volume's root capability fingerprint).
- A user-supplied **alias** (UTF-8, ≤ 64 bytes), scoped to the user.
- The mounting capability (write for `NCFS`, `READONLY_COMPAT_FS` for foreign).

The Helper UI and the Container engine ([`NCIP-Container-006`](./oip-container-006.md))
**MUST** present volumes to users and containers respectively by alias; the
underlying VolumeId remains opaque to user-space applications except via an
explicit capability query.

### S9. Migration boot story (informational)

A user installing NexaCore OS over an existing Linux or Windows installation
**SHOULD** be guided by the installer through a one-time migration flow:

1. Probe existing partitions read-only via `nexacore-fs-compat-ext4` / `-ntfs`.
2. Allow the user to select files/directories to copy into an `NCFS` volume
   on the target disk.
3. Surface the source FS as `READONLY_COMPAT_FS` for the duration of the
   migration; revoke the capability automatically once the user completes or
   cancels the flow.

The installer **MUST NOT** offer in-place conversion (no rewriting of foreign
filesystems into `NCFS`). In-place conversion is rejected because it
violates the project's policy that foreign FS code never has write authority
on the host.

---

## Rationale

### R1. Why a native filesystem and not an external port

The frozen quantitative parameters of NCFS — block size, integrity primitive,
capability fingerprint length, hard-link policy, compression default,
deduplication policy, multi-device policy — are normatively specified in §S1.1
and are the anchor against which the comparison below is made.

The four primary candidates and their structural alignment with the NexaCore OS
design ethos:

| Candidate | Capability binding | Integrity by default | License compat | Port effort | Ecosystem |
|---|---|---|---|---|---|
| **NCFS native** | ✅ Native (encoded in inode) | ✅ Native (per-volume AEAD) | ✅ Apache-2.0 in-tree | 🟥 12–24 person-months (v0+v1) | 🟥 Zero on day one |
| **ZFS port** | ❌ Orthogonal (would need a shim) | ✅ End-to-end Merkle | 🟥 CDDL vs Apache-2.0 | 🟥🟥 24–48 person-months for a faithful port; or rely on `zfs-rs` which is not production-grade | ✅ Mature |
| **ext4 (primary)** | ❌ POSIX permission bits only | ❌ Metadata journal only | ✅ GPL-2.0 source available, Rust rewrite under Apache-2.0 OK | 🟧 6–12 person-months for a Rust rewrite | ✅ Mature |
| **NTFS (primary)** | ❌ ACLs only, no capability concept | ❌ No end-to-end integrity | 🟧 Patent uncertainty | 🟧 6–12 person-months (read-write) | ✅ Mature on Windows |

**Why NCFS native wins on direction**: the only candidate that natively
encodes capability binding and end-to-end integrity, and the only one with
clean license posture. The port-effort column is the worst of the four, but
it is the **only** column that improves with time — every other candidate has
structural mismatches that cannot be patched.

**Why ZFS is rejected for v0–v2** (not "rejected forever"):

1. **License incompatibility with Apache-2.0.** The OpenZFS project remains
   under CDDL-1.0. Static linking is incompatible per the consensus position
   of Debian, Fedora, Red Hat, and the FSF (e.g., FSF's 2016 statement on
   ZFS-on-Linux). Dynamic linking is debated but unsettled; NexaCore OS cannot
   afford to depend on the optimistic interpretation. A Rust-native port
   (`zfs-rs` or equivalent) under Apache-2.0 would be a multi-year project
   reimplementing an FS whose semantics are not capability-aware to begin with.
2. **Port effort blows the Phase 2 timeline.** The smallest known
   user-space ZFS implementation is `ZoF` (ZFS-on-FUSE), which is feature-
   incomplete and unmaintained. A microkernel-IPC port would touch every I/O
   path. The smallest realistic estimate is 24 person-months, which is more
   than the entire Phase 2 budget on the funded staffing model.
3. **No capability binding.** ZFS metadata has no concept of capability
   fingerprints; adding them retroactively would mean amending the on-disk
   format (i.e., it would no longer be ZFS).

**ZFS revisitability**: if `zfs-rs` (or equivalent) reaches production maturity
with an Apache-2.0-compatible license and a capability-aware extension, this
NCIP **MAY** be amended in v3.x to admit ZFS as an additional first-class
volume type alongside `NCFS`. The decision here is not "never ZFS"; it is
"not in v0–v2, on the present evidence".

**Why ext4 is not the primary**: ext4 has no end-to-end data integrity (only
metadata journaling); it has no native CoW (no snapshots without LVM); and
it does not express capability binding. As a primary FS it would commit NexaCore
OS to a layer that violates the threat model M3 and the capability ethos M2.
As a read-only compat driver (S5) it is acceptable because the user has opted
in for a one-way import workflow with documented capability scope.

**Why NTFS is not the primary** (and only optional as compat):

1. **Patent posture.** Microsoft's *Open Specification Promise* (OSP) covers
   the published `[MS-FSCC]` documentation, but the promise's scope and
   durability under future corporate ownership changes are well known to be
   weaker than the Sun-style covenant that historically protected CDDL code.
   Multiple historical incidents (Microsoft's TomTom suit, the FAT licensing
   demands to Android OEMs 2009–2014, the Linux distribution licensing
   negotiations) make the project unwilling to put Microsoft IP at the
   foundation of its persistence layer.
2. **No incentive.** The Wine-in-container architecture
   ([`NCIP-Container-006`](./oip-container-006.md)) removes the main use case
   for host-side NTFS. Windows apps run inside containers against virtual
   disks; they don't see the host filesystem at all.
3. **Format complexity yields exfiltration surface.** Alternate Data Streams,
   reparse points, junction points, and short-name aliasing are NTFS-specific
   features with non-trivial security implications (ADS has been a malware
   hiding technique for two decades; short-name aliasing has been the root of
   path-confusion CVEs). A read-only compat driver can flatly refuse to expose
   these constructs (S6); a primary FS could not.
4. **No end-to-end integrity, no native capability binding.** Same structural
   issues as ext4, layered on top of the patent and surface-area concerns.

**Why FAT/exFAT, APFS, HFS+ are not considered**: low residual user demand
relative to ext4/NTFS, same structural mismatches, and (for APFS/HFS+) the
same patent posture concerns that apply to NTFS in a different vendor.

### R2. Why phased delivery of NCFS

A persistent-on-disk filesystem that ships with a wrong on-disk format is a
permanent technical debt. The classic counter-example is Btrfs's RAID5/6
write-hole bug, which has not been fully fixed since 2014 and locks Btrfs
out of use cases it was designed for. NexaCore OS cannot afford an equivalent
mistake.

The phased delivery model lets the project:

- Ship NCFS v0 (Phase 2) **in-memory only**, against the in-RAM block
  device used by the AI Runtime for model-weight staging. Bugs at this stage
  do not corrupt persistent storage.
- Freeze the on-disk format only in NCFS v1 (Phase 3), after a full design
  cycle including a public Last Call window per
  [`NCIP-Process-001`](./oip-process-001.md) §4 and a cryptographer review of
  the AEAD selection and key-derivation chain.
- Open mesh-replicated volumes only in NCFS v2 (Phase 4+), after the mesh
  protocol itself has reached production maturity per
  [`docs/03-mesh-protocol.md`](../docs/03-mesh-protocol.md).

### R3. Why deferring the on-disk format to a follow-up NCIP

The on-disk wire format depends on prerequisite design work that is not yet
complete:

- The `nexacore-crypto` AEAD selection (BLAKE3-keyed vs. AES-GCM-SIV vs.
  ChaCha20-Poly1305) is open per
  [`ncips/ncip-crypto-002.md`](./oip-crypto-002.md) (Draft).
- The NexaCoreCapability fingerprint format is partially specified in MB13 but
  the encoding rules for cross-boundary attenuation are still in flux.
- The mesh-replication protocol (NCFS v2) requires design decisions that
  belong in a separate NCIP, not this one.

Locking the on-disk format prematurely would either freeze prerequisites that
are not ready, or force a v1.1 reformat that breaks every user. The follow-up
NCIP (`NCIP-FS-Wire-NNN`) **MUST** wait for `NCIP-Crypto-002` to reach `Active`
and for the NexaCoreCapability encoding to stabilize in `NexaCoreCapability v1`.

### R4. Why a strict separation between NCFS and compat drivers

A single FS service that mixes native and foreign formats would either:

- Inherit the foreign FS's threat model (no integrity, no capability binding)
  for the entire service, or
- Maintain two parallel code paths inside one address space, doubling the
  attack surface within a single process.

Per [`NCIP-Driver-Framework-013`](./oip-driver-framework-013.md), the user-space
driver model lets each foreign FS run as a separate process under a separate
manifest with a separate capability set. This makes the read-only compat
posture enforceable by the kernel (the foreign FS service simply cannot mint
a write capability for the host) rather than dependent on internal discipline.

### R5. Why no writable foreign FS, ever, on the host

The project policy is that **the NexaCore host MUST NOT execute foreign FS code
with write authority on the host's storage**. The reasoning is the asymmetric
risk profile: a read-only parser bug typically yields a denial of service
(parser refuses to read further); a writable FS driver bug can corrupt the
disk, including NCFS volumes if they share the device. The cost of the
restriction is low (Wine-in-container handles the Windows-app case), and the
benefit is the structural exclusion of an entire class of disk-corruption
incidents.

Users who need to write to a foreign FS can do so from inside a guest Linux
container that owns the FS driver and mounts the volume via virtio-blk.

---

## Backwards Compatibility

This NCIP introduces a filesystem layer that does not exist today. There is no
prior NexaCore OS filesystem to be compatible with.

The `crates/nexacore-fs` stub introduced by `TASK-011` (per the 2026-05-21
development plan) is re-scoped from "stub-only skeleton" to "NCFS v0 host"
at Phase 2 entry. The stub's current API (`FsService::register(disk_n)`,
`FsService::handle_request(req)` returning `FsResponse::NotImplemented`) is a
strict subset of the eventual NCFS v0 API; no breakage is introduced.

[`docs/02-architecture.md`](../docs/02-architecture.md) § "Open architectural
questions" line 252 **MUST** be updated to mark the filesystem question as
*Resolved by `NCIP-FS-018` (2026-MM-DD): native NCFS as primary; foreign
filesystems as read-only compat services only*. This is a documentation patch
to be applied in the same PR that flips this NCIP to `Active`.

---

## Test Cases

### T1. NCFS v0 (in-memory) acceptance

When NCFS v0 is delivered (Phase 2 entry), the following invariants
**MUST** be covered by unit and integration tests under `crates/nexacore-fs/tests/`:

- **T1.1** Capability binding: a `Read` request with a capability that does
  not derive from the inode's capability fingerprint **MUST** return
  `Err(CapabilityMismatch)`.
- **T1.2** Integrity tag verification: a tampered block in the in-memory
  arena **MUST** cause the next read to return `Err(IntegrityViolation)`
  and **MUST NOT** propagate the corrupted bytes to the caller.
- **T1.3** Snapshot atomicity: a snapshot taken under concurrent writes
  **MUST** be either pre-write or post-write relative to each write, never
  a partial mix.
- **T1.4** Confidentiality: file contents in the in-memory arena
  **MUST NOT** be readable without the per-volume key (i.e., the on-the-fly
  encryption is non-trivially keyed, not a no-op stub).

### T2. Compat-driver acceptance (Phase 3+)

When `nexacore-fs-compat-ext4` is delivered:

- **T2.1** A standard ext4 image (from `e2fsprogs` `mkfs.ext4`) **MUST** be
  parseable; file enumeration **MUST** match the ground truth.
- **T2.2** A mount attempt with a write capability **MUST** be rejected by
  the manifest before the driver process even starts.
- **T2.3** A dirty journal **MUST** cause the mount to fail with a
  user-facing message directing the user to run `e2fsck` in a guest
  container.
- **T2.4** A malformed ext4 image (fuzz-corpus seed) **MUST NOT** cause the
  driver process to write outside its address space or read uninitialised
  memory; a panic is acceptable and **MUST** be confined to the driver
  process per [`NCIP-Driver-Framework-013`](./oip-driver-framework-013.md).

When `nexacore-fs-compat-ntfs` is delivered, analogous tests apply.

### T3. Cross-boundary integration

- **T3.1** An `nexacore-container` mounting an NCFS-backed virtual disk image
  **MUST** see the image as opaque bytes (no leak of NCFS metadata into the
  guest).
- **T3.2** A `READONLY_COMPAT_FS` capability **MUST NOT** be attenuable to
  a write capability via NexaCoreCapability rules (MB13). A test exercising
  attenuation paths and verifying rejection is mandatory.

---

## Reference Implementation

- **Stub baseline:** `crates/nexacore-fs` skeleton per `TASK-011` of the
  Phase-1 development plan.
- **NCFS v0:** to be scheduled at Phase 2 entry; will be filed as a separate
  development-plan task referencing this NCIP.
- **NCFS v1 on-disk format:** to be specified in `NCIP-FS-Wire-NNN`
  (follow-up).
- **Compat drivers:** to be filed as separate tasks at Phase 3 entry; each
  driver is its own crate (`nexacore-fs-compat-ext4`, `nexacore-fs-compat-ntfs`)
  carrying its own user-space-driver manifest per
  [`NCIP-Driver-Framework-013`](./oip-driver-framework-013.md).

---

## Security Considerations

### SC1. The filesystem is part of the TCB for confidentiality and integrity

`NCFS` mediates every persistent-data access in NexaCore OS. A bug in the FS
code is equivalent (in blast radius) to a bug in the kernel for the class of
attacks it touches (data tampering, capability bypass, key leakage). The FS
service therefore inherits the kernel's review requirements: cryptographer
sign-off on the AEAD usage and key-derivation chain (per the
[`docs/audits/cryptographer-engagement-template.md`](../docs/audits/cryptographer-engagement-template.md));
formal review of the capability-binding state machine; fuzz testing
mandatory before v1 freeze.

### SC2. Compat-driver process isolation

ext4 and NTFS parsers have decades-long histories of memory-corruption
vulnerabilities (CVE-2022-0185 ext4, CVE-2021-31956 NTFS-3G, …). The
compat-driver model per S4 places each parser in its own user-space process
with no write capability, no kernel-mode authority, and no access to NCFS
volumes. A compromised compat driver therefore yields, at worst:

- Denial of service against its own mount (the user replugs the disk).
- Disclosure of the foreign volume's contents to a process that the user has
  already authorised to read those contents.

It cannot escalate to NCFS, to other processes' memory, or to the kernel.

### SC3. NTFS-specific patent risk

The Microsoft Open Specification Promise covers the published `[MS-FSCC]`
documentation. The OSP has been criticized in legal scholarship for being
weaker than reciprocal patent grants of the CDDL or GPL-3.0 type (e.g., Moglen
2010 in the GPLv3 context, and the SFLC's 2009 commentary on the original
OSP). The compat-driver model places NTFS in the lowest-priority position
(S6); ships it as opt-in only; and disables it by default. Users who choose
to enable it do so under documented patent uncertainty.

If at any point Microsoft asserts a patent against the NexaCore OS NTFS driver,
the response **MUST** be: (a) immediate disable of the driver across the
network (the Helper UI **MUST** support remote capability revocation per
[`NCIP-Helper-007`](./oip-helper-007.md)), and (b) removal of the crate from
the NexaCore OS release in the next point release. The user retains the option
to mount NTFS volumes inside a guest Linux container that runs the upstream
Linux `ntfs3` driver, which is outside NexaCore OS's licensing surface.

### SC4. CDDL contagion (ZFS) — why even an optional port is rejected

A frequent question is whether ZFS could be admitted as an *optional* primary
FS in the same compat-style spirit as ext4/NTFS. The answer is no, for a
different reason than NTFS: the patent posture is not the issue; the *license
contagion* is. Even a user-space service linking to ZFS code under CDDL would
require the NexaCore OS distribution to ship the ZFS code alongside the Apache-2.0
kernel and userland under joint license terms that no Apache-2.0 project has
been able to engineer cleanly. Dynamic linking via dlopen and a deliberate
process boundary is the canonical mitigation, but the result is a service
that is structurally identical to the read-only compat-driver model — for a
filesystem that is **not** read-only by user expectation, with all the
attendant write-path correctness obligations. The cost-benefit fails.

### SC5. Capability binding fingerprint collisions

The 32-byte capability fingerprint specified in S1 **MUST** be a collision-
resistant hash of the NexaCoreCapability's normalized canonical form. The
follow-up NCIP (`NCIP-FS-Wire-NNN`) **MUST** specify the hash function (default
recommendation: BLAKE3-256 truncated to 32 bytes) and the canonical-form
encoding. Collision resistance at the 128-bit security level is sufficient
given the cap-binding threat model (an attacker would need a second-preimage
attack on a target capability, not a birthday attack).

### SC6. Snapshot / CoW write amplification as a side channel

CoW filesystems have known timing side channels: an observer with access to
the underlying block device can infer write patterns from the allocation
behaviour of the CoW tree. NCFS **MUST** mitigate this for sensitive
volumes (those marked with a confidentiality capability flag) by writing
chaff blocks in randomised positions when below an activity floor. The
precise mitigation policy is in scope for `NCIP-FS-Wire-NNN`, not this NCIP,
but the requirement is recorded here so the follow-up cannot quietly drop it.

### SC7. AES-GCM-SIV vs. BLAKE3-keyed selection (deferred)

The integrity primitive selection is deferred to `NCIP-Crypto-002` (Draft).
This NCIP records the requirement: **the integrity primitive MUST be an AEAD
with strict nonce-misuse resistance**, because the FS service inevitably
restarts with state that may not perfectly track nonce counters across
crashes. AES-GCM (without -SIV) is therefore excluded; AES-GCM-SIV,
XChaCha20-Poly1305, and BLAKE3-keyed MAC are acceptable candidates pending
the NCIP-Crypto-002 decision.

---

## Privacy Considerations

### PC1. File metadata exposure

Filesystem metadata (file sizes, timestamps, directory structures) leaks
information about user behavior even when contents are encrypted. NCFS
**MUST** keep metadata under the same AEAD as data; an offline attacker
holding the disk image **MUST NOT** be able to enumerate the directory
tree without the per-volume key.

### PC2. Volume identifier unlinkability

The VolumeId (S8) is derived from the volume's root capability fingerprint.
The derivation **MUST NOT** include user identity directly; volumes
**MUST NOT** be linkable across users by VolumeId inspection alone. This
matters for the federated-mesh case where a user might present the same
volume to multiple peers; each presentation **SHOULD** be able to use a
different derived identifier if the user requests it.

### PC3. GDPR right to erasure

GDPR Article 17 ("right to erasure") imposes obligations on data controllers
to delete personal data on request. NCFS **MUST** support **cryptographic
erasure**: revoking the per-volume key renders the volume unrecoverable
even with full disk access. This is the canonical satisfaction of Article 17
for at-rest data, and is the only mechanism that satisfies erasure on
solid-state media without secure-overwrite guarantees from the device. The
implementation **MUST** wire the key revocation into the Helper's data-
deletion UI so the user's intent and the technical operation are unified.

### PC4. Compat-driver mounts in the audit log

S4 requires every `READONLY_COMPAT_FS` mount to be logged. The log entry
**MUST** include only the VolumeId, the timestamp, and the mount duration;
it **MUST NOT** include the contents of the volume or any path-level
information. This minimizes the privacy footprint of the audit trail while
preserving the forensic value of "the user mounted a foreign disk at
2026-MM-DD".

### PC5. AI Runtime model weights as persistent state

NCFS v0 is dimensioned for AI Runtime model weights (Phase 2). Model
weights themselves can leak training-data information under inversion attacks
(Carlini et al., 2021). The NCFS confidentiality posture (PC1) protects
weights at rest; runtime exposure is the AI Runtime's concern, not NCFS's.
This NCIP **MUST NOT** be cited as a mitigation for AI-runtime data exfiltration;
the NCFS posture is necessary but not sufficient for that threat class.

---

## Open follow-up NCIPs

| Follow-up | Scope | Earliest filing |
|---|---|---|
| **`NCIP-FS-Wire-NNN`** | NCFS v1 on-disk format | Phase 3 entry, after `NCIP-Crypto-002` Active |
| **`NCIP-FS-Mesh-NNN`** | NCFS v2 mesh-replicated volumes | Phase 4+, after mesh protocol production maturity |
| **`NCIP-FS-Compat-Ext4-NNN`** | `nexacore-fs-compat-ext4` driver acceptance | Phase 3 entry |
| **`NCIP-FS-Compat-NTFS-NNN`** | `nexacore-fs-compat-ntfs` driver acceptance (optional) | Phase 3+, opt-in only |

---

## Amendment history

| Date | Change | Notes |
|---|---|---|
| 2026-05-22 | `Draft → Review` | Editorial transition by the interim editor body (`cySalazar`, sole §6.2 Bootstrap editor). No substantive content change: the NCIP enters the public discussion phase with all 10 canonical sections intact, and the quantitative parameters frozen in §S1.1 (4 KiB fixed block size, 64 ZiB max volume, 8 EiB max file, BLAKE3-keyed MAC 256-bit integrity, AEAD nonce-misuse-resistant confidentiality, 32-byte capability fingerprint, no hard links, ZSTD opt-in compression default off, no v1 dedup, no v1 multi-device) carry into `Review` unchanged. |
| 2026-05-22 | `Review → Last Call` | Editorial transition by the interim editor body. The §5.5 fast-track was **not** invoked (the §5.5 (c) banner required at this transition was not in place); the standard §5.3 ¶1 14-day public-objection window opens 2026-05-22 (this date) and is scheduled to close 2026-06-05 unless §5.3 ¶1 second branch fires first. No content change carried by this transition; the NCIP enters the vote window with the same text the Draft and Review phases had. |
| 2026-05-22 | `Last Call → Active` | Editorial closure of the Last Call window under `NCIP-Process-001` §5.3 ¶1 second branch: the dominant voter (`cySalazar`, 100% weighted eligibility under §5.2 bootstrap defaults — sole §5.1-eligible device, identical state to the 2026-05-22 `NCIP-Bounty-002` / `NCIP-Serde-004` ballots in `docs/audits/ncip-editors-report-2026-Q2.md` and to the §5.5 fast-track log entry for `NCIP-Kernel-005` / `NCIP-Kernel-012` on 2026-05-14) cast an in-favor ballot, satisfying both clauses of §5.3 simultaneously (≥30% weighted vote cast AND ≥50%+1 weighted in favor). Founder ballot recorded in `docs/audits/ncip-editors-report-2026-Q2.md`. No blocking objection was raised during the same-day window; the §5.5 (d) good-faith objection clause remains operative post-`Active` for the standard 14-day horizon (by 2026-06-05) and a substantive technical objection in that window SHOULD trigger an Amendment NCIP. No content change carried by this transition. §5.4 BDFL veto: **not exercised** — NCIP-FS-018 does not break Layer 1 cryptographic guarantees (filesystem direction; no cipher suite / signature scheme / capability format / mesh handshake change), so §5.4 does not apply. §7 activation phase opens upon `Active` and is practically dormant until NCFS v0 ships (Phase 2 entry). |
| 2026-06-12 | Reconciliation note (no normative change) | The §S1.1 frozen parameters stand unchanged. Recorded facts: (a) the Active on-disk format `NCIP-FS-Wire-023` does not yet reach several §S1.1 parameters (max file ~1 GiB vs 8 EiB; 95-byte names vs 255-byte NFC; no per-inode capability fingerprint despite §S1; no CoW-root atomic commit despite the §S1.1 "fsck: none" rationale) — documented in Wire-023's 2026-06-12 erratum note and in `docs/ncfs-compliance-matrix.md`; (b) **`NCIP-FS-Wire-027` (Draft)** is filed to reconcile the wire format with §S1.1 (extents, 255-byte NFC directory entries, 32-byte fingerprint field, dual-superblock CoW root commit, Merkle-rooted integrity, SC7-compliant AEAD with `(generation, block)` nonces, key epochs for PC3 erasure); (c) per `NCIP-Review-Gate-028` (Draft), Wire-027 MUST NOT activate without documented independent review, cryptographer sign-off (SC1), crash-consistency harness results, and benchmarks. |

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
