# ADR-0037: NCFS Root Mount from NVMe + Reboot Persistence (TASK-15)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-15
**Refs:** PLAN.md TASK-15 (DE-B4), NCIP-FS-Wire-023 (NCFS v1 on-disk format),
ADR-0018 (NCFS v0 architecture), ADR-0036 (NVMe BLK service, TASK-14),
ADR-0034 (no_std port pattern), `docs/plans/desktop-environment-the development plan` §5

## Context

TASK-15 closes M2: mount the NCFS root volume from the NVMe block
service (TASK-14) and survive reboot — `create /test.txt → qm reset →
the file persists with identical content`.

Recon (agent team, file:line evidence) established:

- **NCFS on-disk format is complete** (`nexacore-fs::ondisk::OnDiskVolume`,
  NCIP-FS-Wire-023 / DE-B3): `format(total_blocks)`, `mount(&[u8])`,
  `create_file`/`write_file`/`read_file` (AEAD-verified, CoW),
  `sync_to_bytes() -> Vec<u8>`, `fsck()`. 88 unit + 80 doctests. It is
  **byte-buffer-backed**: `mount` parses a whole-volume `&[u8]` into
  in-memory `BTreeMap`s; there is NO block-device trait (lazy block IO
  is a future refactor). `no_std + alloc`.
- The BLK service client protocol is templated by `nexacore-blkcheck-image`
  (deposited `IpcSend` cap → `BlkLookup(78)` `nvme0` + `nvme0-reply` →
  `BlkRequest` over `IpcSend` with inline 2×2048 B chunking, `count = 1`
  per 4 KiB block).
- The kernel has NO mount/pivot machinery: `SHELL_VFS` (`InMemoryVfs`,
  populated from the embedded initramfs) is the only filesystem; file
  syscalls dispatch to it directly. The desktop plan defers chroot-style
  pivot in favour of a future runtime `FsOpen`-redirect to an FS service.
- `nexacore-fs` could not build for `x86_64-unknown-none` because
  `nexacore-types` (default features) pulls `getrandom` via `id-generation`;
  nexacore-fs only uses `nexacore_types::{blk, wire}` (no_std-clean), so the
  ADR-0034 fix (path-style `nexacore-types`, `default-features = false`)
  makes it build bare-metal (verified). chacha20poly1305 + blake3 are
  no_std-clean.
- the test VM's NVMe backing file `/tmp/nvme-test.img` (1 GiB raw, 4 KiB
  blocks) survives `qm reset` (a VM reboot) but not a host reboot
  (tmpfs).

## Decisions

### D1 — `nexacore-fsd`: a Ring 3 NCFS daemon (BLK client)

NCFS runs as a `no_std + alloc` Ring 3 image (`nexacore-fsd-image`),
spawned by `kmain` after the NVMe driver (and `blkcheck`), with a large
static BSS heap (8 MiB — it holds the whole volume plus the mounted
`OnDiskVolume`'s maps plus a `sync_to_bytes` buffer). It is a BLK client
(the `blkcheck` template): deposited `IpcSend` cap → `BlkLookup` `nvme0`
+ `nvme0-reply` → `read_block`/`write_block` helpers over `BlkRequest`
(`count = 1`, inline 2×2048 B chunking). The kernel deposits the
`IpcSend` token via the same `cap_deposit` path TASK-14 added for
blkcheck.

### D2 — Whole-volume-in-RAM mount; SMALL root volume

Because `OnDiskVolume::mount` takes a whole-volume `&[u8]`, the daemon
reads block 0 (superblock), validates the `OMNIFS01` magic + version,
reads `total_blocks` (superblock offset 16, u64 LE), reads all
`total_blocks` blocks into a heap buffer, then `mount`s it. To keep
boot-time block IO bounded (each block is one `BlkRequest` round-trip),
the root volume is SMALL — **128 blocks (512 KiB)** — ample for the
`/test.txt` persistence proof while keeping mount to ~128 round-trips. A
lazy block-device trait (read/write blocks on demand instead of
whole-volume) is the NCFS Phase-3 refactor that lifts this size limit;
out of TASK-15 scope.

### D3 — Format-on-first-boot fallback

A fresh `/tmp/nvme-test.img` is zeros → block 0 has no `OMNIFS01` magic →
`mount` would reject it. The daemon treats "no valid NCFS on nvme0" as
the **fallback**: it FORMATS a fresh 128-block volume
(`OnDiskVolume::format(128)`), creates `/test.txt`, and syncs it to disk
(`sync_to_bytes` → write all 128 blocks). The boot log distinguishes the
two paths explicitly:

- `[nexacore-fsd] root mounted from nvme0 (N blocks)` — a valid on-disk
  volume was found (the steady-state "pivot" success line);
- `[nexacore-fsd] nvme0 has no NCFS volume — formatting fresh root` — the
  fallback (also exercises the "volume assente → fallback" acceptance).

A volume that has the magic but fails integrity/parse is a HARD error
(logged, daemon exits without overwriting) — never a silent reformat of
possibly-recoverable data (the integrity fail-safe the PLAN requires).

### D4 — Persistence proof: a boot counter in `/test.txt`

`/test.txt` holds `NexaCore root FS — boot N\n`. First boot (fallback)
formats and writes `boot 1`. After `qm reset 103`, the daemon mounts the
existing volume, reads `boot 1`, writes `boot 2`, and syncs. The
two-boot serial capture (verbatim) shows the content persisting AND
incrementing across the reboot — the concrete proof the PLAN asks for
(`create /test.txt → reset → exists with identical content`). The daemon
prints the read-back content verbatim each boot.

### D5 — Pivot scope: mount + persistent root authority (honest)

The FULL form of "pivot from initramfs" — the kernel routing `FsOpen`
for a mount prefix to an FS service over IPC so the shell sees the
on-disk files — is a large protocol + kernel change (a new
`FsOpen`/`FsRead`-over-IPC surface), and the desktop plan explicitly
defers it to a runtime `FsOpen`-redirect. TASK-15 delivers the
**substance**: a persistent NCFS root volume mounted from NVMe at
boot, files surviving reboot, the documented `root mounted from nvme0`
log, and the absent-volume fallback. `/bin` stays served from the
initramfs `SHELL_VFS` (unchanged). The persistent-data root authority is
`nexacore-fsd`. The kernel-VFS `FsOpen`-redirect (so the shell reads the
on-disk volume) is the remaining M2/M3 integration, tracked separately.

The daemon is one-shot for TASK-15 (mount → read/update `/test.txt` →
sync → exit), which is sufficient to PROVE persistence; promoting it to
a long-running FS service that answers `FsOpen`/`FsRead` over IPC is the
follow-up that the redirect needs.

## Alternatives considered

- **FS in-kernel** — rejected: the BLK service is a Ring 3 IPC service;
  an in-kernel FS would need the kernel to drive `BlkRequest` IPC to a
  Ring 3 driver (awkward, and it bloats the Ring 0 TCB with the FS +
  AEAD). A Ring 3 daemon keeps the FS out of the kernel and reuses the
  proven BLK client path.
- **Lazy block-device trait now** — rejected for TASK-15: refactoring
  `OnDiskVolume` from whole-buffer to a `read_block`/`write_block` trait
  touches the entire crate + its 88 tests. The small-volume whole-RAM
  mount proves persistence today; the trait is the Phase-3 refactor that
  lifts the size limit.
- **Full kernel `FsOpen`-redirect pivot now** — rejected: a new
  per-file-op IPC protocol + kernel routing is larger than TASK-14; the
  desktop plan defers it. The persistent mount + the logged pivot line
  are the M2-closing substance.
- **mkfs host tool** — unnecessary: format-on-first-boot (D3) seeds the
  volume on hardware without a separate tool; a host `mkfs` can come
  with the ISO builder later.

## Consequences

- `nexacore-fs` gains a path-style `nexacore-types` (`default-features = false`)
  so it builds for `x86_64-unknown-none` (host build unchanged — feature
  unification re-enables id-generation in the workspace).
- New `crates/nexacore-fsd-image` (workspace-excluded, like the other
  images) + a kmain boot-spawn + an `IpcSend` cap deposit (reusing the
  TASK-14 machinery).
- New nexacore-fs unit tests: `mount` rejects a corrupt superblock
  (bad magic/version), and a truncated/tampered volume fails closed.
- The root volume is capped at 128 blocks until the lazy block-device
  refactor; documented in NCIP-FS-Wire-023 + the daemon.
- the test VM keeps the 4 KiB-block NVMe namespace from TASK-14; persistence
  is verified across `qm reset` (not host reboot — tmpfs backing).

## Implementation appendix — TASK-15 CLOSED (2026-06-08)

Implemented and **hardware-verified reliable on the test VM**. Two follow-on
findings refined the daemon during bring-up:

1. **Heap (8 MiB → 32 MiB).** `format(128)` + `create_file` + `write_file`
   + `sync_to_bytes` peaks at only ~535 KiB on the bump (never-freeing)
   allocator, so the bump is comfortable; the heap was raised to 32 MiB
   for headroom and per-step heap-cursor logging was added.

2. **Scheduler priority (Background → System) — the real fix.** The
   daemon performs ~256 SYNCHRONOUS BLK IPC round-trips (128 reads to
   mount + 128 writes to sync). At `Background` the scheduler's 8-pick
   fairness cycle (`scheduling.rs`: System 4 / Interactive 2 /
   `AiInference` 1 / Background 1 per window) gives the daemon only 1/8
   of picks; under concurrent System-task load (the `ai-svc`/`nexacore-net`
   M1 traffic, which varies per boot) its cooperative reply-polls
   starved and the mount intermittently WEDGED (boots passed 3/4). Note
   the wedge was a true hang, not a budget timeout — the daemon was
   simply not being scheduled often enough to make forward progress
   while a reply sat waiting. Running `nexacore-fsd` at **System** priority
   (it is one-shot and exits after the proof, freeing the slot) makes it
   round-robin co-equal with the NVMe driver. Result: **reliable across
   5 consecutive boots** (format → mount×4, counter `boot 1…boot 5`),
   zero #PF / zero PANIC.

**VERIFIED on the test VM** (serial verbatim, clean build):

```
boot 1 (fresh disk): [nexacore-fsd] nvme0 has no NCFS volume — formatting fresh root
                     [nexacore-fsd] formatted + /test.txt = boot 1 (128 blocks synced)
   qm reset 103
boot 2 (disk kept):  [nexacore-fsd] root mounted from nvme0 (128 blocks)
                     [nexacore-fsd] /test.txt was: NexaCore-OS persistent root — boot 1
                     [nexacore-fsd] boot 2 persisted (128 blocks synced)
```

The `/test.txt` content (em-dash included) survived the reboot
byte-identical — the concrete acceptance criterion. The format-fresh
path on an empty disk exercises the absent-volume fallback; the mount
path logs `root mounted from nvme0`. nexacore-fs gained 5 unit tests
(mount rejects corrupt magic / version / truncation; tampered data
block → AEAD read error; format→remount boot-counter persistence).

DE-B4 closed (M2). DE-B5 (AHCI) stays backlog. The full kernel-VFS
`FsOpen`-redirect so the shell reads the on-disk volume remains the
tracked M2/M3 follow-up (D5).
