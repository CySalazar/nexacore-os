# ADR-0018 — NCFS v0 User-Space Service Architecture

**Status:** Accepted
**Date:** 2026-05-24
**Context:** Wave 4, Stream 1 (TASK-011)

## Context

NexaCore OS requires a filesystem service to consume the BLK channels published
by storage drivers (NVMe, virtio-blk, SATA). NCIP-FS-018 (Active) commits the
project to a native NCFS as the single canonical persistent filesystem.
Phase 1 delivers the service skeleton; Phase 2 grows it into the real host.

The skeleton must prove the IPC architecture compiles and the type flow from
`BlkRequest` to `BlkResponse` is well-typed, without implementing actual I/O.

## Decision

Expand `crates/nexacore-fs` from a 208-line stub into a 1252-line NCFS v0
skeleton with three new architectural components:

1. **`VolumeRegistry`** — `BTreeMap<String, u64>` mapping disk-slot names to
   BLK channel IDs. `BTreeMap` chosen over `HashMap` because it lives in
   `alloc` (no `std` required) and provides deterministic iteration order.

2. **`BlkChannelConsumer`** — per-volume BLK channel client tracking pending
   requests by monotonically increasing `u64` correlation IDs. Decoupled from
   `FsService` so unit tests can drive consumers independently.

3. **`FileMetadata`** — `Serialize`/`Deserialize` struct crossing the trust
   boundary via `nexacore_types::wire::encode_canonical`.

All request dispatch stubs return `FsResponse::NotImplemented`. Compile-time
const assertions guard `BLOCK_SIZE_BYTES == 4096` and
`MAX_BLOCK_COUNT_PER_REQUEST == 2048`.

## Alternatives Considered

1. **Inline BLK consumption in the kernel** — rejected: violates the
   microkernel principle that I/O services run in user space.

2. **Wait for Phase 2 to build the service** — rejected: the IPC architecture
   must be validated now to catch type-system issues before the real
   implementation lands.

3. **Use `HashMap` for `VolumeRegistry`** — rejected: `HashMap` requires
   `std::collections` or a hasher dependency; `BTreeMap` is in `alloc`.

## Consequences

- Phase 2 NCFS implementation can start from a proven architecture rather
  than a blank slate.
- The `BlkChannelConsumer` correlation pattern is reusable by any future
  service that consumes IPC channels (NET, TEE, etc.).
- 53 new tests (29 unit + 24 doc) increase workspace coverage.
