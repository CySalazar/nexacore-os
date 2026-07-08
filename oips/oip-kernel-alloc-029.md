---
ncip: 29
title: Kernel slab and free-list allocator — reclaiming heap memory and lifting the IPC channel cap
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-06-14
updated: 2026-06-14
requires:
  - 3
  - 12
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

`NCIP-Kernel-012` § S2 specifies the kernel's v0.1 global allocator as a **bump allocator**: every
allocation advances one atomic pointer and `dealloc` is a no-op. That choice was correct for K3
(smallest possible TCB surface to close the bare-metal link gate), but it never reclaims memory.
Any kernel object with a bounded lifetime — most importantly the ring buffer of a destroyed IPC
channel — leaks its backing store until the next reboot. To keep the leak survivable the kernel
caps long-lived structures (`MAX_CHANNELS_PER_OWNER = 256`, bounded per-channel `queue_depth`),
which converts a memory-safety concern into an arbitrary capacity ceiling.

This NCIP specifies a **slab + free-list allocator** that adds real `dealloc` while preserving the
bump allocator's properties that matter (no external trust base, O(1) fast path, fail-closed OOM,
single-CPU-correct-with-SMP-ready atomics). It defines the **normative allocator contract**
(`alloc` / `free` / alignment / OOM / thread-safety / invariants) that the implementation
(sub-tasks WS1-08.2–.9) MUST satisfy, the fixed size-class structure, the large-allocation
fallback, how the allocator sits behind the existing `GlobalAlloc` interface, and the migration
that lets the IPC layer return channel buffers on `destroy` and lift the `queue_depth ≤ 256` cap.
The panic handler from `NCIP-Kernel-012` § S1 is unchanged.

---

## Motivation

The bump allocator (`crates/nexacore-kernel/src/bare_metal/heap.rs`, `NCIP-Kernel-012` § S2) has one
structural defect: **it never frees.** This is documented in `ADR-0005` (MB12 IPC) and tracked as
plan task `WS1-08`. Three concrete consequences:

1. **IPC channel teardown leaks.** `IpcRegistry::destroy_channel` drops the in-memory channel
   record, but the heap bytes backing its `queue` (a `VecDeque` of messages, depth up to
   `policy.queue_depth`) are never returned to the allocator. A workload that creates and destroys
   channels in a loop — every short-lived RPC, every driver bring-up/teardown, every agent task —
   monotonically grows `BumpHeap::used_bytes()` until it reaches `HEAP_MAX_BYTES` (128 MiB) and the
   kernel OOM-panics. This is `K-D-1` in `docs/04a-threat-model.md` (DoS via kernel memory
   exhaustion, adversary A1) turned from "needs many live objects" into "needs many *churned*
   objects", which is far cheaper for an attacker.

2. **Capacity ceilings stand in for memory safety.** Because nothing is reclaimed, the kernel
   bounds the *live* footprint with hard caps: `MAX_CHANNELS_PER_OWNER = 256` and a bounded
   per-channel `queue_depth`. These are not protocol limits anyone wants — they exist only so the
   non-reclaiming heap cannot be driven to exhaustion by legitimate use. With a reclaiming
   allocator the cap can be governed by an explicit per-owner memory quota (capability-carried)
   instead of an arbitrary integer.

3. **Fragmentation is unmeasured because it cannot occur.** A bump heap never fragments, but it
   also never reuses. The moment `dealloc` becomes real, fragmentation behaviour becomes a
   first-class property the allocator MUST bound. A slab allocator with fixed size classes gives a
   *provable* internal-fragmentation bound (≤ the size-class growth ratio) and zero external
   fragmentation within a class, which is why it is the right v1.0 shape rather than a general
   free-list or buddy allocator.

The allocator mediates **every** kernel-internal allocation, so — exactly as argued in
`NCIP-Kernel-012` § Motivation — its policy is binding for v1.0 and changing it later means
re-auditing every allocation site. That is why this is a Standards Track NCIP and not an ordinary
refactor PR.

---

## Specification

This section is the normative core. RFC 2119 keywords (MUST, SHOULD, MAY) are binding.

### S1. Terminology

- **Allocator** — the kernel object implementing `core::alloc::GlobalAlloc`, installed as the
  `#[global_allocator]` singleton (replacing `BumpHeap`).
- **Arena** — the single contiguous heap region handed to the allocator at boot by
  `NCIP-Kernel-005` `pick_region` (`base`, `len`), `len ≤ HEAP_MAX_BYTES`.
- **Size class** — one of a fixed, compile-time set of block sizes. Every small allocation is
  rounded up to the smallest size class that fits it.
- **Slab** — a contiguous run of equal-size blocks belonging to a single size class.
- **Free-list** — a per-size-class singly linked list of reclaimed blocks available for reuse.
- **Block** — the unit handed back from `alloc`; its size is its size class (small path) or a
  page-rounded run (large path).

### S2. Allocator contract (normative interface)

The allocator MUST expose the `GlobalAlloc` surface. The contract below constrains its observable
behaviour; sub-tasks WS1-08.2–.9 implement it.

#### S2.1 `alloc(layout: Layout) -> *mut u8`

1. The allocator MUST return either a non-null pointer to a writable block of **at least**
   `layout.size()` bytes, aligned to **at least** `layout.align()`, or `null_mut()` on OOM
   (S2.4).
2. For `layout.size()` ≤ `MAX_SMALL_BYTES` (S3.1), the allocator MUST serve the request from the
   smallest size class `c` with `c ≥ max(layout.size(), layout.align())`, popping the free-list
   head if non-empty (O(1)) else carving the next block from the class's current slab.
3. For `layout.size()` > `MAX_SMALL_BYTES`, the allocator MUST serve the request from the
   **large path** (S3.3): a page-granular (4 KiB) run of `ceil(layout.size() / 4096)` contiguous
   pages, aligned to `max(4096, layout.align())`.
4. A `layout.size()` of 0 MUST be treated as a request for 1 byte (consistent with the Rust
   `GlobalAlloc` convention that a zero-size `alloc` returns a valid, unique, non-dereferenceable
   pointer); the returned pointer MUST be `layout.align()`-aligned and MUST NOT alias any live
   block.
5. The returned block's contents are **unspecified** (the allocator MUST NOT be relied on to zero
   memory; callers needing zeroing use `alloc_zeroed`, whose default `GlobalAlloc` provided method
   the allocator MAY override for the large path).

#### S2.2 `free(ptr: *mut u8, layout: Layout)` (`dealloc`)

1. `free` MUST accept any `(ptr, layout)` pair previously returned by `alloc` with the **same**
   `layout`, and MUST make the block available for a future `alloc` (i.e. it MUST actually
   reclaim — this is the entire point of the NCIP). This is the binding departure from
   `NCIP-Kernel-012` § S2 constraint 2.
2. Calling `free` with a `ptr` not produced by this allocator, or with a `layout` different from
   the one passed to the originating `alloc`, is **undefined behaviour** at the `GlobalAlloc`
   level; the allocator is not required to detect it. In debug builds the allocator SHOULD
   `debug_assert` cheap, local invariants (e.g. the block address lies inside the arena and is
   size-class-aligned) to catch caller bugs early.
3. Small-path `free` MUST push the block onto the head of its size class's free-list in O(1). The
   size class MUST be recoverable from `layout` alone (the same rounding rule as S2.1.2), so the
   allocator does not need per-block headers for the small path.
4. Large-path `free` MUST return the page run to the page-run free structure (S3.3) and SHOULD
   coalesce with adjacent free runs to bound external fragmentation of the large region.
5. `free(null_mut(), _)` MUST be a no-op (mirrors `GlobalAlloc` callers that free a never-checked
   allocation result).

#### S2.3 Alignment

1. `layout.align()` is always a power of two (`Layout` invariant). The allocator MUST honour it.
2. Size classes MUST be chosen so that each class size is a multiple of its own value's largest
   power-of-two divisor at least up to `MAX_ALIGN_SMALL` (S3.1); a request whose `align` exceeds
   its size class's natural alignment MUST be promoted to the smallest size class that is a
   multiple of `align`, or to the large path if none qualifies.
3. The large path MUST satisfy alignments up to and including 4096 directly; alignments > 4096
   (huge-page-aligned kernel requests) MAY be rejected (`null_mut()`) at v1.0 and are deferred to
   a future NCIP — the kernel has no current allocation site requiring `align > 4096` on the heap
   (page-table frames come from `BitmapFrameAllocator`, not the heap).

#### S2.4 Out-of-memory

1. When the request cannot be satisfied (no free block in the class **and** the arena cannot carve
   a new slab; or no contiguous page run for the large path), `alloc` MUST return `null_mut()`.
2. The allocator MUST NOT panic on OOM itself. Returning null routes through the Rust `alloc`
   crate's alloc-error hook into the `NCIP-Kernel-012` § S1 panic handler, preserving the existing
   single, audited termination path.
3. OOM MUST be reachable only by genuine arena exhaustion, never by internal bookkeeping
   corruption; the allocator MUST NOT have a reachable state where free memory exists in the arena
   but `alloc` returns null for a request of a size that memory could satisfy after slab carving.

#### S2.5 Thread-safety

1. All allocator operations MUST be safe to call concurrently from multiple CPUs (SMP is enabled
   per `MB1`/multicore INIT-SIPI). The contract is `Sync`.
2. The allocator MUST NOT hold a lock across a call that can re-enter the allocator. The fast
   paths (free-list push/pop, slab bump) MUST be lock-free or use a per-size-class lock of bounded
   hold time; a single global lock over the whole heap is NOT permitted because it serialises every
   kernel allocation across all CPUs.
3. The allocator MUST be safe to call from interrupt context (the IPC `EvictOldest` ring path and
   the driver IRQ path allocate); therefore any lock used MUST be acquired with interrupts
   disabled or be lock-free, to avoid a deadlock against an ISR that allocates.

#### S2.6 Invariants (MUST hold at every observable point)

- **I1 — boundedness.** Every live block lies fully within `[base, base + len)`.
- **I2 — non-overlap.** Two distinct live blocks never overlap.
- **I3 — reuse.** A block returned to a free-list is handed out by a subsequent same-class `alloc`
  before the arena carves fresh backing store for that class, while any block remains free in it
  (free-list-first policy; bounds working-set growth).
- **I4 — alignment.** Every returned pointer satisfies its request's alignment (S2.3).
- **I5 — fast-path complexity.** `alloc`/`free` on the small path are O(1) (no scanning of a
  variable-length structure on the hot path).
- **I6 — no torn state.** Under any CPU interleaving permitted by S2.5, the free-lists and slab
  cursors transition only between valid states (enforced by CAS loops / bounded critical
  sections, mirroring the existing `BumpHeap` `compare_exchange_weak` discipline).

### S3. Slab + free-list structure

#### S3.1 Size classes

The small path MUST use **fixed, power-of-two size classes**:

```
16, 32, 64, 128, 256, 512, 1024, 2048, 4096   (bytes)
```

- `MAX_SMALL_BYTES = 4096`. Requests larger than this take the large path (S3.3).
- `MAX_ALIGN_SMALL = 4096` (the largest small class is page-sized and page-aligned).
- Power-of-two classes bound **internal fragmentation to < 2×** (a request of `n` bytes wastes at
  most `n − 1` bytes) and make the size class a pure function of `max(size, align)` via
  `next_power_of_two`, so the small path needs **no per-block metadata** — the property that keeps
  `free` O(1) and header-free.
- The class set is part of this normative spec; changing it (adding intermediate classes such as
  the common 48/96/192 "tcmalloc" spacing to cut the < 2× bound to < 1.25×) is a tuning change
  that MAY be made by a superseding NCIP once soak data (WS1-08.9) justifies it. v1.0 ships the
  simple power-of-two set.

#### S3.2 Free-list

- Each size class owns one free-list whose nodes are stored **in the free blocks themselves**
  (intrusive list: the first `size_of::<usize>()` bytes of a free block hold the next pointer).
  No external metadata array is needed; this is the standard slab free-list layout.
- `free` pushes at the head; `alloc` pops from the head — LIFO, which maximises cache reuse of
  recently-freed blocks.
- The intrusive pointer write happens only while the block is free and owned by the allocator, so
  it never races a caller's use of the block.

#### S3.3 Slabs and the large path

- Slabs are carved from the arena by a **bump cursor** (the surviving, audited core of the
  existing `BumpHeap`): when a size class's free-list is empty, the allocator advances the cursor
  by one slab worth of blocks for that class and threads them onto the free-list. The bump cursor
  thus becomes the *slab source*, not the per-allocation source.
- The **large path** (`size > 4096`) allocates page-granular runs. v1.0 MAY implement it as a
  second bump cursor with a coalescing free-list of returned runs; it MUST satisfy S2.1.3,
  S2.2.4, and S2.4. Large allocations are rare on the kernel heap (the initramfs-resident VFS and
  the desktop working set dominate and are < 4 KiB per object), so a simple first-fit over
  coalesced runs is acceptable for v1.0.
- Slab and large-path backing MUST stay disjoint from the `BitmapFrameAllocator` pool exactly as
  today: the allocator's arena is the `(base, capped)` region from `pick_region`
  (`NCIP-Kernel-012` § S2 / `HEAP_MAX_BYTES`), and the frame allocator owns everything else. This
  NCIP does **not** change `pick_region` or `HEAP_MAX_BYTES`.

### S4. Integration behind the existing heap interface

- The new allocator MUST be installed as the `#[global_allocator]` in place of `BumpHeap`,
  gated `#[cfg(all(target_os = "none", not(test)))]` (same gate as today), with host integration
  tests constructing a fresh instance over a stack buffer (same pattern as `tests/heap.rs`).
- `init(base, len)` MUST keep the one-shot, panic-on-double-init contract of
  `BumpHeap::init` (`NCIP-Kernel-012` § S2 constraint 1) and the same `# Safety` preconditions.
- The forensic surface (`used_bytes`, `total_bytes`, `is_initialised`) MUST be preserved; a new
  `free_bytes` / per-class occupancy counter SHOULD be added for the soak test (WS1-08.9) and
  telemetry.

### S5. IPC buffer migration and cap removal

- With real `dealloc`, `IpcRegistry::destroy_channel` MUST release the channel's queue backing
  store (drop the `VecDeque`, which now actually frees). No code change is required at the call
  site beyond ensuring the `Drop` runs — the change is that the global allocator now reclaims.
- The `queue_depth ≤ 256`-style ceiling that existed only to bound the non-reclaiming heap MUST be
  replaced by an explicit per-owner heap quota carried on the channel-creation capability, OR
  removed where a quota already bounds the owner. The exact quota mechanism is specified in the
  WS1-08 implementation tasks and MUST NOT weaken any capability check; this NCIP only authorises
  the removal of the *allocator-imposed* ceiling.
- `MAX_CHANNELS_PER_OWNER` MAY be retained as a policy limit (it is a capability-scoping decision,
  not a memory-safety crutch) but its *rationale* changes from "the heap leaks" to "per-owner
  resource governance"; that re-justification MUST be recorded in `ADR-0005`.

---

## Rationale

**Why slab + free-list, not buddy or a general free-list.** Three allocator shapes were
considered:

1. **General free-list (best-fit / first-fit over a single list).** Rejected: O(n) hot path,
   external fragmentation, needs per-block size headers — strictly worse than slab for the
   kernel's allocation profile (many small, same-size objects: IPC messages, capability records,
   task-control blocks).
2. **Buddy allocator.** Rejected for v1.0: larger code/TCB surface, power-of-two rounding gives
   the *same* internal-fragmentation bound as power-of-two slabs but with split/merge bookkeeping
   on every op. Buddy wins only when allocation sizes are wildly variable, which the kernel heap's
   profile is not. It remains a candidate for the large path if soak data shows large-run
   fragmentation; deferred to a future NCIP.
3. **Slab + free-list with power-of-two classes (chosen).** O(1) hot path, header-free small path,
   provable < 2× internal fragmentation, zero external fragmentation within a class, and it reuses
   the already-audited bump cursor as its slab source — minimal new `unsafe`, minimal new TCB.

**Why keep power-of-two and not finer spacing.** Finer size classes (48/96/192…) cut internal
fragmentation but add classes, complicate the "size class = `next_power_of_two`" pure-function
property, and need real soak data to justify. v1.0 ships the simple, analysable set; tuning is a
later, data-driven, superseding NCIP (S3.1).

**Why not just raise `HEAP_MAX_BYTES`.** That defers the OOM, it does not fix it: a churning
workload still leaks monotonically. The defect is the absence of `dealloc`, not the arena size.

**What we are explicitly NOT doing.** No external allocator crate (`talc`,
`linked_list_allocator`, `buddy_system_allocator`) — each expands the trust base, which
`NCIP-Kernel-012` § S2 constraint 6 already deferred behind a separate NCIP; this NCIP keeps the
in-crate, audited-line discipline. No change to `pick_region`, `HEAP_MAX_BYTES`, the panic
handler, or the frame allocator. No `align > 4096` heap support (S2.3.3).

---

## Backwards Compatibility

This NCIP amends the **allocator** portion of `NCIP-Kernel-012` (§ S2). It does **not** supersede
`NCIP-Kernel-012` because that NCIP also specifies the panic handler (§ S1), which is unchanged; the
`supersedes`/`superseded-by` link is therefore left null and the relationship is recorded here and
in `ADR-0005`.

Changes and their blast radius:

- **`NCIP-Kernel-012` § S2 constraint 2 ("No `dealloc`") is reversed.** `dealloc` now reclaims.
  This is observable only as *better* behaviour (memory is returned); no caller relied on the
  no-op semantics (a no-op `dealloc` and a reclaiming `dealloc` are indistinguishable to a correct
  `GlobalAlloc` user).
- **The `#[global_allocator]` type changes** from `BumpHeap` to the new slab allocator. The
  `init`, `used_bytes`, `total_bytes`, `is_initialised` API surface is preserved, so
  `kernel_entry`/`kernel-runner` call sites are source-compatible.
- **IPC capacity ceilings** (`queue_depth ≤ 256`-style) are lifted / re-based on quotas (S5).
  Operators who relied on the cap as an implicit DoS bound are protected instead by the
  capability-carried per-owner quota; the net DoS posture is equal-or-better.
- **Migration path:** single in-tree swap. No on-disk, wire, or capability-format change. No data
  migration. A kernel built before this NCIP and one built after are boot-compatible against the
  same `NCIP-Kernel-005` boot hand-off.

---

## Test Cases

Standards Track — testable invariants. The reference implementation (WS1-08.2–.9) MUST ship:

1. **Host unit tests** (`crates/nexacore-kernel/tests/`, same pattern as `tests/heap.rs`), over a
   stack-backed arena:
   - `alloc` honours size and alignment for every size class and for representative large
     requests (assert returned pointer alignment and in-arena bounds — I1, I4).
   - `free` then `alloc` of the same class returns the **same** block (reuse — I3).
   - Interleaved alloc/free churn of N ≫ arena/blocksize operations does **not** grow
     `used_bytes` beyond the live set (no leak — the core regression vs `BumpHeap`).
   - OOM returns `null_mut()` and does not panic (S2.4); after a `free`, the previously-failing
     `alloc` succeeds (S2.4.3).
   - Zero-size and null-free edge cases (S2.1.4, S2.2.5).
   - Concurrent alloc/free from multiple threads with a shared instance leaves the free-lists and
     counters consistent (I6, S2.5) — run under the host thread sanitizer where available.
2. **Stress test (WS1-08.8):** create/destroy 10⁵ IPC channels against a deliberately
   memory-limited arena; assert no OOM and that `used_bytes` returns to baseline after teardown.
3. **the test VM soak (WS1-08.9):** long boot soak exercising channel churn; assert no OOM panic over
   the soak window and that the new per-class occupancy counters stay bounded. Markers asserted by
   `scripts/vm103-assert.sh` against `tests/expected-boot-lines.txt`.

Illustrative vector (size-class selection): `alloc(Layout::from_size_align(33, 8))` → class `64`;
`alloc(Layout::from_size_align(8, 64))` → class `64` (align-promoted); `alloc(Layout::from_size_align(5000, 8))`
→ large path, 2-page run.

---

## Reference Implementation

To be delivered under plan task `WS1-08`:

- Allocator type + size classes + free-list: `crates/nexacore-kernel/src/bare_metal/heap.rs`
  (extends/replaces the `BumpHeap` impl; the bump cursor is retained as the slab source).
- Host tests: `crates/nexacore-kernel/tests/heap.rs` (extended) + a new churn/leak test.
- IPC migration: `crates/nexacore-kernel/src/ipc.rs` (`destroy_channel` reclaim, cap → quota).
- Stress test: new host test (WS1-08.8); the test VM soak via `scripts/vm103-assert.sh` (WS1-08.9).

Status will move `Draft → Review` once the implementation branch exists and the host tests pass;
this matches the `NCIP-Kernel-012` / `NCIP-Kernel-005` precedent of NCIP-and-implementation landing
together.

---

## Security Considerations

- **Mitigates `K-D-1` (DoS via kernel memory exhaustion, adversary A1, `docs/04a-threat-model.md`).**
  Real reclamation removes the churn-to-exhaustion vector that the bump allocator's leak created;
  the residual DoS surface is bounded by per-owner quotas (S5) rather than by an arbitrary global
  cap.
- **New attack surface: allocator metadata corruption.** The intrusive free-list stores `next`
  pointers inside free blocks (S3.2). A use-after-free or double-free by a *kernel* caller could
  corrupt a free-list and, in the worst case, cause `alloc` to return an attacker-influenced
  pointer (a classic heap-exploitation primitive). Mitigations: (a) the small-path `free` requires
  the exact originating `Layout`, so a wrong-size free is caller UB the debug-assert (S2.2.2) is
  designed to catch; (b) the allocator serves **kernel-internal** allocations only — there is no
  user-controlled `free(ptr)` syscall, so the adversary must already have a kernel memory-safety
  bug (`K-E-1`), which this NCIP neither widens nor narrows beyond the debug-assert hardening; (c) a
  future NCIP MAY add free-list pointer hardening (XOR-masking / safe-linking, as in glibc/hardened
  allocators) — flagged as deferred, not v1.0.
- **Interrupt-context safety (S2.5.3)** is a correctness *and* availability property: a lock held
  across an ISR that allocates would deadlock the kernel — a self-inflicted DoS. The lock-free /
  interrupts-disabled requirement closes that.
- **Termination path unchanged.** OOM still routes through the single audited `NCIP-Kernel-012`
  § S1 panic handler; no new console output or secret-leaking diagnostic surface is introduced.

---

## Privacy Considerations

- **No personal data flow.** The allocator manages anonymous kernel heap bytes; it does not
  observe, store, or route any user content, identity, or capability payload.
- **No new metadata exposure.** The optional forensic counters (`used_bytes`, per-class
  occupancy, S4) are kernel-internal telemetry; they MUST NOT be exposed across a process boundary
  without a capability check (they reveal coarse kernel-activity timing/volume, a weak side
  channel). At v1.0 they are debug/soak-only and not surfaced to user space.
- **Linkability:** none. Reused blocks carry no caller identity; the LIFO free-list (S3.2) does
  not encode which subsystem last owned a block in any externally observable way.
- **GDPR/retention:** N/A — no personal data is processed or retained by the allocator.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
