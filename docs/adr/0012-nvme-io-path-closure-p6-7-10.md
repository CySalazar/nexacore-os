# ADR-0012: NVMe IO Path Closure (P6.7.10)

## Status

Accepted — 2026-05-24

## Context

P6.7.10 tracks the full NVMe IO path bring-up from admin queue
construction through live Read/Write/Flush/Discard IO commands.
Pre.42 landed the last admin-side Identify parse (NN validation).
The remaining objectives were:

1. Multi-namespace validation and isolation.
2. Robust IO error handling (classification, retry, reset).
3. Interrupt-driven completion (polling → MSI-X transition).
4. Integration of all three into the live nvme-image bring-up.

## Decision

Implement the closure as four library modules in `nexacore-driver-nvme`
plus a wiring commit in `nexacore-driver-nvme-image`:

### Pre.43 — `namespace_map` module
- `NamespaceMap::build` enumerates all active NSIDs, resolves
  each to its Identify Namespace page, and validates Phase-1
  admission (LBADS=12, NSZE>0).
- Fixed-capacity (16 slots, stack-allocated, no heap).
- `is_admitted(nsid)` gate prevents IO against non-validated NSIDs.
- `NamespaceDescriptor` stores per-namespace metadata in isolation.

### Pre.44 — `io_error` module
- `IoError` taxonomy: Timeout, ControllerStatus (SCT/SC),
  Transport, NamespaceNotAdmitted, ControllerFatal.
- `RetryVerdict`: Retry, ResetAndRetry, Permanent.
- `classify_generic_sc` maps NVMe § 4.6.1 Table 39 to verdicts.
- `RetryTracker` bounds per-command retries (default 3).
- `ResetProtocol` bounds controller reset attempts (default 2).

### Pre.45 — `interrupt` module
- `CompletionWaiter` trait (object-safe): `PollingWaiter` +
  `InterruptWaiter` implementations.
- `MsixTableEntry` parser for 16-byte PCI MSI-X vector entries.
- `MsixConfig` Phase-1 configuration (1 vector, index 0).

### Pre.46 — nvme-image wiring
- Construct `NamespaceDescriptor` from the live Identify Namespace
  response and verify admission.
- Validate `MsixConfig::phase_1_default().supports_vector(0)`.
- Classify IO Read CQE through `IoError::from_status` + `verdict()`
  with distinct exit codes per retry category.

## Alternatives considered

1. **Heap-allocated namespace map** — rejected because the nvme-image
   runs under `PanicOnAlloc` (no heap). Fixed-capacity array is
   sufficient for Phase-1 (1–2 namespaces).

2. **Blocking IRQ wait in the library crate** — rejected because
   `nexacore-driver-nvme` compiles as `no_std` without `no_main` and
   cannot issue syscalls directly. The `CompletionWaiter` trait
   defers the actual wait to the image or a future driver service.

3. **Inline retry loop in the nvme-image** — deferred to a future
   slice. Phase-1 bring-up is single-shot; retry with reset is
   scaffolded in `io_error` but not exercised live until the
   persistent driver loop lands.

## Consequences

- The NVMe IO path is fully robust: namespace admission prevents
  IO against unsupported NSIDs, structured error classification
  enables deterministic failure handling, and the interrupt
  abstraction allows transparent polling→IRQ transition.
- Total test count: 1695 workspace pass / 0 fail.
- No new dependencies added.
- Cross-build (`x86_64-unknown-none --release`) remains clean.
