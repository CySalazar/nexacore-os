# `nexacore-driver-shared`

NexaCore OS driver SDK helpers: capability deposit window parser and well-known constants.

## Purpose

When the kernel loads a driver via `DriverLoad` (NCIP-013 § S5.3 step 8) it
mints attenuated `CapabilityToken` blobs for every capability declared in the
driver's manifest and deposits them in a read-only 32 KiB window at the
well-known virtual address `0x0010_0000` before transferring execution to the
driver's `_start`.

This crate provides:

- **`DRIVER_CAP_DEPOSIT_VA`** — the well-known deposit VA (`0x0010_0000`).
- **`DRIVER_CAP_DEPOSIT_LEN`** — deposit window length (`0x8000` = 32 KiB).
- **`caps::find_token(action_tag, predicate)`** — production entry point; reads
  from the static deposit VA.
- **`caps::find_token_in_buf(buf, action_tag, predicate)`** — pure-function
  variant for tests and simulation.
- **`NexaCoreCapsHeader`** — `repr(C)` layout of the 16-byte deposit header.
- **`NexaCoreCapsError`** — typed errors from the header/entry parser.
- **`ACTION_TAG_*`** constants for all five capability actions.

## Usage in a driver `_start`

```rust
use nexacore_driver_shared::{ACTION_TAG_MMIO_MAP, caps::find_token};

// Locate the first MmioMap capability token in the deposit window.
// The kernel guarantees at least one such token is present for every
// `mmio_region` entry in the driver's manifest.
let token_bytes: &[u8] = find_token(ACTION_TAG_MMIO_MAP, |_| true)
    .expect("kernel must have deposited an MmioMap token");

// Pass the postcard-encoded CapabilityToken bytes to the MmioMap (70) syscall.
// See NCIP-013 § S5.3 and the driver's syscall entry helper.
```

## Wire format

The deposit window uses a flat indexed layout specified in
[`NCIP-013 § S5.3`](../../oips/oip-driver-framework-013.md)
and implemented by the kernel encoder in
[`crates/nexacore-kernel/src/cap_deposit.rs`](../nexacore-kernel/src/cap_deposit.rs).

```text
Offset  Size     Field
──────  ───────  ────────────────────────────────────────────────────────────
0x000   8 bytes  magic        = b"OMNICAPS"
0x008   4 bytes  version      = 1u32 (little-endian)
0x00C   4 bytes  entry_count  N ∈ [0, 64] (little-endian)
0x010   N×16     entries[N]:
                   u32 action_tag    (1=MmioMap, 2=DmaMap, 3=IrqAttach,
                                      4=PciConfigRead, 5=PciConfigWrite)
                   u32 resource_tag  (1=MmioRegion, 2=DmaWindow,
                                      3=IrqLine, 4=PciDevice, 5=Any)
                   u32 token_offset  (byte offset from page start, 8-byte aligned)
                   u32 token_len     (length of the postcard blob)
…       …        token_blobs[N]     postcard-canonical CapabilityToken bytes
0x7FFF  …        zero padding
```

## Design rationale

**Zero production dependencies.**  Keeping this crate dep-free ensures no
transitive supply-chain vulnerability can reach driver binaries through the
SDK layer.  The parser uses only `core` primitives.

**`find_token_in_buf` for tests.**  The production `find_token` reads from the
kernel-mapped page at the static VA and is only correct inside a live driver
process.  Host-side tests use `find_token_in_buf` with a caller-supplied byte
slice, making the logic fully testable without a running kernel.

## Cross-references

- [NCIP-013 § S5.3 step 8](../../oips/oip-driver-framework-013.md) — deposit
  ABI specification and design decisions for the deposit window.
- [`crates/nexacore-kernel/src/cap_deposit.rs`](../nexacore-kernel/src/cap_deposit.rs)
  — kernel-side encoder; must stay in sync with this crate's parser.

## `no_std` status

`#[cfg_attr(not(test), no_std)]`.  No `alloc` types are used; the crate
compiles cleanly for `x86_64-unknown-none` (the Phase 1 driver Ring 3 target).

## License

Apache-2.0 — see the workspace root [`LICENSE`](../../LICENSE).
