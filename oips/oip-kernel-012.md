---
ncip: 12
title: Kernel panic handler and global allocator (gate K3 of NCIP-Kernel-003)
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-12
updated: 2026-05-14
requires:
  - 1
  - 3
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

`NCIP-Kernel-003` § 3 defines a 5-step transition (K1–K5) that takes `nexacore-kernel` from a `std`-compiling library to a bare-metal binary that boots under UEFI. K1 (feature flag) and K2 (`#![no_std]` switch) already merged; K3 (`cargo build --target x86_64-unknown-none --features bare-metal` succeeding) currently fails because the bare-metal build requires a `#[panic_handler]` and a `#[global_allocator]` that the v0.1 kernel does not yet provide.

This NCIP specifies both. The panic handler is **non-allocating, interrupt-disabled, halt-on-completion**, with a structured record encoded via the wire helper from `NCIP-Serde-004` (`nexacore-types::wire`, postcard-1.0). The global allocator is an **in-crate bump allocator** backed by a single contiguous heap region whose physical address and size come from the boot hand-off ABI (deferred to `NCIP-Kernel-005`). No external allocator crate is pulled in; the bump impl fits in ~80 lines of Rust.

The NCIP closes the K3 gate. K4 (boot hand-off ABI + `kernel-runner/` crate) and K5 (QEMU smoke test) follow as separate NCIPs.

---

## Motivation

The bare-metal build today fails with:

```text
error: `#[panic_handler]` function required, but not found
error: no global memory allocator found but one is required
```

These two requirements are non-negotiable on `x86_64-unknown-none`: without a panic handler the linker has no termination behaviour for failed `Result::unwrap` and friends, and without a `#[global_allocator]` any path that allocates (`Vec`, `Box`, `String`) fails to link.

Both are **policy-relevant**, not just mechanical:

- The panic handler **runs in the kernel's most-privileged context** with potentially-corrupted state. Its design is a security primitive: it must reveal enough to debug a crash but never leak secrets to a console an attacker could read; it must terminate safely without inviting a controlled-fault attack into a useful state.
- The global allocator **mediates every kernel-internal allocation**. Its policy (bump vs slab vs buddy) decides fragmentation behaviour, allocation latency, and the worst-case OOM behaviour. The choice is binding for v1.0 because changing it later requires re-auditing every kernel allocation site.

Both decisions therefore deserve an NCIP. Bundling them avoids two near-empty NCIPs and reflects the fact that the panic handler shares static buffers with the allocator's diagnostic surface.

---

## Specification

### S1. Panic handler

Module: `crates/nexacore-kernel/src/bare_metal/panic.rs` (new file, gated `#[cfg(all(feature = "bare-metal", not(test)))]`).

```rust
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Step 1 — disable interrupts. Architecture-specific.
    arch::interrupts::disable();

    // Step 2 — emit the structured record to every available early-boot
    // sink (serial COM1 + framebuffer if mapped). The record is encoded
    // into a STATIC fixed-size buffer; we never allocate on the panic path.
    let record = PanicRecord::from_info(info);
    let mut buf = [0u8; PANIC_RECORD_MAX_BYTES];
    if let Ok(written) = wire::encode_into_slice(&record, &mut buf) {
        early_console::emit(&buf[..written]);
    } else {
        // Encoding overflowed the static buffer (impossible at v1 sizes,
        // but we degrade gracefully): emit the raw payload-truncation
        // marker so the forensics pipeline knows to expect it.
        early_console::emit_raw(b"NexaCore-KPANIC-OVERFLOW\n");
    }

    // Step 3 — halt forever. `hlt` is the standard non-spinning halt.
    arch::halt_forever()
}
```

Where:

```rust
#[derive(serde::Serialize)]
pub struct PanicRecord<'a> {
    pub kernel_version: &'static str,
    pub panic_at: PanicLocation<'a>,
    pub message: &'a str,
    /// Optional stack pointer captured at panic time. Always `None`
    /// in v0.1 (stack unwinding is out of scope until K4 lands the
    /// proper boot frame). The field exists so adding it later is
    /// non-breaking.
    pub stack_pointer: Option<u64>,
}

#[derive(serde::Serialize)]
pub struct PanicLocation<'a> {
    pub file: &'a str,
    pub line: u32,
    pub column: u32,
}
```

**Constraints (binding):**

1. **MUST NOT allocate.** Every buffer is `[u8; N]` on the stack or in `static` storage. The serialization helper in `nexacore-types::wire::encode_into_slice` is the slice-targeted variant added by this NCIP (companion to `encode_canonical` from `NCIP-Serde-004`); it returns `Err(_)` on overflow rather than reallocating.
2. **MUST disable interrupts before doing anything else.** A nested panic during the panic handler would re-enter the same code path and corrupt the static buffers.
3. **MUST NOT include sensitive process state.** No syscall argument bytes, no capability tokens, no key material. The serialized record carries only kernel-internal infrastructural state.
4. **MUST be `-> !`.** No return path. The CPU halts.
5. **PANIC_RECORD_MAX_BYTES = 1024.** Sized for the early-boot serial line at 115200 baud (≈11 KiB/s; 1 KiB record fits in <100 ms). Larger records would lengthen the post-panic blackout window.

### S2. Global allocator

Module: `crates/nexacore-kernel/src/bare_metal/heap.rs` (new file, same gating as S1).

```rust
#[global_allocator]
static GLOBAL_HEAP: BumpHeap = BumpHeap::new();

pub struct BumpHeap {
    base: AtomicPtr<u8>,
    next: AtomicPtr<u8>,
    end:  AtomicPtr<u8>,
}

unsafe impl GlobalAlloc for BumpHeap { /* O(1) bump via fetch_add */ }

impl BumpHeap {
    pub const fn new() -> Self { /* uninitialized; init() called by kmain */ }
    pub unsafe fn init(&self, base: *mut u8, len: usize) { /* one-shot */ }
}
```

**Constraints (binding):**

1. **One-shot initialisation.** `init()` is called exactly once by `kmain()` after the bootloader has handed `BootInfo.memory_regions` over (per K4 / `NCIP-Kernel-005`). Calling `init()` twice triggers a panic.
2. **No deallocation.** `dealloc()` is a no-op. The kernel's own state is statically sized (per `NCIP-Kernel-003` § 5 rationale); a bump allocator without free is sufficient for v1.
3. **Alignment is honoured.** The bump pointer is rounded up to the requested alignment via `next.fetch_update(Acquire, Acquire, |p| Some(p.add(align_offset)))` before each allocation.
4. **OOM behaviour.** When the bump pointer would exceed `end`, `alloc()` returns `null_mut()`. The Rust `alloc` crate translates this into a panic via the `#[alloc_error_handler]` (also defined in this module) — which then routes to the panic handler from S1. The OOM record carries the failed-allocation `Layout` so post-mortem can identify the offending allocation site.
5. **Thread-safety.** The kernel is single-CPU at v1.0 (`NCIP-Kernel-003` § 4); the atomic operations are present so multi-CPU deployment in v1.x does not require an allocator rewrite.
6. **No external dependency.** The implementation is in-crate. `linked_list_allocator`, `talc`, `buddy_system_allocator` are all reasonable candidates for v1.x evolution but are deferred behind a separate NCIP because each adds an external trust base.

### S3. Heap region provisioning

The kernel does **not** know its own heap region at v0.1 — that is the `BootInfo.memory_regions` entry tagged `Usable` and contiguous, picked by the runner per `NCIP-Kernel-005` § (TBD). For the K3 gate, the heap region is supplied via a dedicated symbol the runner sets:

```rust
extern "Rust" {
    /// Set by the boot runner before calling `kmain`. Length and base
    /// stability is guaranteed by the runner.
    static NEXACORE_KERNEL_HEAP_BASE: *mut u8;
    static NEXACORE_KERNEL_HEAP_LEN:  usize;
}
```

This is a stop-gap until `NCIP-Kernel-005` formalises the `BootInfo` struct. Code dependent on the symbol carries a `// TODO(NCIP-Kernel-005)` and the NCIP body of `NCIP-Kernel-005` MUST explicitly remove the symbol stub.

### S4. Test plan

- **Unit test (host build):** `BumpHeap::init` + N allocations of varying sizes / alignments inside a synthetic `[u8; 64 * 1024]` buffer; assert pointer monotonicity, alignment correctness, and OOM at the documented offset.
- **Unit test (host build):** `wire::encode_into_slice(&PanicRecord{..})` round-trip via `wire::decode_canonical` produces the same struct; oversized record returns `Err(_)`.
- **Compile-fail test (`trybuild`):** any allocation inside a function attributed `#[no_mangle] #[link_section = ".panic"]` (placeholder for the panic-path linkage) fails to compile — defends the "MUST NOT allocate" constraint at the type level.
- **Integration test (host build):** synthetic `BootInfo`-like struct passes through a fake runner that calls `BumpHeap::init`, then a sequence of `Vec::with_capacity` allocations succeeds.
- **K3 gate test (CI):** `cargo build --target x86_64-unknown-none --features bare-metal -p nexacore-kernel` exits 0. (Today this fails; after this NCIP `Active` it must pass. CI matrix gains `x86_64-unknown-none` as a `cargo build`-only target — no `cargo test` because there is no host runtime.)

### S5. Migration sequence

| Step | Description | Verification |
|---|---|---|
| **K3.a** | Add `crates/nexacore-kernel/src/bare_metal/{mod.rs, panic.rs, heap.rs, arch/x86_64.rs}`; gate the module under `#[cfg(all(feature = "bare-metal", not(test)))]`. | `cargo build --workspace --all-features` |
| **K3.b** | Add `nexacore-types::wire::encode_into_slice` (slice-targeted companion to `encode_canonical`); update its callers. | `cargo test -p nexacore-types` |
| **K3.c** | Add the unit tests from § S4 to `crates/nexacore-kernel/tests/heap.rs` and `crates/nexacore-kernel/tests/panic_record.rs`. | `cargo test --workspace --all-features` |
| **K3.d** | Add `x86_64-unknown-none` to the CI build matrix in `.github/workflows/ci.yml` (build-only). | First green CI run on PR. |
| **K3.e** | Update `crates/nexacore-kernel/src/lib.rs` to export `bare_metal` symbols + add the `#[alloc_error_handler]` glue. | All previous gates green. |

---

## Rationale

**Why a custom bump allocator and not `linked_list_allocator` / `talc` / `buddy_system_allocator`?** Because the kernel's own allocation pattern is dominated by **a small number of long-lived allocations** at boot (the IPC queue ring buffers, the task table, the capability table). After boot, kernel-internal allocation is rare to the point that fragmentation behaviour does not differentiate the candidates. A bump allocator:

- Has the smallest TCB surface (≈80 lines of `unsafe`-free Rust over `core::sync::atomic`).
- Is trivially formally analyzable (one invariant: `base ≤ next ≤ end`).
- Has O(1) worst-case allocation, with no metadata bytes in-band of the heap (no fragmentation maps to poison).
- Is the same allocator pattern used by seL4, NOVA, and Redox's early boot path.

The "no `dealloc`" property is **a security feature**: a kernel that does not free cannot suffer a use-after-free in its own heap. Userspace allocation policies (which need full `alloc`/`dealloc`/`realloc` semantics) live in userspace and are out of scope for this NCIP.

**Why postcard for the panic record encoding?** Aligned with `NCIP-Serde-004`. The record is short (typically 100–500 bytes), the recipient (the early-boot console + downstream forensics pipeline) needs a self-delimited format that can be parsed without external schema, and the encoding helper is already going to exist for the wire format.

**Why a static buffer, not a panic-time allocator?** Allocating during a panic is the canonical way to make a panic-during-panic (recursive panic = abort to undefined behaviour). The 1 KiB buffer is sized empirically: 200 bytes for `kernel_version` + `file` + `column` + `line`, up to ~750 bytes for a verbose `message`, leaving headroom.

**Why not unwind?** `panic = "abort"` is set workspace-wide in `Cargo.toml [profile.release]`. Unwinding through a kernel stack with potentially-corrupted state is unsound; abort-on-panic is the standard kernel discipline.

---

## Backwards Compatibility

Not applicable. The bare-metal build does not exist before this NCIP — there are no existing artifacts to be backwards-compatible with. The `bare_metal` module is gated; `cargo build --workspace` (no features) and `cargo test --workspace --all-features` continue to behave exactly as today (the module is `cfg`-excluded under `not(test)`).

---

## Test Cases

Detailed in § S4 above. Summary acceptance for the NCIP:

1. **Host-mode unit tests pass:** `cargo test --workspace --all-features` (185 + 4 new tests = 189).
2. **Bare-metal build succeeds:** `cargo build --target x86_64-unknown-none --features bare-metal -p nexacore-kernel` exits 0.
3. **CI workflow extended:** the new `x86_64-unknown-none` build target appears in `.github/workflows/ci.yml` and is required by branch protection on `main` within 7 calendar days of `Active` (per `NCIP-Process-001` § 9 ¶2).
4. **Trybuild compile-fail test catches in-panic allocation:** any future PR that introduces `Vec`, `Box`, `String`, or `format!` inside the panic-path functions fails CI.

---

## Reference Implementation

Will land on the branch `feat/ncip-kernel-012-panic-and-heap`. Reference layout:

```
crates/nexacore-kernel/src/bare_metal/
├── mod.rs              # Re-exports + module gating doc.
├── panic.rs            # #[panic_handler] + PanicRecord types.
├── heap.rs             # BumpHeap + #[global_allocator] + #[alloc_error_handler].
├── early_console.rs    # COM1 serial + framebuffer write helpers.
└── arch/
    └── x86_64.rs       # interrupts::disable(), halt_forever(), etc.
```

`nexacore-types::wire::encode_into_slice` lands in `crates/nexacore-types/src/wire.rs` alongside the canonical-encoding helpers from `NCIP-Serde-004` (which becomes a hard `requires:` for this NCIP — captured in the frontmatter).

`NCIP-Kernel-005` will:

- Replace the `NEXACORE_KERNEL_HEAP_BASE` / `NEXACORE_KERNEL_HEAP_LEN` extern-symbol stub with a fields on the `BootInfo` struct.
- Define the `_start` entry point and the `kmain` signature.
- Call `BumpHeap::init` from `_start` before invoking `kmain`.

---

## Security Considerations

- **Panic-time information disclosure.** The `PanicRecord` only carries kernel-internal infrastructural state (kernel version, source location, panic message, optional SP). It MUST NOT carry: syscall argument bytes, user-process register state, capability token bytes, key material, sealed-blob plaintext. The compile-fail test in § S4 enforces "no allocation" but does NOT enforce "no sensitive bytes" — that property is upheld by code review of the panic record's `Serialize` implementation. A future cargo-clippy lint can encode the constraint structurally; tracked as a P-tier follow-up.
- **Recursive panic.** Disabling interrupts as the FIRST step of the panic handler is the standard mitigation. A nested panic that bypasses the initial `disable()` (e.g., a panic during the disable itself, which is impossible on `x86_64` but theoretically possible on other arches) would deadlock at the static buffer; we accept the deadlock as a strictly safer state than corruption.
- **Bump allocator and buffer-overflow attacks.** A bump allocator does not have free-list metadata an attacker can corrupt to gain a write primitive (cf. heap-spray attacks against dlmalloc / glibc). The kernel still relies on bounds checks at every slice index, but the allocator stops being part of the attack surface.
- **Heap zeroing.** `BumpHeap::alloc` does NOT zero the returned bytes — Rust's `Layout` contract permits uninitialized return. Callers that need zeroed memory (capability tables, sealed-key vaults) explicitly call `core::ptr::write_bytes(ptr, 0, layout.size())`. We document this in `lib.rs` and provide a `BumpHeap::alloc_zeroed` convenience that does the zero-write inline.
- **Heap region provenance.** The heap's `base` pointer ultimately comes from the bootloader's memory map, which itself is signed by the platform's Secure Boot chain (`NCIP-Kernel-003` § Security Considerations). A heap region under attacker control would imply a compromised bootloader, in which case all kernel-level invariants are already broken; the heap is not a separate trust boundary.
- **Allocator denial-of-service.** A userspace process that triggers many kernel-internal allocations (e.g., spamming `Channel::open` to provoke IPC ring growth) could exhaust the bump heap. The capability check at every syscall (`NCIP-Kernel-003` § 6) is the first defence; a follow-up NCIP adds per-process heap-quota tracking. The OOM behaviour (panic-on-`alloc_error_handler`) is loud and observable, not silent corruption.
- **No `unsafe` in the panic path** outside of the architecture intrinsics. The `BumpHeap` impl uses `core::sync::atomic` for the bump pointer; alignment math is `unsafe`-free via `Layout::pad_to_align`.

---

## Privacy Considerations

The panic handler emits diagnostic information to the early-boot console (serial + framebuffer) when the kernel crashes. From a privacy perspective:

- **No user data on the panic path.** Per § Security Considerations, the `PanicRecord` carries only kernel-internal infrastructural state. A user observing the panic console sees `kernel_version`, the source `file:line:column`, and the panic message string — never user content.
- **Console destination is host-local.** The serial / framebuffer destination is the device's own physical console. There is no network egress on the panic path. (The forensics pipeline that *consumes* panic records, when it exists, is governed by the NCIP that introduces it, with the privacy contract assessed at that point.)
- **No persistent storage of panic records on the kernel side.** The kernel does not write to disk before halting. A subsequent boot that wants to report the prior panic relies on the bootloader / firmware's own logging facilities, which are out of scope.
- **Allocator-side privacy.** The bump allocator's "no zeroing on alloc" property means that uninitialised bytes from a previous allocation may be readable by a subsequent allocation site. Callers MUST zero buffers that will hold privacy-relevant data (capability tokens, sealed-key plaintexts) explicitly. The `BumpHeap::alloc_zeroed` convenience exists for this case. Inline documentation calls this out at the allocator definition site.
- **No timing side-channels introduced.** Bump allocation is constant-time per request; the panic handler's path is data-independent (the encoding loop length depends on the message length, which is itself non-secret).

The full privacy surface for kernel diagnostics (post-mortem aggregation, user-controlled telemetry) is the scope of a future NCIP; this one establishes the panic-time contract as a baseline.

---

## Copyright

This NCIP is licensed under [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/).
