---
ncip: 5
title: Boot hand-off ABI and kernel-runner crate (gate K4 of NCIP-Kernel-003)
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-12
updated: 2026-05-14
requires:
  - 3
  - 12
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

`NCIP-Kernel-003` § 3 defines a 5-step transition (K1–K5) for `nexacore-kernel`. K1 (feature flag) and K2 (`#![no_std]` switch) merged on `feat/p1-foundational-crates`. K3 (panic handler + bump allocator) is specified by `NCIP-Kernel-012` (in `Draft`) and closes the bare-metal build gate. This NCIP — `NCIP-Kernel-005` — specifies K4: the **boot hand-off ABI** between the bootloader and `nexacore-kernel`, and introduces the **`kernel-runner/` crate** (separate workspace member, sibling to `nexacore-kernel`) that owns the `_start` entry point, the `bootloader` crate v0.11+ build glue, the QEMU run configuration, and the `BumpHeap::init` call that bridges the K3 allocator to a real heap region.

K4 is the natural follow-up to K3: once the kernel can *compile* under `x86_64-unknown-none`, it still cannot *boot* without an entry point and a memory map. K4 produces a bootable artifact that halts in `kmain` after printing a recognizable banner. The QEMU smoke test (K5) follows in a separate NCIP.

The boot hand-off ABI is a Layer-1 wire contract between the bootloader and the kernel: both sides must agree byte-for-byte on the `BootInfo` struct, the calling convention of `_start`, and the stability guarantees across bootloader patch releases. The NCIP locks this contract for v1.0 and documents the revisit point for v1.x.

---

## Motivation

After K3 lands, the workspace has a kernel crate that builds under `cargo build --target x86_64-unknown-none --features bare-metal` but produces a **`staticlib` artifact with no entry point**. There is no symbol the firmware can call, no description of where the heap lives, no way to print a panic to a real serial port. Booting it on hardware (or even QEMU) fails immediately: the UEFI firmware looks for a PE/COFF executable with a documented entry, finds none, and refuses to load.

Three things are missing, all of which K4 supplies:

1. **An entry point.** `_start` must be a `#[no_mangle] pub extern "C" fn _start() -> !` symbol with a known calling convention and a known calling frame (16-byte stack alignment per the SysV AMD64 ABI; no caller saves; no return).
2. **A description of the machine state at entry.** UEFI hands the bootloader a memory map, an RSDP pointer, a framebuffer, and several other firmware tables. The bootloader filters / re-shapes these into a `BootInfo` struct and passes a pointer to it as the single `_start` argument. The kernel cannot find its own heap, ACPI tables, or framebuffer without that struct.
3. **A build pipeline that produces a bootable image.** `cargo build -p nexacore-kernel` produces a `staticlib`. The bootable image is the *linkage* of the kernel `staticlib` against the bootloader's BIOS/UEFI loader stub. The `bootloader` crate v0.11+ does this via a separate `kernel-runner` build script that consumes the kernel binary and emits a `.efi` (UEFI) and `.iso` (legacy / VM convenience) artifact.

The K3 NCIP explicitly punts the heap region's `base`/`len` to two extern-symbol stubs (`NEXACORE_KERNEL_HEAP_BASE`, `NEXACORE_KERNEL_HEAP_LEN`). The K4 NCIP removes the stubs and replaces them with fields on `BootInfo`. K3 → K4 → K5 is a strict chain: K5 needs a bootable image (K4) and a kernel that can panic-and-halt safely (K3).

External pressure: P6.2 in the backlog lists "UEFI bootloader integration" as a gating task for the v1.0 hardware bring-up; the kernel engineer hire (per `docs/hiring/`) is recruited against this NCIP's specification.

---

## Specification

> **Normative keywords.** RFC 2119 / RFC 8174 (MUST, MUST NOT, SHOULD, SHOULD NOT, MAY).

### S1. New workspace member: `kernel-runner/`

A new crate `kernel-runner/` is added at the **repository root** (sibling to `crates/`, not under `crates/`). The location is deliberate: `kernel-runner` is a **build harness**, not a runtime library, and the `bootloader` crate's documentation centers the runner crate at the repository root so the `build.rs` paths are predictable.

```
nexacore/
├── crates/
│   ├── nexacore-kernel/        # the kernel itself (this is the `staticlib` consumed by the runner)
│   └── …
├── kernel-runner/          # NEW — owns _start, BootInfo wiring, qemu config
│   ├── Cargo.toml
│   ├── build.rs            # invokes `bootloader::DiskImageBuilder`
│   └── src/
│       ├── main.rs         # _start, kmain bridge, BumpHeap::init
│       └── early_console.rs # COM1 serial + framebuffer writer used pre-init
└── Cargo.toml              # workspace; adds "kernel-runner" to `members`
```

`kernel-runner/Cargo.toml`:

```toml
[package]
name             = "kernel-runner"
description      = "NexaCore OS UEFI bootloader-runner harness (consumes nexacore-kernel; emits *.efi)."
version.workspace      = true
edition.workspace      = true
rust-version.workspace = true
authors.workspace      = true
license.workspace      = true
repository.workspace   = true
homepage.workspace     = true
keywords.workspace     = true
categories.workspace   = true

[lints]
workspace = true

[dependencies]
nexacore-kernel    = { workspace = true, features = ["bare-metal"] }
nexacore-types     = { workspace = true }
bootloader_api = "0.11"

[build-dependencies]
bootloader     = "0.11"
```

`bootloader_api` (the kernel-facing crate) is `no_std` and provides the `BootInfo` type used at runtime. `bootloader` (the build-side crate) provides `DiskImageBuilder` that the `build.rs` invokes to glue the kernel `staticlib` to the loader stub and emit `target/<profile>/bootimage-nexacore-os.{efi,img}`.

The crate is **excluded from the default workspace build matrix** so `cargo build --workspace` on a developer machine without a cross-toolchain still succeeds. CI builds it explicitly via `cargo build -p kernel-runner --target x86_64-unknown-none`.

### S2. `_start` entry point and calling convention

`kernel-runner/src/main.rs` declares the entry point via the `bootloader_api::entry_point!` macro:

```rust
#![no_std]
#![no_main]

use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use bootloader_api::config::Mapping;

// Configure the bootloader: identity-map physical memory (simplest model for v1.0)
// and request a 1 MiB initial stack.
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut cfg = BootloaderConfig::new_default();
    cfg.mappings.physical_memory = Some(Mapping::Dynamic);
    cfg.kernel_stack_size = 1024 * 1024; // 1 MiB; sized for the K3 panic-path static buffers
    cfg
};

entry_point!(kernel_entry, config = &BOOTLOADER_CONFIG);

/// `_start` is generated by `entry_point!`; this is the Rust-level kernel main.
///
/// The function is `-> !`: the kernel never returns. After `kmain` exits, the runner
/// halts the CPU via `arch::halt_forever()` from `nexacore-kernel::bare_metal::arch`.
fn kernel_entry(boot_info: &'static mut BootInfo) -> ! {
    // Pre-init: set up the early console so a panic in BumpHeap::init or kmain
    // produces visible output rather than a silent hang.
    early_console::init(boot_info.framebuffer.as_mut(), /* com1 = */ true);

    // Bridge: turn the bootloader's MemoryRegion list into a heap region,
    // call BumpHeap::init exactly once, then enter the kernel.
    let (heap_base, heap_len) = nexacore_kernel::bare_metal::heap::pick_region(&boot_info.memory_regions);
    // SAFETY: pick_region returns a region tagged Usable, contiguous, and
    // owned by us per the bootloader's hand-off contract. init() is called
    // exactly once per boot.
    unsafe { nexacore_kernel::bare_metal::heap::GLOBAL_HEAP.init(heap_base, heap_len); }

    nexacore_kernel::kmain(boot_info);
}
```

**Constraints (binding):**

1. **The `entry_point!` macro is the *only* sanctioned way to declare `_start`.** Hand-rolling the symbol is forbidden: `bootloader_api::entry_point!` ensures the function signature, the calling convention, and the stack alignment match the bootloader's expectations across patch releases.
2. **The function MUST be `-> !`.** There is no caller to return to. Falling off the end is undefined behaviour.
3. **The first thing the entry function does, after enabling the early console, is initialize the heap.** Any earlier allocation attempt aborts at the K3 OOM handler.
4. **The `BootInfo` argument MUST be treated as `&'static mut`.** The bootloader hands us exclusive ownership of the struct for the lifetime of the kernel; mutation is permitted (the kernel takes ownership of the memory regions list after parsing) but the reference is the unique handle.

### S3. `kmain` signature

```rust
// In crates/nexacore-kernel/src/lib.rs (added by this NCIP, replacing the K3 stub):

#[cfg(all(feature = "bare-metal", not(test)))]
pub fn kmain(boot_info: &'static mut bootloader_api::BootInfo) -> ! {
    // 1. Subsystem init order (each step is its own future NCIP):
    //    - arch::init() — GDT, IDT, TSS (deferred to K6)
    //    - memory::init(boot_info) — page tables, frame allocator (deferred to K6/K7)
    //    - scheduling::init() — task table (deferred to K8)
    //    - ipc::init() — message rings (deferred to K9)
    //    - capabilities::init() — kernel capability table (deferred to K10)
    //
    // For K4 / this NCIP, kmain only:
    //    a) prints the banner via early_console (visible signature of successful boot)
    //    b) records the boot_info pointer + memory map size in a static for K5 inspection
    //    c) halts forever

    bare_metal::early_console::write_str("\n[NexaCore OS] kmain entered.\n");
    bare_metal::early_console::write_str("[NexaCore OS] kernel version: ");
    bare_metal::early_console::write_str(env!("CARGO_PKG_VERSION"));
    bare_metal::early_console::write_str("\n[NexaCore OS] memory regions: ");
    bare_metal::early_console::write_usize(boot_info.memory_regions.len());
    bare_metal::early_console::write_str("\n[NexaCore OS] halting (K4 scope ends here).\n");

    bare_metal::arch::halt_forever()
}
```

**Constraints (binding):**

1. `kmain` is **public** and lives in `nexacore-kernel::lib`, not `kernel-runner`. The runner is a thin shim; the kernel owns the entry logic.
2. `kmain` is gated by `cfg(all(feature = "bare-metal", not(test)))` so the host-mode test build (which does NOT define `bare-metal`) does not see the function and does not pull in `bootloader_api`.
3. `kmain`'s signature is **stable for v1.0.** Adding fields to `BootInfo` is a bootloader-crate concern; renaming, reordering, or removing arguments to `kmain` requires an NCIP that supersedes this one.
4. `kmain` MUST NOT return. The trailing `halt_forever()` is the only legal exit.

### S4. `BootInfo` struct: fields the kernel commits to

`bootloader_api::BootInfo` (v0.11.x) defines many fields; the kernel **commits to using and binding to** the following subset for v1.0. Other fields MAY be read for diagnostics but MUST NOT be load-bearing:

| Field | Type | Used for | Kernel binding |
|---|---|---|---|
| `memory_regions` | `&'static mut MemoryRegions` (≈`[MemoryRegion]`) | Frame allocator + heap region selection | **Load-bearing.** Frame allocator (K6) builds its free list from this. K4 picks the largest Usable contiguous region for the bump heap. |
| `framebuffer` | `Option<FrameBuffer>` | Early console + kernel-mode crash screen | Load-bearing for the early console; absence is non-fatal (serial is the fallback). |
| `rsdp_addr` | `Option<u64>` | ACPI table discovery (HPET, MADT, MCFG) | Load-bearing for K6+ device init; not used in K4 itself. |
| `physical_memory_offset` | `Option<u64>` | Identity-map base for `phys → virt` translation | Load-bearing for K6 page-table walker. K4 records it in a static. |
| `tls_template` | `Option<TlsTemplate>` | (Future) per-CPU TLS for SMP | Reserved; v1.0 is single-CPU, the field is recorded but not consumed. |
| `ramdisk_addr` / `ramdisk_len` | `Option<u64>` / `u64` | (Future) initrd | Reserved; not used in v1.0. |
| `recursive_index` | `Option<u16>` | Page-table self-mapping convenience | Recorded; consumed by K6 page-table impl. |

Fields not listed above (`api_version` etc.) MAY be inspected for sanity logging but the kernel MUST NOT change behaviour based on them. A future bootloader version that adds fields is forward-compatible; a future bootloader version that *removes* one of the load-bearing fields above forces a new NCIP.

### S5. Heap-region selection algorithm

`nexacore-kernel::bare_metal::heap::pick_region(regions) -> (*mut u8, usize)`:

1. Iterate `regions` in order.
2. Filter to entries with `kind == MemoryRegionKind::Usable`.
3. From the filtered set, pick the **largest contiguous region whose length is ≥ `MIN_HEAP_BYTES = 4 * 1024 * 1024`** (4 MiB; sized for the v1.0 kernel's expected long-lived allocations: IPC ring buffers, task table, capability table per `NCIP-Kernel-003` § 5).
4. If no region satisfies (3), `pick_region` calls `panic!("no usable heap region of ≥ 4 MiB found")`. The K3 panic handler emits the structured record and halts; this is the documented "unbootable hardware" termination state.
5. Return `(start as *mut u8, length as usize)`.

**Constraints (binding):**

1. **`MIN_HEAP_BYTES` is a build-time constant exported by `nexacore-kernel::bare_metal::heap`.** Changing it is breaking-change-equivalent at the boot ABI (a hardware that boots today may not boot tomorrow) and therefore requires an NCIP.
2. The selection MUST be **deterministic across boots on the same hardware** (same regions list → same returned region). Tie-breaking when multiple regions of equal length exist: pick the one with the lowest `start` address.
3. Regions returned by `pick_region` are removed from the `MemoryRegions` slice's logical Usable set: the frame allocator (K6) MUST NOT hand out frames within the heap region. The current NCIP enforces this by *consuming* the chosen region in-place (zeroing its entry in the regions list).

### S6. Removal of the K3 extern-symbol stubs

`NCIP-Kernel-012` § S3 introduces `NEXACORE_KERNEL_HEAP_BASE` and `NEXACORE_KERNEL_HEAP_LEN` as `extern "Rust"` symbols that an external runner must set. **This NCIP removes those symbols** and replaces them with the in-kernel `pick_region` API documented in § S5. Removal is mandatory: leaving the stubs in place would invite two ways of provisioning the heap (the runner setting symbols *and* `pick_region` choosing a region), which is exactly the kind of dual-path ambiguity the NCIP process exists to prevent.

The K4 reference branch deletes the `// TODO(NCIP-Kernel-005)` lines introduced by K3, the extern declarations, and the per-symbol documentation block. The K3 NCIP transitions to `Final` when this NCIP's reference branch merges (K3's deferred work is closed by K4 landing).

### S7. Build pipeline

`kernel-runner/build.rs`:

```rust
fn main() {
    // Path to the compiled kernel staticlib produced by `cargo` for the
    // nexacore-kernel crate. `env::var("CARGO_BIN_FILE_NexaCore_KERNEL_nexacore-kernel")`
    // (set automatically by the artifact-dependency machinery) gives us the
    // path to the kernel binary.
    let kernel_path = std::env::var_os("CARGO_BIN_FILE_nexacore_kernel")
        .expect("kernel binary path not set; ensure nexacore-kernel is an artifact-dependency");
    let kernel_path = std::path::PathBuf::from(kernel_path);

    // UEFI image (the v1.0 boot target):
    let uefi_path = std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap())
        .join("nexacore-os-uefi.img");
    bootloader::UefiBoot::new(&kernel_path)
        .create_disk_image(&uefi_path)
        .expect("failed to build UEFI image");
    println!("cargo:rustc-env=UEFI_IMAGE_PATH={}", uefi_path.display());

    // BIOS image (CI convenience for legacy QEMU; not a v1.0 deployment target):
    let bios_path = std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap())
        .join("nexacore-os-bios.img");
    bootloader::BiosBoot::new(&kernel_path)
        .create_disk_image(&bios_path)
        .expect("failed to build BIOS image");
    println!("cargo:rustc-env=BIOS_IMAGE_PATH={}", bios_path.display());
}
```

**Constraints (binding):**

1. **The UEFI image is the v1.0 boot target.** The BIOS image exists for CI convenience (QEMU without OVMF is faster to start) and is explicitly **not a supported deployment artifact** per `NCIP-Kernel-003` § 1.
2. **The build pipeline MUST be reproducible.** `bootloader` v0.11.x produces deterministic images for the same input; we pin the exact version in `Cargo.toml` (`bootloader = "=0.11.X"` once a specific patch is chosen; see § S9).
3. **No external linker invocation.** The `bootloader` crate handles all linking internally. The runner's `build.rs` does not call `ld`, `lld`, or `objcopy`.

### S8. QEMU run configuration

A `Makefile.toml` (cargo-make) target at the repo root, `run-qemu-uefi`:

```toml
[tasks.run-qemu-uefi]
description = "Build the UEFI kernel image and boot it under QEMU + OVMF."
command = "qemu-system-x86_64"
args = [
    "-drive", "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}",
    "-drive", "if=pflash,format=raw,file=${OVMF_VARS}",
    "-drive", "format=raw,file=${UEFI_IMAGE_PATH}",
    "-serial", "stdio",
    "-no-reboot",
    "-no-shutdown",
    "-m", "512M",
    "-smp", "1",
    "-machine", "q35",
]
dependencies = ["build-kernel-runner"]
```

`${OVMF_CODE}` and `${OVMF_VARS}` default to `/usr/share/OVMF/{OVMF_CODE,OVMF_VARS}.fd` (Ubuntu / Debian) and `/usr/share/edk2/ovmf/{OVMF_CODE,OVMF_VARS}.fd` (Arch / Fedora); `kernel-runner/README.md` documents both paths and the macOS Homebrew alternative.

The QEMU smoke test invoking this configuration is the K5 deliverable; this NCIP only defines the configuration so K5 can use it.

### S9. Version pinning

| Crate | Version | Rationale |
|---|---|---|
| `bootloader` (build-side) | `=0.11.X` (specific patch chosen at branch time) | Reproducible builds; an unintended patch upgrade can shift the on-disk layout. |
| `bootloader_api` (kernel-side) | `=0.11.X` (same X) | The kernel-side API and the build-side image generator MUST be the same minor+patch. |

The X placeholder is replaced with the latest stable 0.11 patch at the moment the NCIP transitions from `Draft` to `Active`. A future bump to `0.12` (or, if maintenance ceases, the Limine evaluation per `NCIP-Kernel-003` § 2) is a new NCIP.

### S10. Test plan

- **Host-mode unit tests (`cargo test --workspace --all-features`)**: `pick_region` against synthetic `MemoryRegions` slices (largest-region picked, tie-break by start address, panic when no region ≥ `MIN_HEAP_BYTES`). The synthetic-region helper lives in `nexacore-kernel/tests/boot_info.rs`.
- **Build-only K4 gate (CI)**: `cargo build -p kernel-runner --target x86_64-unknown-none --release` exits 0. Verifies the `bootloader_api` integration compiles and the build script runs.
- **Image-build K4 gate (CI)**: the same command also emits `target/x86_64-unknown-none/release/build/.../out/nexacore-os-uefi.img` (a PE/COFF image). CI artifacts upload the image so QEMU smoke (K5) can consume it.
- **No host-only `bootloader` dependency in `nexacore-kernel`**: `cargo tree -p nexacore-kernel --no-default-features` and `cargo tree -p nexacore-kernel --features bare-metal` MUST NOT contain `bootloader` (the build-side crate). Only `bootloader_api` is permitted, and only transitively via `kernel-runner` when `bare-metal` is on.

### S11. Migration sequence

| Step | Description | Verification |
|---|---|---|
| **K4.a** | Add `kernel-runner/` workspace member (Cargo.toml, build.rs, src/main.rs, src/early_console.rs). `Cargo.toml` workspace `members` updated. | `cargo build --workspace` (host-mode; the runner is skipped because it requires `x86_64-unknown-none`). |
| **K4.b** | Add `nexacore_kernel::kmain` (cfg-gated) and `nexacore_kernel::bare_metal::heap::pick_region`. Remove the K3 extern-symbol stubs. | `cargo build --workspace --all-features` |
| **K4.c** | Add `pick_region` unit tests (`crates/nexacore-kernel/tests/boot_info.rs`). | `cargo test -p nexacore-kernel` |
| **K4.d** | Add `bootloader` + `bootloader_api` to `[workspace.dependencies]` at pinned `=0.11.X`. | `cargo deny check` exits 0 (no new advisories). |
| **K4.e** | CI: `.github/workflows/ci.yml` gains a `kernel-runner-build` job that runs `cargo build -p kernel-runner --target x86_64-unknown-none --release` and uploads the resulting image as an artifact. | First green CI run. |
| **K4.f** | `Makefile.toml` adds the `run-qemu-uefi` task; `kernel-runner/README.md` documents OVMF paths per OS. | Manual smoke on a developer machine. |
| **K4.g** | Update `NCIP-Kernel-003` § 7 "Boot hand-off ABI" cross-reference to point at this NCIP's § S4 (mechanical doc edit). | Lint dogfood + manual diff. |

K4.a → K4.g land as separate commits on `feat/ncip-kernel-005-boot-handoff`. The NCIP transitions to `Active` after K4.e is green for 7 consecutive days (no boot-ABI regressions surface in the CI matrix).

---

## Rationale

**Why `kernel-runner/` as a separate crate, not a `[[bin]]` target inside `nexacore-kernel/`?**

Three reasons:

1. **Feature-flag clarity.** `nexacore-kernel` is a *library*: it exposes traits and types consumed by `nexacore-mesh`, `nexacore-runtime`, etc. Adding a `[[bin]]` target inside it would force a `bin`-only feature flag, and every consumer would need to disable it explicitly. A separate crate isolates the binary-only dependencies (`bootloader`, `bootloader_api`) so they never leak into the dependency closure of the kernel-as-library.
2. **Build-time dependency segregation.** The `bootloader` build-side crate is a host-tooling dependency: it runs on the developer's machine, not on the target. Mixing host and target dependencies in the same crate causes painful cross-compilation issues. Keeping them in `kernel-runner` (which is the only crate built for the target) is the rust-osdev community's standard pattern.
3. **Workspace hygiene.** Excluding `kernel-runner` from the default `cargo build --workspace` matrix keeps the developer-experience baseline (cross-toolchain not required) intact. Developers who want to boot the kernel run `cargo build -p kernel-runner --target x86_64-unknown-none`; everyone else runs `cargo test --workspace --all-features` and gets a full test run without needing a cross-toolchain.

**Why identity-mapped physical memory at v1.0?**

`BootloaderConfig.mappings.physical_memory = Some(Mapping::Dynamic)` is the simplest mapping policy: every physical page is mapped at `virt_addr = phys_addr + physical_memory_offset`. This is the **classic kernel mapping** used by Linux, BSD, seL4, NOVA, and the textbook microkernel literature. It costs one large PML4 entry (or a small range thereof, depending on RAM size) and gives the kernel O(1) `phys → virt` translation.

The alternative — recursive paging — saves a bit of page-table memory but complicates every `phys → virt` computation in the kernel. The cost / benefit favours identity mapping for a v1.0 kernel that has no shipping-product reason to be parsimonious about kernel-mode virtual address space.

**Why 1 MiB initial stack?**

The K3 panic handler reserves a 1 KiB static buffer (`PANIC_RECORD_MAX_BYTES = 1024`) plus framebuffer-write scratch (~16 KiB) plus the deepest plausible call chain during boot (~64 KiB). Doubling to give safety margin gives ~256 KiB. Rounding to a power-of-two and adding margin for K6+ subsystem init (page-table walker recursion, ACPI parser stack) gives 1 MiB. This is the kernel stack at boot; once `scheduling` is up (K8), per-task stacks are sized independently per task class.

**Why 4 MiB minimum heap?**

`NCIP-Kernel-003` § 5 lists the long-lived allocations as: IPC queue ring buffers (≈64 KiB × N channels), task table (≈ N tasks × 1 KiB per slot), capability table (≈ N capabilities × 256 B per entry). For N=256 channels / 1024 tasks / 16k capabilities (the v1.0 "small-server" baseline), the long-lived footprint is ≈ 16 MiB + 1 MiB + 4 MiB = ~21 MiB. 4 MiB is the *minimum* (the bump heap can be the rest of the largest Usable region); it bounds the smallest hardware the kernel can boot on at v1.0. Smaller machines fall back to the panic path with a clear "no usable heap region of ≥ 4 MiB" message.

**Why pin `bootloader` exactly?**

Patch releases of `bootloader` have, in the past, changed the on-disk layout of the loader stub. A `=0.11.X` pin guarantees byte-reproducible images across CI runs and across developer machines. Floating to `^0.11` would let `cargo update` shift the image, which is unacceptable for an artifact that is also the Secure Boot signing input.

**Alternatives considered and rejected:**

- *Custom UEFI loader via `uefi-rs`.* Would give us full control of the loader but reproduces what `bootloader` already provides. Estimated engineering cost: 6–8 weeks for a passable loader, 6 months for one that matches `bootloader`'s feature set. Out of scope for v1.0.
- *Limine.* Mature, well-documented, but a non-Rust dependency. `NCIP-Kernel-003` § 2 explicitly chose `bootloader` over Limine; this NCIP inherits that decision.
- *Multiboot2 + GRUB.* License conflict (`NCIP-Kernel-003` § 2): GRUB's GPL-3 is incompatible with our Apache-2.0 licensing for any patch we would upstream. Same blocker.
- *Direct `_start` in `nexacore-kernel` (skip the runner).* Would couple the kernel to `bootloader_api` in its dependency graph regardless of feature flag, breaking the library-versus-binary separation rationale above.

---

## Backwards Compatibility

`NCIP-Kernel-012` introduced two extern-symbol stubs (`NEXACORE_KERNEL_HEAP_BASE`, `NEXACORE_KERNEL_HEAP_LEN`) as a deliberate placeholder until this NCIP. This NCIP **removes** the stubs (§ S6). The removal is breaking only at the K3 implementation level — no third-party code consumes the stubs, no on-disk artifact depends on them, and no wire-format byte changes.

Because `NCIP-Kernel-012` is still in `Draft` at the time this NCIP is filed, the removal is a coordinated drafting concern, not a backwards-compatibility break in any meaningful sense. The two NCIPs land on adjacent branches and the K3 stubs never survive past the K3 → K4 transition. If K3 transitions to `Active` before K4, the stubs live for the activation phase only and are removed in the K4 PR that lands shortly after.

`nexacore-kernel`'s public Rust API gains one new public symbol: `nexacore_kernel::kmain`. This is additive; no existing consumer's build breaks.

The bare-metal build target `x86_64-unknown-none` is unchanged.

No on-disk format, no wire format, no syscall ABI surface changes in this NCIP. The boot hand-off ABI is itself an ABI, but its consumers are exactly two: the bootloader (third-party crate, pinned) and `kernel-runner` (in-tree). There is no third party to be compatible with.

---

## Test Cases

In addition to the test plan in § S10:

1. **`pick_region` correctness vector test** (`crates/nexacore-kernel/tests/boot_info.rs`):
   - Input: synthetic `MemoryRegions` with regions `[Usable(0..2MiB), Reserved(2MiB..4MiB), Usable(4MiB..20MiB), Usable(20MiB..28MiB)]`.
   - Expected output: `(0x400000, 16 MiB)` — the 4..20 MiB region (largest ≥ 4 MiB; tie-break is moot here).
   - Edge case: only-region-is-3MiB → `panic!` at "no usable heap region of ≥ 4 MiB found".
   - Edge case: two equal-sized regions → lower start address wins.

2. **`kernel_entry` smoke test** (deferred to K5; the QEMU smoke test): a synthetic image boots under `qemu-system-x86_64 -bios OVMF`, prints "[NexaCore OS] kmain entered." on the serial console, and halts. The test passes when the serial output contains both `kmain entered` and `halting (K4 scope ends here)`.

3. **`cargo deny check`** (CI): no new RUSTSEC advisories from `bootloader` or its transitive deps. Specifically, `bootloader` v0.11.x pulls `xmas-elf`, `rsdp`, and `bitflags`; their advisory status is verified at NCIP-Active time.

4. **Image-reproducibility test** (CI, weekly cron): two consecutive CI runs on the same commit produce byte-identical `nexacore-os-uefi.img`. Mismatches block the next merge. (This is a strict-mode reproducibility test enabled by the version pinning in § S9.)

5. **Workspace-build cleanliness**: `cargo build --workspace` on a developer machine *without* the `x86_64-unknown-none` target installed succeeds because the runner is excluded from the default matrix. Verified by a CI job that explicitly does not install the target.

---

## Reference Implementation

Will land on branch `feat/ncip-kernel-005-boot-handoff`. Reference layout:

```
nexacore/
├── kernel-runner/
│   ├── Cargo.toml                # bootloader_api 0.11, bootloader build-dep
│   ├── build.rs                  # UefiBoot::new + BiosBoot::new
│   └── src/
│       ├── main.rs               # entry_point! + kernel_entry()
│       └── early_console.rs      # COM1 + framebuffer writers (used pre-heap-init)
├── crates/nexacore-kernel/src/
│   ├── lib.rs                    # adds `pub fn kmain` (cfg bare-metal+not(test))
│   └── bare_metal/
│       ├── heap.rs               # adds `pick_region`; removes K3 extern stubs
│       └── arch/x86_64.rs        # halt_forever, interrupts::disable (unchanged from K3)
├── Makefile.toml                 # cargo-make: `run-qemu-uefi` target
└── .github/workflows/ci.yml      # `kernel-runner-build` job
```

`NCIP-Kernel-006` and successors will:

- Wire `arch::init()` (GDT/IDT/TSS) before `kmain` calls into subsystem init.
- Wire `memory::init(boot_info)` (frame allocator from `boot_info.memory_regions` minus the heap region selected by `pick_region`).
- Wire ACPI parsing via `boot_info.rsdp_addr`.
- Land the first IDT entries (timer, page-fault, double-fault).

---

## Security Considerations

- **Boot supply chain.** The `bootloader` crate (v0.11.x) is a third-party Rust crate. Compromise of `bootloader` would compromise every NexaCore boot. Mitigations: (a) exact-version pin per § S9; (b) `cargo deny check` audit gate in CI; (c) `cargo vet` (deferred to a future NCIP) on the `bootloader`, `bootloader_api`, and transitive `xmas-elf` / `rsdp` crates; (d) the Secure Boot signing step (`NCIP-Kernel-003` § Security) signs the *final image*, so a malicious `bootloader` could only attack a build before the signing step — i.e., it would need to compromise CI, not just upstream.
- **Image-reproducibility as a defence.** The byte-identical image test (§ Test Cases ¶4) detects supply-chain tampering: an attacker who silently replaces `bootloader`'s loader stub would change the image hash, which CI flags within one day.
- **`BootInfo` provenance.** The `BootInfo` struct comes from the bootloader, which itself runs in UEFI's pre-OS environment. If the bootloader is honest, `BootInfo` accurately reflects the firmware's hand-off. If the bootloader is compromised (see prior point), `BootInfo` is attacker-controlled and every kernel invariant downstream is suspect. The kernel does NOT defend against a compromised loader; that defence belongs to Secure Boot + measured boot (TPM PCR extension), which `NCIP-Kernel-003` § Security Considerations covers.
- **`pick_region` integer overflow.** The largest-region computation must not overflow when computing `start + length`. The reference impl uses `u64` math throughout and bounds-checks against `usize::MAX` before casting. Verified by a property-test in § Test Cases ¶1.
- **Stack overflow in `kernel_entry`.** The 1 MiB initial stack is sized for K3 panic-path + K6+ subsystem init (see Rationale). A stack overflow in `kmain` is detected by the bootloader's optional stack-guard page (enabled by `BootloaderConfig::new_default()` — the loader places an unmapped page below the kernel stack). A stack overflow page-faults rather than silently corrupting adjacent memory.
- **Identity-mapped physical memory is a security trade-off.** The full identity map gives the kernel ambient access to every byte of RAM. This is the **kernel** — every byte of RAM is *already* in the kernel's trust boundary, so the map does not create a new vulnerability; but it does mean a kernel-mode bug has wide access. Mitigation: kernel code is reviewed under the `unsafe`-minimization policy (`NCIP-Kernel-003` § 5 rationale).
- **No early-boot capability checks.** The kernel runs without capability checks until the capability table is initialised (K10). Code that runs in `kernel_entry` and `kmain` (K4 scope) executes with full kernel authority. The K4 scope is *intentionally tiny* — print banner, init heap, halt — to keep the unchecked window minimal. Every additional subsystem activated before the capability table is in place is a deliberate decision, recorded in the relevant NCIP.

---

## Privacy Considerations

This NCIP defines the kernel's *entry path*; no user data flows through the K4 scope.

- **No user data on the boot path.** `kernel_entry` and `kmain` process the bootloader's `BootInfo` (memory map, framebuffer descriptor, RSDP pointer) — all of which is **infrastructural**, not user data. There is no user logged in at boot; there are no capabilities held by any process; there are no IPC messages in flight. The boot-time privacy surface is identical to `NCIP-Kernel-003`'s narrow contract: the kernel reads what the firmware exposed and never persists it off-device.
- **Boot-time identifiers from the bootloader.** `BootInfo` carries memory layout but **no platform serial numbers, no MAC addresses, no SMBIOS strings.** The `bootloader` crate is deliberately minimal on this point (it does not parse SMBIOS at all), which aligns with the project's privacy-first stance. Any subsystem that later needs a platform identity derives it from TEE attestation, not from firmware metadata, as established by `NCIP-Kernel-003` § Privacy ¶1.
- **Early-console output.** `kmain` prints the kernel version, memory-region count, and a "halting" banner to the serial console and (if available) framebuffer. These are kernel-internal infrastructural values, identical in shape to the K3 panic path: never user-derived, never network-egressed, never persisted by the kernel.
- **`physical_memory_offset` is not a privacy concern.** The offset is a virtual-address-space layout choice; it does not leak any information about user data because at the time it is read, there is no user data on the system.
- **The boot artifact (`nexacore-os-uefi.img`) is identical across all installations of the same release.** Two devices booting the same `nexacore-os-uefi.img` produce identical boot transcripts up to the timestamp and the firmware's memory map. The variability is firmware-side, not NexaCore-side; NexaCore itself is fingerprint-equivalent across devices.
- **Future privacy surface for diagnostics.** Once K6+ activate subsystems that *do* touch user data (mesh, capability tokens, sealed keys), the privacy surface expands. Those expansions are governed by their own NCIPs. K4 establishes the **null baseline**: zero user data flows through the boot ABI.

---

## Copyright

This NCIP is licensed under [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/).
