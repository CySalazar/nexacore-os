# ADR-0053: BLAKE3 `pure` for the bare-metal image — build-host portability

**Status:** Accepted
**Date:** 2026-06-28
**Deciders:** agent analysis under operator-approved the development plan WS13-08
**Refs:** the development plan WS13-08 (build-host portability), ADR MB13.a (force-soft
SIMD policy for sha2/poly1305/curve25519 on `x86_64-unknown-none`),
`kernel-runner/Cargo.toml`, `docs/11-tooling-and-ci.md`

## Context

The bootable artifact `kernel-runner` cross-compiles the kernel to
`x86_64-unknown-none`. On an **x86_64 Linux** build host this links and produces
the ISO. On a **non-x86 build host (Apple Silicon / aarch64)** the final link
fails:

```
rust-lld: error: undefined symbol: blake3_compress_in_place_sse41
rust-lld: error: undefined symbol: blake3_compress_in_place_avx512
rust-lld: error: undefined symbol: blake3_compress_in_place_sse2
rust-lld: error: undefined symbol: blake3_hash_many_avx512
rust-lld: error: undefined symbol: blake3_hash_many_sse41
rust-lld: error: undefined symbol: blake3_hash_many_avx2
rust-lld: error: undefined symbol: blake3_hash_many_sse2
```

`nexacore-kernel` (built with `bare-metal`) pulls `blake3` transitively via
`nexacore-crypto`. By default `blake3` selects an x86 SIMD backend on
`x86_64-*` targets and references the corresponding hand-written assembly
symbols. When the build host is aarch64, the cross-toolchain's assembler does
**not** emit those x86 SIMD symbols, so the kernel object references them but
nothing defines them → `undefined symbol` at link.

Crucially, the rest of the bare-metal build now **compiles cleanly**: the LLVM
SIMD ICE that previously blocked `sha2`/`poly1305`/`curve25519-dalek` on
`x86_64-unknown-none` was already neutralised by the force-soft policy (ADR
MB13.a). BLAKE3 was the single remaining blocker — and it is a *link* failure,
not a *compile* failure, so the fix is a backend selection, not a code change.

## Decision

Enable BLAKE3's **`pure`** feature for the `kernel-runner` build graph by
declaring `blake3` as a direct dependency of `kernel-runner` with
`features = ["pure"]`:

```toml
blake3 = { version = "1.5", default-features = false, features = ["pure"] }
```

`pure` disables every assembly/C backend and uses the portable Rust
implementation, which emits **no** target-specific SIMD symbols. Cargo feature
unification applies `pure` onto the transitive `blake3` that `nexacore-kernel`
pulls, so the kernel object stops referencing the x86 SIMD symbols and the image
links on any build host.

This mirrors the existing force-soft posture (ADR MB13.a): on the bare-metal
target we already prefer portable software implementations of the crypto
primitives over SIMD, trading a little throughput for a buildable, ICE-free
image.

### Why per-crate, not workspace-wide

`pure` is scoped to `kernel-runner` rather than the root
`[workspace.dependencies]` blake3 on purpose:

- `kernel-runner` is the **only** artifact that builds for
  `x86_64-unknown-none` *and* pulls blake3 — the userspace image crates
  (`*-image`) link fine because their dependency subset excludes blake3.
- `kernel-runner` is **always** the bare-metal target (it is `no_main` /
  `no_std`; it has no host build), so `pure` here is naturally *per-target* — it
  never touches a host build.
- `kernel-runner` is in the root `[workspace.exclude]` list, so the workspace's
  host/dev/CI builds (`cargo test`, native compiles) keep the **fast SIMD**
  blake3. Verified: `cargo tree -p nexacore-crypto -e features -i blake3` in the
  workspace shows blake3 with only `default`/`rng` features — no `pure`.

A `.cargo/config.toml`-level or `cfg(target)`-level gate is unnecessary because
the per-crate scoping already achieves the "x86_64-unknown-none only" effect.

### Correctness

`pure` is **bit-identical** to the SIMD backends — same BLAKE3 algorithm, only a
slower implementation. Model measurements, capability hashes, and every other
BLAKE3 digest are unchanged. The only cost is throughput on a boot-time hash,
which is negligible.

## Consequences

- **Positive:** `cargo build --target x86_64-unknown-none --release` for
  `kernel-runner` now links on Apple Silicon (verified: a 2 MB
  `kernel-runner` ELF is produced). Developers on aarch64 hosts can build the
  bare-metal image and ISO without a cross x86 toolchain or an x86 build box.
- **Positive:** the kernel bare-metal gate is no longer host-blocked by BLAKE3
  on aarch64 (the previously-feared LLVM SIMD ICE is already handled by MB13.a).
- **Neutral:** the x86_64-Linux ISO build also uses `pure` (it builds the same
  `kernel-runner` manifest) — a negligible slowdown for a boot-time hash, output
  identical.
- **Negative (bounded):** an `unused` direct `blake3` dependency appears in
  `kernel-runner`'s manifest purely to inject the feature. This is a standard
  Cargo feature-injection pattern and carries no runtime cost (the crate is
  already in the graph transitively).

## Alternatives considered

- **Workspace-wide `pure`:** simplest, but penalises every host/dev/CI build
  (native aarch64 and x86_64 Linux) with portable blake3 for no benefit — the
  bare-metal target is the only one that needs it. Rejected.
- **Build on an x86_64 host / container only:** a process workaround, not a fix;
  keeps aarch64 developers blocked. Documented as a fallback in
  `docs/11-tooling-and-ci.md` but not the primary answer.
- **`no_sse2`/`no_avx2`/… opt-outs:** these disable *specific* SIMD tiers but
  still leave at least one asm backend referenced; only `pure` removes them all.
  Rejected.
