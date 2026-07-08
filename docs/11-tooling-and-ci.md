# 11 — Tooling and CI

> **Status:** Draft v0.1 — 2026-05-09
> **Scope:** the toolchain, formatting / linting / supply-chain configuration,
> and the CI/CD pipeline that enforce NexaCore OS's build hygiene.
>
> This document is the human-readable counterpart to the configuration files
> committed at the repository root and under `.github/`. It explains the
> *why* — the configuration files are the *how*.

---

## 11.1 Toolchain

NexaCore OS pins its Rust toolchain to a specific channel via
[`rust-toolchain.toml`](../rust-toolchain.toml). All contributors and CI use
the same channel, removing the "works on my machine" failure mode.

| Item             | Value                          | Source of truth                  |
|------------------|--------------------------------|----------------------------------|
| Rust channel     | stable (latest minor pinned)   | `rust-toolchain.toml`            |
| Rust edition     | 2024                           | `[workspace.package].edition`    |
| MSRV             | 1.85                           | `[workspace.package].rust-version` and `clippy.toml` |
| Cargo resolver   | 3                              | `[workspace].resolver`           |
| Initial target   | `x86_64-unknown-linux-gnu`     | `/docs/07-hardware-requirements.md` |

When the MSRV bumps it must be coordinated across `rust-toolchain.toml`,
`Cargo.toml`, and `clippy.toml`. CI does not enforce this consistency
directly today — adding that lint is on the future-work list.

### 11.1.1 Supported build hosts

The workspace (`cargo build`/`test`) builds on any host the pinned Rust
toolchain supports — Linux x86_64/aarch64 and macOS x86_64/aarch64 are all
exercised by contributors.

The **bare-metal image** (`kernel-runner` → `x86_64-unknown-none`, the
artifact `scripts/build-iso.sh` turns into a bootable ISO) is the one place
where the *build host architecture* matters, because it cross-compiles to an
x86 freestanding target:

| Build host | Bare-metal image / ISO | Notes |
|------------|------------------------|-------|
| Linux x86_64 | ✅ supported | the canonical CI build host |
| macOS / Linux aarch64 (Apple Silicon) | ✅ supported | requires the BLAKE3 `pure` fix below |

Historically the cross-link failed on a non-x86 host (e.g. Apple Silicon)
with `rust-lld: undefined symbol: blake3_compress_in_place_sse41` (and the
other `blake3_*` x86 SIMD symbols): `nexacore-kernel` pulls `blake3`
transitively, and without the `pure` feature blake3 references hand-written
x86 assembly the aarch64 cross-assembler does not emit. This is fixed by
enabling BLAKE3's `pure` (portable, bit-identical) backend **scoped to
`kernel-runner`** — the only bare-metal artifact that pulls blake3 — so the
workspace's host/dev/CI builds keep the fast SIMD backend. See
[ADR-0053](adr/0053-blake3-pure-bare-metal-build-host-portability.md) and the
force-soft SIMD precedent (ADR MB13.a).

Tooling required to produce the ISO: `xorriso` (hybrid ISO wrapping) and the
pinned nightly the `disk-image` bootloader build uses (installed on demand
from `disk-image/rust-toolchain.toml`). `faketime`/`libfaketime` is optional
(reproducible FAT timestamps); a release signing key is optional for
development builds.

### 11.1.2 Reproducible builds (WS13-06)

The release ISO is built to be **byte-identical** across machines and checkout
locations. Three things make that hold:

1. **Pinned toolchain** ([`rust-toolchain.toml`](../rust-toolchain.toml),
   WS13-06.9) — every build uses the exact same compiler.
2. **Pinned timestamps** — `scripts/build-iso.sh` exports `SOURCE_DATE_EPOCH`
   (the commit time, or a fixed fallback) and normalizes the FAT mtimes, so no
   build-time clock leaks into the image.
3. **Path remapping** (WS13-06.8) — `build-iso.sh` exports
   `RUSTFLAGS=--remap-path-prefix=…` mapping the machine-specific absolute
   paths (the repo root → `/nexacore`, the cargo home → `/cargo`, the toolchain
   sysroot → `/rust`) to fixed virtual prefixes, so the absolute checkout path
   never lands in the kernel ELF / ISO. (cargo's native `trim-paths` profile
   option is still unstable on the pinned **stable** toolchain, so the
   equivalent `--remap-path-prefix` flags are applied explicitly in the build
   script, where the absolute paths are known.)

Verify reproducibility with [`scripts/repro-iso-test.sh`](../scripts/repro-iso-test.sh)
(WS13-06.11): it builds the ISO twice from the same tree and asserts the two
images are identical (citing the first differing byte if not).

### 11.1.3 Cross-architecture status (WS13-06)

NexaCore today targets **x86_64** only (`x86_64-unknown-none`). AArch64 /
Apple-Silicon is a roadmap v1.1/v2 target. `aarch64-unknown-none` is a built-in
`rustc` target (no custom target-spec JSON needed); the work to make the kernel
boot there is the *arch abstraction*, tracked as WS13-06.2–.5:

The architecture-specific kernel code is concentrated under
[`crates/nexacore-kernel/src/bare_metal/`](../crates/nexacore-kernel/src/bare_metal/) —
`gdt`, `idt`, `tss`, `paging`, `per_cpu`, `lapic`, `ipi`, `mp*`, `syscall_entry`,
`tlb_shootdown`, `uaccess`, `cpuinfo`, `address_space` — with a started
`bare_metal/arch/` submodule (`arch/mod.rs` + `arch/x86_64.rs`). The AArch64 port
adds `arch/aarch64.rs` mirroring that surface (CPU init, the interrupt
controller, the MMU/paging), selected by a compile-time `cfg(target_arch)` gate;
the boot bring-up itself is tracked separately. Until that lands, a cross-compile
of the bare-metal image for `aarch64-unknown-none` is expected to fail on the
x86-specific modules — by design, not by regression.

## 11.2 Formatting policy — `rustfmt.toml`

Configuration lives in [`rustfmt.toml`](../rustfmt.toml). Highlights:

- `max_width = 100` — modern displays, reasonable diff hygiene.
- `imports_granularity = "Crate"` — collapsed `use crate::{a, b, c};`.
- `group_imports = "StdExternalCrate"` — std → external → internal.
- `use_field_init_shorthand = true` — `Foo { x }` over `Foo { x: x }`.

CI runs `cargo fmt --all -- --check` and fails on any drift. Contributors
who use a pre-commit hook (recommended in `CONTRIBUTING.md` § 7.4) catch
drift before push.

## 11.3 Linting policy — `clippy.toml` + workspace lints

Two layers of lints are in force:

1. **Lint groups** in `Cargo.toml` (`[workspace.lints.rust]` and
   `[workspace.lints.clippy]`) — enforced workspace-wide via
   `lints.workspace = true`.

2. **Option-level configuration** in [`clippy.toml`](../clippy.toml).
   This file holds:
   - `msrv = "1.85"` (gates lints suggesting features unavailable on MSRV).
   - `cognitive-complexity-threshold = 20` (tighter than default 25).
   - `disallowed-methods` — blocks `std::env::var`, `std::process::exit`,
     `std::time::SystemTime::now`, std `Mutex/RwLock`, with reasons.
   - `disallowed-macros` — blocks `println!`, `eprintln!`, `dbg!` in favor
     of the `tracing` crate.
   - `doc-valid-idents` — recognized acronyms (TEE, AGPL, AEAD, BLAKE3, ...).

Each disallowed entry includes a `reason = "..."` so PR reviewers don't
need to re-derive the rationale.

CI runs `cargo clippy --workspace --all-targets -- -D warnings` and fails
on any warning.

## 11.4 Supply-chain policy — `deny.toml`

Configuration: [`deny.toml`](../deny.toml). Run with:

```bash
cargo deny check                   # all four sections
cargo deny check advisories        # RustSec advisories only
cargo deny check licenses          # license allowlist enforcement
cargo deny check bans              # banned crates / wildcards
cargo deny check sources           # registry / git allowlist
```

### 11.4.1 Advisories

- Vulnerabilities → `deny`.
- Yanked crates → `deny`.
- Unmaintained → `warn` (surfaces tech debt without blocking).

Advisory ignores require a tracking issue and a sunset date.

### 11.4.2 Licenses

The inbound license allowlist is fixed and explicit:

```
Apache-2.0, Apache-2.0 WITH LLVM-exception,
MIT, BSD-2-Clause, BSD-3-Clause, BSL-1.0, ISC,
Unicode-DFS-2016, Unicode-3.0, Zlib, CC0-1.0, MPL-2.0
```

Anything outside this list is rejected. Adding to the list requires:
- Founder approval during the 5-year veto window, or
- Stichting NexaCore board approval afterward.

### 11.4.3 Bans (refused crates)

| Banned crate     | Reason                                                                                       |
|------------------|----------------------------------------------------------------------------------------------|
| `openssl-sys`    | Force `rustls + ring`. OpenSSL has a poor supply-chain track record and adds a C-toolchain attack surface incompatible with the NexaCore OS threat model. |
| `openssl`        | Same as above.                                                                                |
| `native-tls`     | Pulls platform-specific TLS stacks. We use `rustls` everywhere for deterministic, audited behavior. |
| `md5`, `sha1`    | Cryptographically weak. Exception path exists for non-security checksums via PR review.       |
| `rand`           | Use `rand_core` + an explicit auditable RNG (`OsRng`, `ChaCha20Rng`).                         |
| `time`           | Historic CVE lineage and ergonomic footguns. Use `chrono` with vetted features, or `jiff`.   |

### 11.4.4 Sources

- `unknown-registry = "deny"` — only `crates.io`.
- `unknown-git = "deny"` — git deps require explicit allowlist with pinned
  full SHA and a sunset date for migration to the registered version.

## 11.5 CI/CD pipeline

The pipeline lives under [`.github/workflows/`](../.github/workflows/).
Branch protection on `main` requires every workflow listed below to be
green before a PR can merge.

| Workflow              | Trigger(s)                         | Purpose                                                                  |
|-----------------------|------------------------------------|--------------------------------------------------------------------------|
| `ci.yml`              | push, PR                           | `cargo fmt`, `cargo clippy`, `cargo test`, `cargo doc`.                  |
| `deny.yml`            | push, PR                           | `cargo deny check` (advisories, licenses, bans, sources).               |
| `dco.yml`             | PR (opened, synchronize, reopened) | Every commit must carry a `Signed-off-by:` trailer.                     |
| `doc.yml`             | push, PR                           | Builds the API documentation.                                           |
| `fuzz.yml`            | PR touching fuzzed crates          | Short fuzz smoke run for `nexacore-types` / `nexacore-fs` / `nexacore-net`. |
| `perf-gate.yml`       | PR                                 | Performance-regression gate against committed baselines.                |
| `qemu-boot-smoke.yml` | push, PR                           | Boots the bare-metal image in QEMU and asserts the expected boot log.   |
| `release.yml`         | tag push (`v*.*.*`)                | Builds and signs the release ISO and publishes the GitHub release.      |

> **Roadmap (not yet wired):** a CycloneDX SBOM + SLSA build-provenance job, a
> dedicated reproducible-build verification workflow, and CodeQL static
> analysis are planned but are not part of the current pipeline.

### 11.5.1 Status check naming

The required status checks configured in the GitHub branch-protection settings
are these job names:

- `ci / cargo fmt`
- `ci / cargo clippy`
- `ci / cargo test (ubuntu-24.04)`
- `ci / cargo doc`
- `deny / cargo deny check`
- `dco / DCO sign-off`

If a workflow's `name:` field is renamed, update the branch-protection required
checks in the same PR.

### 11.5.2 Performance budget

The CI workflow targets **< 10 minutes wall-clock** for a typical PR
(per the backlog P0.4 acceptance criterion). Caching via
`Swatinem/rust-cache@v2` is enabled on `clippy`, `test`, and `doc` jobs.
When budget is exceeded, the first lever is reducing the matrix or
splitting into a separate `nightly-deep-checks.yml` workflow.

### 11.5.3 SLSA / SBOM (roadmap)

A future `sbom.yml` workflow targets **SLSA Level 3** maturity. The planned
shape:

- Build runs on a hosted, ephemeral runner.
- Provenance generated via `actions/attest-build-provenance` (cosign + GitHub
  OIDC).
- SBOM as CycloneDX JSON, attached to the GitHub release.
- Reproducible-build verification runs in parallel — divergent hashes fail the
  release. (`scripts/repro-iso-test.sh` already provides the local equivalent.)

## 11.6 Branch protection and signed commits

Configured in the GitHub repository settings once the repo is on GitHub.
Highlights:

- `main` is the default branch.
- Force-pushes disabled; deletion disabled.
- Linear history required (squash-and-merge only).
- Required PR reviews: **1** until a co-maintainer joins (Phase 1
  hiring), then **2**.
- `dismiss_stale_reviews = true`; `require_last_push_approval = true`.
- **Signed commits required** (SSH or GPG; SSH signing is recommended
  for ergonomics — see `git config gpg.format ssh`).
- All status checks listed in 11.5.1 must be green.

Tag protection: only signed tags matching `v*.*.*` are accepted, and
they must originate from `main`.

## 11.7 Dependabot

Configuration: [`.github/dependabot.yml`](../.github/dependabot.yml).

- **Cargo:** weekly Monday 06:00 Europe/Amsterdam.
  - Security updates grouped.
  - Patch updates auto-approve after CI green.
  - Minor / major updates require human review.
  - **Major bumps for cryptographic and networking crates are explicitly
    ignored** — these come through Dependabot security advisories
    instead, and we triage manually.
- **GitHub Actions:** weekly Monday, minor + patch grouped.

## 11.8 GitHub templates and label taxonomy

Issue / PR templates are under `.github/`:

- [`ISSUE_TEMPLATE/config.yml`](../.github/ISSUE_TEMPLATE/config.yml) —
  blank issues disabled; redirects for security and CoC.
- [`ISSUE_TEMPLATE/bug_report.yml`](../.github/ISSUE_TEMPLATE/bug_report.yml)
- [`ISSUE_TEMPLATE/feature_request.yml`](../.github/ISSUE_TEMPLATE/feature_request.yml)
- [`ISSUE_TEMPLATE/security_advisory.yml`](../.github/ISSUE_TEMPLATE/security_advisory.yml)
  — *redirects* to `SECURITY.md`; not for new vulnerabilities.
- [`ISSUE_TEMPLATE/oip_proposal.yml`](../.github/ISSUE_TEMPLATE/oip_proposal.yml)
- [`PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md)

The label taxonomy configured in the GitHub repository settings:

- `area:kernel | crypto | capability | tee | hal | runtime | mesh | tokenization | sdk | agent | shell | types | docs | ci | ncip`
- `priority:P0 | P1 | P2 | P3`
- `kind:bug | feature | refactor | docs | security | chore`
- Special: `ncip-required`, `breaking-change`, `good-first-issue`, `help-wanted`, `needs-triage`, `dependencies`, `do-not-use`.

## 11.9 Local development quick reference

```bash
# Format and lint
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Test
cargo test --workspace --all-features

# Documentation
cargo doc --workspace --no-deps

# Supply chain
cargo deny check                                # all four sections
cargo audit                                     # RustSec advisories
cargo install --locked cargo-audit cargo-deny   # one-time installs
```

A pre-commit hook template is provided in `CONTRIBUTING.md` § 7.4.

## 11.10 Cross-references

- [`/CONTRIBUTING.md`](../CONTRIBUTING.md) — the contribution flow.
- [`/SECURITY.md`](../SECURITY.md) — disclosure policy.
- [`/docs/04-security-model.md`](./04-security-model.md) § Supply-chain.
- [`/docs/06-roadmap.md`](./06-roadmap.md) — phase-by-phase scope.
- [`/docs/09-tech-specifications.md`](./09-tech-specifications.md) — exact dependency versions.

## 11.11 Maintenance policy

This document is updated **in the same PR** as any change to:

- `rustfmt.toml`, `clippy.toml`, `deny.toml`, `Cargo.toml` `[workspace.lints]`.
- Any file under `.github/`.

Changelog tracking lives at the bottom of each configuration file. This
document carries a brief change history below.

## Change history

- 2026-05-09 — Initial draft. Created during P0 closure (the backlog P0).
