---
ncip: 17
title: Kernel driver-capability issuer key custody and rotation
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-22
updated: 2026-05-22
requires:
  - 1
  - 13
  - 16
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions
license: CC0-1.0
---

## Abstract

This NCIP specifies the **production custody model** for the
kernel-side Ed25519 signing key that mints
`nexacore-capability::CapabilityToken`s deposited at `DriverLoad`
(`NCIP-Driver-Framework-013` § S5.3 step 8). The current
implementation pins a fixed compile-time seed
(`DRIVER_CAP_ISSUER_SEED` at
[`crates/nexacore-kernel/src/driver_cap_issuer.rs:56`](../crates/nexacore-kernel/src/driver_cap_issuer.rs))
that is **DEV ONLY** and trivially recoverable from the binary —
every released kernel image embeds the same `0xCAFEBABE`-patterned
constant. This NCIP replaces that scaffold with a TEE-derived,
boot-time-derived, rotatable signing key bound to the kernel
measurement, with explicit policy on bootstrap, rotation, and the
Phase-1 transitional state where `nexacore-tee` real backends do not
yet exist.

The NCIP is **Draft** at filing. The implementation NCIP follow-up
(rename TBD; tracked as TASK-008-followup in the planning doc)
will land after `Draft → Review → Last Call → Active` ratification
of this policy.

---

## Motivation

### M1. The current `DRIVER_CAP_ISSUER_SEED` is recoverable

The kernel signing seed lives at
[`crates/nexacore-kernel/src/driver_cap_issuer.rs:56`](../crates/nexacore-kernel/src/driver_cap_issuer.rs):

```rust
pub const DRIVER_CAP_ISSUER_SEED: [u8; 32] = [
    0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
    0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
    0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
    0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
];
```

Anyone with a copy of the kernel binary (the same `kernel-runner`
ELF we ship on every Proxmox smoke deploy) can:

1. Read the seed via `objdump --section=.rodata`.
2. Construct the matching `NexaCoreSigningKey` via
   `NexaCoreSigningKey::from_bytes(seed)`.
3. Mint a `CapabilityToken` for any `(Action × Resource ×
   TimeWindow × Caveat)` shape they choose.
4. Submit the forged token to `MmioMap (70)` / `DmaMap (71)` /
   `IrqAttach (72)` and have the kernel's
   `Ed25519CapabilityProvider` validate it successfully — because
   the deposit-side and verify-side share the same compile-time
   key.

The source-level comment on the constant
([`crates/nexacore-kernel/src/driver_cap_issuer.rs:51`](../crates/nexacore-kernel/src/driver_cap_issuer.rs))
explicitly flags this as "**DEV ONLY**. The value is a fixed
pattern that is intentionally not random — it is designed to be
obviously a placeholder when inspected." The placeholder works
for Phase 1 development (no end-user drivers yet, no shipped
binary), but **must be closed before any non-developer driver
lands** — `NCIP-013` § S5.4 mandates that the deposit key be
"derived from the TEE sealing key on every boot, never persisted
to disk in cleartext, and rotated every 90 days at the latest."

### M2. The placeholder shape is a poor isomorphism for the real key

The placeholder is a *deterministic* compile-time constant.
The production key MUST be:

- **Bound to the kernel measurement.** A modified kernel image
  MUST derive a different signing key, so a measurement-violating
  attacker cannot reuse a previously-derived key on a tampered
  kernel.
- **Boot-time-derived.** No persistence to disk in cleartext
  (a stolen disk MUST NOT yield the key).
- **Per-CPU-platform.** Different TEE families (Intel TDX, AMD
  SEV-SNP, ARM CCA) use different derivation primitives;
  NCIP-013 § S5.4 mandates the kernel MUST work across the three.
- **Rotatable.** A leaked or suspected-leaked key MUST be
  invalidatable within a bounded window without rebooting (in
  steady-state) or with one rebuilt-and-redeployed kernel image
  (transitional).

A compile-time constant satisfies none of these properties.

### M3. Phase 1 has no real `nexacore-tee` backend

`nexacore-tee` (`NCIP-016`) is the TEE HAL. The real backends —
`TdxBackend` (Intel TDX) and `SevSnpBackend` (AMD SEV-SNP) —
are scaffolded but not implemented; only `MockTeeBackend` runs
today. This NCIP MUST therefore specify both:

1. **Steady-state production policy** (post-`NCIP-016` real
   backends): TEE-derived signing key, no compile-time seed.
2. **Phase-1 transitional policy**: how to bridge from
   today's `DRIVER_CAP_ISSUER_SEED` to the steady-state model
   without leaving an exploitable window.

---

## Specification

### S1. Two distinct trust roots (re-stated from NCIP-013 for clarity)

`NCIP-013` § S4 already separates two Ed25519 signing roles. This
NCIP applies ONLY to role (2):

| # | Role | Purpose | Custody owner | NCIP |
|---|---|---|---|---|
| 1 | **Driver issuer** | Signs `NexaCore-Pack v1` manifests at build time | Driver author / Stichting NexaCore (after P4.1) | NCIP-013 § S5.4, NCIP-017 (this) is OUT OF SCOPE for role 1 |
| 2 | **Kernel capability issuer** | Signs `CapabilityToken`s deposited in driver address spaces at `DriverLoad` time | The running kernel itself, bound to its TEE measurement | NCIP-013 § S4, NCIP-017 (this) |

A compromise of (1) lets the attacker ship malicious driver
images that the kernel will load. A compromise of (2) lets the
attacker mint deposit tokens that bypass the
`Ed25519CapabilityProvider` check at MMIO/DMA/IRQ syscall time.
The two compromises have different blast radii — (2) is broader
because it skips the per-driver issuer allowlist (`KNOWN_ISSUERS`,
NCIP-013 § S5.4) — so this NCIP exists to close it specifically.

### S2. Steady-state custody model (post-NCIP-016 real backends)

**Source of the key — Intel TDX** (`TdxBackend`):

```text
kernel_cap_issuer_seed_v1 := HKDF-SHA-256(
    ikm  = TDREPORT.measurement || TDREPORT.te_tcb_svn || "NexaCore-PROTO-v0.2",
    salt = b"NexaCore-KEYCUSTODY-017-tdx-cap-issuer",
    info = b"kernel_cap_issuer_seed_v1",
    length = 32 bytes,
)
```

- `TDREPORT.measurement` is the 48-byte TD measurement; a
  modified kernel binary changes this value (different boot
  hash), so the derived key is **measurement-bound** by
  construction.
- `TDREPORT.te_tcb_svn` is the TD TCB Security Version; included
  to make the derivation TCB-aware (TCB rollback invalidates the
  derived key, preventing replay across firmware downgrades).
- The `"NexaCore-PROTO-v0.2"` suffix binds the derivation to the
  current protocol version per `nexacore_types::version::PROTOCOL_VERSION_V0_2`.
- The HKDF salt is a constant domain separator — no per-boot
  randomness needed because the inputs already encode the boot.

**Source of the key — AMD SEV-SNP** (`SevSnpBackend`):

```text
kernel_cap_issuer_seed_v1 := SNP_DERIVE_KEY(
    root_key_select  = VCEK,
    vmpl             = 0,
    guest_field_select = GUEST_POLICY | TCB_VERSION | MEASUREMENT,
    guest_svn        = current TCB SVN,
    tcb_version      = current TCB version,
)  ||  HKDF-SHA-256(
    ikm  = SNP_DERIVE_KEY_output || "NexaCore-PROTO-v0.2",
    salt = b"NexaCore-KEYCUSTODY-017-sev-snp-cap-issuer",
    info = b"kernel_cap_issuer_seed_v1",
    length = 32 bytes,
)
```

- `SNP_DERIVE_KEY` (AMD64 Architecture Programmer's Manual
  Volume 2 § 15.36.4) is the canonical SNP key derivation
  primitive. We bind `GUEST_POLICY | TCB_VERSION | MEASUREMENT`
  so changes to any of those invalidate the derived key.
- VCEK (Versioned Chip Endorsement Key) is the per-chip /
  per-TCB root; using it ties the key to the specific CPU.
- The HKDF post-processing standardises the output shape to
  exactly 32 bytes regardless of `SNP_DERIVE_KEY`'s native size
  (the AMD primitive outputs 32 bytes today, but the
  post-processing future-proofs against ABI changes).

**Source of the key — ARM CCA** (deferred to a follow-up NCIP):

Phase 2+. ARM CCA's `RMI` interface exposes `RMI_REC_AUX_KEY`
which is analogous to TDX `TDREPORT` for derivation purposes.
The schema MUST be added by an amendment to this NCIP when ARM
CCA support lands; until then the platform-detect logic at
boot rejects ARM CCA hardware with a clear error rather than
falling through to the dev seed.

**Source of the key — dev / test fallback**:

When the kernel runs with feature `dev-key-custody` (compile-time,
NOT a runtime switch) and on hardware that does NOT expose a
supported TEE (or under `MockTeeBackend`), the kernel uses a
deterministic dev seed derived from a non-secret constant:

```text
kernel_cap_issuer_seed_dev := HKDF-SHA-256(
    ikm  = b"NexaCore-DEV-CAP-ISSUER-v1-not-a-secret",
    salt = b"NexaCore-KEYCUSTODY-017-dev-fallback",
    info = b"kernel_cap_issuer_seed_v1",
    length = 32 bytes,
)
```

This dev seed is NOT secret. The build that enables it MUST set
`CFG_RELEASE_DEV_BUILD = 1` so the boot banner displays the
warning `"⚠ DEV KEY CUSTODY ACTIVE — not for production"` in
the Build Info panel during the entire boot session.

`MockTeeBackend` always selects the dev fallback regardless of
the feature flag, because mock attestation is dev-only by
construction.

### S3. Bootstrap procedure

**First boot** (no persistent state needed):

1. The bootloader hands off to `kernel_entry` with the standard
   `bootloader 0.11` `BootInfo` shape.
2. After paging + IDT + LAPIC are up (per NCIP-Kernel-005 K1-K3),
   the kernel calls `nexacore_tee::detect_family()` to learn which
   TEE family (if any) is hosting it.
3. Based on the result:
   - `TeeFamily::Tdx` → call `nexacore_tee::tdx::derive_app_key(...)`
     with the inputs from S2 TDX, get the 32-byte seed.
   - `TeeFamily::SevSnp` → call
     `nexacore_tee::sev_snp::derive_app_key(...)`, same shape.
   - `TeeFamily::None` AND `dev-key-custody` feature set → use
     the dev fallback (S2).
   - `TeeFamily::None` AND `dev-key-custody` NOT set → **PANIC
     with banner** `"NexaCore OS PANIC: no TEE detected and dev-key-custody disabled — refusing to boot"`.
4. The seed bytes are loaded into a new module-level
   `OnceLock<NexaCoreSigningKey>` in `driver_cap_issuer`.
   `NexaCoreSigningKey` itself zeroizes on drop; the lock is
   intentionally NEVER dropped during a boot session, so the
   key material lives for the kernel's full uptime in one
   protected location.
5. The 32-byte raw seed value is zeroized immediately after the
   lock is initialised.
6. The kernel logs to serial (NOT to a persistent log):
   `[keycustody] cap-issuer seed initialised from TDX (or SEV-SNP,
   or DEV) at boot+<elapsed_us>us`.

**Subsequent boots**:

The same procedure runs every boot. There is NO persistence of
the key material across boots; the derivation is fully
deterministic from the TEE inputs, so the same kernel measurement
on the same hardware produces the same key every boot.

This makes key rotation a free side effect of changing any
derivation input — kernel measurement (a kernel-binary rebuild
that changes any byte), TCB version (firmware update), VMPL
(SEV-SNP), or the protocol-version suffix (a coordinated
`NexaCore-PROTO-v0.3` cutover).

### S4. Rotation policy

| Rotation trigger | Cadence | Mechanism | NCIP-amend required? |
|---|---|---|---|
| **Routine** | Every 90 calendar days at the latest | Kernel rebuild bumping the salt (e.g. `b"NexaCore-KEYCUSTODY-017-tdx-cap-issuer-2026Q4"`) | No (constant salt rotation per quarter) |
| **Suspected compromise** | Within 24 hours of suspicion | Emergency kernel rebuild with new salt; redeploy across the fleet | No (operational action only) |
| **Confirmed compromise** | Within 4 hours of confirmation | Same as above + revocation broadcast on the mesh; bug-bounty payout per NCIP-Bounty-002 | No |
| **Cryptographic schema change** | When required | New NCIP (amend or supersede this one); bump the `_v1` suffix on `kernel_cap_issuer_seed_vN` | **YES** |
| **TEE family addition** (e.g. ARM CCA) | When hardware lands | Amend NCIP-017 to add the family's derivation block in § S2 | **YES** |

The 90-day routine cadence aligns with the operating-system
industry baseline (Let's Encrypt: 90-day TLS cert; SLSA L3: 90-day
attestation key; SSH best-practice: 90-day session signing key)
and with `NCIP-013` § S5.4 which already mandates the same window
for driver issuer keys.

Rotation cadence is enforced at **kernel build time** via a
`build.rs` check that fails the build if the salt's quarter
suffix is more than 90 days old relative to the build date.
This makes the cadence a hard CI gate, not a soft policy.

### S5. Phase-1 transitional policy

Until `nexacore-tee` ships real backends (`NCIP-016` § S5.2 +
`NCIP-016` § S5.3 — both currently funding-dependent), the kernel
runs under `MockTeeBackend` which always selects the dev
fallback (S2). This is **NOT** production-safe. The transitional
policy:

1. The kernel MUST display the dev-key-custody warning banner
   in the Build Info panel for the entire boot session
   (`crates/nexacore-kernel/src/bare_metal/demo.rs::render_buildinfo`).
2. The kernel MUST log to serial at every `DriverLoad` invocation
   the line `[keycustody] WARNING: minting cap token under DEV
   FALLBACK key — not production-safe`.
3. No driver-image NCIPs may transition to `Active` until the
   transitional state ends. The current state of
   `NCIP-Driver-NVMe-014`, `NCIP-Driver-Net-015`,
   `NCIP-Driver-TEE-016` (all `Active` since 2026-05-20 via
   founder fast-path) is **grandfathered** because the
   transitional state pre-dates this NCIP; future driver NCIPs
   filed AFTER NCIP-017 reaches `Active` MUST cite the steady-state
   custody model.
4. The `KNOWN_ISSUERS` table at
   `crates/nexacore-kernel/src/known_issuers.rs` MUST remain empty
   until S5 ends. Empty KNOWN_ISSUERS means every `DriverLoad`
   currently returns `EACCES` at the issuer-lookup check —
   no real driver can load under the transitional policy, which
   is the desired property (it forces the funding-dep gap to be
   closed before drivers actually ship).
5. The `DRIVER_CAP_ISSUER_SEED` compile-time constant remains in
   place during the transitional period BUT MUST move to a
   feature-gated module under `#[cfg(feature = "dev-key-custody")]`
   so that release builds without the feature flag fail to
   compile rather than silently use the dev seed.

### S6. Migration plan from DEV seed to TEE-derived key

The implementation NCIP (follow-up) will execute this in 5 steps:

1. **M1 — Feature gate the dev seed.** Move
   `DRIVER_CAP_ISSUER_SEED` under
   `#[cfg(feature = "dev-key-custody")]` in
   `crates/nexacore-kernel/src/driver_cap_issuer.rs`. Add the feature
   to `nexacore-kernel/Cargo.toml` with `default = []`. Release builds
   without `--features dev-key-custody` fail to compile with a
   clear `compile_error!` directing the developer to either
   enable the feature for dev or supply a TEE backend.
2. **M2 — Wire the platform-detect path.** Add
   `nexacore_tee::detect_family()` (already a trait method on
   `TeeBackend`; just needs the kernel-side dispatch). Add
   `derive_app_key(...)` that takes the inputs from S2 and
   returns a 32-byte seed.
3. **M3 — Implement TDX derivation.** In
   `nexacore-tee/src/tdx.rs::TdxBackend::derive_app_key`, call
   `TDREPORT` via the `TDCALL[TDG.MR.REPORT]` instruction,
   parse the report, run the HKDF schema from S2 TDX. Test
   with the in-tree `TdxMock` backend that returns fixed
   fixtures.
4. **M4 — Implement SEV-SNP derivation.** In
   `nexacore-tee/src/sev_snp.rs::SevSnpBackend::derive_app_key`,
   call `SNP_GUEST_REQUEST` with `MSG_KEY_REQ`, parse the
   `MSG_KEY_RSP`, run the HKDF schema from S2 SEV-SNP.
5. **M5 — Boot wire-up.** Replace the call to
   `NexaCoreSigningKey::from_bytes(DRIVER_CAP_ISSUER_SEED)` in
   `driver_cap_issuer::kernel_signing_key()` with a
   `OnceLock<NexaCoreSigningKey>::get_or_init` driven by
   `detect_family` + `derive_app_key`. Remove the
   `DRIVER_CAP_ISSUER_SEED` constant in release builds (still
   accessible under `feature = "dev-key-custody"` for dev).

Each milestone lands behind a separate sub-slice with its own
host-side tests. The acceptance gate for M5 is "release build
without `dev-key-custody` feature passes `cargo build` and the
resulting kernel boots successfully on TDX hardware (Proxmox
the test VM with TDX-capable host) + SEV-SNP hardware (whenever
available)".

---

## Rationale

### R1. Why HKDF post-processing on SEV-SNP

`SNP_DERIVE_KEY` already outputs 32 bytes. The HKDF
post-processing standardises the output shape and adds explicit
protocol-version binding — useful if a future `SNP_DERIVE_KEY`
ABI returns a different size. The cost is one HMAC-SHA-256
invocation per boot, which is negligible.

### R2. Why 90-day rotation cadence

Aligned with `NCIP-013` § S5.4 (driver issuer keys) for
consistency. The industry baseline of 90 days (Let's Encrypt,
SLSA L3, SSH best practice) is empirically the longest window
that balances operational overhead vs window-of-exposure. Going
shorter (e.g. 30 days) would force monthly kernel rebuilds in
steady state, which is operationally expensive and increases the
attack surface of the build infrastructure. Going longer (e.g.
180 days) would extend the window during which a stolen key
remains usable.

### R3. Why no key persistence to disk

Persisting the derived key (even encrypted under a TEE-sealed
key) would create a recovery surface that an attacker with
disk access could brute-force or evict-and-replay. By making
the key boot-time-derived from TEE-attested inputs, we move the
recovery surface from "anyone with the disk" to "anyone with
the specific TEE-attested CPU + a valid measurement match" —
which is the actual security boundary we want.

### R4. Why `OnceLock<NexaCoreSigningKey>` instead of static `[u8; 32]`

`NexaCoreSigningKey` (per `nexacore-crypto`) zeroizes on drop. Holding
the seed as a raw `[u8; 32]` after the signing key is
constructed leaves it sitting in `.rodata` for an attacker with
read access to the kernel address space. The `OnceLock` pattern
constructs the signing key once, drops the seed immediately,
and keeps the key inside a `Zeroize`-on-drop wrapper for the
rest of the boot.

### R5. Why the dev fallback is HKDF-derived, not all-zeros

An all-zero seed is the kind of thing that pattern-matching
malware specifically looks for ("scan for `[0u8; 32]` followed
by an Ed25519 keypair derivation"). An HKDF-derived value from
a known constant is the same security level (zero — the input
is public) but does NOT match the heuristic, so it's not a
useful target. Cheap defense in depth.

### R6. Why no in-band rotation (live key replacement)

A live-rotation mechanism would require:

- A new kernel syscall to load a new signing key.
- A capability check on who can call that syscall (chicken-and-egg
  if the old key was the one that minted the issuing capability).
- A migration plan for in-flight capability tokens signed by the
  old key.

All three are doable but introduce attack surface that the boot-time
derivation does not need. Boot-time derivation gives us "rotate the
key by rebooting the kernel" which is operationally simple, has no
in-band attack surface, and aligns with the NexaCore OS preference for
restart-as-recovery (per `docs/04-security-model.md`).

### R7. Why feature-gate the dev seed instead of `cfg(debug_assertions)`

`cfg(debug_assertions)` is set by `cargo build --release` to
`false` — meaning a release build WITHOUT the explicit
`--features dev-key-custody` flag would silently NOT use the dev
seed. That's the right default, but if the developer forgets to
enable the feature on a dev build, they get a `compile_error!`
which is exactly what we want (the build fails loudly rather
than silently using a fallback). Using a feature flag also
allows CI to test BOTH paths (dev-key-custody enabled for unit
tests against the dev seed; dev-key-custody disabled for release
build verification).

---

## Backwards Compatibility

This NCIP is **breaking** in the strict sense: the constant
`DRIVER_CAP_ISSUER_SEED` is removed from release builds. Any
external code that imported the constant via
`nexacore_kernel::driver_cap_issuer::DRIVER_CAP_ISSUER_SEED` will
fail to compile against a release kernel.

Mitigation:

- The constant is currently NOT a public API in the NexaCore OS
  sense — there is no `nexacore-sdk` re-export. The only consumer
  is the kernel itself (internal callers in
  `cap_deposit.rs`).
- Tests that hard-code the seed pattern (e.g.
  `DRIVER_CAP_ISSUER_SEED.chunks_exact(4)`) will move under
  `#[cfg(feature = "dev-key-custody")]` together with the
  constant itself.
- The migration plan (S6 M1-M5) is staged so dev / CI builds
  retain the dev seed under feature gate while release builds
  enforce the TEE-derived path.

The **grandfather clause** for already-`Active` driver NCIPs
(`NCIP-Driver-NVMe-014`, `NCIP-Driver-Net-015`,
`NCIP-Driver-TEE-016`) is documented in S5. Those NCIPs are not
retroactively invalidated; they continue to apply under their
existing terms.

---

## Test Cases

### TC1. Steady-state derivation determinism

Given:
- A `MockTdxBackend` returning a fixed `TDREPORT.measurement`
  + `te_tcb_svn`.
- The same `MockTdxBackend` invoked twice on the same boot.

Assert: `derive_app_key(...)` returns the same 32-byte seed
both times.

### TC2. Steady-state derivation measurement-binding

Given:
- A `MockTdxBackend` returning `TDREPORT.measurement = [0u8; 48]`
  vs `[0xFFu8; 48]`.
- Same `te_tcb_svn`, same protocol version.

Assert: the two derivations produce different seeds (no
collision).

### TC3. TCB-version binding

Given: fixed `TDREPORT.measurement`, varying `te_tcb_svn`.

Assert: every distinct `te_tcb_svn` produces a distinct seed.

### TC4. Dev fallback is reproducible

Assert: `derive_dev_fallback_seed()` always returns the same
32-byte value (the HKDF output of the public constants is
deterministic).

### TC5. Dev fallback differs from any TEE-derived seed

Assert: the dev fallback seed is NOT equal to any seed
producible by the TDX or SEV-SNP paths under any non-degenerate
input.

### TC6. `OnceLock` initialisation is single-shot

Assert: calling `kernel_signing_key()` twice returns the same
signing key (same verifying key bytes).

### TC7. Boot banner displays the dev warning under the dev feature

Assert: when compiled with `--features dev-key-custody`, the
Build Info panel includes a `"⚠ DEV KEY CUSTODY ACTIVE"` row
or banner.

### TC8. Release build fails to compile without the dev feature when no TEE backend is available

Assert: `cargo build --release` (no feature flags) on a
`x86_64-unknown-none` target without the `tdx` or `sev-snp`
features fails with the expected `compile_error!` message.

### TC9. Rotation cadence enforcement

Assert: the `build.rs` check fails the build when the salt's
quarter suffix is more than 90 days old relative to
`SystemTime::now()`.

### TC10. KNOWN_ISSUERS empty during transitional period

Assert: `crates/nexacore-kernel/src/known_issuers.rs::KNOWN_ISSUERS`
is an empty slice during the transitional period (S5).
`DriverLoad` returns `EACCES` for any non-grandfathered driver
issuer.

The implementation NCIP follow-up will provide unit tests for
TC1-TC10. This NCIP carries the spec; the tests live in the
follow-up.

---

## Reference Implementation

None at filing. The implementation NCIP follow-up will land in
`crates/nexacore-kernel/src/driver_cap_issuer.rs` +
`crates/nexacore-tee/src/{tdx,sev_snp,mock}.rs` per the migration
plan in S6.

The follow-up NCIP must be filed within **180 calendar days** of
this NCIP reaching `Active`, OR the implementation is **deferred
until NCIP-016 P5.2 / P5.3 ship real backends**, whichever is
later. If neither has shipped within 180 days, this NCIP
transitions to `Withdrawn` and a successor NCIP is filed with
the lessons learned.

---

## Security Considerations

### SC1. The current gap is exploitable

The placeholder `DRIVER_CAP_ISSUER_SEED` allows anyone with a
copy of the kernel binary to mint deposit tokens that bypass
the `MmioMap` / `DmaMap` / `IrqAttach` capability check. This
is the primary security gap this NCIP closes.

### SC2. The new schema is NOT vulnerable to TCB-rollback replay

By binding to `te_tcb_svn` / `tcb_version`, the derivation
invalidates the key whenever the TEE firmware downgrades.
An attacker who steals the derived key under TCB version N
cannot replay it under TCB version M < N (the input changed,
so the derivation changes).

### SC3. HKDF is the right primitive choice

HKDF-SHA-256 (RFC 5869) is the canonical TLS / SSH / WireGuard
extract-then-expand primitive. The salt/info structure cleanly
encodes domain separation. SHA-256 (NOT SHA-3) for FIPS 140-3
compatibility — NexaCore OS has not yet committed to a FIPS posture
but the option should remain open.

### SC4. Side-channel considerations

`TDREPORT` parsing is on the boot-time fast path; the parsing
code MUST use constant-time comparisons (already required by
`NCIP-013` § S5.4 for `KNOWN_ISSUERS` lookup; reused here for
TCB SVN comparison).

`SNP_DERIVE_KEY` is a TEE-internal instruction with
implementation-defined timing; we cannot side-channel-harden
the AMD primitive itself, but the post-HKDF stage runs in
constant time per `nexacore-crypto`'s existing HKDF implementation
(`subtle::ConstantTimeEq` on every byte comparison).

### SC5. Key material lifetime

The derived seed exists in memory for the duration of the
`NexaCoreSigningKey::from_bytes` call (~microseconds), then is
zeroized. The signing key itself lives for the full boot
session inside a `Zeroize`-on-drop wrapper. On shutdown / panic
the OS zeroizes the wrapper before halting.

### SC6. No HSM dependency

The NexaCore OS threat model does not assume an HSM is available.
The TEE primitives (TDX `TDREPORT`, SEV-SNP `SNP_DERIVE_KEY`)
ARE the HSM-equivalent for the kernel — they provide hardware
attestation of the derivation context. Adding a separate HSM
would be a "second layer of fence around the same yard" without
adding security.

---

## Privacy Considerations

The derivation inputs (`TDREPORT.measurement`, `te_tcb_svn`,
`tcb_version`, `MEASUREMENT`) are NOT personally identifying.
They describe the *kernel binary* and the *TEE firmware*, not
the user. No user-side identifier (NodeId, AgentId, SessionId)
enters the derivation.

The DERIVED key MAY be used (indirectly, via the
`CapabilityToken`s it signs) to authenticate driver processes
on behalf of users. But the key itself does not leak user
identity — it only proves "the running kernel signed this".

The dev fallback is by construction non-private (it uses public
constants); developers using the dev fallback during testing
are responsible for not deploying that build to user-facing
production. The compile-time `compile_error!` makes accidental
deployment difficult.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).

---

## Amendment history

| Date | Change | Notes |
|---|---|---|
| 2026-05-22 | `— → Draft` | Initial filing. Standards Track. Closes TASK-008 of `docs/planning/2026-05-21-development-the development plan`. Cites `crates/nexacore-kernel/src/driver_cap_issuer.rs:56` as the security gap to close. Implementation NCIP follow-up tracked in the planning doc under TASK-008-followup (yet to be assigned a TASK number); follow-up to be filed within 180 calendar days of this NCIP reaching `Active`, OR after `NCIP-016` § S5.2 / § S5.3 real backends ship, whichever is later. |
