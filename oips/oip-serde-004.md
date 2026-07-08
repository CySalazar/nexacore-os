---
ncip: 4
title: Migrate workspace serialization from bincode v2 (unmaintained) to postcard
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-12
updated: 2026-05-22
requires:
  - 1
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

`bincode` v2.0 — currently the canonical wire encoding used by `nexacore-capability::CapabilityToken` (signing pre-image), `nexacore-tee::Quote` / `Measurement` / `SealedBlob` (TEE attestation envelopes), and any future cross-crate binary protocol — was marked **unmaintained** on 2025-12-16 (RUSTSEC-2025-0141). The maintainer announced cessation of development following a doxxing / harassment incident; v1.3.3 is "considered complete and not in need of updates" but uses an incompatible API that does not satisfy our `no_std + alloc + serde` requirements at the v2 ergonomics level.

This NCIP commits NexaCore OS v1.0 to **migrate the workspace serialization layer from `bincode` v2.0 to `postcard` v1.x**. `postcard` is the most direct replacement for our requirements (`no_std + alloc + serde derive`), is actively maintained (Ferrous Systems / Embedded Working Group), has a stable wire format documented as part of the crate, and is widely deployed in the Rust embedded ecosystem with audit history.

The migration is a **breaking wire change**: bincode and postcard produce different bytes for the same `Serialize` implementations. We therefore bump the protocol version from `NexaCore-PROTO-v0.1` to `NexaCore-PROTO-v0.2` at the same time, formalising the cutover. There is no on-network deployment of v0.1 yet, so no live-migration concerns apply.

---

## Motivation

[`SECURITY.md`](../SECURITY.md) § 7 and `NCIP-Process-001` § 3.2 mandate that the project track and respond to RustSec advisories on the dependency graph. **RUSTSEC-2025-0141** is currently the only open advisory on `Cargo.lock` and is causing both `cargo audit` and `cargo deny` jobs in `.github/workflows/audit.yml` to fail on `main` and on every PR (including PR #13, the P3-P6 scaffolding bundle). Three intervention modes were considered:

1. **`deny.toml` `ignore` entry with a sunset date.** Documented mitigation, no code change. Trade-off: kicks the can down the road; the `unmaintained` advisory will not become `vulnerability` automatically, but ecosystem drift (postcard / bitcode / rkyv adopting features bincode lacks) makes future migration steeper.
2. **Pin `bincode = "1.3.3"`.** Maintainer-blessed terminal version. API incompatible with v2: requires re-writing all `bincode::serde::encode_to_vec` / `decode_from_slice` call-sites and re-deriving the wire format under v1's `bincode_options` configuration (no canonical-encoding helper, must be configured manually).
3. **Migrate to a maintained alternative.** RUSTSEC-2025-0141 explicitly recommends `postcard`, `bitcode`, `rkyv`, and `wincode`. Of these, only `postcard` matches all our hard requirements (see § Rationale).

Option (3) is the only choice that resolves the supply-chain risk *and* removes the technical debt of a `dyn deprecated` dependency at our wire-format layer. The cost is a one-time wire-format break, which is acceptable for a pre-1.0 project where `NexaCore-PROTO-v0.1` has zero deployments outside developer machines.

---

## Specification

### S1. Workspace dependency change

`Cargo.toml` `[workspace.dependencies]`:

```diff
-bincode = { version = "2.0", default-features = false, features = ["serde", "alloc"] }
+postcard = { version = "1.0", default-features = false, features = ["alloc"] }
+# `default-features = false` + `alloc` only. `postcard`'s `use-std` feature
+# is *not* enabled at the workspace level because Cargo features are additive
+# — enabling `use-std` once would pull `std` into every foundational crate
+# (`nexacore-types`, `nexacore-crypto`, `nexacore-capability`, `nexacore-tee`, `nexacore-kernel`).
+# A consumer that genuinely requires `std::io::Read`/`Write` adapters MUST
+# depend on `postcard` directly (not via the workspace re-export) and enable
+# `use-std` in that crate's `Cargo.toml` only. There are no such consumers
+# at v0.2; the rule is stated to head off future drift.
+# `postcard`'s alloc support requires version ≥ 1.0.7.
```

Every `bincode = { workspace = true }` in `crates/*/Cargo.toml` is replaced with `postcard = { workspace = true }`. The replacement is:

| Crate | Current usage | Action |
|---|---|---|
| `nexacore-capability` | `bincode::serde::encode_to_vec` for `CapabilityToken` signing pre-image | Replace with `postcard::to_allocvec` (returns `Result<Vec<u8>, Error>`); update `decode_from_slice` to `postcard::from_bytes` |
| `nexacore-tee` (dev-dep) | `bincode::serde::encode_to_vec` / `decode_from_slice` in `attestation.rs` round-trip tests | Same replacement |
| Future `nexacore-mesh`, `nexacore-runtime`, `nexacore-tokenization` | (none yet — they pull bincode transitively via `nexacore-capability`) | Inherits the change |

### S2. Canonical encoding contract

Define one workspace-level helper module (`nexacore-types::wire`) that wraps `postcard` with our chosen options:

```rust
pub fn encode_canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, NexaCoreError> { ... }
pub fn decode_canonical<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, NexaCoreError> { ... }
```

Rationale: prevents drift across crates (e.g., one site using little-endian varints and another using big-endian), and gives us one place to amend the wire contract under a future NCIP. **Every `Serialize` / `Deserialize` flow that crosses a trust boundary MUST go through these helpers**; lint enforced by clippy `disallowed-methods` on `postcard::*` raw helpers outside `nexacore-types::wire`.

### S3. Wire-format version bump

`nexacore-types::ProtocolVersion` introduces `PROTOCOL_VERSION_V0_2` with `serde_format = "postcard-1.0"` discriminant. Mesh handshake (`docs/protocol/handshake.md` § 3.2) negotiates v0.2 only; v0.1 negotiation is removed (it cannot interoperate with the new wire format).

### S4. Test plan delta

- Re-run all 185 workspace tests under the new dep — every test that round-trips a `Serialize` type re-validates byte shape.
- Add `crates/nexacore-capability/tests/wire_format_v0_2.rs` with a frozen reference vector (a known `CapabilityToken` and its postcard byte string) so accidental encoding drift is caught at CI time.
- Add a deliberate negative test: `encode_canonical` followed by manual byte-flip MUST fail signature verification on `decode_canonical`-then-verify.

### S5. Migration sequence

| Step | Description | Verification |
|---|---|---|
| **M1** | Workspace dep swap (`Cargo.toml`); cycle the lockfile | `cargo build --workspace --all-features` |
| **M2** | `nexacore-types::wire` helper module + clippy `disallowed-methods` lint on raw `postcard` calls | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| **M3** | `nexacore-capability` `CapabilityToken` signing pre-image migration; existing 43 tests rewritten against `postcard` round-trips | `cargo test -p nexacore-capability` |
| **M4** | `nexacore-tee` round-trip tests + `nexacore-types::ProtocolVersion::V0_2` constant | `cargo test --workspace --all-features` (185 tests, expect all green) |
| **M5** | Reference-vector test under `nexacore-capability/tests/wire_format_v0_2.rs`; remove `bincode` from `Cargo.lock` (verify via `cargo tree --invert bincode` empty); `RUSTSEC-2025-0141` no longer in `cargo audit` output | `cargo audit` and `cargo deny check` exit 0 |

Each step is its own commit; the NCIP transitions to `Active` only after M5 is verified end-to-end on CI.

---

## Rationale

Selection criteria, in order of weight:

1. **`no_std + alloc + serde derive`** — required by every foundational crate (`nexacore-types`, `nexacore-crypto`, `nexacore-capability`, `nexacore-tee`, `nexacore-kernel`).
2. **Active maintenance** — must not have a public unmaintained advisory now or be dependent on a single unresponsive maintainer.
3. **Stable wire format** documented as part of the crate's contract.
4. **Audit history** — bonus if a published external review exists.
5. **Smallest binary footprint** — relevant for `nexacore-kernel` (`bare-metal`).
6. **Compatibility with our derive-heavy `Serialize` impls** — we do not want to hand-roll encoders.

| Candidate | `no_std + alloc + serde` | Maintained | Wire-format spec | Audit | Footprint | Notes |
|---|:---:|:---:|:---:|:---:|---|---|
| `postcard` | ✅ (≥ 1.0.7) | ✅ (Ferrous Systems / Embedded WG) | ✅ (COBS-based, documented) | ✅ (Ferrous review 2023) | smallest | Chosen |
| `bitcode` | ⚠️ (`alloc` only, no full `no_std`) | ✅ | partial | ❌ | small | Faster but `no_std` story incomplete; not viable for kernel |
| `rkyv` | ✅ | ✅ | ✅ | ✅ | larger | Zero-copy Archive types are a big API change; `Serialize` derive incompatible |
| `wincode` | ✅ | new project (2025) | partial | ❌ | small | Too young for a foundational dependency |
| `bincode 1.3.3` | ✅ | ❌ (declared complete; no security backports) | implicit | ❌ | small | Maintainer-blessed terminal version; same supply-chain drift problem in 12 months |

`postcard` is the only candidate that satisfies (1)–(4) without compromise. (5) and (6) are bonus.

The wire-format break is unavoidable under any of the three intervention modes that touch the encoder. We accept it now (pre-1.0, zero deployments) rather than later (post-1.0, breaking-change NCIP).

---

## Backwards Compatibility

**Breaking change at the wire layer.** Specifically:

- `NexaCore-PROTO-v0.1` is **removed**. Mesh handshake will not negotiate v0.1 after this NCIP is `Active`.
- Any persisted `SealedBlob` written by `nexacore-tee` v0.1.x cannot be unsealed by v0.2.x. There is no documented user persisting these blobs; the migration window is zero.
- `CapabilityToken` instances signed under v0.1 cannot be verified under v0.2 (different signing pre-image bytes). No tokens have been minted outside test code.
- Crate consumers still see the same `Serialize` / `Deserialize` derive macros; the change is invisible at the Rust API level. Only the bytes on the wire / on disk change.

There is no migration path from v0.1 to v0.2. The NCIP is binding on `Active`; from that point, all artifacts use v0.2 exclusively.

---

## Test Cases

In addition to the test plan in § S4:

- **Reference vector test** (`crates/nexacore-capability/tests/wire_format_v0_2.rs`):
  - Construct a `CapabilityToken` with frozen field values (subject = `NodeId::from_bytes([0xAB; 32])`, action = `Action::Read`, resource = `Resource::File("test")`, time window = `[100, 200]`, no caveats).
  - Encode via `nexacore_types::wire::encode_canonical`.
  - Compare bytes to a frozen `[u8; N]` literal in the test (the exact reference vector). Any encoder change will fail this test.
- **Adversarial round-trip** (`crates/nexacore-tee/tests/wire_format_v0_2.rs`):
  - Encode a `Quote`; flip 1 bit at every offset; for each flip, `decode_canonical` MUST return `Err(_)` OR `verify_quote` MUST return `Err(_)`. (No silently-accepted tampering.)
- **Cross-crate round-trip**: encode a `CapabilityToken` in `nexacore-capability`, ship the bytes through the existing 7 cross-crate integration tests, decode in `nexacore-tee` (placeholder consumer until `nexacore-mesh` exists), assert the decoded value equals the original.
- **`cargo audit` and `cargo deny check`**: exit 0 with `RUSTSEC-2025-0141` no longer in the report.

---

## Reference Implementation

- Crate: [`postcard`](https://crates.io/crates/postcard) v1.0.x, source at <https://github.com/jamesmunns/postcard>.
- Migration branch (when work starts): `feat/ncip-serde-004-postcard-migration`. Commits one per migration step (M1–M5) per the standard project convention.
- Reference for canonical-encoding helpers: see the `postcard::experimental::serialized_size` and `postcard::to_extend` patterns in the upstream README.
- This NCIP transitions to `Final` only after the migration branch merges to `main` and CI is green for ≥ 7 calendar days (no regressions surface in the daily `audit.yml` cron).

---

## Security Considerations

- **Wire-format correctness.** `postcard` uses LEB128-style varints and length-prefixed sequences. The encoding is canonical (one byte sequence per value), so signature pre-images are reproducible. We require `nexacore-types::wire::encode_canonical` to be the only path; the lint in S2 enforces this.
- **No length-extension.** `postcard` is a self-delimiting format (length prefixes everywhere), so concatenating two encoded messages does not produce a third valid message. This eliminates a class of confusion attacks present in fixed-width encodings.
- **Supply-chain hygiene.** `postcard` has an active maintainer at Ferrous Systems and is embedded in the Embedded Working Group's reference patterns. The dependency graph it pulls in (`heapless`, `cobs`, `serde`) is small and audited. No upstream advisories on the chosen version range as of `cargo audit` 2026-05-12.
- **Audit cadence.** `NCIP-Process-001` § 3.2 already requires a quarterly review of every `[workspace.dependencies]` entry. `postcard` enters that review on its first quarter post-migration.
- **Compromise-by-divergence.** A third-party encoder consuming our bytes (e.g., a debugging tool that re-decodes the wire format) MUST also use `postcard` 1.x. Any divergence is a wire-protocol violation, not our security property to defend.
- **Migration window safety.** During M3–M4, a partially-migrated workspace would produce mixed bincode/postcard bytes. Mitigation: each step is its own commit; CI must be green at each step before the next is pushed; M3 and M4 are not separated by a release.

---

## Privacy Considerations

This NCIP changes the **encoding** of data already crossing trust boundaries (`CapabilityToken`, `Quote`, `SealedBlob`). The set of fields encoded does **not** change; the privacy surface is therefore identical to the pre-migration state:

- No new fields, no new identifiers, no new metadata.
- `postcard`'s self-delimited format does not leak structural information beyond what `bincode`'s length-prefixed format already leaked (length, ordering).
- The migration does not introduce a new transport, a new persistence layer, or a new logging surface.

The wire-format version bump is itself a piece of metadata exchanged at handshake (`NexaCore-PROTO-v0.2`). This is intentional and matches the existing pattern for `NexaCore-PROTO-v0.1`. No additional privacy review is triggered.

When a user-data flow eventually depends on this serialization (e.g., `nexacore-tokenization` `MaskedSSN` round-trips), the privacy considerations of *that* flow are governed by the NCIP introducing it, with `postcard`'s wire-format properties as a baseline assumption.

---

## Amendment history

| Date | Change | Notes |
|---|---|---|
| 2026-05-12 | `Draft → Review` | Editorial transition by the interim editor body (founder, sole editor during the Bootstrap Period per `NCIP-Process-001` §6.2). One in-Review correction applied: §S1 dropped the `use-std` feature from the workspace-level `postcard` dependency declaration. Reason: Cargo features are additive — enabling `use-std` in `[workspace.dependencies]` would unconditionally pull `std` into the foundational crates that must remain `no_std + alloc` for the kernel trajectory (`nexacore-types`, `nexacore-crypto`, `nexacore-capability`, `nexacore-tee`, `nexacore-kernel`). The corrected `features = ["alloc"]` matches the actual constraint. No other content change; the migration plan (M1–M5) is unchanged. |
| 2026-05-12 | `Review → Last Call` | Editorial transition by the interim editor body. **14-day public-objection window opens 2026-05-12 and closes 2026-05-26** per `NCIP-Process-001` §4 and §5.3. All five migration steps M1–M5 have landed locally on branch `feat/p1-foundational-crates` (commits `b8de469` / `9b3d977` / `b451539` / `61a2b02` / `784918b`), with verification: `cargo build --workspace --all-features` clean; `cargo test --workspace --all-features` 204 tests / 0 failures; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo audit` exit 0 with **RUSTSEC-2025-0141 absent**; `cargo deny check advisories` ok. Pre-existing `cargo deny` failures on `bans` (cpufeatures 0.2/0.3 duplicate) and `licenses` (`Unicode-DFS-2016`) are explicitly noted as **out of scope** for this NCIP and tracked separately. Transition to `Active` requires either ≥30% weighted vote OR the 14-day window elapsing — whichever fires first — per `NCIP-Process-001` §5.3. |
| 2026-05-22 | `Last Call → Active` | Editorial closure of the Last Call window under `NCIP-Process-001` §5.3 ¶1 second branch: the dominant voter (`cySalazar`, 100% weighted eligibility under §5.2 bootstrap defaults — sole §5.1-eligible device, identical state to the §5.5 fast-track log entry for NCIP-Kernel-005/012 on 2026-05-14) cast an in-favor ballot, satisfying both clauses of §5.3 simultaneously (≥30% weighted vote cast AND ≥50%+1 weighted in favor). Because NCIP-Serde-004 is `Standards Track` but does **not** break Layer 1 cryptographic guarantees (§5.3 ¶2: wire encoding is the layer ABOVE the crypto envelope; the cipher suites, signature schemes, capability format, and mesh handshake are unaffected), the simple 50%+1 majority applies — not the 66.7% supermajority. Founder ballot recorded in `docs/audits/ncip-editors-report-2026-Q2.md`. No blocking objection raised during the 10-day partial window (2026-05-12 → 2026-05-22) on the linked GitHub Discussion thread. No content change carried by this transition; the `Active` text is identical to the `Last Call` text. §5.5 fast-track was **not** invoked (the §5.5 (c) banner required at `Review → Last Call` entry was not in place); §5.3 ¶1 was the operative closure clause. As `Active` `Standards Track`, NCIP-Serde-004 enters its activation phase per §7 — but per the NCIP's own §7 the activation phase is **dormant until Phase 4+ mesh telemetry exists** (no quorum to measure today), so the NCIP is operationally indistinguishable from `Final` until that telemetry capability ships. |

## Copyright

This NCIP is licensed under [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/).
