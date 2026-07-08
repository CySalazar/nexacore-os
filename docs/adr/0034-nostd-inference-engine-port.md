# ADR-0034: `no_std` Port of the CPU Inference Engine (TASK-13-pre)

**Status:** Accepted
**Date:** 2026-06-07
**Deciders:** cySalazar (operator scoping decision), agent analysis
**Refs:** PLAN.md TASK-13-pre / TASK-13, ADR-0032 (Ring 3 mock endpoint),
ADR-0033 (LocalCpuProvider), desktop plan §9 + M1 gate,
`crates/nexacore-hal/src/{tensor.rs,transformer.rs}`,
`crates/nexacore-runtime/src/{gguf.rs,tensor_loader.rs,bpe.rs,decode.rs}`

## Context

The M1 smoke (TASK-13/DE-G9) requires, from Ring 3 on the test VM, a prompt
served by real Ollama AND — with Ollama stopped — by the CPU fallback
with `backend_used = LocalCpu`. The real CPU engine (TASK-12) is a
std/tokio stack; the Ring 3 runtime endpoint (TASK-11) therefore ships a
labelled mock. **Operator decision (2026-06-07): M1 closes with the REAL
engine in Ring 3 — no mock-labelled fallback.** TASK-13 is blocked on a
new prerequisite, TASK-13-pre: make the chain GGUF parse → tensor
load/dequantise → BPE tokenize → transformer forward → greedy decode run
under `no_std + alloc` on `x86_64-unknown-none` (no tokio, no threads,
no fs, no getrandom).

A dependency audit (agent-team, file:line evidence) found:

| Module | Blockers | Effort |
|---|---|---|
| `gguf.rs`, `tensor_loader.rs` | none (alloc `Vec`/`String`, bitwise f16/bf16) | ready |
| `nexacore-types` errors | none (`thiserror 2` no_std, `core::result`) | ready |
| `bpe.rs` | `std::collections::HashMap` | swap to `hashbrown` |
| `tensor.rs` | `is_x86_feature_detected!` (std-only) | gate; fallback `SimdCapability::None` |
| `transformer.rs` | `async_trait` decoration; **all `.await`s are TensorBackend trait dispatch, zero real async** | sync variant / gating |
| `decode.rs` | `run_sync` (tokio bridge), `std::cmp::Ordering` import | gate tokio; sampling itself is pure compute |

**Correction to the audit (recorded deliberately):** the audit claims
`core::f32` provides `sqrt/exp/sin/cos/powf` in `no_std`. On stable Rust
1.85 those methods live in **std** (`core_float_math` is not stabilised);
`no_std` builds need **`libm`** (pure-Rust, no_std, the ecosystem
standard) or equivalent. The first cross-compile is the empirical test;
the plan budgets the `libm` swap (a `math` shim module so call-sites
stay readable: `crate::math::sqrt(x)` → `f32::sqrt` on std / `libm::
sqrtf` on no_std — bit-identical results are NOT guaranteed between the
two, so the golden test must pin the path actually shipped, see below).

## Decision

### Strategy: feature-gate the existing crates (audit Option A)

`nexacore-hal` and `nexacore-runtime` gain a default-on `std` feature; the
`no_std` build disables tokio/async-trait/SIMD-detection and swaps
`HashMap` → `hashbrown` (alloc-capable, same API). No engine fork, no
`nexacore-infer-core` extraction yet — extraction (audit Option B) remains
the Phase-6 refactor if a third consumer appears; today it would
duplicate module trees for two consumers.

### Port shape

1. **Math shim** (`nexacore-hal` or shared): `std` → `f32` inherent methods;
   `no_std` → `libm`. One audited point for every transcendental.
2. **Sync forward path**: the transformer's `.await`s are pure trait
   dispatch — provide a sync `TensorBackend::execute`-equivalent
   (`execute_sync`) and a sync `transformer_forward_sync` used by the
   `no_std` build (std keeps the async surface untouched — zero churn
   for existing consumers).
3. **bpe**: `hashbrown::HashMap` unconditionally (it IS std's hashmap
   implementation; one dependency, no cfg forest).
4. **decode**: split the pure sampling core (`sample_token`,
   `extract_last_row`, xorshift) into the no_std surface;
   `streaming_decode`/`run_sync` stay std-gated.
5. **Golden invariance**: the TASK-12 golden ("ab" → "dddd" on the Q8_0
   fixture) must pass on the host BOTH via the std path and via the
   ported sync path compiled for the host; the the test VM smoke then pins
   the same golden from Ring 3. If libm vs std math ever diverge on the
   fixture, the divergence is surfaced, not papered over.
6. **Image integration** (`nexacore-runtime-image`): embed the fixture
   model, replace the mock `serve()` with the real chain, keep the
   TASK-11 wire contract byte-identical.

### Acceptance (mirrors PLAN.md TASK-13-pre)

- Chain compiles for `x86_64-unknown-none` AND the host suite stays
  green (zero regressions; the std surface is unchanged by default).
- Host golden test passes on the ported path.
- the test VM: `[aicheck]` receives the golden answer from the REAL engine
  in Ring 3, serial verbatim, `Page Fault = 0`.

## Alternatives Considered

- **Mock-labelled fallback for M1** (proposed): rejected by the
  operator — the milestone's meaning is "real AI on-device", a labelled
  mock defers the hard part and weakens the M1 claim.
- **RemoteGpu-only M1 smoke**: rejected with the same rationale.
- **`nexacore-infer-core` extraction now**: cleaner long-term layering but
  a large mechanical move while the engine is still evolving (TASK-16
  quantisation); feature-gating gets to the same Ring 3 binary with a
  fraction of the churn. Revisit at Phase 6.
- **Porting tokio / running an async executor in Ring 3**: pointless —
  the audit shows zero real asynchrony in the compute path.

## Consequences

- TASK-13 (agent wiring + M1 smoke) resumes after this port; HW
  authorisation (the test VM deploy + Ollama stop/start on LXC 101) is
  already granted for the smoke.
- `hashbrown` and `libm` enter the workspace dependency set (both
  no_std staples; `cargo deny` review applies).
- The Ring 3 image grows the embedded fixture model; the bump-allocator
  heap budget needs re-checking (256 KiB today).
- The nexacore-agent recon (331 tests, OrchestratorBridge entry point) is
  archived in the session notes for TASK-13's resumption.

## Amendment — implementation record (2026-06-07, port landed)

The port was implemented and verified per this ADR. Deviations and
refinements recorded here:

1. **Working-tree reconciliation.** An interrupted earlier session had
   added `crates/nexacore-infer-core` references to the root manifest,
   contradicting this ADR's strategy (Option A, no extraction). Those
   references were removed; feature-gating was implemented as decided.
2. **`engine` facade module** (`nexacore-runtime::engine`, `no_std`): the
   GGUF→`TransformerWeights` mapping and the greedy loop previously
   lived only inside the std `LocalCpuProvider`; both consumers (std
   provider, Ring 3 image) now share `CpuEngine` — one audited body,
   no duplication. This is a module inside the feature-gated crate,
   NOT the rejected `nexacore-infer-core` extraction.
3. **`fixture` module + `fixture-model` feature**: the canonical tiny
   Q8_0 fixture (synthetic GGUF + config + tokenizer) moved out of
   `cfg(test)` so the Ring 3 image embeds the SAME model the host
   goldens pin.
4. **tokio left nexacore-hal entirely**: with the forward path synchronous,
   `transformer_forward_cached`'s `block_on` bridge and decode's
   `run_sync` were deleted; tokio survives only in dev-dependencies.
   The async `TensorBackend` trait and `transformer_forward` wrapper
   remain (std) for API compatibility — both delegate to the sync body.
5. **hashbrown needs `ahash`**: `default-features = false` alone has no
   default hasher; the `ahash` feature is pulled WITHOUT `getrandom`
   (fixed-seed) — acceptable: vocab keys come from the model file, not
   an adversarial network boundary.
6. **`math` shim grew `round` and `mul_add`** (quantisation + GeLU paths)
   beyond the originally listed transcendentals; libm's `roundf`/`fmaf`
   are bit-identical to the std semantics.
7. **Image heap 256 KiB → 512 KiB**: engine construction (~10 KiB) plus
   ~15 KiB never-freed forward temporaries per 4-token request on the
   bump allocator.
8. **Golden invariance verified**: host (`engine::tests::
   golden_ab_to_dddd_via_sync_engine_surface`, sync surface, std math
   path) AND Ring 3 on the test VM (serial verbatim 2026-06-07:
   `[ai-svc] real CPU engine ready (Q8_0 fixture, vocab=8)` ·
   `[aicheck] response=dddd` · `[aicheck] GOLDEN OK` · EFAULT/ENOSPC
   negatives OK · zero #PF · M0 intact `[netcheck] HTTP status=200`).
   No std-vs-libm divergence surfaced on the fixture.
