# ADR-0033: `LocalCpuProvider` — Engine Reuse, Async Greedy Loop, Degraded Contract (TASK-12, DE-G4)

**Status:** Accepted
**Date:** 2026-06-07
**Deciders:** cySalazar
**Refs:** PLAN.md TASK-12, Sprint 7/8 (GGUF + BPE + transformer forward +
greedy decode), TASK-08/10/11 (provider abstraction / health+events /
ServingRelay), desktop plan §9 (honesty contract),
`crates/nexacore-runtime/src/provider/local_cpu.rs`,
`crates/nexacore-runtime/src/decode.rs`, `crates/nexacore-types/src/ai.rs`

## Context

TASK-12 requires the on-device fallback backend: an `InferenceProvider`
over the inference engine this crate already ships (Sprint 7/8). The
engine's host API is: `gguf::parse_gguf` → `tensor_loader::
load_all_tensors` (F32/F16/BF16/I8 pass-through, Q8_0/Q4_0 real
dequantisation) → `nexacore_hal::transformer::transformer_forward` (async,
`CpuBackend`) → `decode` (greedy sampling). The plan's §9 honesty
contract demands that unacceptable real-model performance be declared
**degraded** explicitly, in the type and in the UI.

## Decision

### 1. Reuse, not a second engine

`LocalCpuProvider` wires existing pieces: `from_gguf` (parse → load →
map tensors by canonical GGUF names into `TransformerWeights`, reframing
block-padded buffers to logical shapes — the same convention as the
crate's e2e test) and a generate path over `transformer_forward`. No new
math, no duplicated codecs.

### 2. Async-native greedy loop (not `streaming_decode`)

`decode::streaming_decode` is a sync `Iterator` that bridges the async
forward pass with an internal per-step `block_on`. Inside the provider's
async methods that would nest a runtime in the caller's runtime — tokio
panics. The provider therefore drives `transformer_forward` with `.await`
directly and reuses the decode module's `extract_last_row` /
`sample_token` (promoted `pub(crate)`): identical maths, no duplication,
no nested runtime. Generation is greedy (`temperature 0`, `top_k 1`) per
the acceptance criterion — fully deterministic, pinned by a golden test
(`"ab"` → `"dddd"` on the shared Q8_0 fixture).

### 3. The degraded contract

`degraded` is computed at construction — total weight bytes >
`DEGRADED_WEIGHTS_BYTES` (1 MiB): anything beyond a toy model is not
interactive on the Phase-2 unoptimised engine. Overridable
(`with_degraded`) for callers with better information (e.g. a measured
benchmark). Propagation: the wiring passes it to
`BackendRouter::with_backend_degraded`; the `HealthRegistry` stores it
per backend and **carries it on every `BackendStatusEvent`** (field
appended in `nexacore-types::ai` — pre-release postcard change, documented),
so the TASK-21 status bar renders "🟡 CPU" without extra plumbing. It is
also readable synchronously (`BackendRouter::backend_degraded`) and
surfaced in `health().detail`. Degraded ≠ unhealthy: the backend stays
fully routable.

### 4. Scope edges (explicit)

- `embeddings`: terminal `Backend` error — the engine has no pooling
  head; pretending otherwise would poison failover semantics. The
  RemoteGpu backend serves embeddings.
- `chat`: plain `role: content` transcript template; model-specific
  templates are TASK-16+.
- Vocabulary ≤ 256 (U8 embedding indices — the documented Sprint 7
  limitation; the fixture tokenizer keeps special ids outside the model
  vocab so greedy runs are budget-terminated and deterministic).
- `config` is caller-supplied in `from_gguf`; deriving architecture
  from GGUF metadata is TASK-16.

## Alternatives Considered

- **Calling `streaming_decode` via `spawn_blocking`:** preserves the
  iterator but requires `'static` captures (cloning the weights per
  request) or `block_in_place` (panics on current-thread runtimes).
  Rejected for the direct async loop + helper promotion.
- **`degraded` on the `InferenceProvider` trait (default method):**
  mockall mocks defaulted methods too — every existing mock-based test
  would need new expectations. The router-level descriptor
  (`with_backend_degraded`) is additive and keeps the trait stable.
- **Separate degraded event stream:** a second wire type for one bit;
  rejected — the existing transition event carries it.
- **A vocab-256 fixture for richer goldens:** more fixture weight for
  marginal coverage; the shared 8-token Q8_0 fixture pins the maths and
  the out-of-vocab path doubles as a clean-error robustness test.

## Consequences

- The TASK-10 failover chain is now real end-to-end on the host: mock
  GPU down → the SAME request served by the real CPU engine, audit
  `backend_used = LocalCpu`, degraded carried on events (pinned by the
  acceptance e2e test).
- TASK-13's M1 smoke can wire `ServingRelay` with a real
  `LocalCpuProvider` as the fallback; TASK-16 upgrades the engine
  (full quantisation, metadata-driven config, wider vocab) without
  touching the provider surface.
- Fixture latency (acceptance #3): ~60–70 µs for 4 greedy tokens
  (1-layer, d_model 4 fixture) on the dev box — measured by the golden
  test via `tracing`; recorded in the commit message. No numeric gate.
- Tests added: 11 (`from_gguf` happy/missing-tensor/garbage, golden
  determinism + pinned `"dddd"`, context bounds, empty prompt,
  out-of-vocab chat → clean error, embeddings honestly unsupported,
  degraded heuristic/override/health detail, failover e2e with audit +
  degraded events). `BackendStatusEvent` round-trips updated for the
  new field.
