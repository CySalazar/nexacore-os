# ADR-0031: Backend Health Hysteresis, Status Events, and `backend_used` Audit (TASK-10, DE-G3 + DE-G5)

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar
**Refs:** PLAN.md TASK-10, TASK-08 (BackendRouter), TASK-09 / ADR-0030
(OllamaProvider), TASK-21 (UI status-bar consumer),
`crates/nexacore-runtime/src/provider/health.rs`,
`crates/nexacore-runtime/src/provider.rs`, `crates/nexacore-runtime/src/audit.rs`,
`crates/nexacore-types/src/ai.rs`

## Context

TASK-08's `BackendRouter` does *per-request* failover only: every request
retries the dead GPU first and pays its connect timeout before falling
back to the CPU. TASK-10 requires the router to become resilient —
periodic health-check (`/api/tags`), automatic RemoteGpu→LocalCpu
failover, automatic recovery when the GPU returns, **without flapping**
on an intermittently-reachable backend — and requires every inference to
record `backend_used` (+ latency) in an `AuditRecord`, plus a backend
status event the UI (TASK-21) can consume.

Constraints inherited from the codebase: deterministic, clock-free
decision logic (every routing test must be reproducible); no PII in
audit records; postcard wire types that cross IPC live in `nexacore-types`;
`parking_lot` is the workspace-standard sync lock.

## Decision

### 1. Counter-based hysteresis, asymmetric thresholds, clock-free

`provider/health.rs` adds a pure FSM (`HealthTracker`): per backend,
`Healthy ↔ Unhealthy` driven only by the observation sequence —
`fail_threshold` (default **1**) consecutive failures demote;
`recover_threshold` (default **3**) consecutive successes recover. An
intermittent backend (ok/fail alternating) never accumulates 3
consecutive successes and stays demoted: no flip-flop, requests keep
flowing to the stable fallback. No clocks, no randomness — time-based
schemes (sliding error-rate windows, exponential backoff) were rejected
because they make routing decisions untestable deterministically and add
tuning surface without adding safety at this scale (2 backends).

### 2. Two evidence sources feeding the same trackers

- **Per-request outcomes:** a retriable provider error
  (`Unavailable`/`Transport`) is failure evidence; a success is recovery
  evidence. With `fail_threshold = 1` the first failed request already
  demotes the GPU — the acceptance's "failover entro 1 richiesta" is met
  by the in-request cascade, and persistence is immediate.
- **Periodic probes:** `BackendRouter::probe_health_once` runs each
  registered provider's `health()` (Ollama: `GET /api/tags`) and feeds
  the same trackers; `spawn_periodic_health_probe` drives it on a tokio
  timer. While demoted a backend receives **no** request traffic, so the
  probe is the *only* recovery path — exactly DE-G3's "health-check
  periodico" role.

**Terminal errors are health-neutral:** a `Backend`/`InvalidRequest`
error proves connectivity (the server answered) but says nothing about
the backend being *down*; counting it as success would mask a
half-broken backend, counting it as failure would demote a reachable
one. The periodic probe remains the authority.

### 3. Demote, never drop

`dispatch_order()` = policy order ∩ registered, stably partitioned
healthy-first; unhealthy backends stay at the tail as last resort. When
*everything* looks down, trying a demoted backend beats failing without
trying (availability over freshness). The TASK-08 `selection_order()`
(configured order, health-blind) is kept unchanged for API stability.

### 4. `BackendKind` and `BackendStatusEvent` move to `nexacore-types::ai`

The status event crosses IPC (runtime service → UI status bar), so it
lives at the bottom of the dependency tree per the workspace rule.
`BackendKind` moves with it (the event carries it); variant order is
preserved — the postcard encoding is **byte-identical** — and
`nexacore-runtime::provider` re-exports it, so every existing path keeps
compiling. The event is minimal (`backend`, `healthy`), emitted **only
on transitions** (never per request/probe), and carries no timestamp
(decisions are clock-free; consumers stamp arrival) and no detail string
(no text channel that could leak content). Health *reasons* stay in
tracing logs.

### 5. Transition delivery: `BackendStatusSink`

The registry holds a `Box<dyn BackendStatusSink>`; the default
`TracingStatusSink` logs transitions, `BufferStatusSink` collects them
(tests today; the TASK-21 IPC bridge can drain it). Emission happens
under the tracker lock so concurrent observers cannot reorder two
transitions; sinks must be cheap and non-blocking (documented contract).

### 6. Audit: `RequestContext` + `AuditSink`, exactly one record per request

`AuditRecord` gains `backend_used: Option<BackendKind>` (appended field;
postcard is not self-describing, so this is a wire-format change —
acceptable pre-release, no persisted logs exist; documented on the
field). The serving layer owns identity and clock, the router owns the
outcome: callers pass a `RequestContext` (session/capability/model ids,
tier, timestamp, input tokens) to the new `*_with_ctx` methods, which
record exactly one record per request — success (`Ok`,
`Some(backend)`), terminal failure (`Failed`/`Rejected`, attributed to
the backend that answered), or exhaustion (`Failed`, `None`). Latency is
measured with `std::time::Instant` (recorded metadata only — control
flow stays clock-free). The context-free TASK-08 methods still feed
health but do not audit; the serving path (TASK-11) is expected to use
`*_with_ctx`.

`AuditLog` (`&mut self`, non-dyn-compatible due to `impl Iterator`) is
unusable as a shared writer, so a narrow object-safe `AuditSink` trait
is added, canonically implemented by `parking_lot::Mutex<L: AuditLog>`
and shared as `Arc` — the owner keeps full read access through the same
handle. The `InMemoryAuditLog` ring (16384, drop-oldest) is unchanged.

## Alternatives Considered

- **Skip unhealthy backends entirely:** simpler ordering, but a
  GPU-only policy with a demoted GPU would fail every request without
  trying. Rejected — demote-not-drop preserves availability.
- **Health-check inline before each request:** adds a probe round-trip
  to every request's latency and still races the backend's state.
  Rejected — async periodic probe + per-request evidence is cheaper and
  converges as fast.
- **Time-windowed error rates / exponential backoff:** richer model,
  but clock-dependent (untestable deterministically) and unneeded for a
  2-backend topology. Rejected.
- **`tokio::sync::broadcast` for status events:** plausible transport,
  but picks the IPC consumer's concurrency model today. The sink trait
  defers that choice to TASK-21 with zero cost.
- **Mirroring `BackendKind` in nexacore-types (duplicate enum + From):**
  avoids touching TASK-08's module but creates a permanent
  drift-prone duplication across a wire boundary. Rejected in favour of
  move + re-export (byte-identical encoding, zero call-site churn).
- **Auditing inside each provider:** would duplicate the logic per
  backend and lose the cascade view (which backend ultimately served).
  Rejected — the router is the only place that knows `backend_used`.

## Consequences

- TASK-11 wires `SessionManager` → `*_with_ctx` with a real
  `RequestContext`; TASK-21 implements a `BackendStatusSink` that
  bridges events over IPC and reads `BackendRouter::health()` for the
  initial indicator state.
- TASK-12's `LocalCpuProvider` plugs in with no router change; its
  health observations get the same hysteresis.
- `AuditRecord` wire format changed (appended optional field) — flagged
  in the field docs and CHANGELOG; pre-release, no migration needed.
- Tests added: 8 health-FSM/registry unit tests, 6 router
  failover/recovery/hysteresis tests (incl. a paused-clock periodic
  probe test via tokio `test-util`, dev-dependency only), 5 audit
  exactly-one-record tests, 1 PII proptest (the canonical encoding of
  every produced record never contains the prompt bytes), 3
  `nexacore-types::ai` wire tests (incl. pinned postcard discriminants).
  Workspace 4188 → 4212.
