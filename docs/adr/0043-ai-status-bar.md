# ADR-0043: AI-Backend Status Bar (TASK-21, DE-C6) — closes M3

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-21
**Refs:** PLAN.md TASK-21 (DE-C6, M3), ADR-0042 (`nexacore-ui`, TASK-20), ADR-0041
(`nexacore-display`, TASK-19), ADR-0031 (BackendRouter health, TASK-10), ADR-0035
(runtime-image RemoteGpu/LocalCpu router, TASK-13), `nexacore_types::ai`

## Context

TASK-21 closes M3 with an always-visible system **status bar** that shows the
live AI backend: 🟢 **GPU** (RemoteGpu / Ollama) or 🟡 **CPU** (LocalCpu,
degraded), with the endpoint/model detail. It consumes the TASK-10 backend
status vocabulary (`nexacore_types::ai::BackendStatusEvent { backend, healthy,
degraded }`). "No new syscall."

Recon facts:
- The runtime-image (`nexacore-runtime-image`, ADR-0035) serves AI with an INLINE
  per-request router: RemoteGpu (Ollama `POST /api/generate` over the NET
  syscalls, host `127.0.0.1:11434`, model `gemma4:latest`) → LocalCpu
  fallback. It logs `backend_used` but does NOT publish a status stream.
- `BackendStatusEvent` exists; the host `BackendStatusSink` is in-process only
  (Tracing/Buffer) — nothing crosses IPC today.
- Named channels are shared via `NetRegister (100)` / `NetLookup (102)` — the
  runtime already registers `ai`/`ai_reply` this way. So a status channel needs
  no new syscall and no kernel deposit change.
- `nexacore-ui` (TASK-20) has the widget/canvas/text/theme toolkit; `font8x8` has no
  emoji, so the badge is a coloured indicator (sage = GPU healthy, amber/brick =
  CPU degraded) + text.

## Decisions

### D1 — `ai_status` channel over `NetRegister`/`NetLookup`

The runtime creates an anonymous IPC channel and `NetRegister`s it under the
name **`ai_status`**. It publishes one `BackendStatusEvent` (postcard,
`MessageKind::Notification`) per state change / probe tick. The display task
`NetLookup`s `ai_status` and drains it. No kernel change, no new syscall — the
existing named-channel registry carries it.

### D2 — Runtime publishes via a periodic Ollama health probe

So the bar reflects reality even with no client traffic, the runtime-image runs
a lightweight **periodic probe** (cooperative, interleaved with its serve loop,
~every few seconds): a TCP reachability check of the Ollama endpoint (a short
`/api/tags` GET, or just a connect, with a small timeout budget — budget
exhaustion = unreachable, never a hang). It publishes:
- reachable → `BackendStatusEvent { backend: RemoteGpu, healthy: true, degraded: false }` (🟢);
- unreachable → `BackendStatusEvent { backend: LocalCpu, healthy: true, degraded: true }` (🟡).
It publishes on transition AND on an initial tick, and de-dups (only re-emit on
change) to keep the channel quiet. This is the on-device mirror of TASK-10's
`spawn_periodic_health_probe`, emitting the same `BackendStatusEvent` type.

### D3 — `nexacore-ui::StatusBar` widget

A new `nexacore-ui` widget `StatusBar` (a reserved full-width bar): renders a
filled state indicator (theme `success`/sage when `backend==RemoteGpu &&
!degraded`; theme `accent`/brick or amber when `degraded`/`LocalCpu`) + a label
("AI: GPU — 127.0.0.1 gemma4" / "AI: CPU (degraded — Ollama unreachable)").
It holds a `BackendState` updated by `apply(event: BackendStatusEvent)`; an
undecodable/garbage event is simply NOT applied (the display drops a decode
error) so a malformed message can never crash or corrupt the bar. The
endpoint/model strings are static brand constants the bar knows (the wire event
stays the minimal `{backend,healthy,degraded}` — no wire change). Unit tests:
`Gpu→Cpu→Gpu` transitions flip the rendered colour/label; a malformed event is
ignored.

### D4 — Display integration (reserved bar surface)

The display task (`nexacore-ui-demo-image`) `NetLookup`s `ai_status` at startup
(retrying a bounded number of times — the runtime registers it slightly later),
reserves a bar region (e.g. a 28 px strip at the top of its window or screen),
renders the `StatusBar` there, and each frame drains the `ai_status` channel:
on a decoded `BackendStatusEvent` it `apply`s it and re-renders just the bar
(damage-tracked). If `NetLookup` never resolves (runtime absent), the bar shows
"AI: status unavailable" and the rest of the UI works.

### D5 — Hardware verification

the test VM: with Ollama up the bar shows GPU/🟢; **stopping Ollama on the GPU host**
makes the next probe tick (within a few seconds) publish LocalCpu/degraded →
the bar flips to CPU/🟡; restarting Ollama flips it back to 🟢. Serial capture +
annotated screenshots of both states.

## Alternatives considered

- **Publish status only per client request** — rejected (D2): the bar would be
  stale until the next AI request; a periodic probe makes it a real,
  always-current status bar and makes the failover test deterministic (no need
  to script a post-failover client request).
- **Kernel deposits the status channel id** (like the TASK-18 input channel) —
  rejected: `NetRegister`/`NetLookup` already exists for exactly this (the
  runtime uses it for `ai`/`ai_reply`); reusing it avoids a kernel change.
- **Extend `BackendStatusEvent` with endpoint/model fields** — deferred: the
  endpoint/model are fixed brand constants the bar already knows; widening the
  wire type churns existing TASK-10 tests for no behavioural gain now. The
  "ultimo failover" detail is the bar's last-transition state.
- **Emoji badge** — not possible with `font8x8`; a coloured indicator + text is
  the equivalent and theme-driven.

## Consequences

- New `nexacore-ui::StatusBar` widget + unit tests (transitions, malformed-event
  tolerance).
- `nexacore-runtime-image`: an `ai_status` channel (`NetRegister`) + a periodic
  Ollama reachability probe publishing `BackendStatusEvent` on transition.
- `nexacore-ui-demo-image`: `NetLookup("ai_status")` + drain + the reserved status
  bar.
- VM-103 failover verification (stop/start Ollama → 🟡/🟢).
- `todo-desktop.md` M3 checked — M3 (userspace desktop DE-C1..C6) complete.
- The richer status detail (per-model, latency, history) and the full
  `BackendRouter` health hysteresis in the image are post-M3 polish.

## Verification appendix — TASK-21 CLOSED (2026-06-08)

Implemented (StatusBar widget, runtime publish, display subscribe — agent team)
and **hardware-verified on the test VM**, zero #PF. Closes M3.

`nexacore-ui::StatusBar` host tests (20 unit + 32 doctests): `Gpu→Cpu→Gpu`
transitions (degraded wins over RemoteGpu), `apply` total over all
backend×healthy×degraded combinations (never panics), render colour reflects
state (sage / brick / muted), and off-canvas/zero-rect render safety.

the test VM (full pipeline: runtime periodic Ollama `/api/tags` probe →
`BackendStatusEvent` → `NetRegister`'d `ai_status` channel → display
`NetLookup` + drain → StatusBar; serial + 2 screendumps):

```
[ai-svc] ai_status channel registered id=0x..
[nexacore-ui-demo] ai_status channel=0x..        # NetLookup resolved
[ai-svc] status -> GPU                         # probe: Ollama reachable
[nexacore-ui-demo] status -> GPU                   # display applied -> badge
   ( backend made unreachable )
[ai-svc] status -> CPU(degraded)               # next probe: unreachable
[nexacore-ui-demo] status -> CPU(degraded)         # badge flips
```

Screenshots: (1) **GPU** — a sage-green indicator + "AI: GPU  127.0.0.1
gemma4:latest"; (2) **CPU degraded** — a brick-red indicator + "AI: CPU
(degraded - Ollama unreachable)". Both above the nexacore-ui demo widgets. The
badge transitions automatically on the probe's next tick (no client AI request
needed). Restoring reachability flips it back to GPU.

**Failover method note (infra safety):** the unreachable condition was induced
by pointing the runtime's probe `CONNECT_ADDR` at a closed port on the live
host (a throwaway build), NOT by stopping the shared Ollama service — the
auto-mode guard correctly declined to disrupt shared infrastructure. The
exercised code path (probe gets no HTTP response → publishes
`LocalCpu/degraded` → display applies → badge flips brick) is IDENTICAL to a
real Ollama stop. The committed code targets the real endpoint
(`127.0.0.1:11434`), re-verified GPU after reverting the simulation.
