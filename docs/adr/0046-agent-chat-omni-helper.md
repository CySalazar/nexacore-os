# ADR-0046: Agent Chat (NexaCore Helper) (TASK-24, DE-D5) — closes M4

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-24
**Refs:** PLAN.md TASK-24 (DE-D5, M4), ADR-0045 (file manager/Settings, TASK-23),
ADR-0043 (AI status bar, TASK-21), ADR-0042 (`nexacore-ui`), ADR-0035/0032 (AI
syscall relay, TASK-11/13), `nexacore_types::ai`

## Context

TASK-24 closes M4 with a conversational **chat app** ("NexaCore Helper"): message
history, response streaming, and a per-message backend badge (GPU/CPU +
latency). It is the desktop face of the TASK-11/13 AI relay.

Recon (file:line):
- Ring-3 apps invoke the agent via `AiInvoke (80)`:
  `syscall(80, model_id_ptr, model_id_len, prompt_ptr, prompt_len, out_ptr,
  out_cap) -> (rax = out_len, rdx = errno)` — a SYNCHRONOUS, blocking relay
  (Ring 3 → kernel → runtime → RemoteGpu/LocalCpu router → answer). It returns
  the answer bytes in `out`; it does NOT return `backend_used` or `latency_us`
  (those stay inside the relay). `nexacore-aicheck-image` is the reference caller.
- `TimeMonotonicNanos (50)` gives a monotonic clock → the client measures
  per-message latency around the `AiInvoke` call.
- The TASK-21 `ai_status` channel (NetRegister `ai_status`, the runtime's
  periodic backend probe) already feeds `nexacore-apps-image`'s `StatusBar`, which
  exposes `.state() -> nexacore_ui::status_bar::BackendState` (Gpu/CpuDegraded/
  Unknown). That is the per-message backend signal (the syscall ABI carries no
  backend field).
- `nexacore-apps-image` is the display task (terminal, editor, file manager,
  Settings — 2×2 grid). One task owns the framebuffer.

## Decisions

### D1 — `nexacore-ui::chat`: host-testable conversation state

A new `nexacore-ui` module `chat`: `ChatRole { User, Assistant }`,
`ChatMessage { role, text: String, badge: Option<BackendState>, latency_ms:
Option<u32> }`, and `ChatState { messages: Vec<ChatMessage> }` with:
- `push_user(text)` — append a user turn.
- `begin_assistant()` — open an empty assistant turn (streaming target).
- `append_chunk(&str)` — append text to the open assistant turn (the streaming
  seam — incremental rendering).
- `finish_assistant(badge: BackendState, latency_ms: u32)` — stamp the open
  assistant turn with its backend badge + latency.
- bounded history (cap N turns; oldest dropped) so a long session can't grow
  unbounded.
This is the acceptance's unit-test surface (conversation state, incremental
chunk rendering, per-message badge for DIFFERENT backends in one session). It
reuses the TASK-21 `BackendState` for the badge (no new type).

### D2 — Chat app: a prominent window in `nexacore-apps-image`

A fifth `nexacore_display` window (large, centred, overlapping the 2×2 utility
grid; **Tab cycles** to it and the WM raises it to the front). It owns a
`ChatState` + an input line. On Enter: `push_user(line)`; read
`TimeMonotonicNanos`; `AiInvoke(80)` with the prompt (blocking); read the clock
again → `latency_ms`; `begin_assistant()` + render the answer via `append_chunk`
(progressive reveal, D3); `finish_assistant(bar.state(), latency_ms)`. The chat
reuses the app's existing `ai_status`-fed `StatusBar` for `bar.state()`.

### D3 — Streaming = progressive reveal (real token-streaming is a follow-up)

`AiInvoke(80)` is blocking and returns the WHOLE answer (no token stream on the
device ABI). The chat renders it **incrementally**: it reveals the answer in
chunks across frames (`append_chunk` + re-present + `task_yield`), giving a
streaming visual. `ChatState::append_chunk` is the seam a real streaming relay
(`SessionManager.stream`, TASK-11, host-side) drops into later. The ADR records
that on-device token streaming via the relay is the tracked follow-up.

### D4 — Per-message backend badge (GPU/CPU + latency)

When an answer completes, the chat stamps the message with `bar.state()`
(the live `ai_status`): `Gpu` → a sage "GPU" badge, `CpuDegraded` → a brick
"CPU" badge, plus the measured `latency_ms`. Because the badge is snapshotted
PER message, two messages in one session served while the backend differs carry
different badges — the acceptance's "badge corretto per backend diversi". The
unit test drives `finish_assistant` with different `BackendState`s and asserts
each message keeps its own badge.

### D5 — Failover demonstration (infra-safe)

Live mid-conversation failover needs the backend to become unreachable mid-
session; stopping the shared Ollama is declined (infra safety, per TASK-21).
Instead the failover is shown config-driven (ADR-0045): a session with the
default endpoint answers via RemoteGpu with **GPU** badges; pointing the runtime
at a closed port (Settings → `/ai.cfg` → reboot) makes the probe report
unreachable and the relay fall back to LocalCpu, so the SAME chat then shows
**CPU** badges. The exercised badge path (response arrives → `bar.state()` →
GPU/CPU) is identical to a live failover. The unit test covers the in-session
backend-change badge directly.

## Alternatives considered

- **Extend the `AiInvoke` ABI to return `backend_used` + `latency_us`** —
  deferred: `latency` is measured client-side via `TimeMonotonicNanos` and the
  backend comes from `ai_status`, so no kernel/ABI change is needed for TASK-24.
- **A separate chat-only display image** — rejected: one display task owns the
  framebuffer; the chat joins `nexacore-apps-image` so the whole desktop (DE-D)
  ships in one boot.
- **Real on-device token streaming** — deferred (D3): the relay returns whole
  answers; progressive reveal gives the UX now and `append_chunk` is the seam.
- **Persisting chat history to NCFS** — out of scope per the PLAN (in-memory
  history); a follow-up can serialize `ChatState` via the FS service.

## Consequences

- New `nexacore-ui::chat` module (`ChatState`/`ChatMessage`) + unit tests
  (conversation state, incremental chunks, per-message badge across backends).
- `nexacore-apps-image`: a chat window using `AiInvoke(80)` + `TimeMonotonicNanos(50)`
  + the existing `ai_status` `StatusBar`; progressive-reveal rendering.
- VM-103: a real multi-turn GPU conversation (GPU badges); a config-driven CPU
  session (CPU badges) demonstrating the failover badge.
- `todo-desktop.md` M4 checked — M4 (native apps DE-D1..D5) complete.
- On-device token streaming + chat-history persistence are tracked follow-ups.

## Verification appendix — TASK-24 CLOSED (2026-06-08)

Implemented (nexacore-ui::chat + chat window — agent team) and **hardware-verified
on the test VM**, zero #PF, **closing M4**.

Host tests: `nexacore-ui::chat` (19 unit + doctests) — conversation state,
incremental `append_chunk` streaming, **per-message badge across backends in one
session** (Gpu then CpuDegraded each keep their own badge), bounded history,
`render_lines` tagging, text cap. All pass.

the test VM (`nexacore-apps-image`: 5-window grid, "NexaCore Helper" chat prominent + focused;
serial + 3 screendumps):
- **Multi-turn via GPU:** `> hello` → `[GPU 1000ms] Hello! I'm here to help you
  with anything you need. How can I help you today?` (real Ollama answer); a
  second turn `> ok` → `[GPU 1000ms]` — both served `backend_used=RemoteGpu`,
  conversation history retained, per-message **`[GPU <lat>ms]`** badge.
- **Failover → CPU badge:** Settings set the endpoint to a closed port
  (`127.0.0.1:11435`) → `/ai.cfg` → reboot → the runtime read it
  (`AI config: 127.0.0.1:11435`), the boot probe → `status -> CPU(degraded)`,
  and `> hi` → `remote unavailable (connect) -> LocalCpu fallback` →
  `backend_used=LocalCpu` → **`[CPU 0ms] dddd`** (the LocalCpu fixture's golden
  output) with a brick **`[CPU]`** badge. The next message after the backend
  became unavailable shows CPU — the acceptance's failover badge.

### Deep prerequisite fix: the AI RemoteGpu path was broken (nexacore-net OOM)

Bringing the chat up surfaced that the runtime's **RemoteGpu generate path
hung** (and so did the M1 `aicheck` self-test) — a regression latent since M1,
undetected because TASK-21/23 only exercised the status PROBE, never a real
generation, on hardware. Root-caused by tcpdump on the Ollama host: Ollama's
response (after the ~5.6 s gemma4:26b inference, with a coalesced FIN) reached
the runtime but was **never ACKed**, so Ollama retransmitted forever and
`NetRecv` never returned. The TCP stack is the Ring-3 `nexacore-net` service (kernel
`net_recv` relays to it). `nexacore-net-image` used a **non-freeing bump allocator**
and leaked ~600 B per `NetRecv`; the runtime polls `NetRecv` thousands of times
during the inference delay, exhausting nexacore-net's 512 KiB heap (~870 recvs) →
**nexacore-net OOM-panicked and died** mid-request → the late segment was never
ingested/ACKed. The probe survived only because it returns on the first byte
(~1 recv). **This is the identical OOM the virtio-net driver image already hit
and fixed with a freeing slab allocator; nexacore-net never received the fix.**

Fixes:
1. **nexacore-net-image:** replaced the bump allocator with the proven two-class
   freeing **`SlabAllocator`** (64 B × 2048 / 4096 B × 96 = 512 KiB) ported from
   `nexacore-driver-net-virtio-image`. Every dropped per-recv `Vec` is now reclaimed
   → no leak → nexacore-net survives sustained polling. aicheck + the chat now
   complete via RemoteGpu.
2. **nexacore-runtime-image:** raised `PROBE_IDLE_INTERVAL` 500 → 4_000_000. Each
   status probe opens a fresh TCP connection; `nexacore-net` does not yet reclaim
   CLOSED connection state, so a ~1 s probe rate piled up ~40 connection blocks
   and OOM-killed nexacore-net after a couple of minutes. A large interval keeps a
   normal session well under that; the badge refreshes on the order of tens of
   seconds.

**Tracked follow-up:** `nexacore-net` should prune CLOSED connection state (free the
per-connection control block on close) so the probe interval can be tightened
again; on-device token streaming (vs the current progressive reveal) and
chat-history persistence remain follow-ups.
