# ADR-0035: Agent→Runtime Wiring and the M1 Dual-Backend Smoke (TASK-13)

**Status:** Accepted
**Date:** 2026-06-07
**Deciders:** agent analysis under operator-approved PLAN.md TASK-13
**Refs:** PLAN.md TASK-13 (DE-G7 + DE-G9), NCIP-022 (five-agent architecture),
ADR-0032 (AI syscall relay), ADR-0033 (LocalCpuProvider degraded contract),
ADR-0034 (no_std engine port), `docs/plans/desktop-environment-the development plan` M1

## Context

TASK-13 closes M1: a user prompt must traverse the five-agent
architecture (NCIP-022) into the real runtime and come back with a real
answer, and the M1 smoke on the test VM must show, from Ring 3, the SAME
question served by Ollama (`backend_used = RemoteGpu`) and — with Ollama
stopped — by the on-device CPU engine (`backend_used = LocalCpu`).

Recon (agent-team, file:line evidence) established:

- `OrchestratorBridge::process_intent` (nexacore-runtime) is the prompt
  entry, but it dispatches through the legacy `AiIpcRelay` →
  `InferencePipeline::infer` STUB (empty output, `lib.rs:945`); the REAL
  path (`ServingRelay::dispatch` → `BackendRouter.generate_with_ctx`,
  TASK-11) already exists with identical signature.
- `nexacore-agent` (std/tokio, 331 tests) classifies and routes intents but
  never calls inference; `TaskAgent::handle_message` answers with a
  synthetic summary. `nexacore-sdk` is an empty 4-module scaffold.
- The wire type `AiSyscallResponse` has NO `backend_used` field; the
  kernel relay is a pass-through and PLAN expects "nessuna modifica
  kernel".
- The Ring 3 image has the real CPU engine (ADR-0034) but no network
  path; `nexacore-netcheck-image` proves the NET syscall TCP chain and
  `nexacore-cmd-curl` is a zero-dependency `no_std + alloc` HTTP/1.1 codec.
- The fixture tokenizer maps out-of-vocab bytes to `unk` (255), which
  faults at `EmbeddingLookup` against the 8-row table — arbitrary text
  CANNOT be served by the fixture model as-is.

## Decisions

### D1 — `IntentDispatcher` seam; the bridge defaults to the REAL path

New trait in `nexacore-runtime` (`async fn dispatch(&self, AiSyscallRequest)
-> AiSyscallResponse`), implemented by BOTH `AiIpcRelay` (legacy stub,
kept for its tests) and `ServingRelay` (real). `OrchestratorBridge`
becomes generic `OrchestratorBridge<D: IntentDispatcher = AiIpcRelay>` —
existing call sites compile unchanged; the agent path instantiates the
bridge over `ServingRelay` so prompts reach `BackendRouter` and the
audit trail (`backend_used`) for real.

### D2 — `RuntimeLink` injection point in `nexacore-agent`

New `nexacore-agent::runtime_link::RuntimeLink` trait (`async fn infer(
prompt, request_id) -> Result<String>`). `TaskAgent` gains an OPTIONAL
link (`with_runtime_link`); when present and the intent requires
inference, the Task agent's `OperationResult.summary` carries the real
model answer. Default `None` → behaviour byte-identical (the 331
existing tests must stay green). Security-mode semantics (NCIP-022) are
NOT moved: pre-auth/veto/autonomy clamps stay where they are.

### D3 — `nexacore-sdk` gets its first real surface

`nexacore_sdk::ai`: re-exports + `ServingInvoker` (thin wrapper over
`ServingRelay` + capability bytes). `nexacore_sdk::agent`: `BridgeLink`,
the `RuntimeLink` implementation that drives
`OrchestratorBridge<ServingRelay>` (PII preprocess → serving → PII
detokenize). The host E2E acceptance test (prompt → Orchestrator
classify → Task agent with `BridgeLink` → mock provider → answer) lives
in nexacore-sdk, where all three crates meet.

### D4 — Ring 3 on-device router with serial `backend_used` audit

`nexacore-runtime-image` gains a minimal backend router: try Ollama
(`POST /api/generate`, `stream:false`, LAN endpoint `127.0.0.1:11434`)
over the NET syscalls (netcheck's proven pattern: NetSocket/NetConnect/
NetSend/NetRecv+TaskYield with bounded budgets); on ANY failure
(connect/send/recv/HTTP≠200/parse) fall back to the embedded
`CpuEngine`. Reuse over duplication: HTTP framing via `nexacore-cmd-curl`
(`no_std`, zero deps); JSON via `serde_json` `default-features=false +
alloc` (network input is untrusted — no hand-rolled parser).

`backend_used` does NOT cross the syscall ABI (no wire/kernel change —
PLAN constraint): the image emits an audit line on COM1,
`[ai-svc] rid=<N> backend_used=RemoteGpu|LocalCpu`, which the smoke
captures verbatim. Host-side audit (`AuditRecord.backend_used`,
TASK-10) is unchanged and remains the structured source of truth for
std deployments. Carrying the field in `AiSyscallResponse` is deferred
to the TASK-21/TASK-24 UI work, which already has the
`BackendStatusEvent` stream for this purpose.

### D5 — Fixture fallback serves arbitrary text via in-vocab filtering

The Q8_0 fixture (vocab 8, `a..=h`) cannot tokenize arbitrary prompts
(out-of-vocab → `unk` → embedding fault). The image's LocalCpu fallback
therefore FILTERS the prompt to in-vocab bytes before encoding (e.g.
`"what is 2+2?"` → `"ha"`), falling back to the canonical probe `"ab"`
when the filter yields nothing, and logs the filtering explicitly
(`[ai-svc] fixture filter: ...`). This is the honest reading of the
degraded contract (plan §9, ADR-0033): the M1 fallback criterion proves
the CHAIN serves when the GPU is down — the fixture's linguistic
ability is explicitly out of scope until TASK-16 lands a real
quantised model. A host golden pins the filtered output so the the test VM
scenario B answer is predictable.

### D6 — `nexacore-aicheck` becomes the M1 client

The TASK-13-pre golden client is repurposed: prompt `"what is 2+2?"`,
assert transport success (errno 0, non-empty output) and PRINT the
answer — content is asserted by the serial capture, not the client
(scenario A's LLM text is non-deterministic). The engine golden
(`"ab"` → `"dddd"`) remains pinned host-side
(`engine::tests::golden_ab_to_dddd_via_sync_engine_surface`); it can no
longer be asserted on hardware because the router may legitimately
serve it from the GPU. EFAULT/ENOSPC negative probes stay.

## Alternatives considered

- **Add `backend_used` to `AiSyscallResponse`** — cleanest for clients,
  but a wire change recompiles the kernel relay and PLAN explicitly
  expects no kernel modification in TASK-13; the UI consumer (TASK-21)
  already has `BackendStatusEvent`. Deferred.
- **Run the agents in Ring 3 for the smoke** — nexacore-agent is std/tokio;
  porting it is M4+ scope (Agent Chat app). The PLAN criterion reads
  "da Ring 3, prompt reale": the Ring 3 boundary is the syscall client;
  the agent traversal is proven host-side by the acceptance test.
- **Byte→`id % 8` lossy mapping in the fallback tokenizer** — rejected:
  it fabricates tokens the tokenizer never produced; filtering keeps
  the REAL tokenizer/engine on a documented sub-alphabet.
- **Hand-rolled JSON extraction in the image** — rejected: Ollama's
  reply is untrusted network input; `serde_json` (alloc) is the
  bounded, fuzz-hardened parser already pinned at workspace level.

## Consequences

- The stub `InferencePipeline::infer` is no longer on the agent path
  (kept for its own tests/back-compat; retirement tracked for the
  Phase 2 gate, TASK-17).
- The image binary grows (~serde_json + HTTP path); heap budget stays
  512 KiB (per-request HTTP accumulator is a 16 KiB BSS buffer, not
  heap).
- The M1 smoke procedure gains an Ollama stop/start step on LXC 101
  (authorisation already granted).
- `nexacore-sdk` is no longer a scaffold; its API privacy posture follows
  the bridge (PII preprocess before serving).

## Status appendix 2 — ROOT CAUSE FOUND AND FIXED (2026-06-07, resumed)

The EINVAL heisenbug is closed. Per-branch diagnostics in the kernel
relay identified the failing branch as `EINVAL:input_oversize` with
`enoent_retries=1` — the client's SECOND AiInvoke arrived with a
corrupted `input_len`, despite the client passing a constant.

**Root cause (systemic, all five Ring 3 images):** the minimal
`task_yield()` asm stubs declared clobbers for ONLY `rcx`/`r11`, but
the kernel syscall entry SHUFFLES the argument registers
(`rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9`) and returns a value pair in
`rax`/`rdx` WITHOUT restoring them.  The compiler — entitled by the
declared clobber set — kept the NEXT syscall's arguments live in those
registers across the yield; the kernel destroyed them; the next
AiInvoke passed garbage.  Boot-timing dependence fully explained:
zero ENOENT retries → no yield between calls → no corruption
(the one successful boot); ≥1 retry → corruption (the failures).
The earlier `NetSend short write rax=0` under TCP-client concurrency
shares the same mechanism (corrupted send arguments after yields).

**Fixes landed:**
1. All five image `task_yield` stubs (`nexacore-aicheck`, `nexacore-runtime`,
   `nexacore-netcheck`, `nexacore-net`, `nexacore-driver-net-virtio` images) now
   issue TaskYield through each file's generic 6-argument stub, which
   declares the full clobber set.  (`TASK_EXIT` stubs are noreturn —
   unaffected.)
2. Kernel AI relay: channel lookup moved BEFORE all copies/allocations
   — the ENOENT retry path now performs ZERO heap allocations (the
   kernel heap is a never-freeing bump allocator; thousands of retries
   previously leaked ~200 B each).
3. Kernel AI relay: per-branch EINVAL/EIO serial diagnostics kept
   (error-path only, zero steady-state cost).

**Hardware verification:** scenario A now passes WITH a non-zero
ENOENT retry count (the previously-failing case):
`[aicheck] enoent_retries=0x1` → `[ai-svc] rid=0x1
backend_used=RemoteGpu` → `[aicheck] answer=4` → EFAULT/ENOSPC
negatives OK → `TASK-13 M1 E2E COMPLETE`.

## Status appendix 3 — M1 DUAL SMOKE COMPLETE (2026-06-07)

Both PLAN.md TASK-13 hardware scenarios verified on the test VM (serial
verbatim, zero #PF/PANIC in every capture):

- **Scenario A (Ollama UP, 3 passing boots incl. retry>0):**
  `[aicheck] enoent_retries=0x1` → `[ai-svc] rid=0x1
  backend_used=RemoteGpu` → `[aicheck] answer=4` →
  EFAULT/ENOSPC negatives OK → `TASK-13 M1 E2E COMPLETE`.
- **Scenario B (Ollama STOPPED on LXC 101, same question):**
  `[ai-svc] remote unavailable (connect) -> LocalCpu fallback` →
  `fixture filter: prompt reduced to in-vocab "ha"` →
  `rid=0x1 backend_used=LocalCpu` → `[aicheck] answer=dddd`
  (matches the pinned host golden) → `E2E COMPLETE`.
  Ollama restarted afterwards; a final boot re-verified scenario A
  (~10 s to completion).

**Known issue (pre-existing M0, OUT of TASK-13 scope, tracked in the
backlog):** intermittent virtio RX death at boot (~50% of rapid
qm stop/start cycles in this session): ARP requests transmit forever
with no reply processed; because nexacore-net's connect path has no
ARP/SYN timeout, a silently-dead network HANGS the caller (no RST →
no failover). Workaround: reboot. Fix belongs to the nexacore-net/virtio
RX bring-up (timeout + RX-ring investigation) — see todo-desktop
DE-F backlog entry added by TASK-13.

## Status appendix — hardware debugging record (2026-06-07)

DE-G7 (host) is COMPLETE and green (E2E acceptance in
`nexacore-sdk/tests/e2e_agent_chain.rs`; 4280 workspace tests; all gates
clean).  DE-G9 hardware verification is PARTIAL and the loop was
STOPPED under the 3-attempt safety rule:

- **Proven on the test VM** (capture `nexacore-103-task13-scenA4.log`): the FULL
  scenario A chain worked once end-to-end — `[ai-svc] rid=0x1
  backend_used=RemoteGpu` → `[aicheck] answer=4` → `M1 OK` (gemma4
  answered "what is 2+2?" from Ring 3 over syscall→IPC→NET→Ollama).
  Earlier runs also proved the LocalCpu failover chain end-to-end
  (`remote unavailable (send) → LocalCpu fallback → fixture filter
  "ha" → backend_used=LocalCpu → answer=dddd`).
- **Open bug**: boot-timing-dependent `EINVAL` from `AiInvoke` when the
  client's ENOENT retry loop starts BEFORE the service registers
  (2 of 3 final boots).  The new step-7 decode diagnostic did NOT fire,
  so the failing branch is pre-rendezvous (constant-argument
  validations — which contradicts their constancy) or an unlogged path;
  root cause NOT identified.  Fix attempts (all landed, all
  individually correct): (1) poll-send/send_all in both TCP clients
  (fixed netcheck's short-write); (2) `m0-netcheck` spawn re-gated
  (removes the M0 probe's TCP contention with the AI path — restores
  the documented default-off behaviour); (3) AI-relay reply-channel
  kind filter + decode diagnostics (defensive hardening of the
  rendezvous, correct regardless of root cause).
- **Next debugging steps** (for the resumed session): per-branch EINVAL
  diagnostics in `ai_handlers` (one serial tag per early-return),
  capture with the client retry loop instrumented (count attempts),
  inspect kernel allocator behaviour under thousands of ENOENT retries
  (each encodes a request Vec), and check the
  `lookup("ai")`-ok/`lookup("ai_reply")`-pending window.
