# ADR-0032: AI Syscall → Runtime Wiring — Relay, Wire Types, Service Endpoint (TASK-11, DE-G6)

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar
**Refs:** PLAN.md TASK-11, Sprint 11.a (`SessionManager`, `AiIpcRelay`),
TASK-08/09/10 (BackendRouter / OllamaProvider / health+audit, ADR-0030/0031),
NCIP-026 WI-4b (uaccess), `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs`
(`ai_handlers`), `crates/nexacore-runtime/src/relay.rs` (`ServingRelay`),
`crates/nexacore-types/src/ai.rs`, `crates/nexacore-runtime-image`,
`crates/nexacore-aicheck-image`, `crates/nexacore-usys/src/ai.rs`

## Context

TASK-11 closes Sprint 11.b: the kernel's AI syscalls (80–84, ENOSYS
scaffolds until now) must reach the runtime serving stack. Constraints:

- The proven IPC pattern is the NET relay's **two-channel synchronous
  rendezvous** (request channel + dedicated reply channel; the caller
  parks `BlockedOnIpc`).
- User memory is touched **only** through the `uaccess` layer (SMAP +
  live page-table probe, WI-4b): a bad pointer is an errno, never a
  kernel #PF.
- Payloads are bounded by the IPC `MAX_PAYLOAD = 4096`.
- `nexacore-runtime` (the serving engine: `SessionManager` +
  `BackendRouter`) is a **std/tokio crate** — it cannot run on
  `x86_64-unknown-none` Ring 3 today.

## Decision

### 1. Wire types move to `nexacore-types::ai`

`AiSyscallRequest`/`AiSyscallResponse`/`AiSyscallNumber` (Sprint 11.a,
previously private to `nexacore-runtime::relay`) move to `nexacore-types::ai`
(no_std, postcard) so the kernel and the Ring 3 service image share
them; `nexacore-runtime` re-exports them (same pattern as `BackendKind`,
ADR-0031). The request gains a `capability: Vec<u8>` field — the
session-capability bytes the serving layer gates on. `AI_MAX_PAYLOAD =
4096` is the shared bound, enforced by the kernel on copy-in AND by the
service on decode (defence in depth — each side treats the other as
untrusted input).

### 2. Kernel relay (`ai_handlers::ai_relay`)

`AiInvoke`/`AiEmbed`/`AiClassify`/`AiTranscribe` (buffer ABI:
`model_id_ptr, model_id_len=16, input_ptr, input_len, output_ptr,
output_cap` → `(output_len, errno)`) relay over the rendezvous:
uaccess copy-in → postcard encode (encoded form bounded ≤ 4096 →
EINVAL) → send on `"ai"` → park on `"ai_reply"` → decode → uaccess
copy-out (response > `output_cap` → ENOSPC; unwritable buffer →
EFAULT). Service-down (names unregistered) → ENOENT, distinct from the
host-build ENOSYS. The channel names live in the **NET registry**
(`NetRegister`), deliberately reused: it is a generic name→channel-pair
table, and a parallel "AI registry" would duplicate ~100 lines of
kernel code for zero isolation gain (the registry has no per-name
authorization today for `"stack"` either — hardening it is one shared
follow-up, not two).

**`AiStream` keeps ENOSYS**: its ABI is channel-based (no output
buffer); it lands with the streaming-delivery design (the provider
trait is request/response, ADR-0030). The runtime's `ServingRelay`
already serves `Stream` requests single-shot so the service side is
ready.

**Capability placeholder:** the kernel fills a minimal well-formed
token (`[0x01]`) for Ring 3 callers. The gating CONTRACT
(`SessionCapability` well-formedness) is enforced service-side and
exercised end-to-end (host negative tests + the wire field); real
per-process capability material is TASK-S11.E — until then every Ring 3
caller is equally authorized, which matches the current single-user
boot reality and is honest about where the trust boundary sits.

### 3. Runtime dispatcher: `ServingRelay` (new), `AiIpcRelay` kept

`ServingRelay` is the kernel-IPC dispatcher: capability gating →
`SessionManager::open_session` → `BackendRouter::*_with_ctx` (the
TASK-10 audited path: exactly one `AuditRecord` per request,
`backend_used` + latency) → `close_session` on every path (the session
table is left as found). Invoke/Stream → `generate`; Embed →
`embeddings` (postcard `Vec<f32>` out); Classify/Transcribe →
structured "not yet supported". Non-UTF-8 input, oversize payloads,
malformed capabilities → structured errors (kernel maps to errnos).
Audit timestamps come from an **injected clock**
(`ServingRelay::with_clock`, default `0`): the workspace bans wall-clock
`now` (attestable clock service pending), and the relay records the
value without reading it for control flow.

`AiIpcRelay` (Sprint 11.a → `InferencePipeline`) is **kept** as the
`OrchestratorBridge`'s in-process path (agent intents, PII pipeline,
NCIP-022); re-pointing the bridge at `ServingRelay` belongs to TASK-13
(nexacore-agent ↔ runtime), not to the syscall wiring. One wire type, two
documented dispatchers, no behavioral overlap.

### 4. Ring 3 endpoint: `nexacore-runtime-image` with a mock provider

A new no_std image registers `"ai"`/`"ai_reply"` and serves the wire
contract with a deterministic mock (Invoke/Stream → `MOCK:`+input echo;
Embed → `[1.0, 2.0]`; same capability gating as the host engine). The
REAL engine cannot run in-image yet (std/tokio); the host test-suite
(`tests/e2e_task11_relay.rs`) proves `ServingRelay` against the **same
bytes** the kernel moves, so the wire contract is pinned on both sides.
Binding the full engine in-image (or bridging to the host engine over
the network) is TASK-13's M1 scope. PLAN's "risposta dal provider mock
o remoto" acceptance is met with the mock on hardware + the real
provider host-side.

### 5. Self-test client + usys wrappers

`nexacore-aicheck-image` proves on hardware: AiInvoke round-trip (prints
the `MOCK:` echo), **EFAULT negative** (unmapped input pointer → errno,
`Page Fault = 0` — the WI-4b probe demonstrably prevents the kernel
fault), **ENOSPC negative** (1-byte output buffer). It retries ENOENT
with a bounded budget so spawn ordering is not load-bearing.
`nexacore-usys::ai` adds the documented wrapper surface (`ai_invoke`/
`ai_embed`, bare-metal-gated) for SDK consumers (TASK-13).

### 6. Boot wiring

`/bin/nexacore-runtime` spawns at `System` priority (services win their
first slices to register — same rationale as nexacore-net);
`/bin/nexacore-aicheck` at `Background` (TASK-06 fairness guarantees its
pick). Both additive/best-effort in kmain and packed by
`build-shell-initramfs.sh`.

## Alternatives Considered

- **A dedicated AI channel registry in the kernel:** parallel
  name→channel table duplicating the NET registry for no isolation gain
  today. Rejected; per-name registration auth is a shared follow-up.
- **Running the full nexacore-runtime engine in Ring 3 now:** requires a
  no_std serving engine or an in-OS std runtime — neither exists;
  blocking TASK-11 on that inverts the plan's sequencing (TASK-13/M1).
  Rejected in favour of mock-on-HW + real-engine-on-host against the
  same pinned wire bytes.
- **Carrying the capability as a 7th syscall argument:** the SysV
  syscall ABI has exactly 6 argument registers and all are taken.
  A pointer-to-struct ABI redesign was rejected as churn before real
  capability material exists (TASK-S11.E will need an ABI decision
  anyway — token in the cap-deposit window vs per-call pointer).
- **Response chunking for > 4096-byte outputs:** required eventually
  (PLAN names it), but the chunking protocol (correlation ids,
  per-chunk syscalls or a shared ring) deserves its own design; TASK-11
  returns clean `ENOSPC`/`EINVAL` at the bounds. Follow-up noted in
  PLAN's deviation log.
- **Rewriting `AiIpcRelay` in place instead of adding `ServingRelay`:**
  would force the OrchestratorBridge (different consumer, different
  pipeline semantics — PII tokenisation, model registry) through the
  session/router path in the same change, coupling two migrations.
  Rejected; the bridge migration is TASK-13.

## Consequences

- The kernel's AI syscall surface is live end-to-end on hardware for
  the buffer-ABI calls; `AiStream` is the documented gap.
- TASK-12's `LocalCpuProvider` plugs into the same `ServingRelay` with
  zero relay changes; TASK-13 binds the real engine to the Ring 3
  endpoint and migrates the OrchestratorBridge.
- The audit pipeline (TASK-10) now fires for every kernel-relayed
  request — `backend_used` lands in the record from day one.
- Tests added: 10 `ServingRelay` unit tests (gating, bounds, UTF-8,
  per-syscall routing, audit exactly-one, session lifecycle), 5 wire
  E2E tests playing the kernel role byte-for-byte, 5 `nexacore-types::ai`
  wire tests (incl. pinned discriminants), 2 `nexacore-usys::ai` tests;
  hardware: `nexacore-aicheck` (positive + EFAULT + ENOSPC, `Page Fault =
  0`).
