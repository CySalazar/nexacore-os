# ADR-0030: `OllamaProvider` — HTTP Protocol/Transport Seam (TASK-09, DE-G2)

**Status:** Accepted
**Date:** 2026-06-06
**Deciders:** cySalazar
**Refs:** PLAN.md TASK-09, TASK-08 (ADR context: `provider` module / `InferenceProvider`),
TASK-05 (nexacore-net socket chain), TASK-11 (syscall AI → runtime → provider wiring),
`crates/nexacore-runtime/src/provider/ollama.rs`, `crates/nexacore-cmd-curl`

## Context

TASK-09 (DE-G2) requires the `RemoteGpu` backend: a minimal HTTP/1.1 client
speaking the Ollama API (`/api/generate`, `/api/chat`, `/api/embeddings`,
`/api/tags`) against configured endpoints (LAN primary, Tailscale fallback),
implementing the `InferenceProvider` trait from TASK-08 so the
`BackendRouter` can route Tier-0 traffic to a user-owned GPU box.

The PLAN names "socket API di `nexacore-net` (la catena provata in TASK-05)" as
the transport. But the runtime service today builds and tests on the **host**
(`std`/`tokio`); the Ring 3 in-OS binding of the runtime is exactly the
integration work of TASK-11, which is out of TASK-09's scope. Implementing
the provider *directly* on `nexacore-usys` NET syscalls would make it untestable
on the host (no mock seam, no CI coverage) and would couple protocol logic to
a transport that cannot run where the test suite runs.

A second tension: `nexacore-cmd-curl` already contains a correct, fuzz-hardened,
`no_std` HTTP/1.1 request builder and response parser. PLAN explicitly asks
to "preferire riuso a duplicazione".

## Decision

Split **protocol** from **transport** with a one-method async trait seam:

```rust
#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn round_trip(&self, host: &str, port: u16,
                        request: &[u8], max_response_bytes: usize)
        -> Result<Vec<u8>, ProviderError>;
}
```

- **Protocol layer** (`OllamaProvider<T: HttpTransport>`): request shaping
  via `nexacore_cmd_curl::build_request`, response parsing via
  `nexacore_cmd_curl::parse_response` (reuse, not duplication), JSON
  marshalling (`serde_json` — Ollama's boundary is JSON, not postcard),
  ordered endpoint failover (LAN → Tailscale) on *retriable* errors only,
  and NDJSON-tolerant body decoding (`fold_ndjson`: single-object fast
  path, line-delimited fallback) so a server that streams anyway parses
  correctly.
- **Transport layer**: `TokioTcpTransport` (host build + integration
  tests; connect/read time-bounded, reads capped at `max_response_bytes`
  *before* buffering) and an in-memory `MockTransport` for unit tests. The
  future `nexacore-usys`-backed transport for Ring 3 (TASK-11) implements the
  same trait; the provider module is identical across all three.

Configuration (`OllamaConfig`) carries endpoints, model, and the response
cap; nothing is hard-coded in the provider. `dev_default()` is a labelled
convenience constructor for the dev topology (LAN `127.0.0.1:11434`,
Tailscale `ai-backend.internal:11434`, `gemma4:latest`), not a default the
provider falls back to silently.

Error taxonomy maps onto the TASK-08 retriability contract:

| Condition | Error | Retriable → next endpoint? |
|---|---|---|
| connect refused / timeout | `Unavailable` | yes |
| mid-request I/O failure | `Transport` | yes |
| response > cap, non-2xx, bad JSON/HTTP | `Backend` | no (server answered; another endpoint won't help) |

The live test against the real dev Ollama (LXC 101) is feature-gated
(`ollama-integration-tests`, off by default and in CI) because it requires
reachable dev infrastructure; a loopback `tokio` TCP mock server exercises
the *real* `TokioTcpTransport` end-to-end on every `cargo test`.

## Alternatives Considered

- **Implement directly on `nexacore-usys` NET syscalls:** matches the PLAN's
  letter but cannot run on the host where tests and CI run; the provider
  would land untested until TASK-11. Rejected — the trait seam delivers the
  same end state (TASK-11 supplies the `nexacore-usys` transport) with full test
  coverage now.
- **Use a full HTTP client crate (reqwest/hyper):** pulls a large
  dependency tree (TLS stacks, HTTP/2) into a security-audited workspace
  for 4 fixed plaintext endpoints on a private network, and none of it can
  follow the provider into Ring 3. Rejected — `nexacore-cmd-curl` is already
  in-tree, fuzzed, and `no_std`.
- **Duplicate a small HTTP codec inside the provider:** violates the PLAN's
  explicit reuse instruction and forks the fuzz surface. Rejected.
- **Streaming (`stream:true`) with incremental chunk delivery:** the
  `InferenceProvider` trait (TASK-08) is request/response; token streaming
  to the UI is a later concern (TASK-21 consumes backend *status* events,
  not token streams). The provider requests `stream:false` but still
  *parses* NDJSON defensively. Revisit when a streaming-capable trait
  method exists.

## Consequences

- TASK-11 binds the provider into Ring 3 by writing one `HttpTransport`
  impl over `nexacore-usys`; no change to protocol logic or tests.
- TASK-10's health-checker reuses `OllamaProvider::health` /
  `list_models` (`GET /api/tags`) as its probe primitive.
- The response cap (`DEFAULT_MAX_RESPONSE_BYTES`, 8 MiB) bounds every
  read from the untrusted network *before* allocation; oversize is a
  terminal error, not a retry storm.
- `serde_json` enters `nexacore-runtime`'s dependency set, justified and
  scoped to the Ollama JSON boundary (the NexaCore wire format remains
  postcard).
- Tests added: 14 unit (mock transport: shaping, NDJSON multi-chunk,
  5xx/malformed/oversize/refused, LAN→Tailscale failover), 4 loopback
  integration (real `TokioTcpTransport` against a throwaway listener),
  1 feature-gated live test (real Ollama `GET /api/tags` → 200 +
  `gemma4:latest`, verified green on the dev network on 2026-06-06).
