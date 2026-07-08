---
ncip: 9
title: nexacore-forge — On-Demand Rust → WASM/ELF Generation and Compilation Pipeline
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-12
updated: 2026-05-12
requires:
  - NCIP-Process-001
  - NCIP-Container-006
  - NCIP-Pkg-008
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

# NCIP-Forge-009 — `nexacore-forge`: On-Demand Generation and Compilation

## Abstract

This NCIP commits NexaCore OS to **`nexacore-forge`**, the integrated source-
generation + compilation + signing pipeline that lets NexaCore generate
small native or WASM applications on demand. Key properties:

- **Rust** as the canonical source language (alignment with workspace +
  type safety + memory safety).
- **`wasmtime` + `cranelift`** runtime + JIT path (fast compile <1s for
  micro-apps).
- **`rustc` + LLVM** AOT path for performance-critical long-lived apps.
- **LLM-assisted generation** with **static analysis + capability
  inference** before any execution.
- **TEE-bound ephemeral signing** for generated artifacts.
- **Mandatory user review** of generated source before first run.
- Output is a **valid `nexacore-pkg` package** that can be installed,
  audited, or published to `nexacore-market` like any other package.

## Motivation

The "NexaCore App Mesh" thesis (per `docs/02-architecture.md` § "NexaCore App
Mesh") requires that if no existing package satisfies a user need,
NexaCore can **generate one on demand**. This is unique to NexaCore among
mainstream OSes:

- Windows Copilot generates **scripts** (PowerShell snippets), not
  capability-bound apps.
- macOS Apple Intelligence does not generate apps.
- Linux has no OS-level generation.

The generation must satisfy three properties:

1. **Capability-safe**: generated code cannot exceed declared
   capabilities (static analysis enforces).
2. **User-reviewable**: source visible before run, mandatory on first
   run.
3. **Auditable**: every generated artifact is signed, CT-logged, and
   audit-trail-bound.

## Specification

### 1. Generation pipeline

```
User intent (text, file analysis, helper trigger)
       ↓
LLM (local Tier 0 default, mesh Tier 1 opt-in)
       ↓
Rust source code (target: WASM by default, ELF for opt-in long-lived)
       ↓
Static analysis (capability inference + safety check)
       ↓
Compilation
   • Default fast path: Cranelift → WASM module (<1s for ≤500 LoC)
   • Performance path: rustc + LLVM → ELF nativo (10-30s typical)
       ↓
TEE-bound ephemeral signing (session key sealed to local TEE)
       ↓
Package manifest with declared capability set
       ↓
User review (mandatory first run) → approval → execute
```

### 2. Language and target choices

| Choice | Rationale |
|---|---|
| **Rust** as source language | Same language as the OS itself, type-safe, memory-safe by construction. LLM models (Llama 4, Phi-4, Gemma 3, GPT-OSS) are well-tuned on Rust as of 2026. |
| **WASM** as default compilation target | Fast compile (<1s via Cranelift), sandboxable by Agent runtime (NCIP-Container-006 § 8), portable across ISA when ARM lands (v1.1+). |
| **ELF** as opt-in target | For long-lived performance-critical apps (e.g. media transcoders, AI inference pipelines). Slower compile, faster runtime. |
| **No Python in `nexacore-forge`** | Python is supported as a runtime *inside containers* (NexaCoreContainer + python image), not as a generation target. Avoids dual-runtime burden inside Forge. |

### 3. Static analysis and capability inference

After source generation, before compilation:

1. **Parse the Rust source** (via `syn`).
2. **Identify syscall usage** (every `nexacore_sdk::*` call maps to a
   capability). Build a "declared capability set" from the source.
3. **Conservative analysis**: assume any I/O call requires the
   corresponding capability; refuse if unclear.
4. **Pattern matching against known dangerous idioms**: file deletion,
   network egress to new hosts, etc. flagged as "user-must-approve".
5. **Compare with user-stated intent**: if intent was "calculator with
   graph" but source calls `net:outbound:huggingface.co:443`, refuse.

### 4. TEE-bound ephemeral signing

Each generated binary:

- Signed with an **ephemeral key sealed to the local TEE
  measurement** (via `nexacore-tee::SealPolicy`).
- Signature includes: `{source-hash, capability-set,
  generation-timestamp, llm-model-id, helper-decision-id}`.
- Logged to local audit log (per NCIP-Crypto-002 CT log infrastructure;
  scope = local audit, not network-published unless user explicitly
  shares).
- Revocable: user can revoke an ephemeral key at any time; all
  artifacts signed by it become unloadable.

### 5. Mandatory user review

On the first run of a generated artifact, the user sees:
- The **plain-language explanation** of what the code does.
- The **source code** (collapsible, viewable).
- The **declared capability set** (the user has already approved it
  during the Helper flow, this is a re-confirmation).
- An option to **edit the source** before running.

Subsequent runs skip the source-display step (already approved).

### 6. Generation cost controls

Generation is privacy-budget-significant:

- Local Tier-0 model: 5% of daily privacy budget per generation
  (configurable).
- Mesh Tier-1 model: 15% of daily privacy budget per generation
  (configurable).
- Cloud Tier-3 model: forbidden for generation by default (overridable
  per-context with explicit consent).

Hard cap: max 10 generations per day default (configurable). Prevents
runaway loops.

### 7. Reference implementation — `crates/nexacore-forge/`

```
crates/nexacore-forge/
├── Cargo.toml
├── src/
│   ├── lib.rs              # public surface
│   ├── llm/
│   │   ├── bridge.rs       # nexacore-runtime AI bridge
│   │   ├── tier0.rs        # local model invocation
│   │   └── prompt.rs       # generation prompt templates
│   ├── analyze.rs          # static analysis + capability inference
│   ├── compile/
│   │   ├── cranelift.rs    # fast WASM path
│   │   └── llvm.rs         # rustc AOT path
│   ├── sign.rs             # TEE-bound ephemeral signing
│   ├── manifest.rs         # produce nexacore-pkg-compatible manifest
│   └── cli/
│       ├── generate.rs
│       └── inspect.rs
└── tests/
    ├── capability_inference.rs
    ├── static_analysis_rejection.rs
    └── round_trip_generation.rs
```

Estimated effort: **12-18 engineer-months** for v0.1 (production-grade
generation + analysis + signing). Cranelift / wasmtime / rustc are all
existing components — the integration is the work.

## Rationale

### Why Rust as the only source language?

Single source-language simplifies static analysis (one parser, one
type system). Multi-language would require parsers, security models,
and capability inference per language — multiplying the audit
surface. Python remains available *inside containers* (NCIP-Container-006).

### Why mandatory user source review on first run?

Trust. Even with static analysis, an LLM-generated app is a fresh
binary the user has not seen. Forcing first-run source review:
- Builds user familiarity with what NexaCore generates over time
- Catches LLM hallucinations the analysis missed
- Provides an audit-trail breadcrumb

### Why ephemeral TEE-bound signing rather than Stichting signing?

Generated apps are user-private by default. Stichting does not see them.
The ephemeral key is bound to the local TEE measurement; only the same
TEE on the same machine can verify; the user can revoke at any time.
If the user later wishes to share the generated app, they explicitly
publish to `nexacore-market` (a separate Foundation-mediated path).

## Backwards Compatibility

Not applicable.

## Test Cases

1. **Hello-world round-trip**: generate a "print hello" Rust binary
   from intent "say hello", static analysis OK, compile to WASM,
   sign, run — output matches.
2. **Capability inference enforcement**: generate code that opens
   a file, capability `fs:read:/path` inferred, user prompted at
   first run.
3. **Static analysis rejection**: LLM produces code that calls
   `unsafe { syscall(...) }` — analysis rejects, helper retries
   with a sandboxed prompt.
4. **Privacy budget gate**: 11th generation in a day refused with
   clear error.
5. **Source review skip on subsequent runs**: first run displays
   source, second run skips, audit log notes both runs.
6. **Edit before run**: user invokes "edit source" in review,
   modifies, helper re-runs static analysis, accepts new
   capability set or refuses.
7. **Ephemeral key revocation**: user revokes the session key,
   previously-generated binary refuses to run.

## Reference Implementation

To land before activation:
- `crates/nexacore-forge/` skeleton with the structure in §7.
- LLM bridge using `nexacore-runtime` (Phase 2 prerequisite).
- Static analysis using `syn` + a project-internal capability inference
  pass.
- Integration tests against a mock local LLM (deterministic outputs).

## Security Considerations

- **LLM prompt injection**: a malicious untrusted input could induce
  the LLM to generate dangerous code. Mitigation: prompt isolation
  (dual-LLM pattern per `docs/04-security-model.md`), static analysis
  refuses suspicious patterns, mandatory user review.
- **Compiler supply chain**: rustc and cranelift are TCB-extending.
  Mitigation: pin exact versions per `docs/09-tech-specifications.md`,
  reproducible builds for the toolchain itself.
- **Ephemeral key leakage**: if the TEE is compromised, ephemeral
  signing keys leak. Mitigation: short-TTL keys (24h default), per-
  user keys, revocation list.

## Privacy Considerations

- **Intent leakage to LLM**: the prompt sent to the LLM contains user
  intent which may reveal sensitive context. Mitigation: tokenization
  service applies to prompts (per `docs/04-security-model.md` § 2);
  Tier-0 local-only by default; Tier-1 mesh is opt-in.
- **Generated source contains user context**: source code may embed
  intent strings, paths, etc. The generated artifact stays in user-
  private storage; published artifacts (to nexacore-market) go through a
  user-initiated sanitization step.

## Future Work

- **NCIP-Forge-AOT-Wine-XXX** (Phase 6, referenced by NCIP-Container-006
  Future Work): AOT-Wine baking using Forge infrastructure for specific
  `.exe` → NexaCore ELF flow.
- **NCIP-Forge-MultiLang-XXX** (Phase 8+): TypeScript or Lua as
  alternative source languages once Rust-LLM-generation matures.
- **NCIP-Forge-Verified-XXX** (Phase 9+): formal verification of
  generated code via Prusti or Creusot for high-stakes apps.

## Copyright

CC0 1.0 Universal.
