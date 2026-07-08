# ADR-0020: Phase 2 Sprint 2 — End-to-End Inference Pipeline

| Field        | Value                                                |
|-------------|------------------------------------------------------|
| Status      | Accepted                                             |
| Date        | 2026-05-24                                           |
| Deciders    | cySalazar                                            |
| Supersedes  | —                                                    |
| Depends on  | ADR-0019 (Phase 2 entry rationale)                   |

## Context

Phase 2 Foundation (ADR-0019) established the runtime scaffold: `ModelRegistry`,
`InferencePipeline` stub, `TensorBackend` trait with zeroed `CpuBackend`, and
the `nexacore-tokenization` vault.  Sprint 2 must close the gap between scaffold
and functional AI by delivering a vertical slice: real tensor math, model
loading from a standard format, kernel-level AI entry points, and an E2E demo
that proves the full path works.

## Decision

Sprint 2 is organized as four parallel streams converging into a single
integration milestone:

### Stream 1 — Real tensor dispatch in CpuBackend

Replace the zeroed stubs in `CpuBackend::execute()` with correct F32
implementations of: MatMul (naive row-major), Add, ReLU, Softmax (numerically
stable), LayerNorm, and EmbeddingLookup.  Two new `TensorOp` variants are
added (`LayerNorm`, `EmbeddingLookup`).  Non-F32 dtypes return
`DeviceFailure` until SIMD-optimized paths land in Phase 4.

**Rationale:** A correct naive kernel is prerequisite for any model execution.
SIMD optimization is deferred because it requires benchmark infrastructure
not yet in place; premature optimization would introduce `unsafe` blocks
without measurable payoff at this model scale (~1M params).

### Stream 2 — AI syscall surface (80–84)

Five new `SyscallNumber` variants (`AiInvoke=80`, `AiStream=81`,
`AiEmbed=82`, `AiClassify=83`, `AiTranscribe=84`) are added to the kernel
dispatcher.  Phase 2 Sprint 2 handlers return `ENOSYS`; the IPC relay wiring
is deferred to Sprint 3 when the runtime's IPC service loop is implemented.

**Rationale:** Defining the ABI surface now — even as stubs — locks the
syscall numbers into the stable ABI table and allows userspace tooling and
SDK crates to compile against the numbers before the runtime is fully wired.

### Stream 3 — GGUF model loader

A from-scratch GGUF v3 parser in `nexacore-runtime::gguf` reads metadata,
tensor info, and data offsets.  `ModelRegistry::load_from_bytes()` verifies
the BLAKE3 hash against the manifest, parses the GGUF header, and transitions
the model to `Loaded` state.

**Rationale:** GGUF is chosen over SafeTensors/ONNX because:
- It is the dominant format for quantized models in the open-source ecosystem.
- It is a single-file format (no sidecar metadata), simplifying the BLK
  channel read path.
- The specification is simple enough to implement without external crates,
  reducing the supply-chain attack surface.

Ed25519 signature verification on `ModelManifest` is enforced at registration
time (already implemented in Stream 1 of Phase 2 Foundation).  BLAKE3 hash
verification at load time closes the TOCTOU gap between registration and
actual binary consumption.

### Stream 4 — E2E toy model inference

A pre-baked ~1M param 2-layer MLP is serialized as GGUF, loaded via the
model registry, and served through the inference pipeline using real tensor
dispatch.  The demo validates the full vertical slice on QEMU.

**Alternatives considered:**

| Alternative                | Rejected because                              |
|---------------------------|-----------------------------------------------|
| Candle/tch backend         | Heavy dependency; pulls in libtorch C++ bindings — unacceptable for `no_std` trajectory |
| SafeTensors first          | Requires sidecar config.json; GGUF is self-contained |
| Skip AI syscalls           | Would defer ABI surface to Sprint 3, risking renumbering conflicts with other NCIPs |
| Real IPC wiring in Sprint 2 | Scope creep; stub → relay is a clean two-step |

## Consequences

- **Positive:** After Sprint 2, NexaCore OS can execute a real (toy) model
  end-to-end — the first time inference runs on the kernel.
- **Positive:** Syscall numbers 80–84 are locked, unblocking SDK development.
- **Negative:** Tensor dispatch is naive O(n^3) MatMul.  Acceptable for ~1M
  params; must be replaced with SIMD paths before any production model lands.
- **Negative:** GGUF parser supports only F32 tensors in Sprint 2.  Quantized
  types (Q4_0, Q8_0, etc.) require dequantization kernels in Phase 4.
- **Risk:** AI syscalls returning ENOSYS may confuse early SDK consumers.
  Mitigated by documenting the stub status in the NCIP and SDK header comments.
