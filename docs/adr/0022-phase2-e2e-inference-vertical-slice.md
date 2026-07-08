# ADR-0022: Phase 2 E2E Inference Vertical Slice

**Status:** Accepted
**Date:** 2026-05-24
**Deciders:** cySalazar

## Context

Phase 2 Sprint 7 requires a working end-to-end inference pipeline: text input is
tokenized, a model is loaded from the filesystem, a transformer forward pass
produces logits, and those logits are decoded back to text. The three prior
sprints established the foundation (HAL tensor dispatch, GGUF parser,
ModelRegistry, AI syscall surface, agent architecture, NCFS CRUD) but no
single code path exercised the full chain.

## Decision

Implement four parallel streams that together form a vertical slice:

1. **Transformer inference engine** (`nexacore-hal::transformer`): 5 new `TensorOp`
   variants (Transpose, GeLU, Scale, Concat, RmsNorm) + a composable forward
   pass (`transformer_forward`) that chains embedding lookup, multi-head
   attention with per-head sequential processing, SwiGLU FFN, and RMSNorm
   residual blocks.

2. **GGUF tensor loading** (`nexacore-runtime::tensor_loader`, `model_loader`):
   extract raw tensor bytes from a GGUF data blob, dequantize F16/BF16 to F32
   (quantized types produce zero-filled stubs), and wire the read path through
   NCFS `read_file`.

3. **BPE tokenizer** (`nexacore-runtime::bpe`): byte-level BPE with O(n*m)
   priority-ordered merge algorithm, 256 single-byte base tokens, encode/decode
   round-trip guarantee for arbitrary UTF-8, special tokens (BOS/EOS/PAD/UNK).

4. **E2E integration test**: exercises tokenize -> load from NCFS -> forward
   pass -> greedy argmax decode in a single `#[tokio::test]`.

## Alternatives Considered

- **External tokenizer crate** (tiktoken-rs, tokenizers): rejected due to heavy
  transitive dependency trees and Python runtime assumptions that conflict with
  the NexaCore OS minimal-dependency policy.
- **Batched matmul op**: deferred to Phase 4; sequential per-head processing is
  correct and sufficient for Phase 2 proof-of-concept.
- **Quantized tensor dequantization**: full Q4_K/Q8_0 dequantization is Phase 4
  scope; Phase 2 returns zero-filled F32 buffers for quantized dtypes so the
  pipeline completes without errors.

## Consequences

- The inference pipeline is testable end-to-end without external model files.
- The transformer forward pass is O(n^2 * d) per layer, acceptable for small
  models (<1B params) on CPU.
- Real model inference with quantized weights requires Phase 4 dequantization.
