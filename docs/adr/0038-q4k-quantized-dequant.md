# ADR-0038: Q4_K Dequantization for GGUF Quantized Inference (TASK-16)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-16
**Refs:** PLAN.md TASK-16 (Sprint 12), ADR-0033 (`LocalCpuProvider`, TASK-12),
ADR-0034 (no_std engine port, TASK-13-pre), llama.cpp `ggml-quants.c`
(`block_q4_K` / `dequantize_row_q4_K` / `get_scale_min_k4`)

## Context

TASK-16 extends `nexacore-runtime`'s CPU engine so the `LocalCpuProvider`
(TASK-12) can serve **real quantized GGUF models** on CPU. Recon
(agent-team, file:line) established the current state:

- The engine **dequantizes every weight tensor to f32 at load time**
  (`tensor_loader::dequantize_to_f32`) and runs a pure-f32 forward
  (`nexacore-hal::transformer`); there is no quantized-weight matmul on the
  hot path (`TensorOp::QuantizedMatMul` exists but is unused).
- Real dequant kernels already exist for **F32 / F16 / BF16 / I8 / Q8_0
  (int8) / Q4_0 (int4)** — bounds-checked, using `f16_bits_to_f32`. The
  Q8_0 path is exercised end-to-end by the `"ab"→"dddd"` golden
  (`engine.rs`, `fixture::build_synthetic_q8_0_gguf`).
- **Q4_K and the other k-quants are zeroed stubs** (`tensor_loader.rs`
  `_ =>` arm) and their byte-size is a 1-byte/element placeholder.
- The crate is `no_std + alloc`; transcendental math routes through the
  `nexacore-hal::math` libm shim.

The PLAN's acceptance names **Q4_K/Q8**. Q8 (int8, Q8_0) already works;
the missing piece is **Q4_K** — the 4-bit k-quant that real Llama-family
GGUF models actually ship in — plus the test suite (golden, E2E
cosine-vs-f32, proptest, bench) the acceptance requires.

## Decisions

### D1 — Dequant-at-load dispatch, NOT quantized matmul (scalar-first)

TASK-16 adds the **Q4_K → f32 dequant kernel** behind the existing
load-time dispatch (`dequantize_to_f32`), keeping the f32 forward
unchanged. This is the PLAN's "dispatch int8/int4" read literally: the
per-dtype dispatch that turns quantized on-disk weights into the f32 the
engine consumes. Keeping weights quantized through a fused
quantized-matmul (using `TensorOp::QuantizedMatMul`) is a **performance**
optimization deferred to a later sprint, per the PLAN's explicit order
**Security > Stability > Performance** ("scalare corretto prima,
ottimizzazione SIMD solo dopo baseline"). No hand-written `unsafe` SIMD
in this task.

### D2 — Q4_K byte-exact to llama.cpp `block_q4_K`

The kernel reproduces llama.cpp's reference **exactly** (a deviation
makes real models produce garbage). `QK_K = 256`; one super-block is
**144 bytes**:

```
offset  size  field
[0..2]    2   d     : f16  super-block scale for the 6-bit sub-scales
[2..4]    2   dmin  : f16  super-block scale for the 6-bit sub-mins
[4..16]  12   scales: 8 × (6-bit scale + 6-bit min), bit-packed
[16..144]128  qs    : 256 × 4-bit quants (low nibble first, 32 bytes/64 elems)
```

Sub-scale/min unpacking — port `get_scale_min_k4(j, scales) -> (sc, m)`
faithfully (j ∈ 0..8):

```
j < 4 : sc = scales[j] & 63;              m = scales[j+4] & 63
j ≥ 4 : sc = (scales[j+4] & 0xF) | (scales[j-4] >> 6 << 4)
        m  = (scales[j+4] >> 4)  | (scales[j-0] >> 6 << 4)
```

Dequant (`dequantize_row_q4_K`), per super-block, 4 outer steps over
`j = 0,64,128,192` consuming 32 qs bytes each, two sub-blocks per step:

```
d  = f16→f32(d);  min = f16→f32(dmin)
for is in 0,2,4,6:
    (sc1,m1) = get_scale_min_k4(is);   d1 = d*sc1;  m1f = min*m1
    (sc2,m2) = get_scale_min_k4(is+1); d2 = d*sc2;  m2f = min*m2
    for l in 0..32: y[..]  = d1*(qs[l] & 0xF) - m1f
    for l in 0..32: y[..]  = d2*(qs[l] >> 4)  - m2f
    qs += 32
```

### D3 — Fail-closed on untrusted model bytes

The model file is untrusted. The kernel validates
`raw_bytes.len() == n_blocks * 144` (exact, like Q8_0/Q4_0) and returns
`Err` on mismatch — never a panic, never an out-of-bounds. The Q4_K
byte-size in `gguf_tensor_byte_size` is corrected from the
1-byte/element stub to `n_elements.div_ceil(256) * 144` (checked). All
index arithmetic stays in-bounds by construction (documented SAFETY
comment, as in the Q8_0/Q4_0 arms). The dequant math is pure f32; the
only integer ops are the 6-bit/4-bit unpacks (no overflow possible on
`u8`).

### D4 — Test suite per the acceptance criteria

- **Golden (dequant):** fixed Q8_0 and Q4_K blocks with hand-chosen
  `d/dmin/scales/qs`, expected f32 computed **independently** in the test
  (not by calling the function under test), asserted within a tight
  tolerance. The Q4_K golden uses VARIED sub-scales/mins so a
  `get_scale_min_k4` bug is caught.
- **E2E (cosine-vs-f32):** build the SAME tiny transformer weights as
  both an f32 GGUF and a quantized GGUF; run the engine forward on each;
  assert the output logits' cosine similarity exceeds a documented
  threshold (Q8_0 with unit scales is exact → ≈1.0; Q4_K → ≥0.99 on the
  fixture). Reuses the existing forward; adds an f32 fixture builder.
- **Proptest:** arbitrary/malformed Q4_K (and Q8_0/Q4_0) byte buffers →
  `dequantize_to_f32` returns `Ok`/`Err` but NEVER panics/overflows.
- **Bench:** a `cargo bench` (criterion or `#[bench]`-style) recording a
  Q4_K dequant throughput baseline — tracking only, no CI gate.

### D5 — Scope: Q4_K only; Q5_K/Q6_K stay stubs

Q4_0/Q8_0 already work; Q4_K is the int4 k-quant this task delivers.
Q2_K/Q3_K/Q5_K/Q6_K remain documented zero-stubs (out of TASK-16 scope);
they keep their conservative byte-size placeholders so loading a model
that uses them fails safe (zeros) rather than mis-slicing.

## Alternatives considered

- **Quantized-matmul on the hot path now** — rejected for TASK-16:
  correct scalar dequant-then-f32 is simpler, fully testable, and matches
  the PLAN's stated priority order; fused quant matmul + SIMD is the
  follow-up perf sprint.
- **Trusting the recon's 224-byte/f32-d Q4_K layout** — rejected: it is
  wrong. The canonical `block_q4_K` is 144 bytes with f16 `d`/`dmin` and
  the `get_scale_min_k4` 6-bit packing; byte-exactness is mandatory for
  real-model correctness.
- **Implementing all k-quants now** — rejected: scope creep. Q4_K is the
  highest-value 4-bit format; the rest are deferred and fail safe.

## Consequences

- `tensor_loader.rs`: Q4_K byte-size corrected + a real `Q4_K` dequant
  arm (≈60 lines) + a `get_scale_min_k4` helper; module doc updated to
  list Q4_K as real.
- `fixture.rs`: a Q4_K GGUF builder + an f32 GGUF builder (for the cosine
  E2E).
- New tests + a bench; no API/signature changes — `engine.rs`,
  `build_weights`, and the forward are untouched (they already consume
  the f32 the new arm produces).
- Real Q4_K Llama-family GGUFs become loadable on the `LocalCpuProvider`
  CPU path (subject to the engine's tiny-model config limits).

## Implementation appendix — TASK-16 CLOSED (2026-06-08)

Implemented and verified (host + bare-metal). The Q4_K dequant arm in
`tensor_loader.rs` is a byte-exact port of llama.cpp `dequantize_row_q4_K`
+ `get_scale_min_k4` (144-byte super-block, f16 `d`/`dmin`, 12-byte 6-bit
packed scales/mins, 128-byte 4-bit quants; 4 outer steps, `is += 2`,
low-then-high nibbles). `gguf_tensor_byte_size` for Q4_K corrected to
`div_ceil(256) * 144`. Q2_K/Q3_K/Q5_K/Q6_K remain fail-safe stubs.

**Tests (13 new):** Q4_K golden (one block with varied sub-scales/mins
exercising both `get_scale_min_k4` branches — expected computed
independently, within 1e-4), Q4_K two-block + byte-count-mismatch→Err,
Q8_0 golden, two `get_scale_min_k4` branch unit tests, a 5-test proptest
module (Q4_K/Q8_0/Q4_0 over arbitrary + mismatched lengths never panic),
and two E2E cosine-vs-f32 tests. The fixtures are constructed lossless
(Q4_K/Q8_0 dequant reproduces the f32 reference exactly), so the cosine
is **1.000** for both (thresholds 0.999 / 0.99) — the E2E proves the
quantized→forward pipeline is correct, while the varied-scale golden test
is the rigorous validation of the dequant math itself.

**Bench baseline** (`benches/q4k_dequant.rs`, criterion, host-only —
gated out of the bare-metal build): Q4_K dequant of 1 867 776 elements
(~1 MiB) ≈ **793 µs median (~2.35 Gelem/s)** scalar, single-thread. No
gate — tracking only. SIMD is the deferred perf follow-up (D1).

**Gates:** nexacore-runtime 290 lib tests (+ integration/doc) 0 failed;
workspace 4298/0; `cargo build` host + `--target x86_64-unknown-none`
clean; clippy `-D warnings` clean; fmt clean.
