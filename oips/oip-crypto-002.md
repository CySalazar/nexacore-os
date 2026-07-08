---
ncip: 2
title: Compliance Proof Scheme — STARK over SNARK for v1
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-10
updated: 2026-05-24
requires:
  - NCIP-Process-001
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

# NCIP-Crypto-002 — Compliance Proof Scheme: STARK over SNARK for v1

## Abstract

This proposal commits NexaCore OS v1.0 to a **STARK-based compliance proof scheme**
(specifically: `winterfell` v0.10+ as reference implementation, with the protocol
abstracted behind a `ComplianceProof` trait so the underlying STARK library can
be replaced under an NCIP). zk-SNARKs (Groth16, PLONK) are **explicitly deferred**
to a future NCIP and require a trusted-setup ceremony that the project will not
undertake without overwhelming security and operational justification.

For v1.0, the compliance proof scheme is a **mandatory baseline of signature-based
proofs (`sig-v1`) plus an optional STARK-based scheme (`stark-v0`)** negotiated
during the mesh handshake (see [`docs/protocol/handshake.md`](../docs/protocol/handshake.md)
§3.3, `compliance_capabilities`).

## Motivation

[`docs/04-security-model.md`](../docs/04-security-model.md) § "Compliance proofs"
states that every mesh payload includes a cryptographic proof that PII has been
tokenized, the schema is conforming, and the session is bound to the destination
TEE. The implementation question is: **which proof system?**

Three options were evaluated:

1. **Signature-based assertion** (`sig-v1`): the sender signs a structured
   assertion over the payload's compliance properties.
2. **zk-SNARK** (Groth16 / PLONK / Halo2): succinct proofs of arbitrary
   predicates; classic but requires trusted setup or universal SRS.
3. **STARK** (`winterfell`, `triton-vm`): transparent (no trusted setup),
   post-quantum sound under the Random Oracle Model, larger proofs than SNARK.

`sig-v1` is sufficient for v1.0 but cannot prove "no PII present in this payload"
without revealing the payload — a fundamental limitation. STARK and SNARK both
solve this; the question is which one.

## Specification

### 1. v1.0 baseline: signature-based compliance assertion (`sig-v1`)

Every payload `P` carries a structured assertion:

```rust
struct ComplianceAssertion {
    schema_version: ProtocolVersion,
    payload_hash: [u8; 32],         // BLAKE3 of canonicalized payload
    tokenization_proof: TokenizationProof,
    routing_envelope_binding: [u8; 32],  // hash of destination TEE measurement
    issuer_node_id: NodeId,
    issued_at: u64,                 // unix seconds
    expires_at: u64,                // sender claim; receiver checks
}

struct ComplianceProof {
    assertion: ComplianceAssertion,
    signature: NexaCoreSignature,       // Ed25519 over canonical encoding
}
```

The signature attests that the issuer's TEE saw the payload pre-tokenization,
ran the tokenization service, and produced this assertion. **It does not prove
the absence of PII; it asserts it under the issuer's TEE attestation chain.**

This is sufficient if the issuer's TEE is trusted (which it must be for the
mesh handshake to have succeeded — see I3 in the handshake spec).

### 2. v1.0 optional: STARK-based compliance proof (`stark-v0`)

For payloads where the issuer wishes to provide a *zero-knowledge proof* of
PII-absence (e.g., when sending to a less-trusted peer in onion-routing
scenarios), a STARK proof of the following predicate is attached:

> Predicate: `no_byte_sequence_matches(payload, pii_regexes)`
>
> where `pii_regexes` is the canonical PII regex set defined in
> `docs/protocol/pii-canonical-regexes.md` (to be published as `NCIP-Crypto-003`).

The STARK implementation MUST:

- Use `winterfell` v0.10 or later with `air-script` for predicate description.
- Prove evaluation of the regex automaton on the payload as a STARK trace.
- Produce a proof of size ≤ 100 KiB for payloads ≤ 32 KiB (engineering target;
  to be validated by benchmark before v1.0 release).
- Verifier time ≤ 50 ms on a 2024-class server CPU.

### 3. Negotiation in the handshake

The handshake (`m3.compliance_capabilities`) carries an opaque byte string
listing the schemes the initiator supports. The responder's session state
records the intersection. Per-payload, the issuer chooses any scheme in the
intersection; `sig-v1` is the unconditional fallback.

### 4. Why STARK, not SNARK

| Concern | STARK (`winterfell`) | SNARK (Groth16 / Halo2) |
|---|---|---|
| Trusted setup | None (transparent) | Per-circuit (Groth16) or universal SRS (PLONK / Halo2). |
| Post-quantum soundness | Yes (collision-resistant hash assumption only) | No (relies on elliptic curve pairings or discrete log). |
| Proof size | Larger (50–200 KB typical) | Smaller (200–800 B for Groth16). |
| Verifier time | 5–100 ms typical | 1–10 ms typical. |
| Prover time | Comparable or faster for some circuits | Faster for small circuits, slower for large ones. |
| Audit history (Rust ecosystem) | `winterfell` 4 years, `triton-vm` 3 years | `arkworks` 6+ years, more deployed. |
| Mission alignment | Transparent / anti-capture: no ceremony, no honest-majority assumption beyond hash function security. | Trusted setup ceremony introduces coordination risk and a "founding sin" problem. |

The decisive factor for NexaCore OS is **mission alignment with anti-capture**. A
trusted-setup ceremony embeds a one-time event where a group of humans had to
be trusted; even if that ceremony was honest, it is a permanent reminder that
the protocol once required external trust. STARK eliminates this entirely.

The cost is larger proofs and slower verification — both engineering problems,
not cryptographic compromises. As proof and verifier hardware improve, STARK
benchmarks improve too; the trust property does not change.

### 5. Migration path

- **v1.0**: `sig-v1` mandatory, `stark-v0` optional. Default deployments use
  `sig-v1`; high-assurance configurations enable `stark-v0`.
- **v1.x**: based on production benchmarks, `stark-v0` may become mandatory if
  prover overhead is acceptable. A separate NCIP will make this call.
- **v2.0+**: post-quantum migration of `sig-v1` to ML-DSA (FIPS 204) lands in a
  separate NCIP; STARK already PQ-sound under ROM.

## Rationale

The choice between STARK and SNARK was contentious. Arguments considered:

- **SNARK proponents** point to the much smaller proof sizes (200 B vs ~100 KB),
  which matter on low-bandwidth links. This is real: a 200 B proof per payload
  is essentially free; a 100 KB proof is bandwidth-significant.
- **SNARK proponents** point to deployed ecosystem maturity (Zcash, Aztec, Mina).
- **STARK proponents** point to the trusted-setup problem and post-quantum
  soundness — both directly aligned with the project's privacy-first / anti-
  capture mission.

The conclusion: **mission alignment wins over performance for v1.** Performance
of `stark-v0` is *acceptable* (verifier 50 ms target, prover 100 ms target);
SNARK performance is *better* but the trusted-setup trade-off is incompatible
with the project's stated values.

Note that this NCIP does NOT forbid SNARK indefinitely. If a transparent SNARK
construction (e.g., a STARK-friendly hash inside a SNARK circuit) becomes
mainstream and audited, a future NCIP can add it as `snark-vN`. The wire-protocol
negotiation supports arbitrary scheme additions.

## Backwards Compatibility

Not applicable: there is no pre-existing compliance proof scheme. The
introduction of `sig-v1` and `stark-v0` is the first compliance proof
specification of the protocol.

## Test Cases

1. **`sig-v1` round-trip**: issuer signs assertion, verifier validates. Vector
   suite in `crates/nexacore-mesh/tests/compliance/sig_v1_vectors.rs`.
2. **`sig-v1` tampering**: any single-bit flip of payload, assertion, or
   signature MUST cause verification failure. 256 randomized tampered cases.
3. **`stark-v0` round-trip** for a payload known to contain no PII: prover
   produces a proof, verifier accepts.
4. **`stark-v0` negative**: prover attempts to produce a proof for a payload
   containing PII — proof generation MUST fail; if a malicious prover forges a
   proof, the verifier MUST reject. 256 randomized adversarial cases.
5. **Negotiation downgrade**: if initiator advertises `["stark-v0", "sig-v1"]`
   and responder advertises `["sig-v1"]`, the session adopts `sig-v1`.

## Reference Implementation

To land before activation:

- `crates/nexacore-mesh/src/compliance/mod.rs` — `ComplianceProof` trait.
- `crates/nexacore-mesh/src/compliance/sig_v1.rs` — `sig-v1` impl.
- `crates/nexacore-mesh/src/compliance/stark_v0.rs` — `stark-v0` impl (feature-gated).
- `crates/nexacore-mesh/Cargo.toml` — `winterfell = "0.10"` behind feature `compliance-stark`.
- Benchmark suite in `crates/nexacore-mesh/benches/compliance.rs`.

## Security Considerations

- **STARK soundness** depends on the collision resistance of BLAKE3 (the
  underlying hash). If BLAKE3 falls, both `sig-v1` and `stark-v0` are affected
  (the hash is also used in `NexaCoreError` taxonomy, capability tokens, etc.).
- **STARK proof verification** is a non-trivial code path. The `winterfell`
  audit history is shorter than `arkworks`'. The project mitigates this by:
  (a) feature-gating `stark-v0` behind opt-in, (b) the mandatory baseline
  `sig-v1` is always usable, (c) external cryptographer review of any
  `stark-v0` production deployment.
- **Padding oracle / side-channel** risks in the verifier are mitigated by
  constant-time AEAD tag checks and `subtle::ConstantTimeEq` throughout.

## Privacy Considerations

`stark-v0` provides zero-knowledge of payload content while attesting to a
public predicate. `sig-v1` provides no zero-knowledge — the assertion structure
is in the clear. Both forms reveal that *a* payload of this approximate size
was sent at this time; observers can infer traffic patterns. Onion-routing
covers traffic-analysis concerns; that is out of scope for this NCIP.

## Amendment history

| Date | Change | Notes |
|---|---|---|
| 2026-05-12 | `Draft → Review` | Editorial transition by the interim editor body (founder, sole editor during the Bootstrap Period per `NCIP-Process-001` §6.2). No content change. |
| 2026-05-12 | `Review → Last Call` | Editorial transition by the interim editor body. **14-day public-objection window opens 2026-05-12 and closes 2026-05-26** per `NCIP-Process-001` §4 and §5.3. All technical content has been reviewed; `winterfell` v0.10 dependency validated against `no_std + alloc` requirements. Transition to `Active` requires either ≥30% weighted vote OR the 14-day window elapsing per `NCIP-Process-001` §5.3. |
| 2026-05-24 | `Last Call → Active` | Editorial closure of the Last Call window under `NCIP-Process-001` §5.3 ¶1 second branch: the dominant voter (`cySalazar`, 100% weighted eligibility under §5.2 bootstrap defaults — sole §5.1-eligible device) cast an in-favor ballot. Because NCIP-Crypto-002 is `Standards Track` and **does** affect Layer 1 cryptographic guarantees (§5.3 ¶2: compliance proof scheme is a cryptographic primitive), the 66.7% supermajority applies — satisfied trivially with a single 100%-weight voter. Founder ballot recorded in `docs/audits/ncip-editors-report-2026-Q2.md`. No blocking objection raised during the 12-day partial window (2026-05-12 → 2026-05-24). No content change carried by this transition; the `Active` text is identical to the `Draft` text. |

## Copyright

This NCIP is licensed under CC0 1.0 Universal.
