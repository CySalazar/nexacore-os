# Security Model

**Status:** Draft v0.1

## Threat model

NexaCore OS defends against six attacker classes by default. Each defense in this document maps to one or more attackers.

| ID | Attacker | Capability | Goal |
|----|----------|------------|------|
| A1 | Malicious local app | User-installed userspace process | Escalate privilege, exfiltrate data |
| A2 | Untrusted content | Files, web pages, emails reaching the model | Prompt injection, leak sensitive context |
| A3 | Supply chain | Compromised model weights, backdoored dependencies | Stealthy backdoor, biased outputs |
| A4 | Curious cloud | Inference cloud provider when user opts in to Tier 3 | Read prompts, log queries |
| A5 | Physical attacker | Physical access to device | Cold boot, TEE side-channel, key extraction |
| A6 | Misaligned model | The model itself | Produce harmful or deceptive output |

## Layered defenses

### Prompt injection (A2)

Prompt injection — where untrusted content carries instructions that hijack the model — is the most underestimated AI security problem.

- **Taint tracking** at the OS level: every byte of input is tagged with provenance (`trusted` / `untrusted`). Tags propagate through pipes, files, and IPC. When `untrusted` data reaches the AI Runtime, it is wrapped in a structured envelope (e.g., XML-style tags) before reaching the model.
- **Dual-LLM pattern**: a privileged "planner" model never sees raw untrusted content. A "quarantined" model processes it and returns only structured, validated data to the planner.
- **Output gating**: no side effects from model output without an action validator + capability check + (for sensitive actions) explicit user confirmation outside the model channel.
- **Constitutional filters**: small classifiers (BERT-class, sub-millisecond) inspect outputs for known injection patterns before any action is executed.

### Capability-based access control (A1, A2)

Every AI invocation requires a signed capability token.

- Capabilities are scoped (action, resource, time-bound).
- Implementation in the style of Macaroons: allows attenuated delegation — an agent can derive a more restricted child capability for a sub-agent, never broader.
- Master signing keys live in TPM 2.0 / Secure Enclave; user-space services request capability minting from the kernel.
- Short TTL (minutes) + revocation list ensures fast revocation if a capability leaks.

### Privacy budget (A4)

A per-user Differential-Privacy-style accountant tracks information disclosure to external parties.

- Each query consumes budget proportional to query sensitivity, estimated by a local classifier.
- Hard cap per time window (e.g., daily): when exhausted, queries to external services are refused or downgraded to local execution.
- User dashboard shows budget consumption per app, model, and target.

### Model attestation (A3)

Sigstore-compatible signature infrastructure for model weights.

- Signed manifest includes: hash of weights (canonical serialization), training data hash or description, provenance card, publisher signature.
- Models without valid signatures are refused at load time.
- Public Certificate-Transparency-style log of all signatures prevents publishers from issuing different versions to different targets.
- Periodic canary tests interrogate models with prompt-triggers known to surface backdoors documented in the security literature; suspicious behavior triggers quarantine.

### Egress control (A1, A4)

- Default deny for traffic to commercial inference endpoints (Tier 3).
- A whitelist per (model × app) governs which apps may reach which Tier 3 endpoints.
- Local PII scrubber inspects every prompt before egress; either masks PII or warns the user.
- User notification is persistent (status bar indicator, not dismissible toast) whenever data leaves the device.

### Audit log (forensics for any A)

- Every AI invocation produces a structured record: `{timestamp, agent_id, model_hash, input_hash, output_hash, capabilities_used, decision_path}`.
- Records form a Merkle tree (tamper-evident append-only log).
- Tree root is anchored periodically against the local TPM clock and optionally a remote witness.
- User-queryable, exportable, suitable for forensic analysis after an incident.

### Side channels (A5, advanced A1)

- KV-cache partitioned per agent; flushed on context switch — prevents inter-agent timing leaks.
- Constant-time inference paths used where feasible.
- Memory wiping between sensitive context switches.
- Defense-in-depth against TEE side-channel attacks via diverse TEE implementations and frequent attestation refresh.

### Adversarial inputs (A2, multimodal)

Images, audio, or video crafted to manipulate vision/voice models.

- Input pre-processing with randomized smoothing for vision and audio inputs.
- Detection of known adversarial patterns at the OS edge.
- For high-stakes actions, multi-model agreement is required (not yet finalized).

### TEE compromise resistance (A5)

- Frequent attestation refresh — re-attest on suspicious behavior or scheduled intervals.
- Use of multiple TEE implementations across the mesh: an attack against one TEE family does not compromise the entire network.
- Cold boot mitigation: TDX and SEV-SNP encrypt memory at rest by default.
- Hardware refresh policy: when academic literature shows a TEE family is compromised, that family is added to the attestation deny-list.

## Privacy by construction (the deeper guarantee)

Beyond layered defenses, NexaCore OS aims for properties that hold by mathematical construction, not by policy enforcement:

1. **PII never appears in cleartext on the network.** Enforced by mandatory tokenization at OS API level and encrypted-by-default data types.
2. **Compute on encrypted data is verifiable.** Compliance proofs prove correctness without revealing inputs.
3. **No node can decrypt data not destined for it.** Enforced by TEE-bound key derivation: session keys are sealed against the destination's attestation report.

These properties are stronger than "policy says so" — they hold because a malicious node literally cannot produce valid network traffic that violates them, without breaking the underlying cryptographic primitives.

## The five privacy primitives in detail

### 1. Encrypted-by-default data types

OS-level types that cannot be instantiated with plaintext PII outside an attested TEE:

```rust
EncryptedString
TokenizedEmail
MaskedSSN
AttestedHash
```

Compiler-level enforcement (similar to Rust's lifetime checker) prevents code paths that would handle PII in cleartext.

### 2. Tokenization service

When an application requests inference on data containing PII:

- A local NER (Named Entity Recognition) classifier identifies PII spans (persons, addresses, emails, IDs).
- Each PII span is replaced with a deterministic token (e.g., `<PERSON_4f3a>`).
- The model receives only tokens, never raw PII.
- De-tokenization happens locally inside the user's TEE on response.
- Tokens are user-specific and not reusable across sessions or devices, preventing cross-session linkability.

### 3. Format-preserving encryption (FPE)

For routing metadata that needs to look "normal" (e.g., for routing decisions, indexing) but must be encrypted:

- Algorithms: NIST-approved FF1 and FF3-1.
- Allows the mesh to route messages by encrypted routing keys without decrypting payload.

### 4. Compliance proofs

Every payload includes a cryptographic proof that:

- PII has been tokenized.
- The schema conforms to NexaCore OS encrypted-data-type definitions.
- The session is bound to the destination's attested TEE.

For simple predicates: a signature over a structured assertion suffices (`sig-v1`).
For complex predicates (e.g., "this prompt does not contain any byte sequence matching a regex of PII patterns"): **STARK proofs are used** (`stark-v0`), not zk-SNARKs.

The STARK-over-SNARK choice for v1 is decided in [`/ncips/ncip-crypto-002.md`](../oips/oip-crypto-002.md): transparent (no trusted setup), post-quantum sound under the Random Oracle Model, larger proof size accepted as the trade-off. SNARK is not forbidden indefinitely; a future NCIP may introduce `snark-vN` if a transparent-setup construction becomes mainstream and audited.

### 5. TEE-only decryption envelope

The payload session key is encrypted with a key derived from the destination TEE's attestation report. Only that specific TEE, on that specific hardware, with that specific binary measurement, can derive the matching key and decrypt.

This means: a compromised host OS on the destination cannot read the payload. Only the attested NexaCore OS binary, running inside the attested TEE, has access.

## Open security questions

- **TEE side-channel attacks**: Intel SGX has a long history of academic side-channel attacks. TDX is improving but not impervious. Mitigation: TEE diversity, hardware refresh policy, and NCIP-driven deny-list of compromised TEE generations.
- **Quantum migration**: PQ-resistant cryptography roadmap. Likely Kyber + Dilithium hybrid starting v1, full migration by 2030 per NIST guidance.
- **Recovery from key compromise**: forward secrecy + key rotation policies. Detailed plan deferred to NCIP-002.
- ~~**zk-SNARK trusted setup**~~: resolved by [`NCIP-Crypto-002`](../oips/oip-crypto-002.md) (2026-05-10). v1 uses STARKs (`winterfell` v0.10+ reference) for transparent setup. SNARKs are not forbidden indefinitely but require a future NCIP and an audited transparent-setup construction.
- **Secure agent sandboxing**: WASM-based sandbox vs. process isolation. Trade-off: WASM is faster but less battle-tested for security boundaries; process isolation is heavier but more conservative.

## Audit and review

The security model will undergo external review by independent auditors before v1 release. Expected focus:

- Cryptographic protocol soundness (formal analysis where feasible)
- TEE attestation chain correctness
- zk-SNARK predicate completeness
- Side-channel resistance
- Capability system formal model

Audit results will be published.
