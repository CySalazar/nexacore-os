# Formal Threat Model

**Status:** Draft v0.1
**Companion to:** [04-security-model.md](./04-security-model.md)

This document is the formal threat model for NexaCore OS. It complements the high-level security model with structured analysis using **STRIDE** for security threats and **LINDDUN** for privacy threats, attack-tree decomposition for high-severity scenarios, and a risk matrix mapping threats to mitigations.

It is a living document. Every architectural change that affects trust boundaries, data flows, or assets MUST trigger a review of this threat model.

---

## 1. Purpose and methodology

### Purpose

- Enumerate threats systematically before they are exploited.
- Provide a shared vocabulary for engineers, reviewers, and auditors.
- Support NCIP discussions where security and privacy trade-offs are involved.
- Drive prioritization of security work in each phase of the roadmap.

### Methodology

- **STRIDE** — applied to security threats per component (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege).
- **LINDDUN** — applied to privacy threats specific to mesh and AI workloads (Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance).
- **Attack trees** for high-priority threats: decompose the goal into refinements until each leaf is either preventable, detectable, or accepted.
- **Risk matrix**: each threat scored on severity (1–5) × likelihood (1–5). Risk = severity × likelihood.

### Severity scale

| Level | Label | Meaning |
|---|---|---|
| 5 | Critical | System-wide compromise; protocol guarantees broken; mass-user impact |
| 4 | High | Single-node compromise leading to PII exposure or service outage |
| 3 | Medium | Limited compromise mitigable in a single deployment |
| 2 | Low | Annoyance; degrades UX without security impact |
| 1 | Informational | Theoretical / not currently exploitable |

### Likelihood scale

| Level | Label | Meaning |
|---|---|---|
| 5 | Near-certain | Will happen during normal operation without mitigation |
| 4 | Likely | Reasonable attacker can execute |
| 3 | Possible | Sophisticated attacker can execute |
| 2 | Unlikely | Requires nation-state-level resources |
| 1 | Remote | Theoretical with no known practical path |

Risk **>= 12** is **High** and must be mitigated before v1.0. Risk **>= 16** is **Critical** and is a release-blocker.

---

## 2. System decomposition

### Trust boundaries

NexaCore OS has six primary trust boundaries:

1. **User application ↔ AI Runtime Service**: capability-checked syscalls.
2. **User-space service ↔ Microkernel**: IPC with capability validation.
3. **Local node ↔ Personal Cluster peers**: mTLS over LAN, mutual TEE attestation.
4. **Local node ↔ Federated Mesh peers**: QUIC + Noise, mutual TEE attestation, compliance proofs on every payload.
5. **Local node ↔ Commercial cloud**: opt-in TLS connection with explicit user consent and privacy-budget accounting.
6. **TEE ↔ Host OS on a node**: TEE protects against the host OS itself.

### Primary assets

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| User PII | Critical | High | Medium |
| User AI conversations | High | High | Medium |
| Capability tokens | High | Critical | Low |
| Model weights (in-flight) | Medium | Critical | Low |
| Compute credit ledger | Low | High | Medium |
| Reputation scores | Low | High | Low |
| Mesh routing tables | Low | Medium | Medium |
| Audit logs | High | Critical | High |

### Data flows (high-level)

```
┌──────────┐  prompt + capability  ┌────────────┐  inference  ┌──────────┐
│   App    │──────────────────────▶│ AI Runtime │────────────▶│ Tier 0/1/2/3 │
└──────────┘                       └────────────┘             └──────────┘
                                          │
                                          │ tokenize PII
                                          ▼
                                   ┌─────────────┐
                                   │ Tokenization│  (TEE-resident)
                                   │   Service   │
                                   └─────────────┘
                                          │
                                          │ (Tier 2 only) compliance proof
                                          ▼
                                   ┌─────────────┐  encrypted envelope ┌──────────┐
                                   │   Mesh      │────────────────────▶│  Peer    │
                                   │  Service    │                      │ (TEE)    │
                                   └─────────────┘                      └──────────┘
```

---

## 3. Attacker profiles

Six attacker classes from [04-security-model.md](./04-security-model.md), expanded.

### A1 — Malicious local app
- **Origin:** user-installed (sideloaded or from a marketplace).
- **Capabilities:** runs in user space; can call OS APIs; cannot violate kernel capability checks.
- **Motivation:** data exfiltration, cryptojacking, ransomware, surveillance.
- **Examples:** trojanized productivity app; legitimate app with malicious update; exploit chain via memory bug.

### A2 — Untrusted content
- **Origin:** files, web pages, emails, attachments, clipboard, IPC payloads from untrusted sources.
- **Capabilities:** content reaches the model as input; may contain instructions designed to hijack the model.
- **Motivation:** cross-context data exfiltration, action hijacking, manipulation of agent behavior.
- **Examples:** prompt-injection in a webpage processed by an agent; PDF with hidden instructions; email with embedded model directives.

### A3 — Supply chain
- **Origin:** upstream model publishers, dependency authors, hardware vendors.
- **Capabilities:** controls inputs to the build / model pipeline.
- **Motivation:** strategic backdoor placement, IP theft, mass surveillance.
- **Examples:** backdoored model weights (BadNets); compromised crate on crates.io; malicious firmware update.

### A4 — Curious cloud
- **Origin:** Tier 3 commercial inference provider, when used.
- **Capabilities:** sees the prompts the user sent; logs them.
- **Motivation:** commercial profiling, regulatory compulsion, data resale.
- **Examples:** any major commercial LLM API.

### A5 — Physical attacker
- **Origin:** has physical or near-physical access to a device.
- **Capabilities:** cold boot attacks, JTAG, side-channel measurement, firmware downgrade.
- **Motivation:** targeted surveillance, key extraction, evidence collection.
- **Examples:** border seizure, theft, "evil maid" attack on a laptop.

### A6 — Misaligned model
- **Origin:** the AI model itself, possibly without the publisher's awareness.
- **Capabilities:** generates outputs that the model "thinks" satisfy its training objective but are harmful in practice.
- **Motivation:** N/A (model has no intent in the human sense, but its outputs can still be harmful).
- **Examples:** model that produces deceptive text; model that follows injected instructions despite training; model with reward hacking.

---

## 4. STRIDE analysis per component

For each major component, threats are listed by STRIDE category. Each threat has an ID, severity (S), likelihood (L), and risk score (S × L). Mitigations link to relevant sections in [04-security-model.md](./04-security-model.md).

### 4.1 Microkernel

| ID | STRIDE | Threat | A* | S | L | Risk | Mitigation |
|---|---|---|---|---|---|---|---|
| K-S-1 | Spoofing | App spoofs another app's identity to obtain capabilities | A1 | 4 | 2 | 8 | Capabilities bound to caller process; kernel-validated |
| K-T-1 | Tampering | App tampers with another app's IPC channel | A1 | 5 | 2 | 10 | Capability-gated IPC; channels are kernel-managed |
| K-R-1 | Repudiation | An action's actor cannot be determined | A1 | 3 | 2 | 6 | Audit log records every capability use |
| K-I-1 | Info disclosure | Side-channel between processes (cache, timing) | A1 | 4 | 3 | 12 | KV-cache partitioning; constant-time crypto |
| K-D-1 | DoS | App exhausts kernel memory by spawning processes | A1 | 3 | 4 | 12 | Per-app resource quotas in capabilities |
| K-E-1 | EoP | Memory bug in unsafe Rust block escalates privilege | A1 | 5 | 2 | 10 | Workspace policy: minimize unsafe; mandatory PR review |
| K-E-2 | EoP | Capability forgery via cryptographic weakness | A1 | 5 | 1 | 5 | TPM-backed signing keys; algorithmic agility |

### 4.2 AI Runtime Service

| ID | STRIDE | Threat | A* | S | L | Risk | Mitigation |
|---|---|---|---|---|---|---|---|
| R-S-1 | Spoofing | Agent presents capability stolen from another agent | A1 | 4 | 3 | 12 | Capability bound to agent ID + TEE; short TTL |
| R-T-1 | Tampering | Model weights modified between attest and load | A3 | 5 | 2 | 10 | Verify weight hash at every load; TEE-sealed cache |
| R-R-1 | Repudiation | Agent denies having issued a tool call | A1 | 3 | 3 | 9 | Audit log Merkle-anchored to TPM clock |
| R-I-1 | Info disclosure | Inference cache leaks across agents | A1 | 4 | 4 | 16 | Per-agent KV-cache; flush on context switch |
| R-D-1 | DoS | Adversarial prompt causes pathological inference time | A1, A2 | 3 | 4 | 12 | Per-agent compute budget; output length caps |
| R-E-1 | EoP | Prompt injection causes runtime to invoke high-privilege tool | A2 | 5 | 4 | **20** | Action validator + capability check + user confirmation |

### 4.3 Mesh Protocol Service

| ID | STRIDE | Threat | A* | S | L | Risk | Mitigation |
|---|---|---|---|---|---|---|---|
| M-S-1 | Spoofing | Attacker spoofs a node identity via fake attestation | A3 | 5 | 2 | 10 | TEE attestation chain verification; vendor PKI |
| M-S-2 | Spoofing | Sybil: many fake nodes flood the mesh | A1 | 4 | 4 | 16 | TEE-bound IDs; rate-limited new identities; reputation; quadratic voting |
| M-T-1 | Tampering | Honest node strips compliance proof and forwards | A1 | 5 | 1 | 5 | Every relay revalidates; protocol rejects |
| M-T-2 | Tampering | Routing table poisoning (eclipse attack) | A1 | 4 | 3 | 12 | Diverse peer selection; periodic fresh DHT lookups |
| M-R-1 | Repudiation | Node denies serving a request | A1 | 2 | 3 | 6 | Compute-credit ledger gossiped + signed |
| M-I-1 | Info disclosure | Malicious peer reads payload contents | A1 | 5 | 1 | 5 | TEE-only decryption envelope sealed against peer attestation |
| M-I-2 | Info disclosure | Traffic analysis reveals query patterns | A1 | 3 | 4 | 12 | Optional onion routing for sensitive workloads; FPE on routing metadata |
| M-D-1 | DoS | Flood of forged compliance proofs | A1 | 3 | 4 | 12 | Cheap pre-validation (signature shape) before expensive zk verification |
| M-D-2 | DoS | Eclipse + selective black-holing | A1 | 4 | 2 | 8 | Diverse peer set; multi-path queries |
| M-E-1 | EoP | Fake reputation gain via collusion | A1 | 3 | 4 | 12 | Inference-redundancy verification; long observation window |

### 4.4 Tokenization Service

| ID | STRIDE | Threat | A* | S | L | Risk | Mitigation |
|---|---|---|---|---|---|---|---|
| T-S-1 | Spoofing | App impersonates user to obtain user's vault | A1 | 5 | 2 | 10 | Vault keys sealed against user TEE + capability |
| T-T-1 | Tampering | Tampered NER classifier misses PII spans | A3 | 5 | 2 | 10 | Signed NER model; periodic canary tests |
| T-I-1 | Info disclosure | Vault contents leaked to host OS | A5 | 5 | 2 | 10 | Vault is TEE-resident; sealed storage |
| T-D-1 | DoS | NER classifier inference too slow on large input | A2 | 2 | 4 | 8 | Streaming tokenization; size limits |

### 4.5 TEE subsystem

| ID | STRIDE | Threat | A* | S | L | Risk | Mitigation |
|---|---|---|---|---|---|---|---|
| TE-S-1 | Spoofing | Attestation report replay | A1 | 4 | 2 | 8 | Nonce challenge in attestation handshake |
| TE-I-1 | Info disclosure | TEE side-channel attack (academic class) | A1, A5 | 5 | 3 | 15 | TEE diversity; deny-list of compromised generations; periodic re-attestation |
| TE-T-1 | Tampering | Firmware downgrade exposing patched vulnerability | A5 | 4 | 2 | 8 | Firmware version included in attestation; minimum-version enforcement |
| TE-D-1 | DoS | Attestation service unavailable | A1 | 3 | 2 | 6 | Vendor PKI + multiple attestation providers where available |

---

## 5. LINDDUN privacy analysis

LINDDUN focuses on privacy threats. Applied to the mesh and AI workloads, where they are most acute.

### Linkability

**L-1**: Two queries from the same user can be linked across mesh peers.
- **Severity 4, Likelihood 3, Risk 12.**
- Mitigation: per-session token re-scrambling in tokenization vault; onion routing for high-sensitivity workloads.

**L-2**: A user's reputation history reveals their query patterns.
- **Severity 2, Likelihood 4, Risk 8.**
- Mitigation: reputation aggregates ignore content; only outcomes (success/failure of inference verification).

### Identifiability

**I-1**: TEE attestation report contains hardware fingerprints that identify a specific device.
- **Severity 3, Likelihood 5, Risk 15.**
- Mitigation: attestation reports are accepted only by mesh peers, not third parties; no transitive disclosure.

**I-2**: Routing metadata (even if FPE-encrypted) leaks source identity over time.
- **Severity 3, Likelihood 3, Risk 9.**
- Mitigation: rotating session IDs; padding traffic; optional onion routing.

### Non-repudiation

**N-1**: Inference requests are signed and gossiped — a user cannot plausibly deny having issued a query.
- **Severity 2, Likelihood 4, Risk 8.**
- Mitigation: signatures are TEE-internal; queries to other peers carry only opaque session IDs, not user-bound credentials.

### Detectability

**D-1**: Pattern of mesh participation reveals "user is online and using AI now".
- **Severity 2, Likelihood 5, Risk 10.**
- Mitigation: persistent low-level traffic ("padding") to obscure presence; opt-in; not v1 priority.

### Disclosure of information

**DI-1**: PII exfiltration via the inference channel (covers the headline scenario).
- **Severity 5, Likelihood 4, Risk 20** without mitigation.
- Mitigation: tokenization (5/5), TEE-only decryption envelope (5/5), compliance proof rejection of cleartext PII (5/5). With mitigations: residual risk 5 (Severity 5 × Likelihood 1).

**DI-2**: Inference output (de-tokenized response) leaked to non-user processes.
- **Severity 5, Likelihood 2, Risk 10.**
- Mitigation: response stays in user's TEE until decoded by the requesting application's capability scope.

### Unawareness

**U-1**: User does not understand that participating in the mesh exposes some metadata.
- **Severity 2, Likelihood 4, Risk 8.**
- Mitigation: clear opt-in flow; persistent UI indicator; readable settings panel.

### Non-compliance

**NC-1**: Mesh operation runs afoul of GDPR/HIPAA in some jurisdictions.
- **Severity 3, Likelihood 3, Risk 9.**
- Mitigation: protocol-enforced PII handling means NexaCore OS can claim privacy-by-design; per-jurisdiction guidance in `/docs` (TODO); legal counsel engagement.

---

## 6. Attack trees for high-priority threats

### Tree 6.1 — Goal: exfiltrate user PII via prompt injection

```
Goal: PII exfiltrated via prompt injection
├── Path A: Inject instructions into untrusted content reaching the model
│   ├── A1: Crafted email body with hidden directives
│   │   └── Mitigation: taint tracking; dual-LLM pattern
│   ├── A2: Crafted webpage processed by an agent
│   │   └── Mitigation: same as A1
│   └── A3: Adversarial image with steganographic instructions (multimodal)
│       └── Mitigation: input pre-processing; randomized smoothing
├── Path B: Cause model to emit data to attacker-controlled tool
│   ├── B1: Trick agent into calling a webhook with PII
│   │   └── Mitigation: capability scope excludes unknown URLs;
│   │     action validator + user confirmation for sensitive actions
│   └── B2: Trick agent into composing an email containing PII
│       └── Mitigation: send action requires user approval
└── Path C: Defeat tokenization
    ├── C1: Express PII in a form NER does not detect
    │   └── Mitigation: periodic NER canary tests; defensive
    │       over-tokenization
    └── C2: De-tokenize through clever output formatting
        └── Mitigation: de-tokenization runs only inside user TEE on
            specific request types; not arbitrary output
```

### Tree 6.2 — Goal: spawn many fake nodes to bias mesh routing

```
Goal: Sybil attack on mesh
├── Path A: Generate many TEE attestations
│   ├── A1: Use cloned TEE state on many VMs
│   │   └── Mitigation: vendor PKI binds attestation to physical hardware
│   ├── A2: Compromise a TEE vendor's attestation service
│   │   └── Mitigation: diversity (TDX + SEV-SNP + others); deny-list
│   └── A3: Reuse a single hardware to mint many identities
│       └── Mitigation: rate-limited new identities per platform fingerprint
├── Path B: Buy many real devices
│   ├── B1: Cost analysis: 1000s of TEE-capable devices = $$$ + logistics
│   │   └── Mitigation: economic friction is the defense at scale
│   └── B2: Distribute compromised consumer devices via supply chain
│       └── Mitigation: hardware certification program; provenance
└── Path C: Compromise existing high-reputation nodes
    ├── C1: Memory bug exploitation
    │   └── Mitigation: Rust memory safety; TEE-restricted blast radius
    └── C2: Social engineering of a node operator
        └── Mitigation: out of NexaCore OS scope; rely on awareness
```

### Tree 6.3 — Goal: forge a capability token

```
Goal: Forge a capability token
├── Path A: Steal the master signing key
│   ├── A1: Extract from TPM/Secure Enclave (hardware compromise)
│   │   └── Mitigation: hardware attestation deny-list; TPM key
│   │       generation never exports private material
│   └── A2: Cold-boot attack on memory
│       └── Mitigation: TDX/SEV-SNP encrypt memory at rest
├── Path B: Cryptographic break of the signing scheme
│   ├── B1: Classical cryptanalysis (Ed25519)
│   │   └── Mitigation: algorithmic agility, sunset dates
│   └── B2: Quantum attack
│       └── Mitigation: PQ migration roadmap to 2030 (Kyber + Dilithium)
└── Path C: Steal a signed token and replay
    ├── C1: Read from another agent's memory
    │   └── Mitigation: capability storage in TEE; per-agent isolation
    └── C2: Capture in-flight via weak transport
        └── Mitigation: capability tokens are bound to TEE attestation;
            useless to a different attestation
```

### Tree 6.4 — Goal: introduce a model backdoor

```
Goal: Backdoored model silently affects outputs on trigger
├── Path A: Compromise the model publisher
│   ├── A1: Infiltrate the publishing organization
│   │   └── Mitigation: out of NexaCore OS direct scope; partial mitigation
│   │       via canary tests + transparency log
│   └── A2: Compromise the publisher's signing key
│       └── Mitigation: signing keys in HSM; multi-party signing for
│           "blessed" models in the registry
├── Path B: Modify weights between publish and load
│   ├── B1: MITM during download
│   │   └── Mitigation: TLS + signature verification at load time
│   └── B2: Tamper with cached weights on disk
│       └── Mitigation: TEE-sealed cache; hash check at every load
└── Path C: Substitute a malicious model with a trusted one's name
    └── Mitigation: model identity is content hash, not name
```

---

## 7. Risk matrix

Threats with risk score ≥ 12 are summarized here. All MUST be mitigated to acceptable residual risk before v1.0 release. Residual risk after planned mitigation is in parentheses.

| ID | Threat | Risk | Residual after mitigation |
|----|--------|------|---------------------------|
| R-E-1 | Prompt injection escalation | 20 | 5 |
| DI-1 | PII exfiltration via inference | 20 | 5 |
| R-I-1 | Inference cache cross-agent leak | 16 | 4 |
| M-S-2 | Mesh Sybil attack | 16 | 6 |
| TE-I-1 | TEE side-channel (academic class) | 15 | 9 (residual is real; ongoing concern) |
| I-1 | Hardware fingerprint identifiability | 15 | 6 |
| K-I-1 | Microkernel side-channel | 12 | 4 |
| K-D-1 | Microkernel resource exhaustion DoS | 12 | 4 |
| R-S-1 | Stolen capability token | 12 | 3 |
| R-D-1 | Pathological inference DoS | 12 | 4 |
| L-1 | Mesh query linkability | 12 | 6 |
| M-T-2 | Routing table poisoning | 12 | 4 |
| M-I-2 | Mesh traffic analysis | 12 | 6 |
| M-D-1 | Compliance proof flood | 12 | 4 |
| M-E-1 | Reputation collusion | 12 | 6 |

Persistent residual risks above 6 require mitigation iteration before v1.0 ship.

---

## 8. Mitigation status

For every threat listed above, mitigations exist either as:

- **Implemented** (will be marked when phase work delivers them)
- **Planned** (designed and scheduled in roadmap)
- **Open** (designed direction but not yet detailed)

Currently (Draft v0.1) all mitigations are **planned** — implementation begins in Phase 1.

A mitigation status tracker will be added to `/docs/security-mitigations.md` (TODO) as Phase 1 starts. It will map each threat ID to:
- Component owning the mitigation
- Phase delivery
- Test coverage
- Audit status

---

## 9. Open issues

These are gaps in the threat model itself, requiring further analysis:

- **OI-1**: Threat modeling for federated training (deferred to v2; will require LINDDUN extension for gradient leakage).
- **OI-2**: Threat model for the NexaCore OS update process (signed releases, rollback, downgrade attacks).
- **OI-3**: Insider-threat model for Stichting NexaCore itself (e.g., compromised key signing the reference implementation).
- **OI-4**: Cross-jurisdiction legal threats (e.g., compelled-backdoor scenarios). Out of pure technical scope but affect overall security posture.
- **OI-5**: Threat model for the WASM agent sandbox (depends on choice between WASM and process-level isolation).
- **OI-6**: Quantum-attack timeline modeling — specifically when classical crypto becomes unsafe.

---

## 10. Review cadence

This document is reviewed:

- At the close of every roadmap phase.
- Before any release (`v0.x`, `v1.0`, etc.).
- After any external security audit.
- Whenever the `Open issues` section grows by ≥ 3 entries.
- Whenever a mitigation moves from `Planned` to `Implemented`.

Each review produces an NCIP if substantive changes are made.
