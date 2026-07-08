---
ncip: 24
title: Tiered trust model — mesh participation beyond full-TEE hardware
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-27
updated: 2026-05-27
requires:
  - 16
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

NCIP-016 mandates Intel TDX or AMD SEV-SNP attestation for mesh
participation and explicitly excludes software-only fallbacks. While
this is correct for protecting the security model's invariants, it
restricts NexaCore OS mesh access to server-class and recent high-end
workstation hardware — a barrier to mass adoption.

This NCIP introduces a **tiered trust model** that preserves the
full-TEE security guarantees where they matter most (Tier 0 validators,
key custodians, sensitive-data handlers) while extending mesh
participation to devices with weaker-but-real hardware security
primitives. Four trust tiers are defined, each with explicit security
properties, permitted mesh roles, and protocol-level isolation. A node's
tier is determined at attestation time, encoded in the `TeeFamily`
discriminant, and propagated to every peer so routing and workload
assignment can respect trust boundaries.

The tiered model does NOT weaken the security of high-trust paths: a
Tier 0 node never relies on, or delegates sensitive data to, a lower-tier
node unless the user's policy explicitly permits it.

---

## Motivation

### M1. Hardware accessibility is the adoption bottleneck

Intel TDX is available only on 4th-generation Xeon Scalable (Sapphire
Rapids, 2023+) and later. AMD SEV-SNP is available on EPYC Milan
(3rd-gen, 2021+) and Ryzen Pro 7040+. As of 2026, the installed base of
TEE-capable consumer hardware is a fraction of the total x86_64 market.
ARM-based consumer devices (Apple M-series, Qualcomm Snapdragon, Samsung
Exynos) — billions of units — are entirely excluded from v1 mesh
participation.

A mesh protocol that requires datacenter-grade hardware to participate
cannot achieve the "million-node decentralized inference network" vision
of `docs/01-manifesto.md`. The protocol must meet users where their
hardware is.

### M2. Not all mesh roles require full confidential computing

The mesh protocol (`docs/03-mesh-protocol.md`) distributes workloads
across nodes with different roles:

- **Expert shard hosting** (Tier 2) — requires runtime memory
  encryption to protect model weights and intermediate activations.
  Full TEE is essential.
- **Relay / routing** — forwards FPE-encrypted packets without
  decrypting payloads. A relay node that cannot read payloads needs
  significantly weaker security guarantees than a node that decrypts
  them.
- **Reputation witness** — signs attestations of observed behavior.
  Requires attestation of node identity, not runtime memory encryption.
- **Bandwidth contribution** — provides connectivity. Needs Sybil
  resistance and identity binding, but not confidential compute.
- **Personal cluster participant** (Tier 1) — operates on a trusted
  LAN. The threat model (`docs/04-security-model.md`) already assumes
  physical co-location.

A single binary requirement (full TEE or nothing) collapses these
distinct trust requirements into one.

### M3. The `TeeFamily` enum already reserves extensibility

`crates/nexacore-tee/src/traits.rs` defines `TeeFamily` as `#[repr(u8)]`
with variants for Apple Secure Enclave (reserved v1.1) and ARM CCA
(reserved v1.2+). This NCIP extends that enum with two additional
families and formalizes the trust tier that each family maps to.

### M4. Competitive landscape demands breadth

Other decentralized compute networks (Gensyn, Together, Bittensor) do
not require TEE for participation. While their security model is weaker,
their node counts dwarf what a TEE-mandatory network can achieve. NexaCore
OS can differentiate by offering *graduated* security: strongest
guarantees where needed, broad participation otherwise.

---

## Specification

> **Normative keywords.** RFC 2119 / RFC 8174 (MUST, MUST NOT, SHOULD,
> SHOULD NOT, MAY).

### S1. Trust tier definitions

Four trust tiers are defined, numbered 0 (highest) through 3 (lowest).

| Tier | Name | Hardware requirement | Security properties | Permitted mesh roles |
|------|------|---------------------|---------------------|---------------------|
| 0 | **Full TEE** | Intel TDX, AMD SEV-SNP | Remote attestation, runtime memory encryption, sealed storage, key derivation bound to measurement | All roles: validator, key custodian, expert shard host, relay, reputation witness, bandwidth contributor |
| 1 | **Enclave-limited** | Apple Secure Enclave, ARM CCA Realms, discrete Secure Element (Titan M, Samsung Knox, Pluton) | Remote attestation, cryptographic operations inside enclave, key storage in enclave; no arbitrary-code execution in enclave, no runtime memory encryption of host RAM | Relay, reputation witness, bandwidth contributor, personal cluster participant (Tier 1 LAN), inference client with e2e-encrypted requests |
| 2 | **Measured boot** | TPM 2.0 (discrete or firmware) | Boot-time attestation (measured boot chain via PCR), sealed storage bound to boot state, no runtime memory protection | Bandwidth contributor, relay (forward-only, no payload inspection), reputation witness (reduced weight), Tier 0 local-only workloads |
| 3 | **Software-only** | None | End-to-end encryption, MPC participation, verifiable computation via STARK proofs; no hardware root of trust | Observer, lightweight client, MPC shard holder (≥ threshold honest nodes required), bandwidth contributor (lowest priority) |

### S2. `TeeFamily` enum extension

The `TeeFamily` enum in `crates/nexacore-tee/src/traits.rs` is extended with
two new variants and one metadata method:

```rust
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash,
         serde::Serialize, serde::Deserialize)]
pub enum TeeFamily {
    IntelTdx          = 1,
    AmdSevSnp         = 2,
    AppleSecureEnclave = 3,   // existing reserved, promoted to Tier 1
    ArmCca            = 4,    // existing reserved, promoted to Tier 1
    Tpm2              = 5,    // NEW — Tier 2
    SoftwareMpc       = 6,    // NEW — Tier 3
    Mock              = 0xFF,
}
```

A new method is added:

```rust
impl TeeFamily {
    /// Returns the trust tier (0–3) for this family. Lower is more
    /// trusted. The `Mock` family returns `u8::MAX` and MUST be
    /// rejected in production.
    #[must_use]
    pub const fn trust_tier(self) -> u8 {
        match self {
            Self::IntelTdx | Self::AmdSevSnp => 0,
            Self::AppleSecureEnclave | Self::ArmCca => 1,
            Self::Tpm2 => 2,
            Self::SoftwareMpc => 3,
            Self::Mock => u8::MAX,
        }
    }

    /// Returns `true` if this family provides runtime memory
    /// encryption (i.e., the host OS cannot read TEE-resident RAM).
    #[must_use]
    pub const fn has_memory_encryption(self) -> bool {
        matches!(self, Self::IntelTdx | Self::AmdSevSnp | Self::ArmCca)
    }

    /// Returns `true` if the family is accepted in production
    /// builds at any tier.
    #[must_use]
    pub const fn is_production(self) -> bool {
        !matches!(self, Self::Mock)
    }
}
```

Wire-format impact: the new variants (`5`, `6`) are one-byte
discriminants under `#[repr(u8)]`. Existing nodes that do not recognize
them MUST reject the quote (standard behavior per `NCIP-Serde-004`'s
unknown-variant handling). Rollout is therefore forward-compatible: old
nodes ignore new-tier nodes until upgraded.

### S3. `TrustTier` type

A new type encodes the tier for type-safe routing decisions:

```rust
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
         serde::Serialize, serde::Deserialize)]
pub enum TrustTier {
    FullTee       = 0,
    EnclaveLimited = 1,
    MeasuredBoot  = 2,
    SoftwareOnly  = 3,
}
```

`TrustTier` implements `Ord` such that `FullTee < EnclaveLimited <
MeasuredBoot < SoftwareOnly`, enabling `tier <= max_acceptable_tier`
comparisons in routing policy.

### S4. Attestation extensions per tier

#### S4.1 Tier 0 — Full TEE (unchanged)

Attestation follows NCIP-016 exactly. No modifications.

#### S4.2 Tier 1 — Enclave-limited

**Apple Secure Enclave:**

The backend produces an attestation using Apple's `DeviceCheck`
Attestation API (App Attest). The quote body contains:

- An App Attest assertion signed by the Secure Enclave's device key.
- A nonce embedding the mesh handshake challenge.
- The `receipts` field for freshness validation.

Measurement: SHA-256 hash of the NexaCore OS App Attest key identifier,
zero-padded to 48 bytes per the `Measurement` type's convention
(documented in `attestation.rs`).

Limitations vs Tier 0:
- The Secure Enclave executes only Apple-defined cryptographic
  operations. Arbitrary code (e.g., inference kernels) runs outside the
  enclave on unprotected host RAM.
- No sealed-blob migration between devices.
- Attestation freshness depends on Apple's infrastructure.

**ARM CCA Realms:**

The backend produces a CCA Realm attestation token (per ARM CCA
specification). The quote body contains the Realm token + Platform
token, signed by the Realm Attestation Key (RAK) and the Platform
Attestation Key (PAK).

Measurement: SHA-256 Realm Initial Measurement (RIM), zero-padded to
48 bytes.

ARM CCA Realms provide runtime memory encryption via the Granule
Protection Table (GPT) and are functionally closer to Tier 0.
`has_memory_encryption()` returns `true` for `ArmCca`. If a future NCIP
determines that ARM CCA provides equivalent guarantees to TDX/SEV-SNP,
the tier assignment MAY be revised to Tier 0 without breaking the wire
format.

#### S4.3 Tier 2 — Measured boot (TPM 2.0)

**Backend: `Tpm2Backend`**

The backend produces an attestation based on:

1. **TPM 2.0 Quote** — a signed structure covering selected Platform
   Configuration Registers (PCRs). The quote is signed by the TPM's
   Attestation Identity Key (AIK).
2. **Event log** — the TCG event log covering the boot chain, allowing
   the verifier to replay the PCR extend operations and confirm the boot
   measurements match the quote.

Measurement: SHA-384 hash of PCRs 0–7 (firmware, bootloader, kernel)
concatenated, truncated/padded to 48 bytes per `Measurement` convention.

PCR selection policy (normative):
- PCR 0: UEFI firmware
- PCR 1: UEFI firmware configuration
- PCR 2: Option ROMs
- PCR 4: Boot loader (NexaCore OS stage 1)
- PCR 5: Boot loader configuration
- PCR 7: Secure Boot policy
- PCR 8–9: NexaCore OS kernel image and initrd

The verifier maintains an allowlist of acceptable PCR value sets,
analogous to `KNOWN_MEASUREMENT_NexaCore_OS` in NCIP-016 § S7.

**Limitations vs Tier 0/1:**
- No runtime memory encryption. A root-level attacker on the host can
  read all process memory.
- No sealed storage bound to runtime state — only bound to boot state.
- Attestation proves "this machine booted the expected software chain"
  but NOT "the software is still unmodified at runtime."

**Mitigation of runtime gap:** Tier 2 nodes MUST NOT be assigned
workloads that require decrypting payload contents. The routing layer
treats Tier 2 as opaque-relay-only for sensitive data. Tier 2 nodes
MAY run local-only inference (Tier 0 workloads per
`docs/07-hardware-requirements.md` § "Local-only operation") where the
user accepts the local trust model.

#### S4.4 Tier 3 — Software-only

**Backend: `SoftwareMpcBackend`**

No hardware attestation is available. Instead, the node participates
via cryptographic protocols that do not require trusting any single
node:

1. **Identity binding** — an Ed25519 keypair generated locally. The
   public key serves as the node's identity. No hardware root of trust.
   Sybil resistance is provided by the compute-credit system (economic
   friction) and network-age weighting.

2. **MPC participation** — for workloads that support it, Tier 3 nodes
   participate in multi-party computation protocols (e.g., secret-shared
   inference via additive secret sharing over `Z_p`). Security holds as
   long as a threshold (`t` of `n`) of participants is honest. The
   threshold is configurable per workload and MUST be ≥ `n/2 + 1`.

3. **STARK-verified computation** — for verifiable inference paths, the
   node produces a STARK proof (per NCIP-Crypto-002) of correct
   execution. The verifier can confirm correctness without trusting the
   prover's hardware.

**Limitations:**
- Sybil resistance is purely economic/reputation-based.
- MPC incurs 3–10x compute overhead and requires synchronous
  coordination among `n` parties.
- STARK proof generation for large models is impractical in 2026 for
  anything beyond small classifiers.

### S5. Routing policy integration

The mesh routing layer (`nexacore-mesh`) MUST enforce tier-aware policies:

```rust
pub struct RoutingPolicy {
    /// Maximum tier accepted for this workload class.
    pub max_tier: TrustTier,
    /// If true, the workload involves decrypting PII-bearing payloads.
    /// Only Tier 0 nodes are eligible.
    pub requires_memory_encryption: bool,
    /// If true, the workload involves long-term key custody.
    /// Only Tier 0 nodes are eligible.
    pub requires_sealed_storage: bool,
    /// Minimum reputation score for the selected tier.
    pub min_reputation: f32,
}
```

Default routing policies per workload class:

| Workload class | `max_tier` | `requires_memory_encryption` | `requires_sealed_storage` |
|---------------|------------|-------|-------|
| Expert shard hosting | `FullTee` | true | true |
| Key custody | `FullTee` | true | true |
| PII-bearing inference | `FullTee` | true | false |
| Non-PII inference | `EnclaveLimited` | false | false |
| Relay (forward-only) | `SoftwareOnly` | false | false |
| Reputation witness | `MeasuredBoot` | false | false |
| Bandwidth contribution | `SoftwareOnly` | false | false |

Users MAY override these defaults via node-local policy, but MUST NOT
lower the tier requirement below what the workload class's privacy
invariants require. The mesh protocol layer enforces this by rejecting
workload assignments that violate the minimum tier for the workload's
compliance proof requirements.

### S6. Handshake extension

The mesh handshake (`docs/protocol/handshake.md`) is extended to include
the attestor's trust tier in the attestation exchange:

```
m2 (attestation response):
  ... existing fields ...
  + tee_family: TeeFamily     (1 byte, u8 discriminant)
  + trust_tier: TrustTier     (1 byte, u8 discriminant, derived from tee_family)
```

The `trust_tier` field is redundant (derivable from `tee_family`) but
included for:
1. Forward compatibility — future NCIPs may reclassify a family's tier.
2. Fast routing — relays can inspect tier without mapping the family.

The verifier MUST validate that `trust_tier == tee_family.trust_tier()`
and reject the handshake if mismatched.

### S7. `BackendKind` extension (NCIP-016 § S4)

The `BackendKind` enum from NCIP-016 is extended:

```rust
#[non_exhaustive]
pub enum BackendKind {
    IntelTdx,
    AmdSevSnp,
    AppleSecureEnclave,
    ArmCca,
    Tpm2,
    SoftwareMpc,
    Stub,
}
```

### S8. Tier isolation invariants (normative)

The following invariants MUST hold and are enforced by the protocol:

1. **No trust escalation.** A lower-tier node MUST NOT be treated as
   equivalent to a higher-tier node for any security-critical decision.
   A Tier 2 relay cannot vouch for the integrity of a Tier 0 workload.

2. **No implicit delegation.** Tier 0 workloads MUST NOT be assigned to
   Tier 1+ nodes without explicit user consent per workload class
   (not a blanket setting).

3. **Tier is immutable per session.** A node's tier is determined at
   attestation time and MUST NOT change during a session. Re-attestation
   (e.g., after a firmware update) starts a new session.

4. **Tier is non-spoofable.** The tier is derived from the `TeeFamily`
   in the verified attestation quote. A Tier 2 node cannot claim Tier 0
   because the TPM quote format is structurally distinct from a TDX
   quote; the verifier's family-specific parser rejects mismatched
   formats.

5. **Compliance proof binding.** Compliance proofs (per
   `docs/04-security-model.md` § "Compliance proofs") MUST include the
   destination node's tier. A proof bound to Tier 0 is invalid at a
   Tier 1+ node.

---

## Rationale

### R1. Why four tiers (not two, not continuous)

**Considered alternative: binary (TEE / no-TEE).**
This is the current model (NCIP-016). It maximizes simplicity but
excludes billions of devices. The gap between "full confidential
computing" and "no hardware security at all" is enormous; collapsing
it into a binary loses real security value from TPMs and secure
enclaves.

**Considered alternative: continuous trust score (0.0–1.0).**
A continuous score offers finer granularity but is harder to reason
about for routing policy ("is 0.72 good enough for expert shard
hosting?"). It also invites gaming and score inflation. Discrete tiers
with clear security properties are easier to audit and to explain to
users.

Four tiers map naturally to the four distinct hardware security profiles
that exist in the market today.

### R2. Why ARM CCA is Tier 1, not Tier 0

ARM CCA Realms provide runtime memory encryption via the Granule
Protection Table and are architecturally similar to TDX/SEV-SNP.
However:

- The ARM CCA ecosystem is nascent (2025–2026 first silicon).
- Attestation infrastructure (equivalent to Intel DCAP or AMD VCEK
  chains) is less mature.
- Real-world side-channel resistance is unproven at scale.

Placing ARM CCA at Tier 1 initially is a conservative choice. The NCIP
explicitly permits re-classification to Tier 0 via a follow-up NCIP once
the ecosystem matures, without wire-format changes.

### R3. Why TPM 2.0 is Tier 2, not Tier 1

TPM 2.0 provides excellent boot-time attestation but no runtime memory
protection. An attacker with root access can read all process memory
after boot. This is a fundamental gap: the mesh protocol's privacy
invariant ("PII never appears in cleartext on the network") cannot be
enforced by a TPM alone, because PII is transiently in cleartext in host
RAM during inference.

Tier 2 compensates by restricting TPM-only nodes to roles that never
handle cleartext PII: opaque relay, bandwidth contribution, and
reputation witness (at reduced weight).

### R4. Why include Tier 3 (software-only) at all

**Considered alternative: exclude software-only entirely.**
This preserves the "hardware root of trust" purity but blocks the
onboarding funnel: a user who wants to try NexaCore OS on existing hardware
has no path to mesh participation. Even a limited role (observer,
bandwidth contributor) builds ecosystem familiarity and eventual hardware
upgrade motivation.

Tier 3 nodes contribute real value (bandwidth, MPC shards where
applicable) while the protocol's cryptographic design (e2e encryption,
STARK proofs, MPC thresholds) prevents them from compromising the
network even if fully malicious.

### R5. Why `trust_tier` is redundant in the handshake

Including a field derivable from `tee_family` seems wasteful.
Justification:

1. A future NCIP may reclassify a family without changing the `TeeFamily`
   discriminant (e.g., ARM CCA promoted to Tier 0). If tier is only
   derived at parse time, all nodes must be upgraded simultaneously.
   An explicit field allows the sender to declare "I am Tier 0 ARM CCA"
   even before the verifier's mapping table is updated — the verifier
   can accept or reject based on its local policy.
2. Relays that do not parse quotes can still filter by tier.

### R6. What we are NOT doing in this NCIP

- **No weakening of Tier 0 requirements.** NCIP-016's TDX/SEV-SNP
  attestation remains the gold standard. This NCIP only adds tiers
  below it.
- **No mandatory MPC for all workloads.** MPC is an option for Tier 3
  participation, not a protocol-wide requirement.
- **No FHE (Fully Homomorphic Encryption).** FHE is 1000x+ slower
  than native execution in 2026 and impractical for inference
  workloads. Future NCIP MAY revisit as the field matures.
- **No hardware purchasing recommendations.** This NCIP defines protocol
  behavior, not market guidance.

---

## Backwards Compatibility

### Wire format

New `TeeFamily` variants (`Tpm2 = 5`, `SoftwareMpc = 6`) are
`#[repr(u8)]` discriminants. Existing v1 nodes that do not recognize
these discriminants MUST reject the quote per `NCIP-Serde-004`'s
unknown-variant rejection rule. This is safe: the rejecting node simply
refuses to peer with the new-tier node, which is the correct behavior
until the rejecting node is upgraded.

### Existing Tier 0 nodes

No behavioral change for existing Tier 0 nodes. They continue to
operate exactly as NCIP-016 specifies. The only visible change is the
presence of new `TeeFamily` values in peer discovery; these are filtered
by the routing policy's `max_tier` setting.

### `is_production()` semantic change

The current `is_production()` method returns `true` only for
`IntelTdx` and `AmdSevSnp`. This NCIP changes it to return `true` for
all non-`Mock` families. Code that relied on `is_production()` to mean
"full TEE" MUST migrate to `trust_tier() == 0` or
`has_memory_encryption()`. A deprecation warning SHOULD be emitted
during the transition period.

### `docs/07-hardware-requirements.md` update

The "Explicitly unsupported" section is revised: "Pre-TEE hardware"
gains a nuance — such hardware MAY participate at Tier 2 (if TPM 2.0
is present) or Tier 3 (software-only). The "no software-only
attestation fallback for the mesh" statement is replaced with
"software-only nodes participate at Tier 3 with restricted roles."

---

## Test Cases

### TC1. Tier derivation from `TeeFamily`

For each `TeeFamily` variant, `trust_tier()` returns the expected tier:

| Variant | Expected tier |
|---------|--------------|
| `IntelTdx` | 0 |
| `AmdSevSnp` | 0 |
| `AppleSecureEnclave` | 1 |
| `ArmCca` | 1 |
| `Tpm2` | 2 |
| `SoftwareMpc` | 3 |
| `Mock` | `u8::MAX` |

### TC2. Routing policy enforcement

A workload with `max_tier = FullTee` assigned to a node whose
`tee_family.trust_tier() > 0` MUST be rejected by the routing layer
with `RoutingError::TierInsufficient`.

### TC3. Handshake tier validation

A handshake message where `trust_tier` does not equal
`tee_family.trust_tier()` MUST be rejected with
`HandshakeError::TierMismatch`.

### TC4. TPM 2.0 attestation round-trip

On a machine with TPM 2.0 (testable on any modern laptop):

1. Generate a TPM quote covering PCRs 0–7.
2. Wrap in `Quote { family: Tpm2, ... }`.
3. Verify via `Tpm2Backend::verify_quote()`.
4. Confirm `trust_tier()` returns `2`.

### TC5. Wire-format forward compatibility

Serialize a `Quote` with `family = Tpm2` using `postcard`. Attempt
deserialization on a node running pre-NCIP-024 code. Expect a
deserialization error (unknown enum variant), NOT a crash or silent
acceptance.

### TC6. `is_production()` migration

Code that previously used `is_production()` to gate Tier 0-only
behavior MUST be identified (via `grep`) and migrated to
`trust_tier() == 0`. A CI check (`scripts/lint-ncips.py` or dedicated
lint) SHOULD flag any new call to `is_production()` without an
accompanying tier check.

### TC7. Tier isolation: no trust escalation

Construct a scenario where a Tier 2 node attempts to respond to an
`AttestRequest::Verify` for a workload tagged `max_tier = FullTee`.
The verification MUST fail with `AttestErrorCode::TierInsufficient`
(new error code).

---

## Reference Implementation

N/A at filing. Expected implementation path:

### Phase 1 (NCIP-024a): `TeeFamily` extension + `TrustTier` type
- Modify `crates/nexacore-tee/src/traits.rs`: add `Tpm2`, `SoftwareMpc`
  variants, `trust_tier()`, `has_memory_encryption()` methods.
- Add `TrustTier` enum to `crates/nexacore-tee/src/traits.rs`.
- Migrate all `is_production()` call sites.
- Update `crates/nexacore-tee/src/mock.rs` to test tier derivation.

### Phase 2 (NCIP-024b): TPM 2.0 backend
- New module: `crates/nexacore-tee/src/tpm2.rs`.
- Dependency: `tss-esapi` crate (Rust bindings for TPM 2.0 TSS).
- PCR quote generation and verification.
- Event log parsing and replay.

### Phase 3 (NCIP-024c): Software MPC backend
- New module: `crates/nexacore-tee/src/software_mpc.rs`.
- Ed25519 identity-only attestation.
- MPC protocol integration point (protocol-specific NCIP TBD).

### Phase 4 (NCIP-024d): Routing policy integration
- Modify `nexacore-mesh` routing layer to consume `TrustTier`.
- Implement `RoutingPolicy` enforcement.
- Update handshake to include tier field.

---

## Security Considerations

### SC1. The tiered model does NOT weaken Tier 0

The critical security invariant: **introducing lower tiers MUST NOT
reduce the security of Tier 0 interactions.** This is enforced by:

- Tier isolation invariants (§ S8): a Tier 0 workload is never
  delegated to a lower-tier node without explicit user consent.
- Compliance proof binding: proofs are bound to the destination tier;
  a proof for Tier 0 is invalid at Tier 1+.
- Routing policy defaults: all PII-bearing and key-custody workloads
  default to `max_tier = FullTee`.

### SC2. Tier 2 runtime gap

TPM 2.0 attests boot state but not runtime state. A root-level attacker
on a Tier 2 node can:

- Read all process memory (no memory encryption).
- Modify running code (no runtime integrity monitoring from the TPM).
- Forge local attestation claims (but NOT TPM quotes — the TPM's
  signing key is hardware-protected).

Mitigations:
- Tier 2 nodes are restricted to opaque-relay roles. They never
  decrypt payload contents.
- The TPM quote proves the node booted legitimate software. An
  attacker who compromises a running Tier 2 node cannot produce a
  fresh TPM quote with a different boot chain.
- Reputation scoring weights Tier 2 attestations lower than Tier 0.

### SC3. Tier 3 Sybil resistance

Software-only nodes have no hardware identity anchor. A single
adversary can spin up thousands of Tier 3 nodes.

Mitigations:
- Compute-credit bootstrapping: new nodes receive minimal initial
  credits and must contribute before consuming.
- Network-age weighting: recent nodes have low reputation.
- MPC threshold: even if `t-1` of `n` Tier 3 nodes are Sybils, the
  protocol is secure as long as `t` honest nodes participate.
- Tier 3 nodes cannot access Tier 0/1 workloads regardless of
  reputation.

### SC4. Tier promotion attacks

An attacker might attempt to claim a higher tier than their hardware
supports. Defense:

- The tier is derived from the `TeeFamily` in the *verified*
  attestation quote. The verifier parses the quote using the
  family-specific parser. A TPM quote cannot pass the TDX parser
  and vice versa — the formats are structurally incompatible.
- The handshake includes a redundant `trust_tier` field validated
  against `tee_family.trust_tier()`. A mismatch terminates the
  handshake.

### SC5. Apple Secure Enclave limitations

Apple's attestation relies on Apple's infrastructure (`DeviceCheck`
servers). If Apple's servers are unavailable, attestation fails. This
is an availability risk, not a security risk — the fail-closed
behavior is correct.

Apple does not publish the Secure Enclave's firmware for independent
audit. The NexaCore OS project trusts Apple's attestation chain at Tier 1
level, which is a weaker trust assumption than Tier 0 (where Intel/AMD
publish sufficient documentation for independent verification).

### SC6. Threat model per tier

| Attacker class (from `docs/04-security-model.md`) | Tier 0 defense | Tier 1 defense | Tier 2 defense | Tier 3 defense |
|---|---|---|---|---|
| A1 (malicious local app) | TEE memory isolation | Enclave-protected keys; host RAM exposed | Boot attestation only; host RAM exposed | No hardware defense; MPC threshold |
| A4 (curious cloud) | TEE-sealed computation | Enclave-sealed keys; compute on host | TPM-attested boot; no runtime protection | E2E encryption; MPC |
| A5 (physical attacker) | TDX/SEV-SNP memory encryption | Secure Enclave tamper resistance | TPM tamper resistance (key storage only) | No defense |

### SC7. New error code

`AttestErrorCode` (NCIP-016 § S4) is extended with:

```rust
#[non_exhaustive]
pub enum AttestErrorCode {
    // ... existing variants ...
    TierInsufficient,  // NEW — requested workload requires a higher trust tier
}
```

---

## Privacy Considerations

### PC1. Tier as metadata leakage

A node's trust tier reveals information about its hardware:
- Tier 0 → datacenter or recent workstation (expensive hardware).
- Tier 1 → Apple Silicon or ARM CCA device.
- Tier 2 → any modern PC with TPM.
- Tier 3 → unknown/minimal hardware.

This is a mild privacy concern: it narrows the anonymity set. However,
the existing NCIP-016 model already leaks hardware information (TDX vs
SEV-SNP identifies the CPU vendor). The tier system does not
significantly worsen this.

Mitigation: the onion routing layer (`docs/03-mesh-protocol.md` §
"optional onion routing through 3 hops") hides the tier of the
originating node from non-adjacent peers.

### PC2. TPM-based hardware fingerprinting

TPM 2.0 Endorsement Keys (EK) are unique per TPM chip. If the EK is
exposed during attestation, it serves as a persistent hardware
fingerprint.

Mitigation: the Tier 2 attestation protocol MUST use an Attestation
Identity Key (AIK) that is ephemeral per NexaCore OS installation. The EK
is used only to certify the AIK via the Privacy CA or DAA (Direct
Anonymous Attestation) protocol. The TPM backend MUST support DAA where
available to maximize unlinkability.

### PC3. Tier 3 linkability

Tier 3 nodes use Ed25519 keypairs as identity. These keys are
persistent across sessions (necessary for reputation tracking) but
linkable. A Tier 3 node that participates over time builds a behavioral
profile linkable to its key.

Mitigation: Tier 3 nodes MAY rotate keys periodically, accepting the
reputation reset. The protocol does not enforce key persistence for
Tier 3.

### PC4. GDPR considerations

No new PII processing beyond what NCIP-016 already permits. The tier
system introduces hardware-class metadata (a `u8` discriminant) which
is not personal data under GDPR. The TPM backend's use of AIK (not EK)
avoids creating a persistent identifier linkable to a natural person.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
