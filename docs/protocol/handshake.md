# NexaCore OS Mesh Handshake — Formal Specification

**Status:** Draft v0.1 — pending external cryptographer review (P3.2)
**NCIP:** to be ratified as `NCIP-Protocol-003` (Standards Track)
**Authors:** cySalazar
**Last updated:** 2026-05-21

This document is the **authoritative wire-level specification** of the mesh handshake.
Any implementation in `crates/nexacore-mesh` MUST conform to this document; any conflict is
a bug in the implementation. The handshake is implemented in two layers:

1. **Transport layer** — QUIC with TLS 1.3, providing reliable ordered streams and
   forward secrecy at the TCP-equivalent layer.
2. **NexaCore mesh handshake** — Noise_IK with mandatory mutual TEE attestation, layered
   *inside* the QUIC stream. This is the NexaCore-specific part: the protocol assumes
   the QUIC layer is already in place and adds attestation + compliance enforcement
   on top.

---

## 1. Notation

| Symbol | Meaning |
|---|---|
| `A`, `B` | The two parties. `A` initiator, `B` responder. |
| `sk_X`, `pk_X` | Static long-term ED25519 keypair of party `X`. Derived from the TEE attestation chain — `pk_X` is bound to the TEE measurement. |
| `esk_X`, `epk_X` | Ephemeral X25519 keypair of party `X`. Fresh per handshake. |
| `Quote_X` | Remote attestation report (Intel TDX quote v4 or AMD SEV-SNP attestation report v2). Contains: TEE measurement, freshness nonce, signed by the platform attestation key. |
| `nonce_X` | 32-byte random nonce contributed by party `X`. |
| `m1`, `m2`, `m3` | Wire messages in the handshake. |
| `H(...)` | BLAKE3 with domain separator `"NexaCore-PROTO-v0.2/handshake"`. |
| `KDF(ikm, info)` | HKDF-SHA-256 with `info = "NexaCore-PROTO-v0.2/handshake/" || info_suffix`. |
| `Sig_X(m)` | ED25519 signature by `sk_X` over `m`. `verify_strict` is used on the receiver. |
| `DH(esk, epk)` | X25519 Diffie–Hellman. Result is rejected if it equals the all-zero element (low-order point detection). |
| `AEAD(k, nonce, aad, m)` | ChaCha20-Poly1305 (RFC 8439). |
| `||` | Byte concatenation. |
| `proto_version` | The 16-byte protocol version string. Current: `"NexaCore-PROTO-v0.2"` padded to 16 bytes with `\x00`. `"NexaCore-PROTO-v0.1"` is removed; see §4.1. |
| `serde_format` | Wire-encoding discriminant `"postcard-1.0"` per `NCIP-Serde-004` § S2 (Active since 2026-05-22 by `NCIP-Process-001` §5.3 ¶1 founder ballot — see [`docs/audits/ncip-editors-report-2026-Q2.md`](../audits/oip-editors-report-2026-Q2.md)). `NexaCore-PROTO-v0.2` implies `postcard-1.0`; `NexaCore-PROTO-v0.1` implied `bincode-2`. |

---

## 2. Goals and invariants

The handshake MUST establish the following properties:

| ID | Invariant | Verified by |
|---|---|---|
| **I1** | Mutual authentication: both parties prove possession of their static key. | Property-test on test vectors, Tamarin proof in `/protocol-proofs/handshake.spthy`. |
| **I2** | Forward secrecy: compromise of `sk_X` after the handshake does NOT reveal session keys. | Tamarin proof. |
| **I3** | Mutual TEE attestation: both parties prove their static key is bound to a currently-valid TEE measurement on an allowlisted hardware family. | Tamarin proof; runtime measurement-allowlist check (see §4.5). |
| **I4** | Attestation freshness: a replayed `Quote` from a previous session is rejected. | Quote contains a nonce contributed by the peer; nonce uniqueness enforced by `nonce_X` length (256 bits). |
| **I5** | Key Compromise Impersonation (KCI) resistance: even with `sk_A` compromised, an attacker cannot impersonate `B` to `A`. | Tamarin proof. |
| **I6** | Unknown Key-Share (UKS) resistance: after handshake, both parties agree on the *identities* used, not only the keys. | Both parties' identities are mixed into the session-key derivation (see `KDF` info strings). Tamarin proof. |
| **I7** | Protocol-version binding: a downgrade to an earlier protocol version cannot succeed silently. | `proto_version` is mixed into every KDF call AND signed in the transcript. |
| **I8** | Measurement-list binding: the set of allowlisted TEE measurements at session-establishment time is committed in the transcript so that an "evicted" measurement cannot retroactively be honored. | Transcript hash includes a Merkle root of the active measurement allowlist; verifier checks it matches its local view ± `Δ_measurement_window` (default 24 h). |

---

## 3. Wire format

### 3.1. Message 1: `A → B` (`m1`)

```
m1 = proto_version || epk_A || nonce_A || Quote_A || Sig_A(transcript_after_m1_payload)
```

where `transcript_after_m1_payload = H(proto_version || epk_A || nonce_A || Quote_A)`.

- `proto_version`: 16 bytes.
- `epk_A`: 32 bytes (X25519 public key).
- `nonce_A`: 32 bytes (random).
- `Quote_A`: variable, length-prefixed (4-byte big-endian `u32`).
- `Sig_A(...)`: 64 bytes.

### 3.2. Message 2: `B → A` (`m2`)

`B` computes:
- `dh1 = DH(esk_B, epk_A)`.
- `chain_key_0 = KDF(H(transcript_after_m1) || dh1, "chain-0")`.

Then:

```
m2_payload = epk_B || nonce_B || Quote_B || measurement_root || Sig_B(transcript_after_m2_payload)
m2 = AEAD(k_resp_0, nonce_0, aad = transcript_after_m1, m2_payload)
```

where:
- `transcript_after_m2_payload = H(transcript_after_m1 || epk_B || nonce_B || Quote_B || measurement_root)`.
- `measurement_root`: 32-byte BLAKE3 Merkle root of the active measurement allowlist at `B`.
- `k_resp_0 = KDF(chain_key_0, "responder-0")`.
- `nonce_0 = 96-bit zero (first AEAD message in chain)`.

### 3.3. Message 3: `A → B` (`m3`)

`A` verifies `m2`, then computes:
- `dh2 = DH(epk_B, esk_A)`.
- `chain_key_1 = KDF(chain_key_0 || dh2, "chain-1")`.

Then `A` MUST verify `measurement_root` matches its local view ± `Δ_measurement_window`.

```
m3_payload = measurement_ack || compliance_capabilities || Sig_A(transcript_after_m3_payload)
m3 = AEAD(k_init_0, nonce_0, aad = transcript_after_m2, m3_payload)
```

where:
- `measurement_ack`: 32-byte BLAKE3 hash of the intersection of `A`'s and `B`'s allowlists. Both sides MUST compute the same value, else abort.
- `compliance_capabilities`: opaque byte string with `A`'s declared compliance proof scheme(s) — e.g. `"sig-v1"`, `"stark-v0"`. See `NCIP-Crypto-002`.
- `k_init_0 = KDF(chain_key_1, "initiator-0")`.

### 3.4. Session keys

After `m3` is accepted, both parties derive:

```
k_send_A = KDF(chain_key_1, "session-init→resp")
k_send_B = KDF(chain_key_1, "session-resp→init")
```

These are the AEAD keys for the rest of the session. Each direction has its own
nonce counter starting at `1` (after the handshake AEAD nonces consumed `0`).

The handshake is complete; static keys (`sk_A`, `sk_B`) MUST be zeroized from
working memory of the QUIC handler. They remain accessible only through the TEE
sealed-key API for next-session signing.

---

## 4. Verification rules (receiver side)

A conforming implementation MUST enforce all the following checks. Failure on
any check is a fatal abort: the QUIC stream is closed, the peer is **not**
penalized in reputation (could be a buggy implementation, not malice), but the
event is logged.

### 4.1. Protocol-version pin

The implementation negotiates `NexaCore-PROTO-v0.2` only. No silent downgrade is
permitted; downgrade requires an explicit "version-renegotiation" frame *before*
`m1`, which itself is bound into a new `proto_version` field. `NexaCore-PROTO-v0.1`
is removed from the negotiation menu as of `NCIP-Serde-004` reaching `Active`
(2026-05-22 by `NCIP-Process-001` §5.3 ¶1 founder ballot — see
[`docs/audits/ncip-editors-report-2026-Q2.md`](../audits/oip-editors-report-2026-Q2.md));
peers announcing only v0.1 MUST be rejected (no silent downgrade).
No legacy support window exists.

### 4.2. Ephemeral-key sanity

Reject `epk_A` (or `epk_B`) if `DH(epk_X, identity_low_order_point) == 0`. This
catches the eight X25519 low-order points and prevents key-collision attacks.

### 4.3. Quote validation

Validate `Quote_X`:

- TEE family is on the active allowlist (see `docs/07-hardware-requirements.md`).
- Signature chain validates against vendor PCK (Provisioning Certification Key).
- Quote nonce equals `H(transcript_so_far)` — bound to this handshake, not replayable.
- Quote freshness window: TDX `cpusvn`/`tcb_status` are within allowlist; SEV-SNP `reported_tcb` is within allowlist.
- TEE measurement (MRTD / MRENCLAVE-equivalent) is on the per-protocol-version measurement allowlist.

### 4.4. Signature verification

`Sig_X(transcript)` is verified with `ed25519-dalek`'s `verify_strict` (rejects
malleable forms, S-bound > L). Failure aborts the handshake.

### 4.5. Measurement-root binding

`A` verifies that `measurement_root` sent by `B` matches `A`'s own measurement
root *up to staleness `Δ_measurement_window`*. The "staleness" window allows
allowlist propagation lag. If the windows diverge by more than `Δ`, the receiver
queries the NCIP-published measurement registry endpoint to refresh, then retries
once. A second failure is a hard abort.

### 4.6. Compliance-capability intersection

The session adopts the compliance proof scheme declared by the *initiator* in
`compliance_capabilities` IF the responder supports it; else the lowest
common-denominator wins, with `"sig-v1"` as mandatory baseline.

---

## 5. State machine

```
                  ┌──────────┐         m1          ┌──────────┐
   START ─────────┤ INIT_SENT├────────────────────►┤  M1_RECV │
                  └──────────┘                     └─────┬────┘
                       ▲                                 │
                       │ m2 verified                     │ validate m1
                       │                                 │ generate m2
                       │                                 ▼
                  ┌────┴─────┐         m2          ┌──────────┐
                  │  M2_RECV │◄────────────────────┤ M2_SENT  │
                  └────┬─────┘                     └──────────┘
                       │ validate m2
                       │ generate m3
                       ▼
                  ┌──────────┐         m3          ┌──────────┐
                  │  M3_SENT │────────────────────►│  M3_RECV │
                  └────┬─────┘                     └─────┬────┘
                       │                                 │
                       └─────► SESSION_ACTIVE ◄──────────┘
```

Each transition has a timeout (`T_handshake = 5 s` default; configurable per
deployment). Timeout = abort.

---

## 6. Quote nonce binding (replay defense)

This is the load-bearing detail for **I4**.

Each `Quote_X` is generated with a *nonce-field* equal to `H(transcript_so_far)`.
A replayed quote — even from the same peer, from a previous session — has a
different transcript hash because `nonce_A` and `epk_A` are fresh per session.
The TEE platform refuses to generate a quote without honoring the nonce field;
the verifier refuses any quote whose nonce field doesn't match the expected
transcript hash.

A failing TEE that accepted any nonce would break replay defense but NOT the
other invariants (signature, transcript binding still protect). This is a
multi-layer defense by design.

---

## 7. Open issues for cryptographer review (P3.2)

The cryptographer's deliverable should explicitly opine on:

1. **`measurement_root` Δ-window**: 24 h default is engineering judgment, not
   cryptographically derived. Is there a principled choice?
2. **`compliance_capabilities` negotiation**: currently last-writer-wins on
   capability mismatch. Is this exploitable for downgrade?
3. **Quote nonce as a hash of transcript-so-far**: TDX quotes have a 64-byte
   nonce field; this fits BLAKE3-256 || zeros but TDX firmware may not constant-time
   compare. Is this a side-channel concern?
4. **Post-handshake key rotation**: not specified here. The `chain_key_1` is used
   to derive both directions; we rotate every 2 GiB or every 1 h. Is this
   sufficient for a 10-year session model?
5. **Post-quantum migration path**: handshake uses X25519 + ED25519 only. We plan
   a hybrid mode (Kyber768 + ML-DSA) for v1.x. Is the current transcript
   structure compatible with adding a hybrid KEM without breaking I1–I8?

---

## 8. References

- `/docs/02-architecture.md` § "Execution tiers"
- `/docs/03-mesh-protocol.md` § "Transport"
- `/docs/04-security-model.md` § "TEE compromise resistance", § "Privacy by construction"
- `/docs/07-hardware-requirements.md`
- `/protocol-proofs/handshake.spthy` — Tamarin model
- `/ncips/ncip-crypto-002.md` — STARK vs SNARK for compliance proofs
- RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 8439 (ChaCha20-Poly1305), RFC 5869 (HKDF)
- Intel TDX Module Specification 1.5; AMD SEV-SNP ABI 1.55
- `nexacore_types::version::PROTOCOL_VERSION_V0_2` — canonical Rust constant; see `crates/nexacore-types/src/version.rs`.
- `/ncips/ncip-serde-004.md` — `bincode → postcard` migration; bumps protocol version to v0.2 (Active since 2026-05-22 by `NCIP-Process-001` §5.3 ¶1 founder ballot; activation phase §7 dormant until Phase 4+ mesh telemetry exists).
- `/docs/audits/ncip-editors-report-2026-Q2.md` — editorial tally for the NCIP-Serde-004 + NCIP-Bounty-002 `Last Call → Active` closure on 2026-05-22.
