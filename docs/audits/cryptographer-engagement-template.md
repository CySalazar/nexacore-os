# Cryptographer Engagement Template

**Status:** Draft v0.1 — template for the backlog P3.2 closure
**Last updated:** 2026-05-10

This document is the canonical template for engaging an external cryptographer
to peer-review the cryptographic protocol design of NexaCore OS. It is referenced
from [`SECURITY.md`](../../SECURITY.md) and [`CONTRIBUTORS.md`](../../CONTRIBUTORS.md).

## Engagement modes

Two modes are supported. The choice depends on the cryptographer's preference
and the project's funding state at the moment of engagement.

### Mode A — Paid review

- **Compensation:** USD 8,000–15,000 lump sum for the review window described
  below, scaled to seniority. Wire transfer or stablecoin acceptable.
- **Funding source:** Stichting NexaCore operating budget. Until Stichting is
  constituted, the founder funds personally and is reimbursed at constitution.
- **Deliverable timeline:** 4–6 weeks from kickoff to written report.

### Mode B — Volunteer review

- **Compensation:** none, but the cryptographer is offered:
  - Public attribution in [`CONTRIBUTORS.md`](../../CONTRIBUTORS.md).
  - Co-authorship credit on the resulting NCIP (`NCIP-Crypto-004`, the formal
    review record).
  - A seat on the Crypto Advisory Board (informal, advisory only) once the
    Stichting forms its scientific advisory body.

The project has no preference between modes; the cryptographer's preference
governs.

## Scope

The cryptographer's review covers, in order of priority:

1. **`nexacore-crypto` API design**
   - `aead`, `signing`, `kex`, `hash`, `kdf` modules.
   - Trait surface, key types, zeroization patterns.
   - Test vectors against RFCs.
2. **Mesh handshake specification**
   ([`/docs/protocol/handshake.md`](../protocol/handshake.md))
   - Wire format soundness.
   - Invariants I1–I8.
   - Open issues §7 in the handshake spec.
3. **Tamarin model**
   ([`/protocol-proofs/handshake.spthy`](../../protocol-proofs/handshake.spthy))
   - Mechanically check the lemmas.
   - Extend lemmas to cover I3 (mutual TEE attestation binding), I7 (measurement-root
     binding), I8 (compliance-capability downgrade resistance).
4. **Capability attenuation**
   - Property-test the monotonicity invariant in `crates/nexacore-capability/src/attenuation.rs`.
   - Adversarial scenarios.
5. **Compliance proof scheme** ([`/ncips/ncip-crypto-002.md`](../../oips/oip-crypto-002.md))
   - STARK choice over SNARK — sound for v1.0?
   - `sig-v1` baseline — sufficient as fallback?
   - Negotiation downgrade resistance.

Out of scope (handled by separate engagements):

- Implementation-level audit (e.g., side-channel timing on production builds) — separate audit firm.
- Formal verification of `nexacore-kernel` (target: P6 mid-Phase-1 audit).
- TEE attestation chain validation (vendor-specific; relies on Intel/AMD audits
  of their own platforms, supplemented by our wrapper review).

## Deliverables

The cryptographer produces a single document:
`/docs/audits/2026-XX-crypto-peer-review.md` containing:

1. **Executive summary** — go / no-go for v1.0 release as currently specified.
2. **Findings table** — each finding tagged Severity {Critical | High | Medium | Low | Informational}, with:
   - Description.
   - Reproduction or proof-sketch.
   - Proposed remediation.
   - Project response (filled in by founder during disposition).
3. **Tamarin proof results** — output of `tamarin-prover handshake.spthy --prove`
   committed to the proofs directory.
4. **Acknowledgement and credential** — name, affiliation (if applicable),
   PGP-signed statement that the review was conducted in good faith.

A redacted public version is published; the full version stays in
`/docs/audits/private/` (not committed to the public repo, distributed
out-of-band to the cryptographer and the trustees).

## Process

1. **Initial contact** — founder reaches out via cryptographer's published
   contact channel. Mention NexaCore OS, the Apache-2.0 license, the privacy-first
   mission, and link this template.
2. **NDA / engagement letter** — Mode A only. Standard ICO-aligned NDA;
   nothing exotic.
3. **Kickoff meeting** — 60-min video call. Walk through the architecture, the
   threat model, and the scope of review. Record (with consent) for the
   founder's own notes; not published.
4. **Async review window** — 4–6 weeks. Cryptographer has read access to a
   private branch with the materials; can file private issues.
5. **Mid-point check-in** — 30-min call at week 2 or 3 to clear blockers.
6. **Report draft** — cryptographer submits draft; founder reviews and may
   request clarifications.
7. **Disposition** — for each finding, founder responds: accept (and remediate),
   reject (with rationale), or defer (with timeline).
8. **Public release** — redacted report published; NCIP-Crypto-004 ratified.
9. **Payment** — Mode A only; settled within 30 days of report acceptance.

## Selection criteria

The cryptographer should have at minimum:

- A PhD in cryptography OR equivalent industry track record (e.g., maintainer
  of a major crypto library, published author at IACR venues).
- Familiarity with: Diffie–Hellman, Noise protocols, formal protocol analysis
  (Tamarin / ProVerif), Macaroons or capability cryptography.
- No conflicts of interest with: surveillance vendors, sanctioned entities,
  Stichting NexaCore excluded funders (per [`docs/08-funding-policy.md`](../08-funding-policy.md)).

Candidates known to the project (long-list to be refined):

- Members of the **RustCrypto** maintainer team.
- Tamarin Prover team at ETH Zürich / University of Düsseldorf.
- Cryptography researchers at **CISPA**, **MPI-SP**, **INRIA**, or
  comparable European institutions.
- Independent consultants with documented Noise / capability protocol work
  (e.g., contributors to Magic Wormhole, WireGuard, Macaroons RFCs).

The shortlisting is the responsibility of the founder; a final list of three
contacted candidates and their responses is published in the engagement record
even if the engagement does not proceed.

## Template engagement letter (Mode A)

```
[Date]

Dear [Name],

On behalf of NexaCore OS (https://github.com/CySalazar/nexacore-os), I am writing to
formally engage you as the external cryptographer for the v1.0 peer review,
in accordance with the engagement scope at
https://github.com/CySalazar/nexacore-os/blob/main/docs/audits/cryptographer-engagement-template.md.

Compensation: USD [amount] lump sum, payable within 30 days of report
acceptance, via [bank transfer | USDC stablecoin] to [details].

Confidentiality: this engagement is governed by the attached NDA. Public
release of the final report (redacted as needed by the reviewer) is a
positive obligation of both parties.

Kickoff date: [date]. Report due: [date].

Please confirm your acceptance by signing below.

Sincerely,
[Founder name]
Lead Architect, NexaCore OS
[email] | PGP: [fingerprint when available]

____________________________
[Reviewer name and signature]
```

## Template engagement letter (Mode B)

```
[Date]

Dear [Name],

On behalf of NexaCore OS (https://github.com/CySalazar/nexacore-os), I would like to
invite you to peer-review our v1.0 cryptographic protocol stack on a
volunteer basis. The scope and deliverables are described at
https://github.com/CySalazar/nexacore-os/blob/main/docs/audits/cryptographer-engagement-template.md.

In recognition of your time, the project offers:
- Public attribution in CONTRIBUTORS.md and the resulting NCIP-Crypto-004.
- A seat on the Crypto Advisory Board (informal, advisory) when Stichting
  NexaCore forms its scientific advisory body.
- Project travel reimbursement for one trip per year for the duration of
  your advisory tenure.

Please reply with your interest and expected timeline.

Sincerely,
[Founder name]
Lead Architect, NexaCore OS
```
