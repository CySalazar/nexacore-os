---
ncip: 28
title: Independent-review gate for on-disk-format and cryptographic NCIPs
track: Process
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-06-12
updated: 2026-06-12
requires:
  - 1
supersedes: ~
superseded-by: ~
discussion: ~
license: CC0-1.0
---

# NCIP-Review-Gate-028 — Independent-review gate for format and crypto NCIPs

## Abstract

This Process NCIP adds a single activation precondition to `NCIP-Process-001`:
a Standards Track NCIP whose Specification defines or modifies an **on-disk
format, a wire format, or a cryptographic primitive selection** MUST attach
at least one **documented independent technical review** — performed by a
reviewer who is not an author of the NCIP — before it may transition to
`Active`. The Solo Founder Fast-Track (`NCIP-Process-001` §5.5) and the
bootstrap single-voter ballot (§5.3 with one eligible device) remain valid
for every other NCIP class but MUST NOT bypass this gate. The review is
recorded as a file under `docs/audits/` and an amendment-history row in the
reviewed NCIP. The gate self-applies: this NCIP's first beneficiary is
`NCIP-FS-Wire-027` (NCFS on-disk format v3), which already cites it as an
activation precondition.

## Motivation

The registry's history shows `NCIP-FS-018` and `NCIP-FS-Wire-023` each
transitioning `Draft → Review → Last Call → Active` **on the same day, with
a single voter holding 100% of weighted eligibility**. That is procedurally
valid under the bootstrap defaults, and acceptable for direction-setting
documents — a wrong direction can be amended. It is not acceptable for
**permanent artifacts**: an on-disk format freeze or a cryptographic
primitive selection is binding on every future volume and every future
implementation; a defect discovered after activation costs a format
migration (or worse, silent data loss in the field). The 2026-06-12 audit of
`NCIP-FS-Wire-023` found exactly this class of defect post-`Active`: a format
whose normative text contradicted the frozen parameters of its parent NCIP
(`NCIP-FS-018` §S1.1) and whose consistency claims were not implemented by
its own layout. A second pair of qualified eyes before the freeze is the
cheapest known mitigation, and the project currently has no rule requiring
it. The contradictory-review function that a multi-party editor body would
normally provide (§6.1) does not exist during the Bootstrap Period (§6.2,
single editor); this gate substitutes for it on the narrow class of NCIPs
where mistakes are irreversible.

## Specification

### S1. Scope

This gate applies to any Standards Track NCIP whose Specification section,
in whole or in part:

1. defines or modifies an **on-disk format** (superblock, inode, allocation,
   integrity, or any persisted layout);
2. defines or modifies a **wire format** crossing a trust boundary (IPC
   channel contracts, mesh protocol frames, capability token encodings); or
3. **selects, replaces, or re-parameterises a cryptographic primitive**
   (cipher, MAC, hash, KDF, signature scheme, nonce construction, key
   hierarchy).

Editors classify borderline cases at the `Draft → Review` transition; the
classification MUST be recorded in the NCIP's amendment history.

### S2. The gate

An in-scope NCIP MUST NOT transition `Last Call → Active` until at least one
**independent technical review** is attached:

1. **Independence**: the reviewer is not an author of the NCIP, has no
   authorship stake in the code the NCIP normatively binds, and — during the
   Bootstrap Period — is not the sole §6.2 editor. External reviewers
   (domain experts engaged informally or under
   `docs/audits/cryptographer-engagement-template.md`) satisfy independence.
   Pseudonymous reviewers are acceptable per the project identity policy;
   independence is asserted by declaration and assessed by the editors.
2. **Documentation**: the review is a dated document under `docs/audits/`
   naming the NCIP, the revision reviewed, the findings (including "no
   findings"), and their disposition. A review with unresolved blocking
   findings blocks the transition exactly like a Last Call objection.
3. **Recording**: the reviewed NCIP gains an amendment-history row citing the
   review file.
4. **Crypto sub-case**: for §S1 class 3, the reviewer MUST have demonstrable
   cryptographic competence (the NCIP-FS-018 SC1 "cryptographer sign-off"
   language); a general systems review does not satisfy the crypto sub-case.

### S3. Interaction with existing process

- The §5.5 Solo Founder Fast-Track and §5.3 single-voter ballots remain
  available for in-scope NCIPs **only after** the gate is satisfied; the gate
  adds a precondition, it does not alter voting.
- The §6.5 critical-security exception (emergency fixes) MAY bypass this
  gate for a time-bounded emergency amendment, but the bypassed review MUST
  be performed retroactively within 30 days or the amendment reverts.
- Already-`Active` in-scope NCIPs (`NCIP-FS-018`, `NCIP-FS-Wire-023`,
  `NCIP-Crypto-002`, …) are not retroactively invalidated; however, any
  future amendment to their in-scope sections re-enters the gate.

### S4. Registry bookkeeping

`ncips/README.md` MUST mark in-scope NCIPs in their index row once this NCIP is
`Active`. `scripts/lint-ncips.py` SHOULD gain a check that an in-scope NCIP in
`Active` state references at least one `docs/audits/` review file; until the
lint lands, editors enforce manually.

## Rationale

**Why a gate and not a second editor**: expanding the editor body is the
§6.1 end-state, but it requires people who do not yet exist in the project;
a per-NCIP review can be sourced externally per case. The gate is also
narrower — it does not slow the high-volume, reversible NCIP classes.

**Why not require N reviews or a full audit**: one independent review is the
minimum that breaks author-monoculture; requiring more during bootstrap
would freeze the project's storage roadmap on recruitment. §S2 sets a floor,
not a ceiling — NCIP-FS-Wire-027 voluntarily layers a cryptographer review,
a crash-consistency harness, benchmarks, and fuzzing on top of it.

**Why self-application matters**: a process rule introduced to fix a
specific incident (same-day single-voter format freezes) must demonstrably
bind the very next instance of that incident class; NCIP-FS-Wire-027 cites
this gate as its own activation precondition, making the first application
concrete rather than aspirational.

## Backwards Compatibility

No retroactive invalidation (§S3). The gate changes only future
`Last Call → Active` transitions of in-scope NCIPs. No code is affected.

## Test Cases

Process NCIP — verification is procedural: (1) an attempt to transition an
in-scope NCIP without an attached review MUST be rejected by the editors and
recorded; (2) `NCIP-FS-Wire-027`'s transition record MUST cite its review
file(s) under `docs/audits/`; (3) once the §S4 lint check lands, a fixture
in-scope NCIP in `Active` state without a review reference MUST fail
`scripts/lint-ncips.py`.

## Reference Implementation

N/A — process change; the optional lint check (§S4) is tracked as backlog
in the backlog (NCFS hardening work stream).

## Security Considerations

This NCIP is itself a security control: it targets the risk that a
cryptographic or format defect is frozen into a permanent artifact without
contradictory review (the highest-leverage, lowest-cost point to catch such
defects). Residual risk: a captured or negligent "independent" reviewer;
mitigated by the documentation requirement (reviews are public and
attributable, even pseudonymously) and by the unaltered Last Call objection
window, which remains open to everyone.

## Privacy Considerations

Reviewers may participate pseudonymously per the project's author identity
policy; review files under `docs/audits/` carry the same permanence and
right-to-erasure-by-pseudonym-replacement semantics as NCIP authorship
(`NCIP-Process-001` §11). No additional personal data is collected.

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
