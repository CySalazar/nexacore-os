---
ncip: 1
title: The NCIP Process
track: Meta
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-10
updated: 2026-05-14
requires: []
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions
license: CC0-1.0
---

## Abstract

This NCIP defines the **NexaCore Improvement Proposal (NCIP) process** — the canonical mechanism by
which the NexaCore OS protocol, governance, and reference implementation evolve. It specifies NCIP
categories, lifecycle, voting, eligibility, the editor body, the BDFL veto window with its
sunset clause, the bootstrap period in effect until the second editor seat is filled, and the
filing/maintenance procedures applied by the editors. NCIP-Process-001 is itself classified as
`Meta` and ratified under a one-time **Bootstrap activation** (BDFL fiat) because no prior
process exists to vote it in. The first formal vote under this process governs the next
non-`Meta` NCIP filed.

This document supersedes the informal procedure sketched in `docs/05-governance.md` §2 and is
the authoritative source for everything related to NCIP filing, review, voting, activation, and
archival. `docs/05-governance.md` is updated to cross-reference this NCIP rather than restate it.

---

## Motivation

NexaCore OS targets a generational lifetime (25+ years), 10M+ mainstream users, and a privacy-first
mission that explicitly excludes governmental funding and regulatory capture. None of those
goals survive an autocratic protocol-evolution path: the project must outlive its founder,
resist hostile takeover attempts, and remain credibly neutral across jurisdictions and
political cycles.

The *Layer 2* governance model in `docs/05-governance.md` already states that protocol evolution
runs through a federated proposal process, but the procedural detail — what counts as a quorum,
what an NCIP author owes the community, how a stalled proposal is resolved, who has authority to
withdraw a proposal, when activation is binding — is missing. Without that detail, every
substantive decision becomes ad-hoc, eroding the very anti-capture property the project was
built to provide.

Concrete pressures that this NCIP resolves:

1. **`docs/06-roadmap.md` Phase 0 closure** explicitly requires `NCIP-Process-001` to be
   published. Without it, Phase 0 cannot close and Phase 1 cannot begin per the documented
   roadmap.
2. **External contribution risk**. `CONTRIBUTING.md` §9 currently points to a TODO. External
   contributors are blocked on substantive proposals because there is no documented filing path.
3. **Audit prerequisites**. Grant evaluators (NLnet, MOSS, Sloan, Open Philanthropy) and any
   future security auditor expect a documented governance process as evidence of project
   maturity. Without it, applications stall.
4. **BDFL veto enforceability**. The 5-year founder veto stated in `docs/05-governance.md` §2.2
   has no immutable start date or sunset date in any versioned document. Without that, a future
   board could quietly extend or shorten the window. This NCIP fixes the dates and binds them.

The cost of NOT filing this NCIP grows linearly with every new contributor and every new
substantive change merged outside a documented process; the cost of filing it is one
well-considered Meta NCIP.

---

## Specification

> **Normative keywords.** This section uses RFC 2119 / RFC 8174 keywords (MUST, MUST NOT,
> SHOULD, SHOULD NOT, MAY) with their conventional meaning. Sub-sections marked *(informative)*
> are explanatory and not normative.

### §1. NCIP categories

Every NCIP MUST be classified into exactly one of the following categories. The category is
declared in the frontmatter `track:` field.

| Category | Definition | Examples |
|---|---|---|
| **Standards Track** | A change to the protocol, wire formats, cryptographic primitives, capability format, kernel ABI, mesh handshake, or any other artifact that two independent implementations must agree on for interoperability. | New cipher suite, new TEE backend ABI, new capability caveat type. |
| **Process** | A change to how the project is run: filing rules, voting parameters, editor rotation, contribution flow, code review, release cadence. | Voting formula change, editor term extension, dual-license clarification. |
| **Informational** | Best practices, advisories, or guidelines that are not binding on the protocol or governance but represent collective judgment. | Threat-model annex, recommended deployment topology, security advisory write-up. |
| **Meta** | An NCIP that governs the NCIP process itself. `NCIP-Process-001` (this document) is `Meta`. | This NCIP; future amendments to this NCIP. |

A `Meta` NCIP MUST be subject to the **same** voting and activation thresholds as a `Process`
NCIP, with the additional requirement defined in §5.4 (the BDFL cannot veto a `Meta` NCIP that
narrows the BDFL's authority).

### §2. Required structure

Every NCIP file MUST contain:

1. A YAML frontmatter block delimited by `---` lines, containing the keys: `ncip`, `title`,
   `track`, `status`, `authors`, `created`, `license`. Optional keys: `updated`, `requires`,
   `supersedes`, `superseded-by`, `discussion`.
2. The following sections, in order, as level-2 ATX headings (`## Section Name`):
   `Abstract`, `Motivation`, `Specification`, `Rationale`, `Backwards Compatibility`,
   `Test Cases`, `Reference Implementation`, `Security Considerations`,
   `Privacy Considerations`, `Copyright`.
3. A `Copyright` section that releases the NCIP into the public domain under
   [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).

The `Backwards Compatibility`, `Test Cases`, and `Reference Implementation` sections MAY contain
`N/A — <one-line reason>` if no substantive content applies; all other sections MUST contain
substantive prose. The CI lint at `scripts/lint-ncips.py` enforces the structural rules above on
every push and pull request that touches `/ncips/`.

### §3. Trigger conditions — when an NCIP is required

An NCIP MUST be filed before merging any change that falls into one or more of the following
classes:

1. Any change to a wire format, on-disk format, or cryptographic primitive in `nexacore-crypto`
   beyond the v0.1 RFC vector list.
2. Any breaking change to the public API of any crate at major-version `>=1.0`. Pre-1.0 crates
   MAY break their public API in a normal PR but MUST file an NCIP for any change that affects
   inter-crate contracts (e.g., `nexacore-types` newtype reshape, `nexacore-capability` token format).
3. Any new TEE backend (each new backend expands the trust base and is therefore protocol-level).
4. Any governance change: editor body composition, voting parameters, BDFL provisions, Stichting
   board composition, funding policy, code-of-conduct enforcement procedure.
5. Any addition or removal of a "blessed model" in the model registry (Phase 2+).
6. Any change to the activation threshold of any prior `Active` Standards Track NCIP.

If a contributor is unsure whether a change qualifies, they SHOULD file a `Draft` NCIP and let
the editors classify. Filing has zero cost; not filing and discovering the change should have
been an NCIP costs a forced revert.

Conversely, an NCIP is NOT required for: bug fixes that preserve external behavior,
documentation typos, internal refactors with no public-API surface change, test additions,
CI tweaks that do not change merge requirements.

### §4. Lifecycle

Every NCIP transitions through the state machine below. State changes are recorded in the
frontmatter `status:` field and explained in the PR body of the transition commit.

```
                    ┌──────────────────► Withdrawn
                    │
   Draft ──► Review ──► Last Call ──► Active ──► Final
                    │              │           │
                    └──► Rejected  └► Withdrawn└► Superseded
```

| State | Entered when | Exited when |
|---|---|---|
| `Draft` | NCIP file is created on a feature branch. | Author opens a PR and at least one editor performs an initial review. |
| `Review` | First editor review opens. Public discussion is encouraged via the linked GitHub Discussion. | Either the editors vote to advance to Last Call, or the author/editors withdraw, or the editors reject. |
| `Last Call` | Editors agree the proposal is mergeable. A **14-day public objection window** opens. | After 14 days with no unresolved blocking objection, the NCIP transitions to `Active`. A blocking objection forces a return to `Review`. |
| `Active` | NCIP is merged into `main`. For `Standards Track`, this **enables but does not require** the activation phase (§7). For `Process`/`Meta`/`Informational`, `Active` is effectively final but a later amendment can supersede. |
| `Final` | (Standards Track only) The activation phase succeeded — the new behavior ran on ≥75% of attested active nodes for ≥30 consecutive days. The NCIP is now binding on conforming implementations. |
| `Rejected` | The editors decline the proposal during `Review` or after a Last Call objection that the author cannot resolve. The file MUST remain in the registry as a record. |
| `Withdrawn` | The author withdraws the proposal at any time before `Final`. The file MUST remain in the registry as a record. |
| `Superseded` | A later `Active`/`Final` NCIP explicitly supersedes this one via its `supersedes:` frontmatter key. The earlier NCIP retains its content as historical record. |

### §5. Voting

#### §5.1. Eligibility *(normative)*

A voter is eligible if and only if:

1. They control a TEE-attested device whose attestation chain is currently valid against the
   reference vendor key set (Intel, AMD, ARM CCA, Apple Silicon — list maintained per
   `docs/07-hardware-requirements.md`).
2. The device has produced at least one valid attestation within the previous 14 days.
3. The device has not been revoked by the Stichting NexaCore emergency-revocation procedure (Layer
   3 mechanism, defined in Stichting bylaws — see `docs/05-governance.md` §3.3).

Eligibility is per-device, not per-person. A natural person controlling N attested devices has
N votes (subject to the rate-limited identity issuance described in `docs/05-governance.md` §3
and the per-fingerprint cap that prevents datacenter cloning).

#### §5.2. Weighting *(normative for the structure, parametric for the formula)*

Each eligible vote is weighted by:

```
weight(device, ncip) = sqrt( uptime_factor(device) × contribution_factor(device, ncip) )
```

The square root is the quadratic-vote softening factor: it sublinearizes the influence of any
single voter's accumulated stake.

The exact functional forms of `uptime_factor` and `contribution_factor` are **deferred** to a
future Process NCIP (placeholder name `NCIP-Voting-XXX`, to be assigned a global number when
filed) so that this NCIP does not lock in numbers that will need calibration in the field. Until
that NCIP is `Active`, the editors MUST use the following bootstrap defaults:

- `uptime_factor(device) = min(1.0, online_days_last_180 / 90)` — saturates after 90 days online
  in the last 180-day window.
- `contribution_factor(device, ncip) = 1.0` — flat. (No contribution data yet exists.)

**Known limitations of the bootstrap defaults *(normative tracking, non-binding direction)*.**
The bootstrap defaults intentionally simplify the weighting to enable activation before any
production telemetry exists. Two limitations are stated explicitly so they cannot be silently
inherited by future readers:

- **(L1) Saturating `uptime_factor` after 90 days.** A 91-day voter and a 5-year voter currently
  carry identical weight. This is adequate for the bootstrap window (where there is *no* 5-year
  voter yet) but **inadequate** for a project targeting generational longevity (25+ years).
  The replacement formula SHOULD have non-saturating but bounded growth on `uptime_factor`
  (a logarithmic curve over a 2-year domain — e.g., `log(1 + days_last_730) / log(1 + 730)`
  — is the editor's current preference, but the choice is the future Process NCIP's to make).
- **(L2) Flat `contribution_factor`.** Contribution does not yet influence the vote at all.
  This means the bootstrap voter set is meritocratically *unweighted*, which is acceptable
  during a period when meritocratic data does not exist. The replacement formula SHOULD ground
  `contribution_factor` in measurable, conflict-of-interest-filtered signals (e.g., signed-off
  commits merged to `main`, NCIP authorship reaching `Active`, code reviews with editor
  acknowledgement, mesh seed-node uptime as operator).

Both limitations MUST be retired by a Process NCIP under slug `voting` before the second
editor seat reaches its second annual rotation, i.e., by **2028-05-10**. If the deadline is
missed, the editors MUST publish a written status update in the next quarterly Editors' Report
explaining the slip and proposing a recovery plan. This is a soft deadline (no automatic
enforcement) but a public commitment.

#### §5.3. Quorum and approval threshold *(normative)*

An NCIP transitions from `Last Call` to `Active` if and only if:

1. Either ≥ **30%** of currently-eligible weighted vote total cast a ballot, **or** the 14-day
   Last Call window has elapsed — whichever occurs first.
2. Of the cast ballots, ≥ **50% + 1** weighted vote is in favor (simple quadratic-weighted
   majority).

A `Standards Track` NCIP that breaks Layer 1 cryptographic guarantees (cipher suites, signature
schemes, capability format, mesh handshake) requires a **supermajority** of ≥ **66.7%** weighted
in favor instead of 50%+1. The editors MUST flag such NCIPs in `Review`.

#### §5.4. BDFL veto *(normative, time-bounded)*

For the 5-year window starting **2026-05-09** (the date the public repository
`github.com/CySalazar/nexacore-os` opened with the founder identity `cySalazar` GitHub-verified) and
ending **2031-05-09** at 23:59 UTC (the **immutable sunset**), the founder MAY veto any
`Standards Track` NCIP that breaks Layer 1 protocol guarantees by submitting a signed veto
statement within the Last Call window.

The BDFL veto:

- **CAN** block the activation of an NCIP.
- **CANNOT** impose an NCIP that did not pass the vote.
- **CANNOT** be applied to `Process`, `Informational`, or `Meta` NCIPs.
- **CANNOT** be applied to a `Meta` NCIP that narrows the BDFL's authority (asymmetric — the
  BDFL cannot veto their own constraint).
- **CANNOT** be extended beyond 2031-05-09 by any mechanism short of a new `Meta` NCIP that
  itself passes without veto. By the asymmetric clause above, this means the veto window is
  **structurally non-extensible** by the BDFL alone.
- After 2031-05-09, the founder retains an **advisory** role with no veto. After 2036-05-09
  (year 10 from the same anchor date), trustee composition transitions per
  `docs/05-governance.md` §3.

The veto count and any veto exercises MUST be logged publicly in
[`docs/audits/bdfl-veto-log.md`](../docs/audits/bdfl-veto-log.md) with the NCIP number, date, and
written rationale (or the file MUST be created the first time a veto is exercised).

#### §5.5. Solo Founder Fast-Track *(normative, structurally self-deactivating)*

The Bootstrap Period (§6.2) and the standard 14-day Last Call window (§5.3 ¶1) interact in a way
that creates a degenerate edge case: when the eligible voter set §5.1 contains a single
contributor whose weighted eligibility exceeds **50%** of the total, the 14-day window protects
no community check the founder cannot already perform alone. Every ballot is decided in advance
by the only voter who can carry the vote. The window's *only* remaining function is to invite
external (non-voter) review — which §5.5 preserves, in compressed form.

The **Solo Founder Fast-Track** allows the editors to compress the Last Call window from 14 days
to **48 hours** **if and only if** all of the following conditions are met:

- **(a) Voter-set trigger.** At the moment the NCIP transitions `Review → Last Call`, the
  eligible voter set §5.1 satisfies **both**:
  - (a.i) Exactly one voter (the **dominant voter**) holds ≥ **50%** of the total weighted
    eligibility under §5.2.
  - (a.ii) No other eligible voter holds ≥ **10%** of the total weighted eligibility under §5.2.

  Once a second voter crosses the 10% floor — whether by their own attestation activity, by a
  Stichting board-issued contribution credit, or by any future replacement of the bootstrap
  defaults under the `voting`-slug Process NCIP — clause (a.ii) fails and §5.5 ceases to apply
  to any future `Review → Last Call` transition. This is the **structural self-deactivation**:
  no calendar sunset, no founder action, no Meta NCIP required.
- **(b) Track scope.** The NCIP MUST be one of: `Process`, `Informational`, `Meta` (subject to
  (b.iii) below), or `Standards Track` **not** breaking Layer 1 cryptographic guarantees per
  §5.3 ¶2. Specifically:
  - (b.i) `Standards Track` NCIPs touching cipher suites, signature schemes, capability format,
    or the mesh handshake **continue to require** the full 14-day window and the 66.7%
    supermajority. The fast-track does **not** apply to them, even when (a) holds. Rationale:
    the supermajority's function is to invite *external* cryptographic review whose reviewers
    are typically not yet eligible voters under §5.1; compressing the window removes their
    operational space.
  - (b.ii) `Standards Track` NCIPs affecting any other surface (kernel internals, boot ABI,
    container engine, wire formats other than crypto / capability / handshake, tooling,
    serialization within the bounds set by an already-`Active` Standards Track NCIP such as
    `NCIP-Serde-004`) ARE in scope.
  - (b.iii) `Meta` NCIPs that narrow the dominant voter's authority are **out of scope** by the
    same asymmetric principle codified in §5.4 ¶2.5: the dominant voter MUST NOT use the
    fast-track to ratify constraints on themselves that a future quorate body might object to.
    Such a `Meta` NCIP MUST go through the standard 14-day flow even under (a).
- **(c) Compressed objection window.** The 48-hour clock starts at the merge of the
  `Review → Last Call` transition PR and is announced simultaneously on the linked GitHub
  Discussion thread and (when available) on the Stichting NexaCore mailing list. The editors MUST
  add a top-of-NCIP banner during the window stating "**Solo Founder Fast-Track per §5.5 —
  Last Call closes <ISO-8601 timestamp> UTC**" so that an external reader cannot miss the
  compressed schedule.
- **(d) Hard veto on objection.** A blocking objection raised in good faith during the 48-hour
  window — by any eligible voter per §5.1, by the Stichting board, **or by any non-voter
  cryptographer / security researcher / domain expert citing a concrete technical artifact**
  (PR comment, diff line, advisory text, formal-model counterexample) — **annuls** the
  compressed window immediately and forces the NCIP back to a full 14-day standard §5.3 Last
  Call. "Good faith" is defined identically to §6.5 (d): technical incorrectness, undisclosed
  scope creep, conflict-of-interest disclosure failure. Procedural-only objections
  ("the window is too short") do NOT meet the threshold; the compressed window's adequacy is
  the policy choice this clause makes and re-litigating it requires a `Meta` NCIP, not an
  objection ballot.
- **(e) Mandatory post-deactivation re-ratification.** Any NCIP that transitioned `Active`
  under §5.5 MUST be re-validated through the standard §5.3 voting flow within **90 calendar
  days** of the first `Review → Last Call` transition that the editors processed under the
  standard (non-fast-track) flow because clause (a.ii) had failed. The re-ratification ballot
  is scheduled by the editors as a single batched vote covering every fast-tracked NCIP still
  in `Active` at the time of deactivation. A re-ratification vote that fails forces a
  **rollback** by a follow-up NCIP under the now-quorate process. This makes every §5.5
  activation **provisional**: it buys schedule velocity during the solo-founder phase but does
  not bypass the federated check forever.
- **(f) Public log.** Every exercise of §5.5 MUST be recorded in
  [`docs/audits/solo-founder-fast-track-log.md`](../docs/audits/solo-founder-fast-track-log.md)
  with the NCIP number, the actual 48-hour window dates (UTC), the dominant voter's measured
  weighted eligibility at clause-(a) evaluation time, the count and identity of any other
  eligible voters at that moment with their measured weights, the editor's written rationale
  for invoking §5.5 instead of the standard flow, and (post-deactivation) the re-ratification
  outcome. The file MUST be created the first time §5.5 is exercised.

The fast-track **does not apply** to and **does not affect**:

- The BDFL veto (§5.4). A fast-tracked `Standards Track` NCIP remains vetoable by the BDFL
  within the compressed 48-hour window; the BDFL has been notified by construction (they are
  the dominant voter) and a veto under §5.4 follows its own signed-statement procedure.
- The Critical-security Bootstrap exception (§6.5). §6.5 retains its dedicated role for
  `Standards Track` NCIPs responding to `Critical` vulnerabilities: when (a)(i) holds *and*
  the NCIP qualifies under §6.5 (a), the editors SHOULD prefer §6.5 because its post-Bootstrap
  re-ratification clause is stricter and its trigger (CVSSv4 ≥ 9.0) is independently
  attestable. §5.5 covers the residual non-critical schedule-velocity case; §6.5 covers the
  emergency-security case. They are orthogonal mechanisms with disjoint primary triggers.
- The quorum and approval thresholds (§5.3 ¶1, ¶2). §5.5 compresses **only** the time axis;
  ≥ 30% weighted vote and ≥ 50% + 1 (or ≥ 66.7% for Layer 1, when applicable per (b.i))
  remain the substantive thresholds. In the solo-founder scenario these are vacuously met by
  the dominant voter casting a single in-favor ballot, which §5.5 expressly does not change.
- §6.5's recusal exclusion ("any `Standards Track` NCIP authored by the BDFL themselves —
  recusal is automatic, deferral to Seat 2 filling is mandatory"). §5.5 (b) makes no recusal
  requirement on the dominant voter; the §6.5 recusal exists to prevent a single-editor /
  single-author loop *during a Critical-security emergency*, where the 72-hour window plus
  the substantive scope of "Critical Layer 1 swap" together justify a stronger guardrail.
  §5.5's compressed window plus clause (e) re-ratification already constrain the
  single-editor / single-author loop in the non-emergency setting; an additional recusal would
  make §5.5 unusable by the dominant voter, which is its primary user by clause-(a)
  construction.

The fast-track is **structurally self-deactivating, scope-bounded, externally-objectable,
post-validable, and publicly logged**. It exists because the federated check the standard
14-day window enables has, by clause-(a) construction, no community to perform it; preserving
the window in name only would be ceremonial governance — exactly the failure mode the
Bootstrap Period was designed to make explicit and bounded rather than implicit and
permanent.

### §6. Editors

#### §6.1. Composition *(normative)*

The NCIP editor body consists of **2 seats**, each held for a **1-year term**, rotating annually.
Editors are nominated by the Stichting board (Layer 3) and confirmed by quadratic vote of the
eligible voter set (Layer 2). Editors MUST be technically literate in at least one of:
cryptography, distributed systems, kernel/embedded systems, or formal methods — the editor body
collectively MUST cover all four areas to the extent practical.

#### §6.2. Bootstrap period *(normative, time-bounded)*

A **Bootstrap Period** is in effect from **2026-05-10** until the earlier of:

(a) the first time both editor seats are filled by formal nomination + ratification, or
(b) **2027-05-10** (one calendar year), whichever occurs first.

During the Bootstrap Period:

- **Seat 1** is held by the founder (`cySalazar <hello@nexacoreos.com>`) as **interim
  editor**.
- **Seat 2** is **vacant**. The editor body cannot reach quorum.
- Therefore, no `Standards Track` NCIP can be transitioned to `Active` during the Bootstrap
  Period **except** by exercising the bootstrap fiat clause (§6.3).
- `Process` and `Informational` NCIPs MAY be transitioned by interim-editor decision, with a
  14-day public objection window. A blocking objection during the window forces deferral until
  the editor body reaches quorum.
- `Meta` NCIPs MAY be transitioned only via the bootstrap fiat clause (§6.3).

The Bootstrap Period MUST end by 2027-05-10 — if Seat 2 remains vacant on that date, the
Stichting board (Layer 3) MUST nominate a candidate within the next 30 days, and the project
MUST pause `Standards Track` NCIP activation until Seat 2 is filled.

#### §6.3. Bootstrap fiat clause *(normative, single-use)*

This `NCIP-Process-001` itself is ratified by **one-time founder fiat** under the bootstrap fiat
clause. The clause:

- Applies **only** to NCIP-Process-001 and any structural amendment to NCIP-Process-001 filed
  during the Bootstrap Period.
- Does **NOT** apply to any future Standards Track NCIP, regardless of urgency.
- The exercise of the clause is recorded in this NCIP's frontmatter `status: Active` and in the
  PR that merged this file.
- The first Process or Standards Track NCIP filed after this NCIP MUST be voted under the formal
  process defined in §5, even though only one editor is in office. This is the **dogfood
  test**: the first non-Bootstrap NCIP both validates the process and forces the editor body to
  resolve quorum (by Seat 2 filling, public deferral, or both).

#### §6.4. Editor responsibilities *(normative)*

Editors MUST:

1. Triage incoming `Draft` NCIPs within **7 calendar days** of opening.
2. Apply the structural lint and request changes when the NCIP fails it.
3. Schedule the Last Call window once `Review` consensus is reached.
4. Tally votes during Last Call and record the result in the merge commit message.
5. Maintain `ncips/README.md` index in sync with the registry.
6. Publish a quarterly **NCIP Editors' Report** in `docs/audits/ncip-editors-report-YYYY-QN.md`
   summarizing NCIPs filed, their status, vote tallies, and any procedural issues encountered.

Editors MUST NOT:

1. Vote on NCIPs they author. (A co-author with a contributor on a particular NCIP must recuse
   themselves from the editorial decision on that NCIP.)
2. Privately negotiate substantive changes outside the public Discussion/PR.
3. Apply the BDFL veto. The veto is the BDFL's exclusive instrument and is separate from the
   editor role. (During the Bootstrap Period, when the founder is also the interim editor, the
   founder MUST disclose explicitly which hat they are wearing in any given decision.)

#### §6.5. Critical-security Bootstrap exception *(normative, time-bounded)*

The Bootstrap Period creates an unavoidable risk: a Layer 1 cryptographic break (e.g., upstream
RustSec advisory rated `Critical` against ChaCha20-Poly1305, Ed25519, X25519, BLAKE3, or any
primitive listed in `nexacore-crypto`) could require a `Standards Track` NCIP to land *before* Seat 2
is filled. Without an exception, the protocol would be stuck on a known-vulnerable primitive
until the editor body reaches quorum — a security posture that contradicts the
`Security > Stability > Performance` lexicographic priority.

The **Critical-security Bootstrap exception** allows the interim editor to transition a
narrowly-scoped `Standards Track` NCIP `Draft → Active` during the Bootstrap Period **if and
only if** all of the following conditions are met:

- **(a) Trigger.** The NCIP is a direct response to a vulnerability classified `Critical` per
  `SECURITY.md` §3 (CVSSv4 ≥ 9.0 or an upstream RustSec advisory of equivalent magnitude
  affecting a primitive in `nexacore-crypto`'s active dependency set).
- **(b) Minimal scope.** The NCIP performs a **one-for-one** primitive substitution within the
  affected family. It MUST NOT add a new primitive family, MUST NOT add a new TEE backend,
  MUST NOT introduce a new wire-format field beyond what is strictly required for the
  substitution, and MUST NOT make any breaking change outside the strictly affected surface.
  Anything broader than a one-for-one swap forces the NCIP back to the standard flow §5 and is
  deferred until Seat 2 is filled.
- **(c) Compressed objection window.** A **72-hour public objection window** opens at merge of
  the `Draft → Active` transition PR. The window is announced simultaneously on the linked
  GitHub Discussion, on a `SECURITY.md`-style security advisory, and (when available) on the
  Stichting NexaCore security mailing list.
- **(d) Hard veto on objection.** A blocking objection raised in good faith during the 72-hour
  window — by any eligible voter per §5.1 or by the Stichting board — **annuls** the transition
  immediately and forces deferral of the NCIP until Seat 2 is filled. "Good faith" objections
  are limited to: technical incorrectness of the proposed fix, undisclosed scope creep, or
  conflict-of-interest disclosure failure; they MUST cite a concrete artifact (PR comment,
  diff line, advisory text) and MUST NOT be procedural-only.
- **(e) Mandatory post-Bootstrap re-ratification.** Any NCIP transitioned under this exception
  MUST be re-validated through the standard §5 voting flow within **90 calendar days** of the
  end of the Bootstrap Period (i.e., from the date Seat 2 is filled or 2027-05-10, whichever
  is earlier). A re-ratification vote that fails forces a **rollback** by a follow-up `Standards
  Track` NCIP under the now-quorate process. This makes the exception *provisional*: it buys
  time for security but does not bypass the federated check.
- **(f) Public emergency log.** Every exercise of this exception MUST be recorded in
  [`docs/audits/bootstrap-emergency-log.md`](../docs/audits/bootstrap-emergency-log.md) with
  the CVE / advisory ID, the NCIP number, the actual objection-window dates, the editor's
  written rationale, and the post-Bootstrap re-ratification status. The file MUST be created
  the first time the exception is exercised.

The exception **does not apply** to:

- `Process`, `Informational`, or `Meta` NCIPs (these have no security pressure that bounds the
  72-hour window meaningfully).
- Any `Standards Track` NCIP authored by the BDFL themselves — recusal is automatic, deferral
  to Seat 2 filling is mandatory, and the BDFL MUST disclose the conflict in the NCIP's
  frontmatter under a `recusal:` key. This prevents a "I am both the only editor *and* the
  author" loop.
- Any NCIP that the BDFL has pre-vetoed under §5.4 — the exception cannot be used to bypass an
  already-exercised veto.

The exception is **single-purpose, narrowly scoped, time-bounded, post-validable, and
publicly logged**. It exists because security-driven changes have an asymmetric cost profile
(every day of delay is a known-exploitable window) that the standard 14-day Last Call cannot
absorb. It does not extend the BDFL's authority and does not weaken any non-emergency control.

### §7. Activation phase *(Standards Track only, normative)*

After a `Standards Track` NCIP transitions to `Active`, the new behavior MAY be deployed by
conforming implementations in parallel with the prior behavior. The NCIP transitions to `Final`
when telemetry reported by the mesh shows:

- ≥ **75%** of currently-attested active nodes have run the new behavior for ≥ **30 consecutive
  days**, AND
- No unresolved Critical-severity finding (per `SECURITY.md` §3) is open against the
  implementation of the NCIP.

The 75%/30-day measurement uses the same eligibility set as voting (§5.1) and is computed by
the editors quarterly based on the public mesh telemetry feed (Phase 4+ — until then, this
clause is dormant and the NCIP remains in `Active` indefinitely).

### §8. Numbering *(normative)*

#### §8.1. Identifier rule

The frontmatter `ncip:` integer is **globally unique and monotonically increasing** across the
entire registry. No two NCIPs in any state at or beyond `Review` MAY share a number. No number
is reused after `Withdrawn`/`Rejected` (the file remains in the registry, occupying its
number). The integer is the canonical identifier; all cross-references — in docs, in
`requires:` / `supersedes:` frontmatter, in the BDFL veto log, in voting tallies — MUST use
the integer.

#### §8.2. Filename convention

The canonical filename is `ncip-<slug>-<NNN>.md` where `<slug>` is a 1–3-word kebab-case
**category hint** (e.g. `process`, `bounty`, `crypto`, `kernel`, `serde`, `voting`,
`container`) and `<NNN>` is the 3-digit zero-padded number. **The slug is informational, not
an identifier.** Two NCIPs MAY share a slug across history without ambiguity (they cannot
share an integer once at or beyond `Review`); the linter does not enforce slug uniqueness,
only that the `<NNN>` in the filename matches the frontmatter `ncip:` field and that the
index table in `ncips/README.md` references every file.

#### §8.3. Draft-stage placeholder numbers

NCIPs in `Draft` MAY hold a **placeholder** integer that collides with another `Draft` NCIP
filed in parallel. Editors reconcile such placeholders at the `Draft → Review` transition:
the first colliding NCIP to reach `Review` retains its placeholder integer, and any other
`Draft` NCIP sharing that integer is renumbered to the next free integer in the same PR that
opens its own `Review` window.

Rationale: editors-of-record do not pre-allocate numbers because that would couple filing
throughput to editor availability during the Bootstrap Period and beyond. A parallel-`Draft`
author MAY pick any free integer at filing time; the global-uniqueness invariant is enforced
at the editorial-attention gate (`Review`), which is also where the index table in
`ncips/README.md` is synchronized with the registry.

The lint at `scripts/lint-ncips.py` enforces filename↔frontmatter coherence (the integer in
the filename matches `ncip:`) and index-table presence; it intentionally does NOT enforce
global uniqueness of `<NNN>` across files, because that invariant is editorial (it binds
at `Review`, not at file creation).

#### §8.4. Reserved numbers

The number `0000` is reserved for the sentinel template (`ncip-0000-template.md`) and MUST
NOT be assigned to any real NCIP.

### §9. Maintenance *(normative)*

- The index in `ncips/README.md` MUST be updated in the same PR that adds or transitions an NCIP.
- The CI lint (`scripts/lint-ncips.py`, surfaced as the `ncip-lint` workflow) MUST pass on every
  push to `main` and on every PR that touches `/ncips/`. Branch protection on `main` MUST
  include `ncip-lint / ncip-lint` as a required status check once the registry contains at least
  one non-template NCIP (this NCIP qualifies; the check MUST be added in a follow-up PR within
  7 calendar days of this NCIP transitioning to `Active`).
- The `ncips/ncip-template.md` and `ncips/ncip-0000-template.md` files MUST NOT be modified except
  via a `Process` or `Meta` NCIP.

### §10. Copyright on NCIPs *(normative)*

Every NCIP MUST be released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/) so it can be quoted, mirrored,
translated, and cited freely without permission. This is independent of the codebase license
(Apache-2.0) — NCIPs describe protocol; the protocol is documented for everyone.

---

## Rationale

### Why "Meta" as a fourth category

`docs/05-governance.md` §2 lists three categories (Standards Track / Process / Informational).
The fourth — `Meta` — is needed because NCIP-Process-001 itself is neither a protocol change nor
a normal process tweak: it bootstraps the entire process and amendments to it have asymmetric
constraints (§5.4: BDFL cannot veto a Meta NCIP that narrows their authority). Distinguishing
`Meta` from `Process` makes that asymmetry explicit and lintable. EIPs use the same distinction
(EIP-1 is `Meta`).

### Why dual thresholds (50%+1 and 66.7%)

Bitcoin (BIP), Ethereum (EIP), and Python (PEP) all converged on a tiered approval system: most
proposals pass on simple majority, but those that affect consensus rules require supermajority.
NexaCore OS's analog of "consensus rules" is Layer 1 cryptography — anything that changes a cipher
suite or capability format must be much harder to change than, say, a CI tweak. 66.7% is the
PEP / BIP / EIP convention for supermajority and is calibrated to be high enough to require
broad consensus while not so high that a small minority can block (e.g., 90% would let any 11%
of voters veto).

### Why a 14-day Last Call window

Shorter than EIP (no fixed window, editor judgment), longer than RustSec (typical 5–7 days),
shorter than IETF Last Call (typically 2–4 weeks). 14 days balances three pressures:

- Long enough for global community across timezones to surface objections without working
  weekends.
- Short enough that a malicious filibuster — opening objections to delay every NCIP — is
  bounded.
- Aligned with the contributor-availability cycle: most volunteer contributors check a project
  at least once every two weeks, even if not daily.

### Why the BDFL window is anchored to 2026-05-09 and not Stichting incorporation

the backlog Open Decisions §4 framed this as a choice between three anchors: first public commit
(2026-05-09), Stichting incorporation (P4.1, future), or v1.0 release (post-Phase 1). The
founder elected the first public commit because:

- It is **certain today**. P4.1 is blocked on funding and could slip by a year or more, leaving
  the BDFL window's start date `TBD` in writing — which violates the §2.3 acceptance criterion
  that the sunset must be in a *versioned, immutable* document.
- It is **maximally constraining on the founder**. Anchoring earlier means the veto expires
  earlier. This is consistent with the project's anti-capture stance: the founder voluntarily
  accepts the strictest available bound.
- It is **independently verifiable**. The first commit's date and signature are on GitHub
  permanently; no future board can dispute when the window started.

### Why the Bootstrap Period exists at all

Without it, NCIP-Process-001 would be unfileable: there is no prior process to vote it in, and
the editors-of-record do not yet exist. EIP-1 had the same chicken-and-egg problem and resolved
it by founder declaration; this NCIP names that resolution explicitly (the "bootstrap fiat
clause") and bounds it tightly: single-use, non-extensible, time-limited, applicable only to
this NCIP.

### Why one editor and not two during Bootstrap

the backlog P2.1 explicitly lists "2 NCIP editors per term, rotated annually" as an acceptance
criterion. Three options were considered (per the AskUserQuestion at the start of this NCIP's
drafting):

1. *2 editors fictitious (founder + 'TBD')* — formally clean, but the second seat is fictional
   and can never reach quorum. Optically dishonest.
2. *1 editor permanent in Bootstrap, expansion to 2 when a community contributor reaches a
   contribution threshold* — opens the door before funding, but introduces a new policy
   surface (the threshold) that itself needs an NCIP, recursively.
3. *1 interim editor (founder), seat 2 vacant until Phase 1 hire* — chosen. Honest, bounded,
   self-resolving (Phase 1 hiring closes the gap; if it slips past 2027-05-10, the Stichting
   board is mandated to nominate). Pairs with the bootstrap fiat clause (§6.3) to make
   Bootstrap-era decisions explicit.

### Why the Solo Founder Fast-Track is structural, not temporal

The two pre-existing exceptional governance mechanisms — the BDFL veto (§5.4) and the
Critical-security Bootstrap exception (§6.5) — are both **calendar-bounded**: §5.4 sunsets
2031-05-09; §6.5 sunsets when Seat 2 is filled or 2027-05-10, whichever is earlier. Both
mechanisms therefore expire whether or not the underlying condition that motivated them is
still present. This was correct for those clauses: §5.4 exists to dampen founder dominance
during a fixed transition; §6.5 exists to bridge a fixed Bootstrap window.

§5.5 is different. The condition it responds to — *"there is no community-side check to
perform during Last Call because the eligible voter set has no contested vote"* — is **not** a
calendar condition. It is a structural fact about the voter set at a given moment. A calendar
sunset for §5.5 would mean either:

- An overly long sunset (e.g., 2031-05-09 aligned with §5.4) that keeps the fast-track alive
  long after the eligible voter set has diversified — which would let the founder compress
  windows on NCIPs that *should* be reviewed by an existing community. This is exactly the
  "bad precedent" failure mode the founder asked the §5.5 design to avoid.
- An overly short sunset (e.g., 90 days from §5.5 activation) that fires while the founder is
  still solo — which would force a return to ceremonial 14-day windows during which still
  nobody can object substantively, achieving only schedule loss.

A **structural** trigger — "deactivates the first time a second voter crosses 10% weighted
eligibility" — is dominant-strategy-correct against both failure modes: it stays alive exactly
as long as the underlying degeneracy holds, and not one moment longer. The 10% floor (rather
than, e.g., 50% to match clause (a.i)) is chosen so that the deactivation triggers on the
*first sign* of meaningful community presence, not on a regime change. This biases the
mechanism toward early self-retirement.

The 48-hour window (rather than 24 h or 72 h) is calibrated to span exactly one waking cycle:
long enough for a non-voter external reviewer (e.g., a cryptographer notified of a `Process`
or `Informational` NCIP via the GitHub Discussion thread) to read the diff and file a
clause-(d) objection during business hours in either Europe or the Americas, short enough that
schedule velocity is materially recovered relative to 14 days (≈ 7× speedup). 24 h would
overlap only the dominant voter's working day and exclude time-zone-shifted reviewers; 72 h
matches §6.5 but §6.5 deals with `Critical`-severity context where the cost of every day's
delay is bounded — §5.5 has no such security-driven cost gradient, so the upper-bound
selection prefers the *external-review* axis (longest reasonable) over the *schedule* axis
(shortest reasonable).

The exclusion of Layer 1 (clause (b.i)) is the most important self-restriction. The Layer 1
supermajority §5.3 ¶2 exists because cryptographic decisions have *non-voter* expert
constituencies (academic cryptographers, audit firms, formal-methods researchers) whose
involvement the standard 14-day window structurally invites. A solo founder cannot
self-substitute for that constituency. §5.5 (b.i) therefore preserves the full 14-day flow
for exactly the NCIPs whose Last Call serves a function §5.5's clause-(a) trigger cannot
satisfy.

### Why a custom linter (and not markdownlint + JSON-schema)

`scripts/lint-ncips.py` enforces three project-local invariants that generic linters cannot:

1. Frontmatter `ncip` integer matches the filename's `<NNN>` suffix.
2. The index table in `ncips/README.md` mentions every NCIP file.
3. The sentinel `ncip-0000-template.md` is treated as an exception (different filename shape).

A custom 500-line stdlib-only Python script is cheaper to maintain than wiring a dozen rules
across markdownlint + ajv + a glue script. It also has zero install footprint in CI.

---

## Backwards Compatibility

This is the first NCIP. There is no prior `Active` process to be backward-compatible with.

`docs/05-governance.md` §2 contains a slightly different lifecycle (`Draft → Review → Last Call
→ Final / Rejected / Withdrawn`) and a slightly different set of categories. This NCIP unifies
both:

- The lifecycle of this NCIP (`Draft → Review → Last Call → Active → Final | Withdrawn |
  Superseded | Rejected`) is the **superset** of the two; the `Active` state added here is
  meaningful for `Standards Track` (the activation phase between merge and 75%/30-day rollout).
- The categories of this NCIP add `Meta` to the three listed in `docs/05-governance.md`.

A docs PR concurrent with this NCIP (P2 closure) updates `docs/05-governance.md` to
cross-reference this NCIP rather than restate the older text, eliminating the discrepancy.

---

## Test Cases

This is a `Meta` NCIP with no protocol artifact to test. The procedural test cases are:

1. **Lint dogfood test.** Running `python3 scripts/lint-ncips.py` against this NCIP MUST exit 0.
   Verified: see CI workflow `ncip-lint`.
2. **Numbering test.** This NCIP's frontmatter `ncip: 1` matches its filename suffix `001`.
   Verified by §8 and the lint.
3. **Self-supersession invariant.** A future amendment to this NCIP MUST set `supersedes:` to
   the current NCIP's number AND MUST itself transition through the process defined here. There
   is no test now (no future amendment exists), but the invariant is stated for the lint to
   enforce on future filings.
4. **First-vote test (deferred).** The first non-`Meta` NCIP filed after this one is the
   dogfood test of §6.3. It MUST go through the full §5 voting flow even with one editor in
   office. Pass criterion: either Seat 2 fills before that NCIP reaches Last Call, or the NCIP
   is publicly deferred until it does.

---

## Reference Implementation

The procedural artifacts implementing this NCIP live in this repository:

- `ncips/README.md` — registry index and filing instructions.
- `ncips/ncip-template.md` — canonical template referenced by §2.
- `ncips/ncip-0000-template.md` — sentinel reserved by §8.
- `scripts/lint-ncips.py` — structural linter referenced by §2 and §9.
- `.github/workflows/ncip-lint.yml` — CI surfacing of the linter referenced by §9.
- `.github/ISSUE_TEMPLATE/ncip_proposal.yml` — pre-existing issue template (P0.8) referenced by
  the filing instructions in `ncips/README.md`.
- `docs/05-governance.md` — Layer 2 cross-reference to this NCIP (updated in the same PR
  closing P2.3).
- `CONTRIBUTING.md` §9 — filing flow cross-reference (updated in the same PR closing P2).

There is no Rust reference implementation: this NCIP defines a process, not a runtime artifact.

---

## Security Considerations

### Threats this NCIP introduces

1. **Editor capture**. A malicious actor reaching one or both editor seats could slow-walk or
   reject hostile-to-them NCIPs. Mitigation: 1-year terms with annual rotation (§6.1), public
   editorial decisions (§6.4), and Stichting-board oversight (Layer 3). The Bootstrap Period
   has explicit founder accountability.
2. **BDFL capture-by-coercion**. The founder, holding the veto for 5 years, is a single point
   of pressure (legal, financial, physical). Mitigation: the veto can only *block*, never
   *impose* (§5.4); any vetoed NCIP can be re-filed after 2031-05-09; the BDFL-non-extensibility
   clause means the window cannot be quietly stretched by founder action.
3. **Sybil voters**. Mitigation already in `docs/05-governance.md` §3 via TEE attestation and
   per-fingerprint rate limits. This NCIP inherits the same anti-Sybil controls.

### Threats this NCIP mitigates

1. **Ad-hoc decision drift.** Without a documented process, every substantive decision is a
   one-off. This NCIP forces decisions into a recorded, archival, public path.
2. **Founder unilateralism.** The voting requirement (§5) and the veto sunset (§5.4) bind the
   founder publicly to relinquishing power on a known schedule.
3. **Hostile fork legitimacy claims.** Any fork that breaks compliance with this NCIP becomes
   identifiable as such (the lint and the registry are reproducible artifacts), supporting the
   forking policy in `docs/05-governance.md` §4.

### Failure modes

- **CI lint failure on a transition PR.** The merge is blocked. This is a feature, not a bug:
  the registry's invariants are enforced on every change.
- **Editor body deadlock during the Bootstrap Period.** Deadlock is impossible during Bootstrap
  (only one editor is in office), but the result is a slow filing path. Mitigation: §6.2's
  hard deadline (2027-05-10) for filling Seat 2.
- **Late-Last-Call objection storm.** A coordinated minority opens objections at hour 13 of
  day 14 to force re-Review. Mitigation: editors MAY extend the Last Call window once by 14
  days if good-faith objections are unresolved at the boundary; persistent stalling is recorded
  in the editors' quarterly report (§6.4 ¶6) for community attention.

### Cryptographic considerations

This NCIP itself ships no cryptographic artifact. The voting eligibility (§5.1) depends on TEE
attestation freshness, which inherits all assumptions in `docs/04-security-model.md` and
`docs/04a-threat-model.md` (TCB integrity, vendor key non-compromise, attestation chain
validation).

---

## Privacy Considerations

### Personal data flows

- **Author identity.** The NCIP frontmatter `authors:` field is part of a permanent
  CC0-1.0 public-domain record (§10) — once an NCIP reaches `Active` the field cannot be
  unilaterally erased without leaving a notice in the next Editors' Report. Because the project
  is privacy-first by design, contributors are **strongly encouraged** to file under a
  project-scoped pseudonym + dedicated mailbox (or a PGP / SSH-signing-key fingerprint as the
  contact channel) rather than a legal-name + personal-mailbox identity. Examples: the
  `cySalazar <hello@nexacoreos.com>` identity used by this NCIP's author is project-scoped,
  not the founder's civil identity. The same pattern is recommended to all contributors.

  Authors using a pseudonym MUST disclose the pseudonymity itself to the editors (without
  revealing the underlying civil identity). Editors MAY require evidence of unique identity
  (e.g., a signed Git commit chain on the contributor's branch, a PGP signature on the
  filing PR) but MUST NOT require linking to a legal name. This preserves pseudonymous
  contribution while preventing puppet accounts.

  The `ncips/ncip-template.md` HTML-comment guidance reproduces this expectation at the point of
  filing, so contributors make the choice deliberately and not after merge.
- **Voter identity.** Voters are identified by a TEE-attested device pseudonym (a
  content-addressed `NodeId` per `nexacore-types::NodeId`), not by a legal name. The Stichting
  cannot construct a name↔NodeId map from the protocol alone; legal identity is leaked only if
  the voter chooses to disclose it (e.g., in a public statement attached to a vote).
- **Discussion archives.** Discussion threads on GitHub Discussions are public and
  long-retained. Authors and discussants SHOULD treat them as permanent public records.

### Metadata exposure

Vote tallies are public, aggregated, and time-stamped. A statistical adversary correlating vote
patterns with public participation timing might attempt to deanonymize specific voters; this is
a known limitation of any open governance system. Mitigation: voters can co-vote in batches,
and the protocol does not record which specific NodeIds voted which way — only weighted
aggregates per NCIP. Per-voter ballots are TEE-encrypted and aggregated client-side (Phase 4+
implementation).

### GDPR / regulatory implications

The author identity field is the only structured personal data in an NCIP. Authors providing a
real email implicitly consent to its public record (CC0-1.0 release per §10). Right-to-erasure
requests on the author email are honored by replacing the email with a pseudonym AND publishing
a notice of the change in the next Editors' Report; the NCIP's substantive content is NOT
removed, since it is now part of the project's historical record and the public has a
legitimate interest in protocol provenance.

---

## Amendment history

This section records every structural amendment to NCIP-Process-001 in chronological order.
It exists for the same reason §5.4 mandates a public veto log: trust requires a paper trail.

| Date | Mechanism | Summary |
|---|---|---|
| 2026-05-10 | Bootstrap fiat (§6.3, ratification) | Initial publication. `Active` under one-time founder fiat because no prior process exists to vote it in. |
| 2026-05-10 | Bootstrap fiat (§6.3, structural amendment) | First amendment, applied the same day as ratification after founder review. Three changes: (i) **new §6.5** "Critical-security Bootstrap exception" — narrow escape valve for `Standards Track` NCIPs responding to `Critical` vulnerabilities while Seat 2 is vacant, with 72h objection window, mandatory post-Bootstrap re-ratification, and public emergency log; (ii) **expanded §5.2** with explicit "Known limitations" of the bootstrap voting defaults and a soft 2028-05-10 deadline for the `voting`-slug Process NCIP that retires them; (iii) **refined `## Privacy Considerations`** and **`ncips/ncip-template.md` HTML guidance** to actively encourage project-scoped pseudonymous filing (privacy-first mission alignment, GDPR pre-emption). Rationale: founder editorial review surfaced three valid critiques that warranted material rather than cosmetic response. |
| 2026-05-12 | Bootstrap fiat (§6.3, structural amendment) | Second amendment, applied 2026-05-12. **Section §8 (Numbering) restructured** into four sub-sections (§8.1 identifier rule, §8.2 filename convention, §8.3 draft-stage placeholder numbers, §8.4 reserved numbers). Substantive clarifications: (a) the integer is the canonical identifier for all cross-references; (b) the slug is explicitly a **category hint**, not a secondary identifier; (c) the global-uniqueness invariant binds at `Review`, not at `Last Call → Active` as the original wording implied — placeholder integer collisions in `Draft` are explicitly permitted and reconciled by the editors at the `Draft → Review` transition. Rationale: the registry currently holds three `Draft`/`Last Call` placeholder collisions (`NCIP-Bounty-002` / `NCIP-Crypto-002`; `NCIP-Serde-004` / `NCIP-Kernel-004`; `NCIP-Kernel-005` / `NCIP-Voting-005`); the previous §8 wording was silent on this case and required ad-hoc footnotes in `ncips/README.md`. This amendment formalizes what the editors were already doing, ahead of the first parallel-`Draft` pair reaching `Review`. No semantic change to any prior `Active` NCIP. |
| 2026-05-14 | Bootstrap fiat (§6.3, structural amendment) | Third amendment, applied 2026-05-14. **New §5.5 "Solo Founder Fast-Track"** — a structurally self-deactivating clause that compresses Last Call from 14 days to **48 hours** when the eligible voter set §5.1 has exactly one dominant voter (≥ 50% weighted eligibility) and no other voter at ≥ 10%. Layer 1 Standards Track NCIPs (cipher suites / signature schemes / capability format / mesh handshake) and `Meta` NCIPs narrowing the dominant voter's authority are **out of scope** and continue to require the full 14-day window. The clause **self-deactivates** the moment a second voter crosses the 10% floor — structural, not calendar-based — and every NCIP activated under §5.5 is subject to **mandatory post-deactivation re-ratification** within 90 days via standard §5.3 voting. Public log mandated at `docs/audits/solo-founder-fast-track-log.md`. New `## Rationale` sub-section "Why the Solo Founder Fast-Track is structural, not temporal" explains the design choices (structural vs. calendar trigger, 48h vs. 24h / 72h, Layer 1 exclusion). Rationale for the amendment itself: the eligible voter set today contains a single voter (founder, sole eligible device under §5.1), the 14-day Last Call protects no community check that the founder cannot perform alone, and the kernel-boot path (`NCIP-Kernel-004` `Draft`, `NCIP-Kernel-005` `Draft`) is gated by exactly this ceremonial window. The amendment recovers ≈ 12 days per non-Layer-1 NCIP without bypassing any substantive threshold; the structural trigger ensures the clause retires itself as soon as it stops being honest. No semantic change to any prior `Active` NCIP. |

Future amendments after the Bootstrap Period MUST go through the standard §5 voting flow as
`Meta` NCIPs that supersede this one, per §4 (Lifecycle) and §8 (Numbering). The bootstrap fiat
clause is single-use *per amendment* and applies only during the Bootstrap Period.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
