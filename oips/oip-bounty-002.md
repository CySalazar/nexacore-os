---
ncip: 2
title: Bug Bounty Program for NexaCore OS
track: Process
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-10
updated: 2026-05-22
requires:
  - 1
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions
license: CC0-1.0
---

## Abstract

This NCIP defines the **NexaCore OS Bug Bounty Program**: a documented framework that turns the
informal "Hall of fame" referenced in [`SECURITY.md`](../SECURITY.md) §7 into a binding
program with explicit severity-tiered payouts, eligibility filters, conflict-of-interest
controls, payment mechanics, and dispute resolution. The NCIP itself is binding on `Active`;
**monetary disbursement is conditional on Stichting NexaCore funding** (the backlog P4) — the rules
become the protocol contract immediately, the cash flow turns on when the legal entity that
can sign payment commitments exists. Until then, the program operates in a **non-monetary
mode** (Hall of fame credit, advisory citation, severity-tagged advisory transparency) that
preserves attribution and reputation incentives.

This NCIP is the **first non-`Meta` NCIP filed under [`NCIP-Process-001`](./oip-process-001.md)**
and is therefore the dogfood test of the formal §5 voting flow during the Bootstrap Period
(per `NCIP-Process-001` §6.3 ¶3). Its progression through `Draft → Review → Last Call → Active`
will be the first practical exercise of every procedural rule set in NCIP-Process-001.

---

## Motivation

A documented bug bounty program is a maturity signal that grant evaluators (NLnet, Mozilla
MOSS, Sloan, Open Philanthropy), security researchers, and prospective Stichting trustees
expect from a project that explicitly bills itself as security-first. Today the project has:

1. **A responsible-disclosure policy** ([`SECURITY.md`](../SECURITY.md)) that is comprehensive
   on *how* to report and *what* will happen — ack SLA, severity, safe harbor, coordinated
   disclosure — but explicitly punts on *whether* a researcher gets paid for their time.
2. **No published bounty rules**, despite `SECURITY.md` §7 promising a future Process NCIP under
   the slug `bounty`. That promise has been a placeholder for the entire Phase 0 window.
3. **A funding bottleneck** at P4 (Stichting incorporation + grant pipeline) that makes any
   commitment of *immediate* monetary outlay irresponsible. But "we cannot pay yet" is not the
   same as "we have no rules to follow when we can pay" — the rules can be ratified now, the
   cash flow turns on later.

The cost of not filing this NCIP grows linearly with the time the project spends asking
researchers to invest unpaid effort in good-faith disclosure. Researchers who would happily
report a bug if the program looked credible currently have no documented signal that their
work will be acknowledged consistently, fairly, and (when funding allows) compensated.

Beyond the substantive content, this NCIP serves a **secondary procedural purpose**: it is the
first NCIP to traverse the formal §5 voting flow defined in NCIP-Process-001. A successful
`Draft → Active` transition for this NCIP validates the process; an unsuccessful one surfaces
defects that become inputs to a future amendment of NCIP-Process-001 itself. Either outcome is
informative.

---

## Specification

> **Normative keywords.** This section uses RFC 2119 / RFC 8174 keywords (MUST, MUST NOT,
> SHOULD, SHOULD NOT, MAY) with their conventional meaning.

### §1. Scope of the program

The Bug Bounty Program covers the same in-scope set as
[`SECURITY.md`](../SECURITY.md) §1.1 (protocol vulnerabilities, implementation bugs in any
crate under `/crates/`, supply-chain issues, TEE attestation failures, capability system
flaws, compliance-proof flaws, privacy regressions). The same out-of-scope list of
[`SECURITY.md`](../SECURITY.md) §1.2 applies (already-published upstream RustSec advisories,
physical-access-with-compromised-TEE attacks, social engineering, spam, sub-cryptographic
theoretical attacks).

A report that is in scope per `SECURITY.md` is in scope for this program; a report that is
out of scope per `SECURITY.md` is out of scope for this program. There is no separate scope
list, by design, to prevent drift between the disclosure policy and the bounty rules.

### §2. Severity classification

Severity is determined by the **same CVSS v4.0 mapping** documented in
[`SECURITY.md`](../SECURITY.md) §4. The four tiers — Critical (9.0–10.0), High (7.0–8.9),
Medium (4.0–6.9), Low (0.1–3.9) — are reused verbatim. Reporters MAY supply a CVSS v4.0
score; the project applies the final score during triage per `SECURITY.md` §3 (within 7 days
of acknowledgement).

This NCIP MUST NOT redefine severity tiers. Any change to the severity model goes through a
change to `SECURITY.md` (small editorial PR) or, if structural, a Process NCIP that supersedes
the relevant section of this one.

### §3. Payout schedule *(normative, monetary clauses gated on §6.1)*

Payouts are denominated in **EUR** (Stichting NexaCore is incorporated in the Netherlands;
disbursement currency follows the legal entity). Reporters MAY request payment in
**USD-equivalent** at the prevailing ECB reference rate on the disbursement date, or in
**privacy-preserving cryptocurrency** (the supported list at the time of this NCIP is
**Monero (XMR)** and **Bitcoin (BTC) over Lightning** — chosen for privacy-preserving
properties and absence of regulatory-capture intermediaries; the list MAY be revised by a
later Process NCIP).

| Severity   | Payout range (EUR)        | Notes                                                                 |
|------------|---------------------------|-----------------------------------------------------------------------|
| **Critical** | **€5,000 – €50,000**     | Discretionary within the band based on impact, novelty, exploit quality, and disclosure cooperation. The €50,000 ceiling MAY be raised by editor decision for a uniquely impactful report (e.g., novel cryptographic break, wormable mesh exploit), with public justification. |
| **High**     | **€1,000 – €10,000**     | Same discretion; quality of PoC and proposed mitigation factor heavily. |
| **Medium**   | **€250 – €2,500**        | Awarded for reports with clear reproducibility and meaningful impact. |
| **Low**      | **€50 – €500**           | Awarded at the project's discretion; many Low reports MAY receive non-monetary recognition only (Hall of fame, advisory credit). |

The **upper bound** is not a guarantee — it is the maximum the program will pay, ever, for a
single report under current rules. The **lower bound** is the minimum the program will pay
for a report at that severity that meets the eligibility criteria of §4 *once monetary mode
is active per §6.1*.

A single research effort that produces multiple reports affecting independent code paths
SHOULD be filed as multiple reports; they are evaluated and paid independently. A single bug
manifesting in multiple ways MUST be filed as one report; the highest severity manifestation
sets the payout band.

#### §3.1. Bonus modifiers *(non-binding, transparent)*

The project MAY add bonus payouts within or above the stated bands for any of the following,
disclosed publicly in the advisory:

- **First report** of a previously-unknown class of vulnerability in NexaCore OS (e.g., the first
  capability attenuation bypass): up to +50% of the base payout.
- **Production-quality fix** included with the report and merged substantially as-is: up to
  +25% of the base payout.
- **Reduced disclosure timeline** at researcher's request — i.e., the researcher accepts a
  shorter embargo than `SECURITY.md` §3 mandates: up to +10% of the base payout (this rewards
  speed, not stealth).

Bonuses are stackable; the cap from §3 still applies (subject to the editor-level override
clause).

### §4. Eligibility *(normative)*

A report is eligible for monetary payout if and only if **all** of the following hold:

#### §4.1. Reporter eligibility

- The reporter is **not** a current member of the NCIP editor body in §6.1 of `NCIP-Process-001`.
- The reporter is **not** a current trustee or director of Stichting NexaCore.
- The reporter does **not** currently hold commit access to `main` of the
  `CySalazar/nexacore-os` repository (the `Maintain` or `Admin` GitHub permission level).
- The reporter has **no undisclosed conflict of interest** per §5 below.
- The reporter is **not subject to a sanctions regime** that would make payment legally
  impossible from the Stichting's jurisdiction (NL/EU). The project will not embargo a
  *technical advisory* for sanctions reasons, but cannot lawfully wire money in violation of
  sanctions; in such cases, monetary payout converts to non-monetary recognition.

#### §4.2. Contributor 6-month guard

A contributor who has merged ≥ 1 commit to `main` in the **6 calendar months** preceding the
report submission date MAY still file reports, but is **NOT eligible for monetary payout** on
any report whose root cause lies in code the contributor has touched in those 6 months. They
MAY receive Hall of fame credit and advisory citation. The 6-month guard:

- Prevents accidental "self-bounty" where a contributor finds a bug in their own recent
  contribution.
- Does NOT prevent the contributor from reporting bugs in untouched code paths and being
  paid normally.
- Is enforced by the editors during triage by checking `git blame` and `git log
  --author=<reporter>` for the affected files in the 6-month window.

#### §4.3. Report quality

- The report MUST follow the format in [`SECURITY.md`](../SECURITY.md) §2.3 (affected
  components, vulnerability class, reproduction steps, impact, suggested mitigation,
  disclosure preference). Reports failing this format are returned for revision once; a
  second insufficient submission is closed without payout.
- The report MUST describe a **reproducible** issue. A non-reproducible report receives Low
  severity at most, regardless of theoretical impact, until reproducibility is established.
- The report MUST NOT be a **duplicate** of an open or closed issue or advisory. The first
  qualifying reporter receives the full payout; subsequent reporters of the same issue
  receive Hall of fame credit only. "First" is determined by the reception timestamp at the
  `SECURITY.md` §2.1 mailbox.

### §5. Conflict of interest

#### §5.1. Required disclosures

A reporter MUST disclose, at the time of report filing, any of the following:

- Employment, contracting, or advisory relationship with **any direct competitor** of NexaCore OS
  in the AI-native OS or privacy-OS space.
- Employment by a **government or government-aligned entity** (per the excluded-funding list
  in [`08-funding-policy.md`](../docs/08-funding-policy.md)).
- Any **financial interest** in NexaCore OS (token holdings — though NexaCore OS does not issue
  tokens; equity in any commercial licensee per `COMMERCIAL-LICENSE.md`; etc.).
- Any **prior or current legal action** between the reporter and the project, the founder,
  or Stichting NexaCore.

Disclosure does **not** automatically disqualify a report. The editors MAY accept a disclosed
conflict and proceed with monetary payout if the conflict does not materially compromise
program integrity. The disclosure itself MUST be recorded in the advisory (with researcher
consent on phrasing) so the public can judge.

**Undisclosed** conflict that is later discovered disqualifies the report from monetary
payout retroactively; the program will not claw back already-paid amounts but will not pay
the next, and the reporter is suspended from the program for 12 months.

#### §5.2. Editor recusal

An editor (per `NCIP-Process-001` §6) who has any relationship with the reporter (employer,
employee, co-author on academic papers in the last 24 months, family) MUST recuse from the
triage and payout decision on that report. The recusal MUST be recorded in the advisory.

During the Bootstrap Period (`NCIP-Process-001` §6.2), with one interim editor in office, a
recusal forces the report to be deferred until either Seat 2 is filled OR the founder
designates an ad-hoc external triage reviewer (a security researcher of standing, not paid by
the project, with no conflict). This avoids both the "single point of bias" problem and the
"deadlock" problem.

### §6. Payment mechanics *(normative)*

#### §6.1. Activation gate

Monetary payouts under this NCIP **become operational** on the date the Stichting NexaCore bank
account is open and a written payout-disbursement procedure has been approved by the
Stichting board (event collectively called the "**Activation Date**"). Until the Activation
Date, the program runs in **non-monetary mode**: all rules of §1, §2, §4, §5 still apply, but
§3 payouts are deferred. Reports that would have qualified for monetary payout in non-monetary
mode are recorded with their would-be payout amount; **the project commits to retroactively
pay these reports at the same amount within 90 days of the Activation Date**, subject to a
single sanity check by the Stichting board for fraud / sanctions compliance.

If the Activation Date does not occur within **24 calendar months** of this NCIP transitioning
to `Active`, the editors MUST publish a written status update explaining the slip, and the
24-month retroactive-payout commitment converts to a best-effort obligation (the project will
pay if and when funded, but the deadline is no longer binding).

#### §6.2. Tax and legal

- The reporter is responsible for any **tax obligations** in their jurisdiction.
- The Stichting will issue a **payout receipt** (PDF, signed by the director) on request,
  showing severity, payout amount, currency, and disbursement date. The receipt does not
  include the underlying vulnerability detail (which remains under the disclosure policy).
- The Stichting cannot wire funds to a counterparty in a sanctioned jurisdiction; in such
  cases see §4.1 last bullet.

#### §6.3. Anonymity

A reporter MAY request:

- **Pseudonymous Hall of fame credit** (e.g., as `cySalazar` rather than legal name).
- **Anonymous payout** to a cryptocurrency address with no Hall of fame credit.
- **Full anonymity** (no advisory citation, no Hall of fame, no public link to the report).

The Stichting's KYC obligations may require the reporter to confirm identity privately to the
director (under NDA) before any monetary disbursement above a threshold (the threshold is set
by Dutch AML/CTF law and is currently €1,000 per disbursement; researchers are encouraged to
consult the threshold as in force on disbursement date). KYC information MUST NOT leave the
Stichting director's records and MUST NOT be linked to any public artifact.

### §7. Hall of fame *(normative)*

Researchers who report valid, non-duplicate issues — at any severity, with or without
monetary payout, with or without identity disclosure — are credited in:

- **The corresponding security advisory**, by name or pseudonym of the researcher's choice
  (or anonymously if requested per §6.3).
- **The repository file `CONTRIBUTORS.md`**, under a section "Security Researchers", with a
  one-line credit, opt-in.
- **An annual `docs/audits/security-researchers-YYYY.md` summary** published with each year's
  Editors' Report (`NCIP-Process-001` §6.4 ¶6), aggregating the year's research contributions.

Hall of fame credit is **opt-in**. The default is to credit; researchers MAY opt out at any
time before public advisory publication.

### §8. Safe harbor *(extension of `SECURITY.md` §5)*

The safe-harbor commitments in [`SECURITY.md`](../SECURITY.md) §5 (no legal action, no DMCA,
no retaliation against employer/affiliates) **apply to bounty participants** in addition to
generic researchers. In particular:

- A researcher who acted in good faith and discovered a bug they did not realize was in code
  they had touched within the 6-month guard window (§4.2) does **not** lose safe-harbor
  protection — they only lose monetary eligibility on that specific report.
- A researcher whose report is rejected for quality reasons (§4.3) does **not** lose safe-
  harbor protection; quality rejection is administrative, not adversarial.
- A researcher who **disagrees with a severity classification or payout amount** invokes the
  dispute-resolution path (§9). Filing a dispute does **not** void safe-harbor protection.

### §9. Dispute resolution

A reporter who disagrees with any of: severity classification, payout amount, eligibility
ruling, conflict-of-interest finding, or program rule application, MAY file a dispute by
emailing the editors (per `NCIP-Process-001` §6) within **30 calendar days** of the disputed
decision being communicated.

The dispute escalates through:

1. **Editor review.** The editors (excluding any recused per §5.2) review the reporter's
   complaint within 14 days and issue a written decision. If the editor body is in
   Bootstrap Period (single interim editor), the founder designates an external reviewer per
   §5.2.
2. **Stichting board review.** If the reporter is unsatisfied with the editor decision, they
   MAY escalate to the Stichting board within 14 days of the editor decision. The board
   reviews within 30 days.
3. **Public arbitration.** If the reporter remains unsatisfied, they MAY publish their
   complaint (the program's safe harbor extends to this publication). The project commits to
   respond publicly within 14 days. There is no further internal appeal — the reputational
   pressure of public arbitration is the final check.

The reporter's choice to invoke this path does not affect their pseudonymity, anonymity,
or safe-harbor protection.

### §10. Program governance

This NCIP is the canonical source of truth for the bounty program. Amendments require a
Process NCIP that supersedes this one (per `NCIP-Process-001` §4 and §8). The editors MAY
publish **non-substantive clarifications** (e.g., correction of a typo, clarification of a
ambiguous phrase that does not change rule semantics) in a follow-up PR with editor-only
approval; substantive changes (any change to §3 payout amounts, §4 eligibility, §5 conflict
rules, §6 payment mechanics, §9 dispute path) require a full Process NCIP.

The program operates under the **transparency commitments** of `NCIP-Process-001` §6.4 ¶6
(quarterly Editors' Reports). Each report MUST include:

- Number of bounty reports received in the quarter, by severity.
- Number paid, total amount paid (in EUR-equivalent), median payout per tier.
- Number of recusals, conflict disclosures, disputes filed, disputes upheld.
- Open balance of *would-be payouts* accumulated under §6.1 non-monetary mode (until the
  Activation Date).

---

## Rationale

### Why a Process NCIP and not just a `SECURITY.md` extension

`SECURITY.md` is the **disclosure policy** — what to do when you find a bug. It is
deliberately editor-mergeable as a normal PR, because it codifies industry norms (CVSS,
RFC 9116-style triage SLAs) that don't need community vote. The bounty program, by contrast,
commits the project (and Stichting) to **financial obligations and a dispute-resolution
framework** that affect every party: researchers, contributors, trustees, and the community.
That kind of commitment belongs to Layer 2 governance, hence Process NCIP.

### Why payout ranges and not single fixed amounts

A single fixed payout per tier (e.g., "Critical = €25,000 flat") is administratively
simpler but creates two known failure modes:

- **Underpaying genuine outliers.** A researcher who produces a chained
  cryptographic-attestation-bypass-with-working-exploit is not equivalently incentivized to a
  researcher who reports a less-severe Critical CVSS by score alone.
- **Overpaying low-quality high-severity reports.** A Critical report with a stub PoC and
  no proposed mitigation is not equivalently valuable to one with a complete fix.

Payout *ranges* let the editors apply discretion while staying public and predictable.
Industry precedent: Mozilla MOSS, GitHub Security Lab, the Internet Bug Bounty all use
ranges with public criteria. The criteria here (impact, novelty, exploit quality, disclosure
cooperation) are explicit in §3.

### Why the upper bound is €50,000 and not €100,000

€50,000 is calibrated for a project with no committed funding yet, where "we promise X" must
be defensible against the Stichting's expected runway. It is below MOSS Critical caps
($100,000) but above many open-source bounty programs (Linux Foundation: not paid;
RustSec: not paid; Curl: $9,000 max). The §3 editor-override clause exists for the
exceptional case where a uniquely impactful report justifies a higher payout — explicit and
publicly justified, not silently negotiated.

### Why the 6-month contributor guard

A contributor who has touched a file in the last 6 months has had access to the code while
forming the *intent* to find bugs in it. Paying them for bugs in their own recent code
creates a perverse incentive (introduce subtle bugs to bounty them later) and a
trust-base contamination signal. The 6-month window is calibrated to:

- Be long enough to cover any commit-to-discovery cycle a malicious contributor could plan.
- Be short enough to not permanently bar legitimate ex-contributors who left the project.
- Be mechanically verifiable via `git blame` and `git log` (no human judgement).

Six months is the convention used by Linux Foundation security bounty programs and is shorter
than EFF's recommendation (12 months for kernel-class projects); 6 is chosen as a starting
point and MAY be revised upward in a future amendment if abuse is detected.

### Why crypto payouts (Monero / Bitcoin LN) are listed by name

The project's mission is privacy-first and explicitly excludes regulatory-capture funding
(`08-funding-policy.md`). A bounty program that pays only via traditional banking forces
researchers in restrictive jurisdictions, or researchers who value financial privacy, to
either disclose their banking identity to the Stichting (KYC) or to forgo the payout. Listing
Monero (privacy-preserving by default) and Bitcoin Lightning (relatively privacy-preserving,
no on-chain payout footprint above the channel level) gives a real privacy option without
falsely promising "fully anonymous payouts" — KYC obligations under Dutch AML/CTF law still
apply above the threshold, and that obligation is documented in §6.3.

### Why §6.1 is a "non-monetary mode" and not a deferred Active

The NCIP could have stated `status: Draft` until Stichting funding lands, then transitioned to
`Active`. Doing it that way would mean: no ratified rules during the Bootstrap window,
researchers operating without a documented framework, no accumulating record of
*would-be-paid* reports. The chosen design — `Active` rules, deferred monetary disbursement
with retroactive obligation — gives researchers procedural certainty *now* and creates a
ledger of obligations that the Stichting can satisfy when funded. The 24-month soft deadline
prevents indefinite "we owe you" accumulation.

### Why dispute resolution ends in public arbitration, not paid arbitration

Paid third-party arbitration (JAMS, AAA, etc.) is the conventional next step. It is also
expensive (€10,000+ for a single dispute) and creates an asymmetry: the project can absorb
that cost; an individual researcher often cannot. Public arbitration — where the reporter
publishes their complaint and the project commits to a public response — equalizes the
asymmetry. The reputational cost to a project that mishandles a public complaint exceeds
the legal cost of being wrong. This is the same mechanism that EFF, Curl, and the Internet
Bug Bounty rely on.

### What this NCIP does not do

- **Does not establish a continuous-vulnerability-disclosure platform** (e.g., HackerOne,
  Bugcrowd integration). The reporting channel remains email per `SECURITY.md` §2.1. A future
  NCIP MAY add platform integration when justified by report volume.
- **Does not commit the project to paying out from operating revenue**. All payouts are
  funded by the Stichting via grants and aligned-sponsor donations per `08-funding-policy.md`.
- **Does not create employment or contractor relationships** with reporters. A bounty payout
  is a one-time honorarium for a specific report, not ongoing engagement.

---

## Backwards Compatibility

This is a new program. There is no prior `Active` bounty rule to be backward-compatible with.

`SECURITY.md` §7 currently says: *"A formal bounty program will be defined by a future Process
NCIP under the slug `bounty`..."* That sentence becomes accurate-but-stale once this NCIP
reaches `Active`. A small concurrent PR (separate from this NCIP, editor-mergeable per §10)
updates `SECURITY.md` §7 to point at this NCIP as the active rule, retains the Hall of fame
text, and removes the placeholder language.

Researchers who already filed reports under `SECURITY.md` *before* this NCIP reaches `Active`
are eligible for retroactive Hall of fame credit but **not** for retroactive monetary payout
under the §6.1 non-monetary mode — the obligation begins on this NCIP's `Active` date, not
before. (If the project has funding when this NCIP is `Active`, the editors MAY decide to
extend retroactivity to a small window of pre-NCIP reports as a goodwill gesture, but this is
a separate decision and not a binding clause of the NCIP.)

---

## Test Cases

This is a `Process` NCIP. The procedural test cases are:

1. **Lint dogfood.** Running `python3 scripts/lint-ncips.py` against this NCIP MUST exit 0.
2. **Numbering test.** The frontmatter `ncip: 2` matches the filename suffix `002`.
3. **Voting flow dogfood test.** This NCIP's transition through `Draft → Review → Last Call →
   Active` is the **first practical exercise** of the formal §5 voting flow defined in
   `NCIP-Process-001`. Pass criteria:
   - The 14-day Last Call window is observed in full.
   - Vote eligibility is determined per `NCIP-Process-001` §5.1 (TEE-attested device set);
     until production telemetry exists, the editors record this as "deferred eligibility:
     editor confidence vote" with the Bootstrap Period limitation explicit.
   - The transition decision is recorded in the merge commit message with vote tally (or
     "deferred" notation).
   - The index in `ncips/README.md` and the lint cross-check both pass on merge.
   Failure of any of these criteria does NOT invalidate this NCIP — instead, the failure becomes
   an input to a future amendment of `NCIP-Process-001` itself.

There is no Rust unit test — there is no Rust artifact. The CI lint and the procedural
verification above are the test surface.

---

## Reference Implementation

This NCIP is fully self-contained as a procedural artifact; no Rust or executable
implementation accompanies it. The artifacts that operationalize it are:

- **The `SECURITY.md` §7 update** (separate, concurrent PR) that swaps the placeholder for a
  link to this NCIP.
- **The `CONTRIBUTORS.md` "Security Researchers" section** (created in the first advisory PR
  that lists a researcher under the program — does not require a separate PR).
- **The `docs/audits/security-researchers-YYYY.md` annual file** (created with the first
  Editors' Report after this NCIP reaches `Active`).
- **The Stichting payout-disbursement procedure** (an internal Stichting document, drafted
  by the director and approved by the board on or before the Activation Date — out of scope
  for this NCIP, but cross-referenced by §6.1).

The CI lint (`scripts/lint-ncips.py`, surfaced as the `ncip-lint` workflow) validates this NCIP
on every push touching `/ncips/`, the same way it validates `NCIP-Process-001`.

---

## Security Considerations

### Threats this NCIP introduces

1. **Bounty-driven adversarial behavior.** A bounty program creates a financial incentive to
   *find* bugs, which is the goal, but also a financial incentive to *introduce* bugs (in
   contributions) and then report them. Mitigation: the §4.2 6-month contributor guard, the
   §5 conflict-of-interest disclosure, the editor recusal rule §5.2, and the public-arbitration
   dispute path §9. The combination is strictly stronger than either rule alone.
2. **Sanctions and KYC leakage.** Cryptocurrency payouts to researchers in restrictive
   jurisdictions create risks of either sanctions violation (project side) or identity
   leakage (researcher side). Mitigation: §4.1 last bullet (sanctions screen at payout time),
   §6.2 (KYC kept inside Stichting director's records, not leaked to public artifacts).
3. **Editor capture via bounty discretion.** The §3 payout *ranges* give editors discretion
   in setting amounts within bands, which could be abused to favor or disfavor specific
   researchers. Mitigation: every payout decision is recorded in the advisory with a
   one-paragraph rationale; aggregate statistics (median per tier, dispute rate) are
   published quarterly per §10; pattern-deviation is therefore detectable.
4. **Coordinated false reporting.** A coordinated set of researchers could file a flood of
   marginal-quality reports to extract small payouts in bulk. Mitigation: §4.3 quality bar,
   the duplicate rule, and the editor's authority to set Low-tier payouts to zero (lower
   bound is €50, but Low MAY receive non-monetary recognition only — §3 last paragraph).

### Threats this NCIP mitigates

1. **Unpaid security research.** Researchers who would invest time finding NexaCore OS bugs
   currently have no documented promise of compensation. Some will skip the project entirely
   in favor of better-funded targets. The NCIP turns this from "we'll see" into "here are
   the rules, deferred until funding".
2. **Drift between disclosure policy and bounty rules.** By referencing `SECURITY.md` §1, §3,
   §4, §5 directly rather than restating them, this NCIP forces any future change to those
   sections to consider bounty implications, and vice versa.
3. **Ad-hoc payment decisions.** Without rules, a future cash-flow scenario would have the
   project negotiating each payout privately with each researcher. That path is slow,
   biased, and unauditable. The NCIP front-loads the rules.

### Failure modes

- **Activation Date never arrives** (Stichting funding stalls indefinitely). §6.1 converts
  the obligation to best-effort after 24 months. Researchers retain Hall of fame credit and
  the *would-be-paid* ledger remains a moral-but-not-legal commitment.
- **Editor body deadlock during Bootstrap on a payout decision.** §5.2 fallback
  (founder-designated external reviewer) handles this; if even that fails, §9.2 escalation
  to Stichting board (when constituted) handles it.
- **Public arbitration scaling problem.** If the volume of public disputes becomes
  unmanageable, a future Process NCIP MAY introduce a structured arbitration step before the
  public arbitration of §9.3.

### Cryptographic considerations

This NCIP introduces no cryptographic artifact. The eligibility under `NCIP-Process-001` §5.1
(TEE attestation) for any future *vote* on amendments to this NCIP inherits all assumptions
in `docs/04-security-model.md`.

---

## Privacy Considerations

### Personal data flows

- **Reporter identity.** Reporters MAY file pseudonymously (via `cySalazar`-style identity)
  or anonymously (§6.3). Hall of fame credit is opt-in. The `SECURITY.md` §2.1 mailbox
  retains an internal record of communications with each reporter; this record is treated
  as confidential and not published outside the resulting advisory.
- **Vulnerability detail.** Embargoed vulnerability information is held by the editors (and,
  during Bootstrap, by the founder as interim editor) under the same handling rules as
  `SECURITY.md`. No new data flow is created.
- **KYC data (post-Activation Date).** Required only for monetary payouts above the Dutch
  AML/CTF threshold (€1,000 at NCIP filing time). KYC information is held by the Stichting
  director under NDA, never published, never linked to any public artifact, and retained
  only as long as Dutch AML/CTF law requires.

### Metadata exposure

- **Advisory metadata.** Every paid advisory exposes: severity, payout band (not exact
  amount unless the researcher consents), researcher identifier (name / pseudonym /
  anonymous), date of disclosure. Aggregate metadata in the quarterly Editors' Report
  exposes: count and total payout per tier, dispute rate, recusal count.
- **Cryptocurrency payout metadata.** Monero payouts have negligible on-chain metadata.
  Bitcoin Lightning payouts have channel-level metadata visible to channel partners but no
  on-chain metadata. The project's payout wallet addresses are NOT published (rotation
  between addresses is at the Stichting director's discretion to prevent payout-flow
  analysis).

### GDPR / regulatory implications

- **Lawful basis** for processing reporter personal data: contract performance (the bounty
  payout) and legitimate interest (security advisory publication with researcher consent).
- **Right to erasure.** Reporters MAY request erasure of their personal data after their
  bounty payout has been disbursed and the relevant retention periods (Dutch AML/CTF) have
  elapsed. The advisory itself is not erased — it is part of the project's permanent
  security record — but the reporter's identity in the advisory MAY be replaced with an
  anonymous designator on request, with a notice in the next Editors' Report (mirroring the
  `NCIP-Process-001` §11 procedure).
- **Cross-border data transfer.** When the reporter is outside the EU, the standard
  GDPR-compliant mechanisms (SCCs, adequacy decisions where available) apply to any data
  transfer involved in the disbursement.

---

## Amendment history

| Date | Change | Notes |
|---|---|---|
| 2026-05-12 | `Draft → Review` | Editorial transition by the interim editor body (founder, sole editor during the Bootstrap Period per `NCIP-Process-001` §6.2). No substantive content change: the NCIP enters the public discussion phase with all 10 canonical sections intact. The defaults applied at filing (CVSS v4.0 severity tiers anchored to `SECURITY.md` §4; payout ranges Critical €5K–€50K / High €1K–€10K / Medium €250–€2.5K / Low €50–€500; 6-month contributor guard; crypto-payout opt-in; non-monetary mode during Bootstrap with 24-month retroactive commitment) carry into `Review` unchanged. As the **first non-`Meta` NCIP** under `NCIP-Process-001`, this NCIP also dogfoods §5 of the process — its `Review → Last Call → Active` path will be the project's first formal vote. |
| 2026-05-12 | `Review → Last Call` | Editorial transition by the interim editor body. **14-day public-objection window opens 2026-05-12 and closes 2026-05-26** per `NCIP-Process-001` §4 and §5.3. No content change carried by this transition; the NCIP enters the vote window with the same text the Draft and Review phases had. Transition to `Active` requires either ≥30% weighted vote OR the 14-day window elapsing — whichever fires first — per `NCIP-Process-001` §5.3. Because the editor body is in Bootstrap (1 interim editor), the Bootstrap clause of `NCIP-Process-001` §6.3 applies to ratification once the window closes. |
| 2026-05-22 | `Last Call → Active` | Editorial closure of the Last Call window under `NCIP-Process-001` §5.3 ¶1 second branch: the dominant voter (`cySalazar`, 100% weighted eligibility under §5.2 bootstrap defaults — sole §5.1-eligible device, identical state to the §5.5 fast-track log entry for NCIP-Kernel-005/012 on 2026-05-14) cast an in-favor ballot, satisfying both clauses of §5.3 simultaneously (≥30% weighted vote cast AND ≥50%+1 weighted in favor). Founder ballot recorded in `docs/audits/ncip-editors-report-2026-Q2.md`. No blocking objection raised during the 10-day partial window (2026-05-12 → 2026-05-22) on the linked GitHub Discussion thread. No content change carried by this transition; the `Active` text is identical to the `Last Call` text. §5.5 fast-track was **not** invoked (the §5.5 (c) banner required at `Review → Last Call` entry was not in place); §5.3 ¶1 was the operative closure clause. Because NCIP-Bounty-002 is `Process` track (not `Standards Track`), no activation-phase per §7 applies — `Active` is effectively `Final` until amended or superseded. |

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
