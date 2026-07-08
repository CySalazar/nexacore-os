---
ncip: 5
title: Voting weight formula — non-saturating uptime, contribution signals, conflict-of-interest guards
track: Process
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-12
updated: 2026-05-12
requires:
  - 1
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

`NCIP-Process-001` § 5.2 defines the voting weight formula as
`weight(device, ncip) = sqrt(uptime_factor(device) × contribution_factor(device, ncip))`
but leaves the functional forms of `uptime_factor` and `contribution_factor` deferred to a future Process NCIP under the slug `voting`. The NCIP additionally documents two **known limitations** of the bootstrap defaults (L1: `uptime_factor` saturates at 90 days; L2: `contribution_factor` is flat) and sets a soft deadline of **2028-05-10** for retiring them.

This NCIP — `NCIP-Voting-005` — defines the replacement formulas, the conflict-of-interest guards that scope the `contribution_factor` inputs, the calibration procedure for the small numeric parameters (the logarithmic-curve domain, the contribution-signal weights), the migration steps that transition the eligible voter set from the bootstrap formula to the new one without a flag-day cutover, and the test vectors that lock the calibration in writing.

The NCIP is **`Process`-category** because it changes how the project is run — specifically how votes are weighted — without altering any wire format, cryptographic primitive, or kernel ABI. Per `NCIP-Process-001` § 5.3, a Process NCIP requires a quadratic-weighted majority (≥ 50% + 1) and is **not** subject to BDFL veto.

The NCIP does NOT change voter eligibility (§ 5.1 unchanged), quorum (§ 5.3 unchanged), the BDFL veto window (§ 5.4 unchanged), or any other clause of `NCIP-Process-001` not explicitly named below.

---

## Motivation

The bootstrap defaults in `NCIP-Process-001` § 5.2 were deliberately conservative — they had to be activated before any production telemetry existed and before any contribution data was meaningful — but the same NCIP names two specific inadequacies:

**(L1) `uptime_factor` saturates at 90 days.** A 91-day voter and a 5-year voter currently carry identical weight. For a project targeting 25+ years of operation, this collapses the long-run distinction between newcomers and stewards. The §5.2 editor preference (logarithmic curve over a 2-year domain) is sketched but not committed in writing.

**(L2) `contribution_factor` is flat (1.0).** Contributions to the project — code, NCIPs, reviews, mesh operation — do not currently influence the vote at all. This makes the bootstrap voter set meritocratically *unweighted*. The §5.2 editor preference (signed commits, NCIPs reaching `Active`, etc.) is sketched but not committed.

The §5.2 deadline of **2028-05-10** is a *soft* deadline: if it is missed, the editors must publish a written status update, but there is no automatic enforcement. The cost of waiting until then is two-fold:

1. **Telemetry is needed *before* the deadline.** If the NCIP that retires the bootstrap defaults is filed on 2028-05-10, the project has had two years of production governance with a known-inadequate formula. The replacement formula in *this* NCIP can begin operating earlier — collecting calibration data through 2026–2027 — only if it is filed *now* and activated when the telemetry pipeline lights up (Phase 4+).
2. **Calibration takes time.** A formula that depends on signed-commit counts, NCIP-authorship records, and uptime histograms cannot be evaluated against synthetic data alone. The earlier the formula is committed, the more real-world data is available to assess whether the calibration choices need a revision before any binding vote relies on them.

This NCIP therefore lands *now* (May 2026) with formulas calibrated against the **pre-telemetry data we already have** (project-history reasoning, contributor-count estimates, conservative scaling) and a documented re-calibration trigger: an Editors' Report annex at each quarterly review, plus a hard pin point at the end of Phase 4 (estimated 2027–2028) when production mesh telemetry first becomes available.

Concrete pressures resolved:

1. **`NCIP-Process-001` § 5.2 known-limitations soft deadline.** Filing this NCIP today (vs. 2028-05-10) buys 24 months of calibration runway.
2. **External funding due diligence.** Grant evaluators (per `docs/funding/`) ask whether governance is operational and whether the weighting formula is locked. A perpetually-deferred § 5.2 is a red flag in the NLnet / Sloan / Open Philanthropy review cycle.
3. **Editor body workload.** Each NCIP filed under the bootstrap voting flow requires the interim editor to manually justify "why the 90-day saturation is OK *this* time"; a stable formula eliminates that ad-hoc explanation.
4. **Generational-scope credibility.** The project's published lifetime target (25+ years) is undermined every quarter that § 5.2 still reads "saturates after 90 days." Filing the replacement formula is a credibility act, not only a technical one.

---

## Specification

> **Normative keywords.** RFC 2119 / RFC 8174 (MUST, MUST NOT, SHOULD, SHOULD NOT, MAY).

### S1. Replacement formula

`NCIP-Process-001` § 5.2 ¶1 (the `weight = sqrt(uptime × contribution)` envelope) is **unchanged**. The square-root softening factor is the quadratic-vote primitive and is not in scope for this NCIP.

What this NCIP **replaces** is the inner definition of `uptime_factor` and `contribution_factor`. The new definitions:

```text
uptime_factor(device) =
    log( 1 + online_days_last_730 ) / log( 1 + 730 )

contribution_factor(device, ncip) =
    1.0
  + 0.25 * commits_factor(device)
  + 0.25 * ncip_authorship_factor(device)
  + 0.20 * review_factor(device)
  + 0.30 * mesh_operator_factor(device)
```

Each `*_factor` term is independently scaled to `[0.0, 1.0]` (defined in § S2 below). The weighting coefficients sum to **`1.00`** so the maximum value of `contribution_factor` is exactly `2.00` (a maximally-contributing voter doubles their pre-square-root weight). The constant `1.0` floor is the **non-contributor baseline**: a voter with zero contribution data still has weight `sqrt(uptime_factor × 1.0)`, which preserves the franchise.

The square root is applied **once at the end**:

```text
weight(device, ncip) = sqrt( uptime_factor(device) × contribution_factor(device, ncip) )
```

For a maximally-tenured (730 online days in the last 730), maximally-contributing voter, the per-device weight is `sqrt(1.0 × 2.0) = sqrt(2) ≈ 1.414`. For a 1-day-tenured, zero-contribution voter, it is `sqrt(log(2)/log(731) × 1.0) ≈ sqrt(0.105) ≈ 0.324`. The ratio between the most-stake voter and the least-stake voter is ≈ 4.4× — within the same order of magnitude (an explicit anti-concentration design choice; see § Rationale).

### S2. Component definitions

#### S2.1. `uptime_factor` — logarithmic over a 2-year domain

```text
uptime_factor(device) = log( 1 + online_days_last_730 ) / log( 1 + 730 )
```

Where:

- `online_days_last_730` is the number of days within the previous 730 calendar days (relative to the NCIP's Last Call open date) on which the device produced at least one valid TEE attestation.
- `log` is the natural logarithm.
- The denominator `log(1 + 730)` normalises the output to `[0.0, 1.0]`.

**Properties:**

- Non-saturating up to 2 years (a 729-day voter has weight `≈ 1.0`; a 730-day voter has exactly `1.0`).
- Strictly increasing in `online_days_last_730`.
- Heavily compressed at the high end: a 365-day voter has `log(366)/log(731) ≈ 0.892`; the marginal benefit of the second year is ≈ 10.8%. This matches the project's anti-concentration stance: long-tenured voters should have *more* weight than short-tenured ones, but not *much* more.
- The denominator is a constant; the function is O(1) to evaluate per device.

**The 2-year domain is the binding choice.** A 5-year domain (`log(1 + online_days_last_1825)`) was considered and rejected (see § Rationale): it would mean a 5-year-old account has dramatically more weight than a 6-month-old account, which contradicts the meritocratic stance. The 2-year horizon is long enough to distinguish "committed participant" from "newcomer" without entrenching incumbency over multiple NCIP cycles.

#### S2.2. `commits_factor` — DCO-signed commits to `main`

```text
commits_factor(device) = clamp_01( commits_last_365 / 100 )
```

Where:

- `commits_last_365` is the number of git commits **(a)** authored by the device's controlling identity (matched by signed-off-by + commit-signature trail per `CONTRIBUTING.md` §3), **(b)** merged into `main` in the previous 365 calendar days, **(c)** DCO-signed (`Signed-off-by:` trailer present and parseable).
- The denominator `100` calibrates "fully-contributing" at ≈ 2 commits per week. This is the **engineer-equivalent** baseline (kernel engineer / cryptographer in `docs/hiring/` salary bands L3+).
- `clamp_01(x) = min(1.0, max(0.0, x))` saturates the factor at 1.0.

**Conflict-of-interest guard.** Commits that the **author of the NCIP under vote** authored are **excluded** from `commits_last_365` for the duration of that NCIP's Last Call. This prevents a voter from inflating their `commits_factor` by self-authoring a flurry of commits in the run-up to a vote they care about. The exclusion is NCIP-scoped (re-included for the next NCIP).

#### S2.3. `ncip_authorship_factor` — NCIPs that reached `Active`

```text
ncip_authorship_factor(device) = clamp_01( active_ncips_authored / 5 )
```

Where:

- `active_ncips_authored` is the count of NCIPs whose frontmatter `authors:` list includes the device's identity, and whose `status:` is `Active` or `Final` at the NCIP-under-vote's Last Call open date.
- The denominator `5` calibrates "fully-contributing" at 5 NCIPs authored. Five NCIPs over a project's lifetime is a substantial commitment (the founder has authored 4 in the first 30 days of the public repository, indicating that 5 is achievable for committed contributors over the project's first quarter).

**Conflict-of-interest guard.** **The NCIP under vote is excluded** from `active_ncips_authored`. An author of NCIP-X does not get extra weight for NCIP-X's own vote — the exclusion is automatic and per-NCIP. The recusal pattern is consistent with `NCIP-Process-001` § 6.4 ¶6 (editors recuse from NCIPs they author); this NCIP extends the same logic to voter contribution counts.

#### S2.4. `review_factor` — editor-acknowledged code reviews

```text
review_factor(device) = clamp_01( acknowledged_reviews_last_365 / 50 )
```

Where:

- `acknowledged_reviews_last_365` is the count of pull-request reviews **(a)** authored by the device's identity, **(b)** submitted as `APPROVED` or `CHANGES_REQUESTED` (not `COMMENTED`), **(c)** on PRs that merged to `main` in the previous 365 days, **(d)** acknowledged by at least one editor through a follow-up reaction or commit-message reference.
- The denominator `50` calibrates "fully-contributing" at ≈ 1 review per week. This is the **active-reviewer** baseline.

**Conflict-of-interest guard.** Reviews **on PRs that implement the NCIP under vote** are excluded from `acknowledged_reviews_last_365`. (A voter cannot self-review their way to higher weight on the implementation PR of the NCIP they will then vote on.)

#### S2.5. `mesh_operator_factor` — seed-node uptime

```text
mesh_operator_factor(device) =
    clamp_01( seed_node_uptime_days_last_180 / 90 )
```

Where:

- `seed_node_uptime_days_last_180` is the number of days in the previous 180 calendar days during which the device was registered as a seed node in the public mesh registry (Phase 4+) AND produced at least one valid heartbeat attestation that day.
- The denominator `90` calibrates "fully-contributing" at 90 days of seed-node uptime — half the 180-day window. The factor saturates at 90/180 to reward consistent operators without giving disproportionate weight to all-or-nothing uptime.

**This factor is the only one that does not directly reward code contributions.** It rewards operating the mesh — the infrastructural counterpart to authoring code. The intent is to ensure that the operator class has commensurate governance weight to the developer class, preventing a developer-only governance capture pattern.

**Phase-gate exception.** Until the mesh registry exists (Phase 4+), `mesh_operator_factor(device) = 0.0` for every device, and the `0.30` coefficient on this term applies to zero. The non-contributor baseline (`1.0` floor in `contribution_factor`) absorbs the missing weight. When the mesh registry lights up, the factor begins computing per the formula above without any other coefficient change.

### S3. Conflict-of-interest meta-rule

Every component-factor above carries an NCIP-specific exclusion. Restated as a single meta-rule for clarity:

> **For the duration of NCIP-X's Last Call window**, any contribution datum (commit, NCIP authorship, review, mesh operation) that has **NCIP-X itself** as its subject is excluded from the voter's `contribution_factor` computation **for the vote on NCIP-X**.

This is the conflict-of-interest backbone: an author's stake in an NCIP must not amplify their vote on that NCIP. The bootstrap defaults' flat `contribution_factor` did not need this rule (every voter's contribution was 1.0); the new formula introduces real signal, which introduces the corresponding integrity requirement.

The exclusion is **per-NCIP** — voters' contributions count fully on every *other* NCIP they vote on during the same window.

The exclusion is **mechanically enforceable**: the editor body's tally script (`scripts/ncip-vote-tally.py`, deferred to a follow-up CI-tooling NCIP) MUST take the NCIP number as input and filter contributions accordingly. The script's output table includes the per-voter pre-exclusion and post-exclusion `contribution_factor` values so the tally is auditable.

### S4. Calibration provenance

Every denominator (100, 5, 50, 90) is a **calibration constant**. This NCIP locks them at the values stated above, with the following provenance:

| Constant | Provenance |
|---|---|
| `100` commits/year | ≈ 2 commits/week, the activity baseline for a part-time committed contributor. Anchored to the founder's commit cadence over the first 30 days of the public repository (≈ 80 commits, exceeding the prorated annual baseline of 100). |
| `5` Active NCIPs | 5 NCIPs is the **committed-author** threshold. Below this, authorship is occasional; at or above, the contributor is a sustained protocol designer. The constant is asymmetric: it rewards multi-NCIP authors but does not let a single prolific author dominate. |
| `50` acknowledged reviews/year | ≈ 1 review/week. Anchored to typical open-source-project review cadence in similarly-scoped projects (Linux, BSDs, Rust). |
| `90` seed-node-days/180 | Half the 180-day window. Matches the bootstrap formula's 90-day saturation point in spirit (a familiar number for the voter base) while shifting the *meaning* from "uptime" to "infrastructure operation." |

These constants are **revisable by a future Process NCIP that supersedes this one**. The revision trigger is documented in § S6. They are not revisable by editor fiat.

### S5. Migration sequence

| Step | Description | Verification |
|---|---|---|
| **V1** | Publish this NCIP as `Draft`. Begin the dogfood: the first NCIP filed *after* this one (chronologically) MUST be voted under both formulas (bootstrap *and* new) and the tally script MUST report both results in the Editors' Report. Discrepancies inform any final calibration adjustment before V3. | Editors' Report comparing the two tallies. |
| **V2** | Publish reference test vectors (§ S7) and the tally script (`scripts/ncip-vote-tally.py`) on a feature branch. The tally script MUST be deterministic for a given input dataset. | `cargo test`-equivalent: a Python pytest suite on the tally script with the § S7 vectors. |
| **V3** | NCIP transitions to `Last Call` after the dogfood NCIP closes (V1). The 14-day Last Call window evaluates this NCIP under the **bootstrap** formula (the new formula is not yet `Active`). | Standard `NCIP-Process-001` § 5 voting flow. |
| **V4** | Upon `Active`, the new formula governs every NCIP whose Last Call opens *after* the activation date. NCIPs already in Last Call at activation time continue under the bootstrap formula (no retroactive change to in-flight votes). | First post-activation NCIP tally uses the new formula; report in next Editors' Report. |
| **V5** | The bootstrap defaults in `NCIP-Process-001` § 5.2 are **frozen as historical record** but no longer normative. A docs PR concurrent with V4 adds a footnote to § 5.2 pointing to this NCIP. The L1 / L2 limitations stated in § 5.2 are marked **retired by NCIP-Voting-005** in the next Editors' Report. | Footnote present; Editors' Report entry filed. |

### S6. Re-calibration trigger

The constants in § S2 (100, 5, 50, 90) and the coefficients in § S1 (0.25, 0.25, 0.20, 0.30) are **eligible for revision** by a future Process NCIP at any time. This NCIP commits to **two automatic triggers** for editorial review of the calibration:

- **Annual review.** Each year on the anniversary of this NCIP's `Active` date, the Editors' Report MUST include a "Voting Calibration Annex" that lists the distribution of `contribution_factor` values observed in the year, flags any factor saturating at 1.0 for more than 25% of voters (a sign the calibration is too generous), and flags any factor returning 0.0 for more than 75% of voters (a sign the calibration is too strict).
- **Phase-4 mesh-telemetry hard pin.** Within 90 calendar days of the public mesh registry going live (Phase 4 closure), a calibration-validation NCIP MUST be filed evaluating `mesh_operator_factor` against real seed-node data. The 90-day deadline is **hard**: if missed, the mesh-operator coefficient (0.30) defaults to 0.0 until the validation NCIP transitions to `Active`. The hard pin is the strict counterpart to the soft pin from `NCIP-Process-001` § 5.2 (which gave rise to this NCIP).

### S7. Test vectors

Three illustrative voter profiles, with the resulting `weight` under both the bootstrap formula and the new formula. These vectors MUST be reproducible by the tally script (§ S5 V2):

```
Profile A — "Newcomer"
  online_days_last_730 = 45
  commits_last_365 = 3
  active_ncips_authored = 0
  acknowledged_reviews_last_365 = 0
  seed_node_uptime_days_last_180 = 0

  Bootstrap weight:
    uptime_factor = min(1.0, 45/90) = 0.500
    contribution_factor = 1.0
    weight = sqrt(0.500 × 1.000) = 0.7071

  New formula weight:
    uptime_factor = log(46) / log(731) ≈ 0.580
    commits_factor = 3/100 = 0.030
    ncip_authorship_factor = 0/5 = 0.000
    review_factor = 0/50 = 0.000
    mesh_operator_factor = 0/90 = 0.000
    contribution_factor = 1.0 + 0.25*0.03 + 0 + 0 + 0 = 1.0075
    weight = sqrt(0.580 × 1.0075) ≈ 0.7647

Profile B — "Steady contributor"
  online_days_last_730 = 365
  commits_last_365 = 50
  active_ncips_authored = 1
  acknowledged_reviews_last_365 = 20
  seed_node_uptime_days_last_180 = 45

  Bootstrap weight:
    uptime_factor = min(1.0, 180/90) = 1.000  (saturated since first 90 days)
    contribution_factor = 1.0
    weight = sqrt(1.000 × 1.000) = 1.0000

  New formula weight:
    uptime_factor = log(366) / log(731) ≈ 0.892
    commits_factor = 50/100 = 0.500
    ncip_authorship_factor = 1/5 = 0.200
    review_factor = 20/50 = 0.400
    mesh_operator_factor = 45/90 = 0.500
    contribution_factor = 1.0 + 0.25*0.50 + 0.25*0.20 + 0.20*0.40 + 0.30*0.50
                        = 1.0 + 0.125 + 0.050 + 0.080 + 0.150 = 1.4050
    weight = sqrt(0.892 × 1.4050) ≈ 1.1199

Profile C — "Long-term steward"
  online_days_last_730 = 700
  commits_last_365 = 100
  active_ncips_authored = 5
  acknowledged_reviews_last_365 = 50
  seed_node_uptime_days_last_180 = 90

  Bootstrap weight:
    uptime_factor = min(1.0, 350/90) = 1.000
    contribution_factor = 1.0
    weight = sqrt(1.000 × 1.000) = 1.0000

  New formula weight:
    uptime_factor = log(701) / log(731) ≈ 0.996
    commits_factor = min(1.0, 100/100) = 1.000
    ncip_authorship_factor = min(1.0, 5/5) = 1.000
    review_factor = min(1.0, 50/50) = 1.000
    mesh_operator_factor = min(1.0, 90/90) = 1.000
    contribution_factor = 1.0 + 0.25 + 0.25 + 0.20 + 0.30 = 2.0000
    weight = sqrt(0.996 × 2.000) ≈ 1.4115
```

**Observations the NCIP commits to:**

1. The newcomer (Profile A) gains slightly under the new formula (`+8%`): the logarithmic curve gives 45-day voters more weight than the linear bootstrap curve in the first 90 days. This is intentional — onboarding deserves more weight than the bootstrap formula gave it.
2. The steady contributor (Profile B) gains substantially (`+12%`), driven entirely by the `contribution_factor`. The uptime side is essentially neutral.
3. The long-term steward (Profile C) gains modestly (`+41%`), with contribution saturating at the maximum.
4. The **ratio between Profile A and Profile C is ≈ 1.85×** under the new formula vs ≈ 1.41× under the bootstrap (where Profile B and Profile C tied at 1.0). The new formula introduces meaningful but bounded contribution differentiation — within the same order of magnitude, never approaching a "whale" outcome.

---

## Rationale

**Why a logarithmic, not linear, uptime curve?** A linear curve over the same 2-year domain (`uptime_factor = online_days_last_730 / 730`) would give a 2-year voter exactly 2× the weight of a 1-year voter, exactly 4× the weight of a 6-month voter. That ratio compounds with the contribution factor and produces "stewardship-equals-stake" outcomes that resemble the very plutocracy the project's TEE-attested-per-device franchise is built to prevent. The logarithmic curve gives a 2-year voter `≈ 1.12×` the weight of a 1-year voter — material but bounded, exactly the anti-concentration stance the project commits to.

**Why a 2-year and not a 5-year horizon?** Three reasons:

1. *Generational fairness.* The project targets 25-year longevity. A 5-year saturation point would mean a 5-year-old account, by virtue of age alone, has 4× the uptime weight of a 1-year-old account. Over 25 years, this entrenches the cohort that joined in 2026–2031 against every later cohort. A 2-year horizon resets the playing field every two years.
2. *Data availability.* In May 2026, no voter has 5 years of attestation history; calibrating against a horizon that exceeds available data is unsound. The 2-year horizon will become "fully realized" in 2028, exactly when the soft deadline of `NCIP-Process-001` § 5.2 expects this NCIP to be in force.
3. *Re-engagement.* A voter who steps away for 6 months and returns is at ≈ 0.78× of their pre-step-away weight under the 2-year horizon, versus ≈ 0.91× under a 5-year horizon. The shorter horizon imposes a real cost on disengagement, which is the project's preferred behavioural signal.

**Why four contribution signals and not one?** Reducing `contribution_factor` to a single signal (e.g., only commits) would systematically disenfranchise non-developer contributors: reviewers, NCIP authors who don't code, mesh operators. Each signal targets a distinct contributor class:

- *Commits* — developer class.
- *NCIP authorship* — protocol-design class.
- *Reviews* — review class (the "checker" function the project depends on, currently underweighted in most OSS governance).
- *Mesh operation* — operator class.

The coefficients (0.25, 0.25, 0.20, 0.30) are weighted to slightly favour the operator class because the operator class is structurally underrepresented in typical OSS governance and the NexaCore mesh's resilience depends on operator commitment. The exact weights are themselves revisable per § S6.

**Why is the `1.0` floor explicit?** Removing the floor would give a zero-contribution voter `weight = sqrt(uptime × 0.0) = 0.0` — effectively disenfranchising them. The franchise model in `NCIP-Process-001` § 5.1 is **per-attested-device**, not per-contribution; reducing weight to zero would convert the franchise into a contribution-conditional vote, which is a substantively different governance model from what § 5.1 establishes. The `1.0` floor preserves the franchise; the contribution multiplier is **additive on top**, never *replacing* the franchise.

**Why the NCIP-scoped exclusion in § S3?** Self-dealing is the canonical governance failure mode. Without the exclusion, an NCIP author would have a structural incentive to pre-load contribution signals (commits, NCIPs, reviews) and time the vote to maximise their weight on their own NCIP. The exclusion is the cheapest, most mechanically auditable defence; the alternative (a global "voters cannot vote on their own NCIPs" rule) is too strict — it disenfranchises authors who have legitimate stake but also are the most informed voters.

**Why land this NCIP *now* and not closer to the 2028-05-10 deadline?** Per the Motivation §2, calibration data is the binding scarce resource. Each month from now until the deadline is a month of real-world data that informs whether the constants in § S4 are well-calibrated. Landing this NCIP on 2028-05-09 produces a formula that has zero hours of real-world calibration; landing it today gives the formula 24 months of dogfood before the bootstrap formula's soft deadline expires.

**Alternatives considered and rejected:**

- *Replace `sqrt` with a steeper softening (e.g., cube root).* Rejected: changes the quadratic-vote primitive, which is out of scope. The square root is `NCIP-Process-001` § 5.2 ¶1 and not revisable here.
- *Add a `tenure_bonus` term that grows linearly in years-since-first-attestation.* Rejected: encodes incumbency in a way that bypasses the 2-year window cap. The 730-day horizon is the binding anti-incumbency mechanism.
- *Add a Sybil-penalty term that down-weights voters whose attestations cluster on a small set of platform fingerprints.* Rejected as out-of-scope for *this* NCIP (handled by `docs/05-governance.md` §3.3 anti-Sybil controls, not by the weighting formula). A future Process NCIP may revisit if Sybil-via-platform-cloning becomes an observed failure mode.
- *Make the formula opaque (a hash-based "reputation score" computed off-chain).* Rejected: opacity defeats auditability. Every term in § S2 must be re-derivable by anyone who can read the inputs.

---

## Backwards Compatibility

This NCIP changes the **interpretation** of `NCIP-Process-001` § 5.2, not the syntax. Specifically:

- The `weight = sqrt(uptime × contribution)` envelope is unchanged.
- `uptime_factor` and `contribution_factor` are redefined per § S2.
- Voter eligibility (§ 5.1) is unchanged.
- Quorum and approval thresholds (§ 5.3) are unchanged.
- BDFL veto window (§ 5.4) is unchanged.

**Effect on in-flight NCIPs at activation time.** Per § S5 V4, NCIPs already in Last Call when this NCIP transitions to `Active` continue under the bootstrap formula. The activation is forward-only — never retroactive. This preserves voter expectations for in-flight votes.

**Effect on historical tallies.** Every NCIP voted under the bootstrap formula remains valid under the bootstrap formula. No tally is re-computed retroactively; the historical record is **frozen** at the formula in force at the vote's Last Call open date. Concrete: if `NCIP-Bounty-002` (the first non-Meta NCIP, currently `Draft`) reaches `Active` under the bootstrap formula, its vote tally remains canonical under the bootstrap formula even after this NCIP is `Active`.

**Effect on tooling.** The tally script (`scripts/ncip-vote-tally.py`) must support both formulas during the transition window (the dogfood period of § S5 V1). After V5, the bootstrap formula's branch of the script is retained as a `--formula=bootstrap` flag for historical reproducibility but is no longer invoked by the default path.

No wire format, on-disk format, cryptographic primitive, or kernel ABI is touched. The NCIP is purely procedural.

---

## Test Cases

The procedural test cases are:

1. **Test vector reproducibility.** A pytest suite (`scripts/tests/test_ncip_vote_tally.py`, deferred to V2) runs the three profiles in § S7 against the tally script and asserts the computed weights match the values in § S7 to 4 decimal places.
2. **Conflict-of-interest exclusion.** Given a synthetic voter whose entire `commits_last_365` consists of commits in the implementation PR of NCIP-X, their weight on NCIP-X must equal their pre-contribution weight (1.0 floor only); their weight on NCIP-Y (any other NCIP) uses the full contribution factor.
3. **Dogfood test.** The first NCIP filed after this one is tallied under both formulas and the Editors' Report includes both tables. Discrepancies > 5% per voter MUST be investigated before any later NCIP is voted under the new formula alone.
4. **Re-calibration trigger test.** A unit test on the Editors' Report annex template confirms that the saturation-flag logic (>25% of voters at 1.0 in any factor) is implemented; deferred to V2.
5. **Formula determinism.** Two runs of the tally script on the same input dataset MUST produce byte-identical output (including the per-voter pre/post-exclusion factors). The script MUST NOT use any source of nondeterminism (no current time, no random seed).
6. **Activation-window correctness.** A test that an NCIP whose Last Call opened *before* this NCIP transitioned to `Active` is tallied under the bootstrap formula, and an NCIP whose Last Call opened *after* is tallied under the new formula. The cutover is on the Last Call open date, not on the vote-casting date — this is the unambiguous boundary.

---

## Reference Implementation

The procedural artifacts implementing this NCIP are:

- **This NCIP itself** — `ncips/ncip-voting-005.md` (the binding text).
- **Tally script** — `scripts/ncip-vote-tally.py` (deferred to V2; pure Python, stdlib-only, mirrors the `scripts/lint-ncips.py` zero-install philosophy).
- **Test suite** — `scripts/tests/test_ncip_vote_tally.py` (deferred to V2; pytest).
- **CI integration** — `.github/workflows/ncip-vote-tally.yml` (deferred; runs the test suite on every push to `main` and on every PR that touches `/ncips/` or `/scripts/ncip-vote-tally.py`).
- **`NCIP-Process-001` § 5.2 footnote** — a docs PR concurrent with V4 adds a footnote pointing at this NCIP.

There is no Rust reference implementation: this NCIP defines a procedural calculation, not a runtime artifact. The tally script is intentionally Python (matching the existing `lint-ncips.py` toolchain) so the editor body can run it without a Rust toolchain.

---

## Security Considerations

### Threats this NCIP introduces

1. **Contribution-signal gaming.** A voter could attempt to inflate their `contribution_factor` by mass-opening trivial PRs (to pump `commits_factor`), drive-by reviewing PRs (to pump `review_factor`), or filing rubber-stamp NCIPs (to pump `ncip_authorship_factor`). Mitigations:
   - *Commits:* must be DCO-signed and merged to `main` — merge requires editor / maintainer review, which filters trivial PRs.
   - *Reviews:* must be **editor-acknowledged** (per § S2.4 ¶4) — drive-by reviews that no editor engages with do not count.
   - *NCIPs:* must reach `Active` (not just `Draft`) — quality-gated by the standard NCIP process.
   The signals are deliberately gated by other humans' attention; gaming requires gaming those humans, which raises the cost above any plausible vote-weight benefit (the maximum contribution boost is `sqrt(2) ≈ 1.41×`, not orders of magnitude).
2. **Self-dealing on the NCIP under vote.** Addressed structurally by the conflict-of-interest meta-rule in § S3.
3. **Calibration capture.** A future Process NCIP could tune the constants in § S4 to favour the proposer. Mitigation: every constant revision is itself a Process NCIP, subject to the same quorum and approval thresholds, and the calibration provenance must be re-stated. Calibration changes are publicly tracked in the Editors' Quarterly Reports per § S6.
4. **Tally-script compromise.** The tally script is the load-bearing artifact: it computes who-voted-how. Mitigations:
   - Stdlib-only Python (no dependency-graph attack surface).
   - Deterministic (§ Test Cases ¶5) — reproducible by independent re-runners.
   - Source-controlled in the repo, subject to the same code-review and DCO requirements as any other commit.
   - The Editors' Report includes the script's git commit hash so a tally can be re-computed against a known version.

### Threats this NCIP mitigates

1. **Bootstrap-defaults staleness.** The known-limitations L1 and L2 in `NCIP-Process-001` § 5.2 are retired by this NCIP, removing a documented and growing gap in the governance process.
2. **Developer monoculture in governance.** The four contribution signals (§ S1) cover four distinct contributor classes; no single class can dominate the contribution side of the weight formula. The mesh-operator class's 0.30 coefficient is the largest, explicitly to counter the prevailing developer-centric capture pattern observed in adjacent OSS projects.
3. **Author self-amplification.** The conflict-of-interest meta-rule (§ S3) makes a self-dealing strategy structurally ineffective.

### Failure modes

- **Mesh registry never lights up (Phase 4 delayed indefinitely).** The mesh-operator factor stays at 0.0 indefinitely; the 0.30 coefficient applies to zero. The non-contributor baseline (1.0 floor) absorbs the missing weight. The formula remains operational but the operator class is structurally underweighted until Phase 4 closes. § S6's annual calibration review surfaces this if it persists.
- **Tally-script divergence.** Two parties run the tally script and produce different results. By § Test Cases ¶5 the script is deterministic, so divergence indicates either (a) different input datasets — a transparency failure resolved by publishing the dataset, or (b) a script version mismatch — resolved by pinning to the editor-reported commit hash.
- **Voter set without any contribution data.** All voters have `contribution_factor = 1.0` (the floor). The formula degenerates to `weight = sqrt(uptime_factor)`. This is strictly *better* than the bootstrap formula (which has the same degeneracy plus the 90-day saturation). No new failure mode introduced.

### Cryptographic considerations

This NCIP ships no cryptographic artifact. The signals (commits, NCIPs, reviews, attestations) all flow through pre-existing cryptographic channels (DCO sign-off, signed commits, TEE attestations); their cryptographic properties are governed by the respective NCIPs / documentation that introduces them. This NCIP **inherits** those properties as preconditions; it does **not** weaken them.

---

## Privacy Considerations

### Personal data flows

- **Voter identity remains pseudonymous.** Per `NCIP-Process-001` § Privacy, voters are identified by TEE-attested NodeIds. This NCIP does not add a name-or-mailbox component to the voter record. The new contribution signals are all keyed on the same NodeId via the project's existing contributor-identity policy (signed-commits trail, NCIP authorship line, editor acknowledgements on reviews).
- **No new personal data collected.** Every datum the new formula consumes — commit counts, NCIP authorship, review counts, attestation uptime — is **already public** in the project's git history, NCIP registry, GitHub-API-accessible review records, and mesh-registry telemetry (Phase 4+). This NCIP does not introduce a new collection surface; it re-aggregates existing public data.
- **Aggregation effect.** The formula produces a single per-voter scalar (`contribution_factor` and its summary `weight`). Per-NCIP tallies publish these scalars in the Editors' Report. The scalar itself is a slight de-anonymization risk for low-population voter sets (e.g., during Bootstrap when there are few voters): a sufficiently distinctive `contribution_factor` value could link an anonymous voter's NodeId to a real-world identity if the observer also knows that real-world identity's commit/review history.

  **Mitigation:** the Editors' Report MAY report `contribution_factor` values **bucketed** (e.g., to the nearest 0.1) rather than precise, when the voter population is small (≤ 50 voters). The bucketing rule is documented in § S2 of the *script* (deferred to V2) and is a pure presentation choice; the tally script computes precise values internally and audits use the precise values, while the public report uses the bucketed values.
- **Conflict-of-interest exclusion does not require linking.** The meta-rule in § S3 operates on **device-side data** (commits and NCIPs authored by the device's identity). The editors do not need to know who the human behind the NodeId is; they only need to know which contributions the NodeId has made. This preserves the pseudonymous-voter property.

### Metadata exposure

- **Per-voter contribution scalars are public** (after bucketing). An adversary with access to the Editors' Report observes that voter `0xAB…` had `contribution_factor ≈ 1.3` on NCIP-X. With access to the full git history, the adversary can in principle identify `0xAB…` if `0xAB…`'s contribution pattern is unique. This is the **fundamental trade-off** of contribution-based weighting: contribution patterns reveal identity to anyone with access to the contribution corpus. The project accepts this trade-off because the contribution corpus is **already public** under the project's open-development policy.
- **Vote-tally aggregation.** Per-voter ballots remain TEE-encrypted and aggregated client-side per `NCIP-Process-001` § Privacy. The new formula does not introduce a per-voter ballot disclosure; only the **weights** are aggregated into the tally, exactly as under the bootstrap formula.

### GDPR / regulatory implications

- **Lawful basis.** The contribution data is provided by voters as part of their public participation (DCO-signed commits, NCIP author lines, etc.). Use of this data for weighting their vote is **purpose-limited** to governance — explicitly stated in this NCIP, which voters can read before contributing.
- **Right-to-erasure.** A voter who exercises right-to-erasure on their contribution record (e.g., requests removal of their email from past NCIPs' `authors:` lines) does not lose past-tally legitimacy: the historical tallies are frozen at the time of the vote. Future tallies recompute the `contribution_factor` against the post-erasure dataset, which may lower the voter's future weight. This is **not** a punishment for erasure: it is the mechanical consequence of the contribution record having shrunk. The Editors' Report explains the recompute in the first quarterly report after the erasure.
- **Right-to-rectification.** If a contribution record is incorrect (e.g., commits incorrectly attributed), the voter contacts the editors and the next quarterly tally re-computes against the corrected record. No special procedure beyond the existing NCIP editor-engagement channel.
- **Data minimization.** The formula uses **counts** of contributions, not their content. The Editors' Report publishes the counts, not the underlying commits / reviews / NCIPs (which are public via the project's regular channels). The minimization is structural: only the count-of-X is in the tally, never X itself.

### Linkability / unlinkability

The new contribution signals are **stronger linkers** than the bootstrap formula. The bootstrap formula's `uptime_factor` is a count of attestation days, which is a relatively coarse signal; the new formula's contribution counts are far more distinctive per voter. This is the inherent cost of a contribution-aware weighting model and is documented here so future readers do not encounter it as a surprise.

Voters who wish to maximise pseudonymity SHOULD consider:

- Using a project-scoped pseudonym (as `NCIP-Process-001` § Privacy already recommends).
- Spreading contributions across multiple devices (each registered as a separate NodeId per § 5.1) so that no single device's contribution pattern uniquely identifies them. Note: this is **not** a Sybil attack — the same human controlling multiple devices is permitted by § 5.1; the anti-Sybil controls in `docs/05-governance.md` §3 prevent unbounded multiplication, not legitimate multi-device ownership.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
