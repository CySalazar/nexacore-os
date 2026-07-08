# NCIP Editors' Report — 2026 Q2

Mandated by `NCIP-Process-001` §5.3 ¶1 and the planning task `TASK-002`
of `docs/planning/2026-05-21-development-the development plan`. Records every
formal `Last Call → Active` ballot the interim editor body executes
during the Bootstrap Period (`NCIP-Process-001` §6.2), with the
voter-set composition, ballot tally, blocking-objection check, and
editorial decision.

This file is a sibling to [`solo-founder-fast-track-log.md`](./solo-founder-fast-track-log.md):
- `solo-founder-fast-track-log.md` records §5.5 (48-hour compressed
  window) transitions.
- This file records §5.3 (standard window) transitions during Q2 2026.

A separate quarterly file is opened each quarter to keep the
per-quarter editorial cadence visible (Q3 → `ncip-editors-report-2026-Q3.md`).

---

## 2026-05-22 — `NCIP-Bounty-002` + `NCIP-Serde-004` (Last Call → Active)

### Summary

Two NCIPs entered `Last Call` on 2026-05-12 and were scheduled to
transition to `Active` automatically at the end of the standard
14-day public-objection window per `NCIP-Process-001` §5.3 ¶1 first
branch (2026-05-26). On 2026-05-22 the interim editor body
(`cySalazar`, sole §6.2 Bootstrap editor) closed the window early
via the §5.3 ¶1 second branch — founder ballot satisfying both ≥30%
weighted-vote-cast and ≥50%+1 in-favor thresholds simultaneously,
since the dominant voter holds 100% bootstrap-default weighted
eligibility per §5.2 (matching the voter-set state recorded in the
`solo-founder-fast-track-log.md` entry for NCIP-Kernel-005/012 on
2026-05-14).

| Field | Value |
|---|---|
| NCIPs transitioned | `NCIP-Bounty-002` (Process), `NCIP-Serde-004` (Standards Track, not Layer 1) |
| Window opened | 2026-05-12 (both, per their own Amendment history) |
| Window scheduled close | 2026-05-26 (14-day standard §5.3 ¶1 first branch) |
| Window actually closed | 2026-05-22 (10 days into the window, by §5.3 ¶1 second branch) |
| Closure clause | `NCIP-Process-001` §5.3 ¶1 second branch (≥30% weight cast → window closes whichever-comes-first vs 14-day timer) |
| Dominant voter | `cySalazar <hello@nexacoreos.com>` |
| Dominant voter weighted eligibility (§5.2 bootstrap defaults) | 100% — sole §5.1-eligible device at ballot-cast time |
| Other eligible voters at ballot-cast moment | 0 (none ≥ 10% floor) |
| Ballot — `NCIP-Bounty-002` | In favor (1/1 ballot, 100% weighted, satisfies §5.3 ¶2 simple 50%+1 — Process track does not invoke the Layer 1 supermajority) |
| Ballot — `NCIP-Serde-004` | In favor (1/1 ballot, 100% weighted, satisfies §5.3 ¶2 simple 50%+1 — Standards Track but **not** breaking Layer 1 per §5.3 ¶2: wire encoding is the layer above the crypto envelope, no cipher suite / signature scheme / capability format / mesh handshake change) |
| Blocking objections (§5.3, §5.5 (d)) | None received on the linked GitHub Discussion thread for either NCIP during the 10-day partial window (2026-05-12 → 2026-05-22). The editor body confirms `NCIP-Process-001` §5.3 was respected: the public-objection space remained open until the ballot fired. |
| Procedural-only objections | None |
| §5.5 fast-track | **Not invoked.** The §5.5 (c) banner required at `Review → Last Call` entry was not in place on either NCIP; §5.5 cannot be applied retroactively per the clause's "if and only if (a)–(f)" structure. §5.3 ¶1 second branch was used instead. |
| §5.4 BDFL veto | **Not exercised.** Neither NCIP breaks Layer 1 cryptographic guarantees, so §5.4 does not apply. |
| Activation phase (§7) | `NCIP-Bounty-002` (Process track): no §7 applies, `Active` is operationally `Final` until amended or superseded by a follow-up NCIP. `NCIP-Serde-004` (Standards Track): §7 activation is **dormant until Phase 4+ mesh telemetry exists** (per the NCIP's own §7 text); the NCIP is operationally indistinguishable from `Final` until that telemetry capability ships. |
| Editor signing | `cySalazar` (interim sole editor per §6.2), commit-signed via SSH ED25519 key (matching every commit in the project's signed-history chain). |

### Editorial rationale for early closure

The §5.3 ¶1 "whichever fires first" clause is symmetric: either
≥30% cast a ballot or 14 days elapse. Under bootstrap conditions
the dominant voter holds 100% weight, so casting a single in-favor
ballot collapses both clauses (the ≥30% trigger fires; the ≥50%+1
in-favor threshold is met by the same ballot). The 14-day window's
operational function — *"invite external review"* — has had 10 days
to run; the partial window collected no blocking objection on the
GitHub Discussion thread, and the editor body found no reason to
delay another 4 days. Closing early reclaims editorial-pipeline
schedule velocity for downstream work (TASK-022 `nexacore-mesh` bincode
→ postcard migration depends on `NCIP-Serde-004` being `Active`).

This is structurally equivalent to invoking §5.5 fast-track — which
would have closed the window 8 days earlier on 2026-05-14 had the
§5.5 (c) banner been in place at `Review → Last Call` entry. Because
that banner was not in place, the editor body used §5.3 ¶1 second
branch (≥30% trigger) instead, which is the lawful equivalent
mechanism for the same voter-set composition.

### Re-ratification requirement

`NCIP-Process-001` §5.5 (e) mandates post-deactivation re-ratification
for NCIPs activated under §5.5. Because today's closure used §5.3 ¶1
(not §5.5), the §5.5 (e) clause does **not** apply to either NCIP —
the §5.3 path is the standard governance flow, not a provisional
buyback of schedule. Future re-ratification of the two NCIPs is
voluntary and only required if a substantive amendment is filed
(§5.3 covers amendments as new NCIPs that supersede the prior one).

### Cross-references

- `ncips/ncip-bounty-002.md` — Amendment history table records the
  `2026-05-22 — Last Call → Active` transition.
- `ncips/ncip-serde-004.md` — same.
- `ncips/README.md` — index rows updated to `Active *(closed 2026-05-22 by §5.3 ¶1 ballot)*`.
- `docs/planning/2026-05-21-development-the development plan` — TASK-002 closed
  by the commit that lands this report.
- the backlog "Still open" item 15 — closed by the commit that lands
  this report.

---

## 2026-05-22 — `NCIP-FS-018` (Draft → Review → Last Call → Active, same-day)

### Summary

`NCIP-FS-018` was filed earlier on 2026-05-22 as `Draft` (commit `bac5254`
on `main`) to close the open architectural question in
`docs/02-architecture.md` line 252 (filesystem direction) and the
corresponding open question logged as Risk R12 in
`docs/planning/2026-05-21-development-the development plan`. The interim editor body
(`cySalazar`, sole §6.2 Bootstrap editor) then transitioned the NCIP
through `Review → Last Call → Active` in the PR that lands this report
via `NCIP-Process-001` §5.3 ¶1 second branch (≥30% weighted-vote-cast
threshold met by the founder's in-favor ballot, satisfying §5.3 ¶2
simple 50%+1 — `Standards Track`, **NOT** Layer 1).

| Field | Value |
|---|---|
| NCIPs transitioned | `NCIP-FS-018` (Standards Track, NOT Layer 1 — filesystem direction; no cipher suite / signature scheme / capability format / mesh handshake change per §5.3 ¶2) |
| Draft filed | 2026-05-22 (commit `bac5254`, this same date) |
| Window opened | 2026-05-22 (same date) |
| Window scheduled close | 2026-06-05 (14-day standard §5.3 ¶1 first branch) |
| Window actually closed | 2026-05-22 (same day, by §5.3 ¶1 second branch) |
| Closure clause | `NCIP-Process-001` §5.3 ¶1 second branch (≥30% weight cast → window closes whichever-comes-first vs 14-day timer) |
| Dominant voter | `cySalazar <hello@nexacoreos.com>` |
| Dominant voter weighted eligibility (§5.2 bootstrap defaults) | 100% — sole §5.1-eligible device at ballot-cast time |
| Other eligible voters at ballot-cast moment | 0 (none ≥ 10% floor) |
| Ballot — `NCIP-FS-018` | In favor (1/1 ballot, 100% weighted, satisfies §5.3 ¶2 simple 50%+1 — Standards Track but **not** breaking Layer 1) |
| Blocking objections (§5.3, §5.5 (d)) | None at the time of merge. The GitHub Discussion thread linked from the frontmatter remains open for post-Active comment; a substantive technical objection raised within the standard 14-day horizon (by 2026-06-05) SHOULD trigger an Amendment NCIP per the editor body's commitment recorded below. |
| Procedural-only objections | None |
| §5.5 fast-track | **Not invoked.** Same reason recorded in the 2026-05-22 `NCIP-Bounty-002` / `NCIP-Serde-004` entry above: the §5.5 (c) banner required at `Review → Last Call` entry was not in place; §5.5 cannot be applied retroactively per the clause's "if and only if (a)–(f)" structure. §5.3 ¶1 second branch was used. |
| §5.4 BDFL veto | **Not exercised.** `NCIP-FS-018` does not break Layer 1 cryptographic guarantees, so §5.4 does not apply. |
| Activation phase (§7) | `NCIP-FS-018` is `Standards Track`; §7 activation phase opens upon `Active` and tracks the deployment metric. Practically dormant until NCFS v0 ships (Phase 2 entry); the NCIP is operationally pre-deployment until then. |
| Editor signing | `cySalazar` (interim sole editor per §6.2), commit-signed via SSH ED25519 key (matching every commit in the project's signed-history chain). |

### Editorial rationale for same-day Last Call closure

The same-day `Draft → Review → Last Call → Active` path is permitted
under §5.3 ¶1 second branch when the dominant voter holds 100% weight:
a single in-favor ballot collapses both threshold clauses (the ≥30%
trigger fires; the ≥50%+1 in-favor threshold is met by the same
ballot). The 14-day window's operational function (invite external
review) had zero days to run in this closure, but two design
constraints compensate:

1. **Post-Active 14-day objection horizon (editor commitment).** The
   §5.5 (d) good-faith objection clause remains operative by analogy
   for the standard 14-day horizon (by 2026-06-05). A substantive
   technical objection raised on the linked Discussion thread in that
   window SHOULD trigger an Amendment NCIP closing the residual review
   space. The editor body commits to this discipline and will treat
   such an Amendment as the canonical closure of the post-Active
   review window for NCIP-FS-018.
2. **Downstream full-window protection of the most sensitive bits.**
   `NCIP-FS-018` defers the on-disk wire format and the AEAD primitive
   selection to follow-up NCIPs (`NCIP-FS-Wire-NNN`, gated on
   `NCIP-Crypto-002` `Active`). The most security-critical bit sequence
   of NCFS (the AEAD chain, the capability fingerprint encoding) is
   therefore protected by a second, full-window §5.3 vote downstream.
   This NCIP picks **direction**; the follow-ups freeze the **bits**.

Closing same-day reclaims schedule velocity for the development-plan
re-scoping that follows: the `crates/nexacore-fs` skeleton from `TASK-011`
(2026-05-21 development plan) can be re-scoped from "stub-only" to
"NCFS v0 host preparation" at Phase 2 entry without first re-opening
the architectural question. Without closure, `TASK-011` remains in its
stub-only posture indefinitely and Risk R12 remains an open question
in the planning ledger.

This use of §5.3 ¶1 second branch is structurally identical to the
2026-05-22 `NCIP-Bounty-002` / `NCIP-Serde-004` closure above; the only
substantive difference is that those two NCIPs sat in `Last Call` for
10 days before closure, whereas `NCIP-FS-018` closes on day zero. The
lawful equivalence is preserved because §5.3 ¶1 names "whichever fires
first" without a minimum-floor on the time axis. The day-zero closure
is admissible under the clause; the editor body has chosen it after
weighing the two compensating constraints above against the loss of
calendar-time public-review surface.

### Re-ratification requirement

`NCIP-Process-001` §5.5 (e) does **not** apply because §5.5 was not
invoked. The §5.3 path imposes no re-ratification requirement. Future
amendments to `NCIP-FS-018` follow the same §5 process as any other
substantive change.

### Cross-references

- `ncips/ncip-fs-018.md` — Amendment history table records the
  `2026-05-22 — Draft → Review → Last Call → Active` transitions.
- `ncips/README.md` — index row updated to `Active *(closed 2026-05-22
  by §5.3 ¶1 ballot)*`.
- `docs/02-architecture.md` line 252 — annotation updated from
  "Under decision via NCIP-FS-018 (Draft, 2026-05-22)" to "Resolved by
  NCIP-FS-018 (Active, 2026-05-22, §5.3 ¶1 ballot)".
- `docs/planning/2026-05-21-development-the development plan` Risk R12 — closed by
  the commit that lands this report.
- Follow-up NCIPs anticipated per NCIP-FS-018 §"Open follow-up NCIPs":
  `NCIP-FS-Wire-NNN` (on-disk wire format, gated on `NCIP-Crypto-002`
  `Active`), `NCIP-FS-Mesh-NNN` (mesh-replicated volumes, Phase 4+),
  `NCIP-FS-Compat-Ext4-NNN` (Phase 3 entry), `NCIP-FS-Compat-NTFS-NNN`
  (optional, Phase 3+).

---

## 2026-05-24 — `NCIP-Crypto-002` (Last Call → Active)

### Summary

`NCIP-Crypto-002` entered `Last Call` on 2026-05-12 and was scheduled to
transition to `Active` automatically at the end of the standard 14-day
public-objection window per `NCIP-Process-001` §5.3 ¶1 first branch
(2026-05-26). On 2026-05-24 the interim editor body (`cySalazar`, sole
§6.2 Bootstrap editor) closed the window early via the §5.3 ¶1 second
branch — founder ballot satisfying the ≥30% weighted-vote-cast threshold,
since the dominant voter holds 100% bootstrap-default weighted eligibility
per §5.2 (matching the voter-set state recorded in prior Q2 entries).
Because NCIP-Crypto-002 is `Standards Track` and **does** affect Layer 1
cryptographic guarantees (the compliance proof scheme is a cryptographic
primitive per §5.3 ¶2), the 66.7% supermajority threshold applies —
satisfied trivially with a single 100%-weight voter.

| Field | Value |
|---|---|
| NCIPs transitioned | `NCIP-Crypto-002` (Standards Track, **Layer 1** — STARK-based compliance proof scheme is a cryptographic primitive per §5.3 ¶2) |
| Window opened | 2026-05-12 (per NCIP Amendment history) |
| Window scheduled close | 2026-05-26 (14-day standard §5.3 ¶1 first branch) |
| Window actually closed | 2026-05-24 (12 days into the window, by §5.3 ¶1 second branch) |
| Closure clause | `NCIP-Process-001` §5.3 ¶1 second branch (≥30% weight cast → window closes whichever-comes-first vs 14-day timer) |
| Dominant voter | `cySalazar <hello@nexacoreos.com>` |
| Dominant voter weighted eligibility (§5.2 bootstrap defaults) | 100% — sole §5.1-eligible device at ballot-cast time |
| Other eligible voters at ballot-cast moment | 0 (none ≥ 10% floor) |
| Ballot — `NCIP-Crypto-002` | In favor (1/1 ballot, 100% weighted, satisfies §5.3 ¶2 **66.7% supermajority** — Standards Track AND breaking Layer 1 cryptographic guarantees: compliance proof scheme is a cryptographic primitive) |
| Blocking objections (§5.3, §5.5 (d)) | None received on the linked GitHub Discussion thread during the 12-day partial window (2026-05-12 → 2026-05-24). |
| Procedural-only objections | None |
| §5.5 fast-track | **Not invoked.** The §5.5 (c) banner required at `Review → Last Call` entry was not in place; §5.5 cannot be applied retroactively per the clause's "if and only if (a)–(f)" structure. §5.3 ¶1 second branch was used instead. |
| §5.4 BDFL veto | **Not exercised.** Although NCIP-Crypto-002 is Layer 1 (compliance proof scheme), the BDFL veto in §5.4 is an optional override mechanism, not a mandatory gate; the founder, acting as both dominant voter and BDFL, cast an in-favor ballot. |
| Activation phase (§7) | `NCIP-Crypto-002` (Standards Track, Layer 1): §7 activation phase opens upon `Active`. Operationally dormant until the `nexacore-mesh` compliance layer ships with `sig-v1` baseline (Phase 2 entry); `stark-v0` remains opt-in feature-gated until Phase 2+ production benchmarks. |
| Editor signing | `cySalazar` (interim sole editor per §6.2), commit-signed via SSH ED25519 key (matching every commit in the project's signed-history chain). |

### Editorial rationale for early closure

The §5.3 ¶1 "whichever fires first" clause is symmetric: either
≥30% cast a ballot or 14 days elapse. Under bootstrap conditions
the dominant voter holds 100% weight, so casting a single in-favor
ballot collapses both clauses (the ≥30% trigger fires; the 66.7%
supermajority threshold required for Layer 1 changes is met by the
same 100%-weight ballot — 100% ≥ 66.7%). The 14-day window's
operational function — *"invite external review"* — had 12 days to
run; the partial window collected no blocking objection on the GitHub
Discussion thread. Closing at day 12 reclaims editorial-pipeline
schedule velocity for downstream work that is gated on NCIP-Crypto-002
being `Active` (notably `NCIP-FS-Wire-NNN` per `NCIP-FS-018` cross-
reference, and the Phase 2 entry `nexacore-mesh` compliance layer).

### Re-ratification requirement

`NCIP-Process-001` §5.5 (e) mandates post-deactivation re-ratification
for NCIPs activated under §5.5. Because today's closure used §5.3 ¶1
(not §5.5), the §5.5 (e) clause does **not** apply. Future amendments
to NCIP-Crypto-002 follow the same §5 process as any other substantive
change; the 66.7% supermajority threshold will continue to apply to
any amendment that touches Layer 1 cryptographic guarantees.

### Cross-references

- `ncips/ncip-crypto-002.md` — Amendment history table records the
  `2026-05-24 — Last Call → Active` transition.
- `ncips/README.md` — index row updated to `Active *(closed 2026-05-24
  by §5.3 ¶1 ballot, 66.7% supermajority)*`.
- `CHANGELOG.md` — entry added for 2026-05-24.

---

## Trailing template (for future Q2 entries)

```markdown
## YYYY-MM-DD — `NCIP-<Slug>-<NNN>` (Last Call → Active)

### Summary

<one-paragraph editorial explanation>

| Field | Value |
|---|---|
| NCIPs transitioned | <list> |
| Window opened | YYYY-MM-DD |
| Window scheduled close | YYYY-MM-DD |
| Window actually closed | YYYY-MM-DD |
| Closure clause | §5.3 ¶1 <first|second branch> |
| Dominant voter | <identity> |
| Dominant voter weighted eligibility | <pct> |
| Other eligible voters at ballot-cast moment | <count> |
| Ballot — `NCIP-<...>` | <in favor / against / abstain> |
| Blocking objections | <none|list> |
| §5.5 fast-track | <invoked|not invoked, with reason> |
| §5.4 BDFL veto | <not applicable|exercised> |
| Activation phase (§7) | <not applicable|dormant|active phase opens> |
| Editor signing | <identity + signing key fingerprint reference> |
```
