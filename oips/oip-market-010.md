---
ncip: 10
title: nexacore-market — Stichting-Curated Marketplace with Continuous CVE Scanning and Tier-Based Trust
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-12
updated: 2026-05-12
requires:
  - NCIP-Process-001
  - NCIP-Container-006
  - NCIP-Pkg-008
  - NCIP-Crypto-002
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

# NCIP-Market-010 — `nexacore-market`: Stichting-Curated Marketplace

## Abstract

This NCIP commits NexaCore OS to **`nexacore-market`**, the Stichting NexaCore-
curated package registry that serves as the default source for
`nexacore-pkg` (NCIP-Pkg-008). Key properties:

- **Bronze / Silver / Gold / Stichting-Curated** trust tiers, each with
  documented verification criteria.
- **Continuous CVE scanning** with public SLA per severity.
- **Capability-minimality verification** (declared caps ≤ used caps,
  enforced).
- **Policy compliance** (license, surveillance vendor, telemetry, DRM).
- **Economics**: 0% commission on OSS, **10%** on commercial apps, 0%
  on Stichting-sponsored.
- **Reproducible build verification** for Silver tier and above.

## Motivation

Mainstream marketplaces (Apple App Store, Google Play, Microsoft Store)
charge 15-30% commission, run opaque verification, and have variable
CVE response. The OSS-aligned ones (Flathub, Snap Store, AUR) are
better on commission and transparency but weak on continuous CVE
scanning and capability verification.

`nexacore-market` aims to be **the most transparent and security-rigorous
marketplace among major OSes**, while charging substantially lower
commercial fees than Apple/Google/Microsoft.

## Specification

### 1. Layer relationship with `nexacore-pkg`

`nexacore-market` is **a registry** that `nexacore-pkg` consults. It is **the
default** but not exclusive. Users can configure additional registries.

When `nexacore-pkg` consults multiple registries for the same package,
trust ranking uses:
- `nexacore-market` tier (Bronze=3 / Silver=4 / Gold=5 / Stichting-Curated=5+
  badge).
- Community reputation score (mesh-aggregated, 0-100).
- Capability minimality score.

### 2. Trust tiers

| Tier | Verification | Time-to-publish | Trust score |
|---|---|---|---|
| **Bronze** | Automated pipeline (Sigstore + license + CVE scan + cap-minimality + reproducible-build optional) | Minutes after pipeline pass | 3/5 |
| **Silver** | Bronze + 1-2h human reviewer (Stichting) + **reproducible build mandatory** + community reputation > 70 | 1-2 weeks | 4/5 |
| **Gold** | Silver + **external security audit** + reproducible build certified + community reputation > 85 + Foundation board sign-off | 1-3 months | 5/5 |
| **Stichting-Curated** | Gold + developed or sponsored directly by Stichting (e.g., NexaCoreCode per NCIP-Flagship-011) | — | 5/5 + "official" badge |

### 3. Submission pipeline (developer-side)

```bash
$ nexacore-market submit my-app.nexacore
  # 1. signature + DCO verification
  # 2. static analysis (caps declared vs used)
  # 3. CVE scan (RustSec + NVD + Sigstore advisories on dep tree)
  # 4. license compatibility (whitelist check)
  # 5. reproducible-build verification (optional Bronze, required Silver+)
  # 6. capability-minimality analysis (over-request → rejection)
  # 7. policy compliance (telemetry, surveillance, DRM, banned deps)
  # 8. assign Bronze tier or queue for human review
```

Pipeline outcomes:
- **PASS** → published at appropriate tier.
- **WARN** → published with caveat banner (e.g., "capability set
  exceeds best-practice"); developer notified.
- **FAIL** → not published; developer receives report; 30 days to
  resubmit before submission window closes.

### 4. Continuous CVE scanning

| Component | Cadence |
|---|---|
| RustSec / NVD / Sigstore advisories sync | Hourly |
| Re-scan all published packages against new advisories | < 6h from publication |
| Critical-severity CVE in published package | Auto banner red + email developer + 14-day SLA to patch |
| High-severity CVE | Yellow banner + 30-day SLA |
| Medium / low | Notification only + 90-day SLA |

SLA breach consequences:
- Bronze → demote to "quarantined" (not removable but not installable
  by default).
- Silver / Gold → demote one tier; re-promotion requires re-verification.
- Stichting-Curated → Foundation board response within 7 days; emergency
  patch or quarantine.

### 5. Policy compliance

| Policy | Verification mechanism |
|---|---|
| License whitelist (Apache-2.0, MIT, Apache-2.0, BSD-2/3, ISC, MPL-2.0, custom open licenses with explicit allowlist) | License manifest + source scanning |
| No closed telemetry (must be opt-out or opt-in if telemetry exists) | Reproducible build + binary scan for known telemetry endpoints |
| No surveillance vendor deps | Dep tree scanned vs Surveillance Industry Index + Stichting curated deny-list |
| No DRM blocking Foundation audit | Manifest declares "audit-friendly"; quarantined if not |
| No FAANG/regulator-funding in commercial path | Best-effort via community-reporting NCIP; Foundation reviews |

### 6. Economics

| Path | Commission |
|---|---|
| Open-source apps (Apache-2.0 + permissive whitelist) | **0%** — Foundation absorbs verification cost |
| Commercial paid apps | **10%** — covers verification + audit + infrastructure |
| Stichting-sponsored apps (translation, accessibility, security tooling) | **0%** — Foundation funded |
| Pay-what-you-want / donation | Pass-through, **0%** Foundation; payment processing fee paid by developer |

Commission collected by Stichting NexaCore; ledger published in annual
transparency report (per `docs/08-funding-policy.md`).

### 7. Reference implementation — `crates/nexacore-market/`

```
crates/nexacore-market/
├── Cargo.toml
├── src/
│   ├── lib.rs                  # public surface
│   ├── registry/
│   │   ├── server.rs           # HTTP API matching nexacore-pkg federation protocol
│   │   ├── search.rs
│   │   └── ranking.rs
│   ├── pipeline/
│   │   ├── signature.rs        # Sigstore verify
│   │   ├── cve_scan.rs         # cargo-audit + NVD + Sigstore adv
│   │   ├── license.rs          # whitelist check
│   │   ├── reproducible.rs     # re-build + hash compare
│   │   ├── cap_minimality.rs   # declared vs used analysis
│   │   └── policy.rs           # telemetry / surveillance / DRM checks
│   ├── tier.rs                 # Bronze / Silver / Gold / Curated logic
│   ├── cve_watcher.rs          # continuous re-scan daemon
│   ├── billing.rs              # commission ledger
│   └── api/
│       ├── submit.rs
│       ├── promote.rs
│       └── transparency_report.rs
└── tests/
    ├── pipeline_end_to_end.rs
    ├── cve_scan_simulation.rs
    └── tier_promotion.rs
```

Plus separate Stichting infrastructure repo for the actual
`market.nexacoreos.com` deployment.

Estimated effort: **18-24 engineer-months** for v0.1 (production-grade
marketplace + CVE scanning + tier management + billing). Includes a
Stichting operations component (verification team).

## Rationale

### Why 10% commission on commercial vs 5% I'd initially proposed?

A 10% rate provides a more sustainable cushion for Foundation operations
without leaning on funding shortfalls during slow grant cycles. 10% is
still 1.5–3× better than Apple/Google/Microsoft (15–30%) and 2× the
typical Patreon/Stripe rate. The Foundation publishes the use of these
funds in annual transparency reports.

### Why mandatory reproducible build at Silver+?

Without reproducible builds, the Foundation cannot independently verify
that the published binary matches the published source. Reproducibility
is the difference between "we trust Sigstore signing" and "we can
prove the artifact matches the source".

### Why continuous CVE re-scan?

Static "scan at publish time" misses CVEs disclosed after publication.
Continuous scan-then-notify-then-SLA closes the window and informs
users via the Helper's Impact Dashboard.

### Why public SLAs?

Predictability. Developers know exactly what's expected. Users know
exactly what to expect. Foundation accountability is measurable.

## Backwards Compatibility

Not applicable.

## Test Cases

1. **Bronze publish round-trip**: developer submits valid package,
   pipeline passes, package available within minutes at Bronze.
2. **Silver promotion**: developer requests Silver promotion;
   reviewer verifies; reproducible build re-runs; tier updated.
3. **CVE response**: simulated Critical CVE on a Bronze package
   triggers red banner + email within 6 hours; SLA timer starts.
4. **License rejection**: package with GPL-2-only-incompatible
   dependency refused at pipeline.
5. **Capability over-grant rejection**: package declares
   `fs:write:/etc` but binary uses only `fs:read:/data`; over-grant
   refused (Bronze) or warning (Silver+).
6. **Reproducible build mismatch**: re-built binary hash differs
   from published; refuse at Silver+; Bronze stays but with banner.
7. **Commission ledger**: commercial app sale; 10% credited to
   Stichting; appears in next quarterly transparency snapshot.

## Reference Implementation

To land before activation:
- `crates/nexacore-market/` skeleton.
- Stichting infra repo `nexacore-market-deploy/` (Stichting-operated; out of
  workspace scope; depends on Phase 0 funding closure).
- Continuous CVE scanner daemon, runs against published packages.
- Integration tests using a mock NVD + mock RustSec feed.

## Security Considerations

- **Marketplace as central point of failure**: a Foundation
  compromise lets attackers ship signed-malicious packages.
  Mitigation: signing keys in HSM with multi-sig (3-of-5 trustees
  required); CT log + external witnesses make retroactive forgery
  detectable.
- **Reviewer collusion**: Silver/Gold human reviewers could be
  compromised. Mitigation: 2-reviewer requirement for Gold; randomized
  reviewer assignment; quarterly cross-audit by external party.
- **CVE feed quality**: false positives produce false alarms; false
  negatives miss vulnerabilities. Mitigation: combine multiple feeds
  (RustSec + NVD + Sigstore); manual override for false positives
  logged publicly.

## Privacy Considerations

- **Browse/install metadata** leak to the registry. Mitigation:
  Tier-2 mesh onion-routing for queries when privacy budget allows;
  Tier-0 local cache for frequently-installed packages.
- **Developer identity** in publications is Sigstore-keyed; pseudonymous
  developers allowed (matches the project's own identity policy with
  cySalazar).
- **Commission ledger** discloses aggregates publicly; per-developer
  earnings only to the developer themselves and Foundation tax records.

## Future Work

- **NCIP-Market-Federation-XXX** (Phase 6+): third-party trust providers
  (independent auditors) can issue signed attestations that the
  marketplace accepts as evidence for Silver/Gold promotion.
- **NCIP-Market-Subscription-XXX** (Phase 7+): subscription model
  pricing for commercial apps.
- **NCIP-Market-BountySync-XXX** (Phase 7+): integration with
  NCIP-Bounty-002 for vulnerability disclosures.

## Copyright

CC0 1.0 Universal.
