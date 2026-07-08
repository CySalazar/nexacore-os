# Commercial License — NexaCore OS

> **Status:** PLACEHOLDER (non-binding) — this template will become a binding offer
> only after the project's legal entity is established. The legal form of that
> entity (foundation, company, or a dual foundation + operating-company structure)
> is **under evaluation**; see [`/docs/05-governance.md`](docs/05-governance.md) and
> [`/docs/08-funding-policy.md`](docs/08-funding-policy.md).
>
> Until then, all distribution of NexaCore OS is governed exclusively by the
> [Apache-2.0](LICENSE) license.

---

## 1. Why this file exists

NexaCore OS is licensed under the **Apache License, Version 2.0** ([LICENSE](LICENSE)).
This permissive license allows any user, contributor, or downstream project
to use, modify, and redistribute NexaCore OS — including in proprietary products —
with no copyleft obligation.

This document describes the **commercial support and certification program**
that the project's legal entity will offer. Unlike a dual-license model, the commercial
offering does not grant additional license rights (Apache-2.0 already grants
them all). Instead, it provides:

- Priority security advisories and SLA-backed incident response.
- Certified builds with reproducible attestation.
- Trademark licensing for "NexaCore OS Certified" branding.
- Professional support and consulting.

The commercial program exists to fund the project sustainably while keeping
the codebase fully open under Apache-2.0.

## 2. Licensor (when established)

- **Legal entity:** to be established — legal form under evaluation (foundation,
  company, or a dual foundation + operating-company structure)
- **Jurisdiction:** to be determined at establishment
- **Registration:** `<TBD: pending establishment>`
- **Authorized signatory:** the entity's governing body, acting per its
  constitutional documents.

Until that entity exists, **no party is authorized to grant a commercial
license on behalf of the project.** Inquiries received before establishment
will be acknowledged but not contracted.

## 3. Scope of the commercial program

A commercial agreement, when offered, will grant the subscriber the following
for the agreed term:

- Priority security advisories (synchronized with public disclosure
  per [`SECURITY.md`](SECURITY.md), not ahead of it).
- SLA-backed incident response (severity-tiered, per the agreement).
- Access to certified, reproducibly-built NexaCore OS images with TEE attestation.
- Right to use the "NexaCore OS Certified" trademark on compliant deployments.
- Professional support and consulting from the core team.

It will **not** grant:

- Any license rights beyond what Apache-2.0 already provides (it provides all).
- Exclusive use of any NexaCore OS component or API.
- Any indemnification beyond what the entity's constitutional documents permit.

## 4. Pricing model (indicative, non-binding)

The entity's governing body will publish a tiered pricing model based on
licensee size and use case. Indicative tiers (subject to ratification):

| Tier | Profile | Indicative annual fee |
|---|---|---|
| Startup | < 50 employees, < €5M ARR | TBD |
| SMB | 50–500 employees | TBD |
| Enterprise | > 500 employees, or revenue > €100M | TBD |
| Sovereign / regulated | governments, defense, regulated finance | **Excluded** per Funding Policy |

**Sovereign and regulated-finance use is explicitly excluded** from
commercial licensing per [`/docs/08-funding-policy.md`](docs/08-funding-policy.md).
This boundary is non-negotiable and will be entrenched in the entity's
constitutional documents.

## 5. Excluded use cases (categorical, non-monetary)

Even with a paid commercial license, the following uses are forbidden:

- Mass surveillance infrastructure, whether state-operated or private.
- Predictive policing, social-scoring systems, or behavioral prediction
  systems aimed at populations rather than consenting individuals.
- Autonomous weapons systems (AWS) as defined by the Campaign to Stop
  Killer Robots, regardless of national-security framing.
- Systems whose primary purpose is to circumvent end-to-end encryption or
  to subvert TEE attestation.

Violation of these clauses voids the commercial license retroactively.

## 6. How to inquire (placeholder)

Until the project's legal entity is operational:

- **Contact:** `commercial@nexacoreos.com` (project founder, acting in
  personal capacity — no binding offer can be made)
- **Subject line prefix:** `[NexaCore OS — Commercial License Inquiry]`
- **Required information:**
  1. Legal entity name and country of registration.
  2. Intended use case (one paragraph).
  3. Approximate scale (employees, revenue, NexaCore OS deployment count).
  4. What commercial support or certification needs the use case has.

Inquiries are logged and triaged in a **read-only ledger** that will be
transferred to the legal entity on establishment, ensuring no licensee is
disadvantaged by the timing of their inquiry.

## 7. Effective date

This document becomes a binding offer on the date the project's legal entity
is registered with the competent authority in its jurisdiction and ratifies
its commercial-licensing policy by resolution of its governing body. Until
that date, this file is informational only.

## 8. Change control

Material changes to this document — pricing model, excluded use cases,
licensor identity — require:

- A resolution of the entity's governing body (post-establishment), and
- A 30-day public comment window referenced by an NCIP (per
  [`/docs/05-governance.md`](docs/05-governance.md) Layer 2).

Editorial changes (typos, broken links, format) may be made by the
maintainer team without an NCIP, with a changelog appended below.

---

## Changelog

- 2026-05-09 — Initial placeholder drafted by the founder. Non-binding.
- 2026-07-04 — Entity-neutral revision: the legal form of the project's entity
  (foundation, company, or dual structure) is under evaluation, so all
  Stichting-specific references were generalized. Apache-2.0 confirmed as the
  sole code license; this program grants no additional license rights.

---

*This file is part of NexaCore OS and is governed by the project's documentation
policy. It is **not** legal advice. If your organization requires a binding
commercial license, contact the founder using the details in Section 6.*
