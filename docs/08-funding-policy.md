# Funding Policy

**Status:** Draft v0.2

> **Entity status (2026-07-04):** the legal form of the project's entity — foundation (`Stichting NexaCore`), company, or a dual foundation + operating-company structure — is **under evaluation**. References to the Stichting and its bylaws below describe the foundation option as drafted and are contingent on that decision.

> **Changelog**
> - **v0.2 (2026-05-10):** cross-referenced Stichting NexaCore bylaws Article 3
>   (Mission Anchor, immutable) and Article 9.1 (30% diversification rule);
>   documented the operational funding materials (sponsor-tier menu, grant
>   application drafts) maintained by the Foundation;
>   tightened the Borderline-Sources subsection with a recorded preliminary
>   founder view on NLnet (final board decision deferred to first board
>   meeting post-Stichting constitution).
> - **v0.1 (initial):** principles, excluded sources, accepted tiers, dual
>   licensing, allocation, transparency commitments, donor relationships,
>   conflict-of-interest, emergency procedures.

## Principles

NexaCore OS funding must satisfy four principles:

1. **Mission-aligned**: from sources sharing the privacy-first, anti-capture mission.
2. **Independent of regulators**: never from entities with legal regulatory power over the project's domain (privacy, AI, telecommunications).
3. **Transparent**: publicly disclosed in annual audited reports.
4. **Diversified**: no single source > 30% of operating budget after year 2.

These principles narrow available funding paths significantly. The trade-off is intentional: it is mission-coherent and reduces the risk of capture by funders, even at the cost of slower growth.

**Bylaws anchor.** Principles 1–3 are reflected in **Stichting NexaCore bylaws Article 3 (Mission Anchor)** — explicitly **immutable** for the lifetime of the Foundation (modification requires unanimous board + 80% NCIP supermajority + 6-month public notice). Principle 4 (diversification) is anchored in **Article 9.1**. A breach of any of these principles by the board is a stop-condition triggering public review.

## Excluded sources

The Foundation will NOT accept funding from:

- **Governments**, government agencies, or government-funded programs disbursing direct grants.
- **Government-aligned investment funds** (sovereign wealth funds, state-controlled VCs).
- **Entities with legal regulatory authority** over privacy, AI, or telecommunications (this excludes most large media platforms, telcos, and cloud hyperscalers headquartered in jurisdictions where they are also regulators-by-influence).
- **Surveillance vendors** or surveillance-adjacent companies (defined by the public Surveillance Industry Index and similar databases).
- **Entities under active investigation** for material privacy violations, fraud, or sanctions.
- **Anonymous or untraceable funding streams** (KYC required for all donors above a small threshold).

This excludes commonly-used routes such as Horizon Europe direct grants, US Naval Research Laboratory, Open Technology Fund, and similar government-funded programs. The trade-off is intentional.

## Borderline sources (case-by-case board decision)

Sources where the principle of independence may or may not be violated, depending on specifics:

- **NLnet Foundation grants**: NLnet is a private nonprofit, but channels EU NGI (Next Generation Internet) funds upstream. The Foundation will evaluate per-grant whether the operational independence is sufficient.
- **University research grants**: depends on the university's funding sources and whether grant terms preserve independence.
- **Aligned-mission corporate sponsorship from companies in regulated industries**: case-by-case based on the specific entity's regulatory exposure to NexaCore OS.

Borderline decisions are documented publicly with rationale.

**Preliminary founder view on NLnet (recorded 2026-05-10, non-binding on future board):** the founder's view is that NLnet's track record of operational independence (project selection, no political interference, no IP claims) meets the Principle-2 bar despite the EU-NGI upstream relationship. The first board, once constituted, makes the final call per the procedure above. The first NLnet application is drafted and held pending foundation constitution + board ratification.

## Accepted sources

### Tier 1 — Mission-aligned private nonprofits

Foundations and grant-makers without governmental control:

- Open Philanthropy
- Sloan Foundation
- Mozilla Open Source Support (MOSS)
- Internet Society / ISOC
- Comparable nonprofits with explicit privacy / digital-rights missions

### Tier 2 — Aligned corporate sponsorship

Companies with values aligned to the NexaCore OS mission and without regulatory power over the project:

- **Privacy-focused service providers**: Proton AG, Tutanota, Mullvad, Element / New Vector, Threema.
- **Privacy-focused hardware vendors**: System76, Framework, Purism, Nitrokey, Solokeys.
- **Aligned ecosystem players** (case-by-case): companies whose business model does not conflict with NexaCore OS goals.

Excluded: FAANG, telcos, banks, cloud hyperscalers, advertising networks. Their participation as customers (commercial license buyers) is allowed; their participation as funders is not.

**Operational menu.** A public sponsor-tier menu (Bronze / Silver / Gold / Platinum) defines annual amounts, what sponsors get (and what they explicitly do NOT get), and the application process.

### Tier 3 — Community

- **Individual donations** (deductible if Foundation has ANBI status).
- **GitHub Sponsors, OpenCollective, Patreon**: recurring contributions.
- **Crowdfunding** for specific milestones (e.g., security audits, hardware bring-up).

### Tier 4 — Self-sustaining (post-adoption)

After significant adoption, the project becomes partially self-funding:

- **Mesh fee**: a small percentage of compute credits flows to a public development fund, allocated transparently per NCIP-approved budget.
- **Commercial license fees** (dual-licensing — see below).
- **Hardware certification fees** from vendors seeking the NexaCore OS Certified mark.

## Dual licensing

Source code is released under Apache-2.0 by default. Stichting NexaCore may grant commercial licenses to organizations that:

- Wish to deploy NexaCore OS in contexts that require commercial support.
- Pay license fees to the Foundation, contributing to development.

Commercial licensing is administered transparently. License fees are reported as a budget line in annual financial statements. The pricing structure is published.

Commercial licensees gain:
- Right to deploy NexaCore OS in proprietary products with commercial support.
- Optional commercial support contracts.

Commercial licensees do NOT gain:
- Influence over protocol direction (governance is layer 2, independent of funding).
- Special access to user data (cryptographic guarantees apply equally).
- Preferential treatment in NCIP processes.

## Funding allocation

Annual budget is approved by the board after public NCIP discussion. Allocation categories:

- **Engineering** (development, security audits): largest line.
- **Infrastructure** (seed nodes, CI/CD, hosting).
- **Legal and compliance** (counsel, audits, regulatory work).
- **Community programs** (events, documentation, translations, contributor stipends).
- **Reserve fund** (≥ 6 months operating runway).

Compensation:
- Board members: nominal stipend + expenses (the Foundation is not a vehicle for board enrichment).
- Director and engineering staff: market-competitive salaries.
- All compensation disclosed in annual reports.

## Annual transparency report

Published yearly, including:

- Total revenue, broken down by source.
- Total expenditure, broken down by category.
- Board composition and compensation.
- Director and senior staff compensation.
- Major commitments and contingent liabilities.
- Independent audit results.
- NCIP-approved budget for next fiscal year.

The Foundation commits to engaging an independent auditor of recognized standing.

## Donor relationships

- Donors are thanked and acknowledged (publicly with consent, otherwise privately).
- Donors do NOT gain influence over protocol or governance.
- Donor preferences may be considered for programmatic priorities (e.g., a donor funding "documentation translation" can earmark for that), but never for protocol changes.
- Conflicts of interest involving board members and donors are disclosed and recused.

## Conflict-of-interest policy

- Board members disclose all material affiliations annually.
- Trustees recuse themselves from decisions involving organizations they are affiliated with.
- All conflicts and recusals are published in board meeting summaries.

## Funding emergency procedures

If funding shortfalls threaten the project:

1. Board declares a funding emergency publicly.
2. Reserve fund is drawn upon to maintain critical operations (security maintenance, infrastructure).
3. Engineering scope is reduced; non-critical phases are paused.
4. Public appeal for community funding launched.
5. If emergency persists > 6 months, Foundation enters formal review per stop-condition criteria in [roadmap](./06-roadmap.md).
