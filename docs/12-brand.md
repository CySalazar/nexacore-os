# Brand & visual identity

**Status:** Draft v0.1
**Last updated:** 2026-05-13

> This document is a **pointer**. The authoritative brand pack lives in [`/brand/`](../brand/). Everything in `/docs/` that needs to refer to the brand should link back to `/brand/` rather than restate its content.

## Identity at a glance

| Role | Identity | Used for |
|---|---|---|
| Product | `NexaCore OS` | Source code, technical docs, READMEs, CLI banner, kernel `uname`, releases |
| International brand | `NexaCore Foundation` | Website, social, press, sponsor materials, grant applications outside NL |
| Legal entity | `Stichting NexaCore` | KVK registration, notarial deed, Dutch tax filings, contracts, ANBI |
| Formal full lockup | `NexaCore Foundation — Stichting NexaCore, Amsterdam` | First-mention in formal external materials |

The three identities follow the Mozilla model: a Dutch foundation carries the legal weight; the international brand name carries the communication; the product name carries the engineering work. See [`brand/STRATEGY.md` §1](../brand/STRATEGY.md) for capitalization rules, possessive forms, first-mention patterns, and the trademark posture.

## Visual direction

The brand follows **Direction C — Civic Tech / Generational**, anchored on the design languages of Mozilla, Wikimedia, GOV.UK, the Internet Archive, and the Long Now Foundation. The choice was made on 2026-05-13 and is recorded in the brand strategy.

- **Palette (canonical hues):** `petrol #0F4C5C`, `cream #F4EBD0`, `brick #C03221`, `sage #7A9E7E`, `charcoal #1F2421`. Tokens: [`brand/colors/tokens.css`](../brand/colors/tokens.css), [`tokens.json`](../brand/colors/tokens.json). Full WCAG contrast matrix: [`brand/colors/palette.md`](../brand/colors/palette.md).
- **Typography:** Source Serif 4 (display), Inter (body & UI), IBM Plex Mono (code & metadata). All three SIL OFL — coherent with Apache-2.0 codebase and CC0 protocol specs. Tokens: [`brand/typography/type-tokens.css`](../brand/typography/type-tokens.css).
- **Mark:** a six-node federated ring around a central brick-red core. The core is the **Mission Anchor** (irrevocable, per the Foundation bylaws Article 3); the six petrol nodes represent federated attested peers; the dimming envelope ring signals inclusion. Construction geometry: [`brand/logos/nexacore-os-construction.svg`](../brand/logos/nexacore-os-construction.svg).

## Voice anchors

The eight voice rules (see [`brand/STRATEGY.md` §5](../brand/STRATEGY.md) for the full set):

1. Name the mechanism. Every claim points to a spec section, a primitive, or an audit.
2. Short sentences. Average 14–18 words. Variety for rhythm.
3. **No exclamation marks. Ever.** Including in error messages and informal chat.
4. No war / religion / sport / family metaphors.
5. The reader is competent.
6. Sound the same in 5 years (no trend vocabulary).
7. Hedge precisely or not at all.
8. Cite yourself with stable file paths.

The owned tagline (canonical): **"An AI-native operating system. Local-first. Decentralized."** Variants and longer-form pitches: [`brand/STRATEGY.md` §6](../brand/STRATEGY.md).

## Reading order

If you are touching brand-facing material:

1. Start with [`brand/STRATEGY.md`](../brand/STRATEGY.md) — the authoritative source for naming, voice, positioning.
2. Open [`brand/NexaCore-Brand-Book-v0.1.pdf`](../brand/NexaCore-Brand-Book-v0.1.pdf) for the consolidated 21-page reference.
3. Pull what you need from [`brand/templates/`](../brand/templates/): README header, slide deck starter, social card SVG, GitHub social preview SVG, NCIP cover template, email signature.
4. Use tokens (not hex literals) from [`brand/colors/tokens.css`](../brand/colors/tokens.css) and [`brand/typography/type-tokens.css`](../brand/typography/type-tokens.css).

## Maintenance

- **Owner:** Lead Architect (cySalazar) for years 1–5. After 2031-05-09, the Foundation's Director (per [`05-governance.md`](./05-governance.md) and [`brand/STRATEGY.md` §12](../brand/STRATEGY.md)).
- **Authority:** [`brand/STRATEGY.md`](../brand/STRATEGY.md) is authoritative. If this pointer document and the strategy disagree, the strategy wins; this file is then updated.
- **Change process:** brand changes follow the same PR review path as code changes. Lockup, palette, or wordmark changes additionally require an ADR in [`/docs/adr/`](./adr/).

## Trademark posture

Per the Foundation bylaws Article 10.3, trademarks are held by the Foundation under a **public trademark policy permitting fair use, forks, and derivative works that maintain protocol compatibility**. The Foundation will not initiate trademark enforcement against good-faith uses. Forks-welcome is a brand asset, not a brand risk. See [`brand/STRATEGY.md` §1.4, §9.3](../brand/STRATEGY.md) for the full posture and qualifier conventions for fork names.

## Contact

`brand@nexacoreos.com` (forthcoming, upon Foundation constitution). Until then: `hello@nexacoreos.com`.
