# NexaCore OS — Palette reference

**Direction:** C — Civic Tech / Generational
**Files in this directory:**
- [`tokens.css`](./tokens.css) — production-ready CSS custom properties (use this in code)
- [`tokens.json`](./tokens.json) — design-tokens-community-group format
- this file — human-readable documentation, contrast matrix, usage rules

## Hue family overview

| Family | Canonical | Role | Personality cue |
|---|---|---|---|
| **petrol** | `#0F4C5C` | Primary brand hue, headings, links, structural lines | Patient, sober, institutional |
| **cream** | `#F4EBD0` | Warm canvas, page background, surface tint on dark mode | Generational, archival, paper |
| **brick** | `#C03221` | Mission Anchor accent — singular red reserved for governance and high-attention status | Honest about risk, no flinch |
| **sage** | `#7A9E7E` | Community, success/OK status, contributor signals | Open, healthy, calm |
| **charcoal** | `#1F2421` | Body text, code blocks, dark surfaces, hairlines on cream | Rigorous, neutral, persistent |

## The "single red" rule

**Brick is the ONLY warm accent in the system.** Sage warns/passes, charcoal carries, petrol leads. Brick is reserved for:

1. The Mission Anchor dot in the NexaCore mark
2. Governance-status pills (`Active`, `Withdrawn`, `Vetoed`)
3. Critical alerts (`SEC-CRITICAL`, `AWAITING_CRYPTO_REVIEW`)
4. Phase indicators on the roadmap when intentionally signalling "this matters"

Brick is never decorative. If a designer is "using brick to add warmth", they are misusing it. Use cream-600 or sage-500 instead.

## Contrast matrix (WCAG 2.1)

All ratios computed against the canonical canvas and surface colors. AAA is the target for body text per [STRATEGY.md §4.1](../STRATEGY.md).

### On cream-300 canvas (`#F4EBD0`)

| Foreground | Hex | Contrast | WCAG verdict |
|---|---|---|---|
| charcoal-800 (text-primary) | `#1F2421` | 12.2 : 1 | **AAA** all sizes |
| charcoal-500 (text-secondary) | `#3E423E` | 7.9 : 1 | **AAA** body |
| charcoal-300 (text-tertiary) | `#888D88` | 2.5 : 1 | Fail body, OK 18pt+/14pt-bold |
| petrol-500 (text-accent, links) | `#0F4C5C` | 9.4 : 1 | **AAA** all sizes |
| petrol-700 (link-hover) | `#0A323C` | 12.6 : 1 | **AAA** all sizes |
| brick-500 (anchor / danger) | `#C03221` | 4.7 : 1 | AA body, **AAA** large |
| sage-700 (success-strong) | `#587657` | 4.6 : 1 | AA body, **AAA** large |

### On white surface (`#FFFFFF`)

| Foreground | Hex | Contrast | WCAG verdict |
|---|---|---|---|
| charcoal-800 | `#1F2421` | 14.6 : 1 | **AAA** all sizes |
| petrol-500 | `#0F4C5C` | 11.2 : 1 | **AAA** all sizes |
| brick-500 | `#C03221` | 5.6 : 1 | AA body, **AAA** large |
| sage-700 | `#587657` | 5.5 : 1 | AA body |

### On charcoal-900 dark canvas (`#14171A`)

| Foreground | Hex | Contrast | WCAG verdict |
|---|---|---|---|
| cream-300 | `#F4EBD0` | 11.8 : 1 | **AAA** all sizes |
| cream-500 | `#D9C68A` | 9.2 : 1 | **AAA** all sizes |
| petrol-200 | `#94B3BC` | 7.4 : 1 | **AAA** body |
| brick-300 | `#D85C50` | 5.1 : 1 | AA body |

> **Practical rule:** if you have to verify a combination against the matrix, it is probably wrong. Default to charcoal-800 on cream-300 for body, petrol-500 for headings/links, brick-500 only when meaning demands it.

## Forbidden combinations

| Pair | Why it fails |
|---|---|
| brick-500 on petrol-500 | Equal luminance, vibrates. 2.1 : 1 contrast. |
| sage-300 on cream-300 | 1.6 : 1 contrast. Body-text legibility fails. |
| petrol-500 on charcoal-900 | 1.9 : 1 contrast. Dark-mode reverses hierarchy. |
| Any gradient between brick and sage | Ambiguous yellow-brown midpoint. |

## Print conversion (CMYK / Pantone)

| Token | sRGB hex | Approx CMYK | Pantone (uncoated) |
|---|---|---|---|
| petrol-500 | `#0F4C5C` | C90 M60 Y45 K50 | 5473 U |
| cream-300 | `#F4EBD0` | C3 M6 Y20 K0 | 7499 U |
| brick-500 | `#C03221` | C0 M85 Y90 K15 | 1795 U |
| sage-500 | `#7A9E7E` | C45 M15 Y45 K15 | 5635 U |
| charcoal-800 | `#1F2421` | C30 M0 Y15 K90 | Black 6 U |

Always include a printer-proof step. Verify petrol-cream pairing under D50 lighting — cream can shift yellow under warm office light.

## How to extend

To add a new semantic token (e.g., `bg-banner`, `text-disabled`):

1. Add to [`tokens.css`](./tokens.css) under Semantic section
2. Add to [`tokens.json`](./tokens.json) under `color.semantic.*`
3. Update the contrast matrix in this file if it introduces a new pairing

**Do NOT** add new Core scale colors without a Brand decision in `docs/adr/` approved by the Lead Architect (years 1–5).
