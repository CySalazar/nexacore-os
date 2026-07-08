# NexaCore OS — Typography system

**Direction:** C — Civic Tech / Generational
**Files in this directory:**
- this file — type families, rationale, scale, pairing rules
- [`type-tokens.css`](./type-tokens.css) — production CSS custom properties

## Three families, one purpose each

NexaCore OS uses three type families. Each does one job. Mixing roles is forbidden.

| Family | Role | Why this family |
|---|---|---|
| **Source Serif 4** | Display, long-form prose, document headlines, wordmark | A humanist serif with strong vertical structure and generous x-height. SIL OFL. Works on screen and print across body and display sizes. Resists "tech startup" geometric sans feel. |
| **Inter** | UI, navigation, captions, body where serif is too literary | Neutral humanist sans with strong technical accuracy at small sizes. SIL OFL. De-facto standard for civic and institutional digital products (GOV.UK, Mozilla, Figma). |
| **IBM Plex Mono** | Code, terminal output, technical labels, metadata, status pills | Most legible open-source monospace at small sizes. SIL OFL. Matches engineering rigor without the "hacker terminal" cliché. |

### Why all three are SIL OFL

The codebase is Apache-2.0; the protocol specs are CC0. Bundling a proprietary font would create a single non-open dependency in the brand layer that contradicts the project's posture. SIL Open Font License permits redistribution, embedding, modification, forks. Forks of NexaCore OS can ship the same fonts without per-seat licensing.

## Font files & licensing

| Family | Source | License |
|---|---|---|
| Source Serif 4 | https://github.com/adobe-fonts/source-serif | SIL OFL 1.1 |
| Inter | https://github.com/rsms/inter | SIL OFL 1.1 |
| IBM Plex Mono | https://github.com/IBM/plex | SIL OFL 1.1 |

For local hosting, drop WOFF2 files into `brand/typography/fonts/` and reference via `@font-face` in [`type-tokens.css`](./type-tokens.css).

## Type scale

Modular scale **1.250 (major third)**.

| Token | Value | Use |
|---|---|---|
| `--nexacore-text-xs`    | 12 px / 0.75 rem  | Captions, metadata, footnotes, status pills |
| `--nexacore-text-sm`    | 14 px / 0.875 rem | UI default, table cells, secondary text |
| `--nexacore-text-base`  | 16 px / 1 rem     | Body text default |
| `--nexacore-text-lg`    | 20 px / 1.25 rem  | Lede paragraph, callout |
| `--nexacore-text-xl`    | 25 px / 1.563 rem | Section headings (h3) |
| `--nexacore-text-2xl`   | 31 px / 1.953 rem | Page sub-headings (h2) |
| `--nexacore-text-3xl`   | 39 px / 2.441 rem | Page headings (h1) |
| `--nexacore-text-4xl`   | 49 px / 3.052 rem | Hero headings |
| `--nexacore-text-5xl`   | 61 px / 3.815 rem | Splash hero (rare) |

### Line-height rules

| Use | Line-height |
|---|---|
| Body text (text-base, text-sm) | 1.55 |
| UI text in interface chrome | 1.4 |
| Display (text-2xl and up) | 1.15 |
| Code blocks (Plex Mono) | 1.6 |

### Letter-spacing rules

| Context | Tracking |
|---|---|
| Body (Source Serif, Inter) | 0 — never adjust |
| All-caps UI labels (text-xs) | `+0.06em` |
| All-caps section labels (text-sm) | `+0.08em` |
| Display headings (text-3xl and up) | `-0.01em` to `-0.015em` |
| Wordmark | `-0.015em` (fixed) |

## Pairing rules

1. **Serif sets the voice, sans carries the work.** Source Serif 4 for things the reader pauses on. Inter for things the reader scans.
2. **Mono carries only technical content.** Never for body prose.
3. **One face per role per page.** No switching between Source Serif 4 and Inter for body.
4. **Weight pairing.** When serif and sans appear together, serif uses 700, sans uses 500.
5. **Italics in serif only.** Source Serif 4 italics carry emphasis; Inter italics are second-rate; Plex Mono italics for code-comment emphasis only.

## Owned typographic patterns

### Status pill
```html
<span class="nexacore-status nexacore-status--active">Active</span>
```
Plex Mono 400, text-xs, letter-spacing 0.08em, all-caps, 3px/8px padding, 2px border-radius.

### Document footer fingerprint
```
brand/STRATEGY.md · v0.1 · 2026-05-13
```
Plex Mono text-xs, letter-spacing 0.06em, charcoal-300.

### Pull quote
Source Serif 4 italic 600, text-2xl, color text-accent, max-width 38em, left rule 3px solid border-accent.

## Anti-patterns

- ❌ Pairing Source Serif 4 with **another** serif (Lora, Merriweather, Playfair).
- ❌ Replacing Inter with a **geometric** sans (Poppins, DM Sans, Manrope).
- ❌ Setting body in Plex Mono "because it looks technical". Mono on body harms reading speed.
- ❌ Using `font-weight: 900` anywhere.
- ❌ Underlined non-link text.
- ❌ Drop caps.
- ❌ Smart quotes inverted.
- ❌ Ligatures off.

## Accessibility commitments

- Minimum body text: 16 px. Smaller body text is forbidden.
- Minimum touch target: 44×44 px (WCAG 2.5.5 AAA).
- Body line length: 45–75 characters per line. Constrain to `max-width: 65ch`.
- Reading order in markup must match visual order.
- All-caps text must NOT exceed text-sm. All-caps body is a brand error.
