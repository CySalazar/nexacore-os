# NexaCore OS — Logo asset index

**Direction:** C — Civic Tech / Generational
**Authoritative brand strategy:** [`../STRATEGY.md`](../STRATEGY.md)
**Mark semantics:** the central red dot is the **Mission Anchor** (irrevocable, per `docs/legal/bylaws-draft.md` Article 3). The six petrol nodes around it represent **federated attested peers** — the mesh as collective compute. The dimming envelope ring signals **inclusion** without coercion.

## Files in this directory

| File | Use | Min size | Notes |
|---|---|---|---|
| [`nexacore-os-primary.svg`](./nexacore-os-primary.svg) | Default lockup for documents, web, slides | 120 px / 30 mm | First choice unless you have a reason to pick another |
| [`nexacore-os-stacked.svg`](./nexacore-os-stacked.svg) | Square/vertical contexts (avatars, narrow columns) | 80 px / 20 mm | Use when horizontal lockup is constrained |
| [`nexacore-os-monogram.svg`](./nexacore-os-monogram.svg) | Favicon, app icon, social avatar, inline glyph | 16 px / 5 mm | Below 16 px use single-color version |
| [`nexacore-os-mono-dark.svg`](./nexacore-os-mono-dark.svg) | Single-ink on light background, embossing, stamping | 120 px / 30 mm | Charcoal `#1F2421` only |
| [`nexacore-os-mono-light.svg`](./nexacore-os-mono-light.svg) | On petrol/charcoal/black backgrounds, dark-mode UI | 120 px / 30 mm | Cream `#F4EBD0` only |
| [`nexacore-foundation-primary.svg`](./nexacore-foundation-primary.svg) | NexaCore Foundation publishing identity | 140 px | Same mark as NexaCore OS — the sibling family signal |
| [`nexacore-foundation-lockup-full.svg`](./nexacore-foundation-lockup-full.svg) | Contracts, statutory docs, annual report cover | 180 px | Adds `Stichting NexaCore · Amsterdam · The Netherlands` |
| [`nexacore-os-construction.svg`](./nexacore-os-construction.svg) | Reference / brand book only — DO NOT use in production | — | Construction geometry, clear-space envelope, mark semantics |

## Clear-space rule

For every lockup, leave a minimum of **1× mark-height** of empty space on all four sides. No other graphic element, type, or image may enter that envelope.

## What you may NEVER do

1. **Recolor** the mark outside the approved palette. The full-color, two monochrome, and single-ink states are the four sanctioned color states.
2. **Add effects**: no drop shadow, glow, bevel, gradient, animation in the static identity.
3. **Change proportions**: the ring radius, node sizes, and core size are fixed (see `nexacore-os-construction.svg`).
4. **Flip, rotate, or invert** the mark. One node always at 12 o'clock.
5. **Redraw** with different node counts. Six nodes only.
6. **Typeset `NexaCore OS`** in a different font/weight. Source Serif 4 700 is the only sanctioned wordmark face.
7. **Crop the wordmark** out of a primary or stacked lockup. Use the monogram if it cannot fit.

## Format conversion

```bash
rsvg-convert -w 1200 nexacore-os-primary.svg -o nexacore-os-primary@1200.png
rsvg-convert -w 256  nexacore-os-monogram.svg -o nexacore-os-monogram@256.png
inkscape nexacore-os-primary.svg --export-type=pdf --export-filename=nexacore-os-primary.pdf
```

## Font dependency

The SVGs declare `Source Serif 4` and `Inter` as preferred families with system-serif/sans fallbacks. For print-grade reproduction, outline the text first: `inkscape --export-text-to-path`. Fonts are SIL OFL (see [`../typography/typography.md`](../typography/typography.md)).
