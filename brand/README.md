# NexaCore — Brand pack

**Version:** v0.1
**Direction:** C — Civic Tech / Generational
**Last updated:** 2026-05-13
**Owner:** Lead Architect (cySalazar) for years 1–5. After 2031-05-09, NexaCore Foundation Director.

> Single source of truth for the visual and verbal identity of **NexaCore OS** (the product) and **NexaCore Foundation** (the international brand of **Stichting NexaCore**, Amsterdam — its Dutch legal entity). The brand book PDF below is the consolidated, distribution-ready artifact; the rest of this directory is the source.

## What's in this directory

| Path | What it is |
|---|---|
| [`STRATEGY.md`](./STRATEGY.md) | The authoritative brand strategy — naming, positioning, voice, lexicon, application guidance, boilerplate |
| [`brand-book.html`](./brand-book.html) | The 22-page brand book as print-ready HTML (open in browser, print to PDF) |
| [`NexaCore-Brand-Book-v0.1.pdf`](./NexaCore-Brand-Book-v0.1.pdf) | Same brand book, pre-rendered to PDF (the distribution-ready artifact) |
| [`logos/`](./logos/) | All logo variants (primary, stacked, monogram, mono dark/light, NexaCore Foundation lockups, construction grid) — see [`logos/README.md`](./logos/README.md) |
| [`colors/`](./colors/) | Color tokens as CSS, JSON, and human-readable palette doc with WCAG contrast matrix |
| [`typography/`](./typography/) | Type-token CSS + the typography specification (families, scale, line-heights, pairing rules) |
| [`icons/`](./icons/) | SVG sprite (16 symbols indexing core NexaCore concepts) |
| [`templates/`](./templates/) | Ready-to-use templates: README header, slide deck, social card, GitHub social preview, NCIP cover, email signature |
| *(mood-boards)* | The 3 visual directions explored before locking Direction C are archived out-of-repo; can be regenerated for design review |

## How to consume

**If you need the brand to drop in:** open [`NexaCore-Brand-Book-v0.1.pdf`](./NexaCore-Brand-Book-v0.1.pdf). Skim it once. The 22 pages cover everything you need.

**If you are writing copy or building something:**
- Voice, lexicon, tagline, payoff → [`STRATEGY.md`](./STRATEGY.md) §5, §6, §8
- Logo or wordmark → [`logos/`](./logos/) (primary lockup is `nexacore-os-primary.svg`)
- Color → [`colors/tokens.css`](./colors/tokens.css) (use Semantic tokens, never Core scale directly)
- Type → [`typography/type-tokens.css`](./typography/type-tokens.css)
- Icon → `<use href="icons/icons.svg#nexacore-mesh">` (the federated-mesh icon)
- A template (README header, slide, OG card, etc.) → [`templates/`](./templates/)

**If you are extending the brand:** see the "How to extend" section in each subdirectory's README.

## Distribution

The brand pack ships **with** the NexaCore OS repository — it is part of the project, not external. This guarantees:

- Source-control history for every brand decision (signed commits).
- Forks of NexaCore OS automatically receive a permission-compatible brand kit (SIL OFL fonts, CC0 protocol specs, Apache-2.0 code, fair-use trademark policy per `docs/legal/bylaws-draft.md` Article 10.3).
- No external CDN or external license is required to use the brand at the legitimacy level it was designed for.

## Regenerating the PDF

```bash
# requires weasyprint (pip install weasyprint)
cd brand
weasyprint brand-book.html NexaCore-Brand-Book-v0.1.pdf
```

Or print to PDF from any Chromium-based browser at A4 portrait, no margins.

## Open work

- Press kit (`press-kit/`) — bios, boilerplate, 2–3 standard quotes for journalists. Phase 4 deliverable, not yet shipped.
- Dutch-language style guide (`STRATEGY-NL.md`) — produced once the notarial deed is filed with the Kamer van Koophandel.
- PNG exports of logos and templates at standard sizes (Phase 4 deliverable).
- WOFF2 font files in `typography/fonts/` for fully local-hosted typography (SIL OFL — download from the upstream repositories listed in `typography/typography.md`).

## Contact

`brand@nexacoreos.com`.

---

*Brand pack v0.1 · NexaCore Foundation · Stichting NexaCore · Amsterdam · 2026-05-13*
