# NexaCore OS / NexaCore Foundation — Operational templates

**Direction:** C — Civic Tech / Generational
**Authoritative brand strategy:** [`../STRATEGY.md`](../STRATEGY.md)

This directory contains ready-to-use templates that consume the brand visual system. Each template can be customized for project-specific content but **must not** alter the brand tokens (logos, palette, typography) directly. If a template needs a token that does not exist, add the token to the appropriate brand directory first.

## Files in this directory

| Template | Use | Notes |
|---|---|---|
| [`README-header.md`](./README-header.md) | Repository README header (top-of-file block with logo, tagline, badges) | Drop in at top of any NexaCore OS repository or fork. Replace `{{...}}` placeholders. |
| [`slide-deck-starter.html`](./slide-deck-starter.html) | Single-file presentation deck — opens in any browser | Keyboard navigation (arrows / F for fullscreen). Print to PDF for export. 5 starter slides: title, section divider, content, pull-quote, closing. |
| [`social-card-1200x630.svg`](./social-card-1200x630.svg) | Open Graph / Twitter / LinkedIn / Mastodon / Bluesky share image | Edit the `.headline-line` text elements to customize. Export to PNG at 1200×630 (or 2400×1260 retina). |
| [`github-social-1280x640.svg`](./github-social-1280x640.svg) | GitHub repository social preview (Settings → Options → Social preview) | Export PNG 1280×640. |
| [`ncip-cover.md`](./oip-cover.md) | Cover/header block for new NexaCore Improvement Proposals and ADRs | Copy the YAML frontmatter + introduction structure. Required sections enforced by `ncips/ncip-process-001.md` §3. |
| [`email-signature.html`](./email-signature.html) | HTML email signature for Gmail / Outlook / Apple Mail | Renders a table with inline SVG mark + contact block. |
| [`email-signature.txt`](./email-signature.txt) | Plain-text companion to the HTML signature | Use for `mutt`, mailing-list replies, PGP-signed plain text. |

## How a template consumes the brand

Every template in this directory follows the same consumption pattern:

1. **Visual assets** are referenced by relative path (`../logos/nexacore-os-primary.svg`, `../icons/icons.svg#nexacore-mesh`). Templates do not duplicate the SVG source — they link to it. This guarantees one place to update if the mark changes.
2. **Colors** are embedded as hex literals taken from [`../colors/tokens.css`](../colors/tokens.css). In CSS contexts the `--nexacore-*` custom properties are preferred; in SVG and email-HTML contexts where custom properties are unreliable, hex values are inlined with a comment naming the token (e.g., `fill="#0F4C5C" /* --nexacore-petrol-500 */`).
3. **Typography** uses the family stacks declared in [`../typography/type-tokens.css`](../typography/type-tokens.css), with explicit fallbacks for environments where the fonts are not available (slide decks rendered offline, email clients).
4. **Iconography** is referenced from [`../icons/icons.svg`](../icons/icons.svg) via fragment id (`<use href="icons.svg#nexacore-mesh">`).

## Format conversion

Most templates need to be rendered to PNG/PDF for distribution. Conversion commands:

```bash
# SVG → PNG (rsvg-convert from librsvg)
rsvg-convert -w 1200 social-card-1200x630.svg -o social-card@1200.png
rsvg-convert -w 2400 social-card-1200x630.svg -o social-card@2400-retina.png
rsvg-convert -w 1280 github-social-1280x640.svg -o github-social.png

# SVG → PDF (inkscape, with embedded fonts)
inkscape social-card-1200x630.svg --export-type=pdf --export-filename=social-card.pdf --export-text-to-path

# HTML slide deck → PDF (via Chrome headless)
chromium --headless --disable-gpu --no-margins \
         --print-to-pdf=deck.pdf \
         --virtual-time-budget=10000 \
         file://$(pwd)/slide-deck-starter.html
```

A helper script will land in `brand/scripts/` in a future revision to automate bulk export.

## Adding a new template

If you find yourself recreating a layout for a third time, it should become a template. Process:

1. Add the source file (`.html`, `.svg`, `.md`) to this directory.
2. Document its use case and customization points in the table above.
3. Verify it consumes the brand correctly (no hardcoded colors outside the token list, no off-system fonts, no logo redraw).
4. Verify accessibility:
   - Contrast minimums per [`../colors/palette.md`](../colors/palette.md)
   - Body text ≥ 16 px
   - Alt text or aria-label on every meaningful image
5. Open a Draft PR. Brand-template changes follow the same review path as code changes.

## Anti-patterns

- ❌ Duplicating SVG source into a template. Always reference by relative path.
- ❌ Hardcoding a color not in the token list. If you need it, add it to the tokens first.
- ❌ Substituting Inter with Helvetica / Arial because "it loads faster". The fallback stack already handles that.
- ❌ Adding tracking / analytics scripts to a brand template. Templates are static-by-default.
- ❌ Templates that reference an external CDN for assets at runtime. Templates are self-contained or reference local files only.
