# NexaCore OS — bundled brand fonts

TrueType (`glyf`-flavored, sfnt) builds of the three brand type families, for
embedding in the OS text engine (`nexacore-display::font` / `raster`). All three
are **SIL Open Font License 1.1** — redistribution, embedding, and forks are
permitted; the accompanying `OFL-*.txt` files carry each family's license and
Reserved Font Name.

TrueType (not the upstream OTF/CFF) builds are used because the OS font
rasterizer parses `glyf` outlines, not PostScript/CFF.

| Family | Role (HIG §3) | Files | Source | License |
|---|---|---|---|---|
| **Inter** | UI, navigation, captions | `Inter-Regular.ttf` (400), `Inter-Medium.ttf` (500), `Inter-SemiBold.ttf` (600) | [rsms/inter](https://github.com/rsms/inter) v4.1 `extras/ttf/` | [OFL-Inter.txt](./OFL-Inter.txt) |
| **IBM Plex Mono** | Code, terminal, metadata, status pills | `IBMPlexMono-Regular.ttf` (400), `IBMPlexMono-Medium.ttf` (500) | [IBM/plex](https://github.com/IBM/plex) `plex-mono/fonts/complete/ttf/` | [OFL-IBMPlex.txt](./OFL-IBMPlex.txt) |
| **Source Serif 4** | Display, headings, long-form, wordmark | `SourceSerif4-Regular.ttf` (400), `SourceSerif4-Bold.ttf` (700), `SourceSerif4-It.ttf` (italic) | [adobe-fonts/source-serif](https://github.com/adobe-fonts/source-serif) `release/TTF/` | [OFL-SourceSerif4.txt](./OFL-SourceSerif4.txt) |

Weight selection follows the HIG pairing rules (`brand/typography/typography.md`):
serif at 700 / sans at 500 when paired; Plex Mono 400 for terminal and status
pills; italics in Source Serif only.

## Engine compatibility note

The `nexacore-display::font` parser supports `glyf` **simple and composite/
compound** glyphs (composite assembly added in WS7-19.3) plus `cmap` format 4,
so accented Latin renders in full. These byte payloads are embedded by the
`nexacore-fonts` crate; `crates/nexacore-display/tests/brand_fonts.rs` validates the
whole pipeline (parse → cmap → outline → AA raster) on these exact files,
including accented glyphs (é/à/ñ/ü) across all three families.

Still out of scope: CFF/`OTTO` (PostScript) outlines — which is why the
TrueType (`glyf`) builds are used rather than the upstream OTF.
