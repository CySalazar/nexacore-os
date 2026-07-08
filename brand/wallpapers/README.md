# NexaCore OS — "Agentic OS" wallpapers

Ten desktop wallpapers on the **Agentic Operating System** theme, generated
procedurally on the NexaCore brand palette (petrol / cream / sage / charcoal,
with **brick** used only as the single "Mission Anchor" focal element per the
[single-red rule](../colors/palette.md)).

- **Resolution:** 2560×1440 (QHD) — exceeds the 1080p minimum; scales cleanly to 1920×1080.
- **Composition:** dark charcoal canvas, off-center focal points, generous negative
  space around the center so desktop icons stay legible.
- **Format:** 16:9, PNG, full-bleed (no letterboxing).

| # | File | Motif |
|---|------|-------|
| 01 | `nexacore-agentic-01-agent-mesh.png` | Peer mesh of agents; one brick anchor node with attestation pulse rings |
| 02 | `nexacore-agentic-02-orchestration-dag.png` | Multi-stage orchestration graph, active edges highlighted in sage |
| 03 | `nexacore-agentic-03-moe-router.png` | Mixture-of-Experts router: token stream → gate → top-k expert clusters |
| 04 | `nexacore-agentic-04-attestation-rings.png` | TEE root-of-trust: concentric measured-boot rings + capability-token hexes |
| 05 | `nexacore-agentic-05-local-first-constellation.png` | Local-first device constellation under an aurora band, private boundary hull |
| 06 | `nexacore-agentic-06-agent-flow-field.png` | Flow field of autonomous agents moving with coherent intent toward an attractor |
| 07 | `nexacore-agentic-07-agentic-loop.png` | The agent loop — perceive → plan → **act** → observe (act = brick anchor) |
| 08 | `nexacore-agentic-08-token-rivers.png` | Token/data streams converging into a single decision node |
| 09 | `nexacore-agentic-09-isometric-agent-grid.png` | Isometric grid of agent cells lighting up; one active brick cell |
| 10 | `nexacore-agentic-10-minimal-hero.png` | Minimal hero: `NEXACORE · AGENTIC OPERATING SYSTEM` wordmark + orbiting agents |

## Regenerating / editing

`_generator.html` is the single self-contained source. Each wallpaper is a scene
function selected by `?w=N` (N = 1..10); `?seed=<int>` varies the random layout.
Rendered headless with the bundled Chromium:

```bash
CH=/opt/pw-browsers/chromium-1194/chrome-linux/chrome   # or any Chromium
# window height 1527 makes the CSS viewport exactly 1440 in this headless build;
# the screenshot is then cropped to the top 2560×1440.
"$CH" --headless=new --hide-scrollbars --force-device-scale-factor=1 \
      --window-size=2560,1527 --screenshot=out.png \
      "file://$PWD/_generator.html?w=6"
```

Palette and the single-red rule are defined in [`../colors/palette.md`](../colors/palette.md)
and [`../colors/tokens.css`](../colors/tokens.css).
