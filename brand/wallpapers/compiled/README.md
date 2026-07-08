# Compiled wallpaper assets

`.nxwp` is a minimal fixed-size-pixel container for the NexaCore desktop shell's
built-in wallpaper renderer. It stores a single row-major RGB565 framebuffer with
a 10-byte header and no compression, so the on-device decoder (WS7 desktop M2,
Task 2) can `mmap`/read it directly without a PNG/JPEG codec.

| Field    | Offset | Size (bytes) | Value                                    |
|----------|-------:|-------------:|-------------------------------------------|
| magic    | 0      | 4            | `"NXWP"` (`4E 58 57 50`)                   |
| version  | 4      | 1            | `1`                                        |
| format   | 5      | 1            | `1` (RGB565, little-endian)                 |
| width    | 6      | 2            | `u16` LE (pixels)                          |
| height   | 8      | 2            | `u16` LE (pixels)                          |
| payload  | 10     | width*height*2 | row-major pixels, each a little-endian `u16` packed `RRRRRGGGGGGBBBBB` |

`brand/wallpapers/compiled/constellation-1280x800.nxwp` is 2,048,010 bytes
(10-byte header + 1280*800*2 payload bytes): magic/version/format/width/height
header `4E 58 57 50 01 01 00 05 20 03`, followed by the RGB565 framebuffer.

## Regenerating

The asset is generated from `brand/wallpapers/nexacore-agentic-05-local-first-constellation.png`
by `scripts/gen-wallpaper-asset.ps1` (PowerShell 5.1 + .NET System.Drawing, no Rust/toolchain
dependency). The script center-crops the source to the target 16:10 aspect, scales it with
HighQualityBicubic interpolation, composites the mockup's radial petrol glow, and Floyd-Steinberg
dithers the result down to RGB565 before writing the `.nxwp` container. Regenerate with:

```powershell
./scripts/gen-wallpaper-asset.ps1 -Source brand/wallpapers/nexacore-agentic-05-local-first-constellation.png -Width 1280 -Height 800 -Out brand/wallpapers/compiled/constellation-1280x800.nxwp
```

The script prints the output path, byte size, and SHA256 of the generated asset on completion.
