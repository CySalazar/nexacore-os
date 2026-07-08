# NexaCore Improvement Proposals (NCIPs)

This directory holds the **machine-lintable** NexaCore Improvement Proposals: the
normative protocol/architecture specifications that the codebase implements. Each
NCIP is a single file `ncip-<slug>-<NNN>.md` with canonical frontmatter and body
sections, validated by [`scripts/lint-oips.py`](../scripts/lint-oips.py).

Specifications that have not yet been promoted to a lintable NCIP continue to live
as Architecture Decision Records under [`docs/adr/`](../docs/adr/); this registry is
the home for specs whose structure is frozen enough to lint.

## Index

| NCIP | Title | Track | Status |
|------|-------|-------|--------|
| 007  | [NexaCore Helper — System Agentic Layer](ncip-helper-007.md) | Standards Track | Draft |
| 008  | [Display-Server ABI — Compositor Input/Output Channel](ncip-display-abi-008.md) | Standards Track | Review |
| 009  | [Input Stack — Unified Event Bus (PS/2, USB-HID, ACPI)](ncip-input-stack-009.md) | Standards Track | Review |
| 010  | [Accessibility — Tree, Focus, Screen Reader, Contrast, Text Scale](ncip-accessibility-010.md) | Standards Track | Review |
| 011  | [Audio Stack — DE-H2 ABI, Mixer, Device Routing, HDA/virtio-snd Codecs](ncip-audio-011.md) | Standards Track | Review |
| 012  | [Windows Application Path — Wine-in-Container](ncip-wine-container-012.md) | Standards Track | Review |
| 013  | [NCFS On-Disk Format (FS-Wire) — v3 Superblock, Inodes, Extents, Integrity](ncip-fs-wire-013.md) | Standards Track | Review |
| 014  | [Design Language — Tokens for Color, Space, Typography, Motion](ncip-design-language-014.md) | Standards Track | Review |
| 015  | [Configuration Store — Schema, Layered Desired State, Config-as-Code](ncip-config-store-015.md) | Standards Track | Review |

## Conventions

- **Filename:** `ncip-<slug>-<NNN>.md` — kebab-case slug, zero-padded 3-digit number.
- **Frontmatter (required):** `ncip`, `title`, `track`, `status`, `authors`,
  `created`, `license` (`CC0-1.0`).
- **Body sections (in order):** Abstract, Motivation, Specification, Rationale,
  Backwards Compatibility, Test Cases, Reference Implementation, Security
  Considerations, Privacy Considerations, Copyright.
- **Licensing:** NCIP prose is CC0-1.0 by policy; the codebase remains Apache-2.0.

Run the linter from the repository root:

```bash
python3 scripts/lint-oips.py
```
