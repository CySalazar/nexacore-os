---
ncip: 11
title: NexaCore* Flagship Apps Program — NexaCoreCode as Phase-1 Reference Editor
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-12
updated: 2026-05-12
requires:
  - NCIP-Process-001
  - NCIP-Container-006
  - NCIP-Pkg-008
  - NCIP-Market-010
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

# NCIP-Flagship-011 — NexaCore* Flagship Apps Program, NexaCoreCode v1

## Abstract

This NCIP commits Stichting NexaCore to a **flagship-app program** that
develops and maintains a set of **Stichting-Curated** reference
applications. These apps:

- Use the `NexaCore{Function}` naming convention (e.g., `NexaCoreCode`,
  `NexaCoreMail`, `NexaCoreNotes`).
- Are **Stichting-Curated** tier in `nexacore-market` (per NCIP-Market-010).
- Serve as exemplars of capability-minimality + reproducible build +
  Apache-2.0 + no-telemetry.
- Are Apache-2.0 source open, with `nexacore-market` distribution.

The first flagship is **`NexaCoreCode`**, a VSCode-experience editor with
Rust + Python pre-configured and OpenVSX extension marketplace integration.
Phased delivery:

- **Phase 1** (immediate, v1.x): Codium inside an NexaCoreContainer (Electron
  in container), shipped as `NexaCoreCode`. Working version available within
  weeks of NexaCoreContainer GA.
- **Phase 2** (v1.x+, target year 4): Tauri-based native port of Codium
  UI to eliminate Electron overhead. Effort: 9-12 engineer-months.

## Motivation

A new OS without flagship apps cannot demonstrate "this is what good
software looks like on this platform". Apple has iWork; GNOME has Files
+ Maps + Photos; macOS has Calculator + Notes + Photos. NexaCore needs an
equivalent set to:

1. **Demonstrate the platform** — capability-minimality, reproducible
   builds, Apache-2.0 alignment in practice.
2. **Onboard developers** with a familiar code editor (VSCode UX is
   the dominant developer mental model in 2026).
3. **Provide reference Stichting-Curated** entries in `nexacore-market`
   so other developers see what Gold-tier looks like.

VSCode itself is owned by Microsoft and includes proprietary telemetry.
**Codium** (`codium.io`) is the community-maintained, telemetry-free,
open-source rebrand of VSCode; it uses the **OpenVSX registry** (Eclipse
Foundation operated) as its extension marketplace, rather than the
Microsoft Marketplace.

## Specification

### 1. Naming convention

Stichting-Curated apps use the prefix **`NexaCore`** followed by a function
name in CamelCase. Examples (planned):

| Name | Function | Phase target |
|---|---|---|
| **NexaCoreCode** | Code editor with Rust + Python + extension support | **Phase 1 immediate / Phase 2 native** |
| **NexaCoreShell** | Already pre-scaffolded in `crates/nexacore-shell` | Phase 6 |
| **NexaCoreMail** | Email + PGP + privacy-first | Phase 7+ |
| **NexaCoreNotes** | Markdown notes + sync | Phase 7+ |
| **NexaCoreDocs** | Document viewer/editor | Phase 7+ |
| **NexaCorePhotos** | Photo viewer + minimal edit | Phase 8+ |
| **NexaCoreCalendar** + **NexaCoreContacts** | PIM suite | Phase 8+ |

The `NexaCore` prefix is **reserved** for Stichting-Curated apps; community
apps may not use it. This is enforced at `nexacore-market` submission.

### 2. Curation criteria for any NexaCore* app

To qualify for the NexaCore* prefix and Stichting-Curated status, an app
must satisfy:

1. **License**: Apache-2.0 or compatible OSS (no permissive escape).
2. **Capability-minimality**: declared capability set is the
   minimum required, reviewed by the Foundation and demonstrated by
   reproducible build + binary analysis.
3. **Reproducible build**: bit-identical artifact from source on two
   independent machines.
4. **No telemetry**: zero network egress not strictly required for app
   function; any optional egress is explicitly opt-in.
5. **Stichting maintenance**: a Foundation-paid maintainer (or
   sponsored volunteer with maintenance SLA).
6. **Annual security review**: rotating across the flagship set;
   external audit at least every 24 months.
7. **OpenVSX-compatible extension system** (where applicable): extensions
   declare capabilities, NexaCore helper presents them at install.

### 3. NexaCoreCode v1 — phased delivery

#### 3.1. Phase 1 — Codium in NexaCoreContainer (v1.x immediate)

The fastest path to a working NexaCoreCode:

- Take upstream Codium (Electron + TypeScript).
- Package as an NexaCoreContainer (Linux guest with `nexacore/linux-codium:N-stable`
  image).
- Pre-install Rust extensions (rust-analyzer LSP), Python (pyright LSP),
  TypeScript, Markdown.
- Pre-configure to use **OpenVSX** as the extension marketplace.
- Distribute via `nexacore-market` Stichting-Curated tier.

User experience: launch NexaCoreCode → opens a fully featured VSCode-experience
editor; install extensions from OpenVSX; develop Rust/Python/TS code that
runs in NexaCoreContainers or as `nexacore-forge` artifacts.

Engineering effort: **2-3 engineer-months** (mostly packaging + integration
testing). Available within weeks of NexaCoreContainer GA (Phase 5).

Trade-off: ~300MB binary (Electron is heavy); ~5s cold start.

#### 3.2. Phase 2 — Native Tauri port (v1.x+ target year 4)

Once NexaCoreContainer Phase-1 is stable and NexaCoreForge can compile non-trivial
binaries, a Tauri-based native port becomes feasible:

- **Tauri 2.x** as the application shell (Rust core + WebView UI).
- **Codium UI ported** from Electron to Tauri (the VSCode UI itself is
  TypeScript/CSS/HTML and largely Tauri-compatible after porting node-
  APIs).
- **Result**: ~50MB binary, sub-second cold start, native NexaCore capability
  binding throughout.

Engineering effort: **9-12 engineer-months** for a feature-parity port.
Significant: the VSCode core has many Node.js-API dependencies that need
Tauri equivalents. A subset of extensions that rely heavily on `nodeIntegration`
may not survive the port; those continue to work in the Phase-1 container path.

Both versions coexist: Phase-1 container for max compatibility, Phase-2 native
for performance.

### 4. Extension marketplace — OpenVSX

NexaCoreCode uses **OpenVSX registry** (Eclipse Foundation, `open-vsx.org`)
for extensions. Rationale:

- License-clean: OpenVSX extensions are licensed for redistribution; the
  Microsoft Marketplace terms-of-service do not permit non-VSCode-product
  consumption.
- Community-governed: aligned with NexaCore's open-mission values.
- Coverage: OpenVSX has ~80% of the Microsoft Marketplace extensions
  most commonly used by developers (LSPs, themes, snippets).

Extensions are subject to **the same `nexacore-market` Bronze/Silver/Gold tier
flow** as native packages, with one exception: OpenVSX-sourced extensions
inherit OpenVSX's signing and are admitted automatically as Bronze tier.
Promotion to Silver+ requires the same Stichting verification as native
apps.

### 5. Default pre-configuration

| Component | Status |
|---|---|
| rust-analyzer LSP | Default-on |
| pyright LSP | Default-on |
| TypeScript (tsserver) | Default-on (needed for NexaCore scripting) |
| Markdown preview | Default-on |
| Tree-sitter highlighting | Default-on |
| `nexacore-forge` integration ("generate snippet from intent") | Default-on (privacy-budget gated) |
| `nexacore-market` extension installer (with capability prompt) | Default-on |
| OpenVSX as the extension registry | Default-on |

### 6. Reference implementation

NexaCoreCode lives in a **separate repo** outside the main NexaCore OS workspace:

```
nexacore-code/
├── README.md
├── LICENSE  (Apache-2.0)
├── packaging/
│   └── nexacore-container/
│       └── linux-codium/    # Phase 1 container image build
└── native/   # Phase 2 Tauri port (initially empty)
```

Reasons for separate repo:

- Different release cadence (apps version independently from the OS).
- Independent CI / test infrastructure.
- Independent contributor pool.

The repo is created at the start of Phase 5 implementation work and
imported into `nexacore-market` Stichting-Curated tier at v1.0 release.

## Rationale

### Why phased Codium-in-container then Tauri port?

The Phase 1 container delivers a working, recognisable editor within
weeks. Users get value immediately. Phase 2 is a quality / performance
upgrade that's worth the wait but doesn't block adoption.

### Why Codium and not Zed?

The founder explicitly chose Codium (VSCode UX 1:1) to leverage the
massive existing VSCode developer mind-share and extension ecosystem.
Zed (the alternative considered) would have meant a different UX and
fewer extensions. The trade-off accepts the larger Electron footprint
for the dominant developer UX.

### Why a separate repo for NexaCoreCode?

NexaCoreCode is a downstream consumer of NexaCore; conflating it with the OS
workspace would couple their release cycles. Keeping it separate
respects the layering: OS first, apps on top.

### Why the `NexaCore` prefix only for Stichting-Curated?

To make the badge meaningful. If anyone could ship "NexaCoreCalculator", the
prefix loses its trust signal. Enforcement at marketplace submission
keeps the namespace clean.

## Backwards Compatibility

Not applicable.

## Test Cases

1. **NexaCoreCode launch (Phase 1)**: `nexacore-pkg install nexacore-code`,
   launch, opens a VSCode-experience UI within 5s.
2. **OpenVSX extension install**: install `rust-analyzer` from
   OpenVSX through the NexaCoreCode UI; capability prompt shown via
   `nexacore-helper`; install succeeds.
3. **No-telemetry verification**: tcpdump during 5-minute idle
   NexaCoreCode session shows zero unexpected network egress.
4. **Reproducible build**: `nexacore-code` package built on two
   independent machines yields bit-identical hash.
5. **Capability-minimality**: NexaCoreCode declares `fs:read:cwd`,
   `fs:write:cwd`, `net:outbound:openvsx.org:443`; binary analysis
   confirms no additional egress.

## Reference Implementation

To land before activation:
- Separate repo `nexacore-code/` initialized.
- Phase-1 Codium container image (`nexacore/linux-codium`) published to
  `nexacore-market`.
- OpenVSX integration validated.
- Phase-2 Tauri port spec'd in a follow-up NCIP.

## Security Considerations

- **Codium upstream supply chain**: we depend on Codium upstream
  honesty + Microsoft's VSCode source. Mitigation: reproducible build
  from a pinned Codium source tag, Foundation re-builds independently.
- **Extension marketplace risk**: malicious OpenVSX extensions could
  exfiltrate code. Mitigation: capability-bound extension model;
  `nexacore-helper` shows extension capability set at install; Bronze tier
  default for fresh OpenVSX extensions until Silver promotion.
- **Electron CVE surface (Phase 1)**: Electron has a non-trivial CVE
  history. Mitigation: pin Codium to latest LTS Electron with
  Foundation-owned patching; container isolation makes most Electron
  CVEs irrelevant to host.

## Privacy Considerations

- NexaCoreCode default settings: no telemetry, no auto-update via internet
  (only via `nexacore-pkg upgrade`), no usage analytics. All can be
  re-enabled per-feature if the user opts in.
- Extensions inherit capability scoping; an extension cannot exceed
  the NexaCoreCode container's declared capability set.

## Future Work

- **NCIP-Flagship-NexaCoreCode-Tauri-XXX** (year 4): formal spec of the
  Tauri-port; activates Phase 2.
- **NCIP-Flagship-NexaCoreMail-XXX** (Phase 7+): first PIM-class flagship.
- **NCIP-Flagship-NexaCoreDocs-XXX** (Phase 7+): document editor (potentially
  forking LibreOffice or building from scratch on Tauri).

## Copyright

CC0 1.0 Universal.
