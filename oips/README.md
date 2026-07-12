# NexaCore Improvement Proposals (NCIPs)

> **Status:** Bootstrap (interim editor: founder; second editor seat vacant until Phase 1 hire — see `NCIP-Process-001` §6).
> **Process spec:** [`ncip-process-001.md`](./oip-process-001.md) (Active, ratified by BDFL fiat under Bootstrap clause; first formal vote deferred to the first non-Meta NCIP).
> **Template:** [`ncip-template.md`](./oip-template.md) — copy this as `ncip-<slug>-<NNN>.md` for new proposals.

> **Registry layout — why there are two directories.** "NCIP" (NexaCore Improvement Proposal) is
> the name of the process. The `oip-` filename prefix and the `oips/` path are a **historical
> artifact** from when the process was briefly called "OIP"; they are kept to preserve link and
> signed-commit stability. Proposals live in two directories, split by *structural maturity*, not
> by kind:
> - **[`oips/`](.)** — this directory: the **process spec** ([`oip-process-001.md`](./oip-process-001.md)),
>   governance and narrative proposals, and the **canonical registry index** (below) of every NCIP.
> - **[`ncips/`](../ncips/)** — the **machine-lintable** normative specs, added once an NCIP's
>   structure is frozen enough to validate in CI.
>
> They are **one process**. Always cross-reference an NCIP by its integer number (e.g. `NCIP-013`),
> never by filename or directory.

---

## What is an NCIP?

An **NexaCore Improvement Proposal (NCIP)** is the canonical, archived design document for any change
to NexaCore OS that is non-trivial — protocol changes, governance changes, breaking API changes,
new TEE backends, new cryptographic primitives, etc. The NCIP process is NexaCore OS's **Layer 2**
governance mechanism (community-federated specification), as defined in
[`docs/05-governance.md`](../docs/05-governance.md).

NCIPs are modeled after Bitcoin BIPs, Ethereum EIPs, Python PEPs, and IETF RFCs, with adaptations
specific to NexaCore OS (TEE-attested anti-Sybil voting, BDFL veto sunset, cryptographic activation
thresholds).

---

## When you must file an NCIP

Per `CONTRIBUTING.md` §9 and `NCIP-Process-001` §3 (*Trigger Conditions*):

- Any **protocol-level** change (wire format, cipher suite, capability format, mesh handshake).
- Any **breaking API change** in a public crate.
- Any **governance change** (process, voting, BDFL, editor body, Stichting bylaws aspects
  delegated to NCIPs).
- Any **new TEE backend** addition (because it expands the trust base).
- Any **new cryptographic primitive** in `nexacore-crypto` not on the v0.1 RFC list.

When in doubt, file a **draft NCIP** and let the editors classify it. Filing has zero cost; not
filing and discovering the change should have been an NCIP costs a forced revert.

---

## When you do **not** need an NCIP

- Bug fixes that preserve external behavior.
- Documentation typos / clarifications.
- Internal refactoring with no public-API surface change.
- Test additions.
- CI tweaks that do not change merge requirements.

These go through ordinary PR flow described in `CONTRIBUTING.md`.

---

## Numbering

Authoritative spec: `NCIP-Process-001` §8 (Numbering). Quick reference:

| Aspect | Convention |
|---|---|
| **Filename** | `ncip-<slug>-<NNN>.md` — kebab-case slug, 3-digit zero-padded number |
| **Number `NNN`** | **Globally unique and monotonically increasing** across the entire registry (not per-track). Authors pick the next free integer at filing; editors reconcile placeholder collisions at the `Draft → Review` transition (§8.3) |
| **Slug** | 1–3 kebab-case **category hint** (e.g. `process`, `bounty`, `kernel`, `serde`). **NOT a secondary identifier** — cross-references MUST use the integer (§8.1, §8.2) |
| **Reserved** | `0000` is reserved for the template (`ncip-0000-template.md`) |

Examples:
- `ncip-process-001.md` — NCIP #1, slug `process` (this registry's first proposal).
- `ncip-bounty-002.md` — NCIP #2, slug `bounty` (Process-track bug-bounty program).
- `ncip-container-006.md` — NCIP #6, slug `container` (NexaCoreContainer micro-VM engine).
- `ncip-helper-007.md` — NCIP #7, slug `helper` (`nexacore-helper` daemon: autonomy levels + Impact Dashboard).
- `ncip-snark-stark-NNN.md` — NCIP #*NNN* (TBD), slug `snark-stark` (hypothetical future, see the backlog P3.3 — number will be allocated at filing).

> **Compatibility note:** older the backlog entries reference identifiers like `NCIP-Voting-002`,
> `NCIP-Bounty-001`, `NCIP-Crypto-002`. These are **placeholder names** from a pre-NCIP-Process-001
> period; the actual numbers will be assigned globally when each NCIP is filed, and the placeholders
> in the backlog will be reconciled at that time.

---

## Lifecycle

States, in order, with allowed transitions:

```
                    ┌──────────────────► Withdrawn (author abandons)
                    │
   Draft ──► Review ──► Last Call ──► Active ──► Final
                    │              │           │
                    └──► Rejected  └► Withdrawn└► Superseded
                                                 (by another NCIP)
```

| State | Meaning |
|---|---|
| **Draft** | Author iterating; no editorial review yet |
| **Review** | Submitted to editors; community discussion open |
| **Last Call** | Editors propose merging; ≥14-day public objection window |
| **Active** | Merged into the registry; for `Standards Track` this enables the **activation phase** (≥75% nodes for ≥30 days) |
| **Final** | Activated and stable; the canonical reference for that decision |
| **Rejected** | Editors / vote concluded against; archived for the record |
| **Withdrawn** | Author or editors withdrew before Final; archived |
| **Superseded** | Replaced by a later NCIP; older NCIP retains historical authority |

Full state machine and transition rules: `NCIP-Process-001` §4 (*Lifecycle*).

---

## Categories

| Category | Use for | Voting requirement |
|---|---|---|
| **Standards Track** | Wire formats, crypto primitives, capability formats, kernel interfaces, mesh protocol | Quadratic-vote majority + activation threshold |
| **Process** | NCIP procedure changes, editor rotation, voting parameters, contribution flow | Quadratic-vote majority |
| **Informational** | Best practices, advisories, guidelines (non-binding) | Editor approval only |
| **Meta** | NCIPs that govern the NCIP process itself (`NCIP-Process-001` is Meta) | Quadratic-vote majority + BDFL non-veto |

---

## Index of NCIPs

| # | Track | Title | Status | Authors | Created |
|---|---|---|---|---|---|
| 0000 | Meta | Template (reserved) | — | — | 2026-05-10 |
| 001 | Meta | The NCIP Process | Active *(Bootstrap)* | cySalazar | 2026-05-10 |
| 002 | Process | Bug Bounty Program for NexaCore OS | Active *(closed 2026-05-22 by §5.3 ¶1 ballot)* | cySalazar | 2026-05-10 |
| 002 | Standards Track | Compliance Proof Scheme — STARK over SNARK for v1 | Active *(closed 2026-05-24 by §5.3 ¶1 ballot, 66.7% supermajority)* | cySalazar | 2026-05-10 |
| 003 | Standards Track | UEFI Bootloader Selection and Kernel `no_std` Transition Plan | Last Call *(closes 2026-05-17)* | cySalazar | 2026-05-15 |
| 004 | Standards Track | Migrate workspace serialization from bincode v2 (unmaintained) to postcard | Active *(closed 2026-05-22 by §5.3 ¶1 ballot)* | cySalazar | 2026-05-12 |
| 005 | Standards Track | Boot hand-off ABI and kernel-runner crate (gate K4 of NCIP-Kernel-003) | Review | cySalazar | 2026-05-12 |
| 005 | Process | Voting weight formula — non-saturating uptime, contribution signals, conflict-of-interest guards | Draft | cySalazar | 2026-05-12 |
| 006 | Standards Track | NexaCoreContainer — native container engine with Linux/Windows compatibility | Draft | cySalazar | 2026-05-12 |
| 007 | Standards Track | NexaCore Helper — Agentic Need-Detection, Autonomy Levels, and Impact Dashboard | Draft | cySalazar | 2026-05-12 |
| 008 | Standards Track | `nexacore-pkg` — Content-Addressed Federated Package Manager | Draft | cySalazar | 2026-05-12 |
| 009 | Standards Track | `nexacore-forge` — On-Demand Rust → WASM/ELF Generation Pipeline | Draft | cySalazar | 2026-05-12 |
| 010 | Standards Track | `nexacore-market` — Stichting-Curated Marketplace + Continuous CVE Re-Scan | Draft | cySalazar | 2026-05-12 |
| 011 | Standards Track | NexaCore\* Flagship Apps Program + NexaCoreCode v1 (Phased Delivery) | Draft | cySalazar | 2026-05-12 |
| 012 | Standards Track | Kernel panic handler and global allocator (gate K3 of NCIP-Kernel-003) | Review | cySalazar | 2026-05-12 |
| 013 | Standards Track | User-space driver framework — capabilities, MMIO, DMA/IOMMU, IRQ routing, manifest | Active *(founder fast-path 2026-05-20)* | cySalazar | 2026-05-20 |
| 014 | Standards Track | NVMe user-space driver — admin/IO queue ABI, PRP transfer model, BLK channel contract | Active *(founder fast-path 2026-05-20)* | cySalazar | 2026-05-20 |
| 015 | Standards Track | Network user-space driver — virtio-net + e1000e + ConnectX phased delivery, NET channel | Active *(founder fast-path 2026-05-20)* | cySalazar | 2026-05-20 |
| 016 | Standards Track | TEE user-space driver — Intel TDX + AMD SEV-SNP backends, attestation channel | Active *(founder fast-path 2026-05-20)* | cySalazar | 2026-05-20 |
| 017 | Standards Track | Kernel driver-capability issuer key custody and rotation | Draft | cySalazar | 2026-05-22 |
| 018 | Standards Track | Filesystem direction for NexaCore OS — native NCFS as primary, foreign filesystems as read-only compatibility services | Active *(closed 2026-05-22 by §5.3 ¶1 ballot)* | cySalazar | 2026-05-22 |
| 019 | Standards Track | Multichannel user experience — voice, vision, messaging, and A11y as first-class OS surfaces | Draft | cySalazar | 2026-05-23 |
| 020 | Informational | Linux and Windows application compatibility — canonical status note | Draft | cySalazar | 2026-05-23 |
| 021 | Standards Track | Phase 2 Entry — AI Runtime Service Foundation | Draft | cySalazar | 2026-05-24 |
| 022 | Standards Track | Five-Agent Architecture — Orchestrator, Guidance, SysAdmin, Security, Task | Draft | cySalazar | 2026-05-24 |
| 023 | Standards Track | NCFS On-Disk Format v1 — Superblock, Inode B+-Tree, CoW Block Allocator, AEAD Integrity | Active | cySalazar | 2026-05-24 |
| 024 | Standards Track | Tiered trust model — mesh participation beyond full-TEE hardware | Draft | cySalazar | 2026-05-27 |
| 025 | Standards Track | NexaCore Mesh Bridge — cross-platform desktop application for tiered mesh participation | Draft | cySalazar | 2026-05-27 |
| 026 | Standards Track | Kernel Threat Model and Performance-Preserving Mitigation Budget | Draft | cySalazar | 2026-06-05 |
| 027 | Standards Track | NCFS On-Disk Format v3 — CoW Root Commit, Extents, Directory Objects, Merkle Integrity, Authenticated Encryption | Draft | cySalazar | 2026-06-12 |
| 028 | Process | Independent-review gate for on-disk-format and cryptographic NCIPs | Draft | cySalazar | 2026-06-12 |
| 029 | Standards Track | Kernel slab and free-list allocator — reclaiming heap memory and lifting the IPC channel cap | Draft | cySalazar | 2026-06-14 |
| 030 | Standards Track | ncScript (NCIP) — a capability-gated, Rust-derived scripting language for NexaCore OS | Draft | cySalazar | 2026-06-23 |

> **Note on duplicate trailing numbers (history):** `NCIP-Bounty-002` / `NCIP-Crypto-002`, `NCIP-Serde-004` / `NCIP-Kernel-004` (was), and `NCIP-Kernel-005` / `NCIP-Voting-005` shared trailing numbers as placeholder collisions at `Draft` stage. Per `NCIP-Process-001` §8.3, placeholder collisions in `Draft` are explicitly permitted and reconciled by the editors at the `Draft → Review` transition: the first of a colliding pair to reach `Review` retains its placeholder integer; the other is renumbered to the next free integer in the same PR that opens its own `Review` window. Current state: `NCIP-Bounty-002` and `NCIP-Serde-004` are canonical (both transitioned `Last Call → Active` on 2026-05-22 by §5.3 ¶1 founder ballot, recorded in [`docs/audits/ncip-editors-report-2026-Q2.md`](../docs/audits/oip-editors-report-2026-Q2.md)). `NCIP-Kernel-005` reached `Review` first within its collision pair, retaining `005`; `NCIP-Voting-005` (still `Draft`) will be renumbered when it reaches `Review`. `NCIP-Kernel-004` was renumbered to **`NCIP-Kernel-012`** at its `Draft → Review` transition (2026-05-14) since `NCIP-Serde-004` was already canonical. `NCIP-Crypto-002` transitioned `Last Call → Active` on 2026-05-24 by §5.3 ¶1 ballot (66.7% supermajority, Layer 1 crypto); it retains `002` pending `Draft → Review` renumbering of the collision counterpart `NCIP-Bounty-002`.

---

## Filing a new NCIP

1. **Read** `NCIP-Process-001` §3 (*Trigger Conditions*) to confirm an NCIP is required.
2. **Open a discussion issue** using the
   [`ncip_proposal.yml`](../.github/ISSUE_TEMPLATE/oip_proposal.yml) issue template. Editors will
   pre-validate scope.
3. **Branch** as `ncip/<slug>` (per `CONTRIBUTING.md` §6).
4. **Copy** [`ncip-template.md`](./oip-template.md) → `ncip-<slug>-<NNN>.md`. Per
   `NCIP-Process-001` §8.3, pick the next free integer at filing (or any free integer if
   filing in parallel with another `Draft`). Editors reconcile placeholder collisions at
   the `Draft → Review` transition — the first colliding NCIP to reach `Review` retains its
   integer; the other is renumbered in the same PR that opens its `Review` window.
5. **Fill all required sections.** The lint at `scripts/lint-ncips.py` will run in CI; fix any
   structural errors before requesting review.
6. **Open a PR** with a `Signed-off-by:` trailer (DCO) and Conventional Commit prefix
   `ncip(<slug>): <title>`.
7. **Iterate** through `Draft → Review → Last Call`. The editors merge on positive Last Call
   outcome.

---

## Maintenance policy

- This file is **auto-validated** in CI (the NCIP lint enforces that the index table mirrors the
  files on disk).
- A new NCIP merge **must** include the corresponding row in the index table; the lint will fail
  otherwise.
- A status transition (e.g. `Active → Final`) is its own PR, with the rationale captured in the
  PR body.

---

## License

NCIPs themselves are released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/) (per `NCIP-Process-001` §10) so they
can be quoted, mirrored, and cited freely. The codebase remains Apache-2.0.
