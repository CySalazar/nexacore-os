---
ncip: 7
title: NexaCore Helper — Agentic Need-Detection, Autonomy Levels, and Impact Dashboard
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-12
updated: 2026-05-12
requires:
  - NCIP-Process-001
  - NCIP-Container-006
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

# NCIP-Helper-007 — NexaCore Helper: Agentic Need-Detection, Autonomy Levels, and Impact Dashboard

## Abstract

This NCIP commits NexaCore OS to **`nexacore-helper`**, a userspace agent daemon
that detects gaps in the user's environment (missing handler for a file
type, command not found, explicit user request) and proposes
**ranked solutions** to fill the gap — including installing an existing
package via `nexacore-pkg` (NCIP-Pkg-008), generating a new app via
`nexacore-forge` (NCIP-Forge-009), or doing nothing. The user controls the
degree of autonomy `nexacore-helper` operates with via a **three-level
configuration** (`Autonomous` / `Guided` / `Inform`), and every
proposal/decision carries a **mandatory Impact Dashboard** with
Privacy / Trust / Cost / Time scores.

## Motivation

Mainstream OSes do not have a first-class "the OS detects you need
something and proposes how to satisfy it" primitive. Closest analogues:

- Windows Copilot can suggest "install X via winget" — but cloud-bound
  and not capability-aware.
- macOS Apple Intelligence can suggest apps from the Store — but does
  not generate code and does not propose alternatives.
- No OS today does **AI-generation as a first-class fallback** ("if no
  package fits, NexaCore can generate a small app for this").

NexaCore's AI-native thesis demands that this be a system primitive, not
an application. It is the "killer feature" that separates NexaCore from
Windows/Linux/macOS at the user-experience layer.

## Specification

### 1. Trigger sources

`nexacore-helper` is invoked through three trigger paths:

1. **Failure-driven** (default-on): a userspace action fails because a
   handler is missing. Examples: `open file.docx` → no handler;
   `convert file.svg to file.png` → no converter; `lint my-code` → no
   linter installed.
2. **Explicit-invoke** (default-on): user types `nexacore-helper <intent>`
   in the shell, or invokes via keyboard shortcut.
3. **Watch-always-on** (default-off, opt-in only): `nexacore-helper`
   observes user actions in real time. Privacy-budget-significant.

### 2. Autonomy levels

The user configures `nexacore-helper.autonomy_level` in system settings.
Three levels, with `Guided` as the system default:

| Variant | Italian display | Behaviour |
|---|---|---|
| `Autonomous` | Autonoma | `nexacore-helper` decides and acts. Post-action notification + Impact Dashboard. Escalation MANDATORY for actions in the §3 taxonomy. |
| `Guided` (default) | Guidata | `nexacore-helper` presents N ranked options with **one recommended option highlighted**, plain-language explanations per option, Impact Dashboard per option. User selects. |
| `Inform` | Informativa | `nexacore-helper` presents N options with explanations and Impact Dashboards but **without recommendation**. User selects unaided. |

**Per-context override**. Users may set per-context autonomy levels via
a declarative grammar:

```
helper.context.code-editor = autonomous
helper.context.network-egress-new-domain = inform
helper.context.* = guided    # fallback
```

### 3. Mandatory-escalation taxonomy

The following action classes are **always escalated to at least `Guided`**
regardless of the configured level. No silent `Autonomous` execution.

| Class | Examples |
|---|---|
| **Destructive** | Deletion of user data; format/wipe of storage; financial transaction; modifying mesh-protected state; sending messages on the user's behalf to third parties; installing code that requests `fs:write` on user-data paths beyond cwd |
| **Privacy-violating** | Sending PII externally; installing software with closed telemetry; opting into Tier 3 cloud inference; enabling `watch-always-on`; sharing capabilities to external accounts; increasing privacy budget allocation above declared monthly limit |
| **Capability-escalation** | Any action requesting capabilities beyond the parent context's scope; promoting an app from user-trust to system-trust; mounting new storage; installing in system-protected paths |
| **Borderline (user-configurable)** | Network egress to non-whitelisted domain; installing community-signed (non-Stichting-blessed) software; invoking LLM generation; updating software with unread changelog |

The borderline class defaults to "escalate to Guided" in `Autonomous`
mode. The user can opt to auto-handle specific borderlines in their
per-context overrides.

### 4. Impact Dashboard

Mandatory for every proposed option (pre-action in `Guided` / `Inform`)
and every executed action (post-action in `Autonomous`). Schema:

```capnp
struct ImpactDashboard {
    privacyScore         @0 :UInt8;     # 1..5
    privacyDescription   @1 :Text;
    trustScore           @2 :UInt8;     # 1..5
    trustDescription     @3 :Text;
    costEuros            @4 :Float32;
    privacyBudgetPercent @5 :Float32;   # 0.0 .. 100.0
    storageBytes         @6 :UInt64;
    estimatedTimeSeconds @7 :UInt32;
    egressHosts          @8 :List(Text);
    capabilitiesRequired @9 :List(Text);
}
```

**Privacy scale** (1-5):

| Score | Meaning |
|---|---|
| 5 | 100% local, no network ever, no telemetry |
| 4 | Local + opt-in Tier 1 (user's LAN cluster) |
| 3 | Tier 2 attested mesh (P2P) |
| 2 | Tier 3 cloud (opt-in, explicit consent) |
| 1 | Tier 3 cloud with active telemetry — **never auto-recommended** |

**Trust scale** (1-5):

| Score | Meaning |
|---|---|
| 5 | Stichting-signed + audited + reproducible build + minimal capability declaration |
| 4 | Stichting-signed OR community reputation > 95% + audited |
| 3 | Community-signed, reputation > 70%, capability-minimal |
| 2 | Community-signed, reputation 50-70% |
| 1 | Unsigned or reputation < 50% — **requires explicit acknowledgement even at L1/L2** |

### 5. Plain-Language Explanation Engine

For every option, `nexacore-helper` generates a plain-language explanation
adapted to the user's declared technical level (`helper.user-level =
beginner | intermediate | expert`). Implementation: local Tier-0 model
(default) with mesh Tier-1 escalation (opt-in) for higher-quality
explanations. Tier-3 cloud explanations are forbidden by default.

Each explanation must:
- Avoid jargon at `beginner` level.
- Clearly state the trade-offs vs the alternatives.
- Cite the source of trust (Stichting / community / generated).
- Disclose privacy budget impact in plain numbers.

### 6. Undo window

In `Autonomous` mode, every non-destructive action exposes a **30-second
undo window** during which the user can rollback:
- Capability tokens revoked.
- Installed package uninstalled (atomic via `nexacore-pkg`).
- Audit log entry tombstoned.

Destructive actions never reach `Autonomous` — they always escalate.

### 7. Audit log integration

Every `nexacore-helper` decision (proposal shown, recommendation made,
action taken, undo invoked) lands in the user audit log
(`docs/04-security-model.md` § "Audit log"). The log is
user-queryable: "show what NexaCore did automatically last week".

### 8. Reference implementation — `crates/nexacore-helper/`

The implementation lives at `crates/nexacore-helper/`:

```
crates/nexacore-helper/
├── Cargo.toml
├── src/
│   ├── lib.rs              # public surface
│   ├── triggers/
│   │   ├── failure.rs      # FS / exec failure interceptor
│   │   ├── invoke.rs       # explicit CLI / keyboard
│   │   └── watch.rs        # always-on (opt-in)
│   ├── proposal.rs         # HelperProposal struct + ranking
│   ├── impact.rs           # ImpactDashboard schema + computation
│   ├── autonomy.rs         # 3-level config + per-context override
│   ├── escalation.rs       # §3 taxonomy enforcement
│   ├── explanation.rs      # plain-language engine (LLM bridge)
│   ├── undo.rs             # 30s undo window manager
│   └── audit.rs            # audit log integration
└── tests/
    ├── autonomy_levels.rs
    ├── escalation_taxonomy.rs
    └── undo_window.rs
```

Estimated effort: **6-8 engineer-months** for v0.1 (one feature-complete
release with the full autonomy/escalation/dashboard surface).

## Rationale

### Why three autonomy levels, not two or five?

Two (auto / manual) is too coarse — most users want "decide for me
unless it's dangerous". Five is too many to remember. Three with
`Guided` as default matches behaviour seen in user research from Apple
(prompt cadence), Microsoft (UAC tiers), and GNOME (sandboxing
permissions UI).

### Why mandatory escalation for some classes?

Because the cost of a silent destructive action is catastrophic to user
trust. The project's "Security > Stability > Performance" stance demands
that we err on the side of one extra dialog rather than one silent
data loss.

### Why local Tier-0 explanation engine by default?

Privacy-by-construction. An OS-level helper that ships every action
context to a cloud LLM is exactly the failure mode NexaCore was built to
prevent. Local models are sufficient for plain-language rephrasing of
structured option metadata; LLM cloud inference is a luxury, not a
requirement.

## Backwards Compatibility

Not applicable: no pre-existing helper service.

## Test Cases

1. **Autonomy `Guided` smoke**: open `.docx`, three options
   presented, recommended one highlighted, Impact Dashboards
   correctly populated.
2. **Autonomy `Autonomous` end-to-end**: configure auto for
   "code-editor install" context, open `.rs` file with no editor,
   helper auto-installs, notification + post-action dashboard
   shown.
3. **Mandatory escalation**: in `Autonomous`, attempt to delete user
   data through a helper proposal — escalates to `Guided` with
   confirmation dialog.
4. **Undo within 30s**: in `Autonomous`, helper installs an app;
   user presses [u] within 30s; capability revoked, package
   uninstalled, audit log shows tombstoned entry.
5. **Per-context override**: configure `code-editor = autonomous`,
   `network-egress = inform`; open `.rs` (auto-install editor),
   then trigger network egress (inform-only).
6. **Plain-language at `beginner` level**: option explanation
   contains no jargon, mentions trade-offs in lay terms.
7. **Privacy budget exhaustion**: helper refuses to make a
   recommendation when budget remaining < required.

## Reference Implementation

To land before activation:
- `crates/nexacore-helper/` skeleton: daemon entry point, autonomy-level
  state, per-context override store, Impact Dashboard renderer trait,
  policy-engine trait, audit-log writer.
- **Need-detection hooks**: `nexacore-runtime` extension points so the
  shell and graphical surfaces can dispatch
  `helper://file-failure?mime=…` and `helper://command-not-found?cmd=…`
  intents (deterministic; no LLM in this path).
- **Policy engine** (`crates/nexacore-helper/src/policy/`): deterministic
  trust-score + capability-minimality scoring. The LLM is only invoked
  for plain-language *explanations*, never for ranking — per the
  Security Considerations.
- **Impact Dashboard schema** (`crates/nexacore-helper/src/dashboard.rs`):
  serializable struct with the six required dimensions (Privacy,
  Trust, Cost, Time, Egress, Capabilities) on 1–5 scales, plus a
  versioned wire format for reuse by `nexacore-pkg` and `nexacore-forge`.
- **30-second undo executor**: tombstoned audit-log entries +
  capability revocation + `nexacore-pkg rollback` invocation in
  `Autonomous` mode.
- Integration tests against a mock `nexacore-pkg` and a mock LLM backend
  to cover the seven Test Cases above without external network.

## Security Considerations

- **Helper as TCB extension**: `nexacore-helper` itself runs with broad
  observe capability. It is a security-critical service. Mitigation:
  small codebase, code review mandatory, no `unsafe`, audit-log every
  decision.
- **LLM-induced bad recommendations**: a compromised or hallucinating
  local LLM could recommend insecure options. Mitigation: trust score
  computed by the **policy engine** (deterministic), not by the LLM.
  LLM only produces explanations, not rankings.
- **Watch-always-on as surveillance risk**: never default-on,
  privacy-budget-costly when enabled, user can disable per-app at any
  time.

## Privacy Considerations

- All helper decisions consume privacy budget (`docs/04-security-model.md`).
- Watch-always-on requires explicit consent dialog the first time and
  every 30 days thereafter.
- Audit log is local-only and not network-exported by default.

## Future Work

- **`NCIP-Helper-Voice-XXX`** (Phase 7+): voice trigger ("Hey NexaCore,
  open this file") as an alternative invoke trigger.
- **`NCIP-Helper-Multi-User-XXX`** (Phase 7+): per-user helper context
  in multi-user installations.
- **`NCIP-Helper-LearnPref-XXX`** (Phase 8+): preference learning from
  past user choices, opt-in only, local-only model.

## Copyright

This NCIP is licensed under CC0 1.0 Universal.
