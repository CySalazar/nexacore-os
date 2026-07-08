---
ncip: 7
title: NexaCore Helper — System Agentic Layer
track: Standards Track
status: Draft
authors: [hello@nexacoreos.com]
created: 2026-06-28
license: CC0-1.0
---

## Abstract

This NCIP specifies the **NexaCore Helper**: the always-on, system-level agentic
layer that turns the five-agent framework (NCIP-Agent-Arch-022) into an assistant
that can not only *explain* but *act* on the system, under a fixed set of user-protection
invariants. The Helper detects when the user needs assistance, reasons about the
need through the five agents, and — when it proposes a system action — gates that
action behind three guarantees that are mandatory and non-negotiable: a four-axis
**Impact Dashboard** (Privacy / Trust / Cost / Time) shown before every action, a
**30-second undo window** backed by a pre-action state snapshot, and a
**capability + privacy-budget escalation gate** that fails closed. The Helper is
reachable from anywhere through a single global hotkey.

## Motivation

`docs/02-architecture.md` requires an AI-native UX in which the operating system
*proactively helps* the user. Left unconstrained, a system agent that can act is a
liability: it can leak data, take irreversible actions, or quietly accumulate
capability. The existing five-agent framework already classifies and routes
intents (NCIP-Agent-Arch-022) and the Guidance Agent already implements the
NCIP-007 reasoning sub-systems (autonomy levels, mandatory-escalation taxonomy,
Impact Dashboard, undo window, audit log). What is missing is the **system layer**
that (1) composes those sub-systems into an always-on service, (2) binds the
five-agent framework as its reasoning backend, and (3) wires the action path to the
capability system and the WS5-07 privacy budget so that *no* proposed action can run
without passing the user-protection gates. This NCIP defines that layer and the
invariants it must enforce, so the behaviour is a stable contract rather than an
implementation accident.

## Specification

### S1 — Service model

The Helper is a long-lived system service (`HelperService`). It has an explicit
lifecycle (`start` / `stop`); while stopped it MUST be silent (it surfaces no
proposals and detects no needs). The service owns the NCIP-007 reasoning
sub-systems and the audit log; it does not own the input stack, the kernel effect
path, the capability store, or the privacy ledger — each of those is reached
through a trait seam so the decision logic stays pure and host-testable.

### S2 — Reasoning backend (five-agent binding)

The Helper MUST reason *through* the five-agent framework, not re-derive intent
handling. A `ReasoningBackend` maps a natural-language need to the responsible
agent. The normative backend (`FiveAgentReasoner`) delegates to the Orchestrator's
classification (`classify_intent` → `dispatch_target`) and surfaces the
mode-imposed pre-authorization requirement (`requires_preauth`). Generative
answers continue to flow through the existing `RuntimeLink` seam at the agent layer
(TASK-13 / ADR-0035); the Helper layer is responsible for routing and gating, not
for inference transport.

### S3 — Need detection

Need detection follows NCIP-007 §1 trigger sources: failure-driven,
explicit-invoke, and watch-always-on. An explicit invocation always fires;
failure-driven and watch triggers fire only on non-empty context. The Helper only
acts on a fired trigger while the service is running.

### S4 — Autonomy resolution

Every proposal resolves to exactly one of three autonomy levels (NCIP-007 §2):
`Autonomous` (act, then notify), `Guided` (recommend, user selects), `Inform`
(present, no recommendation). The effective level is the **stricter** of (a) the
per-context autonomy configuration after the operational-mode clamp (High-Risk and
Emergency-Recovery forbid `Autonomous`), and (b) the mandatory-escalation floor of
S5. The Helper maps the resolved level to a disposition: Autonomous →
auto-execute, Guided → ask, Inform → present.

### S5 — Mandatory-escalation taxonomy

Action classes that MUST raise the autonomy floor (NCIP-007 §3):

| Class | Minimum autonomy |
|-------|------------------|
| Destructive | Guided |
| Privacy-violating | Guided |
| Capability-escalation | Inform |
| Borderline | Inform |

An unclassified action keeps its requested level. Before an escalating action runs,
the Helper renders a capability-authorization prompt that names the action, its
risk class, and the four mandatory impact axes.

### S6 — Impact Dashboard (mandatory four axes)

Before *any* action, the Helper MUST expose the four mandatory axes — **Privacy,
Trust, Cost, Time** — each scored 0–100. These are a fixed subset of the seven
NCIP-007 §4 dimensions (the full set adds Storage, Egress, Capabilities). The four
mandatory axes MUST always be present and in canonical order.

### S7 — Execution gate (fail-closed order)

When an approved action executes, the Helper MUST apply these checks in order, and
MUST abort on the first failure without any partial effect:

1. **Capability gate** (S/NCIP-022 capability tokens) — refuse before any other
   work if the holder is not authorized.
2. **Privacy budget** (WS5-07) — charge the per-user/per-app ledger for the
   action's egress tier. A non-local action whose tier cannot be afforded MUST NOT
   run and MUST NOT touch the executor (no partial egress). Local actions are free.
3. **Pre-action snapshot** — capture reversible prior state *before* the effect.
4. **Effect** — perform the action through the executor.
5. **Record** — push the snapshot into the 30-second undo window and append a
   decision record to the append-only audit log.

### S8 — Undo window

Reversible actions are recorded in a 30-second window together with their
pre-action snapshot (NCIP-007 §6). Within the window, the most recent reversible
action can be undone by restoring its snapshot through the executor. After 30
seconds the entry expires and is no longer reversible through this mechanism.

### S9 — Global hotkey

The Helper declares a single canonical global hotkey (`helper.toggle`) with
platform-appropriate default chords (`Meta+Shift+Space` on macOS,
`Ctrl+Shift+Space` elsewhere). Registration is delegated to the desktop runtime's
global shortcut registry (WS17-04) through a `HotkeyRegistrar` seam; the Helper
does not intercept input directly.

## Rationale

The fail-closed ordering in S7 is deliberate: the capability check is cheapest and
most fundamental, so it runs first; the privacy charge is irreversible (it spends
budget), so it runs only after authorization and only when the tier actually
egresses; the snapshot is taken *before* the effect so undo is always possible for
reversible actions. Resolving autonomy as the *stricter* of the configured level
and the escalation floor (rather than the looser) guarantees that a permissive
user setting can never weaken a mandatory protection — a destructive action is
`Guided` even for a user who chose `Autonomous`. Keeping every effect behind a
trait mirrors the established workspace pattern (`ProcessActions` in
`nexacore-monitor`, `EgressGuard` in `nexacore-tokenization`): the decision logic
is deterministic and host-testable, while the real capability verification, kernel
effects, and ledger live at the integration layer.

## Backwards Compatibility

N/A — this NCIP formalizes a new system layer. The Guidance Agent's NCIP-007
sub-systems it composes keep their existing public APIs; the only change to them is
an additive, non-breaking extension of the undo window to carry an optional
pre-action snapshot (existing `record` / `undo_last` behaviour is unchanged).

## Test Cases

The reference implementation is covered by host unit tests that pin each
invariant:

- Service is silent until started; need detection fires per trigger source (S1/S3).
- The reasoning backend routes to the five-agent framework's responsible agent and
  surfaces high-risk pre-authorization (S2).
- Autonomy resolves to the stricter of the configured level and the escalation
  floor, with the High-Risk clamp applied first (S4/S5).
- Every proposal exposes the four mandatory axes in canonical order (S6).
- Execution refuses when the capability gate denies, with no effect attempted; a
  local action is free and undoable; a non-local action charges the correct tier
  cost; an unaffordable action fails closed with no spend and no effect (S7).
- The most recent reversible action is undone by restoring its snapshot; an empty
  window errors (S8).
- The global hotkey descriptor is platform-aware and registration delegates to the
  registrar (S9).

## Reference Implementation

- `crates/nexacore-agent/src/helper.rs` — the `HelperService`, the reasoning-backend,
  capability-gate, executor, and hotkey-registrar seams, and the proposal /
  execution / undo flow.
- `crates/nexacore-agent/src/guidance/` — the composed NCIP-007 sub-systems (autonomy,
  escalation, impact, undo, audit, triggers, explanation).
- `crates/nexacore-runtime/src/privacy_budget.rs` — the WS5-07 ledger charged by the
  execution gate.

## Security Considerations

The Helper is, by construction, a privileged actor: it can take system actions on
the user's behalf. The execution gate is therefore security-critical and MUST fail
closed — an unauthorized or unaffordable action runs *nothing*. Capability checks
use NCIP-022 capability tokens (TEE-bound, attenuable, revocable); the Helper layer
treats authorization as a hard precondition, not advice. The audit log is
append-only: every decision (denied, blocked, executed, failed, undone) is
recorded, so the Helper's behaviour is fully reconstructable for forensic review.
High-Risk and Emergency-Recovery modes clamp autonomy and require Security-agent
pre-authorization, preventing a compromised or over-eager Helper from acting
autonomously when the system is under elevated threat.

## Privacy Considerations

Privacy is enforced at two points. First, the mandatory Impact Dashboard surfaces
the Privacy axis for every action, so the user always sees the privacy cost before
deciding. Second, the execution gate charges the WS5-07 privacy budget for any
action that egresses beyond the local device; when the budget is exhausted the
action is blocked before any data leaves the device. Local actions (Tier 0) cost
nothing because no data egresses. The privacy-violating escalation class forces at
least `Guided` autonomy, ensuring the user consciously approves any action that
exposes or transfers sensitive data.

## Copyright

This document is placed in the public domain under CC0-1.0.
