# ADR-0021: NCIP-022 Five-Agent Real Logic (Sprint 4+5)

- **Status:** Accepted
- **Date:** 2026-05-24
- **Deciders:** cySalazar
- **Context:** Phase 2 Sprint 4+5 — expanding agent skeletons to operational logic

## Context

Sprint 3 established the five-agent skeleton per NCIP-Agent-Arch-022: Orchestrator,
Guidance, SysAdmin, Security, and Task agents with the `Agent` trait, `AgentKind`
enum, `AgentMessage` protocol, and `OperationalMode` state machine. All five
agents had basic lifecycle support (spawn/suspend/resume/shutdown) and simple
keyword-based dispatch, but no real operational logic.

Sprint 4+5 requires expanding each agent with functional subsystems that fulfil
the NCIP-022 specification: NCIP-007 integration for Guidance, taint tracking and
output gating for Security, rollback management for SysAdmin, background task
execution and filesystem scoping for Task, and Emergency Recovery Mode with
session management.

## Decision

### Guidance Agent — module directory structure

The Guidance Agent was restructured from a single `guidance.rs` file into a
`guidance/` module directory with 7 sub-modules mapping 1:1 to NCIP-007 sections:

| Module | NCIP-007 § | Key types |
|--------|-----------|-----------|
| `triggers` | §1 | `TriggerSource`, `TriggerEvent`, `TriggerEvaluator` |
| `autonomy` | §2 | `AutonomyLevel`, `AutonomyConfig`, `AutonomyManager` |
| `escalation` | §3 | `EscalationClass`, `EscalationPolicy` |
| `impact` | §4 | `ImpactDimension`, `ImpactScore`, `ImpactDashboard`, `ImpactAssessor` |
| `explanation` | §5 | `TechnicalLevel`, `ExplanationEngine` |
| `undo` | §6 | `UndoEntry`, `UndoWindow` (30s rollback) |
| `audit` | §7 | `AuditEntry`, `AuditLog` (append-only) |

**Alternative considered:** Keeping everything in a single file. Rejected because
the 7 sub-systems have distinct responsibilities and the combined file would
exceed 2,000 lines, making navigation and testing unwieldy.

### Security Agent — in-file expansion

Added `TaintTracker` (taint propagation with per-entity tracking), `OutputGate`
(constitutional filter enforcement), `PerformanceBaseline` (rolling-window anomaly
detection), and `VetoContext` for contextual veto evaluation. The existing
`evaluate_action` was preserved; a new `veto_with_context` method provides the
four-stage evaluation (risk classification + taint check + output gating + source
capability cross-reference).

### SysAdmin Agent — operation routing

Added `CategoryRouter` for keyword-based operation classification,
`RollbackManager` for pre-execution snapshot management, `AuditEmitter` for
per-operation event logging, and `CapabilityChecker` mapping operation categories
to required capabilities per NCIP-022 §S5.1.

### Task Agent — user-data isolation

Added `BackgroundTaskRunner` with concurrency-limited task submission,
`FilesystemScope` enforcing user-path-only access (deny `/system/`, `/etc/`,
`/drivers/`, `/boot/`), and `ExternalAccessControl` with a finite privacy budget
per NCIP-022 §S9.4.

### Emergency Recovery Mode — session management

Expanded `mode.rs` with `EmergencyRecoveryManager`, `EmergencySession`,
`EmergencyAction` tracking (`emergency_override: true` tagging),
`PostRecoveryReport` generation, and `AuthenticationMethod` enum. Rate limiting
(3 activations per 24h) and duration clamping (1–60 minutes) are enforced.

## Consequences

- `nexacore-agent` crate grows from ~2,500 to ~10,000 lines with 352 tests.
- Guidance Agent's sub-module structure sets the pattern for future NCIP-007
  extensions without touching the parent `GuidanceAgent` struct.
- `ModeManager::activate_emergency_recovery` signature changed to accept
  authentication method and duration — backward compatibility via
  `activate_emergency_recovery_default()` helper.
- All new subsystems are keyword-heuristic-based (Phase 2 stub); production
  classification via the Tier-0 local model is deferred to Phase 3.
