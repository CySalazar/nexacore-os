---
ncip: 22
title: Five-Agent Architecture — Orchestrator, Guidance, SysAdmin, Security, Task
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-24
updated: 2026-05-24
requires:
  - 1
  - 6
  - 7
supersedes: ~
superseded-by: ~
discussion: ~
license: CC0-1.0
---

# NCIP-Agent-Arch-022 — Five-Agent Architecture: Orchestrator, Guidance, SysAdmin, Security & Performance, Task

## Abstract

This NCIP defines the **five-agent architecture** of NexaCore OS: five
specialized, first-class system agents — **Orchestrator**, **Guidance**,
**System Administrator**, **Security & Performance**, and **Task** —
that together form the AI-driven operational layer of the operating
system. The Orchestrator receives all user intents and dispatches work
to the appropriate agent(s). The Guidance Agent (incorporating
NCIP-Helper-007's `nexacore-helper`) handles user interaction, tutorials,
and explanations. The System Administrator Agent executes technical
operations on the system infrastructure. The Security & Performance
Agent monitors threats, enforces security policies, and optimizes
performance. The Task Agent executes user-delegated, goal-oriented
work: research, content creation, file management, monitoring, and
any productive task operating on user data or external resources.

This NCIP also formalizes two system-wide **operational modes**: **Standard
Mode**, where the Security Agent acts as an advisory consigliere and the
user retains final decision authority; and **High-Risk Mode**, where the
Security Agent gains absolute veto power over all actors — including the
user — to protect systems handling sensitive data or operating in
high-threat environments. A strictly scoped **Emergency Recovery Mode**
provides a hardware-bound escape hatch when High-Risk veto must be
overridden.

---

## Motivation

### M1. Agents need specialization, not generality

The current `nexacore-agent` scaffold (Phase 2 stub) declares a generic
`Agent` trait with no concrete specializations. A single generic agent
model forces every agent instance to carry the full complexity of the
system: security reasoning, user interaction, system administration, and
workflow coordination. This violates the principle of least privilege
and makes auditing intractable — an auditor cannot inspect a bounded
responsibility surface.

Five specialized agents with declared, non-overlapping responsibility
domains allow:
- Capability tokens scoped to each agent's actual needs (Orchestrator
  never holds `fs:write`; SysAdmin never holds `user:explain`).
- Per-agent KV-cache isolation with meaningful boundaries
  (`docs/04-security-model.md` § Side channels).
- Independent budget tracking: the Guidance Agent's token budget for
  explanations does not compete with the SysAdmin Agent's budget for
  system operations.
- Clear audit trails: every action in the audit log maps to exactly one
  responsible agent.

### M2. The Security Agent must be architecturally separable

In a general-purpose agent model, security enforcement is a policy layer
within each agent. This creates two problems: (a) a compromised agent
can bypass its own security layer, and (b) security logic is duplicated
across agents. An architecturally separate Security & Performance Agent,
running in its own sandbox with its own capability set, provides a
security boundary that survives the compromise of any other agent.

### M3. High-Risk environments demand inverted authority

NexaCore OS targets environments that handle sensitive data (healthcare,
finance, legal, government, defense research). In these environments,
the cost of an unauthorized action exceeds the cost of a blocked
legitimate action by orders of magnitude. The Standard Mode assumption —
"user has final say" — is incorrect for these deployments. High-Risk
Mode inverts the authority hierarchy so that the Security Agent can
block any action, including user-initiated ones, when the system
operates in a threat-elevated context. No mainstream OS offers this
capability today.

### M4. NCIP-007 defines the Guidance primitives but not the agent topology

NCIP-Helper-007 defines autonomy levels, the Impact Dashboard, the
escalation taxonomy, and the plain-language explanation engine. These
are the correct primitives. What NCIP-007 does not define is *how these
primitives relate to other system agents*. This NCIP positions the
Guidance Agent as the successor to `nexacore-helper`, inheriting all NCIP-007
primitives and adding coordination with the Orchestrator, SysAdmin, and
Security agents.

### M5. User-delegated productive work needs a dedicated agent

An AI-native OS that cannot autonomously research, create content,
reorganize files, or perform goal-oriented background tasks for the
user is missing its core value proposition. None of the four
infrastructure agents covers this domain: the SysAdmin operates on the
*system* (packages, drivers, config); the Guidance Agent *explains* but
does not *do*; the Security Agent *protects*; the Orchestrator
*coordinates*. A fifth agent — the Task Agent — fills this gap with a
clear responsibility boundary: it operates on *user data* and *external
resources* to accomplish user-delegated goals, with full traceability.

---

## Specification

### S1. Agent taxonomy

NexaCore OS MUST instantiate exactly five system agents at boot. Each agent
is a first-class OS primitive as defined in `docs/10-glossary.md`.

| ID | Agent | Italian display | Role | Responsibility boundary |
|----|-------|-----------------|------|------------------------|
| `orch` | **Orchestrator Agent** | Orchestratore | Central coordinator | Intent analysis, agent dispatch, workflow composition, priority management. MUST NOT execute system operations or generate user-facing explanations directly. |
| `guid` | **Guidance Agent** | Assistente | User assistant / educator | User interaction, tutorials, plain-language explanations, need detection (NCIP-007 triggers). Incorporates all NCIP-Helper-007 responsibilities. |
| `sadm` | **System Administrator Agent** | Amministratore | Technical operator | System configuration, software installation, driver management, updates, mesh configuration, hardware optimization. Executes only on Orchestrator dispatch. |
| `secp` | **Security & Performance Agent** | Sicurezza | Security guardian / performance optimizer | Threat monitoring, hardening, taint tracking enforcement, output gating, capability validation, performance profiling, stability optimization. |
| `task` | **Task Agent** | Esecutore | User-delegated productive work | Research, content creation, file/data management on user paths, external API calls, background monitoring, scheduling. Operates on user data and external resources; MUST NOT operate on system paths or install system software. |

#### S1.1. Agent identity and isolation

Each agent MUST have:

- A stable, unique `AgentId` (the four-character ID in §S1).
- Its own capability token set, scoped to its responsibility boundary.
  Capability delegation follows Macaroons-style attenuation
  (`docs/04-security-model.md` § Capability-based access control).
- Its own KV-cache partition, flushed on context switch
  (`docs/04-security-model.md` § Side channels).
- Its own computational budget (tokens, compute time, memory) tracked by
  the `budget` module.
- Its own WASM sandbox instance (v1) or process-level sandbox
  (`docs/04-security-model.md` § Secure agent sandboxing).
- Its own audit log stream within the system-wide Merkle audit tree
  (`docs/04-security-model.md` § Audit log).

#### S1.2. Minimum capability sets

The principle of least privilege MUST be enforced. Each agent's
capability set is bounded:

| Agent | MUST hold | MUST NOT hold |
|-------|-----------|---------------|
| `orch` | `intent:analyze`, `agent:dispatch`, `workflow:compose`, `audit:write` | `fs:write`, `net:egress`, `pkg:install`, `user:explain` |
| `guid` | `user:explain`, `impact:render`, `autonomy:query`, `audit:write` | `fs:write`, `net:admin`, `pkg:install`, `sys:configure` |
| `sadm` | `fs:read`, `fs:write`, `pkg:install`, `pkg:remove`, `sys:configure`, `net:admin`, `driver:load`, `audit:write` | `user:explain`, `agent:dispatch`, `security:veto` |
| `secp` | `threat:monitor`, `taint:enforce`, `output:gate`, `capability:validate`, `perf:profile`, `audit:write`, `audit:read` | `user:explain`, `pkg:install`, `fs:write` (except security policy files) |
| `task` | `fs:read` (user paths), `fs:write` (user paths), `net:egress`, `web:search`, `api:call`, `content:create`, `audit:write` | `pkg:install`, `sys:configure`, `driver:load`, `security:veto`, `agent:dispatch`, `fs:write` (system paths) |

In High-Risk Mode (§S3), the Security Agent additionally holds
`security:veto` — the capability to block any pending action from any
actor.

### S2. Orchestrator Agent — dispatch protocol

#### S2.1. Intent reception

The Orchestrator Agent MUST receive all user intents, regardless of
input modality (text, voice via NCIP-Multimodal-UX-019, GUI, API). The
Orchestrator MUST NOT be bypassed: no agent receives work except through
the Orchestrator's dispatch.

#### S2.2. Intent analysis and routing

Upon receiving an intent, the Orchestrator MUST:

1. **Classify** the intent into one or more of: `guidance` (explanation,
   tutorial, question), `administration` (system operation, config,
   install), `security` (threat query, hardening request, audit query),
   `task` (research, content creation, file management, monitoring,
   or any goal-oriented user-delegated work), `composite` (requires
   multiple agents).
2. **Check operational mode** (Standard or High-Risk). If High-Risk,
   the Orchestrator MUST submit the action plan to the Security Agent
   for pre-authorization **before** dispatching to any agent (§S3.3).
3. **Dispatch** to the appropriate agent(s). For `composite` intents,
   the Orchestrator MUST decompose the workflow into ordered steps and
   dispatch each step to the correct agent, respecting dependencies.
4. **Aggregate** results from dispatched agents and compose the final
   response to the user.

#### S2.3. Priority management

The Orchestrator MUST maintain a priority queue for pending intents.
Priority order: `security` > `administration` > `task` > `guidance`. A security
alert from the Security Agent MUST preempt any pending guidance or
administration task.

#### S2.4. Orchestrator failure mitigation

The Security Agent MUST monitor the Orchestrator via a heartbeat
protocol (interval: 5 seconds, timeout: 15 seconds). If the
Orchestrator fails to respond:

1. The Security Agent MUST assume **degraded coordinator** role.
2. In degraded mode, only `security`-class operations are dispatched.
3. The Guidance Agent MUST notify the user that the system is operating
   in degraded mode and that administration operations are suspended.
4. The Security Agent MUST attempt to restart the Orchestrator sandbox.
5. If restart fails after 3 attempts, the system MUST enter
   **safe mode**: all non-essential operations suspended, user notified
   via persistent status indicator, full audit log emitted.

### S3. Operational modes

#### S3.1. Standard Mode (default)

In Standard Mode:

- The Security Agent acts as **advisory consigliere**: it evaluates
  actions, computes risk scores, and presents warnings to the user via
  the Impact Dashboard (NCIP-007 §4), but it MUST NOT block actions
  unilaterally.
- The user retains **final decision authority** over all actions.
- NCIP-007 autonomy levels (`Autonomous` / `Guided` / `Inform`) apply
  as documented.
- NCIP-007 mandatory-escalation taxonomy (§3) applies: destructive,
  privacy-violating, and capability-escalation actions always escalate
  to at least `Guided` even in `Autonomous` mode.

#### S3.2. High-Risk Mode

High-Risk Mode is a **system-wide operational mode** that inverts the
authority hierarchy. It is NOT a configuration of the Security Agent
alone — it changes the behavior of the entire agent topology.

**Activation:**

- **Manual**: the user explicitly enables High-Risk Mode via
  `nexacore-settings set system.mode high-risk` or via the system UI.
  Activation MUST require user authentication (at minimum: local
  password; RECOMMENDED: hardware token or biometric).
- **Automatic**: the system MAY activate High-Risk Mode when a
  configured trigger fires. Triggers MUST be explicitly configured by
  the user or system administrator; NexaCore OS MUST NOT activate
  High-Risk Mode without prior user consent to the trigger rule.
  Examples of configurable triggers:
  - TEE attestation detects a tampered environment.
  - Taint tracker detects PII in an egress-bound channel.
  - Threat monitor detects active exploitation attempt.
  - System is enrolled in a compliance profile (HIPAA, PCI-DSS,
    classified-data).

**Behavior in High-Risk Mode:**

| Aspect | Standard Mode | High-Risk Mode |
|--------|--------------|----------------|
| Security Agent role | Advisory (warns only) | **Guardian with absolute veto** |
| Final decision authority | User | **Security Agent** |
| Priority hierarchy | Security > Admin > Guidance | **Security overrides ALL** |
| AI autonomy level | Configurable (Autonomous/Guided/Inform) | **Forced to Guided or Inform; Autonomous disabled** |
| Orchestrator dispatch | Direct to target agent | **Pre-authorized by Security Agent** |
| SysAdmin operations | On Orchestrator dispatch | **Require Security Agent approval** |
| Guidance explanations | Freely generated | **Screened for information leakage** |
| User override of veto | Allowed (user has final say) | **Blocked** (only Emergency Recovery overrides) |

**Veto mechanism:**

When the Security Agent vetoes an action in High-Risk Mode:

1. The action is blocked before execution.
2. The user receives a structured veto notification containing:
   - The vetoed action description.
   - The risk classification (which threat class triggered the veto).
   - The specific policy or rule that was violated.
   - Alternative actions the user MAY take that would not trigger a veto.
3. The veto is recorded in the audit log with full context.
4. The user MUST NOT be able to override the veto through normal
   interaction channels. Only Emergency Recovery Mode (§S3.3) can
   override a High-Risk veto.

#### S3.3. Emergency Recovery Mode

Emergency Recovery Mode is the escape hatch for situations where
High-Risk Mode's veto must be overridden — for example, when the
Security Agent incorrectly vetoes a critical operation, or when a
Security Agent bug renders the system unusable.

**Activation requirements** (ALL of the following MUST be satisfied):

1. **Physical presence**: activation MUST require a local console
   session. Remote activation via SSH, mesh, or network API is
   FORBIDDEN.
2. **Strong authentication**: at minimum, local user password PLUS one
   additional factor: hardware security key (FIDO2/WebAuthn), TPM-bound
   PIN, or biometric. Single-factor authentication MUST NOT be
   sufficient.
3. **Explicit acknowledgement**: the user MUST acknowledge a structured
   warning that explains the security implications of overriding
   High-Risk protections.
4. **Time-bounded**: Emergency Recovery Mode MUST expire automatically
   after a configurable duration (default: 15 minutes, maximum: 60
   minutes). After expiration, High-Risk Mode resumes automatically.

**Behavior in Emergency Recovery Mode:**

- The Security Agent's veto is suspended for the duration.
- The Security Agent continues to monitor and log, but cannot block.
- All actions taken during Emergency Recovery are tagged
  `emergency_override: true` in the audit log.
- A post-recovery audit report MUST be generated automatically,
  summarizing all actions taken during the override window.

**Security considerations for Emergency Recovery:**

- Emergency Recovery MUST NOT be triggerable by any agent (including
  the Orchestrator). Only human-initiated, physically-present
  activation is valid.
- Emergency Recovery invocations MUST be rate-limited: maximum 3
  activations per 24-hour period. After exhaustion, only a full system
  reboot with hardware token can re-enable Emergency Recovery.
- Every Emergency Recovery activation MUST emit a high-priority
  audit event visible in the system dashboard.

### S4. Guidance Agent — NCIP-007 integration

The Guidance Agent MUST implement all responsibilities defined in
NCIP-Helper-007:

| NCIP-007 component | Guidance Agent module |
|--------------------|---------------------|
| Trigger sources (§1) | `triggers/` — failure-driven, explicit-invoke, watch-always-on |
| Autonomy levels (§2) | `autonomy.rs` — three-level config with per-context override |
| Mandatory-escalation taxonomy (§3) | `escalation.rs` — destructive, privacy-violating, capability-escalation, borderline |
| Impact Dashboard (§4) | `impact.rs` — Privacy/Trust/Cost/Time/Storage/Egress/Capabilities |
| Plain-Language Explanation Engine (§5) | `explanation.rs` — beginner/intermediate/expert adaptation |
| Undo window (§6) | `undo.rs` — 30-second rollback for non-destructive Autonomous actions |
| Audit log integration (§7) | `audit.rs` — decision logging into Merkle audit tree |

The Guidance Agent extends NCIP-007 with:

- **Cross-agent explanation**: when the SysAdmin Agent performs an
  operation, the Guidance Agent MUST be able to explain what happened
  and why, in the user's configured technical level.
- **Veto explanation**: when the Security Agent vetoes an action in
  High-Risk Mode, the Guidance Agent MUST provide a clear,
  non-technical explanation of why the veto occurred and what
  alternatives exist.
- **Proactive guidance**: in Standard Mode, the Guidance Agent MAY
  proactively suggest security improvements or system optimizations,
  using the Impact Dashboard to communicate trade-offs. In High-Risk
  Mode, proactive guidance is limited to security-relevant information.

### S5. System Administrator Agent

The System Administrator Agent executes technical operations on the
system. It MUST NOT act autonomously — all operations MUST be initiated
by the Orchestrator Agent.

#### S5.1. Operation categories

| Category | Examples | Required capability |
|----------|----------|-------------------|
| Configuration | System settings, network config, user preferences | `sys:configure` |
| Package management | Install, update, remove software via `nexacore-pkg` | `pkg:install`, `pkg:remove` |
| Driver management | Load, configure, update drivers | `driver:load` |
| Maintenance | Disk cleanup, log rotation, cache management | `fs:write`, `sys:configure` |
| Mesh operations | Node enrollment, peer configuration, mesh health | `net:admin` |
| Diagnostics | System health checks, performance profiling | `fs:read`, `perf:profile` |

#### S5.2. Pre-execution validation

Before executing any operation, the SysAdmin Agent MUST:

1. Verify it holds the required capability for the operation.
2. In High-Risk Mode: verify the Security Agent has pre-authorized the
   operation.
3. Create a rollback point (where technically feasible) before
   executing destructive or configuration-altering operations.
4. Emit a pre-execution audit event.

### S6. Security & Performance Agent

#### S6.1. Continuous monitoring

The Security Agent MUST continuously monitor:

- **Taint propagation** (`docs/04-security-model.md` § Prompt
  injection): verify that taint tags propagate correctly through IPC,
  files, and pipes.
- **Output gating**: inspect model outputs before side effects are
  executed; block outputs that fail constitutional filters.
- **Capability validity**: verify that capability tokens presented by
  agents and applications are valid, non-expired, and appropriately
  scoped.
- **Orchestrator health**: heartbeat monitoring per §S2.4.
- **Performance baselines**: track inference latency, memory usage, CPU
  utilization; alert on anomalous deviations that may indicate
  resource exhaustion attacks.

#### S6.2. Dual-LLM enforcement

The Security Agent MUST enforce the dual-LLM pattern defined in
`docs/04-security-model.md` § Prompt injection:

- The Orchestrator (planner role) MUST NOT see raw untrusted content.
- Untrusted content MUST be processed by a quarantined model that
  returns only structured, validated data to the Orchestrator.
- The Security Agent validates that the quarantine boundary is
  maintained at runtime.

#### S6.3. Performance optimization

The Security Agent is also responsible for system performance:

- Profile inference pipeline latency and recommend backend
  optimizations (SIMD codepath selection, batch sizing).
- Monitor memory pressure and trigger budget enforcement when the
  system approaches resource limits.
- In High-Risk Mode: performance optimization is secondary to security;
  the Security Agent MUST NOT sacrifice security controls for
  performance gains.

### S9. Task Agent

The Task Agent executes user-delegated, goal-oriented work. It operates
on **user data** (files, documents, media in user-scoped paths) and
**external resources** (web, APIs, databases). It MUST NOT operate on
system infrastructure — that is the SysAdmin Agent's domain.

#### S9.1. Task categories

| Category | Examples | Required capability |
|----------|----------|-------------------|
| Research & information | Web search, price comparison, scientific paper search, market analysis | `web:search`, `net:egress`, `api:call` |
| Content creation | Create presentations, generate reports, draft documents, translate content | `content:create`, `fs:write` (user paths) |
| File & data management | Reorganize files, batch rename, photo organization, deduplication, data extraction | `fs:read` (user paths), `fs:write` (user paths) |
| Scheduling & planning | Trip planning, meeting preparation, calendar management | `content:create`, `api:call` |
| Communication drafting | Draft emails, summarize conversations, prepare responses | `content:create` |
| Background monitoring | Price drop alerts, topic monitoring, deadline tracking | `web:search`, `net:egress` |

#### S9.2. Filesystem scoping

The Task Agent's `fs:write` capability MUST be scoped to user data
paths only. The capability token MUST carry a `Resource::Filesystem`
pattern matching user directories (e.g., `/home/user/**`). Any attempt
to write to system paths (`/system/**`, `/etc/**`, `/drivers/**`) MUST
be rejected by the capability system.

The SysAdmin Agent's `fs:write` is scoped inversely: system paths only.
This prevents capability overlap at the architectural level.

#### S9.3. Background execution

The Task Agent MUST support long-running background tasks:

- Tasks MAY execute asynchronously after the Orchestrator dispatches
  them.
- Progress updates MUST be emitted periodically to the audit log and
  optionally to the Guidance Agent (for user-visible progress).
- Background tasks MUST respect the Task Agent's compute budget.
- The user MAY cancel a background task at any time; cancellation MUST
  be clean (partial results preserved, resources released).

#### S9.4. External access controls

Every external request (web search, API call) MUST:

1. Be pre-authorized by the Security Agent in High-Risk Mode.
2. Consume privacy budget proportional to the information disclosed
   (per `docs/04-security-model.md` § Privacy budget).
3. Tokenize any PII in outgoing queries via `nexacore-tokenization` before
   egress.
4. Be logged in the audit log with: URL/endpoint, query (tokenized),
   response size, timestamp.
5. Display an Impact Dashboard entry (NCIP-007 §4) for each external
   interaction.

#### S9.5. Result handling

Task results MUST be returned to the Orchestrator as structured data.
The Orchestrator forwards results to the Guidance Agent for
user-friendly presentation. The Task Agent MUST NOT present results
directly to the user — that is the Guidance Agent's responsibility.

### S7. Inter-agent communication protocol

#### S7.1. Message format

All inter-agent communication MUST use a structured message envelope:

```rust
pub struct AgentMessage {
    pub id: MessageId,
    pub from: AgentId,
    pub to: AgentId,
    pub timestamp: Timestamp,
    pub kind: MessageKind,
    pub payload: MessagePayload,
    pub capabilities: Vec<CapabilityToken>,
    pub mode: OperationalMode,
}

pub enum MessageKind {
    Dispatch,
    Result,
    VetoRequest,
    VetoResponse,
    Heartbeat,
    Alert,
    Escalation,
}

pub enum OperationalMode {
    Standard,
    HighRisk,
    EmergencyRecovery,
}
```

#### S7.2. Message routing

- All messages between agents MUST pass through an audited IPC channel.
- Messages MUST carry the sender's capability tokens; the receiver MUST
  validate them before processing.
- In High-Risk Mode, all `Dispatch` messages from the Orchestrator MUST
  first pass through the Security Agent for pre-authorization. The
  Security Agent responds with a `VetoResponse` containing either
  `Approved` or `Vetoed { reason, alternatives }`.

### S8. Hierarchical relationships

```
                    ┌──────────────┐
                    │   User /     │
                    │   Input      │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
              ┌─────│ Orchestrator │─────┐
              │     │   (orch)     │     │
              │     └──────┬───────┘     │
              │            │             │
     ┌────────▼──┐  ┌──────▼───────┐  ┌──▼────────┐
     │ Guidance  │  │   SysAdmin   │  │ Security  │
     │  (guid)   │  │   (sadm)     │  │  (secp)   │
     └───────────┘  └──────────────┘  └───────────┘
                    ┌──────▲───────┐
                    │    Task      │
                    │   (task)     │
                    └──────────────┘

     SysAdmin operates on SYSTEM (infra, packages, drivers)
     Task operates on USER DATA (files, web, APIs, content)
     Standard Mode: secp advises, user decides
     High-Risk Mode: secp pre-authorizes all dispatch,
                     veto overrides user
```

**Hierarchical rules:**

1. The Orchestrator coordinates all five agents. It dispatches work
   and aggregates results. It MUST NOT execute domain-specific work.
2. In Standard Mode, the Security Agent monitors and advises.
   No agent or user action is blocked by the Security Agent.
3. In High-Risk Mode, the Security Agent pre-authorizes ALL Orchestrator
   dispatches and MAY veto any action from any actor (agents or user).
4. The Guidance, SysAdmin, and Task Agents execute domain-specific
   tasks on Orchestrator dispatch. They MUST NOT initiate work
   autonomously.
5. The Security Agent is the ONLY agent that may act without
   Orchestrator dispatch (for continuous monitoring and alerts).

---

## Rationale

### R1. Why five agents, not two, four, or eight

**Two agents** (coordinator + worker) was considered. Rejected because
it conflates security enforcement with either coordination or execution,
making it impossible to maintain a clean security boundary that survives
compromise of the other agent.

**Four agents** (without the Task Agent) was the initial design.
Extended to five because the SysAdmin Agent operates on system
infrastructure (packages, drivers, config) while user-delegated
productive work (research, content creation, file management) requires
a fundamentally different capability set (`net:egress`, `web:search`,
`fs:write` scoped to user paths). Collapsing both into the SysAdmin
would violate least privilege: a single agent holding both `pkg:install`
and `web:search` has an unnecessarily broad attack surface. The Task
Agent's filesystem scope (user paths only) and the SysAdmin's scope
(system paths only) produce a clean, compiler-enforceable boundary
through capability path patterns.

**Eight agents** (splitting guidance into tutorial/Q&A/proactive,
splitting security into threat/compliance/perf) was considered. Rejected
because: (a) the inter-agent communication overhead scales quadratically
with agent count (5 agents = 10 pairs vs 8 agents = 28 pairs); (b) the
capability model becomes harder to audit; (c) the additional granularity
does not provide meaningful security isolation beyond what five agents
offer. Sub-specialization within an agent (e.g., the Task Agent having
separate handlers for web search vs. file management) is an internal
concern, not an agent-topology concern.

**Five agents** maps cleanly to five non-overlapping responsibility
domains (coordinate, explain, operate, protect, research) and produces
a capability matrix where each column has a clear "MUST NOT hold" set.

### R2. Why the Security Agent has veto rather than a separate policy layer

A policy layer (e.g., a WASM-based policy engine evaluated at dispatch
time) was considered. Rejected because: (a) a policy engine cannot
perform continuous monitoring — it only evaluates at decision points;
(b) a policy engine cannot detect emergent threats (e.g., a sequence of
individually-harmless actions that constitute an attack); (c) the
Security Agent needs state (threat context, performance baselines,
historical patterns) that a stateless policy engine cannot maintain.

The Security Agent incorporates deterministic policy rules (from NCIP-007
escalation taxonomy) as its inner decision engine, but adds stateful
threat monitoring and performance profiling that a pure policy layer
cannot provide.

### R3. Why Emergency Recovery requires physical presence

Remote Emergency Recovery would allow a compromised remote session to
bypass High-Risk protections — exactly the attack that High-Risk Mode
is designed to prevent. Physical presence ensures that the override
requires an attacker to have physical access to the device, which
elevates the attack to adversary class A5 (`docs/04a-threat-model.md`)
and brings it within the TEE threat model.

### R4. Why the Guidance Agent replaces nexacore-helper rather than wrapping it

An intermediate layer (nexacore-helper sits between user and Guidance Agent)
was considered. Rejected because: (a) the Guidance Agent and nexacore-helper
have identical responsibility domains — user interaction, need
detection, explanation, autonomy management; (b) an intermediate layer
adds latency and complexity without adding capability; (c) the NCIP-007
primitives (Impact Dashboard, escalation taxonomy, autonomy levels)
are exactly the tools the Guidance Agent needs. The Guidance Agent IS
nexacore-helper with an explicit position in the five-agent topology.

---

## Backwards Compatibility

### Existing crate: `nexacore-agent`

The current `crates/nexacore-agent/src/lib.rs` scaffold declares five empty
modules (`agent`, `policy`, `context`, `budget`, `sandbox`). This NCIP
restructures the crate to add five agent implementations. The existing
modules are preserved as shared infrastructure:

| Existing module | Kept as | Used by |
|----------------|---------|---------|
| `agent` | `agent.rs` — `Agent` trait + `AgentKind` enum | All five agents |
| `policy` | `policy.rs` — per-agent policy declarations | All five agents |
| `context` | `context.rs` — per-agent persistent context | All five agents |
| `budget` | `budget.rs` — per-agent compute budget | All five agents |
| `sandbox` | `sandbox.rs` — WASM sandbox | All five agents |

New modules added: `orchestrator.rs`, `guidance.rs`, `sysadmin.rs`,
`security.rs`, `message.rs`, `mode.rs`.

### Existing crate: `nexacore-helper`

NCIP-007 specifies `crates/nexacore-helper/` as the reference implementation.
With this NCIP, `nexacore-helper` functionality is absorbed into the Guidance
Agent within `crates/nexacore-agent/src/guidance.rs`. The `crates/nexacore-helper/`
crate SHOULD be deprecated and re-exported as a thin facade over
`nexacore-agent::guidance` for any downstream consumers, then removed in
Phase 3.

### No breaking changes to Phase 1 or Phase 2 crates

This NCIP does not modify any Phase 1 kernel interface or Phase 2 AI
Runtime Service interface. The agent framework is a userspace concern
that consumes the runtime services (inference pipeline, tokenization,
tensor dispatch) via their public APIs.

---

## Test Cases

### T1. Agent bootstrap

- **T1.1** System boot MUST instantiate exactly five agents with IDs
  `orch`, `guid`, `sadm`, `secp`, `task`.
- **T1.2** Each agent MUST have a non-overlapping capability set as
  defined in §S1.2.
- **T1.3** Each agent MUST have its own KV-cache partition and compute
  budget allocation.

### T2. Orchestrator dispatch

- **T2.1** A `guidance`-class intent MUST be dispatched to the Guidance
  Agent and MUST NOT reach the SysAdmin or Security Agent.
- **T2.2** A `composite` intent (e.g., "install X and explain what it
  does") MUST be decomposed into an `administration` step dispatched to
  SysAdmin followed by a `guidance` step dispatched to Guidance.
- **T2.3** A `security`-class intent MUST preempt pending `guidance` and
  `administration` tasks in the priority queue.

### T3. Standard Mode behavior

- **T3.1** The Security Agent MUST produce risk warnings for operations
  matching the NCIP-007 escalation taxonomy.
- **T3.2** The user MUST be able to proceed with an operation despite a
  Security Agent warning.
- **T3.3** The Security Agent MUST NOT block any action in Standard Mode.

### T4. High-Risk Mode behavior

- **T4.1** Activating High-Risk Mode MUST require user authentication.
- **T4.2** In High-Risk Mode, the Orchestrator MUST submit every
  dispatch to the Security Agent for pre-authorization.
- **T4.3** A Security Agent veto MUST block the action; the user MUST
  NOT be able to override the veto through normal interaction.
- **T4.4** A veto notification MUST include the risk classification,
  violated policy, and alternative actions.
- **T4.5** The `Autonomous` autonomy level MUST be disabled in High-Risk
  Mode; only `Guided` and `Inform` are available.

### T5. Emergency Recovery Mode

- **T5.1** Emergency Recovery MUST NOT be activatable via remote session
  (SSH, network API, mesh).
- **T5.2** Emergency Recovery MUST require multi-factor authentication.
- **T5.3** Emergency Recovery MUST expire after the configured duration
  (default: 15 minutes).
- **T5.4** All actions during Emergency Recovery MUST be tagged
  `emergency_override: true` in the audit log.
- **T5.5** After 3 activations within 24 hours, Emergency Recovery MUST
  be locked until system reboot with hardware token.

### T6. Orchestrator failure

- **T6.1** If the Orchestrator misses 3 consecutive heartbeats (15
  seconds), the Security Agent MUST assume degraded coordinator role.
- **T6.2** In degraded mode, only `security`-class operations MUST be
  processed.
- **T6.3** The user MUST be notified of degraded mode via the Guidance
  Agent.
- **T6.4** The Security Agent MUST attempt to restart the Orchestrator
  (up to 3 attempts).
- **T6.5** After 3 failed restarts, the system MUST enter safe mode.

### T7. Inter-agent capability isolation

- **T7.1** The Orchestrator MUST NOT be able to execute an `fs:write`
  operation (capability not held).
- **T7.2** The Guidance Agent MUST NOT be able to install a package
  (capability not held).
- **T7.3** The SysAdmin Agent MUST NOT be able to veto an action
  (capability not held).
- **T7.4** A capability escalation attempt by any agent MUST be
  detected and blocked by the capability system.

### T8. Task Agent

- **T8.1** A `task`-class intent (e.g., "find me a laptop with 32GB
  RAM") MUST be dispatched to the Task Agent.
- **T8.2** The Task Agent MUST NOT be able to write to system paths
  (`/system/**`) — capability scoping MUST reject the attempt.
- **T8.3** The Task Agent MUST NOT be able to install packages
  (capability not held).
- **T8.4** In High-Risk Mode, every external request (web search, API
  call) MUST be pre-authorized by the Security Agent.
- **T8.5** Every external request MUST be logged in the audit log with
  URL, tokenized query, response size, and timestamp.
- **T8.6** Background tasks MUST be cancellable by the user; partial
  results MUST be preserved on cancellation.
- **T8.7** Task results MUST be returned to the Orchestrator, NOT
  presented directly to the user.

---

## Reference Implementation

### Crate structure

```
crates/nexacore-agent/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Agent trait, AgentKind enum, registry, boot
│   ├── agent.rs            # Agent trait definition + lifecycle (spawn, suspend, resume, kill)
│   ├── orchestrator.rs     # Orchestrator: intent analysis, dispatch, priority queue
│   ├── guidance.rs         # Guidance: NCIP-007 integration, explanations, tutorials
│   ├── sysadmin.rs         # SysAdmin: system operations, pkg, drivers, mesh
│   ├── security.rs         # Security: monitoring, veto, perf optimization
│   ├── task.rs             # Task: research, content creation, file mgmt
│   ├── message.rs          # AgentMessage, MessageKind, inter-agent protocol
│   ├── mode.rs             # OperationalMode (Standard, HighRisk, EmergencyRecovery)
│   ├── policy.rs           # Per-agent policy declarations
│   ├── context.rs          # Per-agent persistent context store
│   ├── budget.rs           # Per-agent compute budget tracking
│   └── sandbox.rs          # WASM sandbox (shared infrastructure)
└── tests/
    ├── bootstrap.rs        # T1: agent instantiation
    ├── dispatch.rs         # T2: orchestrator routing
    ├── standard_mode.rs    # T3: advisory security
    ├── high_risk_mode.rs   # T4: veto enforcement
    ├── emergency.rs        # T5: recovery mode
    ├── failover.rs         # T6: orchestrator failure
    ├── capability.rs       # T7: isolation enforcement
    └── task_agent.rs       # T8: task agent behavior
```

### Development timeline

This NCIP is targeted for Phase 2 Sprint 3+ (after the AI Runtime
Service foundation is functional). The agents depend on the inference
pipeline (`nexacore-runtime`), tokenization service (`nexacore-tokenization`),
and tensor HAL (`nexacore-hal::tensor`) established in Sprints 1–2.

| Sprint | Scope |
|--------|-------|
| Sprint 3 | Agent trait, `AgentKind` enum, `AgentMessage` protocol, `OperationalMode` enum, Orchestrator dispatch skeleton |
| Sprint 4 | Guidance Agent with NCIP-007 primitives, SysAdmin Agent operation categories, Security Agent monitoring skeleton |
| Sprint 5 | High-Risk Mode veto mechanism, Emergency Recovery Mode, inter-agent capability isolation tests |
| Sprint 6 | Integration with `nexacore-runtime` inference pipeline, end-to-end test (intent → dispatch → execute → explain) |

Estimated effort: **5–7 engineer-months** for v0.1 (five agents with
Standard and High-Risk modes operational, Emergency Recovery functional).

---

## Security Considerations

### SC1. Orchestrator as attack target (A1, A2)

The Orchestrator receives all user intents, making it the primary
attack surface for prompt injection (adversary class A2 from
`docs/04a-threat-model.md`). Mitigations:

- The Orchestrator operates under the dual-LLM pattern: it is the
  "planner" that never sees raw untrusted content (§S6.2).
- The Orchestrator holds no destructive capabilities (`fs:write`,
  `pkg:install`); compromising it yields coordination control but
  not direct system access.
- The Security Agent monitors the Orchestrator independently and can
  detect anomalous dispatch patterns (e.g., rapid escalation attempts,
  unusual dispatch targets).

### SC2. Security Agent compromise (A1, A4)

If the Security Agent itself is compromised, High-Risk Mode protections
are voided. Mitigations:

- The Security Agent runs in its own WASM sandbox / process boundary,
  isolated from other agents.
- The Security Agent's capability set does not include `fs:write`
  (except for security policy files) or `pkg:install`, limiting the
  blast radius of a compromise.
- The audit log is append-only and tamper-evident (Merkle tree); a
  compromised Security Agent cannot retroactively alter the log.
- TEE attestation of the Security Agent's binary measurement provides
  integrity verification at boot and on demand.

### SC3. Inter-agent privilege escalation (A1)

An agent could attempt to escalate privileges by forging capability
tokens or by exploiting inter-agent message passing. Mitigations:

- All capability tokens are signed by the kernel (TPM-bound master
  key); agents cannot forge tokens.
- All inter-agent messages are validated by the receiver; a message
  with invalid or insufficient capabilities is rejected.
- The capability system enforces Macaroons-style attenuation: an
  agent can only delegate capabilities it holds, and only to
  narrower scopes.

### SC4. Emergency Recovery as attack vector (A5)

Emergency Recovery could be exploited by an attacker with physical
access (adversary class A5). Mitigations:

- Multi-factor authentication required.
- Rate-limited (3 per 24 hours).
- Time-bounded (maximum 60 minutes).
- Full audit trail with `emergency_override: true` tagging.
- Physical presence requirement means remote attackers cannot trigger it.

### SC6. Task Agent external access (A1, A2, A4)

The Task Agent has `net:egress` and `web:search` capabilities, making
it the agent with the broadest external attack surface. Mitigations:

- Every outgoing query is tokenized via `nexacore-tokenization` to strip
  PII before egress.
- Every external interaction consumes privacy budget; the Security
  Agent can block further egress when budget is exhausted.
- In High-Risk Mode, every external request requires Security Agent
  pre-authorization.
- The Task Agent has no system-level capabilities (`pkg:install`,
  `sys:configure`); a compromised Task Agent can access user files
  and external resources but cannot modify system infrastructure.
- External responses are taint-tagged as `untrusted` and processed
  under the dual-LLM quarantine boundary before reaching the
  Orchestrator.

### SC5. Mode transition attacks

An attacker could attempt to force a transition from High-Risk to
Standard Mode to remove the Security Agent's veto. Mitigations:

- Mode transition from High-Risk to Standard MUST require the same
  authentication level as High-Risk activation.
- Mode transitions are audit-logged.
- Automatic High-Risk activation (via triggers) cannot be
  automatically deactivated — only manual deactivation is allowed
  for trigger-activated High-Risk Mode.

---

## Privacy Considerations

### PC1. Agent-level data isolation

Each agent has its own KV-cache partition and persistent context store.
PII processed by the SysAdmin Agent (e.g., user configuration data)
MUST NOT leak to the Guidance Agent's context or vice versa. The
per-agent isolation boundary is enforced by the WASM sandbox and
capability system, satisfying GDPR Article 5(1)(b) purpose limitation.

### PC2. Audit log PII exclusion

Audit log entries for agent actions MUST NOT contain PII values.
Structured metadata (agent ID, action type, risk classification,
timestamp) is permitted. Entity class labels (e.g., "email_address")
without the actual value are permitted. This continues the policy
established in NCIP-Phase2-Entry-021 §PC5.

### PC3. High-Risk Mode veto notifications

Veto notifications (§S3.2) MUST NOT include the PII content that
triggered the veto. The notification MUST describe the risk in terms
of entity classes and policy rules, not data values. Example: "Blocked:
this action would send an email_address entity to an unapproved egress
host" — NOT "Blocked: this action would send john@example.com to
api.example.com".

### PC4. Guidance Agent explanation privacy

The Guidance Agent generates plain-language explanations using the
local Tier-0 model (per NCIP-007 §5). Explanations MUST NOT include
PII from other agents' contexts. When explaining a SysAdmin action
that involved PII, the Guidance Agent MUST use tokenized references
or entity class labels.

### PC6. Task Agent query privacy

Every external query made by the Task Agent reveals user intent
(search terms, comparison criteria, file organization preferences).
Mitigations:

- Outgoing queries MUST be tokenized to replace PII entities with
  opaque tokens before egress.
- Query metadata (search terms excluding PII) is logged in the audit
  log for traceability but MUST NOT be exported off-device.
- The Task Agent's privacy budget is separate from the SysAdmin
  Agent's; exhausting one does not affect the other.
- Background monitoring tasks MUST declare their privacy budget
  impact at creation time via the Impact Dashboard.

### PC5. Emergency Recovery audit as PII risk

The post-recovery audit report (§S3.3) documents all actions taken
during the override window. If those actions involved PII, the report
MUST tokenize PII values before storage, consistent with
`nexacore-tokenization` pipeline requirements.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
