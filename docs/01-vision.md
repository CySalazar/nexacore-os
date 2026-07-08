# Vision and Principles

**Status:** Draft v0.1

## Mission

NexaCore OS aims to be the first operating system designed natively around artificial intelligence — where inference, model orchestration, and intelligent agents are first-class system primitives, on par with processes, files, and sockets.

It exists because the current generation of operating systems was designed before modern AI. Today, AI capabilities are bolted on top: cloud services accessed through APIs, language models living in chat applications, and computation happening in datacenters owned by a small number of corporations.

NexaCore OS proposes a different paradigm: AI runs locally by default, the operating system itself is the orchestrator, and computational scale is achieved by federating with other NexaCore OS instances rather than relying on commercial cloud providers.

## Target audience

NexaCore OS targets **mainstream users** — individuals, professionals, small organizations — not just security researchers or technical enthusiasts.

**Adoption goal:** 10 million+ users on a generational timeline (25+ years).

This shapes design priorities: usability cannot be sacrificed for ideology. Security and privacy must be invisible defaults, not configuration burdens.

## Core principles (in priority order)

### 1. Security
Every component is designed with explicit threat models. Defaults are paranoid; relaxations require explicit user consent. Hardware-rooted security (TEE attestation) is mandatory for any operation that crosses trust boundaries.

### 2. Stability
A 25-year horizon demands stability of architecture, interface, and semantics. Breaking changes are expensive and reserved for security-critical evolution. APIs are versioned; deprecations are gradual; protocol versions negotiate at handshake.

### 3. Performance
Within the bounds of security and stability, the system optimizes for tokens-per-second-per-watt rather than raw cycles. AI inference latency is a first-order metric.

## Operating principles

### Local-first
Nothing leaves the device by default. Cloud is opt-in, granular, and always visible. The user's data, models, and computation reside on hardware they control. When external compute is needed, it flows preferentially through the NexaCore OS mesh — collective compute among NexaCore OS instances — before considering commercial providers.

### Privacy by construction
The mesh protocol enforces privacy cryptographically. PII is tokenized at the OS API level. Encrypted-by-default data types are mandatory at the network layer. A non-compliant node is rejected by the network — not by policy decision but by mathematical impossibility of producing valid messages.

This is a stronger guarantee than "policy says so": even a malicious node cannot produce network traffic that would leak PII, because the cryptographic envelope of every message requires compliance proofs that an attacker cannot forge without breaking the underlying cryptography.

### Decentralization as a means
The project is decentralized to achieve privacy and resist capture. It is not decentralized for ideological purity. Pragmatic centralization is acceptable where it makes the system more secure, more stable, or more accessible, provided it does not compromise the cryptographic privacy guarantees.

### Open evolution
The protocol is public. Any implementation that conforms to it can interoperate. Forks are not just tolerated but welcomed: they are the ultimate guarantee against capture of the project's direction.

### Generational thinking
Decisions are evaluated on 25-year horizons. Quick wins that compromise long-term integrity are rejected. The project is built to outlive its founders.

## What NexaCore OS is NOT

To prevent scope creep and clarify identity:

- **Not a Linux distribution.** NexaCore OS is a custom Rust microkernel, written from scratch. Linux compatibility may exist as a userspace compatibility layer, but it is not central.
- **Not a cryptocurrency project.** The mesh has compute credits for accounting, but no speculative token, no public blockchain, no token sale.
- **Not a closed ecosystem.** The protocol is open, the source is open (Apache-2.0), forks are first-class citizens.
- **Not an experimental research toy.** NexaCore OS is built for production use by real people.
- **Not a fork of an existing OS.** It is a new system.

## Anti-goals

NexaCore OS will explicitly NOT pursue:

- Compatibility with surveillance-friendly architectures (e.g., backdoor-by-design APIs, exceptional access mechanisms).
- Funding from governments or government-aligned entities (see [funding policy](./08-funding-policy.md)).
- Adoption-at-all-costs that would compromise core principles.
- Vendor lock-in patterns of any kind.
- Closed-source dependencies in the trusted computing base.

## Relationship to existing projects

NexaCore OS draws inspiration from, and may interoperate with, several existing projects, but is a distinct system:

- **Linux/BSD**: prior art in OS architecture; NexaCore OS does not derive from these.
- **seL4, Redox**: prior art in Rust/microkernel design; NexaCore OS may share design patterns but not code.
- **Tor, Signal**: prior art in privacy protocols; NexaCore OS adopts similar threat-model rigor.
- **Petals, Hivemind, Exo**: prior art in distributed inference; NexaCore OS extends these concepts to OS-native scope.
- **Apple Private Cloud Compute**: prior art in TEE-attested confidential inference; NexaCore OS generalizes to peer-to-peer.

The intent is not to compete with any of these, but to occupy a previously empty design space: an operating system whose primary identity is AI-native, privacy-by-construction, and decentralized.
