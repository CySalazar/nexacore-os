# NexaCore OS — Brand Strategy

**Status:** Draft v0.1
**Last updated:** 2026-05-13
**Authoritative scope:** brand positioning, naming architecture, voice & tone, messaging hierarchy.
**Language of record:** English. Dutch translation produced only for statutory documents filed with the Kamer van Koophandel.
**Out of scope of this document:** visual system (logos, palette, typography). Those live in `brand/mood-boards/` (selection phase) and then in `brand/logos/`, `brand/colors/`, `brand/typography/`, `brand/icons/` once a direction is approved.

> This document is read together with [`docs/01-vision.md`](../docs/01-vision.md) and [`docs/05-governance.md`](../docs/05-governance.md). In case of conflict with those documents, those documents prevail and this file is updated to match.

---

## 1. Naming architecture (dual brand)

> **Entity status (2026-07-04):** the legal form of the project's entity — foundation (`Stichting`), company, or a dual foundation + operating-company structure — is **under evaluation**. The `NexaCore Foundation` / `Stichting NexaCore` identities below document the foundation option and are contingent on that decision. Until it is made, public materials use only `NexaCore OS` and name no legal entity.

NexaCore operates with three identities serving three distinct purposes. They are deliberately distinct so legal compliance, international brand, and product communication can each be optimized without compromising the others.

| Role | Identity | Authority | Where it appears |
|---|---|---|---|
| **Product** | `NexaCore OS` | Operational | Source code, technical docs, READMEs, CLI banner, kernel `uname`, releases |
| **International brand / "doing business as"** | `NexaCore Foundation` | Communications | Website, social, press releases, sponsor materials, grant applications outside NL |
| **Legal entity** | `Stichting NexaCore` | Statutory | KVK registration, notarial deed (`statuten`), Dutch tax filings, contracts, ANBI documentation |
| **Full lockup (formal)** | `NexaCore Foundation — Stichting NexaCore, Amsterdam` | First-mention in formal materials | Imprint, contract preambles, annual report cover |

### 1.1 Why three names, not one

This is the **Mozilla model** applied verbatim: legally `Mozilla Foundation` (a 501(c)(3)), publicly just `Mozilla`. The split lets the legal entity carry the regulatory burden (`Stichting` in Dutch civil code, ANBI requirements, KVK filings) while the public-facing identity stays linguistically clean and internationally legible.

### 1.2 Capitalization and spelling rules

- `NexaCore` is always set in **all-caps**, no exceptions. It is treated as an initialism, not an acronym (we do not expand it). Setting `NexaCore` or `nexacore` in body copy is a brand error.
- `OS` is always **all-caps** when paired with `NexaCore`. `NexaCore Os` and `NexaCore os` are brand errors.
- `NexaCore OS` carries a **non-breaking space** between the two tokens in HTML and typeset documents (`NexaCore&nbsp;OS`). They are conceptually one word.
- `Stichting NexaCore` — `Stichting` is initial-cap (Dutch proper-noun convention), `NexaCore` all-caps. Never abbreviate to `St. NexaCore`.
- `NexaCore Foundation` — both words initial-cap on the second token (`Foundation`, never `foundation`).
- Possessive: `NexaCore OS's kernel` (apostrophe-s), never `NexaCore OS' kernel`. For the foundation: `the Foundation's bylaws`, never `Stichting NexaCore's bylaws` in body copy.
- Plural: there is no plural of `NexaCore OS`. To refer to many instances we say `NexaCore OS nodes`, `NexaCore OS instances`, or `the mesh`.

### 1.3 First-mention pattern

In any formal external document (press release, grant application, contract, op-ed, conference paper), first mention of the foundation must be one of:

- `NexaCore Foundation (Stichting NexaCore, Amsterdam)` — preferred for international audiences;
- `Stichting NexaCore ("NexaCore Foundation")` — preferred when the Dutch legal identity is the lead.

In informal materials (blog, social, internal Slack-equivalent) just `NexaCore Foundation` is enough; the legal form is implied.

### 1.4 Trademark posture

Per the Foundation bylaws (Article 10.3), trademarks are held by the Foundation under a **public trademark policy permitting fair use, forks, and derivative works that maintain protocol compatibility**. This is non-negotiable and shapes the brand: we will never enforce trademarks against protocol-compliant forks or independent NexaCore OS distributions. A forks-welcome posture is a **brand asset**, not a brand risk.

---

## 2. Positioning

### 2.1 Category

NexaCore OS does not fit neatly into an existing operating-system category. We define a new one:

**AI-native operating system** — an OS whose kernel and runtime treat inference, model orchestration, and intelligent agents as first-class system primitives, on par with processes, files, and sockets.

We use this category label consistently. We do not call NexaCore OS a "Linux distribution", a "privacy OS", an "AI tool", a "platform", a "framework", or a "decentralized network". Each of those framings is technically defensible but strategically misleading.

### 2.2 Positioning statement (canonical, internal)

> For **mainstream users** who want the full power of modern AI **without surrendering their data to centralized providers**, **NexaCore OS** is the **AI-native operating system** that runs intelligence locally by default and federates compute over a peer-to-peer mesh of attested nodes. Unlike cloud-AI platforms, **privacy is enforced cryptographically at the protocol layer** — not as a policy commitment that can be quietly walked back.

This statement is not for external publication verbatim. It is a north star for derivative messages.

### 2.3 Reasons to believe (RTBs)

When asked "why should I believe this is real and not vapor", we point to these in order:

1. **A 25-year horizon, publicly committed.** Sunset dates for founder authority (2031-05-09), trustee terms, and protocol guarantees are anchored in signed Git commits and (eventually) in a Dutch notarial deed.
2. **Privacy by construction, not by policy.** PII tokenization at the OS API level, format-preserving encryption for routing metadata, zk-SNARK compliance proofs on every payload, TEE-only decryption envelopes.
3. **Hardware-rooted trust.** Mesh participation requires attestable TEE (Intel TDX, AMD SEV-SNP, ARMv9 CCA, Apple Silicon SE). No best-effort fallback.
4. **Forks-welcome governance.** The protocol is CC0. The codebase is Apache-2.0. Any captured Foundation can be forked and rejoin the mesh on equal terms.
5. **Anti-capture funding policy.** No government money. No government-aligned entities. Annual audited financials.

### 2.4 Competitive frame

We do not have direct competitors at the OS-native scope. Adjacent projects we compare against:

| Adjacent project | What we say |
|---|---|
| **Cloud-AI providers** | "Capable, but your data is their telemetry. We give you the same class of capabilities running on your hardware." |
| **Local-AI runtimes (Ollama, LM Studio, llama.cpp)** | "Excellent for single-machine inference. NexaCore OS extends this to OS primitives and to federated compute across attested peers." |
| **Distributed inference (Petals, Hivemind, Exo)** | "Prior art we build on. NexaCore OS makes federation a first-class OS service, not a Python library." |
| **Apple Private Cloud Compute** | "Brilliant TEE-attested confidential inference, single vendor. NexaCore OS generalizes the same pattern to peer-to-peer across vendors." |
| **Linux distributions** | "Linux is a kernel optimized for the pre-AI world. NexaCore OS is a new microkernel optimized around AI primitives." |
| **Privacy OSes (Tails, Qubes, GrapheneOS)** | "We share their threat-model rigor. We are not a hardened Linux; we are a new system for mainstream use." |

### 2.5 Anti-positioning (what we never claim)

- ❌ "**A decentralized AI**" — conflates protocol federation with crypto framing. Use "peer-to-peer mesh of attested nodes".
- ❌ "**Privacy-first**" alone — pair with the cryptographic mechanism.
- ❌ "**Web3** / **decentralized** / **trustless**" — crypto-finance baggage.
- ❌ "**Faster / cheaper than cloud AI**" — we will lose those benchmarks and don't care.
- ❌ "**A community of cypherpunks** / **digital sovereignty movement**" — alienates the 10M mainstream-user goal.

---

## 3. Mission, vision, purpose

### 3.1 Mission (one sentence — funders & policy audiences)

> NexaCore Foundation develops and maintains NexaCore OS — an AI-native, privacy-by-construction, decentralized operating system — and stewards its governance in the public interest under an irrevocable Mission Anchor.

### 3.2 Vision (one sentence — mainstream audiences)

> A world where everyone has the full power of modern AI on a computer they actually control.

### 3.3 Purpose narrative (long form — about-page, manifesto)

The current generation of operating systems was designed before modern AI. Today AI capabilities are bolted on top — accessed through cloud APIs owned by a handful of companies, with the user's data as the implicit currency. We accept this because the alternative looks like running a model on your laptop with a fraction of the capability.

NexaCore OS proposes a different paradigm. AI runs locally by default. The operating system itself is the orchestrator. Computational scale is achieved by federating with other NexaCore OS instances over a peer-to-peer mesh — collective compute among people running the same software, not a service rented from a corporation. Privacy is not a setting in a menu; it is the only thing the protocol knows how to do. Non-compliant nodes cannot produce valid messages — it is mathematics, not policy.

We are building for the next 25 years. The decisions we make this year are evaluated on whether they will still be defensible in 2051. Stability of design comes before speed of delivery. Forks are welcome. The Foundation is structurally unable to capture the project.

---

## 4. Brand personality

We pick five attributes.

### 4.1 The five attributes

**1. Patient.**
*Language:* Long-horizon phrasing ("25-year horizon", "generational", "sunsets in 2031"). We avoid urgency.
*Design:* Generous whitespace. No motion design suggesting velocity. Stable type weights.

**2. Rigorous.**
*Language:* Every claim names its mechanism. Numbers cited. Specifications with line references.
*Design:* Visible grid system. Consistent type scale on a defined ratio. Labeled, source-cited diagrams.

**3. Severe.**
*Language:* Short sentences. No filler. Uncomfortable truths tolerated. No exclamation marks ever.
*Design:* Tight letterspacing. High-contrast palettes. Minimal ornament. Decorative illustration forbidden.

**4. Open.**
*Language:* We document the decision behind the decision. ADRs, NCIPs, signed commits, audit reports.
*Design:* Source files for every artifact. Logos as SVG with construction grids. Tokenized colors.

**5. Honest.**
*Language:* Name the risks. `AWAITING_CRYPTO_REVIEW` markers stay until they don't apply.
*Design:* Status labels (Draft, Active, Final) are part of the document chrome.

### 4.2 Anti-personality (what we are not)

| We are not | Looks like |
|---|---|
| **Excited** | Exclamation marks, neon palettes, motion design that pulses, superlative taglines |
| **Friendly-startup** | First-person plural "we love you", mascots, rounded sans display fonts, gradients |
| **Cypherpunk-aesthetic** | Black-and-green CRT terminals, Matrix references, glitch effects, "join the resistance" copy |
| **Corporate-confident** | Stock photography, polished testimonials, "trusted by" logo walls, flat-illustrations |
| **Crypto-finance** | Token charts, "decentralized" as marketing leitmotif, web3 vocabulary, hexagonal honeycomb |

---

## 5. Tone & voice

### 5.1 The voice rules

1. **Name the mechanism.** Don't say "secure"; say what makes it secure. Every benefit claim must point to a mechanism, a spec section, or an audit.
2. **Short sentences. Then a longer one for rhythm.** Average sentence length 14–18 words.
3. **No exclamation marks. Ever.** Including in error messages, social posts, and informal chat.
4. **No metaphors of war, religion, sport, or family.** No "battle", "fight", "crusade", "tribe", "mission-critical sacred trust".
5. **The reader is competent.** We address developers and technical readers as peers.
6. **Sound the same in 5 years.** Avoid trend vocabulary ("vibes", "agentic", "moat", "10x", "superhuman").
7. **Hedge precisely or not at all.** "Probably secure" is forbidden.
8. **Cite yourself.** Internal cross-references use stable file paths, not floating descriptions.

### 5.2 Tone matrix (situational)

| Situation | Formality | Warmth | Technical density |
|---|---|---|---|
| Source code comments | Medium | Low | Maximum |
| Technical docs (`/docs/`, NCIPs, ADRs) | High | Low | High |
| Funding application / grant draft | High | Medium | Medium |
| Annual report / Foundation governance | Maximum | Medium | Low–Medium |
| Press release | Maximum | Low | Medium |
| Blog post / op-ed | Medium | Medium | High |
| Social post (X, Mastodon, Bluesky) | Medium | Medium | Medium |
| Community Q&A / mailing list reply | Medium | High | High |
| Incident communication / security advisory | Maximum | Low | High |
| Error message / CLI output | Medium | Low | High |

### 5.3 Person and address

- Default **first-person plural** (`we`) when speaking as the Foundation or the project.
- Default **second person** (`you`) when speaking to the developer reader of technical docs.
- Avoid **first-person singular** (`I`) except in signed posts from named individuals.
- Never use the **royal we** for an individual.

### 5.4 Tense

- Technical docs use the **present tense** for what the system does.
- Roadmap and governance documents use **dated future** ("Trustees are elected via NCIP starting 2031-05-09").
- Marketing copy uses the **present tense** for capabilities that ship in `main`. Future capabilities are explicitly marked.

---

## 6. Messaging hierarchy

### 6.1 Tagline (canonical, ≤ 8 words)

**`An AI-native operating system. Local-first. Decentralized.`**

Variant for very short contexts (social bio, email signature):

**`Local-first AI for a computer you actually control.`**

### 6.2 Payoff (≤ 16 words, sits under the wordmark)

**`AI as a system primitive — running on hardware you own, federating with peers who prove their compliance.`**

### 6.3 30-second pitch

> NexaCore OS is an AI-native operating system. It treats inference, model orchestration, and intelligent agents the way classical operating systems treat processes and files — as kernel-level primitives. AI runs locally by default. When you need more compute than your machine has, NexaCore OS federates with other instances over a peer-to-peer mesh of attested nodes — collective compute among people running the same software, not a service you rent. Privacy is enforced cryptographically at the protocol layer. We are building for the next 25 years.

### 6.4 60-second pitch

> Today's operating systems were designed before modern AI. AI capabilities are bolted on as cloud services, with the user's data as the implicit currency. NexaCore OS proposes a different paradigm: an operating system where AI is a first-class kernel primitive, runs locally by default, and federates compute over a peer-to-peer mesh of cryptographically-attested nodes rather than over commercial cloud APIs. Privacy is enforced by the protocol, not by policy — a non-compliant node cannot produce valid mesh traffic because the cryptography won't let it. The project is stewarded by NexaCore Foundation, a Dutch foundation (Stichting NexaCore, Amsterdam) under an irrevocable Mission Anchor. Founder authority sunsets in 2031. The codebase is Apache-2.0; the protocol specifications are public domain. Forks are first-class citizens by design. The target is mainstream — 10M users on a 25-year horizon — not just security researchers.

### 6.5 Audience-specific message variants

| Audience | Lead with | Anchor proof | Close with |
|---|---|---|---|
| **Developer / early adopter** | "Inference, mesh, attestation are kernel primitives — written in Rust from scratch." | Repo, NCIP archive, RFC test vectors | "Read [`/docs/02-architecture.md`](../docs/02-architecture.md). Open a Draft NCIP." |
| **Enterprise / sovereign tech buyer** | "Hardware-attested confidential inference at OS-native scope." | Security model, threat model, crypto audit | "Commercial license available via Stichting NexaCore." |
| **Funder / grant officer** | "An anti-capture operating system, stewarded under an irrevocable Mission Anchor." | Bylaws, funding policy, BDFL sunset, ANBI | "See the funding policy ([`docs/08-funding-policy.md`](../docs/08-funding-policy.md))." |
| **Journalist / policy writer** | "The first OS designed natively around AI, governed so no single entity can capture it." | Three-layer governance, signed sunset dates | "Background interview available. PGP-signed responses preferred." |
| **Community / mailing list** | "We ship slow. We document the decisions behind decisions. We welcome forks." | Code of Conduct, CONTRIBUTING, NCIP-Process-001 | "Sign your commits with DCO. Read the NCIP. Open a Draft." |

---

## 7. Storytelling pillars

Five recurring narratives we anchor across content.

1. **The 25-year horizon.** Stability of design over speed of delivery.
2. **Privacy as mathematics, not policy.** Cryptographic enforcement vs. policy enforcement.
3. **Forks as the ultimate guarantee.** A project structurally welcoming its own forks is more trustworthy.
4. **The mesh as collective compute.** Compute as a peer cooperative — without cryptocurrency framing.
5. **Anti-capture as design constraint.** Funding policy, governance layers, Mission Anchor, trademark policy interlock so no one can capture.

---

## 8. Lexicon — owned and rejected

### 8.1 Words we own

`AI-native`, `local-first`, `privacy by construction`, `mesh`, `attestation`, `TEE`, `peer-to-peer`, `compliance proof`, `Mission Anchor`, `generational`, `25-year horizon`, `NCIP`, `BDFL sunset`, `forks-welcome`, `cryptographic envelope`, `protocol-compliant`, `seed node`, `blessed model`, `attested node`, `quadratic vote`, `proof-of-uptime`, `proof-of-contribution`.

### 8.2 Words we reject

- `decentralized` *as a marketing leitmotif on its own* — always pair with a mechanism.
- `blockchain`, `token`, `web3`, `DAO`, `tokenomics`, `staking` — we are explicitly **not** a cryptocurrency project.
- `trustless` — misleading. Use `cryptographically verifiable` instead.
- `agentic`, `vibes`, `superhuman`, `10x`, `moat`, `disruptive` — trend vocabulary.
- `bulletproof`, `unhackable`, `unbreakable`, `military-grade` — security marketing clichés real cryptographers distrust.
- `revolutionary`, `paradigm shift`, `game-changer`, `next-generation` — exclamation-mark equivalents.
- `mission-critical` — corporate-confident vocabulary.
- `cypherpunk`, `crypto-anarchist`, `digital sovereignty` *as movement labels* — too narrow.

### 8.3 Word pairs we always get right

| Wrong | Right |
|---|---|
| `NexaCore`, `NexaCore`, `nexacore`, `NexaCoreOS`, `NexaCore OS` | `NexaCore OS` (with non-breaking space) |
| `Stichting NexaCore` | `Stichting NexaCore` |
| `the NexaCore Foundation` | `NexaCore Foundation` (or `the Foundation` after first mention) |
| `decentralized AI` | `peer-to-peer mesh of attested nodes` |
| `secure by design` | `private by construction` or `secure under threat model X` |
| `military-grade encryption` | name the primitive (e.g., `ChaCha20-Poly1305 AEAD`) |
| `our users` | `people running NexaCore OS`, `the community`, `developers` |
| `we plan to / we hope to / soon` | `scheduled for Q3 2026 (see roadmap §X)` |

---

## 9. Application guidance

### 9.1 Which brand goes where

| Context | Brand | Notes |
|---|---|---|
| Source code, technical docs, READMEs | `NexaCore OS` | Product identity. |
| Public website | `NexaCore Foundation` + product `NexaCore OS` | Foundation is publisher; NexaCore OS is product. |
| Press release | First `NexaCore Foundation (Stichting NexaCore)`, then `NexaCore Foundation` | Boilerplate carries `Stichting NexaCore, Amsterdam` + KVK number. |
| International grant | `NexaCore Foundation` | Cover letter discloses Dutch legal form. |
| Dutch grants (NLnet) | `Stichting NexaCore ("NexaCore Foundation")` | Dutch legal form leads. |
| Annual report | `NexaCore Foundation — Stichting NexaCore, Amsterdam` on cover | Both forms used inside. |
| Contract / commercial license | `Stichting NexaCore` | Always the legal form. |
| Social media bios | `NexaCore Foundation` | One sentence summary. |
| Email signature (Foundation staff) | `NexaCore Foundation | Stichting NexaCore, Amsterdam` | Two lines. |
| Founder personal | `cySalazar` | Pseudonym in all project-scoped communications. |

### 9.2 Co-branding (sponsors, audit partners, funders)

- Acknowledgement format: `NexaCore Foundation gratefully acknowledges [Funder] for [grant ID].`
- Logo lockups: external logo right of NexaCore Foundation wordmark, separated by 2-rem rule. Never composite without separator.
- Endorsement walls: forbidden. Funders listed in transparency report only.

### 9.3 Forks and derivative works

- Forks may use `NexaCore OS` if protocol-compliant. Encouraged to add a qualifier (`NexaCore OS — Acme Edition`).
- Protocol-incompatible forks may not use `NexaCore OS` in their name. May use `derived from NexaCore OS`.
- The Foundation will not initiate trademark enforcement against good-faith uses.

---

## 10. Boilerplate and standard paragraphs

### 10.1 The 60-word "about us" block

> NexaCore Foundation (Stichting NexaCore, Amsterdam) builds NexaCore OS — an AI-native, privacy-by-construction, peer-to-peer operating system. Privacy is enforced cryptographically at the protocol layer; mesh participation requires attestable hardware. The Foundation operates under an irrevocable Mission Anchor and accepts no funding from governments or government-aligned entities. Source code is Apache-2.0; protocol specifications are public domain. Forks are first-class citizens.

### 10.2 The single-sentence about

> NexaCore Foundation builds NexaCore OS — an AI-native operating system that runs intelligence locally by default and federates compute over a peer-to-peer mesh of cryptographically-attested nodes.

### 10.3 The technical one-liner

> NexaCore OS is a Rust microkernel that treats AI inference and peer-to-peer mesh federation as first-class system primitives, with privacy enforced by cryptographic compliance proofs and TEE-bound decryption.

### 10.4 The funding one-liner

> NexaCore Foundation, a Dutch public-interest foundation, develops NexaCore OS — an AI-native operating system designed to give individuals access to modern AI without surrendering their data to centralized providers — under an irrevocable Mission Anchor, with annual audited financials and a forks-welcome trademark policy.

---

## 11. Open questions

- **Q1 — Tagline lock-in.** Confirm with Foundation board (when constituted) before tagline appears on physical artefacts.
- **Q2 — Dutch-language style guide.** Produce `STRATEGY-NL.md` once notarial deed is filed.
- **Q3 — Press / media kit.** `brand/press-kit/` to be added before first external grant deadline.
- **Q4 — Pronunciation guide.** `NexaCore` = `/ˈɒm.ni/` (UK) or `/ˈɑːm.ni/` (US). Not letter-by-letter.
- **Q5 — Mascot / character art.** Out of scope for v0.1 per anti-personality §4.2.

---

## 12. Document maintenance

- **Owner:** Lead Architect (cySalazar) for years 1–5. After 2031-05-09, the Foundation's Director.
- **Review cadence:** Annually, or whenever a brand-affecting decision lands in `/docs/` or `/ncips/`.
- **Update policy:** This file is the authoritative brand strategy. Subsidiary files must reference this file by stable path.

---

*End of brand strategy v0.1. The visual system lives separately in `brand/logos/`, `brand/colors/`, `brand/typography/`, `brand/icons/`.*
