# Security Policy — NexaCore OS

> **Trust is mathematically required, not socially assumed.**
> NexaCore OS is built on the premise that security must be provable, not declared.
> Security researchers are first-class collaborators on this project.

This document is the **canonical responsible-disclosure policy** for NexaCore OS.
It is binding on the project maintainers and on any researcher who follows it
in good faith. Everything in this file is versioned in git; changes are
auditable.

---

## 1. Scope

### 1.1 In scope

The following classes of issue MUST be reported through this policy:

- **Protocol vulnerabilities** in any specification under `/docs/protocol/`,
  `/docs/03-mesh-protocol.md`, or any merged NCIP that defines wire format
  or cryptographic procedures.
- **Implementation bugs** in any crate under `/crates/` that have security
  consequences: memory safety, capability bypass, attestation forgery,
  cryptographic misuse, side channels, denial of service, etc.
- **Supply-chain issues:** typosquatted dependencies, compromised crates in
  the dependency graph, `Cargo.lock` tampering, build-time code injection,
  CI workflow exfiltration.
- **TEE attestation failures:** Quote forgery, replay, downgrade, freshness
  bypass for any of the supported backends (Intel TDX, AMD SEV-SNP, ARM CCA,
  Apple Secure Enclave / Private Cloud Compute pattern).
- **Capability system flaws:** privilege escalation through token
  attenuation, scope confusion, revocation bypass, signature malleability.
- **Compliance-proof flaws:** any issue that breaks the
  zero-knowledge / soundness guarantees of the compliance proof system
  (per `/docs/04-security-model.md`).
- **Privacy regressions:** any path that causes raw PII to leave a TEE
  envelope or to be logged outside of an authorized audit context.

### 1.2 Out of scope

The following are NOT eligible under this policy and should be reported
upstream instead:

- Vulnerabilities in third-party dependencies that already have a published
  RustSec advisory and a fix available — open an upstream issue and let us
  know via the normal channel; we will track the bump in our advisory list.
- Bugs that require physical access to a device whose TEE attestation is
  already compromised (assumed adversary capability outside our threat model).
- Social engineering of project maintainers, contributors, or users.
- Spam / abuse on community forums (handled by `CODE_OF_CONDUCT.md`).
- Theoretical attacks below the cryptographic security parameter (e.g.,
  hypothetical 2^120 attacks on a 128-bit primitive). These are interesting
  research; please publish them.

---

## 2. How to report

### 2.1 Primary channel

- **Email:** `security@nexacoreos.com`
  - Reports are handled directly by the project founder.
- **Subject line:** `[NexaCore OS Security] <one-line summary>`
- **Encryption:** PGP encryption is **strongly preferred** for any report
  that contains exploit details, working PoC code, or sensitive data.

### 2.2 PGP key

- **Fingerprint:** `<TBD: PGP key generation pending legal-entity establishment>`
- **Key servers:** `keys.openpgp.org`, `keyserver.ubuntu.com`
  (will be published on at least two keyservers when generated)
- **Key file in repo:** `/security/pgp-public-key.asc`
  (will be added to the repository before any external audit engagement)
- **Verification:** the fingerprint will be published independently in
  - the project README,
  - a signed git tag (`security-key-v1`),
  - the founder's verified social profiles.

  Researchers should verify the key against **at least two** of these
  sources before encrypting an exploit.

### 2.3 What to include in a report

A useful security report includes:

1. **Affected component(s)** — crate name, version, commit hash if known.
2. **Vulnerability class** — memory safety, crypto misuse, capability
   bypass, attestation forgery, etc.
3. **Reproduction steps** — minimal PoC, environment requirements.
4. **Impact** — what an attacker gains, under what trust assumptions, with
   what prerequisites.
5. **Suggested mitigation** — if you have one. We will not credit you less
   for not providing one.
6. **Disclosure preference** — preferred timeline, credit name, public
   write-up plans.

---

## 3. Service Level Agreement

We commit to the following SLAs, measured from the moment a report is
received at the email address in Section 2.1:

| Phase                  | SLA              | Action                                                              |
|------------------------|------------------|---------------------------------------------------------------------|
| **Acknowledgement**    | within **72 h**  | Human reply confirming receipt and assigning a tracking ID.         |
| **Triage**             | within **7 days**| Severity classification (Section 4), preliminary scope of impact.   |
| **Status updates**     | every **14 days**| Progress note while the issue is open.                              |
| **Fix or disclosure plan** | within **90 days** | Either a patch released, or a written, dated disclosure plan agreed with the reporter. |

### 3.1 Severity-adjusted timelines

For **Critical** severity (Section 4), we aim for:

- Acknowledgement within **24 h**.
- Patched release or coordinated public disclosure within **45 days**.

These are targets, not guarantees, while the project is solo-maintained
(pre-Phase 1 hiring per `/docs/06-roadmap.md`). Reporters will be informed
in writing if a target slips, with a revised commitment.

### 3.2 Reporter-driven extensions

If the reporter and the project agree that a longer embargo is justified
(e.g., the bug requires coordinated multi-vendor patching), we will extend
the timeline in writing. **The reporter retains the right to publish at
the agreed embargo end** — we will not unilaterally request open-ended
embargoes.

---

## 4. Severity classification

We use **CVSS v4.0** (Common Vulnerability Scoring System) for severity
scoring. Reports without a researcher-supplied score will receive one
during triage; the final score is the project's responsibility.

| Severity     | CVSS v4.0 base | Triage example                                                    |
|--------------|----------------|--------------------------------------------------------------------|
| **Critical** | 9.0 – 10.0     | TEE attestation forgery; unauthenticated capability escalation across nodes; cryptographic root compromise. |
| **High**     | 7.0 – 8.9      | Capability privilege escalation within a node; kernel memory disclosure; mesh-handshake KCI. |
| **Medium**   | 4.0 – 6.9      | Local DoS in a userspace service; non-trivial side channel; logged-PII regression. |
| **Low**      | 0.1 – 3.9      | Hardening recommendation; defense-in-depth gap; minor information leak below sensitivity threshold. |

For each accepted report, the project will:

- Open a private security advisory on GitHub (or equivalent).
- Apply the `kind:security` label to any tracking issues.
- Publish a CVE-aligned advisory at fix time, citing the reporter unless
  they request anonymity.

---

## 5. Safe harbor

NexaCore OS supports good-faith security research. If you act in compliance
with this policy, the project commits:

- **No legal action.** We will not initiate or support any legal action
  against you for activities that fall within this policy, including
  reverse engineering, fuzzing, and PoC development against the OSS
  codebase or your own deployments.
- **No DMCA / takedown requests** for write-ups that follow the agreed
  disclosure timeline.
- **No retaliation against employers, collaborators, or affiliates**
  associated with the research.

This safe harbor is bound by:

- **No PII access.** Do not access, exfiltrate, or modify data belonging
  to other users or third parties. Use synthetic data only.
- **No service degradation** of public infrastructure beyond what is
  strictly necessary to demonstrate the issue.
- **No social engineering** of users, contributors, or staff.
- **Compliance with applicable law** in your jurisdiction. We cannot
  promise immunity from third-party legal action, only our own.

If you are uncertain whether a planned action falls within this policy,
**ask first** — we treat scoping questions as cooperative, not adversarial.

---

## 6. Coordinated disclosure

For issues that affect multiple downstream projects (e.g., a flaw in a
shared dependency), we will coordinate with:

- **RustSec** for advisories affecting Rust crates we depend on.
- **CERT/CC** or equivalent national CERTs when government infrastructure
  may be affected (note: governments are excluded as funding sources per
  `/docs/08-funding-policy.md`, but coordinated disclosure to protect
  end-users is unrelated to funding boundaries).
- **Hardware vendors** (Intel, AMD, ARM, Apple) for TEE-specific issues.

We will not embargo a fix to favor a specific commercial licensee
(see `COMMERCIAL-LICENSE.md` § 3 — commercial licensees receive priority
*advisories synchronized with* public disclosure, not ahead of it).

---

## 7. Hall of fame & bounty

The formal bounty program is defined by [`NCIP-Bounty-002`](./oips/oip-bounty-002.md)
(filed 2026-05-10, currently in `Draft`; lifecycle per
[`NCIP-Process-001` §4](./oips/oip-process-001.md)). The NCIP specifies severity-tiered payout
ranges (Critical €5K–€50K, High €1K–€10K, Medium €250–€2.5K, Low €50–€500), eligibility
filters with a 6-month contributor guard, conflict-of-interest disclosure, payment mechanics
including privacy-preserving cryptocurrency options, public-arbitration dispute resolution,
and a 24-month retroactive-payout commitment from the Activation Date (the day the project
legal entity's bank account opens with an approved disbursement procedure).

Until NCIP-Bounty-002 reaches `Active` and the Activation Date is met, the program runs in
**non-monetary mode**:

- **Hall of fame:** researchers who report valid issues are credited in
  the advisory and, with consent, in `CONTRIBUTORS.md` under "Security
  Researchers".
- **Monetary rewards:** deferred. Reports that would qualify for monetary payout per
  NCIP-Bounty-002 §3 once Active are recorded with their would-be payout amount in the
  internal bounty ledger and become payable retroactively per §6.1 of that NCIP.

---

## 8. What this policy does NOT do

- It does **not** authorize you to test third-party deployments of NexaCore OS
  without the operator's permission. Each deployment is a separate authorization.
- It does **not** modify the Apache-2.0 license terms. The license still applies.
- It does **not** create an attorney-client relationship between you and
  the project.

---

## 9. Change history

- 2026-05-09 — Initial policy. Founder solo-maintains; SLA targets reflect
  current capacity. PGP key fingerprint marked TBD until Stichting
  incorporation.

---

## 10. Cross-references

- [`LICENSE`](LICENSE) — Apache-2.0 governs the codebase.
- [`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md) — commercial support &amp; certification terms (not a dual license).
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — general contribution flow.
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — community behavior policy.
- [`/docs/04-security-model.md`](docs/04-security-model.md) — design-level security model.
- [`/docs/04a-threat-model.md`](docs/04a-threat-model.md) — STRIDE / LINDDUN threat model.

---

*Reports sent through this channel are handled with the same seriousness
as a production incident. If you don't get a 72 h acknowledgement, ping
the founder directly via the fallback address — the silence is a bug, not
a feature.*
