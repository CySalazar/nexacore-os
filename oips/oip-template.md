---
ncip: XXX
title: <One-line, sentence-case, no trailing period>
track: <Standards Track | Process | Informational | Meta>
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: YYYY-MM-DD
updated: YYYY-MM-DD
requires: []
supersedes: ~
superseded-by: ~
discussion: <URL of the GitHub issue or forum thread>
license: CC0-1.0
---

<!--
  AUTHOR IDENTITY POLICY (PRIVACY-FIRST PROJECT)
  ----------------------------------------------
  This NCIP is released into the public domain under CC0-1.0 (see ## Copyright). The frontmatter
  `authors:` field BECOMES PERMANENT PUBLIC RECORD on merge — right-to-erasure is honored only
  by replacement-with-pseudonym + Editors' Report notice (per NCIP-Process-001 §11), NOT by
  removal. Choose accordingly at filing time, not after.

  STRONGLY RECOMMENDED for all contributors:
    - Use a project-scoped pseudonym (e.g., `cySalazar`) instead of a legal name.
    - Use a dedicated email tied to the pseudonym (e.g., `hello@nexacoreos.com`) — not a
      personal mailbox tied to your civil identity.
    - You MAY use a PGP fingerprint or SSH signing-key fingerprint as the contact instead of an
      email, for stronger long-term linkability without leaking a mailbox.

  The editor body never requires a legal-name disclosure. Pseudonymity is supported by design.

  HOW TO USE THIS TEMPLATE
  ------------------------
  1. Copy this file as `ncip-<slug>-XXX.md` (slug is a 1–3-word kebab-case tag derived from the
     title; XXX is a placeholder — editors assign the global number on Last Call → Active).
  2. Replace EVERY field in the frontmatter. Set `status: Draft` initially. Leave optional fields
     (`requires`, `supersedes`, `superseded-by`, `updated`) as `~` (YAML null) if not applicable.
  3. Fill in EVERY section below. Sections marked "Required" must have substantive content;
     sections marked "Required, may be N/A" can contain `N/A — <one-line reason>` if the NCIP
     genuinely has no content for that section.
  4. Do not delete sections. The CI lint (`scripts/lint-ncips.py`) will fail if any required
     section is missing.
  5. Read `ncips/README.md` and `ncip-process-001.md` before submitting.
-->

## Abstract

<!--
  Required. 100–250 words. A non-technical, accurate summary of what this NCIP proposes. Anyone
  reading only this section should understand WHAT changes and WHY, but not HOW.
-->

TODO

---

## Motivation

<!--
  Required. Why is this NCIP being filed? What problem does it solve, what gap does it close,
  what risk does it mitigate? Include concrete evidence (incidents, benchmarks, user reports,
  threat-model gaps) where relevant. Avoid generalities; cite specific facts.
-->

TODO

---

## Specification

<!--
  Required. The normative core. Use RFC 2119 keywords (MUST, SHOULD, MAY). Be precise enough
  that two independent implementers would produce interoperable artifacts.

  For Standards Track NCIPs, this section MUST include:
  - Wire format / data structures (with byte layouts where applicable).
  - State transitions / protocol steps.
  - Error conditions and recovery.
  - Versioning / negotiation.

  For Process / Meta NCIPs, this section MUST include:
  - Procedural rules with explicit triggers and outcomes.
  - Roles, authorities, and tenure.

  For Informational NCIPs, this section is descriptive (no MUST/SHOULD).
-->

TODO

---

## Rationale

<!--
  Required. Why this design and not alternatives? Document at least 2 alternatives considered
  and the trade-offs that led to the chosen one. Include explicit "what we are NOT doing and
  why" if the negative space matters.
-->

TODO

---

## Backwards Compatibility

<!--
  Required, may be "N/A — first introduction, no prior behavior". Otherwise: list every
  pre-existing component this NCIP changes; describe migration path; identify breakage and the
  affected user/operator class.
-->

TODO

---

## Test Cases

<!--
  Required for Standards Track; may be "N/A — process change, no testable invariant" for Process
  / Meta / Informational. For Standards Track, link to a test suite or include illustrative
  vectors. For Meta NCIPs that introduce procedural changes, document a "dogfood test" — show
  that the NCIP itself satisfies the rules it imposes.
-->

TODO

---

## Reference Implementation

<!--
  Required for Standards Track; may be "N/A" for non-code NCIPs. For Standards Track, this
  section MUST link to a working branch / PR / crate. For Process NCIPs that introduce tooling
  (e.g., new CI check), link to the implementation here.
-->

TODO

---

## Security Considerations

<!--
  Required, NEVER "N/A". Every NCIP — even purely process-oriented — has security implications
  (e.g., changing the editor body changes the trust base). Document:
  - Threats this NCIP introduces, mitigates, or shifts.
  - Assumptions on the threat model (cite `docs/04a-threat-model.md` adversary classes).
  - Failure modes and their blast radius.
  - Cryptographic considerations (key management, side channels) where applicable.
-->

TODO

---

## Privacy Considerations

<!--
  Required, NEVER "N/A". Document:
  - Personal data flows introduced or changed.
  - Metadata exposure (timing, size, routing).
  - Linkability / unlinkability properties.
  - GDPR / regulatory implications (data minimization, purpose limitation, retention).
-->

TODO

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
