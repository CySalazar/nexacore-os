<!--
  NexaCore OS — NCIP / ADR cover template
  Direction: C — Civic Tech / Generational
  Use:       Copy the YAML block + the introduction block as the head of a new
             NCIP file in /ncips/ or a new ADR in /docs/adr/.
  Authoritative: oips/oip-process-001.md
-->

---
ncip: NNNN                                            # NCIP-NNNN (4-digit, zero-padded)
title: "Short imperative title (≤ 80 chars)"
status: Draft                                        # Draft | Review | Last Call | Active | Final | Withdrawn | Superseded | Rejected
category: Standards Track                            # Standards Track | Process | Informational | Meta
author: "cySalazar <hello@nexacoreos.com>"
created: 2026-05-13
discussions-to: https://github.com/CySalazar/nexacore-os/discussions/NNN
requires: []                                         # list of NCIP numbers this depends on
supersedes: []                                       # list of NCIP numbers this replaces
layer: 1                                             # 1 (Protocol) | 2 (Specification) | 3 (Operational)
breaks-layer-1: false                                # true triggers 66.7% supermajority + BDFL veto applicability
---

<!--
  ── COVER BLOCK ──────────────────────────────────────────────────
  Replace the placeholder content below. Keep the section order and headings;
  they are required by ncips/ncip-process-001.md §3 (canonical NCIP structure).
  ─────────────────────────────────────────────────────────────────
-->

# NCIP-NNNN · Short title

<p align="center"><img alt="NexaCore OS" src="../brand/logos/nexacore-os-stacked.svg" width="120"></p>

> **One-sentence abstract.** State, in a single sentence, what this NCIP proposes and why. If you cannot do this in one sentence, the NCIP is not yet scoped.

<table>
  <tr>
    <td><strong>Status</strong></td>
    <td><code>Draft</code></td>
    <td><strong>Layer</strong></td>
    <td>Layer 1 — Protocol</td>
  </tr>
  <tr>
    <td><strong>Category</strong></td>
    <td>Standards Track</td>
    <td><strong>Author</strong></td>
    <td>cySalazar</td>
  </tr>
  <tr>
    <td><strong>Created</strong></td>
    <td>2026-05-13</td>
    <td><strong>Discussion</strong></td>
    <td><a href="https://github.com/CySalazar/nexacore-os/discussions/NNN">#NNN</a></td>
  </tr>
</table>

---

## 1. Motivation

What is the problem this NCIP addresses? Cite the specific docs, code paths, or community discussions that surfaced it. Avoid generalities — the more specific the motivation, the easier the review.

## 2. Specification

The normative content. Use **MUST**, **SHOULD**, **MAY** per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) when describing required behavior. Include diagrams where it reduces ambiguity. Avoid sample code in this section unless it is normative.

## 3. Rationale

Why this specific design? Discuss alternatives considered and the reasons they were rejected. This section is where reviewers find the *decision behind the decision*.

## 4. Backwards compatibility

What breaks if this NCIP is adopted? What is the migration path? If nothing breaks, say so explicitly. Standards Track NCIPs that break Layer 1 cryptographic guarantees require 66.7% supermajority per `ncip-process-001.md` §5.

## 5. Reference implementation

Required for Standards Track. Link to a PR, a branch, or a code path. Not required for Process / Informational / Meta.

## 6. Security considerations

A first-class section. List every security property this NCIP modifies, threats introduced, and threats mitigated. Reference [`docs/04-security-model.md`](../../docs/04-security-model.md) where relevant.

## 7. Privacy considerations

A first-class section. Privacy is enforced cryptographically (per Mission Anchor); this section is the audit trail showing the NCIP preserves that.

## 8. Test vectors

Required for Standards Track that introduce or modify cryptographic behavior. Cite RFC test vectors where applicable; otherwise produce your own and commit them to `tests/`.

## 9. Copyright

This NCIP is released into the public domain under [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/), per [`oip-process-001.md`](../../oips/oip-process-001.md) §10.

---

<p align="center">
  <sub>
    NCIP-NNNN · <code>Draft</code> · 2026-05-13 · <a href="../STRATEGY.md">brand</a> · <a href="../../oips/oip-process-001.md">process</a>
  </sub>
</p>
