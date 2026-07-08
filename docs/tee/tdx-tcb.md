# Intel TDX — TCB management and TCB-recovery procedure

**Status:** Living document (WS10-01.9)
**Scope:** Intel TDX backend (`nexacore-tee::tdx`), the platform-TCB evaluation
in [`tdx::tcb`](../../crates/nexacore-tee/src/tdx/tcb.rs), and the operational
procedure operators follow when Intel publishes a TCB recovery.
**Refs:** the development plan WS10-01, ADR-0052 (decode pipeline is unrelated; the TEE
trait surface is in `crates/nexacore-tee`), `docs/04-security-model.md`,
`docs/07-hardware-requirements.md`.

## 1. What the TCB is

The **Trusted Computing Base (TCB)** of a TDX platform is the set of
security-relevant components whose versions are attested in a quote:

- the **TDX module** (SEAM) — measured as `MRSEAM` / `MRSIGNERSEAM`;
- the **SEAM micro-architectural state** and CPU microcode — summarised by the
  16 **`TEE_TCB_SVN`** components in the TD report body;
- the **Provisioning Certification Enclave** — its **`PCE_SVN`** in the quote
  header.

A verifier does not trust a platform because it *says* it is patched; it trusts
it because the **quote proves** the SVNs, and Intel's signed **TCB-Info**
collateral states which SVN combinations are still considered up to date.

## 2. How NexaCore evaluates the TCB

`tdx::tcb::TcbInfo::evaluate` implements the Intel Quote-Verification-Library
algorithm exactly:

1. The platform SVNs are taken from the quote
   (`PlatformTcb::from_quote(header, body)`).
2. The TCB-Info levels are walked **newest-first**.
3. The platform earns the status of the **first** level it meets — meaning all
   16 `TEE_TCB_SVN` components are `>=` the level's requirement **and** the
   `PCE_SVN` is `>=` the level's requirement.
4. If it meets no level it is `Unrecognized` (below every published level).

The resulting [`TcbStatus`] is one of `UpToDate`, `ConfigurationNeeded`,
`OutOfDate`, `OutOfDateConfigurationNeeded`, `Revoked`, or `Unrecognized`. A
strict verifier accepts only `UpToDate` (`TcbStatus::is_trusted`); a policy that
tolerates `ConfigurationNeeded` is an explicit, logged operator decision.

The TCB-Info document is itself **signed by Intel** (the TCB-Signing chain to the
Intel SGX Root CA); that signature is verified by the same ECDSA/X.509 path as
the PCK chain ([`tdx::pck`]) before the levels are trusted. `tdx::tcb` operates
on already-authenticated collateral.

## 3. The TCB-recovery procedure

A **TCB recovery** is the event in which Intel discloses a vulnerability,
ships a fix (microcode and/or a TDX-module update), and publishes new TCB-Info
that demotes the now-vulnerable SVN levels to `OutOfDate` (or `Revoked`). When a
recovery is announced, operators of NexaCore TDX nodes follow this procedure.

### 3.1 Detect

- The mesh attestation verifier begins returning a non-`UpToDate`
  [`TcbStatus`] for affected peers as soon as the refreshed TCB-Info is pulled.
- The node's self-attestation (`attest` → local quote → self-evaluate) reports
  the demotion for the **local** platform.

### 3.2 Refresh collateral

1. Pull the new **TCB-Info** and **PCK CRLs** for the platform's `FMSPC` from
   the Intel PCS / the local PCCS cache.
2. Verify the new collateral's Intel signature (PCK/TCB-Signing chain) before
   installing it. Never act on unsigned collateral.
3. Replace the cached `TcbInfo` used by `evaluate`.

### 3.3 Remediate the platform

1. Apply the BIOS/microcode update that raises the CPU `TEE_TCB_SVN` /
   `PCE_SVN`, and/or load the updated TDX module that raises `MRSEAM`.
2. Reboot affected TDs so a **fresh quote** reflects the new SVNs.
3. Re-run self-attestation and confirm the platform is `UpToDate` again.

### 3.4 Re-establish mesh trust

- TDs whose quotes still show the demoted TCB are **failed closed** by the
  verifier policy (no Tier-1 mesh capabilities; originate/consume-only per the
  software-only profile, see WS10-08).
- Once a node re-attests `UpToDate`, its mesh capabilities are restored on the
  next handshake; the 64-byte report-data binding ([`tdx::quote::bind_transcript_hash`])
  ties the fresh quote to the new handshake transcript so a stale quote cannot
  be replayed.

### 3.5 Grace window

Operators may configure a bounded grace window during which `OutOfDate` peers
retain reduced privileges to avoid a fleet-wide outage during staged patching.
The window, the privileges retained, and the deadline are an explicit,
audit-logged policy — never an implicit default. After the deadline, `OutOfDate`
is treated as `Revoked`.

## 4. Failure modes and invariants

- **Never trust an unrecognised or revoked TCB.** `Unrecognized` / `Revoked`
  always fail closed regardless of grace policy.
- **Collateral freshness.** TCB-Info and CRLs have a `nextUpdate`; expired
  collateral fails closed until refreshed.
- **Local demotion is honest.** A node that cannot reach `UpToDate` reports its
  own reduced trust tier rather than masking it — consistent with the project's
  transparency principle.

[`TcbStatus`]: ../../crates/nexacore-tee/src/tdx/tcb.rs
[`tdx::pck`]: ../../crates/nexacore-tee/src/tdx/pck.rs
[`tdx::quote::bind_transcript_hash`]: ../../crates/nexacore-tee/src/tdx/quote.rs
