---
ncip: 16
title: TEE user-space driver — Intel TDX + AMD SEV-SNP backends, attestation channel
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-20
updated: 2026-05-20
activated: 2026-05-20
requires:
  - 13
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

`NCIP-Driver-Framework-013` § S7 enumerates the TEE backend driver as the
third first-party deliverable. This NCIP — `NCIP-Driver-TEE-016` — promotes
the current `StubAttestation` placeholder (introduced in MB13.c, used by
`nexacore-capability::Ed25519CapabilityProvider`) to a **real, kernel-mediated
TEE driver** running as a user-space process.

The driver targets two trust domains:

- **Intel TDX** — Trust Domain Extensions, available on Intel Xeon
  Sapphire Rapids (4th-gen) and later. Attestation via the **TDREPORT** →
  **Quote Generation Service (QGS)** path.
- **AMD SEV-SNP** — Secure Encrypted Virtualization with Secure Nested
  Paging, available on AMD EPYC Milan (3rd-gen) and later. Attestation via
  the **SNP_GET_REPORT** → AMD Secure Processor verification path.

A single driver process — `nexacore-driver-tee` — selects the appropriate
backend at boot based on CPU vendor + capability MSR probing, then exposes
a unified **attestation service channel** (`nexacore.svc.tee.attest`) carrying
backend-agnostic primitives: `quote(nonce)`, `seal(data, policy)`,
`unseal(blob)`, `measurement()`, `info()`.

The driver replaces `StubAttestation` in `crates/nexacore-kernel/src/
capabilities.rs::Ed25519CapabilityProvider::verify_signed_token` (MB13.c):
the kernel-side verifier acquires a real TEE-attested quote and binds it
to the issued capability token, rather than the static placeholder bytes
currently in use.

Hardware availability constraint: TDX-capable and SEV-SNP-capable hardware
is not in the founder's hands at filing time. The NCIP nonetheless locks
the contract so that the implementation can be validated against vendor
documentation today, and against real hardware as soon as access is
secured (per the backlog § P5 funding-dependent). A **third backend**
(`nexacore-tee/stub`, `#[cfg(test)]`-only) preserves the test path so
host-side unit tests continue to pass.

---

## Motivation

### M1. The Phase 1 "TEE attestation" deliverable is missing the substance

`docs/06-roadmap.md` § "Phase 1" lists "TEE" as a deliverable. The current
state (post-MB13.c) is a stub that returns a hard-coded `Quote` blob
sufficient to exercise the verification API but not bound to any real
hardware measurement. An auditor reading the codebase finds:

- `Ed25519CapabilityProvider::verify_signed_token` calls
  `StubAttestation::verify`, which always returns success.
- The "TEE binding" in capability tokens is therefore decorative.
- The kernel's claim "this token was issued by a process running in a
  measured trust domain" is not true — it is issued by any process.

This NCIP closes that gap by inserting a real attestation step.

### M2. A user-space TEE driver matches the microkernel posture

The TDX/SEV-SNP ABIs are large and evolving (Intel TDX module v1.5 vs
v2.0, AMD SEV-SNP API rev 1.55 vs 1.56, etc.). Keeping them in the kernel
inflates the TCB and forces a kernel rebuild on every TEE firmware update.

A user-space TEE driver:
- Stays out of the kernel TCB. A compromised TEE driver process leaks
  attestation tokens but does not compromise other processes (capability
  scope isolation per NCIP-013 § S1).
- Can be updated via `DriverUnload + DriverLoad` (signed image swap)
  without a kernel rebuild.
- Lets the kernel speak to "the TEE" via a single channel
  (`nexacore.svc.tee.attest`), independent of whether TDX or SEV-SNP is on
  the other side.

### M3. The kernel-side integration point already exists

MB13.c introduced `Ed25519CapabilityProvider` and the
`verify_signed_token(token, now)` method. Today it calls a stub. The
intercept point is one function: it calls the TEE driver via
`IpcSend(nexacore.svc.tee.attest, AttestRequest::Verify{...})` instead of
the stub. Replacing the call site is mechanical once the driver lands.

### M4. The "secure-by-default" property of NexaCore OS reduces to this driver

`docs/04-security-model.md` § "TEE attestation root of trust" hinges on
this driver being correct. The whole capability system, the mesh
handshake, the encrypted-by-default data types — all of them transitively
trust the TEE quote that this driver returns. Locking the contract here,
publicly, on a Standards Track NCIP, is the right cadence for a property
this load-bearing.

---

## Specification

> **Normative keywords.** RFC 2119 / RFC 8174 (MUST, MUST NOT, SHOULD,
> SHOULD NOT, MAY).

### S1. Manifest schema extension

The driver manifest (TOML v1, per `NCIP-Driver-Framework-013` § S5.1) MUST
include a top-level `[tee]` table:

```toml
[meta]
name           = "nexacore-driver-tee"
version        = "0.1.0"
nexacore_image_hash = "<64-hex BLAKE3>"
nexacore_signature  = "<base64 Ed25519, MUST be Stichting NexaCore signing key>"
nexacore_issuer_pubkey = "<base64 Ed25519>"

[capabilities]
# TDX: reads TDREPORT via SEAMCALL-equivalent (kernel-mediated)
# SEV-SNP: reads SNP_GET_REPORT via the AMD Secure Processor mailbox
mmio_regions  = [ ]      # backend-specific; populated dynamically at probe
dma_windows   = [ { iova_base = "0x0", len = "0x10000000" } ]   # 256 MiB
irq_lines     = [ ]      # rare; SEV-SNP firmware may signal via MSI on long ops
pci_devices   = [ ]      # not a PCI device
# The TEE driver also requires a NEW capability: Action::TeeProbe (see § S1.1)

[matchers]
# This driver has no PCI matcher; the kernel spawns it from a static
# inventory entry (see § S2).
pci_vendor_device = [ ]

[tee]
# Preferred backend ordering. The driver probes at boot and picks the
# first capability it can confirm. "stub" is only honored when the kernel
# is built with the `tee-stub` feature (test/dev).
backend_preference = [ "tdx", "sev-snp" ]   # never include "stub" in production
# Maximum quote size in bytes (used to size the response buffer pool)
quote_max_bytes = 4096
# Quote freshness window: a quote is considered fresh for this many seconds
# after generation; older quotes are refused on Verify
quote_freshness_sec = 600
```

**S1.1 (New capability action).** `NCIP-Driver-Framework-013` § S1 is
extended with one further `Action` variant for completeness (the
`#[non_exhaustive]` clause permits this without a wire-format break):

```rust
#[non_exhaustive]
pub enum Action {
    // ... existing variants from NCIP-013 § S1 ...
    TeeProbe,    // probe the local CPU for TEE capability and acquire backend access
}
```

The TEE driver process MUST hold a token with `Action::TeeProbe` on
`Resource::Any` to perform the boot-time probing. The token is minted
by the kernel at `DriverLoad` time based on the manifest declaration;
no user process other than the TEE driver itself is ever granted this
action.

### S2. The kernel "static inventory" entry

Unlike NVMe and network drivers, the TEE driver has no PCI device to
match. The kernel maintains a small **static inventory** of non-PCI
drivers that are spawned at boot if their manifest is present in the
known driver-issuer signed image set.

For v0.3 the inventory has one entry: `nexacore-driver-tee`. The kernel:

1. At boot, after PCI enumeration completes, checks the static inventory.
2. For each inventory entry, looks for the signed driver image at a
   well-known location (TBD; for now `kernel-runner` baked-in tarball
   image, future: `nexacore-pkg` per `NCIP-pkg-008`).
3. Spawns the driver via the normal `DriverLoad` path with manifest
   declaring `Action::TeeProbe`.

If the spawn fails (missing image, signature mismatch, TEE probing
returns no usable backend), the kernel falls back to the existing
`StubAttestation` for backward compatibility during the rollout
period (this fallback is itself a transient measure and MUST be removed
in a follow-up cleanup NCIP once the driver ships).

### S3. Backend selection at boot

The driver, upon spawn, executes the backend probe:

```rust
fn probe() -> Result<Backend, NoTee> {
    if cpu_vendor() == "GenuineIntel" && cpuid_leaf(0x21).is_some() {
        // TDX module presence is signaled by a non-zero leaf 0x21 result.
        if let Some(backend) = TdxBackend::init() {
            return Ok(Backend::Tdx(backend));
        }
    }
    if cpu_vendor() == "AuthenticAMD" && cpuid_leaf(0x8000001F).eax & 1 == 1 {
        // SEV bit set in CPUID 0x8000001F EAX.
        if let Some(backend) = SevSnpBackend::init() {
            return Ok(Backend::SevSnp(backend));
        }
    }
    #[cfg(feature = "tee-stub")]
    {
        return Ok(Backend::Stub(StubBackend::init()));
    }
    Err(NoTee)
}
```

`NoTee` propagates as a driver-exit code `2`. The kernel logs
`[driver-tee] no usable backend — falling back to StubAttestation` and
continues operation (see § S2 fallback policy).

### S4. Attestation service channel (`nexacore.svc.tee.attest`)

The driver registers a single service channel. ABI:

```rust
#[non_exhaustive]
pub enum AttestRequest {
    Quote {
        nonce: [u8; 64],          // RFC 9334 challenge nonce
        report_data: [u8; 64],    // measurement-bound caller-chosen data
        opaque_id: u64,
    },
    Seal {
        data: Vec<u8>,            // ≤ 256 KiB; bound to current TEE measurement
        policy: SealPolicy,
        opaque_id: u64,
    },
    Unseal {
        blob: Vec<u8>,            // result of a prior Seal
        opaque_id: u64,
    },
    GetMeasurement {
        opaque_id: u64,
    },
    GetInfo {
        opaque_id: u64,
    },
    Verify {                      // used by the kernel via Ed25519CapabilityProvider
        quote: Vec<u8>,
        expected_measurement: Option<[u8; 48]>,
        opaque_id: u64,
    },
}

#[non_exhaustive]
pub enum SealPolicy {
    BindToCurrentMeasurement,
    BindToMeasurementHash([u8; 48]),   // bind to a future measurement set
}

#[non_exhaustive]
pub enum AttestResponse {
    Quote {
        opaque_id: u64,
        quote_bytes: Vec<u8>,        // backend-specific encoded quote
        backend_kind: BackendKind,
        generated_at_unix: u64,
    },
    SealedBlob {
        opaque_id: u64,
        blob: Vec<u8>,
    },
    UnsealedData {
        opaque_id: u64,
        data: Vec<u8>,
    },
    Measurement {
        opaque_id: u64,
        m: [u8; 48],                 // SHA-384 of the trust domain image (TDX MRTD or SEV SNP measurement)
    },
    Info {
        opaque_id: u64,
        backend_kind: BackendKind,
        backend_version: u32,
        cpu_model: String,
    },
    VerifyOk {
        opaque_id: u64,
        measurement: [u8; 48],
        not_after_unix: u64,
    },
    Error {
        opaque_id: u64,
        code: AttestErrorCode,
        msg_static: &'static str,
    },
}

#[non_exhaustive]
pub enum BackendKind {
    IntelTdx,
    AmdSevSnp,
    Stub,
}

#[non_exhaustive]
pub enum AttestErrorCode {
    NoBackend,
    BackendFault,
    QuoteStale,
    InvalidNonce,
    SealTooLarge,
    UnsealMismatch,
    VerifyFailed,
    NotSupported,
    InvalidArgument,
}
```

### S5. Intel TDX backend specifics

**S5.1 (TDREPORT acquisition).** The driver issues a `TDG.MR.REPORT`
TDCALL (via a kernel-mediated trampoline because TDCALL is a privileged
instruction). Inputs: caller's 64-byte `REPORTDATA`. Output: 1024-byte
`TDREPORT` containing the trust domain's MRTD (Measurement of Trust
Domain), RTMR (Runtime Measurement Registers), and the report MAC.

**S5.2 (Quote generation).** The TDREPORT is converted to a remotely
verifiable Quote by the Intel **Quote Generation Service (QGS)** — a
process running outside the trust domain that signs the report with
Intel's PCK (Provisioning Certification Key). v0.3 of the NexaCore OS
TDX backend uses the **DCAP (Data Center Attestation Primitives)**
quote format.

**S5.3 (Kernel-mediated TDCALL).** The TDCALL instruction must execute
in Ring 0 of the trust domain. The user-space TEE driver cannot execute
it directly. The kernel exposes a syscall `SyscallNo::TeeTdcall = 74`
(reserved here, see `NCIP-Driver-Framework-013` Appendix A for the
editorial reconciliation of the `7x` driver-framework decade) that
takes the leaf number and registers, performs the TDCALL, and returns
the output registers. The syscall is capability-gated on
`Action::TeeProbe`.

**S5.4 (Backend caveats).** TDX module v1.5 vs v2.0 differ in TDREPORT
layout (v2.0 adds servtd_hash and operation flags). The driver MUST
parse the version-tagged header and dispatch accordingly. Hardware
without TDX module loaded returns `NoTee` at probe time (S3).

### S6. AMD SEV-SNP backend specifics

**S6.1 (SNP_GET_REPORT acquisition).** The driver issues the
`SNP_GUEST_REQUEST` MSR write (Ring 0, kernel-mediated as in S5.3) with
`SNP_MSG_REPORT_REQ` payload. The AMD Secure Processor returns the
attestation report (1184 bytes per AMD spec rev 1.55).

**S6.2 (Quote format).** The SEV-SNP report is itself the quote; no
additional QGS step. The report is signed by the VCEK (Versioned Chip
Endorsement Key) which chains back to AMD's PSP root.

**S6.3 (Kernel-mediated MSR access).** Same pattern as S5.3: a single
syscall `SyscallNo::TeeMsr = 75` (reserved, decade `7x` per
`NCIP-Driver-Framework-013` Appendix A) lets the driver request a
specific MSR-mediated SEV-SNP operation. Capability-gated.

**S6.4 (Backend caveats).** Pre-Milan EPYC supports SEV (the predecessor)
and SEV-ES but NOT SEV-SNP. The driver MUST verify the SNP-active bit
in `MSR 0xC0010131` before claiming SEV-SNP support; otherwise it falls
back (or returns `NoTee` if SEV-SNP is the only target).

### S7. Verify path (kernel integration)

`Ed25519CapabilityProvider::verify_signed_token` (MB13.c) currently calls
the in-tree `StubAttestation` struct. Post-NCIP-016 implementation, the
kernel SHOULD call the driver via the same `IpcSend` mechanism every other
client uses:

```rust
fn verify_signed_token(token: &CapabilityToken, now: u64) -> KernelResult<...> {
    // ... existing signature + time-window checks ...
    let resp: AttestResponse = ipc_send_blocking(
        "nexacore.svc.tee.attest",
        AttestRequest::Verify {
            quote: token.tee_quote.clone(),
            expected_measurement: KNOWN_MEASUREMENT_NexaCore_OS,
            opaque_id: 0,
        },
    )?;
    match resp {
        AttestResponse::VerifyOk { measurement, .. } => {
            if measurement != KNOWN_MEASUREMENT_NexaCore_OS {
                return Err(MeasurementMismatch);
            }
            Ok(/* subject from token payload */)
        }
        AttestResponse::Error { code, .. } => Err(code.into()),
        _ => Err(ProtocolError),
    }
}
```

`KNOWN_MEASUREMENT_NexaCore_OS` is a 48-byte SHA-384 baked into the kernel
at compile time (analogous to NCIP-013 `KNOWN_ISSUERS`). It is the
expected measurement of the NexaCore OS trust domain image and changes per
kernel release. A future NCIP MAY introduce a per-measurement allowlist
for staged rollouts.

### S8. Bring-up summary

1. Kernel spawns `nexacore-driver-tee` via static inventory (S2).
2. Driver probes for TDX / SEV-SNP backend (S3).
3. Driver registers `nexacore.svc.tee.attest` service channel.
4. Driver loops on incoming `AttestRequest`, dispatching to the chosen
   backend.
5. On `Verify` requests from the kernel `Ed25519CapabilityProvider`,
   the driver re-uses the backend to confirm the quote's signature
   and freshness, returning `VerifyOk` or `Error`.

---

## Rationale

### R1. Why a single driver covering both TDX and SEV-SNP

A naive design would ship two drivers: `nexacore-driver-tdx` and
`nexacore-driver-sev-snp`. We chose one for three reasons:

- **Mutual exclusion at boot.** Only one of TDX or SEV-SNP is ever
  active on a given CPU (vendor-specific). Shipping two binaries where
  exactly one runs is a manifest-and-static-inventory complication
  without benefit.
- **Backend-agnostic channel ABI.** The `nexacore.svc.tee.attest` channel
  must be identical for both backends or the kernel-side
  `Ed25519CapabilityProvider` has to branch. One driver = one channel
  shape = no branching.
- **Audit surface.** Two drivers double the auditor's surface;
  one driver with two backends is reviewable as a single artifact.

### R2. Why we keep the `StubAttestation` fallback during rollout

A flag day where the kernel hard-requires real attestation would brick
every dev machine without TDX/SEV-SNP hardware. The fallback path keeps
host-side tests passing and lets dev work continue. The fallback MUST be
removed in a follow-up cleanup NCIP once (a) the driver ships, (b) it has
been validated on real hardware. § S2 marks this as transient.

### R3. Why DCAP for TDX (not Intel SGX-style legacy attestation)

DCAP is Intel's modern, third-party-friendly quote format; the legacy
SGX EPID model relies on Intel-operated attestation services and is
deprecated for new designs. TDX uses DCAP natively.

### R4. Why no Apple Secure Enclave / ARM CCA in this NCIP

`docs/06-roadmap.md` lists Apple Silicon and ARMv9 CCA as Phase 5 / 7
targets, not Phase 1. Scope discipline.

### R5. Why a dedicated `Action::TeeProbe`

The TEE backend access primitives (TDCALL, SNP MSR writes) are uniquely
privileged. A naive design would use `Action::PciConfigRead` (since the
SEV-SNP mailbox is at a known address); we reject that because:

- TDCALL is not PCI-mediated at all.
- The blast radius of TDCALL is unique (entering / leaving the trust
  domain).

A dedicated action is auditor-friendly and forecloses scope drift.

### R6. What we are NOT doing in this NCIP

- **No Apple Secure Enclave / ARMv9 CCA / RISC-V Keystone** — out of
  scope for v0.3.
- **No remote attestation service (RATS)** — that is a higher-layer
  service that consumes this driver, not part of it.
- **No nested attestation** (e.g., L2 trust domain inside an L1) —
  Phase 5+.
- **No measurement allowlist** beyond a single baked-in
  `KNOWN_MEASUREMENT_NexaCore_OS` — multi-measurement support is a future
  NCIP for staged rollouts.

---

## Backwards Compatibility

The driver REPLACES `StubAttestation` in production paths. To avoid a
flag day:

- The kernel ships with the existing `StubAttestation` retained behind
  the `tee-stub` feature flag.
- If `nexacore-driver-tee` is present and probes successfully, the kernel
  routes verify requests to the driver.
- If `nexacore-driver-tee` is absent OR probes unsuccessfully (no TEE
  hardware), the kernel logs and falls back to `StubAttestation`.

This fallback is a transient compromise for the rollout window. A
follow-up cleanup NCIP MUST remove `StubAttestation` from production
binaries once real attestation is validated on Stichting-controlled
hardware (P5.2 / P5.3 funding-dependent per the backlog).

---

## Test Cases

### TC1. Probe selects correct backend on QEMU TDX

When running on QEMU with `-machine q35,kernel-irqchip=split,confidential-guest-support=tdx0` (TDX
fake-test mode), the driver MUST log `[driver-tee] backend=IntelTdx
report-format=DCAP`. (TDX in real hardware is hard to test; this exercises
the code path against the public TDX SDK simulator.)

### TC2. Probe selects correct backend on QEMU SEV-SNP

Equivalent test against `-machine q35,confidential-guest-support=sev-snp0`.
Log: `[driver-tee] backend=AmdSevSnp report-version=2`.

### TC3. Probe falls back to stub on bare-metal-without-TEE

On the current the Proxmox test VM (which exposes no TEE features), the
driver MUST log `[driver-tee] no usable backend — kernel will fall back
to StubAttestation` and exit code 2. The kernel MUST continue boot with
`StubAttestation`.

### TC4. Quote round-trip

A test client sends `AttestRequest::Quote{nonce=X, report_data=Y}`.
The driver returns `AttestResponse::Quote{quote_bytes, ...}`. Round-trip
the quote bytes through `AttestRequest::Verify{...}` and expect
`AttestResponse::VerifyOk{measurement, ...}`.

### TC5. Stale quote rejection

Construct a `Verify` request with a `quote.generated_at_unix` older than
`now - quote_freshness_sec` (default 600). Expect `AttestErrorCode::QuoteStale`.

### TC6. Seal / Unseal round-trip

Seal a small payload. Restart the driver process (`DriverUnload + DriverLoad`).
Unseal the same payload. Expect success — sealing is bound to the trust
domain measurement which survives driver restart.

(TC6 requires real TDX/SEV-SNP hardware; deferred to hardware-available
window.)

---

## Reference Implementation

N/A at filing. Future branch: `feat/kernel-p6-7-driver-tee`. Expected
new crates:

- `crates/nexacore-driver-tee/` (new) — the user-space TEE driver with the
  three backends (`tdx`, `sev-snp`, `stub`).
- `crates/nexacore-kernel/src/bare_metal/tee_call.rs` (new) — kernel-side
  trampoline for `SyscallNo::TeeTdcall = 74` and
  `SyscallNo::TeeMsr = 75` (per S5.3, S6.3, editorially reconciled to
  the `7x` driver-framework decade per `NCIP-Driver-Framework-013`
  Appendix A).
- `docs/protocol/driver-manifest-v1.toml` — `[tee]` table documented.

---

## Security Considerations

### SC1. Threat model alignment

The TEE driver is **the highest-trust user-space process** in NexaCore OS:
a compromised TEE driver can issue arbitrary attestation tokens to any
caller, undermining the entire capability system. Mitigations:

- The driver image is signed exclusively by the Stichting NexaCore key
  (manifest `nexacore_issuer_pubkey` MUST match a single, well-known entry
  in `KNOWN_ISSUERS`).
- Capability scope is tighter than other drivers: `Action::TeeProbe`
  is held only by this driver; `Action::DriverLoad`-equivalent is needed
  to spawn an updated driver image.
- IRQ surface is minimal (SEV-SNP may signal via MSI; TDX uses
  TDCALL-blocking calls only).

A successful compromise of the TEE driver is catastrophic but contained
to that process — kernel memory and other drivers' memory are unaffected.

### SC2. Failure modes

| Failure mode | Mitigation |
|---|---|
| Driver crash mid-Verify | Kernel falls back to StubAttestation; logs the crash |
| Backend returns unexpected report | Verify returns Error; capability is rejected |
| TDX module version drift | Driver dispatches on version tag in TDREPORT header |
| Replay (old quote re-used) | quote_freshness_sec ensures stale quotes refused |
| Side-channel from TEE | The TDX/SEV-SNP threat model itself addresses this; NexaCore OS inherits the hardware vendor's posture |

### SC3. Cryptographic considerations

The driver itself does not implement cryptography beyond what the TEE
hardware provides. Quote signature verification uses Intel's PCK chain
(TDX) or AMD's VCEK chain (SEV-SNP), validated against vendor-published
root keys (baked into the driver image at build time, refresh path
deferred to a follow-up NCIP).

`nexacore-crypto` is used only at the `Ed25519CapabilityProvider` boundary
(signing the NexaCore capability token); the TEE driver does not re-sign
quotes.

### SC4. Side channels

TDX/SEV-SNP hardware introduces new side channels (e.g., TDX cache
covert channels documented by Intel). The driver inherits these from
the hardware vendor and does NOT introduce additional mitigations
beyond what the vendor advises.

---

## Privacy Considerations

### PC1. Personal data flows

The TEE driver handles attestation tokens and sealed blobs. Both are
opaque to the driver:

- Quotes contain only the trust domain measurement + nonce + report_data;
  no personal information unless the caller put it in `report_data`
  (callers MUST NOT do that — `report_data` is for measurement binding,
  not data carriage).
- Sealed blobs are encrypted with TEE-derived keys; the driver sees
  ciphertext only.

### PC2. Hardware fingerprinting

The TDX/SEV-SNP attestation reports include hardware-specific identifiers
(the PCK / VCEK certificate chains identify the specific CPU). A quote
emitted off-device is therefore a strong hardware fingerprint.

Privacy posture:

- Quotes leave NexaCore OS only via the mesh protocol's attested handshake
  (Phase 4); the mesh protocol layers an additional onion-routing
  obfuscation per `docs/03-mesh-protocol.md` to minimize fingerprint
  exposure to non-peers.
- The driver MUST NOT log quote contents. Only counters
  (quotes issued, verifies served, errors) are exposed via a metrics
  channel (TBD).

### PC3. Sealed-blob portability

A sealed blob bound to the current measurement (`SealPolicy::BindToCurrentMeasurement`)
cannot be unsealed on a different machine or after a kernel upgrade
(which changes the measurement). This is by design — sealed data is
machine-local. Operators MUST plan migration via an attested key-export
protocol (TBD, follow-up NCIP).

### PC4. GDPR

The driver does not persist personal data. All GDPR considerations
apply at higher layers (the attested key-export protocol, the
remote-attestation service, the encrypted-by-default data types of
Phase 2).

---

## Appendix A — Bootstrap Activation Note

### A1. Founder fast-path activation (2026-05-20)

This NCIP was filed as `Draft` on 2026-05-20 (same calendar day as
`NCIP-Driver-Framework-013` itself) and promoted directly to `Active` on
the same day under the **Solo Founder Fast-Track** of
`NCIP-Process-001 §5.5`, exercised under the Bootstrap Period authority of
`NCIP-Process-001 §6.3`. The standard 14-day public objection window of
`NCIP-Process-001 §5.3` was waived by explicit founder approval; the
state-machine transitions `Draft → Review → Last Call → Active` collapse
into a single editorial pass with `activated: 2026-05-20` recorded in
the frontmatter.

**Rationale for fast-path:**

1. **Dependency unblock.** `NCIP-013` (the driver framework) is the
   prerequisite (`requires: [13]`) and was itself fast-pathed to
   `Active` on 2026-05-20. Keeping `016` in `Draft` would have stalled
   the TEE attestation upgrade path (`Ed25519CapabilityProvider`
   verify-path delegation, MB13.c) by 14 days for no substantive review
   benefit during the Bootstrap Period.
2. **No deployment risk.** Zero TEE driver code exists at activation
   time; the reference implementation is `N/A at filing` per `## Reference
   Implementation`. The fallback to `StubAttestation` documented in § R2
   remains the production path until TDX/SEV-SNP hardware lands
   (P5.2/P5.3 funding-dep).
3. **Scope is bounded.** All normative content is constrained by
   `NCIP-013` (the framework `Active` document) — the new
   `Action::TeeProbe` extension is `#[non_exhaustive]`-safe per
   `NCIP-Serde-004 §S2`, and the kernel-mediated TDCALL/MSR syscalls
   (`TeeTdcall = 74`, `TeeMsr = 75`) follow the syscall renumbering
   convention established by `NCIP-013` Appendix A1.
4. **No conflict with `NCIP-013` Appendix B.** The amendments to NCIP-013
   filed under its Appendix B explicitly state "No follow-up NCIP
   (014/015/016) requires changes" — confirmed by cross-reference audit
   (see NCIP-013 Appendix B trailing list of preserved citations covering
   016:116).

**Re-ratification obligation:** per `NCIP-Process-001 §5.5.e`, this
activation inherits the **mandatory post-Bootstrap re-ratification**
obligation. When the Bootstrap Period ends (second editor seat filled or
Stichting NexaCore constituted, whichever comes first), this NCIP MUST be
re-ratified by the standard quadratic-vote majority + activation
threshold of `NCIP-Process-001 §7`. Failure to re-ratify reverts the
status to `Withdrawn` and forces a fresh filing.

A separate cleanup NCIP — anticipated post-hardware validation per § R2
"Fallback transitorio a `StubAttestation`" — will rescind the StubAttestation
fallback once both TDX and SEV-SNP hardware paths are verified end-to-end.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
