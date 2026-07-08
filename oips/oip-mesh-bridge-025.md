---
ncip: 25
title: NexaCore Mesh Bridge — cross-platform desktop application for tiered mesh participation
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-27
updated: 2026-05-27
requires:
  - 16
  - 24
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

NCIP-024 introduces a four-tier trust model that permits mesh
participation from hardware ranging from full TEE (Tier 0) down to
software-only (Tier 3). However, all existing NexaCore OS mesh components
assume the NexaCore microkernel as host environment — they target
`x86_64-unknown-none` and rely on the kernel's IPC, capability system,
and driver framework.

This NCIP specifies **NexaCore Mesh Bridge**, a cross-platform desktop
application for Linux, Windows, and macOS that enables any conventional
PC or Mac to participate in the NexaCore OS mesh at the highest trust tier
its hardware supports. The application detects available security
primitives (TEE, Secure Enclave, TPM 2.0, or none), provisions the
appropriate `nexacore-tee` backend, and connects to the mesh as a
tier-appropriate node.

The architecture employs three layered defenses to mitigate the
inherent trust reduction of running on a conventional OS rather than
the NexaCore microkernel: (1) an optional **confidential microVM** that
reclaims Tier 0 on TEE-capable hardware, (2) **platform-native
hardware security** (Secure Enclave, VBS, TPM+IMA) for key protection
and measured launch, and (3) **application-level hardening** (sandbox,
memory encryption, reproducible builds) as defense in depth.

The application is a single Rust binary distributed for Linux (x86_64,
aarch64), Windows (x86_64), and macOS (x86_64, aarch64), released
under Apache-2.0 consistent with the NexaCore OS license.

---

## Motivation

### M1. The mesh needs nodes; nodes need accessible onboarding

`docs/06-roadmap.md` targets ≥ 10K mesh nodes within 12 months of v1.0.
NexaCore OS as a standalone operating system faces a cold-start problem:
installing a new OS is a high-friction action that few users will
undertake before seeing value. A desktop application installable in
under a minute on existing hardware removes this barrier.

The funnel is:

1. User installs NexaCore Mesh Bridge on their existing OS.
2. User contributes bandwidth and relay capacity at Tier 2–3.
3. User upgrades hardware or installs NexaCore OS for Tier 0–1 participation.

Each step increases commitment; the application is the entry point.

### M2. Hardware security on conventional OSes is underutilized

Modern consumer hardware ships with significant security infrastructure
that conventional OSes barely leverage for application-level attestation:

- **macOS**: every Apple Silicon Mac has a Secure Enclave capable of
  App Attest, hardware-bound key generation, and biometric-gated
  key release. Virtually unused by third-party apps for mesh attestation.
- **Windows**: TPM 2.0 is a Windows 11 requirement. VBS
  (Virtualization-Based Security) runs on every Secured-core PC. HVCI
  (Hypervisor-Protected Code Integrity) is default-on since Windows 11
  22H2. These primitives are available to applications via CNG/NCrypt
  and Windows Security Center APIs.
- **Linux**: TPM 2.0 is accessible via `tss-esapi`. IMA (Integrity
  Measurement Architecture) provides measured launch. SELinux/AppArmor
  provide mandatory access control. All are available to unprivileged
  applications with appropriate setup.

NexaCore Mesh Bridge turns these dormant primitives into mesh trust
anchors.

### M3. NCIP-024 enables it; this NCIP builds on it

NCIP-024 defines the tier model and `TeeFamily` extensions. This NCIP
specifies the software that makes those tiers accessible on non-NexaCore
hosts. Without this NCIP, NCIP-024's Tier 1–3 have no deployment vehicle
outside NexaCore OS itself.

### M4. NexaCoreContainer (NCIP-006) provides the microVM foundation

NCIP-Container-006 specifies `nexacore-container`, a micro-VM engine for
running Linux applications on NexaCore OS. The same micro-VM pattern
(Firecracker/Cloud Hypervisor) applies in reverse: running an NexaCore
mesh node inside a micro-VM on a conventional OS. This NCIP reuses the
micro-VM architecture for the confidential VM isolation mode.

---

## Specification

> **Normative keywords.** RFC 2119 / RFC 8174 (MUST, MUST NOT, SHOULD,
> SHOULD NOT, MAY).

### S1. Application architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     NexaCore Mesh Bridge                              │
│                                                                   │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  Platform   │  │  Tier        │  │  Mesh Protocol Client     │  │
│  │  Detector   │  │  Provisioner │  │  (nexacore-mesh subset)       │  │
│  └─────┬──────┘  └──────┬───────┘  └──────────┬───────────────┘  │
│        │                │                      │                  │
│  ┌─────▼──────────────▼──────────────────────▼───────────────┐  │
│  │                 Security Substrate                          │  │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────┐  ┌────────────┐  │  │
│  │  │Confident.│  │ Platform │  │ TPM 2.0 │  │ Software   │  │  │
│  │  │ MicroVM  │  │ Enclave  │  │ Backend │  │ MPC Backend│  │  │
│  │  │(optional)│  │ Backend  │  │         │  │            │  │  │
│  │  └──────────┘  └──────────┘  └─────────┘  └────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                   System Tray / Status UI                    │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

The application consists of five major components:

1. **Platform Detector** — probes the host at startup to determine
   available security primitives and the maximum achievable tier.
2. **Tier Provisioner** — activates the appropriate `nexacore-tee` backend
   and, if elected, launches the confidential microVM.
3. **Mesh Protocol Client** — a subset of `nexacore-mesh` compiled for
   `std` targets, handling discovery, handshake, relay, and reputation.
4. **Security Substrate** — the four backend implementations (§ S3–S6).
5. **System Tray / Status UI** — lightweight status interface showing
   tier, peer count, bandwidth contribution, and reputation.

### S2. Platform detection and tier assignment

At startup the Platform Detector executes the following probe sequence
and assigns the highest achievable tier:

```rust
pub fn detect_platform() -> DetectedPlatform {
    // Phase 1: Check for full TEE (Tier 0 via confidential microVM)
    if let Some(cvm) = probe_confidential_vm_support() {
        // AMD SEV-SNP or Intel TDX available on host
        return DetectedPlatform {
            max_tier: TrustTier::FullTee,
            backend: Backend::ConfidentialMicroVm(cvm),
            cvm_available: true,
        };
    }

    // Phase 2: Check for platform enclave (Tier 1)
    #[cfg(target_os = "macos")]
    if let Some(se) = probe_secure_enclave() {
        return DetectedPlatform {
            max_tier: TrustTier::EnclaveLimited,
            backend: Backend::AppleSecureEnclave(se),
            cvm_available: false,
        };
    }

    // Phase 3: Check for TPM 2.0 (Tier 2)
    if let Some(tpm) = probe_tpm2() {
        return DetectedPlatform {
            max_tier: TrustTier::MeasuredBoot,
            backend: Backend::Tpm2(tpm),
            cvm_available: false,
        };
    }

    // Phase 4: Software-only fallback (Tier 3)
    DetectedPlatform {
        max_tier: TrustTier::SoftwareOnly,
        backend: Backend::SoftwareMpc,
        cvm_available: false,
    }
}
```

**Platform-specific probes:**

| Platform | Tier 0 probe | Tier 1 probe | Tier 2 probe |
|----------|-------------|-------------|-------------|
| **Linux** | `/dev/sev-guest` (SEV-SNP) or `/dev/tdx-guest` (TDX), plus KVM support for CVM launch | N/A (no platform enclave on x86 Linux) | `/dev/tpm0` or `/dev/tpmrm0` present; `tss-esapi` initialization succeeds |
| **Windows** | `IsProcessorFeaturePresent()` for SEV/TDX; Hyper-V available for CVM launch | N/A (VBS enhances Tier 2, does not constitute Tier 1) | `Tbsi_GetDeviceInfo()` returns `TPM_DEVICE_INFO` with version ≥ 2.0 |
| **macOS (Apple Silicon)** | N/A (no TDX/SEV-SNP on ARM) | `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` succeeds | N/A (Apple Silicon has no discrete TPM; Secure Enclave subsumes TPM functionality) |
| **macOS (Intel)** | `/dev/tdx-guest` if TDX-capable Xeon (rare on Mac) | N/A | Discrete TPM if present (some Mac Pro models) |

### S3. Backend: Confidential MicroVM (Tier 0)

On hosts with SEV-SNP or TDX support, the application MAY launch a
confidential micro-VM containing a minimal NexaCore OS image. This
reclaims Tier 0 guarantees on conventional operating systems.

**Architecture:**

```
┌─────────────────────────────────────────────┐
│              Host OS (Linux/Windows)          │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │  NexaCore Mesh Bridge (host process)        │  │
│  │  • launches CVM via VMM                 │  │
│  │  • proxies network I/O to CVM           │  │
│  │  • displays status UI                   │  │
│  └───────────────┬─────────────────────────┘  │
│                  │ virtio-vsock                │
│  ┌───────────────▼─────────────────────────┐  │
│  │  Confidential MicroVM                   │  │
│  │  ┌───────────────────────────────────┐  │  │
│  │  │  NexaCore Mesh Node (full nexacore-mesh)  │  │  │
│  │  │  TDX / SEV-SNP attestation        │  │  │
│  │  │  Sealed key storage               │  │  │
│  │  │  Memory encrypted by hardware     │  │  │
│  │  └───────────────────────────────────┘  │  │
│  └─────────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

**VMM selection:**

| Platform | VMM | Rationale |
|----------|-----|-----------|
| Linux | Cloud Hypervisor (Rust, Apache-2.0) | Native SEV-SNP and TDX support; Rust codebase aligns with project values |
| Windows | Hyper-V via WHP (Windows Hypervisor Platform) API | Native integration; SEV-SNP support via Azure Confidential VMs pattern |
| macOS | Virtualization.framework | Apple's native hypervisor; no TEE passthrough (Tier 0 CVM not available on macOS) |

**CVM image:**

The CVM runs a minimal NexaCore OS image (`nexacore-mesh-bridge-cvm.img`)
containing only:

- NexaCore microkernel (stripped to mesh-relevant subsystems)
- `nexacore-tee` driver with TDX or SEV-SNP backend
- `nexacore-mesh` protocol client
- virtio-vsock driver for host communication

Image size target: ≤ 64 MiB. Boot time target: ≤ 2 seconds.
Memory allocation: 256 MiB–2 GiB (configurable by user).

The host process communicates with the CVM via `virtio-vsock`:

- Host → CVM: network packets (relayed from host network stack),
  configuration updates, shutdown commands.
- CVM → Host: status telemetry, peer count, bandwidth metrics.

The CVM's TEE attestation is genuine: the SEV-SNP or TDX hardware
encrypts the CVM's memory and produces attestation reports that chain
back to AMD/Intel PKI. The host OS — even if compromised — cannot
read the CVM's memory or forge its attestation.

**Resource requirements:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM (for CVM) | 256 MiB | 1 GiB |
| Disk (CVM image) | 64 MiB | 128 MiB |
| CPU | 1 vCPU | 2 vCPUs |

The CVM mode is **opt-in** and presented to the user when hardware
support is detected. The UI MUST clearly explain the benefits ("full
privacy protection, your data is encrypted even from your own OS") and
costs ("uses ~1 GB extra RAM").

### S4. Backend: Platform Enclave (Tier 1)

#### S4.1 macOS — Apple Secure Enclave

The macOS backend leverages the Secure Enclave for:

1. **Key generation and storage** — mesh identity keypair generated
   inside the Secure Enclave via `SecKeyCreateRandomKey` with
   `.secureEnclave` protection. The private key never leaves the
   enclave.
2. **Attestation** — App Attest (`DCAppAttestService`) produces
   hardware-backed assertions. The nonce from the mesh handshake is
   embedded in the assertion.
3. **Biometric-gated operations** — sensitive operations (key export
   for migration, tier override) require Touch ID / Face ID via
   `LAContext`.

**Implementation:**

```rust
pub struct SecureEnclaveBackend {
    key_ref: SecKey,          // opaque handle to SE-resident key
    attest_service: DCAppAttestService,
}

impl TeeBackend for SecureEnclaveBackend {
    fn family(&self) -> TeeFamily { TeeFamily::AppleSecureEnclave }

    fn attest(&self, nonce: &Nonce, report_data: Option<&[u8]>)
        -> Result<Quote, TeeError>
    {
        // 1. Generate App Attest key if not already provisioned
        // 2. Request assertion with nonce embedded as clientDataHash
        // 3. Wrap in Quote { family: AppleSecureEnclave, ... }
    }

    fn verify_quote(&self, quote: &Quote, expected_nonce: &Nonce,
                    expected_measurement: &Measurement)
        -> Result<(), TeeError>
    {
        // 1. Validate App Attest assertion signature chain
        //    (Apple App Attest root CA → intermediate → leaf)
        // 2. Verify nonce matches
        // 3. Verify key identifier hash matches expected measurement
    }

    fn seal(&self, plaintext: &[u8], policy: &SealPolicy)
        -> Result<SealedBlob, TeeError>
    {
        // Encrypt with SE-derived key via SecKeyCreateEncryptedData
        // AES-256-GCM, key never leaves enclave
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<Vec<u8>, TeeError> {
        // Decrypt with SE-resident key via SecKeyCreateDecryptedData
    }

    fn derive_key_for(&self, peer_attestation: &Quote)
        -> Result<TeeSharedKey, TeeError>
    {
        // ECDH with peer's public key using SE-resident private key
        // via SecKeyCopyKeyExchangeResult (kSecKeyAlgorithmECDHKeyExchangeStandard)
        // then HKDF-SHA256 to derive 32-byte TeeSharedKey
    }
}
```

**macOS Hardened Runtime** MUST be enabled. The application is notarized
by Apple to satisfy Gatekeeper requirements. The `com.apple.security.
device.apple-secure-enclave` entitlement is declared.

#### S4.2 Windows — VBS-enhanced TPM (Tier 1 candidate)

On Windows Secured-core PCs, VBS (Virtualization-Based Security)
creates an isolated secure world (VSM Level 1) enforced by the
hypervisor. While VBS does not provide full confidential computing,
it protects key material from kernel-level attacks:

- Credential Guard isolates credential hashes in VSM.
- The application can store mesh keys via `NCryptCreatePersistedKey`
  with `NCRYPT_USE_VIRTUAL_ISOLATION_FLAG`, placing them in the VBS
  secure world.

On Secured-core PCs with both VBS and TPM 2.0, the combination
approaches Tier 1 guarantees for key protection. However, host RAM
is not encrypted. This NCIP conservatively assigns Windows VBS+TPM to
**Tier 2** (not Tier 1). A future NCIP MAY reclassify to Tier 1 if
the VBS isolation model is formally evaluated against NexaCore OS threat
classes.

### S5. Backend: TPM 2.0 (Tier 2)

The TPM 2.0 backend provides measured boot attestation on all three
platforms.

**Implementation:**

```rust
pub struct Tpm2Backend {
    context: tss_esapi::Context,   // TPM 2.0 TSS ESAPI context
    aik: KeyHandle,                // Attestation Identity Key handle
    pcr_selection: PcrSelectionList,
}

impl TeeBackend for Tpm2Backend {
    fn family(&self) -> TeeFamily { TeeFamily::Tpm2 }

    fn attest(&self, nonce: &Nonce, _report_data: Option<&[u8]>)
        -> Result<Quote, TeeError>
    {
        // 1. Select PCRs per NCIP-024 § S4.3 policy
        // 2. TPM2_Quote(aik, nonce, pcr_selection)
        // 3. Retrieve TCG event log from platform
        //    - Linux: /sys/kernel/security/tpm0/binary_bios_measurements
        //    - Windows: Tbsi_Get_TCG_Log()
        //    - macOS: IOKit TPM interface (limited)
        // 4. Bundle quote + event log into Quote { family: Tpm2, ... }
    }

    fn verify_quote(&self, quote: &Quote, expected_nonce: &Nonce,
                    expected_measurement: &Measurement)
        -> Result<(), TeeError>
    {
        // 1. Parse TPM2B_ATTEST from quote body
        // 2. Verify AIK signature over the quote
        // 3. Replay event log to recompute PCR values
        // 4. Confirm computed PCR digest matches quote's PCR digest
        // 5. Confirm nonce matches
        // 6. Derive Measurement from PCR values and compare
    }

    fn seal(&self, plaintext: &[u8], policy: &SealPolicy)
        -> Result<SealedBlob, TeeError>
    {
        // TPM2_Create with policyPCR binding
        // Data is encrypted to a key that can only be loaded
        // when PCRs match the specified values
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<Vec<u8>, TeeError> {
        // TPM2_Unseal — fails if current PCRs don't match seal policy
    }

    fn derive_key_for(&self, _peer_attestation: &Quote)
        -> Result<TeeSharedKey, TeeError>
    {
        // TPM2_ECDH_ZGen for key agreement using TPM-resident key
        // then HKDF-SHA256 to derive TeeSharedKey
        // Binding to peer attestation: include peer's quote hash
        // in HKDF info parameter
    }
}
```

**Platform-specific TPM access:**

| Platform | TPM interface | Library |
|----------|-------------|---------|
| Linux | `/dev/tpmrm0` (kernel TPM resource manager) | `tss-esapi` (Rust, Apache-2.0) |
| Windows | TBS (TPM Base Services) via `Tbsi_*` API | `tss-esapi` with Windows TBS TCTI, or `windows` crate FFI |
| macOS | Limited: `IOKit` TPM interface on Intel Macs with discrete TPM; not available on Apple Silicon | `tss-esapi` with device TCTI where hardware present |

**Measured launch of the application itself:**

On Linux with IMA (Integrity Measurement Architecture) enabled, the
application binary is measured into a PCR at exec time. The TPM quote
therefore attests not just the boot chain but also the identity of the
mesh bridge binary. The application MUST document the IMA setup
required to achieve this in its installation guide.

On Windows, the Measured Boot log (`Tbsi_Get_TCG_Log`) includes
measurements of the boot chain through the Windows kernel. The
application SHOULD extend a PCR (via `TPM2_PCR_Extend`) with its own
binary hash at startup to include itself in the attestation chain.

### S6. Backend: Software-only MPC (Tier 3)

The software-only backend provides no hardware root of trust.

```rust
pub struct SoftwareMpcBackend {
    identity_key: Ed25519SigningKey,
    node_id: NodeId,
}

impl TeeBackend for SoftwareMpcBackend {
    fn family(&self) -> TeeFamily { TeeFamily::SoftwareMpc }

    fn attest(&self, nonce: &Nonce, report_data: Option<&[u8]>)
        -> Result<Quote, TeeError>
    {
        // Sign (nonce || report_data || node_id) with identity key
        // No hardware attestation — quote is self-signed
        // Verifiers accept this only for Tier 3 roles
    }

    fn seal(&self, plaintext: &[u8], _policy: &SealPolicy)
        -> Result<SealedBlob, TeeError>
    {
        // Encrypt with a key derived from identity_key via HKDF
        // Stored on disk with OS-level file permissions
        // WARNING: no hardware protection — sealed only against
        // casual access, not a determined local attacker
    }

    // ... verify_quote, unseal, derive_key_for analogous
}
```

Sybil resistance for Tier 3 nodes is provided by:
- Compute-credit bootstrapping (per `docs/03-mesh-protocol.md`)
- Proof-of-work challenge on first mesh join (lightweight, one-time)
- Network-age reputation weighting

### S7. Application-level hardening

Regardless of tier, the following hardening measures MUST be applied:

#### S7.1 Process sandbox

| Platform | Sandbox mechanism |
|----------|------------------|
| Linux | `seccomp-bpf` filter (allowlist of ~60 syscalls), `PR_SET_NO_NEW_PRIVS`, `CLONE_NEWNET` for network namespace isolation, `landlock` where available (kernel ≥ 5.13) |
| Windows | AppContainer with restricted token, Job object with process limit, `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE` |
| macOS | App Sandbox (`com.apple.security.app-sandbox`), Hardened Runtime, library validation |

#### S7.2 In-process memory protection

Sensitive data (keys, attestation material, peer session state) MUST
be handled with:

- **Guarded allocations**: sensitive buffers allocated via `mmap` with
  guard pages on both sides. On Windows, `VirtualAlloc` with
  `PAGE_GUARD`.
- **Zeroization on drop**: all key material types implement `Drop` with
  volatile write zeroing (consistent with `nexacore-tee`'s `TeeSharedKey`
  pattern).
- **`mlock`**: sensitive pages are locked into physical RAM to prevent
  paging to disk. On Windows, `VirtualLock`. On macOS,
  `mlock` + `MAP_RESILIENT_CODESIGN`.
- **ASLR + CFI**: the binary MUST be compiled with full ASLR
  (`-C relocation-model=pic`), stack canaries (`-C overflow-checks=on`),
  and CFI where supported by the toolchain.

#### S7.3 Reproducible builds

The application MUST be reproducibly buildable from source. This means:

- Deterministic build environment (Nix flake or Docker with pinned
  base image).
- All dependencies pinned by hash in `Cargo.lock`.
- Reproducibility CI job that builds twice and compares SHA-256 of
  output binaries.
- Signed release artifacts with Sigstore (consistent with
  `docs/04-security-model.md` § "Model attestation").
- Users can verify: `nexacore-mesh-bridge --verify-binary` computes the
  running binary's hash and checks it against the Sigstore transparency
  log.

#### S7.4 Code signing and distribution

| Platform | Signing mechanism | Distribution |
|----------|------------------|-------------|
| Linux | Sigstore + GPG detached signature | `.deb`, `.rpm`, Flatpak, AppImage |
| Windows | Authenticode (EV code signing certificate) | `.msi` installer, WinGet |
| macOS | Apple Developer ID + notarization | `.dmg`, Homebrew cask |

#### S7.5 Auto-update with rollback

The application includes a self-updater that:

- Checks for updates from a Stichting NexaCore-operated update server
  (HTTPS, certificate-pinned).
- Downloads updates signed by the Stichting NexaCore release key.
- Verifies the signature before applying.
- Keeps one previous version on disk for rollback.
- Exposes a CLI flag `--skip-update` for users who prefer manual
  updates.

### S8. Mesh protocol client

The application embeds a subset of `nexacore-mesh` compiled for `std`
targets (Linux `x86_64-unknown-linux-gnu`, Windows
`x86_64-pc-windows-msvc`, macOS `aarch64-apple-darwin` /
`x86_64-apple-darwin`).

The subset includes:

| Component | Included | Notes |
|-----------|---------|-------|
| Kademlia DHT discovery | Yes | Full implementation |
| QUIC + Noise transport | Yes | Via `quinn` + `snow` crates |
| TEE attestation handshake | Yes | Tier-aware per NCIP-024 § S6 |
| Relay (forward-only) | Yes | Primary role for Tier 2–3 |
| Reputation witness | Yes | Reduced weight for Tier 2–3 |
| Bandwidth contribution | Yes | Primary value proposition for Tier 2–3 |
| Expert shard hosting | CVM only | Requires Tier 0 (confidential microVM) |
| PII-bearing inference | CVM only | Requires Tier 0 |
| Key custody | No | Not appropriate for bridge nodes |
| Compute-credit ledger | Yes | Gossip-replicated |

### S9. User interface

The application runs as a **system tray application** (Linux: tray
icon via `libappindicator` / StatusNotifierItem; Windows: notification
area; macOS: menu bar).

**Status display:**

```
┌─────────────────────────────────┐
│  NexaCore Mesh Bridge               │
│                                 │
│  Status:  ● Connected           │
│  Tier:    2 (TPM 2.0)           │
│  Peers:   142                   │
│  ↑ 12.4 MB/s  ↓ 8.7 MB/s       │
│  Credits: +47.2 (net earned)    │
│  Uptime:  3d 14h 22m            │
│                                 │
│  [Upgrade to Tier 0 ▸]         │
│  [Settings]  [Pause]  [Quit]   │
└─────────────────────────────────┘
```

The "Upgrade to Tier 0" button appears when CVM-capable hardware is
detected but the user has not opted into CVM mode. It explains the
benefits and resource cost.

**Settings:**

- Bandwidth cap (upload/download limits)
- CPU allocation (% of cores available to mesh)
- CVM memory allocation (if Tier 0 CVM mode active)
- Network schedule (e.g., mesh active only overnight on metered
  connections)
- Auto-start at login (on/off)
- Update channel (stable / beta)

### S10. Tier upgrade path

The application MUST detect hardware changes and offer tier upgrades:

- User installs the app on a laptop without TEE → assigned Tier 3.
- User later acquires a TPM-equipped machine → app detects TPM at
  next startup → offers upgrade to Tier 2.
- User enables CVM mode on TEE-capable hardware → app launches CVM →
  upgrades to Tier 0.

Tier downgrade (e.g., TPM removed from system) MUST trigger
re-attestation and honest tier declaration. A node MUST NOT continue
claiming a tier whose hardware prerequisites are no longer met.

### S11. Network and firewall requirements

The application requires outbound connectivity on:

| Port | Protocol | Purpose |
|------|----------|---------|
| 443 | HTTPS | Bootstrap seed node discovery, update checks |
| 4433 | QUIC/UDP | Mesh peer-to-peer traffic |
| Dynamic | UDP | QUIC connections to discovered peers |

Inbound connectivity is NOT required for basic participation (relay
over outbound connections). For nodes that wish to accept inbound
connections (higher reputation), UPnP and NAT-PMP are attempted
automatically; manual port forwarding is documented as fallback.

---

## Rationale

### R1. Why a standalone application, not a browser extension or daemon

**Considered: browser extension.**
WebCrypto API lacks TPM access, Secure Enclave access, and microVM
launch capability. A browser extension would be limited to Tier 3
at best. The mesh protocol requires raw UDP (QUIC), which browsers
do not expose to extensions.

**Considered: background daemon (no UI).**
A daemon without UI creates user anxiety ("what is this process
doing?"). The system tray interface provides transparency and control
with minimal footprint.

A native application provides access to all platform security
primitives, full network control, and user trust through visible
presence.

### R2. Why optional CVM instead of mandatory

Mandating CVM would exclude machines without hardware virtualization
support and would increase the minimum resource requirement. The tiered
model (NCIP-024) already handles this: nodes without CVM participate at
lower tiers. The CVM is an optimization for users who want Tier 0 on a
conventional OS, not a requirement.

### R3. Why Rust, not Electron/Tauri

- **Security**: Rust's memory safety is critical for a
  security-sensitive application. Electron's Chromium attack surface
  is large.
- **Size**: target binary ≤ 15 MiB. Electron apps start at ~150 MiB.
- **Consistency**: the rest of NexaCore OS is Rust. Sharing crates
  (`nexacore-tee`, `nexacore-mesh`, `nexacore-types`, `nexacore-crypto`) eliminates
  re-implementation risk.
- **Performance**: native binary with minimal overhead for a system
  tray app that should be invisible.

UI framework: platform-native menus via `tray-icon` crate (Rust,
cross-platform). No web view. Settings panel via a simple native
window using `iced` or `egui` (decision deferred to implementation).

### R4. Why conservative tier assignment for Windows VBS+TPM

VBS provides hypervisor-enforced isolation of key material, which is
stronger than pure TPM. However:

- VBS protections apply only to keys stored in VBS; host RAM
  containing transient computation is still readable by a
  kernel-level attacker.
- VBS availability depends on hardware (Intel VT-x/AMD-V, SLAT,
  TPM) and Windows SKU (not all Windows 11 editions enable VBS
  by default).
- The formal security analysis of VBS against NexaCore OS threat classes
  (§ 4a) has not been performed.

Conservative Tier 2 assignment avoids over-promising. The upgrade path
is clear: a future NCIP with a formal VBS security evaluation.

### R5. Why include proof-of-work for Tier 3 Sybil resistance

NCIP-024 specifies compute-credit bootstrapping and network-age
weighting for Tier 3 Sybil resistance. This NCIP adds a lightweight
one-time proof-of-work challenge at first join because the desktop
application lowers the barrier to spinning up many nodes
(install → run → mesh join in under a minute). The PoW is calibrated
to ~30 seconds on a modern CPU, negligible for a legitimate user but
expensive at scale for a Sybil attacker launching thousands of nodes.

### R6. What we are NOT doing in this NCIP

- **No mobile application (iOS/Android).** Mobile mesh participation
  is an open research question per `docs/07-hardware-requirements.md`.
  A future NCIP may specify a mobile bridge.
- **No inference execution on non-CVM bridge nodes.** Tier 2–3 nodes
  are relay and bandwidth contributors, not compute providers. Inference
  requires Tier 0 guarantees (CVM mode or NexaCore OS native).
- **No replacement for NexaCore OS.** The bridge is an onboarding tool, not
  a substitute. Full NexaCore OS provides stronger guarantees across the
  entire stack.

---

## Backwards Compatibility

### Mesh protocol

NexaCore Mesh Bridge nodes speak the same mesh protocol as native NexaCore OS
nodes. The `TeeFamily` discriminant in the attestation handshake
identifies the node's backend; native NexaCore OS nodes treat bridge nodes
according to their tier per NCIP-024. No protocol changes required.

### `nexacore-tee` crate

The `nexacore-tee` crate currently targets `no_std + alloc`. The new
backends (`SecureEnclaveBackend`, `Tpm2Backend`, `SoftwareMpcBackend`)
require `std` for platform API access. These backends MUST be gated
behind feature flags:

```toml
[features]
default = ["mock"]
mock = []
tdx = []
sev-snp = []
apple-se = ["std"]        # NEW — requires std
tpm2 = ["std"]            # NEW — requires std
software-mpc = ["std"]    # NEW — requires std
std = []
bridge-backends = ["apple-se", "tpm2", "software-mpc"]
```

The kernel-side `nexacore-tee` (used by NexaCore OS native) continues to use
`no_std` with `tdx` and `sev-snp` features. The bridge application uses
`std` with `bridge-backends`. No conflict.

### Native NexaCore OS nodes

No changes required. Native nodes see bridge nodes as any other peer
with a tier-appropriate `TeeFamily`. The routing policy (NCIP-024 § S5)
automatically restricts workload assignment based on tier.

---

## Test Cases

### TC1. Platform detection accuracy

For each supported platform configuration, `detect_platform()` returns
the expected tier:

| Platform | Hardware | Expected tier | Expected backend |
|----------|---------|--------------|-----------------|
| Linux, AMD EPYC + SEV-SNP | Full TEE | `FullTee` | `ConfidentialMicroVm(SevSnp)` |
| Linux, Intel Xeon + TDX | Full TEE | `FullTee` | `ConfidentialMicroVm(Tdx)` |
| macOS, M3 MacBook | Secure Enclave | `EnclaveLimited` | `AppleSecureEnclave` |
| Windows 11, Secured-core PC | VBS + TPM 2.0 | `MeasuredBoot` | `Tpm2` |
| Linux, older PC with TPM | TPM 2.0 | `MeasuredBoot` | `Tpm2` |
| Linux, no TPM, no TEE | Nothing | `SoftwareOnly` | `SoftwareMpc` |

### TC2. CVM attestation end-to-end

On a Linux host with SEV-SNP:

1. Launch NexaCore Mesh Bridge with CVM mode enabled.
2. CVM boots and produces an SEV-SNP attestation report.
3. Bridge connects to a native NexaCore OS Tier 0 node.
4. Handshake succeeds; peer recognizes bridge as Tier 0.
5. Verify: the peer's routing policy assigns expert-shard-eligible
   workloads to the CVM bridge.

### TC3. Secure Enclave attestation on macOS

On a macOS Apple Silicon host:

1. Launch NexaCore Mesh Bridge.
2. App Attest assertion is generated with mesh handshake nonce.
3. Connect to a Tier 0 peer.
4. Peer verifies assertion, recognizes bridge as Tier 1.
5. Verify: peer assigns relay and reputation-witness roles but NOT
   expert shard hosting.

### TC4. TPM 2.0 attestation on Linux

On a Linux host with TPM 2.0:

1. Launch NexaCore Mesh Bridge.
2. TPM quote is generated covering PCRs 0–7 + app measurement.
3. Connect to a Tier 0 peer.
4. Peer verifies TPM quote, replays event log, recognizes bridge as
   Tier 2.
5. Verify: peer assigns relay and bandwidth roles only.

### TC5. Software-only Sybil resistance

1. Launch 100 NexaCore Mesh Bridge instances in Tier 3 mode.
2. Each must complete the one-time proof-of-work (~30s each).
3. Total time: ~50 minutes (serialized). Verify: this is economically
   prohibitive at scale (1000 nodes = ~8.3 hours CPU time).
4. Verify: each node starts with minimal compute credits.
5. Verify: reputation is near-zero for all 100 nodes.

### TC6. Sandbox enforcement

On each platform, verify that the sandboxed process cannot:

- Open files outside its data directory.
- Spawn child processes (except the CVM VMM when CVM mode is active).
- Make network connections to hosts other than mesh peers and the
  update server.

### TC7. Binary reproducibility

1. Build NexaCore Mesh Bridge twice from the same commit using the Nix
   flake.
2. Compare SHA-256 of output binaries.
3. Verify: hashes are identical.

### TC8. Tier upgrade detection

1. Launch NexaCore Mesh Bridge on a machine without TPM → Tier 3.
2. Stop the app.
3. Simulate TPM availability (mock TPM or move to TPM-equipped machine).
4. Relaunch the app.
5. Verify: app detects TPM, offers Tier 2 upgrade, re-attests at
   Tier 2.

---

## Reference Implementation

N/A at filing. Expected implementation path:

### Phase 1: Core framework + Tier 3
- New workspace crate: `crates/nexacore-mesh-bridge/`
- Platform detection module
- Software MPC backend (reuse `nexacore-tee` `SoftwareMpc`)
- Mesh protocol client (extract `std`-compatible subset from
  `nexacore-mesh`)
- System tray UI (minimal: status, pause, quit)
- Linux `.deb` + `.AppImage` packaging

### Phase 2: TPM 2.0 backend (Tier 2)
- `Tpm2Backend` implementation using `tss-esapi`
- PCR quote generation and verification
- Event log parsing
- Linux + Windows support
- Reproducible build pipeline

### Phase 3: Apple Secure Enclave backend (Tier 1)
- `SecureEnclaveBackend` implementation using Security.framework
- App Attest integration
- macOS notarization and distribution
- Homebrew cask formula

### Phase 4: Confidential MicroVM (Tier 0)
- CVM image build pipeline (minimal NexaCore OS image)
- Cloud Hypervisor integration (Linux)
- Hyper-V WHP integration (Windows)
- virtio-vsock communication channel
- CVM boot and attestation flow

### Phase 5: Polish and distribution
- Windows `.msi` installer + WinGet manifest
- Auto-update system
- Settings UI
- Comprehensive sandbox hardening
- Security audit

---

## Security Considerations

### SC1. The host OS is untrusted

The fundamental threat: on a conventional OS, the application runs as
a userspace process. The host OS kernel, other privileged processes,
and any malware with root/admin access can:

- Read the application's memory.
- Modify the application's code at runtime.
- Intercept network traffic before encryption.
- Tamper with the TPM communication channel.

**Mitigations by tier:**

| Tier | Mitigation | Residual risk |
|------|-----------|--------------|
| 0 (CVM) | Hardware memory encryption (SEV-SNP/TDX). Host OS cannot read CVM RAM. Network traffic originates inside CVM. | Side-channel attacks on TEE (same residual as native NexaCore OS Tier 0). |
| 1 (Enclave) | Keys in Secure Enclave — host cannot extract. Signing/decryption in enclave. | Host can read transient plaintext in application RAM (post-decryption). Limited to key protection, not computation protection. |
| 2 (TPM) | TPM-bound keys resistant to software extraction. Boot chain attested. | Runtime memory fully exposed. Attestation proves boot state, not runtime state. |
| 3 (Software) | No hardware protection. E2E encryption of mesh traffic. | Full exposure to local attacker. Security relies entirely on MPC thresholds and cryptographic protocols. |

### SC2. Tier honesty

A malicious bridge application could lie about its tier (e.g., claim
Tier 0 while running Tier 3). Defense:

- Tier is determined by the `TeeFamily` in the attestation quote.
- A CVM produces a real SEV-SNP/TDX quote verifiable against vendor
  PKI — unforgeable.
- A Secure Enclave produces an App Attest assertion verifiable against
  Apple's root CA — unforgeable.
- A TPM produces a quote signed by the AIK, certifiable via the EK
  chain — unforgeable.
- A Tier 3 node produces a self-signed quote. Verifiers know this is
  Tier 3 because the `TeeFamily::SoftwareMpc` discriminant is present
  and no hardware attestation chain is provided.

### SC3. Supply chain for the bridge binary

The bridge binary is a high-value target: compromising it could route
mesh traffic through a malicious relay. Defenses:

- Reproducible builds: any user can verify the binary matches source.
- Sigstore transparency log: all releases are logged; a compromised
  release is detectable.
- Auto-update with signature verification: updates are signed by the
  Stichting NexaCore release key.
- CVM image is also signed and verified at boot.

### SC4. CVM escape

If an attacker escapes the confidential microVM, they gain Tier 0
attestation on a compromised node. This is the highest-impact attack
against the bridge architecture.

Mitigations:
- The VMM (Cloud Hypervisor, Hyper-V) is a battle-tested hypervisor.
- The CVM image is minimal (~64 MiB), reducing attack surface.
- SEV-SNP/TDX hardware protections are designed to withstand a
  malicious hypervisor — even a VMM compromise does not breach the
  CVM's memory encryption.
- The combination of hardware memory encryption + minimal guest image
  makes CVM escape significantly harder than container escape.

### SC5. Threat model per attacker class

| Attacker (from `docs/04a-threat-model.md`) | Bridge-specific risk | Mitigation |
|---|---|---|
| A1 (malicious local app) | Reads bridge process memory | Tier 0: CVM isolation. Tier 1–3: guarded allocations, mlock, zeroization. |
| A3 (supply chain) | Compromised bridge binary | Reproducible builds, Sigstore, code signing. |
| A5 (physical attacker) | Cold boot on host machine | Tier 0: CVM memory encrypted. Tier 1: SE keys safe. Tier 2–3: exposed. |
| New: A7 (malicious host OS) | Compromised OS reads all non-CVM data | Tier 0: CVM immune. Others: honest tier declaration; restricted roles. |

### SC6. Privacy of platform probe results

The platform detection phase reveals hardware capabilities (TEE support,
TPM presence, Secure Enclave availability). This information:

- Is used locally only for tier assignment.
- Is NOT transmitted to any server during detection.
- Is encoded only as the `TeeFamily` discriminant (1 byte) in the
  mesh handshake — the minimum information needed for tier routing.

---

## Privacy Considerations

### PC1. Bridge as a metadata source

A bridge node on a conventional OS is subject to host-OS telemetry
(Windows telemetry, macOS analytics). The bridge process's network
connections are visible to the host OS and potentially logged.

Mitigations:
- CVM mode: network traffic originates inside the CVM; host sees only
  the virtio-vsock tunnel, not individual mesh connections.
- Non-CVM: mesh traffic uses QUIC (UDP), which is harder to inspect
  than TCP. Payload is always encrypted. However, connection metadata
  (peer IPs, timing, volume) is visible to the host OS.
- The application does NOT implement any telemetry, analytics, or
  phone-home behavior beyond update checks.

### PC2. Apple App Attest linkability

App Attest assertions include a per-device key identifier that is
stable across sessions. This creates a persistent hardware fingerprint
linkable across mesh sessions.

Mitigations:
- The key identifier is shared only with mesh peers during the
  attestation handshake, not broadcast.
- Onion routing (when elected) hides the asserting node from
  non-adjacent peers.
- A future NCIP MAY investigate rotating App Attest keys (subject to
  Apple's API constraints).

### PC3. TPM EK privacy

The TPM Endorsement Key (EK) uniquely identifies the TPM chip. Per
NCIP-024 § PC2, the bridge MUST use an Attestation Identity Key (AIK)
and MUST NOT expose the EK during mesh attestation. DAA (Direct
Anonymous Attestation) MUST be used where the TPM supports it
(TPM 2.0 revision ≥ 1.38).

### PC4. Installation fingerprinting

The presence of the NexaCore Mesh Bridge binary on disk is a local
forensic artifact that identifies the user as a mesh participant. This
is unavoidable for any installed application. Users with heightened
privacy concerns SHOULD use the portable (AppImage / portable .exe)
distribution and store it on encrypted removable media.

### PC5. GDPR considerations

The bridge application processes no personal data beyond the user's
IP address (inherent in network participation) and the TPM/SE hardware
identifiers (mitigated by AIK/DAA per PC3). The mesh protocol's
PII-tokenization requirement (per `docs/04-security-model.md`) applies
equally to bridge nodes. No additional GDPR obligations arise from the
bridge application itself.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
