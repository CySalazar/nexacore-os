---
ncip: 26
title: Kernel Threat Model and Performance-Preserving Mitigation Budget
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-06-05
updated: 2026-06-05
requires: [3, 5, 12]
supersedes: ~
superseded-by: ~
discussion: ~
license: CC0-1.0
---

## Abstract

This NCIP establishes the NexaCore kernel's **threat model**, its **trust assumptions about
the execution substrate**, and a **tiered, performance-budgeted mitigation strategy** whose
guiding rule is: *buy security by eliminating bug classes by construction or by using
hardware features that are already present, and make the costly mitigations adaptive or
opt-in — never pay continuous performance for a defense that a cheaper one subsumes.*

It is filed because the kernel is approaching the transition from a **closed** system (every
Ring-3 binary is baked into the boot image at compile time) to an **open** one (running
untrusted applications, AI agents, and games — the Desktop/AI initiative). Several isolation
controls that are *latent* today become *critical* the instant untrusted code runs. This NCIP
names those risks with verified `file:line` evidence, ranks them, and amends the allocator and
boot-ABI assumptions of `NCIP-Kernel-012` (bump allocator, never frees) and `NCIP-Kernel-005`
(heap region selection) in light of an empirically reproduced kernel-heap-exhaustion DoS.

## Motivation

Two facts reframe every kernel-security decision and were missed by earlier planning:

1. **NexaCore does not control its execution substrate.** It runs as an *untrusted UEFI guest*
   under a hypervisor it does not own (Proxmox/KVM in the reference deployment, the test VM).
   The effective security posture is therefore `(host posture) ∩ (guest posture)`. The kernel
   MUST NOT assume the availability of any opportunistic CPU feature (PKS, CET, eIBRS, LAM,
   up-to-date microcode) and MUST degrade gracefully when a feature is absent. The only
   defense against a *malicious host* is confidential computing (Intel TDX / AMD SEV-SNP),
   which is necessarily a deployment-time profile, not an always-on default.

2. **Closed-today vs open-tomorrow.** There is currently no `FileWrite`/`exec` syscall and no
   path for Ring-3-supplied code; all driver/process ELF images are baked into
   `EMBEDDED_INITRAMFS` at compile time. Consequently the most severe isolation defects are
   **latent** — not reachable by an attacker today — but they become **directly exploitable**
   the moment NexaCore runs untrusted code, which is the explicit goal of the Desktop/AI/games
   roadmap. They MUST be closed *before* that milestone ships, not after.

A reproduced, HW-captured kernel-heap-exhaustion DoS (a user-space NIC driver that replied to
itself on its own receive channel, spinning `ipc_send` 66.6 million times until the
never-freeing `BumpHeap` filled its 128 MiB arena and `handle_alloc_error` panicked the
kernel) is the concrete trigger: it proves the kernel's memory and IPC subsystems can be
exhausted by a *logic* bug that Rust's type system does not catch, and that the bump allocator
cannot recover from by design. The fix for the *class* is bounded queues with backpressure —
not a hardened freeing allocator and not an seL4-style rewrite. This NCIP records that finding
and the surrounding analysis so the decision is traceable.

## Specification

> The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are used per RFC 2119.

### §S1. Trust and substrate assumptions *(normative)*

S1.1 The kernel MUST treat the hypervisor and the platform firmware as **outside its trust
boundary** in any deployment that does not run under an attested confidential-computing
profile (§S6). Documentation and threat analyses MUST state, for each mitigation, whether its
efficacy depends on a host-controlled property.

S1.2 The kernel MUST NOT make correctness or safety contingent on an opportunistic CPU feature
being present. Every such feature MUST be **probed at boot (CPUID / KVM CPUID leaf)** and the
kernel MUST run correctly, with a documented reduction in defense-in-depth, when it is absent.
The kernel MUST record the *effective* mitigation posture (which features were activated) as an
infrastructural telemetry line at boot.

S1.3 Two trust postures are defined and MUST be distinguished in design and review:
- **Closed posture** — every executable is baked at build time; the supply chain is the build.
- **Open posture** — the kernel loads or executes code it did not author. Any control whose
  failure is exploitable only in the open posture is classified **"target-open"**; it MUST be
  closed before the first open-posture capability (user `exec`, third-party driver load,
  downloaded app/agent/game) is enabled.

### §S2. Verified risk inventory *(normative reference; severities binding for prioritization)*

Each item was verified by reading the cited source at the stated revision. Severity is the
maximum over postures; "exploitable" states the posture in which it is reachable.

| ID | Risk | Sev | Exploitable | Evidence |
|----|------|-----|-------------|----------|
| R1 | **Forgeable capability tokens.** Kernel signing seed is a public constant `0xCAFEBABE×8`; `mmio_map`/`dma_map`/`irq_attach` verify the signature against the issuer key *embedded in the token* with **no `KNOWN_ISSUERS` allowlist on the syscall path**; `subject` is the placeholder `[0;32]`. The only syscall gate is the (forgeable) token. ⇒ a process reaching the driver syscalls can self-sign a token for arbitrary MMIO/DMA/IRQ. | Critical | target-open | `driver_cap_issuer.rs` (`DRIVER_CAP_ISSUER_SEED`), `capabilities.rs` (`verify_signed_token`), `nexacore-capability/src/token.rs` (`verify_full`/`verify_signature`), `bare_metal/syscall_entry.rs` (`mmio_map` gate) |
| R2 | **IOMMU provides no DMA confinement.** Backend is passthrough/dormant ("emits no MMIO"); bus-mastering is enabled on devices; user drivers write device descriptor physical addresses directly ⇒ arbitrary-physical DMA. | Critical | target-open | `bare_metal/iommu/vtd.rs` ("Dormant VT-d backend"), `bare_metal/iommu/mod.rs` (Passthrough), `bare_metal/pci_scan.rs` (BME) |
| R3 | **User-space W^X violation.** The ELF loader never sets `PTE_NO_EXEC`; a writable data segment is mapped **RWX**. | High | target-open | `bare_metal/elf_loader.rs` (`pte_flags`, active path) |
| R4 | **Kernel heap cannot free + IPC waiter queues are unbounded.** `BumpHeap::dealloc` is a no-op; blocking send/recv re-push the task into `waiters_*` on every spurious wake ⇒ unbounded growth ⇒ kernel-heap OOM (the reproduced DoS class). | High | **closed (today)** | `bare_metal/heap.rs` (`dealloc` no-op), `ipc.rs` (`waiters_send`/`waiters_recv`), `bare_metal/syscall_entry.rs` (`ipc_send`/`ipc_receive` retry loops) |
| R5 | **Cheap CPU mitigations absent.** `SMEP`/`SMAP`/`UMIP` not set; `PTE_NO_EXEC` not applied to user pages (see R3). | Medium | target-open | `bare_metal/mp_trampoline.rs`, `bare_metal/syscall_entry.rs` (`syscall_init`) |
| R6 | **No measured/Secure Boot; `nexacore-tee` not linked; TEE attestation is an all-zero placeholder.** Makes the R1 trust-root unfixable until a real sealing key exists. | High (mesh node) | latent | `capabilities.rs` (placeholder node id), `nexacore-tee/*` (stubs), `nexacore-kernel/Cargo.toml` |
| R7 | **SMP-latent unsafety.** `SYSCALL_KERNEL_RSP`/`SYSCALL_USER_RSP_SCRATCH` are BSP-global `static mut`; user-copy TOCTOU; `static mut` registries. Safe only because the hot path is single-CPU with `IF` masked. | Critical (SMP) | only when APs run user tasks | `bare_metal/syscall_entry.rs` (entry asm + scratch), `ipc.rs` registries |
| R8 | **Unvalidated ELF `p_vaddr` / header arithmetic.** No user-half bound, no alignment, no overflow checks. | Medium | target-open | `bare_metal/elf_loader.rs` |

S2.1 (binding) The prioritization in §S7 MUST follow `exploitability-when-open × inverse-cost`.
R1 is the highest-priority *design* defect; R4 and R7(SMP) are the only items active in the
current closed/single-CPU posture.

### §S3. Tier A — zero-runtime-cost mitigations (eliminate by construction / verify) *(normative)*

A-tier mitigations remove a risk at no steady-state runtime cost and MUST be preferred over any
runtime check that addresses the same risk.

S3.1 **Fix the bug as the mitigation.** R3 (set `PTE_NO_EXEC` on non-`PF_X` segments), R8
(validate `p_vaddr` user-half + alignment; `checked_*` arithmetic), and the "user-private VA"
assertion at the page-map boundary MUST be implemented as the primary mitigation for those
risks; they are ~1-line/structural and cost nothing at runtime.

S3.2 **Bounded queues + per-channel/per-principal quotas** (R4): the IPC layer MUST NOT grow a
waiter queue without bound; a task already queued as a waiter MUST NOT be re-enqueued. The
number of channels a principal may create MUST be capped. This — not a freeing allocator —
is the canonical fix for the heap-exhaustion class.

S3.3 **Rust safe core + verified `unsafe` boundary.** The `unsafe` blocks (the ≈10% of the
kernel where the type system's guarantees end) are the TCB and MUST be treated as such: each
`unsafe` block MUST carry a documented invariant, and the security-critical `unsafe` cores
(allocator internals, page-table walk, user copies, IPC) SHOULD be covered by Miri (UB /
provenance) and Kani (bounded model checking) on a host harness plus property/fuzz tests. This
removes whole bug classes at compile/CI time at zero runtime cost.

S3.4 **W^X by hardware page bits** (NX) and **capability unforgeability** are design-elimination
controls and MUST be the default; they cost nothing at runtime.

### §S4. Tier B — cheap, universally-available hardware mitigations *(normative)*

B-tier features are available to a KVM guest on essentially any host CPU of the last decade and
cost ~0 at steady state. They constitute the **non-negotiable baseline** and MUST be enabled
when CPUID reports support:
- `NX`/XD (per-PTE), `CR0.WP`, `SMEP` (CR4.20), `SMAP` (CR4.21) with `STAC`/`CLAC` bracketing
  **every** legitimate user-memory access, and `UMIP` (CR4.11).

S4.1 Enabling `SMAP` is **boot-critical**: a single un-bracketed user access faults the kernel.
Its rollout MUST be a dedicated change that (a) wraps all user-copy sites under `STAC`/`CLAC`
and (b) is verified on hardware before merge. It MUST NOT be bundled with unrelated changes.

### §S5. Tier C — opportunistic hardware mitigations (probe-and-degrade) *(normative)*

C-tier features give strong protection cheaply *when present* but are **not guaranteed** on an
arbitrary host (per §S1.2). Each MUST be CPUID/KVM-probed and used only if exposed, with a
documented fallback:
- **PKS/PKRU** protection-key compartments (read-only/inaccessible kernel page tables,
  capability tables) — ~tens of cycles/switch, no TLB flush, ≈10–100× cheaper than `mprotect`.
- **CET shadow stack + IBT/FineIBT** for ROP/JOP — measure on the IPC hot path (indirect-heavy)
  rather than relying on straight-line SPEC numbers.
- **LAM** pointer tagging for `unsafe`/driver arenas only (Rust covers the safe subset; note
  LAM widens the SLAM speculative surface — enable only with the corresponding mitigation).
- **Transient-execution posture**: prefer enhanced-IBRS/Auto-IBRS over retpoline, and rely on
  hardware Meltdown fixes (skip KPTI) **only after** confirming the host CPU provides them;
  otherwise fall back (PCID-backed KPTI).

S5.1 Performance numbers quoted for C-tier features in external literature are predominantly
native benchmarks; the kernel MUST measure the realized cost on the target KVM guest before
treating any C-tier feature as "free" in planning.

### §S6. Tier D — costly mitigations: adaptive or opt-in *(normative)*

D-tier mitigations have material cost and MUST be opt-in or scoped, never always-on defaults:
- **Confidential computing (TDX / SEV-SNP)** is the *only* defense against a malicious host
  (§S1.1) and MUST be offered as an explicit **"NexaCore Confidential" deployment profile** with
  remote attestation, not enabled by default (overhead is large on IPC/IO-heavy paths).
- **Time protection** (cache colouring + micro-architectural state flush at domain switch)
  MUST be applied only at boundaries between security-sensitive domains.
- **Allocator quarantine / slot randomization** (if a freeing allocator is later introduced,
  §S8) MUST default off and be reserved for high-risk user-space sandboxes.

S6.1 (binding prohibition) The kernel MUST NOT implement a "relax mitigations for a trusted
process" mode. Latency for latency-sensitive workloads (e.g. games) MUST instead be obtained by
**core isolation** (per-CPU run queues, tickless/`nohz`-style operation, IRQ steering, an
MCS-style scheduling-context budget) which reduces jitter **without weakening any security
boundary**. Combining a mitigation-relaxation switch with the forgeable-capability defect (R1)
would create a direct user→kernel escalation; the switch is therefore forbidden.

### §S7. Roadmap — work items, order, and acceptance criteria *(normative)*

Implemented in this priority order (`exploitability-when-open × inverse-cost`). Each work item
("WI") is a separate change with its own gates.

- **WI-1 (Tier A, this NCIP's first increment): R3 + R8.** ELF loader sets `PTE_NO_EXEC` on
  non-`PF_X` segments; rejects non-user-half / unaligned `p_vaddr`; `checked_*` arithmetic on
  all header/segment math. *Accept:* host unit tests prove NX on data segments, executable code
  segments preserved, malformed segments rejected; M0 boot unaffected (baked ELFs well-formed).
- **WI-2 (Tier A, this increment): R4.** IPC waiter-queue dedup (no re-enqueue of an
  already-queued task) + per-principal channel-count cap. *Accept:* host unit tests prove no
  duplicate waiter under repeated blocking send/recv and the channel cap is enforced.
- **WI-3 (Tier A, this increment): R1 (partial).** `KNOWN_ISSUERS` allowlist enforced on the
  `mmio_map`/`dma_map`/`irq_attach` syscall path. *Accept:* a token whose issuer ∉
  `KNOWN_ISSUERS` is rejected; the legitimate deposited-capability path (the dev issuer, which
  is in `KNOWN_ISSUERS`) still passes; M0 driver bring-up unaffected.
- **WI-4 (Tier B, dedicated HW-verified step): R5.** `cpu_features_init` enabling
  SMEP/UMIP/WP, then SMAP with `STAC`/`CLAC` bracketing every user copy. *Accept:* boots on
  the test VM with the features reported active; all user-copy syscalls still function.
- **WI-5 (R7, before un-parking APs): per-CPU `SYSCALL_KERNEL_RSP`** (GS-relative) + per-CPU
  registries / TOCTOU hardening. *Accept:* SMP smoke test with APs running user tasks.
- **WI-6 (R1 completion): unique per-process principal** (replace `KernelPrincipal::ZERO`) +
  **TEE-derived signing seed** (depends on `nexacore-tee`; requires its own key-custody NCIP, see
  `NCIP-Key-Custody-017`). *Accept:* distinct principals isolate IPC subjects; seed sourced from
  a sealing key, not the compile-time constant.
- **WI-7 (R2): IOMMU live programming — CLOSED 2026-06-06 (operator-accepted; §S9.1 fault
  *report* hardware-gated).** Per-device second-level domains; token destruction revokes DMA;
  bus-master enable gated on domain attach. *Accept:* a driver confined to its domain cannot
  DMA outside its mapped windows — **met on the test VM**: `GCMD.TE` raised live, virtio-net
  confined to its SLPT with M0 `HTTP 200` under translation, revocation (detach + invalidation)
  verified live, 0 PF/panic. The §S9.1 negative *fault-report-in-log* sub-criterion is
  **deferred to real VT-d / vfio hardware** — QEMU does not drive the FRCD fault-recording
  path for emulated devices (definitive root-cause, 4 boots incl. `caching-mode=on`; the
  out-of-window read IS blocked, only its report is unobservable on the emulator). Same
  hardware-gated class as WI-8's TEE quote; the `iommu-negtest` capture harness is committed
  and ready. Detail below.
  - **Phase 1 (2026-06-05):** vIOMMU substrate on the test VM (`-device intel-iommu`); probe
    detects `IommuVendor::Intel`, `vt-d activated` (root table + IQA + global IOTLB
    invalidate). `GCMD.TE` NOT raised → behavioural passthrough; M0 unaffected (HW 5/5).
  - **WI-7a (2026-06-06, ADR-0026):** **real second-level page-table builder** —
    `vtd::{map_4k_slpt, map_range_slpt, unmap_4k_slpt, translate_slpt}` walk the multi-level
    SLPT tree, allocating intermediate tables from `pt_alloc::FrameSource` (extended with
    `read_entry`/`write_entry`). Closes the gap that `VtdBackend::map` only *recorded* a
    tuple in a `Vec`; with TE off this is inert (passthrough), so an eventual TE flip will
    *translate* legitimate DMA instead of faulting it. Host-tested via `MockFrameSource`
    (14 tests: walkable tree + translate, intermediate reuse, range map, unmap, frame
    exhaustion, RO-leaf permission, 3- vs 4-level AGAW). **Not yet wired into the live
    `dma_map` path** and TE stays off — deliberate, so M0 cannot regress (re-verified on
    the test VM). Status: **WI-7a CLOSED**.
  - **WI-7b (CLOSED 2026-06-06 — wiring + TE flip + confinement + revocation live on the test VM;
    negative fault-report hardware-gated):**
    - **Step 1 (2026-06-06):** live `CAP.SAGAW` read + cache at activation; the test VM
      reports `sagaw=6 levels=4` → 48-bit/4-level AGAW confirmed for every context
      entry + SLPT build.
    - **Step 2 (2026-06-06, ADR-0027):** full live wiring with TE off — `DmaMap (71)`
      and `tear_down_dma_mappings` route through `iommu_map_window`/`iommu_unmap_window`
      (real SLPT build/clear on Intel via `VtdBackend::{map_with_src,unmap_with_src}`,
      `KernelFrameSource`-threaded); the deposit-path spawn binds boot-loaded drivers
      (M0 virtio-net, ADR-0024) with `install_domain` + per-BDF attach + SLPT-root
      provision + live context-entry install sized to live SAGAW
      (`bind_driver_iommu_domain`); `flush` submits per-domain IOTLB invalidates through
      the invalidation queue (mandatory under `CAP.CM=1`); `release_domain_pt` frees the
      whole SLPT subtree (leak fix); `enable_translation` re-asserts `QIE` alongside `TE`
      (§ 11.4.4 fix — TE-only write would have silently disabled the invalidation queue);
      the `DriverLoad` TE auto-flip is compiled out behind the **`iommu-te` cargo feature
      (default OFF)**. Host tests 289 → 301 iommu; workspace `--all-features` 4968 → 4979.
    - **Step 3 C0 (2026-06-06, ADR-0028):** M0-safe TE-flip substrate, TE still off,
      incorporating a tee-specialist VT-d-spec review (verdict on the as-was flip path:
      REJECT, 100 % M0-brick). (a) **identity `phys_base→phys_base` SLPT** — the device
      emits `phys_base` (the `DmaMap` return, programmed into descriptors), so the SLPT is
      now keyed on `phys_base`, resolving the pre-flip IOVA-vs-phys decision below in favour
      of **option (b)**; `DmaMapping` gains `phys_base`, teardown clears the SLPT there.
      (b) **`UntranslatedOnly` (TT=00b)** for the confined entry — 01b needs device ATS +
      `ECAP.DT`, absent on QEMU `intel-iommu`; 00b routes all DMA through the SLPT.
      (c) **DMAR fault reader** — `CAP.FRO`/`CAP.NFR` + FSTS/FRCD decoders +
      `VtdBackend::drain_faults`/`iommu_drain_faults` for the §S9.1 negative test. the test VM
      re-verified TE-off: HTTP 200, `translation enabled`=0, PF=0. Host iommu 301 → 307;
      workspace `--all-features` 4979 → 4985.
    - **Step 3 C1 (2026-06-06, ADR-0028) — first `GCMD.TE` flip, DONE:**
      `iommu_finalize_enable_translation` (kmain, before the desktop loop, behind `iommu-te`)
      scans every PCI device and installs a Passthrough (TT=10b, `slpt_phys=0`,
      `AW=highest CAP.SAGAW`) context entry for each that does not already have one (the
      in-kernel virtio-tablet/e1000e/NVMe/virtio-blk/USB — absent entry = blocked on TE),
      then raises `GCMD.TE` only if every install succeeded. For C1 the confined virtio-net
      is ALSO on passthrough, so the flip is behaviourally TE-off for DMA — isolating
      enumeration completeness from SLPT correctness. the test VM (`iommu-te` build):
      `passthrough installed=28 skipped=1 failed=0`, `GCMD.TE raised — translation ENABLED`,
      `0 DMAR faults post-flip`, full M0 `HTTP 200` AFTER the flip, e1000e + tablet alive,
      PF=0, REPL. Translation genuinely enforced (GSTS.TES observed).
    - **Step 3 C2 (2026-06-06, ADR-0028) — virtio-net CONFINED, DONE:** `bind` switched to
      `UntranslatedOnly` (TT=00b) for virtio-net → all of its DMA routes through its identity
      `phys→phys` SLPT (built by the driver's `DmaMap`); a pre-flip guard
      (`iommu_domain_has_mappings`) refuses the flip until that SLPT is built, so an early
      flip cannot fault the driver. the test VM (`iommu-te`): `GCMD.TE raised — translation
      ENABLED`, `0 DMAR faults post-flip`, `M0 E2E COMPLETE: HTTP 200` with virtio-net's DMA
      going through its SLPT (R2 DMA confinement achieved + the §S9.1 POSITIVE test), PF=0,
      REPL. Host-side §S9.1 confinement proof: `slpt_confines_dma_to_mapped_window_only`
      (in-window → translated, just outside → None). iommu host tests 310; workspace 4988.
    - **Step 3 negtest harness (2026-06-06, ADR-0029) — revocation DONE; live negative-fault
      HARDWARE-GATED:** DEV-only `iommu-negtest` feature gives the in-kernel e1000e (M0 does
      not use it) a translating context entry with an EMPTY SLPT, then forces a TX after the
      flip so its descriptor read is an out-of-window DMA. A **deterministic wait-barrier**
      was added to the finalize step (bounded busy-spin until confined domains' SLPT is built,
      timer dispatches the driver during the spin) so the flip is no longer timing-dependent —
      the test VM confirms `confined domain SLPT ready` → `GCMD.TE raised` reliably. the test VM
      (4 attempts, the last two with **`caching-mode=on`**): the e1000e **revocation** path
      (detach + context-cache + IOTLB invalidation) ran live and clean, M0 stayed up
      (virtio-net confined, `HTTP 200`), system stable — **but no DMAR fault was recorded with
      OR without `caching-mode=on`** (`FSTS=0`, `FRCD[0]=0` at the confirmed `CAP.FRO=0x220`,
      even with a non-zero unmapped TX-ring base; the Proxmox host `journalctl` shows no VT-d
      fault line either). **Definitive root cause:** QEMU does not drive the
      `vtd_report_dmar_fault` → FRCD path for *emulated* devices — its `pci_dma_read` returns
      an error the e1000e model ignores; only **vfio-passthrough** devices and **real VT-d
      silicon** exercise the fault-recording path. e1000e shares bus 6 with virtio-net (whose
      DMA QEMU demonstrably translates — M0 works), so e1000e's DMA *is* translated and the
      out-of-window read *is* blocked; only the fault *report* is unobservable on the emulator.
      The live FRCD-observed negative fault is therefore **hardware-gated** (real VT-d / vfio) —
      the same class of deferred criterion NCIP-026 applies to WI-8's TEE quote — and the harness
      is committed and ready to capture it on real hardware. `drain_faults` hardened to scan
      FRCD unconditionally. For real silicon add the `CAP.RWBF` check + `GCMD.WBF` (QEMU
      `RWBF=0`). Bus-master gating re-home (`virtio_net_live_bringup` status-dance removal) is
      the remaining WI-7 cleanup.
    - **Confinement status:** PROVEN on the VM — C2 positive (virtio-net confined to its SLPT,
      M0 live, translation enforced under `GCMD.TE`), host SLPT test (out-of-window → `None`),
      live revocation. Only the live device-fault *report* is hardware-gated (QEMU emulated-
      device limitation), with the capture harness ready.
    Tracked in `PLAN.md` TASK-07 deviation log.
- **WI-8 (R6): measured boot + attestation** and the **NexaCore Confidential profile** (§S6).
- **WI-9 (capacity): freeing allocator where genuinely needed** (§S8).

### §S8. Amendment to NCIP-Kernel-012 / NCIP-Kernel-005 (allocator) *(normative)*

S8.1 The "never-free bump allocator" of `NCIP-Kernel-012` and the region selection of
`NCIP-Kernel-005` remain correct for **long-lived, allocate-once** kernel structures and are
**not** superseded for that use. The bump allocator's design rationale assumed long-lived
allocations; the network datapath violated it with per-message churn.

S8.2 The datapath churn MUST be addressed by §S3.2 (bounded queues / quotas / no per-message
unbounded growth), **not** by replacing the global allocator.

S8.3 A freeing allocator MAY be introduced later (WI-9) **only** for genuinely dynamic kernel
state that cannot be served by bounded pools. If introduced, it MUST: be a small, auditable
core (a vetted `no_std` crate such as a TLSF/`rlsf`- or `talc`-class allocator, wrapped, OR a
custom core) with **out-of-band metadata**, **guard pages** for large allocations, **canaries**
and **small-slot zero-on-free** (the "light"/near-free hardening tier), and be **verified**
(Miri + Kani + fuzz) before it enters the TCB. Quarantine and slot randomization default off
(§S6). This is an amendment requiring its own activation gate; it does not auto-enable here.

S8.4 The seL4-style "no kernel heap" (untyped/capability memory delegated to user space) is
recorded as the long-term **north-star** architecture but is explicitly **out of scope** for
the current phase: it requires a user-space memory broker and an IPC redesign and is not a
"zero-cost" change at this stage.

### §S9. Process *(normative)*

S9.1 This NCIP is filed `Draft`. Implementation of the Tier-A increment (WI-1..WI-3) proceeds
under the founder's direction per `NCIP-Process-001` §5.5 (Solo Founder Fast-Track); each WI
lands with the project's standard gates (stable `rustfmt`, `clippy -D warnings` across the host
workspace + bare-metal + image crates, host tests, DCO sign-off) and, for any WI that changes
boot or hardware behavior (WI-4, WI-5, WI-7), a verbatim hardware capture on the test VM.

## Rationale

The analysis began as "how do we harden a freeing kernel allocator (Option A)?" An adversarial
review established that (a) no freeing allocator exists yet — the question was malformed; (b)
the reproduced DoS is unbounded growth, which a freeing allocator would not by itself fix; and
(c) the allocator is not the top risk — forgeable capabilities (R1), dormant-IOMMU DMA (R2),
and user W^X (R3) are more severe, and the substrate-trust assumption (§S1) was unstated.

The tiered structure follows the empirical finding that the best security-per-performance comes
from *eliminating bug classes* (Rust + verification + correct design) and *using hardware
already present* (NX/SMEP/SMAP), reserving paid mitigations for an adaptive/opt-in tier. This
mirrors how seL4 (verification → zero runtime cost; no kernel heap), Fuchsia/Zircon (Scudo;
policy-driven driver isolation vs colocation), and hardened userspace allocators
(`hardened_malloc` "light" profile = canaries + zero-on-free, quarantine off) actually buy
security cheaply.

**Alternatives considered and rejected:**
- *Replace the global allocator with a hardened freeing allocator now (original "Option A").*
  Rejected as the primary fix: it does not address the unbounded-growth DoS and adds a complex
  component to the TCB before the cheaper bounded-queue fix is in place. Retained as WI-9, scoped.
- *Adopt the seL4 untyped/no-kernel-heap model now.* Rejected for this phase (§S8.4): multi-year
  rewrite + IPC redesign; recorded as north-star.
- *A "trusted process" mitigation-relaxation mode for games.* Rejected (§S6.1): a well-known
  escalation foot-gun, doubly dangerous with R1 unfixed; core isolation achieves the latency
  goal without weakening boundaries.
- *Assume host CPU features (PKS/CET/eIBRS) are available.* Rejected (§S1.2): NexaCore is an
  untrusted guest; features are probe-and-degrade, not assumptions.

## Backwards Compatibility

The Tier-A increment is behavior-preserving for the current closed posture: baked ELF images
are well-formed (code segments keep `PF_X`; data segments gain NX, which they should already
respect), the IPC dedup only removes pathological duplicate waiters, and the issuer allowlist
admits the existing dev issuer that the M0 drivers already use. No wire format, on-disk
artifact, or syscall ABI changes in WI-1..WI-3. WI-4 (SMAP) and later items may change boot
behavior and are gated on hardware verification (§S9.1). The allocator amendment (§S8) does not
remove the bump allocator; it constrains how the datapath uses memory.

## Test Cases

- WI-1: unit tests asserting `pte_flags` sets `PTE_NO_EXEC` iff `PF_X` is absent; that a
  W-without-X segment is NX; that a segment crossing `USER_HALF_END`, an unaligned `p_vaddr`,
  and an overflowing header are rejected with a typed error.
- WI-2: unit tests asserting a task blocking twice on a full channel appears **once** in
  `waiters_send`; symmetric for `waiters_recv`; that channel creation past the per-principal cap
  returns an error.
- WI-3: unit tests asserting a token signed by an issuer ∉ `KNOWN_ISSUERS` is rejected by
  `mmio_map`/`dma_map`/`irq_attach`, and a token signed by the in-allowlist issuer is accepted.
- WI-4/5/7: hardware smoke captures on the test VM (verbatim serial + behavior), per §S9.1.

## Reference Implementation

WI-1..WI-3 land alongside this NCIP on `feat/m0-networking-e2e` (or a successor branch).
Subsequent WIs land as separate, individually-gated changes referenced from this NCIP. The risk
inventory (§S2) cites the exact sources audited; the reference implementation updates those
sites and adds the tests in `Test Cases`.

## Security Considerations

This NCIP *is* the kernel's security-considerations baseline. Key residual risks it explicitly
names rather than closes: a malicious **host** is only addressed by the opt-in Confidential
profile (WI-8); **side channels** (Spectre/MDS/Rowhammer) are partly inherited from the host
posture and addressed by §S5 + host microcode currency, not fully eliminable in a guest; the
**`unsafe` boundary** (the kernel's `unsafe` blocks) remains the TCB and is addressed by
verification (§S3.3), not by language guarantees. Rust eliminates the spatial-memory-safety
class in safe code but **not** logic/authorization/DoS bugs (R1, R4) or `unsafe`-boundary bugs;
planning MUST mitigate *for* the unsafe boundary, not assume it away.

## Privacy Considerations

The mitigations here are infrastructural and process no user data. Two privacy-positive effects
are intended: **zero-on-free** (if WI-9 lands) prevents cross-allocation leakage of secrets
(keys, plaintext) in reused kernel memory; the **Confidential profile** (WI-8) protects guest
memory — including any user data resident at runtime — from an untrusted host. The boot-time
mitigation-posture telemetry (§S1.2) MUST contain only infrastructural feature flags, never
user-derived values.

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
