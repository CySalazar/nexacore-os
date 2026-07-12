# Changelog

All notable changes to NexaCore OS are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
During Phase 1 the project uses alpha pre-release versioning; the public API is
not yet stable and may change between releases.

## [Unreleased]

## [0.3.0-alpha.2] — 2026-07-12

A broad Phase-2 build-out: on top of the microkernel there is now a working
userspace operating system — networking, storage, an AI runtime, and a desktop
with native applications. The workspace holds 86 crate packages and ~7,700
tests.

### Added
- **Userspace networking stack.** Full dual-stack TCP/IP (ARP, IPv4/IPv6,
  ICMP/ICMPv6, UDP, RFC-793 TCP + Reno, DNS, DHCPv4/v6, NDP/SLAAC, PMTU,
  conntrack, firewall, socket API), TLS 1.3 client + server, and SSH-2
  (curve25519 kex, Ed25519 host key, ChaCha20-Poly1305, publickey/password
  userauth, RFC-4254 channels).
- **Storage and filesystems.** Native NCFS user-space service with an on-disk
  v3 format (superblock, inodes, extents, B-tree, Merkle integrity, block
  crypto, snapshots, mkfs) over a `BlockDevice` seam, plus read-only FAT12/16/32,
  ext2/3/4, and NTFS compatibility readers.
- **AI runtime, agents, and privacy.** Real `no_std` CPU inference chain (GGUF
  loader, tensor dequantization, byte-level BPE, transformer forward pass,
  greedy decode) with local-CPU and Ollama providers behind a resilient
  failover router; a five-agent framework (orchestrator, guidance, sysadmin,
  security, task) with a differential-privacy accountant; a declarative
  workflow engine; on-device PII tokenization with a TEE-sealed vault; and a
  local-first personal-context store.
- **Desktop and native applications.** A userspace compositor / window manager
  (damage tracking, focus and input routing, glyf font rasterization and
  shaping, IME), a retained-mode brand UI toolkit, and native apps: a
  POSIX-style terminal shell, a text editor (PieceTable buffer + syntax
  highlighting), a file manager, and media / image / PDF viewers.
- **Userland and services.** A PID-1 supervisor (service manifests, dependency
  graph, health checks, socket activation), a GPT installer with A/B slots, an
  IPP printing stack, a content-addressed federated package manager, and a
  family of `no_std` CLI network tools (ping, traceroute, nslookup, netstat,
  route, ifconfig, curl, wget).
- **Kernel subsystems.** Per-device IOMMU (Intel VT-d + AMD-Vi), PCI ECAM
  scanning, MSI-X, S4 hibernate with a device suspend/resume power-management
  framework, and USB xHCI HID input on the desktop.
- **Post-quantum cryptography.** ML-DSA-65 (FIPS 204) and ML-KEM-768 (FIPS 203)
  with known-answer-test vectors, alongside the existing RustCrypto primitives.

### Changed
- User-space drivers grew from scaffolds into substantial host-tested cores —
  NVMe, virtio-net, e1000e, Wi-Fi (WPA2/WPA3 supplicant + 802.11), TPM 2.0,
  HD-audio, and virtio-gpu — with privileged hardware execution delegated to
  their Ring-3 image siblings. NVMe, virtio-net, and e1000e run on Proxmox.

### Fixed
- The desktop no longer freezes during long interactive sessions: the
  never-freeing bump allocator was replaced with a reclaiming size-class
  free-list allocator, so input, rendering, and terminal commands no longer
  exhaust the heap.
- USB HID input no longer stalls after the interrupt-IN transfer ring wraps
  (corrected TRB cycle-bit handling on the ring boundary).

### Security
- Established the Ed25519 release-signing key for tagged releases; the public
  half is committed at `keys/nexacore-release-ed25519.pub.pem` and verifies the
  detached `.sig` published next to each release ISO (see `keys/README.md`).

### Known limitations
- The container (micro-VM) engine and TEE backends are partial: confidential-VM
  paths (Intel TDX / AMD SEV-SNP) and per-container attestation are feature-gated
  scaffolds. The mesh transport and routing layers are Phase-4 stubs.

## [0.3.0-alpha.1] — 2026-05-20

Phase 1 (Microkernel PoC) milestone; Phase 2 (AI Runtime) entered in parallel.
A large multi-crate workspace with an extensive automated test suite.

### Added
- **Kernel — bare-metal track MB1–MB14 closed.** Multiprocessor boot with live
  INIT-SIPI AP bring-up, cross-CPU context switching, TLB shootdown, per-CPU
  run queues, x2APIC, Ring 3 with per-process `CR3`, IPC and multitasking,
  kernel-stack isolation, AP dispatch loop.
- **User-space driver framework (P6.7).** Full `NCIP-013` syscall set
  (`MmioMap` / `DmaMap` / `IrqAttach` / `DriverLoad`) wired end-to-end; kernel
  CSPRNG (`RDRAND` + `RDTSC` → ChaCha20); kernel-side Ed25519 capability issuer
  with a read-only token deposit window; virtio-net, NVMe, and e1000e driver
  scaffolds plus bootable image siblings, validated on real hardware.
- **Desktop track A M1–M5 + terminal shell.** GOP framebuffer, bitmap font,
  software cursor, PS/2 + VirtIO tablet input, widget toolkit, desktop window
  manager, RTC clock, ACPI S5 power-off, build-info panel.
- **AI runtime — Phase 2 Sprint 7 E2E.** Native transformer engine, GGUF model
  loader, and BPE tokenizer, with a provider abstraction (native CPU + optional
  remote bridge).

## [0.2.0] — 2026-05-18

### Added
- **Kernel — Track B foundations.** Frame allocator, page-table walker, IDT,
  `SYSCALL`/`SYSRET`, ELF64 loader, scheduler, LAPIC timer.
- MB9 huge-page-aware paging, MB10 kernel-stack isolation, MB11 Ring 3
  trampoline with per-process address spaces.

## [0.1.0] — 2026-05-10

### Added
- Initial architecture and protocol design complete.
- Foundational workspace and crate scaffolding, toolchain pinning, CI matrix,
  lint and dependency policies.
- Formal protocol specifications and Tamarin/ProVerif handshake proofs.

[Unreleased]: https://github.com/CySalazar/nexacore-os/compare/v0.3.0-alpha.2...HEAD
[0.3.0-alpha.2]: https://github.com/CySalazar/nexacore-os/releases/tag/v0.3.0-alpha.2
[0.3.0-alpha.1]: https://github.com/CySalazar/nexacore-os/releases/tag/v0.3.0-alpha.1
[0.2.0]: https://github.com/CySalazar/nexacore-os/releases/tag/v0.2.0
[0.1.0]: https://github.com/CySalazar/nexacore-os/releases/tag/v0.1.0
