# Changelog

All notable changes to NexaCore OS are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
During Phase 1 the project uses alpha pre-release versioning; the public API is
not yet stable and may change between releases.

## [Unreleased]

### Added
- Block-device request/response types and IRQ-attach wiring for the user-space
  driver framework.
- NVMe driver end-to-end IPC loop.

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

[Unreleased]: https://github.com/CySalazar/nexacore-os/compare/v0.3.0-alpha.1...HEAD
[0.3.0-alpha.1]: https://github.com/CySalazar/nexacore-os/releases/tag/v0.3.0-alpha.1
[0.2.0]: https://github.com/CySalazar/nexacore-os/releases/tag/v0.2.0
[0.1.0]: https://github.com/CySalazar/nexacore-os/releases/tag/v0.1.0
