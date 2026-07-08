# ADR-0008 — MB14.f Per-CPU LAPIC scheduling protocol (AP enable + x2APIC)

- **Status:** Accepted
- **Date:** 2026-05-20
- **Deciders:** Matteo Sala (architect / sole founder)
- **Related:** ADR-0007 (MB14 MP/AP startup), `progress-nexacore.md` § 4.1.7, the backlog § MB14.e.4 (open follow-up closed by this ADR), `docs/06-roadmap.md` "Phase 1"

## Context

After MB14.e closed the per-CPU run-queue scaffold (`per_cpu_run_queue` with work-stealing) and the `sti` enable on the AP idle park, smoke validation on the Proxmox test VM surfaced an open issue tracked as **MB14.e.4**: the TLB shootdown broadcast (vector `0xFD`) reached every AP via the LAPIC ICR but the `Shootdown.ack` counter never incremented (`acked=0 / targeted=7`). Three hypotheses were on the table:

1. The AP LAPIC was not enabled (SIVR `LAPIC_ENABLE` bit 8 unset), so the LAPIC dropped the incoming Fixed-delivery IPI before the IDT could dispatch.
2. The AP's kernel stack overflowed on the first IRQ entry (1-frame stack, no guard).
3. The handler VA (`nexacore_tlb_shootdown_handler`) was not mapped in the shared kernel CR3 that the AP loaded post-trampoline.

Code review and ISR construction analysis isolated hypothesis (1): the AP went from real-mode boot → 64-bit kernel CR3 → `lgdt` / `lidt` / `ltr` → `sti` → `hlt`, **without ever programming its own Local APIC**. The BSP's `lapic_init` runs only on the BSP; the LAPIC is a per-CPU register block — every CPU must enable its own SIVR. Without that, a Fixed-delivery IPI is silently discarded by hardware (Intel SDM Vol 3A § 10.4.3, SIVR bit 8 = 0 means "APIC software disabled").

At the same time, MB14.f.2 was scheduled to land **x2APIC awareness**: server-class topologies report LAPIC IDs > 255 via the ACPI MADT `Processor Local x2APIC` ICS (type `0x09`), and those CPUs require MSR-based ICR writes (`IA32_X2APIC_ICR` at MSR `0x830`) rather than the xAPIC split MMIO `ICR_LO`/`ICR_HI` pair. The CPUID leaf `1 EBX[31:24]` 8-bit LAPIC ID also aliases beyond 255; CPUID leaf `0xB` sub-leaf 0 EDX returns the 32-bit ID in both modes.

Both pieces share the same call site (the `kmain_ap` global_asm! body and the kernel-wide LAPIC primitives), so MB14.f bundles them: AP LAPIC enable (.1), x2APIC awareness (.2), and per-AP periodic LAPIC timer setup (.3). Real per-CPU dispatch wiring — binding `RoundRobinScheduler` to `per_cpu_run_queue` and steering timer ticks into per-CPU resched decisions — stays out of scope and is tracked as MB14.g.

## Decision

### Sub-block decomposition

| Sub-block | Scope | Status |
|-----------|-------|--------|
| MB14.a    | Per-CPU descriptor scaffold (`PerCpu` struct + BSP LAPIC ID seed) | ✅ |
| MB14.b    | `IA32_GS_BASE` / `IA32_KERNEL_GS_BASE` per-CPU pointer + `swapgs` in `nexacore_syscall_entry` | ✅ |
| MB14.c.1  | ACPI MADT walker (`parse_madt` + `enumerate_cpus`) | ✅ |
| MB14.c.2.a| INIT-SIPI ICR encoder (xAPIC + x2APIC) + dry-run `start_aps` | ✅ |
| MB14.c.2.b.1 | Pure-function trampoline blob + temp GDT + temp identity-paging builders | ✅ |
| MB14.c.2.b.2 | Bare-metal emplacement of the trampoline page + temp PML4/PDPT/PD | ✅ |
| MB14.c.2.c | Live INIT-SIPI-SIPI fire + AP landing stub + ack barrier | ✅ |
| MB14.c.2.d | Per-AP `PerCpu` + per-AP kernel stack + real `kmain_ap` body | ✅ |
| MB14.d    | TLB shootdown IPI vector `0xFD` + `mm::flush_tlb_range` broadcast | ✅ |
| MB14.e    | Per-CPU run-queue + work-stealing scaffold + `sti` on AP idle park | ✅ |
| **MB14.f.1** | **AP LAPIC enable (`kernel_ap_lapic_init` + SIVR/TPR programming)** | **✅ (this ADR)** |
| **MB14.f.2** | **x2APIC awareness (mode detect + MSR-based EOI/ICR/SIVR/timer + 32-bit LAPIC ID read)** | **✅ (this ADR)** |
| **MB14.f.3** | **Per-AP periodic LAPIC timer at vector `0x20` (BSP-equivalent cadence)** | **✅ (this ADR)** |
| MB14.g    | AP-side dispatch — bind `RoundRobinScheduler` to `per_cpu_run_queue`, NEED_RESCHED per-CPU | open |

### MB14.f.1 specifics (AP LAPIC enable)

`bare_metal::lapic::kernel_ap_lapic_init()` is a Rust `extern "C"` function emitted with `#[unsafe(no_mangle)]`. The `kmain_ap` global_asm! body is extended with a `call kernel_ap_lapic_init` instruction inserted between step 7 (`ltr`) and step 8 (`lock inc AP_ONLINE_ACK`). RSP at the call site is the freshly-loaded per-CPU kernel stack top (16-byte aligned via the page-aligned frame allocation), satisfying the System V AMD64 ABI.

The Rust function:

1. Loads `X2APIC_MODE` (set once by the BSP at `lapic_init` time).
2. If `X2APIC_MODE` is set, flips `IA32_APIC_BASE` bits 10 (`EXTD`) + 11 (`EN`) on this AP — the BSP-side flip does not propagate to other CPUs.
3. Calls `program_lapic_local(mode)` which:
   - Writes SIVR with `LAPIC_ENABLE | 0xFF` (bit 8 set, spurious vector 0xFF).
   - Writes TPR = 0 (accept every priority).
   - Writes the LAPIC timer divider, LVT timer entry (periodic, vector `0x20`), and initial count (`1_000_000`), matching the BSP cadence.

Both register paths (xAPIC MMIO and x2APIC MSR) go through the same `program_lapic_local` helper, pinning the cross-mode equivalence in a single function.

### MB14.f.2 specifics (x2APIC awareness)

`bare_metal::lapic` is extended with:

- `LapicMode::{XApic, X2Apic}` enum and `detect_lapic_mode() -> LapicMode` that reads `IA32_APIC_BASE` bit 10.
- A global `X2APIC_MODE` `AtomicBool` initialised by `lapic_init` from the BSP-observed mode. Every primitive (`lapic_eoi`, `lapic_send_ipi`, `lapic_icr_busy`, `read_lapic_id`) consults this flag and dispatches to the corresponding MSR-based register when set.
- MSR constants pinned by host-side tests against the canonical Intel SDM Vol 3A Table 10-6 mapping (`MSR = 0x800 + (mmio_offset >> 4)`).
- `read_lapic_id()` returns the full 32-bit ID via `IA32_X2APIC_APICID` (MSR `0x802`) in x2APIC mode; the legacy MMIO path stays for xAPIC.
- The `kmain_ap` global_asm! body reads its own LAPIC ID via CPUID leaf `0xB` sub-leaf 0 EDX. In xAPIC mode EDX equals `EBX[31:24]` zero-extended (Intel SDM Vol 2 — CPUID leaf 0BH), so the same instruction works in both modes.

Explicitly **out of scope** for MB14.f.2: the kernel does **not** itself flip `IA32_APIC_BASE` bit 10 at runtime. On QEMU and Proxmox the BSP boots in xAPIC mode and stays in xAPIC mode unless the firmware advertised x2APIC ahead of OS handoff. The infrastructure is in place for a future BIOS that enables x2APIC pre-kernel — and for an opt-in runtime switch — without further refactoring.

### MB14.f.3 specifics (per-AP periodic timer)

`program_lapic_local` writes the LVT timer entry (periodic, vector `0x20`) and the initial count on every CPU. Because the IDT is shared across CPUs (the AP `lgdt`'s the BSP's kernel GDT and `lidt`'s the BSP's kernel IDT in MB14.c.2.d), every AP timer interrupt enters the same `nexacore_lapic_timer_handler` asm stub.

The Rust callback `kernel_lapic_timer_tick` short-circuits on AP CPUs via `current_cpu().is_bsp()`: AP timers EOI and return, **without** incrementing the global `TICK_COUNT` (which is `static mut u64`, not multi-CPU safe) and **without** setting the global `NEED_RESCHED` (which would race the BSP scheduler). `kernel_check_need_resched` carries the same guard defensively.

This intentionally leaves the AP timer interrupt as a no-op tick: the LAPIC stays unmasked and ready to accept IPIs (including the `0xFD` TLB shootdown vector), but no AP-side scheduling decision is made. MB14.g will:

1. Add per-CPU `TICK_COUNT` and `NEED_RESCHED` fields to `PerCpu`.
2. Bind `RoundRobinScheduler` (or a future per-CPU scheduler) to `per_cpu_run_queue` indexed by `current_cpu().cpu_id()`.
3. Replace the BSP-only resched gate with per-CPU dispatch.

## Consequences

### Positive

- **MB14.e.4 closed.** The TLB shootdown broadcast now reaches every AP and the ack counter reaches `targeted` within the BSP's busy-poll budget. The boot log line `[mb14.d] tlb_shootdown vector=0xFD targeted=N acked=N (all APs acked)` is no longer a stale placeholder.
- **x2APIC-capable.** On any firmware that enabled x2APIC pre-handoff, the kernel detects it at boot and routes every LAPIC access through the MSR-based registers. LAPIC IDs > 255 work end-to-end.
- **Per-AP timer ticking.** Each AP runs its own periodic LAPIC timer at the same cadence as the BSP. The infrastructure is in place for MB14.g per-CPU dispatch — only the resched callback needs to grow.
- **Test surface widened.** +6 host-side tests in `bare_metal::lapic::tests::*` pin every x2APIC MSR address against Intel SDM Vol 3A Table 10-6 and the canonical `MSR = 0x800 + (mmio_offset >> 4)` algebra.

### Negative

- **Single source of `X2APIC_MODE`.** The flag is set once by the BSP; APs trust it. If a future code path enables x2APIC after `lapic_init` (e.g. a runtime opt-in), every AP needs to re-run `kernel_ap_lapic_init` — there is no per-CPU re-init API yet. MB14.g should add `lapic::switch_to_x2apic_global()` that broadcasts a re-init IPI.
- **AP timer interrupts are wasted ticks.** Each AP fires `nexacore_lapic_timer_handler` every ~160 ms (QEMU TCG cadence) and immediately EOIs. The cost is negligible (a few hundred cycles per AP per tick) but it is a deliberate placeholder until MB14.g.
- **`TICK_COUNT` remains `static mut`.** The current implementation guards the BSP-only writer via the `current_cpu().is_bsp()` short-circuit, but the type is still `static mut u64` — a future MB14.g refactor should promote it to `AtomicU64` or move it into `PerCpu`.

### Neutral

- **No runtime x2APIC flip.** The BSP does not itself enable x2APIC mode; firmware (or a future opt-in) must do so before `lapic_init`. This matches the conservative posture Linux took in its early SMP days and keeps the bootloader-mapped LAPIC MMIO window valid for the entire boot path in the common case.
- **AP LAPIC ID read uses CPUID leaf `0xB`.** Requires Nehalem-class silicon (2008) or later. Every modern server and every KVM/QEMU/Proxmox-exposed virtual CPU exposes leaf `0xB`. A pre-Nehalem fallback would have to use CPUID leaf 1 EBX[31:24] and accept the 8-bit cap — not relevant to the Phase 1 deployment targets.

## Alternatives considered

### A. Have the BSP `lapic_init` write SIVR on every CPU via IPI broadcast

Rejected: the SIVR write is per-CPU and the BSP cannot synchronously execute an instruction on a sibling CPU. An IPI-driven `lapic_init` would require an "ENABLE LAPIC" cross-CPU function call — a primitive we do not yet have and would have to bootstrap with the very LAPIC mechanism we are trying to enable. The Rust-callable `kernel_ap_lapic_init` invoked from the per-AP init asm avoids the chicken-and-egg.

### B. Enable x2APIC at runtime in the BSP

Rejected for MB14.f closure: enabling x2APIC mid-boot invalidates the bootloader-mapped LAPIC MMIO window — every kernel reference to `LAPIC_BASE` (`lapic_eoi`, `lapic_send_ipi`, `read_lapic_id`) would have to be re-routed in lock-step or the very next interrupt would trigger a #GP. The conservative posture (read the firmware-observed mode and stay in it) is what Linux's `apic_setup` does on every modern kernel.

### C. Promote `TICK_COUNT` to `AtomicU64` in this milestone

Rejected for scope discipline: the type change touches every reader (the desktop demo's clock face, the system info panel, every benchmark scaffold under `tests/`) and would balloon the diff. The current short-circuit in `kernel_lapic_timer_tick` is BSP-only-safe and the carryover is documented as part of the MB14.g scope.

## References

- Intel SDM Vol 3A § 10.4 — Local APIC
- Intel SDM Vol 3A § 10.6 — Interrupt Command Register (xAPIC)
- Intel SDM Vol 3A § 10.12 — Extended XAPIC (x2APIC) Mode
- Intel SDM Vol 3A § 10.12.1.2 — x2APIC Register Address Space
- Intel SDM Vol 3A Table 10-6 — Local APIC Register Address Map (xAPIC ↔ x2APIC MSR mapping)
- Intel SDM Vol 2 — `CPUID` instruction, leaf 0BH "x2APIC ID the current logical processor"
- ADR-0007 — MB14 MP/AP startup (the orchestration this ADR builds on)
- `crates/nexacore-kernel/src/bare_metal/lapic.rs` — implementation
- `crates/nexacore-kernel/src/bare_metal/mp_ap_entry.rs` — `kmain_ap` asm + `kernel_ap_lapic_init` call site
- `crates/nexacore-kernel/src/bare_metal/tlb_shootdown.rs` — beneficiary of MB14.e.4 closure
