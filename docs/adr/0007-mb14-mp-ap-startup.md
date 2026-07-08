# ADR-0007 — MB14 Multi-Processor / AP startup (INIT-SIPI-SIPI live)

- **Status:** Accepted
- **Date:** 2026-05-19
- **Deciders:** Matteo Sala (architect / sole founder)
- **Related:** NCIP-Kernel-005 (kernel-runner contract), ADR-0006 (MB13 capability integration), `progress-nexacore.md` § 4, `docs/06-roadmap.md` "Phase 1"

## Context

After MB13 closed the `nexacore-capability` integration loop, NexaCore OS was still single-CPU end-to-end: the BSP came up via the bootloader, ran `lapic_init`, and never woke any Application Processor. Two deliverables in the Phase 1 roadmap depend on multi-core: P6.7 (user-space driver model — NVMe / Net / TEE) and P6.MB14.d–e (TLB shootdown broadcast and per-CPU scheduler split). MB14 is therefore the sequencing milestone that brings up sibling cores and unlocks the rest of Phase 1.

The Intel SDM Vol 3A § 8.4 INIT-SIPI-SIPI handshake is the canonical way to wake APs on x86_64, but it has four orthogonal risks any one of which can triple-fault the BSP:

1. A stray bit in the encoded ICR command sends the IPI to the wrong CPU or with the wrong delivery mode.
2. A stray byte in the 16→32→64-bit AP trampoline causes the AP to crash inside an unmapped region the BSP cannot diagnose.
3. The AP `mov cr3, rax` switches the address space mid-instruction-stream, so the next instruction fetch must come from a page mapped in **both** the old and the new CR3.
4. The 10 ms / 200 µs delays from Intel MP-Spec § B.4 are mandatory; using a CPU-frequency-dependent timer (TSC / LAPIC timer) at this point in boot risks under-delaying and missing the AP wake.

The MB14 design splits the work into pure-function + bare-metal sub-blocks so each risk lands behind a green host-test suite before the live ICR fire.

## Decision

### Sub-block decomposition

| Sub-block | Scope                                                                                            | Status |
|-----------|--------------------------------------------------------------------------------------------------|--------|
| MB14.a    | Per-CPU descriptor scaffold (`PerCpu` struct + BSP LAPIC ID seed)                                | ✅      |
| MB14.b    | `IA32_GS_BASE` / `IA32_KERNEL_GS_BASE` per-CPU pointer + `swapgs` in `nexacore_syscall_entry`        | ✅      |
| MB14.c.1  | ACPI MADT walker (`parse_madt` + `enumerate_cpus`)                                               | ✅      |
| MB14.c.2.a| INIT-SIPI ICR encoder (xAPIC + x2APIC) + dry-run `start_aps`                                     | ✅      |
| MB14.c.2.b.1 | Pure-function trampoline blob + temp GDT + temp identity-paging builders                      | ✅      |
| MB14.c.2.b.2 | Bare-metal emplacement of the trampoline page + temp PML4/PDPT/PD                             | ✅      |
| **MB14.c.2.c** | **Live INIT-SIPI-SIPI fire + AP landing stub + ack barrier**                                | ✅ (this ADR) |
| MB14.c.2.d| Per-AP `PerCpu` allocation + per-AP kernel stack + real `kmain_ap` body                          | open   |
| MB14.d    | IPI vector for TLB shootdown + `mm::flush_tlb_range` broadcast logic                             | open   |
| MB14.e    | Per-CPU run-queue + scheduler split + work-stealing                                              | open   |

### MB14.c.2.c specifics

1. **AP landing stub at phys `0x0000_8100`** — 32-byte hand-encoded assembly inside the trampoline page. The stub:
   - `lock inc qword ptr [0x8140]` (atomic ack-counter increment).
   - `mov rcx, [0x8148]` (load kernel `CR3` from the runtime slot the BSP wrote pre-fire).
   - `mov rdx, [0x8150]` (load `kmain_ap` higher-half VA from the runtime slot).
   - `mov cr3, rcx` (switch to the kernel address space).
   - `jmp rdx` (enter `kmain_ap`).
   Both `mov` loads happen **before** the `CR3` switch so the values reach a register while the temp PML4 still identity-maps the trampoline page; after the switch, the BSP's kernel address space also identity-maps phys `0x8000` (the c.2.b.2 emplacement installs that mapping defensively for exactly this reason), so the next instruction fetch at RIP ≈ `0x811D` does not fault.

2. **`kmain_ap` higher-half entry** — defined via `global_asm!` (the Rust 1.85 toolchain does not stabilise `#[naked]`):
   ```asm
   .section .text.kmain_ap, "ax", @progbits
   .global kmain_ap
   kmain_ap:
       cli
   1:  hlt
       jmp 1b
   ```
   The function has no prologue, never returns, and does not touch the stack (the AP arrives with no usable `RSP`). MB14.c.2.d will replace the body with a real per-CPU init sequence.

3. **PIT-based delays** — channel 2 mode 0 ("interrupt on terminal count") with the 1.193 MHz fixed-frequency tick. `pit_delay_us(10_000)` covers the post-INIT settle; `pit_delay_us(200)` covers the SIPI spacing. The KBD-controller port `0x61` bit 5 (OUT pin) is polled for terminal-count detection; bit 1 (speaker data) is kept masked so the BSP delay is silent. Channel 2 was chosen over channel 0 because channel 0 is already driving the legacy timer IRQ in the disabled-PIC state `lapic_init` leaves us in.

4. **Live ICR fire** — `start_aps_live` writes `ICR_HI` then `ICR_LO` via `lapic_send_ipi`, busy-polls bit 12 of `ICR_LO` (`Delivery Status`) after each write, and interposes `pit_delay_us` between the INIT, SIPI #1, and SIPI #2 writes per Intel MP-Spec § B.4. The xAPIC encoding from MB14.c.2.a is reused unchanged; x2APIC support is wired in the encoder but the BSP's MSR mode (set by `lapic_init` to xAPIC SIVR-enable) determines the active path.

5. **Ack barrier** — busy-polls phys `0x0000_8140` (a `u64` written exclusively by APs via `lock inc`) until the count reaches the number of targeted APs or `AP_ACK_POLL_ITERATIONS` (1 G iterations ≈ 1 s on modern silicon) expires. The BSP logs `acked=N` and whether the budget was hit.

## Consequences

### Positive

- Multi-core kernel: the BSP can now bring sibling APs to a parked-but-alive state. This unblocks MB14.d (TLB shootdown), MB14.e (per-CPU scheduler), and ultimately P6.7 (driver model in user space).
- Every byte that goes into the AP execution path — trampoline blob, landing stub, GDT entries, PML4/PDPT/PD bits — is pinned by host-side `cargo test`. A regression surfaces as a deterministic test failure on the dev host rather than a triple-fault on Proxmox.
- The 10 ms / 200 µs delays come from PIT, not TSC/LAPIC-timer, so they remain correct regardless of CPU frequency or LAPIC timer calibration state.
- BSP-only systems (Proxmox VM configured with 1 vCPU) skip the live path entirely via the `topo.enabled_count() > 1` guard, so this change is non-regressing for single-CPU deployments.

### Negative

- `kmain_ap` is currently a `cli; hlt; jmp $-2` park loop — no real per-CPU init runs on the AP yet. The AP holds its slot in the BSP's address space but cannot schedule, take interrupts, or run user code. MB14.c.2.d closes this gap.
- The landing stub uses 32-bit absolute-displacement memory addressing (`mov r64, [imm32]`) for the three runtime slots. This forces the trampoline page to live in the low 4 GiB of physical memory; we already require that for the trampoline (SIPI vector is 8-bit, vector V → phys `V << 12`), so the constraint is not tightened.
- The ack-poll budget is a fixed iteration count rather than a wall-clock timeout. On extremely slow virtualised CPUs (e.g. nested-virt TCG) the budget could expire before the AP increments the counter. The BSP logs the failure (`acked < targeted`) rather than retrying, leaving recovery to a future MB14.c.2.d revision.
- The AP never reloads `GDTR` / `IDTR` / `TSS` after the `CR3` switch — it keeps the temp GDT loaded from the trampoline page. As long as `kmain_ap` does not raise an exception or call into stack-using code (which the current `cli; hlt; jmp` body cannot), this is benign. MB14.c.2.d must reload all three before doing anything more interesting.

### Neutral

- The MB14.c.2.b.2 dry-run `place_trampoline` path is preserved unchanged for symmetry with the host-side test arena; the new `place_trampoline_live` is a thin wrapper that adds the landing-stub + runtime-slot writes.
- ADR-0007 captures the design for the entire MB14.c.2.* cycle, not just MB14.c.2.c. Sub-block ADRs for MB14.d (TLB shootdown protocol) and MB14.e (per-CPU run-queue) will be filed as those land — keeping ADR-0007 focused on "AP wake".

## Alternatives considered

### A. Higher-half AP entry without the landing stub

Embed the `mov cr3, rcx` and `jmp r/m64` directly inside the trampoline blob, so the trampoline ends with the AP already in the kernel address space.

**Rejected** because it conflates two responsibilities (16→64-bit transition vs. address-space switch) into one blob, complicating the byte-exact host tests in `mp_trampoline`. Splitting the work into a 256-byte trampoline + 32-byte landing stub keeps each blob testable against a single section of the Intel SDM.

### B. TSC-calibrated busy-spin instead of PIT

Use `rdtsc` with a CPU-frequency calibration step to compute the 10 ms / 200 µs delays.

**Rejected** because TSC frequency is unknown at this point in boot (the BSP has not run its CPUID 0x15/0x16 detection or a PIT/HPET calibration pass), and an under-calibrated spin risks under-delaying the post-INIT settle. PIT runs at a hardware-fixed 1.193 MHz regardless of CPU; the trade-off (slow port I/O) is acceptable for two delays during boot.

### C. Use SIPI vector `0x60` (above the 1 MiB boundary)

The Intel SDM permits the SIPI vector to be any 8-bit value `0x00..=0xFF`, so the trampoline could theoretically live at phys `0x60000` instead of `0x8000`.

**Rejected** because `0x8000` is the canonical de-facto location (used by Linux, FreeBSD, and seL4 AP startup paths); higher-address SIPI vectors are sometimes rejected by buggy firmware (notably some Insyde BIOS revisions). Sticking to `0x8000` minimises the failure surface on the Proxmox dev VM and on future bare-metal hardware.

## References

- Intel SDM Vol 3A § 8.4 — MP Initialization Protocol.
- Intel SDM Vol 3A § 10.6.1 — Interrupt Command Register layout.
- Intel SDM Vol 3A § 4.10 — TLB invalidation on `MOV CR3`.
- Intel MP-Spec v1.4 § B.4 — BSP Initialization of APs (delays).
- Intel 8254 PIT datasheet — channel 2 mode 0 operation.
- IBM PC AT Technical Reference — port 0x61 layout.
- AMD64 APM Vol 2 § 14.8 — startup-IPI handshake & trampoline pattern.
- ADR-0001 / ADR-0002 / ADR-0004 / ADR-0005 / ADR-0006 — antecedents in the MB9 → MB13 progression.
