# ADR-0004: MB11 — Primo processo userspace Ring 3 con per-process CR3

## Metadata

- **ID:** ADR-0004
- **Data:** 2026-05-18
- **Stato:** accepted
- **Sostituisce:** —
- **Sostituito da:** —
- **Riferimenti:** [ADR-0001](./0001-mb9-paging-huge-page-aware.md), [ADR-0002](./0002-mb10-kernel-stack-isolation.md) § "Bootstrap caveat", [ADR-0003](./0003-no-blanket-allows-in-production-crates.md), `ncips/ncip-kernel-003.md`, `progress-nexacore.md` § 5 Step 3

---

## Contesto

Track B chiude MB1-MB10 in v0.2.0 + post-release. Lo stato attuale del
microkernel `nexacore-kernel`:

- Boot UEFI con `bootloader_api 0.11` su QEMU+OVMF, VirtualBox, Proxmox.
- `BitmapFrameAllocator` + `PageMapper` huge-page aware (MB1-MB9).
- IDT con handler #DE/#DF/#GP/#PF + dump CR2 (MB3).
- `SYSCALL`/`SYSRET` MSR setup + `INT 0x80` fallback (MB4).
- ELF64 loader `Elf64::parse` + `map_and_load` (MB5).
- Round-robin scheduler + context switch x86_64 asm (MB6).
- LAPIC xAPIC + preemption + `NEED_RESCHED` (MB7-MB8).
- Kernel stack isolation con guard page in `0xFFFF_C000_0000_0000`
  (MB10, ADR-0002).

Mancano per chiudere il deliverable Phase 1 della roadmap
("Microkernel boots on x86_64 hardware ... IPC primitives operational
... Drivers in user space"):

1. **Nessun task in Ring 3.** Tutto gira in CPL=0. Lo scheduler conosce
   solo kernel-task; il `TaskControlBlock` ([scheduling.rs:167](../../crates/nexacore-kernel/src/scheduling.rs#L167)) ha solo `rsp` come
   `CpuContext` e non porta CR3 o ring level.
2. **GDT a 3 slot.** Solo null, kcode64 (0x08), kdata64 (0x10).
   [gdt.rs:45](../../crates/nexacore-kernel/src/bare_metal/gdt.rs#L45). Nessuno user code (0x1B), user data (0x23), TSS.
   Senza questi, `iretq` a Ring 3 è impossibile.
3. **STAR placeholder errato.** [syscall_entry.rs:308](../../crates/nexacore-kernel/src/bare_metal/syscall_entry.rs#L308) scrive
   `(0x001B << 48) | (0x0008 << 32)`. Per Intel SDM, `SYSRET q`
   produce `CS = STAR[63:48] + 16, RPL=3` e `SS = STAR[63:48] + 8,
   RPL=3`. Il valore attuale produce CS = `0x2B+0x3 = 0x2B|0x3 = 0x2B`
   (slot non esistente nella GDT a 3 slot) e SS = `0x23` (anch'esso
   inesistente). Va riconciliato con la nuova GDT estesa.
4. **Direct-map condiviso.** Tutti i task scrivono nello stesso CR3.
   Nessuna isolation user/user.

ADR-0002 § "Bootstrap caveat" nomina esplicitamente MB11 come consumer
dell'isolamento stack: il primo `iretq` in Ring 3 richiede uno stack
kernel-only su cui ritornare alla prossima syscall/interrupt.

`progress-nexacore.md` § 5 Step 3 (this iteration's roadmap entry) propone
di chiudere MB11 con un singolo binario user ELF che faccia
`WriteConsole("hello\n"); TaskExit(0);` via `syscall` instruction.

---

## Decisione

**Sintesi:** ogni processo possiede una propria PML4. Le entries
256-511 (kernel half) sono copiate per riferimento dal CR3 di boot; le
entries 0-255 (user half) sono allocate per-processo. Un nuovo
`ProcessControlBlock` arricchisce il `TaskControlBlock` MB10 con
`AddressSpace` + `user_entry` + `user_stack_top`. La transizione Ring 0
→ Ring 3 avviene via `iretq` (non `sysretq`) per audit semplicità.

### 1. GDT estesa a 7 slot

| Slot | Selector | Contenuto | Access | Flags | DPL |
|------|----------|-----------|--------|-------|-----|
| 0 | 0x00 | null | — | — | — |
| 1 | 0x08 | kcode64 | 0x9B | 0xA | 0 |
| 2 | 0x10 | kdata64 | 0x93 | 0xC | 0 |
| 3 | 0x18 | user-data (SS placeholder, accessibile a RPL=3) | 0xF2 | 0xC | 3 |
| 4 | 0x20 | ucode64 | 0xFA | 0xA | 3 |
| 5-6 | 0x28 | TSS (system seg 16 byte spanning slot 5+6) | 0x89 | 0x0 | 0 |

### 2. STAR riconciliato

`STAR[63:48] = 0x10`. Per `SYSRET q`:
- `CS = 0x10 + 16 | 3 = 0x23` → slot 4 (ucode64, DPL=3) ✓
- `SS = 0x10 + 8 | 3 = 0x1B` → slot 3 (user-data placeholder, DPL=3) ✓

Per `SYSCALL` (kernel entry): `STAR[47:32] = 0x08`, quindi:
- kernel `CS = 0x08` (slot 1, DPL=0) ✓
- kernel `SS = 0x10` (slot 2, DPL=0) ✓

### 3. TSS unica

```rust
#[repr(C, packed)]
pub struct Tss {
    reserved0: u32,
    pub rsp0: u64, pub rsp1: u64, pub rsp2: u64,
    reserved1: u64,
    pub ist1: u64, pub ist2: u64, pub ist3: u64,
    pub ist4: u64, pub ist5: u64, pub ist6: u64, pub ist7: u64,
    reserved2: u64, reserved3: u16,
    pub iomap_base: u16,  // = 104 (sizeof(Tss))
}
```

`TSS.rsp0` viene aggiornata ad ogni context switch al kernel stack top
del processo entrante. IST1 riservato a `#DF` (già pianificato
ADR-0002), IST2 a `#PF` per evitare faulting su user stack.

### 4. AddressSpace per-process

```rust
pub struct AddressSpace { pub pml4_phys: PhysAddr }

impl AddressSpace {
    pub fn new_with_kernel_half<const N: usize>(
        boot_cr3: PhysAddr,
        mapper: &PageMapper,
        alloc: &mut BitmapFrameAllocator<N>,
    ) -> KernelResult<Self> {
        let pml4 = alloc.alloc_frame().ok_or(...)?;
        // Zero entire frame
        // memcpy entries [256..512] from boot PML4 (kernel-half by ref)
    }

    pub fn map_user_4k<const N: usize>(
        &mut self, virt, phys, flags,
        mapper: &mut PageMapper, alloc: &mut BitmapFrameAllocator<N>,
    ) -> bool { ... }

    pub fn activate(&self);    // wrcr3
}
```

Refactor minimale a `paging.rs`: aggiungere `map_4k_into(root_phys,
...)` accanto a `map_4k`, additivo.

### 5. User VA layout

| Costante | Valore | Significato |
|----------|--------|-------------|
| `USER_STACK_VA_BASE` | `0x0000_0040_0000_0000` | Inizio user-stack range |
| `USER_STACK_VA_END`  | `0x0000_0040_8000_0000` | Fine (32 GiB) |
| `USER_STACK_SIZE`    | `0x4000` (16 KiB) | Stack utile per processo |
| `USER_STACK_STRIDE`  | `0x8000` (32 KiB) | 16 KiB guard + 16 KiB stack |

Mirror del pattern MB10 ma in low VA con `PTE_USER` set. Disgiunto da:
- Direct-map bootloader (`0xFFFF_8800_…`)
- Kernel-stack range (`0xFFFF_C000_…`)
- ELF user-code range (`0x0000_0000_4000_…`, MB5 convention)

### 6. ProcessControlBlock

```rust
pub struct ProcessControlBlock {
    pub task: TaskControlBlock,      // reuse MB10 (kernel stack + ID)
    pub address_space: AddressSpace,
    pub user_entry: u64,
    pub user_stack_top: u64,
    pub next_user_stack_slot: usize,
}

impl ProcessControlBlock {
    pub unsafe fn spawn_from_elf<const N: usize>(
        elf: &[u8], boot_cr3: PhysAddr,
        mapper: &mut PageMapper, alloc: &mut BitmapFrameAllocator<N>,
        scheduler: &mut RoundRobinScheduler, priority: PriorityClass,
    ) -> KernelResult<TaskId>;
}
```

Flow di `spawn_from_elf`:
1. `AddressSpace::new_with_kernel_half(boot_cr3, mapper, alloc)`.
2. `Elf64::parse(elf)` + iterate `PT_LOAD`. Per ogni segmento:
   `address_space.map_user_4k(virt, frame, pte_flags(seg.flags),
   mapper, alloc)`. L'ELF loader (MB5) già imposta `PTE_USER`.
3. Allocate user stack via `user_stack::allocate_user_stack(address_space, mapper, alloc)`.
4. Allocate kernel stack via `RoundRobinScheduler::allocate_stack_slot`
   (MB10 path, invariato).
5. Costruisce PCB e lo registra nel scheduler.

### 7. Trampolino iretq

```nasm
nexacore_iret_to_ring3:           ; (rip=rdi, rsp=rsi, rflags=rdx, cr3=rcx)
    mov cr3, rcx              ; switch AS (kernel-half identica → safe)
    push 0x1B                 ; USER_SS (slot 3+RPL3)
    push rsi                  ; user RSP
    push rdx                  ; RFLAGS | IF (caller sets 0x200)
    push 0x23                 ; USER_CS (slot 4+RPL3)
    push rdi                  ; user RIP
    iretq
```

L'istruzione `mov cr3` è safe perché kernel-half è identica fra CR3
di boot e CR3 del processo — lo stub stesso continua mappato.

### 8. Syscall handler reali

| Numero | Nome | Firma | Comportamento |
|--------|------|-------|---------------|
| 11 | `TaskExit` | `(code: u64) -> !` | `scheduler.dequeue(current); pick_next()` |
| 60 | `WriteConsole` (NEW) | `(ptr, len) -> u64` | Valida `[ptr, ptr+len)` ⊂ user-half, walk PT del current AS, copia in kernel buf 256 byte, call `early_console::emit`. Return `len` o `EFAULT` |
| 1 | `MemMap` | `(size) -> u64` | Allocate phys frames + map in current AS a VA fresh bump-allocated, flags `PTE_USER|WRITABLE|NX`. Return user VA |

Helper `validate_user_buffer(addr_space, ptr, len, mapper)`:
- Check `ptr.checked_add(len) <= 0x0000_8000_0000_0000` (user half).
- Walk page tables verificando PRESENT|USER per ogni page in range.

---

## Alternative Considerate

### Alternativa 1: Shared CR3

- **Descrizione:** kernel e userspace nella stessa PML4. `PTE_USER` su
  user pages, kernel pages senza `PTE_USER` → hardware paging
  garantisce isolamento Ring 3 → kernel.
- **Pro:** zero codice nuovo per address-space management. Mappare
  un nuovo task = aggiungere entries alla PML4 attiva.
- **Contro:** **nessuna isolation user/user**. Process A può
  enumerare le page table del proprio CR3 e leggere le entries di
  Process B (sono nella stessa tabella). Viola `docs/04a-threat-model.md`
  § "Memory-isolation between unprivileged tenants".
- **Motivo di esclusione:** security-first. Phase 1 deliverable
  "Capability-based security primitives" presuppone isolation hard.

### Alternativa 2: Per-process CR3 con kernel-PML4 indipendente

- **Descrizione:** ogni processo possiede una PML4 e ANCHE le tabelle
  inferiori di kernel-half sono copiate (non condivise per riferimento).
- **Pro:** isolation totale; cambio di mapping kernel-side non si
  propaga a processi già attivi (utile se ogni processo avesse una
  "vista" privata del kernel — feature di TEE).
- **Contro:** ogni `vmap` kernel-side richiede broadcast cross-AS
  (visitare ogni PML4 di ogni processo). Costo O(num_processi) per
  ogni mappatura kernel. Sproporzionato per Phase 1 (single-CPU,
  pochi processi).
- **Motivo di esclusione:** complessità sproporzionata. Rivedibile in
  Phase 2 quando TEE entrerà in scena.

### Alternativa 3: Per-process CR3 con kernel-half by reference [scelta]

- **Descrizione:** ogni processo possiede una PML4 (frame
  proprietario). Le entries 256-511 (kernel half) sono memcpy del
  CR3 di boot — copiati i puntatori a PDPT condivise. Le entries
  0-255 (user half) sono allocate per-processo.
- **Pro:** isolation user/user completa. Update kernel-side
  (es. `vmap` di un nuovo frame nel direct-map) si propaga a tutti
  i processi senza sync esplicita (le PDPT condivise vedono il
  nuovo PTE). Memory overhead per processo: 4 KiB (1 PML4 frame).
- **Contro:** una rare modifica top-level kernel (e.g. cambio di una
  PML4 entry kernel-half) richiederebbe broadcast — ma Phase 1 non
  ha questo scenario (kernel-half è statica post-boot).
- **Motivo di adozione:** sweet spot effort/security per Phase 1.

### Alternativa 4: Defer to MB12

- **Descrizione:** MB11 chiude solo "primo Ring 3 entry" con shared
  CR3; MB12 introduce per-process CR3 insieme a IPC.
- **Pro:** MB11 più piccolo, ship più veloce.
- **Contro:** crea un'iterazione "non sicura" intermedia.
  L'integration test di isolation è significativa solo se CR3 è
  isolato. Inoltre senza process abstraction ora, MB12 IPC dovrebbe
  introdurla insieme a queue e capability check.
- **Motivo di esclusione:** stratificazione corretta esige che il
  process model sia fondamento di MB12.

### Alternativa 5: `sysretq` invece di `iretq` per primo Ring 3

- **Descrizione:** usare `sysretq` per il primo salto in Ring 3.
- **Pro:** istruzione più veloce; usata anche per il return da
  syscall.
- **Contro:** `sysretq` richiede stato preciso: RFLAGS in R11, RIP in
  RCX. Costruirlo per il primo entry è più fragile di un esplicito
  frame `iretq` (5 push + 1 iretq). Audit più difficile.
- **Motivo di esclusione:** `iretq` è auditabile come "kernel costruisce
  esplicitamente lo stack frame Ring 3 e lo svolge". `sysretq` resta
  per il return path naturale del syscall.

---

## Conseguenze

### Positive

- **Primo processo Ring 3.** L'OS supera la soglia da "kernel demo"
  a "OS in grado di eseguire codice utente isolato".
- **Isolation user/user.** Process A non può leggere le page table
  di Process B perché vivono in CR3 diversi.
- **Foundation per MB12 IPC.** Process abstraction esiste; il
  capability check di IPC può ancorarsi al `ProcessControlBlock`.
- **STAR fix definitivo.** Il bug placeholder `0x001B << 48`
  riconciliato; SYSCALL / SYSRET sono finalmente coerenti con la GDT.
- **Threat model rispettato.** Riga "Memory-isolation between
  unprivileged tenants" di `docs/04a-threat-model.md` finalmente
  soddisfatta a livello kernel.

### Negative

- **Memory overhead per processo.** 4 KiB (PML4) + 16 KiB (user
  stack) + N × 4 KiB (PT inferiori user-half) ≈ 30-50 KiB per
  processo, di cui 4 KiB sono proprietari del processo. Trascurabile.
- **TLB flush completo su context switch.** `mov cr3` flusha l'intero
  TLB (eccetto `global` pages, di cui non usiamo). Cost ~1000 cicli per
  context switch + cache miss successive. Su single-CPU Phase 1 è
  irrilevante.
- **Complessità del `nexacore_iret_to_ring3` stub.** L'asm va auditato
  con cura (CR3 reload prima del frame setup, ordine dei push).
- **Per-process stack tracking.** Il `next_user_stack_slot` per
  processo invece di globale aggiunge un campo a `ProcessControlBlock`.

### Rischi

| # | Rischio | Sev | Mitigazione |
|---|---------|-----|-------------|
| 1 | STAR/GDT selector mismatch dopo refactor | HIGH | Unit test `sysret_arithmetic_matches_intel_sdm`; probe Ring 3 fa `mov ax, ds` e verifica selector |
| 2 | `lgdt` prima di `ltr` prima di primo `iretq` | HIGH | Documentato in kmain; failure mode = `#GP` su ltr |
| 3 | CR3 reload mid-iretq | MED | kernel-half by-reference garantisce continuità; verify via gdb su QEMU |
| 4 | SYSCALL non switcha CR3 | LOW | user CR3 ha kernel-half mappata → handler LSTAR esegue ok |
| 5 | Timer interrupt da Ring 3 senza TSS.rsp0 valido | MED | aggiornare `TSS.rsp0` ad ogni process switch |
| 6 | #PF su iretq atterra su user stack | LOW | wire #PF (vec 14) a IST2 in `idt_init` |
| 7 | userprobe build hermeticity | LOW | `CARGO_TARGET_DIR=$OUT_DIR/userprobe-target` per evitare recursion |

---

## Note di Implementazione

Sub-step DAG:

```
MB11.1 (GDT+TSS+STAR fix) ─┐
                           ├─► MB11.4 (PCB + scheduler)
MB11.2 (AddressSpace) ─────┘    │
MB11.3 (user_stack) ────────────┤
                                ▼
                           MB11.5 (iretq trampoline)
                                │
                                ▼
                           MB11.6 (syscall handlers)
                                │
                                ▼
                           MB11.7 (user probe binary)
                                │
                                ▼
                           MB11.8 (kmain wiring)
                                │
                                ▼
                           MB11.9 (tests + smoke + Proxmox)
```

File da creare:
- `crates/nexacore-kernel/src/bare_metal/tss.rs`
- `crates/nexacore-kernel/src/bare_metal/address_space.rs`
- `crates/nexacore-kernel/src/bare_metal/user_stack.rs`
- `crates/nexacore-kernel/src/bare_metal/usermode.rs`
- `crates/nexacore-kernel/src/process.rs`
- `crates/nexacore-userprobe-helloworld/` (new workspace crate)
- `crates/nexacore-kernel/tests/mb11_userspace.rs`

File da modificare:
- `crates/nexacore-kernel/src/bare_metal/gdt.rs` (3→7 slot)
- `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs` (STAR fix +
  dispatch table TaskExit/WriteConsole/MemoryAlloc)
- `crates/nexacore-kernel/src/bare_metal/paging.rs` (add `map_4k_into`)
- `crates/nexacore-kernel/src/scheduling.rs` (process integration)
- `crates/nexacore-kernel/src/lib.rs` (kmain wiring)
- `crates/nexacore-kernel/build.rs` (embed userprobe ELF)

---

## Verifica

### Unit test (host, `cargo test --workspace`)

Target: 277 → 285+ pass / 0 fail.

- `address_space::tests::kernel_half_clone_copies_entries_256_to_511`
- `address_space::tests::user_half_is_zero_after_clone`
- `user_stack::tests::first_slot_starts_after_guard_page`
- `user_stack::tests::stride_matches_size_plus_guard`
- `tss::tests::struct_size_is_104_bytes`
- `tss::tests::iomap_base_equals_104`
- `gdt::tests::sysret_arithmetic_matches_intel_sdm`
- `gdt::tests::user_code_selector_is_0x23`
- `process::tests::spawn_from_elf_registers_pcb`

### Integration test bare-metal

`crates/nexacore-kernel/tests/mb11_userspace.rs` (eseguito in QEMU):

1. Userprobe spawns + stampa "hello\n".
2. `TaskExit(0)` rende controllo al kernel; smoke contiene `[user] exit=0`.
3. **Negativo (isolation check):** probe alternativo che fa
   `mov rax, [0xFFFF_8000_0000_0000]; syscall(TaskExit)`. Atteso:
   `#PF` con `CR2 ∈ kernel-half`. Test scrapes serial per la riga
   `#PF CR2=0xFFFF_8000...`.

### Boot smoke (QEMU+OVMF)

`cargo run -p kernel-runner` — serial deve contenere:
```
[user] address space activated cr3 = 0x...
[user] hello
[user] exit=0
```

### the Proxmox test VM

Redeploy via `disk-image` builder; verifica smoke su hardware-like.

### CI required checks (11)

Tutti verdi. `cargo test (ubuntu-24.04)` SIGSEGV carryover preesistente
non bloccante (admin-bypass via PR #29/#33 pattern, debito § 4.5).

---

## Riferimenti

- `progress-nexacore.md` § 5 Step 3 — MB11 priority
- [ADR-0001](./0001-mb9-paging-huge-page-aware.md) — MB9 paging
- [ADR-0002](./0002-mb10-kernel-stack-isolation.md) — MB10 kernel stack
- [ADR-0003](./0003-no-blanket-allows-in-production-crates.md) — lint policy
- `ncips/ncip-kernel-003.md` — UEFI + bootloader + Ring 3 + syscall mandate
- Intel SDM Vol 3A § 5.8.8 (SYSCALL/SYSRET selector arithmetic)
- Linux x86_64 GDT layout reference (arch/x86/kernel/cpu/common.c)
