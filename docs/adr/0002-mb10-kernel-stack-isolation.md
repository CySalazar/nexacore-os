# ADR-0002: MB10 — Kernel stack isolation con guard page

## Metadata

- **ID:** ADR-0002
- **Data:** 2026-05-18
- **Stato:** accepted
- **Sostituisce:** —
- **Sostituito da:** —
- **Riferimenti:** [ADR-0001](./0001-mb9-paging-huge-page-aware.md) (Alt B), `progress-nexacore.md` § 5 Step 2

---

## Contesto

Track B MB6 ha portato un round-robin scheduler con context switch, e MB7+MB8
hanno aggiunto il LAPIC timer + preemption. Lo stack dei task kernel viene
costruito da `RoundRobinScheduler::spawn_kernel_task` come:

```rust
let stack_virt_top = kernel_stack_phys + phys_offset + 4096;
```

Cioè `phys + boot_info.physical_memory_offset`, una VA nel **direct-map del
bootloader**. Funziona dopo MB9 (il validator garantisce che ogni frame
restituito dall'allocator sia raggiungibile attraverso il direct-map), ma ha
tre limiti strutturali:

1. **Stack overflow scrive silenziosamente nel direct-map.** Una ricorsione
   illimitata o un buffer-overflow nello stack non genera #PF: scrive nella
   pagina fisica adiacente, che è ancora mappata RW dal bootloader.
   Corruzione invisibile finché un'altra struttura kernel (page table di un
   altro task, frame allocator bitmap, ...) viene riscritta e produce un crash
   apparentemente non correlato.
2. **Nessuna garanzia di isolamento contro codice futuro.** Driver, IPC e
   syscall handler che dovranno girare in MB11+/MB12+ potrebbero,
   accidentalmente o per malformed input, scrivere dentro la stack di un altro
   task perché tutti gli stack vivono in un range contiguo del direct-map.
3. **Prerequisito hard per MB11 (primo userspace Ring 3).** Il kernel deve
   riservare un range VA dedicato per i propri stack, separato dal range
   user-space, prima che `iretq` salti in Ring 3 — altrimenti il task
   user-space può navigare il direct-map del bootloader come se fosse memoria
   user.

`progress-nexacore.md` § 5 Step 2 propone Alt B di ADR-0001: range VA kernel-only
dedicato, 4 KiB stack utile + 4 KiB guard page non mappata sopra il top, in
modo che stack-overflow → #PF deterministico con CR2 sulla guard.

---

## Decisione

Spostare gli stack kernel da `phys + phys_offset` (direct-map) a una VA range
**kernel-only** half-canonical, con guard page non mappata. Il `PageMapper`
introdotto in MB2/MB9 supporta già `map_4k` per la singola pagina; serve
solo aggiungere la logica di allocazione di slot nel nuovo range e
modificare il sito di chiamata dello scheduler.

### Layout del range

| Costante | Valore | Significato |
|---|---|---|
| `KERNEL_STACK_VA_BASE` | `0xFFFF_C000_0000_0000` | Inizio del range kernel-stack |
| `KERNEL_STACK_VA_END`  | `0xFFFF_C800_0000_0000` | Fine (esclusiva) — 8 TiB di range |
| `KERNEL_STACK_SIZE`    | `0x1000` (4 KiB) | Stack utile per task |
| `KERNEL_STACK_STRIDE`  | `0x2000` (8 KiB) | Per slot: 4 KiB guard + 4 KiB stack |
| Capacità totale | `8 TiB / 8 KiB ≈ 1 G slot` | Ampiamente sufficiente per Phase 1 |

`0xFFFF_C000_…` è half-canonical superiore (kernel half su x86_64 long mode);
non collide con il direct-map del bootloader (`0xFFFF_8800_…` su
`bootloader 0.11`) né con il futuro range user (`0x0000_0040_…` previsto per
MB11).

### Layout di un singolo slot

```
   addr (VA)         contenuto                            mapping
   ──────────────────────────────────────────────────────────────────
   BASE + N*STRIDE                                       (none)        ┐
   BASE + N*STRIDE + 0x0FFF   <guard page — NOT mapped>  (none)        │ 4 KiB guard
   BASE + N*STRIDE + 0x1000   ↑ stack grows downward     PRESENT|WR|NX ┐
   BASE + N*STRIDE + 0x1FFF   stack top                  PRESENT|WR|NX ┘ 4 KiB stack
```

L'`initial_rsp` del task viene puntato a `BASE + N*STRIDE + 0x2000` (subito
oltre il top utile); `setup_task_frame` poi spinge giù 8×u64 = 64 byte di
trampolino + entry + 6 callee-saved, lasciando RSP comodamente all'interno
dei 4 KiB. Stack che cresce oltre 4 KiB → tocca la guard page → `#PF
not-present` con CR2 = guard VA.

### Bump allocator semplice

`RoundRobinScheduler` guadagna un campo `next_kernel_stack_slot: usize`. Ogni
chiamata a `spawn_kernel_task` consuma uno slot, incrementa il contatore, e
**non riusa** slot liberati (dispose fuori scope di MB10 — arriverà con il
process model di MB11+). Errore tipato se `slot * STRIDE >= range_size`.

### Firma `spawn_kernel_task`

```rust
pub unsafe fn spawn_kernel_task<const N: usize>(
    &mut self,
    entry: fn() -> !,
    kernel_stack_phys: u64,
    mapper: &mut PageMapper,
    alloc: &mut BitmapFrameAllocator<N>,
    priority: PriorityClass,
) -> KernelResult<TaskId>
```

Cambiamenti vs MB8:
- **Aggiunti**: `mapper: &mut PageMapper`, `alloc: &mut BitmapFrameAllocator<N>`.
- **Rimosso**: `phys_offset: u64` (la VA non viene più dal direct-map).
- **`kernel_stack_phys`** invariato (il caller lo alloca prima, come oggi).

### Bootstrap caveat

`spawn_bootstrap_task` ([scheduling.rs:272](../../crates/nexacore-kernel/src/scheduling.rs#L272))
continua a registrare `kmain` riusando la boot stack — il sentinel
`kernel_stack_phys=0, context.rsp=0` rimane invariato e il primo timer tick
overscrive RSP col valore reale come oggi. MB10 non tocca il bootstrap path:
solo gli stack creati esplicitamente via `spawn_kernel_task` vivono nel range
isolato.

### Context switch invariato

`nexacore_context_switch` ([context_switch.rs:171](../../crates/nexacore-kernel/src/bare_metal/context_switch.rs#L171))
lavora su `stack_top: u64` astratto — non gli interessa l'origine della VA.
Stesso `setup_task_frame`, stessa convenzione push 8×u64.

---

## Alternative considerate

- **Alt A — Frame fisici sparsi con NX nel direct-map.** Sopprime il bit di
  esecuzione ma non aggiunge una guard page → stack-overflow continua a
  scrivere silenziosamente nel direct-map. Non risolve il vero problema.
  Rigettata.

- **Alt B — Range VA dedicato + guard page (questa).** Adottata.

- **Alt C — Stack su un mappato kernel-private + free-list di slot.**
  Avrebbe richiesto un free-list/recycling allocator, fuori scope di MB10 e
  inutile finché non c'è una task-exit path (arriva con MB11+).
  Rinviata a future iterazioni.

---

## Implementazione

File modificati:

- **`crates/nexacore-kernel/src/scheduling.rs`**
  - Costanti `KERNEL_STACK_VA_BASE`, `KERNEL_STACK_VA_END`, `KERNEL_STACK_SIZE`,
    `KERNEL_STACK_STRIDE`.
  - `RoundRobinScheduler::next_kernel_stack_slot: usize`.
  - `TaskControlBlock::kernel_stack_va: u64` (oltre al `kernel_stack_phys`
    già esistente; utile per debug e future deallocazioni).
  - `spawn_kernel_task` rifattorizzato con la firma nuova; chiama
    `mapper.map_4k(stack_va, phys, PTE_PRESENT|PTE_WRITABLE|PTE_NO_EXEC, alloc)`
    per la pagina utile; **non** mappa la guard page.

- **`crates/nexacore-kernel/src/lib.rs`**
  - Call-site `spawn_kernel_task(idle_task, phys.0, phys_offset_mb2, Idle)`
    aggiornato alla nuova firma — passa `&mut PageMapper`, `&mut FRAME_ALLOC`.
  - Diagnostica `[stack] kernel stack VA range = 0xFFFF_C000_… .. 0xFFFF_C800_… (slot N)`
    per ogni spawn.

- **`crates/nexacore-kernel/src/bare_metal/paging.rs`**
  - Nessuna modifica. `map_4k` esistente è sufficiente.

- **`crates/nexacore-kernel/src/bare_metal/context_switch.rs`**
  - Nessuna modifica. `setup_task_frame` agnostico rispetto all'origine
    della VA.

---

## Verifica

### Unit test (in `scheduling.rs::tests`)

1. `kernel_stack_va_in_dedicated_range`: spawn 1 task, asserisce
   `tcb.kernel_stack_va ∈ [BASE+0x1000, END)`.
2. `consecutive_spawns_have_disjoint_stacks`: spawn 3 task, asserisce
   `va[i+1] - va[i] == STRIDE`.
3. `guard_page_lies_below_stack`: per ogni slot N, la pagina
   `va_base - 0x1000` è la guard (non chiamata `map_4k`).

### Integration test bare-metal (`crates/nexacore-kernel/tests/`)

- `stack_isolation_smoke.rs`: in build `bare-metal`, spawn 2 task kernel,
  scrivi pattern sentinella `0xCAFEBABE_DEADBEEF` sullo stack di ciascuno,
  verifica via `mapper.translate` che VA → diversa PA fisica.

### Stack-overflow probe (gated `mb10-overflow-smoke`)

Task che fa ricorsione illimitata; expected: il `#PF` handler in
`bare_metal/idt.rs` logga `cr2 = expected_guard_va`. Test compilato
condizionalmente per non rompere lo smoke standard.

### Boot smoke

- QEMU+OVMF (`--features bare-metal,mb8-smoke`): banner + paging validator +
  `[stack] kernel stack VA range = 0xFFFF_C000_… .. 0xFFFF_C800_… (slot 0)` +
  `[stack] ... (slot 1)` + LAPIC + scheduler verde.
- the Proxmox test VM (post-deploy via `disk-image` builder): stessa sequenza
  sul seriale.

### Tutto verde

- `cargo test --workspace` ≥ 273 → ~280.
- `cargo test -p nexacore-kernel --features bare-metal` integration green.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- QEMU+OVMF + Proxmox smoke verdi.
