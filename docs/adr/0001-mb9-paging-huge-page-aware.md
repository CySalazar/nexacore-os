# ADR-0001: MB9 — PageMapper huge-page aware + direct-map validation

## Metadata

- **ID:** ADR-0001
- **Data:** 2026-05-18
- **Stato:** accepted (QEMU+OVMF locale 2026-05-18; the Proxmox test VM confermato 2026-05-18 00:49 CEST)
- **Sostituisce:** —
- **Sostituito da:** —

---

## Contesto

Track B MB8 (preemption dal LAPIC timer) è completo e i 273 test passano, ma il
boot path triple-faulta su QEMU+OVMF e the Proxmox test VM dopo `[syscall] LSTAR set`
con `#PF code=2 rip=0x204022 cs=8`. Indagine 2026-05-17:

- `bootloader_api` 0.11 con `Mapping::Dynamic` mappa la physical RAM via huge-page
  (2 MiB / 1 GiB) ma `bare_metal::paging::PageMapper::translate` ritorna `None`
  appena incontra una entry con PS=1 — quindi non vede ciò che il bootloader ha
  mappato come huge-page.
- Inoltre, il direct-map del bootloader copre solo le regioni che il bootloader
  ha effettivamente toccato (ELF kernel, page tables, framebuffer, low memory);
  il primo frame restituito dal `BitmapFrameAllocator` per la stack del task
  scheduler-idle può cadere in una regione Usable ma non direct-mappata.
- La write a `phys + phys_offset` genera #PF non-presente.
- VirtualBox boota perché il suo bootloader-region overlappa il primo free frame
  — caso fortuito, non garanzia di funzionalità.

Workaround difensivo attualmente in `crates/nexacore-kernel/src/lib.rs:241`:
`alloc.mark_range_used(0, 0x100000)`. Non risolve il problema generale.

---

## Decisione

Implementare due fix complementari:

1. **`PageMapper::translate` huge-page aware** — riconoscere PS=1 in PDPT (1 GiB)
   e PD (2 MiB) e calcolare l'indirizzo fisico finale dall'entry leaf più
   l'offset all'interno della huge-page.

2. **Direct-map validator in `kmain`** — dopo la costruzione del `PageMapper` e
   prima dell'init dello scheduler, iterare ogni regione `Usable` di
   `boot_info.memory_regions`; per ogni regione tentare `mapper.translate(VirtAddr(phys_offset + region.start))`
   e idem all'ultima pagina della regione; se una qualsiasi delle due traduzioni
   fallisce, marcare l'intera regione come `used` nel bitmap allocator, con log
   di diagnostica su seriale. Risultato: il bitmap espone solo frame effettivamente
   direct-mappati, garantendo che ogni `alloc_frame()` ritorni un indirizzo la
   cui write a `phys + phys_offset` sia sicura.

**Sintesi:** `PageMapper` segue PS=1; `kmain` filtra il bitmap escludendo regioni
non direct-mappate dal bootloader.

---

## Alternative Considerate

### Alternativa A: `map_4k` split-on-write delle huge-page + map esplicita di tutta la RAM in 4 KiB

- **Descrizione:** Quando `map_4k` incontra un'entry PS=1, splitta la huge-page
  allocando una nuova tabella e popolandola con 512 PTE 4 KiB equivalenti. In
  `kmain`, dopo paging init, mappare 4K esplicito ogni frame Usable non già
  presente.
- **Pro:** Massima flessibilità, ogni frame fisico è direct-mapped.
- **Contro:** Per 4 GiB di RAM significa ~1M entry PTE, spreco enorme di memoria
  per page tables (>8 MiB) e tempo di boot. Non necessario in questa fase.
- **Motivo di esclusione:** Overkill per Track B; il validator è O(N regioni)
  e non O(N frame).

### Alternativa B: Allocare i kernel stack in un range VA alto dedicato (non direct-map)

- **Descrizione:** Riservare un range VA (es. `0xFFFF_C000_0000_0000`+) per gli
  stack del kernel; per ogni stack, allocare un frame fisico via bitmap e
  mappare 4K esplicito nel range dedicato.
- **Pro:** Separazione netta tra direct-map (sola lettura/diagnostica) e VA
  per dati mutabili del kernel.
- **Contro:** Modifica invasiva: cambia l'API di `Scheduler::spawn_*`, il
  context switch, e tutto ciò che oggi presume `kernel_stack_phys + phys_offset`
  come stack VA. Più rischioso per un fix di blocco di boot.
- **Motivo di esclusione:** Sarà introdotto in una milestone Track B successiva
  (MB10+) come parte del corretto isolamento user/kernel; ora avrebbe scope
  eccessivo.

### Alternativa C: Mantenere il workaround `mark_range_used(0, 0x100000)` e basta

- **Descrizione:** Lasciare il workaround attuale.
- **Pro:** Zero modifiche al codice di paging.
- **Contro:** Funziona solo per il caso specifico in cui il primo free frame
  cade nel low-1MiB; non robusto a cambi di memory layout (es. RAM maggiore,
  firmware diverso). Non riproducibile con confidenza.
- **Motivo di esclusione:** Non è un fix, è un side-effect fortunato. Il #PF
  ricompare appena la disposizione delle regioni cambia.

---

## Conseguenze

### Positive

- Boot path eseguibile su QEMU+OVMF e Proxmox (vincolo di feasibility per
  l'intera Track B onwards).
- `translate` corretto anche per le mappature huge-page del bootloader → utile
  in futuro per diagnostica, debug pagefault, introspection.
- Il bitmap allocator riflette esattamente la memoria effettivamente usabile
  dal kernel — invariante esplicito invece che fortuito.

### Negative

- Costo di boot aggiuntivo: una traduzione per ogni regione Usable (tipicamente
  < 20 regioni su un'immagine UEFI). Trascurabile.
- L'invariante "ogni frame del bitmap è direct-mapped" deve essere preservata
  da chiunque tocchi `lib.rs` in futuro — è un contratto implicito.

### Rischi

- Se il bootloader cambia (es. upgrade a `bootloader_api` 0.12) e il direct-map
  non è più garantito linear-contigous, il validator continua a funzionare ma
  potrebbe rendere `used` regioni grandi → memoria libera ridotta. Mitigation:
  log diagnostico esplicito di "regions skipped" e "MiB free" pre/post validator.

---

## Note di Implementazione

- File toccati (kernel-side):
  - `crates/nexacore-kernel/src/bare_metal/paging.rs` — `translate` huge-page aware,
    nuove costanti `PTE_HUGE` / `HUGE_*_FRAME_MASK` / `HUGE_*_OFFSET_MASK`,
    doc-block aggiornato; nessun cambio a `map_4k` (out of scope).
  - `crates/nexacore-kernel/src/lib.rs` — nuovo helper `register_direct_mapped_regions`
    chiamato tra paging init e scheduler init; introdotta const
    `FRAME_BITMAP_WORDS`; rimosso il FIXME(track-b-mb9); il
    `mark_range_used(0, 0x100000)` resta come policy indipendente "BIOS reserved
    area". Aggiunta riga di diagnostica `[paging] validated N MiB direct-mapped,
    skipped M MiB unmapped`.
  - `crates/nexacore-kernel/src/bare_metal/arch/{x86_64,non_x86_64}.rs` — aggiunto
    `read_cr2()` per il dump di CR2 nell'handler #PF.
  - `crates/nexacore-kernel/src/bare_metal/idt.rs` — handler `kernel_handle_pf`
    estesa per stampare CR2 sul serial.

- File toccati (cross-cutting heap-virt fix, MB9-blocking):
  - `kernel-runner/src/main.rs` — `pick_region` ritorna un indirizzo *fisico*;
    il runner ora aggiunge `boot_info.physical_memory_offset` prima di passarlo
    a `BumpHeap::init`. Senza questa traduzione il primo `Vec::push` del
    scheduler scrive a una VA non mappata (sintomo originale del crash MB8 su
    QEMU+OVMF: `#PF code=2 cr2≈0x017800C0`).

- Test:
  - Unit test in `paging.rs::tests` (8 nuovi): traversal di PDPTE PS=1 / PDE PS=1
    a start, middle, last-byte; regressione 4 KiB; non-deref del PD su huge PDPT.
  - Workspace tests: 75 in `nexacore-kernel --features bare-metal` (67 esistenti + 8
    nuovi), tutti pass.

- Smoke (verificato 2026-05-18 su `feat/kernel-vga-wait`):
  - QEMU+OVMF locale (`mb8-smoke` feature): serial mostra K5 banner,
    `[paging] mapper ready CR3=0x101000`, `[paging] validated 245 MiB
    direct-mapped, skipped 0 MiB unmapped`, `[idt] loaded`, `[syscall] LSTAR set`,
    `[sched] scheduler init idle task spawned`, `[sched] bootstrap kmain task
    registered`, `[lapic] timer started vector=0x20`, `[lapic] interrupts
    enabled`, `[mb8-smoke] task A/B spawned`, `[mb8-smoke] kmain halting`.
    Niente `#PF code=2`. Interleaving A/B presente ma sparso (limite QEMU TCG
    timer accuracy + brew-OVMF su macOS arm64 host) — non kernel-side.
  - the Proxmox test VM (host `proxmox.internal`, 2026-05-18 00:49 CEST): **PASSED**.
    Prima del redeploy, l'immagine pre-MB9 crashava con
    `[NexaCore OS EXCEPTION] #PF Page Fault code=2 rip=0x204AE2`. Dopo redeploy
    (build `kernel-runner` + `cargo run -p disk-image` → `dd` su `zvol
    <vmid>-disk` → `qm start <vmid>`), serial log (`/tmp/nexacore-os-serial.log`)
    mostra K5 banner, righe `[paging]` / `[idt]` / `[syscall] LSTAR set` /
    `[sched]` / `[lapic]` / `[virtio] tablet ready`. La `demo::run_desktop`
    procede a disegnare le finestre System Info / Terminal / Clock /
    Power-Control sul framebuffer VNC con taskbar + countdown 5 min attivi.
    Primo boot end-to-end di NexaCore OS su Proxmox dopo MB9; nessun `#PF code=2`
    residuo. Confermato come fix per la regressione pre-MB9.

---

## Riferimenti

- FIXME(track-b-mb9) precedentemente in `crates/nexacore-kernel/src/lib.rs` — rimosso
  in questa milestone (la mitigation `mark_range_used(0, 0x100000)` resta come
  policy BIOS-reserved indipendente, non come workaround MB9).
- Memo: `track-b-mb8-preemption.md` — KNOWN BLOCKER section, ora storica.
- Bootloader: <https://github.com/rust-osdev/bootloader> v0.11, `Mapping::Dynamic`.
- Intel SDM Vol. 3, §4.5 — IA-32e Paging, struttura delle entry PS=1.
