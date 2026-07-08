# ADR-0006: MB13 — `nexacore-capability` integration (Ed25519 verify nel kernel)

## Metadata

- **ID:** ADR-0006
- **Data:** 2026-05-19
- **Stato:** accepted
- **Sostituisce:** —
- **Sostituito da:** —
- **Riferimenti:** [ADR-0001](./0001-mb9-paging-huge-page-aware.md), [ADR-0002](./0002-mb10-kernel-stack-isolation.md), [ADR-0003](./0003-no-blanket-allows-in-production-crates.md), [ADR-0004](./0004-mb11-userspace-ring3-per-process-cr3.md), [ADR-0005](./0005-mb12-ipc-message-passing.md), `progress-nexacore.md` § 2.2 (Track B), the backlog § P6.MB13

---

## Contesto

ADR-0005 (MB12) ha chiuso il deliverable Phase 1 "IPC primitives
operational (typed message passing)" introducendo `KernelIpcRegistry`,
i quattro syscall `IpcCreateChannel/Destroy/Send/Receive`, e un
`StubCapabilityProvider` come unico verificatore lato kernel. ADR-0005
§ *Migration* riconosceva esplicitamente che lo stub non esegue alcuna
verifica crittografica e che il deliverable Phase 1
"Capability-based security primitives implemented" sarebbe rimasto
parziale finché un provider Ed25519 reale non avesse sostituito lo
stub.

Lo stato pre-MB13:

- [crates/nexacore-kernel/src/capabilities.rs](../../crates/nexacore-kernel/src/capabilities.rs)
  esponeva `KernelCapabilityCheck` + `StubCapabilityProvider` — shape
  match `(action, resource)` puro, nessuna firma verificata.
- `nexacore-capability` esisteva come crate host-side (`mint` + `verify`
  feature) ma non era dep di `nexacore-kernel`: la sua catena
  (`nexacore-crypto` → `sha2`/`poly1305`/`curve25519-dalek`) non
  compilava su `x86_64-unknown-none` per via di SIMD intrinsics LLVM
  che lanciavano ICE.
- Il boot-path `kernel-runner` triple-faultava in QEMU+OVMF appena il
  primo task user partiva: l'ELF kernel era linkato `ET_EXEC` con
  base address basso, sovrapponendosi al PML4 entry 0x0 che il primo
  CR3 reload buttava giù.
- Lo smoke `mb12-userprobe` sul the Proxmox test VM si arrestava muto
  dopo `[mb12] handing off to user tasks`, senza emettere alcun
  output dal lato Ring 3.

Obiettivo MB13: sostituire lo `StubCapabilityProvider` con
`Ed25519CapabilityProvider`, sbloccare la build di `nexacore-capability`
su `x86_64-unknown-none`, aprire l'ABI di `IpcCreateChannel` ai token
firmati, e risolvere i blocker di boot che impedivano la validazione
end-to-end del path Ring 3 → Ring 0 → Ring 3.

---

## Decisione

MB13 è stato decomposto in otto sotto-blocchi (`MB13.a` → `MB13.h` +
chiusura `MB13.e`), ciascuno con un commit atomico sul branch
`feat/kernel-mb11-userspace`. La sintesi per blocco è la seguente.

### MB13.a — `nexacore-crypto` su `x86_64-unknown-none`

Le SIMD intrinsics in `sha2`, `poly1305`, `curve25519-dalek` non
sopravvivono al backend LLVM senza SSE3+. La fix è
disabilitare i path SIMD via `force-soft` feature: il
[`kernel-runner/.cargo/config.toml`](../../kernel-runner/.cargo/config.toml) propaga i
`--cfg sha2_backend="soft"` e analoghi a tutta la build bare-metal.
Risultato: `cargo build -p nexacore-crypto --target x86_64-unknown-none
--no-default-features` passa clean. Costo: ~3× di rallentamento
sull'host (irrilevante: la verifica firma in MB13 avviene una volta
per channel, non per IPC).

### MB13.b — Kernel ET_DYN/PIE

[`kernel-runner/.cargo/config.toml`](../../kernel-runner/.cargo/config.toml)
rimuove i flag `-C relocation-model=static` + `-C link-arg=--no-pie`.
Il target spec `x86_64-unknown-none` (Rust 1.83+) marca già
`position-independent-executables = true`, quindi il linker emette
un ELF `ET_DYN` con tutti gli accessi RIP-relative. Il bootloader
mappa il kernel nell'upper half (`0xFFFF_8000_0000_0000`+) e il
primo CR3 reload non spazza più la propria pagina di codice. Triple
fault risolto.

### MB13.c — `nexacore-capability` come dep di `nexacore-kernel`

Sbloccato da MB13.a, `nexacore-capability` entra in
[`crates/nexacore-kernel/Cargo.toml`](../../crates/nexacore-kernel/Cargo.toml)
con `default-features = false` e features esplicite (`verify`,
`bare-metal`). `crates/nexacore-capability/src/scope.rs` guadagna
`Action::IpcSend`, `Action::IpcRecv`, `Resource::IpcChannel(u64)`
(additive via `#[non_exhaustive]`). Nasce
[`Ed25519CapabilityProvider`](../../crates/nexacore-kernel/src/capabilities.rs)
con tre superfici: `verify_signature_only`, `verify_signed_token`
(signature + time window + TEE binding via `StubAttestation`), e
`impl KernelCapabilityCheck::verify` con shape-match O(1) identico
allo stub — drop-in replacement per il per-IPC hot path.

### MB13.d — `IpcCreateChannel` ABI estesa (signed-token slot)

L'ABI di `IpcCreateChannel` ([syscall_entry.rs](../../crates/nexacore-kernel/src/bare_metal/syscall_entry.rs))
guadagna due slot opzionali per i bytes postcard-encoded di un
`nexacore_capability::CapabilityToken` (per send e per recv). La nuova
`KernelIpcRegistry::create_channel_signed`
([ipc.rs](../../crates/nexacore-kernel/src/ipc.rs)) decodifica i token,
invoca `Ed25519CapabilityProvider::verify_signed_token`, e estrae il
`subject` come `KernelPrincipal` per il gating per-IPC. La
backwards-compat: `(send = None, recv = None)` resta un valido
"open channel" — il registry forwarda al path `create_channel` con
lo stesso provider (la `verify` per-IPC è shape-match identico).

### MB13.f — `enter_user_mode` kernel-stack swap

Il deploy MB13.b su Proxmox ha rivelato un secondo bug latente: il
primo dispatch user-side moriva muto prima ancora di scrivere su
COM1. Root cause: `enter_user_mode` eseguiva `mov cr3, dest_cr3`
mentre `RSP` puntava ancora allo stack del chiamante. Nel path MB12
first-dispatch invocato da dentro un syscall handler (`SYSCALL`
x86_64 non commuta `SP`), quello era lo *user stack del task
uscente* — dopo il CR3 reload la sua pagina non era più mappata. Fix
in [bare_metal/usermode.rs](../../crates/nexacore-kernel/src/bare_metal/usermode.rs):
`enter_user_mode` accetta un `kernel_stack_top: u64` aggiuntivo e
fa `mov rsp, kernel_stack_top` PRIMA del `mov cr3`. Follow-up commit
nel modulo di gestione processi del kernel (`bare_metal`):
`spawn_from_elf` alloca + mappa la kernel stack del task entrante
PRIMA di clonare il PML4 (altrimenti il PDPT installato dopo il
`new_with_kernel_half` non propaga al PML4 cloned).

### MB13.g — Comprehensive IDT coverage

Smoke MB13.f su the test VM: VM ancora muta. Lavorando alla cieca per
identificare il vettore colpevole, l'IDT è stata estesa con 16
handler catch-all (`#DE`, `#DB`, `#NMI`, `#BP`, `#OF`, `#BR`, `#UD`,
`#NM`, `#TS`, `#NP`, `#SS`, `#GP` esistente, `#PF` esistente, `#MF`,
`#AC`, `#MC`, `#XM`, `#VE`, `#CP`). Ciascun handler emette
`[NexaCore OS EXCEPTION] vec=NN err=0xXX rip=0xYYYY...` su COM1 e poi
halt. Il commit è puramente diagnostico ma blocca la possibilità di
un altro silent triple-fault.

### MB13.h — TSS `ltr` wiring + IST stacks dedicati

Root cause del silenzio post-iretq finalmente identificata via code
review: `tss::ltr_load()` (che esegue `ltr 0x28`) **non era mai
chiamata** da `kmain`. Conseguenza diretta: anche se `TSS.rsp0`
veniva impostato dallo scheduler prima di ogni dispatch user, il task
register restava nullo. Qualunque eccezione sincrona Ring 3 → Ring 0
non riusciva a risolvere `TSS.rsp0` dal task register e cascadava a
triple-fault PRIMA di poter scrivere `[NexaCore OS EXCEPTION] vec=NN` su
COM1. Inoltre `TSS.ist1` / `ist2` erano hardcoded a zero, quindi
qualunque fault stack-related cascadava a `#DF` muto. Tre cambi
atomici: `tss::init_ist_stacks()` alloca due `[u8; 16384]` in `.bss`
per IST1/IST2; `idt::IdtEntry::interrupt_gate_with_ist` consente di
encodare l'IST index nei low 3 bit dell'entry; `kmain` chiama in
sequenza `gdt_init` → `init_ist_stacks` → `ltr_load` → `idt_init`,
con `#DF (vec 8) → IST=1` e `#PF (vec 14) → IST=2`.

### MB13.e — Chiusura del ciclo

Il blocco MB13.e (questo ADR) chiude formalmente la migrazione:

1. **Boot wiring**: `Ed25519CapabilityProvider::placeholder()` è il
   provider canonico in ogni path di `IpcCreateChannel`
   (syscall handler MB12 fallback + `userprobe_mb12` pre-create +
   shortcut `create_channel_signed(None, None)`).
2. **`StubCapabilityProvider` gating**: lo stub originale è ora
   `#[cfg(test)]`-only — irraggiungibile dalla boot wiring di
   produzione. Il `KernelCapabilityCheck` trait sopravvive con due
   implementazioni: una di produzione (Ed25519) e una di test
   (Stub) usata solo dai unit test che vogliono shape-match
   semantics senza la catena Ed25519 in dipendenza.
3. **Integration test cross-process MB12** migrato a
   `Ed25519CapabilityProvider::placeholder()` (le integration test
   sotto `tests/` non vedono il gate `#[cfg(test)]` della libreria).

**Sintesi:** MB13 sostituisce lo `StubCapabilityProvider` con
`Ed25519CapabilityProvider` reale come unico provider raggiungibile
dal boot path, rimuove il triple-fault smoke MB12 via ET_DYN kernel +
kernel-stack swap pre-CR3 + TSS `ltr` wiring, ed estende l'ABI di
`IpcCreateChannel` per accettare `CapabilityToken` postcard-encoded
firmati Ed25519.

---

## Alternative Considerate

### Alternativa 1: crate `nexacore-crypto-verify` separato (verify-only)

- **Descrizione:** invece di forzare `force-soft` su tutta
  `nexacore-crypto`, splittare in due crate: `nexacore-crypto` (full
  features, host-only) e `nexacore-crypto-verify` (verify-only,
  `no_std`, soft backends statici).
- **Pro:** boundary più pulito; il kernel non eredita le feature
  `mint`/`encrypt` che non userà mai. Performance host massima.
- **Contro:** doppia API surface da mantenere. Forza una scissione
  che a Phase 1 non è giustificata dall'uso reale. Ritarda MB13.
- **Motivo di esclusione:** ROI negativo: la differenza di binario
  bare-metal fra il path `force-soft` e un crate dedicato è
  minimale (cargo elimina le funzioni unreferenced via LTO), e il
  test surface raddoppierebbe. Da rivisitare se Phase 2 introduce
  una platform dove il binary footprint diventa critico.

### Alternativa 2: `IpcCreateChannel` ABI rigida — token obbligatori

- **Descrizione:** rendere i due token slot **obbligatori** in MB13,
  eliminando il fallback `(None, None) → open channel` per allineare
  il kernel a "capability-or-nothing".
- **Pro:** chiusura completa del security gap MB12. Nessun back-door
  dev-mode da rimuovere in Phase 2.
- **Contro:** richiede che ogni userprobe ELF di test porti un
  token canned firmato build-time, il che implica `build.rs`
  ricorsivo (build dell'ELF dipendente da una chiave Ed25519
  embedded) + signing host-side. Complessità non giustificata per
  un milestone tracking la migrazione del provider, non l'enforcement.
- **Motivo di esclusione:** spostiamo l'enforcement strict a MB14 (o
  a un follow-up dedicato dopo `nexacore-tee`): il `mb12-userprobe`
  attuale chiama `IpcCreateChannel(0, 0, …)` e dipende dal kernel
  per il pre-create del canale 1. Forzare token obbligatori
  romperebbe il demo. Lo stato attuale è "enforced by default per i
  caller che presentano un token; open channel per i caller che
  non lo presentano" — un trade-off documentato qui e accettato per
  Phase 1 dev mode.

### Alternativa 3: opzione `(c)` — debugger remoto per il triple-fault

- **Descrizione:** invece di MB13.g (IDT exhaustive coverage), usare
  `-d int,cpu_reset -D /tmp/qemu-trace.log` su QEMU per leggere il
  vec=NN colpevole dal log.
- **Pro:** zero codice nuovo nel kernel; il log riporta il vector
  esattamente.
- **Contro:** richiede modifica del file `/etc/pve/qemu-server/103.conf`
  sul Proxmox host; produce log su disco impossibili da consultare
  in remoto via la sola seriale COM1. La VM resta muta per
  l'osservatore esterno.
- **Motivo di esclusione:** preferiamo che il kernel sia
  self-diagnosing — l'utente che riproduce un bug sulla propria
  hardware non dovrebbe dover toccare la config Proxmox. MB13.g
  consegna una IDT che resta utile anche dopo MB14, non solo per
  questo singolo bug.

---

## Conseguenze

### Positive

- **Capability-based security primitives** Phase 1 deliverable
  passa da `⬜` a `✅`: i token presentati al kernel sono
  verificati Ed25519 + time window + TEE binding via
  `nexacore_capability::CapabilityToken::verify_full`.
- **`nexacore-crypto` ora compila su `x86_64-unknown-none`**: sblocca
  qualunque crate kernel-side che voglia usare hash o firme
  (futuro `nexacore-tee`, drivers user-space P6.7).
- **Boot path triple-fault smoke MB12 risolto**: ET_DYN kernel +
  kernel-stack swap pre-CR3 + TSS `ltr` wiring riportano il
  microkernel a uno stato bootabile end-to-end su Proxmox.
- **IDT esaustiva**: qualunque eccezione sincrona Ring 3 → Ring 0
  che dovesse cadere in un vettore non gestito ora produce un log
  COM1 chiaro invece di un silent triple-fault. Tooling utile
  per qualsiasi bug futuro nella user-mode path.
- **Trait `KernelCapabilityCheck` swap-in compatible**: il path
  `Ed25519CapabilityProvider`-vs-`StubCapabilityProvider` non
  richiede modifiche al sito di chiamata. Gli unit test esistenti
  continuano a funzionare con la mock minimale.

### Negative

- **`(None, None)` open-channel resta un dev-mode back-door**: per
  preservare il demo `mb12-userprobe`, l'ABI estesa
  `IpcCreateChannel` accetta `(send = 0, recv = 0)` come "no
  capability gating". Documentato esplicitamente in
  [syscall_entry.rs](../../crates/nexacore-kernel/src/bare_metal/syscall_entry.rs)
  e in questo ADR. Tracked: MB14 follow-up per enforcement strict
  + userprobe ELF aggiornati con token canned firmati.
- **`StubAttestation` placeholder per TEE binding**: il
  `node_id_bytes` di `Ed25519CapabilityProvider` è all-zero finché
  `nexacore-tee` (P5) non fornisce un'identità attestata reale. Le
  firme sono cripto-valide ma la TEE binding-check resta una
  no-op semantica.
- **`force-soft` su `nexacore-crypto`**: il path SIMD-ottimizzato resta
  disabilitato. Su host le perf scendono ~3× (irrilevante per il
  kernel; rilevante se in futuro `nexacore-crypto` torna ad essere
  usato host-side via lo stesso workspace `.cargo/config.toml`).
  Mitigation: il flag è `cfg=`, non `cfg!`, quindi un workspace
  esterno può riabilitare.

### Rischi

- **TEE binding superficiale finché `nexacore-tee` non lande**: chiunque
  in possesso della signing key può mintare un token che il
  kernel accetta. Mitigation: la signing key è per definizione
  detenuta dal kernel stesso (single-node Phase 1); la minaccia
  reale è multi-node, e si sblocca solo quando i drivers user-space
  (P6.7) introducono peers che possono ricevere token.
- **`Ed25519CapabilityProvider::placeholder()` è il default boot**:
  se domani aggiungiamo un secondo nodo con una `node_id` non-zero,
  i token mintati con un placeholder verranno rejected. Tracked
  come MB14 deliverable: bootloader passa il `node_id` reale al
  kernel, che costruisce il provider con `with_node_id`.
- **`force-soft` SIMD path è non-constant-time**: la
  side-channel-resistance dei `sha2`/`poly1305` soft fallback è
  inferiore al path SIMD ottimizzato (RustCrypto docs). Mitigation:
  il path verify-only è invocato una volta per channel, non per
  IPC. Il numero di sample side-channel disponibile è
  trascurabile.

---

## Note di Implementazione

- **Wiring boot**: il provider `Ed25519CapabilityProvider::placeholder()`
  è istanziato sul kernel stack nei tre call site (`syscall_entry`,
  `userprobe_mb12`, fallback `create_channel_signed`). Costo:
  32 byte di stack + zero allocazioni. Cargo LTO elimina le copie
  duplicate.
- **Tests**: i due unit test path coesistono:
  - `crates/nexacore-kernel/src/capabilities.rs#[cfg(test)] mod tests`
    minta token Ed25519 reali via `nexacore_capability::CapabilityToken`
    + `NexaCoreSigningKey` (i.e. esercita il path full-verify).
  - `crates/nexacore-kernel/src/ipc.rs#[cfg(test)] mod tests` usa
    `StubCapabilityProvider` per testare la registry indipendente
    dalla catena Ed25519.
  - `crates/nexacore-kernel/tests/mb12_ipc_cross_process.rs` usa
    `Ed25519CapabilityProvider::placeholder()` (integration test
    non vede il `cfg(test)` della libreria).
- **Wire format token**: postcard via
  `nexacore_types::wire::decode_canonical`. La policy di "rebind
  resource id" (il kernel ignora `Resource::IpcChannel(_).0` e
  rimappa al channel id appena allocato) è documentata in
  [`capabilities.rs::decode_and_authenticate_token`](../../crates/nexacore-kernel/src/capabilities.rs);
  preserva l'attenuazione perché il subject resta vincolato dal
  signature, e il per-IPC check confronta `requester ==
  channel.send_subject` sulla nuova `(channel_id, subject)` coppia.
- **Build Info panel**: i campi `Active = MB13.e closure`,
  `Next = MB14 MP/AP enable`, `Phase 1 ≈ 82%`,
  `Track B = MB1-MB12 OK, MB13.a-h OK` riflettono lo stato post-MB13.e
  sulla schermata di boot ([bare_metal/demo.rs](../../crates/nexacore-kernel/src/bare_metal/demo.rs)).

---

## Riferimenti

- ADR-0005 § *Migration* — promessa originaria del swap Ed25519
- `progress-nexacore.md` § 2.2 (Track B) — milestone log
- the backlog § P6.MB13 — work breakdown
- `ncips/ncip-kernel-003.md` — capability dispatch design
- `crates/nexacore-capability/src/lib.rs` — userspace token surface
- `crates/nexacore-kernel/src/capabilities.rs` — kernel-side providers
- `crates/nexacore-kernel/src/ipc.rs` — `KernelIpcRegistry`
- `crates/nexacore-kernel/src/bare_metal/syscall_entry.rs` —
  `IpcCreateChannel` ABI handler
