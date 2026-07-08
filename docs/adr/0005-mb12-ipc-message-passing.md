# ADR-0005: MB12 — IPC reale (message-passing tra processi user-space)

## Metadata

- **ID:** ADR-0005
- **Data:** 2026-05-18
- **Stato:** accepted
- **Sostituisce:** —
- **Sostituito da:** —
- **Riferimenti:** [ADR-0001](./0001-mb9-paging-huge-page-aware.md), [ADR-0002](./0002-mb10-kernel-stack-isolation.md), [ADR-0003](./0003-no-blanket-allows-in-production-crates.md), [ADR-0004](./0004-mb11-userspace-ring3-per-process-cr3.md), `ncips/ncip-kernel-003.md`, `progress-nexacore.md` § 5 Step 4

---

## Contesto

ADR-0004 (MB11) ha portato il microkernel a Ring 3 con per-process CR3:
un singolo processo user `mb11-userprobe` boota, chiama `WriteConsole`
+ `TaskExit`, e termina con il kernel halt. Manca il pilastro
fondamentale del modello microkernel: **message-passing IPC**. Senza un
canale IPC kernel-mediated:

- Il driver model user-space (`P6.7` — NVMe, Ethernet, TEE) è bloccato.
- Il modello security capability-based non ha un consumer reale dentro
  il kernel.
- Il deliverable Phase 1 della roadmap "IPC primitives operational
  (typed message passing)" resta `⬜`.

Lo stato pre-MB12:

- [crates/nexacore-kernel/src/ipc.rs](../../crates/nexacore-kernel/src/ipc.rs) ospita lo scaffold:
  `ChannelId`, `MessageKind`, `BackpressurePolicy`, `ChannelPolicy`,
  `MessageEnvelope`, trait `Ipc` con 5 metodi che ritornano
  `NotYetImplemented`.
- `SyscallNumber::IpcCreateChannel/IpcDestroyChannel/IpcSend/IpcReceive`
  (20-23) prenotati ma routati a `NotYetImplemented`.
- `TaskState::BlockedOnIpc` già definito ([scheduling.rs:113](../../crates/nexacore-kernel/src/scheduling.rs#L113));
  `yield_current` rispetta non-Runnable state.
- `validate_user_buffer` + `enter_user_mode` consolidati in MB11.

L'obiettivo MB12 è chiudere questa parte: due processi user spawned
via `spawn_from_elf` scambiano un payload attraverso un canale
kernel-mediated, con capability check verificato lato kernel e
gestione della backpressure (`Block` / `Drop` / `EvictOldest`).

Lungo il path implementativo è emerso un blocker tecnico significativo
(documentato nella sezione *Decision* sotto e nei *Consequences*):
`nexacore-crypto` non compila su `x86_64-unknown-none` per via di SIMD
intrinsics in `sha2`, `poly1305`, `curve25519-dalek`. La piena
integrazione di `nexacore-capability` (che dipende da `nexacore-crypto`) come
dep del kernel è pertanto deferred a **MB13**.

---

## Decisione

MB12 introduce sette sotto-blocchi (`MB12.0a` → `MB12.9`):

### MB12.0a/b — Prerequisiti multi-task user

`RoundRobinScheduler::yield_current` ([scheduling.rs](../../crates/nexacore-kernel/src/scheduling.rs))
ora gestisce lo switch a un task user con tre operazioni in sequenza:

1. **TSS.rsp0 dinamico**: `tss::set_rsp0(next.kernel_stack_va +
   KERNEL_STACK_SIZE)` quando `next` ha un `ProcessControlBlock`
   registrato. Senza questo, la prossima transizione Ring 3 → Ring 0
   atterrerebbe sul kernel stack del task precedente.
2. **CR3 reload**: `mov cr3, next.address_space.pml4_phys.0` carica la
   PML4 del processo entrante. Kernel-half mirrored by reference
   (MB11), quindi le istruzioni successive restano mappate.
3. **First-dispatch detection**: se `next.context.rsp == 0` (sentinel
   da `spawn_from_elf`), il task è vergine — niente context_switch asm
   da restorare. Invece, `enter_user_mode(user_entry, user_stack_top,
   USER_RFLAGS, cr3_phys)` costruisce l'`iretq` frame e dispatcha
   direttamente in Ring 3. Lo stato del task precedente è già stato
   salvato dal yield_current chiamante.

Costante `USER_RFLAGS = 0x202` (IF=1 + reserved bit 1) esportata da
[bare_metal/usermode.rs](../../crates/nexacore-kernel/src/bare_metal/usermode.rs#L51).

### MB12.0c — Feature gating `nexacore-crypto`

[`nexacore-crypto/Cargo.toml`](../../crates/nexacore-crypto/Cargo.toml) introduce una sezione `[features]`:

- `default = ["rng"]` (no regression userspace).
- `rng = ["dep:getrandom", "dep:rand_core", "dep:argon2",
  "nexacore-types/id-generation"]` — propaga al transitive deps che
  richiedono CSPRNG.
- `bare-metal = []` (alias semantic per consumer downstream).

Le 3 deps RNG diventano `optional = true`. I metodi `generate()` su
`NexaCoreSigningKey`, `NexaCoreAeadKey`, `NexaCoreEphemeralSecret`,
`NexaCoreStaticSecret`, `generate_ephemeral` e l'intero blocco `argon2id_*`
in [kdf.rs](../../crates/nexacore-crypto/src/kdf.rs) sono ora `#[cfg(feature = "rng")]`. Il
verify-only path (`NexaCoreVerifyingKey::verify`, `domain_separated_hash`,
HKDF) resta sempre disponibile.

`nexacore-types` è dichiarato `default-features = false` direttamente in
nexacore-crypto/Cargo.toml (Cargo non consente di overrideare
`default-features` su workspace inheritance).

**Scoperta tecnica**: durante la verifica del bare-metal build è
emerso un LLVM ICE (`Do not know how to split the result of this
operator!`) compilando `sha2`, `poly1305`, `curve25519-dalek` per
`x86_64-unknown-none` dal toolchain host `1.85-aarch64-apple-darwin`.
Il problema è ortogonale a `getrandom`: le librerie RustCrypto usano
`cpufeatures` per attivare AVX2/AVX-512 paths senza fallback `soft`
per il target `none`. Soluzione MB13: feature `force-soft` su sha2 +
poly1305 + curve25519-dalek, oppure estrazione di
`nexacore-crypto-verify` come crate separato. Vedi *Alternative* +
*Migration*.

### MB12.0c' — Capability check kernel-internal (pivot)

Dato il blocker su `nexacore-crypto` bare-metal, MB12 NON integra
`nexacore-capability` come dep di `nexacore-kernel`. Invece, introduce un
trait minimale [`KernelCapabilityCheck`](../../crates/nexacore-kernel/src/capabilities.rs) con:

- `KernelPrincipal([u8; 32])` — newtype byte-equality.
- `KernelAction { IpcSend, IpcRecv }` (mirror tipi-tipo di
  `nexacore-capability::Action`).
- `KernelResource { IpcChannel(u64) }`.
- `KernelCapabilityToken { subject, action, resource }`.
- `CapabilityVerdict { Authorised, Denied }`.
- `StubCapabilityProvider`: implementazione MB12 che verifica
  action/resource shape match (senza crypto). MB13 swappa con un
  provider Ed25519 reale (vedi *Migration*).

Il trait shape è progettato per essere swap-in con il provider reale
Ed25519+revocation+TEE attestation di MB13.

### MB12.1+2 — KernelIpcRegistry concreto

`KernelIpcRegistry` ([ipc.rs](../../crates/nexacore-kernel/src/ipc.rs)) sostituisce
lo scaffold `trait Ipc`:

- Storage: `BTreeMap<u64, Channel>` (NON `HashMap` — `hashbrown`
  richiede `ahash` → `getrandom`, conflitto con MB12.0c).
- Singleton `static mut IPC_REGISTRY: KernelIpcRegistry =
  KernelIpcRegistry::new()` (Phase 1 single-CPU, MP arriva in Phase 2).
- Accessor `unsafe fn ipc_registry_mut()` con SAFETY contract sul
  SYSCALL path (interrupts masked via `IA32_FMASK = 0x200`).
- `Channel { id, policy, owner, send_subject, recv_subject, queue,
  waiters_send, waiters_recv }` — wait queues dentro il canale (O(1)
  lookup, cleanup locale a destroy).
- `WakeAction { None, Wake(TaskId), Block(TaskId) }` — contratto
  registry → syscall: il syscall layer chiama `sched.enqueue` /
  `sched.yield_current` in base al `WakeAction` ritornato.
- Capability check a 2 livelli:
  - `create_channel(...)`: chiamata a `verifier.verify(...)` SOLO
    quando il chiamante presenta un token; memorizza il `subject`.
  - `send` / `receive`: comparazione byte-equality
    `requester == channel.{send,recv}_subject`.

### MB12.3 — PCB estesa

[`ProcessControlBlock`](../../crates/nexacore-kernel/src/process.rs)
guadagna due campi:

- `principal: KernelPrincipal` — autorità del processo, usata dalla
  comparazione capability nelle send/recv. Default `KernelPrincipal::ZERO`
  per kernel-spawned smoke tests / dev mode.
- `pending_receive: Option<PendingReceive>` — slot reserved per il
  pattern drain-at-dispatch (MB13 zero-copy / SharedMemoryGrant).

`spawn_from_elf` accetta ora `principal: KernelPrincipal` come ultimo
parametro.

### MB12.4 — Capability gate (inline nel registry)

Il check vive dentro `KernelIpcRegistry` stesso piuttosto che in un
modulo separato — il design Phase 1 evita un trait crossing
syscall→registry. MB13 estrae il check in `enforce_ipc_*` quando si
swap con il provider Ed25519.

### MB12.5 — Syscall handlers 20-23

`bare_metal/syscall_entry.rs` aggiunge il modulo gated
`ipc_handlers` (`cfg(all(feature = "bare-metal", target_os = "none",
not(test)))`) con i 4 handler:

- `ipc_create_channel(args)` — ABI `(queue_depth, backpressure: u8,
  tee_bound: u8, _, _, _) -> channel_id`. Per MB12 niente token via
  syscall (open channels — capability gating restato testabile via
  `KernelIpcRegistry::create_channel` direttamente).
- `ipc_destroy_channel(args)` — ABI `(channel_id, _, _, _, _, _) -> 0
  | u64::MAX`.
- `ipc_send(args)` — ABI `(channel_id, kind, payload_ptr, payload_len,
  _, _) -> 0 | u64::MAX`. Loop di retry sul `WakeAction::Block`: il
  task parka, ri-tenta send dopo wake-up. `MAX_PAYLOAD = 4096`.
- `ipc_receive(args)` — ABI `(channel_id, dst_ptr, dst_cap, blocking,
  _, _) -> bytes_received | u64::MAX`. Loop di retry su empty queue +
  blocking=1.

Tutti chiamano `validate_user_buffer`-equivalent via range guard
manuale (`user_range_ok`) + hardware PT walk durante
`copy_nonoverlapping` (pattern già usato da `write_console`).

### MB12.0f + MB12.6 — User binaries + boot wiring

[`bare_metal/userprobe_mb12.rs`](../../crates/nexacore-kernel/src/bare_metal/userprobe_mb12.rs)
embedda due ELF hand-crafted (pattern MB11.7):

- `USERPROBE_SENDER_ELF` (179 byte totali, code+data 59 byte):
  `IpcSend(ch=1, kind=Notification, "ping", 4)` → `TaskExit(0)`.
- `USERPROBE_RECEIVER_ELF` (197 byte file, 141 in-mem): `IpcReceive(ch=1,
  buf, 64, blocking=1)` → `WriteConsole(buf, n)` → `TaskExit(0)`.

`spawn_userprobe_mb12` pre-crea channel 1 + spawna entrambi i task.
`kmain` (sotto `cfg(feature = "mb12-userprobe")`) chiama questa
funzione, registra sé stesso come bootstrap task, e
`yield_current(kmain, Terminated)` cede agli user task. Il path MB12.0a/b
gestisce il primo dispatch via `enter_user_mode`.

Mutualmente esclusivo con `mb11-userprobe`: quando entrambi i feature
sono on, il blocco MB11 esegue per primo e fa halt prima del MB12.

`task_exit` aggiornato per fare `yield_current(Terminated)` prima di
`halt_forever`, cedendo il flow al prossimo task runnable invece di
fermare il kernel intero — necessario perché MB12 ha più task user
simultanei.

### MB12.7 — Integration test cross-process

[`tests/mb12_ipc_cross_process.rs`](../../crates/nexacore-kernel/tests/mb12_ipc_cross_process.rs)
(8 test host-side):

1. `both_userprobe_elfs_load_into_separate_address_spaces` — sender e
   receiver coesistono in due AS distinte.
2. `cross_process_send_then_receive_round_trip` — happy path.
3. `receiver_parks_then_wakes_on_subsequent_send` — block-on-empty +
   wake-on-send.
4. `block_policy_full_queue_parks_sender_and_wakes_on_drain` — wake
   simmetrico sul drain.
5. `capability_send_subject_mismatch_denied_cross_process`.
6. `capability_recv_subject_mismatch_denied_cross_process`.
7. `destroy_only_by_owner_across_synthetic_processes`.
8. `channel_id_monotonic_across_two_creates_one_destroy` (no id reuse).

---

## Alternative considerate

### A. Integrazione full `nexacore-capability` come dep del kernel

Era il piano originale. Bloccata dal LLVM ICE su sha2 + poly1305 +
curve25519-dalek (vedi *Decision* § MB12.0c). Rimandata a MB13:
richiede `force-soft` feature sulle 3 librerie *o* estrazione di
`nexacore-crypto-verify` come crate separato (verify-only — niente
generate, niente AEAD, niente argon2). Effort stimato MB13: 1-2
giorni.

### B. Drain-at-dispatch nel scheduler

Il piano iniziale ipotizzava che il messaggio fosse copiato nel buffer
user del receiver al context-switch d'ingresso (dispatch-time), non
dal syscall handler stesso. Vantaggio: zero-copy futuro più semplice
per `MessageKind::SharedMemoryGrant`. Svantaggio: hook intrusivo nel
context_switch asm path, accoppiamento stretto scheduler↔IPC.

**Scelto invece**: retry-loop nel syscall handler. Il task park-a su
`BlockedOnIpc`, si rischeglia su `WakeAction::Wake`, ri-tenta l'op. Il
context_switch è invariato. `PendingReceive` resta nel PCB come slot
reserved per MB13 quando l'ottimizzazione zero-copy avrà valore
misurabile.

### C. `HashMap` invece di `BTreeMap` per `KernelIpcRegistry::channels`

`hashbrown::HashMap` (workspace default) usa `ahash` con seed da
`getrandom`. Conflitto frontale con MB12.0c. `BTreeMap` da `alloc` è
zero-dep, deterministico, e Phase 1 alloca decine di canali al massimo
— la differenza O(1) vs O(log n) è irrelevante.

### D. Zero-copy via `MessageKind::SharedMemoryGrant`

Discarded per MB12. Richiede:
- User-VA allocator per il receiver (oggi assente).
- TLB invalidation cross-AS.
- Ownership transfer fra processi (allocator handoff).

MB13+ con un user-space mmap proper.

### E. Capability check ACL-only (no `nexacore-capability` mai)

L'utente ha chiesto esplicitamente di mantenere la traiettoria verso
`nexacore-capability` reale. Il trait `KernelCapabilityCheck` qui è la
forma intermedia: stessa API che il provider Ed25519 esporrà in MB13,
ma con verify=Authorised come stub.

---

## Conseguenze

### Positive

- **v0.1 ABI completa per i 4 syscall IPC** (20-23). I numeri prenotati
  sono ora operativi.
- **Multi-task user funzionante**. Lo scheduler gestisce il dispatch
  CR3 + TSS.rsp0 + first-dispatch trampoline. Apertura per MB13
  (capability reale) + P6.7 (driver in user space).
- **Pattern di retry-loop syscall consolidato**: applicabile a futuri
  syscall blocking (sleep, wait).
- **Feature flag `nexacore-crypto/rng` introdotto**: prepara il terreno per
  MB13 ovvero la verify-only bare-metal build, senza breaking change
  per i consumer userspace (default-on).
- **`task_exit` ora yielda invece di halt-forever** quando ci sono
  task runnable — comportamento corretto per multi-task da qui in poi.
- **Boot wiring smoke `mb12-userprobe`** + image `kernel-runner`
  pronta: serial trace atteso documentato nel modulo.

### Negative / debt

- **`nexacore-crypto` non compila bare-metal**: deferred a MB13. Documentato
  qui + flag CI futuro che eserciti `--no-default-features` su
  `nexacore-crypto`.
- **Capability check è uno stub**: `StubCapabilityProvider::verify`
  ritorna `Authorised` su qualunque match action/resource. Niente
  signature verification. MB13 lo swappa.
- **Heap allocator no-free**: ~~`BumpHeap` non rilascia frame quando un
  canale è distrutto. `queue_depth` cap raccomandato ≤ 256 messaggi
  per canale; con 64 canali ≈ 64 MiB heap usage worst-case. Slab
  allocator → NCIP separato.~~ **RISOLTO (2026-06-14, WS1-08 / NCIP-Kernel-Alloc-029).**
  Il `#[global_allocator]` del kernel è ora lo `SlabHeap` reclaiming
  (slab + free-list, WS1-08.6): `destroy_channel` droppa `queue`/waiter
  `VecDeque` e la memoria è **realmente liberata**. Di conseguenza il cap
  `queue_depth ≤ 256` (mai stato enforced in codice — `create_channel`
  rifiutava solo `queue_depth == 0`) è **ritirato** (NCIP-029 § S5): la
  profondità coda è limitata solo dall'heap disponibile. La pressione di
  risorse per-owner resta governata dal quota di canali *vivi*
  (`MAX_CHANNELS_PER_OWNER = 256` / `MAX_CHANNELS_TOTAL = 4096`,
  NCIP-Kernel-Sec-026 §S3.2), la cui motivazione è ri-giustificata: non più
  "l'heap non libera mai" ma "ogni canale vivo consuma heap proporzionale
  alla sua profondità, quindi un flood di creazione va comunque limitato".
- **HashMap → BTreeMap forced everywhere a livello kernel**: documentato
  qui come baseline.
- **`mb12-userprobe` e `mb11-userprobe` sono mutex** nel boot wiring,
  non in compile: posson coesistere come feature, il MB11 vince. CI
  matrix futuro: due job separati.
- **Serial smoke ancora manuale**: serve un nuovo job
  `qemu-boot-smoke-mb12` con `EXPECTED_LINES` esteso per `[mb12]` +
  `ping`. Non bloccante per il merge MB12.

### Test delta

Workspace test count: **393 → 426** (+33).
- `+4` capability (in `capabilities.rs`).
- `+17` IPC registry (in `ipc.rs`, esclusi i 3 pre-esistenti).
- `+10` userprobe MB12 (ELF byte-pattern, in `userprobe_mb12.rs`).
- `+8` integration test cross-process (`tests/mb12_ipc_cross_process.rs`).
- `+3` PCB (in `process.rs`, sostituiscono 1 pre-esistente).
- `-9` non-existent removed (i baseline trait scaffold tests sono
  evoluti).

### Build matrix

Tutti i build attuali in CI restano verdi:
- `cargo test --workspace --all-features`: 426 pass.
- `cargo build -p nexacore-kernel --target x86_64-unknown-none --features bare-metal`: clean.
- `cargo build -p nexacore-kernel --target x86_64-unknown-none --features mb11-userprobe`: clean (regression MB11).
- `cargo build -p nexacore-kernel --target x86_64-unknown-none --features mb12-userprobe`: clean (nuovo).
- `cargo build --manifest-path kernel-runner/Cargo.toml --target x86_64-unknown-none --features mb12-userprobe`: clean (bootable image).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: clean.
- `cargo clippy -p nexacore-kernel --target x86_64-unknown-none --features bare-metal -- -D warnings`: clean.
- `scripts/check-no-blanket-allow.sh`: ok (12 crate roots scanned).

---

## Migration / Compatibility

### Userspace `nexacore-capability` consumer

Nessun breaking change. `nexacore-capability` continua a compilare con
default features; il path di test esistenti (`131 unit + 7 integration`)
resta invariato. La feature `bare-metal` è aggiunta come no-op per ora;
serve solo a futura propagation MB13.

### `nexacore-crypto` consumer

Nessun breaking change con il default. Consumer che vogliano il
verify-only path bare-metal usano `--no-default-features` — quel path
si compila se e quando il blocker SIMD viene risolto (MB13).

### `nexacore-kernel` syscall ABI

I numeri 20-23 erano già documentati come "reserved per MB12". Il
comportamento cambia da `u64::MAX = NotYetImplemented` a operazione
reale. Nessun consumer userspace esistente li chiamava.

### MB13 follow-up (path verso il capability check reale)

1. **Sbloccare nexacore-crypto bare-metal**: aggiungere `force-soft`
   feature in `nexacore-crypto/Cargo.toml` per propagare a sha2 + poly1305
   + curve25519-dalek. Verificare che il subset verify-only compili
   per `x86_64-unknown-none`. Costo: 4-8 ore.
2. **Aggiungere `nexacore-capability` come dep di `nexacore-kernel`** con
   `default-features = false` + propagation `nexacore-crypto/bare-metal`.
   Costo: 1-2 ore.
3. **Aggiungere `Action::IpcSend/IpcRecv` + `Resource::IpcChannel(u64)`
   in `nexacore-capability::scope`** (variants `#[non_exhaustive]` →
   semver-safe). Costo: 30 min.
4. **Sostituire `StubCapabilityProvider` con `Ed25519CapabilityProvider`**
   che chiama `CapabilityToken::verify_full(now, &attest, &rev)`. Costo:
   2-4 ore. Il trait `KernelCapabilityCheck` ha già la shape
   compatibile.
5. **Estendere l'ABI syscall `IpcCreateChannel`** per accettare due
   pointer (`send_token_ptr`, `recv_token_ptr`) → postcard decode +
   verify. Aggiornare il userprobe ELFs nel test integration MB13.

Stima totale MB13 (solo capability layer, non drivers): ~1-2 giornate.

---

## Riferimenti

- `progress-nexacore.md` § 5 Step 4 — "MB12: IPC concreto".
- `ncips/ncip-kernel-003.md` (UEFI bootloader, Active).
- `ncips/ncip-bounty-002.md` (capability ABI bounty — adjacent).
- `docs/04-security-model.md` § "Capability-based access control".
- `docs/03-mesh-protocol.md` § "Authority flow via CapabilityToken".
- Intel SDM Vol 3A, § 6.14 "64-bit mode interrupts and exceptions"
  (TSS.rsp0 semantics).
- Linux `man 2 syscall` (RDI/RSI/RDX/R10/R8/R9 ABI mirror).
