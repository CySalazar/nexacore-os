# ADR-0003: No blanket `#![allow(...)]` in production crates

## Metadata

- **ID:** ADR-0003
- **Data:** 2026-05-18
- **Stato:** accepted
- **Sostituisce:** —
- **Sostituito da:** —
- **Riferimenti:** [ADR-0001](./0001-mb9-paging-huge-page-aware.md), [ADR-0002](./0002-mb10-kernel-stack-isolation.md), `progress-nexacore.md` § 4.5 (kernel CI debt), § 5 Step 7

---

## Contesto

Il rilascio v0.2.0 ha chiuso il ciclo MB1-MB9 e portato il kernel in stato
boot-end-to-end (UEFI + paging + IDT + syscall + scheduler + LAPIC). Per
chiudere la PR #29 in tempo ragionevole, il crate `nexacore-kernel` ha
accumulato un debito tecnico di sopressione clippy a livello crate-root su
`crates/nexacore-kernel/src/lib.rs:48-152`:

```rust
#![allow(unsafe_code)]                                   // ~216 unsafe {} + ~49 unsafe fn
#![allow(clippy::pedantic, clippy::nursery, clippy::cargo)]  // ~200+ findings
#![allow(
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::new_without_default,
    clippy::fn_to_numeric_cast,
    clippy::doc_lazy_continuation,
    clippy::implicit_saturating_sub
)]                                                       // ~80 sites
#![allow(clippy::missing_errors_doc)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::private_intra_doc_links)]
```

Il commento al sito di sopressione ammette esplicitamente la natura
temporanea:

> *Tracking: a follow-up cleanup pass (post-v0.2.0) will lift the blanket
> suppression by addressing pedantic findings file-by-file and only the
> truly intentional ones will get a localised `#[allow]` + `reason`.*

Il blanket allow ha tre conseguenze indesiderate:

1. **Maschera bug futuri.** Un nuovo `unsafe {}` senza `// SAFETY:` comment,
   un indexing `arr[i]` senza bounds check precedente, una `cast_possible_
   truncation` realmente lossy non vengono più segnalati. Il blanket
   spegne sia il rumore che il segnale.
2. **Disincentiva la pulizia.** Finché il blanket esiste, ogni nuova `unsafe`
   nasce senza ergonomia obbligatoria (reason clause, attenzione editoriale).
   MB11 (Ring 3 trampoline, TSS, CR3 reload) introdurrà ~30 nuovi `unsafe`
   blocks: senza policy, sarebbero altro debito accumulato.
3. **Viola la lint policy del progetto** (§ "Lint policy" negli standard di
   codice): le soppressioni devono essere localizzate e motivate; le
   suppressioni a crate-root sono ammesse solo per gruppi dichiarati
   permanenti (es. `missing_docs` su crate di esempio,
   `cfg_attr(test, allow(...))` su test).

Step 7 della roadmap (post-MB10) chiude questo debito.

---

## Decisione

**Sintesi:** in nessun crate di produzione del workspace `NexaCore OS` è
ammesso un attribute `#![allow(<group>)]` a livello crate-root che spenga
un gruppo di lint largo. Le sole sopressioni crate-root permanenti
ammesse sono quelle elencate in § "Escape hatches" sotto.

### Regola principale

Per ogni lint warning che il workspace policy o `clippy::all` produce in
un crate di produzione (target: il binario finale o una libreria che ne
fa parte), la mitigazione DEVE essere una delle seguenti, in ordine di
preferenza:

1. **Fix del codice.** Riscrivere il sito perché il lint non scatti più.
2. **Allow localizzato + `reason`.** Apporre
   `#[allow(<lint>, reason = "<motivo conciso>")]` immediatamente sopra
   il binding, l'espressione, o l'item che genera il warning. Il `reason`
   deve essere una sola riga, in inglese, distinta da qualunque `// SAFETY:`
   comment adiacente, e motivare *perché* il lint non si applica al
   contesto specifico (invariante, contract upstream, tracking issue).
3. **Allow scoped via `cfg_attr`.** Quando il lint è specifico di una
   configurazione (target, feature, test), apporre
   `#[cfg_attr(<cfg>, allow(<lint>, reason = "..."))]` al minimo scope
   necessario (item, modulo).

### Escape hatches ammessi (whitelist crate-root)

Le seguenti sopressioni crate-root rimangono ammesse, e l'enforcement
script le esclude esplicitamente dalla scansione:

| Attribute pattern | Razionale |
|---|---|
| `#![warn(missing_docs)]` | Workspace policy positiva (warn, non allow). |
| `#![cfg_attr(test, allow(...))]` | Relaxation di lint per test target. Le fixture di test costruiscono dati sintetici e usano `unwrap()`/`expect()`/`panic!` per failing-test deterministico. Documentata workspace-wide. |
| `#![cfg_attr(all(feature = "bare-metal", not(test)), no_std)]` | Conditional `no_std` / `no_main` per target bare-metal. Non è un allow. |
| `#![doc(html_root_url = "...")]` | Doc hosting URL, non un allow. |

Qualunque altro `#![allow(...)]` a crate-root in un crate di produzione è
una **violazione** e blocca la CI.

### Clausola `reason = "..."` obbligatoria

Il `reason` field di `#[allow]` è stato stabilizzato in Rust 1.81
(`lint_reasons`). La sua presenza è **obbligatoria** per ogni allow
localizzato. Le linee guida editoriali:

- **Lunghezza**: 6-25 parole. Una riga.
- **Forma**: dichiarativa, presente, in inglese. Esempio:
  `reason = "i < CAPACITY guarantees w < N"` invece di
  `reason = "We checked the bound earlier so this is safe"`.
- **Distinto dal SAFETY comment**: il `// SAFETY:` documenta *perché
  l'unsafe è sound*; il `reason` documenta *perché siamo autorizzati a
  scrivere unsafe qui*. I due testi possono ripetere il medesimo
  invariante, ma il `reason` deve essere autosufficiente al sito di
  sopressione.

### Enforcement

Lo script `scripts/check-no-blanket-allow.sh` esegue grep ricorsivo su
`crates/<scoped>/src/lib.rs` e `crates/<scoped>/src/main.rs` cercando
`#![allow(<group>)]` non-allowlisted. Il job CI
`blanket-allow-guard` (~2 s di runtime) lo invoca a ogni push e blocca
il merge in caso di violazione, prima della matrice `cargo clippy`
pesante. Lo script è anche raccomandato come pre-commit hook locale.

### Scope iniziale (`SCOPED_CRATES`)

L'enforcement copre i crate del workspace che sono o saranno parte
dell'immagine finale dell'OS:

- `nexacore-types`, `nexacore-crypto`, `nexacore-capability`, `nexacore-tee` (foundational)
- `nexacore-kernel` (target principale di questo ADR)
- `nexacore-hal`, `nexacore-runtime`, `nexacore-mesh`, `nexacore-tokenization`,
  `nexacore-sdk`, `nexacore-agent`, `nexacore-shell` (stub stage, preparati per
  l'enforcement futuro)

**Fuori scope iniziale (eccezioni documentate):**

- `nexacore-container`: porta un workaround per un falso positivo clippy
  upstream (`clippy::literal_string_with_formatting_args`) — la
  diagnostica clippy punta a `clippy.toml`, non a un site di codice,
  quindi non esiste un binding al quale apporre un allow localizzato.
  Tracking: `crates/nexacore-container/src/lib.rs:78-85` (commento esistente
  con razionale completo). Verrà ri-folded nella policy quando l'upstream
  bug clippy sarà risolto, o tramite ADR successivo se la condizione
  persiste.

L'estensione di `SCOPED_CRATES` a nuovi crate richiede aggiornamento
sincrono di questo ADR.

---

## Alternative Considerate

### Alternativa 1: Mantenere il blanket allow

- **Descrizione:** Lasciare `#![allow(clippy::pedantic, clippy::nursery,
  clippy::cargo, unsafe_code, ...)]` su `nexacore-kernel/src/lib.rs` come
  configurazione permanente.
- **Pro:** Zero churn immediato. Nessuna PR di cleanup richiesta.
- **Contro:** Maschera bug, viola L3, disincentiva pulizia, non scala a
  MB11+ (Ring 3) che aggiungerà altro `unsafe`. Debito si accumula.
- **Motivo di esclusione:** Lo schema di lint workspace è progettato per
  *catturare* idiomi pericolosi; spegnerli a crate-root sul kernel —
  l'unico crate dove i bug sono fatali — è il peggior posto possibile.

### Alternativa 2: Targeted lift (solo bug-catching lints)

- **Descrizione:** Sollevare solo i gruppi che cacciano bug reali
  (`indexing_slicing`, `integer_division`, `unsafe_code`) ma mantenere
  `clippy::pedantic` + `nursery` + `cargo` a crate-root in perpetuo.
- **Pro:** Minimo effort. Cattura i bug più severi.
- **Contro:** `pedantic` contiene `cast_possible_truncation`,
  `missing_errors_doc`, `module_name_repetitions`, `must_use_candidate`
  — lint che *fanno la differenza* su un kernel pubblico. Il debito
  pedantic resta indefinitamente.
- **Motivo di esclusione:** Mezza soluzione. Se vogliamo qualità da
  audit-esterno (Phase 1 deliverable: "First external security audit of
  kernel + capability system"), il pedantic deve essere live.

### Alternativa 3: Full lift con policy formalizzata (questa)

- **Descrizione:** Sollevare tutti i blanket allow (eccetto whitelist),
  documentare la policy in questo ADR, applicare CI enforcement
  automatico. Vedi § Decisione.
- **Pro:** Allinea kernel al resto del workspace (`nexacore-types`,
  `nexacore-crypto`, `nexacore-capability` non hanno blanket). Cattura tutti i
  bug. Disciplina futura via reason clauses esplicite. Pre-requisito di
  audit esterno.
- **Contro:** 4 PR sequenziali di cleanup (~480 siti totali su
  `nexacore-kernel`). Effort ~1-2 settimane di review time, distribuito.
- **Motivo di adozione:** Il costo è una-tantum; il beneficio è
  permanente. Lo Step 7 in `progress-nexacore.md` § 5 lo ha già pianificato.

---

## Conseguenze

### Positive

- **Bug futuri visibili.** Indexing out-of-bounds, cast lossy, unsafe
  senza SAFETY, error-doc mancante: tutti tornano warning con file/line.
- **MB11 nasce pulito.** I ~30 nuovi `unsafe` di Ring 3 trampoline,
  TSS, CR3 reload nascono con `#[allow(unsafe_code, reason = "...")]`
  esplicito; nessun debito accumulato.
- **External audit-ready.** Il kernel rispetta lo stesso standard lint
  di `nexacore-types`, `nexacore-crypto`, `nexacore-capability`. Un auditor esterno
  vede attentamente ogni soppressione individuale con motivazione.
- **Reason clauses fanno da documentazione.** Il `reason` field è
  estraibile da `cargo clippy --message-format=json`; può essere
  aggregato in un audit-trail di soppressioni.

### Negative

- **Effort di cleanup distribuito su 4 PR.** ~80 (PR 7.1) + ~140 (PR
  7.3) + ~60 (PR 7.4) + ~265 (PR 7.2, unsafe) = ~545 siti totali.
- **Reason clauses sono editoriali.** Non possono essere auto-generate;
  ogni `reason = "..."` richiede una scelta umana.
- **Eventuale aumento di tempo di review delle PR future.** Reviewer
  deve valutare ogni allow + reason; tradeoff accettabile.

### Rischi

- **Drift della whitelist.** Se l'allowlist degli escape hatch crescesse,
  l'ADR perderebbe forza. Mitigazione: la modifica della whitelist nello
  script `check-no-blanket-allow.sh` richiede un ADR che superseda o
  estenda questo (link esplicito nello script header).
- **`reason` strings poco informativi.** "fix later" o "intentional" non
  sono accettabili. Mitigazione: code review enforcement; in futuro,
  ulteriore linter `nexacore-lint` che verifichi forma del reason.
- **Costi inattesi su crate non-kernel.** Se un crate downstream
  introducesse blanket, lo script li catturerebbe. Mitigazione:
  attualmente lo script copre `crates/*/src/{lib,main}.rs`; ogni
  estensione di scope richiede update sincrono dell'allowlist.

---

## Note di Implementazione

### Sequenza di rollout

Stage in 4 PR per minimizzare la superficie di conflitto con MB11:

1. **PR 7.1 — `chore(kernel): lift blanket allow on restriction + rustdoc lints`**
   - Rimuove `lib.rs:107-123`, `131`, `142`, `152`.
   - Sostituisce con allow localizzati + `reason`.
   - **Crea** `scripts/check-no-blanket-allow.sh` + workflow CI
     `blanket-allow-guard`.
   - **Crea** questo ADR (`docs/adr/0003-...`).
2. **PR 7.3 — `chore(kernel): lift blanket allow on clippy::pedantic`**
   - Rimuove `clippy::pedantic` da `lib.rs:78`.
   - Fix dove triviale (`must_use_candidate`, `missing_errors_doc`,
     `doc_markdown`); allow + reason dove idiomatico (cast bounded,
     similar_names register-level).
3. **PR 7.4 — `chore(kernel): lift blanket allow on clippy::nursery + clippy::cargo`**
   - Rimuove le voci residue da `lib.rs:78`.
   - Fix uniformemente.
4. **PR 7.2 — `chore(kernel): lift blanket allow on unsafe_code`**
   - Rimuove `lib.rs:64`.
   - Apporre `#[allow(unsafe_code, reason = "...")]` a ogni `unsafe {}` e
     `unsafe fn` (~265 siti). Mechanical ma editoriale.
   - **Lands immediatamente prima del branch MB11** per minimizzare
     merge conflict.

### Esempio canonico

Da `crates/nexacore-kernel/src/memory.rs:278` (già in tree, pattern di
riferimento):

```rust
#[allow(clippy::indexing_slicing, reason = "i < CAPACITY guarantees w < N")]
if self.bitmap[w] & (1u64 << b) != 0 {
    return false;
}
```

Da `crates/nexacore-kernel/src/lib.rs:413-432` (già in tree):

```rust
#[allow(
    clippy::cast_possible_truncation,
    reason = "MiB value always fits u32 for any realistic RAM size"
)]
let free_mib = (alloc.free_bytes() / (1024 * 1024)) as u32;
```

Adottare questo pattern uniformemente. `reason` su una riga, in inglese,
6-25 parole.

### Allowlist iniziale dello script

Lo script `scripts/check-no-blanket-allow.sh` riconosce come ammessi i
pattern che matchano:

```
^\s*#!\[doc\(
^\s*#!\[warn\(
^\s*#!\[cfg_attr\(\s*test\s*,\s*allow\(
^\s*#!\[cfg_attr\(\s*all\(feature\s*=\s*"bare-metal"
```

Qualunque altra forma `^\s*#!\[allow\(` su `crates/*/src/{lib,main}.rs`
è una violazione.

---

## Riferimenti

- `progress-nexacore.md` § 4.5 — Kernel CI debt (post-v0.2.0)
- `progress-nexacore.md` § 5 Step 7 — Lift nexacore-kernel blanket allow
- [ADR-0001](./0001-mb9-paging-huge-page-aware.md) — MB9 paging huge-page aware
- [ADR-0002](./0002-mb10-kernel-stack-isolation.md) — MB10 kernel stack isolation
- Rust 1.81 `lint_reasons`: https://blog.rust-lang.org/2024/09/05/Rust-1.81.0.html
- Reference patterns già in tree:
  - `crates/nexacore-kernel/src/memory.rs:278,302,342,346`
  - `crates/nexacore-kernel/src/lib.rs:413-432`
