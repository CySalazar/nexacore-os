---
ncip: 30
title: ncScript (NCIP) — a capability-gated, Rust-derived scripting language for NexaCore OS
track: Standards Track
status: Draft
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-06-23
updated: 2026-06-23
requires:
  - 7
  - 13
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

NexaCore OS today has no system scripting language: the shell only dispatches commands, agentic
automations have no executable form, and config-as-code has no authoring surface. This NCIP
specifies **ncScript** — the canonical scripting language of NexaCore OS, called *NCIP* (the
**O**mni **I**nterpreted **P**rogram) when referring to the language proper and shipped in files
with the **`.oss`** extension (NexaCore System Script).

ncScript is a deliberately **simplified derivation of Rust**: it keeps Rust-familiar syntax
(`let`, `fn`, `match`, `struct`/`enum`, `Result`/`Option`, `?`) so the millions of developers who
know Rust are immediately productive, but it drops the borrow checker and lifetimes entirely.
Memory is managed by **reference counting with a cycle collector** instead, giving simple value
semantics suited to scripting. Typing is **optional and gradual**: annotations are inferred where
omitted and checked where present. Errors are **typed** and carried in `Result`. Concurrency is
**structured** (no detached tasks, no shared mutable aliasing across tasks). Crucially, ncScript
is **capability-safe by construction**: a script can perform *no* side effect (filesystem,
network, AI inference, config access, process/IPC) unless it **declares** the corresponding
capability in a header block, and even then the host must grant a matching token at invocation —
the ambient authority is *empty* by default. This NCIP defines the syntax, the type and error
model, the value semantics, the gradual type system, the structured-concurrency model, the typed
capability-effect system and its declaration syntax, the `.oss` file conventions, the architectural
decision to ship a **tree-walking interpreter first** (bytecode VM deferred), and a complete
**EBNF grammar**. The Rust runtime is specified separately (WS18-02) and is out of scope here.

---

## Motivation

NexaCore OS commits (plan `WS18`, `docs/01-vision.md`) to a **proprietary scripting language** that is
the *lingua franca* of the system: shell scripting, the executable form of agentic automations
(`WS16-04`), an authoring surface for config-as-code (`WS17-02`), a generation target for
`nexacore-forge` (`WS9-05`), and the in-app extensibility layer. As of 2026-06-23 none of this exists:

1. **No system scripting language.** `NexaCoreShell` performs intent dispatch and command invocation
   only; there is no way to express a loop, a conditional, a reusable function, or a typed value in
   a user-authored artifact. Every nontrivial automation must today be written as a Rust crate and
   compiled — far too heavy for the "write a 10-line script" use case.

2. **Agentic automations have no safe executable form.** `NCIP-Helper-007` defines autonomy levels
   and an Impact Dashboard, but the *thing* an agent proposes to run has no language. A language
   whose side effects are **statically declared** and **deny-by-default** is precisely what lets the
   Impact Dashboard show, before execution, exactly which capabilities a proposed automation will
   exercise.

3. **Config-as-code and forge need a shared target.** `WS17-02` (config-as-code) and `WS9-05`
   (`nexacore-forge` generation) both need one language to target. Defining it once, here, avoids two
   divergent mini-languages.

Why *derive from Rust* rather than invent something new or embed an existing language (Lua, Python,
JavaScript)? Three reasons. First, NexaCore OS is written in Rust; a Rust-shaped surface means the
runtime author, the standard-library author, and the script author share one mental model, and the
`nexacore-forge` Rust→artifact pipeline (`WS9-05`) has a near-isomorphic source language. Second, the
existing embeddable interpreters are all **ambient-authority** languages: Lua's `io`/`os`, Python's
`open`/`socket`, JS's `fetch`/`fs` are reachable by default, which is exactly the property NexaCore's
privacy-by-construction threat model (`docs/04a-threat-model.md`) forbids. Retrofitting deny-by-
default capability safety onto them is a perpetual game of sandbox-escape whack-a-mole. Third,
Rust's `Result`/`Option`/`match`/`enum` vocabulary makes **typed errors** and **exhaustive
handling** idiomatic, which raises the floor on script reliability. We keep that vocabulary and
discard the parts (borrow checker, lifetimes, monomorphized generics, `unsafe`) that make Rust hard
to write quickly and impossible to interpret cheaply.

---

## Specification

This section is the normative core. RFC 2119 keywords (MUST, SHOULD, MAY, MUST NOT, SHOULD NOT)
are binding. It is organized by the thirteen design areas of plan task `WS18-01` (cross-referenced
in `## Rationale`). The authoritative concrete syntax is the **EBNF grammar in § S13**; prose in
§§ S1–S12 is normative for semantics and overrides any informal example.

### S1. Rust-like surface syntax (`let`, `fn`, `match`, `struct`/`enum`)

> Satisfies WS18-01.1.

A **compilation unit** is a single `.oss` file: an optional capability header (§ S7), followed by
zero or more **items** (`fn`, `struct`, `enum`, `const`, `use`), followed by top-level statements.
Top-level statements form an implicit `main` body executed in source order after all items are
elaborated.

**Bindings.** `let` introduces an immutable binding; `let mut` introduces a mutable one. Re-binding
the same name (shadowing) is permitted and MUST create a new binding rather than mutate the old.

```
let x = 10;                 // immutable, type inferred (Int)
let mut total: Int = 0;     // mutable, explicit annotation
let name = "nexacore";          // String
```

Assignment (`=`, and the compound forms `+= -= *= /= %=`) is a statement, not an expression, and
its left operand MUST be a `mut` binding or a mutable place expression (field/index of a `mut`
binding). Assigning to an immutable binding is a **compile-time error** (`E_IMMUTABLE_ASSIGN`).

**Functions.** `fn name(params) -> RetType { body }`. The return type and any parameter type MAY be
omitted (§ S4). The last expression of a block is its value unless terminated by `;`; `return expr`
returns early. A function with no `-> RetType` and no value-producing tail returns `Unit` (`()`).

```
fn add(a: Int, b: Int) -> Int { a + b }
fn greet(who) { print("hello, " + who) }   // params/return inferred; returns Unit
```

**Control flow.** `if`/`else` and `match` are **expressions** (they produce a value); `while` and
`for x in iter` are statements producing `Unit`. `loop { ... }` is an infinite loop; `break expr`
yields a value from a `loop`. `break` and `continue` MAY carry an optional loop label
(`'name: loop { ... break 'name v; }`).

```
let sign = if n < 0 { -1 } else if n > 0 { 1 } else { 0 };
for item in items { process(item); }
```

**`match`.** `match` MUST be **exhaustive**: for a `match` on an `enum`, every variant MUST be
covered or a wildcard `_` arm MUST be present; a non-exhaustive `match` is a compile-time error
(`E_NONEXHAUSTIVE_MATCH`). Arms support literal patterns, variant patterns with binding, struct
patterns, tuple patterns, the wildcard `_`, an `or`-pattern (`a | b`), and a guard (`if cond`).

```
match result {
    Ok(v) if v > 0 => v,
    Ok(_)          => 0,
    Err(e)         => { log(e); -1 }
}
```

**`struct` / `enum`.** Structs are nominal product types; enums are nominal sum types whose
variants MAY be unit, tuple, or struct-shaped. Both MAY carry methods via an `impl` block.

```
struct Point { x: Int, y: Int }
enum Shape { Circle(Float), Rect { w: Float, h: Float }, Empty }

impl Point {
    fn origin() -> Point { Point { x: 0, y: 0 } }     // associated function
    fn norm2(self) -> Int { self.x * self.x + self.y * self.y }  // method
}
```

**Primitive types and literals.** `Int` (64-bit signed, two's-complement, wrapping on overflow only
under explicit `wrapping_*` ops; otherwise overflow is a runtime error `E_OVERFLOW`), `Float`
(IEEE-754 binary64), `Bool` (`true`/`false`), `String` (UTF-8, immutable), `Char` (Unicode scalar),
`Unit` (`()`). Compound built-ins: tuples `(a, b)`, lists `[T]` (growable), and maps `{K: V}`.
Comments are `//` line and `/* ... */` block (nestable). Identifiers are `[A-Za-z_][A-Za-z0-9_]*`.

**Modules.** `use path::to::item;` imports from the standard library or other declared modules.
There is no user-defined cross-file module graph in v1 (single-file compilation units); `use`
targets the stdlib namespace and host-provided modules only.

### S2. `Result` / `Option` and the typed-error model

> Satisfies WS18-01.2.

`Option<T>` and `Result<T, E>` are **built-in enums** with language support:

```
enum Option<T> { Some(T), None }
enum Result<T, E> { Ok(T), Err(E) }
```

**Typed errors.** An error value is any value; idiomatically it is a user `enum` implementing the
built-in `Error` trait (a single method `fn message(self) -> String`). Errors are **values carried
in `Result::Err`**; there are **no exceptions** and no stack unwinding visible to scripts. A script
MUST NOT be able to observe a non-local control transfer other than `return`, `break`, `continue`,
and the `?` operator.

**The `?` operator.** `expr?` where `expr: Result<T, E>` evaluates to `T` if `Ok(T)`, otherwise it
returns `Err(E)` from the enclosing function. `?` on `Option<T>` returns `None` from the enclosing
function on `None`. The enclosing function's return type MUST be `Result<_, E>` (resp. `Option<_>`)
or this is a compile-time error (`E_QUESTION_CONTEXT`). When the `Err` types differ, an
`E: From<E0>` conversion MUST exist (built-in `From` for the standard error enums; user types MAY
implement `From`), else `E_ERROR_CONVERT`.

```
fn parse_config(text: String) -> Result<Config, ConfigError> {
    let raw = json::parse(text)?;          // json::ParseError -> ConfigError via From
    let port = raw.get_int("port")?;
    Ok(Config { port })
}
```

**Standard error enums.** The stdlib defines `IoError`, `NetError`, `AiError`, `ConfigError`,
`ParseError`, and the umbrella `Error` trait. Capability denials (§ S6) surface as the typed error
`CapabilityError::Denied(Capability)` returned in `Err`, never as a panic — a script that lacks a
capability sees a *recoverable, typed* failure, not a crash.

**Aborting.** `panic(msg)` exists for unrecoverable programmer errors; it terminates the script with
a diagnostic and a non-zero status and is **not catchable** within the script. Hosts MUST treat a
`panic` as a clean, bounded termination (no host-state corruption). `panic` is reserved for invariant
violations, not for control flow.

### S3. Value semantics with reference counting + cycle collection (no borrow checker)

> Satisfies WS18-01.3.

ncScript has **no borrow checker and no lifetimes.** The memory model is:

- **Scalars** (`Int`, `Float`, `Bool`, `Char`, `Unit`) have **copy** semantics: assignment and
  argument passing copy the value.
- **Aggregates** (`String`, `[T]`, `{K:V}`, tuples, `struct`, `enum` payloads) are managed by
  **automatic reference counting (ARC)**: a binding or field holds a strong reference; assignment
  and argument passing copy the *reference* and increment the count; dropping the last reference
  runs the value's destructor and frees it deterministically.
- Observable semantics are **value semantics with structural sharing**: aggregates are **logically
  immutable through shared references**, and mutation of a `mut` binding that is shared MUST behave
  as **copy-on-write (CoW)** — i.e., a mutation never affects another binding that observed the
  prior value. Implementations MAY elide the copy when the reference count is 1. This gives scripts
  predictable, alias-free value semantics without a borrow checker.
- **Cycles** (e.g. a `struct` that transitively references itself through a `[T]`) cannot be
  reclaimed by reference counting alone. The runtime MUST therefore include a **cycle collector**
  (a bounded, deterministic-budget tracing pass over potentially-cyclic aggregates) that reclaims
  unreachable cycles. The collector is the "GC" half of "refcount/GC"; ARC handles the common,
  acyclic case with deterministic, immediate reclamation, and the collector backstops cycles. This
  NCIP fixes the *contract* (no leaks of unreachable cyclic graphs; collection runs within the
  script's resource budget; collection MUST NOT be observable as a change in value semantics); the
  algorithm is a runtime concern (WS18-02).

There is **no manual `free`, no raw pointers, no `unsafe`, and no shared mutable aliasing** exposed
to scripts. The lack of a borrow checker is the deliberate, defining simplification relative to Rust.

### S4. Optional (gradual) static typing with inference

> Satisfies WS18-01.4.

Typing is **gradual**. Every binding, parameter, and return position MAY carry an explicit type
annotation or omit it.

- **Inference.** Omitted annotations are inferred by a **local Hindley–Milner-style** unification
  pass with the following pragmatics: inference is *function-local* (a function's signature is the
  inference boundary — parameters with no annotation are inferred from call sites within the same
  unit, falling back to the `Any` type if unconstrained). Literal defaults: integer literals default
  to `Int`, float literals to `Float`.
- **The `Any` type (gradual boundary).** A value whose static type cannot be (or is not) determined
  has type `Any`. Operations on `Any` are **dynamically checked at runtime**; a type mismatch
  surfaces as the typed runtime error `E_TYPE` (in `Result::Err` for fallible ops, or a `panic` for
  internal invariants). `Any` is the seam that lets a fully-untyped script and a fully-annotated
  script interoperate.
- **Soundness boundary.** Where both sides of an operation are statically typed, the checker is
  **sound**: a program that type-checks MUST NOT exhibit a static type error at runtime for that
  operation. Where `Any` is involved, checks are deferred to runtime. This is standard *gradual
  typing* (Siek–Taha): statically-typed regions get static guarantees; dynamic regions get runtime
  guarantees; the boundary inserts runtime casts.
- **Generics.** Functions and types MAY be generic (`fn first<T>(xs: [T]) -> Option<T>`). Generics
  are **type-erased** at runtime (uniform representation), not monomorphized — consistent with an
  interpreter and with ARC's uniform aggregate representation.
- **Type-checking is advisory-then-binding.** The runtime MUST run the static checker before
  execution and MUST refuse to run a unit containing a *static* type error in a fully-typed region
  (`E_TYPE` at load time). Inference never *requires* annotations; it only *uses* them.

### S5. Structured concurrency

> Satisfies WS18-01.5.

Concurrency is **structured**: every concurrent task has a parent scope, and a scope MUST NOT
complete until all tasks it spawned have completed (or been cancelled). There are **no detached
tasks** and no global thread pool reachable by scripts.

- **`spawn`.** Inside a `scope { ... }` block, `spawn expr` starts `expr` (a zero-arg closure or
  call) as a concurrent task and returns a `Task<T>` handle. The `scope` block MUST join all its
  tasks before returning; a task still running when the `scope` body finishes is **awaited** (the
  scope blocks) — it is never silently abandoned.
- **`await`.** `task.await` (or `await task`) yields the task's `Result<T, E>`; awaiting is the only
  way to observe a task's value or error. An unawaited task whose scope ends still runs to
  completion and its result is dropped.
- **Cancellation.** If any task in a `scope` returns `Err` (or panics), the scope MAY request
  cancellation of its siblings (cooperative; cancellation is observed at the next `await` or
  `yield` point) and then propagates the first error out of the `scope` as the scope's `Result`.
  This is "abort-on-first-error" structured concurrency. A `scope.all()` form awaits all tasks and
  collects their results without early cancellation.
- **Data sharing.** Tasks MAY only **move** values into a `spawn`ed closure or share **immutable**
  aggregates (ARC shared references are immutable through sharing per § S3); there is **no shared
  mutable state** between tasks, so there are no data races by construction. Inter-task
  communication uses stdlib **channels** (`channel::<T>()` → `(Sender<T>, Receiver<T>)`), which move
  values between tasks.
- **No ambient time/sleep.** `sleep` and timers are capability-mediated host effects, not free
  functions (a script that needs to wait MUST hold a `Time` capability; see § S6).

```
scope {
    let a = spawn fetch("https://a.example/x");   // requires `net` capability
    let b = spawn fetch("https://b.example/y");
    let (ra, rb) = (a.await?, b.await?);           // first Err aborts the scope
    combine(ra, rb)
}
```

### S6. Typed capability-effect model (deny-by-default)

> Satisfies WS18-01.6.

ncScript is **capability-safe**. The ambient authority of a script is **empty**: with no declared
capabilities a script is a **pure** computation — it can compute, allocate, and return a value, but
it can perform **no observable side effect** on the host or the outside world.

**Effects are typed.** Every function in the standard library and every host binding is tagged with
the **set of capabilities** it requires (its *effect set*). The type system tracks effects: a
function's inferred/declared effect set is the union of the effect sets of everything it calls. A
call to a function whose effect set is not a subset of the **granted capability set** of the
compilation unit is a **compile-time error** (`E_CAP_UNDECLARED`) — the script does not even load.
This is the typed-effect discipline: *capabilities are part of the type of the program.*

**The capability lattice.** v1 defines these capability classes (extensible by future NCIPs):

| Capability        | Grants                                                           | Effect tag |
|-------------------|------------------------------------------------------------------|------------|
| `fs.read(path)`   | read files/dirs under `path` (path-scoped)                       | `Fs`       |
| `fs.write(path)`  | create/modify/delete under `path` (path-scoped)                  | `Fs`       |
| `net.connect(host)` | open outbound connections to `host`/port set (host-scoped)     | `Net`      |
| `net.listen(port)`| bind/accept on `port` (port-scoped)                              | `Net`      |
| `ai.invoke`       | call AI Runtime syscalls (`ai_invoke`/`ai_embed`/`ai_classify`)  | `Ai`       |
| `config.read(ns)` | read config keys under namespace `ns`                            | `Config`   |
| `config.write(ns)`| write config keys under namespace `ns`                           | `Config`   |
| `proc.spawn`      | spawn host processes / IPC                                       | `Proc`     |
| `time`            | read the clock, `sleep`, set timers                              | `Time`     |
| `rand`            | draw from the host CSPRNG                                        | `Rand`     |

Capabilities are **attenuable**: a granted `fs.read("/home/u/docs")` does **not** imply
`fs.read("/")`. The *declaration* (§ S7) names the capability and its scope; the **host** decides at
invocation whether to grant a token of equal-or-narrower scope. Deny-by-default means: undeclared ⇒
won't compile; declared-but-not-granted ⇒ the corresponding stdlib call returns
`Err(CapabilityError::Denied(..))` at runtime (the script loads and runs, but the effect fails
safely and typedly).

**No re-delegation beyond declaration.** A script MUST NOT be able to fabricate, widen, or forward a
capability it was not granted. Capability tokens are opaque host objects; scripts hold only the
*right to attempt* an effect, mediated by the runtime (WS18-02 enforces the token check at the
syscall boundary; this NCIP fixes that the *language* surface offers no way around it).

### S7. Capability-declaration syntax

> Satisfies WS18-01.7.

A `.oss` file MAY begin with a **capability header**: a `#![capabilities(...)]` attribute that is
the *first* non-comment construct in the file. It declares the maximal effect set the script may
exercise. Absent the header, the script's granted set is **empty** (pure).

```
#![capabilities(
    fs.read("/etc/nexacore"),
    fs.write("/var/nexacore/out"),
    net.connect("api.nexacore.example:443"),
    ai.invoke,
    config.read("ui.theme"),
)]
```

- Each entry is a **capability literal**: a dotted capability name, optionally followed by a
  parenthesized **scope argument** (a string literal path/host/namespace, or a port integer). Names
  and scope forms are exactly those in the § S6 table.
- The header is **declarative and binding**: the static effect checker (§ S6) verifies that the
  union of effect sets actually used by the program is a **subset** of the declared set. Declaring a
  capability the program never uses is a **warning** (`W_CAP_UNUSED`), not an error (so a script may
  conservatively over-declare for forward compatibility, but is nudged toward least privilege).
- The header is **machine-readable**: tooling (the Impact Dashboard of `NCIP-Helper-007`, `nexacore-pkg`
  manifests, `nexacore-market` review) MUST be able to extract the declared capability set by parsing
  only the header, **without executing** the script. This is the mechanism by which an agentic
  automation's effects are shown to the user *before* it runs.
- A host MAY grant a **narrower** scope than declared (attenuation) but MUST NOT grant a wider one;
  a host MUST NOT grant any capability absent from the header. The intersection of *declared* and
  *granted* is the script's actual authority.

```
// A pure script (no header): cannot touch FS, net, AI, config, time, or rand.
fn fib(n: Int) -> Int { if n < 2 { n } else { fib(n-1) + fib(n-2) } }
print(fib(20));   // ERROR: `print` requires no capability? -> see note
```

> Note: `print` writes to the script's **standard output stream**, which is part of the host-
> provided I/O context and is **not** a privileged capability (it is the script's own stdout, not
> arbitrary FS/console access). Hosts MAY redirect or suppress it. All *other* effects require a
> declared capability.

### S8. Architectural decision: tree-walking interpreter first (bytecode VM deferred)

> Satisfies WS18-01.8.

**Decision (binding for v1):** the reference runtime (WS18-02) MUST be a **tree-walking
interpreter** over the AST. A bytecode compiler + VM is **explicitly deferred** to a future NCIP and
MUST NOT be a prerequisite for v1.

**Rationale:**

1. **Correctness and auditability first.** A tree-walker maps 1:1 onto this specification's
   operational semantics, so the runtime is far easier to make *obviously correct* and to audit
   against the capability and value-semantics rules. For a *security-critical, capability-gated*
   language, an auditable runtime beats a fast one at v1.
2. **`no_std` and small TCB.** WS18-02 requires the runtime to be `no_std`-capable with a small
   trust base. A tree-walker needs no compiler backend, no instruction encoder/decoder, and no
   separate verifier — strictly less code in the TCB.
3. **Deterministic resource accounting.** Per-AST-node "fuel" accounting (for the CPU/instruction
   limit of WS18-02.6) is straightforward in a tree-walker; a bytecode VM would need an equivalent
   per-op fuel scheme with more moving parts.
4. **Workload fit.** ncScript's primary workloads — shell snippets, config-as-code, agentic
   automations, app glue — are short-lived and I/O-bound (the cost is in the gated host effects, not
   in the interpreter loop). The tree-walker's per-node overhead is dominated by syscall/effect
   latency, so the bytecode VM's throughput advantage is largely irrelevant at v1.

**Migration seam.** The grammar (§ S13) and AST are defined independently of the execution strategy.
A later NCIP MAY introduce a bytecode VM as an *alternative backend* behind the same parser and the
same semantics; this NCIP's grammar and semantics MUST remain the source of truth so the two backends
stay observationally equivalent.

### S9. The `.oss` extension and file conventions

> Satisfies WS18-01.9.

- **Extension.** ncScript source files MUST use the extension **`.oss`** (NexaCore System Script).
  Tooling (LSP, formatter, syntax highlighting per WS18-04; `nexacore-pkg`/`nexacore-market` manifests) keys
  off `.oss`.
- **Encoding.** A `.oss` file MUST be valid **UTF-8**. A leading UTF-8 BOM, if present, MUST be
  ignored. Line endings MAY be `LF` or `CRLF`; the formatter normalizes to `LF`.
- **Shebang.** The first line MAY be a shebang (`#!/usr/bin/env ncscript` or
  `#!nexacore script`) for direct execution; it MUST be ignored by the parser. The shebang, if present,
  precedes the `#![capabilities(...)]` header.
- **Header order.** After an optional shebang, the **first** non-comment, non-blank construct, if it
  is an attribute, MUST be the `#![capabilities(...)]` header (§ S7). No other file-level `#![...]`
  attributes are defined in v1.
- **Entry point.** A file MAY define `fn main() -> Result<(), Error>` as an explicit entry point; if
  absent, the top-level statements form the implicit `main` (§ S1). If `fn main` is present, top-
  level statements other than items are a compile-time error (`E_MAIN_AND_TOPLEVEL`).
- **Style conventions (non-normative, enforced by the formatter, WS18-04.3):** 4-space indent;
  `snake_case` for functions/bindings/modules; `UpperCamelCase` for types/enums/variants;
  `SCREAMING_SNAKE_CASE` for `const`; trailing commas in multi-line constructs; one item per line.

### S10. Error conditions (normative catalog)

The following diagnostics are normative. `E_*` are errors (the unit MUST NOT run); `W_*` are
warnings (the unit runs).

| Code                  | Phase     | Meaning                                                        |
|-----------------------|-----------|----------------------------------------------------------------|
| `E_PARSE`             | parse     | input does not match the § S13 grammar                         |
| `E_IMMUTABLE_ASSIGN`  | check     | assignment to a non-`mut` binding/place                        |
| `E_NONEXHAUSTIVE_MATCH` | check   | `match` does not cover all variants and has no `_`             |
| `E_QUESTION_CONTEXT`  | check     | `?` used in a fn whose return type is not `Result`/`Option`    |
| `E_ERROR_CONVERT`     | check     | `?` error type has no `From` conversion to the fn's error type |
| `E_TYPE`              | check/run | static type mismatch (check) or dynamic `Any` mismatch (run)   |
| `E_CAP_UNDECLARED`    | check     | a used effect's capability is not in the header                |
| `E_MAIN_AND_TOPLEVEL` | check     | both `fn main` and top-level statements present                |
| `E_OVERFLOW`          | run       | checked integer overflow                                       |
| `W_CAP_UNUSED`        | check     | a declared capability is never exercised                       |

`CapabilityError::Denied(cap)` and `panic` are **runtime** outcomes, not load diagnostics (§§ S2,
S6).

### S11. Versioning

This NCIP specifies **ncScript v1**. The language version is independent of the NexaCore OS release.
The grammar (§ S13) is the wire-stable definition; additive changes (new stdlib modules, new
capability classes, new optional syntax that does not reject previously-valid programs) MAY ship in
minor revisions documented by follow-on NCIPs. Any change that rejects a previously-valid v1 program,
or that alters the value/effect semantics of a valid v1 program, MUST be a new major version in a
superseding NCIP.

### S12. Worked example (informative)

```
#![capabilities( fs.read("/etc/nexacore/hosts"), ai.invoke )]

use std::fs;
use std::ai;

struct Host { name: String, addr: String }

enum ScanError { Io(IoError), Empty }
impl Error for ScanError { fn message(self) -> String { "scan failed" } }

fn load_hosts(path: String) -> Result<[Host], ScanError> {
    let text = fs::read_to_string(path).map_err(ScanError::Io)?;   // needs fs.read cap
    let mut out: [Host] = [];
    for line in text.lines() {
        match line.split_once(" ") {
            Some((addr, name)) => out.push(Host { name, addr }),
            None => continue,
        }
    }
    if out.len() == 0 { Err(ScanError::Empty) } else { Ok(out) }
}

fn main() -> Result<(), Error> {
    let hosts = load_hosts("/etc/nexacore/hosts")?;
    let summary = ai::invoke("summarize these hosts", hosts.len())?;  // needs ai.invoke cap
    print(summary);
    Ok(())
}
```

### S13. Formal grammar (EBNF)

> Satisfies WS18-01.10.

The grammar below is the **normative concrete syntax** of ncScript v1. Notation: `=` defines a
rule; `|` alternation; `[...]` optional (0 or 1); `{...}` repetition (0 or more); `(...)` grouping;
terminals are in `"quotes"`; `?...?` denotes a lexical predicate described in prose. Whitespace and
comments (`// ...`, `/* ... */`, nestable) MAY appear between any two tokens and are not shown.

```ebnf
(* ---- Compilation unit ---- *)
compilation_unit = [ shebang ] , [ capability_header ] , { item } , { statement } ;
shebang          = "#!" , ?characters up to end of first line? ;

(* ---- Capability header ---- *)
capability_header = "#![" , "capabilities" , "(" ,
                        [ cap_decl , { "," , cap_decl } , [ "," ] ] ,
                    ")" , "]" ;
cap_decl          = cap_name , [ "(" , cap_scope , ")" ] ;
cap_name          = identifier , { "." , identifier } ;
cap_scope         = string_lit | int_lit ;

(* ---- Items ---- *)
item        = fn_item | struct_item | enum_item | const_item | impl_item | use_item ;

use_item    = "use" , path , ";" ;
path        = identifier , { "::" , identifier } ;

const_item  = "const" , identifier , ":" , type , "=" , expr , ";" ;

fn_item     = "fn" , identifier , [ generics ] , "(" , [ param_list ] , ")" ,
              [ "->" , type ] , block ;
param_list  = param , { "," , param } , [ "," ] ;
param       = ( "self" ) | ( identifier , [ ":" , type ] ) ;
generics    = "<" , identifier , { "," , identifier } , ">" ;

struct_item = "struct" , identifier , [ generics ] ,
              ( "{" , [ field_def , { "," , field_def } , [ "," ] ] , "}" | ";" ) ;
field_def   = identifier , ":" , type ;

enum_item   = "enum" , identifier , [ generics ] ,
              "{" , [ variant , { "," , variant } , [ "," ] ] , "}" ;
variant     = identifier ,
              [ "(" , type , { "," , type } , ")"
              | "{" , field_def , { "," , field_def } , "}" ] ;

impl_item   = "impl" , [ identifier , "for" ] , type , "{" , { fn_item } , "}" ;

(* ---- Types ---- *)
type        = type_atom , { "?" } ;            (* trailing "?" is sugar handled by stdlib types *)
type_atom   = path , [ "<" , type , { "," , type } , ">" ]   (* named / generic, e.g. Result<T,E> *)
            | "[" , type , "]"                                (* list *)
            | "{" , type , ":" , type , "}"                   (* map *)
            | "(" , [ type , { "," , type } ] , ")" ;         (* tuple / Unit "()" *)

(* ---- Statements ---- *)
block       = "{" , { statement } , [ expr ] , "}" ;
statement   = let_stmt
            | expr_stmt
            | assign_stmt
            | while_stmt
            | for_stmt
            | item ;
let_stmt    = "let" , [ "mut" ] , pattern , [ ":" , type ] , [ "=" , expr ] , ";" ;
expr_stmt   = expr , ";" ;
assign_stmt = place , assign_op , expr , ";" ;
assign_op   = "=" | "+=" | "-=" | "*=" | "/=" | "%=" ;
place       = identifier , { "." , identifier | "[" , expr , "]" } ;
while_stmt  = "while" , expr , block ;
for_stmt    = "for" , pattern , "in" , expr , block ;

(* ---- Expressions (precedence climbing; lowest to highest) ---- *)
expr        = or_expr ;
or_expr     = and_expr , { "||" , and_expr } ;
and_expr    = cmp_expr , { "&&" , cmp_expr } ;
cmp_expr    = add_expr , [ ( "==" | "!=" | "<" | "<=" | ">" | ">=" ) , add_expr ] ;
add_expr    = mul_expr , { ( "+" | "-" ) , mul_expr } ;
mul_expr    = unary_expr , { ( "*" | "/" | "%" ) , unary_expr } ;
unary_expr  = ( "-" | "!" ) , unary_expr | postfix_expr ;
postfix_expr= primary_expr ,
              { "." , identifier                       (* field / method receiver *)
              | "." , identifier , call_args            (* method call *)
              | call_args                               (* function call *)
              | "[" , expr , "]"                        (* index *)
              | "?"                                     (* try operator *)
              | ".await"                                (* await a Task *)
              } ;
call_args   = "(" , [ expr , { "," , expr } , [ "," ] ] , ")" ;

primary_expr= literal
            | path                                      (* variable / enum variant / fn ref *)
            | struct_lit
            | list_lit
            | map_lit
            | tuple_or_group
            | if_expr
            | match_expr
            | loop_expr
            | scope_expr
            | spawn_expr
            | block ;

struct_lit  = path , "{" , [ field_init , { "," , field_init } , [ "," ] ] , "}" ;
field_init  = identifier , [ ":" , expr ] ;            (* shorthand allowed: { name } *)
list_lit    = "[" , [ expr , { "," , expr } , [ "," ] ] , "]" ;
map_lit     = "{" , [ map_entry , { "," , map_entry } , [ "," ] ] , "}" ;
map_entry   = expr , ":" , expr ;
tuple_or_group = "(" , [ expr , { "," , expr } , [ "," ] ] , ")" ;

if_expr     = "if" , expr , block , [ "else" , ( if_expr | block ) ] ;
match_expr  = "match" , expr , "{" , match_arm , { "," , match_arm } , [ "," ] , "}" ;
match_arm   = pattern , [ "if" , expr ] , "=>" , ( expr | block ) ;
loop_expr   = [ label , ":" ] , "loop" , block
            | [ label , ":" ] , "while" , expr , block
            | [ label , ":" ] , "for" , pattern , "in" , expr , block ;
label       = "'" , identifier ;

scope_expr  = "scope" , block ;
spawn_expr  = "spawn" , expr ;

(* control-flow expressions usable in statement position *)
flow_expr   = "return" , [ expr ]
            | "break" , [ label ] , [ expr ]
            | "continue" , [ label ] ;

(* ---- Patterns ---- *)
pattern     = "_" 
            | literal
            | identifier                                (* binding *)
            | path , [ "(" , pattern , { "," , pattern } , ")" ]   (* variant / tuple-struct *)
            | path , "{" , field_pat , { "," , field_pat } , [ "," ] , "}"  (* struct pattern *)
            | "(" , pattern , { "," , pattern } , ")"   (* tuple pattern *)
            | pattern , "|" , pattern ;                 (* or-pattern *)
field_pat   = identifier , [ ":" , pattern ] ;

(* ---- Lexical ---- *)
literal     = int_lit | float_lit | string_lit | char_lit | bool_lit | unit_lit ;
int_lit     = digit , { digit | "_" } ;
float_lit   = digit , { digit | "_" } , "." , digit , { digit | "_" } ;
bool_lit    = "true" | "false" ;
unit_lit    = "(" , ")" ;
char_lit    = "'" , ( ?any char except ' or \? | escape ) , "'" ;
string_lit  = '"' , { ?any char except " or \? | escape } , '"' ;
escape      = "\" , ( "n" | "t" | "r" | "\" | '"' | "'" | "0" | "u" , "{" , hex , { hex } , "}" ) ;
identifier  = ( letter | "_" ) , { letter | digit | "_" } ;   (* not a keyword *)
letter      = "A".."Z" | "a".."z" ;
digit       = "0".."9" ;
hex         = digit | "a".."f" | "A".."F" ;

(* Reserved keywords (not usable as identifiers): *)
(* let mut fn return if else match while for loop in break continue
   struct enum impl const use self true false scope spawn await as where *)
```

`return`, `break`, and `continue` (`flow_expr`) are accepted wherever an `expr` is grammatically
required in statement/tail position; their typing is `Never` (they diverge), so they unify with any
expected type. The `?` and `.await` postfix forms are defined in `postfix_expr`.

---

## Rationale

**Why a Rust derivation rather than a new or embedded language** — argued in full in `## Motivation`:
shared mental model with the Rust codebase and the `nexacore-forge` source language; existing embeddable
interpreters are ambient-authority by default (the exact property NexaCore forbids); Rust's
`Result`/`Option`/`match` vocabulary makes typed errors idiomatic.

**Why drop the borrow checker (S3).** The borrow checker's value is compile-time prevention of
data races and use-after-free in *systems* code with manual memory management. A *scripting* language
with automatic memory management and no shared mutable aliasing across tasks (S5) gets both
guarantees for free, at the cost of the borrow checker's steep learning curve and its
incompatibility with quick, exploratory scripting. **Alternative considered:** keep a simplified
affine/move checker. **Rejected** because it reintroduces the very friction (move errors, `clone()`
spam) that makes Rust slow to *write*, and our value-semantics-with-CoW model already gives
predictable aliasing without it.

**Why ARC + cycle collector rather than pure tracing GC or pure refcounting (S3).** Pure tracing GC
gives non-deterministic pauses and a larger runtime; pure refcounting leaks cycles. ARC gives
deterministic, immediate reclamation for the common acyclic case (which dominates scripts) and the
cycle collector backstops the rare cyclic case within the resource budget. **Alternative:** a
generational tracing GC (as in most scripting VMs). **Rejected** for v1 because deterministic
reclamation composes better with the deterministic resource limits WS18-02 must enforce, and because
ARC keeps the runtime small and `no_std`-friendly.

**Why gradual (optional) typing rather than fully static or fully dynamic (S4).** Fully static
typing slows down throwaway scripts and demands annotations a one-liner shouldn't need; fully
dynamic typing forfeits the reliability that typed errors and exhaustive `match` are meant to
deliver. Gradual typing (Siek–Taha) is the established middle: annotate where it pays, infer or defer
elsewhere. **Alternative:** mandatory inference with no `Any` (full HM, like ML). **Rejected**
because interop with host-provided dynamic values and config blobs needs a dynamic seam.

**Why structured concurrency rather than free `spawn`/futures (S5).** Detached tasks are the source
of leaks, lost errors, and lifetime bugs; they also make capability accounting harder (a detached
task can outlive the scope that justified its capabilities). Structured concurrency ties task
lifetime to lexical scope, makes error propagation total, and keeps the capability set of a task a
subset of its parent's. **Alternative:** an `async`/`await` future ecosystem like Rust's. **Rejected**
as far too heavy for a scripting language and hostile to the simple tree-walking runtime.

**Why typed capabilities as part of the type system rather than a runtime sandbox only (S6/S7).**
A pure runtime sandbox tells you about a violation *after* it is attempted; a typed effect system
tells you the *complete* capability footprint of a script **before** it runs, by parsing alone. That
is exactly what the `NCIP-Helper-007` Impact Dashboard, `nexacore-pkg`, and `nexacore-market` need to show a
user what an automation will do *before* granting it. We keep the runtime token check too
(defense-in-depth, enforced in WS18-02), but the language-level effect typing is what makes
capabilities *auditable*. **Alternative:** capabilities passed as ordinary function arguments
(object-capability style, no header). **Rejected** because it makes the footprint non-extractable
without whole-program analysis and offers no single declaration point for the user to review.

**Why tree-walking first (S8).** Auditability, small `no_std` TCB, easy deterministic fuel
accounting, and a workload that is I/O-bound rather than interpreter-bound. The bytecode VM is
deferred, not foreclosed; the grammar/AST are the stable seam.

**Why `.oss` (S9).** A distinct extension lets all tooling key off the language unambiguously and
avoids collision with Rust `.rs` (which the `nexacore-forge` pipeline also handles).

**What we are explicitly NOT doing in v1:** no macros/metaprogramming; no `unsafe`/FFI from script
(host bindings are the only escape hatch and they are capability-gated); no multi-file user module
graph (single-file units; `use` targets stdlib/host only); no operator overloading beyond the
built-in traits; no bytecode VM; no inheritance (composition + traits only).

---

## Backwards Compatibility

N/A — first introduction. ncScript and the `.oss` format do not exist prior to this NCIP; there is
no prior behavior, no deployed scripts, and no existing crate to migrate. The Rust runtime that will
consume this specification is a *new* crate (`nexacore-script`, WS18-02) and is out of scope here. This
NCIP establishes the v1 baseline that future ncScript NCIPs (§ S11) must preserve or supersede.

---

## Test Cases

Because no parser exists yet (the runtime is WS18-02), the v1 conformance corpus for *this* NCIP is a
set of example `.oss` programs that MUST parse cleanly under the § S13 grammar and exercise the
specified features. They live alongside this NCIP:

- `ncips/examples/ncscript/hello.oss` — minimal program; no capability header (pure); exercises
  `fn main`, `print`, `string_lit`. Demonstrates that a capability-free script is valid and runs
  with empty ambient authority (§ S6, § S7).
- `ncips/examples/ncscript/match_result.oss` — a `fn` returning `Result<Int, ParseError>`, a
  `match` on `Result` with a guard and an or-pattern, and the `?` operator. Exercises § S1 (`match`,
  exhaustiveness), § S2 (`Result`/`?`/typed errors), § S4 (inference).
- `ncips/examples/ncscript/capability_fs_ai.oss` — a `#![capabilities(fs.read(..), ai.invoke)]`
  header gating a script that reads a file and calls an AI syscall, with a structured-concurrency
  `scope`/`spawn`/`await`. Exercises § S5, § S6, § S7, § S12, and shows a `CapabilityError::Denied`
  path in a comment.

Each example has been **manually verified** to conform to the § S13 grammar (no automated parser
exists at this NCIP's stage). When the WS18-02 parser lands, these files become the seed of its
parser-acceptance test suite, and a future revision of this section SHOULD link that suite.

A representative negative vector (MUST be rejected at load): a script that calls `fs::read_to_string`
without an `fs.read(..)` entry in its header MUST fail with `E_CAP_UNDECLARED` (§ S6, § S10).

---

## Reference Implementation

N/A — this is a design/specification NCIP. The reference runtime (lexer, parser, tree-walking
interpreter, ARC + cycle collector, deterministic resource limits, capability-token enforcement) is
specified and built under plan task **WS18-02** as the `nexacore-script` crate, and is explicitly out of
scope for this NCIP. The example `.oss` programs under `ncips/examples/ncscript/` serve as the
concrete-syntax conformance seeds until that crate exists.

---

## Security Considerations

ncScript's entire reason to exist as a *bespoke* language rather than an embedded Lua/Python is
security, so this section is central.

- **Threat model (cite `docs/04a-threat-model.md`).** The primary adversary is a **malicious or
  buggy script** (e.g. an agentic automation proposed by a compromised or hallucinating agent, a
  third-party app extension, or a `nexacore-market` package). The defining mitigation is
  **deny-by-default capability safety** (§ S6, § S7): a script with no capability header is a pure
  computation that cannot touch the filesystem, network, AI runtime, config store, processes, clock,
  or RNG. This directly bounds the blast radius of a hostile script to *the values it computes*,
  not the host's state or the outside world.
- **Effects are auditable before execution.** Because the capability footprint is extractable by
  parsing the header alone (§ S7), the `NCIP-Helper-007` Impact Dashboard can show the user the
  *complete* set of effects a proposed automation may perform **before** they approve it — there is
  no hidden ambient authority to surprise them. This is a structural anti-confused-deputy property.
- **Defense in depth.** Language-level effect typing (load-time `E_CAP_UNDECLARED`) is backed by a
  **runtime token check** at the syscall boundary (WS18-02): even a runtime that mis-typed an effect
  cannot perform it without a host-granted token, and a declared-but-not-granted capability fails
  *typed and recoverable* (`CapabilityError::Denied`), never as a crash that could corrupt host
  state.
- **Resource exhaustion / DoS.** The language is designed so the runtime (WS18-02) can impose
  deterministic CPU/instruction, memory, and time budgets and abort cleanly. The tree-walking
  decision (§ S8) makes per-node fuel accounting tractable. `panic` and budget-abort are specified
  (§ S2) to be **clean, bounded terminations** that MUST NOT corrupt host state.
- **Memory safety.** No raw pointers, no `unsafe`, no manual `free`, no shared mutable aliasing
  across tasks (§ S3, § S5) ⇒ no use-after-free, no data races *by construction* in script-level
  code. The cycle collector prevents unbounded leaks of cyclic graphs that could otherwise be a slow
  DoS.
- **Capability non-amplification.** Scripts cannot fabricate, widen, or forward capabilities (§ S6);
  hosts may only *attenuate* (grant equal-or-narrower scope), never amplify, and never grant an
  undeclared capability. This prevents privilege escalation through delegation.
- **Residual risks deferred to WS18-02.** Side channels (timing/cache) from script execution, the
  exact cycle-collector budget, and the integer-overflow trapping cost are runtime concerns; this
  NCIP fixes the *contracts* they must satisfy but their enforcement is verified in WS18-02's tests.

---

## Privacy Considerations

- **Personal-data flows are capability-mediated.** A script can read user files, hit the network, or
  invoke AI only with an explicitly declared and host-granted capability (§ S6, § S7). There is no
  ambient path by which a script can exfiltrate personal data: with no `net.connect`/`fs.read`/
  `ai.invoke` capability, those flows are *unrepresentable*. This is data-minimization by
  construction.
- **Purpose limitation via scoped capabilities.** Capabilities are path/host/namespace-scoped and
  attenuable (`fs.read("/home/u/docs")` does not imply `fs.read("/")`), so a script's data reach is
  bounded to exactly the scope the user granted. This supports GDPR purpose-limitation and
  data-minimization principles at the language level.
- **Auditable consent.** The machine-readable capability header (§ S7) lets the user see, before
  granting, precisely which personal-data surfaces a script will touch — informed consent is built
  into the model, not bolted on.
- **Metadata.** ncScript itself introduces no new network protocol and no new metadata exposure;
  any network/timing/size metadata a script produces is a consequence of its *granted* `net`
  capability and is governed by the network stack's privacy properties (`NCIP`s for the net layer),
  not by the language. The language's contribution is to make those flows *declared and bounded*.
- **No telemetry.** This specification defines no implicit telemetry, beaconing, or phone-home
  behavior; a conforming script performs only the effects its capabilities permit.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
