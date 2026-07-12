# 16 — Userland: divergences from GNU/POSIX (WS8-10.19)

> **Scope.** This document records, per NexaCore OS design decision (WS8-10.19),
> every intentional divergence of the NexaCore userland (`nexacore-coreutils`
> and the `nexacore-shell` grammar) from GNU coreutils / POSIX behaviour. It
> tracks the **host-implemented surface** as of 2026-07-12 (WS8-10 subtasks
> `.1`–`.15`, `.17`, `.18`); entries are added as the remaining subtasks land.
>
> Two divergence classes recur and are called out explicitly below:
> **(C) capability model** — permissions/identity are capability tokens, not
> Unix uid/gid/rwx bits; **(H) host-logic phase** — the pure `no_std` logic core
> is implemented and injected effects (clock, VFS, process table) sit behind
> seams, so some ambient-state or kernel-backed behaviours are deliberately out
> of scope until the corresponding kernel service is wired.

## 1. Permissions & identity (capability model) — `chmod`, `chown`, `id`, `whoami`, `stat`, `ls -l`

- **(C) `chmod` / `chown` operate on capability tokens, not octal/`ugo±rwx` bits.**
  `chmod` grants/revokes *named capability tokens* on a path; `chown` reassigns
  the owning *principal*. There is no `0755`/`u+x` syntax and no
  user/group/other triad. (`nexacore-coreutils::perm`.)
- **(C) `id` / `whoami` report a capability principal + role set**, not numeric
  `uid`/`gid`. There is no `/etc/passwd`; identity comes from an injected
  `IdentitySource`. (`nexacore-coreutils::identity`.)
- **(C) `stat` and `ls -l` render permissions as capability tokens**
  (e.g. `rwx (read, write, …)` over the abstract `Capabilities`), not a
  `-rwxr-xr-x` mode string. Owner is a principal id (`ROOT_OWNER = 0` default),
  not a username. (`nexacore-coreutils::{stat, ls}`.)

## 2. Text utilities

- **`grep` is fixed-string by default; regex is not built in.** Regex is routed
  through the same library-gated `Matcher` seam used by the NexaCoreText editor
  search (`nexacore-text`); no regex engine is vendored (the workspace has no
  vetted `no_std` regex crate and the crate is dependency-free by charter).
  Flags implemented: `-i`, `-v`, `-n`, `-c`, `-w`.
- **`tail -f` (follow) is not implemented.** It requires a live side-effecting
  event loop against the kernel VFS **(H)**; the pure synchronous core provides
  `-n`/`-c` only.
- **`sed`-lite** implements `[ADDR]s/pat/rep/[g]` literal substitution
  (custom/escaped delimiter, numeric line addressing, multi-command pipeline).
  Regular-expression patterns, `y///`, hold/pattern-space commands, and
  `BEGIN`/`END`-style constructs are out of scope.
- **`awk`-lite** implements `{print …}` over `$0`/`$N`/`NR`/`NF`/string literals
  with `-F` field separator and space `OFS`. Patterns, `BEGIN`/`END` blocks,
  arithmetic/associative arrays, and user functions are out of scope.
- **`wc`** uses a fixed output field order (`lines words chars/bytes`); GNU's
  exact column widths are not reproduced.
- **`sort`** numeric mode (`-n`) parses an `i64` key and compares integers —
  there is no floating-point or locale-aware collation (no `float_arithmetic`
  by workspace policy).

## 3. Space & filesystem — `du`, `df`, `mount`

- **`-h` human-readable sizes use integer 1024-scaling** (e.g. `1.5K`, `15M`)
  computed without floating point; rounding differs from GNU's float formatting.
- **`df` `Use%` is `ceil(used*100/total)` via integer `div_euclid`.** No
  floating point, so the percentage may differ by one unit from GNU at
  boundaries.
- **(H) `mount` / `umount` are a value model, not syscalls.** `MountTable`
  tracks mounts and validates (`AlreadyMounted`/`NotMounted`/`InvalidTarget`)
  but performs no real VFS mount; the kernel mount path is wired later.
- **`df` reads an injected `FsUsageSource`**, not a live `statfs`; values come
  from the mounted-filesystem model, not the running kernel **(H)**.

## 4. Processes — `ps`, `top`, `kill`, `jobs`

- **(H) The process table is an injected `ProcessSource`**, mirroring
  `nexacore-monitor`'s shape without depending on it; `ps`/`top` render that
  snapshot. Live per-tick kernel telemetry is wired via WS12-04 at deploy time.
- **CPU usage is expressed in integer permille**, not floating-point percent.
- **(C) `kill` is capability-gated before any effect.** A `KillCapability`
  check runs *before* the `SignalController` is invoked; a denied kill returns
  `Denied` and the controller is never called. Signals parse by name/number
  (`-9`, `TERM`, `SIGKILL`), but delivery is capability-mediated, not a raw
  `kill(2)`.
- **`jobs` here is the host-testable formatting half only.** The authoritative
  job table lives in the shell (WS8-10.16); `nexacore-coreutils::jobs` formats a
  supplied `JobTable`.

## 5. Info — `uname`, `date`, `uptime`, `man`

- **(H) `date`, `uname`, `uptime` take injected values/seams** (`Clock`,
  `SystemInfoSource`, uptime value); there is no ambient system clock in the
  pure core (`Date::now` is unavailable by design).
- **`date` uses an integer-only civil (UTC) calendar** (`div_euclid`/
  `rem_euclid`); only a documented `strftime` subset is supported, no locale or
  timezone database.
- **(H) `man` looks pages up through an injected `ManSource`** and fails closed
  when a page is absent; there is no filesystem `man`-path search or troff
  rendering.

## 6. Shell grammar (`nexacore-shell`)

- **(H) Redirections `>`/`>>`/`<`/`2>` are applied through the injected
  `FsQuery` I/O seam**, not real file descriptors. Ordering: redirections apply
  in listed order and the **last redirection per stream wins** (earlier
  same-stream targets are still created/truncated but receive no bytes) —
  matching a POSIX shell's observable end-state. A redirected command's stdout
  does not propagate down the pipeline. Unopenable target → non-zero exit,
  fail-closed, no panic.
- **`$()` command substitution has no IFS word-splitting.** An unquoted
  substitution result splices as a **single word**; trailing newlines are
  stripped (POSIX), interior newlines preserved. Single quotes keep `$(…)`
  literal (POSIX); double quotes execute it. A `MAX_SUBST_DEPTH = 64` guard
  bounds nesting. Env-var assignments inside a substitution leak into the parent
  (it is not a true subshell) — a Phase-1 limitation.
- **(H) `~/.ossrc` runs shell commands, not (yet) ncScript.** On startup the
  shell reads `~/.ossrc` via the read seam and executes each line through the
  existing lex→parse→execute path on the shared environment (aliases/vars/exports
  persist). Full ncScript (WS18) semantics are deferred behind an injectable
  seam; the rc error policy is fail-soft (a failing line is reported and startup
  continues; absent file is a no-op; unreadable file fails closed without
  panic).
- **(H) External (non-builtin) commands are not yet spawned.** The Phase-1
  in-process executor returns `127` (`command not found`) for non-builtins until
  the kernel process-spawning layer is wired; consequently **job control**
  (`&`, `fg`/`bg`, WS8-10.16) is not yet available even though the `jobs`
  formatting model exists.

## Deferred / not-yet-host-actionable (tracked, not divergences)

- **WS8-10.16 job control** — needs real background process execution (kernel
  process layer); only the `jobs` table/formatting half is host-implemented.
- **WS8-10.20** — VM 103 end-to-end validation (`ls -la | grep foo | wc -l`,
  pipes/glob, real `ps`/`kill`, `.ossrc` at startup) runs on the deployed rig.
