# ADR-0044: Windowed Terminal + Text Editor + NCFS Service (TASK-22, DE-D1/DE-D4)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-22
**Refs:** PLAN.md TASK-22 (DE-D1+DE-D4, M4), ADR-0042 (`nexacore-ui`), ADR-0041
(`nexacore-display`), ADR-0040 (display primitives), ADR-0037 (NCFS mount,
TASK-15), `nexacore-shell::repl::process_line`

## Context

TASK-22 opens M4 with two native Ring-3 apps on `nexacore-ui`: (1) a windowed
**terminal** wired to the existing `nexacore-shell` REPL, and (2) a **text editor**
that opens/edits/saves files on NCFS and survives reboot.

Recon (agent-team, file:line) established:
- `nexacore-shell::repl::process_line(input: &str, env: &mut ShellEnv, cwd: &mut
  String, fs: &dyn FsQuery) -> (i32, Vec<u8>)` is **already I/O-agnostic**:
  `no_std + alloc`, FS access abstracted behind the `FsQuery` trait, output
  accumulated into a returned `Vec<u8>` (serial printing is `cfg(std)`-gated
  and OFF on bare metal). FS-free commands (`help`, `echo`, `uname`, `whoami`,
  `pwd`, `env`, `export`) need only a trivial `FsQuery`; `ls`/`cd` use
  `FsQuery::list_dir`. The kernel desktop already drives `process_line` with a
  `KernelFsQuery` over the in-memory `SHELL_VFS` — the "serial backend"; the
  "window backend" is just an app that feeds lines in and renders the bytes
  out. **No nexacore-shell refactor is needed.**
- `nexacore-fsd-image` (TASK-15) is a ONE-SHOT daemon: mount the NCFS volume from
  the NVMe BLK service, run the `/test.txt` boot-counter proof, sync, EXIT. Its
  mount + `read_block`/`write_block` + `OnDiskVolume::{create_file, write_file,
  read_file, sync_to_bytes}` are exactly what a running service needs.
- Named channels are shared via `NetRegister (100)` / `NetLookup (102)` (the
  TASK-21 `ai_status` pattern). IPC payloads are ≤ 4 KiB.
- A Ring-3 app that renders to the screen IS the display task (owns the
  framebuffer via `DisplayMap` + runs the compositor in-process); multi-process
  compositor clients were deferred (ADR-0041 D5). So both apps live in ONE
  display image; the FS service is a SEPARATE (non-display) Ring-3 task.

## Decisions

### D1 — Promote `nexacore-fsd` to a running NCFS FS service

`nexacore-fsd-image` becomes a long-running **FS service**: it mounts the NCFS
volume from NVMe (or formats-on-first-boot, as today), then — instead of
exiting — `NetRegister("nexacore.fs", channel)` and serves a request loop. It is
the SINGLE owner of the on-disk volume (no other task mounts it), which avoids
the multi-writer conflict TASK-15 flagged. The TASK-15 boot-counter proof is
retained as a one-time startup self-check (it still demonstrates persistence)
before the serve loop begins.

### D2 — `nexacore-types::fs_service` wire protocol

A new `nexacore-types::fs_service` module (postcard, `#[non_exhaustive]`):
- `FsRequest`: `Create { path }`, `Write { path, offset, data }`,
  `Read { path, offset, len }`, `Delete { path }`, `ListDir { path }`,
  `Stat { path }`, `Sync` (flush the volume to NVMe — durability point).
- `FsResponse`: `Ok`, `Data { bytes }`, `Listing { names }`,
  `Stat { size, is_dir }`, `Created`, `Error(FsErrno)`.
- A request/response fits one 4 KiB IPC message. **Chunking:** TASK-22 files
  are small (a text editor buffer), so a single `Write`/`Read` ≤ a documented
  cap (`FS_MAX_INLINE_BYTES`, e.g. 3 KiB) is the v1 contract; larger files (a
  `WriteChunk`/`DataChunk` continuation protocol) are a documented follow-up.
  `Sync` after `Write` is what makes the save durable across reboot.

### D3 — Terminal app (DE-D1)

A `nexacore-ui` window hosting `process_line`. Keyboard input (from the TASK-18
display input channel) builds the current line; Enter calls `process_line(line,
&mut env, &mut cwd, &fs_query)` and appends the returned output bytes to a
scrolling history rendered in the window (monospace `font8x8`, a prompt, line
echo, minimal handling — newline/backspace). The `FsQuery` impl is backed by
the FS service (`ListDir` → `ls`/`cd`) when available, else a stub (FS-free
commands still work). Acceptance: `help` + a real command (`echo`, `uname`)
render correct output in the window.

### D4 — Text editor app (DE-D4)

A `nexacore-ui` window with an edit buffer (a `String` + cursor): printable keys
insert, Backspace deletes. It targets a fixed demo path (e.g. `/notes.txt`).
**Open** = `FsRequest::Read` (or start empty if absent). **Save** (a key,
e.g. Ctrl-S / a dedicated key since modifiers may be limited) =
`FsRequest::Create` (if new) + `FsRequest::Write { offset: 0, data }` +
`FsRequest::Sync` → the FS service writes it into the volume and flushes to
NVMe. After `qm reset`, the FS service re-mounts the persisted volume and a
subsequent **Open** returns the saved bytes — the reboot-persistence
acceptance. The buffer round-trips through NCFS, not the in-memory SHELL_VFS.

### D5 — One display image, separate FS-service task

`nexacore-apps-image` is the display task: compositor + a terminal window + an
editor window, Tab cycles focus, keys route to the focused app (TASK-19 WM).
The `nexacore-fsd` FS service runs as a separate Ring-3 task (a BLK client, not a
display task), spawned by the kernel alongside the NVMe driver (it needs the
`IpcSend` cap for the BLK channel). The kernel display boot-spawn prefers
`nexacore-apps-image`. The TASK-21 status bar can sit atop the apps window too.

### D6 — Editor round-trip is unit-tested on a mock FS

The editor's open→modify→save→reopen logic and the terminal's line/echo parsing
are unit-tested host-side against a mock `FsQuery`/mock FS (no hardware), per
the acceptance; the NCFS round-trip itself is covered by the nexacore-fs unit
tests (TASK-15) + the hardware reboot test.

## Alternatives considered

- **Editor mounts the NCFS volume itself** (like nexacore-fsd) — rejected: two
  volume owners (editor + nexacore-fsd) conflict; the single FS service (D1) is the
  correct M4 architecture and the first step of the kernel-VFS `FsOpen`-redirect
  TASK-15 deferred.
- **Terminal + editor as two separate display images** — rejected: only one
  task owns the framebuffer; one apps image with two windows (D5) verifies both
  in a single boot and matches the WM that already does multi-window.
- **Refactor nexacore-shell for a window I/O backend** — unnecessary (recon):
  `process_line` is already I/O-agnostic; the app IS the window backend.
- **Full kernel-VFS `FsOpen`-redirect (syscalls 90-95 → FS service)** —
  deferred: routing the in-kernel file syscalls to the FS service is a larger
  kernel change; the apps talk to the FS service DIRECTLY over IPC for TASK-22,
  which delivers the persistence acceptance without the kernel reroute.
- **>4 KiB file chunking now** — deferred (D2): the editor's demo file is small;
  the chunk-continuation protocol is a documented follow-up.

## Consequences

- `nexacore-types::fs_service` wire types (+ tests).
- `nexacore-fsd-image`: one-shot → running FS service (mount + NetRegister + serve
  loop reusing the existing mount/IO/sync).
- New `nexacore-apps-image`: compositor + terminal (`process_line`) + editor (FS
  client) windows; kernel display boot-spawn prefers it; the FS service spawns
  alongside the NVMe driver.
- Host tests: editor open→modify→save→reopen on a mock FS; terminal line/echo.
- VM-103: windowed `help` + a real command; editor create+save, reopen after
  reboot. M4 begins; the FS service is the foundation TASK-23 (file manager)
  builds on.
- Larger-file chunking + kernel `FsOpen`-redirect are tracked follow-ups.

## Verification appendix — TASK-22 CLOSED (2026-06-08)

Implemented (FS service, terminal+editor apps image, wire types — agent team)
and **hardware-verified on the test VM**, zero #PF. Opens M4.

Host tests: `nexacore-types::fs_service` wire round-trips (4); `nexacore-fs`
editor open→modify→save→reopen-after-reboot round-trip on a mock `OnDiskVolume`
(3 — models the exact `Create`/`Write`/`Sync`/`Read` path the service runs);
the terminal's parsing/echo is covered by `nexacore-shell`'s existing
`process_line` suite (366 tests incl. `echo`, `cd`, unknown-command-127).

the test VM (`nexacore-apps-image` as the display task; `nexacore-fsd` FS service alongside
the NVMe driver; serial + 4 screendumps):

```
[nexacore-fsd] FS service registered (ncfs / ncfs-reply) fs_req_ch=.. fs_reply_ch=..
[nexacore-apps] terminal ready
[nexacore-apps] editor opened /notes.txt (0 bytes)      # fresh disk
   ( Tab → terminal; type "help" + Enter )
[nexacore-apps] term: help -> 0                          # process_line ran
   ( type "pwd" + Enter )
[nexacore-apps] term: pwd -> 0
   ( Tab → editor; type "persist42"; Esc )
[nexacore-apps] editor saved 9 bytes
[nexacore-fsd] Sync: volume flushed to NVMe              # durability point
   ( qm reset 103 — disk NOT zeroed )
[nexacore-fsd] /test.txt was: ...boot 1  → boot 2 persisted   # volume survived
[nexacore-apps] editor opened /notes.txt (9 bytes)       # reopened the saved file
```

Screenshots: (1) two windows — left **terminal** (`nexacore$` prompt + status bar),
right **editor** (`/notes.txt [Esc=save]`); (2) terminal showing the real
`help` built-in-commands list from `nexacore-shell::process_line`; (3) terminal
`pwd → /` and the editor with **"persist42"** + status **"saved /notes.txt
(9 bytes)"**; (4) **after `qm reset`** the editor reopened showing **"persist42"**
— the file saved before the reboot, round-tripped through the NCFS service to
NVMe and back. DE-D1 (terminal) + DE-D4 (editor) both met.

### Integration fixes found + applied during bring-up

1. **`/bin` name mismatch** — the initramfs entry's `vfs_name` field maps to
   `/bin/<vfs_name>`; it was `nexacore-apps` but the kernel boot-spawn looks for
   `/bin/nexacore-apps-image`. Renamed the entry's `vfs_name` to `nexacore-apps-image`.
2. **`NetRegister` name rejected** — NET interface names are `[A-Za-z0-9_-]`,
   ≤ 16 bytes; the dotted `nexacore.fs`/`nexacore.fs-reply` were rejected (the dotted
   convention belongs to the BLK registry, a different syscall). Renamed the
   service channels to `ncfs`/`ncfs-reply` (in `nexacore-types::fs_service`).
3. **Late registration** — `nexacore-fsd` registered the FS channels only AFTER its
   slow mount + 128-block boot-counter sync, by which time the apps image's
   bounded `NetLookup` retry had expired ("FS service unavailable"). Moved the
   channel `NetRegister` to BEFORE the proof (requests buffer in the queue until
   the serve loop starts) and widened the client retry.
