# ADR-0045: File Manager + Settings + Persistent Config (TASK-23, DE-D2/DE-D3)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-23
**Refs:** PLAN.md TASK-23 (DE-D2+DE-D3, M4), ADR-0044 (terminal/editor + NCFS
service, TASK-22), ADR-0043 (AI status bar, TASK-21), ADR-0037 (NCFS),
`nexacore-types::fs_service`

## Context

TASK-23 adds two native `nexacore-ui` apps: (1) a **file manager** (browse + CRUD
on NCFS, including folders); (2) a **Settings** app (display/network/AI
panels) whose AI panel configures the GPU endpoint/model and persists it to
NCFS, where the runtime reads it at boot. Both build on the TASK-22 NCFS FS
service (`ncfs`/`ncfs-reply`, `FsRequest`/`FsResponse`).

Recon (file:line):
- `OnDiskVolume` (`nexacore-fs`) supports directories internally (`FileType::
  Directory`, `list_directory`) but exposes NO public `mkdir`/`rmdir`:
  `delete_file` only removes a `RegularFile` (returns `NotAFile` on a dir).
  `FsError` (nexacore-fs/lib.rs:130) has `NotADirectory` but no `DirectoryNotEmpty`.
- `nexacore-types::fs_service` has `Create/Write/Read/Delete/ListDir/Stat/Sync` but
  no `Mkdir`.
- There is NO canonical config format/file anywhere; the runtime-image hardcodes
  the Ollama endpoint (`remote.rs`: `OLLAMA_HOST`/`OLLAMA_PORT`/`CONNECT_ADDR`).
- The TASK-21 status bar already shows the live backend reachability — it is the
  natural verification surface for "the runtime used the configured endpoint".

## Decisions

### D1 — Both apps are more windows in `nexacore-apps-image`

There is one display task (owns the framebuffer). The file manager and Settings
join the TASK-22 terminal + editor as additional `nexacore_display` windows in
`nexacore-apps-image`, laid out as a 2×2 grid; **Tab cycles focus** across all four
(the TASK-19 WM). Both are FS-service clients (the TASK-22 `fs_request` helper).

### D2 — `nexacore-fs`: public `create_directory` + directory-aware delete

`OnDiskVolume` gains:
- `create_directory(path) -> Result<u64, FsError>` — allocates a `Directory`
  inode (the internal path the format/root already uses), rejecting an existing
  path (`AlreadyExists`) and an invalid name (`InvalidName`/`PathTooLong`).
- directory-aware delete: `delete_file` stays file-only; a new
  `delete_directory(path)` (or `delete` that dispatches on type) removes an
  EMPTY directory and returns the new `FsError::DirectoryNotEmpty` for a
  non-empty one (the acceptance's "delete di non-vuoto" error). The root `/` is
  never deletable.
- `FsError::DirectoryNotEmpty` is added. Name validation (no `/` in a component,
  length ≤ limit) rejects invalid names deterministically.
These are unit-tested in `nexacore-fs` (create dir, list shows it, delete empty ok,
delete non-empty → `DirectoryNotEmpty`, invalid name → error).

### D3 — `nexacore-types::fs_service`: add `Mkdir`; `Delete` covers dirs

`FsRequest::Mkdir { path }` (→ `FsResponse::Created`/`Error`). `FsRequest::
Delete { path }` is extended to remove either a file or an empty directory (the
service dispatches on the inode type), surfacing `FsErrno::DirectoryNotEmpty`
(new `FsErrno` variant) for a non-empty dir. `FsResponse::Stat` already carries
`is_dir`, which the file manager uses to render folders vs files.

### D4 — `nexacore-types::config`: the canonical AI endpoint config

A new `nexacore-types::config` module: `AiEndpointConfig { host: String, port: u16,
model: String }`, postcard-serialized, stored at the canonical path
[`AI_CONFIG_PATH`] = `/config/ai.cfg` in NCFS. A `validate()` method enforces:
non-empty `host` that parses as a dotted-quad IPv4 (4 `u8` octets), `port != 0`,
non-empty `model` ≤ a bound. `AiEndpointConfig::default()` is the built-in
fallback (`127.0.0.1:11434`, `gemma4:latest`) used when the file is absent or
**corrupt** (decode failure → default + a logged warning — never a hard fail).
A `to_connect_addr() -> [u8; 6]` helper yields the 4-byte IP + 2-byte BE port the
runtime's probe/generate use.

### D5 — Settings app reads/writes the config; the runtime reads it at boot

- **Settings (AI panel):** on open, `FsRequest::Read /config/ai.cfg` → decode →
  show host/port/model (or defaults + a "using defaults" note if absent/corrupt).
  The user edits a field; on save it **validates** (D4) — a malformed endpoint
  is REJECTED with an on-screen message and **no write occurs** (never persist
  invalid config). On valid input it `Mkdir /config` (idempotent) + `Write` +
  `Sync`. The display/network panels show read-only system info for v1 (a
  documented follow-up extends them).
- **Runtime reads config at boot:** `nexacore-runtime-image`, after the FS service
  registers (bounded `NetLookup` retry), `FsRequest::Read /config/ai.cfg` →
  decode → `to_connect_addr()`; it uses that endpoint for the periodic probe +
  `generate`. Absent/corrupt → the hardcoded default. This makes
  `nexacore-runtime-image` an FS-service client (read-only). The TASK-21 status bar
  badge then reflects the CONFIGURED endpoint's reachability — the verification
  surface.

### D6 — Validation + safe-default discipline (security)

Every user-supplied endpoint is validated before persistence (D4); an invalid
value is rejected, never written. Every config READ is fail-safe: a missing or
undecodable `/config/ai.cfg` yields `AiEndpointConfig::default()` + a warning,
never a panic or a hard stop (the runtime always has a working endpoint). This
is the unit-tested invariant ("config corrotta → default sicuri + warning").

## Alternatives considered

- **A separate apps image per app** — rejected: one display task owns the
  framebuffer; the 2×2 multi-window `nexacore-apps-image` (D1) verifies all apps in
  one boot and reuses the WM.
- **A text/TOML config format** — rejected for v1: postcard is the project's
  canonical wire format (NCIP-Serde-004), already used for every IPC type, and a
  `no_std` TOML parser is avoidable surface; the config is a tiny struct.
- **Kernel-mediated config (a syscall)** — rejected: the FS service already
  serves files over IPC; the runtime reading a file is the natural path and
  needs no new syscall.
- **Runtime re-reads config live** — deferred: read-at-boot matches the
  acceptance ("reboot → il runtime lo usa") and avoids a config-watch protocol;
  live reconfiguration is a follow-up.

## Consequences

- `nexacore-fs`: `create_directory` + directory-aware delete + `FsError::
  DirectoryNotEmpty` + name validation (+ unit tests).
- `nexacore-types`: `fs_service::FsRequest::Mkdir` + `FsErrno::DirectoryNotEmpty`;
  new `config` module (`AiEndpointConfig`, validation, default) (+ tests).
- `nexacore-fsd` FS service: serve `Mkdir` + directory delete.
- `nexacore-apps-image`: file manager + Settings windows (4-window grid).
- `nexacore-runtime-image`: read `/config/ai.cfg` at boot, use the configured
  endpoint (FS-service client).
- Host tests: file manager ops on a mock FS (incl. delete-non-empty, invalid
  names); Settings config load/save round-trip + corrupt→default+warning.
- VM-103: create/delete a folder in the file manager; change the AI endpoint in
  Settings → reboot → the value persists and the runtime uses it (the status bar
  badge reflects the configured endpoint's reachability).
- Display/network Settings panels (full) + live reconfig + >4 KiB files are
  tracked follow-ups.

## Verification appendix — TASK-23 CLOSED (2026-06-08)

Implemented (nexacore-fs dir ops, fs_service Mkdir, config module, FS-service
handlers, runtime config-read, file-manager + Settings apps — agent team) and
**hardware-verified on the test VM**, zero #PF.

Host tests: `nexacore-fs` directory CRUD (9 — create/list/delete-empty/
delete-non-empty→`DirectoryNotEmpty`/invalid-name/root-protected/persist);
`nexacore-types::config` (5 — validate, round-trip, corrupt→default, IPv4 parser
edge cases); `nexacore-types::fs_service` Mkdir/wire round-trips. The file-manager
ops + Settings load/save are exercised through these mock-FS / wire tests.

the test VM (`nexacore-apps-image` 2×2 grid: terminal, editor, **file manager**,
**Settings**; serial + 5 screendumps):
- **File manager (DE-D2):** `n` created `dir0` + `dir1` (FsRequest::Mkdir →
  `create_directory`), shown beside `test.txt`; deleting an empty dir succeeded;
  the `DirectoryNotEmpty` error path is unit-tested.
- **Settings (DE-D3):** edited `endpoint` `127.0.0.1:11434` → `:11435`, Esc →
  validated + `Write`+`Sync` to `/ai.cfg`; serial `settings: saved
  127.0.0.1:11435`. After `qm reset`: `[ai-svc] AI config:
  127.0.0.1:11435 model=gemma4:latest` (the runtime READ the persisted
  config) → probed the closed port → `status -> CPU(degraded)` → all four status
  bars flipped to brick **"AI: CPU (degraded - Ollama unreachable)"**, and
  Settings re-loaded `:11435` from disk. Restoring `:11434` returns to GPU. This
  proves: change endpoint → persist → reboot → the runtime uses it (badge is the
  witness). Fail-safe confirmed: a fresh disk (no `/ai.cfg`) → `AI config absent
  -- using default endpoint` → GPU.

### Bring-up finding: nested-path persistence (nexacore-fs on-disk format)

The config was first placed at `/config/ai.cfg`. It wrote + listed fine live,
but after remount the runtime/Settings read it as ABSENT while the file manager
showed `ai.cfg` at the ROOT. Root cause: `nexacore-fs`'s `serialize_inodes` stores
only each inode's basename and `deserialize_inodes` rebuilds every path as
`"/" + name` — so a NESTED path flattens to root on mount, and a read of the
original nested path fails. The runtime's read was also widened to re-send
across attempts (the FS service serves only after its boot-counter sync), but
the decisive fix was moving the config to the ROOT path `/ai.cfg` (root files
round-trip correctly — proven by `/notes.txt` and `/test.txt`). **Full
nested-path persistence (parent linkage in the on-disk inode format) is a
tracked `nexacore-fs` follow-up.** The file manager still creates/deletes folders
at the root (the DE-D2 acceptance); nested-file persistence is the follow-up.
