# QEMU boot smoke — `<YYYY-MM-DD>`

> **Status:** template. Replace this header line with the run date when
> filing a real audit entry. Filename convention:
> `docs/audits/qemu-boot-smoke-<YYYY-MM-DD>.md`.

K5 gate of `NCIP-Kernel-003` § 3 — `kernel-runner` boots under QEMU+OVMF
and emits the canonical banner sequence on the serial console.

## Environment

| Field | Value |
|---|---|
| **Date (UTC)** | `<YYYY-MM-DDTHH:MM:SSZ>` |
| **Host** | `<distro + version, e.g., Ubuntu 24.04.1>` |
| **Kernel (host)** | `<uname -r>` |
| **Rust toolchain** | `<rustc --version --verbose | head -1>` |
| **`bootimage` version** | `<bootimage --version>` |
| **`bootloader` crate** | `<from Cargo.lock>` |
| **`bootloader_api` crate** | `<from Cargo.lock>` |
| **QEMU version** | `<qemu-system-x86_64 --version | head -1>` |
| **OVMF version** | `<dpkg -s ovmf | grep Version, or "edk2-stable<year>" on Arch>` |
| **kernel-runner commit** | `<git rev-parse HEAD>` (branch `<branch>`) |
| **CI run URL** | `<https://github.com/CySalazar/nexacore-os/actions/runs/...>` |

## Invocation

```bash
bash scripts/qemu-boot-smoke.sh --release
```

(or, equivalently, the `qemu-boot-smoke` workflow job — paste the URL above.)

## Result

**`<PASS | FAIL>`** — boot completed in `<NN.NNN>` seconds (wall clock).

## Captured serial output

Verbatim, including QEMU's startup banner:

```text
<paste the full stdout/stderr capture of qemu-boot-smoke.sh here>
```

## Banner-sequence assertion

The smoke script asserts that the five lines below appear, in order,
on the serial console. Tick each line on a successful run.

- [ ] `[NexaCore OS] kernel-runner: entry_point reached.`
- [ ] `[NexaCore OS] early console (COM1) is live.`
- [ ] `[NexaCore OS] proceeding to heap init + kmain.`
- [ ] `[NexaCore OS] kmain entered.`
- [ ] `[NexaCore OS] halting (K4 scope ends here).`

Lines 1–3 are emitted by `kernel-runner/src/early_console.rs::
announce_boot`; lines 4–5 are emitted by `nexacore_kernel::kmain` (with
the kernel version + memory-region count between them — assertion
ignores those values, only the framing lines).

## Memory map observed

Paste the `kmain`-reported region count (the integer on the line
`[NexaCore OS] memory regions: <N>` between lines 4 and 5):

| Field | Value |
|---|---|
| Region count | `<N>` |
| `MIN_HEAP_BYTES` met by `pick_region` | `<YES — no panic>` |

If `<NO — panic-on-no-region>`, paste the structured panic record
(postcard-encoded bytes are decoded by the smoke script for human
readability) into the section below.

## Anomalies / follow-ups

| Severity | Description | Action |
|---|---|---|
| `<low|med|high>` | `<observation>` | `<file an issue, fold into next NCIP, ignore>` |

## Sign-off

| Role | Name | Date |
|---|---|---|
| Smoke-test runner | `<cySalazar>` | `<YYYY-MM-DD>` |
| Editor body (Seat 1) | `<cySalazar>` | `<YYYY-MM-DD>` |

---

## EXPECTED_LINES contract by feature (TASK-013 / P10.4)

The smoke script extends its `EXPECTED_LINES` banner sequence
based on the `--feature` flag. The CI matrix runs three jobs:

| Feature | EXPECTED_LINES extension | CI job | Block merge? |
|---|---|---|---|
| *(none)* | K5 baseline only (5 lines from `kernel_entry` + `kmain`). | `qemu-boot-smoke / smoke` | Yes (P10.4 critical-path gate). |
| `mb11-userprobe` | K5 baseline + `[user] hello` + `[user] exit=0` (Ring 3 process spawned by `kmain` exits cleanly via `TaskExit(0)`). | `qemu-boot-smoke / qemu-smoke-mb11` | Yes. |
| `mb12-userprobe` | K5 baseline + `[mb12] channel 1 pre-created` + `[user] hello` + `ping` + 2× `[user] exit=0` (MB12 IPC cross-process). | `qemu-boot-smoke / qemu-smoke-mb12 [KNOWN-ISSUE]` | **No** (`continue-on-error: true` until the MB14+ follow-up closes the "user task stops before emitting ping / exit" regression noted in the `proxmox_deploy` memory). |

Invocation pattern:

```sh
scripts/qemu-boot-smoke.sh --release                              # baseline
scripts/qemu-boot-smoke.sh --release --feature mb11-userprobe     # MB11
scripts/qemu-boot-smoke.sh --release --feature mb12-userprobe     # MB12 (KNOWN ISSUE)
```

When the MB12 known-issue is fixed in a future PR, the `continue-on-error: true` flag in `.github/workflows/qemu-boot-smoke.yml` and the `[KNOWN-ISSUE]` suffix in the job name MUST be removed in the SAME PR.

---

*This file is part of the K5 audit trail mandated by `NCIP-Kernel-003`
§ 3 (last row of the K1–K5 table). Each successful smoke run on `main`
produces a new audit file named
`docs/audits/qemu-boot-smoke-<YYYY-MM-DD>.md`. Failures land in the
same directory with a `FAIL` status — they are not deleted, since the
audit trail must record both successes and regressions.*
