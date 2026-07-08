# 14 — QEMU/Proxmox Pre-Check Parity

> Plan task: **WS0-03** (see the development plan). Status: active since 2026-06-12.

## Purpose

The local QEMU/OVMF smoke (`scripts/qemu-boot-smoke.sh`) is the **fast
pre-filter** for the real hardware-in-the-loop smoke on the Proxmox test VM
(`scripts/vm103-assert.sh` + `scripts/deploy-proxmox.sh`). For QEMU to remain
a *faithful* pre-filter, both paths must assert the **same boot markers from
the same file**, with platform-only divergences made explicit instead of
drifting silently in per-script hardcoded arrays.

## Single source of truth

`tests/expected-boot-lines.txt` is the canonical list of expected boot lines.

| Consumer | Role | `@hw-only` lines |
|----------|------|------------------|
| `scripts/qemu-boot-smoke.sh` | CI/local QEMU+OVMF smoke, in-order assert | **skipped** (logged) |
| `scripts/qemu-desktop-demo.sh` | interactive demo; prints the markers as a visual checklist (serial is on stdio) | skipped |
| `scripts/vm103-assert.sh` | the Proxmox test VM smoke, byte-exact assert with region citation | **asserted** (tag stripped) |

File format (also documented in the file header):

- one marker per line, matched **byte-exact** as a fixed-string substring
  (`grep -F`) against the captured serial log;
- blank lines and `#` comments are ignored;
- the `@hw-only ` prefix (tag + one space) marks markers that only appear on
  the the Proxmox test VM rig; the marker is everything after the first space;
- **order matters**: `qemu-boot-smoke.sh` asserts lines in order of
  appearance (regression catch for a probe stopping midway).

Feature-gated lines (`--feature mb11-userprobe` / `mb12-userprobe`) remain in
`qemu-boot-smoke.sh`: they depend on **build features**, not on the execution
platform, so they do not belong to the platform-parity file.

## Documented divergences (QEMU rig vs the Proxmox test VM rig)

Markers tagged `@hw-only` in `tests/expected-boot-lines.txt` exist because the
bare QEMU smoke rig intentionally lacks the corresponding device models:

| Divergence | the test VM (Proxmox) | QEMU smoke rig | `@hw-only` marker |
|------------|------------------|----------------|-------------------|
| **IOMMU model** | Intel VT-d emulated by the Proxmox QEMU machine (`[iommu] vendor=intel units=1`, VT-d activated, SAGAW levels) | `q35` machine started **without** an IOMMU device — no `[iommu]` lines | `[iommu] vendor=intel units=1` |
| **NIC model: virtio-net** | virtio-net-pci attached (vmbr0); driver completes modern-caps bring-up | **no NIC attached** | `[virtio-net] live bring-up complete` |
| **NIC model: e1000e** | second test NIC (e1000e, devid 10D3) detected by the PCI scan | no NIC attached | `[e1000e] found on` |

Other known (non-asserted) rig differences, for context:

- **Boot media**: QEMU smoke boots `boot-uefi.img` via `virtio-blk-pci`;
  the test VM boots the full ISO attached as `ide2` CD-ROM (`order=ide2;ide0`).
- **Firmware**: smoke uses a single `-bios OVMF.fd` image; the test VM/Proxmox use
  pve-edk2 OVMF code+vars flash pair.
- **Serial transport**: smoke captures `-serial file:`; the the test VM rig writes
  COM1 to a host-side file via its custom `args` (`/tmp/nexacore-os-serial.log`),
  collected by `deploy-proxmox.sh` into `dist/proxmox/`.
- **CPU/memory**: smoke runs `-cpu qemu64 -m 256M -smp 1`; the test VM runs the
  full multicore configuration (INIT-SIPI bring-up lines appear only there).
  None of these produce asserted markers today; add new `@hw-only` entries if
  they ever do.

## Parity verification procedure

The WS0-03 acceptance criterion: **the same build passes both smokes with the
same assert file** (modulo the documented `@hw-only` lines):

```bash
# 1. QEMU pre-check (x86_64 build env, e.g. /root/nexacore-build on the Proxmox host)
bash scripts/qemu-boot-smoke.sh --skip-build --release

# 2. Hardware smoke on the test VM (from the dev machine)
bash scripts/vm103-assert.sh tests/expected-boot-lines.txt -- --remote-build --skip-build

# Inspect the effective QEMU assert set without running anything:
bash scripts/qemu-boot-smoke.sh --print-expected
```

First executed successfully on 2026-06-12 (QEMU smoke on the Proxmox host
build env + the test VM live assert, 8/8 markers incl. 3 `@hw-only`).

## Maintenance rules

1. New boot marker? Add it to `tests/expected-boot-lines.txt`, **not** to the
   scripts. Tag it `@hw-only ` if the QEMU rig cannot reproduce it, and add a
   row to the divergence table above.
2. Keep the baseline block in sync with `kernel_entry`
   (`kernel-runner/src/main.rs`) and `kmain` (`crates/nexacore-kernel/src/lib.rs`).
3. If the QEMU rig gains a device model (e.g. a NIC for net smokes), promote
   the corresponding marker from `@hw-only` to baseline and update the table.
