# Installation

NexaCore OS ships as a **UEFI-bootable live ISO**. There is no install-to-disk
step yet — you boot the image and it runs entirely in memory. This page takes
you from nothing to a booted desktop.

## 1. Check your hardware

NexaCore OS v1 targets **x86_64 with a hardware TEE**. The full requirements
live in
[hardware-requirements](https://github.com/CySalazar/nexacore-os/blob/main/docs/07-hardware-requirements.md);
the essentials:

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Architecture | x86_64 (64-bit) with UEFI firmware | — |
| CPU (for the security features) | Intel TDX (Sapphire Rapids 2023+) **or** AMD SEV-SNP (EPYC 7003 2021+ / Ryzen Pro 7040 2023+) | — |
| RAM | 16 GB | 32 GB+ |
| Storage (for caching models) | 256 GB SSD | 512 GB NVMe |
| GPU | optional — CPU-only inference works (slower) | discrete GPU |

> **No TEE? You can still boot.** The desktop and apps run on any UEFI x86_64
> machine or VM. The hardware TEE is required only for *mesh participation* and
> the strongest attestation guarantees — not to try the system locally.

For a first look, a **virtual machine is the easiest path** and needs none of
the TEE hardware.

## 2. Get the image

You have two options.

### Option A — download a pre-built ISO

Grab the latest `nexacore-os-<version>.iso` from the project's release page (or
your distribution channel). Verify its signature if one is published before you
boot it.

### Option B — build it from source

From a checkout of the repository, on an x86_64 Linux host with `xorriso` and
`rustup` installed:

```bash
bash scripts/build-iso.sh
```

This produces a unique image per commit:

```text
dist/iso/nexacore-os-<short_sha>.iso   # this build
dist/iso/nexacore-os-latest.iso        # symlink to the most recent build
```

The build is **reproducible** — the same commit on two machines yields a
byte-identical ISO (absolute paths are remapped out of the image).

## 3. Boot it

Pick the target that matches where you want to run.

### In QEMU (quickest)

You need OVMF (UEFI firmware for QEMU). A minimal invocation:

```bash
qemu-system-x86_64 \
  -machine q35 -m 4096 -smp 2 \
  -bios /usr/share/OVMF/OVMF_CODE.fd \
  -cdrom dist/iso/nexacore-os-latest.iso \
  -serial stdio
```

`-serial stdio` mirrors the boot log to your terminal — useful if the graphical
output does not appear.

### In VirtualBox / VMware

1. Create a new VM: type **Other/Unknown (64-bit)**, **4 GB+ RAM**, **2+ CPUs**.
2. In the VM settings, **enable EFI** (System → Enable EFI). NexaCore OS will not
   boot in legacy BIOS mode.
3. Attach `nexacore-os-latest.iso` as the optical drive and start the VM.

### On a physical machine (USB stick)

1. Write the ISO to a USB stick (≥ 1 GB). On Linux:
   ```bash
   sudo dd if=dist/iso/nexacore-os-latest.iso of=/dev/sdX bs=4M status=progress oflag=sync
   ```
   Replace `/dev/sdX` with your stick — **double-check the device, `dd` is
   destructive.**
2. In the machine's firmware, **enable UEFI boot** and boot from the stick.
3. If the firmware has **Secure Boot** enabled and the image is unsigned for your
   keys, disable Secure Boot for the test boot.

### On Proxmox (test rig)

The repository includes an automated deploy that builds the ISO, uploads it to a
Proxmox host, and boots a UEFI test VM (the test VM by default):

```bash
bash scripts/deploy-proxmox.sh --remote-build
```

See the script header for the environment variables it honours
(`PROXMOX_HOST`, `PROXMOX_VMID`, …).

## 4. First boot

On a successful boot you will see the kernel banner on the serial console
followed by the graphical desktop. The boot sequence, at a glance:

```text
  firmware (UEFI)
        │
        ▼
  bootloader  ──►  NexaCore microkernel
        │                │
        │                ├─ brings up CPU(s), memory, IOMMU
        │                ├─ starts user-space drivers (input, storage, net)
        │                └─ launches the desktop compositor
        ▼
   NexaCore desktop  ──►  ready to use
```

If the desktop does not appear, head to
[Troubleshooting](./troubleshooting.md).

> **Remember:** this is a **live** image. Anything you do is lost on shutdown —
> there is no persistent disk yet.
