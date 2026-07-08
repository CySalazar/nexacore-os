# NexaCore OS — User Guide

> An AI-native operating system. Local-first, privacy-by-construction,
> decentralized by design.

Welcome. This guide is for **people who want to install and use NexaCore OS** —
not for kernel hackers (the technical documentation lives in
[`/docs`](https://github.com/CySalazar/nexacore-os/tree/main/docs)). It walks you
from a downloaded image to a running desktop, explains the bundled apps, and
helps you recover when something goes wrong.

## What NexaCore OS is

NexaCore OS reimagines the operating system around AI as a first-class citizen.
Inference, model orchestration, and intelligent agents are built into the kernel
and runtime — not bolted on as cloud services. Three principles shape everything
you will see:

- **Local-first** — by default, *nothing leaves your device*. Models run on your
  own hardware.
- **Privacy by construction** — privacy is enforced cryptographically, not by a
  policy you have to trust. Sensitive data is tokenized before it can reach any
  AI path or the network.
- **Hardware-rooted security** — the system uses your CPU's Trusted Execution
  Environment (Intel TDX / AMD SEV-SNP) to attest what is running.

## What works today (and what does not)

NexaCore OS is in **Phase 1**. Be realistic about what you are installing:

| Area | Status |
|------|--------|
| Boots to a graphical desktop on UEFI x86_64 (QEMU, VirtualBox, VMware, Proxmox, USB stick) | ✅ Live image |
| Terminal shell, window management, on-screen keyboard/mouse via USB-HID | ✅ |
| Bundled viewer/monitor apps (documents, images, media, system monitor) | ✅ Core logic; some need specific drivers |
| Local AI inference (quantized transformer + GGUF models) | ✅ Runtime present |
| **Persistent install to disk** | ❌ Not yet — the image is **live only** |
| Wi-Fi, Bluetooth, printing on arbitrary hardware | ⏳ Driver-dependent |
| Mesh (multi-device) compute | ⏳ Phase 2+ |

> **Live image, no installer.** There is currently **no install-to-disk step**.
> You boot the image, use the system, and it forgets everything on shutdown.
> Treat it as a preview / development environment, not a daily driver.

## How to read this guide

1. **[Installation](./installation.md)** — get the image and boot it (virtual
   machine or USB stick).
2. **[The desktop](./desktop.md)** — log in to the desktop, move windows, use
   the keyboard and pointer.
3. **[Bundled apps](./apps.md)** — what ships in the image and how to use it.
4. **[Troubleshooting](./troubleshooting.md)** — the most common problems and
   their fixes.
