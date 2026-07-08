# Troubleshooting

Common problems, in roughly the order you might hit them. If the screen is
blank, the **serial console** is your friend: boot with `-serial stdio` (QEMU)
or attach a serial device (VirtualBox/VMware/Proxmox) — the kernel prints its
progress there even when graphics fail.

## It will not boot at all

**"No bootable device" / firmware ignores the image.**
NexaCore OS is **UEFI-only** — it does not boot in legacy BIOS/CSM mode.

- In a VM: enable **EFI** in the VM settings before first boot.
- On hardware: enter firmware setup and switch the boot mode to **UEFI**.

**Boots a few lines then stops, or the firmware refuses the image.**
If **Secure Boot** is enabled and the image is not signed for your machine's
keys, disable Secure Boot for the test boot.

**On Proxmox: `Could not open '/tmp/...img'`.**
The test VM's scratch disks live in `/tmp` and are wiped on host reboot.
Recreate them (sizes per the deploy script) and start the VM again.

## It boots but the screen is blank

The kernel may be running fine with no graphical output yet.

1. Check the **serial console**. If you see the kernel banner and driver
   start-up lines there, the system is alive — the issue is the display path.
2. Confirm the VM/GPU presents a standard UEFI framebuffer. Exotic or
   passed-through GPUs may not yet have a driver in the image.
3. Give it a moment on first boot — bringing up CPUs, memory, the IOMMU, and the
   compositor takes a few seconds.

## The keyboard or mouse does nothing

Input is **USB-HID**.

- In a VM, attach a **USB keyboard** and a **USB tablet/mouse** (not the legacy
  PS/2 devices some hypervisors default to).
- On hardware, use a directly-connected USB keyboard/mouse; some USB hubs and
  exotic devices are not yet enumerated.

## An app says a codec or driver is missing

Several apps (document, image, media viewers) have a complete core but defer the
heavy decode to a **vetted, gated** component. If that component is not present
in your image, the app reports it rather than crashing. This is expected on
minimal images — it is not data loss, and your file is untouched.

## Networking, Wi-Fi, Bluetooth, or printing does not work

These are **driver-dependent** and not universally present yet. Wired NICs
covered by the bundled drivers (e.g. virtio-net, common Intel parts) work; Wi-Fi,
Bluetooth, and printers depend on hardware the image may not have a driver for.
Check the project roadmap for current driver coverage.

## My changes disappeared after reboot

Expected. The image is **live only** — there is **no persistent disk yet**, so
all state is discarded on shutdown. Nothing you did was "lost" to a bug; the
system simply does not save to disk in this phase.

## An AI action or network send was blocked

That is the privacy model working as designed:

- Actions that would disclose data pass a **capability gate** and draw down your
  **privacy budget**; if the capability is absent or the budget is exhausted,
  the action is refused **fail-closed**.
- Personally identifiable information is **tokenized** before it can reach a
  model or the network. If you expected raw text to go somewhere and it did not,
  this is why.

Open the privacy/budget view to see what was charged and why.

## Still stuck?

- Capture the **serial log** from boot — it is the single most useful artifact
  for diagnosing a failure.
- Note your exact hardware/VM configuration (CPU, firmware mode, attached
  devices).
- File an issue against the
  [repository](https://github.com/CySalazar/nexacore-os) with both.
