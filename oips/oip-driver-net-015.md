---
ncip: 15
title: Network user-space driver — virtio-net + e1000e + ConnectX phased delivery, NET channel
track: Standards Track
status: Active
authors:
  - cySalazar <hello@nexacoreos.com>
created: 2026-05-20
updated: 2026-05-20
activated: 2026-05-20
requires:
  - 13
supersedes: ~
superseded-by: ~
discussion: https://github.com/CySalazar/nexacore-os/discussions (TBD link)
license: CC0-1.0
---

## Abstract

`NCIP-Driver-Framework-013` § S7 enumerates network drivers as the second
first-party deliverable. This NCIP — `NCIP-Driver-Net-015` — specifies a
user-space network driver framework with a **phased multi-device delivery**:

- **M1 — `virtio-net`** (PCI vendor `0x1AF4`, device `0x1041` / `0x1000`).
  First target because QEMU and Proxmox expose it natively, allowing
  bare-metal-equivalent validation without dedicated hardware.
- **M2 — Intel `e1000e`** (device IDs `0x10D3`, `0x153A`, `0x153B`,
  `0x15A0..15A3`, et al.). Bare-metal target for the demo desktop on consumer
  PC class hardware where Intel-IGP integrated NICs are universal.
- **M3 — Mellanox `ConnectX-3/4/5`** (vendor `0x15B3`). Server-class target
  for the future `nexacore-server` profile; deferred until M1+M2 are stable.

All three share a common **NET service channel** (`nexacore.svc.net.<ifN>`)
carrying L2 Ethernet frames in/out. Upper layers (TCP/IP stack, mesh
protocol, etc.) consume the NET channel and are unaware of which underlying
NIC is in use — same abstraction principle as the BLK channel for storage
in `NCIP-Driver-NVMe-014`.

Each milestone is its own driver process / signed image: `nexacore-driver-virtio-net`,
`nexacore-driver-e1000e`, `nexacore-driver-mlx`. They share a common base crate
`nexacore-driver-net-common` (TBD) for the NET channel shape, MAC address
handling, and frame validation, but their PCI bring-up paths are
device-specific.

The driver inherits NCIP-013's kernel-mediated contract (capability tokens,
`MmioMap`, `DmaMap`, `IrqAttach`, `DriverLoad`) and adds network-specific
manifest fields and channel shapes.

---

## Motivation

### M1. Phase 1 requires networking for Tier-1 and Tier-2 deliverables

`docs/06-roadmap.md` Phase 1 includes "Ethernet/Wi-Fi networking" as a
user-space driver. Without networking the system is fully isolated; Phase
3 (Personal Cluster) and Phase 4 (Federated Mesh) cannot even begin
prototyping.

Wi-Fi specifically is deferred to a follow-up NCIP — Wi-Fi drivers are 10-100×
the complexity of Ethernet (regulatory, MAC offload, association state
machines, firmware blobs). Phase 1 targets Ethernet only; Wi-Fi enters in
the same window as Phase 3 / Phase 4 work.

### M2. Three devices = three different bring-up paths

The NCIP-013 framework is device-agnostic by design (capability + MMIO + DMA
+ IRQ), but the bring-up sequence varies dramatically:

- **virtio-net** uses the virtio Common Configuration layout (legacy +
  modern); ring descriptors in IOVA-pinned pages; one virtqueue per direction.
- **e1000e** uses register-mapped queue descriptors at `RDBAL`/`RDBAH`/
  `RDLEN`/`RDH`/`RDT`; PHY auto-negotiation via MDIO; EEPROM-stored MAC.
- **ConnectX** uses a command interface (MAILBOX) that itself sits on top
  of a virtualized PCI BAR; QP (Queue Pair) abstraction; verbs API.

Locking three separate manifests + three command channels in one NCIP would
quadruple the document size and slow down M1 (the only one needed for QEMU
validation). Phased delivery means M1 ships first and unblocks the upper
layers (Phase 3 mesh stack prototyping), while M2 follows for bare metal
and M3 lands when server-class targets enter the roadmap.

### M3. The NET channel decouples the protocol stack

A naive design would have the TCP/IP stack send virtio-net descriptors
directly. We reject for the same reasons articulated in `NCIP-Driver-NVMe-014`
§ R3 (one driver = one stack code path; structural coupling of layers; etc.).

The NET channel shape is identical across all three NIC families:

```rust
enum NetRequest {
    SendFrame {
        bytes_iova: u64,        // start of frame including dst/src MAC + ethertype
        bytes_len: u16,         // 60..=1518 (or 9000 for jumbo)
    },
    GetLinkState,
    GetMac,
    SetPromisc { on: bool },
}
enum NetResponse {
    Ok,
    FrameTooLarge,
    LinkDown,
    NotSupported,
    InvalidArgument,
}
enum NetEvent {
    FrameReceived { bytes_iova: u64, bytes_len: u16 },
    LinkStateChange { up: bool, speed_mbps: u32, duplex_full: bool },
    MacChanged { mac: [u8; 6] },
}
```

### M4. Why we file the framework now, not after M1 ships

M1, M2, M3 share enough structure (manifest schema, capability claims,
NET channel shape, IRQ topology choices) that having one NCIP lock them up
front prevents drift. If M1 ships first under its own NCIP and M2 second
under another, each will reinvent the manifest schema slightly differently
and the upper-layer code paths fragment.

The NCIP locks the shared contract; the per-driver implementations follow,
phased as the roadmap demands.

---

## Specification

> **Normative keywords.** RFC 2119 / RFC 8174 (MUST, MUST NOT, SHOULD,
> SHOULD NOT, MAY).

### S1. Manifest schema extension

The driver manifest (TOML v1, per `NCIP-Driver-Framework-013` § S5.1) MUST
include a top-level `[net]` table with the following shape (common across
all three drivers; per-driver overrides documented in S4-S6):

```toml
[meta]
name           = "nexacore-driver-<family>"   # virtio-net | e1000e | mlx
version        = "0.1.0"
nexacore_image_hash = "<64-hex BLAKE3>"
nexacore_signature  = "<base64 Ed25519>"
nexacore_issuer_pubkey = "<base64 Ed25519>"

[capabilities]
mmio_regions  = [ { phys_base = "<BAR from PCI enum>", len = "<family-specific>" } ]
dma_windows   = [ { iova_base = "0x0", len = "0x100000000" } ]  # 4 GiB IOVA
irq_lines     = [ ]  # populated by IrqAttach
pci_devices   = [ { segment = 0, bus = "<dyn>", device = "<dyn>", function = 0 } ]

[matchers]
pci_vendor_device = [
    # virtio-net: { vendor = "0x1AF4", device = "0x1041" },  # modern
    # virtio-net: { vendor = "0x1AF4", device = "0x1000" },  # legacy
    # e1000e:     { vendor = "0x8086", device = "0x10D3" },  # 82574L
    # e1000e:     { vendor = "0x8086", device = "0x153A" },  # I217-LM
    # mlx ConnectX-4 LX: { vendor = "0x15B3", device = "0x1015" },
]

[net]
# Maximum frame size advertised on the NET channel
mtu                = 1500       # 1500 standard; 9000 jumbo if supported by family
# Receive ring depth
rx_ring_depth      = 256
# Transmit ring depth
tx_ring_depth      = 256
# RX buffer pool: number of pre-allocated 2 KiB buffers
rx_buffer_count    = 512
# Promiscuous mode enabled at boot? (usually false)
promisc_at_boot    = false
# Checksum offload (TX): hardware computes IP/TCP/UDP checksum
tx_checksum_offload = true      # set to false if the device does not advertise it
# Checksum offload (RX): hardware validates checksums; software trusts the hardware-set flag
rx_checksum_offload = true
# TSO (TCP Segmentation Offload): coalesce large TX into MTU-sized frames
tso_enabled        = false      # off by default; opt-in per family
# LRO (Large Receive Offload): coalesce inbound segments
lro_enabled        = false      # off by default
```

**S1.1 (Validation).** `DriverLoad` MUST reject the manifest if:

- `mtu` is not in `64..=9216`,
- `rx_ring_depth` or `tx_ring_depth` is not in `1..=4096` and not a power of 2,
- `rx_buffer_count` is not in `1..=8192`,
- `pci_vendor_device` is empty.

### S2. NET service channel (`nexacore.svc.net.<ifN>`)

The driver MUST register one NET channel per network interface it surfaces.
For v0.3 (single-interface per driver process), this means one channel
named `nexacore.svc.net.eth0`, `nexacore.svc.net.eth1`, … per loaded driver, with
`N` allocated monotonically by the kernel as drivers register.

**S2.1 (Frame format on the channel).** Frames carried over the NET channel
are **full Ethernet frames including header** (destination MAC, source MAC,
EtherType / 802.1Q tag, payload), **without the FCS** (Frame Check Sequence).
The hardware computes FCS on TX and validates / strips on RX; the channel
sees only frames that already passed FCS validation.

**S2.2 (Send path).** The client calls `IpcSend(nexacore.svc.net.eth0,
NetRequest::SendFrame{bytes_iova, bytes_len})`. The driver:

1. Validates `bytes_len` against the negotiated MTU + 18 (Ethernet header
   + optional 4-byte 802.1Q tag).
2. Validates `bytes_iova` lies inside an IOVA range the client previously
   `DmaMap`-ed (kernel enforces this implicitly via IOMMU; driver
   double-checks to return a clean error).
3. Posts the descriptor to the appropriate TX ring.
4. Returns `NetResponse::Ok` once the descriptor is posted (not when the
   device acks completion — completions are asynchronous).

**S2.3 (Receive path).** The driver pre-allocates a pool of RX buffers
(`rx_buffer_count` × 2 KiB) from a per-driver IOVA arena, posts them to the
RX ring at boot, and on each RX completion emits a `NetEvent::FrameReceived`
on the channel. The client is responsible for copying the bytes out before
the driver recycles the buffer (the driver waits a short bounded period
for the client to drain, then refills the ring).

**S2.4 (Backpressure).** The NET channel MUST be created with
`backpressure = true`. If the inbox is full on `IpcSend`, the client gets
`EBUSY` and retries.

**S2.5 (Multi-queue).** v0.3 uses **one TX ring + one RX ring** per driver,
delivered to BSP only (per NCIP-013 § S4.5). Multi-queue (RSS for RX, multiple
TX rings for multi-core sending) is deferred to a follow-up NCIP that lands
together with per-CPU IRQ affinity.

### S3. Event-channel ABI

Each NET service channel has a companion broadcast event channel
`nexacore.svc.net.<ifN>.evt` for `NetEvent` per § M3.

Events:

- `FrameReceived` — one per inbound frame; payload accessible via the
  IOVA pointer, valid for at most 16 ms after emission (after which the
  driver recycles the buffer).
- `LinkStateChange` — emitted on link up/down transitions; carries the
  negotiated speed and duplex.
- `MacChanged` — emitted at boot (initial MAC announcement) and on any
  later admin-driven MAC change (rare).

### S4. virtio-net specifics (M1)

`virtio-net` is the primary target for QEMU and Proxmox VMs. The driver
manifest sets `pci_vendor_device = [{ vendor = "0x1AF4", device = "0x1041" }]`
for modern PCI (1.0+) virtio devices; `0x1000` is the legacy ID and is
supported as a fallback but discouraged.

**S4.1 (Bring-up).** Following virtio 1.0 § 3:

1. `MmioMap` BAR0 (legacy IO ports) AND BAR4 (modern MMIO capability
   structures, located via the PCI Capability Pointer). For modern,
   discover the Common, Notify, ISR, Device-specific, and PCI configurations
   via the vendor-specific capabilities chain.
2. Reset the device: write `0` to `device_status` (Common Cfg byte at
   offset `0x14`). Wait until reads return `0`.
3. Acknowledge: write `ACKNOWLEDGE | DRIVER` (bits 0+1) to `device_status`.
4. Feature negotiation: read `device_feature` 64-bit (banks 0 and 1).
   Negotiate `VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS`
   (and optionally `VIRTIO_NET_F_MRG_RXBUF`, `VIRTIO_NET_F_CSUM` if
   `tx_checksum_offload=true`). Write the negotiated set to
   `driver_feature` and write `FEATURES_OK` to `device_status`.
5. Re-read `device_status`; if `FEATURES_OK` is not still set, abort.
6. Allocate virtqueue 0 (RX) and virtqueue 1 (TX). For each, `DmaMap` a
   page set sized to `queue_size × (16+8+8)` bytes (descriptor + avail +
   used tables), and program the queue's IOVA bases into the Common Cfg.
7. Read the MAC address from the Device Cfg (offset 0).
8. Write `DRIVER_OK` to `device_status`. The device is now operational.
9. Post RX buffers; `IrqAttach` for each virtqueue's interrupt vector.

**S4.2 (Notification).** The driver writes the virtqueue index to the
`Notify` offset to kick the device after each batch of descriptors. The
device interrupts the driver on completion (handled by the kernel-installed
trampoline per NCIP-013 § S4.2).

### S5. e1000e specifics (M2)

The Intel e1000e family covers a wide range of integrated NICs from the
mid-2000s onwards. The driver targets the modern PCI Express variants
(82574L, I217/I218/I219 series, et al.).

**S5.1 (Bring-up).** Per Intel 82574L datasheet § 5:

1. `MmioMap` BAR0 (CSR space, 128 KiB).
2. Disable interrupts: write `0xFFFFFFFF` to `IMC` (`0x000D8`).
3. Global reset: set `CTRL.RST` (bit 26 of `0x00000`), wait 1 ms, then
   poll until `CTRL.RST` reads 0.
4. Read MAC from the Receive Address registers `RAL[0]`/`RAH[0]`
   (`0x05400`/`0x05404`) — the EEPROM has already loaded them by the
   time we get here.
5. Initialize the PHY: read `MII_CTRL` via MDIO transactions (issued via
   MDIC at `0x00020`), trigger auto-negotiation if not already complete.
6. Allocate the RX descriptor ring: `rx_ring_depth × 16 bytes`,
   `DmaMap` into the IOVA arena. Write base + length to `RDBAL`/`RDBAH`/
   `RDLEN`. Initialize the head/tail pointers (`RDH`/`RDT`).
7. Allocate and pre-post `rx_buffer_count` 2 KiB buffers into the ring.
8. Allocate the TX descriptor ring similarly (`TDBAL`/`TDBAH`/`TDLEN`).
9. Configure receive (`RCTL` = `0x00000` plus broadcast accept, strip CRC,
   2 KiB buffer size) and transmit (`TCTL` = `0x00000` plus collision
   threshold + back-off settings).
10. Enable interrupts: `IMS` = `RXT0 | TXDW | LSC` (RX timer, TX
    descriptor written-back, Link Status Change).
11. `IrqAttach` for the single MSI-X vector (e1000e exposes one combined
    vector by default; multi-vector is opt-in via the MSI-X capability
    and deferred to a follow-up NCIP).

**S5.2 (Link state).** Polling `STATUS.LU` (Link Up, bit 1 of `0x00008`)
on every `LSC` interrupt; emit `NetEvent::LinkStateChange` accordingly.

### S6. ConnectX specifics (M3)

The Mellanox ConnectX family uses a fundamentally different model
(verbs + Queue Pairs + MAILBOX) and is deferred to a follow-up NCIP under
the same number. The placeholder section here records:

- **PCI matchers**: vendor `0x15B3`, devices `0x1003` (CX3), `0x1015`
  (CX4 Lx), `0x1017` (CX5).
- **Expected MMIO**: BAR0 (CSR) and BAR2 (DOORBELL).
- **Expected complexity**: order of magnitude larger than virtio-net or
  e1000e. The driver effectively reimplements a subset of RDMA Verbs.

M3 is **not delivered with this NCIP**. The placeholder ensures the
manifest schema (S1) and channel ABI (S2-S3) are compatible when M3 is
filed.

### S7. IRQ topology summary

| Family | Vectors | Allocation | Notes |
|---|---|---|---|
| virtio-net | 2 (RX + TX virtqueues) | MSI-X if device implements `VIRTIO_F_MSI_X`; otherwise INTx fallback | INTx fallback shares one line, polled drain |
| e1000e | 1 (combined RX/TX/LSC) | MSI-X by default | Multi-vector deferred |
| ConnectX | TBD (M3) | TBD | TBD |

### S8. Bring-up summary (common steps)

Every driver, after the family-specific bring-up of S4/S5/S6, MUST:

1. Register the NET service channel `nexacore.svc.net.eth<N>`.
2. Register the event channel `nexacore.svc.net.eth<N>.evt`.
3. Emit `NetEvent::MacChanged{mac=<negotiated>}` as the initial event.
4. Emit `NetEvent::LinkStateChange` to reflect current link state.
5. Log `[driver-net] ready eth<N> mac=<mac> link=<up|down> mtu=<mtu>`.

---

## Rationale

### R1. Why phased delivery rather than one nexacorebus driver

A unified driver targeting all three families would be three drivers' code
in one process, only ever exercising the family that matches the present
hardware. Phased delivery:

- Lets M1 ship in 2-4 weeks (QEMU and Proxmox tests cover it).
- Lets M2 ship independently once a bare-metal target is available.
- Defers M3 until server-class hardware is in scope (Phase 3+).
- Each driver has a smaller TCB; the auditor reviews one family at a time.

### R2. Why NET channel is L2 (frames) and not L3 (IP packets)

The mesh protocol (`docs/03-mesh-protocol.md`) operates over a custom
UDP-based transport; the TCP/IP stack lives in user space. If the NET
channel were L3, the driver would need a built-in IP stack — duplicating
the user-space one and blurring layers.

L2 frames keep the driver minimal (no IP parsing) and let any consumer
(TCP/IP service, mesh transport, raw socket diagnostic tool) speak the
same channel.

### R3. Why we expose hardware checksum offload via the manifest

`tx_checksum_offload` / `rx_checksum_offload` are advertised in the
manifest because (a) not all devices support them, (b) the upper-layer
TCP/IP stack needs to know whether to compute checksums in software or
trust the hardware-set flag.

The manifest is read by the file-system service / TCP/IP service at boot
to discover the device's capabilities; no separate query syscall.

### R4. Why a separate event channel (rather than reuse the cmd channel for replies)

Reusing the cmd channel for replies would force a request-response pattern
on a flow-oriented data path (frames arrive at line rate, not in response
to client commands). The event channel is broadcast-fanout: multiple
clients can subscribe (TCP/IP service + tcpdump-equivalent diagnostic +
mesh transport), each filtering for what they care about.

This mirrors the NVMe driver's separation of cmd/evt (`NCIP-Driver-NVMe-014`
§ S2/S3).

### R5. Why MTU is 1500 default and not 9000 jumbo

Jumbo frames require coordination across the whole network path (every
switch and every peer). Defaulting to 1500 ensures compatibility with
arbitrary LAN environments; jumbo is opt-in via the manifest
(`mtu = 9000`) for environments where the operator controls the path.

### R6. What we are NOT doing in this NCIP

- **No Wi-Fi** — deferred to follow-up NCIP (Phase 3+).
- **No multi-queue / RSS** — single RX + single TX ring for v0.3.
- **No SR-IOV** — single PF only.
- **No DPDK-style polled-mode driver** — every driver is IRQ-driven for
  v0.3. Polled mode is a future optimization.
- **No XDP-style in-kernel packet processing** — out of scope for a
  microkernel design.
- **No VLAN offload** — VLAN tags pass through transparently as part of
  the Ethernet frame; the consumer parses them.

---

## Backwards Compatibility

N/A — first introduction of network driver support. No prior NET channel
exists; the framebuffer/serial/PS/2 startup path does not touch network.

The `[net]` manifest table is an additive extension to the NCIP-013
manifest schema, consistent with how `[nvme]` extends it in `NCIP-Driver-NVMe-014`.

---

## Test Cases

### TC1. virtio-net (M1) link up on QEMU

Boot the driver against `qemu-system-x86_64 -device virtio-net-pci,
netdev=user0 -netdev user,id=user0`. Verify the boot log shows
`[driver-net] ready eth0 mac=52:54:00:... link=up mtu=1500`.

### TC2. virtio-net ARP probe round-trip

Test client constructs an Ethernet frame containing an ARP request for
`10.0.2.2` (QEMU user-mode network default gateway). Send via
`NetRequest::SendFrame`. Within 100 ms, the event channel emits a
`NetEvent::FrameReceived` for the ARP reply. Validate the bytes.

### TC3. Frame too large

Test client sends `NetRequest::SendFrame{bytes_len=2000}` with
`mtu=1500`. Expect `NetResponse::FrameTooLarge`.

### TC4. Link down event

Issue `qemu monitor: set_link user0 off`. Within 200 ms, the event
channel emits `NetEvent::LinkStateChange{up=false, ...}`.

### TC5. e1000e (M2) link up on bare metal

Once M2 lands on `feat/kernel-p6-7-driver-e1000e`, validate on Proxmox
the test VM by switching the NIC model: `qemu-system-x86_64 ... -device
e1000e,...`. Verify the same `[driver-net] ready ...` line.

### TC6. ConnectX (M3) — deferred

To be defined when M3 enters scope.

---

## Reference Implementation

N/A at filing time. Phased branches:

- M1: `feat/kernel-p6-7-driver-virtio-net`
- M2: `feat/kernel-p6-7-driver-e1000e`
- M3: `feat/kernel-p6-7-driver-mlx` (post-Phase-1)

Expected new crates:

- `crates/nexacore-driver-net-common/` (new) — `NetRequest`/`NetResponse`/
  `NetEvent` shapes, MAC handling, frame validation.
- `crates/nexacore-driver-virtio-net/` (M1, new) — virtio-net driver.
- `crates/nexacore-driver-e1000e/` (M2, new) — e1000e driver.
- `crates/nexacore-driver-mlx/` (M3, future) — ConnectX driver.

Each driver depends on `nexacore-driver-net-common` for the shared channel
shape and on the NCIP-013 framework syscalls being present in `nexacore-kernel`.

---

## Security Considerations

### SC1. Threat model alignment

- **C-1, C-2** — bounded by NET channel capability gating; only the
  TCP/IP service holds the matching token.
- **C-3 (compromised driver)** — bounded by IOMMU domain (DMA windows
  scoped to driver's pool), capability scope (MmioMap restricted to
  declared BAR ranges).
- **C-5 (compromised hardware)** — partial. A malicious NIC that
  DMA-writes attacker-chosen data into RX buffers is filtered by the
  IOMMU (the buffer is within the driver's IOVA arena, not in kernel
  memory). The malicious data could still poison the TCP/IP stack;
  defense against that is the upper layer's job (encryption,
  authentication of peers).

### SC2. Failure modes

| Failure mode | Mitigation |
|---|---|
| RX buffer pool exhaustion | Driver drops frames, increments counter |
| Malformed inbound frame | Hardware FCS check + driver length validation |
| Link flap storm | Edge-triggered events; client throttles via debouncing |
| Promiscuous mode abuse | `SetPromisc` is capability-gated separately |

### SC3. Cryptographic considerations

The network driver does NOT do any cryptography. All encryption (TLS, mesh
Noise handshake, WireGuard-equivalent) happens at higher layers.

---

## Privacy Considerations

### PC1. Personal data flows

The NET driver sees every byte of every frame, both incoming and outgoing.
This is unavoidable for a network driver. Privacy posture:

- All sensitive data on the wire MUST be encrypted by higher layers
  (`docs/03-mesh-protocol.md` mandates this for mesh traffic).
- The NET channel is capability-gated; user processes cannot tap.
- The driver MUST NOT log frame contents. Only counters
  (frames RX/TX, drops, errors) are exposed via a metrics
  channel (TBD in a future NCIP — outside this filing).

### PC2. MAC address as identifier

The MAC address is a stable hardware identifier. Privacy-conscious
operators MAY want randomized MACs (per-boot or per-network). The driver
SHOULD support MAC override via a future capability-gated syscall (TBD);
v0.3 uses the device-burned MAC unchanged.

### PC3. Promiscuous mode

`SetPromisc(on=true)` allows the driver to capture frames not addressed to
its MAC. This is a privacy-sensitive operation; the manifest gates it via
a separate capability bit and the kernel refuses promisc unless the caller
holds `Action::NetPromisc` on the device. (This Action is reserved here;
its formal enumeration is part of `NCIP-Driver-Framework-013` § S1 future
amendment.)

### PC4. GDPR

The driver does not persist data. Logging is counter-only. All GDPR
considerations apply at higher layers.

---

## Appendix A — Bootstrap Activation Note

### A1. Founder fast-path activation (2026-05-20)

This NCIP was filed as `Draft` on 2026-05-20 (same calendar day as
`NCIP-Driver-Framework-013` itself) and promoted directly to `Active` on
the same day under the **Solo Founder Fast-Track** of
`NCIP-Process-001 §5.5`, exercised under the Bootstrap Period authority of
`NCIP-Process-001 §6.3`. The standard 14-day public objection window of
`NCIP-Process-001 §5.3` was waived by explicit founder approval; the
state-machine transitions `Draft → Review → Last Call → Active` collapse
into a single editorial pass with `activated: 2026-05-20` recorded in
the frontmatter.

**Rationale for fast-path:**

1. **Dependency unblock.** `NCIP-013` (the driver framework) is the
   prerequisite (`requires: [13]`) and was itself fast-pathed to
   `Active` on 2026-05-20. Keeping `015` in `Draft` would have stalled
   `P6.7.8` virtio-net (M1) — the first driver implementation deliverable
   for Phase 1 closure — by 14 days for no substantive review benefit.
2. **No deployment risk.** Zero network driver code exists at activation
   time; the reference implementation is `N/A at filing` per `## Reference
   Implementation`. The phased delivery plan (M1=virtio-net, M2=e1000e,
   M3=ConnectX) is purely documentary at this stage.
3. **Scope is bounded.** All normative content is constrained by
   `NCIP-013` (the framework `Active` document) — the manifest schema,
   capability shape, IPC channel grammar, and IRQ routing are inherited.
   This NCIP only adds the network-specific overlay (NET service channel,
   per-family bring-up sequences, L2 Ethernet framing contract).
4. **No conflict with `NCIP-013` Appendix B.** The amendments to NCIP-013
   filed under its Appendix B explicitly state "No follow-up NCIP
   (014/015/016) requires changes" — confirmed by cross-reference audit
   (see NCIP-013 Appendix B trailing list of preserved citations covering
   015:135, 015:227, 015:278).

**Re-ratification obligation:** per `NCIP-Process-001 §5.5.e`, this
activation inherits the **mandatory post-Bootstrap re-ratification**
obligation. When the Bootstrap Period ends (second editor seat filled or
Stichting NexaCore constituted, whichever comes first), this NCIP MUST be
re-ratified by the standard quadratic-vote majority + activation
threshold of `NCIP-Process-001 §7`. Failure to re-ratify reverts the
status to `Withdrawn` and forces a fresh filing.

---

## Copyright

This NCIP is released into the public domain under
[CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
