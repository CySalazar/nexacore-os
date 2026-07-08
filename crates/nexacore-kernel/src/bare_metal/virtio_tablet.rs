//! VirtIO 1.0+ (modern) input tablet driver — absolute-coordinate mouse.
//!
//! Drives the `virtio-tablet-pci` device exposed by QEMU and Proxmox so
//! that absolute VNC coordinates reach the guest as `(abs_x, abs_y)` in
//! the range `[0..=0x7FFF]`, eliminating the cursor drift seen with the
//! PS/2 relative-mouse path.
//!
//! ## Why "modern only"
//!
//! `virtio-input` was introduced in VirtIO 1.0 and QEMU forces the
//! transitional bit off (`virtio_pci_force_virtio_1`). The device exposes
//! its registers via memory-mapped BARs and the configuration layout
//! defined in VirtIO 1.0 §4.1.4. Legacy PIO BAR0 is therefore not
//! supported by the device, so this driver implements the modern PCI
//! transport directly.
//!
//! ## Bring-up flow
//!
//! 1. Scan PCI bus 0 for vendor `0x1AF4` / device `0x1052`.
//! 2. Walk the PCI capability list, picking out the `COMMON_CFG` and
//!    `NOTIFY_CFG` regions (the `ISR` and `DEVICE_CFG` regions are not
//!    needed for our polling driver).
//! 3. Resolve each region's `(BAR, offset)` to a virtual pointer via
//!    `phys_offset + bar_phys + offset`. The bootloader (`bootloader 0.11`
//!    with `Mapping::Dynamic`) maps the full physical address window
//!    including PCI MMIO, so this access succeeds without explicit
//!    page-table additions.
//! 4. Run the modern handshake: `ACK | DRIVER | FEATURES_OK | DRIVER_OK`,
//!    negotiating only `VIRTIO_F_VERSION_1`.
//! 5. Set up queue 0 (the event queue) with our descriptor table, avail
//!    ring, and used ring physical addresses (`queue_desc`,
//!    `queue_driver`, `queue_device`), then write `queue_enable = 1`.
//! 6. Pre-publish 64 device-writable descriptors so the device can start
//!    filling them. Kick once.
//!
//! ## Polling
//!
//! [`VirtioTablet::poll`] drains the used ring, parses each 8-byte input
//! event, re-publishes the descriptor, and returns a [`TabletState`] if a
//! `SYN_REPORT` was seen during the drain.
//!
//! ## Safety invariant
//!
//! The NexaCore OS bare-metal kernel is single-CPU with interrupts masked
//! throughout the demo loop. The static `VIRTIO_MEM` virtqueue buffer is
//! therefore accessed by exactly one path at a time, and no locking is
//! required.

#![allow(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    reason = "VirtIO queue indices are bounded by QCAP (=64); truncation is structurally safe"
)]
#![allow(
    clippy::doc_markdown,
    reason = "module references hex offsets, register names, and PCI vendor IDs without ticks"
)]
#![allow(
    clippy::cast_ptr_alignment,
    reason = "MMIO BAR base + byte offset is naturally aligned per VirtIO 1.0 §4.1.4 layout"
)]
#![allow(
    clippy::ptr_as_ptr,
    reason = "mut/const raw pointer reinterpretation across MMIO regions is idiomatic here"
)]

use core::ptr::{addr_of_mut, read_volatile, write_volatile};

#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
use super::paging::{PTE_PRESENT, PTE_WRITABLE};
use super::{arch, paging::PageMapper};
use crate::memory::{PhysAddr, VirtAddr};

// ─── PCI identifier ──────────────────────────────────────────────────────────

/// PCI ID: vendor `0x1AF4` (Red Hat) + device `0x1052` (`virtio-input`).
const VIRTIO_VENDOR_DEVICE: u32 = 0x1052_1AF4;

/// PCI capability vendor type (vendor-specific). VirtIO config caps share it.
const PCI_CAP_VENDOR_SPECIFIC: u8 = 0x09;

// VirtIO PCI capability `cfg_type` values (VirtIO 1.0 §4.1.4.1).
const CFG_TYPE_COMMON: u8 = 1;
const CFG_TYPE_NOTIFY: u8 = 2;

// Common configuration field offsets (VirtIO 1.0 §4.1.4.3).
const COMMON_DEV_FEAT_SEL: usize = 0;
const COMMON_DEV_FEAT: usize = 4;
const COMMON_DRV_FEAT_SEL: usize = 8;
const COMMON_DRV_FEAT: usize = 12;
const COMMON_DEV_STATUS: usize = 20;
const COMMON_Q_SELECT: usize = 22;
const COMMON_Q_SIZE: usize = 24;
const COMMON_Q_ENABLE: usize = 28;
const COMMON_Q_NOTIFY_OFF: usize = 30;
const COMMON_Q_DESC: usize = 32;
const COMMON_Q_DRIVER: usize = 40;
const COMMON_Q_DEVICE: usize = 48;

// Device status bits.
const S_ACK: u8 = 0x01;
const S_DRV: u8 = 0x02;
const S_DRVRDY: u8 = 0x04;
const S_FEATRDY: u8 = 0x08;

// Linux input event codes.
const EV_SYN: u16 = 0x0000;
const EV_KEY: u16 = 0x0001;
const EV_ABS: u16 = 0x0003;
const ABS_X: u16 = 0x0000;
const ABS_Y: u16 = 0x0001;
const BTN_LEFT: u16 = 0x0110;
const BTN_RIGHT: u16 = 0x0111;
const BTN_MIDDLE: u16 = 0x0112;

// Virtqueue descriptor flag: device writes to buffer (required for event queue).
const VRING_DESC_F_WRITE: u16 = 0x0002;

/// Maximum queue size we will allocate descriptors for.
const QCAP: usize = 64;

// ─── Virtqueue memory layout ────────────────────────────────────────────────
//
// Modern VirtIO does NOT require the desc table, avail ring, and used ring
// to live in contiguous physical memory; each region has its own `queue_*`
// physical-address register. We still place all three regions in a single
// 4 KiB, 4 KiB-aligned static so that one page-table translation gives us
// the physical base of all of them.
//
//   [0..1024)        descriptor table   : 64 × 16 bytes
//   [1024..1156)     avail ring         : flags+idx (4) + ring[64] × 2 (128)
//   [1156..1672)     used ring          : flags+idx (4) + ring[64] × 8 (512)
//   [1672..2184)     event buffers      : 64 × 8 bytes

const OFF_DESC: usize = 0;
const OFF_AVAIL_FLAGS: usize = 1024;
const OFF_AVAIL_IDX: usize = 1026;
const OFF_AVAIL_RING: usize = 1028;
const OFF_USED_FLAGS: usize = 1156;
const OFF_USED_IDX: usize = 1158;
const OFF_USED_RING: usize = 1160;
const OFF_EVENTS: usize = 1672;

/// 4 KiB, 4 KiB-aligned virtqueue backing store.
#[repr(C, align(4096))]
struct VirtioMem([u8; 4096]);

// SAFETY: single-CPU bare-metal kernel; the buffer is written once during
// `try_init` and then read/written exclusively by `poll`. No race possible.
static mut VIRTIO_MEM: VirtioMem = VirtioMem([0u8; 4096]);

// ─── Volatile MMIO and virtqueue accessors ──────────────────────────────────

#[inline]
unsafe fn rd8(ptr: *const u8) -> u8 {
    unsafe { read_volatile(ptr) }
}
#[inline]
unsafe fn rd16(ptr: *const u8) -> u16 {
    unsafe { read_volatile(ptr.cast::<u16>()) }
}
#[inline]
unsafe fn rd32(ptr: *const u8) -> u32 {
    unsafe { read_volatile(ptr.cast::<u32>()) }
}
#[inline]
unsafe fn wr8(ptr: *mut u8, v: u8) {
    unsafe { write_volatile(ptr, v) };
}
#[inline]
unsafe fn wr16(ptr: *mut u8, v: u16) {
    unsafe { write_volatile(ptr.cast::<u16>(), v) };
}
#[inline]
unsafe fn wr32(ptr: *mut u8, v: u32) {
    unsafe { write_volatile(ptr.cast::<u32>(), v) };
}
#[inline]
unsafe fn wr64(ptr: *mut u8, v: u64) {
    unsafe { write_volatile(ptr.cast::<u64>(), v) };
}

// ─── PCI capability list walker ─────────────────────────────────────────────

/// A located VirtIO MMIO region (one for `COMMON_CFG`, one for `NOTIFY_CFG`).
#[derive(Clone, Copy)]
struct CapRegion {
    /// Virtual base of the region.
    base: *mut u8,
    /// For `NOTIFY_CFG`, the per-queue notify-offset multiplier.
    notify_off_multiplier: u32,
}

/// Read a single byte from PCI config space, via the dword-granular helper.
unsafe fn pci_cfg_read8(bus: u8, dev: u8, func: u8, off: u8) -> u8 {
    let dword = unsafe { arch::pci_cfg_read32(bus, dev, func, off & 0xFC) };
    ((dword >> ((off & 3) * 8)) & 0xFF) as u8
}

/// Read a 16-bit half-word from PCI config space.
unsafe fn pci_cfg_read16(bus: u8, dev: u8, func: u8, off: u8) -> u16 {
    let dword = unsafe { arch::pci_cfg_read32(bus, dev, func, off & 0xFC) };
    ((dword >> ((off & 2) * 8)) & 0xFFFF) as u16
}

/// Read a memory BAR (32-bit or 64-bit) from PCI config space.
///
/// Returns `(base, is_64bit)`. The base has the low 4 flag bits masked off.
/// Returns `None` if the BAR is I/O space (bit 0 set) — the caller should
/// skip the BAR and continue.
unsafe fn read_bar(bus: u8, dev: u8, bar_idx: u8) -> Option<u64> {
    let off = 0x10 + bar_idx * 4;
    let low = unsafe { arch::pci_cfg_read32(bus, dev, 0, off) };
    if low & 1 != 0 {
        return None; // I/O space BAR
    }
    let is_64 = (low & 0b0110) == 0b0100;
    let base_low = u64::from(low & 0xFFFF_FFF0);
    let base = if is_64 {
        let high = unsafe { arch::pci_cfg_read32(bus, dev, 0, off + 4) };
        base_low | (u64::from(high) << 32)
    } else {
        base_low
    };
    Some(base)
}

/// Walk the PCI capability list and locate the `COMMON_CFG` and `NOTIFY_CFG`
/// regions, returning them resolved to virtual pointers.
///
/// Each VirtIO PCI capability has this layout (VirtIO 1.0 §4.1.4):
///
/// | Offset | Width | Field                  |
/// |--------|-------|------------------------|
/// | 0      | u8    | `cap_vndr` (`0x09`)    |
/// | 1      | u8    | `cap_next`             |
/// | 2      | u8    | `cap_len`              |
/// | 3      | u8    | `cfg_type`             |
/// | 4      | u8    | `bar`                  |
/// | 5      | u8\[3\] | padding              |
/// | 8      | u32   | `offset`               |
/// | 12     | u32   | `length`               |
/// | 16     | u32   | `notify_off_multiplier` (NOTIFY_CFG only) |
unsafe fn find_caps(bus: u8, dev: u8, phys_offset: u64) -> Option<(CapRegion, CapRegion)> {
    // Verify the device has a capability list (Status reg bit 4).
    let status = unsafe { pci_cfg_read16(bus, dev, 0, 0x06) };
    if status & (1 << 4) == 0 {
        return None;
    }

    let mut cap_off = unsafe { pci_cfg_read8(bus, dev, 0, 0x34) } & 0xFC;
    let mut common: Option<CapRegion> = None;
    let mut notify: Option<CapRegion> = None;

    // Walk the linked list. Cap of 0 terminates. We cap iterations at 48 to
    // avoid spinning on a malformed list.
    for _ in 0..48 {
        if cap_off == 0 {
            break;
        }
        let cap_id = unsafe { pci_cfg_read8(bus, dev, 0, cap_off) };
        let cap_next = unsafe { pci_cfg_read8(bus, dev, 0, cap_off + 1) };

        if cap_id == PCI_CAP_VENDOR_SPECIFIC {
            let cfg_type = unsafe { pci_cfg_read8(bus, dev, 0, cap_off + 3) };
            let bar_idx = unsafe { pci_cfg_read8(bus, dev, 0, cap_off + 4) };
            // `offset` (u32 at cap_off + 8) and `length` (u32 at cap_off + 12)
            // — the helper reads aligned dwords directly.
            let off32 = unsafe { arch::pci_cfg_read32(bus, dev, 0, cap_off + 8) };

            let bar_base = unsafe { read_bar(bus, dev, bar_idx) }?;
            let virt = phys_offset
                .wrapping_add(bar_base)
                .wrapping_add(u64::from(off32)) as *mut u8;

            match cfg_type {
                CFG_TYPE_COMMON => {
                    common = Some(CapRegion {
                        base: virt,
                        notify_off_multiplier: 0,
                    });
                }
                CFG_TYPE_NOTIFY => {
                    let mult = unsafe { arch::pci_cfg_read32(bus, dev, 0, cap_off + 16) };
                    notify = Some(CapRegion {
                        base: virt,
                        notify_off_multiplier: mult,
                    });
                }
                _ => {} // ignore ISR, DEVICE_CFG, PCI_CFG
            }
        }

        cap_off = cap_next & 0xFC;
    }

    match (common, notify) {
        (Some(c), Some(n)) => Some((c, n)),
        _ => None,
    }
}

// ─── Public types ────────────────────────────────────────────────────────────

/// A single batched tablet event, emitted on `SYN_REPORT`.
pub struct TabletState {
    /// Absolute X coordinate, range `[0..=0x7FFF]`.
    pub abs_x: u32,
    /// Absolute Y coordinate, range `[0..=0x7FFF]`.
    pub abs_y: u32,
    /// Button mask: bit 0 = left, bit 1 = right, bit 2 = middle.
    pub buttons: u8,
}

/// VirtIO modern input tablet driver state.
pub struct VirtioTablet {
    notify_addr: *mut u8,
    mem_virt: *mut u8,
    avail_prod: u16,
    last_used_idx: u16,
    pending_x: u32,
    pending_y: u32,
    pending_buttons: u8,
    queue_n: usize,
}

impl VirtioTablet {
    /// Scan PCI bus 0 for a modern VirtIO input device and initialise its
    /// event virtqueue. Returns `None` if no device is present or if
    /// initialisation fails at any step.
    ///
    /// # Safety
    ///
    /// - Must be called at most once, before any other access to the static
    ///   `VIRTIO_MEM` buffer.
    /// - `phys_offset` must equal `BootInfo.physical_memory_offset`. The
    ///   driver dereferences MMIO at `phys_offset + bar_phys + cap_off` and
    ///   relies on the bootloader's full-address-space mapping to make those
    ///   pointers valid. It also walks page tables to translate the static's
    ///   virtual address into a physical DMA address.
    /// - Caller is ring 0 with interrupts disabled (the single-core
    ///   invariant shared with the rest of the bare-metal kernel).
    #[allow(
        clippy::too_many_lines,
        reason = "VirtIO 1.0 init handshake is intentionally inlined as a single \
                  sequential transaction — splitting it would obscure the strict \
                  ordering required by the spec (reset → ACK → DRV → feat → \
                  FEATRDY → queue setup → DRVRDY)"
    )]
    pub unsafe fn try_init(phys_offset: u64) -> Option<Self> {
        // ── 1. PCI scan bus 0 for vendor:device ──
        let (bus, dev) = {
            let mut found: Option<(u8, u8)> = None;
            for d in 0_u8..32 {
                let id = unsafe { arch::pci_cfg_read32(0, d, 0, 0x00) };
                if id == VIRTIO_VENDOR_DEVICE {
                    found = Some((0, d));
                    break;
                }
            }
            found?
        };

        // ── 2. Enable Bus Master + Memory Space in the PCI command register ──
        // QEMU may leave Memory Space Enable off until the driver sets it. We
        // also enable Bus Master so the device can DMA into our queue memory.
        let cmd = unsafe { pci_cfg_read16(bus, dev, 0, 0x04) };
        let new_cmd = cmd | 0x0006; // MSE (bit 1) | BME (bit 2)
        if new_cmd != cmd {
            // Writing PCI cmd needs a dword RMW. We don't have pci_cfg_write32
            // in the kernel; the existing pci_cfg_write8 helper only writes 1
            // byte. Two writes cover the 16-bit command register.
            unsafe {
                // SAFETY: the writes target the standard PCI command register
                // at offsets 0x04 and 0x05, which is always safe to drive.
                pci_cfg_write_byte(bus, dev, 0x04, (new_cmd & 0xFF) as u8);
                pci_cfg_write_byte(bus, dev, 0x05, (new_cmd >> 8) as u8);
            }
        }

        // ── 3. Locate COMMON_CFG and NOTIFY_CFG via the PCI cap list ──
        let (common, notify) = unsafe { find_caps(bus, dev, phys_offset) }?;

        // ── 3.b. Ensure the BAR pages are mapped in the active CR3.
        //
        // The bootloader 0.11 `physical_memory` direct map only spans the
        // physical RAM regions reported as `MemoryRegionKind::Usable` by
        // UEFI — typically up to ~4 GiB on a Proxmox q35 VM. PCI BARs for
        // VirtIO devices in q35 are 64-bit prefetchable and OVMF places
        // them well above the RAM ceiling (≈ 60 GiB on the dev VM). The
        // VA `phys_offset + bar_phys + cap_off` returned by `find_caps`
        // therefore lands in a PML4 entry that the bootloader never
        // touched, and the first MMIO write would #PF.
        //
        // Fix: explicitly walk the active page tables and install the 4
        // KiB frame containing each cap region's `base`. Idempotent —
        // `ensure_mmio_page_mapped` skips when the VA already translates.
        // Failing to map is fatal for the tablet path (we fall back to
        // PS/2 input), but never poisons the page tables — `map_4k`
        // returns `false` on its own preconditions without partial
        // writes.
        if !unsafe { ensure_mmio_page_mapped(common.base as u64, phys_offset) } {
            return None;
        }
        if !unsafe { ensure_mmio_page_mapped(notify.base as u64, phys_offset) } {
            return None;
        }

        // ── 4. Translate VIRTIO_MEM virtual → physical via page tables ──
        let mem_virt = addr_of_mut!(VIRTIO_MEM) as *mut u8;
        let cr3_raw = arch::read_cr3();
        let mapper = PageMapper::new(phys_offset, PhysAddr(cr3_raw & !0xFFF));
        let mem_phys = mapper.translate(VirtAddr(mem_virt as u64))?.0;

        // ── 5. Reset + minimum status handshake ──
        unsafe {
            wr8(common.base.add(COMMON_DEV_STATUS), 0);
            // Wait for the device to acknowledge reset by reading status as 0.
            for _ in 0..100_000 {
                if rd8(common.base.add(COMMON_DEV_STATUS)) == 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            wr8(common.base.add(COMMON_DEV_STATUS), S_ACK);
            wr8(common.base.add(COMMON_DEV_STATUS), S_ACK | S_DRV);

            // ── 6. Feature negotiation: accept only VIRTIO_F_VERSION_1 ──
            // Read low 32 bits (feature_select = 0).
            wr32(common.base.add(COMMON_DEV_FEAT_SEL), 0);
            let _low = rd32(common.base.add(COMMON_DEV_FEAT));
            // Read high 32 bits (feature_select = 1) — must include bit 32
            // (VIRTIO_F_VERSION_1, encoded as bit 0 in the high dword).
            wr32(common.base.add(COMMON_DEV_FEAT_SEL), 1);
            let high = rd32(common.base.add(COMMON_DEV_FEAT));
            if high & 1 == 0 {
                return None; // device doesn't claim VirtIO 1.0
            }
            // Write back: accept VIRTIO_F_VERSION_1 only.
            wr32(common.base.add(COMMON_DRV_FEAT_SEL), 0);
            wr32(common.base.add(COMMON_DRV_FEAT), 0);
            wr32(common.base.add(COMMON_DRV_FEAT_SEL), 1);
            wr32(common.base.add(COMMON_DRV_FEAT), 1);

            // ── 7. FEATURES_OK and verify it stuck ──
            wr8(
                common.base.add(COMMON_DEV_STATUS),
                S_ACK | S_DRV | S_FEATRDY,
            );
            if rd8(common.base.add(COMMON_DEV_STATUS)) & S_FEATRDY == 0 {
                return None; // device rejected our feature subset
            }

            // ── 8. Configure queue 0 (the event queue) ──
            wr16(common.base.add(COMMON_Q_SELECT), 0);
            let max_size = rd16(common.base.add(COMMON_Q_SIZE)) as usize;
            if max_size == 0 {
                return None;
            }
            let n = max_size.min(QCAP);
            wr16(common.base.add(COMMON_Q_SIZE), n as u16);

            // Write physical addresses for desc / avail / used regions.
            let q_desc = mem_phys + OFF_DESC as u64;
            let q_driver = mem_phys + OFF_AVAIL_FLAGS as u64;
            let q_device = mem_phys + OFF_USED_FLAGS as u64;
            wr64(common.base.add(COMMON_Q_DESC), q_desc);
            wr64(common.base.add(COMMON_Q_DRIVER), q_driver);
            wr64(common.base.add(COMMON_Q_DEVICE), q_device);

            // Per-queue notify offset.
            let q_notify_off = rd16(common.base.add(COMMON_Q_NOTIFY_OFF));
            let notify_addr = notify
                .base
                .add((u32::from(q_notify_off) * notify.notify_off_multiplier) as usize);

            // ── 9. Build descriptor table: every entry points to a fresh
            //       8-byte event buffer, device-writable, no chaining. ──
            for i in 0..n {
                let event_phys = mem_phys + OFF_EVENTS as u64 + (i as u64) * 8;
                let desc = mem_virt.add(OFF_DESC + i * 16);
                wr64(desc, event_phys);
                wr32(desc.add(8), 8);
                wr16(desc.add(12), VRING_DESC_F_WRITE);
                wr16(desc.add(14), 0);
            }

            // ── 10. Pre-publish all descriptors in the available ring. ──
            wr16(mem_virt.add(OFF_AVAIL_FLAGS), 0);
            for i in 0..n {
                wr16(mem_virt.add(OFF_AVAIL_RING + i * 2), i as u16);
            }
            wr16(mem_virt.add(OFF_AVAIL_IDX), n as u16);

            // ── 11. Enable the queue ──
            wr16(common.base.add(COMMON_Q_ENABLE), 1);

            // ── 12. DRIVER_OK + initial kick ──
            wr8(
                common.base.add(COMMON_DEV_STATUS),
                S_ACK | S_DRV | S_FEATRDY | S_DRVRDY,
            );
            wr16(notify_addr, 0);

            Some(Self {
                notify_addr,
                mem_virt,
                avail_prod: n as u16,
                last_used_idx: 0,
                pending_x: 0,
                pending_y: 0,
                pending_buttons: 0,
                queue_n: n,
            })
        }
    }

    /// Drain pending events from the used ring, replenishing descriptors as
    /// we go. Returns `Some(state)` if a `SYN_REPORT` was seen during this
    /// call (one batched x/y/buttons update); `None` otherwise.
    pub fn poll(&mut self) -> Option<TabletState> {
        let mem = self.mem_virt;
        let mem_ro = mem.cast_const();

        // SAFETY: `mem` is the kernel's own VIRTIO_MEM static; the single-CPU
        // invariant guarantees no concurrent access.
        let current_used = unsafe { rd16(mem_ro.add(OFF_USED_IDX)) };
        if current_used == self.last_used_idx {
            return None;
        }

        let mut emit: Option<TabletState> = None;

        while self.last_used_idx != current_used {
            let slot = (self.last_used_idx as usize) % self.queue_n;
            // Used ring entry layout: id u32, len u32.
            let entry = unsafe { mem_ro.add(OFF_USED_RING + slot * 8) };
            let desc_id = unsafe { rd32(entry) } as usize;
            let did = desc_id % self.queue_n;
            let ev = unsafe { mem_ro.add(OFF_EVENTS + did * 8) };

            let ev_type = unsafe { rd16(ev) };
            let ev_code = unsafe { rd16(ev.add(2)) };
            let ev_value = unsafe { rd32(ev.add(4)) };

            match (ev_type, ev_code) {
                (EV_ABS, ABS_X) => self.pending_x = ev_value,
                (EV_ABS, ABS_Y) => self.pending_y = ev_value,
                (EV_KEY, BTN_LEFT) => self.set_button(0x01, ev_value != 0),
                (EV_KEY, BTN_RIGHT) => self.set_button(0x02, ev_value != 0),
                (EV_KEY, BTN_MIDDLE) => self.set_button(0x04, ev_value != 0),
                (EV_SYN, _) => {
                    emit = Some(TabletState {
                        abs_x: self.pending_x,
                        abs_y: self.pending_y,
                        buttons: self.pending_buttons,
                    });
                }
                _ => {}
            }

            // Re-publish the descriptor so the device can refill it.
            let avail_slot = (self.avail_prod as usize) % self.queue_n;
            // SAFETY: as above.
            unsafe {
                wr16(mem.add(OFF_AVAIL_RING + avail_slot * 2), did as u16);
            }
            self.avail_prod = self.avail_prod.wrapping_add(1);
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
        }

        // Single batched avail-idx publish + single kick per drain.
        // SAFETY: as above.
        unsafe { wr16(mem.add(OFF_AVAIL_IDX), self.avail_prod) };
        // SAFETY: notify_addr is a writable MMIO pointer registered by the
        // device's NOTIFY_CFG capability; written by spec to signal queue 0.
        unsafe { wr16(self.notify_addr, 0) };

        emit
    }

    #[inline]
    fn set_button(&mut self, mask: u8, pressed: bool) {
        if pressed {
            self.pending_buttons |= mask;
        } else {
            self.pending_buttons &= !mask;
        }
    }
}

// ─── PCI config-space byte write (not exposed by `arch`) ────────────────────

/// Write a single byte to PCI configuration space. The kernel's existing
/// `pci_cfg_write8` helper in `arch::x86_64` is private; we re-implement it
/// here to keep the VirtIO driver self-contained and to avoid changing the
/// `arch` module's stable surface for a single one-shot use.
///
/// # Safety
///
/// Ring 0 only. The caller must point at a valid `(bus, dev, offset)`
/// triple in PCI configuration space; writes have device-defined side
/// effects.
unsafe fn pci_cfg_write_byte(bus: u8, dev: u8, off: u8, val: u8) {
    let addr: u32 =
        0x8000_0000 | (u32::from(bus) << 16) | (u32::from(dev) << 11) | u32::from(off & 0xFC);
    unsafe {
        arch::outl(0xCF8, addr);
        arch::outb(0xCFC + u16::from(off & 3), val);
    }
}

// ─── Explicit MMIO mapping for BARs outside the bootloader direct map ───────

/// Ensure the 4 KiB page containing `mmio_virt` is mapped in the active CR3.
///
/// `mmio_virt` is the virtual address that `find_caps` derived from
/// `phys_offset + bar_phys + cap_off`. Bootloader 0.11's `physical_memory`
/// direct map only spans `MemoryRegionKind::Usable` regions reported by
/// UEFI (typically up to RAM ceiling, ≈ 4 GiB on Proxmox q35 with 4 GiB
/// of RAM). 64-bit prefetchable PCI BARs sit well above the RAM ceiling
/// (≈ 60 GiB on the dev VM), so the VA arithmetic lands in a PML4 entry
/// that the bootloader never populated and the first MMIO write would
/// page-fault.
///
/// This helper subtracts `phys_offset` back out to recover the BAR's
/// physical frame and installs a single 4 KiB mapping in the BSP's CR3
/// via [`PageMapper::map_4k`]. The mapping uses
/// `PTE_PRESENT | PTE_WRITABLE`; MMIO caching attributes (PCD/PWT) are
/// deferred — write-back caching is harmless on a small, polled,
/// non-prefetchable VirtIO config region (and the BAR's BAR flags
/// already advertise the prefetchability mode to the platform). A
/// follow-up driver framework will add an MMIO-aware allocator that
/// pins PCD/PWT for true device memory.
///
/// Returns `true` if the page is now mapped (either already was, or
/// was successfully installed), `false` on allocator exhaustion for an
/// intermediate page-table frame.
///
/// # Safety
///
/// - Ring 0, single-CPU bare-metal call site (matches the rest of the
///   VirtIO driver's invariants).
/// - The caller must have access to the global static
///   `crate::FRAME_ALLOC` (the boot-time bitmap frame allocator), which
///   this helper drives via `addr_of_mut!`. No other path concurrently
///   mutates that allocator at the time `try_init` runs (it is invoked
///   from `kmain` after `register_direct_mapped_regions` and before any
///   user-space process is spawned).
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
unsafe fn ensure_mmio_page_mapped(mmio_virt: u64, phys_offset: u64) -> bool {
    let virt_page = mmio_virt & !0xFFF;
    let cr3_raw = arch::read_cr3();
    let mut mapper = PageMapper::new(phys_offset, PhysAddr(cr3_raw & !0xFFF));

    // Fast path: bootloader already mapped this page (e.g. low-memory
    // 32-bit BAR inside the RAM ceiling). Nothing to do.
    if mapper.translate(VirtAddr(virt_page)).is_some() {
        return true;
    }

    // Recover the BAR's physical frame by reversing the
    // `phys_offset + bar_phys + cap_off` arithmetic that `find_caps`
    // applied: stripping `phys_offset` from the page-aligned VA yields
    // the page-aligned physical frame.
    let phys_page = virt_page.wrapping_sub(phys_offset) & !0xFFF;

    // SAFETY: see helper-level Safety section. `crate::FRAME_ALLOC` is
    // a single-CPU static-mut owned by `kmain`; the demo loop runs
    // sequentially after init and `try_init` is the first MMIO
    // consumer. Aliasing-free at this point.
    let alloc = unsafe { &mut *addr_of_mut!(crate::FRAME_ALLOC) };
    mapper.map_4k(
        VirtAddr(virt_page),
        PhysAddr(phys_page),
        PTE_PRESENT | PTE_WRITABLE,
        alloc,
    )
}

/// Host-target stub: the bare-metal `FRAME_ALLOC` does not exist outside the
/// kernel binary, and on host targets `try_init` never reaches a real MMIO
/// device anyway (the `arch::pci_cfg_*` helpers are no-op stubs). Returning
/// `true` keeps the call-site `if !ensure_mmio_page_mapped(...) { return None }`
/// shape identical between targets while letting the host-side fault-path
/// surface as `None` further upstream — `pci_cfg_read32` returns 0, the PCI
/// scan misses the VirtIO vendor:device pair and `try_init` shorts out before
/// any of the MMIO writes the mapping was meant to enable.
#[cfg(not(all(feature = "bare-metal", target_os = "none", not(test))))]
unsafe fn ensure_mmio_page_mapped(_mmio_virt: u64, _phys_offset: u64) -> bool {
    true
}
