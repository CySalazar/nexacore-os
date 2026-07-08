//! Capability deposit trampoline (P6.7.8.9, `NCIP-013` § S5.3 step 8).
//!
//! At `DriverLoad`, after the NexaCore-Pack signature + image hash chain
//! pass, the kernel mints attenuated [`CapabilityToken`]s for every
//! capability declared in the driver's manifest and pre-installs them
//! in a read-only page at a well-known user-VA slot in the new driver
//! process's address space. This module owns:
//!
//! 1. The wire layout of the deposit page (header + indexed entry
//!    table + packed postcard token blobs).
//! 2. The token-minting helper that uses the kernel signing key
//!    ([`crate::driver_cap_issuer::kernel_signing_key`]) plus
//!    fresh `CapabilityId` randomness from [`crate::entropy`].
//! 3. The address-space wiring that allocates the deposit pages,
//!    populates them, and maps them into the driver AS.
//!
//! ## Why a fixed binary layout?
//!
//! The driver runtime cannot afford to deserialize the entire deposit
//! with `postcard::take_from_bytes` — that would mean linking the
//! capability crate into every driver's `#![no_std]` shim plus paying
//! a few KiB of code size. Instead the deposit uses a flat indexed
//! layout (`OMNICAPS` magic + `u32` version + `u32` count + a `[u8; 16]`
//! entry-descriptor array + packed token blobs): the driver shim does
//! one cast-and-bounds-check per lookup, and only the token bytes it
//! actually presents to a syscall are postcard-decoded on the kernel
//! side via the existing `MmioMap` / `DmaMap` / `IrqAttach` paths.
//!
//! ## Why not use the `nexacore-capability/mint` feature?
//!
//! See [`crate::entropy`] module docs. The kernel constructs
//! [`TokenPayload`] directly and signs via
//! [`nexacore_capability::CapabilityToken::sign_payload`], bypassing the
//! `mint`-feature path that would pull `getrandom` on `x86_64-unknown-
//! none`.

#![allow(
    unsafe_code,
    reason = "host-side encoder is fully safe; the bare-metal map path uses one unsafe pointer write per page covered by SAFETY notes."
)]

use alloc::vec::Vec;

use nexacore_capability::{
    Action, Resource, Scope, TimeWindow,
    token::{CapabilityToken, TokenPayload},
};
use nexacore_types::identity::{CapabilityId, NodeId};

use crate::{driver_cap_issuer::kernel_signing_key, driver_manifest::DriverCapabilities, entropy};

// =============================================================================
// Constants — wire format
// =============================================================================

/// Well-known user-VA base where the deposit page batch is mapped.
///
/// 1 MiB — below the ELF default load address (`0x40_0000`), above
/// the conventional NULL guard region (`0..0x1000`), and disjoint
/// from the user stack (`0x0000_0040_0000_0000`) and the driver MMIO
/// PML4 slot (`0x0000_0080_0000_0000..0x0000_0100_0000_0000`).
pub const DRIVER_CAP_DEPOSIT_VA: u64 = 0x0000_0000_0010_0000;

/// Total deposit window length in bytes.
///
/// 8 × 4 KiB pages. Sized to comfortably hold up to [`MAX_ENTRIES`]
/// postcard-encoded [`CapabilityToken`]s (~150 byte each in the worst
/// case) plus the header.
pub const DRIVER_CAP_DEPOSIT_LEN: usize = 8 * 0x1000;

/// Number of 4 KiB pages covered by the deposit window.
///
/// Used by the bare-metal mapper to iterate page-by-page. The
/// `>> 12` (rather than `/ 0x1000`) keeps clippy's `integer_division`
/// happy without obscuring the meaning.
pub const DRIVER_CAP_DEPOSIT_PAGES: usize = DRIVER_CAP_DEPOSIT_LEN >> 12;

/// 8-byte magic at offset 0 of the deposit page.
///
/// Drivers ASCII-check this on `_start` before trusting any other
/// byte in the window.
pub const DEPOSIT_MAGIC: [u8; 8] = *b"OMNICAPS";

/// Wire-format version.
///
/// Bump under a follow-up NCIP if the entry descriptor layout changes.
pub const DEPOSIT_VERSION: u32 = 1;

/// Maximum number of capability entries the deposit can carry.
///
/// 64 covers the worst-case driver manifests planned for Phase 1
/// (`NCIP-Driver-Net-015` M3 `ConnectX`, `NCIP-Driver-NVMe-014`).
pub const MAX_ENTRIES: usize = 64;

/// Size of the fixed deposit header (magic + version + count).
const HEADER_LEN: usize = 8 + 4 + 4;

/// Size of each entry descriptor in the indexed table.
const ENTRY_DESCRIPTOR_LEN: usize = 4 + 4 + 4 + 4;

/// Lifetime of a deposited token: 90 days in seconds.
pub const DEPOSIT_TOKEN_LIFETIME_SECONDS: u64 = 90 * 24 * 3600;

// -----------------------------------------------------------------------------
// Device-info section (M0 Phase 3) — virtio modern geometry hand-off.
// -----------------------------------------------------------------------------
//
// A Ring-3 driver image cannot read PCI config space or do I/O-port, so it
// cannot discover a firmware-assigned BAR4 physical base or the modern-virtio
// register offsets on its own. The kernel discovers them (see
// `pci_scan::parse_virtio_modern_caps`) and hands them across in a fixed-offset
// section near the END of the deposit window, well clear of the token blobs
// (which live just after the header from the front and total ≲ 10 KiB). This
// keeps the token layout byte-for-byte unchanged: when no device info is
// supplied the section bytes stay zero and the image reads "absent" via a magic
// mismatch. Mirrored byte-for-byte in `nexacore-driver-shared`.

/// Byte offset of the device-info section within the deposit window (page 7).
pub const DEVICE_INFO_OFFSET: usize = 0x7000;
/// 4-byte magic at the start of the device-info section.
pub const DEVICE_INFO_MAGIC: [u8; 4] = *b"VDEV";
/// Device-info section wire-format version.
pub const DEVICE_INFO_VERSION: u32 = 1;

/// Modern-virtio register geometry handed to a Ring-3 driver image.
///
/// All offsets are byte offsets WITHIN the MMIO window that begins at
/// `bar_phys` (which the image `MmioMap`s for `mmio_len` bytes). The notify
/// doorbell for a queue is `notify_offset + queue_notify_off * notify_off_multiplier`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioDeviceInfo {
    /// Physical base of the modern-virtio BAR (firmware-assigned BAR4).
    pub bar_phys: u64,
    /// Total bytes of the BAR window the image should `MmioMap`.
    pub mmio_len: u32,
    /// Offset of the `common_cfg` structure within the BAR.
    pub common_offset: u32,
    /// Offset of the `notify` structure within the BAR.
    pub notify_offset: u32,
    /// Offset of the `isr` structure within the BAR.
    pub isr_offset: u32,
    /// Offset of the device-specific config (MAC …) within the BAR.
    pub device_offset: u32,
    /// `notify_off_multiplier` from the notify capability.
    pub notify_off_multiplier: u32,
}

// -----------------------------------------------------------------------------
// Action / Resource discriminator tags (wire-format).
// -----------------------------------------------------------------------------

/// `Action::MmioMap` tag.
pub const ACTION_TAG_MMIO_MAP: u32 = 1;
/// `Action::DmaMap` tag.
pub const ACTION_TAG_DMA_MAP: u32 = 2;
/// `Action::IrqAttach` tag.
pub const ACTION_TAG_IRQ_ATTACH: u32 = 3;
/// `Action::PciConfigRead` tag.
pub const ACTION_TAG_PCI_CFG_READ: u32 = 4;
/// `Action::PciConfigWrite` tag.
pub const ACTION_TAG_PCI_CFG_WRITE: u32 = 5;
/// `Action::IpcSend` tag (TASK-14, ADR-0036 D6): lets the kernel deposit
/// an IPC-send capability to a NON-driver task (the block-service client
/// / future filesystem) so it can pass the `BlkLookup` gate.
pub const ACTION_TAG_IPC_SEND: u32 = 6;
/// `Action::DisplayMap` tag (TASK-18, ADR-0040 D3): deposited to the
/// Ring-3 compositor / display probe so it can call `DisplayMap (79)`.
pub const ACTION_TAG_DISPLAY_MAP: u32 = 7;

/// `Resource::MmioRegion { .. }` tag.
pub const RESOURCE_TAG_MMIO_REGION: u32 = 1;
/// `Resource::DmaWindow { .. }` tag.
pub const RESOURCE_TAG_DMA_WINDOW: u32 = 2;
/// `Resource::IrqLine(_)` tag.
pub const RESOURCE_TAG_IRQ_LINE: u32 = 3;
/// `Resource::PciDevice { .. }` tag.
pub const RESOURCE_TAG_PCI_DEVICE: u32 = 4;
/// `Resource::Any` tag.
pub const RESOURCE_TAG_ANY: u32 = 5;
/// `Resource::IpcChannel(_)` tag (TASK-14, ADR-0036 D6).
pub const RESOURCE_TAG_IPC_CHANNEL: u32 = 6;
/// `Resource::Framebuffer { .. }` tag (TASK-18, ADR-0040 D3): the whole
/// GOP framebuffer region deposited to the Ring-3 display probe /
/// compositor.
pub const RESOURCE_TAG_FRAMEBUFFER: u32 = 7;

// =============================================================================
// Error types
// =============================================================================

/// Errors produced by [`encode_deposit_page`] and [`deposit_for_driver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositError {
    /// More than [`MAX_ENTRIES`] capabilities requested in the manifest.
    TokenCountExceeded {
        /// Number of entries the manifest asked for.
        requested: usize,
    },
    /// Canonical postcard encoding of a [`CapabilityToken`] failed.
    /// In practice this only happens on out-of-memory.
    TokenEncodingFailed,
    /// Token signing failed (the canonical payload encoding step
    /// inside [`CapabilityToken::sign_payload`] returned an error).
    TokenSigningFailed,
    /// The encoded deposit overflowed [`DRIVER_CAP_DEPOSIT_LEN`].
    /// Indicates an unusually large token (e.g. caveat-heavy parent
    /// scope) — the caller should split the manifest.
    ScopeBytesOverflow {
        /// Bytes required to hold the encoded deposit.
        required: usize,
    },
    /// `AddressSpace::map_user_4k` returned `false` for one of the
    /// deposit pages. Frame allocator most likely exhausted.
    #[cfg(feature = "bare-metal")]
    MapFailed,
    /// Host-side stub when [`deposit_for_driver`] is invoked outside
    /// a bare-metal build. Returned in lieu of a panic so unit tests
    /// can exercise the encoding side without needing a real AS.
    #[cfg(not(feature = "bare-metal"))]
    HostStub,
}

// =============================================================================
// Encoding — pure function, no side effects
// =============================================================================

/// Build the byte layout of the deposit page for `caps` at boot time
/// `boot_seconds`. The kernel signing key is used to sign each token.
///
/// Returns a `Vec<u8>` of length ≤ [`DRIVER_CAP_DEPOSIT_LEN`] padded
/// with zeros to the next 4 KiB boundary. The caller is responsible
/// for `copy_nonoverlapping` into the mapped driver page(s).
///
/// # Errors
///
/// - [`DepositError::TokenCountExceeded`] — more than
///   [`MAX_ENTRIES`] entries requested.
/// - [`DepositError::TokenSigningFailed`] — canonical encoding of a
///   token payload failed (out-of-memory only).
/// - [`DepositError::TokenEncodingFailed`] — re-encoding the signed
///   token failed.
/// - [`DepositError::ScopeBytesOverflow`] — total encoded size
///   exceeds [`DRIVER_CAP_DEPOSIT_LEN`].
pub fn encode_deposit_page(
    caps: &DriverCapabilities,
    boot_seconds: u64,
    subject_node_id_bytes: [u8; 32],
) -> Result<Vec<u8>, DepositError> {
    encode_deposit_page_with_device_info(caps, boot_seconds, subject_node_id_bytes, None)
}

/// Encode a deposit page, optionally appending a [`VirtioDeviceInfo`] section.
///
/// Identical to [`encode_deposit_page`] when `device_info` is `None` (the
/// section bytes stay zero, so the token layout is byte-for-byte unchanged).
/// When `Some`, writes the `VDEV` section at [`DEVICE_INFO_OFFSET`] so a Ring-3
/// driver can learn the modern-virtio register geometry it cannot otherwise
/// discover (no PCI-config / I/O-port access from Ring 3).
///
/// # Errors
///
/// Same as [`encode_deposit_page`].
#[allow(
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "encoder writes into a fresh `Vec<u8>` of `DRIVER_CAP_DEPOSIT_LEN` bytes; the \
              cursor / blob walk above each indexed write enforces in-bounds invariants and the \
              `debug_assert!` lines pin them in test builds; the device-info section adds a \
              handful of bounded writes guarded by the SECTION_LEN checks"
)]
pub fn encode_deposit_page_with_device_info(
    caps: &DriverCapabilities,
    boot_seconds: u64,
    subject_node_id_bytes: [u8; 32],
    device_info: Option<VirtioDeviceInfo>,
) -> Result<Vec<u8>, DepositError> {
    let entries = build_entry_list(caps);
    if entries.len() > MAX_ENTRIES {
        return Err(DepositError::TokenCountExceeded {
            requested: entries.len(),
        });
    }

    // Mint + sign each token using the kernel issuer key. The signing
    // key lives on the stack for the duration of this function;
    // `NexaCoreSigningKey` zeroizes on drop.
    let issuer = kernel_signing_key();
    let subject = NodeId::from_attestation_hash(subject_node_id_bytes);
    let window = TimeWindow::new(
        boot_seconds,
        boot_seconds.saturating_add(DEPOSIT_TOKEN_LIFETIME_SECONDS),
    )
    .ok_or(DepositError::TokenSigningFailed)?;

    // Build (action_tag, resource_tag, postcard_token_bytes) triples.
    let mut blobs: Vec<(u32, u32, Vec<u8>)> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let scope = Scope {
            action: entry.action,
            resource: entry.resource.clone(),
            window,
            caveats: Vec::new(),
        };
        let cap_id_bytes = entropy::with_csprng(entropy::KernelCsprng::next_16_bytes);
        let payload = TokenPayload {
            id: CapabilityId::from_bytes(cap_id_bytes),
            subject,
            issuer: issuer.verifying_key(),
            parent: None,
            scope,
        };
        let token = CapabilityToken::sign_payload(&issuer, payload)
            .map_err(|_| DepositError::TokenSigningFailed)?;
        let encoded = nexacore_types::wire::encode_canonical(&token)
            .map_err(|_| DepositError::TokenEncodingFailed)?;
        blobs.push((entry.action_tag, entry.resource_tag, encoded));
    }

    // Compute the final layout offsets up front so we can detect
    // overflow before allocating the output buffer.
    let header_and_table_len = HEADER_LEN + blobs.len() * ENTRY_DESCRIPTOR_LEN;
    // Align each token blob to 8 bytes to keep `token_offset` field
    // suitable for `u32 -> &[u8]` casts in driver shims.
    let mut cursor = align_up(header_and_table_len, 8);
    let mut blob_offsets: Vec<u32> = Vec::with_capacity(blobs.len());
    for (_, _, encoded) in &blobs {
        let off = u32::try_from(cursor).map_err(|_| DepositError::ScopeBytesOverflow {
            required: cursor + encoded.len(),
        })?;
        blob_offsets.push(off);
        cursor = align_up(
            cursor
                .checked_add(encoded.len())
                .ok_or(DepositError::ScopeBytesOverflow {
                    required: usize::MAX,
                })?,
            8,
        );
    }
    if cursor > DRIVER_CAP_DEPOSIT_LEN {
        return Err(DepositError::ScopeBytesOverflow { required: cursor });
    }

    // Allocate output buffer padded to the full window length so the
    // bare-metal copy path can pour it straight into the mapped pages
    // without per-page slicing logic.
    let mut buf = alloc::vec![0u8; DRIVER_CAP_DEPOSIT_LEN];

    // Header.
    debug_assert!(buf.len() >= HEADER_LEN);
    buf[0..8].copy_from_slice(&DEPOSIT_MAGIC);
    buf[8..12].copy_from_slice(&DEPOSIT_VERSION.to_le_bytes());
    let count = u32::try_from(blobs.len()).map_err(|_| DepositError::TokenCountExceeded {
        requested: blobs.len(),
    })?;
    buf[12..16].copy_from_slice(&count.to_le_bytes());

    // Entry descriptor table.
    for (i, (action_tag, resource_tag, encoded)) in blobs.iter().enumerate() {
        let descriptor_base = HEADER_LEN + i * ENTRY_DESCRIPTOR_LEN;
        // Bounds guaranteed by the cursor check above (descriptor_base
        // is inside header_and_table_len, which is ≤ cursor ≤ buf.len()).
        debug_assert!(descriptor_base + ENTRY_DESCRIPTOR_LEN <= buf.len());
        buf[descriptor_base..descriptor_base + 4].copy_from_slice(&action_tag.to_le_bytes());
        buf[descriptor_base + 4..descriptor_base + 8].copy_from_slice(&resource_tag.to_le_bytes());
        let blob_off = *blob_offsets.get(i).unwrap_or(&0);
        let blob_len =
            u32::try_from(encoded.len()).map_err(|_| DepositError::ScopeBytesOverflow {
                required: encoded.len(),
            })?;
        buf[descriptor_base + 8..descriptor_base + 12].copy_from_slice(&blob_off.to_le_bytes());
        buf[descriptor_base + 12..descriptor_base + 16].copy_from_slice(&blob_len.to_le_bytes());
    }

    // Pack the token blobs.
    for (i, (_, _, encoded)) in blobs.iter().enumerate() {
        let off = *blob_offsets.get(i).unwrap_or(&0) as usize;
        // CRITICAL boundary: re-check that off + encoded.len() fits
        // in the buffer even though the cursor walk above already
        // enforced it. Cheap defence in depth.
        let end = off
            .checked_add(encoded.len())
            .ok_or(DepositError::ScopeBytesOverflow {
                required: usize::MAX,
            })?;
        if end > buf.len() {
            return Err(DepositError::ScopeBytesOverflow { required: end });
        }
        buf[off..end].copy_from_slice(encoded);
    }

    // Device-info section (M0 Phase 3). Lives at a fixed offset near the end of
    // the window, disjoint from the token region. The token cursor must not
    // have run into it (it never does in practice — tokens total ≲ 10 KiB and
    // the section starts at 0x7000), but guard explicitly.
    if let Some(info) = device_info {
        const SECTION_LEN: usize = 4 + 4 + 8 + 4 * 6; // magic+ver+bar_phys+6×u32
        if cursor > DEVICE_INFO_OFFSET {
            return Err(DepositError::ScopeBytesOverflow { required: cursor });
        }
        if DEVICE_INFO_OFFSET + SECTION_LEN > buf.len() {
            return Err(DepositError::ScopeBytesOverflow {
                required: DEVICE_INFO_OFFSET + SECTION_LEN,
            });
        }
        let b = DEVICE_INFO_OFFSET;
        buf[b..b + 4].copy_from_slice(&DEVICE_INFO_MAGIC);
        buf[b + 4..b + 8].copy_from_slice(&DEVICE_INFO_VERSION.to_le_bytes());
        buf[b + 8..b + 16].copy_from_slice(&info.bar_phys.to_le_bytes());
        buf[b + 16..b + 20].copy_from_slice(&info.mmio_len.to_le_bytes());
        buf[b + 20..b + 24].copy_from_slice(&info.common_offset.to_le_bytes());
        buf[b + 24..b + 28].copy_from_slice(&info.notify_offset.to_le_bytes());
        buf[b + 28..b + 32].copy_from_slice(&info.isr_offset.to_le_bytes());
        buf[b + 32..b + 36].copy_from_slice(&info.device_offset.to_le_bytes());
        buf[b + 36..b + 40].copy_from_slice(&info.notify_off_multiplier.to_le_bytes());
    }

    Ok(buf)
}

// =============================================================================
// Helpers — entry projection from DriverCapabilities
// =============================================================================

/// Internal projection of a [`DriverCapabilities`] entry into a
/// `(action, resource, tags)` quadruple used by the encoder. Keeping
/// it inside this module means callers don't need to know the
/// `Resource::*` discriminants; tag mapping stays a single audit
/// point.
struct EncoderEntry {
    action: Action,
    resource: Resource,
    action_tag: u32,
    resource_tag: u32,
}

fn build_entry_list(caps: &DriverCapabilities) -> Vec<EncoderEntry> {
    let mut out: Vec<EncoderEntry> = Vec::new();
    for r in &caps.mmio_regions {
        if matches!(r, Resource::MmioRegion { .. }) {
            out.push(EncoderEntry {
                action: Action::MmioMap,
                resource: r.clone(),
                action_tag: ACTION_TAG_MMIO_MAP,
                resource_tag: RESOURCE_TAG_MMIO_REGION,
            });
        }
    }
    for r in &caps.dma_windows {
        if matches!(r, Resource::DmaWindow { .. }) {
            out.push(EncoderEntry {
                action: Action::DmaMap,
                resource: r.clone(),
                action_tag: ACTION_TAG_DMA_MAP,
                resource_tag: RESOURCE_TAG_DMA_WINDOW,
            });
        }
    }
    for r in &caps.irq_lines {
        if matches!(r, Resource::IrqLine(_)) {
            out.push(EncoderEntry {
                action: Action::IrqAttach,
                resource: r.clone(),
                action_tag: ACTION_TAG_IRQ_ATTACH,
                resource_tag: RESOURCE_TAG_IRQ_LINE,
            });
        }
    }
    for r in &caps.pci_devices {
        if matches!(r, Resource::PciDevice { .. }) {
            // Two tokens per PCI device — read + write.
            out.push(EncoderEntry {
                action: Action::PciConfigRead,
                resource: r.clone(),
                action_tag: ACTION_TAG_PCI_CFG_READ,
                resource_tag: RESOURCE_TAG_PCI_DEVICE,
            });
            out.push(EncoderEntry {
                action: Action::PciConfigWrite,
                resource: r.clone(),
                action_tag: ACTION_TAG_PCI_CFG_WRITE,
                resource_tag: RESOURCE_TAG_PCI_DEVICE,
            });
        }
    }
    // IpcSend tokens (TASK-14, ADR-0036 D6): deposited to a NON-driver
    // task (the block-service client) so it can pass the `BlkLookup`
    // capability gate. The `BlkLookup` handler checks `action == IpcSend`
    // + per-boot issuer + validity window (not the channel resource), so
    // the `Resource::IpcChannel(id)` value is informational here.
    for r in &caps.ipc_send_channels {
        if matches!(r, Resource::IpcChannel(_)) {
            out.push(EncoderEntry {
                action: Action::IpcSend,
                resource: r.clone(),
                action_tag: ACTION_TAG_IPC_SEND,
                resource_tag: RESOURCE_TAG_IPC_CHANNEL,
            });
        }
    }
    // DisplayMap tokens (TASK-18, ADR-0040 D3): deposited to the Ring-3
    // compositor / display probe so it can call `DisplayMap (79)` to map
    // the GOP framebuffer into its address space. The `Resource::Framebuffer`
    // carries the whole-framebuffer phys_base+len; the probe may request
    // any page-aligned sub-window that passes the is_subset_of range check.
    for r in &caps.framebuffer_regions {
        if matches!(r, Resource::Framebuffer { .. }) {
            out.push(EncoderEntry {
                action: Action::DisplayMap,
                resource: r.clone(),
                action_tag: ACTION_TAG_DISPLAY_MAP,
                resource_tag: RESOURCE_TAG_FRAMEBUFFER,
            });
        }
    }
    out
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

// =============================================================================
// Bare-metal deposit installer
// =============================================================================

/// Allocate, map, and populate the deposit window in the target
/// driver's address space.
///
/// The window starts at [`DRIVER_CAP_DEPOSIT_VA`] and spans
/// [`DRIVER_CAP_DEPOSIT_PAGES`] consecutive 4 KiB pages. Pages are
/// mapped read-only user (`PTE_PRESENT | PTE_USER | PTE_NO_EXEC`) so
/// the driver can read but not modify the deposited tokens; a buggy
/// or compromised driver still cannot exfiltrate a parent token by
/// re-signing it.
///
/// On success the caller is expected to record
/// [`DRIVER_CAP_DEPOSIT_VA`] in the target
/// [`crate::process::ProcessControlBlock`] so later inspectors (e.g.
/// a diagnostic tool) can locate the page without having to parse
/// the PML4.
///
/// # Errors
///
/// Forwards [`DepositError`] from [`encode_deposit_page`] plus
/// [`DepositError::MapFailed`] if any page mapping fails.
///
/// # Safety
///
/// On `cfg(bare-metal)` this function performs raw `unsafe` writes
/// through the kernel's direct-map of the freshly-allocated phys
/// frame. The frames are not aliased — the allocator just produced
/// them — so the writes are sound. The caller MUST ensure
/// `phys_offset` is the canonical kernel direct-map offset
/// (`bootloader_api::BootInfo::physical_memory_offset`).
#[cfg(feature = "bare-metal")]
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "address_space is taken by reference to match the by-ref signature the bare-metal \
              device-info variant uses (which calls methods on it); keeping the ABI uniform"
)]
pub unsafe fn deposit_for_driver<const N: usize>(
    caps: &DriverCapabilities,
    boot_seconds: u64,
    subject_node_id_bytes: [u8; 32],
    address_space: &crate::bare_metal::address_space::AddressSpace,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
) -> Result<u64, DepositError> {
    // SAFETY: forwards to the device-info variant with no section; same
    // direct-map write contract as documented on this function.
    unsafe {
        deposit_for_driver_with_device_info(
            caps,
            boot_seconds,
            subject_node_id_bytes,
            None,
            address_space,
            mapper,
            alloc,
        )
    }
}

/// [`deposit_for_driver`] plus an optional [`VirtioDeviceInfo`] section.
///
/// Identical to [`deposit_for_driver`] when `device_info` is `None`. When
/// `Some`, the deposited page carries the modern-virtio register geometry the
/// Ring-3 image needs (it cannot discover it itself).
///
/// # Errors
///
/// Same as [`deposit_for_driver`].
///
/// # Safety
///
/// Same as [`deposit_for_driver`].
#[cfg(feature = "bare-metal")]
pub unsafe fn deposit_for_driver_with_device_info<const N: usize>(
    caps: &DriverCapabilities,
    boot_seconds: u64,
    subject_node_id_bytes: [u8; 32],
    device_info: Option<VirtioDeviceInfo>,
    address_space: &crate::bare_metal::address_space::AddressSpace,
    mapper: &mut crate::bare_metal::paging::PageMapper,
    alloc: &mut crate::memory::BitmapFrameAllocator<N>,
) -> Result<u64, DepositError> {
    let buf = encode_deposit_page_with_device_info(
        caps,
        boot_seconds,
        subject_node_id_bytes,
        device_info,
    )?;

    let phys_offset = mapper.phys_offset();
    let flags = crate::bare_metal::paging::PTE_PRESENT
        | crate::bare_metal::paging::PTE_USER
        | crate::bare_metal::paging::PTE_NO_EXEC;

    // Allocate + map + populate one page at a time. Page i covers
    // bytes `[i*0x1000, (i+1)*0x1000)` of `buf`.
    for page_idx in 0..DRIVER_CAP_DEPOSIT_PAGES {
        let phys = alloc.alloc_frame().ok_or(DepositError::MapFailed)?.0;
        let virt = DRIVER_CAP_DEPOSIT_VA + (page_idx as u64) * 0x1000;
        if !address_space.map_user_4k(
            mapper,
            crate::memory::VirtAddr(virt),
            crate::memory::PhysAddr(phys),
            flags,
            alloc,
        ) {
            return Err(DepositError::MapFailed);
        }

        // Pour the page into its physical frame via the direct-map.
        // SAFETY: `phys` was just returned by the allocator and has
        // no other live mapping; `phys_offset + phys` is in the
        // kernel direct-map and is writable Ring 0.
        let dst = phys_offset.wrapping_add(phys) as *mut u8;
        let src_start = page_idx * 0x1000;
        let src_end = src_start + 0x1000;
        // CRITICAL: bounds-check the source slice. `buf.len()` is
        // exactly `DRIVER_CAP_DEPOSIT_LEN == DRIVER_CAP_DEPOSIT_PAGES *
        // 0x1000`, so `src_end <= buf.len()` is statically true, but
        // assert it explicitly to defend against future buffer-size
        // changes that forget to bump the page count.
        debug_assert!(src_end <= buf.len());
        // SAFETY (continued): src + 4096 ≤ buf.len(); dst points to
        // freshly allocated physical memory accessed through the
        // direct map.
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr().add(src_start), dst, 0x1000);
        }
    }

    Ok(DRIVER_CAP_DEPOSIT_VA)
}

/// Host-side stub for [`deposit_for_driver`] — returns
/// [`DepositError::HostStub`] without touching any global state. The
/// encoder is exercised separately via [`encode_deposit_page`].
#[cfg(not(feature = "bare-metal"))]
#[allow(
    clippy::missing_errors_doc,
    reason = "host stub; the bare-metal variant carries the real # Errors section"
)]
pub fn deposit_for_driver(
    _caps: &DriverCapabilities,
    _boot_seconds: u64,
    _subject_node_id_bytes: [u8; 32],
) -> Result<u64, DepositError> {
    Err(DepositError::HostStub)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::range_plus_one,
    reason = "tests inspect well-known offsets in the encoder output; the encoder guarantees \
              the buffer is exactly `DRIVER_CAP_DEPOSIT_LEN` bytes long"
)]
mod tests {
    use nexacore_capability::scope::TimeWindow;

    use super::*;

    fn caps_with_one_mmio() -> DriverCapabilities {
        let mut caps = DriverCapabilities::default();
        caps.mmio_regions.push(Resource::MmioRegion {
            phys_base: 0xFEBC_0000,
            len: 0x0002_0000,
        });
        caps
    }

    fn deterministic_csprng() {
        crate::entropy::init_for_test([0x11; 32]);
    }

    #[test]
    fn encode_writes_magic_version_and_count() {
        deterministic_csprng();
        let caps = caps_with_one_mmio();
        let buf = encode_deposit_page(&caps, 1_000_000, [0u8; 32]).expect("encode");
        assert_eq!(&buf[0..8], &DEPOSIT_MAGIC);
        assert_eq!(
            u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            DEPOSIT_VERSION
        );
        assert_eq!(u32::from_le_bytes(buf[12..16].try_into().unwrap()), 1);
    }

    #[test]
    fn encode_buffer_length_matches_window_size() {
        deterministic_csprng();
        let caps = caps_with_one_mmio();
        let buf = encode_deposit_page(&caps, 1_000_000, [0u8; 32]).expect("encode");
        assert_eq!(buf.len(), DRIVER_CAP_DEPOSIT_LEN);
    }

    #[test]
    fn encode_entry_descriptor_layout() {
        deterministic_csprng();
        let caps = caps_with_one_mmio();
        let buf = encode_deposit_page(&caps, 1_000_000, [0u8; 32]).expect("encode");
        // First entry descriptor lives at offset 16.
        let action_tag = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let resource_tag = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let token_off = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let token_len = u32::from_le_bytes(buf[28..32].try_into().unwrap());
        assert_eq!(action_tag, ACTION_TAG_MMIO_MAP);
        assert_eq!(resource_tag, RESOURCE_TAG_MMIO_REGION);
        // token_off must point past the header + 1-entry table (32),
        // aligned to 8 bytes (so ≥ 32).
        assert!(token_off >= 32);
        assert!(token_len > 0);
        // Token slice must lie inside the buffer.
        let token_off_us = token_off as usize;
        let token_end = token_off_us + token_len as usize;
        assert!(token_end <= buf.len());
    }

    #[test]
    fn encode_minted_token_verifies_against_placeholder_provider() {
        deterministic_csprng();
        let caps = caps_with_one_mmio();
        let buf = encode_deposit_page(&caps, 1_000_000, [0u8; 32]).expect("encode");
        // Recover the first token's bytes from the deposit.
        let off = u32::from_le_bytes(buf[24..28].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(buf[28..32].try_into().unwrap()) as usize;
        let token_bytes = &buf[off..off + len];
        let token: CapabilityToken =
            nexacore_types::wire::decode_canonical(token_bytes).expect("decode");
        // Verify under the placeholder provider — subject = zero
        // node id, time window centred on `now = 1_000_001`.
        let provider = crate::capabilities::Ed25519CapabilityProvider::placeholder();
        let verdict = provider.verify_signed_token(&token, 1_000_001);
        assert_eq!(verdict, crate::capabilities::CapabilityVerdict::Authorised);
        // Verify the scope shape — action is MmioMap, resource is the
        // exact MMIO region we requested.
        assert_eq!(token.payload.scope.action, Action::MmioMap);
        let expected = Resource::MmioRegion {
            phys_base: 0xFEBC_0000,
            len: 0x0002_0000,
        };
        assert_eq!(token.payload.scope.resource, expected);
    }

    #[test]
    fn encode_pci_device_emits_read_and_write_tokens() {
        deterministic_csprng();
        let mut caps = DriverCapabilities::default();
        caps.pci_devices.push(Resource::PciDevice {
            segment: 0,
            bus: 0x12,
            device: 0x03,
            function: 0,
        });
        let buf = encode_deposit_page(&caps, 500_000, [0u8; 32]).expect("encode");
        let count = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        assert_eq!(count, 2);
        // Descriptor 0 → PciConfigRead, descriptor 1 → PciConfigWrite.
        assert_eq!(
            u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            ACTION_TAG_PCI_CFG_READ
        );
        assert_eq!(
            u32::from_le_bytes(buf[32..36].try_into().unwrap()),
            ACTION_TAG_PCI_CFG_WRITE
        );
    }

    #[test]
    fn encode_rejects_more_than_max_entries() {
        deterministic_csprng();
        let mut caps = DriverCapabilities::default();
        for i in 0..(MAX_ENTRIES as u64 + 1) {
            caps.mmio_regions.push(Resource::MmioRegion {
                phys_base: 0x1000_0000 + i * 0x1000,
                len: 0x1000,
            });
        }
        let err = encode_deposit_page(&caps, 0, [0u8; 32]).unwrap_err();
        assert!(matches!(err, DepositError::TokenCountExceeded { .. }));
    }

    #[test]
    fn align_up_basics() {
        assert_eq!(align_up(0, 8), 0);
        assert_eq!(align_up(1, 8), 8);
        assert_eq!(align_up(7, 8), 8);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(9, 8), 16);
    }

    #[test]
    fn time_window_helper_construction() {
        // Sanity: TimeWindow::new accepts valid bounds.
        assert!(TimeWindow::new(0, 1).is_some());
        assert!(TimeWindow::new(1, 0).is_none());
    }

    #[cfg(not(feature = "bare-metal"))]
    #[test]
    fn host_stub_returns_host_stub_error() {
        let caps = DriverCapabilities::default();
        assert_eq!(
            deposit_for_driver(&caps, 0, [0u8; 32]).unwrap_err(),
            DepositError::HostStub
        );
    }
}
