//! # `nexacore-driver-nvme`
//!
//! NexaCore OS first-party NVMe user-space driver — P6.7.8.4 scaffold.
//!
//! ## Scope
//!
//! This crate implements the storage driver of [`NCIP-Driver-NVMe-014`]
//! § S1-S6: NVMe 1.4-compliant PCIe SSDs (PCI class `0x01:0x08:0x02`). The
//! driver runs as a Ring 3 user-space process spawned by the kernel
//! through the [`NCIP-Driver-Framework-013`] § S5 `DriverLoad` syscall flow,
//! holds capability tokens for `MmioMap` / `DmaMap` / `IrqAttach`
//! attenuated from its issuer, and exposes the BLK service channel
//! `nexacore.svc.blk.nvme0` per § S4 of NCIP-Driver-NVMe-014.
//!
//! ## Delivery layering
//!
//! P6.7.8 is split into atomic sub-tasks. This crate covers **P6.7.8.4 —
//! NVMe driver scaffold** only:
//!
//! - [`pci_ids`] — PCI class code matchers pinned by NCIP-014 § S1.
//! - [`controller_regs`] — NVMe Controller Register offsets from
//!   NVMe 1.4 base spec § 3.1.
//! - [`queue_config`] — admin + IO submission/completion queue depth
//!   bounds and queue entry sizes per NVMe 1.4 § 5.
//! - [`transfer_model`] — PRP-only [`TransferModel`](crate::transfer_model::TransferModel)
//!   enum + 4 KiB alignment helpers (PRP is the only model accepted in
//!   v0.3 per NCIP-014 § M4).
//! - [`bringup`] — 13-step bring-up state-machine driver
//!   (`PciEnumeration → MmioMap → ReadCap → DisableController → SetupAdminQueues
//!   → EnableController → AttachInterrupts → IdentifyController → IdentifyActiveNsList
//!   → IdentifyNamespace → CreateIoQueues → RegisterBlkChannel → Ready`)
//!   per NCIP-014 § S6. No syscall calls — the actual `MmioMap` /
//!   `DmaMap` / `IrqAttach` invocations live in the bootable image
//!   sibling `nexacore-driver-nvme-image` (P6.7.8.5).
//!
//! The bootable image sibling mirrors the `nexacore-kernel` ↔ `kernel-runner`
//! and `nexacore-driver-net-virtio` ↔ `nexacore-driver-net-virtio-image` split
//! that already powers the bare-metal boot path.
//!
//! ## Cross-references
//!
//! - Driver framework: [`ncips/ncip-driver-framework-013.md`](../../../ncips/ncip-driver-framework-013.md)
//! - NVMe driver: [`ncips/ncip-driver-nvme-014.md`](../../../ncips/ncip-driver-nvme-014.md)
//! - Developer-authored manifest TOML template:
//!   `crates/nexacore-driver-nvme/manifest.toml` (consumed offline by the
//!   `nexacore-driver-pack` build tool — NexaCore Forge — to produce the
//!   `NexaCore-Pack v1` binary blob that `DriverLoad` ingests per
//!   NCIP-013 § S5.5).
//!
//! [`NCIP-Driver-NVMe-014`]: ../../../ncips/ncip-driver-nvme-014.md
//! [`NCIP-Driver-Framework-013`]: ../../../ncips/ncip-driver-framework-013.md

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-driver-nvme")]
#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
// Test-only allow list — mirrors `nexacore-kernel`'s ADR-0003 carve-out and
// the precedent set by `nexacore-driver-net-virtio` (P6.7.8.2). The bring-up
// FSM tests use `.unwrap()` / `.expect()` for terseness; production code
// keeps the workspace `deny(unwrap_used, expect_used, panic)` invariants
// at "deny".
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::doc_markdown
    )
)]

extern crate alloc;

pub mod admin;
pub mod admin_session;
pub mod blk_channel;
pub mod blk_gateway;
pub mod bringup;
pub mod bringup_live;
pub mod controller_regs;
pub mod discard;
pub mod identify;
pub mod interrupt;
pub mod io;
pub mod io_error;
pub mod io_session;
pub mod namespace_map;
pub mod pci_ids;
pub mod queue;
pub mod queue_config;
pub mod ring;
pub mod transfer_model;
