//! # `nexacore-driver-net-virtio`
//!
//! NexaCore OS first-party virtio-net user-space driver — P6.7.8.2 scaffold.
//!
//! ## Scope
//!
//! This crate implements the M1 driver of [`NCIP-Driver-Net-015`] § S4:
//! virtio-net over PCI (vendor `0x1AF4`, device `0x1041` modern / `0x1000`
//! legacy). The driver runs as a Ring 3 user-space process spawned by the
//! kernel through the [`NCIP-Driver-Framework-013`] § S5 `DriverLoad` syscall
//! flow, holds capability tokens for `MmioMap` / `DmaMap` / `IrqAttach`
//! attenuated from its issuer, and exposes a `nexacore.svc.net.<ifN>` IPC
//! channel per § S2 of NCIP-Driver-Net-015.
//!
//! ## Delivery layering
//!
//! P6.7.8 is split into atomic sub-tasks. This crate covers **P6.7.8.2 —
//! virtio-net crate scaffold** only:
//!
//! - [`pci_ids`] — PCI vendor/device matchers pinned by NCIP-015 § S4.
//! - [`device_status`] — `device_status` byte constants from virtio 1.0 § 2.1.
//! - [`features`] — `device_feature` / `driver_feature` bit positions for
//!   the v0.3 negotiated feature set (`VIRTIO_F_VERSION_1`,
//!   `VIRTIO_NET_F_MAC`, `VIRTIO_NET_F_STATUS`).
//! - [`virtqueue`] — virtqueue descriptor / avail-ring / used-ring layout
//!   constants (no allocators, no syscall calls).
//! - [`bringup`] — state-machine **enum-only** scaffold for the
//!   `Reset → Acknowledge → Driver → FeaturesOk → DriverOk` sequence
//!   described by NCIP-015 § S4.1. No state transitions are wired here;
//!   the actual driver loop lands in P6.7.8.3.
//!
//! The bootable image sibling that links this lib into a `no_std` +
//! `no_main` ELF (loaded by the kernel's `spawn_from_elf` per NCIP-013
//! § S5.3 step 9) lands as `crates/nexacore-driver-net-virtio-image/` in
//! P6.7.8.3, mirroring the `nexacore-kernel` ↔ `kernel-runner` split that
//! already powers the bare-metal boot path.
//!
//! ## Cross-references
//!
//! - Driver framework: [`docs/ncips/ncip-driver-framework-013.md`](../../../ncips/ncip-driver-framework-013.md)
//! - Net driver family: [`docs/ncips/ncip-driver-net-015.md`](../../../ncips/ncip-driver-net-015.md)
//! - Developer-authored manifest TOML template:
//!   `crates/nexacore-driver-net-virtio/manifest.toml` (consumed offline by
//!   the `nexacore-driver-pack` build tool — NexaCore Forge — to produce the
//!   `NexaCore-Pack v1` binary blob that `DriverLoad` ingests per
//!   NCIP-013 § S5.5).
//!
//! [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md
//! [`NCIP-Driver-Framework-013`]: ../../../ncips/ncip-driver-framework-013.md

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-driver-net-virtio")]
#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
// Test-only allow list — mirrors `nexacore-kernel`'s ADR-0003 carve-out. The
// driver bring-up FSM tests use `.unwrap()` / `.expect()` for terseness;
// production code keeps the workspace `deny(unwrap_used, expect_used,
// panic)` invariants at "deny".
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::doc_markdown,
        // Tests write to fixed offsets in pre-allocated byte buffers whose
        // sizes are known at test construction time.  The ADR-0003 carve-out
        // extends to indexing in test-only code.
        clippy::indexing_slicing,
        // Test-only casts from small `usize` values (known to fit in u32).
        clippy::cast_possible_truncation
    )
)]

extern crate alloc;

pub mod bringup;
pub mod device_status;
pub mod driver;
pub mod features;
pub mod pci_ids;
pub mod ring;
pub mod service_loop;
pub mod tx_rx;
pub mod virtqueue;
