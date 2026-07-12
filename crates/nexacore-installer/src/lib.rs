//! # `nexacore-installer`
//!
//! Host-testable core of the NexaCore installer (WS11-03).
//!
//! Installing NexaCore to disk means: enumerate the target disks, lay down a
//! GPT with an EFI System Partition and an NCFS root, create those filesystems,
//! copy the system across, and write a UEFI boot entry. This crate is the
//! device-independent, pure-bytes half of that:
//!
//! - [`disk`] (WS11-03.1) — a [`disk::DiskInfo`] geometry model and the
//!   [`disk::DiskEnumerator`] seam (the real NVMe/SATA probe is driver-backed).
//! - [`gpt`] (WS11-03.2) — a spec-correct [`gpt::GptLayout`] builder: protective
//!   MBR, primary + backup headers with little-endian CRC32, and the 128-entry
//!   partition array, carrying the EFI-System and NexaCore-root type GUIDs.
//! - [`plan`] — an install [`plan::plan_partitions`]/[`plan::build_layout`] that
//!   sizes and 1-MiB-aligns the ESP + root.
//! - [`live`] (WS11-01.1) — a [`live::LiveImageLayout`] descriptor + builder for a
//!   live USB image: a 1-MiB-aligned FAT ESP region and a read-only squashfs root
//!   region, with computed LBA offsets/lengths and total image size.
//! - [`config`] (WS11-03.8) — the [`config::InitialConfig`] first-boot seed
//!   (hostname/timezone/locale/keymap/user/networking) with validation and a
//!   round-tripping `key = value` serialisation for the config store (WS17-01).
//! - [`bootentry`] (WS11-03.7) — the [`bootentry::EfiLoadOption`] + EFI device
//!   path for the `Boot####` variable that boots the installed loader from the
//!   ESP (efibootmgr-class).
//! - [`detect`] (WS11-04.1) — [`detect::detect_loaders`] enumerates existing OS
//!   loaders in the ESP (via the FAT reader) so dual-boot can preserve them.
//! - [`mode`] (WS11-04.2/.3/.4) — [`mode::InstallMode`] dual-boot vs whole-disk
//!   replace: boot-order preservation and the GPT-wipe regions.
//! - [`firstboot`] (WS11-04.5/.6/.7) — the [`firstboot::FirstBootWizard`] linear
//!   state machine (user → locale → network) producing the [`config::InitialConfig`].
//! - [`ab`] (WS11-05.1/.2) — the A/B [`ab::Slot`] scheme and [`ab::AbState`]
//!   boot-control block, plus [`slotwrite::write_image_to_slot`] (WS11-05.5),
//!   the atomic image write to the inactive slot over the v3 `BlockDevice` seam.
//!
//! Creating the filesystems (`mkfs.fat` for the ESP, `mkfs.ncfs` for root),
//! copying the system, and writing the bootloader + UEFI boot entry (WS11-03.3–.8)
//! are the driver/firmware-backed integration steps.
//!
//! ## `no_std` + `alloc`
//!
//! `#![no_std]` pulling only `alloc`, dependency-free, so it builds for
//! `x86_64-unknown-none` as well as the developer host.

#![no_std]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
        // Tests express disk sizes as `<GiB> / 512` sector counts.
        clippy::integer_division,
    )
)]

extern crate alloc;

pub mod ab;
pub mod bootentry;
pub mod config;
pub mod detect;
pub mod disk;
pub mod firstboot;
pub mod gpt;
pub mod live;
pub mod mkfs;
pub mod mode;
pub mod plan;
pub mod slotwrite;
