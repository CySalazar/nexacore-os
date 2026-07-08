//! # `nexacore-driver-ahci`
//!
//! Host-testable core of the NexaCore OS AHCI/SATA storage driver (WS2-07,
//! DE-B5). Like the NVMe driver, the parts whose correctness is *byte layout*
//! — not hardware behaviour — live here as pure `no_std` logic so they are unit
//! tested on the host; the MMIO/DMA/IRQ bring-up that can only be confirmed on
//! real silicon stays in the bring-up shell.
//!
//! * **[`regs`]** — the generic + per-port HBA register map at the ABAR
//!   (AHCI 1.3.1 § 3): `CAP`/`GHC`/`PI`/… and the per-port `PxCLB`/`PxCMD`/
//!   `PxSSTS`/… offsets, with the bit constants the bring-up needs (WS2-07.1).
//! * **[`fis`]** — Frame Information Structure types and
//!   [`fis::build_h2d_register_fis`]: the 20-byte Host-to-Device Register FIS an
//!   ATA command is issued through (WS2-07.4).
//! * **[`identify`]** — [`identify::IdentifyDevice`]: parses the 512-byte
//!   `IDENTIFY DEVICE` response for sector count, logical sector size, LBA48
//!   support, and the model string (WS2-07.5).
//!
//! The HBA reset + port enumeration (WS2-07.2), per-port DMA structures
//! (WS2-07.3), READ/WRITE DMA EXT (WS2-07.6/.7), NCQ (WS2-07.8), the completion
//! IRQ (WS2-07.9), and the BLK provider (WS2-07.10) are device-side.

#![no_std]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-driver-ahci")]
#![deny(missing_docs)]
// Byte-layout code: u16/u32/u64 assembled from bytes via `as` is inherent and
// each site is bounds-reasoned; raw indexing is avoided in favour of `.get()`.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
// Sector-size / model-length math divides by exact compile-time constants.
#![allow(clippy::integer_division)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
    )
)]

pub mod fis;
pub mod identify;
pub mod regs;

pub use fis::{FisType, build_h2d_register_fis};
pub use identify::{IdentifyDevice, IdentifyError};
