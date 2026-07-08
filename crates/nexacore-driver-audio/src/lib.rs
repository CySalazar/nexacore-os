//! # `nexacore-driver-audio`
//!
//! Host-testable core of the NexaCore OS audio stack (WS2-10). The byte-layout
//! and integer-DSP parts — the HDA register map + CORB/RIRB verb codec, the
//! Buffer Descriptor List, the virtio-snd control/PCM messages, the mixer,
//! per-app volume, device routing, and the DE-H2 audio ABI — live here as pure
//! `no_std` logic and are unit-tested on the host. The MMIO/DMA bring-up, the
//! buffer-completion IRQ, and the live tone/loopback verification are device-
//! side on the rig.
//!
//! * **[`hda`]** — Intel HDA controller register map + CORB/RIRB verb encode /
//!   response decode + codec parameter discovery (WS2-10.1, .2).
//! * **[`bdl`]** — HDA stream Buffer Descriptor List entries (WS2-10.3).
//! * **[`virtio_snd`]** — virtio-snd control + PCM transfer message structures
//!   for the control/tx/rx virtqueues (WS2-10.4, .5, .6).
//! * **[`abi`]** — the DE-H2 audio syscall ABI (PCM formats, playback/capture
//!   request/response) (WS2-10.8).
//! * **[`mixer`]** — the user-space mixer: saturating integer stream summing
//!   (WS2-10.9), per-app [`mixer::Volume`] (WS2-10.10).
//! * **[`routing`]** — output/input device selection (WS2-10.11).
//!
//! The completion IRQ (WS2-10.7) and the VM-103 tone/loopback check
//! (WS2-10.12) are rig-side.

#![no_std]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-driver-audio")]
#![deny(missing_docs)]
// Byte-layout + fixed-point DSP code: `as` casts between integer widths are
// inherent and each site is range-reasoned; raw indexing is avoided.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
// Volume / sample-rate math divides by exact compile-time constants.
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

extern crate alloc;

pub mod abi;
pub mod bdl;
pub mod hda;
pub mod mixer;
pub mod routing;
pub mod virtio_snd;

pub use abi::{AudioRequest, AudioResponse, PcmFormat};
pub use bdl::{BDL_ENTRY_LEN, BdlEntry};
pub use hda::{HdaVerb, decode_response, make_verb};
pub use mixer::{Mixer, Volume};
pub use routing::{AudioDirection, AudioRouter, DeviceId};
pub use virtio_snd::{PcmXferHdr, SndCtrlHdr, SndPcmSetParams};
