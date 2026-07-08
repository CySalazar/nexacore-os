//! # `nexacore-driver-gpu`
//!
//! Host-testable core of the NexaCore OS GPU driver (WS2-09, first the
//! virtio-gpu path). Like the AHCI / NVMe drivers, the parts whose correctness
//! is *byte layout* — the virtio-gpu command protocol — live here as pure
//! `no_std` logic so they are unit-tested on the host; the virtqueue
//! notify/IRQ bring-up, scanout present, and DMA-BUF sharing that can only be
//! confirmed against an emulated/real device stay in the bring-up shell on the
//! rig.
//!
//! * **[`protocol`]** — the `virtio_gpu_ctrl_hdr`, the control-queue command
//!   serializers (`GET_DISPLAY_INFO`, `RESOURCE_CREATE_2D`,
//!   `RESOURCE_ATTACH_BACKING`, `TRANSFER_TO_HOST_2D`, `SET_SCANOUT`,
//!   `RESOURCE_FLUSH`, …) and the response parsers, per VIRTIO 1.x § 5.7
//!   (WS2-09.1–.6).
//! * **[`context`]** — the 3D (virgl/venus) context commands `CTX_CREATE` and
//!   `SUBMIT_3D` (WS2-09.7).
//! * **[`cursor`]** — the cursor-queue `UPDATE_CURSOR` / `MOVE_CURSOR`
//!   commands (WS2-09.13).
//! * **[`display`]** — `DisplayInfo` parsing and resolution/refresh selection
//!   (`select_mode`, WS2-09.9 host side).
//! * **[`submit`]** — the [`submit::GpuSubmit`] tensor-HAL dispatch seam
//!   (WS2-09.11), the [`submit::KmsDriver`] vendor-driver scaffold (WS2-09.15),
//!   and the [`submit::FpsMeter`] presentation-throughput instrument
//!   (WS2-09.14).
//!
//! The control/cursor virtqueue notify + completion IRQ (WS2-09.8), the live
//! `SET_SCANOUT` present (WS2-09.6 device side), DMA-BUF resource sharing
//! (WS2-09.10), the compositor wiring (WS2-09.12), and the VM-103 acceleration
//! check (WS2-09.16) are device-side.

#![no_std]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-driver-gpu")]
#![deny(missing_docs)]
// Byte-layout code: u32/u64 assembled from / split into bytes via `as` is
// inherent to wire serialization and each site is bounds-reasoned; raw indexing
// is avoided in favour of `.get()`.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
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

pub mod context;
pub mod cursor;
pub mod display;
pub mod protocol;
pub mod submit;

pub use context::{build_ctx_create, build_submit_3d};
pub use cursor::{CursorPos, build_move_cursor, build_update_cursor};
pub use display::{DisplayInfo, ScanoutMode, select_mode};
pub use protocol::{
    CtrlHeader, CtrlType, GpuFormat, MemEntry, ParsedScanout, Rect, parse_ctrl_type,
    parse_display_info,
};
pub use submit::{FpsMeter, GpuSubmit, KmsDriver, SubmitError};
