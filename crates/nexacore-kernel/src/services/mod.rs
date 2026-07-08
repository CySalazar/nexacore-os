//! Kernel-side registries for the well-known `nexacore.svc.<kind>.<slot>`
//! IPC channels surfaced by user-space service drivers.
//!
//! ## Why a dedicated `services` module
//!
//! The kernel's [`crate::ipc`] layer treats channel names as opaque
//! strings owned by user space: it allocates a [`crate::ipc::ChannelId`]
//! and stores per-channel state but does NOT index channels by name.
//! That is the right contract for the IPC layer (the kernel must stay
//! type-agnostic) but it leaves filesystem services, diagnostic
//! clients, and the future cap-gated multiplexers without a
//! kernel-mediated way to resolve "the block channel for disk slot
//! `nvme0`" → live [`crate::ipc::ChannelId`].
//!
//! The `services::*` submodules close that gap. Each one owns one
//! channel-name namespace (`nexacore.svc.<kind>.`) and exposes a
//! kernel-internal table that lets the consumer side perform a
//! constant-string lookup without sniffing the IPC registry by name.
//!
//! ## Submodules
//!
//! - [`blk`] — the BLK channel registry (`nexacore.svc.blk.<diskN>`),
//!   first consumer is the user-space NVMe driver per
//!   [`NCIP-Driver-NVMe-014`](../../../../ncips/ncip-driver-nvme-014.md)
//!   § S4 + § S6 step 12.
//! - [`net`] — the NET channel registry (`nexacore.svc.net.<iface>`),
//!   mapping interface name → (command [`crate::ipc::ChannelId`],
//!   event [`crate::ipc::ChannelId`]) per NCIP-Driver-Net-015 § S2.
//!   First consumer is the user-space NIC driver + network stack
//!   service.
//! - [`sysinfo`] — the boot-time-cached CPU count backing the
//!   `SysInfo (114)` telemetry syscall.
//!
//! ## Scope
//!
//! These registries are pure-state bookkeeping tables. They do not
//! emit any MMIO, do not touch the page-tables, and never call into
//! the IPC layer themselves — they only **record** what user space
//! has already created through [`crate::ipc::KernelIpcRegistry`]. The
//! kernel-side syscall handler (future work for P6.7.10-pre.3+)
//! glues the two together.

pub mod blk;
pub mod net;
pub mod sysinfo;
