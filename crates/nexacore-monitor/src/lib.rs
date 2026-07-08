//! # `nexacore-monitor`
//!
//! Host-testable core of the NexaCore OS system monitor (WS8-05).
//!
//! The monitor shows live CPU/RAM, disk and network throughput, the
//! per-process resource table, and offers capability-gated kill/renice. This
//! crate is the **device-independent** half: every kernel-bound effect sits
//! behind a trait so the orchestration logic is exercised entirely host-side.
//!
//! ## Architecture
//!
//! ```text
//!   WS12-04 /proc surface ──ProcSource──▶ MonitorClient ──▶ SystemSample
//!                                                              │
//!                          ┌───────────────┬──────────────────┤
//!                          ▼               ▼                  ▼
//!                     LiveSeries      DiskNetView        ProcessTable
//!                   (CPU/RAM ‰)    (throughput rates)   (sorted rows)
//!
//!   kill / renice ──ActionCapability gate──▶ ProcessController (kernel effect)
//! ```
//!
//! - [`client`] (WS8-05.1) — reads the `/proc`-class telemetry surface
//!   (WS12-04) through the [`client::ProcSource`] seam and parses it into a
//!   structured [`client::SystemSample`].
//! - [`view`] (WS8-05.2/.3/.4) — [`view::LiveSeries`] (CPU/RAM history in
//!   integer permille), [`view::DiskNetRates`] (throughput rates), and
//!   [`view::ProcessTable`] (the per-process resource table).
//! - [`actions`] (WS8-05.5/.6) — capability-gated [`actions::ProcessActions`]
//!   for kill and renice.
//!
//! The real `/proc` transport (kernel VFS over IPC), the process-control
//! syscalls, and the capability check are the production trait impls; host
//! tests use in-memory doubles.
//!
//! ## `no_std` + `alloc`
//!
//! The crate is `#![no_std]` and pulls only `alloc` (`String`, `Vec`), so it
//! compiles for `x86_64-unknown-none` as well as the developer host. No float
//! arithmetic is used: rates and usages are integer permille / bytes-per-second.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-monitor")]
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
    )
)]

extern crate alloc;

pub mod actions;
pub mod client;
pub mod view;
