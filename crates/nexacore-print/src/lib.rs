//! # `nexacore-print`
//!
//! Host-testable core of the NexaCore print subsystem (WS2-13).
//!
//! * **[`ipp`]** — IPP message encode/decode and the common operations
//!   (Get-Printer-Attributes, Create-Job, Send-Document, Print-Job) — WS2-13.1/.3.
//! * **[`spooler`]** — a print spooler with a persistent job queue and job-state
//!   tracking — WS2-13.4/.7.
//! * **[`pwg`]** — PWG-Raster page-header encoding (the raster print format) —
//!   WS2-13.6.
//! * **[`discovery`]** — the DNS-SD (`_ipp._tcp`) service-record model for
//!   printer discovery — WS2-13.2 (the live mDNS query/response is device-side).
//! * **[`render`]** — the [`render::PdfRasterizer`] seam; the real PDF→raster
//!   library is gated behind it — WS2-13.5.
//!
//! `no_std + alloc`. Every effect that needs a real library (PDF rasterizer) or
//! the network (mDNS, the IPP HTTP transport) sits behind a trait or is fed
//! bytes, so the protocol/spooler/format logic is pure and host-testable.

#![no_std]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-print")]
#![deny(missing_docs)]
// This crate serializes binary protocol/format fields whose lengths are bounded
// by the wire format (IPP 2-byte name/value lengths, single-byte DNS-SD TXT
// lengths): the length casts are intentional and bounded, not lossy bugs.
#![allow(clippy::cast_possible_truncation)]
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

pub mod discovery;
pub mod ipp;
pub mod pwg;
pub mod render;
pub mod spooler;

pub use crate::{
    ipp::{IppError, IppMessage, IppOperation, IppStatus},
    spooler::{JobState, PrintJob, Spooler},
};
