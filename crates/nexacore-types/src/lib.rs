//! # `nexacore-types`
//!
//! Shared core types for NexaCore OS.
//!
//! This crate sits at the bottom of the NexaCore OS dependency tree: every other
//! crate may depend on `nexacore-types`, but `nexacore-types` depends on nothing
//! internal. It defines the strongly-typed identifier newtypes, the top-level
//! error taxonomy, the protocol/OS version vocabulary, and the sealed marker
//! types that gate construction of encrypted-by-default values.
//!
//! ## Crate-level guarantees
//!
//! 1. **`no_std + alloc`.** This crate compiles without the standard library.
//!    The kernel (P6 in `/todo.md`) consumes these types directly, so any
//!    accidental dependence on `std` would force a downstream refactor.
//! 2. **No `unsafe`.** The workspace lint `unsafe_code = "warn"` is upgraded
//!    here to `forbid` — there is no situation in which a foundational types
//!    crate needs raw memory access.
//! 3. **No `Display` for raw byte identifiers.** Identifier types
//!    deliberately omit a `core::fmt::Display` implementation so that an
//!    accidental `format!("{}", node_id)` is a compile error. Use
//!    [`identity::IdHex::to_hex`] when an identifier must be surfaced in
//!    logs or wire protocols — that path is auditable via `grep`.
//! 4. **Errors carry no PII.** All error variants use opaque identifiers
//!    rather than secret content. See [`error`] for the rationale.
//! 5. **Encrypted types are sealed.** [`encrypted::EncryptedType`] cannot be
//!    implemented outside this crate, and the marker types it gates have
//!    no public constructor. Construction is only possible through the
//!    tokenization service (`nexacore-tokenization`), which runs inside an
//!    attested TEE.
//!
//! ## Status
//!
//! v0.1 — first implementation. Implements all P1.1 sub-tasks declared in
//! `/todo.md`. The `encrypted` module exposes API surface only; concrete
//! constructors land in P2 with the tokenization service.
//!
//! ## Modules
//!
//! - [`ai`] — AI backend vocabulary that crosses the IPC boundary
//!   (`BackendKind`, `BackendStatusEvent`) per TASK-10 / ADR-0031. The
//!   runtime's backend router emits these; the UI status bar consumes
//!   them.
//! - [`blk`] — BLK service-channel ABI (`BlkRequest` / `BlkResponse`) per
//!   `NCIP-Driver-NVMe-014` § M3 / § S4. Wire shape every storage driver
//!   (NVMe today, future SATA/virtio-blk) MUST expose.
//! - [`nvme`] — NVMe driver-private command + event channel ABI
//!   (`NvmeCommand` / `NvmeEvent` / `IdentifyTarget`) per
//!   `NCIP-Driver-NVMe-014` § S2 / § S3. Lower-level NVMe-specific
//!   surface the user-space NVMe driver uses between its hardware
//!   interaction code and its admin / IO queue logic.
//! - [`encrypted`] — Sealed marker types for encrypted-by-default data.
//! - [`identity`] — Node, agent, model, capability, session identifiers.
//! - [`error`] — Top-level [`error::NexaCoreError`] taxonomy and [`error::Result`].
//! - [`version`] — OS and protocol version vocabulary.
//! - [`wire`] — Canonical `postcard` wire-encoding helper (single audit point
//!   for serialization across the workspace, per `NCIP-Serde-004`).
//!
//! ## See also
//!
//! - [`/docs/02-architecture.md`](../../../docs/02-architecture.md) for layering.
//! - [`/docs/04-security-model.md`](../../../docs/04-security-model.md) for the
//!   privacy-by-construction rationale that drives the sealed encrypted types.
//! - [`/docs/09-tech-specifications.md`](../../../docs/09-tech-specifications.md)
//!   for the dependency rationale (`RustCrypto` family, `no_std + alloc`).

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-types")]
#![no_std]
// Forbid `unsafe` in the foundational types crate. There is no legitimate
// reason for raw memory access in this layer; raise the workspace `warn`
// to `forbid` so any future contributor cannot smuggle it in.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
// `unwrap`, `expect`, `panic`, and `unnecessary_wraps` are first-class
// patterns in test code (assertions are expected to panic on failure;
// `?` propagation in `#[test]` fns muddies the failure signal). The
// workspace-level `warn` for these lints is upgraded to `allow` only
// when building the `cfg(test)` configuration. Production code paths
// keep the strict policy.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        clippy::indexing_slicing,
    )
)]

// `alloc` provides `String`, `Vec`, `Box`, etc. without pulling in `std`.
// The kernel target (P6) provides an allocator; userspace targets get it
// via the standard library transparently.
extern crate alloc;

pub mod ai;
pub mod blk;
pub mod config;
pub mod display_channel;
/// Client ⇄ compositor IPC wire protocol (TASK-19, DE-C2/DE-C3).
///
/// Defines the `postcard`-encoded message enums ([`crate::display_protocol::ClientRequest`]
/// and [`crate::display_protocol::CompositorEvent`]) that flow over the
/// [`crate::display_protocol::DISPLAY_CHANNEL_NAME`] IPC channel.
/// See [`ADR-0041`](../../../docs/adr/0041-nexacore-display-compositor-wm.md)
/// (D5) for the protocol design and backward-compatibility policy.
pub mod display_protocol;
pub mod encrypted;
pub mod error;
pub mod fs_service;
pub mod net;
pub mod net_channel;
pub mod nvme;
pub mod socket;
// `identity` is feature-gated behind `id-types` (default ON via
// `id-generation`) because its newtypes wrap `uuid::Uuid`. The
// CSPRNG-driven `::new()` constructors live in the same module but are
// gated separately behind `id-generation` so bare-metal builds can
// reference the type names (`NodeId`, `CapabilityId`, …) for
// verify-only paths without dragging `getrandom`. MB13.c split (see
// the corresponding Cargo.toml comment).
#[cfg(feature = "id-types")]
pub mod identity;
pub mod version;
pub mod wire;

// Re-export the most frequently used items at the crate root for ergonomic
// imports (`use nexacore_types::{NodeId, NexaCoreError, Result}`).
#[cfg(feature = "id-types")]
pub use crate::identity::{AgentId, CapabilityId, ModelId, NodeId, SessionId};
pub use crate::{
    error::{NexaCoreError, Result},
    version::{OsVersion, ProtocolVersion},
};
