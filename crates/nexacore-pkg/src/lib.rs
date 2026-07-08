//! # `nexacore-pkg`
//!
//! Federated, content-addressed package manager for NexaCore OS (NCIP-Pkg-008).
//!
//! A package is identified by the `BLAKE3` content hash of its artifact and
//! described by a [`manifest::PackageManifest`] that declares its identity,
//! version, dependencies, and — crucially — the **capabilities** it requests.
//! Honest nodes only ever run packages whose manifest is signed (Sigstore,
//! WS9-02.3), included in the CT-log (WS9-02.4), and whose declared
//! capabilities the installer is willing to grant.
//!
//! ## Status
//!
//! This crate currently implements the **manifest format** (WS9-02.1), the
//! **content-addressed store** (WS9-02.2), and **dependency resolution +
//! install** (WS9-02.5). Signature/CT-log verification (WS9-02.3/.4) and atomic
//! upgrade/rollback (WS9-02.6/.7) arrive in later sub-tasks.
//!
//! ## Modules
//!
//! - [`manifest`] — package manifest schema with capability declaration.
//! - [`store`] — content-addressed package store.
//! - [`install`] — dependency resolution and installation.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-pkg")]
#![deny(missing_docs)]

pub mod ctlog;
pub mod federation;
pub mod install;
pub mod manifest;
pub mod store;
