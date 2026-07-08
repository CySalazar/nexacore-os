//! # `nexacore-context`
//!
//! Personal AI context store for NexaCore OS (WS16-05): a **local-first**,
//! encrypted-at-rest store of the user's personal context — preferences, opt-in
//! documents, and interaction history — that agents may query only through a
//! capability + privacy-budget gate. A useful native AI needs personal context;
//! NexaCore keeps that context on the device, under the user's control, with
//! one-click export and erasure.
//!
//! ## Status
//!
//! This crate currently defines the **context schema** (WS16-05.1) and the
//! **local-first store** (WS16-05.2). Encryption at rest (WS16-05.3,
//! via WS3-07), tokenization before agent exposure (WS16-05.4, via WS5-06), the
//! explicit document opt-in flow (WS16-05.5), the capability + privacy-budget
//! query gate (WS16-05.6/.7, via WS5-07), the disable toggle (WS16-05.8), and
//! one-click export/erasure (WS16-05.9/.10) build on it.
//!
//! ## Modules
//!
//! - [`model`] — the personal-context schema (preferences, documents, history).
//! - [`store`] — the local-first context store.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-context")]
#![deny(missing_docs)]

pub mod model;
pub mod store;
