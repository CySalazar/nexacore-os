//! # `nexacore-workflow`
//!
//! Agentic automation framework for NexaCore OS (WS16-04): declarative, local-first
//! workflows the user composes (or an agent generates) — a **trigger** fires a
//! sequence of **steps**, each performing an **action** on apps, files, or the
//! network, with every step gated behind the capability check and the Impact
//! Dashboard.
//!
//! ## Status
//!
//! Host-complete: the **declarative workflow model** (WS16-04.1), the
//! **local-first execution engine** with per-step action logging
//! (WS16-04.2/.10), **trigger evaluation** (WS16-04.3), the **concrete action
//! executors** behind effect seams (WS16-04.4/.5/.6), **config-as-code**
//! persistence (WS16-04.8), **per-step capability + Impact gating**
//! (WS16-04.9), and **natural-language generation** behind the WS5-03 runtime
//! seam with fail-closed validation (WS16-04.7). Helper undo integration
//! (WS16-04.11) and the VM-103 scenario (WS16-04.12) build on top.
//!
//! ## Modules
//!
//! - [`model`] — the declarative workflow schema (trigger → steps → actions).
//! - [`generate`] — natural-language workflow generation behind the AI-runtime
//!   seam, with fail-closed validation (WS16-04.7).
//! - [`engine`] — the execution engine and per-step action log.
//! - [`triggers`] — trigger evaluation against observed events (WS16-04.3).
//! - [`executors`] — concrete app/file/network action executors behind effect
//!   seams (WS16-04.4/.5/.6).
//! - [`gate`] — per-step capability gate + Impact assessment (WS16-04.9).
//! - [`store`] — the config-as-code workflow store (WS16-04.8).

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-workflow")]
#![deny(missing_docs)]

pub mod engine;
pub mod executors;
pub mod gate;
pub mod generate;
pub mod model;
pub mod store;
pub mod triggers;
