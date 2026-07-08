//! # `nexacore-log`
//!
//! A journald-class structured logging service for NexaCore OS (WS12-03),
//! replacing serial-only logging with structured, queryable, reboot-surviving
//! logs.
//!
//! | Concern | Item | Sub-task |
//! |---------|------|----------|
//! | Structured record schema + severity | [`record::LogRecord`], [`record::Severity`] | .1 |
//! | Ingestion bus | [`store::LogStore::ingest`] | .2 |
//! | Persistent ring + rotation | [`store::LogStore`], [`store::LogSink`] | .3 |
//! | Service / severity indices | [`store::LogStore::seqs_for_service`] | .4 |
//! | Query API | [`query::LogQuery`], [`store::LogStore::query`] | .5 |
//! | System-monitor surface | [`monitor::MonitorSummary`] | .6 |
//!
//! ## Design
//!
//! Records carry a monotonic sequence number, a timestamp, a syslog severity, a
//! service name, a message, and structured `key=value` fields. The ingestion
//! bus stamps the sequence number, persists the encoded record through a
//! [`store::LogSink`] seam (a rotated on-disk journal in production, an
//! in-memory sink in tests), and maintains a bounded in-memory ring plus
//! per-service / per-severity indices. On restart, [`store::LogStore::recover`]
//! rebuilds the ring and indices from the persisted records — the mechanism
//! behind reboot survival (WS12-03.7).
//!
//! Dep-free `no_std + alloc`, so it builds for `x86_64-unknown-none`.
//!
//! ## Example
//!
//! ```
//! use nexacore_log::{
//!     query::LogQuery,
//!     record::{LogRecord, Severity},
//!     store::{LogStore, MemSink},
//! };
//!
//! let mut log = LogStore::new(MemSink::new(1024), 256);
//! log.ingest(LogRecord::new(1_000, Severity::Warning, "net", "link down"));
//! log.ingest(LogRecord::new(2_000, Severity::Info, "net", "link up"));
//!
//! let warns = log.query(
//!     &LogQuery::new()
//!         .service("net")
//!         .min_severity(Severity::Warning),
//! );
//! assert_eq!(warns.len(), 1);
//! assert_eq!(warns[0].message, "link down");
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod monitor;
pub mod query;
pub mod record;
pub mod store;
