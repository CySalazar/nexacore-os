//! `nexacore-script` — the ncScript interpreter / runtime (WS18-02).
//!
//! ncScript (`NCIP-ncScript-030`) is a capability-gated, Rust-derived
//! scripting language. This crate is its sandboxed runtime:
//! lexer → parser → AST → tree-walking interpreter, with deterministic
//! resource limits and deny-by-default capability gating of every effect.
//!
//! `no_std + alloc`, embeddable as a library, zero production dependencies —
//! it builds for the host and for `x86_64-unknown-none`.
//!
//! ## Pipeline status
//!
//! - [`lexer`] — tokenizer (WS18-02.2). **Implemented.**
//! - [`ast`] + [`parser`] — parse to AST (WS18-02.3). **Implemented.**
//! - [`interp`] — tree-walking interpreter + refcounted value model
//!   (WS18-02.4/.5), deterministic step/memory/time limits (WS18-02.6/.7/.8),
//!   a deny-by-default capability gate over host effects (WS18-02.9/.10), and
//!   the pure `string`/`math` stdlib modules (WS18-03.2/.3). **Implemented.**
//! - remaining stdlib modules and capability-gated system bindings (WS18-03) —
//!   landing incrementally.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

extern crate alloc;

pub mod ast;
pub mod bindings;
pub mod interp;
pub mod lexer;
pub mod module;
pub mod parser;

pub use bindings::{AiBackend, ConfigBackend, FsBackend, IpcBackend, NetBackend, SystemBindings};
pub use interp::{
    Capability, Clock, EffectHandler, Grants, HostValue, Interpreter, Limit, Limits, RunError,
    RuntimeError, Value, run, run_with_limits,
};
pub use lexer::{LexError, LexErrorKind, SpannedToken, Token, tokenize};
pub use parser::{ParseError, parse};
