//! `nexacore-container` CLI argument types.
//!
//! See `NCIP-Container-006` § 4 ("CLI surface") and § 8 ("Wine
//! integration for Windows applications").
//!
//! v0.1 status: this module defines the **argument structs** that the
//! CLI parser will populate. No real argument parsing is wired up yet
//! (the binary entry point lands in a follow-up NCIP that selects a
//! parser — `clap` or `argh` — without locking the rest of the
//! workspace into the choice). The structs are designed to be
//! mockall-friendly: every field is plain `String` / `u16` / etc., so
//! the tests can construct them by-field without going through a CLI
//! parse step.

pub mod ps;
pub mod run;
pub mod run_windows;

pub use ps::PsArgs;
pub use run::RunArgs;
pub use run_windows::RunWindowsArgs;
