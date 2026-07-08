//! The six app windows hosted on the compositor: terminal, file manager,
//! NexaCore Helper chat, settings, the system monitor, and System Info
//! (launcher-only).
//!
//! Split out of `main.rs` (mechanical, no behaviour change); each submodule
//! owns one window's render function (and, where applicable, its
//! save/load/refresh logic). Shared plumbing (syscalls, IPC/FS client,
//! `handle_key`, `_start`) stays in `main.rs`; shared rendering primitives
//! (fonts, AA text, cursor, `present`) live in `crate::gfx`.

pub(crate) mod files;
pub(crate) mod helper;
pub(crate) mod monitor;
pub(crate) mod settings;
pub(crate) mod system_info;
pub(crate) mod terminal;
