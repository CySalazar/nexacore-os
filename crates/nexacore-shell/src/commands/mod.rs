//! External commands implemented as shell builtins (Phase 1).
//!
//! In Phase 1 all "external" commands are compiled into the shell binary and
//! registered alongside the core builtins. This lets the full command set be
//! available immediately without kernel process-spawning support.
//!
//! In Phase 2 (Layer 6) these commands will be extracted into standalone ELF
//! binaries installed at well-known paths (e.g. `/bin/ls`). The shell will
//! spawn them via the kernel process layer rather than calling them directly.
//!
//! ## Modules
//!
//! | Module | Commands |
//! |--------|---------|
//! | [`crate::commands::fs_cmds`] | `ls`, `cat`, `cp`, `mv`, `rm`, `mkdir`, `touch` |
//! | [`crate::commands::text_cmds`] | `grep`, `head`, `tail`, `wc` |
//! | [`crate::commands::sys_cmds`] | `uname`, `whoami`, `hostname`, `ps`, `kill` |
//! | [`crate::commands::fs_info`] | `df`, `find` |
//! | [`crate::commands::net_cmds`] | `ifconfig` |

pub mod fs_cmds;
pub mod fs_info;
pub mod net_cmds;
pub mod sys_cmds;
pub mod text_cmds;

use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::string::String;

use crate::executor::BuiltinFn;

/// Register all external commands into the builtin registry.
///
/// This function merges all four command groups into the provided map.
/// It is called by [`crate::command::register_builtins`] so that the full
/// command set (core builtins + external commands) is available to the
/// executor in a single lookup table.
///
/// # Examples
///
/// ```rust
/// use std::collections::BTreeMap;
///
/// use nexacore_shell::{commands::register_external_commands, executor::BuiltinFn};
///
/// let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
/// register_external_commands(&mut map);
/// assert!(map.contains_key("ls"));
/// assert!(map.contains_key("uname"));
/// assert!(map.contains_key("grep"));
/// assert!(map.contains_key("find"));
/// ```
pub fn register_external_commands(map: &mut BTreeMap<String, BuiltinFn>) {
    fs_cmds::register(map);
    text_cmds::register(map);
    sys_cmds::register(map);
    fs_info::register(map);
    net_cmds::register(map);
}
