//! `uname` - format injected system information (WS8-10.10).
//!
//! There is no ambient "system" to query in pure `no_std` logic, so the facts
//! `uname` reports are an injected [`SystemInfo`] value, obtained through the
//! [`SystemInfoSource`] seam (host double [`StaticSystemInfo`]). This keeps the
//! utility deterministic and testable.
//!
//! ## Flags
//!
//! - `-s` kernel name (the default when no flag is given)
//! - `-n` network node hostname
//! - `-r` kernel release
//! - `-m` machine hardware name
//! - `-a` all of the above, in the order name, nodename, release, machine
//!
//! Short flags may be bundled (`-sr`). When several fields are selected they are
//! printed space-separated in the canonical order above.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::CoreError;

/// The facts `uname` reports about the running system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInfo {
    /// Kernel/OS name (`uname -s`), e.g. `NexaCore`.
    pub kernel_name: String,
    /// Network node hostname (`uname -n`).
    pub nodename: String,
    /// Kernel release/version string (`uname -r`).
    pub kernel_release: String,
    /// Machine hardware name (`uname -m`), e.g. `x86_64`.
    pub machine: String,
}

impl SystemInfo {
    /// Construct a [`SystemInfo`] from its four fields.
    #[must_use]
    pub fn new(kernel_name: &str, nodename: &str, kernel_release: &str, machine: &str) -> Self {
        Self {
            kernel_name: kernel_name.to_string(),
            nodename: nodename.to_string(),
            kernel_release: kernel_release.to_string(),
            machine: machine.to_string(),
        }
    }
}

/// The seam that yields the current [`SystemInfo`].
pub trait SystemInfoSource {
    /// The system information to report.
    fn info(&self) -> SystemInfo;
}

/// A fixed host double for [`SystemInfoSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticSystemInfo {
    /// The information this source always reports.
    info: SystemInfo,
}

impl StaticSystemInfo {
    /// Wrap a fixed [`SystemInfo`].
    #[must_use]
    pub fn new(info: SystemInfo) -> Self {
        Self { info }
    }
}

impl SystemInfoSource for StaticSystemInfo {
    fn info(&self) -> SystemInfo {
        self.info.clone()
    }
}

/// Which `uname` fields to print, held as a small bit set so the four
/// independent flags live in one field (rather than as separate `bool`s).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnameFlags {
    /// Bit set of selected [field bits](UnameFlags#associated-constants).
    bits: u8,
}

impl UnameFlags {
    /// `-s`: the kernel name.
    pub const KERNEL_NAME: u8 = 1 << 0;
    /// `-n`: the nodename.
    pub const NODENAME: u8 = 1 << 1;
    /// `-r`: the kernel release.
    pub const KERNEL_RELEASE: u8 = 1 << 2;
    /// `-m`: the machine.
    pub const MACHINE: u8 = 1 << 3;

    /// An empty selection.
    #[must_use]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// The flag set selected by `-a` (every field).
    #[must_use]
    pub const fn all() -> Self {
        Self {
            bits: Self::KERNEL_NAME | Self::NODENAME | Self::KERNEL_RELEASE | Self::MACHINE,
        }
    }

    /// Add `bit` to the selection.
    fn set(&mut self, bit: u8) {
        self.bits |= bit;
    }

    /// Whether `bit` is selected.
    const fn has(self, bit: u8) -> bool {
        self.bits & bit != 0
    }

    /// `-s`: whether the kernel name is selected.
    #[must_use]
    pub const fn kernel_name(self) -> bool {
        self.has(Self::KERNEL_NAME)
    }

    /// `-n`: whether the nodename is selected.
    #[must_use]
    pub const fn nodename(self) -> bool {
        self.has(Self::NODENAME)
    }

    /// `-r`: whether the kernel release is selected.
    #[must_use]
    pub const fn kernel_release(self) -> bool {
        self.has(Self::KERNEL_RELEASE)
    }

    /// `-m`: whether the machine is selected.
    #[must_use]
    pub const fn machine(self) -> bool {
        self.has(Self::MACHINE)
    }

    /// Whether no field is selected (so the default, `-s`, applies).
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }
}

/// Parse `uname` arguments into a [`UnameFlags`] selection.
///
/// Recognises `-s`, `-n`, `-r`, `-m`, `-a`, and bundled short flags such as
/// `-sr`. `-a` sets every field.
///
/// # Errors
///
/// [`CoreError::InvalidArgument`] for any unrecognised flag or non-flag token.
pub fn parse_flags<'a, I>(args: I) -> Result<UnameFlags, CoreError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut flags = UnameFlags::default();
    for arg in args {
        let Some(letters) = arg.strip_prefix('-') else {
            return Err(CoreError::InvalidArgument);
        };
        if letters.is_empty() {
            return Err(CoreError::InvalidArgument);
        }
        for letter in letters.chars() {
            match letter {
                's' => flags.set(UnameFlags::KERNEL_NAME),
                'n' => flags.set(UnameFlags::NODENAME),
                'r' => flags.set(UnameFlags::KERNEL_RELEASE),
                'm' => flags.set(UnameFlags::MACHINE),
                'a' => flags = UnameFlags::all(),
                _ => return Err(CoreError::InvalidArgument),
            }
        }
    }
    Ok(flags)
}

/// Render `info` according to `flags`.
///
/// With no field selected the kernel name is printed (the `-s` default).
/// Selected fields are printed space-separated in the order kernel name,
/// nodename, kernel release, machine.
#[must_use]
pub fn uname(info: &SystemInfo, flags: UnameFlags) -> String {
    let effective = if flags.is_empty() {
        let mut only_name = UnameFlags::empty();
        only_name.set(UnameFlags::KERNEL_NAME);
        only_name
    } else {
        flags
    };
    let mut parts: Vec<&str> = Vec::new();
    if effective.kernel_name() {
        parts.push(&info.kernel_name);
    }
    if effective.nodename() {
        parts.push(&info.nodename);
    }
    if effective.kernel_release() {
        parts.push(&info.kernel_release);
    }
    if effective.machine() {
        parts.push(&info.machine);
    }
    parts.join(" ")
}

/// Parse `args` and render `info` in one step.
///
/// # Errors
///
/// Propagates [`parse_flags`] errors.
pub fn uname_from_args<'a, I>(info: &SystemInfo, args: I) -> Result<String, CoreError>
where
    I: IntoIterator<Item = &'a str>,
{
    Ok(uname(info, parse_flags(args)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> SystemInfo {
        SystemInfo::new("NexaCore", "workstation", "1.0.0", "x86_64")
    }

    #[test]
    fn default_prints_kernel_name() {
        assert_eq!(uname(&info(), UnameFlags::default()), "NexaCore");
    }

    #[test]
    fn all_prints_every_field_in_order() {
        assert_eq!(
            uname(&info(), UnameFlags::all()),
            "NexaCore workstation 1.0.0 x86_64"
        );
    }

    #[test]
    fn single_fields() {
        assert_eq!(uname(&info(), parse_flags(["-n"]).unwrap()), "workstation");
        assert_eq!(uname(&info(), parse_flags(["-r"]).unwrap()), "1.0.0");
        assert_eq!(uname(&info(), parse_flags(["-m"]).unwrap()), "x86_64");
    }

    #[test]
    fn bundled_flags_combine_in_canonical_order() {
        // `-mr` still prints release before machine.
        assert_eq!(
            uname(&info(), parse_flags(["-mr"]).unwrap()),
            "1.0.0 x86_64"
        );
    }

    #[test]
    fn dash_a_parses_to_all() {
        assert_eq!(parse_flags(["-a"]).unwrap(), UnameFlags::all());
    }

    #[test]
    fn unknown_flag_errors() {
        assert_eq!(parse_flags(["-z"]), Err(CoreError::InvalidArgument));
        assert_eq!(parse_flags(["bad"]), Err(CoreError::InvalidArgument));
        assert_eq!(parse_flags(["-"]), Err(CoreError::InvalidArgument));
    }

    #[test]
    fn uname_from_args_end_to_end() {
        assert_eq!(
            uname_from_args(&info(), ["-a"]).unwrap(),
            "NexaCore workstation 1.0.0 x86_64"
        );
    }

    #[test]
    fn source_seam_round_trips() {
        let source = StaticSystemInfo::new(info());
        assert_eq!(uname(&source.info(), UnameFlags::default()), "NexaCore");
    }
}
