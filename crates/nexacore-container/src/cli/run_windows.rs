//! `nexacore-container run-windows` argument struct.
//!
//! Per `NCIP-Container-006` § 8, this command is a sugar form of
//! `nexacore-container run` that:
//!
//! - Defaults `--image` to `nexacore/linux-wine:N-stable`.
//! - Defaults `--profile` to `windows-app` (alias to `desktop-app` +
//!   the Wine base image).
//! - Adds a `--wine-prefix=<path>` argument that maps to a virtio-fs
//!   write capability on the prefix directory.
//!
//! Example:
//!
//! ```sh
//! nexacore-container run-windows photoshop.exe \
//!     --wine-prefix=/home/<user>/.wine/photoshop \
//!     --profile=windows-app
//! ```

/// Parsed arguments for `nexacore-container run-windows`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RunWindowsArgs {
    /// Path to the Windows `.exe` to launch inside the Wine guest.
    pub exe: String,
    /// `--wine-prefix=<path>`. The host-side path where the Wine
    /// prefix lives; mapped to `fs:write:<path>` inside the
    /// container.
    pub wine_prefix: Option<String>,
    /// The container name (auto-generated from the exe basename if
    /// not supplied via `--name`).
    pub name: Option<String>,
}

impl RunWindowsArgs {
    /// Construct minimal args for a smoke test.
    #[must_use]
    pub fn minimal(exe: impl Into<String>) -> Self {
        Self {
            exe: exe.into(),
            wine_prefix: None,
            name: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn minimal_constructor_smoke() {
        let args = RunWindowsArgs::minimal("photoshop.exe");
        assert_eq!(args.exe, "photoshop.exe");
        assert!(args.wine_prefix.is_none());
        assert!(args.name.is_none());
    }

    #[test]
    fn full_args_round_trip() {
        let args = RunWindowsArgs {
            exe: "notepad.exe".into(),
            wine_prefix: Some("/home/user/.wine/test".into()),
            name: Some("my-notepad".into()),
        };
        assert_eq!(args.exe, "notepad.exe");
        assert_eq!(args.wine_prefix.as_deref(), Some("/home/user/.wine/test"));
        assert_eq!(args.name.as_deref(), Some("my-notepad"));
    }
}
