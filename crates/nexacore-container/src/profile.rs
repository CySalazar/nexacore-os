//! Capability profiles for `nexacore-container`.
//!
//! See `NCIP-Container-006` § 4 ("CLI surface") for the five built-in
//! profiles and their granted capability sets:
//!
//! - `desktop-app`     — Documents read/write, GPU shared, outbound :443.
//! - `cli-tool`        — cwd read/write, no network.
//! - `network-service` — inbound user-port, service-config / logs FS.
//! - `ai-workload`     — GPU shared, huggingface.co/pypi.org outbound,
//!                       model FS read, output FS write.
//! - `windows-app`     — alias to `desktop-app` + `nexacore/linux-wine`
//!                       base image.
//!
//! v0.1 status: this module provides the enum, slug round-trip, and
//! parser. The concrete `CapabilityToken` minting that a profile
//! implies lands when the host-side virtio backends are implemented
//! in a follow-up NCIP.

/// One of the five built-in capability profiles, or a user-supplied
/// custom profile name (resolved later against
/// `~/.config/nexacore-container/profiles/` per `NCIP-Container-006` § 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityProfile {
    /// `desktop-app` — graphical productivity application.
    DesktopApp,
    /// `cli-tool` — non-interactive batch tool with no network and
    /// cwd-scoped filesystem.
    CliTool,
    /// `network-service` — server-style workload listening on a
    /// user-supplied port.
    NetworkService,
    /// `ai-workload` — model training / inference job needing GPU
    /// and specific outbound endpoints.
    AiWorkload,
    /// `windows-app` — alias to `desktop-app` + `nexacore/linux-wine`
    /// base image, per `NCIP-Container-006` § 4 + § 8.
    WindowsApp,
    /// User-supplied profile, resolved later by reading
    /// `~/.config/nexacore-container/profiles/<name>.toml`.
    Custom(String),
}

impl CapabilityProfile {
    /// All five built-in profiles, in registry order. Useful for
    /// `nexacore-container ps --profiles` listings and exhaustiveness tests.
    pub const BUILTIN: &'static [Self] = &[
        Self::DesktopApp,
        Self::CliTool,
        Self::NetworkService,
        Self::AiWorkload,
        Self::WindowsApp,
    ];

    /// Return the canonical CLI slug for this profile.
    ///
    /// For [`Self::Custom`], the slug is the user-supplied name; for
    /// the five built-ins, it is the value passed to `--profile` on
    /// the CLI. Construction from a slug goes through `FromStr` on
    /// [`CapabilityProfile`].
    #[must_use]
    pub fn as_slug(&self) -> &str {
        match self {
            Self::DesktopApp => "desktop-app",
            Self::CliTool => "cli-tool",
            Self::NetworkService => "network-service",
            Self::AiWorkload => "ai-workload",
            Self::WindowsApp => "windows-app",
            Self::Custom(name) => name.as_str(),
        }
    }

    /// Whether this profile implies the use of the
    /// `nexacore/linux-wine:N-stable` base image (per
    /// `NCIP-Container-006` § 8).
    #[must_use]
    pub const fn implies_wine_image(&self) -> bool {
        matches!(self, Self::WindowsApp)
    }

    /// Whether this profile grants GPU access.
    #[must_use]
    pub const fn grants_gpu(&self) -> bool {
        matches!(self, Self::DesktopApp | Self::AiWorkload | Self::WindowsApp)
    }

    /// Whether this profile grants any outbound network access.
    #[must_use]
    pub const fn grants_outbound_network(&self) -> bool {
        matches!(
            self,
            Self::DesktopApp | Self::AiWorkload | Self::NetworkService | Self::WindowsApp
        )
    }
}

impl core::str::FromStr for CapabilityProfile {
    type Err = ProfileParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Built-in match first; falls through to Custom for anything
        // else with a valid slug shape.
        match s {
            "desktop-app" => Ok(Self::DesktopApp),
            "cli-tool" => Ok(Self::CliTool),
            "network-service" => Ok(Self::NetworkService),
            "ai-workload" => Ok(Self::AiWorkload),
            "windows-app" => Ok(Self::WindowsApp),
            _ => {
                if s.is_empty() {
                    return Err(ProfileParseError::Empty);
                }
                if s.len() > 64 {
                    return Err(ProfileParseError::TooLong);
                }
                if !s
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                {
                    return Err(ProfileParseError::InvalidChars);
                }
                if s.starts_with('-') || s.ends_with('-') {
                    return Err(ProfileParseError::InvalidShape);
                }
                Ok(Self::Custom(s.to_owned()))
            }
        }
    }
}

/// Error returned by the `FromStr` impl on
/// [`CapabilityProfile`] when the input does not match a built-in
/// slug and cannot be accepted as a custom profile name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProfileParseError {
    /// Empty input string.
    #[error("profile name is empty")]
    Empty,
    /// Custom profile name exceeds 64 characters.
    #[error("profile name exceeds 64 characters")]
    TooLong,
    /// Custom profile name contains characters outside `[a-z0-9-]`.
    #[error("profile name contains invalid characters (expected `[a-z0-9-]`)")]
    InvalidChars,
    /// Custom profile name starts or ends with `-`.
    #[error("profile name must not start or end with `-`")]
    InvalidShape,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn parse_all_builtins() {
        for p in CapabilityProfile::BUILTIN {
            let slug = p.as_slug();
            let parsed = CapabilityProfile::from_str(slug).expect("builtin slug parses");
            assert_eq!(&parsed, p);
        }
    }

    #[test]
    fn parse_custom_profile() {
        let p = CapabilityProfile::from_str("my-custom-2").expect("parses");
        assert!(matches!(p, CapabilityProfile::Custom(_)));
        assert_eq!(p.as_slug(), "my-custom-2");
    }

    #[test]
    fn parse_rejects_empty() {
        assert_eq!(
            CapabilityProfile::from_str(""),
            Err(ProfileParseError::Empty)
        );
    }

    #[test]
    fn parse_rejects_too_long() {
        let huge = "a".repeat(65);
        assert_eq!(
            CapabilityProfile::from_str(&huge),
            Err(ProfileParseError::TooLong)
        );
    }

    #[test]
    fn parse_rejects_uppercase() {
        assert_eq!(
            CapabilityProfile::from_str("Custom-Profile"),
            Err(ProfileParseError::InvalidChars)
        );
    }

    #[test]
    fn parse_rejects_leading_or_trailing_hyphen() {
        assert_eq!(
            CapabilityProfile::from_str("-leading"),
            Err(ProfileParseError::InvalidShape)
        );
        assert_eq!(
            CapabilityProfile::from_str("trailing-"),
            Err(ProfileParseError::InvalidShape)
        );
    }

    #[test]
    fn windows_app_implies_wine() {
        assert!(CapabilityProfile::WindowsApp.implies_wine_image());
        for p in [
            CapabilityProfile::DesktopApp,
            CapabilityProfile::CliTool,
            CapabilityProfile::NetworkService,
            CapabilityProfile::AiWorkload,
        ] {
            assert!(!p.implies_wine_image());
        }
    }

    #[test]
    fn gpu_grants_match_spec() {
        // Per NCIP-Container-006 § 4: desktop-app, ai-workload, and
        // windows-app (alias to desktop-app) grant GPU. cli-tool and
        // network-service do not.
        assert!(CapabilityProfile::DesktopApp.grants_gpu());
        assert!(CapabilityProfile::AiWorkload.grants_gpu());
        assert!(CapabilityProfile::WindowsApp.grants_gpu());
        assert!(!CapabilityProfile::CliTool.grants_gpu());
        assert!(!CapabilityProfile::NetworkService.grants_gpu());
    }

    #[test]
    fn outbound_network_grants_match_spec() {
        // cli-tool is the only built-in profile that grants no
        // outbound network at all.
        assert!(!CapabilityProfile::CliTool.grants_outbound_network());
        for p in [
            CapabilityProfile::DesktopApp,
            CapabilityProfile::AiWorkload,
            CapabilityProfile::NetworkService,
            CapabilityProfile::WindowsApp,
        ] {
            assert!(p.grants_outbound_network());
        }
    }
}
