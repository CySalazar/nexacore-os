//! `nexacore-container run` argument struct.
//!
//! Maps the CLI surface defined in `NCIP-Container-006` § 4. Example:
//!
//! ```sh
//! nexacore-container run my-python-ml \
//!     --image=python:3.12-slim \
//!     --fs-read=/data/dataset \
//!     --fs-write=/data/output \
//!     --network=outbound:huggingface.co:443 \
//!     --network=outbound:pypi.org:443 \
//!     --gpu=shared \
//!     --memory=8GB \
//!     --cpus=4 \
//!     --tee-required
//! ```

use crate::profile::CapabilityProfile;

/// Parsed arguments for `nexacore-container run`.
///
/// This struct is intentionally non-exhaustive: follow-up NCIPs add
/// fields for `--memory`, `--cpus`, `--snapshot-id`, and other knobs
/// without breaking the v0.1 trait surface.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RunArgs {
    /// User-supplied container name (must be unique on the host).
    pub name: String,
    /// `--image=<ref>`. Required unless `--profile=windows-app` is
    /// passed (in which case the engine defaults to
    /// `nexacore/linux-wine:N-stable`).
    pub image: Option<String>,
    /// `--profile=<name>`. Either one of the five built-ins (per
    /// `NCIP-Container-006` § 4) or a custom profile resolved against
    /// `~/.config/nexacore-container/profiles/`.
    pub profile: Option<CapabilityProfile>,
    /// All `--fs-read=<path>` occurrences.
    pub fs_read: Vec<String>,
    /// All `--fs-write=<path>` occurrences.
    pub fs_write: Vec<String>,
    /// All `--network=<direction>:<host>:<port>` occurrences.
    pub network: Vec<String>,
    /// `--gpu=<access>`. Empty if GPU access is not requested.
    pub gpu: Option<String>,
    /// `--tee-required` boolean flag.
    pub tee_required: bool,
}

impl RunArgs {
    /// Construct a `RunArgs` with the minimum fields for a smoke test.
    /// Production use goes through the CLI parser (not yet wired).
    #[must_use]
    pub fn minimal(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            image: None,
            profile: None,
            fs_read: Vec::new(),
            fs_write: Vec::new(),
            network: Vec::new(),
            gpu: None,
            tee_required: false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn minimal_constructor_smoke() {
        let args = RunArgs::minimal("my-app");
        assert_eq!(args.name, "my-app");
        assert!(args.image.is_none());
        assert!(args.profile.is_none());
        assert!(args.fs_read.is_empty());
        assert!(args.fs_write.is_empty());
        assert!(args.network.is_empty());
        assert!(args.gpu.is_none());
        assert!(!args.tee_required);
    }

    #[test]
    #[allow(clippy::redundant_clone)] // intentional: exercising the Clone impl
    fn args_are_clone_and_debug() {
        let args = RunArgs {
            name: "x".into(),
            image: Some("alpine:latest".into()),
            profile: Some(CapabilityProfile::CliTool),
            fs_read: vec!["/data".into()],
            fs_write: vec![],
            network: vec!["outbound:huggingface.co:443".into()],
            gpu: None,
            tee_required: true,
        };
        let clone = args.clone();
        assert_eq!(clone.name, args.name);
        assert_eq!(clone.image, args.image);
        assert_eq!(clone.fs_read, args.fs_read);
        assert!(format!("{args:?}").contains("RunArgs"));
    }
}
