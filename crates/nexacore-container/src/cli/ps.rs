//! `nexacore-container ps` argument struct — list containers managed by
//! the engine.

/// Output format requested by `nexacore-container ps --format=<fmt>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsFormat {
    /// Human-readable table (default).
    Table,
    /// JSON one-line-per-container (for scripting).
    Json,
}

impl Default for PsFormat {
    fn default() -> Self {
        Self::Table
    }
}

/// Parsed arguments for `nexacore-container ps`.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PsArgs {
    /// `--all` — include terminated containers in the output.
    pub all: bool,
    /// `--format=<fmt>` — output format.
    pub format: PsFormat,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_args_smoke() {
        let args = PsArgs::default();
        assert!(!args.all);
        assert_eq!(args.format, PsFormat::Table);
    }

    #[test]
    fn json_format_round_trips() {
        let args = PsArgs {
            all: true,
            format: PsFormat::Json,
        };
        assert!(args.all);
        assert_eq!(args.format, PsFormat::Json);
    }
}
