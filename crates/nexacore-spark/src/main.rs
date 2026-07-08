//! NexaCore Spark — entry point.
//!
//! Launches NexaCore Spark. See `lib.rs` for the full architecture
//! overview and NCIP-025 for the specification.

use std::process::ExitCode;

// `cognitive_complexity`: the match arms for runtime-build and run
// failures expand into branches that inflate Clippy's score. The function
// is intentionally the top-level binary entry point and cannot usefully
// be split further without introducing artificial indirection.
#[allow(
    clippy::cognitive_complexity,
    reason = "binary entry point; match arms on runtime/run errors inflate score trivially"
)]
fn main() -> ExitCode {
    // Initialize tracing (structured logging).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("NexaCore Spark starting");

    // Build the async runtime.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "failed to build tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(nexacore_spark::run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "fatal error");
            ExitCode::FAILURE
        }
    }
}
