//! Integration tests for `KvmEngine` lifecycle — full E2E with `MockHypervisor`.
//!
//! These tests exercise the complete container lifecycle through the public
//! [`nexacore_container::engine::ContainerEngine`] trait surface using
//! [`nexacore_container::engine::KvmEngine::with_mock`] so that no KVM hardware,
//! `/dev/kvm`, or root privileges are required.
//!
//! The tests live in `tests/` (not `src/`) so they only access public API,
//! mirroring what an external consumer of the crate would do.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    // Same workspace-bug carve-out as `src/lib.rs`.
    clippy::literal_string_with_formatting_args
)]

#[cfg(feature = "kvm")]
mod kvm_lifecycle {
    use nexacore_container::{
        ContainerError,
        engine::{ContainerEngine, ContainerSpec, KvmEngine},
        image::OciImageRef,
        lifecycle::ContainerLifecycleState,
        profile::CapabilityProfile,
    };

    /// Construct a minimal valid [`ContainerSpec`] for use across tests.
    ///
    /// Uses [`ContainerSpec::new`] because the struct is `#[non_exhaustive]`
    /// and cannot be constructed via struct literal syntax in external crates.
    fn spec() -> ContainerSpec {
        ContainerSpec::new(
            OciImageRef::parse("alpine:latest").expect("parse"),
            CapabilityProfile::CliTool,
            false,
        )
    }

    // -----------------------------------------------------------------------
    // Happy-path E2E lifecycle
    // -----------------------------------------------------------------------

    /// Full happy-path: provision → run → console → suspend → resume →
    /// terminate. This is the canonical lifecycle documented in the task spec.
    #[test]
    fn full_e2e_lifecycle() {
        let engine = KvmEngine::with_mock();

        // provision → Provisioning
        let id = engine.provision(spec()).expect("provision");
        assert_eq!(
            engine.state(id).expect("state after provision"),
            ContainerLifecycleState::Provisioning,
            "state after provision must be Provisioning"
        );

        // run → Running; mock guest writes "hello\n" to serial
        engine.run(id).expect("run");
        assert_eq!(
            engine.state(id).expect("state after run"),
            ContainerLifecycleState::Running,
            "state after run must be Running"
        );

        // console output must contain the mock guest's greeting
        let output = engine.console_output(id).expect("console_output");
        assert!(
            output.contains("hello"),
            "console output must contain 'hello', got: {output:?}"
        );

        // suspend → Suspended
        engine.suspend(id).expect("suspend");
        assert_eq!(
            engine.state(id).expect("state after suspend"),
            ContainerLifecycleState::Suspended,
            "state after suspend must be Suspended"
        );

        // resume → Running (re-runs vCPU; more output may be appended)
        engine.resume(id).expect("resume");
        assert_eq!(
            engine.state(id).expect("state after resume"),
            ContainerLifecycleState::Running,
            "state after resume must be Running"
        );

        // terminate → Terminated
        engine.terminate(id).expect("terminate");
        assert_eq!(
            engine.state(id).expect("state after terminate"),
            ContainerLifecycleState::Terminated,
            "state after terminate must be Terminated"
        );

        // console output is still readable after termination
        let post_terminate_output = engine.console_output(id).expect("console after terminate");
        assert!(
            post_terminate_output.contains("hello"),
            "console output must still contain 'hello' after terminate"
        );
    }

    // -----------------------------------------------------------------------
    // Snapshot path
    // -----------------------------------------------------------------------

    /// Provision → run → suspend → snapshot → resume → terminate.
    #[test]
    fn snapshot_lifecycle() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(spec()).expect("provision");
        engine.run(id).expect("run");
        engine.suspend(id).expect("suspend");

        engine.snapshot(id).expect("snapshot");
        assert_eq!(
            engine.state(id).expect("state"),
            ContainerLifecycleState::Snapshotted
        );

        // Restore the snapshot: Snapshotted → Running
        engine.resume(id).expect("resume from snapshot");
        assert_eq!(
            engine.state(id).expect("state"),
            ContainerLifecycleState::Running
        );

        engine.terminate(id).expect("terminate");
        assert_eq!(
            engine.state(id).expect("state"),
            ContainerLifecycleState::Terminated
        );
    }

    // -----------------------------------------------------------------------
    // Multiple independent containers
    // -----------------------------------------------------------------------

    /// Two containers run concurrently and do not interfere with each other.
    #[test]
    fn two_independent_containers() {
        let engine = KvmEngine::with_mock();
        let id1 = engine.provision(spec()).expect("provision c1");
        let id2 = engine.provision(spec()).expect("provision c2");
        assert_ne!(
            id1.as_raw(),
            id2.as_raw(),
            "containers must have distinct IDs"
        );

        engine.run(id1).expect("run c1");
        engine.run(id2).expect("run c2");

        assert_eq!(
            engine.state(id1).expect("state c1"),
            ContainerLifecycleState::Running
        );
        assert_eq!(
            engine.state(id2).expect("state c2"),
            ContainerLifecycleState::Running
        );

        let out1 = engine.console_output(id1).expect("console c1");
        let out2 = engine.console_output(id2).expect("console c2");
        assert!(out1.contains("hello"));
        assert!(out2.contains("hello"));

        engine.terminate(id1).expect("terminate c1");
        engine.terminate(id2).expect("terminate c2");
    }

    // -----------------------------------------------------------------------
    // Reject invalid lifecycle transitions
    // -----------------------------------------------------------------------

    /// `run` from `Running` must be rejected (must suspend first).
    #[test]
    fn run_from_running_is_rejected() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(spec()).expect("provision");
        engine.run(id).expect("first run");
        let err = engine.run(id).expect_err("run from Running must fail");
        assert!(
            matches!(err, ContainerError::Lifecycle(_)),
            "expected Lifecycle error, got {err:?}"
        );
    }

    /// `suspend` from `Provisioning` must be rejected.
    #[test]
    fn suspend_from_provisioning_is_rejected() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(spec()).expect("provision");
        let err = engine
            .suspend(id)
            .expect_err("suspend from Provisioning must fail");
        assert!(matches!(err, ContainerError::Lifecycle(_)));
    }

    /// `resume` from `Running` must be rejected.
    #[test]
    fn resume_from_running_is_rejected() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(spec()).expect("provision");
        engine.run(id).expect("run");
        let err = engine
            .resume(id)
            .expect_err("resume from Running must fail");
        assert!(matches!(err, ContainerError::Lifecycle(_)));
    }

    /// `snapshot` from `Running` must be rejected (must suspend first).
    #[test]
    fn snapshot_from_running_is_rejected() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(spec()).expect("provision");
        engine.run(id).expect("run");
        let err = engine
            .snapshot(id)
            .expect_err("snapshot from Running must fail");
        assert!(matches!(err, ContainerError::Lifecycle(_)));
    }

    /// `terminate` from `Terminated` must be rejected (terminal state).
    #[test]
    fn terminate_from_terminated_is_rejected() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(spec()).expect("provision");
        engine.terminate(id).expect("first terminate");
        let err = engine
            .terminate(id)
            .expect_err("second terminate must fail");
        assert!(matches!(err, ContainerError::Lifecycle(_)));
    }

    // -----------------------------------------------------------------------
    // Error cases — unknown container ID
    // -----------------------------------------------------------------------

    /// All engine methods return an error for an unknown `ContainerId`.
    #[test]
    fn unknown_id_returns_error_for_all_methods() {
        use nexacore_container::engine::ContainerId;

        let engine = KvmEngine::with_mock();
        let bad = ContainerId::from_raw(0xDEAD_BEEF);

        assert!(matches!(engine.state(bad), Err(ContainerError::Backend(_))));
        assert!(matches!(engine.run(bad), Err(ContainerError::Backend(_))));
        assert!(matches!(
            engine.suspend(bad),
            Err(ContainerError::Backend(_))
        ));
        assert!(matches!(
            engine.resume(bad),
            Err(ContainerError::Backend(_))
        ));
        assert!(matches!(
            engine.snapshot(bad),
            Err(ContainerError::Backend(_))
        ));
        assert!(matches!(
            engine.terminate(bad),
            Err(ContainerError::Backend(_))
        ));
        assert!(matches!(
            engine.console_output(bad),
            Err(ContainerError::Backend(_))
        ));
    }

    // -----------------------------------------------------------------------
    // tee_required rejection
    // -----------------------------------------------------------------------

    /// Specs with `tee_required = true` are rejected in v0.1 since no TEE
    /// hardware is available.
    #[test]
    fn tee_required_spec_rejected_at_provision() {
        let engine = KvmEngine::with_mock();
        let tee_spec = ContainerSpec::new(
            OciImageRef::parse("alpine:latest").expect("parse"),
            CapabilityProfile::AiWorkload,
            true,
        );
        let err = engine
            .provision(tee_spec)
            .expect_err("tee must be rejected");
        assert!(
            matches!(err, ContainerError::Backend(_)),
            "expected Backend error, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Attestation stub
    // -----------------------------------------------------------------------

    /// `attest` returns `NotYetImplemented` for all containers.
    #[test]
    fn attest_returns_not_yet_implemented() {
        use nexacore_container::engine::ContainerId;

        let engine = KvmEngine::with_mock();
        let id = engine.provision(spec()).expect("provision");
        let err = engine
            .attest(id, b"test-nonce")
            .expect_err("attest must fail");
        assert!(
            matches!(err, ContainerError::NotYetImplemented(_)),
            "expected NotYetImplemented, got {err:?}"
        );

        // Also check on an arbitrary (non-existent) ID — consistent stub behaviour.
        let ghost = ContainerId::from_raw(42);
        let err2 = engine.attest(ghost, b"nonce").expect_err("stub");
        assert!(matches!(err2, ContainerError::NotYetImplemented(_)));
    }
}
