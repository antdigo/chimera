use super::super::{CommandOutcome, CommandTarget};
use super::native_fixture::{
    NativeDomainFixture, NativePrerequisites, control_fd_probe_spec, installed_rootlesskit_235,
};

#[test]
fn native_fd_probe_is_the_direct_workflow_executable() {
    let command = control_fd_probe_spec().unwrap();
    let CommandTarget::Sandboxed { program, args, cwd } = command.target else {
        panic!("probe must use production sandbox command execution");
    };
    assert_eq!(program.as_str(), "/work/native-fd-probe");
    assert!(
        args.is_empty(),
        "probe must not be a shell command argument"
    );
    assert_eq!(cwd.as_str(), "/work");
}

#[tokio::test]
#[ignore = "requires dedicated native Debian systemd delegation"]
async fn native_pid_one_private_root_and_control_fd() {
    let mut fixture = NativeDomainFixture::prepare().await.unwrap();
    assert!(fixture.kernel().namespaces.is_some());
    let result = fixture
        .run(concat!(
            "test \"$(cat /proc/1/comm)\" = chimera-domain\n",
            "test ! -e /.oldroot\n",
            "test ! -e /run/docker.sock\n",
            "test ! -e /root/.ssh\n",
            "test ! -e /proc/1/fd/3\n",
        ))
        .await;
    // Check set -eu too: an early failed assertion must never be hidden.
    let early_failure = fixture.run("false; true").await;
    let probe = fixture.probe_control_fds().await;
    let report = fixture.destroy().await.unwrap();
    assert_eq!(fixture.destroy().await.unwrap(), report);
    fixture.assert_no_resources().await.unwrap();
    assert_eq!(fixture.snapshot().live_processes, 0);
    assert_eq!(result, CommandOutcome::Exited(0));
    assert_ne!(early_failure, CommandOutcome::Exited(0));
    assert_eq!(probe, CommandOutcome::Exited(0));
}

#[test]
fn native_preflight_requires_all_three_paths() {
    assert!(NativePrerequisites::from_paths(None, None, None).is_err());
}

#[test]
fn native_preflight_requires_exact_installed_rootlesskit_package() {
    let valid = "Package: rootlesskit\nStatus: install ok installed\nVersion: 2.3.5-1\n";
    assert!(installed_rootlesskit_235(valid));
    assert!(!installed_rootlesskit_235(
        &valid.replace("2.3.5-1", "2.3.6-1")
    ));
    assert!(!installed_rootlesskit_235(
        &valid.replace("install ok installed", "deinstall ok config-files")
    ));
    assert!(!installed_rootlesskit_235(
        &valid.replace("Package: rootlesskit", "Package: other")
    ));
}

macro_rules! native_case {
    ($name:ident) => {
        #[tokio::test]
        #[ignore = "requires dedicated native Debian systemd delegation"]
        async fn $name() {
            panic!(
                "{} has no qualified production-path assertion; native gate remains blocked",
                stringify!($name)
            );
        }
    };
}

#[tokio::test]
#[ignore = "requires dedicated native Debian systemd delegation"]
async fn native_detached_term_ignoring_descendant_is_destroyed() {
    let mut fixture = NativeDomainFixture::prepare().await.unwrap();
    let baseline = fixture.snapshot().live_processes;
    let started = fixture
        .run_until_started(
            "trap '' TERM\n\
             setsid sh -c 'trap \"\" TERM; while :; do printf x >> /work/native-detached-heartbeat; sleep 0.1; done' >/dev/null 2>&1 &\n\
             while :; do wait || true; done",
        )
        .await;
    let descendant_is_live = if started.is_ok() {
        fixture
            .wait_for_live_processes(baseline + 2, std::time::Duration::from_secs(2))
            .await
    } else {
        Ok(false)
    };
    let descendant_heartbeat_grows = if descendant_is_live.as_ref().is_ok_and(|live| *live) {
        fixture
            .wait_for_heartbeat_growth(std::time::Duration::from_secs(2))
            .await
    } else {
        Ok(false)
    };
    let destroy_started = std::time::Instant::now();
    let destroy = fixture.destroy().await;
    let destroy_elapsed = destroy_started.elapsed();
    let no_resources = fixture.assert_no_resources().await;

    assert!(
        started.is_ok(),
        "TERM-ignoring command must start: {started:?}"
    );
    assert!(
        descendant_is_live.unwrap_or(false),
        "the detached descendant must be live before teardown"
    );
    assert!(
        descendant_heartbeat_grows.unwrap_or(false),
        "the detached TERM-ignoring descendant heartbeat must grow before teardown"
    );
    assert!(
        destroy.is_ok(),
        "production destroy must complete: {destroy:?}"
    );
    assert!(
        destroy_elapsed <= std::time::Duration::from_secs(20),
        "production destroy exceeded its bounded teardown deadline: {destroy_elapsed:?}"
    );
    assert!(
        no_resources.is_ok(),
        "destroy must remove exact owned resources"
    );
}
native_case!(native_namespace_identity_matrix);
native_case!(native_old_root_is_unreachable);
native_case!(native_readonly_nested_mounts);
native_case!(native_state_special_files_are_refused);
native_case!(native_policy_and_environment);
native_case!(native_output_drain_is_bounded);
native_case!(native_memory_and_pid_limits);
native_case!(native_cpu_and_io_limits);
native_case!(native_fault_after_each_provision_stage);
native_case!(native_cancel_in_each_phase);
native_case!(native_kill_and_restart_each_phase);
native_case!(native_reconcile_ignores_recycled_pid);
native_case!(native_two_sequential_tenant_waves);
