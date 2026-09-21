use super::super::CommandOutcome;
use super::native_fixture::{NativeDomainFixture, NativePrerequisites, installed_rootlesskit_235};

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

native_case!(native_detached_term_ignoring_descendant_is_destroyed);
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
