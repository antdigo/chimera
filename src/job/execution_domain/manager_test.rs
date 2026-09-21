use std::num::NonZeroUsize;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use super::super::{
    AttemptIdentity, CancelReason, CommandOutcome, CommandSpec, CommandTarget, DOCKER_CONFIG_ENV,
    ExecutionDomainRoot,
};
use crate::job::workspace::Workspace;

#[cfg(target_os = "linux")]
fn sandboxed_spec() -> CommandSpec {
    CommandSpec {
        target: CommandTarget::Sandboxed {
            program: super::super::DomainPath::parse("/bin/true").unwrap(),
            args: vec![],
            cwd: super::super::DomainPath::parse("/work").unwrap(),
        },
        env: std::collections::HashMap::new(),
        timeout: std::time::Duration::from_secs(2),
        state: None,
    }
}

#[cfg(target_os = "linux")]
fn linux_backend_for_test() -> (
    super::LinuxBackend,
    super::super::protocol::ControlConnection,
) {
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;

    let attempt = AttemptIdentity::new();
    let (manager, peer) = UnixStream::pair().unwrap();
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
    assert!(raw >= 0);
    let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    let backend = super::Backend::Linux(super::LinuxBackend {
        cleanup: None,
        test_kernel: Some(super::super::linux::launcher::KernelDomain {
            control: super::super::protocol::ControlConnection::new(manager, attempt).unwrap(),
            launcher: child,
            pidfd,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(2),
            namespaces: None,
            require_foreign_namespaces: false,
        }),
        path_mappings: Vec::new(),
        next_command_id: 1,
        control_broken: false,
    });
    let super::Backend::Linux(backend) = backend else {
        unreachable!()
    };
    (
        backend,
        super::super::protocol::ControlConnection::new(peer, attempt).unwrap(),
    )
}

#[cfg(target_os = "linux")]
fn constrain_control_send_buffer(backend: &super::LinuxBackend) {
    use std::os::fd::AsRawFd;

    let send_buffer: libc::c_int = 1024;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                backend.kernel().control.control_fd().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const send_buffer).cast(),
                std::mem::size_of_val(&send_buffer) as libc::socklen_t,
            )
        },
        0
    );
}

#[cfg(target_os = "linux")]
fn sandbox_path_mappings() -> Vec<(std::path::PathBuf, super::super::DomainPath)> {
    let paths = super::super::DomainPaths::sandboxed();
    [
        paths.work,
        paths.tmp,
        paths.home,
        paths.run,
        paths.docker_config,
        paths.docker_data,
        paths.docker_exec,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, path)| (std::path::PathBuf::from(format!("/host/{index}")), path))
    .collect()
}

#[tokio::test]
async fn explicit_destroy_releases_manager_owned_permit() {
    let temp = tempfile::tempdir().unwrap();
    let root_path = temp.path().join("domains");
    let root = ExecutionDomainRoot::prepare(&root_path, NonZeroUsize::new(1).unwrap()).unwrap();
    let permit = root.reserve().await.unwrap();
    let mut domain = permit.provision(AttemptIdentity::new()).await.unwrap();
    assert_eq!(root.admission.available_permits(), 0);

    domain.destroy().await.unwrap();

    assert_eq!(root.admission.available_permits(), 1);
    assert!(root.reserve().await.is_ok());
}

#[tokio::test]
async fn failed_destroy_retains_backend_and_can_be_retried() {
    let temp = tempfile::tempdir().unwrap();
    let root_path = temp.path().join("domains");
    let root = ExecutionDomainRoot::prepare(&root_path, NonZeroUsize::new(1).unwrap()).unwrap();
    let mut domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let attempt = domain.attempt_dir().to_path_buf();
    let original = attempt.with_extension("original");
    std::fs::rename(&attempt, &original).unwrap();
    std::fs::create_dir(&attempt).unwrap();

    assert!(domain.destroy().await.is_err());
    assert_eq!(root.admission.available_permits(), 0);
    std::fs::remove_dir(&attempt).unwrap();
    std::fs::rename(&original, &attempt).unwrap();

    domain.destroy().await.unwrap();
    assert!(!attempt.exists());
    assert_eq!(root.admission.available_permits(), 1);
}

#[tokio::test]
async fn dropping_handle_after_failed_destroy_retains_cleanup_authority() {
    let temp = tempfile::tempdir().unwrap();
    let root_path = temp.path().join("domains");
    let root = ExecutionDomainRoot::prepare(&root_path, NonZeroUsize::new(1).unwrap()).unwrap();
    let mut domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let attempt = domain.attempt_dir().to_path_buf();
    let original = attempt.with_extension("original");
    std::fs::rename(&attempt, &original).unwrap();
    std::fs::create_dir(&attempt).unwrap();

    assert!(domain.destroy().await.is_err());
    drop(domain);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if root.retained_cleanup_count_for_test() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    assert_eq!(root.admission.available_permits(), 0);
    assert!(*root.state.poisoned.borrow());
}

#[tokio::test]
async fn provisioning_future_drop_still_runs_manager_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let root_path = temp.path().join("domains");
    let root = ExecutionDomainRoot::prepare(&root_path, NonZeroUsize::new(1).unwrap()).unwrap();
    let (started, proceed) = root.pause_after_provision_for_test();
    let permit = root.reserve().await.unwrap();
    let provisioning = tokio::spawn(async move { permit.provision(AttemptIdentity::new()).await });
    tokio::time::timeout(std::time::Duration::from_secs(1), started)
        .await
        .unwrap()
        .unwrap();

    provisioning.abort();
    let _ = provisioning.await;
    proceed.send(()).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if root.admission.available_permits() == 1
                && std::fs::read_dir(&root_path).unwrap().next().is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(root.reserve().await.is_ok());
}

#[tokio::test]
async fn dropped_domain_poisons_before_permit_can_be_reused() {
    let temp = tempfile::tempdir().unwrap();
    let root_path = temp.path().join("domains");
    let root = ExecutionDomainRoot::prepare(&root_path, NonZeroUsize::new(1).unwrap()).unwrap();
    let permit = root.reserve().await.unwrap();
    let domain = permit.provision(AttemptIdentity::new()).await.unwrap();

    drop(domain);

    assert!(root.reserve().await.is_err());
}

#[tokio::test]
async fn permit_guard_poisons_before_its_permit_is_dropped() {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.clone().acquire_owned().await.unwrap();
    let state = std::sync::Arc::new(super::super::ExecutionDomainState::new());
    let guard = super::ManagerPermitGuard {
        root_state: state.clone(),
        permit: Some(permit),
        clean_exit: false,
    };

    drop(guard);

    assert!(*state.poisoned.borrow());
    assert_eq!(semaphore.available_permits(), 1);
}

#[tokio::test]
async fn trusted_state_bridge_rejects_replaced_command_file_after_bind() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let workspace = Workspace::create(
        &temp.path().join("work"),
        &temp.path().join("tmp"),
        &temp.path().join("tools"),
        "runner",
        "owner/repo",
    )
    .unwrap();
    domain.bind_workspace(&workspace).await.unwrap();

    let original = workspace.env_file().with_extension("bound");
    std::fs::rename(workspace.env_file(), &original).unwrap();
    std::fs::write(workspace.env_file(), "attacker=value\n").unwrap();

    assert!(domain.prepare_step(b"{}").await.is_err());
    assert_eq!(
        std::fs::read_to_string(workspace.env_file()).unwrap(),
        "attacker=value\n"
    );
    drop(domain);
}

#[tokio::test]
async fn manager_panic_retains_cleanup_authority_and_poisons_before_release() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let attempt = domain.attempt_dir().to_path_buf();
    domain.panic_manager_for_test().await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if root.admission.available_permits() == 1 && !attempt.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(*root.state.poisoned.borrow());
    assert!(root.reserve().await.is_err());
    drop(domain);
}

#[tokio::test]
async fn manager_panic_during_run_kills_the_trusted_process_group_before_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let attempt = domain.attempt_dir().to_path_buf();
    let pid_file = temp.path().join("command.pid");
    let spec = CommandSpec {
        target: CommandTarget::Trusted {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "echo $$ > \"$1\"; while :; do sleep 1; done".into(),
                "chimera".into(),
                pid_file.as_os_str().to_owned(),
            ],
            cwd: temp.path().to_path_buf(),
        },
        env: std::collections::HashMap::from([(
            DOCKER_CONFIG_ENV.to_owned(),
            domain.docker_config_dir().to_str().unwrap().to_owned(),
        )]),
        timeout: std::time::Duration::from_secs(30),
        state: None,
    };
    let (output, _events) = tokio::sync::mpsc::channel(1);
    let run = domain.run(spec, output, tokio_util::sync::CancellationToken::new());
    let panic = async {
        let pid = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(&pid_file)
                    && let Ok(pid) = contents.trim().parse::<i32>()
                {
                    break pid;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        domain.panic_manager_for_test().await.unwrap();
        pid
    };
    let (run_result, pid) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(run, panic)
    })
    .await
    .unwrap();
    assert!(run_result.is_err());

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if !alive {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("panic cleanup must kill and reap the in-flight process group");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while root.admission.available_permits() != 1 || attempt.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("panic cleanup must finish before releasing the permit");
    assert!(!attempt.exists());
    assert_eq!(root.admission.available_permits(), 1);
    assert!(*root.state.poisoned.borrow());
    drop(domain);
}

#[tokio::test]
async fn dropping_destroy_reply_does_not_cancel_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let mut domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let attempt = domain.attempt_dir().to_path_buf();
    let sender = domain.request.take().unwrap();
    domain.explicit_destroy = true;
    let (reply, response) = tokio::sync::oneshot::channel();
    drop(response);
    sender
        .send(super::ManagerRequest::Destroy { reply })
        .await
        .unwrap();
    drop(sender);
    drop(domain);

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if root.admission.available_permits() == 1 && !attempt.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(root.reserve().await.is_ok());
}

#[tokio::test]
async fn trusted_backend_delivers_non_utf8_argument_byte_for_byte() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let mut domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let output_path = temp.path().join("argument.bin");
    let argument = std::ffi::OsString::from_vec(b"native-\xff-argument".to_vec());
    let spec = CommandSpec {
        target: CommandTarget::Trusted {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "printf %s \"$1\" > \"$2\"".into(),
                "chimera".into(),
                argument.clone(),
                output_path.as_os_str().to_owned(),
            ],
            cwd: temp.path().to_path_buf(),
        },
        env: std::collections::HashMap::from([(
            DOCKER_CONFIG_ENV.to_owned(),
            domain.docker_config_dir().to_str().unwrap().to_owned(),
        )]),
        timeout: std::time::Duration::from_secs(5),
        state: None,
    };
    let (output, _events) = tokio::sync::mpsc::channel(1);

    let outcome = domain
        .run(spec, output, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(outcome, CommandOutcome::Exited(0));
    assert_eq!(
        std::fs::read(output_path).unwrap(),
        argument.as_os_str().as_bytes()
    );
    domain.destroy().await.unwrap();
}

fn trusted_spec(domain: &super::super::ExecutionDomain, script: &str) -> CommandSpec {
    CommandSpec {
        target: CommandTarget::Trusted {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            cwd: std::env::temp_dir(),
        },
        env: std::collections::HashMap::from([(
            DOCKER_CONFIG_ENV.to_owned(),
            domain.docker_config_dir().to_str().unwrap().to_owned(),
        )]),
        timeout: std::time::Duration::from_secs(30),
        state: None,
    }
}

#[tokio::test]
async fn domain_cancel_interrupts_in_flight_trusted_command_but_allows_post_command() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let mut domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let (output, _events) = tokio::sync::mpsc::channel(1);
    let run = domain.run(
        trusted_spec(&domain, "while :; do sleep 1; done"),
        output,
        tokio_util::sync::CancellationToken::new(),
    );
    let cancel = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        domain.cancel(CancelReason::User).await.unwrap();
    };
    let (outcome, ()) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(run, cancel)
    })
    .await
    .expect("manager cancel must interrupt the in-flight command");
    assert_eq!(outcome.unwrap(), CommandOutcome::Cancelled);

    let (output, _events) = tokio::sync::mpsc::channel(1);
    assert_eq!(
        domain
            .run(
                trusted_spec(&domain, "exit 0"),
                output,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap(),
        CommandOutcome::Exited(0)
    );
    domain.destroy().await.unwrap();
}

#[tokio::test]
async fn blocking_state_work_in_one_domain_does_not_stall_another_domain() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(2).unwrap())
            .unwrap();
    let mut blocked = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let mut responsive = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let request = blocked.request.as_ref().unwrap().clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    request
        .send(super::ManagerRequest::BlockStateForTest {
            started: started_tx,
            proceed: proceed_rx,
            reply: reply_tx,
        })
        .await
        .unwrap();
    started_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();

    let cancel = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        responsive.cancel(CancelReason::User),
    )
    .await;
    proceed_tx.send(()).unwrap();
    reply_rx.await.unwrap();

    assert!(
        cancel.is_ok(),
        "one domain blocked the shared manager runtime"
    );
    blocked.destroy().await.unwrap();
    responsive.destroy().await.unwrap();
}

#[tokio::test]
async fn cancel_racing_with_command_finish_is_command_scoped_and_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let mut domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();

    for _ in 0..16 {
        let (output, _events) = tokio::sync::mpsc::channel(1);
        let run = domain.run(
            trusted_spec(&domain, "exit 0"),
            output,
            tokio_util::sync::CancellationToken::new(),
        );
        let cancel = async {
            tokio::task::yield_now().await;
            domain.cancel(CancelReason::User).await
        };
        let (outcome, cancel) = tokio::join!(run, cancel);
        assert!(cancel.is_ok());
        assert!(matches!(
            outcome.unwrap(),
            CommandOutcome::Exited(0) | CommandOutcome::Cancelled
        ));
    }

    let (output, _events) = tokio::sync::mpsc::channel(1);
    assert_eq!(
        domain
            .run(
                trusted_spec(&domain, "exit 0"),
                output,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap(),
        CommandOutcome::Exited(0)
    );
    domain.destroy().await.unwrap();
}

#[tokio::test]
async fn destroy_interrupts_in_flight_trusted_command_before_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let mut domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let attempt = domain.attempt_dir().to_path_buf();
    let request = domain.request.as_ref().unwrap().clone();
    let (output, _events) = tokio::sync::mpsc::channel(1);
    let (run_reply, run_response) = tokio::sync::oneshot::channel();
    request
        .send(super::ManagerRequest::Run {
            spec: trusted_spec(&domain, "while :; do sleep 1; done"),
            output,
            cancelled: tokio_util::sync::CancellationToken::new(),
            reply: run_reply,
        })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let (destroy_reply, destroy_response) = tokio::sync::oneshot::channel();
    domain.explicit_destroy = true;
    domain.request.take();
    request
        .send(super::ManagerRequest::Destroy {
            reply: destroy_reply,
        })
        .await
        .unwrap();
    drop(request);

    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(3), run_response)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        CommandOutcome::Cancelled
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), destroy_response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!attempt.exists());
    assert_eq!(root.admission.available_permits(), 1);
}

#[tokio::test]
async fn trusted_normal_exit_has_a_bounded_drain_when_descendant_holds_pipes() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let mut domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let (output, _events) = tokio::sync::mpsc::channel(1);
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        domain.run(
            trusted_spec(&domain, "sleep 30 &"),
            output,
            tokio_util::sync::CancellationToken::new(),
        ),
    )
    .await
    .expect("pipe drain must not wait for the background descendant")
    .unwrap();
    assert_eq!(outcome, CommandOutcome::Exited(0));
    domain.destroy().await.unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_command_mapping_uses_domain_paths_and_rejects_non_utf8_argv() {
    let mapping = super::super::DomainCommandMapping::Sandboxed(vec![
        (
            std::path::PathBuf::from("/host/work"),
            super::super::DomainPath::parse("/work").unwrap(),
        ),
        (
            std::path::PathBuf::from("/usr/bin"),
            super::super::DomainPath::parse("/usr/bin").unwrap(),
        ),
    ]);
    let env = std::collections::HashMap::from([("PATH".into(), "/usr/bin".into())]);
    let target = mapping
        .target(
            std::ffi::OsStr::new("bash"),
            &[std::ffi::OsStr::new("/host/work/step.sh")],
            std::path::Path::new("/host/work"),
            &env,
        )
        .unwrap();
    assert_eq!(
        target,
        CommandTarget::Sandboxed {
            program: super::super::DomainPath::parse("/usr/bin/bash").unwrap(),
            args: vec!["/work/step.sh".into()],
            cwd: super::super::DomainPath::parse("/work").unwrap(),
        }
    );
    let mapped_env = mapping
        .environment(
            &std::collections::HashMap::from([
                ("PATH".into(), "/usr/bin".into()),
                ("GITHUB_WORKSPACE".into(), "/host/work".into()),
                ("GITHUB_ENV".into(), "/host/work/_env".into()),
            ]),
            &super::super::DomainEnvironment::sandboxed(),
        )
        .unwrap();
    assert_eq!(mapped_env.get("GITHUB_WORKSPACE").unwrap(), "/work");
    assert_eq!(mapped_env.get("PATH").unwrap(), "/usr/bin");
    assert!(!mapped_env.contains_key("GITHUB_ENV"));
    assert_eq!(mapped_env.get("HOME").unwrap(), "/home/chimera");
    assert_eq!(
        mapping
            .environment(&mapped_env, &super::super::DomainEnvironment::sandboxed(),)
            .unwrap(),
        mapped_env
    );

    let non_utf8 = std::ffi::OsString::from_vec(b"bad-\xff".to_vec());
    assert!(
        mapping
            .target(
                std::ffi::OsStr::new("bash"),
                &[non_utf8.as_os_str()],
                std::path::Path::new("/host/work"),
                &env,
            )
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_path_filters_debian_aliases_and_resolves_first_executable() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let host_work = temp.path().join("host-work");
    let host_sbin = temp.path().join("usr-sbin");
    let host_bin = temp.path().join("usr-bin");
    std::fs::create_dir_all(&host_work).unwrap();
    std::fs::create_dir_all(&host_sbin).unwrap();
    std::fs::create_dir_all(&host_bin).unwrap();
    let earlier_non_executable = host_sbin.join("chimera-path-probe");
    std::fs::write(&earlier_non_executable, "not executable").unwrap();
    std::fs::set_permissions(
        &earlier_non_executable,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let executable = host_bin.join("chimera-path-probe");
    std::fs::write(&executable, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();

    let mapping = super::super::DomainCommandMapping::Sandboxed(vec![
        (
            host_work.clone(),
            super::super::DomainPath::parse("/work").unwrap(),
        ),
        (
            host_sbin,
            super::super::DomainPath::parse("/usr/sbin").unwrap(),
        ),
        (
            host_bin,
            super::super::DomainPath::parse("/usr/bin").unwrap(),
        ),
    ]);
    let supplied = std::collections::HashMap::from([(
        "PATH".into(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
    )]);

    let mapped = mapping
        .environment(&supplied, &super::super::DomainEnvironment::sandboxed())
        .unwrap();
    assert_eq!(
        mapped.get("PATH").map(String::as_str),
        Some("/usr/sbin:/usr/bin")
    );
    assert!(!mapped["PATH"].contains(temp.path().to_str().unwrap()));
    assert_eq!(
        mapping
            .target(
                std::ffi::OsStr::new("chimera-path-probe"),
                &[],
                &host_work,
                &mapped,
            )
            .unwrap(),
        CommandTarget::Sandboxed {
            program: super::super::DomainPath::parse("/usr/bin/chimera-path-probe").unwrap(),
            args: vec![],
            cwd: super::super::DomainPath::parse("/work").unwrap(),
        }
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sandbox_mapping_error_does_not_leave_a_prepared_step_transaction() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let mut domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let workspace = Workspace::create(
        &temp.path().join("work"),
        &temp.path().join("tmp"),
        &temp.path().join("tools"),
        "runner",
        "owner/repo",
    )
    .unwrap();
    domain.command_mapping = super::super::DomainCommandMapping::Sandboxed(vec![(
        workspace.workspace_dir().to_path_buf(),
        super::super::DomainPath::parse("/work").unwrap(),
    )]);
    let mut state = crate::job::execute::JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        std::collections::HashMap::new(),
        serde_json::json!({}),
    );
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(8);
    let log = crate::job::logs::LogSender::new_for_test(
        log_tx,
        crate::job::secret_masker::shared_masker_for_test(&[]),
    );
    let non_utf8 = std::ffi::OsString::from_vec(b"bad-\xff".to_vec());

    let error = crate::job::execute::run_process(
        workspace.workspace_dir().join("command").as_os_str(),
        &[non_utf8.as_os_str()],
        &std::collections::HashMap::new(),
        workspace.workspace_dir(),
        &workspace,
        &domain,
        &mut state,
        &log,
        std::time::Duration::from_secs(1),
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<super::super::ExecutionDomainError>(),
        Some(super::super::ExecutionDomainError::InvalidDomainPath)
    ));

    domain.bind_workspace(&workspace).await.unwrap();
    let next = domain.prepare_step(b"{}").await.unwrap();
    domain.read_step(next).await.unwrap();
    domain.destroy().await.unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn private_linux_layout_is_strict_but_handle_publication_stays_not_ready() {
    let (mut linux, _peer) = linux_backend_for_test();
    linux.path_mappings = sandbox_path_mappings();
    let backend = super::Backend::Linux(linux);
    let (paths, environment) = backend.domain_layout().unwrap();
    assert_eq!(paths, super::super::DomainPaths::sandboxed());
    assert_eq!(environment, super::super::DomainEnvironment::sandboxed());
    let (request, _receiver) = tokio::sync::mpsc::channel(1);
    let error = super::build_handle(
        &backend,
        AttemptIdentity::new(),
        request,
        super::super::DomainWorkspaceReader::unbound(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        super::super::ExecutionDomainError::Backend {
            category: super::super::FailureCategory::NotReady,
            ..
        }
    ));
    let super::Backend::Linux(mut linux) = backend else {
        unreachable!()
    };
    linux.kernel_mut().launcher.kill().unwrap();
    linux.kernel_mut().launcher.wait().unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_backend_uses_monotonic_ids_and_correlates_rejection() {
    use super::super::protocol::{Message, Request, Response};

    let (mut backend, mut peer) = linux_backend_for_test();
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let Message::Request(Request::Run { command_id, .. }) = peer.receive(deadline).unwrap()
        else {
            panic!("expected first Run request")
        };
        assert_eq!(command_id, 1);
        peer.send(
            Message::Response(Response::CommandStarted { command_id }),
            deadline,
        )
        .unwrap();
        peer.send(
            Message::Response(Response::CommandFinished {
                command_id,
                outcome: CommandOutcome::Exited(0),
            }),
            deadline,
        )
        .unwrap();

        let Message::Request(Request::Run { command_id, .. }) = peer.receive(deadline).unwrap()
        else {
            panic!("expected second Run request")
        };
        assert_eq!(command_id, 2);
        peer.send(
            Message::Response(Response::CommandRejected {
                command_id,
                category: super::super::FailureCategory::Unavailable,
            }),
            deadline,
        )
        .unwrap();
        assert!(matches!(
            peer.receive(deadline).unwrap(),
            Message::Request(Request::CancelCommand {
                command_id: actual,
                reason: CancelReason::User,
            }) if actual == command_id
        ));
        peer.send(
            Message::Response(Response::CommandCancelAcknowledged {
                command_id,
                disposition: super::super::protocol::CancelDisposition::NotRunning,
            }),
            deadline,
        )
        .unwrap();
        let Message::Request(Request::PrepareStepChunk { id, .. }) =
            peer.receive(deadline).unwrap()
        else {
            panic!("expected PrepareStep after rejected command cancellation")
        };
        peer.send(Message::Response(Response::StepPrepared { id }), deadline)
            .unwrap();
    });
    let (output, _events) = tokio::sync::mpsc::channel(1);
    assert_eq!(
        backend
            .run(
                sandboxed_spec(),
                output,
                tokio_util::sync::CancellationToken::new(),
                super::ManagerCancellation::new(),
            )
            .await
            .unwrap(),
        CommandOutcome::Exited(0)
    );
    let (output, _events) = tokio::sync::mpsc::channel(1);
    let manager_cancelled = super::ManagerCancellation::new();
    manager_cancelled.cancel(CancelReason::User);
    let error = backend
        .run(
            sandboxed_spec(),
            output,
            tokio_util::sync::CancellationToken::new(),
            manager_cancelled,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        super::super::ExecutionDomainError::Backend {
            category: super::super::FailureCategory::Unavailable,
            ..
        }
    ));
    assert!(backend.prepare_step(b"{}").is_ok());
    responder.join().unwrap();
    backend.destroy(AttemptIdentity::new()).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_backend_receiver_close_sends_handle_dropped_and_drains_finish() {
    use super::super::protocol::{Message, Request, Response};

    let (mut backend, mut peer) = linux_backend_for_test();
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let Message::Request(Request::Run { command_id, .. }) = peer.receive(deadline).unwrap()
        else {
            panic!("expected Run request")
        };
        peer.send(
            Message::Response(Response::CommandStarted { command_id }),
            deadline,
        )
        .unwrap();
        assert!(matches!(
            peer.receive(deadline).unwrap(),
            Message::Request(Request::CancelCommand {
                command_id: actual,
                reason: super::super::CancelReason::HandleDropped,
            }) if actual == command_id
        ));
        peer.send(
            Message::Response(Response::CommandCancelAcknowledged {
                command_id,
                disposition: super::super::protocol::CancelDisposition::Applied,
            }),
            deadline,
        )
        .unwrap();
        peer.send(
            Message::Response(Response::CommandFinished {
                command_id,
                outcome: CommandOutcome::Cancelled,
            }),
            deadline,
        )
        .unwrap();
    });
    let (output, events) = tokio::sync::mpsc::channel(1);
    drop(events);
    assert_eq!(
        backend
            .run(
                sandboxed_spec(),
                output,
                tokio_util::sync::CancellationToken::new(),
                super::ManagerCancellation::new(),
            )
            .await
            .unwrap(),
        CommandOutcome::Cancelled
    );
    responder.join().unwrap();
    backend.destroy(AttemptIdentity::new()).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_backend_manager_cancel_sends_correlated_shutdown_reason() {
    use super::super::protocol::{Message, Request, Response};

    let (mut backend, mut peer) = linux_backend_for_test();
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let Message::Request(Request::Run { command_id, .. }) = peer.receive(deadline).unwrap()
        else {
            panic!("expected Run request")
        };
        assert!(matches!(
            peer.receive(deadline).unwrap(),
            Message::Request(Request::CancelCommand {
                command_id: actual,
                reason: CancelReason::Shutdown,
            }) if actual == command_id
        ));
        peer.send(
            Message::Response(Response::CommandStarted { command_id }),
            deadline,
        )
        .unwrap();
        peer.send(
            Message::Response(Response::CommandCancelAcknowledged {
                command_id,
                disposition: super::super::protocol::CancelDisposition::Applied,
            }),
            deadline,
        )
        .unwrap();
        peer.send(
            Message::Response(Response::CommandFinished {
                command_id,
                outcome: CommandOutcome::Cancelled,
            }),
            deadline,
        )
        .unwrap();
    });
    let manager_cancelled = super::ManagerCancellation::new();
    manager_cancelled.cancel(CancelReason::Shutdown);
    let (output, _events) = tokio::sync::mpsc::channel(1);
    assert_eq!(
        backend
            .run(
                sandboxed_spec(),
                output,
                tokio_util::sync::CancellationToken::new(),
                manager_cancelled,
            )
            .await
            .unwrap(),
        CommandOutcome::Cancelled
    );
    responder.join().unwrap();
    backend.destroy(AttemptIdentity::new()).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_backend_drains_late_cancel_acknowledgement_before_next_request() {
    use super::super::protocol::{Message, Request, Response};

    let (mut backend, mut peer) = linux_backend_for_test();
    // Keep the cancel frame partially sent while the peer publishes the
    // natural terminal result, exercising the exact race that used to leave
    // the late cancel acknowledgement queued for the next request.
    backend.kernel_mut().control.limit_flush_chunk_for_test(4);
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let Message::Request(Request::Run { command_id, .. }) = peer.receive(deadline).unwrap()
        else {
            panic!("expected Run request")
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        peer.send(
            Message::Response(Response::CommandStarted { command_id }),
            deadline,
        )
        .unwrap();
        peer.send(
            Message::Response(Response::CommandFinished {
                command_id,
                outcome: CommandOutcome::Exited(0),
            }),
            deadline,
        )
        .unwrap();
        assert!(matches!(
            peer.receive(deadline).unwrap(),
            Message::Request(Request::CancelCommand {
                command_id: actual,
                reason: CancelReason::User,
            }) if actual == command_id
        ));
        peer.send(
            Message::Response(Response::CommandCancelAcknowledged {
                command_id,
                disposition: super::super::protocol::CancelDisposition::NotRunning,
            }),
            deadline,
        )
        .unwrap();
        let Message::Request(Request::PrepareStepChunk { id, .. }) =
            peer.receive(deadline).unwrap()
        else {
            panic!("expected PrepareStep after drained late cancel acknowledgement")
        };
        peer.send(Message::Response(Response::StepPrepared { id }), deadline)
            .unwrap();
    });
    let manager_cancelled = super::ManagerCancellation::new();
    manager_cancelled.cancel(CancelReason::User);
    let (output, _events) = tokio::sync::mpsc::channel(1);

    assert_eq!(
        backend
            .run(
                sandboxed_spec(),
                output,
                tokio_util::sync::CancellationToken::new(),
                manager_cancelled,
            )
            .await
            .unwrap(),
        CommandOutcome::Exited(0)
    );
    let prepared = backend.prepare_step(b"{}").unwrap();
    assert!(!prepared.uuid().is_nil());

    responder.join().unwrap();
    backend.destroy(AttemptIdentity::new()).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_backend_drains_cancel_after_independent_init_timeout() {
    use super::super::protocol::{Message, Request, Response};

    let (mut backend, mut peer) = linux_backend_for_test();
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let Message::Request(Request::Run { command_id, .. }) = peer.receive(deadline).unwrap()
        else {
            panic!("expected Run request")
        };
        peer.send(
            Message::Response(Response::CommandStarted { command_id }),
            deadline,
        )
        .unwrap();
        peer.send(
            Message::Response(Response::CommandFinished {
                command_id,
                outcome: CommandOutcome::TimedOut,
            }),
            deadline,
        )
        .unwrap();
        assert!(matches!(
            peer.receive(deadline).unwrap(),
            Message::Request(Request::CancelCommand {
                command_id: actual,
                reason: CancelReason::User,
            }) if actual == command_id
        ));
        peer.send(
            Message::Response(Response::CommandCancelAcknowledged {
                command_id,
                disposition: super::super::protocol::CancelDisposition::NotRunning,
            }),
            deadline,
        )
        .unwrap();
        let Message::Request(Request::PrepareStepChunk { id, .. }) =
            peer.receive(deadline).unwrap()
        else {
            panic!("expected PrepareStep after timed-out command cancellation")
        };
        peer.send(Message::Response(Response::StepPrepared { id }), deadline)
            .unwrap();
    });
    let manager_cancelled = super::ManagerCancellation::new();
    manager_cancelled.cancel(CancelReason::User);
    let (output, _events) = tokio::sync::mpsc::channel(1);

    assert_eq!(
        backend
            .run(
                sandboxed_spec(),
                output,
                tokio_util::sync::CancellationToken::new(),
                manager_cancelled,
            )
            .await
            .unwrap(),
        CommandOutcome::TimedOut
    );
    let prepared = backend.prepare_step(b"{}");

    responder.join().unwrap();
    backend.kernel_mut().launcher.kill().unwrap();
    backend.kernel_mut().launcher.wait().unwrap();
    assert!(prepared.is_ok());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_backend_breaks_control_on_ambiguous_late_cancel_rejection() {
    use super::super::protocol::{Message, Request, Response};

    let (mut backend, mut peer) = linux_backend_for_test();
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let Message::Request(Request::Run { command_id, .. }) = peer.receive(deadline).unwrap()
        else {
            panic!("expected Run request")
        };
        peer.send(
            Message::Response(Response::CommandStarted { command_id }),
            deadline,
        )
        .unwrap();
        peer.send(
            Message::Response(Response::CommandFinished {
                command_id,
                outcome: CommandOutcome::Exited(0),
            }),
            deadline,
        )
        .unwrap();
        assert!(matches!(
            peer.receive(deadline).unwrap(),
            Message::Request(Request::CancelCommand {
                command_id: actual,
                reason: CancelReason::User,
            }) if actual == command_id
        ));
        peer.send(
            Message::Response(Response::CommandRejected {
                command_id,
                category: super::super::FailureCategory::Protocol,
            }),
            deadline,
        )
        .unwrap();
    });
    let manager_cancelled = super::ManagerCancellation::new();
    manager_cancelled.cancel(CancelReason::User);
    let (output, _events) = tokio::sync::mpsc::channel(1);

    assert!(matches!(
        backend
            .run(
                sandboxed_spec(),
                output,
                tokio_util::sync::CancellationToken::new(),
                manager_cancelled,
            )
            .await,
        Err(super::super::ExecutionDomainError::Backend {
            category: super::super::FailureCategory::Protocol,
            ..
        })
    ));
    assert!(backend.control_broken);

    responder.join().unwrap();
    backend.kernel_mut().launcher.kill().unwrap();
    backend.kernel_mut().launcher.wait().unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_backend_marks_a_closed_control_transport_broken() {
    use super::super::protocol::{Message, Request};

    let (mut backend, mut peer) = linux_backend_for_test();
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        assert!(matches!(
            peer.receive(deadline).unwrap(),
            Message::Request(Request::Run { .. })
        ));
    });
    let (output, _events) = tokio::sync::mpsc::channel(1);

    assert!(
        backend
            .run(
                sandboxed_spec(),
                output,
                tokio_util::sync::CancellationToken::new(),
                super::ManagerCancellation::new(),
            )
            .await
            .is_err()
    );
    assert!(backend.control_broken);

    responder.join().unwrap();
    backend.kernel_mut().launcher.kill().unwrap();
    backend.kernel_mut().launcher.wait().unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn stalled_linux_control_send_does_not_block_a_trusted_domain() {
    use super::super::protocol::{Message, Request, Response};

    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let mut trusted = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let (mut linux, mut peer) = linux_backend_for_test();
    constrain_control_send_buffer(&linux);
    let mut spec = sandboxed_spec();
    spec.env
        .insert("STALL_FRAME".into(), "x".repeat(512 * 1024));
    let (stalled_output, _stalled_events) = tokio::sync::mpsc::channel(1);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let stalled = super::manager_runtime().unwrap().spawn(async move {
        let _ = started_tx.send(());
        let result = linux
            .run(
                spec,
                stalled_output,
                tokio_util::sync::CancellationToken::new(),
                super::ManagerCancellation::new(),
            )
            .await;
        (linux, result)
    });
    started_rx.await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (output, mut events) = tokio::sync::mpsc::channel(4);
    let healthy = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        trusted.cancel(CancelReason::User).await.unwrap();
        let outcome = trusted
            .run(
                trusted_spec(&trusted, "printf healthy-progress"),
                output,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        let event = events.recv().await.unwrap();
        (outcome, event)
    })
    .await;

    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let Message::Request(Request::Run { command_id, .. }) = peer.receive(deadline).unwrap()
        else {
            panic!("expected stalled Run request")
        };
        peer.send(
            Message::Response(Response::CommandStarted { command_id }),
            deadline,
        )
        .unwrap();
        peer.send(
            Message::Response(Response::CommandFinished {
                command_id,
                outcome: CommandOutcome::Exited(0),
            }),
            deadline,
        )
        .unwrap();
    });
    let (mut linux, stalled_result) = stalled.await.unwrap();
    responder.join().unwrap();
    assert_eq!(stalled_result.unwrap(), CommandOutcome::Exited(0));
    linux.kernel_mut().launcher.kill().unwrap();
    linux.kernel_mut().launcher.wait().unwrap();

    let (outcome, event) = healthy.expect("stalled Linux control blocked the manager runtime");
    assert_eq!(outcome, CommandOutcome::Exited(0));
    assert!(
        matches!(event, super::super::CommandEvent::Stdout(bytes) if bytes == b"healthy-progress")
    );
    trusted.destroy().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancel_converges_when_a_large_run_frame_remains_backpressured() {
    use super::super::protocol::{Message, Request, Response};

    let temp = tempfile::tempdir().unwrap();
    let root =
        ExecutionDomainRoot::prepare(&temp.path().join("domains"), NonZeroUsize::new(1).unwrap())
            .unwrap();
    let mut trusted = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let (mut linux, mut peer) = linux_backend_for_test();
    constrain_control_send_buffer(&linux);
    let mut spec = sandboxed_spec();
    spec.timeout = std::time::Duration::from_secs(60 * 60);
    spec.env
        .insert("STALL_FRAME".into(), "x".repeat(512 * 1024));
    let cancel = tokio_util::sync::CancellationToken::new();
    let run_cancel = cancel.clone();
    let (stalled_output, _stalled_events) = tokio::sync::mpsc::channel(1);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let mut stalled = super::manager_runtime().unwrap().spawn(async move {
        let _ = started_tx.send(());
        let result = linux
            .run(
                spec,
                stalled_output,
                run_cancel,
                super::ManagerCancellation::new(),
            )
            .await;
        (linux, result)
    });
    started_rx.await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    cancel.cancel();

    let (output, mut events) = tokio::sync::mpsc::channel(4);
    let healthy = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        trusted.cancel(CancelReason::User).await.unwrap();
        let outcome = trusted
            .run(
                trusted_spec(&trusted, "printf still-healthy"),
                output,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        let event = events.recv().await.unwrap();
        (outcome, event)
    })
    .await;
    let convergence = tokio::time::timeout(std::time::Duration::from_secs(2), &mut stalled).await;
    let converged = convergence.is_ok();

    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        if let Ok(Message::Request(Request::Run { command_id, .. })) = peer.receive(deadline) {
            let _ = peer.send(
                Message::Response(Response::CommandStarted { command_id }),
                deadline,
            );
            if matches!(
                peer.receive(deadline),
                Ok(Message::Request(Request::CancelCommand {
                    command_id: actual,
                    reason: CancelReason::User,
                })) if actual == command_id
            ) {
                let _ = peer.send(
                    Message::Response(Response::CommandCancelAcknowledged {
                        command_id,
                        disposition: super::super::protocol::CancelDisposition::Applied,
                    }),
                    deadline,
                );
                let _ = peer.send(
                    Message::Response(Response::CommandFinished {
                        command_id,
                        outcome: CommandOutcome::Cancelled,
                    }),
                    deadline,
                );
            }
        }
    });
    let (mut linux, stalled_result) = match convergence {
        Ok(joined) => joined.unwrap(),
        Err(_) => stalled.await.unwrap(),
    };
    responder.join().unwrap();
    linux.kernel_mut().launcher.kill().unwrap();
    linux.kernel_mut().launcher.wait().unwrap();

    assert!(
        converged,
        "cancel waited for the original one-hour command deadline"
    );
    assert!(matches!(
        stalled_result,
        Err(super::super::ExecutionDomainError::Backend {
            category: super::super::FailureCategory::Unavailable
                | super::super::FailureCategory::Timeout,
            ..
        })
    ));
    let (outcome, event) = healthy.expect("cancel backpressure stalled a healthy domain");
    assert_eq!(outcome, CommandOutcome::Exited(0));
    assert!(
        matches!(event, super::super::CommandEvent::Stdout(bytes) if bytes == b"still-healthy")
    );
    trusted.destroy().await.unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn idle_linux_command_cancel_never_sends_domain_shutdown() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::super::protocol::{Message, Request, Response};

    let (linux, mut peer) = linux_backend_for_test();
    let mut backend = super::Backend::Linux(linux);
    let observed_shutdown = std::sync::Arc::new(AtomicBool::new(false));
    let responder_observed = observed_shutdown.clone();
    let responder = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
        if let Ok(message) = peer.receive(deadline) {
            if matches!(message, Message::Request(Request::Shutdown { .. })) {
                responder_observed.store(true, Ordering::SeqCst);
                peer.send(Message::Response(Response::ShuttingDown), deadline)
                    .unwrap();
            } else {
                panic!("idle command cancellation emitted an unexpected request: {message:?}");
            }
        }
    });

    backend.cancel(CancelReason::User).unwrap();
    responder.join().unwrap();
    assert!(!observed_shutdown.load(Ordering::SeqCst));

    let super::Backend::Linux(mut linux) = backend else {
        unreachable!()
    };
    linux.kernel_mut().launcher.kill().unwrap();
    linux.kernel_mut().launcher.wait().unwrap();
}
