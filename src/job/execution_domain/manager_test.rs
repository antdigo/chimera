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
        kernel: super::super::linux::launcher::KernelDomain {
            control: super::super::protocol::ControlConnection::new(manager, attempt).unwrap(),
            launcher: child,
            pidfd,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(2),
        },
        cleanup: None,
        path_mappings: Vec::new(),
        next_command_id: 1,
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
    let domain = permit.provision(AttemptIdentity::new()).await.unwrap();
    assert_eq!(root.admission.available_permits(), 0);

    domain.destroy().await.unwrap();

    assert_eq!(root.admission.available_permits(), 1);
    assert!(root.reserve().await.is_ok());
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
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !pid_file.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        domain.panic_manager_for_test().await.unwrap();
    };
    let (run_result, ()) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(run, panic)
    })
    .await
    .unwrap();
    assert!(run_result.is_err());

    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
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
    let domain = root
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
    let domain = root
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
    let domain = root
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
    linux.kernel.launcher.kill().unwrap();
    linux.kernel.launcher.wait().unwrap();
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
    let error = backend
        .run(
            sandboxed_spec(),
            output,
            tokio_util::sync::CancellationToken::new(),
            super::ManagerCancellation::new(),
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
    responder.join().unwrap();
    backend.destroy().unwrap();
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
    backend.destroy().unwrap();
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
    backend.destroy().unwrap();
}
