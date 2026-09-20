use std::num::NonZeroUsize;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use super::super::{
    AttemptIdentity, CommandOutcome, CommandSpec, CommandTarget, DOCKER_CONFIG_ENV,
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
async fn dropping_destroy_reply_does_not_cancel_cleanup() {
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
    let mut destroy = Box::pin(domain.destroy());
    assert!(futures::poll!(&mut destroy).is_pending());
    drop(destroy);

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
            )
            .await
            .unwrap(),
        CommandOutcome::Cancelled
    );
    responder.join().unwrap();
    backend.destroy().unwrap();
}
