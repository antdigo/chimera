use super::launcher::*;
use crate::job::execution_domain::AttemptIdentity;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[test]
fn kernel_ready_transfers_exact_mount_and_pid_namespace_handles() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let expected = NamespaceHandles::open_current_for_test().unwrap();
    let identities = expected.identities_for_test();
    send_namespace_handles_for_test(&sender, &expected).unwrap();

    let received =
        receive_namespace_handles_for_test(&receiver, Instant::now() + Duration::from_secs(1))
            .unwrap();

    assert_eq!(received.identities_for_test(), identities);
    for fd in [received.mount.as_raw_fd(), received.pid.as_raw_fd()] {
        assert!(fd >= 0);
    }
}

#[test]
fn launcher_never_selects_host_network_or_outer_ports() {
    let args = rootlesskit_arguments(
        &AttemptIdentity::from_uuid(uuid::Uuid::from_u128(7)).unwrap(),
        std::path::Path::new("/test/chimera"),
        std::path::Path::new("/test/rootlesskit-state"),
        NetworkLaunch::Disconnected,
    )
    .unwrap();
    assert!(args.contains(&"--subid-source=static".into()));
    assert!(args.contains(&"--net=none".into()));
    assert!(args.contains(&"--port-driver=none".into()));
    assert!(args.contains(&"--evacuate-cgroup2=init".into()));
    for required in [
        "--pidns",
        "--cgroupns",
        "--ipcns",
        "--utsns",
        "--propagation=rprivate",
    ] {
        assert!(args.contains(&required.into()));
    }
    assert!(
        !args.iter().any(|v| v.to_string_lossy().contains("host")
            || v.to_string_lossy().starts_with("--publish"))
    );
    assert_eq!(args[args.len() - 2], "--internal-domain-bootstrap");
    assert_eq!(args[args.len() - 1], "00000000000000000000000000000007");
}

#[test]
fn inherited_control_requires_connected_unix_stream_and_cloexec() {
    let file = std::fs::File::open("/dev/null").unwrap();
    assert!(duplicate_control(file.as_fd()).is_err());
    let (a, _b) = UnixStream::pair().unwrap();
    let owned = duplicate_control(a.as_fd()).unwrap();
    assert_ne!(owned.as_raw_fd(), a.as_raw_fd());
    assert_ne!(
        unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let listener_path = tempfile::tempdir().unwrap();
    let listener =
        std::os::unix::net::UnixListener::bind(listener_path.path().join("socket")).unwrap();
    assert!(duplicate_control(listener.as_fd()).is_err());
    let (a, _b) = std::os::unix::net::UnixDatagram::pair().unwrap();
    assert!(duplicate_control(a.as_fd()).is_err());
}

#[test]
fn launcher_rejects_foreign_membership_before_writing() {
    let mut file = tempfile::tempfile().unwrap();
    use std::io::{Read, Seek, Write};
    file.write_all(b"CANARY").unwrap();
    assert!(join_cgroup(file.as_fd()).is_err());
    file.rewind().unwrap();
    let mut bytes = String::new();
    file.read_to_string(&mut bytes).unwrap();
    assert_eq!(bytes, "CANARY");
}

#[test]
fn reserved_entry_fails_closed_and_trusted_cli_is_untouched() {
    for args in [vec![], vec!["run"], vec!["--help"]] {
        assert_eq!(
            dispatch_internal(&args.into_iter().map(Into::into).collect::<Vec<_>>()),
            None
        );
    }
    for args in [
        vec!["--internal-domain-bootstrap"],
        vec!["--internal-domain-launch"],
        vec!["--internal-domain-bootstrap", "CANARY"],
        vec![
            "--internal-domain-bootstrap",
            "00000000-0000-0000-0000-000000000007",
        ],
    ] {
        assert_eq!(
            dispatch_internal(&args.into_iter().map(Into::into).collect::<Vec<_>>()),
            Some(78)
        );
    }
    assert!(
        rootlesskit_arguments(
            &AttemptIdentity::new(),
            "/test/chimera".as_ref(),
            "/test/state".as_ref(),
            NetworkLaunch::Slirp
        )
        .is_err()
    );
}

#[test]
fn control_fd_does_not_survive_exec_and_failed_copy_preserves_peer() {
    let (a, _b) = UnixStream::pair().unwrap();
    let control = duplicate_control(a.as_fd()).unwrap();
    let result = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("test ! -e /proc/self/fd/{}", control.as_raw_fd()))
        .status()
        .unwrap();
    assert!(result.success());
    assert!(duplicate_control(a.as_fd()).is_ok());
}

#[test]
fn init_transport_only_acknowledges_bootstrap_then_shutdown() {
    // Run separately so the PID1 reaper cannot consume other test children.
    const MARKER: &str = "CHIMERA_B5_TEST_INIT_LOOP";
    if std::env::var_os(MARKER).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "job::execution_domain::linux::launcher_test::init_transport_only_acknowledges_bootstrap_then_shutdown", "--nocapture"])
            .env(MARKER, "1").status().unwrap();
        assert!(status.success());
        return;
    }
    use crate::job::execution_domain::protocol::{
        BootstrapSpec, ControlConnection, Request, Response,
    };
    use crate::job::execution_domain::{CancelReason, FailureCategory, StepFilesId};
    let attempt = AttemptIdentity::new();
    let (a, b) = UnixStream::pair().unwrap();
    let peer = std::thread::spawn(move || {
        super::init::serve(ControlConnection::new(b, attempt).unwrap(), attempt)
    });
    let mut connection = ControlConnection::new(a, attempt).unwrap();
    let bootstrap = BootstrapSpec {
        attempt,
        rootfs: super::rootfs::RootfsPlan {
            inputs: vec![],
            staging_root: "/test/rootfs".into(),
        },
        hostname: "attempt-7".into(),
    };
    assert!(matches!(
        connection
            .request(Request::Bootstrap {
                spec: bootstrap.clone()
            })
            .unwrap(),
        Response::Bootstrapped
    ));
    for request in [
        Request::Hello,
        Request::ReadStep {
            id: StepFilesId::new(),
        },
        Request::PrepareStep {
            id: StepFilesId::new(),
            event: vec![],
        },
        Request::CancelCommand {
            command_id: 1,
            reason: CancelReason::User,
        },
    ] {
        assert!(matches!(
            connection.request(request).unwrap(),
            Response::Rejected {
                category: FailureCategory::NotReady
            }
        ));
    }
    assert!(matches!(
        connection
            .request(Request::Bootstrap { spec: bootstrap })
            .unwrap(),
        Response::Rejected {
            category: FailureCategory::Protocol
        }
    ));
    assert!(matches!(
        connection
            .request(Request::Shutdown {
                reason: CancelReason::Shutdown
            })
            .unwrap(),
        Response::ShuttingDown
    ));
    peer.join().unwrap().unwrap();
}

#[test]
fn kernel_handle_retains_deadline_and_detects_failed_launcher() {
    use crate::job::execution_domain::protocol::{
        BootstrapSpec, ControlConnection, Message, Request, Response,
    };
    let attempt = AttemptIdentity::new();
    let (a, b) = UnixStream::pair().unwrap();
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
    assert!(raw >= 0);
    use std::os::fd::FromRawFd;
    let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    let peer = std::thread::spawn(move || {
        let mut control = ControlConnection::new(b, attempt).unwrap();
        assert!(matches!(
            control
                .receive(Instant::now() + Duration::from_secs(2))
                .unwrap(),
            Message::Request(Request::Bootstrap { .. })
        ));
        control
            .send(
                Message::Response(Response::Bootstrapped),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert!(matches!(
            control
                .receive(Instant::now() + Duration::from_secs(2))
                .unwrap(),
            Message::Request(Request::Hello)
        ));
        control
            .send(
                Message::Response(Response::KernelReady),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        let namespaces = NamespaceHandles::open_current_for_test().unwrap();
        send_namespace_handles(control.control_fd(), &namespaces).unwrap();
    });
    let spec = BootstrapSpec {
        attempt,
        rootfs: super::rootfs::RootfsPlan {
            inputs: vec![],
            staging_root: "/test/rootfs".into(),
        },
        hostname: "attempt".into(),
    };
    let mut handle = KernelDomain {
        control: ControlConnection::new(a, attempt).unwrap(),
        launcher: child,
        pidfd,
        deadline: Instant::now() + Duration::from_secs(2),
        namespaces: None,
        require_foreign_namespaces: false,
    };
    handle.bootstrap(spec.clone()).unwrap();
    peer.join().unwrap();
    handle.launcher.kill().unwrap();
    handle.launcher.wait().unwrap();
    assert!(handle.bootstrap(spec).is_err());
}
