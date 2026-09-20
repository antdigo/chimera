use super::*;
use crate::job::execution_domain::CommandOutcome;

#[test]
fn init_exit_status_preserves_signal_vs_exit_code() {
    assert_eq!(decode_wait_status(7 << 8), CommandOutcome::Exited(7));
    assert_eq!(
        decode_wait_status(libc::SIGTERM),
        CommandOutcome::Signalled(libc::SIGTERM)
    );
}

#[test]
fn command_preparation_clears_inherited_environment_and_rejects_reserved_overrides() {
    use crate::job::execution_domain::{CommandSpec, CommandTarget, DomainPath};
    use std::collections::HashMap;
    let spec = || CommandSpec {
        target: CommandTarget::Sandboxed {
            program: DomainPath::parse("/bin/sh").unwrap(),
            args: vec!["-c".into(), "exit 7".into()],
            cwd: DomainPath::parse("/").unwrap(),
        },
        env: HashMap::from([("SAFE".into(), "value".into())]),
        timeout: std::time::Duration::from_secs(1),
        state: None,
    };
    let prepared = PreparedCommand::new(spec()).unwrap();
    let values: Vec<_> = prepared
        .env
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert!(values.contains(&"SAFE=value"));
    assert!(values.contains(&"HOME=/home/chimera"));
    assert!(values.contains(&"DOCKER_HOST=unix:///run/chimera/docker.sock"));
    assert_eq!(values.len(), 5);
    let mut bad = spec();
    bad.env.insert("DOCKER_HOST".into(), "CANARY_SECRET".into());
    assert!(PreparedCommand::new(bad).is_err());
    let mut bad = spec();
    bad.env.insert("BAD=KEY".into(), "value".into());
    assert!(PreparedCommand::new(bad).is_err());
    let mut bad = spec();
    bad.timeout = std::time::Duration::MAX;
    assert!(PreparedCommand::new(bad).is_err());
}

#[test]
fn command_state_binding_injects_private_files_and_rejects_any_override() {
    let root = tempfile::tempdir().unwrap();
    let mut steps = StepFiles::create(root.path()).unwrap();
    let id = StepFilesId::new();
    steps.prepare(id.clone(), b"{}").unwrap();
    let spec = CommandSpec {
        target: CommandTarget::Sandboxed {
            program: DomainPath::parse("/bin/sh").unwrap(),
            args: vec![],
            cwd: DomainPath::parse("/").unwrap(),
        },
        env: HashMap::new(),
        timeout: Duration::from_secs(1),
        state: Some(id.clone()),
    };
    let prepared = PreparedCommand::with_state(spec.clone(), &steps).unwrap();
    let env: Vec<_> = prepared
        .env
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert!(
        env.contains(
            &format!(
                "GITHUB_EVENT_PATH=/run/chimera/steps/{}/event.json",
                id.component()
            )
            .as_str()
        )
    );
    assert!(
        env.contains(&format!("GITHUB_STATE=/run/chimera/steps/{}/state", id.component()).as_str())
    );
    for key in [
        "GITHUB_ENV",
        "GITHUB_PATH",
        "GITHUB_OUTPUT",
        "GITHUB_STATE",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_EVENT_PATH",
    ] {
        let mut bad = spec.clone();
        bad.env.insert(key.into(), "/CANARY".into());
        let error = PreparedCommand::with_state(bad, &steps).err().unwrap();
        assert!(!format!("{error:?}").contains("CANARY"));
    }
    let mut unknown = spec;
    unknown.state = Some(StepFilesId::new());
    assert!(PreparedCommand::with_state(unknown, &steps).is_err());
}

use super::super::hardening::hardening_test::{fixture_policy, native_child};
use crate::job::execution_domain::{CommandEvent, CommandTarget, DomainPath};
use std::collections::HashMap;

struct Fixture {
    connection: ControlConnection,
    pid: i32,
    root: tempfile::TempDir,
}

impl Fixture {
    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let policy = fixture_policy(root.path());
        let attempt = AttemptIdentity::new();
        let (a, b) = UnixStream::pair().unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            drop(a);
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
            retain_init_capabilities().unwrap();
            let runtime = InitRuntime {
                connection: ControlConnection::new(b, attempt).unwrap(),
                policy,
                active: None,
                outbound: OutboundQueue::new(),
                sending: false,
                connected: true,
                stopping: false,
                write_deadline: None,
                terminal_error: None,
                last_command_id: 0,
                steps: StepFiles::create(root.path()).unwrap(),
                event: None,
                snapshot: Default::default(),
            };
            let result = runtime.run();
            unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
        }
        drop(b);
        Self {
            connection: ControlConnection::new(a, attempt).unwrap(),
            pid,
            root,
        }
    }
    fn send(&mut self, request: Request) {
        self.connection
            .send(
                Message::Request(request),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
    }
    fn run(&mut self, id: u64, script: &str, timeout: Duration) {
        self.send(Request::Run {
            command_id: id,
            spec: CommandSpec {
                target: CommandTarget::Sandboxed {
                    program: DomainPath::parse("/bin/sh").unwrap(),
                    args: vec!["-c".into(), script.into()],
                    cwd: DomainPath::parse(self.root.path().to_str().unwrap()).unwrap(),
                },
                env: HashMap::new(),
                timeout,
                state: None,
            },
        });
    }
    fn receive(&mut self) -> Response {
        let Message::Response(response) = self
            .connection
            .receive(Instant::now() + Duration::from_secs(10))
            .unwrap()
        else {
            panic!()
        };
        response
    }
    fn finish(&mut self, id: u64) -> (CommandOutcome, Vec<u8>, Vec<u8>) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            match self.receive() {
                Response::Output { command_id, event } => {
                    assert_eq!(command_id, id);
                    match event {
                        CommandEvent::Stdout(bytes) => stdout.extend(bytes),
                        CommandEvent::Stderr(bytes) => stderr.extend(bytes),
                    }
                }
                Response::CommandFinished {
                    command_id,
                    outcome,
                } => {
                    assert_eq!(command_id, id);
                    return (outcome, stdout, stderr);
                }
                response => panic!("unexpected response {response:?}"),
            }
        }
    }
    fn shutdown(mut self) {
        self.send(Request::Shutdown {
            reason: CancelReason::Shutdown,
        });
        assert!(matches!(self.receive(), Response::ShuttingDown));
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(self.pid, &mut status, 0) }, self.pid);
        self.pid = 0;
        assert_eq!(status, 0);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.pid != 0 {
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                libc::waitpid(self.pid, std::ptr::null_mut(), 0);
            }
        }
    }
}

#[test]
#[ignore = "requires disposable user/mount namespaces and Landlock"]
fn native_state_protocol_roundtrip_and_command_binding() {
    if !native_child(
        "job::execution_domain::linux::init::init_test::native_state_protocol_roundtrip_and_command_binding",
    ) {
        return;
    }
    let mut fixture = Fixture::start();
    let id = StepFilesId::new();
    let response = fixture
        .connection
        .request(Request::PrepareStep {
            id: id.clone(),
            event: vec![b' '; 4 * 1024 * 1024],
        })
        .unwrap();
    assert!(matches!(response, Response::StepPrepared { id: actual } if actual == id));
    let directory = fixture.root.path().join("steps").join(id.component());
    let env = format!("TOKEN={}\n", "x".repeat(100_000));
    std::fs::write(directory.join("env"), &env).unwrap();
    let response = fixture
        .connection
        .request(Request::ReadStep { id: id.clone() })
        .unwrap();
    assert!(matches!(response, Response::StepSnapshot { snapshot, .. } if snapshot.env == env));
    fixture.send(Request::Run {
        command_id: 1,
        spec: CommandSpec {
            target: CommandTarget::Sandboxed {
                program: DomainPath::parse("/bin/sh").unwrap(),
                args: vec!["-c".into(), "printf '%s' \"$GITHUB_ENV\"".into()],
                cwd: DomainPath::parse(fixture.root.path().to_str().unwrap()).unwrap(),
            },
            env: HashMap::new(),
            timeout: Duration::from_secs(5),
            state: Some(id.clone()),
        },
    });
    assert!(matches!(
        fixture.receive(),
        Response::CommandStarted { command_id: 1 }
    ));
    let (outcome, stdout, _) = fixture.finish(1);
    assert_eq!(outcome, CommandOutcome::Exited(0));
    assert_eq!(
        stdout,
        format!("/run/chimera/steps/{}/env", id.component()).as_bytes()
    );
    let next = StepFilesId::new();
    fixture
        .connection
        .request(Request::PrepareStep {
            id: next.clone(),
            event: b"{}".to_vec(),
        })
        .unwrap();
    let response = fixture
        .connection
        .request(Request::ReadStep { id: next })
        .unwrap();
    assert!(matches!(response, Response::StepSnapshot { snapshot, .. } if snapshot.env.is_empty()));
    fixture.shutdown();
}

#[test]
#[ignore = "disposable Linux user/PID namespace; actual hardened exec/reaping"]
fn init_exec_output_signal_busy_and_orphans_are_correlated() {
    if !native_child(
        "job::execution_domain::linux::init::init_test::init_exec_output_signal_busy_and_orphans_are_correlated",
    ) {
        return;
    }
    let mut fixture = Fixture::start();
    fixture.run(
        1,
        "printf stdout; printf stderr >&2; sleep .1; (sleep .1 &); exit 7",
        Duration::from_secs(5),
    );
    assert!(matches!(
        fixture.receive(),
        Response::CommandStarted { command_id: 1 }
    ));
    fixture.run(2, "exit 0", Duration::from_secs(5));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        match fixture.receive() {
            Response::CommandRejected {
                command_id: 2,
                category: FailureCategory::Unavailable,
            } => break,
            Response::Output {
                command_id: 1,
                event: CommandEvent::Stdout(bytes),
            } => stdout.extend(bytes),
            Response::Output {
                command_id: 1,
                event: CommandEvent::Stderr(bytes),
            } => stderr.extend(bytes),
            response => panic!("unexpected {response:?}"),
        }
    }
    let (outcome, out, err) = fixture.finish(1);
    stdout.extend(out);
    stderr.extend(err);
    assert_eq!(outcome, CommandOutcome::Exited(7));
    assert_eq!(stdout, b"stdout");
    assert_eq!(stderr, b"stderr");
    let reap_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let children = std::fs::read_to_string(format!(
            "/proc/{}/task/{}/children",
            fixture.pid, fixture.pid
        ))
        .unwrap();
        if children.trim().is_empty() {
            break;
        }
        assert!(
            Instant::now() < reap_deadline,
            "unreaped children {children}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    fixture.run(3, "kill -TERM $$", Duration::from_secs(5));
    assert!(matches!(
        fixture.receive(),
        Response::CommandStarted { command_id: 3 }
    ));
    assert_eq!(
        fixture.finish(3).0,
        CommandOutcome::Signalled(libc::SIGTERM)
    );
    fixture.run(3, "exit 0", Duration::from_secs(5));
    assert!(matches!(
        fixture.receive(),
        Response::CommandRejected {
            command_id: 3,
            category: FailureCategory::Protocol
        }
    ));
    let start = Instant::now();
    fixture.run(
        4,
        "exec 1>&- 2>&-; sleep .2; exit 5",
        Duration::from_secs(5),
    );
    assert!(matches!(
        fixture.receive(),
        Response::CommandStarted { command_id: 4 }
    ));
    assert_eq!(fixture.finish(4).0, CommandOutcome::Exited(5));
    assert!(start.elapsed() >= Duration::from_millis(180));
    fixture.shutdown();
}

#[test]
#[ignore = "disposable Linux user/PID namespace; bounded cancellation and pipe drain"]
fn init_timeout_and_cancel_kill_term_ignoring_groups_and_bound_lingering_output() {
    if !native_child(
        "job::execution_domain::linux::init::init_test::init_timeout_and_cancel_kill_term_ignoring_groups_and_bound_lingering_output",
    ) {
        return;
    }
    let mut fixture = Fixture::start();
    let start = Instant::now();
    fixture.run(
        1,
        "trap '' TERM; printf ready; while :; do sleep 1; done",
        Duration::from_millis(300),
    );
    assert!(matches!(
        fixture.receive(),
        Response::CommandStarted { command_id: 1 }
    ));
    let (outcome, stdout, _) = fixture.finish(1);
    assert_eq!(outcome, CommandOutcome::TimedOut);
    assert_eq!(stdout, b"ready");
    assert!(start.elapsed() >= Duration::from_secs(5));
    assert!(start.elapsed() < Duration::from_secs(8));
    fixture.run(
        2,
        "trap '' TERM; printf ready; while :; do sleep 1; done",
        Duration::from_secs(30),
    );
    assert!(matches!(
        fixture.receive(),
        Response::CommandStarted { command_id: 2 }
    ));
    assert!(matches!(
        fixture.receive(),
        Response::Output { command_id: 2, .. }
    ));
    fixture.send(Request::CancelCommand {
        command_id: 2,
        reason: CancelReason::User,
    });
    assert_eq!(fixture.finish(2).0, CommandOutcome::Cancelled);
    let start = Instant::now();
    fixture.run(
        3,
        "setsid sh -c 'sleep 20' & exit 9",
        Duration::from_secs(30),
    );
    assert!(matches!(
        fixture.receive(),
        Response::CommandStarted { command_id: 3 }
    ));
    assert_eq!(fixture.finish(3).0, CommandOutcome::Exited(9));
    assert!(start.elapsed() < Duration::from_secs(4));
    fixture.shutdown();
}

#[test]
#[ignore = "disposable Linux user/PID namespace; output backpressure and control disconnect"]
fn init_backpressure_preserves_cancel_and_disconnect_bounds_reaping() {
    if !native_child(
        "job::execution_domain::linux::init::init_test::init_backpressure_preserves_cancel_and_disconnect_bounds_reaping",
    ) {
        return;
    }
    let mut fixture = Fixture::start();
    fixture.run(
        1,
        "trap '' TERM; while :; do printf 'backpressure output fills both queue and socket'; done",
        Duration::from_secs(30),
    );
    assert!(matches!(
        fixture.receive(),
        Response::CommandStarted { command_id: 1 }
    ));
    std::thread::sleep(Duration::from_millis(200));
    let start = Instant::now();
    fixture.send(Request::CancelCommand {
        command_id: 1,
        reason: CancelReason::User,
    });
    assert_eq!(fixture.finish(1).0, CommandOutcome::Cancelled);
    assert!(start.elapsed() < Duration::from_secs(8));
    fixture.run(
        2,
        "trap '' TERM; printf ready; while :; do printf x; done",
        Duration::from_secs(30),
    );
    assert!(matches!(
        fixture.receive(),
        Response::CommandStarted { command_id: 2 }
    ));
    assert!(matches!(
        fixture.receive(),
        Response::Output { command_id: 2, .. }
    ));
    let start = Instant::now();
    unsafe { libc::shutdown(fixture.connection.control_fd().as_raw_fd(), libc::SHUT_RDWR) };
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(fixture.pid, &mut status, 0) },
        fixture.pid
    );
    fixture.pid = 0;
    assert_eq!(libc::WEXITSTATUS(status), 1);
    assert!(start.elapsed() < Duration::from_secs(8));
}
