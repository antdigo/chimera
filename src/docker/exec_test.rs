use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::job::execute::{JobState, StepConclusion};
use crate::job::execution_domain::{AttemptIdentity, ExecutionDomainRoot};
use crate::job::logs::LogSender;
use crate::job::workspace::Workspace;
use std::num::NonZeroUsize;

/// Integration test: requires Docker daemon running.
#[tokio::test]
#[ignore]
async fn exec_echo_in_container() {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:latest", None)
        .await
        .unwrap();

    let name = format!("chimera-exec-test-{}", uuid::Uuid::new_v4());

    use bollard::container::{Config, CreateContainerOptions, RemoveContainerOptions};
    let config = Config {
        image: Some("alpine:latest"),
        cmd: Some(vec!["tail", "-f", "/dev/null"]),
        ..Default::default()
    };
    let container = docker
        .create_container(
            Some(CreateContainerOptions {
                name: name.as_str(),
                ..Default::default()
            }),
            config,
        )
        .await
        .unwrap();
    docker
        .start_container::<String>(&container.id, None)
        .await
        .unwrap();

    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (tx, _rx) = tokio::sync::mpsc::channel(256);
    let sender = LogSender::new_for_test(tx, masks.clone());
    let processor = OutputProcessor::new(sender, masks, false);

    let result = docker_exec(
        &docker,
        &container.id,
        vec!["echo".into(), "hello".into()],
        &HashMap::new(),
        "/",
        &processor,
        Duration::from_secs(30),
        &CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);

    // Cleanup
    let _ = docker.stop_container(&container.id, None).await;
    let _ = docker
        .remove_container(
            &container.id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

/// Integration test: verify a failing command returns Failed.
#[tokio::test]
#[ignore]
async fn exec_failing_command() {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:latest", None)
        .await
        .unwrap();

    let name = format!("chimera-exec-fail-{}", uuid::Uuid::new_v4());

    use bollard::container::{Config, CreateContainerOptions, RemoveContainerOptions};
    let config = Config {
        image: Some("alpine:latest"),
        cmd: Some(vec!["tail", "-f", "/dev/null"]),
        ..Default::default()
    };
    let container = docker
        .create_container(
            Some(CreateContainerOptions {
                name: name.as_str(),
                ..Default::default()
            }),
            config,
        )
        .await
        .unwrap();
    docker
        .start_container::<String>(&container.id, None)
        .await
        .unwrap();

    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (tx, _rx) = tokio::sync::mpsc::channel(256);
    let sender = LogSender::new_for_test(tx, masks.clone());
    let processor = OutputProcessor::new(sender, masks, false);

    let result = docker_exec(
        &docker,
        &container.id,
        vec!["sh".into(), "-c".into(), "exit 1".into()],
        &HashMap::new(),
        "/",
        &processor,
        Duration::from_secs(30),
        &CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Failed);

    let _ = docker.stop_container(&container.id, None).await;
    let _ = docker
        .remove_container(
            &container.id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
#[ignore]
async fn exec_malformed_state_does_not_apply_buffered_workflow_commands() {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:latest", None)
        .await
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let workspace = Workspace::create(
        &temp.path().join("work"),
        &temp.path().join("tmp"),
        &temp.path().join("tool-cache"),
        "test-runner",
        "owner/repo",
    )
    .unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    domain.bind_workspace(&workspace).await.unwrap();
    let state_id = domain.prepare_step(b"{}").await.unwrap();
    let workflow_dir = workspace.workspace_dir().parent().unwrap();
    let name = format!("chimera-exec-state-test-{}", uuid::Uuid::new_v4());
    let config = bollard::container::Config {
        image: Some("alpine:latest"),
        cmd: Some(vec!["tail", "-f", "/dev/null"]),
        host_config: Some(bollard::models::HostConfig {
            binds: Some(vec![format!("{}:/github/workflow", workflow_dir.display())]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let container = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: name.as_str(),
                ..Default::default()
            }),
            config,
        )
        .await
        .unwrap();
    docker
        .start_container::<String>(&container.id, None)
        .await
        .unwrap();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(32);
    let sender = LogSender::new_for_test(log_tx, masks.clone());
    let processor = OutputProcessor::new(sender, masks.clone(), false);
    let mut job_state = JobState::new(masks, HashMap::new(), serde_json::json!({}));
    let env = HashMap::from([
        ("GITHUB_ENV".into(), "/github/workflow/_env".into()),
        ("GITHUB_OUTPUT".into(), "/github/workflow/_output".into()),
    ]);

    let result = docker_exec(
        &docker,
        &container.id,
        vec![
            "sh".into(),
            "-c".into(),
            "printf '%s\\n' '::set-env name=STDOUT_ENV::leak' '::set-output name=stdout_output::leak'; printf 'FILE_ENV=leak\\n' > \"$GITHUB_ENV\"; printf '\\377' >> \"$GITHUB_ENV\"; printf 'file_output=leak\\n' > \"$GITHUB_OUTPUT\"".into(),
        ],
        &env,
        "/",
        &processor,
        Duration::from_secs(30),
        &CancellationToken::new(),
    )
    .await;
    let completed = crate::job::execute::complete_docker_exec_transaction(
        &domain,
        state_id,
        &processor,
        &mut job_state,
        result,
    )
    .await;

    assert!(completed.is_err());
    assert!(job_state.env.is_empty());
    assert!(job_state.outputs.is_empty());
    let next = domain.prepare_step(b"{}").await.unwrap();
    domain.read_step(next).await.unwrap();

    let _ = docker.stop_container(&container.id, None).await;
    let _ = docker
        .remove_container(
            &container.id,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[derive(Clone, Copy)]
enum ExecInterruption {
    Cancel,
    Timeout,
}

async fn assert_interrupted_exec_cannot_write_into_next_step(interruption: ExecInterruption) {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:latest", None)
        .await
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let workspace = Workspace::create(
        &temp.path().join("work"),
        &temp.path().join("tmp"),
        &temp.path().join("tool-cache"),
        "test-runner",
        "owner/repo",
    )
    .unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    domain.bind_workspace(&workspace).await.unwrap();
    let first_state_id = domain.prepare_step(b"{}").await.unwrap();
    let workflow_dir = workspace.workspace_dir().parent().unwrap();
    let started = workflow_dir.join("exec-started");
    let name = format!("chimera-exec-terminal-test-{}", uuid::Uuid::new_v4());
    let container = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: name.as_str(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("alpine:latest"),
                cmd: Some(vec!["tail", "-f", "/dev/null"]),
                host_config: Some(bollard::models::HostConfig {
                    binds: Some(vec![format!("{}:/github/workflow", workflow_dir.display())]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container::<String>(&container.id, None)
        .await
        .unwrap();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(32);
    let processor = OutputProcessor::new(
        LogSender::new_for_test(log_tx, masks.clone()),
        masks.clone(),
        false,
    );
    let mut job_state = JobState::new(masks, HashMap::new(), serde_json::json!({}));
    let env = HashMap::from([
        ("GITHUB_ENV".into(), "/github/workflow/_env".into()),
        ("GITHUB_PATH".into(), "/github/workflow/_path".into()),
    ]);
    let cancel = CancellationToken::new();
    let timeout = match interruption {
        ExecInterruption::Cancel => Duration::from_secs(30),
        ExecInterruption::Timeout => Duration::from_millis(200),
    };
    let trigger_cancel = async {
        if matches!(interruption, ExecInterruption::Cancel) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !started.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("docker exec must start before cancellation");
            cancel.cancel();
        }
    };
    let run = docker_exec(
        &docker,
        &container.id,
        vec![
            "sh".into(),
            "-c".into(),
            "for control in /tmp/.chimera-exec-*.pid; do test ! -e \"$control\" || printf '1\\n' > \"$control\"; done; setsid sh -c 'sleep 1; printf \"LATE_ENV=leak\\n\" > \"$GITHUB_ENV\"' </dev/null >/dev/null 2>&1 & touch /github/workflow/exec-started; sleep 30".into(),
        ],
        &env,
        "/",
        &processor,
        timeout,
        &cancel,
    );

    let (result, ()) = tokio::join!(run, trigger_cancel);
    let result = result.unwrap();
    assert_eq!(
        result.conclusion,
        match interruption {
            ExecInterruption::Cancel => StepConclusion::Cancelled,
            ExecInterruption::Timeout => StepConclusion::Failed,
        }
    );
    crate::job::execute::complete_docker_exec_transaction(
        &domain,
        first_state_id,
        &processor,
        &mut job_state,
        Ok(result),
    )
    .await
    .unwrap();

    let next_state_id = domain.prepare_step(b"{}").await.unwrap();
    let next_processor = OutputProcessor::new(
        LogSender::new_for_test(
            tokio::sync::mpsc::channel(32).0,
            crate::job::secret_masker::shared_masker_for_test(&[]),
        ),
        crate::job::secret_masker::shared_masker_for_test(&[]),
        false,
    );
    let next_result = docker_exec(
        &docker,
        &container.id,
        vec![
            "sh".into(),
            "-c".into(),
            "sleep 2; set -- /tmp/.chimera-exec-*.pid; test ! -e \"$1\"; printf '%s\\n' '::add-path::/stdout/docker-exec'; printf '/file/docker-exec\\n' > \"$GITHUB_PATH\"; printf 'NEXT_ENV=ok\\n' > \"$GITHUB_ENV\"".into(),
        ],
        &env,
        "/",
        &next_processor,
        Duration::from_secs(10),
        &CancellationToken::new(),
    )
    .await;
    crate::job::execute::complete_docker_exec_transaction(
        &domain,
        next_state_id,
        &next_processor,
        &mut job_state,
        next_result,
    )
    .await
    .unwrap();

    assert_eq!(
        job_state.env.get("NEXT_ENV").map(String::as_str),
        Some("ok")
    );
    assert!(!job_state.env.contains_key("LATE_ENV"));

    let post_state_id = domain.prepare_step(b"{}").await.unwrap();
    let post_processor = OutputProcessor::new(
        LogSender::new_for_test(
            tokio::sync::mpsc::channel(32).0,
            crate::job::secret_masker::shared_masker_for_test(&[]),
        ),
        crate::job::secret_masker::shared_masker_for_test(&[]),
        false,
    );
    let post_result = docker_exec(
        &docker,
        &container.id,
        vec![
            "sh".into(),
            "-c".into(),
            "printf 'POST_ENV=ok\\n' > \"$GITHUB_ENV\"".into(),
        ],
        &env,
        "/",
        &post_processor,
        Duration::from_secs(10),
        &CancellationToken::new(),
    )
    .await;
    crate::job::execute::complete_docker_exec_transaction(
        &domain,
        post_state_id,
        &post_processor,
        &mut job_state,
        post_result,
    )
    .await
    .unwrap();
    let inspected = docker.inspect_container(&container.id, None).await.unwrap();

    assert_eq!(
        job_state.env.get("POST_ENV").map(String::as_str),
        Some("ok")
    );
    assert_eq!(
        job_state.path_prepends,
        ["/stdout/docker-exec", "/file/docker-exec"]
    );
    assert_eq!(inspected.state.and_then(|state| state.running), Some(true));
    let _ = docker.stop_container(&container.id, None).await;
    let _ = docker
        .remove_container(
            &container.id,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
#[ignore]
async fn cancelled_exec_is_stopped_before_state_snapshot() {
    assert_interrupted_exec_cannot_write_into_next_step(ExecInterruption::Cancel).await;
}

#[tokio::test]
#[ignore]
async fn timed_out_exec_is_stopped_before_state_snapshot() {
    assert_interrupted_exec_cannot_write_into_next_step(ExecInterruption::Timeout).await;
}

#[derive(Clone, Copy)]
enum ProxyFault {
    DisconnectStart,
    DelayCreate,
    DelayStart,
}

struct FaultingDockerProxy {
    _directory: tempfile::TempDir,
    socket: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl FaultingDockerProxy {
    async fn start(upstream: &Path, fault: ProxyFault) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let upstream = upstream.to_owned();
        let injected = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                let upstream = upstream.clone();
                let injected = Arc::clone(&injected);
                tokio::spawn(async move {
                    let mut daemon = UnixStream::connect(upstream).await.unwrap();
                    let mut request = Vec::with_capacity(1024);
                    loop {
                        let mut byte = [0_u8; 1];
                        if client.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        request.push(byte[0]);
                        if request.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let headers = String::from_utf8_lossy(&request).to_ascii_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut body = vec![0_u8; content_length];
                    client.read_exact(&mut body).await.unwrap();
                    daemon.write_all(&request).await.unwrap();
                    daemon.write_all(&body).await.unwrap();
                    let request_line = request.split(|byte| *byte == b'\r').next().unwrap_or(&[]);
                    let is_exec_create = request_line.starts_with(b"POST ")
                        && request_line
                            .windows(b"/containers/".len())
                            .any(|part| part == b"/containers/")
                        && request_line
                            .windows(b"/exec ".len())
                            .any(|part| part == b"/exec ");
                    let is_exec_start = request_line.starts_with(b"POST ")
                        && request_line
                            .windows(b"/exec/".len())
                            .any(|part| part == b"/exec/")
                        && request_line
                            .windows(b"/start".len())
                            .any(|part| part == b"/start");
                    let matches_fault = match fault {
                        ProxyFault::DisconnectStart | ProxyFault::DelayStart => is_exec_start,
                        ProxyFault::DelayCreate => is_exec_create,
                    };
                    let should_inject = matches_fault
                        && injected
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok();
                    if should_inject {
                        match fault {
                            ProxyFault::DisconnectStart => {
                                tokio::time::sleep(Duration::from_millis(300)).await;
                                return;
                            }
                            ProxyFault::DelayCreate | ProxyFault::DelayStart => {
                                tokio::time::sleep(Duration::from_millis(500)).await;
                            }
                        }
                    }
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut daemon).await;
                });
            }
        });
        Self {
            _directory: directory,
            socket,
            task,
        }
    }
}

impl Drop for FaultingDockerProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn pre_cancelled_exec_does_not_contact_docker() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("docker.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    let docker = bollard::Docker::connect_with_unix(
        socket.to_str().unwrap(),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .unwrap();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let processor = OutputProcessor::new(
        LogSender::new_for_test(tokio::sync::mpsc::channel(8).0, masks.clone()),
        masks,
        false,
    );
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = docker_exec(
        &docker,
        "never-contact-daemon",
        vec!["irrelevant".into()],
        &HashMap::new(),
        "/",
        &processor,
        Duration::from_secs(30),
        &cancel,
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Cancelled);
}

async fn assert_rpc_deadline_recovers_same_container(fault: ProxyFault) {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:latest", None)
        .await
        .unwrap();
    let docker_host = std::env::var("DOCKER_HOST").expect("DinD test requires DOCKER_HOST");
    let upstream = docker_host
        .strip_prefix("unix://")
        .expect("DinD test requires a Unix Docker socket");
    let proxy = FaultingDockerProxy::start(Path::new(upstream), fault).await;
    let proxied_docker = bollard::Docker::connect_with_unix(
        proxy.socket.to_str().unwrap(),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .unwrap();
    let name = format!("chimera-exec-rpc-deadline-{}", uuid::Uuid::new_v4());
    let container = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: name.as_str(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("alpine:latest"),
                cmd: Some(vec!["tail", "-f", "/dev/null"]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container::<String>(&container.id, None)
        .await
        .unwrap();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let processor = OutputProcessor::new(
        LogSender::new_for_test(tokio::sync::mpsc::channel(8).0, masks.clone()),
        masks,
        false,
    );

    let interrupted = docker_exec(
        &proxied_docker,
        &container.id,
        vec!["sh".into(), "-c".into(), "sleep 30".into()],
        &HashMap::new(),
        "/",
        &processor,
        Duration::from_millis(100),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    let next = docker_exec(
        &proxied_docker,
        &container.id,
        vec!["sh".into(), "-c".into(), "exit 0".into()],
        &HashMap::new(),
        "/",
        &processor,
        Duration::from_secs(5),
        &CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(interrupted.conclusion, StepConclusion::Failed);
    assert_eq!(next.conclusion, StepConclusion::Succeeded);
    assert_eq!(
        docker
            .inspect_container(&container.id, None)
            .await
            .unwrap()
            .state
            .and_then(|state| state.running),
        Some(true)
    );

    let _ = docker.stop_container(&container.id, None).await;
    let _ = docker
        .remove_container(
            &container.id,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
#[ignore]
async fn create_exec_deadline_recovers_same_container() {
    assert_rpc_deadline_recovers_same_container(ProxyFault::DelayCreate).await;
}

#[tokio::test]
#[ignore]
async fn start_exec_deadline_recovers_same_container() {
    assert_rpc_deadline_recovers_same_container(ProxyFault::DelayStart).await;
}

#[tokio::test]
#[ignore]
async fn early_exec_stream_end_is_terminalized_before_next_step() {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:latest", None)
        .await
        .unwrap();
    let docker_host = std::env::var("DOCKER_HOST").expect("DinD test requires DOCKER_HOST");
    let upstream = docker_host
        .strip_prefix("unix://")
        .expect("DinD test requires a Unix Docker socket");
    let proxy = FaultingDockerProxy::start(Path::new(upstream), ProxyFault::DisconnectStart).await;
    let proxied_docker = bollard::Docker::connect_with_unix(
        proxy.socket.to_str().unwrap(),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .unwrap();

    let temp = tempfile::tempdir().unwrap();
    let workspace = Workspace::create(
        &temp.path().join("work"),
        &temp.path().join("tmp"),
        &temp.path().join("tool-cache"),
        "test-runner",
        "owner/repo",
    )
    .unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let domain = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    domain.bind_workspace(&workspace).await.unwrap();
    let first_state_id = domain.prepare_step(b"{}").await.unwrap();
    let workflow_dir = workspace.workspace_dir().parent().unwrap();
    let name = format!("chimera-exec-stream-test-{}", uuid::Uuid::new_v4());
    let container = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: name.as_str(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("alpine:latest"),
                cmd: Some(vec!["tail", "-f", "/dev/null"]),
                host_config: Some(bollard::models::HostConfig {
                    binds: Some(vec![format!("{}:/github/workflow", workflow_dir.display())]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container::<String>(&container.id, None)
        .await
        .unwrap();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let processor = OutputProcessor::new(
        LogSender::new_for_test(tokio::sync::mpsc::channel(32).0, masks.clone()),
        masks.clone(),
        false,
    );
    let mut job_state = JobState::new(masks, HashMap::new(), serde_json::json!({}));
    let env = HashMap::from([("GITHUB_ENV".into(), "/github/workflow/_env".into())]);

    let first_result = docker_exec(
        &proxied_docker,
        &container.id,
        vec![
            "sh".into(),
            "-c".into(),
            "sleep 1; printf 'LATE_ENV=leak\\n' > \"$GITHUB_ENV\"; sleep 30".into(),
        ],
        &env,
        "/",
        &processor,
        Duration::from_secs(30),
        &CancellationToken::new(),
    )
    .await;
    let first_completed = crate::job::execute::complete_docker_exec_transaction(
        &domain,
        first_state_id,
        &processor,
        &mut job_state,
        first_result,
    )
    .await;

    let next_state_id = domain.prepare_step(b"{}").await.unwrap();
    let next_masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let next_processor = OutputProcessor::new(
        LogSender::new_for_test(tokio::sync::mpsc::channel(32).0, next_masks.clone()),
        next_masks,
        false,
    );
    let next_result = docker_exec(
        &proxied_docker,
        &container.id,
        vec![
            "sh".into(),
            "-c".into(),
            "sleep 2; printf 'NEXT_ENV=ok\\n' > \"$GITHUB_ENV\"".into(),
        ],
        &env,
        "/",
        &next_processor,
        Duration::from_secs(10),
        &CancellationToken::new(),
    )
    .await;
    crate::job::execute::complete_docker_exec_transaction(
        &domain,
        next_state_id,
        &next_processor,
        &mut job_state,
        next_result,
    )
    .await
    .unwrap();

    assert!(first_completed.is_err());
    assert_eq!(
        job_state.env.get("NEXT_ENV").map(String::as_str),
        Some("ok")
    );
    assert!(!job_state.env.contains_key("LATE_ENV"));
    assert_eq!(
        docker
            .inspect_container(&container.id, None)
            .await
            .unwrap()
            .state
            .and_then(|state| state.running),
        Some(true)
    );

    let _ = docker.stop_container(&container.id, None).await;
    let _ = docker
        .remove_container(
            &container.id,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}
