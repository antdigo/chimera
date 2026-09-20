use std::collections::HashMap;
use std::time::Duration;

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
    let completed = crate::job::execute::complete_step_transaction(
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
    let env = HashMap::from([("GITHUB_ENV".into(), "/github/workflow/_env".into())]);
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
            "touch /github/workflow/exec-started; sleep 1; printf 'LATE_ENV=leak\\n' > \"$GITHUB_ENV\"; printf '%s\\n' '::set-env name=LATE_STDOUT::leak'; sleep 30".into(),
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
    crate::job::execute::complete_step_transaction(
        &domain,
        first_state_id,
        &processor,
        &mut job_state,
        Ok(result),
    )
    .await
    .unwrap();

    let next_state_id = domain.prepare_step(b"{}").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let next = domain
        .read_step(next_state_id)
        .await
        .unwrap()
        .parse()
        .unwrap();
    let inspected = docker.inspect_container(&container.id, None).await.unwrap();

    assert!(next.env.is_empty(), "late exec write reached the next step");
    assert_eq!(inspected.state.and_then(|state| state.running), Some(false));
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
