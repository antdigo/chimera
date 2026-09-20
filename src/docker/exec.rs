use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::container::{KillContainerOptions, StopContainerOptions};
use bollard::exec::{CreateExecOptions, StartExecResults};
use futures::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::output::{DockerErrorDiagnostic, DockerLogFramer, OutputProcessor};
use crate::job::execute::{StepConclusion, StepResult};

const EXEC_STOP_TIMEOUT_SECS: i64 = 5;

/// Run a command inside a running container via `docker exec`.
///
/// This is the container equivalent of `run_process()` — it handles stdout/stderr
/// streaming, workflow command parsing, timeout, and cancellation.
#[allow(clippy::too_many_arguments)]
pub async fn docker_exec(
    docker: &Docker,
    container_id: &str,
    cmd: Vec<String>,
    env: &HashMap<String, String>,
    working_dir: &str,
    processor: &OutputProcessor,
    timeout: Duration,
    cancel_token: &CancellationToken,
) -> Result<StepResult> {
    let env_list: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();

    let exec = docker
        .create_exec(
            container_id,
            CreateExecOptions::<String> {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(cmd),
                env: Some(env_list),
                working_dir: Some(working_dir.to_string()),
                ..Default::default()
            },
        )
        .await
        .context("creating docker exec")?;

    let exec_output = docker
        .start_exec(&exec.id, None)
        .await
        .context("starting docker exec")?;

    let StartExecResults::Attached { mut output, .. } = exec_output else {
        anyhow::bail!("docker exec did not return attached output");
    };

    let stream_processor = processor.clone();
    let mut stream_task = tokio::spawn(async move {
        let mut framer = DockerLogFramer::default();
        loop {
            match output.next().await {
                Some(Ok(output)) => {
                    for line in framer.push(output) {
                        stream_processor.process_line(&line).await;
                    }
                }
                Some(Err(error)) => {
                    let diagnostic = DockerErrorDiagnostic::from(&error);
                    warn!(
                        error_kind = diagnostic.kind,
                        status_code = ?diagnostic.status_code,
                        error_code = ?diagnostic.error_code,
                        column = ?diagnostic.column,
                        "Docker exec log stream failed"
                    );
                    return;
                }
                None => break,
            }
        }
        for line in framer.finish() {
            stream_processor.process_line(&line).await;
        }
    });
    let interruption = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => {
            warn!("job cancelled, docker exec will be stopped");
            Some(StepConclusion::Cancelled)
        }
        _ = tokio::time::sleep(timeout) => {
            warn!("docker exec timed out");
            Some(StepConclusion::Failed)
        }
        joined = &mut stream_task => {
            if let Err(error) = joined {
                warn!(error = %error, "docker exec stream task panicked");
            }
            None
        }
    };

    if let Some(conclusion) = interruption {
        stop_exec_container(docker, container_id).await?;
        if let Err(error) = stream_task.await {
            warn!(error = %error, "docker exec stream task failed while reaping");
        }
        let inspect = docker
            .inspect_exec(&exec.id)
            .await
            .context("confirming interrupted docker exec termination")?;
        anyhow::ensure!(
            inspect.running != Some(true),
            "interrupted docker exec remained running after its container stopped"
        );
        return Ok(StepResult { conclusion });
    }

    // Check exit code
    let inspect = docker
        .inspect_exec(&exec.id)
        .await
        .context("inspecting docker exec result")?;

    let exit_code = inspect.exit_code.unwrap_or(-1);
    let conclusion = if exit_code == 0 {
        StepConclusion::Succeeded
    } else {
        StepConclusion::Failed
    };

    Ok(StepResult { conclusion })
}

async fn stop_exec_container(docker: &Docker, container_id: &str) -> Result<()> {
    if let Err(error) = docker
        .stop_container(
            container_id,
            Some(StopContainerOptions {
                t: EXEC_STOP_TIMEOUT_SECS,
            }),
        )
        .await
    {
        let diagnostic = DockerErrorDiagnostic::from(&error);
        warn!(
            error_kind = diagnostic.kind,
            status_code = ?diagnostic.status_code,
            error_code = ?diagnostic.error_code,
            column = ?diagnostic.column,
            "stopping interrupted Docker exec container failed; checking terminal state"
        );
    }

    let inspected = docker
        .inspect_container(container_id, None)
        .await
        .context("inspecting interrupted docker exec container")?;
    if inspected.state.and_then(|state| state.running) == Some(true) {
        docker
            .kill_container(
                container_id,
                Some(KillContainerOptions { signal: "SIGKILL" }),
            )
            .await
            .context("killing interrupted docker exec container")?;
    }

    let inspected = docker
        .inspect_container(container_id, None)
        .await
        .context("confirming interrupted docker exec container termination")?;
    anyhow::ensure!(
        inspected.state.and_then(|state| state.running) != Some(true),
        "interrupted docker exec container remained running"
    );
    Ok(())
}

#[cfg(test)]
#[path = "exec_test.rs"]
mod exec_test;
