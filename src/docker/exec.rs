use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::container::{KillContainerOptions, StopContainerOptions};
use bollard::exec::{CreateExecOptions, StartExecResults};
use futures::StreamExt;
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::output::{DockerErrorDiagnostic, DockerLogFramer, OutputProcessor};
use crate::job::execute::{StepConclusion, StepResult};

const RECOVERY_BUDGET: Duration = Duration::from_secs(10);
const CONTAINER_STOP_TIMEOUT_SECS: i64 = 0;
const CONTAINER_STATE_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Error)]
pub(crate) enum DockerExecRecoveryError {
    #[error("Docker exec recovery exceeded its lifecycle deadline during {stage}")]
    Deadline { stage: &'static str },
    #[error(
        "Docker exec recovery RPC failed during {stage} ({kind}, status {status_code:?}, code {error_code:?})"
    )]
    Rpc {
        stage: &'static str,
        kind: &'static str,
        status_code: Option<u16>,
        error_code: Option<i64>,
    },
    #[error("Docker job container remained running during recovery")]
    ContainerStillRunning,
    #[error("Docker exec remained running after its container stopped")]
    ExecStillRunning,
    #[error("Docker job container was not running after recovery restart")]
    ContainerNotRunning,
}

#[derive(Debug, Error)]
enum DockerExecOperationError {
    #[error("Docker exec create failed ({kind}, status {status_code:?}, code {error_code:?})")]
    Create {
        kind: &'static str,
        status_code: Option<u16>,
        error_code: Option<i64>,
    },
    #[error("Docker exec start failed ({kind}, status {status_code:?}, code {error_code:?})")]
    Start {
        kind: &'static str,
        status_code: Option<u16>,
        error_code: Option<i64>,
    },
    #[error(
        "Docker exec output stream failed ({kind}, status {status_code:?}, code {error_code:?})"
    )]
    Stream {
        kind: &'static str,
        status_code: Option<u16>,
        error_code: Option<i64>,
    },
    #[error("Docker exec output stream task failed")]
    StreamTask,
    #[error("Docker exec attach stream ended before the exec became terminal")]
    EarlyEnd,
    #[error("Docker exec did not return attached output")]
    Detached,
}

enum StreamOutcome {
    Ended,
    Failed(DockerErrorDiagnostic),
}

#[derive(Clone, Copy)]
enum Interruption {
    Cancelled,
    TimedOut,
}

impl Interruption {
    fn result(self) -> StepResult {
        StepResult {
            conclusion: match self {
                Self::Cancelled => StepConclusion::Cancelled,
                Self::TimedOut => StepConclusion::Failed,
            },
        }
    }
}

/// Whether workflow state may still be changing after a Docker exec failure.
///
/// Recovery errors are unsafe: callers must fail closed without reading the
/// command-file snapshot. Operation errors are returned only after terminality
/// or successful container recovery has been proven.
pub(crate) fn state_may_still_change(error: &anyhow::Error) -> bool {
    error.downcast_ref::<DockerExecRecoveryError>().is_some()
}

/// Run a command in a long-lived job container.
///
/// Docker has no API for killing one exec. Interrupted or ambiguous execs are
/// therefore recovered at the container boundary: stop, settle producers,
/// prove terminality, and restart the same container before returning.
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
    if cancel_token.is_cancelled() {
        return Ok(Interruption::Cancelled.result());
    }

    let command_deadline = Instant::now()
        .checked_add(timeout)
        .context("Docker exec timeout exceeds monotonic clock range")?;
    if Instant::now() >= command_deadline {
        return Ok(Interruption::TimedOut.result());
    }

    let env_list: Vec<String> = env
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    let mut create = Box::pin(docker.create_exec(
        container_id,
        CreateExecOptions::<String> {
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            cmd: Some(cmd),
            env: Some(env_list),
            working_dir: Some(working_dir.to_owned()),
            ..Default::default()
        },
    ));

    let exec = match wait_for_stage(&mut create, command_deadline, cancel_token).await {
        StageOutcome::Ready(Ok(exec)) => exec,
        StageOutcome::Ready(Err(error)) => {
            let diagnostic = DockerErrorDiagnostic::from(&error);
            let recovery_deadline = recovery_deadline(command_deadline, Instant::now())?;
            recover_container(docker, container_id, None, recovery_deadline).await?;
            return Err(DockerExecOperationError::Create {
                kind: diagnostic.kind,
                status_code: diagnostic.status_code,
                error_code: diagnostic.error_code,
            }
            .into());
        }
        StageOutcome::Interrupted(interruption) => {
            let recovery_deadline = recovery_deadline(command_deadline, Instant::now())?;
            stop_container_for_recovery(docker, container_id, recovery_deadline).await?;
            let settled =
                before_deadline(recovery_deadline, "settling create-exec RPC", &mut create).await?;
            let exec_id = settled.ok().map(|exec| exec.id);
            if let Some(exec_id) = exec_id.as_deref() {
                prove_exec_stopped(docker, exec_id, recovery_deadline).await?;
            }
            restart_container(docker, container_id, recovery_deadline).await?;
            return Ok(interruption.result());
        }
    };

    let mut start = Box::pin(docker.start_exec(&exec.id, None));
    let start_result = match wait_for_stage(&mut start, command_deadline, cancel_token).await {
        StageOutcome::Ready(Ok(result)) => result,
        StageOutcome::Ready(Err(error)) => {
            let diagnostic = DockerErrorDiagnostic::from(&error);
            let recovery_deadline = recovery_deadline(command_deadline, Instant::now())?;
            recover_container(docker, container_id, Some(&exec.id), recovery_deadline).await?;
            return Err(DockerExecOperationError::Start {
                kind: diagnostic.kind,
                status_code: diagnostic.status_code,
                error_code: diagnostic.error_code,
            }
            .into());
        }
        StageOutcome::Interrupted(interruption) => {
            let recovery_deadline = recovery_deadline(command_deadline, Instant::now())?;
            stop_container_for_recovery(docker, container_id, recovery_deadline).await?;
            let settled =
                before_deadline(recovery_deadline, "settling start-exec RPC", &mut start).await?;
            if let Ok(started) = settled {
                drain_start_result(started, processor, recovery_deadline).await?;
            }
            prove_exec_stopped(docker, &exec.id, recovery_deadline).await?;
            restart_container(docker, container_id, recovery_deadline).await?;
            return Ok(interruption.result());
        }
    };

    let StartExecResults::Attached { output, .. } = start_result else {
        let recovery_deadline = recovery_deadline(command_deadline, Instant::now())?;
        recover_container(docker, container_id, Some(&exec.id), recovery_deadline).await?;
        return Err(DockerExecOperationError::Detached.into());
    };
    let mut stream_task = spawn_stream_task(output, processor.clone());

    let completion = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => Completion::Interrupted(Interruption::Cancelled),
        _ = tokio::time::sleep_until(command_deadline) => Completion::Interrupted(Interruption::TimedOut),
        joined = &mut stream_task => Completion::Stream(joined),
    };

    match completion {
        Completion::Interrupted(interruption) => {
            let recovery_deadline = recovery_deadline(command_deadline, Instant::now())?;
            if let Err(error) =
                stop_container_for_recovery(docker, container_id, recovery_deadline).await
            {
                stream_task.abort();
                let _ = stream_task.await;
                return Err(error);
            }
            let _ = await_stream_task(&mut stream_task, recovery_deadline).await?;
            prove_exec_stopped(docker, &exec.id, recovery_deadline).await?;
            restart_container(docker, container_id, recovery_deadline).await?;
            Ok(interruption.result())
        }
        Completion::Stream(stream_outcome) => {
            let recovery_deadline = recovery_deadline(command_deadline, Instant::now())?;
            let terminal = inspect_exec_state(docker, &exec.id, recovery_deadline).await;
            let exit_code = match terminal {
                Ok((false, exit_code)) => exit_code,
                Ok((true, _)) | Err(_) => {
                    recover_container(docker, container_id, Some(&exec.id), recovery_deadline)
                        .await?;
                    return stream_completion_error(stream_outcome, true);
                }
            };
            match stream_outcome {
                Err(error) => {
                    warn!(error = %error, "Docker exec stream task panicked");
                    Err(DockerExecOperationError::StreamTask.into())
                }
                Ok(StreamOutcome::Failed(diagnostic)) => Err(DockerExecOperationError::Stream {
                    kind: diagnostic.kind,
                    status_code: diagnostic.status_code,
                    error_code: diagnostic.error_code,
                }
                .into()),
                Ok(StreamOutcome::Ended) => Ok(StepResult {
                    conclusion: if exit_code == 0 {
                        StepConclusion::Succeeded
                    } else {
                        StepConclusion::Failed
                    },
                }),
            }
        }
    }
}

fn recovery_deadline(command_deadline: Instant, recovery_started_at: Instant) -> Result<Instant> {
    recovery_deadline_with_budget(command_deadline, recovery_started_at, RECOVERY_BUDGET)
}

fn recovery_deadline_with_budget(
    command_deadline: Instant,
    recovery_started_at: Instant,
    recovery_budget: Duration,
) -> Result<Instant> {
    let fresh_deadline = recovery_started_at.checked_add(recovery_budget).ok_or(
        DockerExecRecoveryError::Deadline {
            stage: "computing Docker exec recovery deadline",
        },
    )?;
    Ok(command_deadline
        .checked_add(recovery_budget)
        .map_or(fresh_deadline, |command_bound| {
            command_bound.min(fresh_deadline)
        }))
}

enum StageOutcome<T> {
    Ready(T),
    Interrupted(Interruption),
}

enum Completion {
    Interrupted(Interruption),
    Stream(std::result::Result<StreamOutcome, tokio::task::JoinError>),
}

async fn wait_for_stage<F>(
    future: &mut std::pin::Pin<Box<F>>,
    command_deadline: Instant,
    cancel_token: &CancellationToken,
) -> StageOutcome<F::Output>
where
    F: Future,
{
    tokio::select! {
        biased;
        _ = cancel_token.cancelled() => StageOutcome::Interrupted(Interruption::Cancelled),
        _ = tokio::time::sleep_until(command_deadline) => StageOutcome::Interrupted(Interruption::TimedOut),
        result = future => StageOutcome::Ready(result),
    }
}

fn spawn_stream_task(
    mut output: impl futures::Stream<
        Item = std::result::Result<bollard::container::LogOutput, bollard::errors::Error>,
    > + Send
    + Unpin
    + 'static,
    processor: OutputProcessor,
) -> JoinHandle<StreamOutcome> {
    tokio::spawn(async move {
        let mut framer = DockerLogFramer::default();
        loop {
            match output.next().await {
                Some(Ok(output)) => {
                    for line in framer.push(output) {
                        processor.process_line(&line).await;
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
                    return StreamOutcome::Failed(diagnostic);
                }
                None => break,
            }
        }
        for line in framer.finish() {
            processor.process_line(&line).await;
        }
        StreamOutcome::Ended
    })
}

async fn drain_start_result(
    started: StartExecResults,
    processor: &OutputProcessor,
    deadline: Instant,
) -> Result<()> {
    if let StartExecResults::Attached { output, .. } = started {
        let mut task = spawn_stream_task(output, processor.clone());
        let _ = await_stream_task(&mut task, deadline).await?;
    }
    Ok(())
}

async fn await_stream_task(
    task: &mut JoinHandle<StreamOutcome>,
    deadline: Instant,
) -> Result<std::result::Result<StreamOutcome, tokio::task::JoinError>> {
    match tokio::time::timeout_at(deadline, &mut *task).await {
        Ok(result) => Ok(result),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(DockerExecRecoveryError::Deadline {
                stage: "draining Docker exec output",
            }
            .into())
        }
    }
}

fn stream_completion_error(
    stream_outcome: std::result::Result<StreamOutcome, tokio::task::JoinError>,
    was_running: bool,
) -> Result<StepResult> {
    match stream_outcome {
        Err(error) => {
            warn!(error = %error, "Docker exec stream task panicked");
            Err(DockerExecOperationError::StreamTask.into())
        }
        Ok(StreamOutcome::Failed(diagnostic)) => Err(DockerExecOperationError::Stream {
            kind: diagnostic.kind,
            status_code: diagnostic.status_code,
            error_code: diagnostic.error_code,
        }
        .into()),
        Ok(StreamOutcome::Ended) if was_running => Err(DockerExecOperationError::EarlyEnd.into()),
        Ok(StreamOutcome::Ended) => unreachable!("normal terminal stream handled by caller"),
    }
}

async fn recover_container(
    docker: &Docker,
    container_id: &str,
    exec_id: Option<&str>,
    deadline: Instant,
) -> Result<()> {
    stop_container_for_recovery(docker, container_id, deadline).await?;
    if let Some(exec_id) = exec_id {
        prove_exec_stopped(docker, exec_id, deadline).await?;
    }
    restart_container(docker, container_id, deadline).await
}

async fn stop_container_for_recovery(
    docker: &Docker,
    container_id: &str,
    deadline: Instant,
) -> Result<()> {
    match before_deadline(
        deadline,
        "stopping job container",
        docker.stop_container(
            container_id,
            Some(StopContainerOptions {
                t: CONTAINER_STOP_TIMEOUT_SECS,
            }),
        ),
    )
    .await?
    {
        Ok(()) => {}
        Err(error) => log_recovery_rpc_error("stopping job container", &error),
    }

    if inspect_container_running(docker, container_id, deadline).await? {
        match before_deadline(
            deadline,
            "killing job container",
            docker.kill_container(
                container_id,
                Some(KillContainerOptions { signal: "SIGKILL" }),
            ),
        )
        .await?
        {
            Ok(()) => {}
            Err(error) => log_recovery_rpc_error("killing job container", &error),
        }
    }

    loop {
        if !inspect_container_running(docker, container_id, deadline).await? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(DockerExecRecoveryError::ContainerStillRunning.into());
        }
        sleep_before(
            deadline,
            CONTAINER_STATE_POLL,
            "waiting for job container stop",
        )
        .await?;
    }
}

async fn restart_container(docker: &Docker, container_id: &str, deadline: Instant) -> Result<()> {
    docker_call(
        deadline,
        "restarting job container",
        docker.start_container::<String>(container_id, None),
    )
    .await?;

    for observation in 0..2 {
        if !inspect_container_running(docker, container_id, deadline).await? {
            return Err(DockerExecRecoveryError::ContainerNotRunning.into());
        }
        if observation == 0 {
            sleep_before(
                deadline,
                CONTAINER_STATE_POLL,
                "confirming restarted job container",
            )
            .await?;
        }
    }
    Ok(())
}

async fn prove_exec_stopped(docker: &Docker, exec_id: &str, deadline: Instant) -> Result<()> {
    let inspected = before_deadline(
        deadline,
        "inspecting stopped Docker exec state",
        docker.inspect_exec(exec_id),
    )
    .await?;
    match inspected {
        Ok(inspect) if inspect.running == Some(true) => {
            Err(DockerExecRecoveryError::ExecStillRunning.into())
        }
        Ok(_) => Ok(()),
        Err(error) => {
            let diagnostic = DockerErrorDiagnostic::from(&error);
            if diagnostic.status_code == Some(404) {
                Ok(())
            } else {
                Err(recovery_rpc_error(
                    "inspecting stopped Docker exec state",
                    &error,
                ))
            }
        }
    }
}

async fn inspect_exec_state(
    docker: &Docker,
    exec_id: &str,
    deadline: Instant,
) -> Result<(bool, i64)> {
    let inspect = docker_call(
        deadline,
        "inspecting Docker exec state",
        docker.inspect_exec(exec_id),
    )
    .await?;
    Ok((
        inspect.running == Some(true),
        inspect.exit_code.unwrap_or(-1),
    ))
}

async fn inspect_container_running(
    docker: &Docker,
    container_id: &str,
    deadline: Instant,
) -> Result<bool> {
    let inspect = docker_call(
        deadline,
        "inspecting job container state",
        docker.inspect_container(container_id, None),
    )
    .await?;
    Ok(inspect.state.and_then(|state| state.running) == Some(true))
}

async fn docker_call<T, F>(deadline: Instant, stage: &'static str, future: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, bollard::errors::Error>>,
{
    before_deadline(deadline, stage, future)
        .await?
        .map_err(|error| recovery_rpc_error(stage, &error))
}

fn recovery_rpc_error(stage: &'static str, error: &bollard::errors::Error) -> anyhow::Error {
    let diagnostic = DockerErrorDiagnostic::from(error);
    DockerExecRecoveryError::Rpc {
        stage,
        kind: diagnostic.kind,
        status_code: diagnostic.status_code,
        error_code: diagnostic.error_code,
    }
    .into()
}

fn log_recovery_rpc_error(stage: &'static str, error: &bollard::errors::Error) {
    let diagnostic = DockerErrorDiagnostic::from(error);
    warn!(
        stage,
        error_kind = diagnostic.kind,
        status_code = ?diagnostic.status_code,
        error_code = ?diagnostic.error_code,
        "Docker exec recovery RPC failed; verifying engine state"
    );
}

async fn before_deadline<T, F>(deadline: Instant, stage: &'static str, future: F) -> Result<T>
where
    F: Future<Output = T>,
{
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| DockerExecRecoveryError::Deadline { stage }.into())
}

async fn sleep_before(deadline: Instant, duration: Duration, stage: &'static str) -> Result<()> {
    before_deadline(deadline, stage, tokio::time::sleep(duration)).await
}

#[cfg(test)]
#[path = "exec_test.rs"]
mod exec_test;
