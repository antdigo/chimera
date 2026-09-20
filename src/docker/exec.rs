use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::exec::{CreateExecOptions, StartExecResults};
use futures::StreamExt;
use thiserror::Error;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::output::{DockerErrorDiagnostic, DockerLogFramer, OutputProcessor};
use crate::job::execute::{StepConclusion, StepResult};

const TERMINALIZATION_TIMEOUT: Duration = Duration::from_secs(10);
const TERM_GRACE: Duration = Duration::from_secs(2);
const EXEC_SUPERVISOR: &str = r#"
control=$1
shift
rm -f "$control"
setsid /bin/sh -c 'control=$1; shift; printf "%s\n" "$$" > "$control"; exec "$@"' chimera-exec-child "$control" "$@" &
leader=$!
wait "$leader"
status=$?
kill -TERM "-$leader" 2>/dev/null || true
sleep 0.05
kill -KILL "-$leader" 2>/dev/null || true
rm -f "$control"
exit "$status"
"#;
const SIGNAL_EXEC_GROUP: &str = r#"
control=$1
signal=$2
attempt=0
while ! test -s "$control"; do
    attempt=$((attempt + 1))
    test "$attempt" -lt 100 || exit 3
    sleep 0.02
done
IFS= read -r pgid < "$control"
case "$pgid" in
    ''|*[!0-9]*) exit 4 ;;
esac
kill -"$signal" "-$pgid" 2>/dev/null || true
"#;

#[derive(Debug, Error)]
pub(crate) enum DockerExecTerminalizationError {
    #[error("Docker exec terminalization exceeded its deadline during {stage}")]
    Deadline { stage: &'static str },
    #[error(
        "Docker exec terminalization RPC failed during {stage} ({kind}, status {status_code:?}, code {error_code:?})"
    )]
    Rpc {
        stage: &'static str,
        kind: &'static str,
        status_code: Option<u16>,
        error_code: Option<i64>,
    },
    #[error("Docker exec remained running after command-scoped termination")]
    StillRunning,
}

#[derive(Debug, Error)]
enum DockerExecStreamError {
    #[error(
        "Docker exec output stream failed ({kind}, status {status_code:?}, code {error_code:?})"
    )]
    Transport {
        kind: &'static str,
        status_code: Option<u16>,
        error_code: Option<i64>,
    },
    #[error("Docker exec output stream task failed")]
    Task,
    #[error("Docker exec attach stream ended while the command was still running")]
    EarlyEnd,
    #[error("Docker exec start failed ({kind}, status {status_code:?}, code {error_code:?})")]
    Start {
        kind: &'static str,
        status_code: Option<u16>,
        error_code: Option<i64>,
    },
    #[error("Docker exec did not return attached output")]
    Detached,
}

enum StreamOutcome {
    Ended,
    Failed(DockerErrorDiagnostic),
}

/// Whether state files may still be changing after a Docker exec failure.
///
/// Callers must not consume a step snapshot for these errors. All other errors
/// are returned only after the exec was proven terminal.
pub(crate) fn state_may_still_change(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<DockerExecTerminalizationError>()
        .is_some()
}

/// Run a command inside a running container via `docker exec`.
///
/// The command runs in its own session so cancellation can terminate only this
/// exec's process group while preserving the long-lived job container.
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
    let control_path = format!("/tmp/.chimera-exec-{}.pid", uuid::Uuid::new_v4());
    let mut supervised_cmd = vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        EXEC_SUPERVISOR.to_owned(),
        "chimera-exec-supervisor".to_owned(),
        control_path.clone(),
    ];
    supervised_cmd.extend(cmd);

    let exec = docker
        .create_exec(
            container_id,
            CreateExecOptions::<String> {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(supervised_cmd),
                env: Some(env_list),
                working_dir: Some(working_dir.to_string()),
                ..Default::default()
            },
        )
        .await
        .context("creating docker exec")?;

    let exec_output = match docker.start_exec(&exec.id, None).await {
        Ok(output) => output,
        Err(error) => {
            let diagnostic = DockerErrorDiagnostic::from(&error);
            ensure_exec_terminal(
                docker,
                container_id,
                &exec.id,
                &control_path,
                Instant::now() + TERMINALIZATION_TIMEOUT,
            )
            .await?;
            return Err(DockerExecStreamError::Start {
                kind: diagnostic.kind,
                status_code: diagnostic.status_code,
                error_code: diagnostic.error_code,
            }
            .into());
        }
    };

    let StartExecResults::Attached { mut output, .. } = exec_output else {
        ensure_exec_terminal(
            docker,
            container_id,
            &exec.id,
            &control_path,
            Instant::now() + TERMINALIZATION_TIMEOUT,
        )
        .await?;
        return Err(DockerExecStreamError::Detached.into());
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
                    return StreamOutcome::Failed(diagnostic);
                }
                None => break,
            }
        }
        for line in framer.finish() {
            stream_processor.process_line(&line).await;
        }
        StreamOutcome::Ended
    });

    enum Completion {
        Cancelled,
        TimedOut,
        Stream(std::result::Result<StreamOutcome, tokio::task::JoinError>),
    }

    let completion = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => {
            warn!("job cancelled, Docker exec process group will be stopped");
            Completion::Cancelled
        },
        _ = tokio::time::sleep(timeout) => {
            warn!("Docker exec timed out; process group will be stopped");
            Completion::TimedOut
        },
        joined = &mut stream_task => Completion::Stream(joined),
    };
    let deadline = Instant::now() + TERMINALIZATION_TIMEOUT;

    match completion {
        Completion::Cancelled | Completion::TimedOut => {
            if let Err(error) =
                ensure_exec_terminal(docker, container_id, &exec.id, &control_path, deadline).await
            {
                stream_task.abort();
                let _ = stream_task.await;
                return Err(error);
            }
            let joined = match tokio::time::timeout_at(deadline, &mut stream_task).await {
                Ok(joined) => joined,
                Err(_) => {
                    stream_task.abort();
                    let _ = stream_task.await;
                    return Err(DockerExecTerminalizationError::Deadline {
                        stage: "draining interrupted exec output",
                    }
                    .into());
                }
            };
            match joined {
                Ok(_) => {}
                Err(error) => {
                    warn!(error = %error, "Docker exec stream task failed while reaping");
                }
            }
            let conclusion = match completion {
                Completion::Cancelled => StepConclusion::Cancelled,
                Completion::TimedOut => StepConclusion::Failed,
                Completion::Stream(_) => unreachable!(),
            };
            Ok(StepResult { conclusion })
        }
        Completion::Stream(stream_outcome) => {
            let was_running =
                inspect_exec_state(docker, &exec.id, deadline, "inspecting exec after stream")
                    .await?
                    .0;
            let (_, exit_code) =
                ensure_exec_terminal(docker, container_id, &exec.id, &control_path, deadline)
                    .await?;
            match stream_outcome {
                Err(error) => {
                    warn!(error = %error, "Docker exec stream task panicked");
                    Err(DockerExecStreamError::Task.into())
                }
                Ok(StreamOutcome::Failed(diagnostic)) => Err(DockerExecStreamError::Transport {
                    kind: diagnostic.kind,
                    status_code: diagnostic.status_code,
                    error_code: diagnostic.error_code,
                }
                .into()),
                Ok(StreamOutcome::Ended) if was_running => {
                    Err(DockerExecStreamError::EarlyEnd.into())
                }
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

async fn ensure_exec_terminal(
    docker: &Docker,
    container_id: &str,
    exec_id: &str,
    control_path: &str,
    deadline: Instant,
) -> Result<(bool, i64)> {
    let state =
        inspect_exec_state(docker, exec_id, deadline, "checking exec terminal state").await?;
    if !state.0 {
        return Ok(state);
    }

    signal_exec_group(docker, container_id, control_path, "TERM", deadline).await?;
    let grace_deadline = std::cmp::min(deadline, Instant::now() + TERM_GRACE);
    loop {
        let state =
            inspect_exec_state(docker, exec_id, deadline, "waiting for exec after TERM").await?;
        if !state.0 {
            return Ok(state);
        }
        if Instant::now() >= grace_deadline {
            break;
        }
        sleep_before(
            deadline,
            Duration::from_millis(50),
            "waiting for exec after TERM",
        )
        .await?;
    }

    signal_exec_group(docker, container_id, control_path, "KILL", deadline).await?;
    loop {
        let state =
            inspect_exec_state(docker, exec_id, deadline, "waiting for exec after KILL").await?;
        if !state.0 {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            return Err(DockerExecTerminalizationError::StillRunning.into());
        }
        sleep_before(
            deadline,
            Duration::from_millis(50),
            "waiting for exec after KILL",
        )
        .await?;
    }
}

async fn signal_exec_group(
    docker: &Docker,
    container_id: &str,
    control_path: &str,
    signal: &str,
    deadline: Instant,
) -> Result<()> {
    let signal_exec = docker_call(
        deadline,
        "creating command-scoped signal exec",
        docker.create_exec(
            container_id,
            CreateExecOptions::<String> {
                attach_stdout: Some(false),
                attach_stderr: Some(false),
                cmd: Some(vec![
                    "/bin/sh".to_owned(),
                    "-c".to_owned(),
                    SIGNAL_EXEC_GROUP.to_owned(),
                    "chimera-exec-signal".to_owned(),
                    control_path.to_owned(),
                    signal.to_owned(),
                ]),
                ..Default::default()
            },
        ),
    )
    .await?;
    docker_call(
        deadline,
        "starting command-scoped signal exec",
        docker.start_exec(&signal_exec.id, None),
    )
    .await?;

    loop {
        let (running, exit_code) = inspect_exec_state(
            docker,
            &signal_exec.id,
            deadline,
            "reaping command-scoped signal exec",
        )
        .await?;
        if !running {
            if exit_code != 0 {
                warn!(exit_code, signal, "command-scoped signal helper failed");
            }
            return Ok(());
        }
        sleep_before(
            deadline,
            Duration::from_millis(20),
            "reaping command-scoped signal exec",
        )
        .await?;
    }
}

async fn inspect_exec_state(
    docker: &Docker,
    exec_id: &str,
    deadline: Instant,
    stage: &'static str,
) -> Result<(bool, i64)> {
    let inspect = docker_call(deadline, stage, docker.inspect_exec(exec_id)).await?;
    Ok((
        inspect.running == Some(true),
        inspect.exit_code.unwrap_or(-1),
    ))
}

async fn docker_call<T, F>(deadline: Instant, stage: &'static str, future: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, bollard::errors::Error>>,
{
    let result = before_deadline(deadline, stage, future).await?;
    result.map_err(|error| {
        let diagnostic = DockerErrorDiagnostic::from(&error);
        DockerExecTerminalizationError::Rpc {
            stage,
            kind: diagnostic.kind,
            status_code: diagnostic.status_code,
            error_code: diagnostic.error_code,
        }
        .into()
    })
}

async fn before_deadline<T, F>(deadline: Instant, stage: &'static str, future: F) -> Result<T>
where
    F: Future<Output = T>,
{
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| DockerExecTerminalizationError::Deadline { stage }.into())
}

async fn sleep_before(deadline: Instant, duration: Duration, stage: &'static str) -> Result<()> {
    before_deadline(deadline, stage, tokio::time::sleep(duration)).await
}

#[cfg(test)]
#[path = "exec_test.rs"]
mod exec_test;
