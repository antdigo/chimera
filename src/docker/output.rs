use std::sync::Arc;

use bollard::container::LogOutput;
use bollard::errors::Error as DockerError;

use crate::job::commands::{WorkflowCommand, parse_command};
use crate::job::execute::JobState;
use crate::job::logs::LogSender;
use crate::job::secret_masker::SharedSecretMasker;

/// A payload-free projection of a Bollard error suitable for global tracing.
///
/// Docker daemon messages and stream payloads are untrusted and can echo
/// credentials, command arguments, or environment values. Keep only stable,
/// structural fields here.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DockerErrorDiagnostic {
    pub(crate) kind: &'static str,
    pub(crate) status_code: Option<u16>,
    pub(crate) error_code: Option<i64>,
    pub(crate) column: Option<usize>,
}

impl From<&DockerError> for DockerErrorDiagnostic {
    fn from(error: &DockerError) -> Self {
        match error {
            DockerError::DockerResponseServerError { status_code, .. } => Self {
                kind: "response",
                status_code: Some(*status_code),
                error_code: None,
                column: None,
            },
            DockerError::DockerStreamError { .. } => Self {
                kind: "stream",
                status_code: None,
                error_code: None,
                column: None,
            },
            DockerError::DockerContainerWaitError { code, .. } => Self {
                kind: "container_wait",
                status_code: None,
                error_code: Some(*code),
                column: None,
            },
            DockerError::JsonDataError { column, .. } => Self {
                kind: "json",
                status_code: None,
                error_code: None,
                column: Some(*column),
            },
            DockerError::RequestTimeoutError => Self {
                kind: "timeout",
                status_code: None,
                error_code: None,
                column: None,
            },
            _ => Self {
                kind: "client",
                status_code: None,
                error_code: None,
                column: None,
            },
        }
    }
}

#[derive(Default)]
pub(crate) struct LineFramer {
    buffer: Vec<u8>,
}

impl LineFramer {
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buffer.extend_from_slice(chunk);
        let Some(last_lf) = self.buffer.iter().rposition(|byte| *byte == b'\n') else {
            return Vec::new();
        };

        let tail = self.buffer.split_off(last_lf + 1);
        let mut complete = std::mem::replace(&mut self.buffer, tail);
        complete.pop();
        complete
            .split(|byte| *byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect()
    }

    pub(crate) fn finish(&mut self) -> Option<String> {
        if self.buffer.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(&std::mem::take(&mut self.buffer)).into_owned())
    }
}

#[derive(Default)]
pub(crate) struct DockerLogFramer {
    stdout: LineFramer,
    stderr: LineFramer,
}

impl DockerLogFramer {
    pub(crate) fn push(&mut self, output: LogOutput) -> Vec<String> {
        match output {
            LogOutput::StdOut { message } => self.stdout.push(&message),
            LogOutput::StdErr { message } => self.stderr.push(&message),
            _ => Vec::new(),
        }
    }

    pub(crate) fn finish(&mut self) -> Vec<String> {
        [self.stdout.finish(), self.stderr.finish()]
            .into_iter()
            .flatten()
            .collect()
    }
}

/// Bundles the buffers and settings needed to process stdout/stderr output lines.
///
/// Shared between `run_process()` (host mode), `docker_exec()` (container mode),
/// and docker action log streaming.
#[derive(Clone)]
pub struct OutputProcessor {
    sender: LogSender,
    secret_masker: SharedSecretMasker,
    env_buf: Arc<tokio::sync::Mutex<Vec<(String, String)>>>,
    path_buf: Arc<tokio::sync::Mutex<Vec<String>>>,
    output_buf: Arc<tokio::sync::Mutex<Vec<(String, String)>>>,
    state_buf: Arc<tokio::sync::Mutex<Vec<(String, String)>>>,
    debug_enabled: bool,
}

impl OutputProcessor {
    pub(crate) fn new(
        sender: LogSender,
        secret_masker: SharedSecretMasker,
        debug_enabled: bool,
    ) -> Self {
        Self {
            sender,
            secret_masker,
            env_buf: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            path_buf: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            output_buf: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            state_buf: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            debug_enabled,
        }
    }

    /// Process a single output line: parse workflow commands and forward to log sender.
    pub async fn process_line(&self, line: &str) {
        if let Some(cmd) = parse_command(line) {
            match cmd {
                WorkflowCommand::SetEnv { name, value } => {
                    self.env_buf.lock().await.push((name, value));
                }
                WorkflowCommand::AddPath(p) => {
                    self.path_buf.lock().await.push(p);
                }
                WorkflowCommand::SetOutput { name, value } => {
                    self.output_buf.lock().await.push((name, value));
                }
                WorkflowCommand::AddMask(secret) => {
                    self.secret_masker.write().await.add_value(&secret);
                }
                WorkflowCommand::Debug(msg) => {
                    if self.debug_enabled {
                        self.sender.send(format!("##[debug]{msg}")).await;
                    }
                }
                WorkflowCommand::Warning(msg) => {
                    self.sender.send(format!("##[warning]{msg}")).await;
                }
                WorkflowCommand::Error(msg) => {
                    self.sender.send(format!("##[error]{msg}")).await;
                }
                WorkflowCommand::Group(title) => {
                    self.sender.send(format!("##[group]{title}")).await;
                }
                WorkflowCommand::EndGroup => {
                    self.sender.send("##[endgroup]".into()).await;
                }
                WorkflowCommand::SaveState { name, value } => {
                    self.state_buf.lock().await.push((name, value));
                }
            }
        } else {
            self.sender.send(line.to_string()).await;
        }
    }

    /// Drain collected state mutations into the job state.
    pub async fn apply_to_job_state(&self, job_state: &mut JobState) {
        for (k, v) in self.env_buf.lock().await.drain(..) {
            job_state.env.insert(k, v);
        }
        job_state
            .path_prepends
            .extend(self.path_buf.lock().await.drain(..));
        for (k, v) in self.output_buf.lock().await.drain(..) {
            crate::utils::insert_case_insensitive(&mut job_state.outputs, k, v);
        }
        for (k, v) in self.state_buf.lock().await.drain(..) {
            let entry = job_state.action_states.entry(String::new()).or_default();
            crate::utils::insert_case_insensitive(entry, k, v);
        }
    }
}

#[cfg(test)]
#[path = "output_test.rs"]
mod output_test;
