use std::collections::HashMap;
use std::ffi::OsStr;
#[cfg(all(test, target_os = "linux"))]
use std::ffi::{CStr, CString};
#[cfg(all(test, target_os = "linux"))]
use std::io;
#[cfg(all(test, target_os = "linux"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(all(test, target_os = "linux"))]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
#[cfg(test)]
use tokio::process::Command;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::JobClient;
use super::action::{ActionCache, TrustedActionDirectory, load_action_metadata, resolve_action};
use super::client::{JobConclusion, ResultsConclusion, ResultsStatus, ResultsStep};
use super::expression::ExprContext;
use super::live_feed::FeedSender;
use super::logs::{JobLogger, LogLine, LogSender, StepLogger};
use super::schema::{JobManifest, Step};
use super::secret_masker::{SecretMasker, SharedSecretMasker};
use super::timeline::{TimelineLogRef, TimelineRecord, TimelineResult, TimelineState};
use super::workspace::Workspace;
use crate::docker::build::{BuiltDockerImage, DockerActionBuilder, DockerBuildScope, RegistryAuth};
use crate::docker::output::OutputProcessor;
use crate::docker::resources::JobDockerResources;
use crate::job::execution_domain::ExecutionDomainError;
use crate::job::execution_domain::{
    CommandEvent, CommandOutcome, CommandSpec, DOCKER_CONFIG_ENV, ExecutionDomain,
};
use crate::node::NodeRuntimes;
use crate::utils::{
    find_case_insensitive, format_results_timestamp, format_timeline_timestamp,
    insert_case_insensitive, merge_case_insensitive,
};

pub struct JobExecutionContext<'a> {
    domain: &'a ExecutionDomain,
    docker_resources: Option<&'a JobDockerResources>,
    node_runtimes: &'a NodeRuntimes,
}

impl<'a> JobExecutionContext<'a> {
    pub fn new(
        domain: &'a ExecutionDomain,
        docker_resources: Option<&'a JobDockerResources>,
        node_runtimes: &'a NodeRuntimes,
    ) -> Self {
        Self {
            domain,
            docker_resources,
            node_runtimes,
        }
    }

    pub fn docker_config(&self) -> &'a ExecutionDomain {
        self.domain
    }

    pub fn docker_resources(&self) -> Option<&'a JobDockerResources> {
        self.docker_resources
    }

    pub fn docker_endpoint(&self) -> &'a crate::docker::endpoint::DockerEndpoint {
        self.domain.docker_endpoint()
    }

    pub fn docker_client(&self) -> anyhow::Result<bollard::Docker> {
        match self.docker_resources {
            Some(resources) => Ok(resources.docker().clone()),
            None => crate::docker::client::connect(self.docker_endpoint()),
        }
    }

    pub fn node_runtimes(&self) -> &'a NodeRuntimes {
        self.node_runtimes
    }

    pub fn host_docker_config(&self) -> Option<&'a ExecutionDomain> {
        self.docker_resources
            .and_then(JobDockerResources::job_container_id)
            .is_none()
            .then_some(self.domain)
    }
}

/// Per-step result for `steps.<id>.outcome` and `steps.<id>.conclusion`.
///
/// `outcome` is the raw result before `continue-on-error` is applied.
/// `conclusion` is the final result after `continue-on-error`:
/// if `continue-on-error: true` and the step failed, outcome="failure" but conclusion="success".
#[derive(Debug, Clone)]
pub struct StepOutcome {
    pub outcome: String,
    pub conclusion: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActionStepPhase {
    Main,
    Pre,
    Post,
}

impl ActionStepPhase {
    fn entry_point(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Pre => "pre",
            Self::Post => "post",
        }
    }
}

struct ActionStepContext {
    instance_key: String,
    phase: ActionStepPhase,
}

pub struct JobState {
    pub env: HashMap<String, String>,
    pub path_prepends: Vec<String>,
    pub outputs: HashMap<String, String>,
    pub(crate) secret_masker: SharedSecretMasker,
    /// Per-action state for pre→post transfer via SaveState workflow command.
    /// Key: action context_name, Value: map of state name→value.
    pub action_states: HashMap<String, HashMap<String, String>>,
    /// Per-step outputs for `steps.<id>.outputs.<name>` expression resolution.
    pub step_outputs: HashMap<String, HashMap<String, String>>,
    /// Per-step outcome/conclusion for `steps.<id>.outcome` / `steps.<id>.conclusion`.
    pub step_outcomes: HashMap<String, StepOutcome>,
    pub docker_action_images: HashMap<String, BuiltDockerImage>,
    trusted_action_directories: HashMap<String, TrustedActionDirectory>,
    action_step_contexts: HashMap<String, ActionStepContext>,
    /// Secret variables (name → value) for `secrets.<name>` expression resolution.
    pub secrets: HashMap<String, String>,
    /// Context data from the job manifest (needs, matrix, job, etc.).
    pub context_data: serde_json::Value,
    /// Host filesystem workspace path for hashFiles(). In container mode, GITHUB_WORKSPACE
    /// points to the container path (/github/workspace) but file operations need the real path.
    pub host_workspace: Option<String>,
    /// Opaque workspace reader owned and revoked by the execution-domain manager.
    pub workspace_reader: Option<crate::job::execution_domain::DomainWorkspaceReader>,
    /// Validated step summaries, retained in execution order for the result uploader.
    pub step_summaries: Vec<String>,
    /// `defaults.run.working-directory` for the job, used by any `run:` step that
    /// does not set its own.
    pub default_working_directory: Option<String>,
    /// Whether `::debug::` workflow commands should be emitted to the log stream.
    /// Only true when the `ACTIONS_STEP_DEBUG` secret is set to `"true"`.
    pub debug_enabled: bool,
}

#[derive(Default)]
pub(crate) struct BufferedWorkflowState {
    env: Vec<(String, String)>,
    path: Vec<String>,
    output: Vec<(String, String)>,
    state: Vec<(String, String)>,
}

pub(crate) struct WorkflowStateDrainPermit(());

impl WorkflowStateDrainPermit {
    fn new() -> Self {
        Self(())
    }

    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self::new()
    }
}

impl BufferedWorkflowState {
    pub(crate) fn new(
        _permit: &WorkflowStateDrainPermit,
        env: Vec<(String, String)>,
        path: Vec<String>,
        output: Vec<(String, String)>,
        state: Vec<(String, String)>,
    ) -> Self {
        Self {
            env,
            path,
            output,
            state,
        }
    }

    fn apply(self, job_state: &mut JobState) {
        for (key, value) in self.env {
            job_state.env.insert(key, value);
        }
        job_state.path_prepends.extend(self.path);
        for (key, value) in self.output {
            insert_case_insensitive(&mut job_state.outputs, key, value);
        }
        for (key, value) in self.state {
            insert_case_insensitive(
                job_state.action_states.entry(String::new()).or_default(),
                key,
                value,
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn env(&self) -> &[(String, String)] {
        &self.env
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &[String] {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn output(&self) -> &[(String, String)] {
        &self.output
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> &[(String, String)] {
        &self.state
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.env.is_empty()
            && self.path.is_empty()
            && self.output.is_empty()
            && self.state.is_empty()
    }
}

impl JobState {
    pub(crate) fn new(
        secret_masker: SharedSecretMasker,
        secrets: HashMap<String, String>,
        context_data: serde_json::Value,
    ) -> Self {
        let debug_enabled = find_case_insensitive(&secrets, "ACTIONS_STEP_DEBUG")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        Self {
            env: HashMap::new(),
            path_prepends: Vec::new(),
            outputs: HashMap::new(),
            secret_masker,
            action_states: HashMap::new(),
            step_outputs: HashMap::new(),
            step_outcomes: HashMap::new(),
            docker_action_images: HashMap::new(),
            trusted_action_directories: HashMap::new(),
            action_step_contexts: HashMap::new(),
            secrets,
            context_data,
            host_workspace: None,
            workspace_reader: None,
            step_summaries: Vec::new(),
            default_working_directory: None,
            debug_enabled,
        }
    }

    pub(crate) fn action_instance_key<'a>(&'a self, step: &'a Step) -> &'a str {
        self.action_step_contexts
            .get(&step.id)
            .map(|context| context.instance_key.as_str())
            .unwrap_or(&step.id)
    }

    pub(crate) fn action_step_phase(&self, step: &Step) -> ActionStepPhase {
        self.action_step_contexts
            .get(&step.id)
            .map(|context| context.phase)
            .unwrap_or(ActionStepPhase::Main)
    }

    fn link_action_step(
        &mut self,
        synthetic_step: &Step,
        original_step: &Step,
        phase: ActionStepPhase,
    ) {
        let instance_key = self.action_instance_key(original_step).to_string();
        self.action_step_contexts.insert(
            synthetic_step.id.clone(),
            ActionStepContext {
                instance_key,
                phase,
            },
        );
    }
}

/// Where a `run:` step's script should execute, relative to the workspace.
///
/// A step's own `working-directory` wins; otherwise the job's
/// `defaults.run.working-directory` applies. Both may carry expressions, and both
/// are resolved against the workspace — an absolute path replaces it outright,
/// which is what `Path::join` and the official runner's `Path.Combine` both do.
fn step_working_directory(
    step: &Step,
    job_state: &JobState,
    env: &HashMap<String, String>,
) -> Option<String> {
    let raw = step
        .inputs
        .get("workingDirectory")
        .or(job_state.default_working_directory.as_ref())
        .filter(|dir| !dir.is_empty())?;

    let ctx = ExprContext::new(env, job_state, false, false);
    let resolved = super::expression::resolve_template(raw, &ctx);
    let trimmed = resolved.trim();
    match trimmed.is_empty() {
        true => None,
        false => Some(trimmed.to_string()),
    }
}

/// Build the `job` context object for expression evaluation.
/// Contains `status`, and optionally `container` and `services` when Docker is in use.
fn build_job_context(docker_resources: Option<&JobDockerResources>) -> serde_json::Value {
    let mut job = serde_json::json!({
        "status": "success"
    });

    if let Some(resources) = docker_resources {
        if let Some(container_id) = resources.job_container_id() {
            let mut container = serde_json::json!({
                "id": container_id
            });
            if let Some(network) = resources.network_name() {
                container["network"] = serde_json::json!(network);
            }
            job["container"] = container;
        }

        let svc_map = resources.service_container_map();
        if !svc_map.is_empty() {
            let mut services = serde_json::Map::new();
            for (alias, container_id) in svc_map {
                let mut svc = serde_json::json!({
                    "id": container_id
                });
                if let Some(network) = resources.network_name() {
                    svc["network"] = serde_json::json!(network);
                }
                if let Some(ports) = resources.service_ports().get(alias) {
                    svc["ports"] = serde_json::json!(ports);
                }
                services.insert(alias.clone(), svc);
            }
            job["services"] = serde_json::Value::Object(services);
        }
    }

    job
}

/// Update `context_data["job"]["status"]` based on current job state.
fn update_job_status(context_data: &mut serde_json::Value, failed: bool, cancelled: bool) {
    let status = if cancelled {
        "cancelled"
    } else if failed {
        "failure"
    } else {
        "success"
    };

    if let Some(job) = context_data.get_mut("job") {
        job["status"] = serde_json::json!(status);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StepConclusion {
    Succeeded,
    Failed,
    Cancelled,
}

impl StepConclusion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "success",
            Self::Failed => "failure",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug)]
pub struct StepResult {
    pub conclusion: StepConclusion,
}

impl From<StepConclusion> for ResultsConclusion {
    fn from(c: StepConclusion) -> Self {
        match c {
            StepConclusion::Succeeded => Self::Success,
            StepConclusion::Failed => Self::Failure,
            StepConclusion::Cancelled => Self::Cancelled,
        }
    }
}

/// Per-step tracking for Results API updates.
struct StepTracker {
    id: String,
    name: String,
    order: u32,
    status: ResultsStatus,
    conclusion: ResultsConclusion,
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl StepTracker {
    fn from_step(step: &Step) -> Self {
        Self {
            id: step.id.clone(),
            name: step.display_name.clone(),
            order: step.order,
            status: ResultsStatus::Pending,
            conclusion: ResultsConclusion::Unknown,
            started_at: None,
            completed_at: None,
        }
    }

    /// Resolve a templated `name:` (`Build ${{ matrix.os }}`). Deferred to step
    /// start because the manifest carries the raw template — GitHub resolves it in
    /// the runner, not on the server.
    fn resolve_name(&mut self, ctx: &ExprContext) {
        if self.name.contains("${{") {
            self.name = super::expression::resolve_template(&self.name, ctx);
        }
    }

    fn mark_started(&mut self) {
        self.status = ResultsStatus::InProgress;
        self.started_at = Some(format_results_timestamp(Utc::now()));
    }

    fn mark_completed(&mut self, conclusion: ResultsConclusion) {
        self.status = ResultsStatus::Completed;
        self.conclusion = conclusion;
        self.completed_at = Some(format_results_timestamp(Utc::now()));
    }

    fn to_results_step(&self) -> ResultsStep {
        ResultsStep {
            external_id: self.id.clone(),
            number: self.order,
            name: self.name.clone(),
            status: self.status,
            started_at: self.started_at.clone(),
            completed_at: self.completed_at.clone(),
            conclusion: self.conclusion,
        }
    }
}

/// Execute a single run: step as a host process.
pub async fn run_host_step(
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    cancel_token: &CancellationToken,
    domain: &ExecutionDomain,
) -> Result<StepResult> {
    let script_raw = step
        .inputs
        .get("script")
        .context("step has no 'script' input")?;

    let env = build_step_env(step, job_state, workspace, base_env, Some(domain))?;

    let expr_ctx = ExprContext::new(&env, job_state, false, false);
    let script = super::expression::resolve_template(script_raw, &expr_ctx);

    let script_file = workspace.runner_temp().join(format!("step_{}.sh", step.id));
    std::fs::write(&script_file, &script)
        .with_context(|| format!("writing script file {}", script_file.display()))?;
    let timeout = Duration::from_secs(step.timeout_in_minutes.unwrap_or(360) * 60);

    debug!(
        step_id = %step.id,
        "running host step"
    );

    let working_dir = match step_working_directory(step, job_state, &env) {
        Some(dir) => workspace.workspace_dir().join(dir),
        None => workspace.workspace_dir().to_path_buf(),
    };

    let result = run_process(
        OsStr::new("bash"),
        &[OsStr::new("-e"), script_file.as_os_str()],
        &env,
        &working_dir,
        workspace,
        domain,
        job_state,
        log_sender,
        timeout,
        cancel_token,
    )
    .await;

    // Re-key saved state from the empty-key bucket into the correct action-keyed bucket
    if let Some(unnamed_state) = job_state.action_states.remove("") {
        let key = step.context_name.as_deref().unwrap_or(&step.id);
        job_state
            .action_states
            .entry(key.to_string())
            .or_default()
            .extend(unnamed_state);
    }

    let _ = std::fs::remove_file(&script_file);
    result
}

/// Execute a single run: step inside a Docker container via `docker exec`.
#[expect(
    clippy::too_many_arguments,
    reason = "step execution keeps domain transaction and Docker context explicit"
)]
pub async fn run_container_step(
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    docker_resources: &JobDockerResources,
    cancel_token: &CancellationToken,
    domain: &ExecutionDomain,
) -> Result<StepResult> {
    let script_raw = step
        .inputs
        .get("script")
        .context("step has no 'script' input")?;

    let env = build_step_env(step, job_state, workspace, base_env, None)?;

    let expr_ctx = ExprContext::new(&env, job_state, false, false);
    let script = super::expression::resolve_template(script_raw, &expr_ctx);

    let timeout = Duration::from_secs(step.timeout_in_minutes.unwrap_or(360) * 60);
    let container_id = docker_resources
        .job_container_id()
        .context("no job container for container step")?;

    debug!(
        step_id = %step.id,
        "running container step"
    );

    let working_dir = match step_working_directory(step, job_state, &env) {
        Some(dir) if dir.starts_with('/') => dir,
        Some(dir) => format!("/github/workspace/{dir}"),
        None => "/github/workspace".into(),
    };

    let state_id = prepare_step_transaction(domain, workspace).await?;
    let processor = OutputProcessor::new(
        log_sender.clone(),
        job_state.secret_masker.clone(),
        job_state.debug_enabled,
    );
    let result = crate::docker::exec::docker_exec(
        docker_resources.docker(),
        container_id,
        vec!["bash".into(), "-e".into(), "-c".into(), script],
        &env,
        &working_dir,
        &processor,
        timeout,
        cancel_token,
    )
    .await;
    let result = complete_step_transaction(domain, state_id, &processor, job_state, result).await;

    // Re-key saved state from the empty-key bucket into the correct action-keyed bucket
    if let Some(unnamed_state) = job_state.action_states.remove("") {
        let key = step.context_name.as_deref().unwrap_or(&step.id);
        job_state
            .action_states
            .entry(key.to_string())
            .or_default()
            .extend(unnamed_state);
    }

    result
}

#[cfg(test)]
fn validate_host_docker_capabilities(
    env: &HashMap<String, String>,
    working_dir: &Path,
    private_tmp: &Path,
) -> Result<(), ExecutionDomainError> {
    crate::job::execution_domain::validate_host_docker_capabilities(env, working_dir, private_tmp)
}

#[cfg(test)]
fn build_host_command<D: TestHostDomain + ?Sized>(
    program: &str,
    args: &[&OsStr],
    env: &HashMap<String, String>,
    working_dir: &Path,
    domain: &D,
) -> Result<Command> {
    let configured = env
        .get(DOCKER_CONFIG_ENV)
        .context("host step is missing runner-owned DOCKER_CONFIG")?;
    domain.test_validate_override(configured, "host spawn")?;

    let mut command = Command::new(program);
    command.args(args);

    #[cfg(target_os = "linux")]
    configure_private_tmp(&mut command, domain.test_private_tmp(), working_dir)?;

    #[cfg(not(target_os = "linux"))]
    command.current_dir(working_dir);

    command
        .env_remove(DOCKER_CONFIG_ENV)
        .envs(env)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    Ok(command)
}

#[cfg(test)]
fn host_command<D: TestHostDomain + ?Sized>(
    program: &str,
    args: &[&OsStr],
    env: &HashMap<String, String>,
    working_dir: &Path,
    domain: &D,
) -> Result<Command> {
    validate_host_docker_capabilities(env, working_dir, domain.test_private_tmp())?;
    build_host_command(program, args, env, working_dir, domain)
}

#[cfg(test)]
trait TestHostDomain {
    fn test_private_tmp(&self) -> &Path;
    fn test_validate_override(
        &self,
        value: &str,
        source: &'static str,
    ) -> Result<(), ExecutionDomainError>;
}

#[cfg(test)]
impl TestHostDomain for ExecutionDomain {
    fn test_private_tmp(&self) -> &Path {
        self.private_tmp()
    }
    fn test_validate_override(
        &self,
        value: &str,
        source: &'static str,
    ) -> Result<(), ExecutionDomainError> {
        self.validate_override(value, source)
    }
}

#[cfg(test)]
impl TestHostDomain for crate::job::execution_domain::TrustedBackend {
    fn test_private_tmp(&self) -> &Path {
        self.private_tmp()
    }
    fn test_validate_override(
        &self,
        value: &str,
        source: &'static str,
    ) -> Result<(), ExecutionDomainError> {
        self.validate_override(value, source)
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
fn configure_private_tmp(
    command: &mut Command,
    private_tmp: &Path,
    working_dir: &Path,
) -> Result<()> {
    let source = CString::new(private_tmp.as_os_str().as_bytes())
        .context("private job temp path contains a NUL byte")?;
    let working_dir = CString::new(working_dir.as_os_str().as_bytes())
        .context("host working directory contains a NUL byte")?;
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let uid_map = format!("{uid} {uid} 1\n").into_bytes();
    let gid_map = format!("{gid} {gid} 1\n").into_bytes();

    // SAFETY: after fork, the closure performs only raw async-signal-safe syscalls and
    // reads buffers/C strings fully allocated before `pre_exec`; it does not allocate,
    // log, or acquire process-global locks.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) == -1 {
                return Err(io::Error::last_os_error());
            }
            write_proc_file(c"/proc/self/setgroups", b"deny\n")?;
            write_proc_file(c"/proc/self/uid_map", &uid_map)?;
            write_proc_file(c"/proc/self/gid_map", &gid_map)?;

            if libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                (libc::MS_PRIVATE | libc::MS_REC) as libc::c_ulong,
                std::ptr::null(),
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if libc::mount(
                source.as_ptr(),
                c"/tmp".as_ptr(),
                std::ptr::null(),
                libc::MS_BIND as libc::c_ulong,
                std::ptr::null(),
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if libc::chdir(working_dir.as_ptr()) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg(test)]
unsafe fn write_proc_file(path: &CStr, value: &[u8]) -> io::Result<()> {
    let file = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if file == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut written = 0;
    while written < value.len() {
        let result = unsafe {
            libc::write(
                file,
                value[written..].as_ptr().cast(),
                value.len() - written,
            )
        };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { libc::close(file) };
            return Err(error);
        }
        if result == 0 {
            unsafe { libc::close(file) };
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        written += result as usize;
    }

    if unsafe { libc::close(file) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Shared process runner used by host steps, node actions, and composite steps.
#[allow(clippy::too_many_arguments)]
pub async fn run_process(
    program: &OsStr,
    args: &[&OsStr],
    env: &HashMap<String, String>,
    working_dir: &Path,
    workspace: &Workspace,
    domain: &ExecutionDomain,
    job_state: &mut JobState,
    log_sender: &LogSender,
    timeout: Duration,
    cancel_token: &CancellationToken,
) -> Result<StepResult> {
    // All fallible host-to-domain mapping must complete before opening the
    // single outstanding command-file transaction.
    let env = domain.command_environment(env)?;
    let target = domain.command_target(program, args, working_dir, &env)?;
    let state_id = prepare_step_transaction(domain, workspace).await?;
    let processor = OutputProcessor::new(
        log_sender.clone(),
        job_state.secret_masker.clone(),
        job_state.debug_enabled,
    );
    let (output, mut events) = mpsc::channel(32);
    let spec = CommandSpec {
        target,
        env,
        timeout,
        state: Some(state_id.clone()),
    };
    let consume = consume_command_events(&mut events, &processor, log_sender);
    let run = domain.run(spec, output, cancel_token.clone());
    let (outcome, ()) = tokio::join!(run, consume);
    let outcome = complete_step_transaction(
        domain,
        state_id,
        &processor,
        job_state,
        outcome.map_err(anyhow::Error::from),
    )
    .await?;
    let conclusion = match outcome {
        CommandOutcome::Exited(0) => StepConclusion::Succeeded,
        CommandOutcome::Cancelled => StepConclusion::Cancelled,
        CommandOutcome::Exited(_) | CommandOutcome::Signalled(_) | CommandOutcome::TimedOut => {
            StepConclusion::Failed
        }
    };
    Ok(StepResult { conclusion })
}

pub(crate) async fn prepare_step_transaction(
    domain: &ExecutionDomain,
    workspace: &Workspace,
) -> Result<crate::job::execution_domain::StepFilesId> {
    domain.bind_workspace(workspace).await?;
    let event = workspace.read_event_file_bounded()?;
    Ok(domain.prepare_step(&event).await?)
}

#[cfg(test)]
pub(crate) async fn finish_step_transaction(
    domain: &ExecutionDomain,
    state_id: crate::job::execution_domain::StepFilesId,
    job_state: &mut JobState,
) -> Result<()> {
    let snapshot = domain.read_step(state_id).await?;
    apply_step_snapshot(
        snapshot,
        BufferedWorkflowState::default(),
        domain,
        job_state,
    )
}

pub(crate) async fn complete_step_transaction<T>(
    domain: &ExecutionDomain,
    state_id: crate::job::execution_domain::StepFilesId,
    processor: &OutputProcessor,
    job_state: &mut JobState,
    command_result: Result<T>,
) -> Result<T> {
    // Terminal state validation has deterministic priority over a command error:
    // a corrupted bridge must never be hidden by a simultaneous spawn/transport failure.
    let snapshot = domain.read_step(state_id).await?;
    let permit = WorkflowStateDrainPermit::new();
    let commands = processor.take_workflow_state(&permit).await;
    apply_step_snapshot(snapshot, commands, domain, job_state)?;
    command_result
}

async fn consume_command_events(
    events: &mut mpsc::Receiver<CommandEvent>,
    processor: &OutputProcessor,
    log_sender: &LogSender,
) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    while let Some(event) = events.recv().await {
        match event {
            CommandEvent::Stdout(bytes) => {
                stdout.extend_from_slice(&bytes);
                drain_processor_lines(&mut stdout, processor).await;
                drain_bounded_processor_chunk(&mut stdout, processor).await;
            }
            CommandEvent::Stderr(bytes) => {
                stderr.extend_from_slice(&bytes);
                drain_log_lines(&mut stderr, log_sender).await;
                drain_bounded_log_chunk(&mut stderr, log_sender).await;
            }
        }
    }
    if !stdout.is_empty() {
        processor
            .process_line(&String::from_utf8_lossy(&stdout))
            .await;
    }
    if !stderr.is_empty() {
        log_sender
            .send(String::from_utf8_lossy(&stderr).into_owned())
            .await;
    }
}

const MAX_PARTIAL_OUTPUT_BYTES: usize = 64 * 1024;

async fn drain_bounded_processor_chunk(buffer: &mut Vec<u8>, processor: &OutputProcessor) {
    while buffer.len() > MAX_PARTIAL_OUTPUT_BYTES {
        let chunk = buffer.drain(..MAX_PARTIAL_OUTPUT_BYTES).collect::<Vec<_>>();
        processor
            .process_line(&String::from_utf8_lossy(&chunk))
            .await;
    }
}

async fn drain_bounded_log_chunk(buffer: &mut Vec<u8>, sender: &LogSender) {
    while buffer.len() > MAX_PARTIAL_OUTPUT_BYTES {
        let chunk = buffer.drain(..MAX_PARTIAL_OUTPUT_BYTES).collect::<Vec<_>>();
        sender
            .send(String::from_utf8_lossy(&chunk).into_owned())
            .await;
    }
}

async fn drain_processor_lines(buffer: &mut Vec<u8>, processor: &OutputProcessor) {
    while let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
        let line = buffer.drain(..=index).collect::<Vec<_>>();
        let line = String::from_utf8_lossy(&line[..line.len().saturating_sub(1)]);
        processor.process_line(&line).await;
    }
}

async fn drain_log_lines(buffer: &mut Vec<u8>, sender: &LogSender) {
    while let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
        let line = buffer.drain(..=index).collect::<Vec<_>>();
        sender
            .send(String::from_utf8_lossy(&line[..line.len().saturating_sub(1)]).into_owned())
            .await;
    }
}

fn apply_step_snapshot(
    snapshot: crate::job::execution_domain::StepStateSnapshot,
    commands: BufferedWorkflowState,
    domain: &ExecutionDomain,
    job_state: &mut JobState,
) -> Result<()> {
    let parsed = snapshot.parse()?;
    validate_step_environment(
        parsed
            .env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
        domain,
    )?;
    validate_step_environment(
        commands
            .env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
        domain,
    )?;

    commands.apply(job_state);
    merge_case_insensitive(&mut job_state.outputs, parsed.output);
    job_state.env.extend(parsed.env);
    job_state.path_prepends.extend(parsed.path);
    merge_case_insensitive(
        job_state.action_states.entry(String::new()).or_default(),
        parsed.state,
    );
    if !parsed.summary.is_empty() {
        job_state.step_summaries.push(parsed.summary);
    }
    Ok(())
}

fn validate_step_environment<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    domain: &ExecutionDomain,
) -> Result<()> {
    for (key, value) in entries {
        if is_reserved_command_file_env(key) {
            return Err(ExecutionDomainError::ReservedEnvironmentOverride {
                source: "GITHUB_ENV",
            }
            .into());
        }
        if key == DOCKER_CONFIG_ENV {
            domain.validate_override(value, "GITHUB_ENV")?;
        }
    }
    Ok(())
}

/// Build the full environment for a step execution.
pub fn build_step_env(
    step: &Step,
    job_state: &JobState,
    _workspace: &Workspace,
    base_env: &HashMap<String, String>,
    domain: Option<&ExecutionDomain>,
) -> Result<HashMap<String, String>> {
    let mut env = base_env.clone();
    merge_checked(&mut env, &job_state.env, domain, "job environment")?;

    if let Some(step_env) = &step.environment {
        for (key, value) in step_env {
            let context = ExprContext::new(&env, job_state, false, false);
            let resolved = super::expression::resolve_expression(value, &context);
            insert_checked(&mut env, key.clone(), resolved, domain, "step environment")?;
        }
    }

    if let Some(ctx_name) = &step.context_name
        && let Some(base_ctx) = ctx_name
            .strip_suffix("_post")
            .or_else(|| ctx_name.strip_suffix("_pre"))
        && let Some(states) = job_state.action_states.get(base_ctx)
    {
        for (key, value) in states {
            env.insert(format!("STATE_{key}"), value.clone());
        }
    }

    if !job_state.path_prepends.is_empty() {
        let prepend = job_state.path_prepends.join(":");
        let path = match env.get("PATH") {
            Some(existing) if !existing.is_empty() => format!("{prepend}:{existing}"),
            _ => prepend,
        };
        env.insert("PATH".into(), path);
    }

    Ok(env)
}

fn insert_checked(
    env: &mut HashMap<String, String>,
    key: String,
    value: String,
    domain: Option<&ExecutionDomain>,
    source: &'static str,
) -> Result<()> {
    if is_reserved_command_file_env(&key) {
        return Err(ExecutionDomainError::ReservedEnvironmentOverride { source }.into());
    }
    if key == DOCKER_CONFIG_ENV
        && let Some(config) = domain
    {
        config.validate_override(&value, source)?;
    }
    env.insert(key, value);
    Ok(())
}

pub(crate) fn is_reserved_command_file_env(key: &str) -> bool {
    matches!(
        key,
        "GITHUB_ENV"
            | "GITHUB_PATH"
            | "GITHUB_OUTPUT"
            | "GITHUB_STATE"
            | "GITHUB_STEP_SUMMARY"
            | "GITHUB_EVENT_PATH"
    )
}

fn merge_checked(
    env: &mut HashMap<String, String>,
    values: &HashMap<String, String>,
    domain: Option<&ExecutionDomain>,
    source: &'static str,
) -> Result<()> {
    for (key, value) in values {
        insert_checked(env, key.clone(), value.clone(), domain, source)?;
    }
    Ok(())
}

/// Run all steps in a job manifest.
#[allow(clippy::too_many_arguments)]
pub async fn run_all_steps(
    manifest: &JobManifest,
    job_client: &Arc<JobClient>,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    runner_name: &str,
    action_cache: &ActionCache,
    docker_action_builder: &DockerActionBuilder,
    registry_auth: Option<&RegistryAuth>,
    access_token: &str,
    cancel_token: CancellationToken,
    execution: &JobExecutionContext<'_>,
    feed_sender: Option<&FeedSender>,
) -> Result<(JobConclusion, HashMap<String, String>)> {
    let secret_masker = Arc::new(RwLock::new(SecretMasker::from_manifest(manifest)?));
    run_all_steps_with_masker(
        manifest,
        job_client,
        workspace,
        base_env,
        runner_name,
        action_cache,
        docker_action_builder,
        registry_auth,
        access_token,
        cancel_token,
        execution,
        feed_sender,
        secret_masker,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_all_steps_with_masker(
    manifest: &JobManifest,
    job_client: &Arc<JobClient>,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    runner_name: &str,
    action_cache: &ActionCache,
    docker_action_builder: &DockerActionBuilder,
    registry_auth: Option<&RegistryAuth>,
    access_token: &str,
    cancel_token: CancellationToken,
    execution: &JobExecutionContext<'_>,
    feed_sender: Option<&FeedSender>,
    secret_masker: SharedSecretMasker,
) -> Result<(JobConclusion, HashMap<String, String>)> {
    let server = manifest
        .context_data
        .get("github")
        .and_then(|github| github.get("server_url"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("https://github.com");
    let github_scope = match manifest.repository() {
        Ok(repository) => format!("{server}/{repository}"),
        Err(_) => format!(
            "{server}/unknown/{}/{}",
            manifest.plan.plan_id, manifest.plan.job_id
        ),
    };
    let docker_build_scope = DockerBuildScope::new(runner_name, github_scope);

    let secrets = collect_secrets(manifest);

    let mut job_state = JobState::new(
        secret_masker.clone(),
        secrets,
        manifest.context_data.clone(),
    );
    job_state.workspace_reader = execution.docker_config().workspace_reader();

    // Populate the `job` context for expression evaluation
    if let serde_json::Value::Object(ref mut map) = job_state.context_data {
        map.insert(
            "job".to_string(),
            build_job_context(execution.docker_resources()),
        );
    }

    // In container mode, GITHUB_WORKSPACE points to /github/workspace (container path).
    // hashFiles() runs on the host and needs the real filesystem path.
    if execution
        .docker_resources()
        .and_then(JobDockerResources::job_container_id)
        .is_some()
    {
        job_state.host_workspace = Some(workspace.workspace_dir().to_string_lossy().into_owned());
    }

    job_state.default_working_directory = manifest.default_working_directory().map(str::to_string);

    let mut job_failed = false;
    let mut job_cancelled = false;
    let use_results = job_client.has_results_url();

    let mut trackers: Vec<StepTracker> =
        manifest.steps.iter().map(StepTracker::from_step).collect();

    // The job-level log is what GitHub serves as the downloadable archive, and it
    // only exists on the Results API — legacy runs have no equivalent.
    let job_logger = use_results.then(|| {
        JobLogger::new(
            job_client.clone(),
            manifest.plan.plan_id.clone(),
            manifest.plan.job_id.clone(),
        )
    });
    let job_log_tx = job_logger.as_ref().map(JobLogger::sender);

    let mut pending_post_steps: Vec<(Step, Option<String>)> = Vec::new();

    // --- Pre steps ---
    // Actions can define a `pre` entry point in their action.yml (e.g.
    // actions/checkout pre-checks the repository state). Pre steps run
    // before all main steps, in forward order (matching manifest order).
    let mut pre_steps = Vec::new();
    for (idx, step) in manifest.steps.iter().enumerate() {
        let collected =
            match collect_pre_step(step, action_cache, workspace.workspace_dir(), access_token)
                .await
            {
                Ok(Some(collected)) => collected,
                Ok(None) => continue,
                Err(_) => {
                    // A local action only becomes resolvable once an earlier
                    // step (typically checkout) has materialized it, and a
                    // step behind a false condition may reference an action
                    // that never resolves at all: discovery failures must not
                    // fail the job before those steps can decide.
                    warn!(step_id = %step.id, "deferring action resolution to step execution");
                    continue;
                }
            };
        job_state
            .trusted_action_directories
            .insert(step.id.clone(), collected.action_dir);

        let Some((orig_step, pre_if)) = collected.pre_step else {
            continue;
        };
        let ctx_name = orig_step
            .context_name
            .clone()
            .unwrap_or_else(|| orig_step.id.clone());
        let pre_step = Step {
            id: uuid::Uuid::new_v4().to_string(),
            display_name: format!("Pre {}", orig_step.display_name),
            context_name: Some(format!("{ctx_name}_pre")),
            order: idx as u32,
            condition: Some(pre_if.unwrap_or_else(|| "always()".to_string())),
            ..orig_step.clone()
        };
        job_state.link_action_step(&pre_step, &orig_step, ActionStepPhase::Pre);
        pre_steps.push(pre_step);
    }

    let pre_step_count = pre_steps.len();
    if !pre_steps.is_empty() {
        // Prepend pre step trackers so they appear before main steps in the UI
        let mut pre_trackers: Vec<StepTracker> =
            pre_steps.iter().map(StepTracker::from_step).collect();
        pre_trackers.append(&mut trackers);
        trackers = pre_trackers;

        for pre_step in &pre_steps {
            if cancel_token.is_cancelled() {
                job_cancelled = true;
            }

            let tracker_idx = trackers
                .iter()
                .position(|t| t.id == pre_step.id)
                .context("pre step tracker not found")?;

            update_job_status(&mut job_state.context_data, job_failed, job_cancelled);
            let condition_ctx = ExprContext::new(base_env, &job_state, job_failed, job_cancelled);
            trackers[tracker_idx].resolve_name(&condition_ctx);
            if !super::expression::evaluate_condition(pre_step.condition.as_deref(), &condition_ctx)
            {
                debug!(step_id = %pre_step.id, "skipping pre step (condition not met)");
                let now = format_timeline_timestamp(Utc::now());
                trackers[tracker_idx].mark_started();
                trackers[tracker_idx].mark_completed(ResultsConclusion::Skipped);
                report_step_completed(
                    use_results,
                    job_client,
                    manifest,
                    &trackers,
                    tracker_idx,
                    &now,
                    &now,
                    ResultsConclusion::Skipped,
                    0,
                )
                .await;
                continue;
            }

            let start_time = format_timeline_timestamp(Utc::now());
            trackers[tracker_idx].mark_started();
            report_step_started(
                use_results,
                job_client,
                manifest,
                &trackers,
                tracker_idx,
                &start_time,
            )
            .await;

            let logger = create_step_logger(
                use_results,
                job_client,
                &manifest.plan.plan_id,
                &manifest.plan.job_id,
                &pre_step.id,
                &pre_step.display_name,
                secret_masker.clone(),
                feed_sender,
                job_log_tx.as_ref(),
            )
            .await;

            let (conclusion, result_conclusion) = execute_step(
                pre_step,
                &mut job_state,
                workspace,
                base_env,
                logger.sender(),
                runner_name,
                action_cache,
                docker_action_builder,
                &docker_build_scope,
                registry_auth,
                access_token,
                &cancel_token,
                execution,
            )
            .await;

            let legacy_log_id = logger.log_id();
            logger.finish().await;

            let finish_time = format_timeline_timestamp(Utc::now());
            trackers[tracker_idx].mark_completed(result_conclusion);
            report_step_completed(
                use_results,
                job_client,
                manifest,
                &trackers,
                tracker_idx,
                &start_time,
                &finish_time,
                result_conclusion,
                legacy_log_id,
            )
            .await;

            // Pre steps DO affect job conclusion (unlike post steps)
            if conclusion == StepConclusion::Cancelled {
                job_cancelled = true;
            } else if conclusion == StepConclusion::Failed {
                if pre_step.continue_on_error {
                    info!(step_id = %pre_step.id, "pre step failed but continue_on_error is set");
                } else {
                    job_failed = true;
                }
            }
        }
    }

    for (idx, step) in manifest.steps.iter().enumerate() {
        let idx = idx + pre_step_count;
        // Check for cancellation between steps
        if cancel_token.is_cancelled() {
            job_cancelled = true;
        }

        if let Some(condition) = &step.condition {
            debug!(
                step_id = %step.id,
                has_condition = !condition.is_empty(),
                "step has condition"
            );
        }

        // Check condition before starting the step — skipped steps get no
        // logs and are reported as completed immediately.
        update_job_status(&mut job_state.context_data, job_failed, job_cancelled);
        let condition_ctx = ExprContext::new(base_env, &job_state, job_failed, job_cancelled);
        trackers[idx].resolve_name(&condition_ctx);
        if !super::expression::evaluate_condition(step.condition.as_deref(), &condition_ctx) {
            debug!(step_id = %step.id, "skipping step (condition not met)");
            let now = format_timeline_timestamp(Utc::now());
            trackers[idx].mark_started();
            trackers[idx].mark_completed(ResultsConclusion::Skipped);

            if let Some(ctx_name) = step.context_name.as_deref() {
                job_state.step_outcomes.insert(
                    ctx_name.to_string(),
                    StepOutcome {
                        outcome: "skipped".into(),
                        conclusion: "skipped".into(),
                    },
                );
            }

            report_step_completed(
                use_results,
                job_client,
                manifest,
                &trackers,
                idx,
                &now,
                &now,
                ResultsConclusion::Skipped,
                0,
            )
            .await;
            continue;
        }

        let start_time = format_timeline_timestamp(Utc::now());
        trackers[idx].mark_started();

        report_step_started(
            use_results,
            job_client,
            manifest,
            &trackers,
            idx,
            &start_time,
        )
        .await;

        let logger = create_step_logger(
            use_results,
            job_client,
            &manifest.plan.plan_id,
            &manifest.plan.job_id,
            &step.id,
            &step.display_name,
            secret_masker.clone(),
            feed_sender,
            job_log_tx.as_ref(),
        )
        .await;

        let (conclusion, result_conclusion) = execute_step(
            step,
            &mut job_state,
            workspace,
            base_env,
            logger.sender(),
            runner_name,
            action_cache,
            docker_action_builder,
            &docker_build_scope,
            registry_auth,
            access_token,
            &cancel_token,
            execution,
        )
        .await;

        let legacy_log_id = logger.log_id();

        logger.finish().await;

        let finish_time = format_timeline_timestamp(Utc::now());
        trackers[idx].mark_completed(result_conclusion);

        report_step_completed(
            use_results,
            job_client,
            manifest,
            &trackers,
            idx,
            &start_time,
            &finish_time,
            result_conclusion,
            legacy_log_id,
        )
        .await;

        // If this action has a `post` entry point, schedule it for later.
        let action_key = job_state.action_instance_key(step).to_string();
        if let Some(action_dir) = job_state
            .trusted_action_directories
            .get(&action_key)
            .cloned()
            && let Some(post_info) = collect_post_step(step, &action_dir)?
        {
            pending_post_steps.push(post_info);
        }

        // Save this step's outputs for `steps.<id>.outputs.<name>` resolution.
        // Always take() to prevent outputs from bleeding into subsequent steps.
        let step_key = step.context_name.as_deref().unwrap_or(&step.id);
        let step_outs = std::mem::take(&mut job_state.outputs);
        if !step_outs.is_empty() {
            job_state
                .step_outputs
                .insert(step_key.to_string(), step_outs);
        }

        // Save outcome/conclusion for `steps.<id>.outcome` / `steps.<id>.conclusion`
        if let Some(ctx_name) = step.context_name.as_deref() {
            let effective_conclusion =
                if step.continue_on_error && conclusion == StepConclusion::Failed {
                    StepConclusion::Succeeded
                } else {
                    conclusion
                };
            job_state.step_outcomes.insert(
                ctx_name.to_string(),
                StepOutcome {
                    outcome: conclusion.as_str().to_string(),
                    conclusion: effective_conclusion.as_str().to_string(),
                },
            );
        }

        if conclusion == StepConclusion::Cancelled {
            job_cancelled = true;
        } else if conclusion == StepConclusion::Failed {
            if step.continue_on_error {
                info!(step_id = %step.id, "step failed but continue_on_error is set");
            } else {
                job_failed = true;
            }
        }
    }

    // --- Post steps ---
    // Actions can define a `post` entry point in their action.yml (e.g.
    // actions/cache saves the cache in its post step). The official runner
    // generates these dynamically; chimera does the same here.
    // Post steps run in reverse order (last action's post runs first).
    if !pending_post_steps.is_empty() {
        let max_order = manifest.steps.iter().map(|s| s.order).max().unwrap_or(0);
        let mut post_steps = Vec::new();
        for (rev_idx, (orig_step, post_if)) in pending_post_steps.into_iter().rev().enumerate() {
            let ctx_name = orig_step
                .context_name
                .clone()
                .unwrap_or_else(|| orig_step.id.clone());
            let post_step = Step {
                id: uuid::Uuid::new_v4().to_string(),
                display_name: format!("Post {}", orig_step.display_name),
                context_name: Some(format!("{ctx_name}_post")),
                order: max_order + 1 + rev_idx as u32,
                // Default post-if is always() (not success()), so post steps
                // run even when the job failed (e.g. to save partial caches).
                condition: Some(post_if.unwrap_or_else(|| "always()".to_string())),
                ..orig_step.clone()
            };
            job_state.link_action_step(&post_step, &orig_step, ActionStepPhase::Post);
            post_steps.push(post_step);
        }

        for ps in &post_steps {
            trackers.push(StepTracker::from_step(ps));
        }

        for post_step in &post_steps {
            let tracker_idx = trackers
                .iter()
                .position(|t| t.id == post_step.id)
                .context("post step tracker not found")?;

            update_job_status(&mut job_state.context_data, job_failed, job_cancelled);
            let condition_ctx = ExprContext::new(base_env, &job_state, job_failed, job_cancelled);
            trackers[tracker_idx].resolve_name(&condition_ctx);
            if !super::expression::evaluate_condition(
                post_step.condition.as_deref(),
                &condition_ctx,
            ) {
                debug!(step_id = %post_step.id, "skipping post step (condition not met)");
                let now = format_timeline_timestamp(Utc::now());
                trackers[tracker_idx].mark_started();
                trackers[tracker_idx].mark_completed(ResultsConclusion::Skipped);
                report_step_completed(
                    use_results,
                    job_client,
                    manifest,
                    &trackers,
                    tracker_idx,
                    &now,
                    &now,
                    ResultsConclusion::Skipped,
                    0,
                )
                .await;
                continue;
            }

            let start_time = format_timeline_timestamp(Utc::now());
            trackers[tracker_idx].mark_started();
            report_step_started(
                use_results,
                job_client,
                manifest,
                &trackers,
                tracker_idx,
                &start_time,
            )
            .await;

            let logger = create_step_logger(
                use_results,
                job_client,
                &manifest.plan.plan_id,
                &manifest.plan.job_id,
                &post_step.id,
                &post_step.display_name,
                secret_masker.clone(),
                feed_sender,
                job_log_tx.as_ref(),
            )
            .await;

            let (conclusion, result_conclusion) = execute_step(
                post_step,
                &mut job_state,
                workspace,
                base_env,
                logger.sender(),
                runner_name,
                action_cache,
                docker_action_builder,
                &docker_build_scope,
                registry_auth,
                access_token,
                &cancel_token,
                execution,
            )
            .await;

            let legacy_log_id = logger.log_id();
            logger.finish().await;

            let finish_time = format_timeline_timestamp(Utc::now());
            trackers[tracker_idx].mark_completed(result_conclusion);
            report_step_completed(
                use_results,
                job_client,
                manifest,
                &trackers,
                tracker_idx,
                &start_time,
                &finish_time,
                result_conclusion,
                legacy_log_id,
            )
            .await;

            // Post steps don't affect job conclusion
            if conclusion == StepConclusion::Failed {
                info!(step_id = %post_step.id, "post step failed (does not affect job conclusion)");
            }
        }
    }

    // Every step's sender is dropped by now, so this seals the job blob on the
    // complete log rather than a partial one.
    drop(job_log_tx);
    if let Some(logger) = job_logger {
        logger.finish().await;
    }

    let mut output_env = base_env.clone();
    output_env.extend(job_state.env.clone());
    let output_ctx = ExprContext::new(&output_env, &job_state, job_failed, job_cancelled);
    let mut job_outputs = HashMap::new();
    for (key, expression) in &manifest.job_outputs {
        let value = super::expression::resolve_template(expression, &output_ctx);
        if value.is_empty() {
            debug!("skipping empty job output");
            continue;
        }
        if secret_masker.read().await.contains_secret(&value) {
            warn!("skipping job output because it may contain a secret");
            continue;
        }
        insert_case_insensitive(&mut job_outputs, key.clone(), value);
    }

    let conclusion = if job_cancelled {
        JobConclusion::Cancelled
    } else if job_failed {
        JobConclusion::Failed
    } else {
        JobConclusion::Succeeded
    };
    Ok((conclusion, job_outputs))
}

/// Build the secrets map for `secrets.<name>` expression resolution.
///
/// Effective precedence, highest first: contextData["secrets"] (merged last,
/// replacing same-name entries regardless of casing), the `github_token`
/// secret variable, and the `GITHUB_TOKEN` alias — the latter is only filled
/// from the `system.github.token` variable when no earlier source provided a
/// token. The map never holds two keys differing only by case.
fn collect_secrets(manifest: &JobManifest) -> HashMap<String, String> {
    // The official ToSecretsContext excludes the dotted system token names:
    // they reach workflows only through the canonical `github.token` /
    // `GITHUB_TOKEN` aliases, never as literal `secrets['system.github.token']`.
    const EXCLUDED_SECRET_VARIABLES: [&str; 2] = ["system.github.token", "system.accessToken"];

    let mut secrets: HashMap<String, String> = HashMap::new();
    for (k, v) in manifest.variables.iter() {
        if v.is_secret
            && !EXCLUDED_SECRET_VARIABLES
                .iter()
                .any(|name| k.eq_ignore_ascii_case(name))
        {
            insert_case_insensitive(&mut secrets, k.clone(), v.value.clone());
        }
    }

    // `secrets.GITHUB_TOKEN` is documented to always exist. The job message
    // delivers the system token as `github_token` and/or `system.github.token`;
    // make sure it resolves no matter which path carried it (#15).
    if find_case_insensitive(&secrets, "GITHUB_TOKEN").is_none()
        && let Some(token) = manifest.github_token()
        && !token.is_empty()
    {
        secrets.insert("GITHUB_TOKEN".to_string(), token.to_string());
    }

    // User-defined secrets (repo/org secrets) come via contextData["secrets"],
    // not through the variables dict which only has system-level secrets.
    if let Some(ctx_secrets) = manifest
        .context_data
        .get("secrets")
        .and_then(|v| v.as_object())
    {
        for (k, v) in ctx_secrets {
            if EXCLUDED_SECRET_VARIABLES
                .iter()
                .any(|name| k.eq_ignore_ascii_case(name))
            {
                continue;
            }
            if let Some(s) = v.as_str() {
                insert_case_insensitive(&mut secrets, k.clone(), s.to_string());
            }
        }
    }

    secrets
}

#[allow(clippy::too_many_arguments)]
async fn create_step_logger(
    use_results: bool,
    client: &Arc<JobClient>,
    plan_id: &str,
    job_id: &str,
    step_id: &str,
    step_name: &str,
    secret_masker: SharedSecretMasker,
    feed_sender: Option<&FeedSender>,
    job_log_tx: Option<&mpsc::Sender<LogLine>>,
) -> StepLogger {
    let feed = feed_sender.map(|f| (f.clone(), step_id.to_string()));
    if use_results {
        StepLogger::results(
            client.clone(),
            plan_id.to_string(),
            job_id.to_string(),
            step_id.to_string(),
            secret_masker,
            feed,
            job_log_tx.cloned(),
        )
    } else {
        StepLogger::legacy(client.clone(), plan_id, step_name, secret_masker, feed).await
    }
}

/// Run a step (already determined to not be skipped).
#[allow(clippy::too_many_arguments)]
async fn execute_step(
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    runner_name: &str,
    action_cache: &ActionCache,
    docker_action_builder: &DockerActionBuilder,
    docker_build_scope: &DockerBuildScope,
    registry_auth: Option<&RegistryAuth>,
    access_token: &str,
    cancel_token: &CancellationToken,
    execution: &JobExecutionContext<'_>,
) -> (StepConclusion, ResultsConclusion) {
    let has_docker = execution
        .docker_resources()
        .and_then(JobDockerResources::job_container_id)
        .is_some();

    log_sender.send_banner(runner_name, has_docker).await;
    debug!(
        step_id = %step.id,
        is_script = step.is_script(),
        has_docker,
        "executing step"
    );

    let timeout = Duration::from_secs(step.timeout_in_minutes.unwrap_or(360) * 60);
    let deadline = tokio::time::Instant::now() + timeout;

    let result = if step.is_script() {
        // Script steps: container mode if docker_resources has a job container, else host
        if let Some(resources) = execution
            .docker_resources()
            .filter(|resources| resources.job_container_id().is_some())
        {
            run_container_step(
                step,
                job_state,
                workspace,
                base_env,
                log_sender,
                resources,
                cancel_token,
                execution.docker_config(),
            )
            .await
        } else {
            run_host_step(
                step,
                job_state,
                workspace,
                base_env,
                log_sender,
                cancel_token,
                execution.docker_config(),
            )
            .await
        }
    } else {
        run_action_step(
            step,
            job_state,
            workspace,
            base_env,
            log_sender,
            action_cache,
            docker_action_builder,
            docker_build_scope,
            registry_auth,
            access_token,
            deadline,
            cancel_token,
            execution,
        )
        .await
    };

    if let Some(unnamed_state) = job_state.action_states.remove("") {
        let key = step.context_name.as_deref().unwrap_or(&step.id);
        job_state
            .action_states
            .entry(key.to_string())
            .or_default()
            .extend(unnamed_state);
    }

    match result {
        Ok(result) => {
            let rc = ResultsConclusion::from(result.conclusion);
            (result.conclusion, rc)
        }
        Err(e) => {
            log_sender.send(format!("Step error: {e}")).await;
            (StepConclusion::Failed, ResultsConclusion::Failure)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_action_step(
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    action_cache: &ActionCache,
    docker_action_builder: &DockerActionBuilder,
    docker_build_scope: &DockerBuildScope,
    registry_auth: Option<&RegistryAuth>,
    access_token: &str,
    deadline: tokio::time::Instant,
    cancel_token: &CancellationToken,
    execution: &JobExecutionContext<'_>,
) -> Result<StepResult> {
    use super::action::resolve::ActionSource;

    let source = resolve_action(step)?;

    // Case 1: inline docker://image — skip metadata, run directly
    if let ActionSource::Docker { ref image } = source {
        return super::action::docker::run_docker_image_action(
            image,
            step,
            job_state,
            workspace,
            base_env,
            log_sender,
            deadline,
            cancel_token,
            execution,
        )
        .await;
    }

    let action_key = job_state.action_instance_key(step).to_string();
    let action_dir = if let Some(action_dir) = job_state
        .trusted_action_directories
        .get(&action_key)
        .cloned()
    {
        action_dir
    } else {
        let action_dir = action_cache
            .get_action(&source, workspace.workspace_dir(), access_token)
            .await?;
        job_state
            .trusted_action_directories
            .insert(action_key, action_dir.clone());
        action_dir
    };
    let metadata = load_action_metadata(&action_dir)?;

    if metadata.runs.is_node() {
        action_dir.validate_path_identity()?;
        let entry_point = job_state.action_step_phase(step).entry_point();
        super::action::node::run_node_action(
            action_dir.path(),
            &metadata,
            entry_point,
            step,
            job_state,
            workspace,
            base_env,
            log_sender,
            cancel_token,
            execution,
        )
        .await
    } else if metadata.runs.is_composite() {
        action_dir.validate_path_identity()?;
        super::action::composite::run_composite_action(
            &action_dir,
            &metadata,
            step,
            job_state,
            workspace,
            base_env,
            log_sender,
            action_cache,
            docker_action_builder,
            docker_build_scope,
            registry_auth,
            access_token,
            0,
            deadline,
            cancel_token,
            execution,
        )
        .await
    } else if metadata.runs.is_docker() {
        let entry_point = job_state.action_step_phase(step).entry_point();
        super::action::docker::run_docker_metadata_action(
            &action_dir,
            &metadata,
            entry_point,
            step,
            job_state,
            workspace,
            base_env,
            log_sender,
            docker_action_builder,
            docker_build_scope,
            registry_auth,
            deadline,
            cancel_token,
            execution,
        )
        .await
    } else {
        anyhow::bail!("unsupported action runtime: {}", metadata.runs.using)
    }
}

/// Check if an action step has a `post` entry point, returning the cloned
/// step and its `post-if` condition for deferred execution.
fn collect_post_step(
    step: &Step,
    action_dir: &TrustedActionDirectory,
) -> Result<Option<(Step, Option<String>)>> {
    if step.is_script() {
        return Ok(None);
    }

    let metadata = load_action_metadata(action_dir)?;
    let has_post = metadata.runs.post.is_some() || metadata.runs.post_entrypoint.is_some();
    Ok(has_post.then(|| (step.clone(), metadata.runs.post_if.clone())))
}

struct CollectedAction {
    action_dir: TrustedActionDirectory,
    pre_step: Option<(Step, Option<String>)>,
}

/// Resolve an action during pre-step collection and retain its trusted directory
/// even when it has no `pre` entry point.
async fn collect_pre_step(
    step: &Step,
    action_cache: &ActionCache,
    workspace_dir: &Path,
    access_token: &str,
) -> Result<Option<CollectedAction>> {
    if step.is_script() {
        return Ok(None);
    }

    use super::action::resolve::ActionSource;
    let source = resolve_action(step)?;

    if matches!(source, ActionSource::Docker { .. }) {
        return Ok(None);
    }

    let action_dir = action_cache
        .get_action(&source, workspace_dir, access_token)
        .await?;
    let metadata = load_action_metadata(&action_dir)?;
    let has_pre = metadata.runs.pre.is_some() || metadata.runs.pre_entrypoint.is_some();
    let pre_step = has_pre.then(|| (step.clone(), metadata.runs.pre_if.clone()));

    Ok(Some(CollectedAction {
        action_dir,
        pre_step,
    }))
}

async fn report_step_started(
    use_results: bool,
    client: &Arc<JobClient>,
    manifest: &JobManifest,
    trackers: &[StepTracker],
    idx: usize,
    start_time: &str,
) {
    if use_results {
        let steps: Vec<ResultsStep> = trackers.iter().map(|t| t.to_results_step()).collect();
        let _ = client
            .update_steps(&manifest.plan.plan_id, &manifest.plan.job_id, &steps)
            .await;
    } else {
        let tracker = &trackers[idx];
        let _ = client
            .update_timeline(
                &manifest.plan.plan_id,
                &manifest.plan.timeline_id,
                &[TimelineRecord {
                    id: tracker.id.clone(),
                    state: Some(TimelineState::InProgress),
                    result: None,
                    start_time: Some(start_time.to_string()),
                    finish_time: None,
                    name: Some(tracker.name.clone()),
                    order: Some(tracker.order),
                    log: None,
                }],
            )
            .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn report_step_completed(
    use_results: bool,
    client: &Arc<JobClient>,
    manifest: &JobManifest,
    trackers: &[StepTracker],
    idx: usize,
    start_time: &str,
    finish_time: &str,
    result_conclusion: ResultsConclusion,
    legacy_log_id: u64,
) {
    if use_results {
        let steps: Vec<ResultsStep> = trackers.iter().map(|t| t.to_results_step()).collect();
        let _ = client
            .update_steps(&manifest.plan.plan_id, &manifest.plan.job_id, &steps)
            .await;
    } else {
        let timeline_result = match result_conclusion {
            ResultsConclusion::Success => TimelineResult::Succeeded,
            ResultsConclusion::Failure => TimelineResult::Failed,
            ResultsConclusion::Cancelled => TimelineResult::Cancelled,
            ResultsConclusion::Skipped => TimelineResult::Skipped,
            _ => TimelineResult::Failed,
        };
        let tracker = &trackers[idx];
        let _ = client
            .update_timeline(
                &manifest.plan.plan_id,
                &manifest.plan.timeline_id,
                &[TimelineRecord {
                    id: tracker.id.clone(),
                    state: Some(TimelineState::Completed),
                    result: Some(timeline_result),
                    start_time: Some(start_time.to_string()),
                    finish_time: Some(finish_time.to_string()),
                    name: Some(tracker.name.clone()),
                    order: Some(tracker.order),
                    log: Some(TimelineLogRef { id: legacy_log_id }),
                }],
            )
            .await;
    }
}

#[cfg(test)]
#[path = "execute_test.rs"]
mod execute_test;
