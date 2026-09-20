use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, LogsOptions, RemoveContainerOptions, StopContainerOptions,
};
use bollard::errors::Error as DockerError;
use bollard::image::CreateImageOptions;
use bollard::models::{EndpointSettings, HostConfig};
use futures::StreamExt;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::metadata::ActionMetadata;
use super::{TrustedActionDirectory, build_action_inputs};
use crate::docker::build::{
    DockerActionBuilder, DockerBuildOutcome, DockerBuildRequest, DockerBuildScope, RegistryAuth,
    require_local_image,
};
use crate::docker::build_cache::{BudgetOutcome, within_budget};
use crate::docker::output::{DockerErrorDiagnostic, DockerLogFramer, OutputProcessor};
use crate::docker::resources::JobDockerResources;
use crate::job::execute::{
    JobExecutionContext, JobState, StepConclusion, StepResult, build_step_env,
    complete_step_transaction, is_reserved_command_file_env, prepare_step_transaction,
};
use crate::job::execution_domain::DOCKER_CONFIG_ENV;
use crate::job::expression::ExprContext;
use crate::job::logs::LogSender;
use crate::job::schema::Step;
use crate::job::workspace::Workspace;

/// Case 1: Inline `docker://image` — no action.yml, image/entrypoint/args from step inputs.
#[allow(clippy::too_many_arguments)]
pub async fn run_docker_image_action(
    image: &str,
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    deadline: Instant,
    cancel_token: &CancellationToken,
    execution: &JobExecutionContext<'_>,
) -> Result<StepResult> {
    let plan = build_inline_action_env(step, job_state, workspace, base_env)?;

    trace_inline_docker_action(&plan);

    let docker = execution.docker_client()?;

    let state_id = prepare_step_transaction(execution.docker_config(), workspace).await?;
    let processor = OutputProcessor::new(
        log_sender.clone(),
        job_state.secret_masker.clone(),
        job_state.debug_enabled,
    );
    let result = run_docker_container(RunDockerParams {
        docker: &docker,
        image,
        pull_if_missing: true,
        deadline,
        entrypoint: plan.entrypoint.as_deref(),
        args: &plan.args,
        env: &plan.env,
        processor: &processor,
        workspace,
        cancel_token,
        docker_resources: execution.docker_resources(),
    })
    .await;
    let result = complete_step_transaction(
        execution.docker_config(),
        state_id,
        &processor,
        job_state,
        result,
    )
    .await?;

    rekey_action_state(job_state, step);
    Ok(result)
}

/// Case 2: Repo action with `runs.using: docker` — has action.yml with Docker fields.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_docker_metadata_action(
    action_dir: &TrustedActionDirectory,
    metadata: &ActionMetadata,
    entry_point: &str,
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    docker_action_builder: &DockerActionBuilder,
    docker_build_scope: &DockerBuildScope,
    registry_auth: Option<&RegistryAuth>,
    deadline: Instant,
    cancel_token: &CancellationToken,
    execution: &JobExecutionContext<'_>,
) -> Result<StepResult> {
    let (entrypoint, args) = match resolve_entry_point(metadata, entry_point) {
        Some(pair) => pair,
        None => {
            return Ok(StepResult {
                conclusion: StepConclusion::Succeeded,
            });
        }
    };

    let docker = execution.docker_client()?;

    let selected_image = match resolve_metadata_image(metadata)? {
        MetadataImage::Prebuilt(image) => SelectedDockerImage::Prebuilt(image.to_string()),
        MetadataImage::Dockerfile(dockerfile) => {
            let action_key = job_state.action_instance_key(step).to_string();
            let reusable = job_state.docker_action_images.get(&action_key).cloned();
            let outcome = docker_action_builder
                .build(DockerBuildRequest {
                    docker: &docker,
                    action_dir,
                    dockerfile,
                    scope: docker_build_scope,
                    registry_auth,
                    log_sender,
                    cancel_token,
                    deadline,
                    reuse: reusable.as_ref(),
                })
                .await?;
            match outcome {
                DockerBuildOutcome::Ready(built) => {
                    let image_id = built.image_id.clone();
                    job_state.docker_action_images.insert(action_key, built);
                    SelectedDockerImage::Built(image_id)
                }
                DockerBuildOutcome::Cancelled => {
                    return Ok(StepResult {
                        conclusion: StepConclusion::Cancelled,
                    });
                }
                DockerBuildOutcome::TimedOut => {
                    // Dropping the timeout notice is acceptable; extending the
                    // step's lifecycle to wait for log channel capacity is not.
                    let _ = within_budget(
                        deadline,
                        cancel_token,
                        log_sender.send("Docker action image build timed out".into()),
                    )
                    .await;
                    return Ok(StepResult {
                        conclusion: StepConclusion::Failed,
                    });
                }
            }
        }
    };

    let (env, resolved_args) = build_metadata_action_env(
        metadata,
        entry_point,
        &args,
        step,
        job_state,
        workspace,
        base_env,
    )?;

    trace_docker_metadata_action(&selected_image, entrypoint.is_some(), resolved_args.len());

    let state_id = prepare_step_transaction(execution.docker_config(), workspace).await?;
    let processor = OutputProcessor::new(
        log_sender.clone(),
        job_state.secret_masker.clone(),
        job_state.debug_enabled,
    );
    let result = run_docker_container(RunDockerParams {
        docker: &docker,
        image: selected_image.image(),
        pull_if_missing: selected_image.pull_if_missing(),
        deadline,
        entrypoint: entrypoint.as_deref(),
        args: &resolved_args,
        env: &env,
        processor: &processor,
        workspace,
        cancel_token,
        docker_resources: execution.docker_resources(),
    })
    .await;
    let result = complete_step_transaction(
        execution.docker_config(),
        state_id,
        &processor,
        job_state,
        result,
    )
    .await?;

    rekey_action_state(job_state, step);
    Ok(result)
}

// ── Env assembly ────────────────────────────────────────────────

/// Env every docker-action expression resolves against: step env, INPUT_*
/// vars, runs.env, and args. The runner owns DOCKER_CONFIG for host-side
/// docker calls, but action images are untrusted code: the variable must not
/// be observable through `${{ env.DOCKER_CONFIG }}`. Host shell and Node
/// action steps keep it — they legitimately call the docker CLI with it.
fn build_docker_action_env(
    step: &Step,
    job_state: &JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut base = base_env.clone();
    base.remove(DOCKER_CONFIG_ENV);
    let mut env = build_step_env(step, job_state, workspace, &base, None)?;
    // The job env and GITHUB_ENV writes are validated to carry the
    // runner-owned value, which the merge above would reintroduce.
    env.remove(DOCKER_CONFIG_ENV);
    Ok(env)
}

/// Case 1 expression surface: step env plus the `entrypoint`/`args` inputs.
struct InlineActionPlan {
    env: HashMap<String, String>,
    entrypoint: Option<String>,
    args: Vec<String>,
}

fn trace_inline_docker_action(plan: &InlineActionPlan) {
    debug!(
        image_source = "prebuilt",
        has_entrypoint = plan.entrypoint.is_some(),
        resolved_arg_count = plan.args.len(),
        "running inline docker action"
    );
}

fn build_inline_action_env(
    step: &Step,
    job_state: &JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
) -> Result<InlineActionPlan> {
    let env = build_docker_action_env(step, job_state, workspace, base_env)?;
    let expr_ctx = ExprContext::new(&env, job_state, false, false);

    let entrypoint = step.inputs.get("entrypoint").cloned();
    let args = step
        .inputs
        .get("args")
        .map(|a| {
            let resolved = crate::job::expression::resolve_expression(a, &expr_ctx);
            split_shell_args(&resolved)
        })
        .unwrap_or_default();

    Ok(InlineActionPlan {
        env,
        entrypoint,
        args,
    })
}

/// Case 2 expression surface: step env, INPUT_* vars, runs.env, post state,
/// and args.
fn build_metadata_action_env(
    metadata: &ActionMetadata,
    entry_point: &str,
    args: &[String],
    step: &Step,
    job_state: &JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
) -> Result<(HashMap<String, String>, Vec<String>)> {
    let mut env = build_docker_action_env(step, job_state, workspace, base_env)?;
    let expr_ctx = ExprContext::new(&env, job_state, false, false);
    env.extend(build_action_inputs(metadata, step, &expr_ctx));
    merge_action_env(&mut env, metadata, job_state)?;
    inject_post_state(&mut env, entry_point, step, job_state);

    let resolved_args = resolve_args(args, &env, job_state);
    Ok((env, resolved_args))
}

// ── Metadata helpers ────────────────────────────────────────────

enum SelectedDockerImage {
    Prebuilt(String),
    Built(String),
}

impl SelectedDockerImage {
    fn image(&self) -> &str {
        match self {
            Self::Prebuilt(image) | Self::Built(image) => image,
        }
    }

    fn pull_if_missing(&self) -> bool {
        matches!(self, Self::Prebuilt(_))
    }
}

/// Resolved argument values bypass the masking pipeline, so they must never
/// enter global tracing; only their count is recorded here.
fn trace_docker_metadata_action(
    selected_image: &SelectedDockerImage,
    has_entrypoint: bool,
    resolved_arg_count: usize,
) {
    match selected_image {
        SelectedDockerImage::Prebuilt(_) => debug!(
            image_source = "prebuilt",
            has_entrypoint, resolved_arg_count, "running docker metadata action"
        ),
        SelectedDockerImage::Built(_) => debug!(
            image_source = "built",
            has_entrypoint, resolved_arg_count, "running docker metadata action"
        ),
    }
}

enum MetadataImage<'a> {
    Prebuilt(&'a str),
    Dockerfile(&'a str),
}

fn resolve_metadata_image(metadata: &ActionMetadata) -> Result<MetadataImage<'_>> {
    let raw = metadata
        .runs
        .image
        .as_deref()
        .context("docker action has no image field")?;
    if let Some(image) = raw.strip_prefix("docker://") {
        return Ok(MetadataImage::Prebuilt(image));
    }
    let path = Path::new(raw);
    if path.file_name().and_then(|name| name.to_str()) == Some("Dockerfile") {
        return Ok(MetadataImage::Dockerfile(raw));
    }
    Ok(MetadataImage::Prebuilt(raw))
}

/// Route entry_point ("pre"/"main"/"post") to the matching entrypoint + args.
/// Returns `None` when a pre/post entrypoint is absent (caller should skip).
fn resolve_entry_point(
    metadata: &ActionMetadata,
    entry_point: &str,
) -> Option<(Option<String>, Vec<String>)> {
    match entry_point {
        "pre" => metadata
            .runs
            .pre_entrypoint
            .as_ref()
            .map(|ep| (Some(ep.clone()), Vec::new())),
        "post" => metadata
            .runs
            .post_entrypoint
            .as_ref()
            .map(|ep| (Some(ep.clone()), Vec::new())),
        _ => Some((
            metadata.runs.entrypoint.clone(),
            metadata.runs.args.clone().unwrap_or_default(),
        )),
    }
}

fn merge_action_env(
    env: &mut HashMap<String, String>,
    metadata: &ActionMetadata,
    job_state: &JobState,
) -> Result<()> {
    if let Some(action_env) = &metadata.runs.env {
        for (k, v) in action_env {
            if is_reserved_command_file_env(k) {
                anyhow::bail!("reserved workflow command-file environment variable");
            }
            let ctx = ExprContext::new(env, job_state, false, false);
            let resolved = crate::job::expression::resolve_expression(v, &ctx);
            env.insert(k.clone(), resolved);
        }
    }
    Ok(())
}

fn inject_post_state(
    env: &mut HashMap<String, String>,
    entry_point: &str,
    step: &Step,
    job_state: &JobState,
) {
    if entry_point != "post" {
        return;
    }
    let action_ctx = step
        .context_name
        .as_deref()
        .unwrap_or("")
        .replace("_post", "");
    if let Some(states) = job_state.action_states.get(&action_ctx) {
        for (k, v) in states {
            env.insert(format!("STATE_{k}"), v.clone());
        }
    }
}

fn resolve_args(
    args: &[String],
    env: &HashMap<String, String>,
    job_state: &JobState,
) -> Vec<String> {
    args.iter()
        .map(|a| {
            let ctx = ExprContext::new(env, job_state, false, false);
            crate::job::expression::resolve_expression(a, &ctx)
        })
        .collect()
}

// ── Container lifecycle ─────────────────────────────────────────

struct RunDockerParams<'a> {
    docker: &'a Docker,
    image: &'a str,
    pull_if_missing: bool,
    deadline: Instant,
    entrypoint: Option<&'a str>,
    args: &'a [String],
    env: &'a HashMap<String, String>,
    processor: &'a OutputProcessor,
    workspace: &'a Workspace,
    cancel_token: &'a CancellationToken,
    docker_resources: Option<&'a JobDockerResources>,
}

const ACTION_CLEANUP_BUDGET: Duration = Duration::from_secs(2);
const ACTION_CLEANUP_RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleBudgetState {
    Active,
    Cancelled,
    TimedOut,
}

fn lifecycle_budget_state(
    deadline: Instant,
    cancel_token: &CancellationToken,
) -> LifecycleBudgetState {
    if cancel_token.is_cancelled() {
        LifecycleBudgetState::Cancelled
    } else if Instant::now() >= deadline {
        LifecycleBudgetState::TimedOut
    } else {
        LifecycleBudgetState::Active
    }
}

async fn within_lifecycle_budget<T>(
    deadline: Instant,
    cancel_token: &CancellationToken,
    future: impl Future<Output = T>,
) -> BudgetOutcome<T> {
    match lifecycle_budget_state(deadline, cancel_token) {
        LifecycleBudgetState::Cancelled => BudgetOutcome::Cancelled,
        LifecycleBudgetState::TimedOut => BudgetOutcome::TimedOut,
        LifecycleBudgetState::Active => within_budget(deadline, cancel_token, future).await,
    }
}

async fn run_docker_container(params: RunDockerParams<'_>) -> Result<StepResult> {
    let container_name = unique_action_container_name();
    run_docker_container_with_name(params, &container_name).await
}

async fn run_docker_container_with_name(
    params: RunDockerParams<'_>,
    container_name: &str,
) -> Result<StepResult> {
    if let Some(interrupted) = ensure_action_image_ready(
        params.docker,
        params.image,
        params.pull_if_missing,
        params.deadline,
        params.cancel_token,
    )
    .await?
    {
        return Ok(interrupted);
    }

    launch_ready_action_container(params, container_name).await
}

async fn launch_ready_action_container(
    params: RunDockerParams<'_>,
    container_name: &str,
) -> Result<StepResult> {
    let docker = params.docker;
    let container_env = build_container_env(params.env);
    let env_list: Vec<String> = container_env
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let binds = build_bind_mounts(params.workspace)?;
    let network_mode = params
        .docker_resources
        .and_then(|resources| resources.network_name())
        .map(str::to_string);
    let entrypoint_vec = params
        .entrypoint
        .map(|entrypoint| vec![entrypoint.to_string()]);
    let cmd: Option<Vec<&str>> = if params.args.is_empty() {
        None
    } else {
        Some(params.args.iter().map(String::as_str).collect())
    };
    let network_for_config = network_mode.clone();
    let networking_config =
        network_for_config
            .as_ref()
            .map(|network| bollard::container::NetworkingConfig {
                endpoints_config: HashMap::from([(network.as_str(), EndpointSettings::default())]),
            });
    let config = Config {
        image: Some(params.image),
        entrypoint: entrypoint_vec
            .as_deref()
            .map(|values| values.iter().map(String::as_str).collect()),
        cmd,
        env: Some(env_list.iter().map(String::as_str).collect()),
        working_dir: Some("/github/workspace"),
        host_config: Some(HostConfig {
            binds: Some(binds),
            network_mode,
            security_opt: Some(vec!["no-new-privileges:true".into()]),
            ..Default::default()
        }),
        networking_config,
        ..Default::default()
    };

    if let Err(interrupted) = lifecycle_preflight(
        params.deadline,
        params.cancel_token,
        "creating Docker action container",
    ) {
        return Ok(interrupted);
    }
    let create = within_budget(
        params.deadline,
        params.cancel_token,
        docker.create_container(
            Some(CreateContainerOptions {
                name: container_name,
                ..Default::default()
            }),
            config,
        ),
    )
    .await;
    let create = match lifecycle_value(create, "creating Docker action container") {
        Ok(create) => create,
        Err(interrupted) => {
            cleanup_action_container(docker, container_name, true).await;
            return Ok(interrupted);
        }
    };
    let container = match create {
        Ok(container) => container,
        Err(error) => {
            cleanup_action_container(docker, container_name, true).await;
            return Err(error).context("creating Docker action container");
        }
    };

    let result = start_and_stream_logs(
        docker,
        &container.id,
        params.processor,
        params.deadline,
        params.cancel_token,
    )
    .await;

    cleanup_action_container(docker, container_name, false).await;
    result
}

fn unique_action_container_name() -> String {
    format!("chimera-docker-action-{}", uuid::Uuid::new_v4().simple())
}

fn lifecycle_value<T>(
    outcome: BudgetOutcome<T>,
    operation: &'static str,
) -> std::result::Result<T, StepResult> {
    match outcome {
        BudgetOutcome::Ready(value) => Ok(value),
        BudgetOutcome::Cancelled => {
            warn!(operation, "job cancelled during Docker action lifecycle");
            Err(StepResult {
                conclusion: StepConclusion::Cancelled,
            })
        }
        BudgetOutcome::TimedOut => {
            warn!(operation, "Docker action lifecycle timed out");
            Err(StepResult {
                conclusion: StepConclusion::Failed,
            })
        }
    }
}

fn lifecycle_preflight(
    deadline: Instant,
    cancel_token: &CancellationToken,
    operation: &'static str,
) -> std::result::Result<(), StepResult> {
    let outcome = match lifecycle_budget_state(deadline, cancel_token) {
        LifecycleBudgetState::Active => BudgetOutcome::Ready(()),
        LifecycleBudgetState::Cancelled => BudgetOutcome::Cancelled,
        LifecycleBudgetState::TimedOut => BudgetOutcome::TimedOut,
    };
    lifecycle_value(outcome, operation)
}

async fn ensure_action_image_ready(
    docker: &Docker,
    image: &str,
    pull_if_missing: bool,
    deadline: Instant,
    cancel_token: &CancellationToken,
) -> Result<Option<StepResult>> {
    if !pull_if_missing {
        let inspect =
            within_lifecycle_budget(deadline, cancel_token, require_local_image(docker, image))
                .await;
        return match lifecycle_value(inspect, "inspecting built Docker action image") {
            Ok(result) => {
                result?;
                Ok(None)
            }
            Err(interrupted) => Ok(Some(interrupted)),
        };
    }

    let inspect =
        within_lifecycle_budget(deadline, cancel_token, docker.inspect_image(image)).await;
    match lifecycle_value(inspect, "inspecting Docker action image") {
        Ok(Ok(_)) => return Ok(None),
        Ok(Err(_)) => {}
        Err(interrupted) => return Ok(Some(interrupted)),
    }

    let pull =
        within_lifecycle_budget(deadline, cancel_token, pull_action_image(docker, image)).await;
    match lifecycle_value(pull, "pulling Docker action image") {
        Ok(result) => {
            result?;
            Ok(None)
        }
        Err(interrupted) => Ok(Some(interrupted)),
    }
}

async fn pull_action_image(docker: &Docker, image: &str) -> Result<()> {
    let (repository, tag) = split_action_image_reference(image);
    let options = CreateImageOptions {
        from_image: repository,
        tag,
        ..Default::default()
    };
    let mut stream = docker.create_image(options.into(), None, None);
    while let Some(result) = stream.next().await {
        result.context("pulling Docker action image")?;
    }
    Ok(())
}

fn split_action_image_reference(image: &str) -> (&str, &str) {
    if let Some(colon) = image.rfind(':') {
        let tag = &image[colon + 1..];
        if !tag.contains('/') {
            return (&image[..colon], tag);
        }
    }
    (image, "latest")
}

async fn cleanup_action_container(docker: &Docker, container_name: &str, ambiguous: bool) {
    let cleanup_deadline = Instant::now() + ACTION_CLEANUP_BUDGET;
    loop {
        if Instant::now() >= cleanup_deadline {
            warn!(
                container = container_name,
                "Docker action cleanup timed out"
            );
            return;
        }

        let stop = docker.stop_container(container_name, Some(StopContainerOptions { t: 0 }));
        match tokio::time::timeout_at(cleanup_deadline, stop).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if docker_error_is_not_found(&error) => {}
            Ok(Err(error)) => {
                let diagnostic = DockerErrorDiagnostic::from(&error);
                debug!(
                    container = container_name,
                    error_kind = diagnostic.kind,
                    status_code = ?diagnostic.status_code,
                    error_code = ?diagnostic.error_code,
                    column = ?diagnostic.column,
                    "Docker action stop failed"
                );
            }
            Err(_) => {
                warn!(
                    container = container_name,
                    "Docker action stop cleanup timed out"
                );
                return;
            }
        }

        if Instant::now() >= cleanup_deadline {
            warn!(
                container = container_name,
                "Docker action cleanup timed out before removal"
            );
            return;
        }
        let remove = docker.remove_container(
            container_name,
            Some(RemoveContainerOptions {
                force: true,
                v: true,
                ..Default::default()
            }),
        );
        match tokio::time::timeout_at(cleanup_deadline, remove).await {
            Ok(Ok(())) => {
                debug!(
                    container = container_name,
                    "Docker action container removed"
                );
                return;
            }
            Ok(Err(error)) if ambiguous && docker_error_is_not_found(&error) => {
                let retry_at = std::cmp::min(
                    cleanup_deadline,
                    Instant::now() + ACTION_CLEANUP_RETRY_DELAY,
                );
                tokio::time::sleep_until(retry_at).await;
            }
            Ok(Err(error)) if docker_error_is_not_found(&error) => return,
            Ok(Err(error)) => {
                let diagnostic = DockerErrorDiagnostic::from(&error);
                warn!(
                    container = container_name,
                    error_kind = diagnostic.kind,
                    status_code = ?diagnostic.status_code,
                    error_code = ?diagnostic.error_code,
                    column = ?diagnostic.column,
                    "Docker action container removal failed"
                );
                return;
            }
            Err(_) => {
                warn!(
                    container = container_name,
                    "Docker action removal cleanup timed out"
                );
                return;
            }
        }
    }
}

fn docker_error_is_not_found(error: &DockerError) -> bool {
    matches!(
        error,
        DockerError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

fn build_container_env(host_env: &HashMap<String, String>) -> HashMap<String, String> {
    let mut env = host_env.clone();

    // The action's image defines its own PATH; carrying the runner's over would point
    // the container at directories that only exist outside it.
    env.remove("PATH");
    env.remove(DOCKER_CONFIG_ENV);

    let remaps = [
        ("GITHUB_WORKSPACE", "/github/workspace"),
        ("GITHUB_ENV", "/github/workflow/_env"),
        ("GITHUB_PATH", "/github/workflow/_path"),
        ("GITHUB_OUTPUT", "/github/workflow/_output"),
        ("GITHUB_STATE", "/github/workflow/_state"),
        ("GITHUB_STEP_SUMMARY", "/github/workflow/_step_summary"),
        ("RUNNER_TEMP", "/github/tmp"),
        ("RUNNER_TOOL_CACHE", "/github/tool-cache"),
    ];
    for (key, val) in remaps {
        env.insert(key.into(), val.into());
    }
    env
}

fn build_bind_mounts(workspace: &Workspace) -> Result<Vec<String>> {
    let workspace_dir = workspace.workspace_dir();
    let workflow_files = workspace_dir.parent().context("workspace has no parent")?;

    // The action directory is deliberately NOT mounted here: its contents reach
    // the image only through the descriptor-pinned build context, so nothing
    // re-resolves the action pathname at container start. runc-based engines
    // cannot bind /proc/<pid>/fd sources cross-process anyway (the source's
    // mount instance belongs to the fd holder's mount namespace).
    Ok(vec![
        format!("{}:/github/workspace", workspace_dir.display()),
        format!("{}:/github/workflow", workflow_files.display()),
        format!("{}:/github/tmp", workspace.runner_temp().display()),
    ])
}

// ── Log streaming + exit code ───────────────────────────────────

async fn start_and_stream_logs(
    docker: &Docker,
    container_id: &str,
    processor: &OutputProcessor,
    deadline: Instant,
    cancel_token: &CancellationToken,
) -> Result<StepResult> {
    let start = within_lifecycle_budget(
        deadline,
        cancel_token,
        docker.start_container::<String>(container_id, None),
    )
    .await;
    let start = match lifecycle_value(start, "starting Docker action container") {
        Ok(start) => start,
        Err(interrupted) => return Ok(interrupted),
    };
    start.context("starting Docker action container")?;
    if let Err(interrupted) =
        lifecycle_preflight(deadline, cancel_token, "streaming Docker action logs")
    {
        return Ok(interrupted);
    }

    let docker_for_logs = docker.clone();
    let container_id_for_logs = container_id.to_string();
    let processor_for_logs = processor.clone();
    let mut stream_task = tokio::spawn(async move {
        let mut stream = docker_for_logs.logs::<String>(
            &container_id_for_logs,
            Some(LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );
        let mut framer = DockerLogFramer::default();
        loop {
            match stream.next().await {
                Some(Ok(output)) => {
                    for line in framer.push(output) {
                        processor_for_logs.process_line(&line).await;
                    }
                }
                Some(Err(error)) => {
                    let diagnostic = DockerErrorDiagnostic::from(&error);
                    warn!(
                        error_kind = diagnostic.kind,
                        status_code = ?diagnostic.status_code,
                        error_code = ?diagnostic.error_code,
                        column = ?diagnostic.column,
                        "Docker action log stream failed"
                    );
                    return;
                }
                None => break,
            }
        }
        for line in framer.finish() {
            processor_for_logs.process_line(&line).await;
        }
    });

    let stream_result = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => {
            warn!("job cancelled, stopping Docker action container");
            Err(StepResult {
                conclusion: StepConclusion::Cancelled,
            })
        }
        _ = tokio::time::sleep_until(deadline) => {
            warn!("Docker action timed out");
            Err(StepResult {
                conclusion: StepConclusion::Failed,
            })
        }
        joined = &mut stream_task => Ok(joined),
    };

    let joined = match stream_result {
        Ok(joined) => joined,
        Err(interrupted) => {
            stream_task.abort();
            if let Err(error) = stream_task.await
                && !error.is_cancelled()
            {
                warn!(error = %error, "Docker action stream task failed while aborting");
            }
            return Ok(interrupted);
        }
    };
    if let Err(error) = joined {
        warn!(error = %error, "Docker action stream task panicked");
    }

    let inspect = within_lifecycle_budget(
        deadline,
        cancel_token,
        docker.inspect_container(container_id, None),
    )
    .await;
    let inspect = match lifecycle_value(inspect, "inspecting Docker action container") {
        Ok(inspect) => inspect,
        Err(interrupted) => return Ok(interrupted),
    };
    let exit_code = inspect
        .context("inspecting Docker action container")?
        .state
        .and_then(|state| state.exit_code)
        .unwrap_or(-1);

    Ok(StepResult {
        conclusion: if exit_code == 0 {
            StepConclusion::Succeeded
        } else {
            StepConclusion::Failed
        },
    })
}

// ── Utilities ───────────────────────────────────────────────────

fn rekey_action_state(job_state: &mut JobState, step: &Step) {
    if let Some(unnamed_state) = job_state.action_states.remove("") {
        let key = step.context_name.as_deref().unwrap_or(&step.id);
        job_state
            .action_states
            .entry(key.to_string())
            .or_default()
            .extend(unnamed_state);
    }
}

/// Split a string into arguments respecting double and single quotes.
/// `"-c" "echo hello && world"` → `["-c", "echo hello && world"]`
fn split_shell_args(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = ' ';

    for ch in s.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = true;
            quote_char = ch;
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

#[cfg(test)]
#[path = "docker_test.rs"]
mod docker_test;
