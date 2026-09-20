use std::num::NonZeroUsize;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::docker::endpoint::DockerEndpoint;
use crate::github::auth::TokenManager;
use crate::job::action::ActionCache;
use crate::job::client::JobConclusion;
use crate::job::execution_domain::{
    AttemptIdentity, DOCKER_CONFIG_ENV, ExecutionDomain, ExecutionDomainError, ExecutionDomainRoot,
};
use crate::job::schema::{StepReference, StepReferenceKind};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::job::docker_endpoint_test_support::EngineProbe;

async fn setup_execute() -> (tempfile::TempDir, Workspace, Arc<JobClient>, MockServer) {
    let tmp = tempfile::tempdir().unwrap();
    let work_dir = tmp.path().join("work");
    let tmp_dir = tmp.path().join("tmp");
    let tool_cache = tmp.path().join("tool-cache");

    let ws = Workspace::create(
        &work_dir,
        &tmp_dir,
        &tool_cache,
        "test-runner",
        "owner/repo",
    )
    .unwrap();

    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 7200
        })))
        .mount(&mock_server)
        .await;

    // Mock log create
    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 1})))
        .mount(&mock_server)
        .await;

    // Mock log upload
    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs/\d+"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Mock timeline update
    Mock::given(method("PATCH"))
        .and(path_regex(
            r"/_apis/distributedtask/hubs/build/plans/.*/timelines/.*",
        ))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let private_key = crate::testing::test_private_key();
    let tm = Arc::new(TokenManager::new(
        reqwest::Client::new(),
        format!("{}/oauth2/token", mock_server.uri()),
        private_key,
        "test-client".into(),
    ));

    let mut job_client = JobClient::new(
        reqwest::Client::new(),
        tm,
        mock_server.uri(),
        mock_server.uri(),
    );
    job_client.set_job_access_token("test-job-token".into());

    (tmp, ws, Arc::new(job_client), mock_server)
}

fn make_step(id: &str, script: &str) -> Step {
    Step {
        id: id.into(),
        display_name: format!("Run {script}"),
        reference: StepReference {
            name: "script".into(),
            kind: StepReferenceKind::Script,
            ..Default::default()
        },
        inputs: HashMap::from([("script".into(), script.into())]),
        condition: None,
        timeout_in_minutes: None,
        continue_on_error: false,
        order: 1,
        environment: None,
        context_name: None,
    }
}

fn test_step() -> Step {
    make_step("step", "true")
}

fn test_job_state() -> JobState {
    JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    )
}

#[test]
fn step_debug_secret_name_is_case_insensitive() {
    let secrets = HashMap::from([("actions_step_debug".to_string(), "true".to_string())]);
    let state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        secrets,
        serde_json::json!({}),
    );
    assert!(state.debug_enabled);
}

#[tokio::test]
async fn context_data_secret_overrides_variable_regardless_of_case() {
    // A variable secret and a contextData secret whose names differ only by
    // case must collapse to a single entry; contextData wins and any spelling
    // resolves to its value.
    let manifest: JobManifest = serde_json::from_value(serde_json::json!({
        "variables": { "Deploy_Token": { "value": "old", "isSecret": true } },
        "contextData": { "secrets": { "DEPLOY_TOKEN": "new" } }
    }))
    .unwrap();
    let secrets = collect_secrets(&manifest);

    assert_eq!(secrets.len(), 1);
    assert_eq!(
        find_case_insensitive(&secrets, "DEPLOY_TOKEN").unwrap(),
        "new"
    );
    assert_eq!(
        find_case_insensitive(&secrets, "deploy_token").unwrap(),
        "new"
    );
}

#[tokio::test]
async fn allowed_secrets_keep_empty_values_and_exclude_service_credentials() {
    let manifest: JobManifest = serde_json::from_value(serde_json::json!({
        "variables": {
            "EMPTY_VARIABLE": { "value": "", "isSecret": true },
            "system.github.token": { "value": "ghs_job_token", "isSecret": true },
            "system.accessToken": { "value": "service-token", "isSecret": true }
        },
        "contextData": {
            "secrets": {
                "APP_KEY": "app-value",
                "EMPTY_CONTEXT": "",
                "system.accessToken": "context-service-token"
            }
        }
    }))
    .unwrap();
    let secrets = collect_secrets(&manifest);

    assert_eq!(secrets.get("EMPTY_VARIABLE").map(String::as_str), Some(""));
    assert_eq!(secrets.get("EMPTY_CONTEXT").map(String::as_str), Some(""));
    assert_eq!(
        secrets.get("APP_KEY").map(String::as_str),
        Some("app-value")
    );
    assert_eq!(
        secrets.get("GITHUB_TOKEN").map(String::as_str),
        Some("ghs_job_token")
    );
    assert!(find_case_insensitive(&secrets, "system.github.token").is_none());
    assert!(find_case_insensitive(&secrets, "system.accessToken").is_none());
}

fn test_workspace() -> (tempfile::TempDir, Workspace) {
    let temp = tempfile::tempdir().unwrap();
    let workspace = Workspace::create(
        &temp.path().join("work"),
        &temp.path().join("tmp"),
        &temp.path().join("tool-cache"),
        "test-runner",
        "owner/repo",
    )
    .unwrap();
    (temp, workspace)
}

fn test_docker_config() -> (tempfile::TempDir, ExecutionDomain) {
    let temp = tempfile::tempdir().unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = futures::executor::block_on(async {
        root.reserve()
            .await?
            .provision(AttemptIdentity::new())
            .await
    })
    .unwrap();
    (temp, config)
}

fn provision_test_domain(root: &ExecutionDomainRoot) -> ExecutionDomain {
    futures::executor::block_on(async {
        root.reserve()
            .await?
            .provision(AttemptIdentity::new())
            .await
    })
    .unwrap()
}

const DOCKER_CONTEXT_CHILD_CASE: &str = "CHIMERA_DOCKER_CONTEXT_CHILD_CASE";

async fn run_docker_context_child(
    test_name: &str,
    case: &str,
    docker_host: &str,
    resource_endpoint: Option<&DockerEndpoint>,
) {
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .kill_on_drop(true)
        .args(["--exact", test_name, "--nocapture"])
        .env(DOCKER_CONTEXT_CHILD_CASE, case)
        .env("DOCKER_HOST", docker_host);
    if let Some(endpoint) = resource_endpoint {
        command.env(
            "CHIMERA_DOCKER_CONTEXT_RESOURCE_ENDPOINT",
            endpoint.socket_address(),
        );
    }

    let output = tokio::time::timeout(Duration::from_secs(5), command.output())
        .await
        .expect("Docker context child must remain bounded")
        .unwrap();

    assert!(
        output.status.success(),
        "Docker context child {case} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn docker_context_exposes_snapshotted_endpoint_and_fails_selected_missing_socket() {
    if std::env::var_os(DOCKER_CONTEXT_CHILD_CASE).as_deref()
        == Some(std::ffi::OsStr::new("missing"))
    {
        let (_temp, domain) = test_docker_config();
        let node_runtimes = crate::node::NodeRuntimes::single("node".into());
        let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

        assert_eq!(execution.docker_endpoint(), domain.docker_endpoint());
        assert!(execution.docker_client().is_err());
        return;
    }

    run_docker_context_child(
        "job::execute::execute_test::docker_context_exposes_snapshotted_endpoint_and_fails_selected_missing_socket",
        "missing",
        "unix:///absent/context.sock",
        None,
    )
    .await;
}

#[tokio::test]
async fn docker_context_without_resources_routes_to_the_domain_endpoint() {
    if std::env::var_os(DOCKER_CONTEXT_CHILD_CASE).as_deref()
        == Some(std::ffi::OsStr::new("domain"))
    {
        let (_temp, domain) = test_docker_config();
        let node_runtimes = crate::node::NodeRuntimes::single("node".into());
        let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

        assert_eq!(execution.docker_endpoint(), domain.docker_endpoint());
        assert_eq!(
            execution.docker_client().unwrap().ping().await.unwrap(),
            "engine-a"
        );
        return;
    }

    let probe = EngineProbe::start("engine-a").await.unwrap();
    run_docker_context_child(
        "job::execute::execute_test::docker_context_without_resources_routes_to_the_domain_endpoint",
        "domain",
        probe.endpoint().socket_address(),
        None,
    )
    .await;
    assert_eq!(probe.requests().len(), 1);
}

#[tokio::test]
async fn docker_context_with_resources_reuses_the_resource_client() {
    if std::env::var_os(DOCKER_CONTEXT_CHILD_CASE).as_deref()
        == Some(std::ffi::OsStr::new("resources"))
    {
        let endpoint = std::env::var("CHIMERA_DOCKER_CONTEXT_RESOURCE_ENDPOINT").unwrap();
        let socket_path = endpoint.strip_prefix("unix://").unwrap();
        let endpoint = DockerEndpoint::unix_socket(std::path::Path::new(socket_path)).unwrap();
        let docker = crate::docker::client::connect(&endpoint).unwrap();
        let docker_resources = JobDockerResources::new(docker);
        let (_temp, domain) = test_docker_config();
        let node_runtimes = crate::node::NodeRuntimes::single("node".into());
        let execution = JobExecutionContext::new(&domain, Some(&docker_resources), &node_runtimes);

        assert_eq!(
            execution.docker_client().unwrap().ping().await.unwrap(),
            "engine-b"
        );
        return;
    }

    let probe = EngineProbe::start("engine-b").await.unwrap();
    run_docker_context_child(
        "job::execute::execute_test::docker_context_with_resources_reuses_the_resource_client",
        "resources",
        "unix:///absent/domain.sock",
        Some(probe.endpoint()),
    )
    .await;
    assert_eq!(probe.requests().len(), 1);
}

fn step_with_environment(key: &str, value: &str) -> Step {
    let mut step = test_step();
    step.environment = Some(HashMap::from([(key.to_string(), value.to_string())]));
    step
}

fn host_base_env(config: &ExecutionDomain) -> HashMap<String, String> {
    HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        config.docker_config_dir().to_string_lossy().into_owned(),
    )])
}

fn write_executable(path: &std::path::Path) {
    std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn step_environment_cannot_override_docker_config() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    let state = test_job_state();
    let step = step_with_environment(DOCKER_CONFIG_ENV, "/shared/.docker");
    let base = host_base_env(&config);

    let error = build_step_env(&step, &state, &workspace, &base, Some(&config)).unwrap_err();

    assert!(matches!(
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::ReservedEnvironmentOverride {
            source: "step environment"
        })
    ));
}

#[test]
fn step_environment_cannot_override_runner_command_files() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    let state = test_job_state();
    let base = host_base_env(&config);

    for key in [
        "GITHUB_ENV",
        "GITHUB_PATH",
        "GITHUB_OUTPUT",
        "GITHUB_STATE",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_EVENT_PATH",
    ] {
        let step = step_with_environment(key, "/tmp/attacker");
        assert!(build_step_env(&step, &state, &workspace, &base, Some(&config)).is_err());
    }
}

#[test]
fn job_environment_cannot_override_docker_config() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    let mut state = test_job_state();
    state
        .env
        .insert(DOCKER_CONFIG_ENV.into(), "/shared/.docker".into());
    let base = host_base_env(&config);

    let error = build_step_env(&test_step(), &state, &workspace, &base, Some(&config)).unwrap_err();

    assert!(matches!(
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::ReservedEnvironmentOverride {
            source: "job environment"
        })
    ));
}

#[tokio::test]
async fn github_env_cannot_override_docker_config() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    config.bind_workspace(&workspace).await.unwrap();
    let state_id = config.prepare_step(b"{}").await.unwrap();
    std::fs::write(workspace.env_file(), "DOCKER_CONFIG=/shared/.docker\n").unwrap();
    let mut state = test_job_state();
    let error = finish_step_transaction(&config, state_id, &mut state)
        .await
        .unwrap_err();

    assert!(matches!(
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::ReservedEnvironmentOverride {
            source: "GITHUB_ENV"
        })
    ));
}

#[tokio::test]
async fn failed_spawn_still_closes_the_step_transaction() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    let mut state = test_job_state();
    let env = host_base_env(&config);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(8);
    let log_sender = LogSender::new_for_test(
        log_tx,
        crate::job::secret_masker::shared_masker_for_test(&[]),
    );

    let result = run_process(
        OsStr::new("/definitely-missing-chimera-command"),
        &[],
        &env,
        workspace.workspace_dir(),
        &workspace,
        &config,
        &mut state,
        &log_sender,
        Duration::from_secs(1),
        &CancellationToken::new(),
    )
    .await;
    assert!(result.is_err());

    let next = config.prepare_step(b"{}").await.unwrap();
    config.read_step(next).await.unwrap();
}

#[tokio::test]
async fn shell_malformed_state_discards_all_mutations_and_closes_transaction() {
    let (_temp, workspace) = test_workspace();
    let (_resources, domain) = test_docker_config();
    let mut state = test_job_state();
    let env = host_base_env(&domain);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(8);
    let log_sender = LogSender::new_for_test(
        log_tx,
        crate::job::secret_masker::shared_masker_for_test(&[]),
    );
    let step = make_step(
        "malformed-shell",
        "printf '%s\\n' '::set-env name=STDOUT_ENV::leak' \
         '::set-output name=stdout_output::leak' \
         '::add-path::/stdout/leak' \
         '::save-state name=stdout_state::leak'; \
         printf 'FILE_ENV=leak\\n' > \"$GITHUB_ENV\"; \
         printf '\\377' >> \"$GITHUB_ENV\"; \
         printf 'file_output=leak\\n' > \"$GITHUB_OUTPUT\"",
    );

    let error = run_host_step(
        &step,
        &mut state,
        &workspace,
        &env,
        &log_sender,
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap_err();

    assert!(error.downcast_ref::<ExecutionDomainError>().is_some());
    assert!(state.env.is_empty());
    assert!(state.outputs.is_empty());
    assert!(state.path_prepends.is_empty());
    assert!(state.action_states.is_empty());
    assert!(state.step_summaries.is_empty());
    let next = domain.prepare_step(b"{}").await.unwrap();
    domain.read_step(next).await.unwrap();
}

#[tokio::test]
async fn command_files_win_collisions_with_buffered_stdout_commands() {
    let (_temp, workspace) = test_workspace();
    let (_resources, domain) = test_docker_config();
    let mut state = test_job_state();
    let env = host_base_env(&domain);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(8);
    let log_sender = LogSender::new_for_test(
        log_tx,
        crate::job::secret_masker::shared_masker_for_test(&[]),
    );
    let step = make_step(
        "state-order",
        "printf '%s\\n' '::set-env name=COLLISION::stdout' \
         '::set-output name=collision::stdout' \
         '::add-path::/stdout/path' \
         '::save-state name=collision::stdout'; \
         printf 'COLLISION=file\\n' > \"$GITHUB_ENV\"; \
         printf 'collision=file\\n' > \"$GITHUB_OUTPUT\"; \
         printf '/file/path\\n' > \"$GITHUB_PATH\"; \
         printf 'collision=file\\n' > \"$GITHUB_STATE\"",
    );

    let result = run_host_step(
        &step,
        &mut state,
        &workspace,
        &env,
        &log_sender,
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
    assert_eq!(state.env.get("COLLISION").map(String::as_str), Some("file"));
    assert_eq!(
        state.outputs.get("collision").map(String::as_str),
        Some("file")
    );
    assert_eq!(state.path_prepends, ["/stdout/path", "/file/path"]);
    assert_eq!(
        state
            .action_states
            .get("state-order")
            .and_then(|values| values.get("collision"))
            .map(String::as_str),
        Some("file")
    );
}

#[tokio::test]
async fn valid_step_transaction_applies_each_workflow_command_once() {
    let (_temp, workspace) = test_workspace();
    let (_resources, domain) = test_docker_config();
    let mut state = test_job_state();
    let mut env = host_base_env(&domain);
    env.insert("PATH".into(), "/usr/bin:/bin".into());
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(8);
    let log_sender = LogSender::new_for_test(
        log_tx,
        crate::job::secret_masker::shared_masker_for_test(&[]),
    );
    let first = make_step(
        "first",
        "printf '%s\\n' '::add-path::/stdout/once'; \
         printf '/file/once\\n' > \"$GITHUB_PATH\"",
    );

    run_host_step(
        &first,
        &mut state,
        &workspace,
        &env,
        &log_sender,
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();
    run_host_step(
        &make_step("second", "true"),
        &mut state,
        &workspace,
        &env,
        &log_sender,
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();

    assert_eq!(state.path_prepends, ["/stdout/once", "/file/once"]);
}

#[tokio::test]
async fn snapshot_failure_has_priority_over_command_failure_without_partial_mutation() {
    let (_temp, workspace) = test_workspace();
    let (_resources, domain) = test_docker_config();
    domain.bind_workspace(&workspace).await.unwrap();
    let state_id = domain.prepare_step(b"{}").await.unwrap();
    std::fs::remove_file(workspace.env_file()).unwrap();
    std::fs::write(workspace.env_file(), "FILE_ENV=leak\n").unwrap();

    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(8);
    let processor = OutputProcessor::new(
        LogSender::new_for_test(
            log_tx,
            crate::job::secret_masker::shared_masker_for_test(&[]),
        ),
        crate::job::secret_masker::shared_masker_for_test(&[]),
        false,
    );
    processor
        .process_line("::set-env name=STDOUT_ENV::leak")
        .await;
    let mut state = test_job_state();
    let command_result: Result<StepResult> = Err(anyhow::anyhow!("spawn canary"));

    let error =
        complete_step_transaction(&domain, state_id, &processor, &mut state, command_result)
            .await
            .unwrap_err();

    assert!(
        matches!(
            error.downcast_ref::<ExecutionDomainError>(),
            Some(ExecutionDomainError::Backend {
                category: crate::job::execution_domain::FailureCategory::IdentityMismatch,
                ..
            })
        ),
        "snapshot failure must win: {error}"
    );
    assert!(state.env.is_empty());
    let next_error = domain.prepare_step(b"{}").await.unwrap_err();
    assert!(matches!(
        next_error,
        ExecutionDomainError::Backend {
            category: crate::job::execution_domain::FailureCategory::IdentityMismatch,
            ..
        }
    ));
}

#[tokio::test]
async fn unterminated_docker_exec_failure_does_not_consume_or_apply_state() {
    let (_temp, workspace) = test_workspace();
    let (_resources, domain) = test_docker_config();
    domain.bind_workspace(&workspace).await.unwrap();
    let state_id = domain.prepare_step(b"{}").await.unwrap();
    std::fs::write(workspace.path_file(), "/file/leak\n").unwrap();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let processor = OutputProcessor::new(
        LogSender::new_for_test(tokio::sync::mpsc::channel(8).0, masks.clone()),
        masks,
        false,
    );
    processor.process_line("::add-path::/stdout/leak").await;
    let mut state = test_job_state();
    let command_result: Result<StepResult> =
        Err(crate::docker::exec::DockerExecTerminalizationError::StillRunning.into());

    let error =
        complete_docker_exec_transaction(&domain, state_id, &processor, &mut state, command_result)
            .await
            .unwrap_err();

    assert!(
        error
            .downcast_ref::<crate::docker::exec::DockerExecTerminalizationError>()
            .is_some()
    );
    assert!(state.path_prepends.is_empty());
    assert!(matches!(
        domain.prepare_step(b"{}").await.unwrap_err(),
        ExecutionDomainError::Backend { .. }
    ));
}

#[test]
fn matching_override_is_allowed() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    let value = config.docker_config_dir().to_string_lossy().into_owned();
    let step = step_with_environment(DOCKER_CONFIG_ENV, &value);
    let base = HashMap::from([(DOCKER_CONFIG_ENV.to_string(), value.clone())]);

    let env = build_step_env(&step, &test_job_state(), &workspace, &base, Some(&config)).unwrap();

    assert_eq!(env.get(DOCKER_CONFIG_ENV), Some(&value));
}

fn make_action_step(id: &str, context_name: &str) -> Step {
    Step {
        id: id.into(),
        display_name: context_name.into(),
        reference: StepReference {
            name: "local-action".into(),
            kind: StepReferenceKind::Repository,
            repository_type: Some("self".into()),
            path: Some("local-action".into()),
            ..Default::default()
        },
        inputs: HashMap::new(),
        condition: None,
        timeout_in_minutes: None,
        continue_on_error: false,
        order: 1,
        environment: None,
        context_name: Some(context_name.into()),
    }
}

#[tokio::test]
async fn echo_step_stdout_captured() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "echo hello world");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);

    let result = run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();
    assert_eq!(result.conclusion, StepConclusion::Succeeded);

    drop(logger);
}

#[tokio::test]
async fn nonzero_exit_returns_failed() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "exit 1");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);

    let result = run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();
    assert_eq!(result.conclusion, StepConclusion::Failed);

    drop(logger);
}

#[tokio::test]
async fn set_env_updates_job_state() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "echo '::set-env name=MY_KEY::my_val'");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);

    run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();
    assert_eq!(state.env.get("MY_KEY").unwrap(), "my_val");

    drop(logger);
}

#[tokio::test]
async fn add_path_updates_path() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "echo '::add-path::/opt/custom/bin'");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);

    run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();
    assert!(state.path_prepends.contains(&"/opt/custom/bin".to_string()));

    drop(logger);
}

#[tokio::test]
async fn set_output_populates_outputs() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "echo '::set-output name=result::42'");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);

    run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();
    assert_eq!(state.outputs.get("result").unwrap(), "42");

    drop(logger);
}

#[tokio::test]
async fn env_propagation_across_steps() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step1 = make_step("1", "echo '::set-env name=STEP1_VAR::hello'");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);

    run_host_step(
        &step1,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();

    let step2 = make_step("2", "test \"$STEP1_VAR\" = \"hello\"");
    let result = run_host_step(
        &step2,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &domain,
    )
    .await
    .unwrap();
    assert_eq!(result.conclusion, StepConclusion::Succeeded);

    drop(logger);
}

#[tokio::test]
async fn continue_on_error_works() {
    let (tmp, ws, client, _mock) = setup_execute().await;

    let manifest_json = r#"{
        "plan": { "planId": "p", "jobId": "j", "timelineId": "t" },
        "steps": [
            {
                "id": "s1",
                "displayName": "Failing step",
                "reference": { "name": "script", "type": "script" },
                "inputs": { "script": "exit 1" },
                "condition": null,
                "timeoutInMinutes": null,
                "continueOnError": true,
                "order": 1,
                "environment": null
            },
            {
                "id": "s2",
                "displayName": "Should still run",
                "reference": { "name": "script", "type": "script" },
                "inputs": { "script": "echo still running" },
                "condition": null,
                "timeoutInMinutes": null,
                "continueOnError": false,
                "order": 2,
                "environment": null
            }
        ],
        "variables": {},
        "resources": { "endpoints": [] },
        "contextData": {},
        "jobContainer": null,
        "serviceContainers": null
    }"#;

    let manifest: crate::job::schema::JobManifest = serde_json::from_str(manifest_json).unwrap();
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);
    let action_cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_all_steps(
        &manifest,
        &client,
        &ws,
        &base_env,
        "test-runner",
        &action_cache,
        &docker_action_builder,
        None,
        "fake-token",
        CancellationToken::new(),
        &execution,
        None,
    )
    .await
    .unwrap();
    assert_eq!(result.0, JobConclusion::Succeeded);
}

#[tokio::test]
async fn failure_stops_remaining_steps() {
    let (tmp, ws, client, _mock) = setup_execute().await;

    let manifest_json = r#"{
        "plan": { "planId": "p", "jobId": "j", "timelineId": "t" },
        "steps": [
            {
                "id": "s1",
                "displayName": "Failing step",
                "reference": { "name": "script", "type": "script" },
                "inputs": { "script": "exit 1" },
                "condition": null,
                "timeoutInMinutes": null,
                "continueOnError": false,
                "order": 1,
                "environment": null
            },
            {
                "id": "s2",
                "displayName": "Should be skipped",
                "reference": { "name": "script", "type": "script" },
                "inputs": { "script": "echo should not run" },
                "condition": null,
                "timeoutInMinutes": null,
                "continueOnError": false,
                "order": 2,
                "environment": null
            }
        ],
        "variables": {},
        "resources": { "endpoints": [] },
        "contextData": {},
        "jobContainer": null,
        "serviceContainers": null
    }"#;

    let manifest: crate::job::schema::JobManifest = serde_json::from_str(manifest_json).unwrap();
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);
    let action_cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_all_steps(
        &manifest,
        &client,
        &ws,
        &base_env,
        "test-runner",
        &action_cache,
        &docker_action_builder,
        None,
        "fake-token",
        CancellationToken::new(),
        &execution,
        None,
    )
    .await
    .unwrap();
    assert_eq!(result.0, JobConclusion::Failed);
}

#[tokio::test]
async fn secrets_from_context_data_resolved() {
    let (tmp, ws, client, _mock) = setup_execute().await;

    let manifest_json = r#"{
        "plan": { "planId": "p", "jobId": "j", "timelineId": "t" },
        "steps": [
            {
                "id": "s1",
                "displayName": "Use secret",
                "reference": { "name": "script", "type": "script" },
                "inputs": { "script": "test -n \"$MY_SECRET\"" },
                "condition": null,
                "timeoutInMinutes": null,
                "continueOnError": false,
                "order": 1,
                "environment": { "MY_SECRET": "${{ secrets.SECRET }}" }
            }
        ],
        "variables": {},
        "resources": { "endpoints": [] },
        "contextData": {
            "secrets": {
                "SECRET": "super-secret-value"
            }
        },
        "jobContainer": null,
        "serviceContainers": null
    }"#;

    let manifest: crate::job::schema::JobManifest = serde_json::from_str(manifest_json).unwrap();
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);
    let action_cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_all_steps(
        &manifest,
        &client,
        &ws,
        &base_env,
        "test-runner",
        &action_cache,
        &docker_action_builder,
        None,
        "fake-token",
        CancellationToken::new(),
        &execution,
        None,
    )
    .await
    .unwrap();
    assert_eq!(result.0, JobConclusion::Succeeded);
}

#[tokio::test]
async fn step_diagnostics_omit_secret_bearing_manifest_fields() {
    let (tmp, ws, client, _mock) = setup_execute().await;
    let manifest: JobManifest = serde_json::from_value(serde_json::json!({
        "plan": { "planId": "p", "jobId": "j", "timelineId": "t" },
        "steps": [{
            "id": "safe-step-id",
            "displayName": "CANARY-STEP-DIAGNOSTIC",
            "reference": { "name": "script", "type": "script" },
            "inputs": { "script": "true" },
            "condition": "'CANARY-STEP-DIAGNOSTIC' == 'different'",
            "order": 1
        }],
        "variables": {
            "TRACE_SECRET": { "value": "CANARY-STEP-DIAGNOSTIC", "isSecret": true },
            "EMPTY_KEY_SECRET": { "value": "CANARY-EMPTY-OUTPUT-KEY", "isSecret": true },
            "VALUE_KEY_SECRET": { "value": "CANARY-VALUE-OUTPUT-KEY", "isSecret": true }
        },
        "jobOutputs": {
            "CANARY-EMPTY-OUTPUT-KEY": "${{ '' }}",
            "CANARY-VALUE-OUTPUT-KEY": "${{ secrets.OUTPUT_VALUE }}"
        },
        "resources": { "endpoints": [] },
        "contextData": { "secrets": { "OUTPUT_VALUE": "CANARY-OUTPUT-VALUE" } },
        "jobContainer": null,
        "serviceContainers": null
    }))
    .unwrap();
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);
    let action_cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);
    let captured = crate::testing::TracingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .with_writer(captured.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);

    let result = run_all_steps(
        &manifest,
        &client,
        &ws,
        &base_env,
        "test-runner",
        &action_cache,
        &docker_action_builder,
        None,
        "fake-token",
        CancellationToken::new(),
        &execution,
        None,
    )
    .await
    .unwrap();
    let trace = captured.text();

    assert_eq!(result.0, JobConclusion::Succeeded);
    assert!(trace.contains("safe-step-id"), "{trace}");
    for canary in [
        "CANARY-STEP-DIAGNOSTIC",
        "CANARY-EMPTY-OUTPUT-KEY",
        "CANARY-VALUE-OUTPUT-KEY",
        "CANARY-OUTPUT-VALUE",
    ] {
        assert!(!trace.contains(canary), "trace leaked {canary}: {trace}");
    }
}

#[tokio::test]
async fn cancel_token_returns_cancelled_between_steps() {
    let (tmp, ws, client, _mock) = setup_execute().await;

    let manifest_json = r#"{
        "plan": { "planId": "p", "jobId": "j", "timelineId": "t" },
        "steps": [
            {
                "id": "s1",
                "displayName": "First step",
                "reference": { "name": "script", "type": "script" },
                "inputs": { "script": "echo step1" },
                "condition": null,
                "timeoutInMinutes": null,
                "continueOnError": false,
                "order": 1,
                "environment": null
            },
            {
                "id": "s2",
                "displayName": "Should be cancelled",
                "reference": { "name": "script", "type": "script" },
                "inputs": { "script": "echo step2" },
                "condition": null,
                "timeoutInMinutes": null,
                "continueOnError": false,
                "order": 2,
                "environment": null
            }
        ],
        "variables": {},
        "resources": { "endpoints": [] },
        "contextData": {},
        "jobContainer": null,
        "serviceContainers": null
    }"#;

    let manifest: crate::job::schema::JobManifest = serde_json::from_str(manifest_json).unwrap();
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);
    let action_cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let cancel_token = CancellationToken::new();
    // Cancel immediately — step 1 may run but the conclusion should be "cancelled"
    cancel_token.cancel();

    let result = run_all_steps(
        &manifest,
        &client,
        &ws,
        &base_env,
        "test-runner",
        &action_cache,
        &docker_action_builder,
        None,
        "fake-token",
        cancel_token,
        &execution,
        None,
    )
    .await
    .unwrap();
    assert_eq!(result.0, JobConclusion::Cancelled);
}

#[tokio::test]
async fn cancel_token_kills_running_process() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "sleep 60");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, domain) = test_docker_config();
    let base_env = host_base_env(&domain);

    let cancel_token = CancellationToken::new();
    let cancel_clone = cancel_token.clone();

    // Cancel after a brief delay
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        cancel_clone.cancel();
    });

    let start = std::time::Instant::now();
    let result = run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &cancel_token,
        &domain,
    )
    .await
    .unwrap();

    // Should return quickly (well under 60s)
    assert!(start.elapsed().as_secs() < 5);
    assert_eq!(result.conclusion, StepConclusion::Cancelled);

    drop(logger);
}

#[test]
fn host_command_rejects_default_docker_credential_helpers_on_effective_path() {
    for helper in ["docker-credential-pass", "docker-credential-secretservice"] {
        let temp = tempfile::tempdir().unwrap();
        let root = ExecutionDomainRoot::prepare(
            &temp.path().join("job-resources"),
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        let config = futures::executor::block_on(async {
            root.reserve()
                .await?
                .provision(AttemptIdentity::new())
                .await
        })
        .unwrap();
        let bin = temp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        write_executable(&bin.join(helper));
        let mut env = host_base_env(&config);
        env.insert("PATH".into(), bin.to_string_lossy().into_owned());

        let error = host_command("/usr/bin/true", &[], &env, temp.path(), &config).unwrap_err();

        assert!(error.to_string().contains("reserved-host-capability"));
        assert!(error.to_string().contains(helper));
    }
}

#[test]
fn host_command_allows_non_executable_default_credential_helper() {
    let temp = tempfile::tempdir().unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let helper = bin.join("docker-credential-pass");
    std::fs::write(&helper, "not executable").unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut env = host_base_env(&config);
    env.insert("PATH".into(), bin.to_string_lossy().into_owned());

    host_command("/usr/bin/true", &[], &env, temp.path(), &config).unwrap();
}

#[test]
fn host_command_prefers_step_path_and_falls_back_to_non_utf8_inherited_path() {
    let temp = tempfile::tempdir().unwrap();
    let helper_dir = temp.path().join("helper-bin");
    std::fs::create_dir(&helper_dir).unwrap();
    write_executable(&helper_dir.join("docker-credential-pass"));
    let safe_dir = temp.path().join("safe-bin");
    std::fs::create_dir(&safe_dir).unwrap();
    let mut inherited_path = std::ffi::OsString::from_vec(b"/missing-\xff:".to_vec());
    inherited_path.push(&helper_dir);

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "job::execute::execute_test::host_command_path_precedence_child",
            "--nocapture",
        ])
        .env("PATH", inherited_path)
        .env("CHIMERA_EFFECTIVE_PATH_CHILD", &safe_dir)
        .status()
        .unwrap();

    assert!(status.success());
}

#[test]
fn host_command_path_precedence_child() {
    let Some(safe_dir) = std::env::var_os("CHIMERA_EFFECTIVE_PATH_CHILD") else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let mut explicit = host_base_env(&config);
    explicit.insert("PATH".into(), safe_dir.to_string_lossy().into_owned());

    host_command("/usr/bin/true", &[], &explicit, temp.path(), &config).unwrap();

    let inherited = host_base_env(&config);
    let error = host_command("/usr/bin/true", &[], &inherited, temp.path(), &config).unwrap_err();
    assert!(error.to_string().contains("docker-credential-pass"));
}

#[test]
fn host_command_rejects_missing_runner_owned_docker_config() {
    let temp = tempfile::tempdir().unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);

    let error =
        host_command("/usr/bin/true", &[], &HashMap::new(), temp.path(), &config).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("host step is missing runner-owned DOCKER_CONFIG")
    );
}

#[test]
fn host_command_explicitly_overrides_inherited_docker_config() {
    let temp = tempfile::tempdir().unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let env = host_base_env(&config);

    let command = host_command("/usr/bin/true", &[], &env, temp.path(), &config).unwrap();
    let configured = command
        .as_std()
        .get_envs()
        .find(|(key, _)| *key == DOCKER_CONFIG_ENV)
        .and_then(|(_, value)| value)
        .unwrap();

    assert_eq!(configured, std::ffi::OsStr::new(&env[DOCKER_CONFIG_ENV]));
}

#[cfg(target_os = "linux")]
#[test]
fn host_command_rejects_credential_helper_from_private_tmp_path() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let directory_name = format!("chimera-helper-{}", uuid::Uuid::new_v4().simple());
    let private_bin = config.private_tmp().join(&directory_name);
    std::fs::create_dir(&private_bin).unwrap();
    write_executable(&private_bin.join("docker-credential-pass"));
    let mut env = host_base_env(&config);
    env.insert("PATH".into(), format!("/tmp/{directory_name}"));

    let error = host_command("/usr/bin/true", &[], &env, temp.path(), &config).unwrap_err();

    assert!(matches!(
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::ImplicitCredentialStore {
            helper: "docker-credential-pass"
        })
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn host_command_rejects_credential_helper_from_relative_private_tmp_path() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let directory_name = format!("chimera-helper-{}", uuid::Uuid::new_v4().simple());
    let private_bin = config.private_tmp().join(&directory_name);
    std::fs::create_dir(&private_bin).unwrap();
    write_executable(&private_bin.join("docker-credential-secretservice"));
    let mut env = host_base_env(&config);
    env.insert("PATH".into(), ".".into());
    let working_dir = std::path::PathBuf::from("/tmp").join(&directory_name);

    let error = host_command("/usr/bin/true", &[], &env, &working_dir, &config).unwrap_err();

    assert!(matches!(
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::ImplicitCredentialStore {
            helper: "docker-credential-secretservice"
        })
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn host_command_rejects_credential_helper_through_symlink_into_private_tmp() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let directory_name = format!("chimera-helper-{}", uuid::Uuid::new_v4().simple());
    let private_bin = config.private_tmp().join(&directory_name);
    std::fs::create_dir(&private_bin).unwrap();
    write_executable(&private_bin.join("docker-credential-pass"));
    let path_link = temp.path().join("private-tmp-bin");
    std::os::unix::fs::symlink(format!("/tmp/{directory_name}"), &path_link).unwrap();
    let mut env = host_base_env(&config);
    env.insert("PATH".into(), path_link.to_string_lossy().into_owned());

    let error = host_command("/usr/bin/true", &[], &env, temp.path(), &config).unwrap_err();

    assert!(matches!(
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::ImplicitCredentialStore {
            helper: "docker-credential-pass"
        })
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn host_command_rejects_credential_helper_through_symlink_within_private_tmp() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let real_name = format!("chimera-helper-real-{}", uuid::Uuid::new_v4().simple());
    let link_name = format!("chimera-helper-link-{}", uuid::Uuid::new_v4().simple());
    let private_bin = config.private_tmp().join(&real_name);
    std::fs::create_dir(&private_bin).unwrap();
    write_executable(&private_bin.join("docker-credential-secretservice"));
    std::os::unix::fs::symlink(
        format!("/tmp/{real_name}"),
        config.private_tmp().join(&link_name),
    )
    .unwrap();
    let mut env = host_base_env(&config);
    env.insert("PATH".into(), format!("/tmp/{link_name}"));

    let error = host_command("/usr/bin/true", &[], &env, temp.path(), &config).unwrap_err();

    assert!(matches!(
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::ImplicitCredentialStore {
            helper: "docker-credential-secretservice"
        })
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn host_command_skips_inaccessible_path_entry() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let inaccessible = temp.path().join("inaccessible");
    std::fs::create_dir(&inaccessible).unwrap();
    std::fs::set_permissions(&inaccessible, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut env = host_base_env(&config);
    env.insert(
        "PATH".into(),
        format!("{}:/usr/bin:/bin", inaccessible.display()),
    );

    let result = host_command("/usr/bin/true", &[], &env, temp.path(), &config);
    std::fs::set_permissions(&inaccessible, std::fs::Permissions::from_mode(0o700)).unwrap();

    result.unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn host_command_resets_symlink_budget_after_working_directory_lookup() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let final_directory = temp.path().join("resolved-working-directory");
    let real_bin = final_directory.join("real-bin");
    std::fs::create_dir_all(&real_bin).unwrap();
    write_executable(&real_bin.join("docker-credential-pass"));
    std::os::unix::fs::symlink("real-bin", final_directory.join("bin")).unwrap();

    let mut target = final_directory;
    for index in (0..40).rev() {
        let link = temp.path().join(format!("cwd-link-{index}"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        target = link;
    }
    let mut env = host_base_env(&config);
    env.insert("PATH".into(), "bin:/usr/bin:/bin".into());

    let error = host_command("/usr/bin/true", &[], &env, &target, &config).unwrap_err();

    assert!(matches!(
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::ImplicitCredentialStore {
            helper: "docker-credential-pass"
        })
    ));
}

#[cfg(target_os = "linux")]
fn hmac_sha256_hex(key: &[u8], body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let mut key_block = [0_u8; 64];
    if key.len() > key_block.len() {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..key_block.len() {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }
    let inner = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(body)
        .finalize();
    let digest = Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner)
        .finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    hex
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn concurrent_webhook_flows_get_private_absolute_tmp() {
    const JOBS: usize = 20;
    const WEBHOOK_SECRET: &str = "synthetic-webhook-secret";

    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(JOBS).unwrap(),
    )
    .unwrap();
    let barrier = temp.path().join("barrier");
    std::fs::create_dir(&barrier).unwrap();

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("^/deploy$"))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = request.body_json().unwrap();
            let canary = body["canary"].as_str().unwrap();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "deploy_id": format!("deploy:{canary}")
            }))
        })
        .expect(JOBS as u64)
        .mount(&mock_server)
        .await;

    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(256);
    let log_sender = LogSender::new_for_test(
        log_tx,
        crate::job::secret_masker::shared_masker_for_test(&[]),
    );
    let mut runs = Vec::new();
    for index in 0..JOBS {
        let config = root
            .reserve()
            .await
            .unwrap()
            .provision(AttemptIdentity::new())
            .await
            .unwrap();
        let workspace_root = temp.path().join(format!("workspace-{index}"));
        let workspace = Workspace::create(
            &workspace_root.join("work"),
            &workspace_root.join("runner-tmp"),
            &workspace_root.join("tool-cache"),
            "test-runner",
            "owner/repo",
        )
        .unwrap();
        let mut base_env = host_base_env(&config);
        base_env.insert("PATH".into(), "/usr/bin:/bin".into());
        base_env.insert("CANARY".into(), format!("job-{index}"));
        base_env.insert("BARRIER_DIR".into(), barrier.to_string_lossy().into_owned());
        base_env.insert(
            "WEBHOOK_URL".into(),
            format!("{}/deploy", mock_server.uri()),
        );
        base_env.insert("WEBHOOK_SECRET".into(), WEBHOOK_SECRET.into());
        base_env.insert(
            "GITHUB_OUTPUT".into(),
            workspace.output_file().to_string_lossy().into_owned(),
        );
        let script = r#"
            set -eu
            payload_file=/tmp/deploy-payload.json
            response_file=/tmp/deploy-response.json
            trap 'rm -f "$payload_file" "$response_file"' EXIT

            wait_at_barrier() {
                phase=$1
                : > "$BARRIER_DIR/$CANARY.$phase.ready"
                while test ! -e "$BARRIER_DIR/$phase.release"; do sleep 0.01; done
            }

            printf '{"run_id":"%s","canary":"%s"}' \
                "$CANARY" "$CANARY" > "$payload_file"
            wait_at_barrier payload

            signature=$(openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" \
                "$payload_file" | sed 's/^.*= //')
            wait_at_barrier hmac

            curl --fail --silent --show-error \
                --request POST \
                --header 'Content-Type: application/json' \
                --header "X-Webhook-Signature: sha256=$signature" \
                --data-binary "@$payload_file" \
                "$WEBHOOK_URL" > "$response_file"
            wait_at_barrier response

            deploy_id=$(sed -n 's/.*"deploy_id":"\([^"]*\)".*/\1/p' \
                "$response_file")
            test -n "$deploy_id"
            printf 'deploy_id=%s\n' "$deploy_id" >> "$GITHUB_OUTPUT"
        "#;
        let step = make_step(&format!("webhook-{index}"), script);
        let sender = log_sender.clone();
        runs.push(tokio::spawn(async move {
            let mut state = test_job_state();
            let result = run_host_step(
                &step,
                &mut state,
                &workspace,
                &base_env,
                &sender,
                &CancellationToken::new(),
                &config,
            )
            .await;
            let outputs = workspace.read_output_file();
            (result, outputs, config)
        }));
    }

    for phase in ["payload", "hmac", "response"] {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let suffix = format!(".{phase}.ready");
                let ready = std::fs::read_dir(&barrier)
                    .unwrap()
                    .map(Result::unwrap)
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(&suffix))
                    .count();
                if ready == JOBS {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("host commands did not reach the {phase} barrier"));
        std::fs::write(barrier.join(format!("{phase}.release")), "go").unwrap();
    }

    let completed = futures::future::join_all(runs)
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    for (index, (result, outputs, config)) in completed.into_iter().enumerate() {
        assert_eq!(
            result.as_ref().unwrap().conclusion,
            StepConclusion::Succeeded
        );
        assert_eq!(
            outputs.as_ref().unwrap().get("deploy_id"),
            Some(&format!("deploy:job-{index}"))
        );
        assert_eq!(
            std::fs::read_dir(config.private_tmp()).unwrap().count(),
            0,
            "EXIT trap left files in {}",
            config.private_tmp().display()
        );
        let attempt_dir = config.attempt_dir().to_path_buf();
        config.destroy().await.unwrap();
        assert!(!attempt_dir.exists(), "job {index} cleanup");
    }

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), JOBS);
    let mut seen = std::collections::HashSet::new();
    for request in requests {
        let body: serde_json::Value = request.body_json().unwrap();
        let canary = body["canary"].as_str().unwrap();
        assert_eq!(body["run_id"].as_str(), Some(canary));
        let expected_body = format!(r#"{{"run_id":"{canary}","canary":"{canary}"}}"#);
        assert_eq!(request.body, expected_body.as_bytes());
        let expected_signature = hmac_sha256_hex(WEBHOOK_SECRET.as_bytes(), &request.body);
        let signature = request
            .headers
            .get("x-webhook-signature")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(signature, format!("sha256={expected_signature}"));
        assert!(seen.insert(canary.to_owned()), "duplicate canary {canary}");
    }
    assert_eq!(seen.len(), JOBS);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_command_fails_closed_when_private_tmp_is_missing() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = provision_test_domain(&root);
    let sentinel = temp.path().join("command-ran");
    let script = format!("touch '{}'", sentinel.display());
    let env = host_base_env(&config);
    let mut command = host_command(
        "/bin/sh",
        &[std::ffi::OsStr::new("-c"), std::ffi::OsStr::new(&script)],
        &env,
        temp.path(),
        &config,
    )
    .unwrap();
    std::fs::remove_dir(config.private_tmp()).unwrap();

    let error = command.spawn().unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
    assert!(!sentinel.exists());
    config.destroy().await.unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn host_spawn_error_explains_denied_private_namespace_setup() {
    let context = ExecutionDomainError::Backend {
        attempt: None,
        stage: crate::job::execution_domain::Stage::Command,
        category: crate::job::execution_domain::FailureCategory::Io,
        errno: Some(libc::EPERM),
    }
    .to_string();

    assert!(
        context.contains("private user/mount namespace setup"),
        "error should identify the failing setup boundary: {context}"
    );
    assert!(
        context.contains("AppArmor"),
        "error should name the common Ubuntu restriction: {context}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn private_tmp_mount_precedes_working_directory_lookup() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let env = host_base_env(&config);
    let directory_name = format!("chimera-cwd-{}", uuid::Uuid::new_v4().simple());
    let private_working_directory = std::path::PathBuf::from("/tmp").join(&directory_name);

    let create_status = host_command(
        "/bin/mkdir",
        &[
            std::ffi::OsStr::new("-p"),
            private_working_directory.as_os_str(),
        ],
        &env,
        temp.path(),
        &config,
    )
    .unwrap()
    .status()
    .await
    .unwrap();
    assert!(create_status.success());

    let use_status = host_command(
        "/bin/sh",
        &[
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new("printf private > relative-file"),
        ],
        &env,
        &private_working_directory,
        &config,
    )
    .unwrap()
    .status()
    .await
    .unwrap();

    assert!(use_status.success());
    assert_eq!(
        std::fs::read_to_string(
            config
                .private_tmp()
                .join(&directory_name)
                .join("relative-file")
        )
        .unwrap(),
        "private"
    );
    config.destroy().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn working_directory_tmp_does_not_write_to_host_tmp() {
    let test_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&test_root).unwrap();
    let temp = tempfile::tempdir_in(test_root).unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let env = host_base_env(&config);
    let file_name = format!("chimera-cwd-{}", uuid::Uuid::new_v4().simple());
    let host_path = std::path::Path::new("/tmp").join(&file_name);
    let private_path = config.private_tmp().join(&file_name);
    let script = format!("printf private > '{file_name}'");

    let status = host_command(
        "/bin/sh",
        &[std::ffi::OsStr::new("-c"), std::ffi::OsStr::new(&script)],
        &env,
        std::path::Path::new("/tmp"),
        &config,
    )
    .unwrap()
    .status()
    .await
    .unwrap();
    let host_file_existed = host_path.exists();
    if host_file_existed {
        std::fs::remove_file(&host_path).unwrap();
    }

    assert!(status.success());
    assert!(!host_file_existed, "relative write escaped to host /tmp");
    assert_eq!(std::fs::read_to_string(private_path).unwrap(), "private");
    config.destroy().await.unwrap();
}

#[test]
fn host_command_preserves_original_socket_runtime_and_path() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "job::execute::execute_test::host_command_inheritance_child",
            "--nocapture",
        ])
        .env(DOCKER_CONFIG_ENV, "/daemon/shared-docker")
        .env("DOCKER_HOST", "unix:///synthetic/docker.sock")
        .env("XDG_RUNTIME_DIR", "/synthetic/runtime")
        .env("PATH", "/synthetic/path")
        .status()
        .unwrap();

    assert!(status.success());
}

#[tokio::test]
async fn host_command_inheritance_child() {
    if std::env::var_os("DOCKER_HOST").as_deref()
        != Some(std::ffi::OsStr::new("unix:///synthetic/docker.sock"))
    {
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let root = ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = root
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let job_config = config.docker_config_dir().to_path_buf();
    let env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        job_config.to_string_lossy().into_owned(),
    )]);
    let script = r#"
        test "$DOCKER_CONFIG" = "$EXPECTED_CONFIG"
        test "$DOCKER_HOST" = 'unix:///synthetic/docker.sock'
        test "$XDG_RUNTIME_DIR" = '/synthetic/runtime'
        test "$PATH" = '/synthetic/path'
    "#;
    let expected = job_config.to_string_lossy().into_owned();
    let mut command = host_command(
        "/bin/sh",
        &[std::ffi::OsStr::new("-c"), std::ffi::OsStr::new(script)],
        &env,
        temp.path(),
        &config,
    )
    .unwrap();
    command.env("EXPECTED_CONFIG", expected);

    let status = command.status().await.unwrap();

    assert!(status.success());
}

#[test]
fn step_is_script_detection() {
    let script_step = make_step("1", "echo hi");
    assert!(script_step.is_script());

    let action_step = Step {
        id: "2".into(),
        display_name: "Checkout".into(),
        reference: StepReference {
            name: "actions/checkout@v4".into(),
            kind: StepReferenceKind::Unknown("action".into()),
            ..Default::default()
        },
        inputs: HashMap::new(),
        condition: None,
        timeout_in_minutes: None,
        continue_on_error: false,
        order: 1,
        environment: None,
        context_name: None,
    };
    assert!(!action_step.is_script());
}

#[tokio::test]
async fn pre_collection_retains_directory_for_action_without_pre() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("local-action");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: local\nruns:\n  using: node20\n  main: index.js\n",
    )
    .unwrap();
    let step = Step {
        id: "action".into(),
        display_name: "Local action".into(),
        reference: StepReference {
            name: "local-action".into(),
            kind: StepReferenceKind::Repository,
            repository_type: Some("self".into()),
            path: Some("local-action".into()),
            ..Default::default()
        },
        inputs: HashMap::new(),
        condition: None,
        timeout_in_minutes: None,
        continue_on_error: false,
        order: 1,
        environment: None,
        context_name: Some("action".into()),
    };
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());

    let collected = collect_pre_step(&step, &cache, &workspace, "fake-token")
        .await
        .expect("pre collection must propagate no error")
        .expect("pre collection must retain the trusted directory");

    assert!(collected.pre_step.is_none());
    assert_eq!(
        collected.action_dir.path(),
        action_dir.canonicalize().unwrap()
    );
}

#[tokio::test]
async fn collection_error_pre_propagates_action_resolution_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let mut step = make_action_step("action", "action");
    step.reference.path = None;
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());

    let error = match collect_pre_step(&step, &cache, &workspace, "fake-token").await {
        Err(error) => error,
        Ok(_) => panic!("action resolution failure must propagate"),
    };

    assert!(
        error
            .to_string()
            .contains("local action reference missing path"),
        "{error:#}"
    );
}

#[tokio::test]
async fn collection_error_pre_propagates_missing_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir_all(workspace.join("local-action")).unwrap();
    let step = make_action_step("action", "action");
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());

    let error = match collect_pre_step(&step, &cache, &workspace, "fake-token").await {
        Err(error) => error,
        Ok(_) => panic!("metadata failure must propagate"),
    };

    assert!(error.to_string().contains("no action.yml"), "{error:#}");
}

#[tokio::test]
async fn collection_error_pre_propagates_directory_resolution_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let step = make_action_step("action", "action");
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());

    let error = match collect_pre_step(&step, &cache, &workspace, "fake-token").await {
        Err(error) => error,
        Ok(_) => panic!("trusted directory resolution failure must propagate"),
    };

    assert!(
        error.to_string().contains("resolving action directory"),
        "{error:#}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn collection_error_post_propagates_metadata_capability_failure() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("local-action");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: local\nruns:\n  using: node20\n  main: index.js\n",
    )
    .unwrap();
    let outside = tmp.path().join("outside.yml");
    std::fs::write(
        &outside,
        "name: canary\nruns:\n  using: node20\n  main: canary.js\n",
    )
    .unwrap();
    let step = make_action_step("action", "action");
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let trusted = cache
        .get_action(&resolve_action(&step).unwrap(), &workspace, "fake-token")
        .await
        .unwrap();
    std::fs::remove_file(action_dir.join("action.yml")).unwrap();
    symlink(&outside, action_dir.join("action.yml")).unwrap();

    let error = collect_post_step(&step, &trusted).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("action metadata must be a regular file"),
        "{error:#}"
    );
}

#[cfg(all(unix, not(target_os = "linux")))]
#[tokio::test]
async fn collection_error_post_propagates_directory_identity_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("local-action");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: local\nruns:\n  using: node20\n  main: index.js\n  post: cleanup.js\n",
    )
    .unwrap();
    let step = make_action_step("action", "action");
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let trusted = cache
        .get_action(&resolve_action(&step).unwrap(), &workspace, "fake-token")
        .await
        .unwrap();

    std::fs::rename(&workspace, tmp.path().join("original-workspace")).unwrap();
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: replacement\nruns:\n  using: node20\n  main: canary.js\n  post: canary-cleanup.js\n",
    )
    .unwrap();

    let error = collect_post_step(&step, &trusted).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("action directory changed after it was resolved"),
        "{error:#}"
    );
}

#[test]
fn action_lifecycle_suffix_bearing_identifiers_stay_main() {
    let state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let pre_suffix = make_action_step("opaque-pre", "foo_pre");
    let post_suffix = make_action_step("opaque-post", "foo_post");

    assert_eq!(state.action_instance_key(&pre_suffix), "opaque-pre");
    assert_eq!(state.action_step_phase(&pre_suffix), ActionStepPhase::Main);
    assert_eq!(state.action_instance_key(&post_suffix), "opaque-post");
    assert_eq!(state.action_step_phase(&post_suffix), ActionStepPhase::Main);
}

#[test]
fn action_lifecycle_colliding_identifiers_keep_distinct_capabilities() {
    let tmp = tempfile::tempdir().unwrap();
    let first_dir = tmp.path().join("first");
    let second_dir = tmp.path().join("second");
    std::fs::create_dir_all(&first_dir).unwrap();
    std::fs::create_dir_all(&second_dir).unwrap();
    let first = TrustedActionDirectory::resolve(&first_dir, Path::new(".")).unwrap();
    let second = TrustedActionDirectory::resolve(&second_dir, Path::new(".")).unwrap();
    let plain = make_action_step("opaque-plain", "foo");
    let suffix = make_action_step("opaque-suffix", "foo_pre");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );

    let plain_key = state.action_instance_key(&plain).to_string();
    let suffix_key = state.action_instance_key(&suffix).to_string();
    state
        .trusted_action_directories
        .insert(plain_key.clone(), first);
    state
        .trusted_action_directories
        .insert(suffix_key.clone(), second);

    assert_ne!(plain_key, suffix_key);
    assert_eq!(
        state.trusted_action_directories[&plain_key].path(),
        first_dir.canonicalize().unwrap()
    );
    assert_eq!(
        state.trusted_action_directories[&suffix_key].path(),
        second_dir.canonicalize().unwrap()
    );
}

#[test]
fn action_lifecycle_synthetic_steps_share_explicit_instance() {
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let main = make_action_step("opaque-main", "foo_pre");
    let synthetic_pre = make_action_step("synthetic-pre", "foo_pre_pre");
    let synthetic_post = make_action_step("synthetic-post", "foo_pre_post");

    state.link_action_step(&synthetic_pre, &main, ActionStepPhase::Pre);
    state.link_action_step(&synthetic_post, &main, ActionStepPhase::Post);

    assert_eq!(state.action_instance_key(&synthetic_pre), "opaque-main");
    assert_eq!(
        state.action_step_phase(&synthetic_pre),
        ActionStepPhase::Pre
    );
    assert_eq!(state.action_instance_key(&synthetic_post), "opaque-main");
    assert_eq!(
        state.action_step_phase(&synthetic_post),
        ActionStepPhase::Post
    );
}

#[test]
fn build_job_context_no_docker() {
    let ctx = build_job_context(None);
    assert_eq!(ctx["status"], "success");
    assert!(ctx.get("container").is_none());
    assert!(ctx.get("services").is_none());
}

#[test]
fn update_job_status_transitions() {
    let mut data = serde_json::json!({
        "job": { "status": "success" }
    });

    // Initially success
    update_job_status(&mut data, false, false);
    assert_eq!(data["job"]["status"], "success");

    // After failure
    update_job_status(&mut data, true, false);
    assert_eq!(data["job"]["status"], "failure");

    // Cancelled takes priority
    update_job_status(&mut data, true, true);
    assert_eq!(data["job"]["status"], "cancelled");

    // Cancelled without failure
    update_job_status(&mut data, false, true);
    assert_eq!(data["job"]["status"], "cancelled");

    // Back to success
    update_job_status(&mut data, false, false);
    assert_eq!(data["job"]["status"], "success");
}

#[tokio::test]
async fn server_mask_hint_registers_literal_encoded_forms_as_well_as_regex() {
    let manifest: JobManifest = serde_json::from_value(serde_json::json!({
        "mask": [{
            "type": "regex",
            "value": "credential-\"private\""
        }]
    }))
    .unwrap();
    let masker = crate::job::secret_masker::SecretMasker::from_manifest(&manifest).unwrap();

    assert_eq!(masker.mask(r#"credential-\"private\""#), "***");
    assert!(masker.contains_secret(r#"credential-\"private\""#));
}
