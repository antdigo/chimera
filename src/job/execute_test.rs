use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::github::auth::TokenManager;
use crate::job::action::ActionCache;
use crate::job::client::JobConclusion;
use crate::job::docker_config::{
    DOCKER_CONFIG_ENV, JobDockerConfig, JobDockerConfigError, JobResourceRoot,
};
use crate::job::schema::{StepReference, StepReferenceKind};
use rsa::RsaPrivateKey;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

    let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
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
        Arc::new(RwLock::new(Vec::new())),
        HashMap::new(),
        serde_json::json!({}),
    )
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

fn test_docker_config() -> (tempfile::TempDir, JobDockerConfig) {
    let temp = tempfile::tempdir().unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
    (temp, config)
}

fn step_with_environment(key: &str, value: &str) -> Step {
    let mut step = test_step();
    step.environment = Some(HashMap::from([(key.to_string(), value.to_string())]));
    step
}

fn host_base_env(config: &JobDockerConfig) -> HashMap<String, String> {
    HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        config.directory().to_string_lossy().into_owned(),
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
        error.downcast_ref::<JobDockerConfigError>(),
        Some(JobDockerConfigError::ReservedEnvironmentOverride {
            source: "step environment"
        })
    ));
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
        error.downcast_ref::<JobDockerConfigError>(),
        Some(JobDockerConfigError::ReservedEnvironmentOverride {
            source: "job environment"
        })
    ));
}

#[test]
fn github_env_cannot_override_docker_config() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    std::fs::write(workspace.env_file(), "DOCKER_CONFIG=/shared/.docker\n").unwrap();
    let base = host_base_env(&config);

    let error = build_step_env(
        &test_step(),
        &test_job_state(),
        &workspace,
        &base,
        Some(&config),
    )
    .unwrap_err();

    assert!(matches!(
        error.downcast_ref::<JobDockerConfigError>(),
        Some(JobDockerConfigError::ReservedEnvironmentOverride {
            source: "GITHUB_ENV"
        })
    ));
}

#[test]
fn matching_override_is_allowed() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    let value = config.directory().to_string_lossy().into_owned();
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
    let masks = Arc::new(RwLock::new(Vec::new()));
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "echo hello world");
    let mut state = JobState::new(
        Arc::new(RwLock::new(Vec::new())),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);

    let result = run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &docker_config,
    )
    .await
    .unwrap();
    assert_eq!(result.conclusion, StepConclusion::Succeeded);

    drop(logger);
}

#[tokio::test]
async fn nonzero_exit_returns_failed() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = Arc::new(RwLock::new(Vec::new()));
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "exit 1");
    let mut state = JobState::new(
        Arc::new(RwLock::new(Vec::new())),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);

    let result = run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &docker_config,
    )
    .await
    .unwrap();
    assert_eq!(result.conclusion, StepConclusion::Failed);

    drop(logger);
}

#[tokio::test]
async fn set_env_updates_job_state() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = Arc::new(RwLock::new(Vec::new()));
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "echo '::set-env name=MY_KEY::my_val'");
    let mut state = JobState::new(
        Arc::new(RwLock::new(Vec::new())),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);

    run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &docker_config,
    )
    .await
    .unwrap();
    assert_eq!(state.env.get("MY_KEY").unwrap(), "my_val");

    drop(logger);
}

#[tokio::test]
async fn add_path_updates_path() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = Arc::new(RwLock::new(Vec::new()));
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "echo '::add-path::/opt/custom/bin'");
    let mut state = JobState::new(
        Arc::new(RwLock::new(Vec::new())),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);

    run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &docker_config,
    )
    .await
    .unwrap();
    assert!(state.path_prepends.contains(&"/opt/custom/bin".to_string()));

    drop(logger);
}

#[tokio::test]
async fn set_output_populates_outputs() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = Arc::new(RwLock::new(Vec::new()));
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "echo '::set-output name=result::42'");
    let mut state = JobState::new(
        Arc::new(RwLock::new(Vec::new())),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);

    run_host_step(
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &docker_config,
    )
    .await
    .unwrap();
    assert_eq!(state.outputs.get("result").unwrap(), "42");

    drop(logger);
}

#[tokio::test]
async fn env_propagation_across_steps() {
    let (_tmp, ws, client, _mock) = setup_execute().await;
    let masks = Arc::new(RwLock::new(Vec::new()));
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step1 = make_step("1", "echo '::set-env name=STEP1_VAR::hello'");
    let mut state = JobState::new(
        Arc::new(RwLock::new(Vec::new())),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);

    run_host_step(
        &step1,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &docker_config,
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
        &docker_config,
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
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);
    let action_cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&docker_config, None, &node_runtimes);

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
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);
    let action_cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&docker_config, None, &node_runtimes);

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
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);
    let action_cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&docker_config, None, &node_runtimes);

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
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);
    let action_cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&docker_config, None, &node_runtimes);

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
    let masks = Arc::new(RwLock::new(Vec::new()));
    let logger = StepLogger::legacy(client, "plan", "step", masks, None).await;

    let step = make_step("1", "sleep 60");
    let mut state = JobState::new(
        Arc::new(RwLock::new(Vec::new())),
        HashMap::new(),
        serde_json::json!({}),
    );
    let (_resources, docker_config) = test_docker_config();
    let base_env = host_base_env(&docker_config);

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
        &docker_config,
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
        let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
        let config = root.create_docker_config().unwrap();
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
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
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
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
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
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();

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
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
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
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
    let job_config = config.directory().to_path_buf();
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
        Arc::new(RwLock::new(Vec::new())),
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
        Arc::new(RwLock::new(Vec::new())),
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
        Arc::new(RwLock::new(Vec::new())),
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
