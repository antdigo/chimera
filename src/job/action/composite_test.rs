use std::collections::HashMap;
use std::num::NonZeroUsize;

use super::*;
use crate::job::action::download::{ActionCache, TrustedActionDirectory};
use crate::job::action::metadata::{ActionInput, ActionMetadata, ActionRuns};
use crate::job::execute::{JobExecutionContext, JobState, StepConclusion};
use crate::job::execution_domain::{AttemptIdentity, DOCKER_CONFIG_ENV, ExecutionDomainRoot};
use crate::job::logs::StepLogger;
use crate::job::schema::{Step, StepReference};
use crate::job::workspace::Workspace;
use tokio_util::sync::CancellationToken;

fn test_docker_config(tmp: &tempfile::TempDir) -> crate::job::execution_domain::ExecutionDomain {
    let root = ExecutionDomainRoot::prepare(
        &tmp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    futures::executor::block_on(async {
        root.reserve()
            .await?
            .provision(AttemptIdentity::new())
            .await
    })
    .unwrap()
}

fn make_test_workspace(tmp: &tempfile::TempDir) -> Workspace {
    Workspace::create(
        &tmp.path().join("work"),
        &tmp.path().join("tmp"),
        &tmp.path().join("tool-cache"),
        "test-runner",
        "owner/repo",
    )
    .unwrap()
}

fn make_composite_metadata(steps_yaml: &str) -> ActionMetadata {
    let steps: Vec<serde_yaml::Value> = serde_yaml::from_str(steps_yaml).unwrap();
    ActionMetadata {
        name: Some("Composite Test".into()),
        inputs: HashMap::new(),

        runs: ActionRuns {
            using: crate::job::action::metadata::ActionRuntime::Composite,
            main: None,
            pre: None,
            post: None,
            pre_if: None,
            post_if: None,
            steps: Some(steps),
            image: None,
            entrypoint: None,
            args: None,
            pre_entrypoint: None,
            post_entrypoint: None,
            env: None,
        },
    }
}

fn write_local_node_action(workspace: &Workspace, script: &str) {
    let action_dir = workspace
        .workspace_dir()
        .join(".github/actions/nested-node");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: nested-node\nruns:\n  using: node20\n  main: main.js\n",
    )
    .unwrap();
    std::fs::write(action_dir.join("main.js"), script).unwrap();
}

fn make_step() -> Step {
    Step {
        id: "1".into(),
        display_name: "Composite".into(),
        reference: StepReference {
            name: "test/composite".into(),
            kind: crate::job::schema::StepReferenceKind::Repository,
            ..Default::default()
        },
        inputs: HashMap::new(),
        condition: None,
        timeout_in_minutes: None,
        continue_on_error: false,
        order: 1,
        environment: None,
        context_name: None,
    }
}

#[tokio::test]
async fn nested_script_steps_execute() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();

    let metadata = make_composite_metadata(
        r#"
- run: echo "step one"
  shell: bash
- run: echo "step two"
  shell: bash
"#,
    );

    let step = make_step();
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::results_for_test(masks);
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360 * 60);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_composite_action(
        &action_dir,
        &metadata,
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        deadline,
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
}

#[tokio::test]
async fn composite_replaced_state_discards_substep_mutations_and_terminates_transaction() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();
    let metadata = make_composite_metadata(
        r#"
- run: |
    printf '%s\n' '::set-env name=STDOUT_ENV::leak' '::set-output name=stdout_output::leak' '::add-path::/stdout/leak' '::save-state name=stdout_state::leak'
    printf 'FILE_ENV=leak\n' > "$GITHUB_ENV"
    rm "$GITHUB_OUTPUT"
    printf 'file_output=leak\n' > "$GITHUB_OUTPUT"
  shell: bash
"#,
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let mut state = JobState::new(masks.clone(), HashMap::new(), serde_json::json!({}));
    let logger = StepLogger::results_for_test(masks);
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let error = run_composite_action(
        &action_dir,
        &metadata,
        &make_step(),
        &mut state,
        &workspace,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        tokio::time::Instant::now() + std::time::Duration::from_secs(30),
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            error.downcast_ref::<crate::job::execution_domain::ExecutionDomainError>(),
            Some(
                crate::job::execution_domain::ExecutionDomainError::Backend {
                    category: crate::job::execution_domain::FailureCategory::IdentityMismatch,
                    ..
                }
            )
        ),
        "{error}"
    );
    assert!(state.env.is_empty());
    assert!(state.outputs.is_empty());
    assert!(state.path_prepends.is_empty());
    assert!(state.action_states.is_empty());
    let next_error = domain.prepare_step(b"{}").await.unwrap_err();
    assert!(matches!(
        next_error,
        crate::job::execution_domain::ExecutionDomainError::Backend {
            category: crate::job::execution_domain::FailureCategory::IdentityMismatch,
            ..
        }
    ));
}

#[tokio::test]
async fn composite_substeps_apply_each_workflow_command_once() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();
    let metadata = make_composite_metadata(
        r#"
- run: |
    printf '%s\n' '::add-path::/stdout/composite'
    printf '/file/composite\n' > "$GITHUB_PATH"
  shell: bash
"#,
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let mut state = JobState::new(masks.clone(), HashMap::new(), serde_json::json!({}));
    let logger = StepLogger::results_for_test(masks);
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_composite_action(
        &action_dir,
        &metadata,
        &make_step(),
        &mut state,
        &workspace,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        tokio::time::Instant::now() + std::time::Duration::from_secs(30),
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
    assert_eq!(
        state.path_prepends,
        ["/stdout/composite", "/file/composite"]
    );
}

#[tokio::test]
async fn skipped_composite_condition_is_not_written_to_daemon_trace() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();
    let metadata = make_composite_metadata(
        r#"
- run: true
  shell: bash
  if: "'CANARY-COMPOSITE-CONDITION' == 'different'"
"#,
    );
    let masker = crate::job::secret_masker::shared_masker_for_test(&["CANARY-COMPOSITE-CONDITION"]);
    let mut state = JobState::new(masker.clone(), HashMap::new(), serde_json::json!({}));
    let logger = StepLogger::results_for_test(masker);
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360 * 60);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
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

    let result = run_composite_action(
        &action_dir,
        &metadata,
        &make_step(),
        &mut state,
        &workspace,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        deadline,
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();
    let trace = captured.text();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
    assert!(trace.contains("composite_step=0"), "{trace}");
    assert!(!trace.contains("CANARY-COMPOSITE-CONDITION"), "{trace}");
}

#[tokio::test]
async fn failure_propagates() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();

    let metadata = make_composite_metadata(
        r#"
- run: exit 1
  shell: bash
- run: echo "should not run"
  shell: bash
"#,
    );

    let step = make_step();
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::results_for_test(masks);
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360 * 60);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_composite_action(
        &action_dir,
        &metadata,
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        deadline,
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Failed);
}

#[tokio::test]
async fn inputs_available_as_env() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();

    let mut metadata = make_composite_metadata(
        r#"
- run: test "$INPUT_NAME" = "world"
  shell: bash
"#,
    );
    metadata
        .inputs
        .insert("name".into(), ActionInput { default: None });

    let mut step = make_step();
    step.inputs.insert("name".into(), "world".into());

    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::results_for_test(masks);
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360 * 60);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_composite_action(
        &action_dir,
        &metadata,
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        deadline,
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
}

#[tokio::test]
async fn nested_host_script_rejects_mismatched_docker_config_before_spawn() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let marker = tmp.path().join("nested-script-ran");
    let metadata = make_composite_metadata(&format!(
        r#"
- run: touch "{}"
  shell: bash
  env:
    DOCKER_CONFIG: /shared/.docker
"#,
        marker.display()
    ));
    let step = make_step();
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let logger =
        StepLogger::results_for_test(crate::job::secret_masker::shared_masker_for_test(&[]));
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360 * 60);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let error = run_composite_action(
        &action_dir,
        &metadata,
        &step,
        &mut state,
        &workspace,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        deadline,
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("reserved-environment-variable"));
    assert!(!marker.exists());
}

#[tokio::test]
async fn nested_host_script_allows_matching_docker_config() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let metadata = make_composite_metadata(
        r#"
- run: test "$DOCKER_CONFIG" = "$EXPECTED_CONFIG"
  shell: bash
  env:
    DOCKER_CONFIG: ${{ env.EXPECTED_CONFIG }}
"#,
    );
    let step = make_step();
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let logger =
        StepLogger::results_for_test(crate::job::secret_masker::shared_masker_for_test(&[]));
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360 * 60);
    let domain = test_docker_config(&tmp);
    let docker_config_path = domain.docker_config_dir().to_string_lossy().into_owned();
    let base_env = HashMap::from([
        (DOCKER_CONFIG_ENV.to_string(), docker_config_path.clone()),
        ("EXPECTED_CONFIG".into(), docker_config_path),
    ]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_composite_action(
        &action_dir,
        &metadata,
        &step,
        &mut state,
        &workspace,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        deadline,
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
}

#[tokio::test]
async fn nested_local_node_rejects_mismatched_docker_config_before_spawn() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = make_test_workspace(&tmp);
    write_local_node_action(&workspace, r#": > "$GITHUB_WORKSPACE/nested-node-ran""#);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let metadata = make_composite_metadata(
        r#"
- uses: ./.github/actions/nested-node
  env:
    DOCKER_CONFIG: /shared/.docker
"#,
    );
    let step = make_step();
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let logger =
        StepLogger::results_for_test(crate::job::secret_masker::shared_masker_for_test(&[]));
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360 * 60);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([
        (
            DOCKER_CONFIG_ENV.to_string(),
            domain.docker_config_dir().to_string_lossy().into_owned(),
        ),
        (
            "GITHUB_WORKSPACE".into(),
            workspace.workspace_dir().to_string_lossy().into_owned(),
        ),
    ]);
    let node_runtimes = crate::node::NodeRuntimes::single("/bin/sh".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let error = run_composite_action(
        &action_dir,
        &metadata,
        &step,
        &mut state,
        &workspace,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        deadline,
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("reserved-environment-variable"));
    assert!(!workspace.workspace_dir().join("nested-node-ran").exists());
}

#[tokio::test]
async fn nested_local_node_allows_matching_docker_config() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = make_test_workspace(&tmp);
    write_local_node_action(
        &workspace,
        r#"
test "$DOCKER_CONFIG" = "$EXPECTED_CONFIG"
: > "$GITHUB_WORKSPACE/nested-node-ran"
"#,
    );
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let metadata = make_composite_metadata(
        r#"
- uses: ./.github/actions/nested-node
  env:
    DOCKER_CONFIG: ${{ env.EXPECTED_CONFIG }}
"#,
    );
    let step = make_step();
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let logger =
        StepLogger::results_for_test(crate::job::secret_masker::shared_masker_for_test(&[]));
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360 * 60);
    let domain = test_docker_config(&tmp);
    let docker_config_path = domain.docker_config_dir().to_string_lossy().into_owned();
    let base_env = HashMap::from([
        (DOCKER_CONFIG_ENV.to_string(), docker_config_path.clone()),
        ("EXPECTED_CONFIG".into(), docker_config_path),
        (
            "GITHUB_WORKSPACE".into(),
            workspace.workspace_dir().to_string_lossy().into_owned(),
        ),
    ]);
    let node_runtimes = crate::node::NodeRuntimes::single("/bin/sh".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_composite_action(
        &action_dir,
        &metadata,
        &step,
        &mut state,
        &workspace,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        0,
        deadline,
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
    assert!(workspace.workspace_dir().join("nested-node-ran").exists());
}

#[tokio::test]
async fn recursion_depth_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    let action_dir =
        TrustedActionDirectory::resolve(&action_dir, std::path::Path::new(".")).unwrap();

    let metadata = make_composite_metadata(
        r#"
- run: echo "hi"
  shell: bash
"#,
    );

    let step = make_step();
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::results_for_test(masks);
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let docker_action_builder = crate::docker::build::DockerActionBuilder::new();
    let docker_build_scope =
        crate::docker::build::DockerBuildScope::new("test-runner", "https://github.com/owner/repo");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360 * 60);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_composite_action(
        &action_dir,
        &metadata,
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &cache,
        &docker_action_builder,
        &docker_build_scope,
        None,
        "fake-token",
        10, // Already at limit
        deadline,
        &CancellationToken::new(),
        &execution,
    )
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("recursion depth"));
}
