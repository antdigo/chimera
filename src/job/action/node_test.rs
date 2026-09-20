use std::collections::HashMap;
use std::num::NonZeroUsize;

use super::*;
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

fn make_action_step(name: &str) -> Step {
    Step {
        id: "1".into(),
        display_name: name.into(),
        reference: StepReference {
            name: "test-owner/test-action".into(),
            kind: crate::job::schema::StepReferenceKind::Repository,
            git_ref: Some("v1".into()),
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

fn make_node_metadata(main_script: &str) -> ActionMetadata {
    ActionMetadata {
        name: Some("Test Action".into()),
        inputs: HashMap::new(),

        runs: crate::job::action::metadata::ActionRuns {
            using: crate::job::action::metadata::ActionRuntime::Node("20".into()),
            main: Some(main_script.into()),
            pre: None,
            post: None,
            pre_if: None,
            post_if: None,
            steps: None,
            image: None,
            entrypoint: None,
            args: None,
            pre_entrypoint: None,
            post_entrypoint: None,
            env: None,
        },
    }
}

#[tokio::test]
async fn node_action_executes_script() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = make_test_workspace(&tmp);

    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("index.js"),
        "console.log('hello from action');",
    )
    .unwrap();

    let metadata = make_node_metadata("index.js");
    let step = make_action_step("Test");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::results_for_test(masks);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_node_action(
        &action_dir,
        &metadata,
        "main",
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &execution,
    )
    .await;

    // May fail if node is not installed — skip gracefully
    match result {
        Ok(r) => assert_eq!(r.conclusion, StepConclusion::Succeeded),
        Err(e) if e.to_string().contains("spawning node") => {
            eprintln!("skipping test: node not found on PATH");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[tokio::test]
async fn node_action_diagnostics_omit_action_paths_and_script_names() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = make_test_workspace(&tmp);
    let canary = "CANARY-NODE-DIAGNOSTIC";
    let action_dir = tmp.path().join(canary);
    std::fs::create_dir_all(&action_dir).unwrap();
    let script_file = format!("{canary}.sh");
    std::fs::write(action_dir.join(&script_file), "exit 0\n").unwrap();
    let masker = crate::job::secret_masker::shared_masker_for_test(&[canary]);
    let mut state = JobState::new(masker.clone(), HashMap::new(), serde_json::json!({}));
    let logger = StepLogger::results_for_test(masker);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("/bin/sh".into());
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

    let result = run_node_action(
        &action_dir,
        &make_node_metadata(&script_file),
        "main",
        &make_action_step("Test"),
        &mut state,
        &workspace,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();
    let trace = captured.text();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
    assert!(trace.contains("running node action"), "{trace}");
    assert!(!trace.contains(canary), "{trace}");
}

#[tokio::test]
async fn input_env_vars_set() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = make_test_workspace(&tmp);

    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    // Script that checks INPUT_TOKEN is set and prints it
    std::fs::write(
        action_dir.join("index.js"),
        r#"
if (process.env.INPUT_TOKEN !== 'my-secret') {
    process.exit(1);
}
"#,
    )
    .unwrap();

    let mut metadata = make_node_metadata("index.js");
    metadata.inputs.insert(
        "token".into(),
        crate::job::action::metadata::ActionInput { default: None },
    );

    let mut step = make_action_step("Test");
    step.inputs.insert("token".into(), "my-secret".into());

    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::results_for_test(masks);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_node_action(
        &action_dir,
        &metadata,
        "main",
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &execution,
    )
    .await;

    match result {
        Ok(r) => assert_eq!(r.conclusion, StepConclusion::Succeeded),
        Err(e) if e.to_string().contains("spawning node") => {
            eprintln!("skipping test: node not found on PATH");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[tokio::test]
async fn defaults_used_when_no_step_input() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = make_test_workspace(&tmp);

    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("index.js"),
        r#"
if (process.env.INPUT_FLAVOR !== 'vanilla') {
    process.exit(1);
}
"#,
    )
    .unwrap();

    let mut metadata = make_node_metadata("index.js");
    metadata.inputs.insert(
        "flavor".into(),
        crate::job::action::metadata::ActionInput {
            default: Some("vanilla".into()),
        },
    );

    let step = make_action_step("Test");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::results_for_test(masks);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_node_action(
        &action_dir,
        &metadata,
        "main",
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &execution,
    )
    .await;

    match result {
        Ok(r) => assert_eq!(r.conclusion, StepConclusion::Succeeded),
        Err(e) if e.to_string().contains("spawning node") => {
            eprintln!("skipping test: node not found on PATH");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[tokio::test]
async fn nonzero_exit_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = make_test_workspace(&tmp);

    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("index.js"), "process.exit(1);").unwrap();

    let metadata = make_node_metadata("index.js");
    let step = make_action_step("Test");
    let mut state = JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    );
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::results_for_test(masks);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_node_action(
        &action_dir,
        &metadata,
        "main",
        &step,
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &execution,
    )
    .await;

    match result {
        Ok(r) => assert_eq!(r.conclusion, StepConclusion::Failed),
        Err(e) if e.to_string().contains("spawning node") => {
            eprintln!("skipping test: node not found on PATH");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[tokio::test]
async fn failing_node_action_masks_secret_in_collected_log() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = make_test_workspace(&tmp);
    let action_dir = tmp.path().join("action");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("index.js"),
        r#"
console.log('safe-node-line');
console.log('json=quote-\\\"slash\\\\-node-41');
console.error('stderr=quote-\\\"slash\\\\-node-41');
process.exit(1);
"#,
    )
    .unwrap();

    let secret = "quote-\"slash\\-node-41";
    let masks = crate::job::secret_masker::shared_masker_for_test(&[secret]);
    let mut state = JobState::new(masks.clone(), HashMap::new(), serde_json::json!({}));
    let logger = StepLogger::results_for_test(masks);
    let domain = test_docker_config(&tmp);
    let base_env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        domain.docker_config_dir().to_string_lossy().into_owned(),
    )]);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = run_node_action(
        &action_dir,
        &make_node_metadata("index.js"),
        "main",
        &make_action_step("Test"),
        &mut state,
        &ws,
        &base_env,
        logger.sender(),
        &CancellationToken::new(),
        &execution,
    )
    .await;

    let result = match result {
        Ok(result) => result,
        Err(error) if error.to_string().contains("spawning node") => {
            eprintln!("skipping test: node not found on PATH");
            return;
        }
        Err(error) => panic!("unexpected error: {error}"),
    };
    let collected = logger.finish().await.expect("collected node action log");

    assert_eq!(result.conclusion, StepConclusion::Failed);
    assert!(collected.text.contains("safe-node-line"));
    assert!(collected.text.contains("***"));
    assert!(!collected.text.contains(secret));
    assert!(!collected.text.contains(r#"quote-\"slash\\-node-41"#));
}
