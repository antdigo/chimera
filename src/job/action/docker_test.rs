use std::collections::HashMap;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::docker::endpoint::DockerEndpoint;
use crate::job::action::metadata::{ActionInput, ActionRuns, ActionRuntime};
use crate::job::execution_domain::{DOCKER_CONFIG_ENV, ExecutionDomainRoot};
use crate::job::logs::LogSender;
use crate::job::schema::{StepReference, StepReferenceKind};
use crate::job::workspace::Workspace;

use crate::job::docker_endpoint_test_support::EngineProbe;

struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TraceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn lifecycle_budget_state_reports_active_cancelled_and_timed_out() {
    let active = CancellationToken::new();
    assert_eq!(
        lifecycle_budget_state(Instant::now() + Duration::from_secs(60), &active),
        LifecycleBudgetState::Active
    );

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        lifecycle_budget_state(Instant::now() - Duration::from_secs(1), &cancelled),
        LifecycleBudgetState::Cancelled
    );

    assert_eq!(
        lifecycle_budget_state(
            Instant::now() - Duration::from_secs(1),
            &CancellationToken::new()
        ),
        LifecycleBudgetState::TimedOut
    );
}

#[test]
fn action_container_names_are_unique_and_docker_safe() {
    let left = unique_action_container_name();
    let right = unique_action_container_name();

    assert_ne!(left, right);
    for name in [left, right] {
        assert!(name.starts_with("chimera-docker-action-"));
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
    }
}

#[test]
fn action_image_reference_preserves_registry_ports_and_defaults_tag() {
    assert_eq!(
        split_action_image_reference("registry.example:5000/owner/image:v1"),
        ("registry.example:5000/owner/image", "v1")
    );
    assert_eq!(
        split_action_image_reference("registry.example:5000/owner/image"),
        ("registry.example:5000/owner/image", "latest")
    );
}

#[tokio::test]
async fn lifecycle_budget_does_not_poll_operation_after_cancellation() {
    let polled = Arc::new(AtomicBool::new(false));
    let polled_by_operation = Arc::clone(&polled);
    let cancel = CancellationToken::new();
    cancel.cancel();

    let outcome = within_lifecycle_budget(
        Instant::now() - Duration::from_secs(1),
        &cancel,
        async move {
            polled_by_operation.store(true, Ordering::SeqCst);
        },
    )
    .await;

    assert!(matches!(outcome, BudgetOutcome::Cancelled));
    assert!(!polled.load(Ordering::SeqCst));
}

#[tokio::test]
async fn lifecycle_budget_does_not_poll_operation_after_deadline() {
    let polled = Arc::new(AtomicBool::new(false));
    let polled_by_operation = Arc::clone(&polled);

    let outcome = within_lifecycle_budget(
        Instant::now() - Duration::from_secs(1),
        &CancellationToken::new(),
        async move {
            polled_by_operation.store(true, Ordering::SeqCst);
        },
    )
    .await;

    assert!(matches!(outcome, BudgetOutcome::TimedOut));
    assert!(!polled.load(Ordering::SeqCst));
}

#[derive(Clone, Copy)]
enum EngineTestLaunchPath {
    FullLifecycle,
    ReadyImage,
}

async fn run_engine_test_container(
    docker: &Docker,
    image: &str,
    container_name: &str,
    cancel_token: &CancellationToken,
    launch_path: EngineTestLaunchPath,
) -> Result<StepResult> {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = Workspace::create(
        &tmp.path().join("work"),
        &tmp.path().join("tmp"),
        &tmp.path().join("tool-cache"),
        "test-runner",
        "owner/repo",
    )
    .unwrap();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(32);
    let log_sender = LogSender::new_for_test(log_tx, Arc::clone(&masks));
    let processor = OutputProcessor::new(log_sender, masks, false);
    let env = HashMap::new();
    let args = vec!["-c".to_string(), "sleep 30".to_string()];
    let params = RunDockerParams {
        docker,
        image,
        pull_if_missing: false,
        deadline: Instant::now() + Duration::from_secs(30),
        entrypoint: Some("/bin/sh"),
        args: &args,
        env: &env,
        processor: &processor,
        workspace: &workspace,
        cancel_token,
        docker_resources: None,
    };

    match launch_path {
        EngineTestLaunchPath::FullLifecycle => {
            run_docker_container_with_name(params, container_name).await
        }
        EngineTestLaunchPath::ReadyImage => {
            launch_ready_action_container(params, container_name).await
        }
    }
}

async fn assert_engine_container_absent(docker: &Docker, container_name: &str) {
    assert!(matches!(
        docker.inspect_container(container_name, None).await,
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            ..
        })
    ));
}

#[tokio::test]
#[ignore]
async fn cancellation_immediately_before_create_does_not_create_container() {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let container_name = format!(
        "chimera-test-before-create-{}",
        uuid::Uuid::new_v4().simple()
    );
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = tokio::time::timeout(
        Duration::from_secs(4),
        run_engine_test_container(
            &docker,
            "alpine:3.19",
            &container_name,
            &cancel,
            EngineTestLaunchPath::ReadyImage,
        ),
    )
    .await
    .expect("pre-create cancellation and cleanup must be bounded")
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Cancelled);
    assert_engine_container_absent(&docker, &container_name).await;
}

#[tokio::test]
#[ignore]
async fn cancellation_at_engine_create_event_removes_container() {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let container_name = format!(
        "chimera-test-create-event-{}",
        uuid::Uuid::new_v4().simple()
    );
    let cancel = CancellationToken::new();
    let cancel_on_event = cancel.clone();
    let event_docker = docker.clone();
    let event_container_name = container_name.clone();
    let event_task = tokio::spawn(async move {
        let mut events = event_docker.events(Some(bollard::system::EventsOptions {
            since: None,
            until: None,
            filters: HashMap::from([
                ("type".to_string(), vec!["container".to_string()]),
                ("container".to_string(), vec![event_container_name.clone()]),
                (
                    "event".to_string(),
                    vec!["create".to_string(), "start".to_string()],
                ),
            ]),
        }));
        let event = tokio::time::timeout(Duration::from_secs(10), events.next())
            .await
            .expect("Docker create/start event must arrive")
            .expect("Docker event stream ended")
            .unwrap();
        assert!(matches!(event.action.as_deref(), Some("create" | "start")));
        cancel_on_event.cancel();
    });
    tokio::task::yield_now().await;

    let result = tokio::time::timeout(
        Duration::from_secs(15),
        run_engine_test_container(
            &docker,
            "alpine:3.19",
            &container_name,
            &cancel,
            EngineTestLaunchPath::ReadyImage,
        ),
    )
    .await
    .expect("create/start cancellation and cleanup must be bounded")
    .unwrap();
    event_task.await.unwrap();

    assert_eq!(result.conclusion, StepConclusion::Cancelled);
    assert_engine_container_absent(&docker, &container_name).await;
}

#[tokio::test]
#[ignore]
async fn cancellation_after_build_publication_does_not_launch_container() {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let action = tempfile::tempdir().unwrap();
    std::fs::write(
        action.path().join("Dockerfile"),
        "FROM alpine:3.19\nRUN true\n",
    )
    .unwrap();
    let action_dir = TrustedActionDirectory::resolve(action.path(), Path::new(".")).unwrap();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(64);
    let log_sender = LogSender::new_for_test(log_tx, masks);
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new(
        "test-runner",
        format!("test/post-publication-{}", uuid::Uuid::new_v4()),
    );
    let built = builder
        .build(DockerBuildRequest {
            docker: &docker,
            action_dir: &action_dir,
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &log_sender,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(120),
            reuse: None,
        })
        .await
        .unwrap();
    let DockerBuildOutcome::Ready(image) = built else {
        panic!("expected published Docker action image");
    };
    let container_name = format!(
        "chimera-test-post-publication-{}",
        uuid::Uuid::new_v4().simple()
    );
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = run_engine_test_container(
        &docker,
        &image.image_id,
        &container_name,
        &cancel,
        EngineTestLaunchPath::FullLifecycle,
    )
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Cancelled);
    assert_engine_container_absent(&docker, &container_name).await;
}

// ── split_shell_args ────────────────────────────────────────────

#[test]
fn split_args_simple() {
    assert_eq!(split_shell_args("echo hello"), vec!["echo", "hello"]);
}

#[test]
fn split_args_double_quotes() {
    assert_eq!(
        split_shell_args(r#"-c "echo hello && uname -a""#),
        vec!["-c", "echo hello && uname -a"]
    );
}

#[test]
fn split_args_single_quotes() {
    assert_eq!(
        split_shell_args("-c 'echo hello world'"),
        vec!["-c", "echo hello world"]
    );
}

#[test]
fn split_args_empty() {
    assert!(split_shell_args("").is_empty());
    assert!(split_shell_args("   ").is_empty());
}

#[test]
fn split_args_mixed_quotes() {
    assert_eq!(
        split_shell_args(r#"-e "console.log('hi')""#),
        vec!["-e", "console.log('hi')"]
    );
}

// ── resolve_image ───────────────────────────────────────────────

fn make_docker_metadata(image: &str) -> ActionMetadata {
    ActionMetadata {
        name: None,
        inputs: HashMap::new(),
        runs: ActionRuns {
            using: ActionRuntime::Docker,
            main: None,
            pre: None,
            post: None,
            pre_if: None,
            post_if: None,
            steps: None,
            image: Some(image.into()),
            entrypoint: None,
            args: None,
            pre_entrypoint: None,
            post_entrypoint: None,
            env: None,
        },
    }
}

#[test]
fn metadata_image_classifies_dockerfile_and_prebuilt_references() {
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("Dockerfile")).unwrap(),
        MetadataImage::Dockerfile("Dockerfile")
    ));
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("docker/build/Dockerfile")).unwrap(),
        MetadataImage::Dockerfile("docker/build/Dockerfile")
    ));
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("docker://alpine:3.19")).unwrap(),
        MetadataImage::Prebuilt("alpine:3.19")
    ));
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("docker://example/Dockerfile")).unwrap(),
        MetadataImage::Prebuilt("example/Dockerfile")
    ));
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("ghcr.io/owner/image:v1")).unwrap(),
        MetadataImage::Prebuilt("ghcr.io/owner/image:v1")
    ));
}

// ── trace_docker_metadata_action ────────────────────────────────

const TRACE_ARG_VALUE_SENTINEL: &str = "sentinel-arg-value-never-trace";

/// Resolve args the way the real caller does, so the sentinel value is
/// genuinely part of the resolved arguments a caller holds at trace time.
fn sentinel_resolved_args() -> Vec<String> {
    let (_temp, workspace) = action_workspace();
    let state = action_job_state();
    let step = docker_action_step(Some(HashMap::from([(
        "SENTINEL_ARG".to_string(),
        TRACE_ARG_VALUE_SENTINEL.to_string(),
    )])));
    let raw_args = vec!["${{ env.SENTINEL_ARG }}".to_string()];
    let base_env = HashMap::new();

    let (_env, resolved_args) = build_metadata_action_env(
        &make_docker_metadata("alpine:3.19"),
        "main",
        &raw_args,
        &step,
        &state,
        &workspace,
        &base_env,
    )
    .unwrap();

    assert_eq!(
        resolved_args,
        vec![TRACE_ARG_VALUE_SENTINEL.to_string()],
        "arrange must produce the sentinel in the resolved args"
    );
    resolved_args
}

fn capture_docker_metadata_trace(
    selected_image: &SelectedDockerImage,
    entrypoint: &Option<String>,
    resolved_arg_count: usize,
) -> String {
    let captured_output = Arc::new(Mutex::new(Vec::new()));
    let writer_output = Arc::clone(&captured_output);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .without_time()
        .with_ansi(false)
        .with_target(false)
        .with_writer(move || TraceWriter(Arc::clone(&writer_output)))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        trace_docker_metadata_action(selected_image, entrypoint.is_some(), resolved_arg_count);
    });
    String::from_utf8(captured_output.lock().unwrap().clone()).unwrap()
}

fn capture_inline_docker_trace(plan: &InlineActionPlan) -> String {
    let captured_output = Arc::new(Mutex::new(Vec::new()));
    let writer_output = Arc::clone(&captured_output);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .without_time()
        .with_ansi(false)
        .with_target(false)
        .with_writer(move || TraceWriter(Arc::clone(&writer_output)))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        trace_inline_docker_action(plan);
    });
    String::from_utf8(captured_output.lock().unwrap().clone()).unwrap()
}

#[test]
fn inline_trace_omits_resolved_entrypoint_and_arguments() {
    let plan = InlineActionPlan {
        env: HashMap::new(),
        entrypoint: Some("CANARY-INLINE-ENTRYPOINT".into()),
        args: vec!["CANARY-INLINE-ARG".into()],
    };

    let captured = capture_inline_docker_trace(&plan);

    assert!(!captured.contains("CANARY-INLINE"), "{captured}");
    assert!(captured.contains("has_entrypoint=true"), "{captured}");
    assert!(captured.contains("resolved_arg_count=1"), "{captured}");
}

#[test]
fn built_image_trace_omits_arg_values_and_local_id() {
    const SENTINEL_IMAGE_ID: &str = "sha256:sentinel-built-image-id";
    let resolved_args = sentinel_resolved_args();
    let selected_image = SelectedDockerImage::Built(SENTINEL_IMAGE_ID.to_string());
    let entrypoint: Option<String> = None;

    let captured = capture_docker_metadata_trace(&selected_image, &entrypoint, resolved_args.len());

    assert!(!captured.contains(SENTINEL_IMAGE_ID), "{captured}");
    assert!(!captured.contains(TRACE_ARG_VALUE_SENTINEL), "{captured}");
    assert!(captured.contains("image_source=\"built\""), "{captured}");
    assert!(
        captured.contains("resolved_arg_count=1"),
        "resolved argument count must be traced: {captured}"
    );
}

#[test]
fn prebuilt_image_trace_omits_arg_values_and_reference() {
    const IMAGE_REFERENCE: &str = "ghcr.io/owner/safe-action:v1";
    let resolved_args = sentinel_resolved_args();
    let selected_image = SelectedDockerImage::Prebuilt(IMAGE_REFERENCE.to_string());
    let entrypoint: Option<String> = None;

    let captured = capture_docker_metadata_trace(&selected_image, &entrypoint, resolved_args.len());

    assert!(!captured.contains(TRACE_ARG_VALUE_SENTINEL), "{captured}");
    assert!(!captured.contains(IMAGE_REFERENCE), "{captured}");
    assert!(captured.contains("image_source=\"prebuilt\""), "{captured}");
    assert!(
        captured.contains("resolved_arg_count=1"),
        "resolved argument count must be traced: {captured}"
    );
}

// ── run_docker_metadata_action ──────────────────────────────────

fn test_docker_config(tmp: &tempfile::TempDir) -> crate::job::execution_domain::ExecutionDomain {
    let root = ExecutionDomainRoot::prepare(
        &tmp.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    futures::executor::block_on(async {
        root.reserve()
            .await?
            .provision(crate::job::execution_domain::AttemptIdentity::new())
            .await
    })
    .unwrap()
}

#[tokio::test]
async fn docker_action_rekeys_saved_state_before_returning_command_error() {
    let (temp, workspace) = action_workspace();
    let domain = test_docker_config(&temp);
    domain.bind_workspace(&workspace).await.unwrap();
    let state_id = domain.prepare_step(b"{}").await.unwrap();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(8);
    let processor = OutputProcessor::new(
        LogSender::new_for_test(log_tx, Arc::clone(&masks)),
        masks,
        false,
    );
    processor
        .process_line("::save-state name=cleanup::ready")
        .await;
    let mut state = action_job_state();
    let step = docker_action_step(None);
    let command_result: Result<StepResult> = Err(anyhow::anyhow!("command canary"));

    let error = complete_docker_action_transaction(
        &domain,
        state_id,
        &processor,
        &mut state,
        &step,
        command_result,
    )
    .await
    .unwrap_err();

    assert!(format!("{error:#}").contains("command canary"));
    assert!(!state.action_states.contains_key(""));
    assert_eq!(
        state
            .action_states
            .get("step")
            .and_then(|values| values.get("cleanup"))
            .map(String::as_str),
        Some("ready")
    );
}

#[tokio::test]
#[ignore]
async fn docker_action_transactions_apply_each_workflow_command_once() {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let (temp, workspace) = action_workspace();
    let action_root = temp.path().join("action");
    std::fs::create_dir(&action_root).unwrap();
    let action_dir = TrustedActionDirectory::resolve(&action_root, Path::new(".")).unwrap();
    let domain = test_docker_config(&temp);
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let log_sender = LogSender::new_for_test(tokio::sync::mpsc::channel(32).0, masks);
    let mut state = action_job_state();
    let step = docker_action_step(None);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);
    let mut metadata = make_metadata_with_entrypoints(
        Some("/bin/sh"),
        None,
        None,
        Some(vec![
            "-c".into(),
            "printf '%s\\n' '::add-path::/stdout/docker-action'; printf '/file/docker-action\\n' > \"$GITHUB_PATH\"".into(),
        ]),
    );
    metadata.runs.image = Some("docker://alpine:3.19".into());

    run_docker_metadata_action(
        &action_dir,
        &metadata,
        "main",
        &step,
        &mut state,
        &workspace,
        &HashMap::new(),
        &log_sender,
        &DockerActionBuilder::new(),
        &DockerBuildScope::new("test-runner", "test/exactly-once"),
        None,
        Instant::now() + Duration::from_secs(30),
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();

    metadata.runs.args = Some(vec!["-c".into(), "true".into()]);
    run_docker_metadata_action(
        &action_dir,
        &metadata,
        "main",
        &step,
        &mut state,
        &workspace,
        &HashMap::new(),
        &log_sender,
        &DockerActionBuilder::new(),
        &DockerBuildScope::new("test-runner", "test/exactly-once"),
        None,
        Instant::now() + Duration::from_secs(30),
        &CancellationToken::new(),
        &execution,
    )
    .await
    .unwrap();

    assert_eq!(
        state.path_prepends,
        ["/stdout/docker-action", "/file/docker-action"]
    );
}

const DOCKER_ACTION_ENDPOINT_CHILD_CASE: &str = "CHIMERA_DOCKER_ACTION_ENDPOINT_CHILD_CASE";

async fn run_docker_action_endpoint_child(test_name: &str, endpoint: &DockerEndpoint) {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .kill_on_drop(true)
            .args(["--exact", test_name, "--nocapture"])
            .env(DOCKER_ACTION_ENDPOINT_CHILD_CASE, "run")
            .env("DOCKER_HOST", endpoint.socket_address())
            .output(),
    )
    .await
    .expect("Docker action endpoint child must remain bounded")
    .unwrap();

    assert!(
        output.status.success(),
        "Docker action endpoint child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn isolate_action_from_current_docker_host() {
    // The exact-test child runs this test alone. Changing its environment after
    // domain provisioning proves action routing uses the retained domain endpoint.
    unsafe { std::env::set_var("DOCKER_HOST", "unix:///absent/action-fallback.sock") };
}

fn action_endpoint_fixture() -> (
    tempfile::TempDir,
    Workspace,
    JobState,
    LogSender,
    crate::job::execution_domain::ExecutionDomain,
    crate::node::NodeRuntimes,
) {
    let (workspace_temp, workspace) = action_workspace();
    let state = action_job_state();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(32);
    let log_sender = LogSender::new_for_test(log_tx, masks);
    let domain = test_docker_config(&workspace_temp);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    (
        workspace_temp,
        workspace,
        state,
        log_sender,
        domain,
        node_runtimes,
    )
}

#[tokio::test]
async fn docker_action_inline_routes_image_operation_to_domain_endpoint() {
    if std::env::var_os(DOCKER_ACTION_ENDPOINT_CHILD_CASE).is_some() {
        let (_temp, workspace, mut state, log_sender, domain, node_runtimes) =
            action_endpoint_fixture();
        isolate_action_from_current_docker_host();
        let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

        let error = run_docker_image_action(
            "fixture-image",
            &docker_action_step(None),
            &mut state,
            &workspace,
            &HashMap::new(),
            &log_sender,
            Instant::now() + Duration::from_secs(2),
            &CancellationToken::new(),
            &execution,
        )
        .await
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("synthetic endpoint probe failure"),
            "unexpected inline Docker action error: {error:#}"
        );
        return;
    }

    let probe = EngineProbe::start_failing_images().await.unwrap();
    run_docker_action_endpoint_child(
        "job::action::docker::docker_test::docker_action_inline_routes_image_operation_to_domain_endpoint",
        probe.endpoint(),
    )
    .await;
    assert!(
        probe
            .requests()
            .iter()
            .any(|request| request.contains("/images/fixture-image/"))
    );
}

#[tokio::test]
async fn docker_action_metadata_routes_image_operation_to_domain_endpoint() {
    if std::env::var_os(DOCKER_ACTION_ENDPOINT_CHILD_CASE).is_some() {
        let (temp, workspace, mut state, log_sender, domain, node_runtimes) =
            action_endpoint_fixture();
        isolate_action_from_current_docker_host();
        let action_root = temp.path().join("action");
        std::fs::create_dir(&action_root).unwrap();
        let action_dir = TrustedActionDirectory::resolve(&action_root, Path::new(".")).unwrap();
        let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

        let error = run_docker_metadata_action(
            &action_dir,
            &make_docker_metadata("fixture-image"),
            "main",
            &docker_action_step(None),
            &mut state,
            &workspace,
            &HashMap::new(),
            &log_sender,
            &DockerActionBuilder::new(),
            &DockerBuildScope::new("test-runner", "test/endpoint-routing"),
            None,
            Instant::now() + Duration::from_secs(2),
            &CancellationToken::new(),
            &execution,
        )
        .await
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("synthetic endpoint probe failure"),
            "unexpected metadata Docker action error: {error:#}"
        );
        return;
    }

    let probe = EngineProbe::start_failing_images().await.unwrap();
    run_docker_action_endpoint_child(
        "job::action::docker::docker_test::docker_action_metadata_routes_image_operation_to_domain_endpoint",
        probe.endpoint(),
    )
    .await;
    assert!(
        probe
            .requests()
            .iter()
            .any(|request| request.contains("/images/fixture-image/"))
    );
}

#[tokio::test]
#[ignore]
async fn docker_action_replaced_state_discards_buffered_log_commands() {
    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let (temp, workspace) = action_workspace();
    let action_root = temp.path().join("action");
    std::fs::create_dir(&action_root).unwrap();
    let action_dir = TrustedActionDirectory::resolve(&action_root, Path::new(".")).unwrap();
    let mut metadata = make_metadata_with_entrypoints(
        Some("/bin/sh"),
        None,
        None,
        Some(vec![
            "-c".into(),
            "printf '%s\\n' '::set-env name=STDOUT_ENV::leak' '::set-output name=stdout_output::leak'; printf 'FILE_ENV=leak\\n' > \"$GITHUB_ENV\"; rm \"$GITHUB_OUTPUT\"; printf 'file_output=leak\\n' > \"$GITHUB_OUTPUT\"".into(),
        ]),
    );
    metadata.runs.image = Some("docker://alpine:3.19".into());
    let mut state = action_job_state();
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(32);
    let log_sender = LogSender::new_for_test(log_tx, masks);
    let domain = test_docker_config(&temp);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    let execution = JobExecutionContext::new(&domain, None, &node_runtimes);

    let error = run_docker_metadata_action(
        &action_dir,
        &metadata,
        "main",
        &docker_action_step(None),
        &mut state,
        &workspace,
        &HashMap::new(),
        &log_sender,
        &DockerActionBuilder::new(),
        &DockerBuildScope::new("test-runner", "test/atomic-state"),
        None,
        Instant::now() + Duration::from_secs(30),
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
async fn build_timeout_log_send_never_blocks_on_a_full_log_channel() {
    let action = tempfile::tempdir().unwrap();
    std::fs::write(
        action.path().join("action.yml"),
        "name: dockerfile-action\nruns:\n  using: docker\n  image: Dockerfile\n",
    )
    .unwrap();
    std::fs::write(action.path().join("Dockerfile"), "FROM alpine:3.19\n").unwrap();
    let action_dir = TrustedActionDirectory::resolve(action.path(), Path::new(".")).unwrap();
    let (_work_temp, workspace) = action_workspace();
    let mut job_state = action_job_state();
    let step = docker_action_step(None);
    let metadata = make_docker_metadata("Dockerfile");

    // A capacity-1 channel already holding one line has no room for the
    // timeout notice, and nothing drains it for the lifetime of the test.
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(1);
    let log_sender = LogSender::new_for_test(log_tx, Arc::clone(&masks));
    log_sender.send("filler line".into()).await;

    let docker_action_builder = DockerActionBuilder::new();
    let docker_build_scope = DockerBuildScope::new("test-runner", "test/timeout-notice");
    let base_env = HashMap::new();
    let resources = tempfile::tempdir().unwrap();
    let domain = test_docker_config(&resources);
    let node_runtimes = crate::node::NodeRuntimes::single("node".into());
    // An HTTP-transport client never dials until a request is made, so the
    // expired-deadline short-circuit is under test, not daemon reachability.
    let docker = Docker::connect_with_http("127.0.0.1:9", 120, bollard::API_DEFAULT_VERSION)
        .expect("lazy HTTP docker client must construct without a daemon");
    let docker_resources = JobDockerResources::new(docker);
    let execution = JobExecutionContext::new(&domain, Some(&docker_resources), &node_runtimes);
    let deadline = Instant::now() - Duration::from_secs(1);
    let cancel_token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        run_docker_metadata_action(
            &action_dir,
            &metadata,
            "main",
            &step,
            &mut job_state,
            &workspace,
            &base_env,
            &log_sender,
            &docker_action_builder,
            &docker_build_scope,
            None,
            deadline,
            &cancel_token,
            &execution,
        ),
    )
    .await
    .expect("timeout notice must not wait for log channel capacity")
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Failed);
}

#[test]
fn resolve_image_missing_field() {
    let m = ActionMetadata {
        name: None,
        inputs: HashMap::new(),
        runs: ActionRuns {
            using: ActionRuntime::Docker,
            main: None,
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
    };
    assert!(resolve_metadata_image(&m).is_err());
}

// ── resolve_entry_point ─────────────────────────────────────────

fn make_metadata_with_entrypoints(
    entrypoint: Option<&str>,
    pre: Option<&str>,
    post: Option<&str>,
    args: Option<Vec<String>>,
) -> ActionMetadata {
    ActionMetadata {
        name: None,
        inputs: HashMap::new(),
        runs: ActionRuns {
            using: ActionRuntime::Docker,
            main: None,
            pre: None,
            post: None,
            pre_if: None,
            post_if: None,
            steps: None,
            image: Some("alpine".into()),
            entrypoint: entrypoint.map(|s| s.into()),
            args,
            pre_entrypoint: pre.map(|s| s.into()),
            post_entrypoint: post.map(|s| s.into()),
            env: None,
        },
    }
}

#[test]
fn entry_point_main_with_entrypoint_and_args() {
    let m = make_metadata_with_entrypoints(
        Some("/entrypoint.sh"),
        None,
        None,
        Some(vec!["--flag".into()]),
    );
    let (ep, args) = resolve_entry_point(&m, "main").unwrap();
    assert_eq!(ep.as_deref(), Some("/entrypoint.sh"));
    assert_eq!(args, vec!["--flag"]);
}

#[test]
fn entry_point_main_no_entrypoint() {
    let m = make_metadata_with_entrypoints(None, None, None, None);
    let (ep, args) = resolve_entry_point(&m, "main").unwrap();
    assert!(ep.is_none());
    assert!(args.is_empty());
}

#[test]
fn entry_point_pre_present() {
    let m = make_metadata_with_entrypoints(None, Some("/pre.sh"), None, None);
    let (ep, args) = resolve_entry_point(&m, "pre").unwrap();
    assert_eq!(ep.as_deref(), Some("/pre.sh"));
    assert!(args.is_empty());
}

#[test]
fn entry_point_pre_absent_returns_none() {
    let m = make_metadata_with_entrypoints(None, None, None, None);
    assert!(resolve_entry_point(&m, "pre").is_none());
}

#[test]
fn entry_point_post_present() {
    let m = make_metadata_with_entrypoints(None, None, Some("/post.sh"), None);
    let (ep, args) = resolve_entry_point(&m, "post").unwrap();
    assert_eq!(ep.as_deref(), Some("/post.sh"));
    assert!(args.is_empty());
}

#[test]
fn entry_point_post_absent_returns_none() {
    let m = make_metadata_with_entrypoints(None, None, None, None);
    assert!(resolve_entry_point(&m, "post").is_none());
}

// ── build_container_env ─────────────────────────────────────────

#[test]
fn container_env_remaps_github_paths() {
    let mut host = HashMap::new();
    host.insert("GITHUB_WORKSPACE".into(), "/home/runner/work".into());
    host.insert("CUSTOM_VAR".into(), "kept".into());
    host.insert(DOCKER_CONFIG_ENV.into(), "/private/job/docker".into());

    let env = build_container_env(&host);

    assert_eq!(env["GITHUB_WORKSPACE"], "/github/workspace");
    assert_eq!(env["GITHUB_ENV"], "/github/workflow/_env");
    assert_eq!(env["GITHUB_OUTPUT"], "/github/workflow/_output");
    assert_eq!(env["GITHUB_STATE"], "/github/workflow/_state");
    assert_eq!(env["RUNNER_TEMP"], "/github/tmp");
    assert_eq!(env["RUNNER_TOOL_CACHE"], "/github/tool-cache");
    assert_eq!(env["CUSTOM_VAR"], "kept");
    assert!(!env.contains_key(DOCKER_CONFIG_ENV));
}

// ── docker action env boundary ──────────────────────────────────

const HOST_DOCKER_CONFIG_PATH: &str = "/var/lib/chimera/job-resources/attempt/docker";

fn action_workspace() -> (tempfile::TempDir, Workspace) {
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

fn action_job_state() -> JobState {
    JobState::new(
        crate::job::secret_masker::shared_masker_for_test(&[]),
        HashMap::new(),
        serde_json::json!({}),
    )
}

fn docker_action_step(environment: Option<HashMap<String, String>>) -> Step {
    Step {
        id: "step".into(),
        display_name: "Run docker action".into(),
        reference: StepReference {
            name: "uses".into(),
            kind: StepReferenceKind::ContainerRegistry,
            ..Default::default()
        },
        inputs: HashMap::new(),
        condition: None,
        timeout_in_minutes: None,
        continue_on_error: false,
        order: 1,
        environment,
        context_name: None,
    }
}

fn docker_host_base_env() -> HashMap<String, String> {
    HashMap::from([
        (
            DOCKER_CONFIG_ENV.to_string(),
            HOST_DOCKER_CONFIG_PATH.to_string(),
        ),
        (
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        ),
    ])
}

#[test]
fn docker_action_step_env_cannot_alias_docker_config() {
    let (_temp, workspace) = action_workspace();
    let state = action_job_state();
    let step = docker_action_step(Some(HashMap::from([(
        "LEAK".to_string(),
        "${{ env.DOCKER_CONFIG }}".to_string(),
    )])));

    let env = build_docker_action_env(&step, &state, &workspace, &docker_host_base_env()).unwrap();

    assert!(!env.contains_key(DOCKER_CONFIG_ENV));
    assert_eq!(env.get("LEAK").map(String::as_str), Some(""));
}

#[test]
fn docker_action_metadata_expressions_cannot_alias_docker_config() {
    let (_temp, workspace) = action_workspace();
    let state = action_job_state();
    let step = docker_action_step(None);
    let mut metadata = make_docker_metadata("alpine:3");
    metadata.inputs.insert(
        "config_path".into(),
        ActionInput {
            default: Some("${{ env.DOCKER_CONFIG }}".into()),
        },
    );
    metadata.runs.env = Some(HashMap::from([(
        "LEAK".to_string(),
        "${{ env.DOCKER_CONFIG }}".to_string(),
    )]));
    let raw_args = vec![
        "--verbose".to_string(),
        "${{ env.DOCKER_CONFIG }}".to_string(),
    ];

    let (env, resolved_args) = build_metadata_action_env(
        &metadata,
        "main",
        &raw_args,
        &step,
        &state,
        &workspace,
        &docker_host_base_env(),
    )
    .unwrap();

    assert!(!env.contains_key(DOCKER_CONFIG_ENV));
    assert_eq!(env.get("INPUT_CONFIG_PATH").map(String::as_str), Some(""));
    assert_eq!(env.get("LEAK").map(String::as_str), Some(""));
    assert_eq!(resolved_args, vec!["--verbose".to_string(), String::new()]);
}

#[test]
fn docker_action_inline_args_cannot_alias_docker_config() {
    let (_temp, workspace) = action_workspace();
    let state = action_job_state();
    let mut step = docker_action_step(Some(HashMap::from([(
        "LEAK".to_string(),
        "${{ env.DOCKER_CONFIG }}".to_string(),
    )])));
    step.inputs
        .insert("args".to_string(), "${{ env.DOCKER_CONFIG }}".to_string());

    let plan = build_inline_action_env(&step, &state, &workspace, &docker_host_base_env()).unwrap();

    assert!(!plan.env.contains_key(DOCKER_CONFIG_ENV));
    assert_eq!(plan.env.get("LEAK").map(String::as_str), Some(""));
    assert!(plan.args.is_empty());
}

#[test]
fn docker_action_env_drops_job_env_docker_config() {
    let (_temp, workspace) = action_workspace();
    let mut state = action_job_state();
    state
        .env
        .insert(DOCKER_CONFIG_ENV.into(), HOST_DOCKER_CONFIG_PATH.into());
    let step = docker_action_step(None);
    let mut base = docker_host_base_env();
    base.remove(DOCKER_CONFIG_ENV);

    let env = build_docker_action_env(&step, &state, &workspace, &base).unwrap();

    assert!(!env.contains_key(DOCKER_CONFIG_ENV));
}

#[test]
fn docker_action_env_drops_github_env_docker_config() {
    let (_temp, workspace) = action_workspace();
    std::fs::write(
        workspace.env_file(),
        format!("{DOCKER_CONFIG_ENV}={HOST_DOCKER_CONFIG_PATH}\n"),
    )
    .unwrap();
    let state = action_job_state();
    let step = docker_action_step(None);
    let mut base = docker_host_base_env();
    base.remove(DOCKER_CONFIG_ENV);

    let env = build_docker_action_env(&step, &state, &workspace, &base).unwrap();

    assert!(!env.contains_key(DOCKER_CONFIG_ENV));
}

#[test]
fn docker_action_binds_never_mount_the_action_directory() {
    let (_temp, workspace) = action_workspace();

    let binds = build_bind_mounts(&workspace).unwrap();

    // The action directory reaches the container only through the
    // descriptor-pinned build context; no runtime bind may expose it (a
    // pathname bind would reopen the root-swap TOCTOU window, and runc
    // engines reject /proc/<pid>/fd bind sources cross-process).
    assert_eq!(binds.len(), 3);
    assert!(
        binds
            .iter()
            .any(|bind| bind.ends_with(":/github/workspace"))
    );
    assert!(binds.iter().any(|bind| bind.ends_with(":/github/workflow")));
    assert!(binds.iter().any(|bind| bind.ends_with(":/github/tmp")));
    assert!(!binds.iter().any(|bind| bind.contains("/github/action")));
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn engine_action_contents_come_from_pinned_context_after_root_replacement() {
    use crate::job::action::{ActionCache, ActionSource};

    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let source_root = tmp.path().join("source");
    let action_dir = source_root.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("sentinel"), "original").unwrap();
    std::fs::write(
        action_dir.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY sentinel /baked/sentinel\n",
    )
    .unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &source_root, "fake-token")
        .await
        .unwrap();
    let workspace = Workspace::create(
        &tmp.path().join("work"),
        &tmp.path().join("runner-temp"),
        &tmp.path().join("tool-cache"),
        "runner",
        "owner/repo",
    )
    .unwrap();

    // Swap the pathname out from under the resolved capability before the
    // build: the context must still be prepared from the pinned descriptors.
    std::fs::rename(&source_root, tmp.path().join("original-source")).unwrap();
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("sentinel"), "replacement-canary").unwrap();
    std::fs::write(
        action_dir.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY sentinel /baked/sentinel\n",
    )
    .unwrap();

    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(32);
    let log_sender = LogSender::new_for_test(log_tx, Arc::clone(&masks));
    let job_state = JobState::new(masks, HashMap::new(), serde_json::json!({}));

    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new(
        "test-runner",
        format!("test/context-swap-{}", uuid::Uuid::new_v4()),
    );
    let outcome = builder
        .build(DockerBuildRequest {
            docker: &docker,
            action_dir: &trusted,
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &log_sender,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(120),
            reuse: None,
        })
        .await
        .unwrap();
    let DockerBuildOutcome::Ready(built) = outcome else {
        panic!("expected the pinned-context build to succeed");
    };

    // The run path mounts no action directory; the container must observe
    // only what the pinned context baked into the image.
    let env = HashMap::new();
    let args = vec![
        "-c".to_string(),
        "test \"$(cat /baked/sentinel)\" = original".to_string(),
    ];
    let processor = OutputProcessor::new(
        log_sender.clone(),
        job_state.secret_masker.clone(),
        job_state.debug_enabled,
    );
    let result = run_docker_container(RunDockerParams {
        docker: &docker,
        image: &built.image_id,
        pull_if_missing: false,
        deadline: Instant::now() + Duration::from_secs(30),
        entrypoint: Some("/bin/sh"),
        args: &args,
        env: &env,
        processor: &processor,
        workspace: &workspace,
        cancel_token: &CancellationToken::new(),
        docker_resources: None,
    })
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn engine_action_contents_come_from_pinned_context_after_symlink_root_replacement() {
    use std::os::unix::fs::symlink;

    use crate::job::action::{ActionCache, ActionSource};

    let docker =
        crate::docker::client::connect(&crate::docker::endpoint::DockerEndpoint::trusted_host())
            .unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let source_root = tmp.path().join("source");
    let action_dir = source_root.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(action_dir.join("sentinel"), "original").unwrap();
    std::fs::write(
        action_dir.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY sentinel /baked/sentinel\n",
    )
    .unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &source_root, "fake-token")
        .await
        .unwrap();
    let workspace = Workspace::create(
        &tmp.path().join("work"),
        &tmp.path().join("runner-temp"),
        &tmp.path().join("tool-cache"),
        "runner",
        "owner/repo",
    )
    .unwrap();

    std::fs::rename(&source_root, tmp.path().join("original-source")).unwrap();
    let replacement = tmp.path().join("replacement-source");
    let replacement_action = replacement.join("actions/test");
    std::fs::create_dir_all(&replacement_action).unwrap();
    std::fs::write(replacement_action.join("sentinel"), "replacement-canary").unwrap();
    std::fs::write(
        replacement_action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY sentinel /baked/sentinel\n",
    )
    .unwrap();
    symlink(&replacement, &source_root).unwrap();

    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (log_tx, _log_rx) = tokio::sync::mpsc::channel(32);
    let log_sender = LogSender::new_for_test(log_tx, Arc::clone(&masks));
    let job_state = JobState::new(masks, HashMap::new(), serde_json::json!({}));

    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new(
        "test-runner",
        format!("test/context-symlink-swap-{}", uuid::Uuid::new_v4()),
    );
    let outcome = builder
        .build(DockerBuildRequest {
            docker: &docker,
            action_dir: &trusted,
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &log_sender,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(120),
            reuse: None,
        })
        .await
        .unwrap();
    let DockerBuildOutcome::Ready(built) = outcome else {
        panic!("expected the pinned-context build to succeed");
    };

    let env = HashMap::new();
    let args = vec![
        "-c".to_string(),
        "test \"$(cat /baked/sentinel)\" = original".to_string(),
    ];
    let processor = OutputProcessor::new(
        log_sender.clone(),
        job_state.secret_masker.clone(),
        job_state.debug_enabled,
    );
    let result = run_docker_container(RunDockerParams {
        docker: &docker,
        image: &built.image_id,
        pull_if_missing: false,
        deadline: Instant::now() + Duration::from_secs(30),
        entrypoint: Some("/bin/sh"),
        args: &args,
        env: &env,
        processor: &processor,
        workspace: &workspace,
        cancel_token: &CancellationToken::new(),
        docker_resources: None,
    })
    .await
    .unwrap();

    assert_eq!(result.conclusion, StepConclusion::Succeeded);
}
