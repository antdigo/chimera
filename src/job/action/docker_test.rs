use std::collections::HashMap;

use super::*;
use crate::job::action::metadata::{ActionInput, ActionRuns, ActionRuntime};
use crate::job::docker_config::DOCKER_CONFIG_ENV;
use crate::job::schema::{StepReference, StepReferenceKind};

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
fn resolve_image_strips_docker_prefix() {
    let m = make_docker_metadata("docker://node:18");
    assert_eq!(resolve_image(&m).unwrap(), "node:18");

    let m = make_docker_metadata("docker://alpine:latest");
    assert_eq!(resolve_image(&m).unwrap(), "alpine:latest");
}

#[test]
fn resolve_image_no_prefix() {
    let m = make_docker_metadata("node:18");
    assert_eq!(resolve_image(&m).unwrap(), "node:18");

    let m = make_docker_metadata("alpine");
    assert_eq!(resolve_image(&m).unwrap(), "alpine");
}

#[test]
fn resolve_image_dockerfile_error() {
    let m = make_docker_metadata("Dockerfile");
    let err = resolve_image(&m).unwrap_err();
    assert!(err.to_string().contains("Dockerfile"));
    assert!(err.to_string().contains("not supported"));
}

#[test]
fn resolve_image_path_dockerfile_error() {
    let m = make_docker_metadata("path/to/Dockerfile");
    let err = resolve_image(&m).unwrap_err();
    assert!(err.to_string().contains("not supported"));
}

#[test]
fn resolve_image_registry_with_prefix() {
    let m = make_docker_metadata("docker://ghcr.io/owner/image:v1");
    assert_eq!(resolve_image(&m).unwrap(), "ghcr.io/owner/image:v1");
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
    assert!(resolve_image(&m).is_err());
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
        std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
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
