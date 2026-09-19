use super::*;
use crate::job::docker_config::{DOCKER_CONFIG_ENV, JobDockerConfig, JobResourceRoot};
use crate::job::schema::{JobManifest, JobVariable};
use serde_json::json;

fn minimal_manifest() -> JobManifest {
    serde_json::from_value(json!({
        "plan": { "planId": "p", "jobId": "j", "timelineId": "t" },
        "contextData": {
            "github": {
                "repository": "owner/repo",
                "sha": "abc123",
                "ref": "refs/heads/main",
                "server_url": "https://github.com",
                "api_url": "https://api.github.com",
                "actor": "octocat",
                "workflow": "CI",
                "run_id": "12345",
                "run_number": "1",
                "job": "build",
                "event_name": "push"
            }
        },
        "variables": {
            "system.github.token": { "value": "ghs_test123", "isSecret": true },
            "MY_VAR": { "value": "hello" }
        },
        "resources": {
            "endpoints": [{
                "name": "SystemVssConnection",
                "url": "https://pipelines.actions.githubusercontent.com/abc/",
                "authorization": {
                    "parameters": { "AccessToken": "runtime-token" },
                    "scheme": "OAuth"
                }
            }]
        }
    }))
    .unwrap()
}

fn test_workspace() -> (tempfile::TempDir, Workspace) {
    let tmp = tempfile::tempdir().unwrap();
    let ws = Workspace::create(
        tmp.path(),
        &tmp.path().join("tmp"),
        &tmp.path().join("tool_cache"),
        "test-runner",
        "owner/repo",
    )
    .unwrap();
    (tmp, ws)
}

fn test_docker_config() -> (tempfile::TempDir, JobDockerConfig) {
    let temp = tempfile::TempDir::new().unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
    (temp, config)
}

#[test]
fn sets_github_context_vars() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(env.get("GITHUB_REPOSITORY").unwrap(), "owner/repo");
    assert_eq!(env.get("GITHUB_SHA").unwrap(), "abc123");
    assert_eq!(env.get("GITHUB_REF").unwrap(), "refs/heads/main");
    assert_eq!(env.get("GITHUB_SERVER_URL").unwrap(), "https://github.com");
    assert_eq!(env.get("GITHUB_API_URL").unwrap(), "https://api.github.com");
    assert_eq!(env.get("GITHUB_ACTOR").unwrap(), "octocat");
    assert_eq!(env.get("GITHUB_WORKFLOW").unwrap(), "CI");
    assert_eq!(env.get("GITHUB_RUN_ID").unwrap(), "12345");
    assert_eq!(env.get("GITHUB_EVENT_NAME").unwrap(), "push");
}

#[test]
fn sets_github_token() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(env.get("GITHUB_TOKEN").unwrap(), "ghs_test123");
}

#[test]
fn sets_runner_vars() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "my-runner", &config).unwrap();

    assert_eq!(env.get("RUNNER_NAME").unwrap(), "my-runner");
    assert!(env.contains_key("RUNNER_OS"));
    assert!(env.contains_key("RUNNER_ARCH"));
    assert!(env.contains_key("RUNNER_TEMP"));
    assert!(env.contains_key("RUNNER_TOOL_CACHE"));
}

#[test]
fn sets_workspace_paths() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(env.get("GITHUB_ACTIONS").unwrap(), "true");
    assert!(!env.get("GITHUB_WORKSPACE").unwrap().is_empty());
    assert!(env.contains_key("GITHUB_ENV"));
    assert!(env.contains_key("GITHUB_PATH"));
    assert!(env.contains_key("GITHUB_OUTPUT"));
    assert!(env.contains_key("GITHUB_STATE"));
    assert!(env.contains_key("GITHUB_STEP_SUMMARY"));
    assert!(env.contains_key("GITHUB_EVENT_PATH"));
}

#[test]
fn seeds_host_path_from_process() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(env.get("PATH"), std::env::var("PATH").ok().as_ref());
}

#[test]
fn sets_non_secret_variables() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(env.get("MY_VAR").unwrap(), "hello");
    assert!(!env.contains_key("system.github.token"));
}

#[test]
fn sets_actions_runtime() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(
        env.get("ACTIONS_RUNTIME_URL").unwrap(),
        "https://pipelines.actions.githubusercontent.com/abc/"
    );
    assert_eq!(env.get("ACTIONS_RUNTIME_TOKEN").unwrap(), "runtime-token");
}

#[test]
fn sets_actions_results_url_from_endpoint_data() {
    let mut manifest = minimal_manifest();
    manifest.resources.endpoints[0].data.insert(
        "ResultsServiceUrl".into(),
        "https://results-receiver.actions.githubusercontent.com/x/".into(),
    );
    manifest.variables.insert(
        "system.github.results_endpoint".into(),
        JobVariable {
            value: "https://from-variable/".into(),
            is_secret: false,
        },
    );
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(
        env.get("ACTIONS_RESULTS_URL").unwrap(),
        "https://results-receiver.actions.githubusercontent.com/x/"
    );
}

#[test]
fn falls_back_to_results_endpoint_variable() {
    let mut manifest = minimal_manifest();
    manifest.variables.insert(
        "system.github.results_endpoint".into(),
        JobVariable {
            value: "https://results.actions.githubusercontent.com/y/".into(),
            is_secret: false,
        },
    );
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(
        env.get("ACTIONS_RESULTS_URL").unwrap(),
        "https://results.actions.githubusercontent.com/y/"
    );
}

#[test]
fn omits_actions_results_url_when_manifest_has_none() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert!(!env.contains_key("ACTIONS_RESULTS_URL"));
}

#[test]
fn container_env_sets_actions_results_url() {
    let mut manifest = minimal_manifest();
    manifest.variables.insert(
        "system.github.results_endpoint".into(),
        JobVariable {
            value: "https://results.actions.githubusercontent.com/y/".into(),
            is_secret: false,
        },
    );
    let (_tmp, ws) = test_workspace();

    let env = build_container_env(&manifest, &ws, "test-runner");

    assert_eq!(
        env.get("ACTIONS_RESULTS_URL").unwrap(),
        "https://results.actions.githubusercontent.com/y/"
    );
}

#[test]
fn host_env_sets_runner_owned_docker_config() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(env[DOCKER_CONFIG_ENV], config.directory().to_string_lossy());
    drop(resources);
}

#[test]
fn host_env_rejects_manifest_override() {
    let mut manifest = minimal_manifest();
    manifest.variables.insert(
        "DOCKER_CONFIG".into(),
        JobVariable {
            value: "/shared/.docker".into(),
            is_secret: true,
        },
    );
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let error = build_base_env(&manifest, &ws, "test-runner", &config).unwrap_err();

    assert!(error.to_string().contains("reserved-environment-variable"));
}

#[test]
fn container_env_remaps_paths() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();

    let env = build_container_env(&manifest, &ws, "test-runner");

    assert_eq!(env.get("GITHUB_WORKSPACE").unwrap(), "/github/workspace");
    assert_eq!(env.get("GITHUB_ENV").unwrap(), "/github/workflow/_env");
    assert_eq!(env.get("GITHUB_PATH").unwrap(), "/github/workflow/_path");
    assert_eq!(
        env.get("GITHUB_OUTPUT").unwrap(),
        "/github/workflow/_output"
    );
    assert_eq!(env.get("GITHUB_STATE").unwrap(), "/github/workflow/_state");
    assert_eq!(
        env.get("GITHUB_STEP_SUMMARY").unwrap(),
        "/github/workflow/_step_summary"
    );
    assert_eq!(
        env.get("GITHUB_EVENT_PATH").unwrap(),
        "/github/workflow/_event.json"
    );
    assert_eq!(env.get("RUNNER_TEMP").unwrap(), "/github/tmp");
    assert_eq!(env.get("RUNNER_TOOL_CACHE").unwrap(), "/github/tool-cache");
}

#[test]
fn container_env_preserves_non_path_vars() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();

    let env = build_container_env(&manifest, &ws, "test-runner");

    assert_eq!(env.get("GITHUB_ACTIONS").unwrap(), "true");
    assert_eq!(env.get("GITHUB_REPOSITORY").unwrap(), "owner/repo");
    assert_eq!(env.get("GITHUB_TOKEN").unwrap(), "ghs_test123");
    assert_eq!(env.get("RUNNER_OS").unwrap(), "Linux");
    assert!(env.contains_key("RUNNER_ARCH"));
}

#[test]
fn container_env_never_contains_host_docker_config() {
    let mut manifest = minimal_manifest();
    manifest.variables.insert(
        DOCKER_CONFIG_ENV.into(),
        JobVariable {
            value: "/shared/.docker".into(),
            is_secret: false,
        },
    );
    let (_tmp, ws) = test_workspace();

    let env = build_container_env(&manifest, &ws, "test-runner");

    assert!(!env.contains_key(DOCKER_CONFIG_ENV));
}
