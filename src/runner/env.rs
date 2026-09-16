use std::collections::HashMap;

use anyhow::Result;

use crate::job::docker_config::{DOCKER_CONFIG_ENV, JobDockerConfig};
use crate::job::schema::JobManifest;
use crate::job::workspace::Workspace;
use crate::utils::{arch_label, os_label};

/// Build the base environment variables for host-mode step execution.
pub fn build_base_env(
    manifest: &JobManifest,
    workspace: &Workspace,
    runner_name: &str,
    docker_config: &JobDockerConfig,
) -> Result<HashMap<String, String>> {
    for (key, variable) in &manifest.variables {
        let env_key = key.replace('.', "_").to_uppercase();
        if env_key == DOCKER_CONFIG_ENV {
            docker_config.validate_override(&variable.value, "job environment")?;
        }
    }

    let mut env = build_common_env(manifest, workspace, runner_name);
    docker_config.insert_into_host_env(&mut env, "job environment")?;
    Ok(env)
}

/// Build environment variables for container-mode execution.
pub fn build_container_env(
    manifest: &JobManifest,
    workspace: &Workspace,
    runner_name: &str,
) -> HashMap<String, String> {
    let mut env = build_common_env(manifest, workspace, runner_name);
    env.remove(DOCKER_CONFIG_ENV);
    env.insert("RUNNER_OS".into(), "Linux".into());
    env.insert("ImageOS".into(), "ubuntu22".into());
    env.insert("GITHUB_WORKSPACE".into(), "/github/workspace".into());
    env.insert("GITHUB_ENV".into(), "/github/workflow/_env".into());
    env.insert("GITHUB_PATH".into(), "/github/workflow/_path".into());
    env.insert("GITHUB_OUTPUT".into(), "/github/workflow/_output".into());
    env.insert("GITHUB_STATE".into(), "/github/workflow/_state".into());
    env.insert(
        "GITHUB_STEP_SUMMARY".into(),
        "/github/workflow/_step_summary".into(),
    );
    env.insert(
        "GITHUB_EVENT_PATH".into(),
        "/github/workflow/_event.json".into(),
    );
    env.insert("RUNNER_TEMP".into(), "/github/tmp".into());
    env.insert("RUNNER_TOOL_CACHE".into(), "/github/tool-cache".into());
    env.insert(
        "PATH".into(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
    );
    env
}

/// Build values shared by host and container step environments.
fn build_common_env(
    manifest: &JobManifest,
    workspace: &Workspace,
    runner_name: &str,
) -> HashMap<String, String> {
    let mut env = HashMap::new();

    env.insert("GITHUB_ACTIONS".into(), "true".into());
    env.insert(
        "GITHUB_WORKSPACE".into(),
        workspace.workspace_dir().to_string_lossy().into_owned(),
    );
    env.insert(
        "GITHUB_ENV".into(),
        workspace.env_file().to_string_lossy().into_owned(),
    );
    env.insert(
        "GITHUB_PATH".into(),
        workspace.path_file().to_string_lossy().into_owned(),
    );
    env.insert(
        "GITHUB_OUTPUT".into(),
        workspace.output_file().to_string_lossy().into_owned(),
    );
    env.insert(
        "GITHUB_STATE".into(),
        workspace.state_file().to_string_lossy().into_owned(),
    );
    env.insert(
        "GITHUB_STEP_SUMMARY".into(),
        workspace.step_summary_file().to_string_lossy().into_owned(),
    );
    env.insert(
        "GITHUB_EVENT_PATH".into(),
        workspace.event_file().to_string_lossy().into_owned(),
    );
    env.insert("RUNNER_OS".into(), os_label().into());
    env.insert("RUNNER_ARCH".into(), arch_label().into());
    env.insert("RUNNER_NAME".into(), runner_name.into());
    env.insert(
        "RUNNER_TEMP".into(),
        workspace.runner_temp().to_string_lossy().into_owned(),
    );
    env.insert(
        "RUNNER_TOOL_CACHE".into(),
        workspace.tool_cache().to_string_lossy().into_owned(),
    );

    if let Ok(path) = std::env::var("PATH") {
        env.insert("PATH".into(), path);
    }

    if let Some(token) = manifest.github_token() {
        env.insert("GITHUB_TOKEN".into(), token.into());
    }

    if let Some(github) = manifest.context_data.get("github") {
        let mappings = [
            ("workflow", "GITHUB_WORKFLOW"),
            ("run_id", "GITHUB_RUN_ID"),
            ("run_number", "GITHUB_RUN_NUMBER"),
            ("run_attempt", "GITHUB_RUN_ATTEMPT"),
            ("job", "GITHUB_JOB"),
            ("action", "GITHUB_ACTION"),
            ("actor", "GITHUB_ACTOR"),
            ("repository", "GITHUB_REPOSITORY"),
            ("repository_owner", "GITHUB_REPOSITORY_OWNER"),
            ("event_name", "GITHUB_EVENT_NAME"),
            ("sha", "GITHUB_SHA"),
            ("ref", "GITHUB_REF"),
            ("server_url", "GITHUB_SERVER_URL"),
            ("api_url", "GITHUB_API_URL"),
            ("graphql_url", "GITHUB_GRAPHQL_URL"),
        ];

        for (json_key, env_key) in mappings {
            if let Some(value) = github.get(json_key).and_then(|value| value.as_str()) {
                env.insert(env_key.into(), value.into());
            }
        }
    }

    for (key, variable) in &manifest.variables {
        if !variable.is_secret {
            let env_key = key.replace('.', "_").to_uppercase();
            env.insert(env_key, variable.value.clone());
        }
    }

    if let Ok(server_url) = manifest.server_url() {
        env.insert("ACTIONS_RUNTIME_URL".into(), server_url.into());
    }
    if let Ok(token) = manifest.access_token() {
        env.insert("ACTIONS_RUNTIME_TOKEN".into(), token.into());
    }

    env
}

#[cfg(test)]
#[path = "env_test.rs"]
mod env_test;
