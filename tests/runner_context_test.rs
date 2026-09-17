mod common;

use std::collections::HashMap;

use chimera::job::client::JobConclusion;
use common::*;
use tokio_util::sync::CancellationToken;

const ORIGINAL_CONDITION: &str = "always() && contains(runner.labels, 'self-hosted')";

#[tokio::test]
async fn original_runner_labels_condition_runs_after_success_and_failure() {
    let env = TestEnv::setup().await;
    let after_success = env.workspace.runner_temp().join("labels-after-success");
    let after_failure = env.workspace.runner_temp().join("labels-after-failure");
    let manifest = manifest_with_steps(
        vec![
            script_step("success", "true"),
            script_step_if(
                "mark_after_success",
                r#"touch "$RUNNER_TEMP/labels-after-success""#,
                ORIGINAL_CONDITION,
            ),
            script_step("failure", "exit 1"),
            script_step_if(
                "mark_after_failure",
                r#"touch "$RUNNER_TEMP/labels-after-failure""#,
                ORIGINAL_CONDITION,
            ),
        ],
        &env.mock_server.uri(),
    );

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Failed);
    assert!(after_success.is_file());
    assert!(after_failure.is_file());
}

#[tokio::test]
async fn workflow_environment_cannot_spoof_runner_owned_context() {
    let env = TestEnv::setup().await;
    let step_environment = HashMap::from([
        ("RUNNER_LABELS".to_string(), "from-step-env".to_string()),
        (
            "RUNNER_ENVIRONMENT".to_string(),
            "github-hosted".to_string(),
        ),
    ]);
    let verify = r#"
        test "${{ join(runner.labels, ',') }}" = "self-hosted"
        test "${{ runner.environment }}" = "self-hosted"
        test "${{ vars.RUNNER_LABELS }}" = "repo-custom-label"
    "#;
    let write_file_env = format!(
        "{verify}\nprintf '%s\n' 'RUNNER_LABELS=from-github-env' \
         'RUNNER_ENVIRONMENT=github-hosted' >> \"$GITHUB_ENV\""
    );
    let manifest = manifest_with_variables(
        vec![
            script_step_env("step_env", &write_file_env, step_environment),
            script_step("github_env", verify),
        ],
        &env.mock_server.uri(),
        serde_json::json!({
            "vars": { "RUNNER_LABELS": "repo-custom-label" }
        }),
        serde_json::json!({
            "RUNNER_LABELS": { "value": "from-manifest", "isSecret": false },
            "RUNNER_ENVIRONMENT": { "value": "github-hosted", "isSecret": false }
        }),
    );

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn parallel_jobs_keep_runner_context_isolated() {
    let first = TestEnv::setup().await;
    let second = TestEnv::setup().await;
    let first_marker = first.workspace.runner_temp().join("first-job");
    let second_marker = second.workspace.runner_temp().join("second-job");
    let first_manifest = manifest_with_variables(
        vec![script_step_if(
            "first",
            r#"test "${{ vars.RUNNER_LABELS }}" = "first-only"
               touch "$RUNNER_TEMP/first-job""#,
            ORIGINAL_CONDITION,
        )],
        &first.mock_server.uri(),
        serde_json::json!({ "vars": { "RUNNER_LABELS": "first-only" } }),
        serde_json::json!({
            "RUNNER_LABELS": { "value": "first-spoof", "isSecret": false }
        }),
    );
    let second_manifest = manifest_with_variables(
        vec![script_step_if(
            "second",
            r#"test "${{ vars.RUNNER_LABELS }}" = "second-only"
               touch "$RUNNER_TEMP/second-job""#,
            ORIGINAL_CONDITION,
        )],
        &second.mock_server.uri(),
        serde_json::json!({ "vars": { "RUNNER_LABELS": "second-only" } }),
        serde_json::json!({
            "RUNNER_LABELS": { "value": "second-spoof", "isSecret": false }
        }),
    );

    let (first_result, second_result) =
        tokio::join!(first.run(&first_manifest), second.run(&second_manifest),);

    assert_eq!(first_result.unwrap().0, JobConclusion::Succeeded);
    assert_eq!(second_result.unwrap().0, JobConclusion::Succeeded);
    assert!(first_marker.is_file());
    assert!(second_marker.is_file());
}

#[tokio::test]
async fn pre_cancelled_job_reaches_runner_labels_step() {
    let mut env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step_if(
            "cancelled_probe",
            "true",
            ORIGINAL_CONDITION,
        )],
        &env.mock_server.uri(),
    );
    // Timeline PATCHes are only observable once the client carries the job
    // access token from the manifest's endpoint.
    env.configure_from_manifest(&manifest);
    let cancel_token = CancellationToken::new();
    cancel_token.cancel();

    let conclusion = env
        .run_observed(&manifest, cancel_token)
        .await
        .unwrap()
        .conclusion;
    let requests = env.mock_server.received_requests().await.unwrap();
    let probe_started = requests.iter().any(|request| {
        if request.method.as_str() != "PATCH" {
            return false;
        }
        let Ok(body) = serde_json::from_slice::<serde_json::Value>(&request.body) else {
            return false;
        };
        body["value"].as_array().is_some_and(|records| {
            records.iter().any(|record| {
                record["id"] == "cancelled_probe" && record["state"].as_u64() == Some(1)
            })
        })
    });

    assert_eq!(conclusion, JobConclusion::Cancelled);
    assert!(
        probe_started,
        "condition must schedule, not skip, the probe step"
    );
}

fn create_runner_context_composite(workspace: &std::path::Path) {
    let action_dir = workspace.join(".github/actions/runner-context-composite");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        r#"
name: Runner context composite
runs:
  using: composite
  steps:
    - if: always() && contains(runner.labels, 'self-hosted')
      shell: bash
      run: |
        test "${{ runner.environment }}" = "self-hosted"
        touch "$RUNNER_TEMP/runner-context-composite"
"#,
    )
    .unwrap();
}

#[tokio::test]
async fn composite_substeps_share_runner_context() {
    let env = TestEnv::setup().await;
    create_runner_context_composite(env.workspace.workspace_dir());
    let marker = env.workspace.runner_temp().join("runner-context-composite");
    let manifest = manifest_with_steps(
        vec![repository_action_step(
            "composite",
            ".github/actions/runner-context-composite",
        )],
        &env.mock_server.uri(),
    );

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(marker.is_file());
}

fn create_runner_context_post_action(workspace: &std::path::Path) {
    let action_dir = workspace.join(".github/actions/runner-context-post");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        r#"
name: Runner context post
runs:
  using: node20
  main: main.js
  post: post.js
  post-if: always() && contains(runner.labels, 'self-hosted')
"#,
    )
    .unwrap();
    std::fs::write(action_dir.join("main.js"), "console.log('main');\n").unwrap();
    std::fs::write(
        action_dir.join("post.js"),
        r#"
const fs = require('fs');
const path = require('path');
if (process.env.RUNNER_CONTEXT_ENVIRONMENT !== 'self-hosted') {
  process.exit(1);
}
fs.writeFileSync(
  path.join(process.env.RUNNER_TEMP, 'runner-context-post'),
  'post'
);
"#,
    )
    .unwrap();
}

#[tokio::test]
async fn post_action_uses_the_same_runner_context() {
    let env = TestEnv::setup().await;
    create_runner_context_post_action(env.workspace.workspace_dir());
    let marker = env.workspace.runner_temp().join("runner-context-post");
    let mut action = repository_action_step("post_action", ".github/actions/runner-context-post");
    action["environment"] = serde_json::json!({
        "RUNNER_CONTEXT_ENVIRONMENT": "${{ runner.environment }}"
    });
    let manifest = manifest_with_steps(vec![action], &env.mock_server.uri());

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(marker.is_file());
}
