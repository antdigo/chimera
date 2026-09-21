mod common;

use std::collections::HashMap;

use chimera::job::client::JobConclusion;
use chimera::job::execution_domain::AttemptIdentity;
use common::*;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn env_vars_are_set() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step(
            "s1",
            r#"
            test "$GITHUB_ACTIONS" = "true" || exit 1
            test -n "$GITHUB_WORKSPACE" || exit 1
            test -n "$GITHUB_ENV" || exit 1
            test -n "$GITHUB_PATH" || exit 1
            test -n "$GITHUB_OUTPUT" || exit 1
            test -n "$GITHUB_STATE" || exit 1
            test -n "$GITHUB_STEP_SUMMARY" || exit 1
            test -n "$GITHUB_EVENT_PATH" || exit 1
            test -n "$RUNNER_OS" || exit 1
            test -n "$RUNNER_NAME" || exit 1
            test -n "$RUNNER_TEMP" || exit 1
            test -n "$RUNNER_TOOL_CACHE" || exit 1
            "#,
        )],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn github_context_env_vars() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps_and_context(
        vec![script_step(
            "s1",
            r#"
            test "$GITHUB_REPOSITORY" = "owner/test-repo" || exit 1
            test "$GITHUB_SHA" = "abc123" || exit 1
            test "$GITHUB_REF" = "refs/heads/main" || exit 1
            test "$GITHUB_WORKFLOW" = "test.yml" || exit 1
            test "$GITHUB_ACTOR" = "testuser" || exit 1
            test "$GITHUB_EVENT_NAME" = "push" || exit 1
            "#,
        )],
        &env.mock_server.uri(),
        serde_json::json!({
            "github": {
                "repository": "owner/test-repo",
                "sha": "abc123",
                "ref": "refs/heads/main",
                "workflow": "test.yml",
                "actor": "testuser",
                "event_name": "push"
            }
        }),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn event_file_exists_and_is_json() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step(
            "s1",
            r#"test -f "$GITHUB_EVENT_PATH" || exit 1"#,
        )],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn env_file_propagation_between_steps() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step("s1", r#"echo "MY_VAR=hello_from_env" >> "$GITHUB_ENV""#),
            script_step("s2", r#"test "$MY_VAR" = "hello_from_env" || exit 1"#),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn env_file_heredoc_multiline() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "s1",
                "echo 'MULTI<<EOF' >> \"$GITHUB_ENV\"\necho 'line1' >> \"$GITHUB_ENV\"\necho 'line2' >> \"$GITHUB_ENV\"\necho 'EOF' >> \"$GITHUB_ENV\"",
            ),
            script_step(
                "s2",
                "echo \"MULTI=$MULTI\"\ntest \"$MULTI\" = \"line1\nline2\" || exit 1",
            ),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn path_file_prepend_between_steps() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step("s1", r#"echo "/custom/test/bin" >> "$GITHUB_PATH""#),
            script_step(
                "s2",
                r#"echo "$PATH" | grep -q "/custom/test/bin" || exit 1"#,
            ),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn path_file_prepend_keeps_host_path() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step("s1", r#"echo "/custom/test/bin" >> "$GITHUB_PATH""#),
            // `command -v` resolves against PATH, so this fails if the addition
            // above replaced the host PATH instead of prepending to it.
            script_step("s2", r#"command -v env >/dev/null || exit 1"#),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn output_file_sets_step_output() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "s1",
                r#"echo "greeting=hello from step" >> "$GITHUB_OUTPUT""#,
            ),
            script_step(
                "s2",
                r#"test "${{ steps.s1.outputs.greeting }}" = "hello from step" || exit 1"#,
            ),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn output_keys_differing_only_in_case_last_write_wins() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "s1",
                "echo 'version=old' >> \"$GITHUB_OUTPUT\"\necho 'VERSION=new' >> \"$GITHUB_OUTPUT\"",
            ),
            script_step(
                "s2",
                r#"
                test "${{ steps.s1.outputs.VERSION }}" = "new" || exit 1
                test "${{ steps.s1.outputs.version }}" = "new" || exit 1
                "#,
            ),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn output_file_heredoc_multiline() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "s1",
                "echo 'result<<EOF' >> \"$GITHUB_OUTPUT\"\necho 'multi' >> \"$GITHUB_OUTPUT\"\necho 'line' >> \"$GITHUB_OUTPUT\"\necho 'EOF' >> \"$GITHUB_OUTPUT\"",
            ),
            script_step(
                "s2",
                r#"test -n "${{ steps.s1.outputs.result }}" || exit 1"#,
            ),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn state_file_captures_state() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step(
            "s1",
            r#"echo "mykey=myval" >> "$GITHUB_STATE""#,
        )],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn step_summary_file_writable() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step(
            "s1",
            "echo '## Test Summary' >> \"$GITHUB_STEP_SUMMARY\" && test -s \"$GITHUB_STEP_SUMMARY\"",
        )],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn step_env_vars_resolved() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "s1",
        r#"test "$GREETING" = "hello world" || exit 1"#,
        HashMap::from([("GREETING".into(), "hello world".into())]),
    );
    let manifest = manifest_with_steps(vec![step], &env.mock_server.uri());
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn only_declared_job_outputs_are_returned_and_step_outputs_stay_in_job() {
    let env = TestEnv::setup().await;
    let produce = script_step_env(
        "collect-secrets",
        r#"
        printf '%s' "$ALL_SECRETS" | jq -e '
          type == "object" and
          .DEPLOY_TOKEN == "synthetic-secret" and
          .EMPTY_SECRET == ""
        ' >/dev/null
        echo "published=release-42" >> "$GITHUB_OUTPUT"
        echo 'app_env<<CHIMERA_OUTPUT' >> "$GITHUB_OUTPUT"
        printf '%s\n' "$ALL_SECRETS" >> "$GITHUB_OUTPUT"
        echo 'CHIMERA_OUTPUT' >> "$GITHUB_OUTPUT"
        "#,
        HashMap::from([("ALL_SECRETS".into(), "${{ toJSON(secrets) }}".into())]),
    );
    let consume = script_step_env(
        "consume",
        r#"
        printf '%s' "$APP_ENV" | jq -e '
          .DEPLOY_TOKEN == "synthetic-secret" and
          .EMPTY_SECRET == ""
        ' >/dev/null
        "#,
        HashMap::from([(
            "APP_ENV".into(),
            "${{ steps.collect-secrets.outputs.app_env }}".into(),
        )]),
    );
    let mut manifest = manifest_with_steps_and_context(
        vec![produce, consume],
        &env.mock_server.uri(),
        serde_json::json!({
            "secrets": {
                "DEPLOY_TOKEN": "synthetic-secret",
                "EMPTY_SECRET": ""
            }
        }),
    );
    manifest.job_outputs = HashMap::from([(
        "published".to_string(),
        "${{ steps.collect-secrets.outputs.published }}".to_string(),
    )]);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert_eq!(
        outputs,
        HashMap::from([("published".to_string(), "release-42".to_string())])
    );
}

#[tokio::test]
async fn undeclared_secret_output_reaches_webhook_but_completejob_gets_no_outputs() {
    let mut env = TestEnv::setup().await;
    Mock::given(method("POST"))
        .and(path("/deploy-hook"))
        .and(body_json(serde_json::json!({
            "DEPLOY_TOKEN": "synthetic-secret",
            "EMPTY_SECRET": ""
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&env.mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/completejob"))
        .and(body_json(serde_json::json!({
            "planId": "p",
            "jobId": "j",
            "conclusion": "succeeded",
            "outputs": {},
            "stepResults": []
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&env.mock_server)
        .await;

    let produce = script_step_env(
        "collect-secrets",
        r#"
        echo 'app_env<<CHIMERA_OUTPUT' >> "$GITHUB_OUTPUT"
        printf '%s\n' "$ALL_SECRETS" >> "$GITHUB_OUTPUT"
        echo 'CHIMERA_OUTPUT' >> "$GITHUB_OUTPUT"
        "#,
        HashMap::from([("ALL_SECRETS".into(), "${{ toJSON(secrets) }}".into())]),
    );
    let consume = script_step_env(
        "notify",
        r#"curl --fail --silent --show-error -H 'Content-Type: application/json' --data "$APP_ENV" "$WEBHOOK_URL""#,
        HashMap::from([
            (
                "APP_ENV".into(),
                "${{ steps.collect-secrets.outputs.app_env }}".into(),
            ),
            (
                "WEBHOOK_URL".into(),
                format!("{}/deploy-hook", env.mock_server.uri()),
            ),
        ]),
    );
    let manifest = manifest_with_steps_and_context(
        vec![produce, consume],
        &env.mock_server.uri(),
        serde_json::json!({
            "secrets": {
                "DEPLOY_TOKEN": "synthetic-secret",
                "EMPTY_SECRET": ""
            }
        }),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();
    let completejob_outputs = serde_json::Value::Object(
        outputs
            .iter()
            .map(|(name, value)| (name.clone(), serde_json::json!({ "value": value })))
            .collect(),
    );
    env.job_client
        .complete_job(
            &manifest.plan.plan_id,
            &manifest.plan.job_id,
            conclusion,
            &completejob_outputs,
            &[],
        )
        .await
        .unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(outputs.is_empty());
}

#[tokio::test]
async fn declared_job_output_containing_a_secret_is_suppressed() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "produce",
        r#"
        echo "safe=release-42" >> "$GITHUB_OUTPUT"
        echo "exposed=prefix-$DEPLOY_TOKEN-suffix" >> "$GITHUB_OUTPUT"
        "#,
        HashMap::from([("DEPLOY_TOKEN".into(), "${{ secrets.DEPLOY_TOKEN }}".into())]),
    );
    let mut manifest = manifest_with_variables(
        vec![step],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "DEPLOY_TOKEN": { "value": "synthetic-secret", "isSecret": true }
        }),
    );
    manifest.job_outputs = HashMap::from([
        (
            "safe".to_string(),
            "${{ steps.produce.outputs.safe }}".to_string(),
        ),
        (
            "exposed".to_string(),
            "${{ steps.produce.outputs.exposed }}".to_string(),
        ),
    ]);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert_eq!(
        outputs,
        HashMap::from([("safe".to_string(), "release-42".to_string())])
    );
}

#[tokio::test]
async fn declared_job_output_with_json_escaped_secret_is_suppressed() {
    let env = TestEnv::setup().await;
    let mut manifest = manifest_with_variables(
        vec![script_step("noop", "true")],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "COMPLEX_SECRET": {
                "value": "first \"quoted\" line\nsecond line",
                "isSecret": true
            }
        }),
    );
    manifest.job_outputs = HashMap::from([(
        "serialized_secrets".to_string(),
        "${{ toJSON(secrets) }}".to_string(),
    )]);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(outputs.is_empty());
}

#[tokio::test]
async fn declared_job_output_with_base64_secret_is_suppressed() {
    let env = TestEnv::setup().await;
    let mut manifest = manifest_with_variables(
        vec![script_step("noop", "true")],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "DEPLOY_TOKEN": {
                "value": "synthetic-secret",
                "isSecret": true
            }
        }),
    );
    manifest.job_outputs = HashMap::from([(
        "encoded".to_string(),
        "c3ludGhldGljLXNlY3JldA==".to_string(),
    )]);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(outputs.is_empty());
}

#[tokio::test]
async fn declared_job_output_matching_a_regex_mask_is_suppressed() {
    let env = TestEnv::setup().await;
    let mut manifest =
        manifest_with_steps(vec![script_step("noop", "true")], &env.mock_server.uri());
    manifest.mask = vec![serde_json::json!({
        "type": "regex",
        "value": "credential-[0-9]+"
    })];
    manifest.job_outputs =
        HashMap::from([("credential".to_string(), "credential-12345".to_string())]);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(outputs.is_empty());
}

#[tokio::test]
async fn empty_declared_job_output_is_not_returned() {
    let env = TestEnv::setup().await;
    let step = script_step("produce", r#"echo "empty=" >> "$GITHUB_OUTPUT""#);
    let mut manifest = manifest_with_steps(vec![step], &env.mock_server.uri());
    manifest.job_outputs = HashMap::from([(
        "empty".to_string(),
        "${{ steps.produce.outputs.empty }}".to_string(),
    )]);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(outputs.is_empty());
}

#[tokio::test]
async fn env_accumulates_across_three_steps() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step("s1", r#"echo "A=1" >> "$GITHUB_ENV""#),
            script_step("s2", r#"echo "B=2" >> "$GITHUB_ENV""#),
            script_step(
                "s3",
                r#"
                test "$A" = "1" || exit 1
                test "$B" = "2" || exit 1
                "#,
            ),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn declared_job_output_can_use_env_written_by_a_step() {
    let env = TestEnv::setup().await;
    let mut manifest = manifest_with_steps(
        vec![script_step(
            "set-version",
            r#"echo "VERSION=1.2.3" >> "$GITHUB_ENV""#,
        )],
        &env.mock_server.uri(),
    );
    manifest.job_outputs =
        HashMap::from([("version".to_string(), "${{ env.VERSION }}".to_string())]);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert_eq!(outputs.get("version").map(String::as_str), Some("1.2.3"));
}

#[tokio::test]
async fn declared_job_output_env_keeps_linux_case_distinctions() {
    let env = TestEnv::setup().await;
    let mut manifest = manifest_with_variables(
        vec![script_step(
            "set-lowercase",
            r#"echo "foo=from-step" >> "$GITHUB_ENV""#,
        )],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "FOO": { "value": "from-base", "isSecret": false }
        }),
    );
    manifest.job_outputs = HashMap::from([
        ("upper".to_string(), "${{ env.FOO }}".to_string()),
        ("lower".to_string(), "${{ env.foo }}".to_string()),
    ]);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert_eq!(outputs.get("upper").map(String::as_str), Some("from-base"));
    assert_eq!(outputs.get("lower").map(String::as_str), Some("from-step"));
}

#[tokio::test]
async fn path_accumulates_across_steps() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step("s1", r#"echo "/first/bin" >> "$GITHUB_PATH""#),
            script_step("s2", r#"echo "/second/bin" >> "$GITHUB_PATH""#),
            script_step(
                "s3",
                r#"
                echo "$PATH" | grep -q "/first/bin" || exit 1
                echo "$PATH" | grep -q "/second/bin" || exit 1
                "#,
            ),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn multiple_outputs_from_one_step() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "s1",
                "echo \"key1=val1\" >> \"$GITHUB_OUTPUT\"\necho \"key2=val2\" >> \"$GITHUB_OUTPUT\"",
            ),
            script_step(
                "s2",
                r#"
                test "${{ steps.s1.outputs.key1 }}" = "val1" || exit 1
                test "${{ steps.s1.outputs.key2 }}" = "val2" || exit 1
                "#,
            ),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn step_output_chaining_three_steps() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step("s1", r#"echo "val=hello" >> "$GITHUB_OUTPUT""#),
            script_step(
                "s2",
                "echo \"val=${{ steps.s1.outputs.val }}-world\" >> \"$GITHUB_OUTPUT\"",
            ),
            script_step(
                "s3",
                r#"test "${{ steps.s2.outputs.val }}" = "hello-world" || exit 1"#,
            ),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn env_var_overwrite_between_steps() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step("s1", r#"echo "X=first" >> "$GITHUB_ENV""#),
            script_step("s2", r#"echo "X=second" >> "$GITHUB_ENV""#),
            script_step("s3", r#"test "$X" = "second" || exit 1"#),
        ],
        &env.mock_server.uri(),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn cancel_token_cancels_job() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step("s1", "echo step1")],
        &env.mock_server.uri(),
    );

    let mut domain = env
        .execution_domains
        .reserve()
        .await
        .unwrap()
        .provision(AttemptIdentity::new())
        .await
        .unwrap();
    let base_env =
        chimera::runner::env::build_base_env(&manifest, &env.workspace, "test-runner", &domain)
            .unwrap();
    let action_cache = chimera::job::action::ActionCache::new(
        env.workspace.runner_temp().join("actions"),
        reqwest::Client::new(),
    );
    let docker_action_builder = chimera::docker::build::DockerActionBuilder::new();
    let cancel_token = tokio_util::sync::CancellationToken::new();
    cancel_token.cancel();
    let node_runtimes = chimera::node::NodeRuntimes::single("node".into());
    let execution = chimera::job::execute::JobExecutionContext::new(&domain, None, &node_runtimes);

    let result = chimera::job::execute::run_all_steps(
        &manifest,
        &env.job_client,
        &env.workspace,
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
    .await;
    domain.destroy().await.unwrap();

    let (conclusion, _) = result.unwrap();
    assert_eq!(conclusion, JobConclusion::Cancelled);
}
