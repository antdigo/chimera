mod common;

use std::collections::HashMap;

use chimera::job::client::JobConclusion;
use common::*;

#[tokio::test]
async fn secrets_from_context_data() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "s1",
        r#"test "$MY_SECRET" = "super-secret-value" || exit 1"#,
        HashMap::from([("MY_SECRET".into(), "${{ secrets.TEST_SECRET }}".into())]),
    );
    let manifest = manifest_with_steps_and_context(
        vec![step],
        &env.mock_server.uri(),
        serde_json::json!({
            "secrets": { "TEST_SECRET": "super-secret-value" }
        }),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn missing_secret_resolves_empty() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "s1",
        r#"test -z "$MY_SECRET" || exit 1"#,
        HashMap::from([("MY_SECRET".into(), "${{ secrets.NONEXISTENT }}".into())]),
    );
    let manifest = manifest_with_steps(vec![step], &env.mock_server.uri());
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn multiple_secrets() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "s1",
        r#"
        test "$SECRET_A" = "value_a" || exit 1
        test "$SECRET_B" = "value_b" || exit 1
        "#,
        HashMap::from([
            ("SECRET_A".into(), "${{ secrets.A }}".into()),
            ("SECRET_B".into(), "${{ secrets.B }}".into()),
        ]),
    );
    let manifest = manifest_with_steps_and_context(
        vec![step],
        &env.mock_server.uri(),
        serde_json::json!({
            "secrets": { "A": "value_a", "B": "value_b" }
        }),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

// The system job token is delivered as a lowercase `github_token` variable;
// every GHCR-login workflow spells it `${{ secrets.GITHUB_TOKEN }}` (#15).
#[tokio::test]
async fn github_token_variable_resolves_regardless_of_case() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "s1",
        r#"
        test "$TOKEN_UPPER" = "ghs_system_token" || exit 1
        test "$TOKEN_LOWER" = "ghs_system_token" || exit 1
        "#,
        HashMap::from([
            ("TOKEN_UPPER".into(), "${{ secrets.GITHUB_TOKEN }}".into()),
            ("TOKEN_LOWER".into(), "${{ secrets.github_token }}".into()),
        ]),
    );
    let manifest = manifest_with_variables(
        vec![step],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "github_token": { "value": "ghs_system_token", "isSecret": true }
        }),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

// Some job messages only carry the token as the `system.github.token`
// variable; `secrets.GITHUB_TOKEN` must resolve there too (#15).
#[tokio::test]
async fn github_token_resolves_from_system_variable() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "s1",
        r#"test "$TOKEN" = "ghs_system_token" || exit 1"#,
        HashMap::from([("TOKEN".into(), "${{ secrets.GITHUB_TOKEN }}".into())]),
    );
    let manifest = manifest_with_variables(
        vec![step],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "system.github.token": { "value": "ghs_system_token", "isSecret": true }
        }),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

// The official ToSecretsContext excludes the dotted `system.github.token`
// name from the secrets context; only the canonical GITHUB_TOKEN alias
// resolves.
#[tokio::test]
async fn dotted_system_token_name_is_not_reachable_as_secret() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "s1",
        r#"
        test "$TOKEN" = "ghs_system_token" || exit 1
        test -z "$DOTTED" || exit 1
        "#,
        HashMap::from([
            ("TOKEN".into(), "${{ secrets.GITHUB_TOKEN }}".into()),
            (
                "DOTTED".into(),
                "${{ secrets['system.github.token'] }}".into(),
            ),
        ]),
    );
    let manifest = manifest_with_variables(
        vec![step],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "system.github.token": { "value": "ghs_system_token", "isSecret": true }
        }),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

// When both delivery paths arrive, the explicit `github_token` variable wins
// over the `system.github.token` fallback.
#[tokio::test]
async fn github_token_variable_wins_over_system_variable() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "s1",
        r#"test "$TOKEN" = "primary_token" || exit 1"#,
        HashMap::from([("TOKEN".into(), "${{ secrets.GITHUB_TOKEN }}".into())]),
    );
    let manifest = manifest_with_variables(
        vec![step],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "github_token": { "value": "primary_token", "isSecret": true },
            "system.github.token": { "value": "secondary_token", "isSecret": true }
        }),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

// The Variables dictionary is case-insensitive officially, so a mixed-case
// spelling of the system token variable must still feed the alias.
#[tokio::test]
async fn github_token_resolves_from_mixed_case_system_variable() {
    let env = TestEnv::setup().await;
    let step = script_step_env(
        "s1",
        r#"test "$TOKEN" = "ghs_mixed_case_token" || exit 1"#,
        HashMap::from([("TOKEN".into(), "${{ secrets.GITHUB_TOKEN }}".into())]),
    );
    let manifest = manifest_with_variables(
        vec![step],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "System.GitHub.Token": { "value": "ghs_mixed_case_token", "isSecret": true }
        }),
    );
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);
}

// Whatever the fallback lets into the secrets map must be masked, even when
// the delivering variable was not flagged as a secret.
#[tokio::test]
async fn fallback_token_is_masked_when_variable_not_flagged_secret() {
    let mut env = TestEnv::setup().await;
    // Verify the resolved value inside the step so the test fails if the
    // token stops resolving (an empty echo would otherwise pass vacuously).
    let step = script_step_env(
        "s1",
        r#"
        test "$TOKEN" = "ghs_unflagged_token" || exit 1
        echo "token=$TOKEN"
        "#,
        HashMap::from([("TOKEN".into(), "${{ secrets.GITHUB_TOKEN }}".into())]),
    );
    let manifest = manifest_with_variables(
        vec![step],
        &env.mock_server.uri(),
        serde_json::json!({}),
        serde_json::json!({
            "system.github.token": { "value": "ghs_unflagged_token", "isSecret": false }
        }),
    );
    // Configure the client from the manifest so step logs are actually
    // uploaded to the mock server (AccessToken comes from SystemVssConnection).
    env.configure_from_manifest(&manifest);
    let (conclusion, _) = env.run(&manifest).await.unwrap();
    assert_eq!(conclusion, JobConclusion::Succeeded);

    let logs = env.uploaded_log_text().await;
    assert!(
        logs.contains("token=***"),
        "masked echo line missing from uploaded logs"
    );
    assert!(
        !logs.contains("ghs_unflagged_token"),
        "unflagged system token leaked into uploaded logs"
    );
}
