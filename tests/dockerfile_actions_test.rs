mod common;

use std::collections::HashMap;
use std::time::Duration;

use chimera::docker::build::RegistryAuth;
use chimera::job::client::JobConclusion;
use common::*;
use tokio_util::sync::CancellationToken;

async fn wait_for_exact_uploaded_log(env: &TestEnv, expected: &str) {
    let mut last_seen = String::new();
    let found = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let uploaded = env.uploaded_log_text().await;
            if uploaded.lines().any(|line| {
                line.split_once(' ')
                    .is_some_and(|(_, content)| content == expected)
            }) {
                return true;
            }
            last_seen = uploaded;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or(false);
    if !found {
        let requests: Vec<String> = env
            .mock_server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|request| format!("{} {}", request.method, request.url.path()))
            .collect();
        panic!(
            "timed out waiting for exact uploaded log: {expected}; uploaded logs:\n{last_seen}\nreceived requests:\n{}",
            requests.join("\n")
        );
    }
}

#[tokio::test]
#[ignore]
async fn dockerfile_action_builds_and_propagates_exit_code() {
    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/dockerfile-basic");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: basic\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY entrypoint.sh /entrypoint.sh\nRUN chmod +x /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(
        action.join("entrypoint.sh"),
        "#!/bin/sh\necho result=ok >> \"$GITHUB_OUTPUT\"\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "docker",
            ".github/actions/dockerfile-basic",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(
        conclusion,
        JobConclusion::Succeeded,
        "uploaded logs:\n{logs}"
    );
    assert_eq!(outputs.get("result").map(String::as_str), Some("ok"));
}

#[tokio::test]
#[ignore]
async fn successfully_built_dockerfile_action_propagates_nonzero_exit_code() {
    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/dockerfile-nonzero");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: nonzero\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY entrypoint.sh /entrypoint.sh\nRUN chmod +x /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(
        action.join("entrypoint.sh"),
        "#!/bin/sh\ntouch /github/workspace/nonzero-entrypoint-ran\nexit 17\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "nonzero",
            ".github/actions/dockerfile-nonzero",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, _) = env.run(&manifest).await.unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(conclusion, JobConclusion::Failed);
    assert!(
        env.workspace
            .workspace_dir()
            .join("nonzero-entrypoint-ran")
            .exists(),
        "entrypoint marker missing; uploaded logs:\n{logs}"
    );
    assert!(
        logs.contains("Docker action image is ready"),
        "uploaded logs:\n{logs}"
    );
}

#[tokio::test]
#[ignore]
async fn subdirectory_dockerfile_uses_action_root_as_context() {
    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/subdir-build");
    std::fs::create_dir_all(action.join("docker files")).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: subdir\nruns:\n  using: docker\n  image: docker files/Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join("payload.txt"), "from-action-root").unwrap();
    std::fs::write(
        action.join("entrypoint.sh"),
        "#!/bin/sh\ntest \"$(cat /payload.txt)\" = from-action-root\n",
    )
    .unwrap();
    std::fs::write(
        action.join("docker files/Dockerfile"),
        "FROM alpine:3.19\nCOPY payload.txt /payload.txt\nCOPY entrypoint.sh /entrypoint.sh\nRUN chmod +x /entrypoint.sh\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "subdir",
            ".github/actions/subdir-build",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
#[ignore]
async fn dockerfile_specific_ignore_overrides_root_ignore() {
    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/ignore-rules");
    std::fs::create_dir_all(action.join("docker")).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: ignores\nruns:\n  using: docker\n  image: docker/Dockerfile\n  entrypoint: /context/entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join(".dockerignore"), "root-only.txt\n").unwrap();
    std::fs::write(
        action.join("docker/Dockerfile.dockerignore"),
        "specific-only.txt\n",
    )
    .unwrap();
    std::fs::write(action.join("root-only.txt"), "must-be-present").unwrap();
    std::fs::write(action.join("specific-only.txt"), "must-be-absent").unwrap();
    std::fs::write(action.join("entrypoint.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(
        action.join("docker/Dockerfile"),
        "FROM alpine:3.19\nCOPY . /context\nRUN test -f /context/root-only.txt && test ! -e /context/specific-only.txt && chmod +x /context/entrypoint.sh\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "ignores",
            ".github/actions/ignore-rules",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn context_symlink_escape_fails_before_action_container_starts() {
    use std::os::unix::fs::symlink;

    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/symlink-escape");
    std::fs::create_dir_all(&action).unwrap();
    let outside = env.tmp.path().join("synthetic-canary");
    std::fs::write(&outside, "CHIMERA_OUTSIDE_CONTEXT_CANARY").unwrap();
    symlink(&outside, action.join("escape")).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: escape\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join("Dockerfile"), "FROM alpine:3.19\n").unwrap();
    std::fs::write(
        action.join("entrypoint.sh"),
        "#!/bin/sh\ntouch /github/workspace/main-ran\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "escape",
            ".github/actions/symlink-escape",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, _) = env.run(&manifest).await.unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(conclusion, JobConclusion::Failed);
    assert!(!env.workspace.workspace_dir().join("main-ran").exists());
    assert!(logs.contains("build context symlink must stay inside the action directory"));
    assert!(!logs.contains("CHIMERA_OUTSIDE_CONTEXT_CANARY"));
}

#[tokio::test]
#[ignore]
async fn synthetic_secrets_stay_out_of_context_and_logs() {
    let mut env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/canary");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: canary\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /bin/true\n",
    )
    .unwrap();
    std::fs::write(action.join(".dockerignore"), "synthetic-secret.txt\n").unwrap();
    std::fs::write(
        action.join("synthetic-secret.txt"),
        "CHIMERA_SYNTHETIC_CONTEXT_CANARY",
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY . /context\nRUN test ! -e /context/synthetic-secret.txt\n",
    )
    .unwrap();
    let auth = RegistryAuth::from([(
        "https://synthetic.invalid/v1/".to_string(),
        bollard::auth::DockerCredentials {
            username: Some("synthetic-user".to_string()),
            password: Some("CHIMERA_SYNTHETIC_AUTH_CANARY".to_string()),
            ..Default::default()
        },
    )]);
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "canary",
            ".github/actions/canary",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, _) = env.run_with_registry_auth(&manifest, &auth).await.unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(!logs.contains("CHIMERA_SYNTHETIC_CONTEXT_CANARY"));
    assert!(!logs.contains("CHIMERA_SYNTHETIC_AUTH_CANARY"));
}

#[tokio::test]
#[ignore]
async fn changed_context_rebuilds_while_unchanged_context_hits_cache() {
    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/cache-key");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: cache\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /bin/true\n",
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY payload.txt /payload.txt\n",
    )
    .unwrap();
    std::fs::write(action.join("payload.txt"), "first").unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "cache",
            ".github/actions/cache-key",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    assert_eq!(
        env.run(&manifest).await.unwrap().0,
        JobConclusion::Succeeded
    );
    assert_eq!(
        env.run(&manifest).await.unwrap().0,
        JobConclusion::Succeeded
    );
    std::fs::write(action.join("payload.txt"), "second").unwrap();
    assert_eq!(
        env.run(&manifest).await.unwrap().0,
        JobConclusion::Succeeded
    );
    let logs = env.uploaded_log_text().await;

    assert_eq!(logs.matches("Building Docker action image").count(), 2);
    assert_eq!(
        logs.matches("Reusing cached Docker action image").count(),
        1
    );
}

#[tokio::test]
#[ignore]
async fn cancelled_build_does_not_start_action_and_same_key_retries() {
    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/cancelled-build");
    std::fs::create_dir_all(&action).unwrap();
    let build_marker = format!("executor-cancel-build-started-{}", uuid::Uuid::new_v4());
    std::fs::write(
        action.join("action.yml"),
        "name: cancellation\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join("build-marker.txt"), format!("{build_marker}\n")).unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY entrypoint.sh /entrypoint.sh\nCOPY build-marker.txt /chimera-build-marker\nRUN chmod +x /entrypoint.sh\nRUN cat /chimera-build-marker && sleep 6\n",
    )
    .unwrap();
    std::fs::write(
        action.join("entrypoint.sh"),
        "#!/bin/sh\ntouch /github/workspace/cancel-main-ran\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "cancelled",
            ".github/actions/cancelled-build",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);
    let cancel_token = CancellationToken::new();

    let run = env.run_with_cancel(&manifest, cancel_token.clone());
    let cancel_after_build_starts = async {
        wait_for_exact_uploaded_log(&env, &build_marker).await;
        cancel_token.cancel();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(45), async {
        tokio::join!(run, cancel_after_build_starts)
    })
    .await
    .expect("cancelled executor run must return promptly");

    assert_eq!(result.unwrap().0, JobConclusion::Cancelled);
    assert!(
        !env.workspace
            .workspace_dir()
            .join("cancel-main-ran")
            .exists()
    );

    assert_eq!(
        env.run(&manifest).await.unwrap().0,
        JobConclusion::Succeeded
    );
    assert!(
        env.workspace
            .workspace_dir()
            .join("cancel-main-ran")
            .exists()
    );
    let logs = env.uploaded_log_text().await;
    assert_eq!(logs.matches("Building Docker action image").count(), 2);
    assert_eq!(
        logs.matches("Reusing cached Docker action image").count(),
        0
    );
}

#[tokio::test]
#[ignore]
async fn timed_out_action_does_not_start_entrypoint_and_same_key_retries() {
    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/timed-out-build");
    std::fs::create_dir_all(&action).unwrap();
    let build_marker = format!("executor-timeout-build-started-{}", uuid::Uuid::new_v4());
    std::fs::write(
        action.join("action.yml"),
        "name: timeout\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join("build-marker.txt"), format!("{build_marker}\n")).unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY entrypoint.sh /entrypoint.sh\nCOPY build-marker.txt /chimera-build-marker\nRUN chmod +x /entrypoint.sh\nRUN cat /chimera-build-marker && sleep 65\n",
    )
    .unwrap();
    std::fs::write(
        action.join("entrypoint.sh"),
        "#!/bin/sh\ntouch /github/workspace/timeout-main-ran\n",
    )
    .unwrap();
    let mut timed_out_step =
        local_action_step("timeout", ".github/actions/timed-out-build", HashMap::new());
    timed_out_step["timeoutInMinutes"] = serde_json::json!(1);
    let timed_out_manifest = manifest_with_steps(vec![timed_out_step], &env.mock_server.uri());
    env.configure_from_manifest(&timed_out_manifest);

    let run = env.run(&timed_out_manifest);
    let wait_for_build_process = wait_for_exact_uploaded_log(&env, &build_marker);
    let (timed_out_result, ()) = tokio::time::timeout(Duration::from_secs(90), async {
        tokio::join!(run, wait_for_build_process)
    })
    .await
    .expect("timed-out executor run must return promptly");
    assert_eq!(timed_out_result.unwrap().0, JobConclusion::Failed);
    assert!(
        !env.workspace
            .workspace_dir()
            .join("timeout-main-ran")
            .exists()
    );

    let retry_manifest = manifest_with_steps(
        vec![local_action_step(
            "timeout",
            ".github/actions/timed-out-build",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    let retry = tokio::time::timeout(Duration::from_secs(120), env.run(&retry_manifest))
        .await
        .expect("same-key retry must complete")
        .unwrap();
    assert_eq!(retry.0, JobConclusion::Succeeded);
    assert!(
        env.workspace
            .workspace_dir()
            .join("timeout-main-ran")
            .exists()
    );
    let logs = env.uploaded_log_text().await;
    assert_eq!(logs.matches("Building Docker action image").count(), 2);
    assert_eq!(
        logs.matches("Reusing cached Docker action image").count(),
        0
    );
}

#[tokio::test]
#[ignore]
async fn failed_build_does_not_start_action_entrypoint() {
    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/failing-build");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: failure\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY entrypoint.sh /entrypoint.sh\nRUN chmod +x /entrypoint.sh\nRUN false\n",
    )
    .unwrap();
    std::fs::write(
        action.join("entrypoint.sh"),
        "#!/bin/sh\ntouch /github/workspace/main-ran\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "failure",
            ".github/actions/failing-build",
            HashMap::new(),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, _) = env.run(&manifest).await.unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(conclusion, JobConclusion::Failed);
    assert!(!env.workspace.workspace_dir().join("main-ran").exists());
    assert!(logs.contains("Docker action image build failed"));
}

#[tokio::test]
#[ignore]
async fn dockerfile_action_reuses_image_for_pre_main_post() {
    let mut env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/phases");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        r#"name: phases
inputs:
  message:
    default: default-message
runs:
  using: docker
  image: Dockerfile
  pre-entrypoint: /pre.sh
  entrypoint: /main.sh
  post-entrypoint: /post.sh
  args:
    - ${{ inputs.message }}
  env:
    ACTION_ENV: env-value
"#,
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY pre.sh main.sh post.sh /\nRUN chmod +x /pre.sh /main.sh /post.sh\n",
    )
    .unwrap();
    std::fs::write(
        action.join("pre.sh"),
        "#!/bin/sh\necho pre >> /github/workspace/phases\n",
    )
    .unwrap();
    std::fs::write(
        action.join("main.sh"),
        "#!/bin/sh\nset -eu\ntest \"$INPUT_MESSAGE\" = expected\ntest \"$ACTION_ENV\" = env-value\ntest \"$1\" = expected\necho main >> /github/workspace/phases\necho phase=main >> \"$GITHUB_STATE\"\necho result=ok >> \"$GITHUB_OUTPUT\"\n",
    )
    .unwrap();
    std::fs::write(
        action.join("post.sh"),
        "#!/bin/sh\nset -eu\ntest \"$STATE_phase\" = main\necho post >> /github/workspace/phases\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "phases",
            ".github/actions/phases",
            HashMap::from([("message".to_string(), "expected".to_string())]),
        )],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert_eq!(outputs.get("result").map(String::as_str), Some("ok"));
    assert_eq!(
        std::fs::read_to_string(env.workspace.workspace_dir().join("phases")).unwrap(),
        "pre\nmain\npost\n"
    );
    assert_eq!(
        logs.matches("Docker action image is ready").count(),
        1,
        "uploaded logs:\n{logs}"
    );
    assert_eq!(
        logs.matches("Reusing Docker action image for this job")
            .count(),
        2
    );
}

#[tokio::test]
#[ignore]
async fn prebuilt_metadata_and_inline_docker_actions_still_run() {
    let mut env = TestEnv::setup().await;
    let action = env
        .workspace
        .workspace_dir()
        .join(".github/actions/prebuilt");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        r#"name: prebuilt
runs:
  using: docker
  image: docker://alpine:3.19
  entrypoint: /bin/sh
  args:
    - -c
    - echo prebuilt=ran >> "$GITHUB_OUTPUT"; touch /github/workspace/prebuilt-ran
"#,
    )
    .unwrap();
    let inline = serde_json::json!({
        "id": "inline",
        "displayName": "Inline Docker",
        "reference": {
            "name": "docker://alpine:3.19",
            "type": "containerregistry",
            "image": "alpine:3.19"
        },
        "inputs": {
            "entrypoint": "/bin/sh",
            "args": "-c 'echo inline=ran >> \"$GITHUB_OUTPUT\"; touch /github/workspace/inline-ran'"
        },
        "condition": null,
        "timeoutInMinutes": null,
        "continueOnError": false,
        "order": 2,
        "environment": null,
        "contextName": "inline"
    });
    let manifest = manifest_with_steps(
        vec![
            local_action_step("prebuilt", ".github/actions/prebuilt", HashMap::new()),
            inline,
        ],
        &env.mock_server.uri(),
    );
    env.configure_from_manifest(&manifest);

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert_eq!(outputs.get("prebuilt").map(String::as_str), Some("ran"));
    assert_eq!(outputs.get("inline").map(String::as_str), Some("ran"));
    assert!(env.workspace.workspace_dir().join("prebuilt-ran").exists());
    assert!(env.workspace.workspace_dir().join("inline-ran").exists());
    assert!(!logs.contains("Preparing Docker action build context"));
}

#[cfg(feature = "acceptance-tests")]
#[tokio::test]
#[ignore]
async fn hadolint_pinned_sha_acceptance_on_rootless_engine() {
    let token = std::env::var("CHIMERA_GITHUB_TOKEN")
        .expect("CHIMERA_GITHUB_TOKEN is required for exact-pin acceptance");
    let docker = chimera::docker::client::connect(None).unwrap();
    let info = docker.info().await.unwrap();
    let security = info
        .security_options
        .unwrap_or_default()
        .join(" ")
        .to_lowercase();
    assert!(
        security.contains("rootless"),
        "acceptance requires a rootless Docker daemon"
    );

    let env = TestEnv::setup().await;
    let infra = env.workspace.workspace_dir().join("infra");
    std::fs::create_dir_all(&infra).unwrap();
    let hadolint = serde_json::json!({
        "id": "hadolint",
        "displayName": "Run pinned Hadolint",
        "reference": {
            "name": "hadolint/hadolint-action",
            "type": "repository",
            "ref": "2332a7b74a6de0dda2e2221d575162eba76ba5e5",
            "path": null
        },
        "inputs": { "dockerfile": "infra/Dockerfile" },
        "condition": null,
        "timeoutInMinutes": 10,
        "continueOnError": false,
        "order": 1,
        "environment": null,
        "contextName": "hadolint"
    });
    let manifest = manifest_with_steps(vec![hadolint.clone()], &env.mock_server.uri());

    std::fs::write(infra.join("Dockerfile"), "FROM alpine:3.19\nRUN true\n").unwrap();
    let (good, _) = env.run_with_access_token(&manifest, &token).await.unwrap();
    assert_eq!(good, JobConclusion::Succeeded);

    std::fs::write(infra.join("Dockerfile"), "FROM ubuntu\nRUN true\n").unwrap();
    let bad_manifest = manifest_with_steps(vec![hadolint], &env.mock_server.uri());
    let (bad, _) = env
        .run_with_access_token(&bad_manifest, &token)
        .await
        .unwrap();
    assert_eq!(bad, JobConclusion::Failed);
}
