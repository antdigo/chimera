mod common;

use chimera::job::client::JobConclusion;
use chimera::job::docker_config::JobResourceRoot;
use chimera::job::workspace::Workspace;
use common::*;
use tokio_util::sync::CancellationToken;

fn local_node_action_step(id: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "displayName": format!("Run {path}"),
        "reference": {
            "name": "",
            "type": "repository",
            "repositoryType": "self",
            "path": path
        },
        "inputs": {},
        "condition": null,
        "timeoutInMinutes": null,
        "continueOnError": false,
        "order": 1,
        "environment": null,
        "contextName": id
    })
}

fn write_docker_config_probe_action(workspace: &Workspace) -> anyhow::Result<()> {
    let action_dir = workspace
        .workspace_dir()
        .join(".github/actions/docker-config-probe");
    std::fs::create_dir_all(&action_dir)?;
    std::fs::write(
        action_dir.join("action.yml"),
        "name: docker-config-probe\nruns:\n  using: node20\n  pre: pre.js\n  main: main.js\n  post: post.js\n  post-if: always()\n",
    )?;
    let source = r#"
const fs = require('fs');
const path = require('path');
const phase = path.basename(__filename, '.js');
const config = process.env.DOCKER_CONFIG;
if (!config || !fs.existsSync(path.join(config, 'config.json'))) process.exit(1);
fs.writeFileSync(path.join(process.env.GITHUB_WORKSPACE, `${phase}-docker-config`), config);
"#;
    for phase in ["pre", "main", "post"] {
        std::fs::write(action_dir.join(format!("{phase}.js")), source)?;
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_jobs_use_distinct_configs() {
    let daemon_root = tempfile::tempdir().unwrap();
    let job_resources =
        JobResourceRoot::prepare(&daemon_root.path().join("job-resources")).unwrap();
    let first = TestEnv::setup_with_job_resources(job_resources.clone()).await;
    let second = TestEnv::setup_with_job_resources(job_resources).await;
    let first_manifest = manifest_with_steps(
        vec![script_step(
            "first",
            r#"printf '%s' "$DOCKER_CONFIG" > "$GITHUB_WORKSPACE/docker-config-path""#,
        )],
        &first.mock_server.uri(),
    );
    let second_manifest = manifest_with_steps(
        vec![script_step(
            "second",
            r#"printf '%s' "$DOCKER_CONFIG" > "$GITHUB_WORKSPACE/docker-config-path""#,
        )],
        &second.mock_server.uri(),
    );

    let (first_run, second_run) = tokio::join!(
        first.run_observed(&first_manifest, CancellationToken::new()),
        second.run_observed(&second_manifest, CancellationToken::new()),
    );
    let first_run = first_run.unwrap();
    let second_run = second_run.unwrap();

    assert_eq!(first_run.conclusion, JobConclusion::Succeeded);
    assert_eq!(second_run.conclusion, JobConclusion::Succeeded);
    assert_ne!(first_run.docker_config_dir, second_run.docker_config_dir);

    let first_seen =
        std::fs::read_to_string(first.workspace.workspace_dir().join("docker-config-path"))
            .unwrap();
    let second_seen =
        std::fs::read_to_string(second.workspace.workspace_dir().join("docker-config-path"))
            .unwrap();
    assert_eq!(
        std::path::Path::new(&first_seen),
        first_run.docker_config_dir
    );
    assert_eq!(
        std::path::Path::new(&second_seen),
        second_run.docker_config_dir
    );
    assert!(!first_run.attempt_dir.exists());
    assert!(!second_run.attempt_dir.exists());
}

#[tokio::test]
async fn sequential_jobs_start_empty_and_use_new_paths() {
    let env = TestEnv::setup().await;
    let first_manifest = manifest_with_steps(
        vec![script_step(
            "write",
            r#"printf '%s' '{"auths":{"registry.test":{"auth":"synthetic"}}}' > "$DOCKER_CONFIG/config.json""#,
        )],
        &env.mock_server.uri(),
    );
    let first = env
        .run_observed(&first_manifest, CancellationToken::new())
        .await
        .unwrap();
    let second_manifest = manifest_with_steps(
        vec![script_step(
            "read",
            r#"test "$(cat "$DOCKER_CONFIG/config.json")" = '{}'"#,
        )],
        &env.mock_server.uri(),
    );

    let second = env
        .run_observed(&second_manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(second.conclusion, JobConclusion::Succeeded);
    assert_ne!(first.docker_config_dir, second.docker_config_dir);
}

#[tokio::test]
async fn pre_main_post_share_config_until_post_finishes() {
    let env = TestEnv::setup().await;
    write_docker_config_probe_action(&env.workspace).unwrap();
    let manifest = manifest_with_steps(
        vec![local_node_action_step(
            "probe",
            ".github/actions/docker-config-probe",
        )],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    for phase in ["pre", "main", "post"] {
        let path = std::fs::read_to_string(
            env.workspace
                .workspace_dir()
                .join(format!("{phase}-docker-config")),
        )
        .unwrap();
        assert_eq!(std::path::Path::new(&path), observed.docker_config_dir);
    }
    assert!(!observed.attempt_dir.exists());
}

#[tokio::test]
async fn cleanup_runs_for_all_job_outcomes() {
    let daemon_root = tempfile::tempdir().unwrap();
    let job_resources =
        JobResourceRoot::prepare(&daemon_root.path().join("job-resources")).unwrap();
    let mut neighbor = job_resources.create_docker_config().unwrap();
    let neighbor_dir = neighbor.attempt_dir().to_path_buf();

    for case in ["success", "failure", "cancelled", "pre-error"] {
        let env = TestEnv::setup_with_job_resources(job_resources.clone()).await;
        let cancel = CancellationToken::new();
        let steps = match case {
            "success" => vec![script_step("success", "true")],
            "failure" => vec![script_step("failure", "exit 1")],
            "cancelled" => {
                cancel.cancel();
                vec![script_step("cancelled", "sleep 10")]
            }
            "pre-error" => {
                let action_dir = env
                    .workspace
                    .workspace_dir()
                    .join(".github/actions/failing-pre");
                std::fs::create_dir_all(&action_dir).unwrap();
                std::fs::write(
                    action_dir.join("action.yml"),
                    "name: failing-pre\nruns:\n  using: node20\n  pre: pre.js\n  main: main.js\n",
                )
                .unwrap();
                std::fs::write(action_dir.join("pre.js"), "process.exit(1);\n").unwrap();
                std::fs::write(action_dir.join("main.js"), "process.exit(0);\n").unwrap();
                vec![local_node_action_step(
                    "failing-pre",
                    ".github/actions/failing-pre",
                )]
            }
            _ => unreachable!(),
        };
        let manifest = manifest_with_steps(steps, &env.mock_server.uri());

        let observed = env.run_observed(&manifest, cancel).await.unwrap();

        let expected = match case {
            "success" => JobConclusion::Succeeded,
            "cancelled" => JobConclusion::Cancelled,
            "failure" | "pre-error" => JobConclusion::Failed,
            _ => unreachable!(),
        };
        assert_eq!(observed.conclusion, expected, "case {case}");
        assert!(!observed.attempt_dir.exists(), "case {case}");
        assert!(neighbor_dir.exists(), "case {case}");
    }

    neighbor.cleanup().unwrap();
}

#[tokio::test]
async fn step_env_override_fails_before_spawn() {
    let env = TestEnv::setup().await;
    let sentinel = env.workspace.workspace_dir().join("spawned");
    let manifest = manifest_with_steps(
        vec![script_step_env(
            "override",
            "touch spawned",
            std::collections::HashMap::from([("DOCKER_CONFIG".into(), "/shared/.docker".into())]),
        )],
        &env.mock_server.uri(),
    );

    let result = env.run(&manifest).await.unwrap();

    assert_eq!(result.0, JobConclusion::Failed);
    assert!(!sentinel.exists());
}

#[tokio::test]
async fn github_env_override_fails_before_next_spawn() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "write",
                r#"echo 'DOCKER_CONFIG=/shared/.docker' >> "$GITHUB_ENV""#,
            ),
            script_step("affected", "touch affected-step-ran"),
        ],
        &env.mock_server.uri(),
    );

    let result = env.run(&manifest).await.unwrap();

    assert_eq!(result.0, JobConclusion::Failed);
    assert!(
        !env.workspace
            .workspace_dir()
            .join("affected-step-ran")
            .exists()
    );
}

#[tokio::test]
async fn matching_step_environment_is_allowed() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step_env(
            "matching",
            r#"test -f "$DOCKER_CONFIG/config.json""#,
            std::collections::HashMap::from([(
                "DOCKER_CONFIG".into(),
                "${{ env.DOCKER_CONFIG }}".into(),
            )]),
        )],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn matching_github_env_is_allowed() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "write",
                r#"printf 'DOCKER_CONFIG=%s\n' "$DOCKER_CONFIG" >> "$GITHUB_ENV""#,
            ),
            script_step("affected", r#"test -f "$DOCKER_CONFIG/config.json""#),
        ],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn legacy_set_env_override_fails_before_next_spawn() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "write",
                "echo '::set-env name=DOCKER_CONFIG::/shared/.docker'",
            ),
            script_step("affected", "touch legacy-affected-step-ran"),
        ],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Failed);
    assert!(
        !env.workspace
            .workspace_dir()
            .join("legacy-affected-step-ran")
            .exists()
    );
}

#[test]
fn inherited_daemon_config_is_neither_used_nor_modified() {
    let temp = tempfile::tempdir().unwrap();
    let daemon_dir = temp.path().join("daemon-docker");
    std::fs::create_dir_all(&daemon_dir).unwrap();
    let daemon_file = daemon_dir.join("config.json");
    let marker = r#"{"auths":{"registry.test":{"auth":"synthetic-host"}},"currentContext":"host"}"#;
    std::fs::write(&daemon_file, marker).unwrap();

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "inherited_daemon_config_child", "--nocapture"])
        .env("DOCKER_CONFIG", &daemon_dir)
        .env("CHIMERA_C11_DAEMON_CONFIG", &daemon_dir)
        .status()
        .unwrap();

    assert!(status.success());
    assert_eq!(std::fs::read_to_string(daemon_file).unwrap(), marker);
}

#[tokio::test]
async fn inherited_daemon_config_child() {
    let Some(daemon_config) = std::env::var_os("CHIMERA_C11_DAEMON_CONFIG") else {
        return;
    };
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step(
            "probe",
            r#"
                test "$DOCKER_CONFIG" != "$CHIMERA_C11_DAEMON_CONFIG"
                test "$(cat "$DOCKER_CONFIG/config.json")" = '{}'
            "#,
        )],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
    assert_ne!(
        observed.docker_config_dir,
        std::path::PathBuf::from(daemon_config)
    );
}
