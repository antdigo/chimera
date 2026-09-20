mod common;

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chimera::job::client::JobConclusion;
use chimera::job::execution_domain::ExecutionDomainRoot;
use chimera::job::workspace::Workspace;
use common::*;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SYNTHETIC_CREDENTIAL: &[u8] = br#"{"auths":{"registry.test":{"auth":"synthetic"}}}"#;

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
fs.appendFileSync(path.join(process.env.GITHUB_WORKSPACE, 'docker-config-phases'), `${phase} ${config}\n`);
"#;
    for phase in ["pre", "main", "post"] {
        std::fs::write(action_dir.join(format!("{phase}.js")), source)?;
    }
    Ok(())
}

async fn wait_until(condition: impl Fn() -> bool) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

struct DescendantGuard {
    pid_file: PathBuf,
    stopped: bool,
}

impl DescendantGuard {
    fn new(pid_file: PathBuf) -> Self {
        Self {
            pid_file,
            stopped: false,
        }
    }

    fn pid(&self) -> std::io::Result<i32> {
        let raw = std::fs::read_to_string(&self.pid_file)?;
        let pid = raw.trim().parse::<i32>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid descendant pid: {error}"),
            )
        })?;
        if pid <= 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "descendant pid must be greater than one",
            ));
        }
        Ok(pid)
    }

    fn is_alive(&self) -> bool {
        self.pid().is_ok_and(process_is_alive)
    }

    fn stop(&mut self) -> std::io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        let pid = self.pid()?;
        if process_is_alive(pid) {
            let result = unsafe { libc::kill(pid, libc::SIGKILL) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while process_is_alive(pid) {
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("descendant {pid} did not exit"),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.stopped = true;
        Ok(())
    }
}

impl Drop for DescendantGuard {
    fn drop(&mut self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            match self.stop() {
                Ok(()) => return,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    }
}

fn process_is_alive(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn attempt_count(root: &Path) -> usize {
    std::fs::read_dir(root).unwrap().count()
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
}

fn write_bash_probe(workspace: &Workspace) -> PathBuf {
    let bin_dir = workspace.workspace_dir().join("bash-probe");
    let log_file = workspace.workspace_dir().join("bash-spawns");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let wrapper = bin_dir.join("bash");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$2\" >> {}\nexec /bin/bash \"$@\"\n",
            shell_quote(&log_file)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(workspace.path_file(), format!("{}\n", bin_dir.display())).unwrap();
    bin_dir
}

fn bash_spawn_log(workspace: &Workspace) -> String {
    std::fs::read_to_string(workspace.workspace_dir().join("bash-spawns")).unwrap_or_default()
}

fn assert_bash_started(workspace: &Workspace, step_id: &str) {
    assert!(
        bash_spawn_log(workspace).contains(&format!("step_{step_id}.sh")),
        "expected the {step_id} step to be spawned"
    );
}

fn assert_bash_not_started(workspace: &Workspace, step_id: &str) {
    assert!(
        !bash_spawn_log(workspace).contains(&format!("step_{step_id}.sh")),
        "the {step_id} step was spawned despite the protected override"
    );
}

struct StepLogSpy {
    content: Arc<Mutex<String>>,
}

async fn spy_on_step_logs(server: &MockServer) -> StepLogSpy {
    let content = Arc::new(Mutex::new(String::new()));
    Mock::given(method("POST"))
        .and(path_regex(r".*GetStepLogsSignedBlobURL$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "logs_url": format!("{}/step-log?sig=x", server.uri()),
            "blob_storage_type": "BLOB_STORAGE_TYPE_AZURE",
        })))
        .mount(server)
        .await;

    let sink = content.clone();
    Mock::given(method("PUT"))
        .and(path_regex(r"^/step-log$"))
        .respond_with(move |request: &wiremock::Request| {
            sink.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&request.body));
            ResponseTemplate::new(201)
        })
        .mount(server)
        .await;

    StepLogSpy { content }
}

fn assert_reserved_override_diagnostic(spy: &StepLogSpy) {
    let logs = spy.content.lock().unwrap();
    assert!(
        logs.contains("reserved-environment-variable: DOCKER_CONFIG cannot be changed"),
        "expected reserved override diagnostic in step logs; captured: {logs}"
    );
}

#[tokio::test]
async fn concurrent_jobs_use_distinct_configs() {
    let daemon_root = tempfile::tempdir().unwrap();
    let execution_domains =
        ExecutionDomainRoot::prepare(
            &daemon_root.path().join("job-resources"),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
    let resource_root = execution_domains.path().to_path_buf();
    let release = daemon_root.path().join("release");
    let first = TestEnv::setup_with_job_resources(execution_domains.clone()).await;
    let second = TestEnv::setup_with_job_resources(execution_domains).await;
    let first_workspace = first.workspace.workspace_dir().to_path_buf();
    let second_workspace = second.workspace.workspace_dir().to_path_buf();
    let first_ready = first_workspace.join("ready");
    let second_ready = second_workspace.join("ready");
    let first_manifest = manifest_with_steps(
        vec![script_step(
            "first",
            &format!(
                "touch {}; while [ ! -f {} ]; do sleep 0.01; done; printf '%s' \"$DOCKER_CONFIG\" > \"$GITHUB_WORKSPACE/docker-config-path\"",
                shell_quote(&first_ready),
                shell_quote(&release),
            ),
        )],
        &first.mock_server.uri(),
    );
    let second_manifest = manifest_with_steps(
        vec![script_step(
            "second",
            &format!(
                "touch {}; while [ ! -f {} ]; do sleep 0.01; done; printf '%s' \"$DOCKER_CONFIG\" > \"$GITHUB_WORKSPACE/docker-config-path\"",
                shell_quote(&second_ready),
                shell_quote(&release),
            ),
        )],
        &second.mock_server.uri(),
    );

    let first_task = tokio::spawn(async move {
        let result = first
            .run_observed(&first_manifest, CancellationToken::new())
            .await;
        (first, result)
    });
    let second_task = tokio::spawn(async move {
        let result = second
            .run_observed(&second_manifest, CancellationToken::new())
            .await;
        (second, result)
    });
    let overlapped = wait_until(|| {
        first_ready.exists() && second_ready.exists() && attempt_count(&resource_root) == 2
    })
    .await;
    std::fs::write(&release, "release").unwrap();
    assert!(
        overlapped,
        "both jobs did not reach the shared execution barrier with live configs"
    );

    let (_first_env, first_run) = tokio::time::timeout(Duration::from_secs(5), first_task)
        .await
        .expect("first job did not finish after release")
        .unwrap();
    let first_run = first_run.unwrap();
    let (_second_env, second_run) = tokio::time::timeout(Duration::from_secs(5), second_task)
        .await
        .expect("second job did not finish after release")
        .unwrap();
    let second_run = second_run.unwrap();

    assert_eq!(first_run.conclusion, JobConclusion::Succeeded);
    assert_eq!(second_run.conclusion, JobConclusion::Succeeded);
    assert_ne!(first_run.docker_config_dir, second_run.docker_config_dir);
    let first_seen = std::fs::read_to_string(first_workspace.join("docker-config-path")).unwrap();
    let second_seen = std::fs::read_to_string(second_workspace.join("docker-config-path")).unwrap();
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
            &format!(
                "printf '%s' '{}' > \"$DOCKER_CONFIG/config.json\"; cp \"$DOCKER_CONFIG/config.json\" \"$GITHUB_WORKSPACE/first-config.json\"",
                std::str::from_utf8(SYNTHETIC_CREDENTIAL).unwrap(),
            ),
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
            r#"cp "$DOCKER_CONFIG/config.json" "$GITHUB_WORKSPACE/second-config.json"; test "$(cat "$DOCKER_CONFIG/config.json")" = '{}'"#,
        )],
        &env.mock_server.uri(),
    );
    let second = env
        .run_observed(&second_manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(first.conclusion, JobConclusion::Succeeded);
    assert_eq!(second.conclusion, JobConclusion::Succeeded);
    assert_ne!(first.docker_config_dir, second.docker_config_dir);
    assert_eq!(
        std::fs::read(env.workspace.workspace_dir().join("first-config.json")).unwrap(),
        SYNTHETIC_CREDENTIAL
    );
    assert_eq!(
        std::fs::read(env.workspace.workspace_dir().join("second-config.json")).unwrap(),
        b"{}"
    );
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

    let phase_log =
        std::fs::read_to_string(env.workspace.workspace_dir().join("docker-config-phases"))
            .unwrap();
    let observed_phases: Vec<_> = phase_log.lines().collect();
    let expected_phases = ["pre", "main", "post"]
        .map(|phase| format!("{phase} {}", observed.docker_config_dir.display()));
    assert_eq!(observed_phases, expected_phases);
    assert!(!observed.attempt_dir.exists());
}

#[tokio::test]
async fn cleanup_runs_for_all_job_outcomes() {
    let daemon_root = tempfile::tempdir().unwrap();
    let execution_domains =
        ExecutionDomainRoot::prepare(
            &daemon_root.path().join("job-resources"),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
    let neighbor = execution_domains.reserve().await.unwrap().provision().unwrap();
    let neighbor_dir = neighbor.attempt_dir().to_path_buf();

    for case in ["success", "failure", "cancelled", "pre-error"] {
        let env = TestEnv::setup_with_job_resources(execution_domains.clone()).await;
        let workspace_dir = env.workspace.workspace_dir().to_path_buf();
        let cancel = CancellationToken::new();
        let steps = match case {
            "success" => vec![script_step(
                "success",
                "if [ \"$(uname -s)\" = Linux ]; then touch /tmp/chimera-dpl03-cleanup; fi",
            )],
            "failure" => vec![script_step(
                "failure",
                "if [ \"$(uname -s)\" = Linux ]; then touch /tmp/chimera-dpl03-cleanup; fi; exit 1",
            )],
            "cancelled" => vec![script_step(
                "cancelled",
                "if [ \"$(uname -s)\" = Linux ]; then touch /tmp/chimera-dpl03-cleanup; fi; touch \"$GITHUB_WORKSPACE/cancel-ready\"; while :; do sleep 1; done",
            )],
            "pre-error" => {
                let action_dir = workspace_dir.join(".github/actions/failing-pre");
                std::fs::create_dir_all(&action_dir).unwrap();
                std::fs::write(
                    action_dir.join("action.yml"),
                    "name: failing-pre\nruns:\n  using: node20\n  pre: pre.js\n  main: main.js\n",
                )
                .unwrap();
                std::fs::write(
                    action_dir.join("pre.js"),
                    "const fs = require('fs'); if (process.platform === 'linux') fs.writeFileSync('/tmp/chimera-dpl03-cleanup', 'yes'); fs.writeFileSync(require('path').join(process.env.GITHUB_WORKSPACE, 'pre-ran'), 'yes'); process.exit(1);\n",
                )
                .unwrap();
                std::fs::write(
                    action_dir.join("main.js"),
                    "require('fs').writeFileSync(require('path').join(process.env.GITHUB_WORKSPACE, 'main-ran'), 'yes');\n",
                )
                .unwrap();
                vec![local_node_action_step(
                    "failing-pre",
                    ".github/actions/failing-pre",
                )]
            }
            _ => unreachable!(),
        };
        let manifest = manifest_with_steps(steps, &env.mock_server.uri());
        let observed = if case == "cancelled" {
            let cancel_for_run = cancel.clone();
            let run =
                tokio::spawn(async move { env.run_observed(&manifest, cancel_for_run).await });
            let ready = wait_until(|| workspace_dir.join("cancel-ready").exists()).await;
            cancel.cancel();
            let result = tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("cancelled step did not finish")
                .unwrap()
                .unwrap();
            assert!(ready, "cancelled step never started");
            result
        } else {
            env.run_observed(&manifest, cancel).await.unwrap()
        };

        let expected = match case {
            "success" => JobConclusion::Succeeded,
            "cancelled" => JobConclusion::Cancelled,
            "failure" | "pre-error" => JobConclusion::Failed,
            _ => unreachable!(),
        };
        assert_eq!(observed.conclusion, expected, "case {case}");
        assert!(!observed.attempt_dir.exists(), "case {case}");
        assert!(neighbor_dir.exists(), "case {case}");
        if case == "pre-error" {
            assert!(workspace_dir.join("pre-ran").exists());
            assert!(!workspace_dir.join("main-ran").exists());
        }
    }

    neighbor.destroy().unwrap();
}

#[tokio::test]
async fn cancellation_records_descendant_survival_after_owner_cleanup() {
    let env = TestEnv::setup().await;
    let workspace_dir = env.workspace.workspace_dir().to_path_buf();
    let probe = tempfile::tempdir().unwrap();
    let pid_file = probe.path().join("descendant.pid");
    let config_file = probe.path().join("descendant-config");
    let observation_file = probe.path().join("survived-cleanup");
    let mut descendant = DescendantGuard::new(pid_file.clone());
    let step = script_step_env(
        "cancelled-descendant",
        r#"
            sh -c '
                trap "" HUP TERM
                exec </dev/null >/dev/null 2>&1
                printf "%s\n" "$$" > "$DESCENDANT_PID_FILE"
                printf "%s" "$DOCKER_CONFIG" > "$DESCENDANT_CONFIG_FILE"
                touch "$GITHUB_WORKSPACE/cancel-ready"
                while [ -d "$DOCKER_CONFIG" ]; do sleep 0.01; done
                printf "survived-cleanup" > "$DESCENDANT_OBSERVATION_FILE"
                while :; do :; done
            ' &
            wait
        "#,
        HashMap::from([
            (
                "DESCENDANT_PID_FILE".into(),
                pid_file.to_string_lossy().into_owned(),
            ),
            (
                "DESCENDANT_CONFIG_FILE".into(),
                config_file.to_string_lossy().into_owned(),
            ),
            (
                "DESCENDANT_OBSERVATION_FILE".into(),
                observation_file.to_string_lossy().into_owned(),
            ),
        ]),
    );
    let manifest = manifest_with_steps(vec![step], &env.mock_server.uri());
    let cancel = CancellationToken::new();
    let cancel_for_run = cancel.clone();
    let run = tokio::spawn(async move {
        let result = env.run_observed(&manifest, cancel_for_run).await;
        (env, result)
    });
    let ready = wait_until(|| workspace_dir.join("cancel-ready").exists()).await;
    cancel.cancel();

    let (_env, observed) = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("cancelled descendant probe did not finish")
        .unwrap();
    let observed = observed.unwrap();

    assert!(ready, "descendant probe never started");
    assert_eq!(observed.conclusion, JobConclusion::Cancelled);
    assert!(
        !observed.attempt_dir.exists(),
        "job-owned attempt directory survived cancellation cleanup"
    );
    let recorded = wait_until(|| observation_file.exists()).await;
    assert!(recorded, "descendant did not observe owner cleanup");
    assert_eq!(
        Path::new(&std::fs::read_to_string(config_file).unwrap()),
        observed.docker_config_dir
    );
    assert!(
        descendant.is_alive(),
        "descendant exited before observation"
    );
    descendant.stop().unwrap();
}

#[tokio::test]
async fn step_env_override_fails_before_spawn() {
    let mut env = TestEnv::setup().await;
    write_bash_probe(&env.workspace);
    let spy = spy_on_step_logs(&env.mock_server).await;
    let step = script_step_env(
        "override",
        "touch spawned",
        HashMap::from([("DOCKER_CONFIG".into(), "/shared/.docker".into())]),
    );
    let manifest = manifest_with_results_endpoint(vec![step], &env.mock_server.uri());
    env.configure_from_manifest(&manifest);

    let result = env.run(&manifest).await.unwrap();

    assert_eq!(result.0, JobConclusion::Failed);
    assert_bash_not_started(&env.workspace, "override");
    assert!(!env.workspace.workspace_dir().join("spawned").exists());
    assert_reserved_override_diagnostic(&spy);
}

#[tokio::test]
async fn implicit_default_credential_helper_fails_before_spawn() {
    let mut env = TestEnv::setup().await;
    let probe_bin = write_bash_probe(&env.workspace);
    let helper = probe_bin.join("docker-credential-pass");
    std::fs::write(&helper, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let spy = spy_on_step_logs(&env.mock_server).await;
    let step = script_step("helper-capability", "touch helper-capability-ran");
    let manifest = manifest_with_results_endpoint(vec![step], &env.mock_server.uri());
    env.configure_from_manifest(&manifest);

    let result = env.run(&manifest).await.unwrap();

    assert_eq!(result.0, JobConclusion::Failed);
    assert_bash_not_started(&env.workspace, "helper-capability");
    assert!(
        !env.workspace
            .workspace_dir()
            .join("helper-capability-ran")
            .exists()
    );
    let logs = spy.content.lock().unwrap();
    assert!(logs.contains("reserved-host-capability"));
    assert!(logs.contains("docker-credential-pass"));
}

#[tokio::test]
async fn github_env_override_fails_before_next_spawn() {
    let mut env = TestEnv::setup().await;
    write_bash_probe(&env.workspace);
    let spy = spy_on_step_logs(&env.mock_server).await;
    let writer = script_step(
        "write",
        r#"touch "$GITHUB_WORKSPACE/github-env-writer-ran"; echo 'DOCKER_CONFIG=/shared/.docker' >> "$GITHUB_ENV""#,
    );
    let affected = script_step("affected", "touch affected-step-ran");
    let manifest = manifest_with_results_endpoint(vec![writer, affected], &env.mock_server.uri());
    env.configure_from_manifest(&manifest);

    let result = env.run(&manifest).await.unwrap();

    assert_eq!(result.0, JobConclusion::Failed);
    assert!(
        env.workspace
            .workspace_dir()
            .join("github-env-writer-ran")
            .exists(),
        "writer marker missing; spawns: {}; logs: {}",
        bash_spawn_log(&env.workspace),
        spy.content.lock().unwrap()
    );
    assert_bash_started(&env.workspace, "write");
    assert_bash_not_started(&env.workspace, "affected");
    assert!(
        !env.workspace
            .workspace_dir()
            .join("affected-step-ran")
            .exists()
    );
    assert_reserved_override_diagnostic(&spy);
}

#[tokio::test]
async fn matching_step_environment_is_allowed() {
    let env = TestEnv::setup().await;
    write_bash_probe(&env.workspace);
    let step = script_step_env(
        "matching",
        r#"test -f "$DOCKER_CONFIG/config.json""#,
        HashMap::from([("DOCKER_CONFIG".into(), "${{ env.DOCKER_CONFIG }}".into())]),
    );
    let manifest = manifest_with_steps(vec![step], &env.mock_server.uri());

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
    assert_bash_started(&env.workspace, "matching");
}

#[tokio::test]
async fn matching_github_env_is_allowed() {
    let env = TestEnv::setup().await;
    write_bash_probe(&env.workspace);
    let writer = script_step(
        "write",
        r#"printf 'DOCKER_CONFIG=%s\n' "$DOCKER_CONFIG" >> "$GITHUB_ENV""#,
    );
    let affected = script_step("affected", r#"test -f "$DOCKER_CONFIG/config.json""#);
    let manifest = manifest_with_steps(vec![writer, affected], &env.mock_server.uri());

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
    assert_bash_started(&env.workspace, "write");
    assert_bash_started(&env.workspace, "affected");
}

#[tokio::test]
async fn legacy_set_env_override_fails_before_next_spawn() {
    let mut env = TestEnv::setup().await;
    write_bash_probe(&env.workspace);
    let spy = spy_on_step_logs(&env.mock_server).await;
    let writer = script_step(
        "write",
        "touch \"$GITHUB_WORKSPACE/legacy-writer-ran\"; echo '::set-env name=DOCKER_CONFIG::/shared/.docker'",
    );
    let affected = script_step("affected", "touch legacy-affected-step-ran");
    let manifest = manifest_with_results_endpoint(vec![writer, affected], &env.mock_server.uri());
    env.configure_from_manifest(&manifest);

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Failed);
    assert!(
        env.workspace
            .workspace_dir()
            .join("legacy-writer-ran")
            .exists()
    );
    assert_bash_started(&env.workspace, "write");
    assert_bash_not_started(&env.workspace, "affected");
    assert!(
        !env.workspace
            .workspace_dir()
            .join("legacy-affected-step-ran")
            .exists()
    );
    assert_reserved_override_diagnostic(&spy);
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

#[test]
fn rootless_operator_link_targets_existing_readme_heading() {
    let operator_docs = include_str!("../docs/job-docker-config.md");
    let readme = include_str!("../README.md");

    assert!(operator_docs.contains("(../README.md#rootless-docker-alternative)"));
    assert!(readme.contains("### Rootless Docker alternative"));
}
