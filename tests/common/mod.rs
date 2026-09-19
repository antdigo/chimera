#![allow(dead_code)]

pub mod docker_registry;
pub mod pinned_action;

use std::collections::HashMap;
use std::sync::Arc;

use chimera::docker::build::{DockerActionBuilder, RegistryAuth};
use chimera::docker::client as docker_client;
use chimera::docker::container::{JobContainerSpec, ServiceContainerSpec};
use chimera::docker::resources::{JobDockerResources, SetupParams};
use chimera::github::auth::TokenManager;
use chimera::job::action::ActionCache;
use chimera::job::client::{JobClient, JobConclusion};
use chimera::job::docker_config::JobResourceRoot;
use chimera::job::execute::{JobExecutionContext, run_all_steps};
use chimera::job::schema::JobManifest;
use chimera::job::workspace::Workspace;
use chimera::runner::env::{build_base_env, build_container_env};

use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The result of an execution after its per-job Docker configuration was cleaned up.
pub struct ObservedRun {
    pub conclusion: JobConclusion,
    pub outputs: HashMap<String, String>,
    pub docker_config_dir: std::path::PathBuf,
    pub attempt_dir: std::path::PathBuf,
}

/// Everything needed to run integration tests against the execution engine.
pub struct TestEnv {
    pub workspace: Workspace,
    pub job_client: Arc<JobClient>,
    pub mock_server: MockServer,
    pub tmp: tempfile::TempDir,
    pub job_resources: JobResourceRoot,
    actions_dir: std::path::PathBuf,
    docker_action_builder: Arc<DockerActionBuilder>,
}

impl TestEnv {
    pub async fn setup() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let job_resources = JobResourceRoot::prepare(&tmp.path().join("job-resources")).unwrap();
        Self::setup_with_tmp(tmp, job_resources).await
    }

    pub async fn setup_with_job_resources(job_resources: JobResourceRoot) -> Self {
        Self::setup_with_tmp(tempfile::tempdir().unwrap(), job_resources).await
    }

    async fn setup_with_tmp(tmp: tempfile::TempDir, job_resources: JobResourceRoot) -> Self {
        let work_dir = tmp.path().join("work");
        let tmp_dir = tmp.path().join("tmp");
        let tool_cache = tmp.path().join("tool-cache");
        let actions_dir = tmp.path().join("actions");
        let workspace = Workspace::create(
            &work_dir,
            &tmp_dir,
            &tool_cache,
            "test-runner",
            "owner/repo",
        )
        .unwrap();
        let mock_server = MockServer::start().await;
        mount_default_mocks(&mock_server).await;
        let job_client = create_job_client(&mock_server).await;

        Self {
            workspace,
            job_client,
            mock_server,
            tmp,
            job_resources,
            docker_action_builder: Arc::new(DockerActionBuilder::new()),
            actions_dir,
        }
    }

    pub fn actions_dir(&self) -> &std::path::Path {
        &self.actions_dir
    }

    /// Point the client at the manifest's Results endpoint. Without this a run
    /// takes the legacy VSS path and never touches the blob APIs.
    pub fn configure_from_manifest(&mut self, manifest: &JobManifest) {
        Arc::get_mut(&mut self.job_client)
            .expect("job client already shared")
            .configure_from_manifest(manifest)
            .unwrap();
    }

    /// Run a manifest in host mode and retain the paths used during execution.
    pub async fn run_observed(
        &self,
        manifest: &JobManifest,
        cancel_token: CancellationToken,
    ) -> anyhow::Result<ObservedRun> {
        let node_runtimes = chimera::node::NodeRuntimes::single("node".into());
        self.run_observed_with_runtimes(manifest, cancel_token, &node_runtimes)
            .await
    }

    pub async fn run_observed_with_runtimes(
        &self,
        manifest: &JobManifest,
        cancel_token: CancellationToken,
        node_runtimes: &chimera::node::NodeRuntimes,
    ) -> anyhow::Result<ObservedRun> {
        self.run_observed_with_options(manifest, cancel_token, node_runtimes, "fake-token", None)
            .await
    }

    async fn run_observed_with_options(
        &self,
        manifest: &JobManifest,
        cancel_token: CancellationToken,
        node_runtimes: &chimera::node::NodeRuntimes,
        access_token: &str,
        registry_auth: Option<&RegistryAuth>,
    ) -> anyhow::Result<ObservedRun> {
        let mut docker_config = self.job_resources.create_docker_config()?;
        let docker_config_dir = docker_config.directory().to_path_buf();
        let attempt_dir = docker_config.attempt_dir().to_path_buf();
        let run_result =
            match build_base_env(manifest, &self.workspace, "test-runner", &docker_config) {
                Ok(base_env) => {
                    let action_cache =
                        ActionCache::new(self.actions_dir.clone(), reqwest::Client::new());
                    let execution = JobExecutionContext::new(&docker_config, None, node_runtimes);
                    run_all_steps(
                        manifest,
                        &self.job_client,
                        &self.workspace,
                        &base_env,
                        "test-runner",
                        &action_cache,
                        self.docker_action_builder.as_ref(),
                        registry_auth,
                        access_token,
                        cancel_token,
                        &execution,
                        None,
                    )
                    .await
                }
                Err(error) => Err(error),
            };
        let cleanup_result = docker_config.cleanup();

        let (conclusion, outputs) = match (run_result, cleanup_result) {
            (Ok(value), Ok(())) => value,
            (Err(run_error), Ok(())) => return Err(run_error),
            (Ok(_), Err(cleanup_error)) => return Err(cleanup_error.into()),
            (Err(run_error), Err(cleanup_error)) => {
                return Err(run_error.context(cleanup_error.to_string()));
            }
        };

        Ok(ObservedRun {
            conclusion,
            outputs,
            docker_config_dir,
            attempt_dir,
        })
    }

    /// Run a manifest in host mode and return (conclusion, outputs).
    pub async fn run(
        &self,
        manifest: &JobManifest,
    ) -> anyhow::Result<(JobConclusion, HashMap<String, String>)> {
        let observed = self
            .run_observed(manifest, CancellationToken::new())
            .await?;
        Ok((observed.conclusion, observed.outputs))
    }

    pub async fn run_with_cancel(
        &self,
        manifest: &JobManifest,
        cancel_token: CancellationToken,
    ) -> anyhow::Result<(JobConclusion, HashMap<String, String>)> {
        let observed = self
            .run_observed_with_options(
                manifest,
                cancel_token,
                &chimera::node::NodeRuntimes::single("node".into()),
                "fake-token",
                None,
            )
            .await?;
        Ok((observed.conclusion, observed.outputs))
    }

    pub async fn run_with_access_token(
        &self,
        manifest: &JobManifest,
        access_token: &str,
    ) -> anyhow::Result<(JobConclusion, HashMap<String, String>)> {
        let observed = self
            .run_observed_with_options(
                manifest,
                CancellationToken::new(),
                &chimera::node::NodeRuntimes::single("node".into()),
                access_token,
                None,
            )
            .await?;
        Ok((observed.conclusion, observed.outputs))
    }

    pub async fn run_with_registry_auth(
        &self,
        manifest: &JobManifest,
        registry_auth: &RegistryAuth,
    ) -> anyhow::Result<(JobConclusion, HashMap<String, String>)> {
        let observed = self
            .run_observed_with_options(
                manifest,
                CancellationToken::new(),
                &chimera::node::NodeRuntimes::single("node".into()),
                "fake-token",
                Some(registry_auth),
            )
            .await?;
        Ok((observed.conclusion, observed.outputs))
    }

    pub async fn uploaded_log_text(&self) -> String {
        self.uploaded_legacy_log_text().await
    }

    pub async fn uploaded_legacy_log_text(&self) -> String {
        self.mock_server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|request| {
                request.method.as_str() == "POST" && request.url.path().contains("/logs/")
            })
            .map(|request| String::from_utf8_lossy(&request.body).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub async fn uploaded_results_log_text(&self) -> String {
        self.mock_server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|request| request.method.as_str() == "PUT")
            .map(|request| String::from_utf8_lossy(&request.body).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Run a manifest in container mode with Docker resources.
    pub async fn run_with_docker(
        &self,
        manifest: &JobManifest,
        docker_resources: &JobDockerResources,
    ) -> anyhow::Result<(JobConclusion, HashMap<String, String>)> {
        let mut docker_config = self.job_resources.create_docker_config()?;
        let base_env = build_container_env(manifest, &self.workspace, "test-runner");
        let action_cache = ActionCache::new(self.actions_dir.clone(), reqwest::Client::new());
        let node_runtimes =
            chimera::node::NodeRuntimes::single(docker_resources.node_path(None).into());
        let execution =
            JobExecutionContext::new(&docker_config, Some(docker_resources), &node_runtimes);
        let run_result = run_all_steps(
            manifest,
            &self.job_client,
            &self.workspace,
            &base_env,
            "test-runner",
            &action_cache,
            self.docker_action_builder.as_ref(),
            None,
            "fake-token",
            CancellationToken::new(),
            &execution,
            None,
        )
        .await;
        let cleanup_result = docker_config.cleanup();

        match (run_result, cleanup_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(run_error), Ok(())) => Err(run_error),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error.into()),
            (Err(run_error), Err(cleanup_error)) => {
                Err(run_error.context(cleanup_error.to_string()))
            }
        }
    }
}

/// Set up Docker resources for a job. Returns resources that must be cleaned up.
pub async fn setup_docker(
    tmp: &tempfile::TempDir,
    workspace: &Workspace,
    job_container: Option<&JobContainerSpec>,
    services: &[ServiceContainerSpec],
) -> JobDockerResources {
    let docker = docker_client::connect(None).unwrap();
    docker_client::ping(&docker).await.unwrap();

    let job_id = uuid::Uuid::new_v4().to_string();
    let mut resources = JobDockerResources::new(docker);

    let workflow_files_path = workspace.workspace_dir().parent().unwrap();
    // Shared across tests on purpose: a per-test directory means re-downloading
    // every Node runtime for every container test. Concurrent downloads are safe —
    // they extract to a temp dir and rename into place.
    let externals_dir = std::env::temp_dir().join("chimera-test-externals");
    std::fs::create_dir_all(&externals_dir).unwrap();

    resources
        .setup(&SetupParams {
            runner_name: "test-runner",
            job_id: &job_id,
            job_container,
            services,
            workspace_host_path: workspace.workspace_dir(),
            workflow_files_host_path: workflow_files_path,
            runner_temp_host_path: workspace.runner_temp(),
            actions_host_path: &tmp.path().join("actions"),
            tool_cache_host_path: workspace.tool_cache(),
            externals_dir: &externals_dir,
        })
        .await
        .unwrap();

    resources
}

async fn mount_default_mocks(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path_regex("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 7200
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 1})))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs/\d+"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("PATCH"))
        .and(path_regex(
            r"/_apis/distributedtask/hubs/build/plans/.*/timelines/.*",
        ))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

/// One RSA keygen per test binary: 2048-bit generation costs up to a second on
/// CI hardware, and the mock OAuth endpoints accept any token, so tests never
/// need distinct keys. Each caller gets a clone, keeping key state private.
fn test_private_key() -> rsa::RsaPrivateKey {
    static KEY: std::sync::OnceLock<rsa::RsaPrivateKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap())
        .clone()
}

async fn create_job_client(mock_server: &MockServer) -> Arc<JobClient> {
    let private_key = test_private_key();
    let tm = Arc::new(TokenManager::new(
        reqwest::Client::new(),
        format!("{}/oauth2/token", mock_server.uri()),
        private_key,
        "test-client".into(),
    ));

    Arc::new(JobClient::new(
        reqwest::Client::new(),
        tm,
        mock_server.uri(),
        mock_server.uri(),
    ))
}

// ─── Manifest / Step builders ────────────────────────────────────────

pub fn local_action_step(
    id: &str,
    path: &str,
    inputs: HashMap<String, String>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "displayName": format!("Run {path}"),
        "reference": {
            "name": "",
            "type": "repository",
            "repositoryType": "self",
            "path": path
        },
        "inputs": inputs,
        "condition": null,
        "timeoutInMinutes": null,
        "continueOnError": false,
        "order": 1,
        "environment": null,
        "contextName": id
    })
}

pub fn manifest_with_steps(steps: Vec<serde_json::Value>, server_url: &str) -> JobManifest {
    manifest_with_steps_and_context(steps, server_url, serde_json::json!({}))
}

pub fn manifest_with_steps_and_context(
    steps: Vec<serde_json::Value>,
    server_url: &str,
    context_data: serde_json::Value,
) -> JobManifest {
    manifest_with_variables(steps, server_url, context_data, serde_json::json!({}))
}

/// Manifest carrying a Results endpoint, so a client configured from it uses the
/// Results API rather than the legacy VSS fallback.
pub fn manifest_with_results_endpoint(
    steps: Vec<serde_json::Value>,
    server_url: &str,
) -> JobManifest {
    manifest_with_variables(
        steps,
        server_url,
        serde_json::json!({}),
        serde_json::json!({
            "system.github.results_endpoint": { "value": server_url, "isSecret": false }
        }),
    )
}

pub fn manifest_with_variables(
    steps: Vec<serde_json::Value>,
    server_url: &str,
    context_data: serde_json::Value,
    variables: serde_json::Value,
) -> JobManifest {
    let manifest_json = serde_json::json!({
        "plan": { "planId": "p", "jobId": "j", "timelineId": "t" },
        "steps": steps,
        "variables": variables,
        "resources": {
            "endpoints": [{
                "name": "SystemVssConnection",
                "url": server_url,
                "authorization": {
                    "scheme": "OAuth",
                    "parameters": { "AccessToken": "test-access-token" }
                },
                "data": { "PipelinesServiceUrl": server_url }
            }]
        },
        "contextData": context_data,
        "jobContainer": null,
        "serviceContainers": null
    });
    serde_json::from_value(manifest_json).unwrap()
}

pub fn script_step(id: &str, script: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "displayName": format!("Run: {id}"),
        "reference": { "name": "script", "type": "script" },
        "inputs": { "script": script },
        "condition": null,
        "timeoutInMinutes": null,
        "continueOnError": false,
        "order": 1,
        "environment": null,
        "contextName": id
    })
}

/// A `run:` step with a `working-directory:`, which reaches the runner as the
/// step input `workingDirectory`.
pub fn script_step_in_dir(id: &str, script: &str, dir: &str) -> serde_json::Value {
    let mut step = script_step(id, script);
    step["inputs"]["workingDirectory"] = serde_json::json!(dir);
    step
}

pub fn script_step_continue(id: &str, script: &str) -> serde_json::Value {
    let mut step = script_step(id, script);
    step["continueOnError"] = serde_json::json!(true);
    step
}

pub fn script_step_if(id: &str, script: &str, condition: &str) -> serde_json::Value {
    let mut step = script_step(id, script);
    step["condition"] = serde_json::json!(condition);
    step
}

pub fn script_step_env(id: &str, script: &str, env: HashMap<String, String>) -> serde_json::Value {
    let mut step = script_step(id, script);
    step["environment"] = serde_json::to_value(env).unwrap();
    step
}

pub fn repository_action_step(id: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "displayName": format!("Run: {id}"),
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
