use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::{ChimeraPaths, RunnerCredentials, rsa_params_to_private_key};
use crate::daemon::{DaemonState, JobInfo, RunnerPhase};
use crate::docker::build::DockerActionBuilder;
use crate::docker::resources::{JobDockerResources, SetupParams};
use crate::github::RUNNER_VERSION;
use crate::github::auth::TokenManager;
use crate::github::broker::{BrokerClient, BrokerError, BrokerMessage, MessageType};
use crate::job::JobClient;
use crate::job::action::ActionCache;
use crate::job::client::JobConclusion;
use crate::job::docker_config::{
    JobDockerConfig, JobDockerConfigError, JobResourceCleanupFatalError, JobResourceRoot,
};
use crate::job::execute::{JobExecutionContext, run_all_steps};
use crate::job::live_feed::LiveFeed;
use crate::job::schema::JobManifest;
use crate::job::workspace::Workspace;

use super::cancel::spawn_cancel_poller;
use super::env::{build_base_env, build_container_env};
use super::report::{outputs_to_variable_values, report_setup_failure};

const CONTROL_MSG_DELAY: Duration = Duration::from_millis(2000);

struct JobExecutionOutcome {
    conclusion: JobConclusion,
    outputs: HashMap<String, String>,
}

#[derive(Debug)]
struct CompletionPublicationError {
    source: anyhow::Error,
}

impl std::fmt::Display for CompletionPublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.source)
    }
}

impl std::error::Error for CompletionPublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn conclusion_after_cleanup_failure(conclusion: JobConclusion) -> JobConclusion {
    match conclusion {
        JobConclusion::Succeeded => JobConclusion::Failed,
        JobConclusion::Failed => JobConclusion::Failed,
        JobConclusion::Cancelled => JobConclusion::Cancelled,
    }
}

fn is_poisoned_job_resource_error(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<JobDockerConfigError>(),
        Some(JobDockerConfigError::PoisonedRoot { .. })
    )
}

/// A job error the runner must not recover from by polling again: the job
/// resource root is known-untrustworthy (poisoned) or a completion was already
/// published after a failed cleanup. Classified by construction, not by the
/// separate poisoning side effect.
fn job_execution_error_is_terminal(error: &anyhow::Error) -> bool {
    is_poisoned_job_resource_error(error) || is_job_resource_cleanup_fatal(error)
}

fn is_job_resource_cleanup_fatal(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<JobResourceCleanupFatalError>()
        .is_some()
}

async fn finish_job(
    job_client: &Arc<JobClient>,
    manifest: &JobManifest,
    execution_result: Result<JobExecutionOutcome>,
    cleanup_result: std::result::Result<(), JobDockerConfigError>,
) -> Result<()> {
    let mut outcome = match execution_result {
        Ok(outcome) => outcome,
        Err(execution_error) => {
            return match cleanup_result {
                Ok(()) => Err(execution_error),
                Err(cleanup_error) => Err(execution_error.context(cleanup_error.to_string())),
            };
        }
    };

    let cleanup_error = cleanup_result.err();
    if cleanup_error.is_some() {
        outcome.conclusion = conclusion_after_cleanup_failure(outcome.conclusion);
    }

    let outputs = outputs_to_variable_values(&outcome.outputs);
    job_client
        .complete_job(
            &manifest.plan.plan_id,
            &manifest.plan.job_id,
            outcome.conclusion,
            &outputs,
            &[],
        )
        .await
        .context("completing job")
        .map_err(|source| anyhow::Error::new(CompletionPublicationError { source }))?;

    match cleanup_error {
        Some(source) => Err(anyhow::Error::new(JobResourceCleanupFatalError { source })),
        None => Ok(()),
    }
}

pub struct Runner {
    pub(super) name: String,
    pub(super) credentials: RunnerCredentials,
    pub(super) paths: ChimeraPaths,
    pub(super) state: Option<Arc<DaemonState>>,
    pub(super) job_resources: JobResourceRoot,
    pub(super) cache_port: u16,
    pub(super) docker_action_builder: Arc<DockerActionBuilder>,
}

impl Runner {
    pub fn with_state(
        name: String,
        credentials: RunnerCredentials,
        paths: ChimeraPaths,
        state: Arc<DaemonState>,
        job_resources: JobResourceRoot,
        cache_port: u16,
        docker_action_builder: Arc<DockerActionBuilder>,
    ) -> Self {
        Self {
            name,
            credentials,
            paths,
            state: Some(state),
            job_resources,
            cache_port,
            docker_action_builder,
        }
    }

    async fn report_phase(&self, phase: RunnerPhase) {
        if let Some(ref state) = self.state {
            state.set_phase(&self.name, phase).await;
        }
    }

    async fn report_running(&self, repo: &str, job_id: &str) {
        if let Some(ref state) = self.state {
            state
                .set_running(
                    &self.name,
                    JobInfo {
                        repo: repo.to_string(),
                        job_id: job_id.to_string(),
                        started_at: Utc::now(),
                    },
                )
                .await;
        }
    }

    pub async fn start(self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        info!(runner = %self.name, "starting runner");
        debug!(job_resource_root = %self.job_resources.path().display(), "using prepared job resource root");

        let private_key = rsa_params_to_private_key(&self.credentials.rsa_params)
            .context("reconstructing RSA private key")?;

        let client = reqwest::Client::builder()
            .user_agent(format!("chimera/{RUNNER_VERSION}"))
            // Bound connection setup well below the 60s long-poll deadline so
            // a stalled connect surfaces as a connection error (warn + backoff)
            // instead of expiring as a quiet long-poll timeout.
            .connect_timeout(Duration::from_secs(30))
            .build()
            .context("building HTTP client")?;

        let token_manager = Arc::new(TokenManager::new(
            client.clone(),
            self.credentials.oauth.authorization_url.clone(),
            private_key,
            self.credentials.oauth.client_id.clone(),
        ));

        token_manager
            .get_token()
            .await
            .context("getting initial OAuth token")?;
        info!("authenticated successfully");

        let broker = BrokerClient::connect(
            client.clone(),
            &self.credentials.info.server_url_v2,
            token_manager.clone(),
            self.credentials.info.agent_id,
            &self.credentials.info.agent_name,
        )
        .await
        .context("creating broker session")?;

        info!(session_id = %broker.session_id(), "broker session created");
        self.report_phase(RunnerPhase::Idle).await;
        info!("entering poll loop, waiting for jobs...");
        let mut terminal_error = None;

        loop {
            let result = self.poll_loop(&broker, &mut shutdown_rx).await;

            match result {
                Ok(Some(msg)) => {
                    info!(
                        message_id = msg.message_id,
                        message_type = %msg.message_type,
                        "received job message"
                    );

                    if let Err(error) = self
                        .handle_job_message(&msg, &broker, &client, token_manager.clone())
                        .await
                    {
                        terminal_error = Some(error);
                        break;
                    }
                    self.report_phase(RunnerPhase::Idle).await;

                    if *shutdown_rx.borrow() {
                        self.report_phase(RunnerPhase::Stopping).await;
                        info!("shutdown after job completion");
                        break;
                    }
                }
                Ok(None) => {
                    self.report_phase(RunnerPhase::Stopping).await;
                    info!("poll loop exited (shutdown)");
                    break;
                }
                Err(error) => {
                    error!(error = %error, "poll loop error");
                    if is_poisoned_job_resource_error(&error) {
                        terminal_error = Some(error);
                    }
                    break;
                }
            }
        }

        if let Err(e) = broker.disconnect().await {
            error!(error = %e, "failed to delete session");
        } else {
            info!("session deleted");
        }

        match terminal_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn handle_job_message(
        &self,
        msg: &BrokerMessage,
        broker: &BrokerClient,
        client: &reqwest::Client,
        token_manager: Arc<TokenManager>,
    ) -> Result<()> {
        let (runner_request_id, run_service_url) = match msg.parse_job_request() {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "failed to parse job request");
                return Ok(());
            }
        };

        debug!(%runner_request_id, %run_service_url, "parsed job request");

        if let Err(e) = broker.ack_job(&runner_request_id).await {
            error!(error = %e, "failed to ack job");
        }

        let cancel_token = CancellationToken::new();
        let poller_handle = spawn_cancel_poller(broker, cancel_token.clone());

        let result = self
            .execute_job(
                client,
                token_manager,
                &runner_request_id,
                &run_service_url,
                cancel_token.clone(),
            )
            .await;

        // Stop the cancel poller regardless of how the job ended
        cancel_token.cancel();
        let _ = poller_handle.await;

        if let Err(error) = result {
            if job_execution_error_is_terminal(&error) {
                // Correct by construction, not by the poisoning side effect:
                // the runner stops on the fatal marker itself.
                return Err(error);
            }
            error!(error = %error, cause = ?error, "job execution failed");
        }

        self.job_resources.ensure_healthy()?;
        Ok(())
    }

    async fn execute_job(
        &self,
        client: &reqwest::Client,
        token_manager: Arc<TokenManager>,
        runner_request_id: &str,
        run_service_url: &str,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        info!(runner_request_id, run_service_url, "acquiring job");

        let mut job_client = JobClient::new(
            client.clone(),
            token_manager,
            run_service_url.to_string(),
            self.credentials.info.server_url.clone(),
        );

        let manifest = job_client
            .acquire_job(runner_request_id)
            .await
            .context("acquiring job manifest")?;

        let var_names: Vec<&str> = manifest.variables.keys().map(|s| s.as_str()).collect();
        let container_image = manifest
            .job_container
            .as_ref()
            .map(|c| c.image.as_str())
            .unwrap_or("none");
        info!(
            plan_id = %manifest.plan.plan_id,
            job_id = %manifest.plan.job_id,
            steps = manifest.steps.len(),
            has_container = manifest.has_container(),
            container_image,
            has_services = manifest.has_services(),
            mask_regexes = manifest.mask_regexes().len(),
            files = ?manifest.file_table(),
            variables = ?var_names,
            "job acquired"
        );

        for ep in &manifest.resources.endpoints {
            let data_keys: Vec<&str> = ep.data.keys().map(|s| s.as_str()).collect();
            debug!(endpoint = %ep.name, url = %ep.url, data_keys = ?data_keys, "manifest endpoint");
        }

        job_client
            .configure_from_manifest(&manifest)
            .context("configuring job client from manifest")?;

        let repo = manifest
            .repository()
            .unwrap_or_else(|_| "unknown/repo".into());

        self.report_running(&repo, &manifest.plan.job_id).await;

        let job_client = Arc::new(job_client);
        let result = self
            .run_job(&manifest, &job_client, client, cancel_token, &repo)
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(error) if error.downcast_ref::<CompletionPublicationError>().is_some() => {
                error!(error = %error, cause = ?error, "job completion request failed; not retrying completion");
                Err(error)
            }
            Err(error)
                if error
                    .downcast_ref::<JobResourceCleanupFatalError>()
                    .is_some() =>
            {
                error!(error = %error, cause = ?error, "job completed after cleanup failure; stopping runner");
                Err(error)
            }
            Err(error) => {
                error!(error = %error, cause = ?error, "job failed before completion, reporting failure to GitHub");
                if let Err(report_error) =
                    report_setup_failure(&job_client, &manifest, &error).await
                {
                    error!(error = %report_error, "failed to report setup failure to GitHub");
                }
                Err(error)
            }
        }
    }

    async fn run_job(
        &self,
        manifest: &JobManifest,
        job_client: &Arc<JobClient>,
        client: &reqwest::Client,
        cancel_token: CancellationToken,
        repo: &str,
    ) -> Result<()> {
        let mut docker_config = self
            .job_resources
            .create_docker_config()
            .context("creating per-job Docker config")?;
        let attempt_id = docker_config.attempt_id();
        info!(%attempt_id, "created job Docker config");

        let execution_result = self
            .run_job_body(
                manifest,
                job_client,
                client,
                cancel_token,
                repo,
                &docker_config,
            )
            .await;

        let cleanup_result = docker_config.cleanup();
        match &cleanup_result {
            Ok(()) => info!(%attempt_id, "cleaned job Docker config"),
            Err(cleanup_error) => error!(
                category = "job-resource-cleanup",
                %attempt_id,
                error = %cleanup_error,
                "job Docker config cleanup failed"
            ),
        }

        finish_job(job_client, manifest, execution_result, cleanup_result).await
    }

    async fn run_job_body(
        &self,
        manifest: &JobManifest,
        job_client: &Arc<JobClient>,
        client: &reqwest::Client,
        cancel_token: CancellationToken,
        repo: &str,
        docker_config: &JobDockerConfig,
    ) -> Result<JobExecutionOutcome> {
        let workspace = Workspace::create(
            &self.paths.work_dir(),
            &self.paths.tmp_dir(),
            &self.paths.tool_cache_dir(),
            &self.name,
            repo,
        )
        .context("creating workspace")?;
        let mut docker_resources = None;

        let execution_result = async {
            let event_data = manifest
                .context_data
                .get("github")
                .and_then(|github| github.get("event"))
                .cloned()
                .unwrap_or_default();
            workspace
                .write_event_file(&event_data)
                .context("writing event payload")?;

            let node_runtimes = crate::node::ensure_node(&self.paths.externals_dir())
                .await
                .context("ensuring node binaries")?;

            if manifest.has_container() || manifest.has_services() {
                let docker = crate::docker::client::connect(None)?;
                crate::docker::client::ping(&docker).await?;
                let mut resources = JobDockerResources::new(docker);
                let services = manifest.service_containers.as_deref().unwrap_or_default();
                let workflow_files_path = workspace
                    .workspace_dir()
                    .parent()
                    .context("workspace has no parent")?;

                if let Err(setup_error) = resources
                    .setup(&SetupParams {
                        runner_name: &self.name,
                        job_id: &manifest.plan.job_id,
                        job_container: manifest.job_container.as_ref(),
                        services,
                        workspace_host_path: workspace.workspace_dir(),
                        workflow_files_host_path: workflow_files_path,
                        runner_temp_host_path: workspace.runner_temp(),
                        actions_host_path: &self.paths.actions_dir(),
                        tool_cache_host_path: workspace.tool_cache(),
                        externals_dir: &self.paths.externals_dir(),
                    })
                    .await
                {
                    resources.cleanup().await;
                    return Err(setup_error.context("setting up Docker resources"));
                }
                docker_resources = Some(resources);
            }

            self.run_job_steps(
                manifest,
                job_client,
                client,
                cancel_token,
                repo,
                &workspace,
                &node_runtimes,
                &mut docker_resources,
                docker_config,
            )
            .await
        }
        .await;

        if let Some(resources) = docker_resources.as_mut() {
            resources.cleanup().await;
        }
        if let Err(cleanup_error) = workspace.cleanup() {
            warn!(error = %cleanup_error, "workspace cleanup failed");
        }

        execution_result
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_job_steps(
        &self,
        manifest: &JobManifest,
        job_client: &Arc<JobClient>,
        client: &reqwest::Client,
        cancel_token: CancellationToken,
        repo: &str,
        workspace: &Workspace,
        node_runtimes: &crate::node::NodeRuntimes,
        docker_resources: &mut Option<JobDockerResources>,
        docker_config: &JobDockerConfig,
    ) -> Result<JobExecutionOutcome> {
        // Choose env builder based on execution mode
        let mut base_env = if manifest.has_container() {
            build_container_env(manifest, workspace, &self.name)
        } else {
            build_base_env(manifest, workspace, &self.name, docker_config)?
        };

        // Merge the Docker image's default PATH so tools installed via ENV in
        // the Dockerfile (e.g. rust:1-bookworm sets /usr/local/cargo/bin) are available.
        if let Some(resources) = docker_resources.as_ref() {
            if let Some(image_path) = resources.image_env().get("PATH") {
                let chimera_default =
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
                if image_path != chimera_default {
                    base_env.insert("PATH".into(), image_path.clone());
                }
            }

            // Inject service container addresses into environment for discoverability
            for (alias, ip) in resources.service_addresses() {
                let env_key = format!("SERVICE_{}_HOST", alias.to_uppercase().replace('-', "_"));
                base_env.insert(env_key, ip.clone());
            }
        }

        // Inject ACTIONS_CACHE_URL for actions/cache support, with scope prefix
        let git_ref = manifest
            .context_data
            .get("github")
            .and_then(|g| g.get("ref"))
            .and_then(|v| v.as_str())
            .unwrap_or("refs/heads/main");
        let default_branch = manifest
            .context_data
            .get("github")
            .and_then(|g| g.get("event"))
            .and_then(|e| e.get("repository"))
            .and_then(|r| r.get("default_branch"))
            .and_then(|v| v.as_str())
            .unwrap_or("main");
        let default_ref = format!("refs/heads/{default_branch}");

        let scope_repo = crate::cache::server::encode_scope(repo);
        let scope_ref = crate::cache::server::encode_scope(git_ref);
        let scope_default = crate::cache::server::encode_scope(&default_ref);

        if manifest.has_container() {
            // On macOS, Docker Desktop runs in a Linux VM so the bridge gateway IP
            // doesn't route to the macOS host. Use host.docker.internal instead.
            let cache_host = if cfg!(target_os = "macos") {
                "host.docker.internal".to_string()
            } else {
                docker_resources
                    .as_ref()
                    .and_then(|r| r.host_gateway_ip())
                    .unwrap_or("172.17.0.1")
                    .to_string()
            };
            base_env.insert(
                "ACTIONS_CACHE_URL".into(),
                format!(
                    "http://{cache_host}:{}/cache/{scope_repo}/{scope_ref}/{scope_default}/",
                    self.cache_port
                ),
            );
        } else {
            base_env.insert(
                "ACTIONS_CACHE_URL".into(),
                format!(
                    "http://localhost:{}/cache/{scope_repo}/{scope_ref}/{scope_default}/",
                    self.cache_port
                ),
            );
        }

        let action_cache = ActionCache::new(self.paths.actions_dir(), client.clone());
        let github_token = manifest.github_token().unwrap_or("").to_string();

        // Connect to the WebSocket live console feed for real-time log streaming
        let live_feed = match (manifest.feed_stream_url(), manifest.access_token()) {
            (Some(feed_url), Ok(token)) => {
                debug!("connecting live console feed");
                LiveFeed::connect(feed_url, token).await
            }
            _ => None,
        };

        // Start heartbeat
        let (heartbeat_handle, heartbeat_cancel) =
            job_client.start_heartbeat(manifest.plan.plan_id.clone(), manifest.plan.job_id.clone());

        let execution =
            JobExecutionContext::new(docker_config, docker_resources.as_ref(), node_runtimes);
        let job_result = run_all_steps(
            manifest,
            job_client,
            workspace,
            &base_env,
            &self.name,
            &action_cache,
            self.docker_action_builder.as_ref(),
            // CHM-03 will provide job-owned registry auth; never inherit process credentials.
            None,
            &github_token,
            cancel_token.clone(),
            &execution,
            live_feed.as_ref().map(|f| f.sender()),
        )
        .await;

        // Close the live feed so remaining lines are flushed over WebSocket.
        if let Some(feed) = live_feed {
            feed.close().await;
        }

        heartbeat_cancel.cancel();
        let heartbeat_result = heartbeat_handle.await.context("heartbeat task panicked");
        let job_result = job_result.context("running job steps");
        let (mut conclusion, outputs) = match (job_result, heartbeat_result) {
            (Ok(outcome), Ok(())) => outcome,
            (Err(job_error), Ok(())) => return Err(job_error),
            (Ok(_), Err(heartbeat_error)) => return Err(heartbeat_error),
            (Err(job_error), Err(heartbeat_error)) => {
                return Err(job_error.context(heartbeat_error.to_string()));
            }
        };

        if cancel_token.is_cancelled() && conclusion != JobConclusion::Cancelled {
            conclusion = JobConclusion::Cancelled;
        }

        info!(conclusion = %conclusion, "job steps completed");
        Ok(JobExecutionOutcome {
            conclusion,
            outputs,
        })
    }

    pub(super) async fn poll_loop(
        &self,
        broker: &BrokerClient,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<Option<BrokerMessage>> {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);
        let mut poisoned_rx = self.job_resources.poisoned_receiver();
        // Set when the previous iteration handled a 401 by refreshing the
        // token. A 401 on the very next poll means the fresh token is also
        // rejected (e.g. the registration was revoked) and must not loop.
        let mut token_just_refreshed = false;

        loop {
            self.job_resources.ensure_healthy()?;
            if *shutdown_rx.borrow() {
                info!("shutdown signal received, exiting poll loop");
                return Ok(None);
            }

            let poll_result = tokio::select! {
                result = broker.poll_message() => result,
                _ = shutdown_rx.changed() => {
                    info!("shutdown signal received, cancelling poll");
                    return Ok(None);
                }
                _ = poisoned_rx.changed() => {
                    self.job_resources.ensure_healthy()?;
                    continue;
                }
            };

            match poll_result {
                Ok(Some(msg)) => {
                    // Any successful poll proves the token still works.
                    token_just_refreshed = false;

                    if msg.message_type != MessageType::RunnerJobRequest {
                        debug!(
                            message_id = msg.message_id,
                            message_type = %msg.message_type,
                            "received control message, skipping"
                        );
                        // Control messages (JobCancellation, BrokerMigration, etc)
                        // are ephemeral — don't try to delete them. Brief pause to
                        // avoid tight-looping when broker keeps resending.
                        let delay = if cfg!(test) {
                            Duration::from_millis(10)
                        } else {
                            CONTROL_MSG_DELAY
                        };
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    // V2 broker: job messages are acknowledged via /acknowledge,
                    // not deleted. No delete needed here.
                    info!(
                        message_id = msg.message_id,
                        message_type = %msg.message_type,
                        "received job message"
                    );
                    return Ok(Some(msg));
                }
                Ok(None) => {
                    backoff = Duration::from_secs(1);
                    token_just_refreshed = false;
                    continue;
                }
                Err(e) => {
                    // The broker holding an idle long-poll open past the client
                    // timeout is a normal empty cycle, not a failure: repoll
                    // immediately without warning or backoff.
                    if e.downcast_ref::<BrokerError>()
                        .is_some_and(|be| matches!(be, BrokerError::Timeout))
                    {
                        debug!("long-poll window expired without a message");
                        backoff = Duration::from_secs(1);
                        token_just_refreshed = false;
                        continue;
                    }

                    if e.downcast_ref::<BrokerError>()
                        .is_some_and(|be| matches!(be, BrokerError::Unauthorized))
                    {
                        if token_just_refreshed {
                            warn!("still unauthorized after token refresh");
                            return Err(e);
                        }
                        warn!("got 401, refreshing token");
                        broker.token_manager().invalidate().await;
                        token_just_refreshed = true;
                        continue;
                    }

                    token_just_refreshed = false;
                    warn!(error = %e, backoff_secs = backoff.as_secs(), "poll error, backing off");

                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown_rx.changed() => {
                            return Ok(None);
                        }
                        _ = poisoned_rx.changed() => {
                            self.job_resources.ensure_healthy()?;
                            continue;
                        }
                    }

                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "instance_test.rs"]
mod instance_test;
