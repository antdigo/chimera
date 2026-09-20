use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::panic::{AssertUnwindSafe, resume_unwind};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use futures::FutureExt;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::cache::auth::{CacheAuthority, CacheScope, CapabilityHandle, JobCapabilityClaims};
use crate::config::{ChimeraPaths, RunnerCredentials, rsa_params_to_private_key};
use crate::daemon::{DaemonState, JobInfo, RunnerPhase};
use crate::docker::build::DockerActionBuilder;
use crate::docker::resources::{JobDockerResources, SetupParams};
use crate::github::RUNNER_VERSION;
use crate::github::auth::{AuthError, TokenManager};
use crate::github::broker::{AgentStatus, BrokerClient, BrokerError, BrokerMessage, MessageType};
use crate::job::JobClient;
use crate::job::action::ActionCache;
use crate::job::client::JobConclusion;
use crate::job::execute::{JobExecutionContext, run_all_steps_with_masker};
use crate::job::execution_domain::{
    DomainPermit, ExecutionDomain, ExecutionDomainCleanupFatalError, ExecutionDomainError,
    ExecutionDomainRoot,
};
use crate::job::live_feed::LiveFeed;
use crate::job::schema::JobManifest;
use crate::job::secret_masker::{SecretMasker, SharedSecretMasker};
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
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::PoisonedRoot { .. })
    )
}

/// A job error the runner must not recover from by polling again: the job
/// resource root is known-untrustworthy (poisoned) or completion was attempted
/// after a failed cleanup. Classified by construction, not by the
/// separate poisoning side effect.
fn job_execution_error_is_terminal(error: &anyhow::Error) -> bool {
    is_poisoned_job_resource_error(error) || is_job_resource_cleanup_fatal(error)
}

fn is_job_resource_cleanup_fatal(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ExecutionDomainCleanupFatalError>()
        .is_some()
}

/// Startup failures that plausibly heal on their own: transport errors and
/// server-side trouble (5xx, 429) on either the token endpoint or the broker.
/// A malformed success body is treated as transient on both endpoints too —
/// a truncated 200 through flaky edge infra is a blip, and permanent
/// misconfig reliably shows up as 4xx or a request-builder error instead.
/// Those — auth rejections, malformed URLs, local setup failures — are
/// permanent and must leave the runner Stopped instead of retrying forever.
fn startup_error_is_transient(error: &anyhow::Error) -> bool {
    if let Some(auth_error) = error.downcast_ref::<AuthError>() {
        return match auth_error {
            AuthError::InvalidEndpoint(_) => false,
            AuthError::Send(_) | AuthError::BadResponse(_) => true,
            AuthError::Status { status, .. } => status.is_server_error() || status.as_u16() == 429,
        };
    }
    matches!(
        error.downcast_ref::<BrokerError>(),
        Some(BrokerError::ServerError { .. })
            | Some(BrokerError::Connection(_))
            | Some(BrokerError::BadResponse(_))
    )
}

fn cache_scope_for_job(manifest: &JobManifest, repo: &str) -> CacheScope {
    let git_ref = manifest
        .context_data
        .get("github")
        .and_then(|github| github.get("ref"))
        .and_then(|value| value.as_str())
        .unwrap_or("refs/heads/main");
    let default_branch = manifest
        .context_data
        .get("github")
        .and_then(|github| github.get("event"))
        .and_then(|event| event.get("repository"))
        .and_then(|repository| repository.get("default_branch"))
        .and_then(|value| value.as_str())
        .unwrap_or("main");
    let default_ref = if default_branch.starts_with("refs/") {
        default_branch.to_string()
    } else {
        format!("refs/heads/{default_branch}")
    };

    CacheScope {
        repo: repo.to_string(),
        git_ref: git_ref.to_string(),
        default_ref,
    }
}

async fn register_job_cache_capability(
    authority: &CacheAuthority,
    manifest: &JobManifest,
    scope: CacheScope,
    issued_at: chrono::DateTime<Utc>,
) -> Result<CapabilityHandle> {
    authority
        .register_job(
            manifest
                .access_token()
                .context("reading cache runtime token")?,
            JobCapabilityClaims {
                scope,
                job_id: manifest.plan.job_id.clone(),
            },
            issued_at,
        )
        .await
        .context("registering cache capability")
}

struct JobCacheCapability {
    authority: Arc<CacheAuthority>,
    capability: CapabilityHandle,
    active: bool,
}

impl JobCacheCapability {
    fn new(authority: Arc<CacheAuthority>, capability: CapabilityHandle) -> Self {
        Self {
            authority,
            capability,
            active: true,
        }
    }

    async fn revoke(&mut self) {
        if self.active {
            self.authority.revoke(&self.capability).await;
            self.active = false;
        }
    }
}

impl Drop for JobCacheCapability {
    fn drop(&mut self) {
        if self.active {
            self.authority.revoke_immediately(&self.capability);
        }
    }
}

async fn run_with_cache_capability<F, T>(capability: &mut JobCacheCapability, execution: F) -> T
where
    F: Future<Output = T>,
{
    match AssertUnwindSafe(execution).catch_unwind().await {
        Ok(output) => output,
        Err(panic) => {
            capability.revoke().await;
            resume_unwind(panic)
        }
    }
}

async fn finish_job(
    job_client: &Arc<JobClient>,
    manifest: &JobManifest,
    execution_result: Result<JobExecutionOutcome>,
    cleanup_result: std::result::Result<(), ExecutionDomainError>,
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
    let completion_result = job_client
        .complete_job(
            &manifest.plan.plan_id,
            &manifest.plan.job_id,
            outcome.conclusion,
            &outputs,
            &[],
        )
        .await
        .context("completing job")
        .map_err(|source| anyhow::Error::new(CompletionPublicationError { source }));

    match cleanup_error {
        Some(source) => {
            let fatal = ExecutionDomainCleanupFatalError { source };
            Err(match completion_result {
                Ok(()) => anyhow::Error::new(fatal),
                Err(publication_error) => publication_error.context(fatal),
            })
        }
        None => completion_result,
    }
}

async fn finish_job_after_cache_revoke_and_destroy<F>(
    capability: &mut JobCacheCapability,
    destroy: F,
    job_client: &Arc<JobClient>,
    manifest: &JobManifest,
    execution_result: Result<JobExecutionOutcome>,
) -> Result<()>
where
    F: Future<Output = std::result::Result<(), ExecutionDomainError>>,
{
    capability.revoke().await;
    let destroy_result = destroy.await;
    finish_job(job_client, manifest, execution_result, destroy_result).await
}

pub struct Runner {
    pub(super) name: String,
    pub(super) credentials: RunnerCredentials,
    pub(super) paths: ChimeraPaths,
    pub(super) state: Option<Arc<DaemonState>>,
    pub(super) execution_domains: ExecutionDomainRoot,
    pub(super) cache_port: u16,
    pub(super) cache_authority: Arc<CacheAuthority>,
    pub(super) docker_action_builder: Arc<DockerActionBuilder>,
}

impl Runner {
    #[expect(
        clippy::too_many_arguments,
        reason = "the daemon's sole runner construction boundary keeps each shared dependency explicit"
    )]
    pub fn with_state(
        name: String,
        credentials: RunnerCredentials,
        paths: ChimeraPaths,
        state: Arc<DaemonState>,
        execution_domains: ExecutionDomainRoot,
        cache_port: u16,
        cache_authority: Arc<CacheAuthority>,
        docker_action_builder: Arc<DockerActionBuilder>,
    ) -> Self {
        Self {
            name,
            credentials,
            paths,
            state: Some(state),
            execution_domains,
            cache_port,
            cache_authority,
            docker_action_builder,
        }
    }

    async fn report_phase(&self, phase: RunnerPhase) {
        if let Some(ref state) = self.state {
            state.set_phase(&self.name, phase).await;
        }
    }

    /// Authenticate and create the broker session, retrying transient
    /// failures with exponential backoff. Returns Ok(None) when shutdown
    /// interrupts the retry loop; permanent failures bubble up so the runner
    /// lands in Stopped.
    async fn connect_with_retry(
        &self,
        client: &reqwest::Client,
        token_manager: &Arc<TokenManager>,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<Option<BrokerClient>> {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);

        loop {
            if *shutdown_rx.borrow() {
                return Ok(None);
            }

            let attempt = async {
                token_manager
                    .get_token()
                    .await
                    .context("getting initial OAuth token")?;
                BrokerClient::connect(
                    client.clone(),
                    &self.credentials.info.server_url_v2,
                    token_manager.clone(),
                    self.credentials.info.agent_id,
                    &self.credentials.info.agent_name,
                )
                .await
                .context("creating broker session")
            };

            // Shutdown must interrupt an in-flight attempt too, not just the
            // backoff sleep: the token POST is otherwise unbounded from the
            // runner's perspective. Abandoning a mid-flight session POST can
            // orphan a session the broker will reap on its own timeout.
            let outcome = tokio::select! {
                result = attempt => result,
                _ = shutdown_rx.changed() => return Ok(None),
            };

            match outcome {
                Ok(broker) => return Ok(Some(broker)),
                Err(error) if !startup_error_is_transient(&error) => return Err(error),
                Err(error) => {
                    // Debug format carries the full anyhow chain — the warn
                    // must show the actual cause while the runner keeps
                    // retrying in Starting.
                    warn!(
                        error = ?error,
                        backoff_secs = backoff.as_secs(),
                        "startup attempt failed, retrying"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown_rx.changed() => return Ok(None),
                    }
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
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
        debug!(job_resource_root = %self.execution_domains.path().display(), "using prepared job resource root");

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

        let broker = match self
            .connect_with_retry(&client, &token_manager, &mut shutdown_rx)
            .await?
        {
            Some(broker) => broker,
            None => {
                info!("shutdown signal received during startup, exiting");
                return Ok(());
            }
        };

        info!("authenticated successfully");
        info!(session_id = %broker.session_id(), "broker session created");
        self.report_phase(RunnerPhase::Idle).await;
        info!("entering poll loop, waiting for jobs...");
        let mut terminal_error = None;

        loop {
            if *shutdown_rx.borrow() {
                self.report_phase(RunnerPhase::Stopping).await;
                break;
            }
            let permit = tokio::select! {
                _ = shutdown_rx.changed() => {
                    self.report_phase(RunnerPhase::Stopping).await;
                    break;
                }
                permit = self.execution_domains.reserve() => match permit {
                    Ok(permit) => permit,
                    Err(error) => {
                        terminal_error = Some(error.into());
                        break;
                    }
                },
            };
            let result = self.poll_loop(&broker, &mut shutdown_rx).await;

            match result {
                Ok(Some(msg)) => {
                    info!(
                        message_id = msg.message_id,
                        message_type = %msg.message_type.diagnostic_kind(),
                        "received job message"
                    );

                    if let Err(error) = self
                        .handle_job_message(&msg, &broker, &client, token_manager.clone(), permit)
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
        permit: DomainPermit,
    ) -> Result<()> {
        let (runner_request_id, run_service_url) = match msg.parse_job_request() {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "failed to parse job request");
                return Ok(());
            }
        };

        debug!(%runner_request_id, "parsed job request");
        self.execution_domains.ensure_healthy()?;

        if let Err(e) = broker.ack_job(&runner_request_id).await {
            error!(error = %e, "failed to ack job");
            return Ok(());
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
                permit,
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
            error!("job execution failed");
        }

        self.execution_domains.ensure_healthy()?;
        Ok(())
    }

    async fn execute_job(
        &self,
        client: &reqwest::Client,
        token_manager: Arc<TokenManager>,
        runner_request_id: &str,
        run_service_url: &str,
        cancel_token: CancellationToken,
        permit: DomainPermit,
    ) -> Result<()> {
        info!(runner_request_id, "acquiring job");

        let mut job_client = JobClient::new(
            client.clone(),
            token_manager,
            run_service_url.to_string(),
            self.credentials.info.server_url.clone(),
        );

        let manifest = match job_client.acquire_job(runner_request_id).await {
            Ok(manifest) => manifest,
            Err(error) => {
                // JobClient acquisition errors are payload-free by construction;
                // no job-scoped masker exists until a manifest is available.
                error!(error = %error, "job acquisition failed");
                return Err(error.context("acquiring job manifest"));
            }
        };
        let secret_masker = Arc::new(tokio::sync::RwLock::new(SecretMasker::from_manifest(
            &manifest,
        )?));

        log_job_acquired(&manifest);

        job_client
            .configure_from_manifest(&manifest)
            .context("configuring job client from manifest")?;

        let repo = manifest
            .repository()
            .unwrap_or_else(|_| "unknown/repo".into());

        self.report_running(&repo, &manifest.plan.job_id).await;

        let job_client = Arc::new(job_client);
        let result = self
            .run_job(
                &manifest,
                &job_client,
                client,
                cancel_token,
                &repo,
                &secret_masker,
                permit,
            )
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(error) if error.downcast_ref::<CompletionPublicationError>().is_some() => {
                let masked_error = mask_error_chain(&error, &secret_masker).await;
                error!(error = %masked_error, "job completion request failed; not retrying completion");
                Err(error)
            }
            Err(error)
                if error
                    .downcast_ref::<ExecutionDomainCleanupFatalError>()
                    .is_some() =>
            {
                let masked_error = mask_error_chain(&error, &secret_masker).await;
                error!(error = %masked_error, "job completed after cleanup failure; stopping runner");
                Err(error)
            }
            Err(error) => {
                let masked_error = mask_error_chain(&error, &secret_masker).await;
                error!(error = %masked_error, "job failed before completion, reporting failure to GitHub");
                if let Err(report_error) =
                    report_setup_failure(&job_client, &manifest, &error, &secret_masker).await
                {
                    let masked_report_error = mask_error_chain(&report_error, &secret_masker).await;
                    error!(error = %masked_report_error, "failed to report setup failure to GitHub");
                }
                Err(error)
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the lifecycle owns the admission permit alongside job execution inputs"
    )]
    async fn run_job(
        &self,
        manifest: &JobManifest,
        job_client: &Arc<JobClient>,
        client: &reqwest::Client,
        cancel_token: CancellationToken,
        repo: &str,
        secret_masker: &SharedSecretMasker,
        permit: DomainPermit,
    ) -> Result<()> {
        let cache_scope = cache_scope_for_job(manifest, repo);
        let mut domain = tokio::task::spawn_blocking(move || permit.provision())
            .await
            .context("joining execution domain provisioning task")?
            .context("provisioning execution domain")?;
        let attempt_id = domain.attempt_id();
        info!(%attempt_id, "created job Docker config");

        let capability_id = match register_job_cache_capability(
            &self.cache_authority,
            manifest,
            cache_scope.clone(),
            Utc::now(),
        )
        .await
        {
            Ok(capability_id) => capability_id,
            Err(registration_error) => {
                let cleanup_path = domain.attempt_dir().to_path_buf();
                let cleanup_result = tokio::task::spawn_blocking(move || domain.destroy())
                    .await
                    .unwrap_or_else(|source| {
                        Err(ExecutionDomainError::Cleanup {
                            path: cleanup_path,
                            source: io::Error::other(format!(
                                "per-job resource cleanup task failed: {source}"
                            )),
                        })
                    });
                match &cleanup_result {
                    Ok(()) => info!(%attempt_id, "cleaned job Docker config"),
                    Err(cleanup_error) => {
                        let masked_error = mask_error_chain(
                            &anyhow::Error::msg(cleanup_error.to_string()),
                            secret_masker,
                        )
                        .await;
                        error!(
                            category = "job-resource-cleanup",
                            %attempt_id,
                            error = %masked_error,
                            "job Docker config cleanup failed"
                        );
                    }
                }
                return match cleanup_result {
                    Ok(()) => Err(registration_error),
                    Err(cleanup_error) => {
                        Err(registration_error.context(cleanup_error.to_string()))
                    }
                };
            }
        };
        let mut cache_capability =
            JobCacheCapability::new(Arc::clone(&self.cache_authority), capability_id);

        let execution_result = run_with_cache_capability(&mut cache_capability, async {
            domain
                .mark_running()
                .context("marking execution domain running")?;
            self.run_job_body(
                manifest,
                job_client,
                client,
                cancel_token,
                repo,
                &cache_scope,
                &domain,
                secret_masker,
            )
            .await
        })
        .await;
        // Always transition to Cleaning after the body returns, including setup
        // failures and cancellation, and still destroy if the journal write fails.
        let execution_result = match domain.mark_cleaning() {
            Ok(()) => execution_result,
            Err(error) => match execution_result {
                Ok(_) => {
                    Err(anyhow::Error::new(error).context("marking execution domain cleaning"))
                }
                Err(execution_error) => Err(execution_error.context(error.to_string())),
            },
        };
        let destroy = async move {
            let destroy_path = domain.attempt_dir().to_path_buf();
            let cleanup_result = tokio::task::spawn_blocking(move || domain.destroy())
                .await
                .unwrap_or_else(|source| {
                    Err(ExecutionDomainError::Cleanup {
                        path: destroy_path,
                        source: io::Error::other(format!(
                            "execution domain destroy task failed: {source}"
                        )),
                    })
                });
            match &cleanup_result {
                Ok(()) => info!(%attempt_id, "cleaned job Docker config"),
                Err(cleanup_error) => {
                    let masked_error = mask_error_chain(
                        &anyhow::Error::msg(cleanup_error.to_string()),
                        secret_masker,
                    )
                    .await;
                    error!(
                        category = "job-resource-cleanup",
                        %attempt_id,
                        error = %masked_error,
                        "job Docker config cleanup failed"
                    );
                }
            }
            cleanup_result
        };

        finish_job_after_cache_revoke_and_destroy(
            &mut cache_capability,
            destroy,
            job_client,
            manifest,
            execution_result,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the job lifecycle boundary keeps execution, cache scope, cleanup ownership, and secret masking explicit"
    )]
    async fn run_job_body(
        &self,
        manifest: &JobManifest,
        job_client: &Arc<JobClient>,
        client: &reqwest::Client,
        cancel_token: CancellationToken,
        repo: &str,
        cache_scope: &CacheScope,
        domain: &ExecutionDomain,
        secret_masker: &SharedSecretMasker,
    ) -> Result<JobExecutionOutcome> {
        let workspace = self.create_job_workspace(domain, repo)?;
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
                cache_scope,
                &workspace,
                &node_runtimes,
                &mut docker_resources,
                domain,
                secret_masker,
            )
            .await
        }
        .await;

        if let Some(resources) = docker_resources.as_mut() {
            resources.cleanup().await;
        }
        if let Err(cleanup_error) = workspace.cleanup() {
            let masked_error = mask_error_chain(&cleanup_error, secret_masker).await;
            warn!(error = %masked_error, "workspace cleanup failed");
        }

        execution_result
    }

    fn create_job_workspace(&self, domain: &ExecutionDomain, repo: &str) -> Result<Workspace> {
        Workspace::create(
            domain.work_dir(),
            domain.private_tmp(),
            &self.paths.tool_cache_dir(),
            &self.name,
            repo,
        )
        .context("creating workspace")
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_job_steps(
        &self,
        manifest: &JobManifest,
        job_client: &Arc<JobClient>,
        client: &reqwest::Client,
        cancel_token: CancellationToken,
        cache_scope: &CacheScope,
        workspace: &Workspace,
        node_runtimes: &crate::node::NodeRuntimes,
        docker_resources: &mut Option<JobDockerResources>,
        domain: &ExecutionDomain,
        secret_masker: &SharedSecretMasker,
    ) -> Result<JobExecutionOutcome> {
        // Choose env builder based on execution mode
        let mut base_env = if manifest.has_container() {
            build_container_env(manifest, workspace, &self.name)
        } else {
            build_base_env(manifest, workspace, &self.name, domain)?
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
        let scope_repo = crate::cache::server::encode_scope(&cache_scope.repo);
        let scope_ref = crate::cache::server::encode_scope(&cache_scope.git_ref);
        let scope_default = crate::cache::server::encode_scope(&cache_scope.default_ref);

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

        let execution = JobExecutionContext::new(domain, docker_resources.as_ref(), node_runtimes);
        let job_result = run_all_steps_with_masker(
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
            secret_masker.clone(),
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
        let mut poisoned_rx = self.execution_domains.poisoned_receiver();
        // Set when the previous iteration handled a 401 by refreshing the
        // token. A 401 on the very next poll means the fresh token is also
        // rejected (e.g. the registration was revoked) and must not loop.
        let mut token_just_refreshed = false;

        loop {
            self.execution_domains.ensure_healthy()?;
            if *shutdown_rx.borrow() {
                info!("shutdown signal received, exiting poll loop");
                return Ok(None);
            }

            let poll_result = tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    info!("shutdown signal received, cancelling poll");
                    return Ok(None);
                }
                _ = poisoned_rx.changed() => {
                    self.execution_domains.ensure_healthy()?;
                    continue;
                }
                result = broker.poll_message(AgentStatus::Online) => result,
            };

            match poll_result {
                Ok(Some(msg)) => {
                    self.execution_domains.ensure_healthy()?;
                    // Any successful poll proves the token still works.
                    token_just_refreshed = false;

                    if msg.message_type != MessageType::RunnerJobRequest {
                        info!(
                            message_id = msg.message_id,
                            message_type = %msg.message_type.diagnostic_kind(),
                            "received control message while idle, skipping"
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
                        message_type = %msg.message_type.diagnostic_kind(),
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
                            self.execution_domains.ensure_healthy()?;
                            continue;
                        }
                    }

                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }
}

fn log_job_acquired(manifest: &JobManifest) {
    info!(
        plan_id = %manifest.plan.plan_id,
        job_id = %manifest.plan.job_id,
        steps = manifest.steps.len(),
        variable_count = manifest.variables.len(),
        endpoint_count = manifest.resources.endpoints.len(),
        has_container = manifest.has_container(),
        has_services = manifest.has_services(),
        mask_hint_count = manifest.mask_regexes().len(),
        "job acquired"
    );

    for (index, endpoint) in manifest.resources.endpoints.iter().enumerate() {
        debug!(
            index,
            data_field_count = endpoint.data.len(),
            "manifest endpoint"
        );
    }
}

async fn mask_error_chain(error: &anyhow::Error, masker: &SharedSecretMasker) -> String {
    let rendered = format!("{error:#}");
    masker.read().await.mask(&rendered)
}

#[cfg(test)]
#[path = "instance_test.rs"]
mod instance_test;
