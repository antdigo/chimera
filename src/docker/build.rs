use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bollard::Docker;
use bollard::auth::DockerCredentials;
use bollard::errors::Error as DockerError;
use bollard::image::{BuildImageOptions, BuilderVersion};
use bollard::models::BuildInfo;
use futures::StreamExt;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub use super::build_cache::DockerBuildScope;
use super::build_cache::{BudgetOutcome, BuildCache, BuildCacheKey, CacheOutcome, within_budget};
use super::build_context::{PreparedBuildContext, prepare_build_context};
use crate::job::action::TrustedActionDirectory;
use crate::job::logs::LogSender;

pub const DOCKER_ACTION_PLATFORM: &str = "linux/amd64";
const INTERNAL_TAG_REDACTION: &str = "[internal Docker action image]";
const ENGINE_ID_REDACTION: &str = "[Docker Engine object ID]";
const TERMINAL_LOG_BUDGET: Duration = Duration::from_millis(100);
pub type RegistryAuth = HashMap<String, DockerCredentials>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltDockerImage {
    pub daemon_id: String,
    pub image_id: String,
}

#[derive(Debug)]
pub enum DockerBuildOutcome {
    Ready(BuiltDockerImage),
    Cancelled,
    TimedOut,
}

pub struct DockerBuildRequest<'a> {
    pub docker: &'a Docker,
    pub action_dir: &'a TrustedActionDirectory,
    pub dockerfile: &'a str,
    pub scope: &'a DockerBuildScope,
    pub registry_auth: Option<&'a RegistryAuth>,
    pub log_sender: &'a LogSender,
    pub cancel_token: &'a CancellationToken,
    pub deadline: Instant,
    pub reuse: Option<&'a BuiltDockerImage>,
}

// Test-only: lets Engine-state tests observe raw stream elements directly
// instead of synchronizing on LogSender delivery, whose latency is unrelated
// to the cancellation behavior under test.
#[cfg(test)]
type BuildInfoObserver = std::sync::Arc<dyn Fn(&BuildInfo) + Send + Sync>;

pub struct DockerActionBuilder {
    cache: BuildCache,
    tag_namespace: String,
    #[cfg(test)]
    build_info_observer_for_test: Option<BuildInfoObserver>,
}

impl DockerActionBuilder {
    pub fn new() -> Self {
        Self {
            cache: BuildCache::new(),
            tag_namespace: uuid::Uuid::new_v4().simple().to_string(),
            #[cfg(test)]
            build_info_observer_for_test: None,
        }
    }

    pub async fn build(&self, request: DockerBuildRequest<'_>) -> Result<DockerBuildOutcome> {
        match send_budgeted_log(
            request.log_sender,
            request.cancel_token,
            request.deadline,
            "Preparing Docker action build context".into(),
        )
        .await
        {
            BudgetOutcome::Ready(()) => {}
            BudgetOutcome::Cancelled => return Ok(DockerBuildOutcome::Cancelled),
            BudgetOutcome::TimedOut => return Ok(DockerBuildOutcome::TimedOut),
        }
        let action_dir = request.action_dir.clone();
        let dockerfile = request.dockerfile.to_string();
        let prepared = match within_budget(
            request.deadline,
            request.cancel_token,
            tokio::task::spawn_blocking(move || prepare_build_context(&action_dir, &dockerfile)),
        )
        .await
        {
            BudgetOutcome::Ready(joined) => joined.context("preparing Docker build context")??,
            BudgetOutcome::Cancelled => return Ok(DockerBuildOutcome::Cancelled),
            BudgetOutcome::TimedOut => return Ok(DockerBuildOutcome::TimedOut),
        };

        let daemon_id = match within_budget(
            request.deadline,
            request.cancel_token,
            daemon_id(request.docker),
        )
        .await
        {
            BudgetOutcome::Ready(result) => result?,
            BudgetOutcome::Cancelled => return Ok(DockerBuildOutcome::Cancelled),
            BudgetOutcome::TimedOut => return Ok(DockerBuildOutcome::TimedOut),
        };

        if let Some(reuse) = request.reuse
            && reuse.daemon_id == daemon_id
        {
            match within_budget(
                request.deadline,
                request.cancel_token,
                image_exists(request.docker, reuse.image_id.clone()),
            )
            .await
            {
                BudgetOutcome::Ready(Ok(true)) => {
                    match send_budgeted_log(
                        request.log_sender,
                        request.cancel_token,
                        request.deadline,
                        "Reusing Docker action image for this job".into(),
                    )
                    .await
                    {
                        BudgetOutcome::Ready(()) => {
                            return Ok(DockerBuildOutcome::Ready(reuse.clone()));
                        }
                        BudgetOutcome::Cancelled => return Ok(DockerBuildOutcome::Cancelled),
                        BudgetOutcome::TimedOut => return Ok(DockerBuildOutcome::TimedOut),
                    }
                }
                BudgetOutcome::Ready(Ok(false)) => {}
                BudgetOutcome::Ready(Err(error)) => return Err(error),
                BudgetOutcome::Cancelled => return Ok(DockerBuildOutcome::Cancelled),
                BudgetOutcome::TimedOut => return Ok(DockerBuildOutcome::TimedOut),
            }
        }

        let key = BuildCacheKey::new(
            &daemon_id,
            request.scope,
            DOCKER_ACTION_PLATFORM,
            &prepared.dockerfile,
            prepared.digest,
        );
        let internal_tag = key.internal_tag(&self.tag_namespace);
        let inspect_docker = request.docker.clone();
        let build_docker = request.docker.clone();
        let build_key = key.clone();
        let logger = request.log_sender.clone();
        let registry_auth = request.registry_auth.cloned();
        #[cfg(test)]
        let build_info_observer = self.build_info_observer_for_test.clone();
        let outcome = self
            .cache
            .get_or_build(
                key,
                request.deadline,
                request.cancel_token,
                move |image_id| {
                    let docker = inspect_docker.clone();
                    async move { image_exists(&docker, image_id).await }
                },
                move || async move {
                    logger.send("Building Docker action image".into()).await;
                    build_archive(
                        &build_docker,
                        prepared,
                        &internal_tag,
                        &build_key,
                        registry_auth,
                        &logger,
                        #[cfg(test)]
                        build_info_observer,
                    )
                    .await
                },
            )
            .await?;

        match outcome {
            CacheOutcome::Ready {
                image_id,
                cache_hit,
            } => Ok(finalize_ready_outcome(
                BuiltDockerImage {
                    daemon_id,
                    image_id,
                },
                cache_hit,
                request.log_sender,
                request.cancel_token,
                request.deadline,
            )
            .await),
            CacheOutcome::Cancelled => Ok(DockerBuildOutcome::Cancelled),
            CacheOutcome::TimedOut => Ok(DockerBuildOutcome::TimedOut),
        }
    }

    #[cfg(test)]
    fn new_with_build_info_observer_for_test(observer: BuildInfoObserver) -> Self {
        Self {
            build_info_observer_for_test: Some(observer),
            ..Self::new()
        }
    }

    #[cfg(test)]
    async fn cache_entry_count_for_test(&self) -> usize {
        self.cache.entry_count_for_test().await
    }

    #[cfg(test)]
    async fn internal_tag_for_context_for_test(
        &self,
        docker: &Docker,
        action_dir: &TrustedActionDirectory,
        dockerfile: &str,
        scope: &DockerBuildScope,
    ) -> Result<String> {
        let prepared = prepare_build_context(action_dir, dockerfile)?;
        let daemon_id = daemon_id(docker).await?;
        let key = BuildCacheKey::new(
            &daemon_id,
            scope,
            DOCKER_ACTION_PLATFORM,
            &prepared.dockerfile,
            prepared.digest,
        );
        Ok(key.internal_tag(&self.tag_namespace))
    }
}

impl Default for DockerActionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

async fn build_archive(
    docker: &Docker,
    prepared: PreparedBuildContext,
    internal_tag: &str,
    cache_key: &BuildCacheKey,
    registry_auth: Option<RegistryAuth>,
    log_sender: &LogSender,
    #[cfg(test)] build_info_observer: Option<BuildInfoObserver>,
) -> Result<String> {
    let options = BuildImageOptions {
        dockerfile: prepared.dockerfile.clone(),
        t: internal_tag.to_string(),
        pull: false,
        rm: true,
        forcerm: true,
        platform: DOCKER_ACTION_PLATFORM.to_string(),
        labels: HashMap::from([
            ("io.chimera.action-cache".to_string(), "v1".to_string()),
            ("io.chimera.action-key".to_string(), cache_key.fingerprint()),
        ]),
        version: BuilderVersion::BuilderV1,
        ..Default::default()
    };
    let mut stream = docker.build_image(options, registry_auth, Some(prepared.archive.into()));

    while let Some(item) = stream.next().await {
        #[cfg(test)]
        if let Some(observer) = build_info_observer.as_ref()
            && let Ok(info) = item.as_ref()
        {
            observer(info);
        }
        let info = item.map_err(|_| anyhow!("Docker action image build failed"))?;
        if info.error.is_some() {
            return Err(anyhow!("Docker action image build failed"));
        }
        send_build_progress(log_sender, info, internal_tag).await;
    }

    let expected_fingerprint = cache_key.fingerprint();
    let inspected = docker
        .inspect_image(internal_tag)
        .await
        .map_err(|_| anyhow!("Docker action image verification failed"))?;
    let label_matches = inspected
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .and_then(|labels| labels.get("io.chimera.action-key"))
        .is_some_and(|value| value == &expected_fingerprint);
    if !label_matches {
        return Err(anyhow!("Docker action image verification failed"));
    }

    let image_id = inspected
        .id
        .filter(|image_id| !image_id.is_empty())
        .ok_or_else(|| anyhow!("Docker action image verification failed"))?;
    let verified = docker
        .inspect_image(&image_id)
        .await
        .map_err(|_| anyhow!("Docker action image verification failed"))?;
    if verified.id.as_deref() != Some(image_id.as_str()) {
        return Err(anyhow!("Docker action image verification failed"));
    }

    Ok(image_id)
}

async fn send_build_progress(log_sender: &LogSender, info: BuildInfo, internal_tag: &str) {
    for message in format_build_progress(info, internal_tag) {
        log_sender.send(message).await;
    }
}

fn format_build_progress(info: BuildInfo, internal_tag: &str) -> Vec<String> {
    if let Some(stream) = info.stream {
        return stream
            .lines()
            .map(|line| sanitize_build_progress(line, internal_tag))
            .collect();
    }

    let status = info
        .status
        .map(|status| sanitize_build_progress(&status, internal_tag));
    let progress = info
        .progress
        .map(|progress| sanitize_build_progress(&progress, internal_tag));
    match (status, progress) {
        (Some(status), Some(progress)) => vec![format!("{status} {progress}")],
        (Some(status), None) => vec![status],
        (None, Some(progress)) => vec![progress],
        (None, None) => Vec::new(),
    }
}

fn sanitize_build_progress(value: &str, internal_tag: &str) -> String {
    let value = redact_internal_tag(value, internal_tag);
    redact_engine_protocol_id(&value)
}

fn redact_internal_tag(value: &str, internal_tag: &str) -> String {
    if internal_tag.is_empty() {
        return value.to_string();
    }
    value.replace(internal_tag, INTERNAL_TAG_REDACTION)
}

fn redact_engine_protocol_id(value: &str) -> String {
    for prefix in [
        "Successfully built ",
        "Removing intermediate container ",
        "Removed intermediate container ",
        " ---> Running in ",
        "Running in ",
        " ---> ",
    ] {
        if value
            .strip_prefix(prefix)
            .is_some_and(is_recognized_engine_id)
        {
            return format!("{prefix}{ENGINE_ID_REDACTION}");
        }
    }

    let Some((candidate, status)) = value.split_once(": ") else {
        return value.to_string();
    };
    let layer_status = matches!(
        status,
        "Pulling fs layer"
            | "Waiting"
            | "Downloading"
            | "Verifying Checksum"
            | "Download complete"
            | "Extracting"
            | "Pull complete"
            | "Already exists"
    ) || status.starts_with('[');
    if layer_status && is_recognized_engine_id(candidate) {
        return format!("{ENGINE_ID_REDACTION}: {status}");
    }

    value.to_string()
}

fn is_recognized_engine_id(value: &str) -> bool {
    let (hex, exact_length) = match value.strip_prefix("sha256:") {
        Some(hex) => (hex, Some(64)),
        None => (value, None),
    };
    let valid_length = match exact_length {
        Some(length) => hex.len() == length,
        None => (12..=64).contains(&hex.len()),
    };
    valid_length && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn send_budgeted_log(
    log_sender: &LogSender,
    cancel_token: &CancellationToken,
    deadline: Instant,
    message: String,
) -> BudgetOutcome<()> {
    within_budget(deadline, cancel_token, log_sender.send(message)).await
}

async fn finalize_ready_outcome(
    image: BuiltDockerImage,
    cache_hit: bool,
    log_sender: &LogSender,
    cancel_token: &CancellationToken,
    deadline: Instant,
) -> DockerBuildOutcome {
    let terminal_deadline = std::cmp::min(deadline, Instant::now() + TERMINAL_LOG_BUDGET);
    if cache_hit
        && !matches!(
            send_budgeted_log(
                log_sender,
                cancel_token,
                terminal_deadline,
                "Reusing cached Docker action image".into(),
            )
            .await,
            BudgetOutcome::Ready(())
        )
    {
        return DockerBuildOutcome::Ready(image);
    }

    let _ = send_budgeted_log(
        log_sender,
        cancel_token,
        terminal_deadline,
        "Docker action image is ready".into(),
    )
    .await;
    DockerBuildOutcome::Ready(image)
}

async fn daemon_id(docker: &Docker) -> Result<String> {
    let info = docker
        .info()
        .await
        .context("reading Docker daemon information")?;
    info.id
        .filter(|id| !id.is_empty())
        .context("Docker daemon did not report an ID")
}

async fn image_exists(docker: &Docker, image_id: String) -> Result<bool> {
    match docker.inspect_image(&image_id).await {
        Ok(_) => Ok(true),
        Err(DockerError::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub async fn require_local_image(docker: &Docker, image_id: &str) -> Result<()> {
    match docker.inspect_image(image_id).await {
        Ok(_) => Ok(()),
        Err(DockerError::DockerResponseServerError {
            status_code: 404, ..
        }) => Err(anyhow!("built Docker action image is no longer present")),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
#[path = "build_test.rs"]
mod build_test;
