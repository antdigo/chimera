use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::RUNNER_VERSION;
use super::auth::TokenManager;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SESSION_CONFLICT_RETRY_DELAYS: [Duration; 2] =
    [Duration::from_secs(1), Duration::from_secs(2)];

// Values the official runner sends on every broker poll and acknowledge
// (VarUtil.OS / VarUtil.OSArchitecture). They ride along on the same requests
// that drive message routing, so chimera must send them too.
fn broker_os() -> &'static str {
    match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "macOS",
        "windows" => "Windows",
        other => other,
    }
}

fn broker_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "X64",
        "x86" => "X86",
        "aarch64" => "ARM64",
        "arm" => "ARM",
        other => other,
    }
}

// The official runner's message-queue connection uses a 60s send timeout, and
// the broker answers an idle long-poll with 202 shortly before that. A client
// timeout shorter than the broker's hold window aborts every idle cycle.
const POLL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub enum MessageType {
    RunnerJobRequest,
    JobCancellation,
    Unknown(String),
}

impl MessageType {
    pub(crate) fn diagnostic_kind(&self) -> &'static str {
        match self {
            Self::RunnerJobRequest => "RunnerJobRequest",
            Self::JobCancellation => "JobCancellation",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RunnerJobRequest => write!(f, "RunnerJobRequest"),
            Self::JobCancellation => write!(f, "JobCancellation"),
            Self::Unknown(s) => write!(f, "{s}"),
        }
    }
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "RunnerJobRequest" => Ok(Self::RunnerJobRequest),
            "JobCancellation" => Ok(Self::JobCancellation),
            _ => Ok(Self::Unknown(s)),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerMessage {
    pub message_id: u64,
    pub message_type: MessageType,
    pub body: Option<String>,
}

/// Agent status reported to the broker on every poll (TaskAgentStatus in the
/// official protocol: Offline=1, Online=2, Busy=3). The official runner
/// reports Busy for the whole duration of a job and Online while idle, and
/// delivery appears to follow the reported status: polling as Online while
/// a job executes is how issue #18 lost its cancellation — the message never
/// reached the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStatus {
    Online,
    Busy,
}

impl AgentStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Online => "Online",
            Self::Busy => "Busy",
        }
    }
}

#[derive(Deserialize)]
struct JobRequestBody {
    runner_request_id: String,
    run_service_url: String,
}

#[derive(Deserialize)]
struct CancellationBody {
    #[serde(rename = "jobId")]
    job_id: String,
}

impl BrokerMessage {
    /// Parse the body of a RunnerJobRequest message into (runner_request_id, run_service_url).
    pub fn parse_job_request(&self) -> Result<(String, String)> {
        let body = self.body.as_deref().context("job message has no body")?;
        let req: JobRequestBody = serde_json::from_str(body).context("parsing job request body")?;
        Ok((req.runner_request_id, req.run_service_url))
    }

    /// Parse the body of a JobCancellation message into the job ID.
    pub fn parse_cancellation_job_id(&self) -> Result<String> {
        let body = self
            .body
            .as_deref()
            .context("cancellation message has no body")?;
        let parsed: CancellationBody =
            serde_json::from_str(body).context("parsing cancellation body")?;
        Ok(parsed.job_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("broker server error (status={status}, response_body_bytes={response_body_bytes})")]
    ServerError {
        status: u16,
        response_body_bytes: usize,
    },

    #[error("unauthorized (401)")]
    Unauthorized,

    #[error("poll timeout")]
    Timeout,

    #[error("connection error: {0}")]
    Connection(String),

    #[error("malformed broker response: {0}")]
    BadResponse(String),
}

// ---------------------------------------------------------------------------
// Session request/response
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionRequest {
    session_id: String,
    owner_name: String,
    agent: SessionAgent,
    use_fips_encryption: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionAgent {
    id: u64,
    name: String,
    version: String,
    os_description: String,
    ephemeral: bool,
    status: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    session_id: String,
}

// ---------------------------------------------------------------------------
// BrokerClient
// ---------------------------------------------------------------------------

pub struct BrokerClient {
    client: reqwest::Client,
    server_url: String,
    session_id: String,
    token_manager: Arc<TokenManager>,
    poll_timeout: Duration,
}

impl BrokerClient {
    /// Create a client with a pre-existing session.
    pub fn new(
        client: reqwest::Client,
        server_url: String,
        session_id: String,
        token_manager: Arc<TokenManager>,
    ) -> Self {
        Self {
            client,
            server_url,
            session_id,
            token_manager,
            poll_timeout: POLL_TIMEOUT,
        }
    }

    /// Override the long-poll timeout (used by tests to shorten poll cycles).
    pub fn with_poll_timeout(mut self, poll_timeout: Duration) -> Self {
        self.poll_timeout = poll_timeout;
        self
    }

    /// Create a new broker session and return a connected client.
    pub async fn connect(
        client: reqwest::Client,
        server_url: &str,
        token_manager: Arc<TokenManager>,
        agent_id: u64,
        agent_name: &str,
    ) -> Result<Self> {
        let token = token_manager
            .get_token()
            .await
            .context("getting token for session")?;

        let session_id = uuid::Uuid::new_v4().to_string();
        let owner_name = format!(
            "{} (PID: {})",
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".into()),
            std::process::id()
        );

        let body = CreateSessionRequest {
            session_id,
            owner_name,
            agent: SessionAgent {
                id: agent_id,
                name: agent_name.to_string(),
                version: RUNNER_VERSION.to_string(),
                os_description: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
                ephemeral: false,
                status: 0,
            },
            use_fips_encryption: false,
        };

        let url = format!("{}/session", server_url.trim_end_matches('/'));
        let mut conflict_retry_delays = SESSION_CONFLICT_RETRY_DELAYS.into_iter();

        loop {
            debug!(agent_id, agent_name, "creating broker session");

            let resp = client
                .post(&url)
                .bearer_auth(&token)
                .json(&body)
                .timeout(REQUEST_TIMEOUT)
                .send()
                .await
                .map_err(|e| {
                    // A request-builder failure means the broker URL itself is
                    // unusable (bad registration data) — not something to retry.
                    if e.is_builder() {
                        anyhow::anyhow!("invalid broker URL {server_url}: {e}")
                    } else {
                        BrokerError::Connection(e.to_string()).into()
                    }
                })
                .context("sending create session request")?;

            let status = resp.status();
            if !status.is_success() {
                let response_body_bytes = resp
                    .bytes()
                    .await
                    .map(|body| body.len())
                    .unwrap_or_default();

                if status.as_u16() == 409
                    && let Some(delay) = conflict_retry_delays.next()
                {
                    debug!(
                        agent_id,
                        agent_name,
                        delay_secs = delay.as_secs(),
                        "deleting stale broker session after create conflict"
                    );
                    Self::delete_session(&client, &url, &token)
                        .await
                        .context("deleting stale broker session after create conflict")?;
                    tokio::time::sleep(delay).await;
                    continue;
                }

                return match status.as_u16() {
                    401 => Err(BrokerError::Unauthorized.into()),
                    s if (500..600).contains(&s) || s == 429 => Err(BrokerError::ServerError {
                        status: s,
                        response_body_bytes,
                    }
                    .into()),
                    _ => bail!(
                        "create session failed ({status}), response_body_bytes={response_body_bytes}"
                    ),
                };
            }

            // Read the body before parsing so transport failures while reading
            // (stalled body, connection reset) stay retryable instead of being
            // misfiled as a permanent malformed-response error.
            let body = resp
                .bytes()
                .await
                .map_err(|e| BrokerError::Connection(e.to_string()))
                .context("reading create session response")?;

            let session: CreateSessionResponse = serde_json::from_slice(&body)
                .map_err(|e| BrokerError::BadResponse(e.to_string()))
                .context("parsing create session response")?;

            debug!(session_id = %session.session_id, "broker session created");

            return Ok(Self {
                client,
                server_url: server_url.to_string(),
                session_id: session.session_id,
                token_manager,
                poll_timeout: POLL_TIMEOUT,
            });
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub fn token_manager(&self) -> &TokenManager {
        &self.token_manager
    }

    pub fn token_manager_arc(&self) -> Arc<TokenManager> {
        self.token_manager.clone()
    }

    /// Single poll request. Returns Some(message) when the broker delivers
    /// one, None on an empty long-poll cycle.
    pub async fn poll_message(&self, status: AgentStatus) -> Result<Option<BrokerMessage>> {
        let token = self
            .token_manager
            .get_token()
            .await
            .context("getting token for poll")?;

        let url = format!(
            "{}/message?sessionId={}&status={}&runnerVersion={}&os={}&architecture={}&disableUpdate=true",
            self.server_url.trim_end_matches('/'),
            self.session_id,
            status.as_str(),
            RUNNER_VERSION,
            broker_os(),
            broker_architecture(),
        );

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .header(reqwest::header::ACCEPT, "application/json")
            .timeout(self.poll_timeout)
            .send()
            .await
            .map_err(|e| {
                // A timeout on an already-established request means the broker
                // held the idle long-poll past our window — a normal cycle. A
                // timeout while still connecting is a real failure.
                if e.is_timeout() && !e.is_connect() {
                    BrokerError::Timeout
                } else {
                    BrokerError::Connection(e.to_string())
                }
            })?;

        let status = resp.status();
        debug!(status = %status, "poll response");

        // Any 2xx is a successful poll. The official client reads the body of
        // every success status and treats an empty or JSON-null one as "no
        // message", so a 202 or 204 empty long-poll cycle is not an error.
        if status.is_success() {
            let body = resp.text().await.context("reading poll response body")?;
            if body.trim().is_empty() {
                return Ok(None);
            }
            let msg: Option<BrokerMessage> =
                serde_json::from_str(&body).context("parsing broker message")?;
            return Ok(msg);
        }

        match status.as_u16() {
            401 => Err(BrokerError::Unauthorized.into()),
            s if (500..600).contains(&s) => {
                let response_body_bytes = resp
                    .bytes()
                    .await
                    .map(|body| body.len())
                    .unwrap_or_default();
                Err(BrokerError::ServerError {
                    status: s,
                    response_body_bytes,
                }
                .into())
            }
            other => {
                let response_body_bytes = resp
                    .bytes()
                    .await
                    .map(|body| body.len())
                    .unwrap_or_default();
                bail!("unexpected poll status {other}, response_body_bytes={response_body_bytes}");
            }
        }
    }

    /// Acknowledge a job message via POST /acknowledge (V2 broker protocol).
    pub async fn ack_job(&self, runner_request_id: &str) -> Result<()> {
        let token = self.token_manager.get_token().await?;

        let url = format!(
            "{}/acknowledge?sessionId={}&status={}&runnerVersion={}&os={}&architecture={}",
            self.server_url.trim_end_matches('/'),
            self.session_id,
            AgentStatus::Online.as_str(),
            RUNNER_VERSION,
            broker_os(),
            broker_architecture(),
        );

        let body = serde_json::json!({
            "runnerRequestId": runner_request_id,
        });

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&token)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .context("sending ack request")?;

        let status = resp.status();
        if !status.is_success() {
            let response_body_bytes = resp
                .bytes()
                .await
                .map(|body| body.len())
                .unwrap_or_default();
            tracing::warn!(
                runner_request_id,
                status = %status,
                response_body_bytes,
                "ack failed"
            );
        } else {
            debug!(runner_request_id, "job acknowledged");
        }

        Ok(())
    }

    /// Delete the broker session.
    pub async fn disconnect(&self) -> Result<()> {
        let token = self.token_manager.get_token().await.unwrap_or_default();

        let url = format!("{}/session", self.server_url.trim_end_matches('/'));

        debug!(session_id = %self.session_id, "deleting broker session");

        Self::delete_session(&self.client, &url, &token).await?;

        debug!("broker session deleted");
        Ok(())
    }

    async fn delete_session(client: &reqwest::Client, url: &str, token: &str) -> Result<()> {
        let resp = client
            .delete(url)
            .bearer_auth(token)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|error| {
                if error.is_builder() {
                    anyhow::anyhow!("invalid broker session URL {url}: {error}")
                } else {
                    BrokerError::Connection(error.to_string()).into()
                }
            })
            .context("sending delete session request")?;

        let status = resp.status();
        if !status.is_success() && status.as_u16() != 404 {
            let response_body_bytes = resp
                .bytes()
                .await
                .map(|body| body.len())
                .unwrap_or_default();
            return match status.as_u16() {
                401 => Err(BrokerError::Unauthorized.into()),
                value if (500..600).contains(&value) || value == 429 => {
                    Err(BrokerError::ServerError {
                        status: value,
                        response_body_bytes,
                    }
                    .into())
                }
                _ => bail!(
                    "delete session failed ({status}), response_body_bytes={response_body_bytes}"
                ),
            };
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "broker_test.rs"]
mod broker_test;
