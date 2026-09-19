use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::watch;
use tracing_subscriber::fmt::MakeWriter;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::config::ChimeraPaths;
use crate::github::auth::TokenManager;
use crate::github::broker::{BrokerClient, MessageType};
use crate::job::docker_config::JobDockerConfigError;

use super::*;

#[derive(Clone, Default)]
struct TracingWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TracingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for TracingWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

impl TracingWriter {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

#[test]
fn acquired_job_trace_contains_only_safe_structural_fields() {
    let manifest: JobManifest = serde_json::from_value(serde_json::json!({
        "plan": { "planId": "safe-plan", "jobId": "safe-job", "timelineId": "safe-timeline" },
        "steps": [{
            "id": "safe-step",
            "reference": { "type": "script" },
            "inputs": {},
            "order": 1
        }],
        "variables": {
            "CANARY_VARIABLE_NAME": { "value": "CANARY_VARIABLE_VALUE", "isSecret": true }
        },
        "resources": { "endpoints": [{
            "name": "CANARY_ENDPOINT_NAME",
            "url": "https://CANARY-ENDPOINT.invalid",
            "authorization": null,
            "data": { "CANARY_DATA_KEY": "CANARY_DATA_VALUE" }
        }]},
        "contextData": {},
        "jobContainer": { "image": "CANARY-CONTAINER-IMAGE" },
        "serviceContainers": null,
        "mask": [{ "type": "regex", "value": "CANARY-MASK" }],
        "fileTable": ["CANARY-FILENAME"]
    }))
    .unwrap();
    let captured = TracingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .with_writer(captured.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);

    log_job_acquired(&manifest);
    let trace = captured.text();

    for field in [
        "steps",
        "variable_count",
        "endpoint_count",
        "has_container",
        "has_services",
        "mask_hint_count",
    ] {
        assert!(trace.contains(field), "missing field {field}: {trace}");
    }
    for canary in [
        "CANARY_VARIABLE_NAME",
        "CANARY_VARIABLE_VALUE",
        "CANARY_ENDPOINT_NAME",
        "CANARY-ENDPOINT",
        "CANARY_DATA_KEY",
        "CANARY_DATA_VALUE",
        "CANARY-CONTAINER-IMAGE",
        "CANARY-MASK",
        "CANARY-FILENAME",
    ] {
        assert!(!trace.contains(canary), "trace leaked {canary}: {trace}");
    }
}

async fn setup() -> (MockServer, Arc<TokenManager>, watch::Sender<bool>) {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 7200
        })))
        .mount(&mock_server)
        .await;

    let private_key = crate::testing::test_private_key();

    let tm = Arc::new(TokenManager::new(
        reqwest::Client::new(),
        format!("{}/oauth2/token", mock_server.uri()),
        private_key,
        "test-client".into(),
    ));

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);

    (mock_server, tm, shutdown_tx)
}

fn make_runner() -> (TempDir, Runner) {
    let temp = TempDir::new().unwrap();
    let paths = ChimeraPaths::new(temp.path().to_path_buf());
    let job_resources =
        crate::job::docker_config::JobResourceRoot::prepare(&paths.job_resources_dir()).unwrap();

    let runner = Runner {
        name: "test-runner".into(),
        credentials: crate::config::RunnerCredentials {
            info: crate::config::RunnerInfo {
                agent_id: 1,
                agent_name: "test".into(),
                pool_id: 1,
                server_url: "http://unused".into(),
                server_url_v2: "http://unused".into(),
                git_hub_url: "http://unused".into(),
                work_folder: "_work".into(),
                use_v2_flow: true,
            },
            oauth: crate::config::OAuthCredentials {
                scheme: "OAuth".into(),
                client_id: "unused".into(),
                authorization_url: "http://unused".into(),
            },
            rsa_params: crate::config::RsaParameters {
                d: String::new(),
                dp: String::new(),
                dq: String::new(),
                exponent: String::new(),
                inverse_q: String::new(),
                modulus: String::new(),
                p: String::new(),
                q: String::new(),
            },
        },
        paths,
        state: None,
        job_resources,
        cache_port: 9999,
        docker_action_builder: Arc::new(crate::docker::build::DockerActionBuilder::new()),
    };

    (temp, runner)
}

#[tokio::test]
async fn poll_loop_returns_job_request() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .and(query_param("status", "Online"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 99,
            "messageType": "RunnerJobRequest",
            "body": "{\"runner_request_id\": \"abc123\"}"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );

    let (_temp, runner) = make_runner();
    let mut rx = shutdown_tx.subscribe();
    // Bounded so a status regression (poll sent as Busy, mock answers 404,
    // poll_loop backs off and retries forever) fails fast instead of hanging.
    let result = tokio::time::timeout(Duration::from_secs(30), runner.poll_loop(&broker, &mut rx))
        .await
        .expect("poll_loop should return within 30s")
        .unwrap();
    let msg = result.expect("should return job message");
    assert_eq!(msg.message_id, 99);
    assert_eq!(msg.message_type, MessageType::RunnerJobRequest);
}

#[tokio::test]
async fn poll_loop_skips_control_then_returns_job() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 1,
            "messageType": "AgentRefresh",
            "body": null
        })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 2,
            "messageType": "RunnerJobRequest",
            "body": "{\"runner_request_id\": \"xyz\"}"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/message/2"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );

    let (_temp, runner) = make_runner();
    let mut rx = shutdown_tx.subscribe();
    let result = runner.poll_loop(&broker, &mut rx).await.unwrap();
    let msg = result.expect("should return job after skipping control message");
    assert_eq!(msg.message_id, 2);
    assert_eq!(msg.message_type, MessageType::RunnerJobRequest);
}

#[tokio::test]
async fn poll_loop_shutdown_returns_none() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );

    let mut rx = shutdown_tx.subscribe();
    shutdown_tx.send(true).unwrap();

    let (_temp, runner) = make_runner();
    let result = runner.poll_loop(&broker, &mut rx).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn poll_loop_stops_when_job_resource_root_is_poisoned() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202).set_delay(Duration::from_secs(10)))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );

    let (_temp, runner) = make_runner();
    let root = runner.job_resources.clone();
    let mut rx = shutdown_tx.subscribe();
    let poll = tokio::spawn(async move { runner.poll_loop(&broker, &mut rx).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut config = root.create_docker_config().unwrap();
    let outside = root.path().parent().unwrap().join("outside");
    std::fs::write(&outside, "outside").unwrap();
    let symlink_path = config.attempt_dir().join("unexpected-link");
    std::os::unix::fs::symlink(&outside, &symlink_path).unwrap();
    config.cleanup().unwrap_err();
    std::fs::remove_file(symlink_path).unwrap();
    config.cleanup().unwrap();

    let error = tokio::time::timeout(Duration::from_secs(1), poll)
        .await
        .expect("poisoning the resource root should interrupt broker polling")
        .unwrap()
        .unwrap_err();

    assert!(error.to_string().contains("poisoned-job-resource-root"));
}

#[tokio::test]
async fn poll_loop_backoff_on_error() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(500).set_body_string("error"))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );

    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let _ = shutdown_tx_clone.send(true);
    });

    let (_temp, runner) = make_runner();
    let mut rx = shutdown_tx.subscribe();
    let result = runner.poll_loop(&broker, &mut rx).await.unwrap();
    assert!(
        result.is_none(),
        "should return None on shutdown after backoff"
    );
}

#[tokio::test]
async fn poll_loop_repolls_immediately_after_long_poll_timeout() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    // First poll never completes within the (shortened) client timeout —
    // the broker holds the long-poll window open past it.
    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202).set_delay(Duration::from_secs(5)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 7,
            "messageType": "RunnerJobRequest",
            "body": "{\"runner_request_id\": \"abc123\"}"
        })))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    )
    .with_poll_timeout(Duration::from_millis(300));

    let (_temp, runner) = make_runner();
    let mut rx = shutdown_tx.subscribe();
    let poll = runner.poll_loop(&broker, &mut rx);

    // With backoff the job would arrive after 300ms timeout + 1s sleep > 1.2s;
    // an immediate repoll returns it within one poll cycle.
    let result = tokio::time::timeout(Duration::from_millis(900), poll)
        .await
        .expect("job should be picked up without backoff after a long-poll timeout")
        .unwrap()
        .expect("should return job message");
    assert_eq!(result.message_id, 7);
}

#[tokio::test]
async fn poll_loop_long_poll_timeout_resets_backoff() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(500).set_body_string("error"))
        .up_to_n_times(2)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202).set_delay(Duration::from_secs(5)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(500).set_body_string("error"))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 8,
            "messageType": "RunnerJobRequest",
            "body": "{\"runner_request_id\": \"abc123\"}"
        })))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    )
    .with_poll_timeout(Duration::from_millis(300));

    let (_temp, runner) = make_runner();
    let mut rx = shutdown_tx.subscribe();
    let poll = runner.poll_loop(&broker, &mut rx);

    // Two genuine failures grow the backoff to 2s; the idle timeout in
    // between must reset it, so the third failure sleeps 1s and the job
    // arrives in ~4.4s. If the timeout did not reset the backoff, the sleep
    // would be 4s and the job would arrive after ~7.4s.
    let result = tokio::time::timeout(Duration::from_millis(5500), poll)
        .await
        .expect("backoff should reset across a long-poll timeout")
        .unwrap()
        .expect("should return job message");
    assert_eq!(result.message_id, 8);
}

#[tokio::test]
async fn poll_loop_refreshes_token_on_401() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 11,
            "messageType": "RunnerJobRequest",
            "body": "{\"runner_request_id\": \"abc123\"}"
        })))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );

    let (_temp, runner) = make_runner();
    let mut rx = shutdown_tx.subscribe();
    let result = runner.poll_loop(&broker, &mut rx).await.unwrap();
    let msg = result.expect("empty poll after 401 refresh must keep polling, not exit");
    assert_eq!(msg.message_id, 11);
}

#[tokio::test]
async fn poll_loop_401_refresh_then_timeout_still_returns_job() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202).set_delay(Duration::from_secs(5)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 12,
            "messageType": "RunnerJobRequest",
            "body": "{\"runner_request_id\": \"abc123\"}"
        })))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    )
    .with_poll_timeout(Duration::from_millis(300));

    let (_temp, runner) = make_runner();
    let mut rx = shutdown_tx.subscribe();
    let result = runner.poll_loop(&broker, &mut rx).await.unwrap();
    let msg = result.expect("long-poll timeout after 401 refresh must keep polling, not exit");
    assert_eq!(msg.message_id, 12);
}

#[tokio::test]
async fn poll_loop_persistent_401_returns_error() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );

    let (_temp, runner) = make_runner();
    let mut rx = shutdown_tx.subscribe();
    let result = runner.poll_loop(&broker, &mut rx).await;
    assert!(
        result.is_err(),
        "401 persisting after a token refresh should surface as an error"
    );
}

/// A runner whose credentials point at a live mock server: a real RSA key
/// (so `start` can reconstruct it) plus controllable token and broker URLs.
fn make_startup_runner(
    state: Option<Arc<DaemonState>>,
    authorization_url: String,
    server_url_v2: String,
) -> (TempDir, Runner) {
    let temp = TempDir::new().unwrap();
    let paths = ChimeraPaths::new(temp.path().to_path_buf());
    let job_resources =
        crate::job::docker_config::JobResourceRoot::prepare(&paths.job_resources_dir()).unwrap();

    let rsa_params =
        crate::config::private_key_to_rsa_params(&crate::testing::test_private_key()).unwrap();

    let runner = Runner {
        name: "test-runner".into(),
        credentials: crate::config::RunnerCredentials {
            info: crate::config::RunnerInfo {
                agent_id: 1,
                agent_name: "test".into(),
                pool_id: 1,
                server_url: server_url_v2.clone(),
                server_url_v2,
                git_hub_url: "http://unused".into(),
                work_folder: "_work".into(),
                use_v2_flow: true,
            },
            oauth: crate::config::OAuthCredentials {
                scheme: "OAuth".into(),
                client_id: "test-client".into(),
                authorization_url,
            },
            rsa_params,
        },
        paths,
        state,
        job_resources,
        cache_port: 9999,
        docker_action_builder: Arc::new(crate::docker::build::DockerActionBuilder::new()),
    };

    (temp, runner)
}

async fn wait_for_phase(
    state: &Arc<DaemonState>,
    runner_name: &str,
    phase: RunnerPhase,
) -> Result<(), tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = state.snapshot().await;
            if snapshot
                .runners
                .get(runner_name)
                .is_some_and(|status| status.phase == phase)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
}

#[tokio::test]
async fn start_retries_transient_token_exchange_failure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(
            ResponseTemplate::new(503).set_body_string("GitHub Actions is temporarily unavailable"),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 7200
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sessionId": "session-uuid-123"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202).set_delay(Duration::from_millis(50)))
        .mount(&mock_server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let state = Arc::new(DaemonState::new(&["test-runner".to_string()]));
    let (_temp, runner) = make_startup_runner(
        Some(Arc::clone(&state)),
        format!("{}/oauth2/token", mock_server.uri()),
        mock_server.uri(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let start = tokio::spawn(runner.start(shutdown_rx));

    wait_for_phase(&state, "test-runner", RunnerPhase::Idle)
        .await
        .expect("runner should reach Idle after a transient token exchange failure");

    shutdown_tx.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), start)
        .await
        .expect("runner should exit after shutdown")
        .unwrap();
    assert!(
        result.is_ok(),
        "runner should shut down cleanly after reaching Idle"
    );
}

#[tokio::test]
async fn start_retries_transient_broker_session_failure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 7200
        })))
        // The cached token must serve both the initial exchange and the
        // session-creation retry: a second exchange would mean the retry
        // rebuilt the token manager instead of reusing it.
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(503).set_body_string("try later"))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sessionId": "session-uuid-123"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202).set_delay(Duration::from_millis(50)))
        .mount(&mock_server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let state = Arc::new(DaemonState::new(&["test-runner".to_string()]));
    let (_temp, runner) = make_startup_runner(
        Some(Arc::clone(&state)),
        format!("{}/oauth2/token", mock_server.uri()),
        mock_server.uri(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let start = tokio::spawn(runner.start(shutdown_rx));

    wait_for_phase(&state, "test-runner", RunnerPhase::Idle)
        .await
        .expect("runner should reach Idle after a transient broker session failure");

    shutdown_tx.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), start)
        .await
        .expect("runner should exit after shutdown")
        .unwrap();
    assert!(
        result.is_ok(),
        "runner should shut down cleanly after reaching Idle"
    );
}

#[tokio::test]
async fn start_permanent_token_failure_returns_error_without_retry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid_client"))
        // Exactly one exchange: a permanent auth rejection must not be retried.
        .expect(1)
        .mount(&mock_server)
        .await;

    let (_temp, runner) = make_startup_runner(
        None,
        format!("{}/oauth2/token", mock_server.uri()),
        mock_server.uri(),
    );

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let result = tokio::time::timeout(Duration::from_secs(5), runner.start(shutdown_rx))
        .await
        .expect("start should fail fast on a permanent auth rejection");

    let error = result.unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("401"),
        "error should mention the rejected status: {message}"
    );
}

#[tokio::test]
async fn start_shutdown_during_startup_retry_exits_cleanly() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&mock_server)
        .await;

    let (_temp, runner) = make_startup_runner(
        None,
        format!("{}/oauth2/token", mock_server.uri()),
        mock_server.uri(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let start = tokio::spawn(runner.start(shutdown_rx));

    // Land inside the post-failure backoff window, then shut down. Best-effort
    // send: the assertion below is what flags a runner that already died.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let _ = shutdown_tx.send(true);

    let result = tokio::time::timeout(Duration::from_secs(10), start)
        .await
        .expect("shutdown should interrupt the startup retry loop")
        .unwrap();
    assert!(
        result.is_ok(),
        "runner should exit cleanly when shutdown interrupts startup retries"
    );
}

#[tokio::test]
async fn start_fails_fast_on_malformed_authorization_url() {
    let (_temp, runner) = make_startup_runner(None, "not a url".into(), "http://unused".into());

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let result = tokio::time::timeout(Duration::from_secs(5), runner.start(shutdown_rx))
        .await
        .expect("a malformed endpoint URL must fail fast instead of retrying forever");

    let error = result.unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("invalid token endpoint URL"),
        "error should name the bad URL: {message}"
    );
}

#[tokio::test]
async fn start_fails_fast_on_malformed_broker_url() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 7200
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let (_temp, runner) = make_startup_runner(
        None,
        format!("{}/oauth2/token", mock_server.uri()),
        "not a url".into(),
    );

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let result = tokio::time::timeout(Duration::from_secs(5), runner.start(shutdown_rx))
        .await
        .expect("a malformed broker URL must fail fast instead of retrying forever");

    let error = result.unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("invalid broker URL"),
        "error should name the bad URL: {message}"
    );
}

#[tokio::test]
async fn start_shutdown_during_in_flight_startup_request_exits_cleanly() {
    let mock_server = MockServer::start().await;

    // The token exchange accepts the connection but never finishes, so the
    // only way out of startup is the shutdown path, not a request timeout.
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&mock_server)
        .await;

    let (_temp, runner) = make_startup_runner(
        None,
        format!("{}/oauth2/token", mock_server.uri()),
        mock_server.uri(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let start = tokio::spawn(runner.start(shutdown_rx));

    // Wait until the request has actually reached the server, so the test
    // exercises the in-flight cancellation branch even on slow schedulers.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let requests = mock_server.received_requests().await.unwrap();
            if requests
                .iter()
                .any(|request| request.method == "POST" && request.url.path() == "/oauth2/token")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("token exchange request should reach the server before shutdown");

    let _ = shutdown_tx.send(true);

    let result = tokio::time::timeout(Duration::from_secs(5), start)
        .await
        .expect("shutdown should interrupt an in-flight startup request")
        .unwrap();
    assert!(
        result.is_ok(),
        "runner should exit cleanly when shutdown interrupts an in-flight startup request"
    );
}

#[tokio::test]
async fn start_retries_transient_malformed_session_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 7200
        })))
        .mount(&mock_server)
        .await;
    // A 200 whose body is not the expected session JSON — a truncated or
    // proxy-mangled response, not a misconfigured registration.
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>gateway</html>"))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sessionId": "session-uuid-123"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202).set_delay(Duration::from_millis(50)))
        .mount(&mock_server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let state = Arc::new(DaemonState::new(&["test-runner".to_string()]));
    let (_temp, runner) = make_startup_runner(
        Some(Arc::clone(&state)),
        format!("{}/oauth2/token", mock_server.uri()),
        mock_server.uri(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let start = tokio::spawn(runner.start(shutdown_rx));

    wait_for_phase(&state, "test-runner", RunnerPhase::Idle)
        .await
        .expect("runner should reach Idle after a malformed session response");

    shutdown_tx.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), start)
        .await
        .expect("runner should exit after shutdown")
        .unwrap();
    assert!(
        result.is_ok(),
        "runner should shut down cleanly after reaching Idle"
    );
}

#[test]
fn startup_error_transient_classification() {
    let auth_status = |code: u16| {
        anyhow::Error::new(AuthError::Status {
            status: reqwest::StatusCode::from_u16(code).unwrap(),
            body: "synthetic body".into(),
        })
        .context("getting initial OAuth token")
    };
    assert!(startup_error_is_transient(&auth_status(503)));
    assert!(startup_error_is_transient(&auth_status(500)));
    assert!(startup_error_is_transient(&auth_status(429)));
    assert!(!startup_error_is_transient(&auth_status(401)));
    assert!(!startup_error_is_transient(&auth_status(400)));

    let auth_invalid_endpoint = anyhow::Error::new(AuthError::InvalidEndpoint("not a url".into()))
        .context("getting initial OAuth token");
    assert!(!startup_error_is_transient(&auth_invalid_endpoint));

    let auth_send =
        anyhow::Error::new(AuthError::Send("dns failure".into())).context("getting token");
    assert!(startup_error_is_transient(&auth_send));

    let auth_bad_response = anyhow::Error::new(AuthError::BadResponse("bad json".into()))
        .context("parsing token exchange response");
    assert!(startup_error_is_transient(&auth_bad_response));

    let broker_server = anyhow::Error::new(BrokerError::ServerError("503: blip".into()))
        .context("creating broker session");
    assert!(startup_error_is_transient(&broker_server));

    let broker_connection = anyhow::Error::new(BrokerError::Connection("reset".into()))
        .context("creating broker session");
    assert!(startup_error_is_transient(&broker_connection));

    let broker_bad_response = anyhow::Error::new(BrokerError::BadResponse("bad json".into()))
        .context("creating broker session");
    assert!(startup_error_is_transient(&broker_bad_response));

    let broker_unauthorized =
        anyhow::Error::new(BrokerError::Unauthorized).context("creating broker session");
    assert!(!startup_error_is_transient(&broker_unauthorized));

    let local = anyhow::anyhow!("reconstructing RSA private key");
    assert!(
        !startup_error_is_transient(&local),
        "local setup failures must stay terminal"
    );
}

#[tokio::test]
async fn poll_loop_401_after_control_message_refreshes_again() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 5,
            "messageType": "AgentRefresh",
            "body": null
        })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 13,
            "messageType": "RunnerJobRequest",
            "body": "{\"runner_request_id\": \"abc123\"}"
        })))
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );

    let (_temp, runner) = make_runner();
    let mut rx = shutdown_tx.subscribe();
    let result = runner.poll_loop(&broker, &mut rx).await.unwrap();
    // A successful control-message poll proves the refreshed token works, so
    // a later 401 is a new expiry and must be refreshed, not treated as
    // "still unauthorized".
    let msg = result.expect("401 after a successful poll should refresh again, not exit");
    assert_eq!(msg.message_id, 13);
}

fn finish_manifest_value(server_url: &str) -> serde_json::Value {
    serde_json::json!({
        "plan": { "planId": "plan", "jobId": "job", "timelineId": "timeline" },
        "steps": [],
        "variables": {
            "system.github.results_endpoint": { "value": server_url, "isSecret": false }
        },
        "resources": {
            "endpoints": [{
                "name": "SystemVssConnection",
                "url": server_url,
                "authorization": {
                    "scheme": "OAuth",
                    "parameters": { "AccessToken": "synthetic" }
                },
                "data": { "PipelinesServiceUrl": server_url }
            }]
        },
        "contextData": {},
        "jobContainer": null,
        "serviceContainers": null
    })
}

fn finish_manifest(server_url: &str) -> JobManifest {
    serde_json::from_value(finish_manifest_value(server_url)).unwrap()
}

async fn finish_client(server: &MockServer) -> Arc<JobClient> {
    let private_key = crate::testing::test_private_key();
    let token_manager = Arc::new(TokenManager::new(
        reqwest::Client::new(),
        format!("{}/oauth2/token", server.uri()),
        private_key,
        "test-client".into(),
    ));
    let mut client = JobClient::new(
        reqwest::Client::new(),
        token_manager,
        server.uri(),
        server.uri(),
    );
    client.set_job_access_token("synthetic-job-token".into());
    Arc::new(client)
}

#[test]
fn cleanup_failure_only_downgrades_success() {
    assert_eq!(
        conclusion_after_cleanup_failure(JobConclusion::Succeeded),
        JobConclusion::Failed
    );
    assert_eq!(
        conclusion_after_cleanup_failure(JobConclusion::Failed),
        JobConclusion::Failed
    );
    assert_eq!(
        conclusion_after_cleanup_failure(JobConclusion::Cancelled),
        JobConclusion::Cancelled
    );
}

#[test]
fn job_execution_error_is_terminal_covers_both_fatal_markers() {
    let cleanup_fatal = anyhow::Error::new(JobResourceCleanupFatalError {
        source: JobDockerConfigError::Cleanup {
            path: "/synthetic/job-resources/attempt".into(),
            source: std::io::Error::other("synthetic cleanup failure"),
        },
    })
    .context("runner job path");
    let poisoned = anyhow::Error::new(JobDockerConfigError::PoisonedRoot {
        path: "/synthetic/job-resources".into(),
    });
    let ordinary = anyhow::anyhow!("job execution failed for an ordinary reason");

    assert!(job_execution_error_is_terminal(&cleanup_fatal));
    assert!(job_execution_error_is_terminal(&poisoned));
    assert!(!job_execution_error_is_terminal(&ordinary));
}

#[tokio::test]
async fn successful_job_reports_failed_when_docker_config_cleanup_fails() {
    use wiremock::matchers::body_json;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/completejob"))
        .and(body_json(serde_json::json!({
            "planId": "plan",
            "jobId": "job",
            "conclusion": "failed",
            "outputs": {},
            "stepResults": []
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let client = finish_client(&server).await;
    let manifest = finish_manifest(&server.uri());
    let execution = Ok(JobExecutionOutcome {
        conclusion: JobConclusion::Succeeded,
        outputs: HashMap::new(),
    });
    let cleanup = Err(JobDockerConfigError::UnsafeEntry {
        path: "/synthetic/job-resource/entry".into(),
    });

    let error = finish_job(&client, &manifest, execution, cleanup)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("job-resource-cleanup-fatal"));
}

#[tokio::test]
async fn execution_and_cleanup_errors_are_both_returned_without_early_completion() {
    let server = MockServer::start().await;
    let client = finish_client(&server).await;
    let manifest = finish_manifest(&server.uri());
    let execution = Err(anyhow::anyhow!("job-execution-category"));
    let cleanup = Err(JobDockerConfigError::UnsafeEntry {
        path: "/synthetic/job-resource/entry".into(),
    });

    let error = finish_job(&client, &manifest, execution, cleanup)
        .await
        .unwrap_err();

    let chain = format!("{error:#}");
    assert!(chain.contains("job-execution-category"));
    assert!(chain.contains("unsafe-job-resource-path"));
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() != "/completejob")
    );
}

fn cache_node_runtimes(runner: &Runner) {
    let node_os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let node_arch = match std::env::consts::ARCH {
        "x86_64" | "x86" => "x64",
        "aarch64" => "arm64",
        other => other,
    };

    for major in ["20", "24"] {
        let node = runner
            .paths
            .externals_dir()
            .join(format!("node{major}-{node_os}-{node_arch}/bin/node"));
        std::fs::create_dir_all(node.parent().unwrap()).unwrap();
        std::fs::write(node, "synthetic node").unwrap();
    }
}

#[tokio::test]
async fn completion_failure_is_not_reported_as_a_setup_failure() {
    use wiremock::matchers::body_json;

    let (server, token_manager, _shutdown_tx) = setup().await;
    let (_temp, runner) = make_runner();
    cache_node_runtimes(&runner);

    Mock::given(method("POST"))
        .and(path("/acquirejob"))
        .and(body_json(serde_json::json!({
            "jobMessageId": "request",
            "runnerOS": "Linux"
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(finish_manifest_value(&server.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/completejob"))
        .respond_with(ResponseTemplate::new(500).set_body_string("completion unavailable"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/twirp/github.actions.results.api.v1.WorkflowStepUpdateService/WorkflowStepsUpdate",
        ))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/twirp/results.services.receiver.Receiver/GetStepLogsSignedBlobURL",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "logs_url": format!("{}/step-log?signature=synthetic", server.uri()),
            "blob_storage_type": ""
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/step-log"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/twirp/results.services.receiver.Receiver/CreateStepLogsMetadata",
        ))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    assert!(
        runner
            .execute_job(
                &reqwest::Client::new(),
                token_manager,
                "request",
                &server.uri(),
                CancellationToken::new(),
            )
            .await
            .is_err()
    );

    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/completejob")
            .count(),
        1
    );
}
