use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::github::auth::TokenManager;
use crate::github::broker::BrokerClient;

use super::spawn_cancel_poller;

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

#[tokio::test]
async fn cancel_poller_triggers_token_on_cancellation() {
    let (mock_server, tm, _shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 42,
            "messageType": "JobCancellation",
            "body": "{\"jobId\": \"job-123\"}"
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

    let cancel_token = CancellationToken::new();
    let handle = spawn_cancel_poller(&broker, cancel_token.clone());

    tokio::time::timeout(Duration::from_secs(5), cancel_token.cancelled())
        .await
        .expect("cancel token should be triggered within 5s");

    assert!(cancel_token.is_cancelled());
    let _ = handle.await;
}

#[tokio::test]
async fn cancel_poller_polls_with_busy_status() {
    let (mock_server, tm, _shutdown_tx) = setup().await;

    // Only requests reporting the agent as Busy may be answered; anything the
    // poller sends with another status falls through to wiremock's 404.
    Mock::given(method("GET"))
        .and(path("/message"))
        .and(query_param("status", "Busy"))
        .respond_with(ResponseTemplate::new(202))
        .expect(3..)
        .mount(&mock_server)
        .await;

    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );

    let cancel_token = CancellationToken::new();
    let handle = spawn_cancel_poller(&broker, cancel_token.clone());

    // The broker only delivers JobCancellation to a session that reports
    // Busy while its job executes, so every poll the cancel poller makes
    // must carry status=Busy — from the first request on, not just once.
    // Let several poll cycles run so a regression that mixes statuses gets
    // caught by the every-poll assertion below.
    let min_polls = 3;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let busy_polls = count_busy_message_polls(&mock_server).await;
        if busy_polls >= min_polls {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cancel poller issued only {busy_polls} polls with status=Busy"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    cancel_token.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("poller should exit within 5s")
        .expect("poller task should not panic");

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock request journal disabled");
    let all_polls_busy = requests
        .iter()
        .filter(|request| is_message_poll(request))
        .all(|request| {
            request
                .url
                .query_pairs()
                .any(|(key, value)| key == "status" && value == "Busy")
        });
    assert!(
        all_polls_busy,
        "cancel poller issued a GET /message without status=Busy"
    );
}

async fn count_busy_message_polls(mock_server: &MockServer) -> usize {
    mock_server
        .received_requests()
        .await
        .expect("wiremock request journal disabled")
        .iter()
        .filter(|request| is_message_poll(request))
        .filter(|request| {
            request
                .url
                .query_pairs()
                .any(|(key, value)| key == "status" && value == "Busy")
        })
        .count()
}

fn is_message_poll(request: &wiremock::Request) -> bool {
    request.method == "GET" && request.url.path() == "/message"
}

#[tokio::test]
async fn cancel_poller_stops_when_token_cancelled_externally() {
    let (mock_server, tm, _shutdown_tx) = setup().await;

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

    let cancel_token = CancellationToken::new();
    let handle = spawn_cancel_poller(&broker, cancel_token.clone());

    cancel_token.cancel();

    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("poller should exit within 5s")
        .expect("poller task should not panic");
}

#[tokio::test]
async fn cancel_poller_unknown_message_trace_omits_external_type() {
    let (mock_server, tm, _shutdown_tx) = setup().await;
    let canary = "CANARY-UNKNOWN-MESSAGE-TYPE";

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 91,
            "messageType": canary,
            "body": null
        })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );
    let captured = crate::testing::TracingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .without_time()
        .with_writer(captured.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let cancel_token = CancellationToken::new();
    let handle = spawn_cancel_poller(&broker, cancel_token.clone());

    let deadline = Instant::now() + Duration::from_secs(5);
    while !captured
        .text()
        .contains("received non-cancellation message while busy")
    {
        assert!(
            Instant::now() < deadline,
            "poller did not emit the control-message trace"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cancel_token.cancel();
    handle.await.unwrap();
    let trace = captured.text();

    assert!(trace.contains("message_type=Unknown"), "{trace}");
    assert!(!trace.contains(canary), "{trace}");
}

#[tokio::test]
async fn cancel_poller_error_trace_omits_broker_response_body() {
    let (mock_server, tm, _shutdown_tx) = setup().await;
    let canary = "CANARY-CANCEL-POLL-BODY";

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(500).set_body_string(canary))
        .mount(&mock_server)
        .await;
    let broker = BrokerClient::new(
        reqwest::Client::new(),
        mock_server.uri(),
        "session-123".into(),
        tm,
    );
    let captured = crate::testing::TracingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .without_time()
        .with_writer(captured.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let cancel_token = CancellationToken::new();
    let handle = spawn_cancel_poller(&broker, cancel_token.clone());

    let deadline = Instant::now() + Duration::from_secs(5);
    while !captured.text().contains("cancellation poll failed") {
        assert!(
            Instant::now() < deadline,
            "poller did not emit an error trace"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cancel_token.cancel();
    handle.await.unwrap();
    let trace = captured.text();

    assert!(trace.contains("error_kind"), "{trace}");
    assert!(!trace.contains(canary), "{trace}");
}
