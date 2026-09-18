use std::time::Duration;

use super::*;
use crate::github::auth::TokenManager;
use wiremock::matchers::{body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup() -> (MockServer, Arc<TokenManager>) {
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

    (mock_server, tm)
}

fn make_client(server_url: &str, tm: Arc<TokenManager>) -> BrokerClient {
    BrokerClient::new(
        reqwest::Client::new(),
        server_url.to_string(),
        "session-123".into(),
        tm,
    )
}

// --- Session tests ---

#[tokio::test]
async fn connect_creates_session() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("POST"))
        .and(path("/session"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sessionId": "session-uuid-123"
        })))
        .mount(&mock_server)
        .await;

    let client = BrokerClient::connect(
        reqwest::Client::new(),
        &mock_server.uri(),
        tm,
        42,
        "chimera-0",
    )
    .await
    .unwrap();

    assert_eq!(client.session_id(), "session-uuid-123");
}

#[tokio::test]
async fn connect_version_rejected() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("POST"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(400).set_body_string("runner version too old"))
        .mount(&mock_server)
        .await;

    let result = BrokerClient::connect(
        reqwest::Client::new(),
        &mock_server.uri(),
        tm,
        42,
        "chimera-0",
    )
    .await;

    let err = result.err().expect("should be an error");
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("400"),
        "error should mention 400: {err_msg}"
    );
}

#[tokio::test]
async fn connect_marks_persistent_runner_as_non_ephemeral() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("POST"))
        .and(path("/session"))
        .and(body_partial_json(serde_json::json!({
            "useFipsEncryption": false,
            "agent": {
                "id": 1,
                "name": "r0",
                "version": RUNNER_VERSION,
                "ephemeral": false,
                "status": 0
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sessionId": "abc"
        })))
        .mount(&mock_server)
        .await;

    BrokerClient::connect(reqwest::Client::new(), &mock_server.uri(), tm, 1, "r0")
        .await
        .unwrap();
}

#[tokio::test]
async fn disconnect_success() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("DELETE"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server.uri(), tm);
    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn disconnect_404_is_ok() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("DELETE"))
        .and(path("/session"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server.uri(), tm);
    let result = client.disconnect().await;
    assert!(result.is_ok(), "404 should be treated as success");
}

// --- Poll tests ---

#[tokio::test]
async fn poll_202_returns_none() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .and(query_param("sessionId", "session-123"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server.uri(), tm);
    let result = client.poll_message(AgentStatus::Online).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn poll_200_returns_message() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messageId": 12345,
            "messageType": "RunnerJobRequest",
            "body": "{\"runner_request_id\": \"abc\"}"
        })))
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server.uri(), tm);
    let msg = client
        .poll_message(AgentStatus::Online)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(msg.message_id, 12345);
    assert_eq!(msg.message_type, MessageType::RunnerJobRequest);
    assert!(msg.body.is_some());
}

#[tokio::test]
async fn poll_sends_requested_agent_status_on_the_wire() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .and(query_param("status", "Busy"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server.uri(), tm);
    let result = client.poll_message(AgentStatus::Busy).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn ack_job_posts_acknowledge() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("POST"))
        .and(path("/acknowledge"))
        .and(query_param("sessionId", "session-123"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server.uri(), tm);
    client.ack_job("request-abc").await.unwrap();
}

#[tokio::test]
async fn poll_500_returns_error() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server.uri(), tm);
    let result = client.poll_message(AgentStatus::Online).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn poll_401_returns_error() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server.uri(), tm);
    let result = client.poll_message(AgentStatus::Online).await;
    let err = result.unwrap_err();
    assert!(
        err.downcast_ref::<BrokerError>()
            .is_some_and(|be| matches!(be, BrokerError::Unauthorized)),
        "expected BrokerError::Unauthorized, got: {err}"
    );
}

#[tokio::test]
async fn poll_timeout_classified_as_broker_timeout() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(202).set_delay(Duration::from_secs(5)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server.uri(), tm).with_poll_timeout(Duration::from_millis(300));
    let result = client.poll_message(AgentStatus::Online).await;
    let err = result.expect_err("client timeout should be an error");
    assert!(
        err.downcast_ref::<BrokerError>()
            .is_some_and(|be| matches!(be, BrokerError::Timeout)),
        "expected BrokerError::Timeout, got: {err}"
    );
    assert!(
        err.to_string().contains("poll timeout"),
        "error display should name the timeout, not mask it: {err}"
    );
}

#[tokio::test]
async fn poll_connect_timeout_classified_as_connection_error() {
    // The mock server only serves the token endpoint the TokenManager hits.
    let (_mock_server, tm) = setup().await;

    // A local listener that accepts the TCP connection but never speaks
    // TLS: the handshake stalls until the connect timeout fires, without
    // depending on external routing or proxy configuration.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let conn = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(10));
        drop(conn);
    });

    // The production client configures a connect timeout shorter than the
    // poll deadline; a stalled connect must surface as a connection error
    // (warn + backoff), never as a quiet long-poll timeout.
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(500))
        .no_proxy()
        .build()
        .unwrap();
    let broker = BrokerClient::new(
        client,
        format!("https://{addr}"),
        "session-123".into(),
        tm.clone(),
    )
    .with_poll_timeout(Duration::from_secs(60));

    // Warm the token cache so the poll itself is the only HTTP request left.
    tm.get_token().await.unwrap();

    let result = broker.poll_message(AgentStatus::Online).await;
    let err = result.expect_err("stalled connect should be an error");
    assert!(
        err.downcast_ref::<BrokerError>()
            .is_some_and(|be| matches!(be, BrokerError::Connection(_))),
        "expected BrokerError::Connection, got: {err}"
    );
}
