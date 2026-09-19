use super::*;
use crate::github::auth::TokenManager;
use crate::job::timeline;
use std::io::Write;
use std::sync::Mutex;
use tracing_subscriber::fmt::MakeWriter;
use wiremock::matchers::{body_json, header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone, Default)]
struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

impl CapturedWriter {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn debug_dispatch(writer: CapturedWriter) -> tracing::Dispatch {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .with_writer(writer)
        .finish();
    tracing::Dispatch::new(subscriber)
}

async fn setup() -> (MockServer, Arc<TokenManager>) {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-oauth-token",
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

fn make_client(
    mock_server: &MockServer,
    token_manager: Arc<TokenManager>,
    job_token: bool,
) -> JobClient {
    let mut client = JobClient::new(
        reqwest::Client::new(),
        token_manager,
        mock_server.uri(),
        mock_server.uri(),
    );
    if job_token {
        client.set_job_access_token("test-job-token".into());
    }
    client
}

#[tokio::test]
async fn acquire_job_correct_body_and_response() {
    let (mock_server, tm) = setup().await;

    let manifest_json = include_str!("../../tests/fixtures/job_manifest.json");
    let manifest_value: serde_json::Value = serde_json::from_str(manifest_json).unwrap();

    Mock::given(method("POST"))
        .and(path("/acquirejob"))
        .and(body_json(serde_json::json!({
            "jobMessageId": "req-123",
            "runnerOS": "Linux",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(manifest_value))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, tm, false);
    let manifest = client.acquire_job("req-123").await.unwrap();
    assert_eq!(manifest.plan.plan_id, "plan-001");
    assert_eq!(manifest.steps.len(), 2);
}

#[tokio::test]
async fn acquire_job_timeout_error() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("POST"))
        .and(path("/acquirejob"))
        .respond_with(ResponseTemplate::new(408).set_body_string("timeout"))
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, tm, false);
    let result = client.acquire_job("req-123").await;
    assert!(result.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn acquire_job_semantic_error_omits_raw_and_normalized_canary() {
    let (mock_server, tm) = setup().await;
    Mock::given(method("POST"))
        .and(path("/acquirejob"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "variables": "CANARY-MANIFEST",
            "jobContainer": { "image": "CANARY-MANIFEST" }
        })))
        .mount(&mock_server)
        .await;
    let captured = CapturedWriter::default();
    let dispatch = debug_dispatch(captured.clone());
    let _guard = tracing::dispatcher::set_default(&dispatch);

    let error = make_client(&mock_server, tm, false)
        .acquire_job("req-123")
        .await
        .unwrap_err();
    let combined = format!("{}\n{}", error, captured.text());

    assert!(
        error
            .to_string()
            .contains("deserializing normalized job manifest")
    );
    assert!(!combined.contains("CANARY-MANIFEST"));
}

#[tokio::test(flavor = "current_thread")]
async fn acquire_job_syntax_error_reports_category_and_position_without_body() {
    let (mock_server, tm) = setup().await;
    let body = r#"{"CANARY-SYNTAX":"#;
    Mock::given(method("POST"))
        .and(path("/acquirejob"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&mock_server)
        .await;
    let captured = CapturedWriter::default();
    let dispatch = debug_dispatch(captured.clone());
    let _guard = tracing::dispatcher::set_default(&dispatch);

    let error = make_client(&mock_server, tm, false)
        .acquire_job("req-123")
        .await
        .unwrap_err();
    let message = error.to_string();

    assert!(message.contains("parsing raw job manifest JSON failed"));
    assert!(message.contains("Eof"));
    assert!(message.contains("line 1"));
    assert!(message.contains("column"));
    assert!(!format!("{message}\n{}", captured.text()).contains("CANARY-SYNTAX"));
}

#[tokio::test(flavor = "current_thread")]
async fn acquire_job_http_error_reports_status_and_length_without_response_body() {
    let (mock_server, tm) = setup().await;
    let body = "CANARY-HTTP-BODY";
    Mock::given(method("POST"))
        .and(path("/acquirejob"))
        .respond_with(ResponseTemplate::new(503).set_body_string(body))
        .mount(&mock_server)
        .await;

    let error = make_client(&mock_server, tm, false)
        .acquire_job("req-123")
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("503 Service Unavailable"));
    assert!(error.contains(&format!("response body {} bytes", body.len())));
    assert!(!error.contains(body));
}

#[tokio::test(flavor = "current_thread")]
async fn job_api_error_responses_never_include_response_body() {
    let (mock_server, tm) = setup().await;
    const CANARY: &str = "CANARY-API-BODY";
    Mock::given(path_regex(r"^/(renewjob|completejob|twirp/|_apis/|blob$)"))
        .respond_with(ResponseTemplate::new(500).set_body_string(CANARY))
        .mount(&mock_server)
        .await;

    let mut client = make_client(&mock_server, tm, true);
    client.set_results_url(mock_server.uri());
    let signed = SignedUrlResponse {
        logs_url: format!("{}/blob?sig=x", mock_server.uri()),
        blob_storage_type: "BLOB_STORAGE_TYPE_AZURE".into(),
    };
    let captured = CapturedWriter::default();
    let dispatch = debug_dispatch(captured.clone());
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let mut returned_errors = Vec::new();

    client.renew_job("p", "j").await.unwrap();
    if let Err(error) = client
        .complete_job("p", "j", JobConclusion::Failed, &serde_json::json!({}), &[])
        .await
    {
        returned_errors.push(error.to_string());
    }
    client.update_steps("p", "j", &[]).await.unwrap();
    if let Err(error) = client.get_job_log_signed_url("p", "j").await {
        returned_errors.push(error.to_string());
    }
    for result in [
        client.create_append_blob(&signed).await,
        client.append_blob_block(&signed, "safe-content").await,
    ] {
        if let Err(error) = result {
            returned_errors.push(error.to_string());
        }
    }
    client.seal_blob(&signed).await.unwrap();
    client.create_job_log_metadata("p", "j", 1).await.unwrap();
    client
        .create_step_log_metadata("p", "j", "s", 1)
        .await
        .unwrap();
    if let Err(error) = client.create_log("p", "step").await {
        returned_errors.push(error.to_string());
    }
    client.upload_log_lines("p", 1, "safe").await.unwrap();
    client.update_timeline("p", "t", &[]).await.unwrap();

    let combined = format!("{}\n{}", returned_errors.join("\n"), captured.text());
    assert!(!combined.contains(CANARY), "API body leaked: {combined}");
}

#[tokio::test]
async fn renew_job_correct_body() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("POST"))
        .and(path("/renewjob"))
        .and(body_json(serde_json::json!({
            "planId": "plan-1",
            "jobId": "job-1",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "lockedUntil": "2024-01-01T00:10:00Z"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, tm, true);
    client.renew_job("plan-1", "job-1").await.unwrap();
}

#[tokio::test]
async fn complete_job_sends_conclusion_and_outputs() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("POST"))
        .and(path("/completejob"))
        .and(body_json(serde_json::json!({
            "planId": "plan-1",
            "jobId": "job-1",
            "conclusion": "succeeded",
            "outputs": {},
            "stepResults": [],
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, tm, true);
    client
        .complete_job(
            "plan-1",
            "job-1",
            super::JobConclusion::Succeeded,
            &serde_json::json!({}),
            &[],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn create_log_returns_id() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 42
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, tm, true);
    let log_id = client.create_log("plan-1", "step-log").await.unwrap();
    assert_eq!(log_id, 42);
}

#[tokio::test]
async fn upload_log_lines_sends_text_plain() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs/\d+"))
        .and(header("Content-Type", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, tm, true);
    client
        .upload_log_lines("plan-1", 42, "2024-01-01T00:00:00.0000000Z hello\n")
        .await
        .unwrap();
}

#[tokio::test]
async fn update_timeline_sends_patch() {
    let (mock_server, tm) = setup().await;

    Mock::given(method("PATCH"))
        .and(path_regex(
            r"/_apis/pipelines/workflows/.*/timelines/.*/records",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = make_client(&mock_server, tm, true);
    let records = vec![timeline::TimelineRecord {
        id: "step-1".into(),
        state: Some(timeline::TimelineState::InProgress),
        result: None,
        start_time: Some("2024-01-01T00:00:00.0000000Z".into()),
        finish_time: None,
        name: Some("Run tests".into()),
        order: Some(1),
        log: None,
    }];

    client
        .update_timeline("plan-1", "timeline-1", &records)
        .await
        .unwrap();
}

#[test]
fn results_status_wire_values_match_official_runner() {
    let json = |s: ResultsStatus| serde_json::to_string(&s).unwrap();

    assert_eq!(json(ResultsStatus::InProgress), "3");
    assert_eq!(json(ResultsStatus::Pending), "5");
    assert_eq!(json(ResultsStatus::Completed), "6");
}

#[test]
fn results_conclusion_wire_values_match_official_runner() {
    let json = |c: ResultsConclusion| serde_json::to_string(&c).unwrap();

    assert_eq!(json(ResultsConclusion::Unknown), "0");
    assert_eq!(json(ResultsConclusion::Success), "2");
    assert_eq!(json(ResultsConclusion::Failure), "3");
    assert_eq!(json(ResultsConclusion::Cancelled), "4");
    // Not 5 — GitHub renders 5 as `action_required`.
    assert_eq!(json(ResultsConclusion::Skipped), "7");
}
