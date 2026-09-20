use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::github::auth::TokenManager;
use crate::utils::format_log_timestamp;
use wiremock::matchers::{header, method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup_log_server() -> (MockServer, Arc<JobClient>) {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/oauth2/token"))
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

    let mut job_client = super::super::JobClient::new(
        reqwest::Client::new(),
        tm,
        mock_server.uri(),
        mock_server.uri(),
    );
    job_client.set_job_access_token("test-job-token".into());

    (mock_server, Arc::new(job_client))
}

/// Same as `setup_log_server`, but with the Results API configured so the blob
/// collectors have somewhere to upload to.
async fn setup_results_server() -> (MockServer, Arc<JobClient>) {
    let (mock_server, client) = setup_log_server().await;
    let mut client = Arc::try_unwrap(client).ok().expect("sole owner");
    client.set_results_url(mock_server.uri());
    (mock_server, Arc::new(client))
}

/// Mount a mock for creating a legacy log (returns log ID 1).
async fn mount_create_log(mock_server: &MockServer) {
    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": 1 })))
        .mount(mock_server)
        .await;
}

#[test]
fn format_log_timestamp_seven_decimal_places() {
    use chrono::TimeZone;
    let ts = Utc.with_ymd_and_hms(2024, 6, 15, 12, 30, 45).unwrap();
    let formatted = format_log_timestamp(ts);
    assert_eq!(formatted, "2024-06-15T12:30:45.0000000Z");
    assert!(formatted.contains(".0000000Z"));
}

#[tokio::test]
async fn flush_on_sender_drop() {
    let (mock_server, client) = setup_log_server().await;
    mount_create_log(&mock_server).await;

    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs/\d+"))
        .and(header("Content-Type", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan-1", "step-1", masks, None).await;

    logger.sender().send("hello world".into()).await;
    logger.finish().await;
}

#[tokio::test]
async fn flush_on_interval() {
    let (mock_server, client) = setup_log_server().await;
    mount_create_log(&mock_server).await;

    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs/\d+"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1..)
        .mount(&mock_server)
        .await;

    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan-1", "step-1", masks, None).await;

    logger.sender().send("line 1".into()).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;

    logger.finish().await;
}

#[tokio::test]
async fn flush_on_large_buffer() {
    let (mock_server, client) = setup_log_server().await;
    mount_create_log(&mock_server).await;

    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs/\d+"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1..)
        .mount(&mock_server)
        .await;

    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::legacy(client, "plan-1", "step-1", masks, None).await;

    let big_line = "x".repeat(70_000);
    logger.sender().send(big_line).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    logger.finish().await;
}

#[tokio::test]
async fn masking_replaces_secrets() {
    let (mock_server, client) = setup_log_server().await;
    mount_create_log(&mock_server).await;

    let uploaded = Arc::new(tokio::sync::Mutex::new(String::new()));
    let uploaded_clone = uploaded.clone();

    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs/\d+"))
        .respond_with(move |req: &wiremock::Request| {
            let body = String::from_utf8_lossy(&req.body).to_string();
            let uploaded = uploaded_clone.clone();
            tokio::spawn(async move {
                let mut guard = uploaded.lock().await;
                guard.push_str(&body);
            });
            ResponseTemplate::new(200)
        })
        .mount(&mock_server)
        .await;

    let masks = crate::job::secret_masker::shared_masker_for_test(&["supersecret"]);
    let logger = StepLogger::legacy(client, "plan-1", "step-1", masks, None).await;

    logger
        .sender()
        .send("my password is supersecret here".into())
        .await;
    logger.finish().await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let content = uploaded.lock().await;
    assert!(!content.contains("supersecret"), "secret should be masked");
    assert!(content.contains("***"), "should contain mask replacement");
}

#[tokio::test]
async fn legacy_vss_masks_multiline_and_json_encoded_canaries() {
    let (mock_server, client) = setup_log_server().await;
    mount_create_log(&mock_server).await;

    let uploaded = Arc::new(tokio::sync::Mutex::new(String::new()));
    let sink = uploaded.clone();
    Mock::given(method("POST"))
        .and(path_regex(r"/_apis/pipelines/workflows/.*/logs/\d+"))
        .respond_with(move |req: &wiremock::Request| {
            let body = String::from_utf8_lossy(&req.body).to_string();
            let sink = sink.clone();
            tokio::spawn(async move { sink.lock().await.push_str(&body) });
            ResponseTemplate::new(200)
        })
        .mount(&mock_server)
        .await;

    let secret = "two-lines\nquote-\"slash\\";
    let masks = crate::job::secret_masker::shared_masker_for_test(&[secret]);
    let logger = StepLogger::legacy(client, "plan-1", "step-1", masks, None).await;

    logger.sender().send("safe-one=two-lines".into()).await;
    logger
        .sender()
        .send("safe-two=quote-\"slash\\".into())
        .await;
    logger
        .sender()
        .send(r#"safe-json=two-lines\nquote-\"slash\\"#.into())
        .await;
    logger.finish().await;
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let content = uploaded.lock().await;
    assert!(content.contains("safe-one=***"));
    assert!(content.contains("safe-two=***"));
    assert!(content.contains("safe-json=***"));
    assert!(!content.contains("two-lines"));
    assert!(!content.contains("quote-\"slash\\"));
    assert!(!content.contains(r#"two-lines\nquote-\"slash\\"#));
}

#[tokio::test]
async fn collector_collects_lines() {
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let logger = StepLogger::results_for_test(masks);

    logger.sender().send("line one".into()).await;
    logger.sender().send("line two".into()).await;

    let collected = logger.finish().await.expect("should collect lines");
    assert_eq!(collected.line_count, 2);
    assert!(collected.text.contains("line one"));
    assert!(collected.text.contains("line two"));
}

#[tokio::test]
async fn collector_masks_secrets() {
    let masks = crate::job::secret_masker::shared_masker_for_test(&["secret123"]);
    let logger = StepLogger::results_for_test(masks);

    logger.sender().send("token is secret123 here".into()).await;

    let collected = logger.finish().await.expect("should collect lines");
    assert!(!collected.text.contains("secret123"));
    assert!(collected.text.contains("***"));
}

#[tokio::test]
async fn collector_applies_regex_mask_hints() {
    let masks =
        crate::job::secret_masker::shared_masker_with_regex_for_test(&[], &[r"credential-[0-9]+"]);
    let logger = StepLogger::results_for_test(masks);

    logger
        .sender()
        .send("token is credential-12345 here".into())
        .await;

    let collected = logger.finish().await.expect("should collect lines");
    assert!(!collected.text.contains("credential-12345"));
    assert!(collected.text.contains("***"));
}

#[tokio::test]
async fn collector_merges_overlapping_value_and_regex_masks() {
    let masks = crate::job::secret_masker::shared_masker_with_regex_for_test(
        &["secret"],
        &[r"secret-[0-9]+"],
    );
    let logger = StepLogger::results_for_test(masks);

    logger
        .sender()
        .send("token is secret-12345 here".into())
        .await;

    let collected = logger.finish().await.expect("should collect lines");
    assert!(collected.text.contains("token is *** here"));
    assert!(!collected.text.contains("12345"));
}

/// Mount the Results endpoints a blob collector needs, recording every line that
/// reaches the blob and counting the metadata publishes.
async fn mount_results_blob(
    mock_server: &MockServer,
    signed_url_path: &str,
    metadata_path: &str,
) -> (Arc<tokio::sync::Mutex<String>>, Arc<AtomicUsize>) {
    let appended = Arc::new(tokio::sync::Mutex::new(String::new()));
    let metadata_calls = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path_regex(format!(".*{signed_url_path}$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "logs_url": format!("{}/blob?sig=x", mock_server.uri()),
            "blob_storage_type": "BLOB_STORAGE_TYPE_AZURE",
        })))
        .mount(mock_server)
        .await;

    let sink = appended.clone();
    Mock::given(method("PUT"))
        .and(path_regex(r"/blob$"))
        .respond_with(move |req: &wiremock::Request| {
            let body = String::from_utf8_lossy(&req.body).to_string();
            let sink = sink.clone();
            tokio::spawn(async move { sink.lock().await.push_str(&body) });
            ResponseTemplate::new(201)
        })
        .mount(mock_server)
        .await;

    let counter = metadata_calls.clone();
    Mock::given(method("POST"))
        .and(path_regex(format!(".*{metadata_path}$")))
        .respond_with(move |_: &wiremock::Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200)
        })
        .mount(mock_server)
        .await;

    (appended, metadata_calls)
}

async fn mount_distinct_results_blob(
    mock_server: &MockServer,
    signed_url_path: &str,
    metadata_path: &str,
    blob_path: &str,
) -> Arc<tokio::sync::Mutex<String>> {
    Mock::given(method("POST"))
        .and(path_regex(format!(".*{signed_url_path}$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "logs_url": format!("{}{blob_path}?sig=x", mock_server.uri()),
            "blob_storage_type": "BLOB_STORAGE_TYPE_AZURE",
        })))
        .mount(mock_server)
        .await;

    let appended = Arc::new(tokio::sync::Mutex::new(String::new()));
    let sink = appended.clone();
    Mock::given(method("PUT"))
        .and(path_regex(format!(r"{blob_path}$")))
        .respond_with(move |req: &wiremock::Request| {
            let body = String::from_utf8_lossy(&req.body).to_string();
            let sink = sink.clone();
            tokio::spawn(async move { sink.lock().await.push_str(&body) });
            ResponseTemplate::new(201)
        })
        .mount(mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path_regex(format!(".*{metadata_path}$")))
        .respond_with(ResponseTemplate::new(200))
        .mount(mock_server)
        .await;

    appended
}

#[tokio::test]
async fn results_step_and_job_blobs_receive_identical_masked_content() {
    let (mock_server, client) = setup_results_server().await;
    let step_blob = mount_distinct_results_blob(
        &mock_server,
        "GetStepLogsSignedBlobURL",
        "CreateStepLogsMetadata",
        "/step-blob",
    )
    .await;
    let job_blob = mount_distinct_results_blob(
        &mock_server,
        "GetJobLogsSignedBlobURL",
        "CreateJobLogsMetadata",
        "/job-blob",
    )
    .await;

    let secret = "two-lines\nquote-\"slash\\";
    let masks = crate::job::secret_masker::shared_masker_for_test(&[secret]);
    let job_logger = JobLogger::new(client.clone(), "plan-1".into(), "job-1".into());
    let step = StepLogger::results(
        client,
        "plan-1".into(),
        "job-1".into(),
        "step-1".into(),
        masks,
        None,
        Some(job_logger.sender()),
    );

    step.sender().send("safe-one=two-lines".into()).await;
    step.sender().send("safe-two=quote-\"slash\\".into()).await;
    step.sender()
        .send(r#"safe-json=two-lines\nquote-\"slash\\"#.into())
        .await;
    step.finish().await;
    job_logger.finish().await;
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let step_content = step_blob.lock().await.clone();
    let job_content = job_blob.lock().await.clone();
    assert_eq!(step_content, job_content);
    for content in [&step_content, &job_content] {
        assert!(content.contains("safe-one=***"));
        assert!(content.contains("safe-two=***"));
        assert!(content.contains("safe-json=***"));
        assert!(!content.contains("two-lines"));
        assert!(!content.contains("quote-\"slash\\"));
        assert!(!content.contains(r#"two-lines\nquote-\"slash\\"#));
    }
}

#[tokio::test]
async fn job_logger_streams_and_publishes_once() {
    let (mock_server, client) = setup_results_server().await;
    let (appended, metadata_calls) = mount_results_blob(
        &mock_server,
        "GetJobLogsSignedBlobURL",
        "CreateJobLogsMetadata",
    )
    .await;

    let job_logger = JobLogger::new(client.clone(), "plan-1".into(), "job-1".into());
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let step = StepLogger::results(
        client,
        "plan-1".into(),
        "job-1".into(),
        "step-1".into(),
        masks,
        None,
        Some(job_logger.sender()),
    );

    step.sender().send("hello from the step".into()).await;
    step.finish().await;
    job_logger.finish().await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let content = appended.lock().await;
    assert!(
        content.contains("hello from the step"),
        "step line should reach the job log blob, got: {content}"
    );
    // Once for the job log; the step blob publishes as it streams and is mounted
    // on a different path, so it does not land in this counter.
    assert_eq!(metadata_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn job_logger_skips_upload_when_no_output() {
    let (mock_server, client) = setup_results_server().await;
    let (_, metadata_calls) = mount_results_blob(
        &mock_server,
        "GetJobLogsSignedBlobURL",
        "CreateJobLogsMetadata",
    )
    .await;

    JobLogger::new(client, "plan-1".into(), "job-1".into())
        .finish()
        .await;

    assert_eq!(metadata_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn step_without_job_logger_still_uploads_its_own_blob() {
    let (mock_server, client) = setup_results_server().await;
    let (appended, _) = mount_results_blob(
        &mock_server,
        "GetStepLogsSignedBlobURL",
        "CreateStepLogsMetadata",
    )
    .await;

    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let step = StepLogger::results(
        client,
        "plan-1".into(),
        "job-1".into(),
        "step-1".into(),
        masks,
        None,
        None,
    );

    step.sender().send("step only".into()).await;
    step.finish().await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert!(appended.lock().await.contains("step only"));
}
