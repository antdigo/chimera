use std::sync::Arc;

use anyhow::anyhow;
use tokio::sync::RwLock;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::github::auth::TokenManager;
use crate::job::secret_masker::SecretMasker;

fn manifest() -> JobManifest {
    serde_json::from_value(serde_json::json!({
        "plan": {
            "planId": "plan",
            "jobId": "job",
            "timelineId": "timeline"
        },
        "steps": [],
        "variables": {},
        "resources": { "endpoints": [] },
        "contextData": {},
        "jobContainer": null,
        "serviceContainers": null
    }))
    .unwrap()
}

fn job_client(server: &MockServer) -> JobClient {
    let token_manager = Arc::new(TokenManager::new(
        reqwest::Client::new(),
        format!("{}/oauth2/token", server.uri()),
        crate::testing::test_private_key(),
        "test-client".into(),
    ));
    let mut client = JobClient::new(
        reqwest::Client::new(),
        token_manager,
        server.uri(),
        server.uri(),
    );
    client.set_job_access_token("test-job-token".into());
    client.set_results_url(server.uri());
    client
}

#[tokio::test]
async fn setup_failure_blob_masks_nested_error_chain() {
    let server = MockServer::start().await;
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
            "logs_url": format!("{}/blob?sig=test", server.uri()),
            "blob_storage_type": "BLOB_STORAGE_TYPE_AZURE"
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/blob"))
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
    Mock::given(method("POST"))
        .and(path("/completejob"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let source = anyhow!("source contains CANARY-SETUP and CANARY\nJSON");
    let error = source.context("safe setup stage");
    let mut masker = SecretMasker::default();
    masker.add_value("CANARY-SETUP and CANARY\nJSON");
    let masker = Arc::new(RwLock::new(masker));

    report_setup_failure(&job_client(&server), &manifest(), &error, &masker)
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    let blob = requests
        .iter()
        .find(|request| {
            request.method.as_str() == "PUT"
                && request.url.path() == "/blob"
                && request
                    .url
                    .query_pairs()
                    .any(|(key, value)| key == "comp" && value == "appendblock")
        })
        .expect("append blob request");
    let body = String::from_utf8_lossy(&blob.body);

    assert!(
        body.contains("safe setup stage"),
        "missing safe context: {body}"
    );
    assert!(body.contains("***"), "missing redaction marker: {body}");
    for canary in ["CANARY", "JSON"] {
        assert!(!body.contains(canary), "blob leaked {canary}: {body}");
    }
}
