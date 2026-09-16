use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::watch;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::config::ChimeraPaths;
use crate::github::auth::TokenManager;
use crate::github::broker::{BrokerClient, MessageType};
use crate::job::docker_config::JobDockerConfigError;

use super::*;

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

    let private_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();

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
    };

    (temp, runner)
}

#[tokio::test]
async fn poll_loop_returns_job_request() {
    let (mock_server, tm, shutdown_tx) = setup().await;

    Mock::given(method("GET"))
        .and(path("/message"))
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
    let result = runner.poll_loop(&broker, &mut rx).await.unwrap();
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
    assert!(result.is_none());
}

fn finish_manifest(server_url: &str) -> JobManifest {
    serde_json::from_value(serde_json::json!({
        "plan": { "planId": "plan", "jobId": "job", "timelineId": "timeline" },
        "steps": [],
        "variables": {},
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
    }))
    .unwrap()
}

async fn finish_client(server: &MockServer) -> Arc<JobClient> {
    let private_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
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

    finish_job(&client, &manifest, execution, cleanup)
        .await
        .unwrap();
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
