use super::*;
use crate::config::{ChimeraConfig, load_config, save_config};
use crate::storage::RootLock;
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn parse_repo_url() {
    let target = GitHubTarget::parse("https://github.com/myorg/myrepo").unwrap();
    assert_eq!(
        target,
        GitHubTarget::Repo {
            owner: "myorg".into(),
            repo: "myrepo".into(),
        }
    );
}

#[test]
fn parse_org_url() {
    let target = GitHubTarget::parse("https://github.com/myorg").unwrap();
    assert_eq!(
        target,
        GitHubTarget::Org {
            org: "myorg".into(),
        }
    );
}

#[test]
fn parse_url_with_trailing_slash() {
    let target = GitHubTarget::parse("https://github.com/org/repo/").unwrap();
    assert_eq!(
        target,
        GitHubTarget::Repo {
            owner: "org".into(),
            repo: "repo".into(),
        }
    );
}

#[test]
fn parse_invalid_url_errors() {
    assert!(GitHubTarget::parse("https://gitlab.com/org/repo").is_err());
    assert!(GitHubTarget::parse("https://github.com/a/b/c").is_err());
    assert!(GitHubTarget::parse("not-a-url").is_err());
}

#[tokio::test]
async fn v1_registration_via_pipelines() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex("/_apis/connectionData.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "locationServiceData": {
                "serviceDefinitions": []
            }
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(wiremock::matchers::path_regex(
            "/_apis/distributedtask/pools/1/agents.*",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 42,
            "name": "test-runner",
            "authorization": {
                "authorizationUrl": format!("{}/oauth2/token", mock_server.uri()),
                "clientId": "client-id-xyz"
            }
        })))
        .mount(&mock_server)
        .await;

    let auth = GitHubAuthResult {
        url: mock_server.uri(),
        token: "test-oauth-token".into(),
        extra: serde_json::Value::Object(serde_json::Map::new()),
    };

    let private_key = crate::testing::test_private_key();
    let result = register_v1(
        &reqwest::Client::new(),
        &auth,
        "test-runner",
        &private_key,
        &[],
    )
    .await
    .unwrap();

    assert_eq!(result.agent_id, 42);
    assert_eq!(result.agent_name, "test-runner");
    assert_eq!(result.client_id, "client-id-xyz");
    assert!(result.authorization_url.contains("/oauth2/token"));
}

#[tokio::test]
async fn unregister_removes_files() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();

    let runner_dir = root.join("runners").join("test-runner");
    std::fs::create_dir_all(&runner_dir).unwrap();
    std::fs::write(runner_dir.join("runner.json"), "{}").unwrap();
    std::fs::write(runner_dir.join("credentials.json"), "{}").unwrap();

    let config = ChimeraConfig {
        runners: vec!["test-runner".into(), "other-runner".into()],
        ..Default::default()
    };
    save_config(&root.join("config.toml"), &config).unwrap();

    unregister("test-runner", root).await.unwrap();

    assert!(!runner_dir.exists());

    let updated_config = load_config(&root.join("config.toml")).unwrap();
    assert_eq!(updated_config.runners, vec!["other-runner"]);
}

#[tokio::test]
async fn unregister_refuses_busy_root() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let _held = RootLock::acquire(root).unwrap();
    let runner_dir = root.join("runners").join("test-runner");
    std::fs::create_dir_all(&runner_dir).unwrap();
    std::fs::write(runner_dir.join("runner.json"), b"runner data").unwrap();

    let config = ChimeraConfig {
        runners: vec!["test-runner".into(), "other-runner".into()],
        ..Default::default()
    };
    let config_path = root.join("config.toml");
    save_config(&config_path, &config).unwrap();
    let original_config = std::fs::read(&config_path).unwrap();

    let error = unregister("test-runner", root).await.unwrap_err();

    assert!(error.to_string().contains("root storage is busy"));
    assert_eq!(
        std::fs::read(runner_dir.join("runner.json")).unwrap(),
        b"runner data"
    );
    assert_eq!(std::fs::read(&config_path).unwrap(), original_config);
    let unchanged_config = load_config(&config_path).unwrap();
    assert_eq!(
        unchanged_config.runners,
        vec!["test-runner", "other-runner"]
    );
}

#[tokio::test]
async fn malformed_config_stops_register_before_remote_or_local_side_effects() {
    let root = TempDir::new().unwrap();
    let config_path = root.path().join("config.toml");
    let malformed = b"runners = [\"SECRET_CONFIG\"";
    std::fs::write(&config_path, malformed).unwrap();

    let error = register(
        "not-a-github-url",
        "unused-token",
        "test-runner",
        &[],
        root.path(),
    )
    .await
    .unwrap_err();
    let diagnostic = error.to_string();

    assert!(diagnostic.contains("parsing config"));
    assert!(!diagnostic.contains("SECRET_CONFIG"));
    assert!(std::fs::read(&config_path).unwrap() == malformed);
    assert!(!root.path().join("runners").exists());
}

#[tokio::test]
async fn malformed_config_stops_unregister_before_credential_deletion() {
    let root = TempDir::new().unwrap();
    let runner_dir = root.path().join("runners/test-runner");
    std::fs::create_dir_all(&runner_dir).unwrap();
    let marker_path = runner_dir.join("runner.json");
    let marker = b"synthetic-runner-marker";
    std::fs::write(&marker_path, marker).unwrap();
    let config_path = root.path().join("config.toml");
    let malformed = b"runners = [\"SECRET_CONFIG\"";
    std::fs::write(&config_path, malformed).unwrap();

    let error = unregister("test-runner", root.path()).await.unwrap_err();
    let diagnostic = error.to_string();

    assert!(diagnostic.contains("parsing config"));
    assert!(!diagnostic.contains("SECRET_CONFIG"));
    assert!(std::fs::read(&config_path).unwrap() == malformed);
    assert!(std::fs::read(&marker_path).unwrap() == marker);
}
