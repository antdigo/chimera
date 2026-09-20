use chimera::docker::endpoint::DockerEndpoint;

#[path = "common/docker_endpoint.rs"]
mod docker_endpoint;

use docker_endpoint::EngineProbe;

#[tokio::test]
async fn explicit_clients_route_to_distinct_unix_endpoints() {
    let a = EngineProbe::start("engine-a").await.unwrap();
    let b = EngineProbe::start("engine-b").await.unwrap();
    let client_a = chimera::docker::client::connect(a.endpoint()).unwrap();
    let client_b = chimera::docker::client::connect(b.endpoint()).unwrap();

    assert_eq!(client_a.ping().await.unwrap(), "engine-a");
    assert_eq!(client_b.ping().await.unwrap(), "engine-b");
    assert_eq!(a.requests().len(), 1);
    assert_eq!(b.requests().len(), 1);
}

#[tokio::test]
async fn absent_explicit_endpoint_does_not_fall_back_to_ambient_live_probe() {
    const CHILD_MARKER: &str = "CHIMERA_ABSENT_ENDPOINT_CHILD";

    if std::env::var_os(CHILD_MARKER).is_some() {
        let absent_dir = tempfile::Builder::new()
            .prefix("ch-ep-absent-")
            .tempdir_in("/tmp")
            .unwrap();
        let explicit_endpoint =
            DockerEndpoint::unix_socket(&absent_dir.path().join("docker.sock")).unwrap();
        let operation_failed = match chimera::docker::client::connect(&explicit_endpoint) {
            Ok(client) => tokio::time::timeout(std::time::Duration::from_secs(2), client.ping())
                .await
                .expect("explicit Docker operation must remain bounded")
                .is_err(),
            Err(_) => true,
        };

        assert!(operation_failed);
        return;
    }

    let live = EngineProbe::start("unexpected-fallback").await.unwrap();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .kill_on_drop(true)
            .args([
                "--exact",
                "absent_explicit_endpoint_does_not_fall_back_to_ambient_live_probe",
                "--nocapture",
            ])
            .env(CHILD_MARKER, "1")
            .env("DOCKER_HOST", live.endpoint().socket_address())
            .output(),
    )
    .await
    .expect("explicit endpoint child must remain bounded")
    .unwrap();

    assert!(
        live.requests().is_empty(),
        "explicit endpoint operation reached the ambient Docker endpoint"
    );
    assert!(
        output.status.success(),
        "explicit endpoint child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn failing_image_probe_returns_a_synthetic_engine_error() {
    let probe = EngineProbe::start_failing_images().await.unwrap();
    let client = chimera::docker::client::connect(probe.endpoint()).unwrap();

    let error = client.inspect_image("fixture-image").await.unwrap_err();

    assert!(
        error
            .to_string()
            .contains("synthetic endpoint probe failure")
    );
    assert_eq!(
        probe.requests(),
        ["GET /images/fixture-image/json HTTP/1.1"]
    );
}
