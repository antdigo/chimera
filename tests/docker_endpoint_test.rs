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
async fn refused_explicit_endpoint_does_not_fall_back_to_a_live_probe() {
    let refused_dir = tempfile::Builder::new()
        .prefix("ch-ep-refused-")
        .tempdir_in("/tmp")
        .unwrap();
    let socket_path = refused_dir.path().join("docker.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    drop(listener);
    let refused_endpoint = DockerEndpoint::unix_socket(&socket_path).unwrap();
    let live = EngineProbe::start("unexpected-fallback").await.unwrap();
    let client = chimera::docker::client::connect(&refused_endpoint).unwrap();

    let ping = tokio::time::timeout(std::time::Duration::from_secs(2), client.ping())
        .await
        .unwrap();

    assert!(ping.is_err());
    assert!(live.requests().is_empty());
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
