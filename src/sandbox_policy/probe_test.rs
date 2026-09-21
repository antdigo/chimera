use super::{ConnectOutcome, probe_connect};

#[tokio::test]
async fn connect_probe_identifies_a_live_listener() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let result = probe_connect(
        listener.local_addr().unwrap(),
        std::time::Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(matches!(result, ConnectOutcome::Connected));
}
