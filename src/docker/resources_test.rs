use super::*;

#[derive(Clone, Default)]
struct CapturedWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedWriter {
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

#[test]
fn health_diagnostic_omits_probe_output() {
    let inspect = bollard::models::ContainerInspectResponse {
        state: Some(bollard::models::ContainerState {
            exit_code: Some(17),
            health: Some(bollard::models::Health {
                log: Some(vec![
                    bollard::models::HealthcheckResult {
                        exit_code: Some(1),
                        output: Some("CANARY-HEALTH first".into()),
                        ..Default::default()
                    },
                    bollard::models::HealthcheckResult {
                        exit_code: Some(17),
                        output: Some("CANARY-HEALTH last".into()),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let captured = CapturedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_ansi(false)
        .without_time()
        .with_writer(captured.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);

    log_health_check_results(&inspect, "safe-container-id");
    let trace = captured.text();

    assert!(trace.contains("safe-container-id"));
    assert!(trace.contains("17"));
    assert!(trace.contains("record_count=2"));
    assert!(
        !trace.contains("CANARY-HEALTH"),
        "health output leaked: {trace}"
    );
}

#[test]
fn container_tail_summary_discards_payload_bytes() {
    let chunks = [
        LogOutput::StdOut {
            message: b"CANARY-TAIL stdout".to_vec().into(),
        },
        LogOutput::StdErr {
            message: b"CANARY-TAIL stderr".to_vec().into(),
        },
    ];

    let summary = summarize_container_tail(&chunks);
    let rendered = format!("{summary:?}");

    assert_eq!(summary.chunk_count, 2);
    assert_eq!(summary.byte_count, 36);
    assert!(!rendered.contains("CANARY-TAIL"));
}

#[test]
fn parse_port_bindings_simple() {
    let ports = vec!["8080:8080".into()];
    let bindings = parse_port_bindings(&ports);
    assert!(bindings.contains_key("8080/tcp"));
    let binding = bindings["8080/tcp"].as_ref().unwrap();
    assert_eq!(binding[0].host_port.as_deref(), Some("8080"));
}

#[test]
fn parse_port_bindings_with_protocol() {
    let ports = vec!["5432:5432/tcp".into()];
    let bindings = parse_port_bindings(&ports);
    assert!(bindings.contains_key("5432/tcp"));
}

#[test]
fn parse_port_bindings_different_ports() {
    let ports = vec!["3000:80".into()];
    let bindings = parse_port_bindings(&ports);
    let binding = bindings["80/tcp"].as_ref().unwrap();
    assert_eq!(binding[0].host_port.as_deref(), Some("3000"));
}

#[test]
fn parse_port_bindings_empty() {
    let ports: Vec<String> = vec![];
    let bindings = parse_port_bindings(&ports);
    assert!(bindings.is_empty());
}

#[test]
fn remap_to_container_path_works() {
    use std::path::PathBuf;
    let docker = bollard::Docker::connect_with_http_defaults().expect("create bollard HTTP client");
    let mut resources = JobDockerResources::new(docker);
    resources.path_mappings = vec![
        (PathBuf::from("/host/workspace"), "/github/workspace".into()),
        (PathBuf::from("/host/actions"), "/github/actions".into()),
        (
            PathBuf::from("/host/tool-cache"),
            "/github/tool-cache".into(),
        ),
    ];

    assert_eq!(
        resources
            .remap_to_container_path(Path::new("/host/workspace/src/main.rs"))
            .unwrap(),
        "/github/workspace/src/main.rs"
    );
    assert_eq!(
        resources
            .remap_to_container_path(Path::new("/host/actions/actions/checkout/v4"))
            .unwrap(),
        "/github/actions/actions/checkout/v4"
    );
    assert_eq!(
        resources
            .remap_to_container_path(Path::new("/host/workspace"))
            .unwrap(),
        "/github/workspace"
    );
    assert!(
        resources
            .remap_to_container_path(Path::new("/other/path"))
            .is_none()
    );
}

#[test]
fn job_container_bind_mounts_make_only_actions_read_only() {
    let params = SetupParams {
        runner_name: "runner",
        job_id: "job",
        job_container: None,
        services: &[],
        workspace_host_path: Path::new("/host/workspace"),
        workflow_files_host_path: Path::new("/host/workflow"),
        runner_temp_host_path: Path::new("/host/tmp"),
        actions_host_path: Path::new("/host/actions"),
        tool_cache_host_path: Path::new("/host/tool-cache"),
        externals_dir: Path::new("/host/externals"),
    };

    let binds = job_container_bind_mounts(&params);

    assert_eq!(
        binds,
        vec![
            "/host/workspace:/github/workspace",
            "/host/workflow:/github/workflow",
            "/host/tmp:/github/tmp",
            "/host/actions:/github/actions:ro",
            "/host/tool-cache:/github/tool-cache",
        ]
    );
}

/// Integration test: requires Docker daemon.
/// Uses a unique job ID per run to avoid network name collisions.
#[tokio::test]
#[ignore]
async fn setup_and_cleanup_job_container() {
    let docker = crate::docker::client::connect(None).unwrap();
    crate::docker::client::ping(&docker).await.unwrap();

    let job_id = uuid::Uuid::new_v4().to_string();
    let mut resources = JobDockerResources::new(docker);

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let workflow = tmp.path().join("workflow");
    let runner_temp = tmp.path().join("tmp");
    let actions = tmp.path().join("actions");
    let tool_cache = tmp.path().join("tool-cache");
    let externals = tmp.path().join("externals");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&workflow).unwrap();
    std::fs::create_dir_all(&runner_temp).unwrap();
    std::fs::create_dir_all(&actions).unwrap();
    std::fs::create_dir_all(&tool_cache).unwrap();
    std::fs::create_dir_all(&externals).unwrap();

    let job_spec = JobContainerSpec {
        image: "alpine:latest".into(),
        environment: HashMap::new(),
        ports: vec![],
        volumes: vec![],
        options: None,
        credentials: None,
    };

    resources
        .setup(&SetupParams {
            runner_name: "test-runner",
            job_id: &job_id,
            job_container: Some(&job_spec),
            services: &[],
            workspace_host_path: &workspace,
            workflow_files_host_path: &workflow,
            runner_temp_host_path: &runner_temp,
            actions_host_path: &actions,
            tool_cache_host_path: &tool_cache,
            externals_dir: &externals,
        })
        .await
        .unwrap();

    assert!(resources.job_container_id().is_some());

    // Verify the container is actually running
    let id = resources.job_container_id().unwrap();
    let inspect = resources
        .docker()
        .inspect_container(id, None)
        .await
        .unwrap();
    let running = inspect
        .state
        .as_ref()
        .and_then(|s| s.running)
        .unwrap_or(false);
    assert!(running, "job container should be running");

    resources.cleanup().await;

    assert!(resources.job_container_id().is_none());
}

/// Integration test: job container with a service container on a shared network.
#[tokio::test]
#[ignore]
async fn setup_and_cleanup_with_service() {
    let docker = crate::docker::client::connect(None).unwrap();
    crate::docker::client::ping(&docker).await.unwrap();

    // Use nginx as the service — it stays running and gets an IP
    crate::docker::client::ensure_image(&docker, "nginx:alpine", None)
        .await
        .unwrap();

    let job_id = uuid::Uuid::new_v4().to_string();
    let mut resources = JobDockerResources::new(docker);

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let workflow = tmp.path().join("workflow");
    let runner_temp = tmp.path().join("tmp");
    let actions = tmp.path().join("actions");
    let tool_cache = tmp.path().join("tool-cache");
    let externals = tmp.path().join("externals");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&workflow).unwrap();
    std::fs::create_dir_all(&runner_temp).unwrap();
    std::fs::create_dir_all(&actions).unwrap();
    std::fs::create_dir_all(&tool_cache).unwrap();
    std::fs::create_dir_all(&externals).unwrap();

    let job_spec = JobContainerSpec {
        image: "alpine:latest".into(),
        environment: HashMap::new(),
        ports: vec![],
        volumes: vec![],
        options: None,
        credentials: None,
    };

    let service_spec = ServiceContainerSpec {
        image: "nginx:alpine".into(),
        ports: vec![],
        environment: HashMap::new(),
        volumes: vec![],
        options: None,
        credentials: None,
        alias: Some("web".into()),
    };

    resources
        .setup(&SetupParams {
            runner_name: "test-runner",
            job_id: &job_id,
            job_container: Some(&job_spec),
            services: &[service_spec],
            workspace_host_path: &workspace,
            workflow_files_host_path: &workflow,
            runner_temp_host_path: &runner_temp,
            actions_host_path: &actions,
            tool_cache_host_path: &tool_cache,
            externals_dir: &externals,
        })
        .await
        .unwrap();

    assert!(resources.job_container_id().is_some());
    assert!(
        resources.service_addresses().contains_key("web"),
        "service should have an IP: {:?}",
        resources.service_addresses()
    );
    assert!(
        resources.service_container_map().contains_key("web"),
        "service should have a container ID mapping"
    );

    resources.cleanup().await;

    assert!(resources.job_container_id().is_none());
    assert!(resources.service_addresses().is_empty());
    assert!(resources.service_container_map().is_empty());
}
