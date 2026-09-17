use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bollard::Docker;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::job::action::TrustedActionDirectory;
use crate::job::logs::{LogLine, LogSender};

fn trusted_action(path: &Path) -> TrustedActionDirectory {
    TrustedActionDirectory::resolve(path, Path::new(".")).unwrap()
}

fn test_log_sender() -> (LogSender, tokio::sync::mpsc::Receiver<LogLine>) {
    test_log_sender_with_capacity(256)
}

fn test_log_sender_with_capacity(
    capacity: usize,
) -> (LogSender, tokio::sync::mpsc::Receiver<LogLine>) {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    let masks = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    (LogSender::new_for_test(tx, masks), rx)
}

async fn saturated_log_sender() -> (LogSender, tokio::sync::mpsc::Receiver<LogLine>) {
    let (logger, receiver) = test_log_sender_with_capacity(1);
    logger.send("queued".into()).await;
    (logger, receiver)
}

#[tokio::test]
#[ignore]
async fn engine_build_returns_verified_local_image_id() {
    let docker = crate::docker::client::connect(None).unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Dockerfile"),
        "FROM alpine:3.19\nRUN true\n",
    )
    .unwrap();
    let (logger, _receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/engine-build");
    let action_dir = trusted_action(tmp.path());

    let outcome = builder
        .build(DockerBuildRequest {
            docker: &docker,
            action_dir: &action_dir,
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &logger,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(120),
            reuse: None,
        })
        .await
        .unwrap();

    let DockerBuildOutcome::Ready(image) = outcome else {
        panic!("expected a built image");
    };
    assert!(image.image_id.starts_with("sha256:"));
    assert_eq!(
        docker
            .inspect_image(&image.image_id)
            .await
            .unwrap()
            .id
            .as_deref(),
        Some(image.image_id.as_str())
    );
}

#[tokio::test]
#[ignore]
async fn engine_build_failure_does_not_publish_cache_entry() {
    let docker = crate::docker::client::connect(None).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Dockerfile"),
        "FROM alpine:3.19\nRUN false\n",
    )
    .unwrap();
    let (logger, _receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/failing-build");
    let action_dir = trusted_action(tmp.path());

    let result = builder
        .build(DockerBuildRequest {
            docker: &docker,
            action_dir: &action_dir,
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &logger,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(120),
            reuse: None,
        })
        .await;

    assert_eq!(
        result.unwrap_err().to_string(),
        "Docker action image build failed"
    );
    assert_eq!(builder.cache_entry_count_for_test().await, 0);
}

#[tokio::test]
#[ignore]
async fn cancelling_build_stops_engine_work_and_never_publishes_image() {
    let docker = crate::docker::client::connect(None).unwrap();
    let engine_version = docker.version().await.unwrap();
    eprintln!("D-06 Docker Engine: {engine_version:?}");
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let unique = uuid::Uuid::new_v4();
    let marker = format!("CHIMERA_CANCEL_STARTED_{unique}");
    std::fs::write(tmp.path().join("build-marker.txt"), format!("{marker}\n")).unwrap();
    std::fs::write(
        tmp.path().join("Dockerfile"),
        format!(
            "# {unique}\nFROM alpine:3.19\nCOPY build-marker.txt /chimera-build-marker\nRUN cat /chimera-build-marker && sleep 6\n"
        ),
    )
    .unwrap();
    let (logger, mut receiver) = test_log_sender();
    let builder = std::sync::Arc::new(DockerActionBuilder::new());
    let scope = DockerBuildScope::new("test-runner", format!("test/cancel-{unique}"));
    let cancel = CancellationToken::new();

    let task = {
        let docker = docker.clone();
        let action_dir = trusted_action(tmp.path());
        let builder = builder.clone();
        let scope = scope.clone();
        let logger = logger.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            builder
                .build(DockerBuildRequest {
                    docker: &docker,
                    action_dir: &action_dir,
                    dockerfile: "Dockerfile",
                    scope: &scope,
                    registry_auth: None,
                    log_sender: &logger,
                    cancel_token: &cancel,
                    deadline: Instant::now() + Duration::from_secs(60),
                    reuse: None,
                })
                .await
        })
    };

    loop {
        let line = tokio::time::timeout(Duration::from_secs(30), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        if line.content == marker {
            break;
        }
    }
    cancel.cancel();

    let outcome = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("build cancellation must be bounded")
        .unwrap()
        .unwrap();
    assert!(matches!(outcome, DockerBuildOutcome::Cancelled));

    let action_dir = trusted_action(tmp.path());
    let tag = builder
        .internal_tag_for_context_for_test(&docker, &action_dir, "Dockerfile", &scope)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(matches!(
        docker.inspect_image(&tag).await,
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            ..
        })
    ));
    assert_eq!(builder.cache_entry_count_for_test().await, 0);
}

#[tokio::test]
#[ignore]
async fn timed_out_build_returns_bounded_and_never_publishes_image() {
    let docker = crate::docker::client::connect(None).unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let unique = uuid::Uuid::new_v4();
    let marker = format!("CHIMERA_TIMEOUT_STARTED_{unique}");
    std::fs::write(tmp.path().join("build-marker.txt"), format!("{marker}\n")).unwrap();
    std::fs::write(
        tmp.path().join("Dockerfile"),
        format!(
            "# {unique}\nFROM alpine:3.19\nCOPY build-marker.txt /chimera-build-marker\nRUN cat /chimera-build-marker && sleep 6\n"
        ),
    )
    .unwrap();
    let (logger, mut receiver) = test_log_sender();
    let builder = Arc::new(DockerActionBuilder::new());
    let scope = DockerBuildScope::new("test-runner", format!("test/timeout-{unique}"));

    let task = {
        let docker = docker.clone();
        let action_dir = trusted_action(tmp.path());
        let builder = builder.clone();
        let scope = scope.clone();
        let logger = logger.clone();
        tokio::spawn(async move {
            builder
                .build(DockerBuildRequest {
                    docker: &docker,
                    action_dir: &action_dir,
                    dockerfile: "Dockerfile",
                    scope: &scope,
                    registry_auth: None,
                    log_sender: &logger,
                    cancel_token: &CancellationToken::new(),
                    deadline: Instant::now() + Duration::from_secs(2),
                    reuse: None,
                })
                .await
        })
    };

    loop {
        let line = tokio::time::timeout(Duration::from_secs(30), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        if line.content == marker {
            break;
        }
    }
    let started = Instant::now();

    let outcome = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("build timeout must be bounded")
        .unwrap()
        .unwrap();
    assert!(matches!(outcome, DockerBuildOutcome::TimedOut));
    assert!(started.elapsed() < Duration::from_secs(4));

    let action_dir = trusted_action(tmp.path());
    let tag = builder
        .internal_tag_for_context_for_test(&docker, &action_dir, "Dockerfile", &scope)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(matches!(
        docker.inspect_image(&tag).await,
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            ..
        })
    ));
    assert_eq!(builder.cache_entry_count_for_test().await, 0);
}

async fn test_build(
    builder: &DockerActionBuilder,
    docker: &Docker,
    action_dir: &Path,
    scope: &DockerBuildScope,
    logger: &LogSender,
) -> DockerBuildOutcome {
    test_build_with_reuse(builder, docker, action_dir, scope, logger, None).await
}

async fn test_build_with_reuse(
    builder: &DockerActionBuilder,
    docker: &Docker,
    action_dir: &Path,
    scope: &DockerBuildScope,
    logger: &LogSender,
    reuse: Option<&BuiltDockerImage>,
) -> DockerBuildOutcome {
    let trusted = trusted_action(action_dir);
    builder
        .build(DockerBuildRequest {
            docker,
            action_dir: &trusted,
            dockerfile: "Dockerfile",
            scope,
            registry_auth: None,
            log_sender: logger,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(120),
            reuse,
        })
        .await
        .unwrap()
}

#[tokio::test]
#[ignore]
async fn missing_cached_image_is_rebuilt() {
    let docker = crate::docker::client::connect(None).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Dockerfile"),
        "FROM alpine:3.19\nRUN true\n",
    )
    .unwrap();
    let (logger, mut receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/stale-image");

    let DockerBuildOutcome::Ready(first) =
        test_build(&builder, &docker, tmp.path(), &scope, &logger).await
    else {
        panic!("expected first build");
    };
    docker
        .remove_image(
            &first.image_id,
            Some(bollard::image::RemoveImageOptions {
                force: true,
                noprune: false,
            }),
            None,
        )
        .await
        .unwrap();
    let DockerBuildOutcome::Ready(second) =
        test_build(&builder, &docker, tmp.path(), &scope, &logger).await
    else {
        panic!("expected rebuild");
    };

    docker.inspect_image(&second.image_id).await.unwrap();
    drop(logger);
    let mut build_messages = 0;
    while let Some(line) = receiver.recv().await {
        build_messages += usize::from(line.content == "Building Docker action image");
    }
    assert_eq!(build_messages, 2);
}

#[tokio::test]
#[ignore]
async fn concurrent_same_context_builds_once() {
    let docker = crate::docker::client::connect(None).unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Dockerfile"),
        "FROM alpine:3.19\nRUN sleep 1\n",
    )
    .unwrap();
    let (logger, mut receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/concurrent");

    let (left, right) = tokio::join!(
        test_build(&builder, &docker, tmp.path(), &scope, &logger),
        test_build(&builder, &docker, tmp.path(), &scope, &logger),
    );
    let DockerBuildOutcome::Ready(left) = left else {
        panic!("expected left image");
    };
    let DockerBuildOutcome::Ready(right) = right else {
        panic!("expected right image");
    };
    assert_eq!(left.image_id, right.image_id);

    drop(logger);
    let mut build_messages = 0;
    while let Some(line) = receiver.recv().await {
        build_messages += usize::from(line.content == "Building Docker action image");
    }
    assert_eq!(build_messages, 1);
}

#[tokio::test]
#[ignore]
async fn same_daemon_reuse_skips_present_image_and_rebuilds_missing_image() {
    let docker = crate::docker::client::connect(None).unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Dockerfile"),
        "FROM alpine:3.19\nRUN true\n",
    )
    .unwrap();
    let (logger, mut receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new(
        "test-runner",
        format!("test/reuse-{}", uuid::Uuid::new_v4()),
    );

    let DockerBuildOutcome::Ready(first) =
        test_build(&builder, &docker, tmp.path(), &scope, &logger).await
    else {
        panic!("expected first build");
    };
    let DockerBuildOutcome::Ready(reused) =
        test_build_with_reuse(&builder, &docker, tmp.path(), &scope, &logger, Some(&first)).await
    else {
        panic!("expected reuse");
    };
    assert_eq!(reused, first);

    docker
        .remove_image(
            &first.image_id,
            Some(bollard::image::RemoveImageOptions {
                force: true,
                noprune: false,
            }),
            None,
        )
        .await
        .unwrap();
    let DockerBuildOutcome::Ready(rebuilt) =
        test_build_with_reuse(&builder, &docker, tmp.path(), &scope, &logger, Some(&first)).await
    else {
        panic!("expected rebuild");
    };

    docker.inspect_image(&rebuilt.image_id).await.unwrap();
    drop(logger);
    let mut build_messages = 0;
    let mut reuse_messages = 0;
    while let Some(line) = receiver.recv().await {
        build_messages += usize::from(line.content == "Building Docker action image");
        reuse_messages += usize::from(line.content == "Reusing Docker action image for this job");
    }
    assert_eq!(build_messages, 2);
    assert_eq!(reuse_messages, 1);
}

#[test]
fn progress_formatter_redacts_internal_tag_from_stream_lines() {
    let internal_tag = "chimera-internal/action-cache:secret-key";
    let messages = format_build_progress(
        BuildInfo {
            stream: Some(format!(
                "Successfully tagged {internal_tag}\nretagged {internal_tag}\n"
            )),
            ..Default::default()
        },
        internal_tag,
    );

    assert_eq!(messages.len(), 2);
    assert!(
        messages
            .iter()
            .all(|message| !message.contains(internal_tag))
    );
    assert!(messages[0].contains("Successfully tagged"));
    assert!(messages[1].contains("retagged"));
}

#[test]
fn progress_formatter_redacts_internal_tag_from_status_and_progress() {
    let internal_tag = "chimera-internal/action-cache:secret-key";
    let messages = format_build_progress(
        BuildInfo {
            status: Some(format!("tagging {internal_tag}")),
            progress: Some(format!("progress for {internal_tag}")),
            ..Default::default()
        },
        internal_tag,
    );

    assert_eq!(messages.len(), 1);
    assert!(!messages[0].contains(internal_tag));
    assert!(messages[0].contains("tagging"));
    assert!(messages[0].contains("progress for"));
}

#[test]
fn progress_formatter_redacts_engine_ids_from_builder_v1_stream_records() {
    const SENTINEL_ENGINE_ID: &str = "deadbeefcaf0";
    let messages = format_build_progress(
        BuildInfo {
            stream: Some(format!(
                "Successfully built {SENTINEL_ENGINE_ID}\n ---> {SENTINEL_ENGINE_ID}\n ---> Running in {SENTINEL_ENGINE_ID}\nRemoving intermediate container {SENTINEL_ENGINE_ID}\n{SENTINEL_ENGINE_ID}: Pulling fs layer\napplication output id={SENTINEL_ENGINE_ID}\n"
            )),
            ..Default::default()
        },
        "unused-internal-tag",
    );

    assert_eq!(messages.len(), 6);
    for message in &messages[..5] {
        assert!(!message.contains(SENTINEL_ENGINE_ID), "{message}");
        assert!(message.contains(ENGINE_ID_REDACTION), "{message}");
    }
    assert_eq!(
        messages[5],
        format!("application output id={SENTINEL_ENGINE_ID}")
    );
}

#[test]
fn progress_formatter_redacts_engine_ids_from_status_and_progress_records() {
    const SENTINEL_ENGINE_ID: &str = "0123456789ab";
    let messages = format_build_progress(
        BuildInfo {
            status: Some(format!("{SENTINEL_ENGINE_ID}: Pulling fs layer")),
            progress: Some(format!(" ---> {SENTINEL_ENGINE_ID}")),
            ..Default::default()
        },
        "unused-internal-tag",
    );

    assert_eq!(messages.len(), 1);
    assert!(!messages[0].contains(SENTINEL_ENGINE_ID));
    assert_eq!(messages[0].matches(ENGINE_ID_REDACTION).count(), 2);
}

#[test]
fn progress_formatter_keeps_ordinary_command_output_verbatim() {
    const COMMAND_OUTPUT: &str = "application generated object deadbeefcaf0";
    let messages = format_build_progress(
        BuildInfo {
            stream: Some(format!("{COMMAND_OUTPUT}\n")),
            ..Default::default()
        },
        "unused-internal-tag",
    );

    assert_eq!(messages, vec![COMMAND_OUTPUT]);
}

#[test]
fn progress_formatter_never_logs_build_info_id_or_aux() {
    const SENTINEL_ENGINE_ID: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let info: BuildInfo = serde_json::from_value(serde_json::json!({
        "id": SENTINEL_ENGINE_ID,
        "aux": { "ID": SENTINEL_ENGINE_ID }
    }))
    .unwrap();

    let messages = format_build_progress(info, "unused-internal-tag");

    assert!(messages.is_empty());
}

#[tokio::test]
async fn already_cancelled_build_does_not_block_on_saturated_initial_log() {
    let docker = Docker::connect_with_http_defaults().unwrap();
    let (logger, _receiver) = saturated_log_sender().await;
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/cancelled-log");
    let tmp = tempfile::tempdir().unwrap();
    let action_dir = trusted_action(tmp.path());
    let cancel = CancellationToken::new();
    cancel.cancel();

    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        builder.build(DockerBuildRequest {
            docker: &docker,
            action_dir: &action_dir,
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &logger,
            cancel_token: &cancel,
            deadline: Instant::now() + Duration::from_secs(60),
            reuse: None,
        }),
    )
    .await
    .expect("cancelled build must not wait for log capacity")
    .unwrap();

    assert!(matches!(outcome, DockerBuildOutcome::Cancelled));
}

#[tokio::test]
async fn expired_build_does_not_block_on_saturated_initial_log() {
    let docker = Docker::connect_with_http_defaults().unwrap();
    let (logger, _receiver) = saturated_log_sender().await;
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/expired-log");
    let tmp = tempfile::tempdir().unwrap();
    let action_dir = trusted_action(tmp.path());

    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        builder.build(DockerBuildRequest {
            docker: &docker,
            action_dir: &action_dir,
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &logger,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now(),
            reuse: None,
        }),
    )
    .await
    .expect("expired build must not wait for log capacity")
    .unwrap();

    assert!(matches!(outcome, DockerBuildOutcome::TimedOut));
}

#[tokio::test]
async fn published_ready_outcome_survives_cancelled_terminal_logging() {
    let (logger, _receiver) = saturated_log_sender().await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let image = BuiltDockerImage {
        daemon_id: "daemon".into(),
        image_id: "sha256:image".into(),
    };

    let outcome = finalize_ready_outcome(
        image.clone(),
        true,
        &logger,
        &cancel,
        Instant::now() + Duration::from_secs(60),
    )
    .await;

    let DockerBuildOutcome::Ready(ready) = outcome else {
        panic!("published image must remain ready");
    };
    assert_eq!(ready, image);
}

#[tokio::test]
async fn published_ready_outcome_does_not_block_on_terminal_log_backpressure() {
    let (logger, _receiver) = saturated_log_sender().await;
    let image = BuiltDockerImage {
        daemon_id: "daemon".into(),
        image_id: "sha256:image".into(),
    };

    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        finalize_ready_outcome(
            image.clone(),
            true,
            &logger,
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(60),
        ),
    )
    .await
    .expect("terminal logging must be best effort");

    let DockerBuildOutcome::Ready(ready) = outcome else {
        panic!("published image must remain ready");
    };
    assert_eq!(ready, image);
}
