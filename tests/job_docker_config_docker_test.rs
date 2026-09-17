mod common;

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use chimera::job::client::JobConclusion;
use chimera::job::docker_config::JobResourceRoot;
use chimera::job::schema::JobManifest;
use common::docker_registry::*;
use common::pinned_action::*;
use common::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use tar::{Builder, EntryType, Header};
use tokio_util::sync::CancellationToken;

const SETUP_BUILDX_SHA: &str = "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5";
const LOGIN_SHA: &str = "650006c6eb7dba73a995cc03b0b2d7f5ca915bee";
const BUILD_PUSH_SHA: &str = "f9f3042f7e2789586610d6e8b85c8f03e5195baf";

fn archive_with_file(path: &str, contents: &[u8], mode: u32) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    let mut header = Header::new_gnu();
    header.set_path(path).unwrap();
    header.set_entry_type(EntryType::Regular);
    header.set_mode(mode);
    header.set_size(contents.len() as u64);
    header.set_cksum();
    archive.append(&header, contents).unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

fn archive_with_raw_path(path: &[u8], contents: &[u8]) -> Vec<u8> {
    assert!(path.len() < 100);
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    let mut header = Header::new_gnu();
    header.set_path("prefix/placeholder").unwrap();
    header.set_entry_type(EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(contents.len() as u64);
    header.as_mut_bytes()[..100].fill(0);
    header.as_mut_bytes()[..path.len()].copy_from_slice(path);
    header.set_cksum();
    archive.append(&header, contents).unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

fn archive_with_symlink(path: &str, target: &str) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    let mut header = Header::new_gnu();
    header.set_path(path).unwrap();
    header.set_entry_type(EntryType::Symlink);
    header.set_link_name(target).unwrap();
    header.set_mode(0o777);
    header.set_size(0);
    header.set_cksum();
    archive.append(&header, std::io::empty()).unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

#[test]
fn pinned_action_extraction_strips_github_prefix() {
    let archive = archive_with_file("owner-repo-sha/action.yml", b"name: probe\n", 0o644);
    let destination = tempfile::tempdir().unwrap();

    extract_public_action(&archive, destination.path()).unwrap();

    assert_eq!(
        std::fs::read(destination.path().join("action.yml")).unwrap(),
        b"name: probe\n"
    );
}

#[test]
fn pinned_action_extraction_preserves_executable_mode() {
    let archive = archive_with_file("owner-repo-sha/dist/run.sh", b"#!/bin/sh\n", 0o755);
    let destination = tempfile::tempdir().unwrap();

    extract_public_action(&archive, destination.path()).unwrap();

    let mode = std::fs::symlink_metadata(destination.path().join("dist/run.sh"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o755);
}

#[test]
fn pinned_action_extraction_rejects_parent_paths() {
    let archive = archive_with_raw_path(b"owner-repo-sha/../../escaped", b"escape");
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("nested/extract");
    std::fs::create_dir_all(&destination).unwrap();

    let error = extract_public_action(&archive, &destination).unwrap_err();

    assert!(error.to_string().contains("unsafe path"));
    assert!(!root.path().join("escaped").exists());
}

#[test]
fn pinned_action_extraction_rejects_symbolic_links() {
    let archive = archive_with_symlink("owner-repo-sha/link", "../../escaped");
    let destination = tempfile::tempdir().unwrap();

    let error = extract_public_action(&archive, destination.path()).unwrap_err();

    assert!(error.to_string().contains("non-file entry"));
    assert!(!destination.path().join("link").exists());
}

#[test]
fn pinned_action_publication_cleans_temporary_after_concurrent_winner() {
    let archive = archive_with_file("owner-repo-sha/action.yml", b"name: probe\n", 0o644);
    let root = tempfile::tempdir().unwrap();
    let destination = root
        .path()
        .join("docker/probe/0123456789abcdef0123456789abcdef01234567");
    std::fs::create_dir_all(&destination).unwrap();
    std::fs::write(destination.join("action.yml"), "name: winner\n").unwrap();

    publish_action_archive(&archive, &destination).unwrap();

    let parent = destination.parent().unwrap();
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 1);
    assert_eq!(
        std::fs::read_to_string(destination.join("action.yml")).unwrap(),
        "name: winner\n"
    );
}

#[tokio::test]
async fn pinned_action_installer_rejects_unpinned_refs_before_download() {
    let actions = tempfile::tempdir().unwrap();

    let error = install_pinned_action(actions.path(), "docker", "login-action", "main")
        .await
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("40-character hexadecimal commit")
    );
}

#[tokio::test]
async fn pinned_action_installer_rejects_unsafe_cache_coordinates_before_download() {
    let actions = tempfile::tempdir().unwrap();

    let error = install_pinned_action(actions.path(), "..", "login-action", LOGIN_SHA)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("unsafe action owner"));
    assert_eq!(std::fs::read_dir(actions.path()).unwrap().count(), 0);
}

fn registry_login_manifest(
    username: &str,
    password: &str,
    registry: &str,
    sync: &Path,
    body: &str,
    server_url: &str,
) -> JobManifest {
    let script = format!(
        "printf '%s' \"$PASSWORD\" | docker login --username \"$USERNAME\" --password-stdin \"$REGISTRY\"\n{body}"
    );
    let mut step = script_step_env(
        "registry",
        &script,
        HashMap::from([
            ("USERNAME".into(), username.into()),
            ("PASSWORD".into(), password.into()),
            ("REGISTRY".into(), registry.into()),
            ("SYNC".into(), sync.to_string_lossy().into_owned()),
        ]),
    );
    step["timeoutInMinutes"] = serde_json::json!(1);
    manifest_with_steps(vec![step], server_url)
}

#[tokio::test]
#[ignore = "requires a local Docker endpoint"]
async fn concurrent_logout_does_not_remove_other_job_credentials() {
    let registry = AuthenticatedRegistry::start().await.unwrap();
    let seeded = registry.seed_image("probe", "seed").await.unwrap();
    assert_eq!(seeded, format!("{}/probe:seed", registry.address()));
    let sync = tempfile::tempdir().unwrap();
    let daemon_root = tempfile::tempdir().unwrap();
    let job_resources =
        JobResourceRoot::prepare(&daemon_root.path().join("job-resources")).unwrap();
    let first = TestEnv::setup_with_job_resources(job_resources.clone()).await;
    let second = TestEnv::setup_with_job_resources(job_resources).await;

    let first_manifest = registry_login_manifest(
        ALICE_USER,
        ALICE_PASSWORD,
        registry.address(),
        sync.path(),
        r#"
          touch "$SYNC/a-ready"
          while [ ! -f "$SYNC/b-ready" ]; do sleep 0.05; done
          docker logout "$REGISTRY"
          touch "$SYNC/a-logout"
        "#,
        &first.mock_server.uri(),
    );
    let second_manifest = registry_login_manifest(
        BOB_USER,
        BOB_PASSWORD,
        registry.address(),
        sync.path(),
        r#"
          touch "$SYNC/b-ready"
          while [ ! -f "$SYNC/a-logout" ]; do sleep 0.05; done
          docker pull "$REGISTRY/probe:seed"
        "#,
        &second.mock_server.uri(),
    );

    let (first_run, second_run) =
        tokio::join!(first.run(&first_manifest), second.run(&second_manifest),);

    assert_eq!(first_run.unwrap().0, JobConclusion::Succeeded);
    assert_eq!(second_run.unwrap().0, JobConclusion::Succeeded);
}

#[tokio::test]
#[ignore = "requires a local Docker endpoint"]
async fn docker_cli_atomic_rewrite_stays_private() {
    let registry = AuthenticatedRegistry::start().await.unwrap();
    let root_parent = tempfile::tempdir().unwrap();
    let root = JobResourceRoot::prepare(&root_parent.path().join("job-resources")).unwrap();
    let mut config = root.create_docker_config().unwrap();
    let attempt = config.attempt_dir().to_path_buf();

    docker_output(
        &[
            "login",
            "--username",
            ALICE_USER,
            "--password-stdin",
            registry.address(),
        ],
        config.directory(),
        Some(ALICE_PASSWORD.as_bytes()),
    )
    .await
    .unwrap();

    let metadata = std::fs::symlink_metadata(config.config_file()).unwrap();
    assert!(metadata.is_file());
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(
        std::fs::symlink_metadata(config.directory())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    let parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config.config_file()).unwrap()).unwrap();
    let auths = parsed
        .get("auths")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert_eq!(auths.len(), 1);
    assert!(auths.contains_key(registry.address()));

    docker_output(&["logout", registry.address()], config.directory(), None)
        .await
        .unwrap();
    assert!(attempt.exists());

    config.cleanup().unwrap();
    assert!(!attempt.exists());
}

#[tokio::test]
#[ignore = "requires a local Docker endpoint"]
async fn docker_action_does_not_receive_host_config() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![serde_json::json!({
            "id": "docker-config-boundary",
            "displayName": "Docker config boundary",
            "reference": {
                "name": "docker://httpd:2.4-alpine",
                "type": "containerregistry",
                "image": "httpd:2.4-alpine"
            },
            "inputs": {
                "entrypoint": "/bin/sh",
                "args": "-c 'test -z \"$DOCKER_CONFIG\"'"
            },
            "condition": null,
            "timeoutInMinutes": 2,
            "continueOnError": false,
            "order": 1,
            "environment": null,
            "contextName": "docker-config-boundary"
        })],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
    assert!(!observed.attempt_dir.exists());
}

fn remote_action_step(
    id: &str,
    name: &str,
    sha: &str,
    inputs: HashMap<String, String>,
    order: u32,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "displayName": format!("Run {name}@{sha}"),
        "reference": {
            "name": name,
            "type": "repository",
            "ref": sha
        },
        "inputs": inputs,
        "condition": null,
        "timeoutInMinutes": 15,
        "continueOnError": false,
        "order": order,
        "environment": null,
        "contextName": id
    })
}

struct BuildxBuilderCleanup {
    builder_name_file: std::path::PathBuf,
    docker_config: tempfile::TempDir,
}

impl BuildxBuilderCleanup {
    fn new(builder_name_file: std::path::PathBuf) -> Self {
        let docker_config = tempfile::tempdir().unwrap();
        std::fs::write(docker_config.path().join("config.json"), "{}").unwrap();
        Self {
            builder_name_file,
            docker_config,
        }
    }

    fn docker_config(&self) -> &Path {
        self.docker_config.path()
    }
}

impl Drop for BuildxBuilderCleanup {
    fn drop(&mut self) {
        let Ok(builder_name) = std::fs::read_to_string(&self.builder_name_file) else {
            return;
        };
        let builder_name = builder_name.trim();
        if builder_name.is_empty() {
            return;
        }
        let _ = docker_cleanup(
            &["buildx", "rm", "--force", builder_name],
            self.docker_config.path(),
        );
    }
}

#[tokio::test]
#[ignore = "requires Docker, Buildx, and the explicitly pinned public actions"]
async fn pinned_buildx_flow_uses_job_config_and_original_socket() {
    let registry = AuthenticatedRegistry::start().await.unwrap();
    let env = TestEnv::setup().await;
    std::fs::write(
        env.workspace.workspace_dir().join("Dockerfile"),
        "FROM scratch\nCOPY marker /marker\n",
    )
    .unwrap();
    std::fs::write(
        env.workspace.workspace_dir().join("marker"),
        "synthetic-buildx-probe\n",
    )
    .unwrap();
    install_pinned_action(
        env.actions_dir(),
        "docker",
        "setup-buildx-action",
        SETUP_BUILDX_SHA,
    )
    .await
    .unwrap();
    install_pinned_action(env.actions_dir(), "docker", "login-action", LOGIN_SHA)
        .await
        .unwrap();
    install_pinned_action(
        env.actions_dir(),
        "docker",
        "build-push-action",
        BUILD_PUSH_SHA,
    )
    .await
    .unwrap();

    let tag = format!(
        "{}/buildx-probe:{}",
        registry.address(),
        uuid::Uuid::new_v4().simple()
    );
    registry.track_local_image(tag.clone());
    let expected = HashMap::from([
        (
            "EXPECTED_DOCKER_HOST".into(),
            std::env::var("DOCKER_HOST").unwrap_or_default(),
        ),
        (
            "EXPECTED_XDG_RUNTIME_DIR".into(),
            std::env::var("XDG_RUNTIME_DIR").unwrap_or_default(),
        ),
        (
            "EXPECTED_PATH".into(),
            std::env::var("PATH").unwrap_or_default(),
        ),
    ]);
    let probe = script_step_env(
        "environment-probe",
        r#"
            test -f "$DOCKER_CONFIG/config.json"
            test "${DOCKER_HOST-}" = "$EXPECTED_DOCKER_HOST"
            test "${XDG_RUNTIME_DIR-}" = "$EXPECTED_XDG_RUNTIME_DIR"
            test "${PATH-}" = "$EXPECTED_PATH"
        "#,
        expected,
    );
    let setup = remote_action_step(
        "buildx",
        "docker/setup-buildx-action",
        SETUP_BUILDX_SHA,
        HashMap::from([
            ("driver-opts".into(), "network=host".into()),
            (
                "buildkitd-config-inline".into(),
                format!(
                    "[registry.\"{}\"]\n  http = true\n  insecure = true\n",
                    registry.address()
                ),
            ),
        ]),
        2,
    );
    let builder_name_file = env.workspace.workspace_dir().join("buildx-builder-name");
    let builder_cleanup = BuildxBuilderCleanup::new(builder_name_file.clone());
    let mut record_builder = script_step(
        "record-builder",
        r#"printf '%s' '${{ steps.buildx.outputs.name }}' > buildx-builder-name"#,
    );
    record_builder["order"] = serde_json::json!(3);
    let login = remote_action_step(
        "login",
        "docker/login-action",
        LOGIN_SHA,
        HashMap::from([
            ("registry".into(), registry.address().into()),
            ("username".into(), ALICE_USER.into()),
            ("password".into(), "${{ secrets.REGISTRY_PASSWORD }}".into()),
        ]),
        4,
    );
    let build = remote_action_step(
        "build",
        "docker/build-push-action",
        BUILD_PUSH_SHA,
        HashMap::from([
            ("context".into(), ".".into()),
            ("file".into(), "Dockerfile".into()),
            ("push".into(), "true".into()),
            ("provenance".into(), "false".into()),
            ("tags".into(), tag.clone()),
        ]),
        5,
    );
    let mut pull = script_step_env(
        "pull",
        "docker pull \"$IMAGE\"",
        HashMap::from([("IMAGE".into(), tag.clone())]),
    );
    pull["order"] = serde_json::json!(6);
    let manifest = manifest_with_steps_and_context(
        vec![probe, setup, record_builder, login, build, pull],
        &env.mock_server.uri(),
        serde_json::json!({
            "secrets": { "REGISTRY_PASSWORD": ALICE_PASSWORD }
        }),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
    assert!(!observed.attempt_dir.exists());
    let builder_name = std::fs::read_to_string(builder_name_file).unwrap();
    let builder_name = builder_name.trim();
    assert!(!builder_name.is_empty());
    let inspect = docker_output(
        &["buildx", "inspect", builder_name],
        builder_cleanup.docker_config(),
        None,
    )
    .await;
    assert!(
        inspect.is_err(),
        "setup-buildx post did not remove its builder"
    );
    registry.remove_local_image(&tag).await.unwrap();
}
