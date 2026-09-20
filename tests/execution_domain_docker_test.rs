mod common;

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use chimera::job::client::JobConclusion;
use chimera::job::execution_domain::ExecutionDomainRoot;
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
const BUILDKIT_IMAGE_ID_ENV: &str = "CHIMERA_TEST_BUILDKIT_IMAGE_ID";

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

fn archive_with_global_pax_header(path: &str, contents: &[u8]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);

    let mut pax_header = Header::new_gnu();
    pax_header.set_path("pax_global_header").unwrap();
    pax_header.set_entry_type(EntryType::XGlobalHeader);
    pax_header.set_mode(0o644);
    pax_header.set_size(0);
    pax_header.set_cksum();
    archive.append(&pax_header, std::io::empty()).unwrap();

    let mut file_header = Header::new_gnu();
    file_header.set_path(path).unwrap();
    file_header.set_entry_type(EntryType::Regular);
    file_header.set_mode(0o644);
    file_header.set_size(contents.len() as u64);
    file_header.set_cksum();
    archive.append(&file_header, contents).unwrap();

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
fn pinned_action_extraction_accepts_global_pax_metadata() {
    let archive =
        archive_with_global_pax_header("owner-repo-sha/action.yml", b"name: global pax probe\n");
    let destination = tempfile::tempdir().unwrap();

    extract_public_action(&archive, destination.path()).unwrap();

    assert_eq!(
        std::fs::read(destination.path().join("action.yml")).unwrap(),
        b"name: global pax probe\n"
    );
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

const VALID_BUILDKIT_IMAGE_ID: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VALID_CONTAINER_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn buildkit_image_id_accepts_an_immutable_sha256_id() {
    assert_eq!(
        parse_buildkit_image_id(VALID_BUILDKIT_IMAGE_ID).unwrap(),
        VALID_BUILDKIT_IMAGE_ID
    );
}

#[test]
fn buildkit_image_id_rejects_tags_and_malformed_digests() {
    for value in [
        "moby/buildkit:latest",
        "sha256:abcd",
        "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
    ] {
        assert!(parse_buildkit_image_id(value).is_err(), "accepted {value}");
    }
}

#[test]
fn local_image_inspection_must_match_the_requested_id() {
    assert!(
        validate_local_image_id(
            VALID_BUILDKIT_IMAGE_ID,
            &format!("{VALID_BUILDKIT_IMAGE_ID}\n")
        )
        .is_ok()
    );
    assert!(
        validate_local_image_id(
            VALID_BUILDKIT_IMAGE_ID,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .is_err()
    );
}

#[test]
fn docker_container_id_parser_requires_one_full_id() {
    assert_eq!(
        parse_container_id(&format!("{VALID_CONTAINER_ID}\n")).unwrap(),
        VALID_CONTAINER_ID
    );
    assert!(parse_container_id("abcd\n").is_err());
    assert!(parse_container_id(&format!("{VALID_CONTAINER_ID}\n{VALID_CONTAINER_ID}\n")).is_err());
}

#[test]
fn exact_resource_listing_reports_an_empty_result_as_absent() {
    assert!(!exact_resource_is_present("\n", VALID_CONTAINER_ID).unwrap());
}

#[test]
fn exact_resource_listing_reports_the_expected_result_as_present() {
    assert!(
        exact_resource_is_present(&format!("{VALID_CONTAINER_ID}\n"), VALID_CONTAINER_ID).unwrap()
    );
}

#[test]
fn exact_resource_listing_rejects_an_unexpected_result() {
    assert!(exact_resource_is_present("unexpected\n", VALID_CONTAINER_ID).is_err());
}

#[test]
fn offline_action_environment_allows_only_loopback_http() {
    let environment = offline_action_environment();

    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        assert_eq!(environment[key], "http://127.0.0.1:1");
    }
    assert_eq!(environment["NO_PROXY"], "127.0.0.1,localhost");
    assert_eq!(environment["no_proxy"], "127.0.0.1,localhost");
}

#[test]
fn explicit_builder_name_derives_exact_owned_resource_names() {
    let resources = BuildxOwnedResources::new("chimera-buildx-test".into());

    assert_eq!(resources.builder_name, "chimera-buildx-test");
    assert_eq!(
        resources.container_name,
        "buildx_buildkit_chimera-buildx-test0"
    );
    assert_eq!(
        resources.state_volume_name,
        "buildx_buildkit_chimera-buildx-test0_state"
    );
}

#[test]
fn buildx_setup_inputs_pin_local_artifacts_without_a_version_request() {
    let inputs = buildx_setup_inputs(
        "chimera-buildx-test",
        VALID_BUILDKIT_IMAGE_ID,
        "127.0.0.1:5000",
    );

    assert_eq!(inputs["name"], "chimera-buildx-test");
    assert_eq!(inputs["cache-binary"], "false");
    assert!(!inputs.contains_key("version"));
    assert_eq!(
        inputs["driver-opts"],
        format!("network=host\nimage={VALID_BUILDKIT_IMAGE_ID}")
    );
    assert_eq!(
        inputs["buildkitd-config-inline"],
        "[registry.\"127.0.0.1:5000\"]\n  http = true\n  insecure = true\n"
    );
}

#[test]
fn rootless_environment_requires_explicit_nonempty_values() {
    for (docker_host, runtime_dir) in [
        (None, Some("/run/user/1501")),
        (Some(""), Some("/run/user/1501")),
        (Some("unix:///run/user/1501/docker.sock"), None),
        (Some("unix:///run/user/1501/docker.sock"), Some("")),
    ] {
        assert!(
            validate_rootless_environment(docker_host, runtime_dir).is_err(),
            "accepted DOCKER_HOST={docker_host:?}, XDG_RUNTIME_DIR={runtime_dir:?}"
        );
    }
}

#[test]
fn rootless_environment_rejects_malformed_or_incoherent_endpoints() {
    for docker_host in [
        "tcp://127.0.0.1:2375",
        "unix://relative/docker.sock",
        "unix:///run/user/1501/other.sock",
        "unix:///run/user/1502/docker.sock",
    ] {
        assert!(
            validate_rootless_environment(Some(docker_host), Some("/run/user/1501")).is_err(),
            "accepted {docker_host}"
        );
    }
}

#[test]
fn rootless_environment_accepts_matching_unix_socket() {
    let environment = validate_rootless_environment(
        Some("unix:///run/user/1501/docker.sock"),
        Some("/run/user/1501"),
    )
    .unwrap();

    assert_eq!(environment.docker_host, "unix:///run/user/1501/docker.sock");
    assert_eq!(environment.xdg_runtime_dir, "/run/user/1501");
}

#[test]
fn daemon_security_options_require_valid_rootless_marker() {
    for output in [
        "",
        "{}",
        r#"["name=seccomp,profile=builtin"]"#,
        r#"["rootless"]"#,
    ] {
        assert!(
            validate_rootless_security_options(output).is_err(),
            "accepted {output:?}"
        );
    }

    validate_rootless_security_options(
        r#"["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]"#,
    )
    .unwrap();
}

#[test]
fn registry_cleanup_removes_only_exact_container_with_volumes() {
    assert_eq!(
        registry_container_cleanup_args("chimera-registry-test"),
        ["rm", "--force", "--volumes", "--", "chimera-registry-test"]
    );
}

// ── Docker CLI isolation in the test harness ─────────────────────

const SYNTHETIC_AUTH_VALUE: &str = "c3ludGhldGljLWF1dGg=";

fn write_cli_executable(path: &Path) {
    std::fs::write(path, "#!/bin/sh\n").unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).unwrap();
}

#[test]
fn docker_cli_resolution_uses_the_first_executable_match() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("first");
    let second = root.path().join("second");
    for dir in [&first, &second] {
        std::fs::create_dir(dir).unwrap();
    }
    write_cli_executable(&first.join("docker"));
    write_cli_executable(&second.join("docker"));
    std::fs::write(first.join("not-docker"), "plain file").unwrap();
    let path_value = std::env::join_paths([&first, &second]).unwrap();

    let resolved = resolve_docker_cli(&path_value).unwrap();

    assert_eq!(resolved, first.join("docker"));
}

#[test]
fn docker_cli_resolution_skips_non_executables_and_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("bin");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("docker"), "not executable").unwrap();
    let path_value = std::env::join_paths([&dir]).unwrap();

    assert!(resolve_docker_cli(&path_value).is_err());
    let empty_path = std::env::join_paths(Vec::<&Path>::new()).unwrap();
    assert!(resolve_docker_cli(&empty_path).is_err());
}

#[test]
fn harness_child_env_is_helper_free_and_forwards_socket_variables() {
    let environment = harness_child_env(
        Path::new("/test-assets/harness-config"),
        Path::new("/test-assets/harness-empty-path"),
        Some("unix:///run/user/1000/docker.sock"),
        Some("/run/user/1000"),
        Some("/chimera-tmp"),
    );

    assert_eq!(environment["DOCKER_CONFIG"], "/test-assets/harness-config");
    assert_eq!(environment["PATH"], "/test-assets/harness-empty-path");
    assert_eq!(
        environment["DOCKER_HOST"],
        "unix:///run/user/1000/docker.sock"
    );
    assert_eq!(environment["XDG_RUNTIME_DIR"], "/run/user/1000");
    assert_eq!(environment["TMPDIR"], "/chimera-tmp");
    assert!(!environment.contains_key("DOCKER_CONTEXT"));
    assert!(!environment.contains_key("HOME"));
}

#[test]
fn harness_child_env_omits_absent_socket_variables() {
    let environment = harness_child_env(Path::new("/c"), Path::new("/p"), None, None, None);

    assert_eq!(environment.len(), 2);
    assert!(!environment.contains_key("DOCKER_HOST"));
    assert!(!environment.contains_key("XDG_RUNTIME_DIR"));
    assert!(!environment.contains_key("TMPDIR"));
}

#[test]
fn local_auth_assertion_accepts_inline_only_credentials() {
    let config = format!(r#"{{"auths":{{"127.0.0.1:5000":{{"auth":"{SYNTHETIC_AUTH_VALUE}"}}}}}}"#);

    assert_local_auth_only(&config, "127.0.0.1:5000").unwrap();
}

#[test]
fn local_auth_assertion_rejects_credential_stores_without_echoing_the_secret() {
    let cred_store = format!(
        r#"{{"credsStore":"desktop","auths":{{"127.0.0.1:5000":{{"auth":"{SYNTHETIC_AUTH_VALUE}"}}}}}}"#
    );
    let cred_helpers = format!(
        r#"{{"credHelpers":{{"127.0.0.1:5000":"desktop"}},"auths":{{"127.0.0.1:5000":{{"auth":"{SYNTHETIC_AUTH_VALUE}"}}}}}}"#
    );

    let error = assert_local_auth_only(&cred_store, "127.0.0.1:5000").unwrap_err();
    assert!(error.to_string().contains("credential store"));
    assert!(!error.to_string().contains(SYNTHETIC_AUTH_VALUE));
    assert!(assert_local_auth_only(&cred_helpers, "127.0.0.1:5000").is_err());
}

#[test]
fn local_auth_assertion_requires_a_non_empty_entry_for_the_test_registry() {
    assert!(assert_local_auth_only("{}", "127.0.0.1:5000").is_err());
    assert!(assert_local_auth_only("not json", "127.0.0.1:5000").is_err());
    let empty_auth = r#"{"auths":{"127.0.0.1:5000":{"auth":""}}}"#;
    assert!(assert_local_auth_only(empty_auth, "127.0.0.1:5000").is_err());
    let other_registry = r#"{"auths":{"other.example:5000":{"auth":"value"}}}"#;
    assert!(assert_local_auth_only(other_registry, "127.0.0.1:5000").is_err());
}

#[test]
fn local_auth_absence_assertion_holds_only_after_logout() {
    let present =
        format!(r#"{{"auths":{{"127.0.0.1:5000":{{"auth":"{SYNTHETIC_AUTH_VALUE}"}}}}}}"#);
    assert!(assert_local_auth_absent(&present, "127.0.0.1:5000").is_err());

    assert_local_auth_absent("{}", "127.0.0.1:5000").unwrap();
    let other_registry = r#"{"auths":{"other.example:5000":{"auth":"value"}}}"#;
    assert_local_auth_absent(other_registry, "127.0.0.1:5000").unwrap();
}

fn timeline_record_update(name: &str, state: u8, result: Option<u8>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "value": [{
            "id": uuid::Uuid::new_v4().to_string(),
            "state": state,
            "result": result,
            "name": name,
        }],
        "count": 1,
    }))
    .unwrap()
}

#[test]
fn pinned_post_records_accept_each_expected_success_once() {
    let expected = vec![
        "Post Run setup@pin".to_string(),
        "Post Run login@pin".to_string(),
        "Post Run build@pin".to_string(),
    ];
    let mut updates = expected
        .iter()
        .map(|name| timeline_record_update(name, 2, Some(0)))
        .collect::<Vec<_>>();
    updates.push(timeline_record_update("Run unrelated main", 2, Some(2)));

    validate_successful_post_records(&updates, &expected).unwrap();
}

#[test]
fn pinned_post_records_reject_missing_or_incomplete_expected_post() {
    let expected = vec![
        "Post Run setup@pin".to_string(),
        "Post Run login@pin".to_string(),
    ];
    let updates = vec![
        timeline_record_update(&expected[0], 2, Some(0)),
        timeline_record_update(&expected[1], 1, None),
    ];

    assert!(validate_successful_post_records(&updates, &expected).is_err());
}

#[test]
fn pinned_post_records_reject_failed_cancelled_or_skipped_post() {
    let expected = vec!["Post Run action@pin".to_string()];

    for result in [2, 3, 4] {
        let updates = vec![timeline_record_update(&expected[0], 2, Some(result))];
        assert!(
            validate_successful_post_records(&updates, &expected).is_err(),
            "accepted timeline result {result}"
        );
    }
}

#[test]
fn pinned_post_records_reject_duplicate_or_unrelated_post() {
    let expected = vec!["Post Run action@pin".to_string()];
    let duplicate = vec![
        timeline_record_update(&expected[0], 2, Some(0)),
        timeline_record_update(&expected[0], 2, Some(0)),
    ];
    let unrelated = vec![
        timeline_record_update(&expected[0], 2, Some(0)),
        timeline_record_update("Post Run unrelated@pin", 2, Some(0)),
    ];

    assert!(validate_successful_post_records(&duplicate, &expected).is_err());
    assert!(validate_successful_post_records(&unrelated, &expected).is_err());
}

#[tokio::test]
async fn configured_client_reports_local_action_post_completion() {
    let mut env = TestEnv::setup().await;
    let action_path = ".github/actions/timeline-post-probe";
    let action_dir = env.workspace.workspace_dir().join(action_path);
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: timeline-post-probe\nruns:\n  using: node20\n  main: main.js\n  post: post.js\n  post-if: always()\n",
    )
    .unwrap();
    std::fs::write(action_dir.join("main.js"), "").unwrap();
    std::fs::write(action_dir.join("post.js"), "").unwrap();
    let manifest = manifest_with_steps(
        vec![serde_json::json!({
            "id": "timeline-post-probe",
            "displayName": format!("Run {action_path}"),
            "reference": {
                "name": "",
                "type": "repository",
                "repositoryType": "self",
                "path": action_path
            },
            "inputs": {},
            "condition": null,
            "timeoutInMinutes": null,
            "continueOnError": false,
            "order": 1,
            "environment": null,
            "contextName": "timeline-post-probe"
        })],
        &env.mock_server.uri(),
    );
    let timeline = spy_on_timeline_updates(&env.mock_server).await;
    env.configure_from_manifest(&manifest);

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
    validate_successful_post_records(
        &timeline.updates.lock().unwrap(),
        &[format!("Post Run {action_path}")],
    )
    .unwrap();
}

#[derive(Debug, PartialEq, Eq)]
struct RootlessDockerEnvironment {
    docker_host: String,
    xdg_runtime_dir: String,
}

fn validate_rootless_environment(
    docker_host: Option<&str>,
    xdg_runtime_dir: Option<&str>,
) -> Result<RootlessDockerEnvironment> {
    let docker_host = docker_host
        .filter(|value| !value.is_empty())
        .context("DOCKER_HOST must be set explicitly to a non-empty rootless Unix endpoint")?;
    let xdg_runtime_dir = xdg_runtime_dir
        .filter(|value| !value.is_empty())
        .context("XDG_RUNTIME_DIR must be set explicitly for the rootless Docker daemon")?;
    let runtime_path = Path::new(xdg_runtime_dir);
    if !runtime_path.is_absolute()
        || runtime_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        bail!("XDG_RUNTIME_DIR must be an absolute normalized path");
    }

    let socket = docker_host
        .strip_prefix("unix://")
        .context("DOCKER_HOST must use a Unix endpoint")?;
    if Path::new(socket) != runtime_path.join("docker.sock") {
        bail!("DOCKER_HOST must target XDG_RUNTIME_DIR/docker.sock");
    }

    Ok(RootlessDockerEnvironment {
        docker_host: docker_host.to_string(),
        xdg_runtime_dir: xdg_runtime_dir.to_string(),
    })
}

fn validate_rootless_security_options(output: &str) -> Result<()> {
    let options: Vec<String> = serde_json::from_str(output.trim())
        .context("Docker daemon security options were not a JSON string array")?;
    if !options.iter().any(|option| option == "name=rootless") {
        bail!("Docker daemon is not running in rootless mode");
    }
    Ok(())
}

async fn preflight_rootless_docker(docker_config: &Path) -> Result<RootlessDockerEnvironment> {
    let docker_host = std::env::var("DOCKER_HOST")
        .context("DOCKER_HOST must be explicitly available as UTF-8 for C-10")?;
    let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .context("XDG_RUNTIME_DIR must be explicitly available as UTF-8 for C-10")?;
    let environment = validate_rootless_environment(Some(&docker_host), Some(&xdg_runtime_dir))?;
    let security_options = docker_output(
        &["info", "--format", "{{json .SecurityOptions}}"],
        docker_config,
        None,
    )
    .await
    .context("querying Docker daemon rootless security information")?;
    validate_rootless_security_options(&security_options)?;
    Ok(environment)
}

fn validate_successful_post_records(updates: &[Vec<u8>], expected: &[String]) -> Result<()> {
    let mut completion_counts = HashMap::new();
    for name in expected {
        if completion_counts.insert(name.as_str(), 0usize).is_some() {
            bail!("duplicate expected post record name: {name}");
        }
    }

    for update in updates {
        let body: serde_json::Value =
            serde_json::from_slice(update).context("timeline update was not valid JSON")?;
        let records = body
            .get("value")
            .and_then(serde_json::Value::as_array)
            .context("timeline update had no record array")?;
        for record in records {
            if record.get("state").and_then(serde_json::Value::as_u64) != Some(2) {
                continue;
            }
            let name = record
                .get("name")
                .and_then(serde_json::Value::as_str)
                .context("completed timeline record had no name")?;
            if !name.starts_with("Post ") {
                continue;
            }
            let Some(count) = completion_counts.get_mut(name) else {
                bail!("unexpected completed post record: {name}");
            };
            if record.get("result").and_then(serde_json::Value::as_u64) != Some(0) {
                bail!("post record did not complete successfully: {name}");
            }
            *count += 1;
            if *count > 1 {
                bail!("post record completed more than once: {name}");
            }
        }
    }

    for (name, count) in completion_counts {
        if count != 1 {
            bail!("post record did not complete exactly once: {name}");
        }
    }
    Ok(())
}

struct TimelineUpdateSpy {
    updates: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn spy_on_timeline_updates(server: &wiremock::MockServer) -> TimelineUpdateSpy {
    let updates = Arc::new(Mutex::new(Vec::new()));
    let sink = updates.clone();
    wiremock::Mock::given(wiremock::matchers::method("PATCH"))
        .and(wiremock::matchers::path_regex(
            r"/_apis/pipelines/workflows/.*/timelines/.*",
        ))
        .respond_with(move |request: &wiremock::Request| {
            sink.lock().unwrap().push(request.body.clone());
            wiremock::ResponseTemplate::new(200)
        })
        .with_priority(1)
        .mount(server)
        .await;
    TimelineUpdateSpy { updates }
}

fn parse_buildkit_image_id(value: &str) -> Result<&str> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        bail!("BuildKit image ID must use sha256");
    };
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("BuildKit image ID must contain a 64-character hexadecimal digest");
    }
    Ok(value)
}

fn validate_local_image_id(expected: &str, output: &str) -> Result<()> {
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let actual = lines
        .next()
        .context("Docker image inspect returned no image ID")?;
    if lines.next().is_some() {
        bail!("Docker image inspect returned multiple image IDs");
    }
    if actual != expected {
        bail!("Docker image inspect returned a different image ID");
    }
    Ok(())
}

fn parse_container_id(output: &str) -> Result<String> {
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let id = lines
        .next()
        .context("Docker inspect returned no container ID")?;
    if lines.next().is_some()
        || id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("Docker inspect returned an invalid container ID");
    }
    Ok(id.to_string())
}

fn exact_resource_is_present(output: &str, expected: &str) -> Result<bool> {
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let Some(actual) = lines.next() else {
        return Ok(false);
    };
    if actual != expected || lines.next().is_some() {
        bail!("Docker listed an unexpected resource");
    }
    Ok(true)
}

fn offline_action_environment() -> HashMap<String, String> {
    let dead_proxy = "http://127.0.0.1:1".to_string();
    HashMap::from([
        ("HTTP_PROXY".into(), dead_proxy.clone()),
        ("HTTPS_PROXY".into(), dead_proxy.clone()),
        ("ALL_PROXY".into(), dead_proxy.clone()),
        ("http_proxy".into(), dead_proxy.clone()),
        ("https_proxy".into(), dead_proxy.clone()),
        ("all_proxy".into(), dead_proxy),
        ("NO_PROXY".into(), "127.0.0.1,localhost".into()),
        ("no_proxy".into(), "127.0.0.1,localhost".into()),
    ])
}

fn buildx_setup_inputs(
    builder_name: &str,
    buildkit_image_id: &str,
    registry: &str,
) -> HashMap<String, String> {
    HashMap::from([
        ("name".into(), builder_name.into()),
        ("cache-binary".into(), "false".into()),
        (
            "driver-opts".into(),
            format!("network=host\nimage={buildkit_image_id}"),
        ),
        (
            "buildkitd-config-inline".into(),
            format!("[registry.\"{registry}\"]\n  http = true\n  insecure = true\n"),
        ),
    ])
}

async fn preflight_local_buildx(docker_config: &Path) -> Result<String> {
    let configured_image_id = std::env::var(BUILDKIT_IMAGE_ID_ENV)
        .with_context(|| format!("{BUILDKIT_IMAGE_ID_ENV} must name a local immutable image ID"))?;
    let buildkit_image_id = parse_buildkit_image_id(&configured_image_id)?.to_string();

    docker_output(&["buildx", "version"], docker_config, None)
        .await
        .context("the local Docker CLI has no working Buildx plugin")?;
    let inspected = docker_output(
        &[
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            "--",
            &buildkit_image_id,
        ],
        docker_config,
        None,
    )
    .await
    .context("the configured immutable BuildKit image is not local")?;
    validate_local_image_id(&buildkit_image_id, &inspected)?;

    Ok(buildkit_image_id)
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
    let execution_domains =
        ExecutionDomainRoot::prepare(
            &daemon_root.path().join("job-resources"),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
    let first = TestEnv::setup_with_job_resources(execution_domains.clone()).await;
    let second = TestEnv::setup_with_job_resources(execution_domains).await;

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
    let root = ExecutionDomainRoot::prepare(
        &root_parent.path().join("job-resources"),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let config = root.reserve().await.unwrap().provision().unwrap();
    let attempt = config.attempt_dir().to_path_buf();

    docker_output(
        &[
            "login",
            "--username",
            ALICE_USER,
            "--password-stdin",
            registry.address(),
        ],
        config.docker_config_dir(),
        Some(ALICE_PASSWORD.as_bytes()),
    )
    .await
    .unwrap();

    let metadata = std::fs::symlink_metadata(config.config_file()).unwrap();
    assert!(metadata.is_file());
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(
        std::fs::symlink_metadata(config.docker_config_dir())
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
    assert_local_auth_only(
        &std::fs::read_to_string(config.config_file()).unwrap(),
        registry.address(),
    )
    .unwrap();

    docker_output(
        &["logout", registry.address()],
        config.docker_config_dir(),
        None,
    )
    .await
    .unwrap();
    assert!(attempt.exists());

    config.destroy().unwrap();
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
    environment: HashMap<String, String>,
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
        "environment": environment,
        "contextName": id
    })
}

#[derive(Clone, Debug)]
struct BuildxOwnedResources {
    builder_name: String,
    container_name: String,
    state_volume_name: String,
}

impl BuildxOwnedResources {
    fn new(builder_name: String) -> Self {
        let container_name = format!("buildx_buildkit_{builder_name}0");
        let state_volume_name = format!("{container_name}_state");
        Self {
            builder_name,
            container_name,
            state_volume_name,
        }
    }
}

struct BuildxResourcesCleanup {
    resources: BuildxOwnedResources,
    docker_config: tempfile::TempDir,
}

impl BuildxResourcesCleanup {
    fn new(resources: BuildxOwnedResources) -> Self {
        let docker_config = tempfile::tempdir().unwrap();
        std::fs::write(docker_config.path().join("config.json"), "{}").unwrap();
        Self {
            resources,
            docker_config,
        }
    }

    fn docker_config(&self) -> &Path {
        self.docker_config.path()
    }
}

impl Drop for BuildxResourcesCleanup {
    fn drop(&mut self) {
        let _ = docker_cleanup(
            &[
                "container",
                "rm",
                "--force",
                "--",
                &self.resources.container_name,
            ],
            self.docker_config.path(),
        );
        let _ = docker_cleanup(
            &[
                "volume",
                "rm",
                "--force",
                "--",
                &self.resources.state_volume_name,
            ],
            self.docker_config.path(),
        );
    }
}

#[tokio::test]
#[ignore = "requires Docker, local Buildx/BuildKit, and the explicitly pinned public actions"]
async fn pinned_buildx_flow_uses_job_config_and_original_socket() {
    let preflight_config = tempfile::tempdir().unwrap();
    std::fs::write(preflight_config.path().join("config.json"), "{}").unwrap();
    let rootless_environment = preflight_rootless_docker(preflight_config.path())
        .await
        .unwrap();
    let buildkit_image_id = preflight_local_buildx(preflight_config.path())
        .await
        .unwrap();

    let registry = AuthenticatedRegistry::start().await.unwrap();
    let mut env = TestEnv::setup().await;
    let timeline = spy_on_timeline_updates(&env.mock_server).await;
    let resources =
        BuildxOwnedResources::new(format!("chimera-buildx-{}", uuid::Uuid::new_v4().simple()));
    let buildx_cleanup = BuildxResourcesCleanup::new(resources.clone());
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
            rootless_environment.docker_host,
        ),
        (
            "EXPECTED_XDG_RUNTIME_DIR".into(),
            rootless_environment.xdg_runtime_dir,
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
    let action_environment = offline_action_environment();
    let setup = remote_action_step(
        "buildx",
        "docker/setup-buildx-action",
        SETUP_BUILDX_SHA,
        buildx_setup_inputs(
            &resources.builder_name,
            &buildkit_image_id,
            registry.address(),
        ),
        action_environment.clone(),
        2,
    );
    let builder_name_file = env.tmp.path().join("observed-buildx-builder-name");
    let builder_container_id_file = env.tmp.path().join("observed-buildx-container-id");
    let mut record_builder = script_step_env(
        "record-builder",
        r#"
            printf '%s' '${{ steps.buildx.outputs.name }}' > "$BUILDER_NAME_FILE"
            docker container inspect --format '{{.Id}}' "$BUILDER_CONTAINER" > "$BUILDER_CONTAINER_ID_FILE"
            test "$(docker container inspect --format '{{.Image}}' "$BUILDER_CONTAINER")" = "$BUILDKIT_IMAGE_ID"
            docker volume inspect "$BUILDER_STATE_VOLUME" >/dev/null
        "#,
        HashMap::from([
            (
                "BUILDER_NAME_FILE".into(),
                builder_name_file.to_string_lossy().into_owned(),
            ),
            (
                "BUILDER_CONTAINER_ID_FILE".into(),
                builder_container_id_file.to_string_lossy().into_owned(),
            ),
            ("BUILDER_CONTAINER".into(), resources.container_name.clone()),
            (
                "BUILDER_STATE_VOLUME".into(),
                resources.state_volume_name.clone(),
            ),
            ("BUILDKIT_IMAGE_ID".into(), buildkit_image_id.clone()),
        ]),
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
        action_environment.clone(),
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
        action_environment,
        5,
    );
    let mut pull_environment = offline_action_environment();
    pull_environment.insert("IMAGE".into(), tag.clone());
    let mut pull = script_step_env("pull", "docker pull \"$IMAGE\"", pull_environment);
    pull["order"] = serde_json::json!(6);
    let manifest = manifest_with_steps_and_context(
        vec![probe, setup, record_builder, login, build, pull],
        &env.mock_server.uri(),
        serde_json::json!({
            "github": {
                "repository": "chimera/buildx-probe",
                "repository_owner": "chimera",
                "ref": "refs/heads/main",
                "sha": "0123456789abcdef0123456789abcdef01234567",
                "server_url": "https://github.com",
                "api_url": "https://api.github.com",
                "graphql_url": "https://api.github.com/graphql"
            },
            "secrets": { "REGISTRY_PASSWORD": ALICE_PASSWORD }
        }),
    );
    env.configure_from_manifest(&manifest);

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
    assert!(!observed.attempt_dir.exists());
    let expected_posts = vec![
        format!("Post Run docker/build-push-action@{BUILD_PUSH_SHA}"),
        format!("Post Run docker/login-action@{LOGIN_SHA}"),
        format!("Post Run docker/setup-buildx-action@{SETUP_BUILDX_SHA}"),
    ];
    validate_successful_post_records(&timeline.updates.lock().unwrap(), &expected_posts).unwrap();
    assert_eq!(
        std::fs::read_to_string(builder_name_file).unwrap(),
        resources.builder_name
    );
    let builder_container_id =
        parse_container_id(&std::fs::read_to_string(builder_container_id_file).unwrap()).unwrap();

    let container_filter = format!("id={builder_container_id}");
    let container_listing = docker_output(
        &[
            "container",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            &container_filter,
        ],
        buildx_cleanup.docker_config(),
        None,
    )
    .await
    .unwrap();
    assert!(
        !exact_resource_is_present(&container_listing, &builder_container_id).unwrap(),
        "setup-buildx post left its exact builder container"
    );

    let volume_filter = format!("name={}", resources.state_volume_name);
    let volume_listing = docker_output(
        &["volume", "ls", "--quiet", "--filter", &volume_filter],
        buildx_cleanup.docker_config(),
        None,
    )
    .await
    .unwrap();
    assert!(
        !exact_resource_is_present(&volume_listing, &resources.state_volume_name).unwrap(),
        "setup-buildx post left its exact state volume"
    );

    registry.remove_local_image(&tag).await.unwrap();
}
