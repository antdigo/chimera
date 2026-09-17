use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::SystemTime;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chimera::config::{load_config, load_runner_credentials, rsa_params_to_private_key};
use rsa::traits::PublicKeyParts;
use serde_json::Value;
use tempfile::TempDir;

const CREDENTIAL_FILES: [&str; 3] = ["runner.json", "credentials.json", "rsa_params.json"];
const OFFICIAL_FILES: [&str; 3] = [".runner", ".credentials", ".credentials_rsaparams"];
const SYNTHETIC_AGENT_ID: u64 = 42;

type SourceMutation = fn(&Path, &str);

#[derive(PartialEq, Eq)]
struct FileSnapshot {
    bytes: Vec<u8>,
    inode: u64,
    modified: SystemTime,
}

#[derive(PartialEq, Eq)]
struct TargetSnapshot {
    files: Vec<FileSnapshot>,
    root_entries: Vec<OsString>,
    runners_entries: Vec<OsString>,
    runner_entries: Vec<OsString>,
    root_mode: u32,
    runners_mode: u32,
    runner_mode: u32,
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/official-runner-v2")
}

fn copy_fixture() -> TempDir {
    let destination = tempfile::tempdir().unwrap();
    for name in OFFICIAL_FILES {
        fs::copy(fixture_path().join(name), destination.path().join(name)).unwrap();
    }
    destination
}

fn import_command(source: &Path, name: &str, root: &Path, dry_run: bool) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chimera"));
    command
        .arg("import-official")
        .arg("--source")
        .arg(source)
        .arg("--name")
        .arg(name)
        .arg("--root")
        .arg(root)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("http_proxy", "http://127.0.0.1:9")
        .env("https_proxy", "http://127.0.0.1:9")
        .env("all_proxy", "http://127.0.0.1:9")
        .env("NO_PROXY", "")
        .env("no_proxy", "");
    if dry_run {
        command.arg("--dry-run");
    }
    command
}

fn run_import(source: &Path, name: &str, root: &Path, dry_run: bool) -> Output {
    import_command(source, name, root, dry_run)
        .output()
        .unwrap()
}

fn run_import_with_umask(source: &Path, name: &str, root: &Path, umask: libc::mode_t) -> Output {
    let mut command = import_command(source, name, root, false);
    // Only the child needs the altered mask; changing the test process would leak state.
    unsafe {
        command.pre_exec(move || {
            libc::umask(umask);
            Ok(())
        });
    }
    command.output().unwrap()
}

fn output_contains(output: &Output, text: &str) -> bool {
    String::from_utf8_lossy(&output.stdout).contains(text)
        || String::from_utf8_lossy(&output.stderr).contains(text)
}

fn assert_success_output(output: &Output, status: &str, name: &str, source: &Path) {
    assert!(output.status.success());
    let expected = format!(
        "{status}: local-name={name}, agent-id={SYNTHETIC_AGENT_ID}; offline validation only\n"
    );
    assert!(output.stdout.as_slice() == expected.as_bytes());
    assert!(output.stderr.is_empty());
    assert_source_credentials_redacted(output, source);
}

fn assert_error_category(output: &Output, category: &str) {
    assert!(!output.status.success());
    let expected_prefix = format!("Error: {category}:");
    assert!(String::from_utf8_lossy(&output.stderr).starts_with(&expected_prefix));
}

fn assert_redacted(output: &Output, secret: &str) {
    assert!(!output_contains(output, secret));
}

fn assert_source_credentials_redacted(output: &Output, source: &Path) {
    let credentials = read_json(&source.join(".credentials"));
    let rsa = read_json(&source.join(".credentials_rsaparams"));
    assert_redacted(output, json_string(&credentials["data"], "clientId"));
    assert_redacted(
        output,
        json_string(&credentials["data"], "authorizationUrl"),
    );
    for field in ["D", "DP", "DQ", "Exponent", "InverseQ", "Modulus", "P", "Q"] {
        assert_redacted(output, json_string(&rsa, field));
    }
}

fn snapshot(path: &Path) -> FileSnapshot {
    let metadata = fs::metadata(path).unwrap();
    FileSnapshot {
        bytes: fs::read(path).unwrap(),
        inode: metadata.ino(),
        modified: metadata.modified().unwrap(),
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn rewrite_json(path: &Path, change: impl FnOnce(&mut Value)) {
    let mut value = read_json(path);
    change(&mut value);
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

fn json_string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn assert_exact_mode(path: &Path, expected: u32) {
    assert_eq!(mode(path), expected);
}

fn directory_entries(path: &Path) -> Vec<OsString> {
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    entries
}

fn snapshot_target(root: &Path, name: &str) -> TargetSnapshot {
    let runner = root.join("runners").join(name);
    let mut files = vec![snapshot(&root.join("config.toml"))];
    files.extend(
        CREDENTIAL_FILES
            .iter()
            .map(|file| snapshot(&runner.join(file))),
    );

    TargetSnapshot {
        files,
        root_entries: directory_entries(root),
        runners_entries: directory_entries(&root.join("runners")),
        runner_entries: directory_entries(&runner),
        root_mode: mode(root),
        runners_mode: mode(&root.join("runners")),
        runner_mode: mode(&runner),
    }
}

fn assert_private_target_modes(root: &Path, name: &str) {
    assert_exact_mode(root, 0o700);
    assert_exact_mode(&root.join("runners"), 0o700);
    assert_exact_mode(&root.join("runners").join(name), 0o700);
}

fn assert_conflict_target_unchanged(
    before: &TargetSnapshot,
    root: &Path,
    name: &str,
    alternative_name: &str,
) {
    assert!(!root.join("runners").join(alternative_name).exists());
    assert_private_target_modes(root, name);
    assert!(before == &snapshot_target(root, name));
}

fn assert_private_import_modes(root: &Path, name: &str) {
    assert_private_target_modes(root, name);
    assert_exact_mode(&root.join(".chimera.lock"), 0o600);
    assert_exact_mode(&root.join("config.toml"), 0o600);
    for file in CREDENTIAL_FILES {
        assert_exact_mode(&root.join("runners").join(name).join(file), 0o600);
    }
}

#[test]
fn imports_fixture_and_chimera_loader_preserves_every_field() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("chimera");
    let output = run_import(&fixture_path(), "imported-runner", &root, false);

    assert_success_output(&output, "imported", "imported-runner", &fixture_path());

    let official_runner = read_json(&fixture_path().join(".runner"));
    let official_credentials = read_json(&fixture_path().join(".credentials"));
    let official_rsa = read_json(&fixture_path().join(".credentials_rsaparams"));
    let loaded = load_runner_credentials(&root.join("runners"), "imported-runner").unwrap();

    assert_eq!(
        loaded.info.agent_id,
        official_runner["agentId"].as_u64().unwrap()
    );
    assert_eq!(
        loaded.info.agent_name,
        json_string(&official_runner, "agentName")
    );
    assert_eq!(
        loaded.info.pool_id,
        official_runner["poolId"].as_u64().unwrap()
    );
    assert_eq!(
        loaded.info.server_url,
        json_string(&official_runner, "serverUrl")
    );
    assert_eq!(
        loaded.info.server_url_v2,
        json_string(&official_runner, "serverUrlV2")
    );
    assert_eq!(
        loaded.info.git_hub_url,
        json_string(&official_runner, "gitHubUrl")
    );
    assert_eq!(
        loaded.info.work_folder,
        json_string(&official_runner, "workFolder")
    );
    assert_eq!(
        loaded.info.use_v2_flow,
        official_runner["useV2Flow"].as_bool().unwrap()
    );
    assert_eq!(
        loaded.oauth.scheme,
        json_string(&official_credentials, "scheme")
    );
    assert_eq!(
        loaded.oauth.client_id,
        json_string(&official_credentials["data"], "clientId")
    );
    assert_eq!(
        loaded.oauth.authorization_url,
        json_string(&official_credentials["data"], "authorizationUrl")
    );

    let imported_components = [
        &loaded.rsa_params.d,
        &loaded.rsa_params.dp,
        &loaded.rsa_params.dq,
        &loaded.rsa_params.exponent,
        &loaded.rsa_params.inverse_q,
        &loaded.rsa_params.modulus,
        &loaded.rsa_params.p,
        &loaded.rsa_params.q,
    ];
    let official_components = ["D", "DP", "DQ", "Exponent", "InverseQ", "Modulus", "P", "Q"];
    for (imported, field) in imported_components.into_iter().zip(official_components) {
        assert!(
            BASE64.decode(imported).unwrap()
                == BASE64.decode(json_string(&official_rsa, field)).unwrap()
        );
    }

    let private_key = rsa_params_to_private_key(&loaded.rsa_params).unwrap();
    assert!(
        private_key.n().to_bytes_be()
            == BASE64
                .decode(json_string(&official_rsa, "Modulus"))
                .unwrap()
    );
    assert!(
        private_key.e().to_bytes_be()
            == BASE64
                .decode(json_string(&official_rsa, "Exponent"))
                .unwrap()
    );
}

#[test]
fn dry_run_is_offline_and_does_not_create_new_root() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("missing-root");
    let output = run_import(&fixture_path(), "dry-runner", &root, true);

    assert_success_output(&output, "eligible", "dry-runner", &fixture_path());
    assert!(!root.exists());
}

#[test]
fn repeat_reports_already_imported_without_duplicate_or_rewrite() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("chimera");
    let name = "repeat-runner";
    let first = run_import(&fixture_path(), name, &root, false);
    assert_success_output(&first, "imported", name, &fixture_path());

    let credentials_before: Vec<_> = CREDENTIAL_FILES
        .iter()
        .map(|file| snapshot(&root.join("runners").join(name).join(file)))
        .collect();
    let second = run_import(&fixture_path(), name, &root, false);
    let credentials_after: Vec<_> = CREDENTIAL_FILES
        .iter()
        .map(|file| snapshot(&root.join("runners").join(name).join(file)))
        .collect();

    assert_success_output(&second, "already-imported", name, &fixture_path());
    assert!(credentials_before == credentials_after);
    assert_eq!(
        load_config(&root.join("config.toml")).unwrap().runners,
        vec![name.to_owned()]
    );
}

#[test]
fn same_name_or_same_identity_conflict_leaves_target_unchanged() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("chimera");
    let name = "conflict-runner";
    let alternative_name = "another-local-runner";
    let first = run_import(&fixture_path(), name, &root, false);
    assert_success_output(&first, "imported", name, &fixture_path());
    let before = snapshot_target(&root, name);

    let changed_source = copy_fixture();
    let same_name_secret = "same-name-credential-canary";
    rewrite_json(&changed_source.path().join(".runner"), |runner| {
        runner["agentName"] = Value::String(same_name_secret.into());
    });
    let same_name = run_import(changed_source.path(), name, &root, false);
    assert_error_category(&same_name, "identity-conflict");
    assert_redacted(&same_name, same_name_secret);
    assert_conflict_target_unchanged(&before, &root, name, alternative_name);

    let same_identity = run_import(&fixture_path(), alternative_name, &root, false);
    assert_error_category(&same_identity, "identity-conflict");
    assert_conflict_target_unchanged(&before, &root, name, alternative_name);
}

#[test]
fn invalid_inputs_fail_before_publish_and_redact_secrets() {
    let cases: [(&str, &str, SourceMutation); 6] = [
        ("missing", "invalid-source", |source, secret| {
            rewrite_json(&source.join(".credentials"), |credentials| {
                credentials["data"]["clientId"] = Value::String(secret.into());
                credentials["data"]
                    .as_object_mut()
                    .unwrap()
                    .remove("authorizationUrl");
            });
        }),
        ("malformed-json", "invalid-source", |source, secret| {
            fs::write(source.join(".runner"), format!("{{\"secret\":\"{secret}")).unwrap();
        }),
        ("malformed-base64", "invalid-source", |source, secret| {
            rewrite_json(&source.join(".credentials_rsaparams"), |rsa| {
                rsa["D"] = Value::String(secret.into());
            });
        }),
        ("malformed-rsa", "invalid-source", |source, secret| {
            rewrite_json(&source.join(".credentials_rsaparams"), |rsa| {
                rsa["D"] = Value::String(BASE64.encode(secret));
            });
        }),
        (
            "unsupported-auth",
            "unsupported-registration",
            |source, secret| {
                rewrite_json(&source.join(".credentials"), |credentials| {
                    credentials["scheme"] = Value::String(secret.into());
                });
            },
        ),
        (
            "unsupported-flow",
            "unsupported-registration",
            |source, secret| {
                rewrite_json(&source.join(".runner"), |runner| {
                    runner["agentName"] = Value::String(secret.into());
                    runner["useV2Flow"] = Value::Bool(false);
                });
            },
        ),
    ];

    for (label, category, mutate) in cases {
        let source = copy_fixture();
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join(label);
        let secret = format!("redaction-{label}-canary");
        mutate(source.path(), &secret);
        let injected_rsa_value = (label == "malformed-rsa").then(|| {
            json_string(
                &read_json(&source.path().join(".credentials_rsaparams")),
                "D",
            )
            .to_owned()
        });

        let output = run_import(source.path(), "invalid-runner", &root, false);

        assert_error_category(&output, category);
        assert_redacted(&output, &secret);
        if let Some(injected_rsa_value) = injected_rsa_value {
            assert_redacted(&output, &injected_rsa_value);
        }
        assert!(!root.exists());
    }
}

#[test]
fn traversal_symlink_and_unsafe_root_fail_closed() {
    let parent = tempfile::tempdir().unwrap();
    let missing_root = parent.path().join("missing-root");
    let traversal = run_import(&fixture_path(), "../escaped", &missing_root, false);
    assert_error_category(&traversal, "invalid-source");
    assert!(!missing_root.exists());
    assert!(!parent.path().join("escaped").exists());

    let symlink_source = copy_fixture();
    fs::remove_file(symlink_source.path().join(".runner")).unwrap();
    symlink(
        fixture_path().join(".runner"),
        symlink_source.path().join(".runner"),
    )
    .unwrap();
    let symlink_root = parent.path().join("symlink-root");
    let symlink_output = run_import(
        symlink_source.path(),
        "symlink-runner",
        &symlink_root,
        false,
    );
    assert_error_category(&symlink_output, "invalid-source");
    assert!(!symlink_root.exists());

    let unsafe_root = parent.path().join("unsafe-root");
    fs::create_dir(&unsafe_root).unwrap();
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o777)).unwrap();
    fs::write(unsafe_root.join("marker"), b"preserve").unwrap();
    let unsafe_output = run_import(&fixture_path(), "unsafe-runner", &unsafe_root, false);
    assert_error_category(&unsafe_output, "write-failed");
    assert_eq!(fs::read(unsafe_root.join("marker")).unwrap(), b"preserve");
    assert!(!unsafe_root.join("config.toml").exists());
    assert!(!unsafe_root.join("runners").exists());
}

#[test]
fn published_directory_without_config_is_recovered_by_cli() {
    let parent = tempfile::tempdir().unwrap();
    let completed_root = parent.path().join("completed");
    let name = "resume-runner";
    let completed = run_import(&fixture_path(), name, &completed_root, false);
    assert_success_output(&completed, "imported", name, &fixture_path());
    let completed_lock = completed_root.join(".chimera.lock");
    assert!(fs::metadata(&completed_lock).unwrap().is_file());
    assert_exact_mode(&completed_lock, 0o600);

    let crash_root = parent.path().join("crash-window");
    let crash_runner = crash_root.join("runners").join(name);
    fs::create_dir_all(&crash_runner).unwrap();
    fs::set_permissions(&crash_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        crash_root.join("runners"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&crash_runner, fs::Permissions::from_mode(0o700)).unwrap();
    for file in CREDENTIAL_FILES {
        let destination = crash_runner.join(file);
        fs::copy(
            completed_root.join("runners").join(name).join(file),
            &destination,
        )
        .unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let crash_lock = crash_root.join(".chimera.lock");
    fs::copy(&completed_lock, &crash_lock).unwrap();
    fs::set_permissions(&crash_lock, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(fs::metadata(&crash_lock).unwrap().is_file());
    assert_exact_mode(&crash_lock, 0o600);
    let lock_before = snapshot(&crash_lock);
    assert!(!crash_root.join("config.toml").exists());

    let recovered = run_import(&fixture_path(), name, &crash_root, false);

    assert_success_output(&recovered, "imported", name, &fixture_path());
    assert!(lock_before == snapshot(&crash_lock));
    assert_eq!(
        load_config(&crash_root.join("config.toml"))
            .unwrap()
            .runners,
        vec![name.to_owned()]
    );
}

#[test]
fn umask_zero_still_creates_private_credentials() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("chimera");
    let output = run_import_with_umask(&fixture_path(), "umask-zero", &root, 0o000);

    assert_success_output(&output, "imported", "umask-zero", &fixture_path());
    assert_private_import_modes(&root, "umask-zero");
}

#[test]
fn restrictive_umask_still_creates_exact_private_modes() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("chimera");
    let output = run_import_with_umask(&fixture_path(), "umask-restrictive", &root, 0o777);

    assert_success_output(&output, "imported", "umask-restrictive", &fixture_path());
    assert_private_import_modes(&root, "umask-restrictive");
}
