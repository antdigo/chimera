use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{ImportError, ImportOutcome};

pub(crate) const LOCK_RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

// Other tests in this binary spawn child processes, and between fork and exec
// such a child transiently duplicates this process's lock-holding open file
// description, so TargetBusy can outlive the release of a previous
// import_official call (or an explicit drop of its lock) by milliseconds.
// import_official writes nothing before the root lock is acquired, so retrying
// the whole call is safe; once the deadline passes the error is returned
// unchanged and a genuinely held lock still fails the test.
pub(crate) fn import_official_after_lock_release(
    source: &Path,
    name: &str,
    root: &Path,
) -> Result<ImportOutcome, ImportError> {
    let deadline = Instant::now() + LOCK_RELEASE_TIMEOUT;
    loop {
        match super::import_official(source, name, root, false) {
            Err(ImportError::TargetBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            outcome => return outcome,
        }
    }
}

pub(crate) fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/official-runner-v2")
}

pub(crate) fn copy_fixture() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    for name in [".runner", ".credentials", ".credentials_rsaparams"] {
        std::fs::copy(fixture_path().join(name), temp.path().join(name)).unwrap();
    }
    temp
}

pub(crate) fn mutate_json(source: &Path, name: &str, mutate: impl FnOnce(&mut serde_json::Value)) {
    let path = source.join(name);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    mutate(&mut value);
    std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

pub(crate) fn prepend_utf8_bom(source: &Path, name: &str) {
    let path = source.join(name);
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend_from_slice(&std::fs::read(&path).unwrap());
    std::fs::write(&path, bytes).unwrap();
}

pub(crate) fn fixture_credentials() -> crate::config::RunnerCredentials {
    crate::import::source::read_official_registration(&fixture_path())
        .unwrap()
        .credentials
}

pub(crate) fn write_chimera_credentials(root: &Path, name: &str) {
    use std::os::unix::fs::PermissionsExt;

    crate::config::save_runner_credentials(&root.join("runners"), name, &fixture_credentials())
        .unwrap();
    let directory = root.join("runners").join(name);
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    for file in ["runner.json", "credentials.json", "rsa_params.json"] {
        std::fs::set_permissions(directory.join(file), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
}
