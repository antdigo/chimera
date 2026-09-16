use std::path::{Path, PathBuf};

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

pub(crate) fn fixture_credentials() -> crate::config::RunnerCredentials {
    crate::import::source::read_official_registration(&fixture_path())
        .unwrap()
        .credentials
}

pub(crate) fn write_chimera_credentials(root: &Path, name: &str) {
    crate::config::save_runner_credentials(&root.join("runners"), name, &fixture_credentials())
        .unwrap();
}
