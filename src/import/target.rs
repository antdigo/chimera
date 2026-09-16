use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::config::{ChimeraConfig, ChimeraPaths, RunnerCredentials};
use crate::storage::validate_existing_root;

use super::source::{read_official_registration, runner_identity};
use super::{ImportError, RunnerIdentity, ValidatedRegistration, read_regular_no_follow};

const CREDENTIAL_FILES: [&str; 3] = ["runner.json", "credentials.json", "rsa_params.json"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetDisposition {
    New,
    Resume,
    AlreadyImported,
}

#[derive(Debug)]
pub(crate) struct PreservedConfig {
    model: ChimeraConfig,
    document: toml::Table,
    original_mode: Option<u32>,
}

#[derive(Debug)]
pub(crate) struct PreparedImport {
    name: String,
    registration: ValidatedRegistration,
    paths: ChimeraPaths,
    config: PreservedConfig,
    disposition: TargetDisposition,
}

pub(crate) fn prepare_import(
    source: &Path,
    name: &str,
    root: &Path,
) -> Result<PreparedImport, ImportError> {
    validate_local_name(name)?;
    let registration = read_official_registration(source)?;
    validate_root_if_present(root)?;

    let canonical_root = canonicalize_allow_missing(root)?;
    let paths = ChimeraPaths::new(canonical_root);
    let target = paths.runner_dir(name);
    if registration.canonical_source.starts_with(&target)
        || target.starts_with(&registration.canonical_source)
    {
        return Err(ImportError::InvalidSource(
            "source and target paths must not overlap".into(),
        ));
    }

    let config = load_preserved_config(&paths.config_file())?;
    let existing = inspect_existing_credentials(&paths.runners_dir())?;
    validate_config_entries(name, &config, &existing)?;
    let disposition = classify_disposition(name, &registration, &config, &existing)?;

    Ok(PreparedImport {
        name: name.to_owned(),
        registration,
        paths,
        config,
        disposition,
    })
}

fn validate_local_name(name: &str) -> Result<(), ImportError> {
    let valid_length = (1..=128).contains(&name.len());
    let valid_chars = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid_length || !valid_chars || matches!(name, "." | "..") {
        return Err(ImportError::InvalidSource(
            "local name must be 1-128 ASCII characters from [A-Za-z0-9._-] and not '.' or '..'"
                .into(),
        ));
    }
    Ok(())
}

fn validate_root_if_present(root: &Path) -> Result<(), ImportError> {
    match std::fs::symlink_metadata(root) {
        Ok(_) => validate_existing_root(root).map_err(|_| {
            ImportError::WriteFailed("unable to validate existing target root".into())
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ImportError::WriteFailed(
            "unable to inspect target root".into(),
        )),
    }
}

fn canonicalize_allow_missing(path: &Path) -> Result<PathBuf, ImportError> {
    let mut ancestor = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| ImportError::WriteFailed("unable to resolve target root".into()))?
            .join(path)
    };
    let mut missing = Vec::<OsString>::new();

    loop {
        match std::fs::symlink_metadata(&ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let component = ancestor.components().next_back().ok_or_else(|| {
                    ImportError::WriteFailed("unable to resolve target root".into())
                })?;
                match component {
                    Component::Normal(value) => missing.push(value.to_owned()),
                    Component::CurDir => {}
                    Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                        return Err(ImportError::WriteFailed(
                            "target root has an unsupported missing path component".into(),
                        ));
                    }
                }
                if !ancestor.pop() {
                    return Err(ImportError::WriteFailed(
                        "unable to resolve target root".into(),
                    ));
                }
            }
            Err(_) => {
                return Err(ImportError::WriteFailed(
                    "unable to inspect target root".into(),
                ));
            }
        }
    }

    let mut canonical = std::fs::canonicalize(&ancestor)
        .map_err(|_| ImportError::WriteFailed("unable to resolve target root".into()))?;
    for component in missing.into_iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn load_preserved_config(path: &Path) -> Result<PreservedConfig, ImportError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return default_preserved_config();
        }
        Err(_) => {
            return Err(ImportError::WriteFailed(
                "unable to inspect existing config.toml".into(),
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ImportError::WriteFailed(
            "unable to read existing config.toml".into(),
        ));
    }

    let bytes = read_regular_no_follow(path)
        .map_err(|_| ImportError::WriteFailed("unable to read existing config.toml".into()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ImportError::WriteFailed("unable to parse existing config.toml".into()))?;
    let model = toml::from_str(text)
        .map_err(|_| ImportError::WriteFailed("unable to parse existing config.toml".into()))?;
    let document = toml::from_str(text)
        .map_err(|_| ImportError::WriteFailed("unable to parse existing config.toml".into()))?;

    Ok(PreservedConfig {
        model,
        document,
        original_mode: Some(metadata.permissions().mode() & 0o777),
    })
}

fn default_preserved_config() -> Result<PreservedConfig, ImportError> {
    let model = ChimeraConfig::default();
    let text = toml::to_string_pretty(&model)
        .map_err(|_| ImportError::WriteFailed("unable to prepare default config.toml".into()))?;
    let document = toml::from_str(&text)
        .map_err(|_| ImportError::WriteFailed("unable to prepare default config.toml".into()))?;
    Ok(PreservedConfig {
        model,
        document,
        original_mode: None,
    })
}

fn inspect_existing_credentials(
    runners_dir: &Path,
) -> Result<BTreeMap<String, RunnerCredentials>, ImportError> {
    let metadata = match std::fs::symlink_metadata(runners_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => {
            return Err(ImportError::WriteFailed(
                "unable to inspect existing runners directory".into(),
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ImportError::WriteFailed(
            "existing runners path is not a directory".into(),
        ));
    }

    let entries = std::fs::read_dir(runners_dir).map_err(|_| {
        ImportError::WriteFailed("unable to read existing runners directory".into())
    })?;
    let mut paths = entries
        .map(|entry| {
            entry.map(|entry| entry.path()).map_err(|_| {
                ImportError::WriteFailed("unable to read existing runner entry".into())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();

    let mut existing = BTreeMap::new();
    for path in paths {
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
            ImportError::WriteFailed("unable to inspect existing runner directory".into())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ImportError::WriteFailed(
                "existing runner entry is not a directory".into(),
            ));
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                ImportError::WriteFailed("existing runner name is not valid UTF-8".into())
            })?
            .to_owned();
        existing.insert(name, read_existing_credentials(&path)?);
    }
    Ok(existing)
}

fn read_existing_credentials(path: &Path) -> Result<RunnerCredentials, ImportError> {
    let info = parse_existing_json(path, CREDENTIAL_FILES[0])?;
    let oauth = parse_existing_json(path, CREDENTIAL_FILES[1])?;
    let rsa_params = parse_existing_json(path, CREDENTIAL_FILES[2])?;
    Ok(RunnerCredentials {
        info,
        oauth,
        rsa_params,
    })
}

fn parse_existing_json<T: DeserializeOwned>(
    directory: &Path,
    name: &str,
) -> Result<T, ImportError> {
    let path = directory.join(name);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
        ImportError::WriteFailed(format!(
            "unable to read existing runner credential file {name}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ImportError::WriteFailed(format!(
            "unable to read existing runner credential file {name}"
        )));
    }
    let bytes = read_regular_no_follow(&path).map_err(|_| {
        ImportError::WriteFailed(format!(
            "unable to read existing runner credential file {name}"
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        ImportError::WriteFailed(format!(
            "unable to parse existing {name} at line {} column {}",
            error.line(),
            error.column()
        ))
    })
}

fn validate_config_entries(
    name: &str,
    config: &PreservedConfig,
    existing: &BTreeMap<String, RunnerCredentials>,
) -> Result<(), ImportError> {
    let mut configured = BTreeSet::new();
    for configured_name in &config.model.runners {
        if !configured.insert(configured_name) {
            return Err(ImportError::WriteFailed(
                "existing config.toml contains duplicate runner names".into(),
            ));
        }
        if configured_name != name && !existing.contains_key(configured_name) {
            return Err(ImportError::WriteFailed(
                "existing config.toml references incomplete runner credentials".into(),
            ));
        }
    }
    Ok(())
}

fn classify_disposition(
    name: &str,
    registration: &ValidatedRegistration,
    config: &PreservedConfig,
    existing: &BTreeMap<String, RunnerCredentials>,
) -> Result<TargetDisposition, ImportError> {
    for (existing_name, credentials) in existing {
        if existing_name == name {
            continue;
        }
        let identity = identity_from_credentials(credentials).map_err(|()| {
            ImportError::WriteFailed(
                "unable to derive identity from existing runner credentials".into(),
            )
        })?;
        if identity == registration.identity {
            return Err(ImportError::IdentityConflict(
                "registration identity already exists under another local name".into(),
            ));
        }
    }

    let name_in_config = config.model.runners.iter().any(|runner| runner == name);
    match (existing.get(name), name_in_config) {
        (Some(credentials), true) if credentials == &registration.credentials => {
            Ok(TargetDisposition::AlreadyImported)
        }
        (Some(credentials), false) if credentials == &registration.credentials => {
            Ok(TargetDisposition::Resume)
        }
        (Some(_), _) => Err(ImportError::IdentityConflict(
            "local name already stores different credentials".into(),
        )),
        (None, true) => Err(ImportError::IdentityConflict(
            "local name is configured without a complete credential set".into(),
        )),
        (None, false) => Ok(TargetDisposition::New),
    }
}

fn identity_from_credentials(credentials: &RunnerCredentials) -> Result<RunnerIdentity, ()> {
    if credentials.info.pool_id == 0 || credentials.info.agent_id == 0 {
        return Err(());
    }
    runner_identity(
        &credentials.info.git_hub_url,
        credentials.info.pool_id,
        credentials.info.agent_id,
    )
    .map_err(|_| ())
}

#[cfg(test)]
#[path = "target_test.rs"]
mod target_test;
