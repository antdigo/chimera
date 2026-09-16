use std::collections::HashMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use uuid::Uuid;

pub const DOCKER_CONFIG_ENV: &str = "DOCKER_CONFIG";

#[derive(Debug)]
pub enum JobDockerConfigError {
    StaleJobResources {
        path: PathBuf,
    },
    UnsafeRoot {
        path: PathBuf,
        reason: &'static str,
    },
    AttemptCollision {
        attempt_id: Uuid,
    },
    UnsafeEntry {
        path: PathBuf,
    },
    ReservedEnvironmentOverride {
        source: &'static str,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Cleanup {
        path: PathBuf,
        source: io::Error,
    },
    CreationRollback {
        path: PathBuf,
        create: Box<JobDockerConfigError>,
        cleanup: io::Error,
    },
}

impl std::fmt::Display for JobDockerConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleJobResources { path } => write!(
                formatter,
                "stale-job-resources: resource root is not empty: {}",
                path.display()
            ),
            Self::UnsafeRoot { path, reason } => write!(
                formatter,
                "unsafe-job-resource-root: {reason}: {}",
                path.display()
            ),
            Self::AttemptCollision { attempt_id } => write!(
                formatter,
                "job-resource-collision: generated attempt id already exists: {attempt_id}"
            ),
            Self::UnsafeEntry { path } => write!(
                formatter,
                "unsafe-job-resource-path: refusing symlink or special file: {}",
                path.display()
            ),
            Self::ReservedEnvironmentOverride { source } => write!(
                formatter,
                "reserved-environment-variable: DOCKER_CONFIG cannot be changed by {source}"
            ),
            Self::Io {
                operation, path, ..
            } => write!(
                formatter,
                "job-docker-config-io: {operation} failed for {}",
                path.display()
            ),
            Self::Cleanup { path, .. } => write!(
                formatter,
                "job-resource-cleanup: cleanup failed for {}",
                path.display()
            ),
            Self::CreationRollback {
                path,
                create,
                cleanup,
            } => write!(
                formatter,
                "job-resource-rollback: creation failed for {}: {create}; rollback failed: {cleanup}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for JobDockerConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::Cleanup { source, .. } => Some(source),
            Self::CreationRollback { create, .. } => Some(create),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JobResourceRoot {
    canonical_path: PathBuf,
}

#[derive(Debug)]
pub struct JobDockerConfig {
    root: PathBuf,
    attempt_id: Uuid,
    attempt_dir: PathBuf,
    config_dir: PathBuf,
    config_file: PathBuf,
    cleaned: bool,
}

impl JobResourceRoot {
    pub fn prepare(path: &Path) -> Result<Self, JobDockerConfigError> {
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_dir(path, "creating job resource root")?;
            }
            Err(source) => return Err(io_error("reading job resource root", path, source)),
        }

        validate_private_directory(path)?;
        let canonical_path = fs::canonicalize(path)
            .map_err(|source| io_error("canonicalizing job resource root", path, source))?;
        let mut entries = fs::read_dir(&canonical_path)
            .map_err(|source| io_error("reading job resource root", &canonical_path, source))?;
        if entries
            .next()
            .transpose()
            .map_err(|source| io_error("reading job resource entry", &canonical_path, source))?
            .is_some()
        {
            return Err(JobDockerConfigError::StaleJobResources {
                path: canonical_path,
            });
        }

        Ok(Self { canonical_path })
    }

    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub fn create_docker_config(&self) -> Result<JobDockerConfig, JobDockerConfigError> {
        self.create_with_id(Uuid::new_v4())
    }

    fn create_with_id(&self, attempt_id: Uuid) -> Result<JobDockerConfig, JobDockerConfigError> {
        validate_private_directory(&self.canonical_path)?;
        let attempt_dir = self.canonical_path.join(attempt_id.simple().to_string());
        match create_private_dir(&attempt_dir, "creating job attempt directory") {
            Ok(()) => {}
            Err(JobDockerConfigError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                return Err(JobDockerConfigError::AttemptCollision { attempt_id });
            }
            Err(error) => return Err(error),
        }

        let config_dir = attempt_dir.join("docker");
        let config_file = config_dir.join("config.json");
        let creation = (|| {
            create_private_dir(&config_dir, "creating Docker config directory")?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&config_file)
                .map_err(|source| io_error("creating Docker config", &config_file, source))?;
            file.write_all(b"{}")
                .map_err(|source| io_error("writing Docker config", &config_file, source))?;
            file.sync_all()
                .map_err(|source| io_error("syncing Docker config", &config_file, source))?;
            fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).map_err(
                |source| io_error("setting Docker config permissions", &config_file, source),
            )?;
            Ok(())
        })();

        if let Err(create) = creation {
            return match fs::remove_dir_all(&attempt_dir) {
                Ok(()) => Err(create),
                Err(cleanup) => Err(JobDockerConfigError::CreationRollback {
                    path: attempt_dir,
                    create: Box::new(create),
                    cleanup,
                }),
            };
        }

        Ok(JobDockerConfig {
            root: self.canonical_path.clone(),
            attempt_id,
            attempt_dir,
            config_dir,
            config_file,
            cleaned: false,
        })
    }
}

impl JobDockerConfig {
    pub fn directory(&self) -> &Path {
        &self.config_dir
    }

    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    pub fn attempt_dir(&self) -> &Path {
        &self.attempt_dir
    }

    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }

    pub fn validate_override(
        &self,
        value: &str,
        source: &'static str,
    ) -> Result<(), JobDockerConfigError> {
        if value == self.directory().to_string_lossy() {
            return Ok(());
        }
        Err(JobDockerConfigError::ReservedEnvironmentOverride { source })
    }

    pub fn insert_into_host_env(
        &self,
        env: &mut HashMap<String, String>,
        source: &'static str,
    ) -> Result<(), JobDockerConfigError> {
        if let Some(existing) = env.get(DOCKER_CONFIG_ENV) {
            self.validate_override(existing, source)?;
        }
        env.insert(
            DOCKER_CONFIG_ENV.to_string(),
            self.directory().to_string_lossy().into_owned(),
        );
        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<(), JobDockerConfigError> {
        if self.cleaned {
            return Ok(());
        }

        match fs::symlink_metadata(&self.attempt_dir) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.cleaned = true;
                return Ok(());
            }
            Err(source) => {
                return Err(JobDockerConfigError::Cleanup {
                    path: self.attempt_dir.clone(),
                    source,
                });
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(JobDockerConfigError::UnsafeEntry {
                    path: self.attempt_dir.clone(),
                });
            }
            Ok(_) => {}
        }

        let canonical_root =
            fs::canonicalize(&self.root).map_err(|source| JobDockerConfigError::Cleanup {
                path: self.root.clone(),
                source,
            })?;
        let canonical_attempt = fs::canonicalize(&self.attempt_dir).map_err(|source| {
            JobDockerConfigError::Cleanup {
                path: self.attempt_dir.clone(),
                source,
            }
        })?;
        if self.attempt_dir.parent() != Some(self.root.as_path())
            || canonical_attempt.parent() != Some(canonical_root.as_path())
            || !canonical_attempt.starts_with(&canonical_root)
        {
            return Err(JobDockerConfigError::UnsafeEntry {
                path: self.attempt_dir.clone(),
            });
        }

        validate_removal_tree(&canonical_attempt)?;
        fs::remove_dir_all(&canonical_attempt).map_err(|source| JobDockerConfigError::Cleanup {
            path: canonical_attempt.clone(),
            source,
        })?;
        self.cleaned = true;
        Ok(())
    }
}

fn create_private_dir(path: &Path, operation: &'static str) -> Result<(), JobDockerConfigError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|source| io_error(operation, path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("setting private directory permissions", path, source))
}

fn validate_private_directory(path: &Path) -> Result<(), JobDockerConfigError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading directory metadata", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(JobDockerConfigError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "path is not a real directory",
        });
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(JobDockerConfigError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "directory is owned by another uid",
        });
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(JobDockerConfigError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "directory mode is not 0700",
        });
    }
    Ok(())
}

fn validate_removal_tree(path: &Path) -> Result<(), JobDockerConfigError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading cleanup metadata", path, source))?;
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(JobDockerConfigError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }
    if metadata.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|source| io_error("reading cleanup directory", path, source))?;
        for entry in entries {
            let entry = entry.map_err(|source| io_error("reading cleanup entry", path, source))?;
            validate_removal_tree(&entry.path())?;
        }
    }
    Ok(())
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> JobDockerConfigError {
    JobDockerConfigError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
#[path = "docker_config_test.rs"]
mod docker_config_test;
