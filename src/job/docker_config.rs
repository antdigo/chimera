use std::collections::HashMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::watch;
use uuid::Uuid;

pub const DOCKER_CONFIG_ENV: &str = "DOCKER_CONFIG";

#[derive(Debug)]
pub enum JobDockerConfigError {
    StaleJobResources {
        path: PathBuf,
    },
    StaleLegacyJobData {
        path: PathBuf,
    },
    UnsafeRoot {
        path: PathBuf,
        reason: &'static str,
    },
    ChimeraRootUnderHostTmp {
        path: PathBuf,
    },
    PoisonedRoot {
        path: PathBuf,
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
    ImplicitCredentialStore {
        helper: &'static str,
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
            Self::StaleLegacyJobData { path } => write!(
                formatter,
                "stale-legacy-job-data: refusing jobs until the legacy path is recovered: {}",
                path.display()
            ),
            Self::UnsafeRoot { path, reason } => write!(
                formatter,
                "unsafe-job-resource-root: {reason}: {}",
                path.display()
            ),
            Self::ChimeraRootUnderHostTmp { path } => write!(
                formatter,
                "chimera-root-under-host-tmp: Linux host-job isolation hides /tmp; move the Chimera root outside /tmp: {}",
                path.display()
            ),
            Self::PoisonedRoot { path } => write!(
                formatter,
                "poisoned-job-resource-root: cleanup failed; refusing new jobs: {}",
                path.display()
            ),
            Self::AttemptCollision { attempt_id } => write!(
                formatter,
                "job-resource-collision: generated attempt id already exists: {attempt_id}"
            ),
            Self::UnsafeEntry { path } => write!(
                formatter,
                "unsafe-job-resource-path: refusing replaced, symlink, or special file: {}",
                path.display()
            ),
            Self::ReservedEnvironmentOverride { source } => write!(
                formatter,
                "reserved-environment-variable: DOCKER_CONFIG cannot be changed by {source}"
            ),
            Self::ImplicitCredentialStore { helper } => write!(
                formatter,
                "reserved-host-capability: implicit Docker credential helper {helper} is not supported in host step PATH"
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

/// A job completed and its completion was published, but the per-job Docker
/// config cleanup failed. Terminal for the runner: the resource root is no
/// longer trustworthy, so the daemon must stop instead of taking new jobs.
#[derive(Debug)]
pub struct JobResourceCleanupFatalError {
    pub source: JobDockerConfigError,
}

impl std::fmt::Display for JobResourceCleanupFatalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "job-resource-cleanup-fatal: completion published after cleanup failed: {}",
            self.source
        )
    }
}

impl std::error::Error for JobResourceCleanupFatalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct JobResourceState {
    operation_gate: Mutex<()>,
    poisoned: watch::Sender<bool>,
}

impl JobResourceState {
    fn new() -> Self {
        let (poisoned, _) = watch::channel(false);
        Self {
            operation_gate: Mutex::new(()),
            poisoned,
        }
    }

    fn lock<'a>(&'a self, path: &Path) -> Result<MutexGuard<'a, ()>, JobDockerConfigError> {
        self.operation_gate.lock().map_err(|_| {
            self.poison();
            JobDockerConfigError::PoisonedRoot {
                path: path.to_path_buf(),
            }
        })
    }

    fn ensure_healthy(&self, path: &Path) -> Result<(), JobDockerConfigError> {
        if *self.poisoned.borrow() {
            return Err(JobDockerConfigError::PoisonedRoot {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    fn poison(&self) {
        self.poisoned.send_replace(true);
    }
}

#[derive(Debug, Clone)]
pub struct JobResourceRoot {
    canonical_path: PathBuf,
    identity: DirectoryIdentity,
    state: Arc<JobResourceState>,
}

#[derive(Debug)]
pub struct JobDockerConfig {
    root: PathBuf,
    root_identity: DirectoryIdentity,
    state: Arc<JobResourceState>,
    attempt_id: Uuid,
    attempt_dir: PathBuf,
    attempt_identity: DirectoryIdentity,
    config_dir: PathBuf,
    config_dir_env: String,
    config_file: PathBuf,
    private_tmp: PathBuf,
    private_tmp_identity: DirectoryIdentity,
    work_dir: PathBuf,
    work_dir_identity: DirectoryIdentity,
    cleaned: bool,
}

impl JobResourceRoot {
    pub fn prepare(path: &Path) -> Result<Self, JobDockerConfigError> {
        // Reject before any mutation: creating the directory first would leave
        // behind a non-UTF-8 path that fails every later start until removed
        // by hand.
        utf8_path(path)?;
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
        utf8_path(&canonical_path)?;
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

        let identity = directory_identity(&canonical_path, "reading job resource root identity")?;
        Ok(Self {
            canonical_path,
            identity,
            state: Arc::new(JobResourceState::new()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub(crate) fn ensure_healthy(&self) -> Result<(), JobDockerConfigError> {
        self.state.ensure_healthy(&self.canonical_path)
    }

    pub(crate) fn poisoned_receiver(&self) -> watch::Receiver<bool> {
        self.state.poisoned.subscribe()
    }

    pub fn create_docker_config(&self) -> Result<JobDockerConfig, JobDockerConfigError> {
        self.create_with_id(Uuid::new_v4())
    }

    fn create_with_id(&self, attempt_id: Uuid) -> Result<JobDockerConfig, JobDockerConfigError> {
        let _operation = self.state.lock(&self.canonical_path)?;
        self.ensure_healthy()?;
        validate_bound_private_directory(&self.canonical_path, self.identity)?;
        let attempt_dir = self.canonical_path.join(attempt_id.simple().to_string());
        let config_dir = attempt_dir.join("docker");
        let private_tmp = attempt_dir.join("tmp");
        let work_dir = attempt_dir.join("work");
        let config_dir_env = utf8_path(&config_dir)?.to_owned();
        let config_file = config_dir.join("config.json");
        match create_private_dir(&attempt_dir, "creating job attempt directory") {
            Ok(()) => {}
            Err(JobDockerConfigError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                return Err(JobDockerConfigError::AttemptCollision { attempt_id });
            }
            Err(error) => return Err(error),
        }

        let creation = (|| {
            let attempt_identity =
                directory_identity(&attempt_dir, "reading job attempt directory identity")?;
            create_private_dir(&config_dir, "creating Docker config directory")?;
            create_private_dir(&private_tmp, "creating private job temp directory")?;
            let private_tmp_identity =
                directory_identity(&private_tmp, "reading private job temp identity")?;
            create_private_dir(&work_dir, "creating private job work directory")?;
            let work_dir_identity =
                directory_identity(&work_dir, "reading private job work identity")?;
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
            Ok((attempt_identity, private_tmp_identity, work_dir_identity))
        })();

        let (attempt_identity, private_tmp_identity, work_dir_identity) = match creation {
            Ok(identities) => identities,
            Err(create) => {
                return match fs::remove_dir_all(&attempt_dir) {
                    Ok(()) => Err(create),
                    Err(cleanup) => {
                        self.state.poison();
                        Err(JobDockerConfigError::CreationRollback {
                            path: attempt_dir,
                            create: Box::new(create),
                            cleanup,
                        })
                    }
                };
            }
        };

        Ok(JobDockerConfig {
            root: self.canonical_path.clone(),
            root_identity: self.identity,
            state: Arc::clone(&self.state),
            attempt_id,
            attempt_dir,
            attempt_identity,
            config_dir,
            config_dir_env,
            config_file,
            private_tmp,
            private_tmp_identity,
            work_dir,
            work_dir_identity,
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

    pub fn private_tmp(&self) -> &Path {
        &self.private_tmp
    }

    pub fn work_dir(&self) -> &Path {
        &self.work_dir
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
        if value == self.config_dir_env.as_str() {
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
        env.insert(DOCKER_CONFIG_ENV.to_string(), self.config_dir_env.clone());
        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<(), JobDockerConfigError> {
        self.cleanup_with_remover(|path| fs::remove_dir_all(path))
    }

    fn cleanup_with_remover<F>(&mut self, remove_attempt: F) -> Result<(), JobDockerConfigError>
    where
        F: FnOnce(&Path) -> io::Result<()>,
    {
        if self.cleaned {
            return Ok(());
        }

        let state = Arc::clone(&self.state);
        let _operation = state.lock(&self.root)?;
        let result = self.cleanup_locked(remove_attempt);
        if result.is_err() {
            state.poison();
        }
        result
    }

    fn cleanup_locked<F>(&mut self, remove_attempt: F) -> Result<(), JobDockerConfigError>
    where
        F: FnOnce(&Path) -> io::Result<()>,
    {
        let root_metadata =
            fs::symlink_metadata(&self.root).map_err(|source| JobDockerConfigError::Cleanup {
                path: self.root.clone(),
                source,
            })?;
        validate_bound_directory(&self.root, self.root_identity, &root_metadata)?;

        let attempt_metadata = match fs::symlink_metadata(&self.attempt_dir) {
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
            Ok(metadata) => metadata,
        };
        validate_bound_directory(&self.attempt_dir, self.attempt_identity, &attempt_metadata)?;

        if self.attempt_dir.parent() != Some(self.root.as_path()) {
            return Err(JobDockerConfigError::UnsafeEntry {
                path: self.attempt_dir.clone(),
            });
        }

        validate_attempt_removal_tree(
            &self.attempt_dir,
            &self.private_tmp,
            self.private_tmp_identity,
            &self.work_dir,
            self.work_dir_identity,
        )?;
        remove_attempt(&self.attempt_dir).map_err(|source| JobDockerConfigError::Cleanup {
            path: self.attempt_dir.clone(),
            source,
        })?;
        self.cleaned = true;
        Ok(())
    }
}

fn directory_identity(
    path: &Path,
    operation: &'static str,
) -> Result<DirectoryIdentity, JobDockerConfigError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error(operation, path, source))?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validate_bound_directory(
    path: &Path,
    expected_identity: DirectoryIdentity,
    metadata: &fs::Metadata,
) -> Result<(), JobDockerConfigError> {
    let actual_identity = DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || actual_identity != expected_identity
    {
        return Err(JobDockerConfigError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }

    let canonical = fs::canonicalize(path).map_err(|source| JobDockerConfigError::Cleanup {
        path: path.to_path_buf(),
        source,
    })?;
    if canonical != path {
        return Err(JobDockerConfigError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }
    Ok(())
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

fn validate_bound_private_directory(
    path: &Path,
    expected_identity: DirectoryIdentity,
) -> Result<(), JobDockerConfigError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading directory metadata", path, source))?;
    validate_private_directory_metadata(path, &metadata)?;
    validate_bound_directory(path, expected_identity, &metadata)
}

fn validate_private_directory(path: &Path) -> Result<(), JobDockerConfigError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading directory metadata", path, source))?;
    validate_private_directory_metadata(path, &metadata)
}

fn validate_private_directory_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), JobDockerConfigError> {
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

fn validate_attempt_removal_tree(
    attempt_dir: &Path,
    private_tmp: &Path,
    private_tmp_identity: DirectoryIdentity,
    work_dir: &Path,
    work_dir_identity: DirectoryIdentity,
) -> Result<(), JobDockerConfigError> {
    let entries = fs::read_dir(attempt_dir)
        .map_err(|source| io_error("reading cleanup directory", attempt_dir, source))?;
    for entry in entries {
        let entry =
            entry.map_err(|source| io_error("reading cleanup entry", attempt_dir, source))?;
        let path = entry.path();
        if path == private_tmp {
            prepare_owned_directory_for_removal(&path, private_tmp_identity)?;
        } else if path == work_dir {
            prepare_owned_directory_for_removal(&path, work_dir_identity)?;
        } else {
            validate_removal_tree(&path)?;
        }
    }
    Ok(())
}

fn prepare_owned_directory_for_removal(
    path: &Path,
    expected_identity: DirectoryIdentity,
) -> Result<(), JobDockerConfigError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading private cleanup metadata", path, source))?;
    validate_bound_directory(path, expected_identity, &metadata)?;
    prepare_owned_directory_tree_for_removal(path, &metadata)
}

fn prepare_owned_directory_tree_for_removal(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), JobDockerConfigError> {
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(JobDockerConfigError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("restoring cleanup directory permissions", path, source))?;

    let entries = fs::read_dir(path)
        .map_err(|source| io_error("reading private temp cleanup directory", path, source))?;
    for entry in entries {
        let entry =
            entry.map_err(|source| io_error("reading private temp cleanup entry", path, source))?;
        let child = entry.path();
        let child_metadata = fs::symlink_metadata(&child)
            .map_err(|source| io_error("reading private temp cleanup entry", &child, source))?;
        if child_metadata.is_dir() && !child_metadata.file_type().is_symlink() {
            prepare_owned_directory_tree_for_removal(&child, &child_metadata)?;
        }
    }
    Ok(())
}

fn utf8_path(path: &Path) -> Result<&str, JobDockerConfigError> {
    path.to_str()
        .ok_or_else(|| JobDockerConfigError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "path is not valid UTF-8",
        })
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
