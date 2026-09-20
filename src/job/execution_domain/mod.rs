use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use uuid::Uuid;

mod admission;
mod error;
mod filesystem;
mod journal;

use journal::{DomainLifecycle, DomainState};

#[cfg(test)]
mod journal_test;

#[cfg(test)]
mod admission_test;

pub use admission::DomainPermit;
pub use error::{ExecutionDomainCleanupFatalError, ExecutionDomainError};

use filesystem::{
    DirectoryIdentity, create_private_dir, directory_identity, io_error, sync_bound_directory,
    utf8_path, validate_attempt_removal_tree, validate_bound_directory,
    validate_bound_private_directory, validate_private_directory,
};

pub const DOCKER_CONFIG_ENV: &str = "DOCKER_CONFIG";

#[derive(Debug)]
struct ExecutionDomainState {
    operation_gate: Mutex<()>,
    poisoned: watch::Sender<bool>,
}

impl ExecutionDomainState {
    fn new() -> Self {
        let (poisoned, _) = watch::channel(false);
        Self {
            operation_gate: Mutex::new(()),
            poisoned,
        }
    }

    fn lock<'a>(&'a self, path: &Path) -> Result<MutexGuard<'a, ()>, ExecutionDomainError> {
        self.operation_gate.lock().map_err(|_| {
            self.poison();
            ExecutionDomainError::PoisonedRoot {
                path: path.to_path_buf(),
            }
        })
    }

    fn ensure_healthy(&self, path: &Path) -> Result<(), ExecutionDomainError> {
        if *self.poisoned.borrow() {
            return Err(ExecutionDomainError::PoisonedRoot {
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
pub struct ExecutionDomainRoot {
    canonical_path: PathBuf,
    identity: DirectoryIdentity,
    state: Arc<ExecutionDomainState>,
    admission: Arc<Semaphore>,
}

#[derive(Debug)]
pub struct ExecutionDomain {
    root: PathBuf,
    root_identity: DirectoryIdentity,
    state: Arc<ExecutionDomainState>,
    attempt_id: Uuid,
    attempt_dir: PathBuf,
    attempt_identity: DirectoryIdentity,
    docker_config_dir: PathBuf,
    docker_config_dir_env: String,
    docker_config_file: PathBuf,
    private_tmp: PathBuf,
    private_tmp_identity: DirectoryIdentity,
    work_dir: PathBuf,
    work_dir_identity: DirectoryIdentity,
    destroyed: bool,
    lifecycle: DomainLifecycle,
    admission_permit: Option<OwnedSemaphorePermit>,
}

impl ExecutionDomainRoot {
    pub fn prepare(path: &Path, capacity: NonZeroUsize) -> Result<Self, ExecutionDomainError> {
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
        let stale_entries = entries.try_fold(0usize, |count, entry| {
            entry
                .map_err(|source| io_error("reading job resource entry", &canonical_path, source))
                .map(|_| count + 1)
        })?;
        if stale_entries != 0 {
            return Err(ExecutionDomainError::StaleJobResources {
                path: canonical_path,
                entries: stale_entries,
            });
        }

        let identity = directory_identity(&canonical_path, "reading job resource root identity")?;
        Ok(Self {
            canonical_path,
            identity,
            state: Arc::new(ExecutionDomainState::new()),
            admission: Arc::new(Semaphore::new(capacity.get())),
        })
    }

    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub(crate) fn ensure_healthy(&self) -> Result<(), ExecutionDomainError> {
        self.state.ensure_healthy(&self.canonical_path)
    }

    pub(crate) fn poisoned_receiver(&self) -> watch::Receiver<bool> {
        self.state.poisoned.subscribe()
    }

    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        self.state.poison();
    }

    fn create_domain_with_id(
        &self,
        attempt_id: Uuid,
    ) -> Result<ExecutionDomain, ExecutionDomainError> {
        self.create_with_id_and_sync(attempt_id, File::sync_all)
    }

    fn create_with_id_and_sync<F>(
        &self,
        attempt_id: Uuid,
        sync_root: F,
    ) -> Result<ExecutionDomain, ExecutionDomainError>
    where
        F: FnOnce(&File) -> io::Result<()>,
    {
        let _operation = self.state.lock(&self.canonical_path)?;
        self.ensure_healthy()?;
        validate_bound_private_directory(&self.canonical_path, self.identity)?;
        let attempt_dir = self.canonical_path.join(attempt_id.simple().to_string());
        let docker_config_dir = attempt_dir.join("docker");
        let private_tmp = attempt_dir.join("tmp");
        let work_dir = attempt_dir.join("work");
        let docker_config_dir_env = utf8_path(&docker_config_dir)?.to_owned();
        let docker_config_file = docker_config_dir.join("config.json");
        match create_private_dir(&attempt_dir, "creating job attempt directory") {
            Ok(()) => {}
            Err(ExecutionDomainError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                return Err(ExecutionDomainError::AttemptCollision { attempt_id });
            }
            Err(error) => return Err(error),
        }

        let creation = (|| {
            let attempt_identity =
                directory_identity(&attempt_dir, "reading job attempt directory identity")?;
            let mut lifecycle = DomainLifecycle::create(&attempt_dir, attempt_id)?;
            create_private_dir(&docker_config_dir, "creating Docker config directory")?;
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
                .open(&docker_config_file)
                .map_err(|source| {
                    io_error("creating Docker config", &docker_config_file, source)
                })?;
            file.write_all(b"{}")
                .map_err(|source| io_error("writing Docker config", &docker_config_file, source))?;
            file.sync_all()
                .map_err(|source| io_error("syncing Docker config", &docker_config_file, source))?;
            fs::set_permissions(&docker_config_file, fs::Permissions::from_mode(0o600)).map_err(
                |source| {
                    io_error(
                        "setting Docker config permissions",
                        &docker_config_file,
                        source,
                    )
                },
            )?;
            lifecycle.transition(DomainState::Ready)?;
            Ok((
                attempt_identity,
                private_tmp_identity,
                work_dir_identity,
                lifecycle,
            ))
        })();

        let (attempt_identity, private_tmp_identity, work_dir_identity, lifecycle) = match creation
        {
            Ok(identities) => identities,
            Err(create) => {
                return match fs::remove_dir_all(&attempt_dir) {
                    Ok(()) => Err(create),
                    Err(cleanup) => {
                        self.state.poison();
                        Err(ExecutionDomainError::CreationRollback {
                            path: attempt_dir,
                            create: Box::new(create),
                            cleanup,
                        })
                    }
                };
            }
        };

        // The Ready journal and attempt directory are synced before their parent entry.
        // If that barrier fails, retain the complete attempt for recovery rather
        // than removing through a root whose binding may have changed.
        sync_bound_directory(&self.canonical_path, self.identity, sync_root)
            .inspect_err(|_| self.state.poison())?;

        Ok(ExecutionDomain {
            root: self.canonical_path.clone(),
            root_identity: self.identity,
            state: Arc::clone(&self.state),
            attempt_id,
            attempt_dir,
            attempt_identity,
            docker_config_dir,
            docker_config_dir_env,
            docker_config_file,
            private_tmp,
            private_tmp_identity,
            work_dir,
            work_dir_identity,
            destroyed: false,
            lifecycle,
            admission_permit: None,
        })
    }
}

impl ExecutionDomain {
    pub(crate) fn mark_running(&mut self) -> Result<(), ExecutionDomainError> {
        self.lifecycle.transition(DomainState::Running)
    }

    pub(crate) fn mark_cleaning(&mut self) -> Result<(), ExecutionDomainError> {
        self.lifecycle.transition(DomainState::Cleaning)
    }

    pub fn docker_config_dir(&self) -> &Path {
        &self.docker_config_dir
    }

    pub fn config_file(&self) -> &Path {
        &self.docker_config_file
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
    ) -> Result<(), ExecutionDomainError> {
        if value == self.docker_config_dir_env.as_str() {
            return Ok(());
        }
        Err(ExecutionDomainError::ReservedEnvironmentOverride { source })
    }

    pub fn insert_into_host_env(
        &self,
        env: &mut HashMap<String, String>,
        source: &'static str,
    ) -> Result<(), ExecutionDomainError> {
        if let Some(existing) = env.get(DOCKER_CONFIG_ENV) {
            self.validate_override(existing, source)?;
        }
        env.insert(
            DOCKER_CONFIG_ENV.to_string(),
            self.docker_config_dir_env.clone(),
        );
        Ok(())
    }

    pub fn destroy(mut self) -> Result<(), ExecutionDomainError> {
        self.destroy_with_remover(|path| fs::remove_dir_all(path))
    }

    fn destroy_with_remover<F>(&mut self, remove_attempt: F) -> Result<(), ExecutionDomainError>
    where
        F: FnOnce(&Path) -> io::Result<()>,
    {
        self.destroy_with_remover_and_sync(remove_attempt, File::sync_all)
    }

    fn destroy_with_remover_and_sync<F, S>(
        &mut self,
        remove_attempt: F,
        sync_root: S,
    ) -> Result<(), ExecutionDomainError>
    where
        F: FnOnce(&Path) -> io::Result<()>,
        S: FnOnce(&File) -> io::Result<()>,
    {
        if self.destroyed {
            return Ok(());
        }

        let state = Arc::clone(&self.state);
        let _operation = state.lock(&self.root)?;
        let result = self.destroy_locked(remove_attempt, sync_root);
        if result.is_err() {
            state.poison();
        }
        match result {
            Err(cleanup) if self.lifecycle.state() == DomainState::Destroying => {
                match self.lifecycle.transition(DomainState::Quarantined) {
                    Ok(()) => Err(cleanup),
                    Err(quarantine) => Err(ExecutionDomainError::QuarantineFailed {
                        cleanup: Box::new(cleanup),
                        quarantine: Box::new(quarantine),
                    }),
                }
            }
            result => result,
        }
    }

    fn destroy_locked<F, S>(
        &mut self,
        remove_attempt: F,
        sync_root: S,
    ) -> Result<(), ExecutionDomainError>
    where
        F: FnOnce(&Path) -> io::Result<()>,
        S: FnOnce(&File) -> io::Result<()>,
    {
        let root_metadata =
            fs::symlink_metadata(&self.root).map_err(|source| ExecutionDomainError::Cleanup {
                path: self.root.clone(),
                source,
            })?;
        validate_bound_directory(&self.root, self.root_identity, &root_metadata)?;

        let attempt_metadata = match fs::symlink_metadata(&self.attempt_dir) {
            Err(source) => {
                return Err(ExecutionDomainError::Cleanup {
                    path: self.attempt_dir.clone(),
                    source,
                });
            }
            Ok(metadata) => metadata,
        };
        validate_bound_directory(&self.attempt_dir, self.attempt_identity, &attempt_metadata)?;

        if self.attempt_dir.parent() != Some(self.root.as_path()) {
            return Err(ExecutionDomainError::UnsafeEntry {
                path: self.attempt_dir.clone(),
            });
        }

        // Establish the bound paths before writing: replacements must never
        // receive a journal or have their existing contents changed.
        self.lifecycle.transition(DomainState::Destroying)?;

        validate_attempt_removal_tree(
            &self.attempt_dir,
            &self.private_tmp,
            self.private_tmp_identity,
            &self.work_dir,
            self.work_dir_identity,
        )?;
        remove_attempt(&self.attempt_dir).map_err(|source| ExecutionDomainError::Cleanup {
            path: self.attempt_dir.clone(),
            source,
        })?;
        sync_bound_directory(&self.root, self.root_identity, sync_root)?;
        self.lifecycle.complete_destroyed()?;
        self.destroyed = true;
        Ok(())
    }
}

impl Drop for ExecutionDomain {
    fn drop(&mut self) {
        if !self.destroyed {
            self.state.poison();
        }
    }
}

#[cfg(test)]
#[path = "../execution_domain_test.rs"]
mod execution_domain_test;
