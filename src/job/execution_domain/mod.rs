use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{Semaphore, watch};
use uuid::Uuid;

use crate::docker::endpoint::DockerEndpoint;

mod admission;
mod contracts;
mod docker_paths;
mod error;
mod filesystem;
mod journal;
#[cfg(any(target_os = "linux", test))]
mod linux;
mod manager;
#[cfg(any(target_os = "linux", test))]
mod protocol;
#[cfg(test)]
#[path = "protocol_test.rs"]
mod protocol_test;
mod state_bridge;
#[cfg(test)]
#[path = "state_bridge_test.rs"]
mod state_bridge_test;
mod trusted;
mod workspace_reader;

#[cfg(test)]
pub(crate) use trusted::validate_host_docker_capabilities;

/// Dispatch reserved bootstrap modes before constructing any async runtime.
pub fn internal_entry() -> Option<i32> {
    #[cfg(target_os = "linux")]
    {
        linux::launcher::internal_entry()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::args_os()
            .nth(1)
            .filter(|arg| arg == "--internal-domain-launch" || arg == "--internal-domain-bootstrap")
            .map(|_| 78)
    }
}

#[cfg(test)]
#[path = "contracts_test.rs"]
mod contracts_test;

use journal::{DomainLifecycle, DomainState};

#[cfg(test)]
mod journal_test;

#[cfg(test)]
mod admission_test;

pub use admission::DomainPermit;
pub use contracts::{
    AttemptIdentity, CancelReason, CommandEvent, CommandOutcome, CommandSpec, CommandTarget,
    DestroyReport, DomainEnvironment, DomainPath, DomainPaths, FailureCategory, Stage, StepFilesId,
    StepStateSnapshot,
};
pub use docker_paths::DockerPaths;
pub use error::{ExecutionDomainCleanupFatalError, ExecutionDomainError};
pub use state_bridge::ParsedStepState;
pub use workspace_reader::DomainWorkspaceReader;

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
    manager_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    #[cfg(test)]
    provision_pause: Arc<Mutex<Option<ProvisionPause>>>,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ProvisionPause {
    started: tokio::sync::oneshot::Sender<()>,
    proceed: tokio::sync::oneshot::Receiver<()>,
}

#[derive(Debug)]
pub(crate) struct TrustedBackend {
    root: PathBuf,
    root_identity: DirectoryIdentity,
    state: Arc<ExecutionDomainState>,
    #[cfg(test)]
    attempt_id: Uuid,
    attempt_dir: PathBuf,
    attempt_identity: DirectoryIdentity,
    docker_endpoint: DockerEndpoint,
    docker_paths: DockerPaths,
    docker_config_dir_env: String,
    docker_config_file: PathBuf,
    private_tmp: PathBuf,
    private_tmp_identity: DirectoryIdentity,
    work_dir: PathBuf,
    work_dir_identity: DirectoryIdentity,
    destroyed: bool,
    lifecycle: DomainLifecycle,
    workspace: Option<trusted::TrustedStateStore>,
    prepared_step: Option<StepFilesId>,
}

pub struct ExecutionDomain {
    request: Option<tokio::sync::mpsc::Sender<manager::ManagerRequest>>,
    state: Arc<ExecutionDomainState>,
    root: PathBuf,
    attempt_id: AttemptIdentity,
    docker_endpoint: DockerEndpoint,
    docker_paths: DockerPaths,
    docker_config_dir_env: String,
    docker_config_file: PathBuf,
    private_tmp: PathBuf,
    work_dir: PathBuf,
    attempt_dir: PathBuf,
    paths: DomainPaths,
    environment: DomainEnvironment,
    command_mapping: DomainCommandMapping,
    workspace_reader: DomainWorkspaceReader,
    explicit_destroy: bool,
}

#[derive(Clone)]
enum DomainCommandMapping {
    Trusted,
    #[cfg(target_os = "linux")]
    Sandboxed(Vec<(PathBuf, DomainPath)>),
}

impl DomainCommandMapping {
    #[cfg(target_os = "linux")]
    fn map_path(&self, path: &Path) -> Result<DomainPath, ExecutionDomainError> {
        match self {
            Self::Trusted => path
                .to_str()
                .ok_or(ExecutionDomainError::InvalidDomainPath)
                .and_then(DomainPath::parse),
            #[cfg(target_os = "linux")]
            Self::Sandboxed(mappings) => {
                let canonical = canonical_sandbox_path(path);
                let path = canonical.as_path();
                if mappings
                    .iter()
                    .any(|(_, target)| path.starts_with(target.as_str()))
                {
                    return path
                        .to_str()
                        .ok_or(ExecutionDomainError::InvalidDomainPath)
                        .and_then(DomainPath::parse);
                }
                let (source, mut target) = mappings
                    .iter()
                    .filter(|(source, _)| path.starts_with(source))
                    .max_by_key(|(source, _)| source.components().count())
                    .map(|(source, target)| (source, target.clone()))
                    .ok_or(ExecutionDomainError::InvalidDomainPath)?;
                let relative = path
                    .strip_prefix(source)
                    .map_err(|_| ExecutionDomainError::InvalidDomainPath)?;
                for component in relative.components() {
                    let std::path::Component::Normal(component) = component else {
                        return Err(ExecutionDomainError::InvalidDomainPath);
                    };
                    target = target.join(
                        component
                            .to_str()
                            .ok_or(ExecutionDomainError::InvalidDomainPath)?,
                    )?;
                }
                Ok(target)
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn executable_exists(&self, path: &DomainPath) -> bool {
        let Self::Sandboxed(mappings) = self else {
            return false;
        };
        let domain_path = Path::new(path.as_str());
        let Some((source, target)) = mappings
            .iter()
            .filter(|(_, target)| domain_path.starts_with(target.as_str()))
            .max_by_key(|(_, target)| Path::new(target.as_str()).components().count())
        else {
            return false;
        };
        let Ok(relative) = domain_path.strip_prefix(target.as_str()) else {
            return false;
        };
        let Ok(metadata) = fs::metadata(source.join(relative)) else {
            return false;
        };
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }

    fn target(
        &self,
        program: &OsStr,
        args: &[&OsStr],
        cwd: &Path,
        env: &HashMap<String, String>,
    ) -> Result<CommandTarget, ExecutionDomainError> {
        #[cfg(not(target_os = "linux"))]
        let _ = env;
        match self {
            Self::Trusted => Ok(CommandTarget::Trusted {
                program: program.to_os_string(),
                args: args.iter().map(|arg| (*arg).to_os_string()).collect(),
                cwd: cwd.to_path_buf(),
            }),
            #[cfg(target_os = "linux")]
            Self::Sandboxed(_) => {
                let program_path = Path::new(program);
                let program = if program_path.is_absolute() {
                    self.map_path(program_path)?
                } else {
                    let program = program
                        .to_str()
                        .ok_or(ExecutionDomainError::InvalidDomainPath)?;
                    env.get("PATH")
                        .into_iter()
                        .flat_map(|path| path.split(':'))
                        .filter(|path| !path.is_empty())
                        .filter_map(|directory| {
                            self.map_path(Path::new(directory).join(program).as_path())
                                .ok()
                        })
                        .find(|candidate| self.executable_exists(candidate))
                        .ok_or(ExecutionDomainError::InvalidDomainPath)?
                };
                let args = args
                    .iter()
                    .map(|arg| {
                        let value = arg
                            .to_str()
                            .ok_or(ExecutionDomainError::InvalidDomainPath)?;
                        let path = Path::new(arg);
                        if path.is_absolute() {
                            self.map_path(path).map(|path| path.as_str().to_owned())
                        } else {
                            Ok(value.to_owned())
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(CommandTarget::Sandboxed {
                    program,
                    args,
                    cwd: self.map_path(cwd)?,
                })
            }
        }
    }

    fn environment(
        &self,
        supplied: &HashMap<String, String>,
        owned: &DomainEnvironment,
    ) -> Result<HashMap<String, String>, ExecutionDomainError> {
        #[cfg(not(target_os = "linux"))]
        let _ = owned;
        match self {
            Self::Trusted => Ok(supplied.clone()),
            #[cfg(target_os = "linux")]
            Self::Sandboxed(_) => {
                let mut mapped = supplied.clone();
                for reserved in [
                    "GITHUB_ENV",
                    "GITHUB_PATH",
                    "GITHUB_OUTPUT",
                    "GITHUB_STATE",
                    "GITHUB_STEP_SUMMARY",
                    "GITHUB_EVENT_PATH",
                ] {
                    mapped.remove(reserved);
                }
                for key in [
                    "GITHUB_WORKSPACE",
                    "RUNNER_TEMP",
                    "RUNNER_TOOL_CACHE",
                    "GITHUB_ACTION_PATH",
                ] {
                    if let Some(value) = mapped.get(key).cloned() {
                        mapped.insert(
                            key.into(),
                            self.map_path(Path::new(&value))?.as_str().into(),
                        );
                    }
                }
                if let Some(path) = mapped.get("PATH").cloned() {
                    let mut seen = std::collections::HashSet::new();
                    let path = path
                        .split(':')
                        .filter(|part| !part.is_empty())
                        .filter_map(|part| self.map_path(Path::new(part)).ok())
                        .map(|part| part.as_str().to_owned())
                        .filter(|part| seen.insert(part.clone()))
                        .collect::<Vec<_>>()
                        .join(":");
                    mapped.insert("PATH".into(), path);
                }
                owned.merge(&mapped, "sandbox command")
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn canonical_sandbox_path(path: &Path) -> PathBuf {
    for (alias, canonical) in [("/bin", "/usr/bin"), ("/sbin", "/usr/sbin")] {
        if let Ok(relative) = path.strip_prefix(alias) {
            return Path::new(canonical).join(relative);
        }
    }
    path.to_path_buf()
}

impl std::fmt::Debug for ExecutionDomain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionDomain")
            .field("attempt_id", &self.attempt_id)
            .finish_non_exhaustive()
    }
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
            manager_tasks: Arc::new(Mutex::new(Vec::new())),
            #[cfg(test)]
            provision_pause: Arc::new(Mutex::new(None)),
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

    pub(crate) fn register_manager(&self, handle: tokio::task::JoinHandle<()>) {
        let mut handles = self
            .manager_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.retain(|handle| !handle.is_finished());
        handles.push(handle);
    }

    pub(crate) async fn drain_managers(&self) {
        let handles = {
            let mut handles = self
                .manager_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *handles)
        };
        for handle in handles {
            let _ = handle.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn pause_after_provision_for_test(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (proceed, proceed_rx) = tokio::sync::oneshot::channel();
        *self
            .provision_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ProvisionPause {
            started,
            proceed: proceed_rx,
        });
        (started_rx, proceed)
    }

    #[cfg(test)]
    pub(crate) fn take_provision_pause_for_test(&self) -> Option<ProvisionPause> {
        self.provision_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        self.state.poison();
    }

    fn create_domain_with_id(
        &self,
        attempt_id: Uuid,
    ) -> Result<TrustedBackend, ExecutionDomainError> {
        self.create_with_id_and_sync(attempt_id, File::sync_all)
    }

    fn create_with_id_and_sync<F>(
        &self,
        attempt_id: Uuid,
        sync_root: F,
    ) -> Result<TrustedBackend, ExecutionDomainError>
    where
        F: FnOnce(&File) -> io::Result<()>,
    {
        let _operation = self.state.lock(&self.canonical_path)?;
        self.ensure_healthy()?;
        validate_bound_private_directory(&self.canonical_path, self.identity)?;
        let docker_endpoint = DockerEndpoint::trusted_host();
        let attempt_dir = self.canonical_path.join(attempt_id.simple().to_string());
        let docker_paths = DockerPaths::for_attempt(&attempt_dir);
        let docker_config_dir = docker_paths.config_dir();
        let private_tmp = attempt_dir.join("tmp");
        let work_dir = attempt_dir.join("work");
        let docker_config_dir_env = utf8_path(docker_config_dir)?.to_owned();
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
            create_private_dir(docker_config_dir, "creating Docker config directory")?;
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

        Ok(TrustedBackend {
            root: self.canonical_path.clone(),
            root_identity: self.identity,
            state: Arc::clone(&self.state),
            #[cfg(test)]
            attempt_id,
            attempt_dir,
            attempt_identity,
            docker_endpoint,
            docker_paths,
            docker_config_dir_env,
            docker_config_file,
            private_tmp,
            private_tmp_identity,
            work_dir,
            work_dir_identity,
            destroyed: false,
            lifecycle,
            workspace: None,
            prepared_step: None,
        })
    }
}

impl TrustedBackend {
    pub(crate) fn mark_running(&mut self) -> Result<(), ExecutionDomainError> {
        self.lifecycle.transition(DomainState::Running)
    }

    pub(crate) fn mark_cleaning(&mut self) -> Result<(), ExecutionDomainError> {
        self.lifecycle.transition(DomainState::Cleaning)
    }

    #[cfg(test)]
    pub(crate) fn docker_config_dir(&self) -> &Path {
        self.docker_paths.config_dir()
    }
    #[cfg(test)]
    pub(crate) fn docker_endpoint(&self) -> &DockerEndpoint {
        &self.docker_endpoint
    }
    #[cfg(test)]
    pub(crate) fn docker_paths(&self) -> &DockerPaths {
        &self.docker_paths
    }
    #[cfg(test)]
    pub(crate) fn config_file(&self) -> &Path {
        &self.docker_config_file
    }
    #[cfg(test)]
    pub(crate) fn private_tmp(&self) -> &Path {
        &self.private_tmp
    }
    #[cfg(test)]
    pub(crate) fn work_dir(&self) -> &Path {
        &self.work_dir
    }
    #[cfg(test)]
    pub(crate) fn attempt_dir(&self) -> &Path {
        &self.attempt_dir
    }
    #[cfg(test)]
    pub(crate) fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    #[cfg(test)]
    pub(crate) fn validate_override(
        &self,
        value: &str,
        source: &'static str,
    ) -> Result<(), ExecutionDomainError> {
        if value == self.docker_config_dir_env {
            Ok(())
        } else {
            Err(ExecutionDomainError::ReservedEnvironmentOverride { source })
        }
    }
    #[cfg(test)]
    pub(crate) fn insert_into_host_env(
        &self,
        env: &mut HashMap<String, String>,
        source: &'static str,
    ) -> Result<(), ExecutionDomainError> {
        if let Some(existing) = env.get(DOCKER_CONFIG_ENV) {
            self.validate_override(existing, source)?;
        }
        env.insert(
            DOCKER_CONFIG_ENV.to_owned(),
            self.docker_config_dir_env.clone(),
        );
        Ok(())
    }

    #[cfg(test)]
    fn destroy(mut self) -> Result<(), ExecutionDomainError> {
        self.destroy_with_remover(|path| fs::remove_dir_all(path))
    }

    fn destroy_in_place(&mut self) -> Result<(), ExecutionDomainError> {
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

impl ExecutionDomain {
    fn sender(
        &self,
    ) -> Result<&tokio::sync::mpsc::Sender<manager::ManagerRequest>, ExecutionDomainError> {
        self.request
            .as_ref()
            .ok_or_else(|| ExecutionDomainError::AdmissionClosed {
                path: self.root.clone(),
            })
    }

    pub async fn bind_workspace(
        &self,
        workspace: &crate::job::workspace::Workspace,
    ) -> Result<(), ExecutionDomainError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.sender()?
            .send(manager::ManagerRequest::BindWorkspace {
                paths: workspace.state_paths(),
                work: workspace.workspace_dir().to_path_buf(),
                reply,
            })
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?;
        response
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?
    }

    pub(crate) async fn mark_running(&self) -> Result<(), ExecutionDomainError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.sender()?
            .send(manager::ManagerRequest::MarkRunning { reply })
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?;
        response
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?
    }

    pub(crate) async fn mark_cleaning(&self) -> Result<(), ExecutionDomainError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.sender()?
            .send(manager::ManagerRequest::MarkCleaning { reply })
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?;
        response
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?
    }

    pub async fn run(
        &self,
        spec: CommandSpec,
        output: tokio::sync::mpsc::Sender<CommandEvent>,
        cancelled: tokio_util::sync::CancellationToken,
    ) -> Result<CommandOutcome, ExecutionDomainError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.sender()?
            .send(manager::ManagerRequest::Run {
                spec,
                output,
                cancelled,
                reply,
            })
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?;
        response
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?
    }

    pub(crate) fn command_target(
        &self,
        program: &OsStr,
        args: &[&OsStr],
        cwd: &Path,
        env: &HashMap<String, String>,
    ) -> Result<CommandTarget, ExecutionDomainError> {
        self.command_mapping.target(program, args, cwd, env)
    }

    pub(crate) fn command_environment(
        &self,
        supplied: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>, ExecutionDomainError> {
        self.command_mapping
            .environment(supplied, &self.environment)
    }

    pub async fn prepare_step(&self, event: &[u8]) -> Result<StepFilesId, ExecutionDomainError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.sender()?
            .send(manager::ManagerRequest::PrepareStep {
                event: event.to_vec(),
                reply,
            })
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?;
        response
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?
    }

    pub async fn read_step(
        &self,
        id: StepFilesId,
    ) -> Result<StepStateSnapshot, ExecutionDomainError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.sender()?
            .send(manager::ManagerRequest::ReadStep { id, reply })
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?;
        response
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?
    }

    pub async fn cancel(&self, reason: CancelReason) -> Result<(), ExecutionDomainError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.sender()?
            .send(manager::ManagerRequest::Cancel { reason, reply })
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?;
        response
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?
    }

    #[cfg(test)]
    async fn panic_manager_for_test(&self) -> Result<(), ExecutionDomainError> {
        self.sender()?
            .send(manager::ManagerRequest::Panic)
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })
    }

    pub async fn destroy(mut self) -> Result<DestroyReport, ExecutionDomainError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let sender = self
            .request
            .take()
            .ok_or_else(|| ExecutionDomainError::AdmissionClosed {
                path: self.root.clone(),
            })?;
        self.explicit_destroy = true;
        sender
            .send(manager::ManagerRequest::Destroy { reply })
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?;
        drop(sender);
        response
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: self.root.clone(),
            })?
    }

    pub fn paths(&self) -> &DomainPaths {
        &self.paths
    }
    pub fn environment(&self) -> &DomainEnvironment {
        &self.environment
    }
    pub fn workspace_reader(&self) -> Option<DomainWorkspaceReader> {
        (self.paths == DomainPaths::sandboxed()).then(|| self.workspace_reader.clone())
    }
    pub fn docker_config_dir(&self) -> &Path {
        self.docker_paths.config_dir()
    }
    pub fn docker_endpoint(&self) -> &DockerEndpoint {
        &self.docker_endpoint
    }
    pub fn docker_paths(&self) -> &DockerPaths {
        &self.docker_paths
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
        self.attempt_id.uuid()
    }

    pub fn validate_override(
        &self,
        value: &str,
        source: &'static str,
    ) -> Result<(), ExecutionDomainError> {
        if value == self.docker_config_dir_env {
            Ok(())
        } else {
            Err(ExecutionDomainError::ReservedEnvironmentOverride { source })
        }
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
            DOCKER_CONFIG_ENV.to_owned(),
            self.docker_config_dir_env.clone(),
        );
        Ok(())
    }
}

impl Drop for ExecutionDomain {
    fn drop(&mut self) {
        if !self.explicit_destroy {
            self.state.poison();
            self.request.take();
        }
    }
}

impl Drop for TrustedBackend {
    fn drop(&mut self) {
        if !self.destroyed {
            self.state.poison();
        }
    }
}

#[cfg(test)]
#[path = "../execution_domain_test.rs"]
mod execution_domain_test;
