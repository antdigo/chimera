use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinSet;
use tracing::{Instrument, error, info, warn};

use crate::cache::manager::CacheManager;
use crate::cache::server as cache_server;
use crate::config::{
    ChimeraConfig, ChimeraPaths, ExecutionProfile, load_config, load_runner_credentials,
};
use crate::job::execution_domain::{
    ExecutionDomainCleanupFatalError, ExecutionDomainError, ExecutionDomainRoot,
};
use crate::runner::Runner;
use crate::storage::RootLock;
#[cfg(target_os = "linux")]
use crate::storage::RootLockProof;

// --- PID Lock ---

#[derive(Debug)]
pub struct PidLock {
    path: PathBuf,
    device: u64,
    inode: u64,
    _file: std::fs::File,
}

impl PidLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        Self::acquire_with_hooks(path, || {}, || {})
    }

    fn acquire_with_hooks<AfterOpen, AfterLock>(
        path: &Path,
        after_open: AfterOpen,
        after_lock: AfterLock,
    ) -> Result<Self>
    where
        AfterOpen: FnOnce(),
        AfterLock: FnOnce(),
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mut file = open_pid_lock_file(path)?;
        after_open();
        claim_pid_lock(&file, path)?;
        let metadata = file
            .metadata()
            .context("reading acquired PID lock metadata")?;
        verify_pid_lock_path(path, metadata.dev(), metadata.ino())?;
        after_lock();

        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("seeking PID file {}", path.display()))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .with_context(|| format!("reading PID file {}", path.display()))?;
        if !content.is_empty() {
            let pid: u32 = content
                .trim()
                .parse()
                .with_context(|| format!("parsing PID from {}", path.display()))?;
            if is_process_alive(pid) {
                bail!("chimera daemon already running (pid {pid}). Use 'chimera status' to check.");
            }
        }

        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting PID file permissions {}", path.display()))?;
        file.set_len(0)
            .with_context(|| format!("clearing PID file {}", path.display()))?;
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("seeking PID file {}", path.display()))?;
        write!(file, "{}", std::process::id())
            .with_context(|| format!("writing PID file {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing PID file {}", path.display()))?;

        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            _file: file,
        })
    }
}

fn open_pid_lock_file(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let nofollow_nonblocking = libc::O_NOFOLLOW | libc::O_NONBLOCK;
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nofollow_nonblocking)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)
                .with_context(|| format!("reading PID file metadata {}", path.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("unsafe PID lock path: {}", path.display());
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(nofollow_nonblocking)
                .open(path)
                .map_err(|error| {
                    if error.raw_os_error() == Some(libc::ELOOP) {
                        anyhow::anyhow!("unsafe PID lock path: {}", path.display())
                    } else {
                        error.into()
                    }
                })
                .with_context(|| format!("opening PID file {}", path.display()))?;
            let metadata = file
                .metadata()
                .with_context(|| format!("reading PID file metadata {}", path.display()))?;
            if !metadata.is_file() {
                bail!("unsafe PID lock path: {}", path.display());
            }
            Ok(file)
        }
        Err(error) => Err(error).with_context(|| format!("creating PID file {}", path.display())),
    }
}

fn claim_pid_lock(file: &std::fs::File, path: &Path) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(());
    }

    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        bail!("chimera daemon already running. Use 'chimera status' to check.");
    }
    Err(error).with_context(|| format!("claiming PID lock {}", path.display()))
}

fn verify_pid_lock_path(path: &Path, device: u64, inode: u64) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading PID lock metadata {}", path.display()))?;
    if metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.dev() == device
        && metadata.ino() == inode
    {
        return Ok(());
    }
    bail!("PID lock changed while held: {}", path.display());
}

fn remove_if_same_inode(path: &Path, device: u64, inode: u64) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("reading PID lock metadata {}", path.display()))
        }
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.dev() == device
                && metadata.ino() == inode =>
        {
            std::fs::remove_file(path)
                .with_context(|| format!("removing PID lock {}", path.display()))
        }
        Ok(_) => bail!("PID lock changed while held: {}", path.display()),
    }
}

impl Drop for PidLock {
    fn drop(&mut self) {
        if let Err(error) = remove_if_same_inode(&self.path, self.device, self.inode) {
            warn!(error = %error, path = %self.path.display(), "failed to release PID lock");
        }
    }
}

// --- Process liveness check ---

pub fn is_process_alive(pid: u32) -> bool {
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    // EPERM means the process exists but we lack permission to signal it
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn prepare_daemon_root(
    paths: &ChimeraPaths,
    capacity: NonZeroUsize,
) -> Result<(PidLock, ExecutionDomainRoot)> {
    #[cfg(target_os = "linux")]
    {
        let lexical_root = lexical_absolute_path(&paths.root)?;
        let canonical_root = std::fs::canonicalize(&paths.root)
            .with_context(|| format!("canonicalizing Chimera root {}", paths.root.display()))?;
        let canonical_host_tmp =
            std::fs::canonicalize("/tmp").context("canonicalizing host /tmp")?;
        if lexical_root.starts_with("/tmp") || canonical_root.starts_with(&canonical_host_tmp) {
            return Err(
                ExecutionDomainError::ChimeraRootUnderHostTmp { path: lexical_root }.into(),
            );
        }
    }
    reject_stale_legacy_job_data(paths)?;
    let pid_lock = PidLock::acquire(&paths.pid_file()).context("acquiring PID lock")?;
    let execution_domains = ExecutionDomainRoot::prepare(&paths.job_resources_dir(), capacity)?;
    Ok((pid_lock, execution_domains))
}

fn reject_stale_legacy_job_data(paths: &ChimeraPaths) -> Result<()> {
    for path in [paths.work_dir(), paths.tmp_dir()] {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading legacy job path {}", path.display()));
            }
        };

        let stale = if metadata.is_dir() && !metadata.file_type().is_symlink() {
            std::fs::read_dir(&path)
                .with_context(|| format!("reading legacy job path {}", path.display()))?
                .next()
                .transpose()
                .with_context(|| format!("reading legacy job entry in {}", path.display()))?
                .is_some()
        } else {
            true
        };

        if stale {
            return Err(ExecutionDomainError::StaleLegacyJobData { path }.into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn lexical_absolute_path(path: &Path) -> Result<PathBuf> {
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("reading current directory for Chimera root")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => normalized.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
        }
    }
    Ok(normalized)
}

// --- Runner state ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunnerPhase {
    Starting,
    Idle,
    Running,
    Stopping,
    Stopped,
}

impl std::fmt::Display for RunnerPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Starting => write!(f, "Starting"),
            Self::Idle => write!(f, "Idle"),
            Self::Running => write!(f, "Running"),
            Self::Stopping => write!(f, "Stopping"),
            Self::Stopped => write!(f, "Stopped"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub repo: String,
    pub job_id: String,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerStatus {
    pub phase: RunnerPhase,
    pub current_job: Option<JobInfo>,
    pub last_error: Option<String>,
    pub started_at: DateTime<Utc>,
    pub phase_changed_at: DateTime<Utc>,
}

pub struct DaemonState {
    runners: RwLock<HashMap<String, RunnerStatus>>,
    pid: u32,
    started_at: DateTime<Utc>,
}

impl DaemonState {
    pub fn new(runner_names: &[String]) -> Self {
        let now = Utc::now();
        let mut runners = HashMap::new();
        for name in runner_names {
            runners.insert(
                name.clone(),
                RunnerStatus {
                    phase: RunnerPhase::Starting,
                    current_job: None,
                    last_error: None,
                    started_at: now,
                    phase_changed_at: now,
                },
            );
        }
        Self {
            runners: RwLock::new(runners),
            pid: std::process::id(),
            started_at: now,
        }
    }

    pub async fn set_phase(&self, name: &str, phase: RunnerPhase) {
        let mut runners = self.runners.write().await;
        if let Some(status) = runners.get_mut(name) {
            status.phase = phase;
            status.phase_changed_at = Utc::now();
            if !matches!(status.phase, RunnerPhase::Running) {
                status.current_job = None;
            }
        }
    }

    pub async fn set_running(&self, name: &str, job: JobInfo) {
        let mut runners = self.runners.write().await;
        if let Some(status) = runners.get_mut(name) {
            status.phase = RunnerPhase::Running;
            status.current_job = Some(job);
            status.phase_changed_at = Utc::now();
        }
    }

    pub async fn set_error(&self, name: &str, error: String) {
        let mut runners = self.runners.write().await;
        if let Some(status) = runners.get_mut(name) {
            status.phase = RunnerPhase::Stopped;
            status.last_error = Some(error);
            status.current_job = None;
            status.phase_changed_at = Utc::now();
        }
    }

    pub async fn snapshot(&self) -> StateSnapshot {
        let runners = self.runners.read().await;
        StateSnapshot {
            pid: self.pid,
            started_at: self.started_at,
            runners: runners.clone(),
        }
    }
}

// --- State file ---

#[derive(Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub runners: HashMap<String, RunnerStatus>,
}

pub fn write_state_file(path: &Path, snapshot: &StateSnapshot) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(snapshot).context("serializing state")?;
    std::fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming to {}", path.display()))?;
    Ok(())
}

pub fn read_state_file(path: &Path) -> Result<StateSnapshot> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading state file {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing state file {}", path.display()))
}

fn is_fatal_job_resource_error(error: &anyhow::Error) -> bool {
    // anyhow's downcast_ref walks the error chain, so wrappers added along
    // the way do not hide the fatal marker.
    let poisoned = matches!(
        error.downcast_ref::<ExecutionDomainError>(),
        Some(ExecutionDomainError::PoisonedRoot { .. })
    );
    let cleanup_fatal = error
        .downcast_ref::<ExecutionDomainCleanupFatalError>()
        .is_some();
    poisoned || cleanup_fatal
}

fn validate_execution_profile(config: &ChimeraConfig) -> Result<()> {
    match config.execution.profile {
        ExecutionProfile::TrustedHost => Ok(()),
        ExecutionProfile::Sandboxed => {
            bail!("sandboxed execution profile is not available in this build")
        }
    }
}

// --- Daemon ---

pub struct Daemon {
    paths: ChimeraPaths,
    config: ChimeraConfig,
    _root_lock: RootLock,
    #[cfg(target_os = "linux")]
    _root_lock_proof: RootLockProof,
}

impl Daemon {
    pub fn load(mut paths: ChimeraPaths) -> Result<Self> {
        let root_lock = RootLock::acquire(&paths.root).map_err(|error| {
            let context = format!("acquiring root storage lock: {error}");
            anyhow::Error::new(error).context(context)
        })?;
        #[cfg(target_os = "linux")]
        let root_lock_proof = root_lock.reconciliation_proof().map_err(|error| {
            anyhow::Error::new(error).context("retaining root reconciliation proof")
        })?;
        #[cfg(target_os = "linux")]
        ExecutionDomainRoot::validate_reconciliation_proof(&root_lock_proof)
            .context("validating root reconciliation proof")?;
        paths.root = paths
            .root
            .canonicalize()
            .with_context(|| format!("canonicalizing daemon root {}", paths.root.display()))?;
        let config = load_config(&paths.config_file()).context("loading config")?;

        Ok(Self {
            paths,
            config,
            _root_lock: root_lock,
            #[cfg(target_os = "linux")]
            _root_lock_proof: root_lock_proof,
        })
    }

    pub fn config(&self) -> &ChimeraConfig {
        &self.config
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        validate_execution_profile(&self.config)?;

        // Trusted-host keeps one slot per runner identity. The configured
        // execution limit is reserved for sandboxed admission.
        let trusted_capacity = NonZeroUsize::new(self.config.runners.len().max(1)).unwrap();
        let (_pid_lock, execution_domains) = prepare_daemon_root(&self.paths, trusted_capacity)?;

        // Start cache server if configured
        let cache_config = self.config.cache.clone();
        let cache_manager = Arc::new(
            CacheManager::new(
                self.paths.cache_entries_dir(),
                self.paths.cache_data_dir(),
                self.paths.cache_tmp_dir(),
                cache_config.max_gb * 1024 * 1024 * 1024,
            )
            .await
            .context("initializing cache manager")?,
        );
        let cache_authority = Arc::new(crate::cache::auth::CacheAuthority::new());

        let cache_addr = cache_server::start(
            Arc::clone(&cache_manager),
            Arc::clone(&cache_authority),
            cache_config.cache_port,
        )
        .await
        .context("starting cache server")?;
        let cache_port = cache_addr.port();

        let state = Arc::new(DaemonState::new(&self.config.runners));
        let docker_action_builder = Arc::new(crate::docker::build::DockerActionBuilder::new());

        let mut join_set = JoinSet::new();
        let mut started = 0usize;

        for name in &self.config.runners {
            let creds = match load_runner_credentials(&self.paths.runners_dir(), name) {
                Ok(c) => c,
                Err(e) => {
                    error!(runner = %name, error = %e, "failed to load credentials, skipping");
                    state.set_error(name, format!("{e:#}")).await;
                    continue;
                }
            };

            let runner = Runner::with_state(
                name.clone(),
                creds,
                self.paths.clone(),
                Arc::clone(&state),
                execution_domains.clone(),
                cache_port,
                Arc::clone(&cache_authority),
                Arc::clone(&docker_action_builder),
            );

            let rx = shutdown_rx.clone();
            let runner_name = name.clone();
            let state_ref = Arc::clone(&state);

            join_set.spawn(
                async move {
                    let result = runner.start(rx).await;
                    if let Err(ref e) = result {
                        state_ref.set_error(&runner_name, format!("{e:#}")).await;
                    }
                    (runner_name, result)
                }
                .instrument(tracing::info_span!("runner", name = %name)),
            );

            started += 1;
        }

        if started == 0 {
            bail!("no runners could be started");
        }

        // Spawn state file writer
        let state_writer = Arc::clone(&state);
        let state_path = self.paths.state_file();
        let mut writer_shutdown_rx = shutdown_rx.clone();
        let writer_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {
                        let snapshot = state_writer.snapshot().await;
                        if let Err(e) = write_state_file(&state_path, &snapshot) {
                            warn!(error = %e, "failed to write state file");
                        }
                    }
                    _ = writer_shutdown_rx.changed() => break,
                }
            }
        });

        // Write initial state immediately
        let snapshot = state.snapshot().await;
        if let Err(e) = write_state_file(&self.paths.state_file(), &snapshot) {
            warn!(error = %e, "failed to write initial state file");
        }

        let shutdown_timeout = self.config.daemon.shutdown_timeout_secs;

        info!(runners = started, "daemon started");
        let mut fatal_error = None;

        // Wait for either: all runners exit or shutdown signal
        loop {
            tokio::select! {
                result = join_set.join_next() => {
                    match result {
                        Some(Ok((name, Ok(())))) => {
                            info!(runner = %name, "runner exited cleanly");
                        }
                        Some(Ok((name, Err(error)))) => {
                            let fatal = is_fatal_job_resource_error(&error);
                            error!(runner = %name, error = %error, "runner exited with error");
                            if fatal {
                                fatal_error = Some(error);
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            error!(error = %e, "runner task panicked");
                        }
                        None => {
                            info!("all runners exited");
                            break;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("shutdown signal received, waiting for runners to finish");
                    break;
                }
            }
        }

        // Drain remaining runners with timeout
        if !join_set.is_empty() {
            let timeout = Duration::from_secs(shutdown_timeout);
            let drain = async {
                while let Some(result) = join_set.join_next().await {
                    match result {
                        Ok((name, Ok(()))) => info!(runner = %name, "runner exited cleanly"),
                        Ok((name, Err(e))) => {
                            error!(runner = %name, error = %e, "runner exited with error")
                        }
                        Err(e) => error!(error = %e, "runner task panicked"),
                    }
                }
            };
            if tokio::time::timeout(timeout, drain).await.is_err() {
                warn!(
                    timeout_secs = shutdown_timeout,
                    "shutdown timeout exceeded, forcing exit"
                );
                join_set.abort_all();
            }
        }

        if tokio::time::timeout(
            Duration::from_secs(shutdown_timeout),
            execution_domains.drain_managers(),
        )
        .await
        .is_err()
        {
            warn!(
                timeout_secs = shutdown_timeout,
                "shutdown timeout exceeded while draining execution-domain managers"
            );
        }

        // Stop state writer
        writer_handle.abort();
        let _ = writer_handle.await;

        // Clean up state file
        let _ = std::fs::remove_file(self.paths.state_file());

        info!("daemon shut down");
        match fatal_error {
            Some(error) => Err(error.context("job resource cleanup made the daemon unhealthy")),
            None => Ok(()),
        }
    }
}

// --- Status display ---

pub fn format_status_display(snapshot: &StateSnapshot) -> String {
    let mut out = String::new();

    let uptime = Utc::now() - snapshot.started_at;
    out.push_str(&format!(
        "Daemon: running (pid {}, uptime {})\n",
        snapshot.pid,
        format_duration(uptime),
    ));
    out.push('\n');
    out.push_str("Runners:\n");

    let mut names: Vec<&String> = snapshot.runners.keys().collect();
    names.sort();

    for name in names {
        let status = &snapshot.runners[name];
        out.push_str(&format!("  {name}: {}\n", format_runner_line(status)));
    }

    out
}

pub fn format_runner_line(status: &RunnerStatus) -> String {
    match &status.phase {
        RunnerPhase::Running => {
            if let Some(ref job) = status.current_job {
                let elapsed = Utc::now() - job.started_at;
                format!("Running job {} ({})", job.repo, format_duration(elapsed))
            } else {
                "Running".to_string()
            }
        }
        RunnerPhase::Idle => {
            let idle_dur = Utc::now() - status.phase_changed_at;
            format!("Idle ({})", format_duration(idle_dur))
        }
        RunnerPhase::Stopped => {
            if let Some(ref err) = status.last_error {
                format!("Stopped — error: {err}")
            } else {
                "Stopped".to_string()
            }
        }
        phase => phase.to_string(),
    }
}

pub fn format_duration(d: chrono::Duration) -> String {
    let secs = d.num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[cfg(test)]
#[path = "daemon_test.rs"]
mod daemon_test;
