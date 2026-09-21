use super::catalog::{CaseKey, Reason, ScenarioId, required_cases};
use super::report::{EvidenceMode, EvidenceProvenance, RunIdentity, valid_identity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const STDOUT_CAP: usize = 1024 * 1024;
const STDERR_CAP: usize = 64 * 1024;
const MAX_DEADLINE_MS: u64 = 300_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverHello {
    pub schema_version: u32,
    pub commit: String,
    pub binary_digest: String,
    pub backend: String,
    pub supported: Vec<ScenarioId>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverRequest {
    pub schema_version: u32,
    pub identity: RunIdentity,
    pub key: CaseKey,
    pub recipe: Recipe,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub operations: Vec<Operation>,
    pub deadline_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Operation {
    Preflight {
        missing: String,
    },
    Provision {
        attempt: uuid::Uuid,
        fail_after: Option<String>,
    },
    RunFixture {
        attempt: uuid::Uuid,
        fixture: String,
    },
    Cancel {
        attempt: uuid::Uuid,
        phase: String,
    },
    CrashSupervisor {
        phase: String,
    },
    Reconcile,
    Destroy {
        attempt: uuid::Uuid,
    },
    Observe,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub name: String,
    pub value: serde_json::Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverResponse {
    pub schema_version: u32,
    pub run_id: uuid::Uuid,
    pub commit: String,
    pub config_digest: String,
    pub host_boot_id: uuid::Uuid,
    pub driver_digest: String,
    pub key: CaseKey,
    pub observations: Vec<Observation>,
}
#[derive(Debug)]
pub struct AuthenticatedResponse {
    provenance: EvidenceProvenance,
    observations: Vec<Observation>,
}
impl AuthenticatedResponse {
    pub fn provenance(&self) -> &EvidenceProvenance {
        &self.provenance
    }
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn file_identity(file: &File) -> Result<FileIdentity, Reason> {
    let metadata = file.metadata().map_err(|_| Reason::ProtocolViolation)?;
    // SAFETY: geteuid takes no pointers and has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || ![0, uid].contains(&metadata.uid())
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o6000 != 0
        || metadata.len() > 256 * 1024 * 1024
    {
        return Err(Reason::ProtocolViolation);
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        size: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

fn hash(file: &File, size: u64, cancelled: Option<&AtomicBool>) -> Result<String, Reason> {
    let mut digest = Sha256::new();
    let mut offset = 0;
    let mut buffer = [0; 64 * 1024];
    while offset < size {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err(Reason::DeadlineExceeded);
        }
        let length = (size - offset).min(buffer.len() as u64) as usize;
        let count = file
            .read_at(&mut buffer[..length], offset)
            .map_err(|_| Reason::ProtocolViolation)?;
        if count == 0 {
            return Err(Reason::ProtocolViolation);
        }
        digest.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// The FD and digest are inseparable and private: callers cannot substitute a
/// path or supply the digest that authenticates a native response.
pub struct PinnedDriver {
    file: File,
    identity: FileIdentity,
    digest: String,
    fixture_path: Option<PathBuf>,
}
impl PinnedDriver {
    /// Native execution is supported only on Linux, through this retained FD.
    #[allow(dead_code)] // Consumed by the later native orchestrator.
    pub fn open(path: &Path) -> Result<Self, Reason> {
        if !cfg!(target_os = "linux") {
            return Err(Reason::PlatformUnsupported);
        }
        Self::pin(path, false)
    }

    /// Portable synthetic subprocesses have a separate, non-native path.
    #[cfg(test)]
    pub fn open_fixture(path: &Path) -> Result<Self, Reason> {
        Self::pin(path, true)
    }

    fn pin(path: &Path, fixture: bool) -> Result<Self, Reason> {
        if !path.is_absolute() {
            return Err(Reason::InvalidConfig);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| Reason::ProtocolViolation)?;
        let identity = file_identity(&file)?;
        let digest = hash(&file, identity.size, None)?;
        if file_identity(&file)? != identity {
            return Err(Reason::StaleEvidence);
        }
        Ok(Self {
            file,
            identity,
            digest,
            fixture_path: fixture.then(|| path.to_path_buf()),
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    async fn recheck(&self) -> Result<(), Reason> {
        // File reads and hashing must not prevent the async deadline from
        // firing. Cancellation stops the worker between bounded hash chunks.
        let worker = Self {
            file: self
                .file
                .try_clone()
                .map_err(|_| Reason::ProtocolViolation)?,
            identity: self.identity.clone(),
            digest: self.digest.clone(),
            fixture_path: self.fixture_path.clone(),
        };
        let cancel = CancelHash(Arc::new(AtomicBool::new(false)));
        let flag = cancel.0.clone();
        tokio::task::spawn_blocking(move || worker.recheck_sync(&flag))
            .await
            .map_err(|_| Reason::ProtocolViolation)?
    }

    fn recheck_sync(&self, cancelled: &AtomicBool) -> Result<(), Reason> {
        if file_identity(&self.file)? != self.identity
            || hash(&self.file, self.identity.size, Some(cancelled))? != self.digest
            || file_identity(&self.file)? != self.identity
        {
            return Err(Reason::StaleEvidence);
        }
        if let Some(path) = &self.fixture_path {
            let metadata = std::fs::symlink_metadata(path).map_err(|_| Reason::StaleEvidence)?;
            if !metadata.is_file()
                || metadata.dev() != self.identity.device
                || metadata.ino() != self.identity.inode
            {
                return Err(Reason::StaleEvidence);
            }
        }
        Ok(())
    }
}

struct CancelHash(Arc<AtomicBool>);
impl Drop for CancelHash {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

// A process group also bounds a driver's descendants, including descendants
// holding inherited stdout open. Kill the group on success, error or timeout.
struct ProcessGroup(u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.0 > 1 {
            unsafe {
                libc::kill(-(self.0 as i32), libc::SIGKILL);
            }
        }
    }
}

async fn bounded_read(mut stream: impl AsyncRead + Unpin, cap: usize) -> Result<Vec<u8>, Reason> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|_| Reason::ProtocolViolation)?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len() + count > cap {
            return Err(Reason::ProtocolViolation);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

async fn invoke(driver: &PinnedDriver, argument: &str, input: &[u8]) -> Result<Vec<u8>, Reason> {
    driver.recheck().await?;
    let executable = match &driver.fixture_path {
        Some(path) => path.clone(),
        None if cfg!(target_os = "linux") => {
            PathBuf::from(format!("/proc/self/fd/{}", driver.file.as_raw_fd()))
        }
        None => return Err(Reason::PlatformUnsupported),
    };
    let mut command = tokio::process::Command::new(executable);
    command
        .arg(argument)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    if driver.fixture_path.is_none() {
        let fd = driver.file.as_raw_fd();
        // SAFETY: only async-signal-safe fcntl is executed between fork/exec.
        // Clearing CLOEXEC in the child's FD table preserves the pinned file
        // for /proc/self/fd execution, including interpreter-backed drivers.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command.spawn().map_err(|_| Reason::ProtocolViolation)?;
    let _group = ProcessGroup(child.id().ok_or(Reason::ProtocolViolation)?);
    let mut stdin = child.stdin.take().ok_or(Reason::ProtocolViolation)?;
    let stdout = child.stdout.take().ok_or(Reason::ProtocolViolation)?;
    let stderr = child.stderr.take().ok_or(Reason::ProtocolViolation)?;
    let result = tokio::try_join!(
        async {
            stdin
                .write_all(input)
                .await
                .map_err(|_| Reason::ProtocolViolation)?;
            stdin
                .shutdown()
                .await
                .map_err(|_| Reason::ProtocolViolation)?;
            drop(stdin);
            Ok(())
        },
        bounded_read(stdout, STDOUT_CAP),
        bounded_read(stderr, STDERR_CAP),
        async {
            let status = child.wait().await.map_err(|_| Reason::ProtocolViolation)?;
            if status.success() {
                Ok(())
            } else {
                Err(Reason::ProtocolViolation)
            }
        },
    );
    match result {
        Ok(((), output, _stderr, ())) => {
            driver.recheck().await?;
            Ok(output)
        }
        Err(reason) => {
            let _ = child.kill().await;
            Err(reason)
        }
    }
}

pub async fn run_driver(
    driver: &PinnedDriver,
    request: &DriverRequest,
) -> Result<AuthenticatedResponse, Reason> {
    if request.schema_version != 1
        || !valid_identity(&request.identity)
        || !required_cases().contains(&request.key)
        || request.recipe.operations.is_empty()
        || request.recipe.operations.len() > 1024
        || !(1..=MAX_DEADLINE_MS).contains(&request.recipe.deadline_ms)
    {
        return Err(Reason::InvalidConfig);
    }
    if driver.fixture_path.is_some() && request.identity.mode != EvidenceMode::Fixture {
        return Err(Reason::PlatformUnsupported);
    }
    let input = serde_json::to_vec(request).map_err(|_| Reason::ProtocolViolation)?;
    if input.len() > STDOUT_CAP {
        return Err(Reason::InvalidConfig);
    }
    let exchange = async {
        let hello: DriverHello =
            serde_json::from_slice(&invoke(driver, "--qualification-hello=1", &[]).await?)
                .map_err(|_| Reason::ProtocolViolation)?;
        if hello.schema_version != 1
            || hello.binary_digest != driver.digest
            || hello.commit != request.identity.commit
            || hello.backend != "sandboxed"
            || !hello.supported.contains(&request.key.scenario)
            || hello.supported.iter().collect::<BTreeSet<_>>().len() != hello.supported.len()
        {
            return Err(Reason::ProtocolViolation);
        }
        let response: DriverResponse =
            serde_json::from_slice(&invoke(driver, "--qualification-protocol=1", &input).await?)
                .map_err(|_| Reason::ProtocolViolation)?;
        if response.schema_version != 1
            || response.run_id != request.identity.run_id
            || response.commit != request.identity.commit
            || response.config_digest != request.identity.config_digest
            || response.host_boot_id != request.identity.host_boot_id
            || response.driver_digest != driver.digest
            || response.key != request.key
            || response.observations.len() > 128
        {
            return Err(Reason::ProtocolViolation);
        }
        let mut names = BTreeSet::new();
        for observation in &response.observations {
            if observation.name.is_empty()
                || observation.name.len() > 64
                || !observation
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
                || !names.insert(&observation.name)
                || serde_json::to_vec(&observation.value)
                    .map_err(|_| Reason::ProtocolViolation)?
                    .len()
                    > STDERR_CAP
            {
                return Err(Reason::ProtocolViolation);
            }
        }
        Ok(AuthenticatedResponse {
            provenance: EvidenceProvenance {
                identity: request.identity.clone(),
                key: response.key,
                driver_commit: hello.commit,
                driver_digest: driver.digest.clone(),
            },
            observations: response.observations,
        })
    };
    tokio::time::timeout(Duration::from_millis(request.recipe.deadline_ms), exchange)
        .await
        .map_err(|_| Reason::DeadlineExceeded)?
}
