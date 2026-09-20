use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::collections::VecDeque;
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::job::workspace::WorkspaceStatePaths;

use super::{
    CancelReason, CommandEvent, CommandOutcome, CommandSpec, CommandTarget, ExecutionDomainError,
    FailureCategory, Stage, StepFilesId, StepStateSnapshot, TrustedBackend,
};

const IMPLICIT_DOCKER_CREDENTIAL_HELPERS: [&str; 2] =
    ["docker-credential-pass", "docker-credential-secretservice"];
const STATE_FILE_LIMIT: usize = 1024 * 1024;

#[derive(Debug)]
struct BoundStateFile {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(super) struct TrustedStateStore {
    paths: WorkspaceStatePaths,
    env: BoundStateFile,
    path: BoundStateFile,
    output: BoundStateFile,
    state: BoundStateFile,
    summary: BoundStateFile,
    event: BoundStateFile,
}

impl TrustedStateStore {
    fn bind(paths: WorkspaceStatePaths) -> Result<Self, ExecutionDomainError> {
        Ok(Self {
            env: BoundStateFile::open(paths.env.clone())?,
            path: BoundStateFile::open(paths.path.clone())?,
            output: BoundStateFile::open(paths.output.clone())?,
            state: BoundStateFile::open(paths.state.clone())?,
            summary: BoundStateFile::open(paths.summary.clone())?,
            event: BoundStateFile::open(paths.event.clone())?,
            paths,
        })
    }

    fn prepare(&mut self, event: &[u8]) -> Result<(), ExecutionDomainError> {
        self.env.write_all_bounded(&[], STATE_FILE_LIMIT)?;
        self.path.write_all_bounded(&[], STATE_FILE_LIMIT)?;
        self.output.write_all_bounded(&[], STATE_FILE_LIMIT)?;
        self.state.write_all_bounded(&[], STATE_FILE_LIMIT)?;
        self.summary.write_all_bounded(&[], STATE_FILE_LIMIT)?;
        self.event.write_all_bounded(event, 4 * 1024 * 1024)
    }

    fn snapshot(&mut self) -> Result<StepStateSnapshot, ExecutionDomainError> {
        Ok(StepStateSnapshot {
            env: self.env.read_utf8(STATE_FILE_LIMIT)?,
            path: self.path.read_utf8(STATE_FILE_LIMIT)?,
            output: self.output.read_utf8(STATE_FILE_LIMIT)?,
            state: self.state.read_utf8(STATE_FILE_LIMIT)?,
            summary: self.summary.read_utf8(STATE_FILE_LIMIT)?,
        })
    }

    fn verify_all_named(&self) -> Result<(), ExecutionDomainError> {
        for file in [
            &self.env,
            &self.path,
            &self.output,
            &self.state,
            &self.summary,
            &self.event,
        ] {
            file.verify_named(usize::MAX)?;
        }
        Ok(())
    }
}

impl BoundStateFile {
    fn open(path: PathBuf) -> Result<Self, ExecutionDomainError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|error| io_failure(Stage::State, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| io_failure(Stage::State, error))?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        let state = Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            file,
        };
        state.verify_named(usize::MAX)?;
        Ok(state)
    }

    fn verify_named(&self, limit: usize) -> Result<std::fs::Metadata, ExecutionDomainError> {
        let named = std::fs::symlink_metadata(&self.path)
            .map_err(|error| io_failure(Stage::State, error))?;
        let bound = self
            .file
            .metadata()
            .map_err(|error| io_failure(Stage::State, error))?;
        if named.file_type().is_symlink()
            || !named.is_file()
            || !bound.is_file()
            || named.dev() != self.device
            || named.ino() != self.inode
            || bound.dev() != self.device
            || bound.ino() != self.inode
            || named.nlink() != 1
            || bound.nlink() != 1
            || named.len() > limit as u64
            || bound.len() > limit as u64
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(bound)
    }

    fn write_all_bounded(
        &mut self,
        bytes: &[u8],
        limit: usize,
    ) -> Result<(), ExecutionDomainError> {
        if bytes.len() > limit {
            return Err(failure(FailureCategory::InvalidInput));
        }
        self.verify_named(limit)?;
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.set_len(0))
            .and_then(|_| self.file.write_all(bytes))
            .and_then(|_| self.file.flush())
            .map_err(|error| io_failure(Stage::State, error))?;
        let metadata = self.verify_named(limit)?;
        if metadata.len() != bytes.len() as u64 {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        Ok(())
    }

    fn read_utf8(&mut self, limit: usize) -> Result<String, ExecutionDomainError> {
        let before = self.verify_named(limit)?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| io_failure(Stage::State, error))?;
        let mut bytes = Vec::with_capacity((before.len() as usize).min(limit));
        (&mut self.file)
            .take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| io_failure(Stage::State, error))?;
        let after = self.verify_named(limit)?;
        if bytes.len() > limit
            || bytes.len() as u64 != after.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        String::from_utf8(bytes).map_err(|_| failure(FailureCategory::InvalidInput))
    }
}

impl TrustedBackend {
    pub(super) fn bind_workspace(
        &mut self,
        paths: WorkspaceStatePaths,
    ) -> Result<(), ExecutionDomainError> {
        if self
            .workspace
            .as_ref()
            .is_some_and(|store| store.paths == paths)
        {
            return Ok(());
        }
        if self.workspace.is_some() {
            return Err(failure(FailureCategory::Unavailable));
        }
        self.workspace = Some(TrustedStateStore::bind(paths)?);
        Ok(())
    }

    pub(super) fn prepare_step(
        &mut self,
        event: &[u8],
    ) -> Result<StepFilesId, ExecutionDomainError> {
        if event.len() > 4 * 1024 * 1024 {
            return Err(failure(FailureCategory::InvalidInput));
        }
        let store = self
            .workspace
            .as_mut()
            .ok_or_else(|| failure(FailureCategory::NotReady))?;
        if self.prepared_step.is_some() {
            return Err(failure(FailureCategory::Unavailable));
        }
        store.prepare(event)?;
        let id = StepFilesId::new();
        self.prepared_step = Some(id.clone());
        Ok(id)
    }

    pub(super) fn read_step(
        &mut self,
        id: StepFilesId,
    ) -> Result<StepStateSnapshot, ExecutionDomainError> {
        if self.prepared_step.as_ref() != Some(&id) {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        self.prepared_step.take();
        let store = self
            .workspace
            .as_mut()
            .ok_or_else(|| failure(FailureCategory::NotReady))?;
        // Trusted mode has one foreground command. The manager correlates the
        // opaque id and never exposes these paths through it.
        let _ = id;
        store.snapshot()
    }

    pub(super) async fn run(
        &mut self,
        spec: CommandSpec,
        output: mpsc::Sender<CommandEvent>,
        cancelled: CancellationToken,
    ) -> Result<CommandOutcome, ExecutionDomainError> {
        let CommandTarget::Trusted { program, args, cwd } = spec.target else {
            return Err(failure(FailureCategory::InvalidInput));
        };
        let mut env = spec.env;
        if let Some(id) = spec.state {
            if self.prepared_step.as_ref() != Some(&id) {
                return Err(failure(FailureCategory::IdentityMismatch));
            }
            let store = self
                .workspace
                .as_ref()
                .ok_or_else(|| failure(FailureCategory::NotReady))?;
            store.verify_all_named()?;
            bind_state_environment(&mut env, &store.paths)?;
        }
        let validation_env = env.clone();
        let validation_cwd = cwd.clone();
        let private_tmp = self.private_tmp.clone();
        tokio::task::spawn_blocking(move || {
            validate_host_docker_capabilities(&validation_env, &validation_cwd, &private_tmp)
        })
        .await
        .map_err(|_| failure(FailureCategory::Io))??;

        let mut command = build_host_command(
            &program,
            &args,
            &env,
            &cwd,
            &self.docker_config_dir_env,
            &self.private_tmp,
        )?;
        let mut child = command
            .spawn()
            .map_err(|error| io_failure(Stage::Command, error))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| failure(FailureCategory::Io))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| failure(FailureCategory::Io))?;
        let receiver_closed = CancellationToken::new();
        let stdout_task = pump(stdout, output.clone(), true, receiver_closed.clone());
        let stderr_task = pump(stderr, output, false, receiver_closed.clone());

        let (outcome, drain_output) = tokio::select! {
            result = child.wait() => (status_outcome(result.map_err(|error| io_failure(Stage::Command, error))?), true),
            _ = cancelled.cancelled() => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                (CommandOutcome::Cancelled, false)
            }
            _ = receiver_closed.cancelled() => {
                let _reason = CancelReason::HandleDropped;
                let _ = child.kill().await;
                let _ = child.wait().await;
                (CommandOutcome::Cancelled, false)
            }
            _ = tokio::time::sleep(spec.timeout) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                (CommandOutcome::TimedOut, false)
            }
        };
        if !drain_output {
            // Descendants may retain inherited pipe descriptors after the
            // direct child is killed. Command cancellation must not become a
            // domain-level stall that prevents post actions.
            stdout_task.abort();
            stderr_task.abort();
        }
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        if let Some(store) = self.workspace.as_ref() {
            store.verify_all_named()?;
        }
        Ok(outcome)
    }
}

fn bind_state_environment(
    env: &mut HashMap<String, String>,
    paths: &WorkspaceStatePaths,
) -> Result<(), ExecutionDomainError> {
    for (key, path) in [
        ("GITHUB_ENV", &paths.env),
        ("GITHUB_PATH", &paths.path),
        ("GITHUB_OUTPUT", &paths.output),
        ("GITHUB_STATE", &paths.state),
        ("GITHUB_STEP_SUMMARY", &paths.summary),
        ("GITHUB_EVENT_PATH", &paths.event),
    ] {
        let value = path
            .to_str()
            .ok_or_else(|| failure(FailureCategory::InvalidInput))?
            .to_owned();
        env.insert(key.to_owned(), value);
    }
    Ok(())
}

fn pump<R>(
    mut reader: R,
    output: mpsc::Sender<CommandEvent>,
    stdout: bool,
    receiver_closed: CancellationToken,
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = vec![0; 32 * 1024];
        while let Ok(count) = reader.read(&mut buffer).await {
            if count == 0 {
                break;
            }
            let event = if stdout {
                CommandEvent::Stdout(buffer[..count].to_vec())
            } else {
                CommandEvent::Stderr(buffer[..count].to_vec())
            };
            if output.send(event).await.is_err() {
                receiver_closed.cancel();
                break;
            }
        }
    })
}

fn status_outcome(status: std::process::ExitStatus) -> CommandOutcome {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => CommandOutcome::Exited(code),
        (_, Some(signal)) => CommandOutcome::Signalled(signal),
        _ => CommandOutcome::Signalled(0),
    }
}

fn build_host_command(
    program: &OsStr,
    args: &[OsString],
    env: &HashMap<String, String>,
    working_dir: &Path,
    docker_config: &str,
    _private_tmp: &Path,
) -> Result<Command, ExecutionDomainError> {
    if env.get("DOCKER_CONFIG").map(String::as_str) != Some(docker_config) {
        return Err(ExecutionDomainError::ReservedEnvironmentOverride {
            source: "host spawn",
        });
    }
    let mut command = Command::new(program);
    command.args(args);
    #[cfg(target_os = "linux")]
    configure_private_tmp(&mut command, _private_tmp, working_dir)?;
    #[cfg(not(target_os = "linux"))]
    command.current_dir(working_dir);
    command
        .env_remove("DOCKER_CONFIG")
        .envs(env)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    Ok(command)
}

pub(crate) fn validate_host_docker_capabilities(
    env: &HashMap<String, String>,
    working_dir: &Path,
    private_tmp: &Path,
) -> Result<(), ExecutionDomainError> {
    let inherited = env
        .get("PATH")
        .is_none()
        .then(|| std::env::var_os("PATH"))
        .flatten();
    let Some(path) = env
        .get("PATH")
        .map(|value| OsStr::new(value.as_str()))
        .or(inherited.as_deref())
    else {
        return Ok(());
    };
    for helper in IMPLICIT_DOCKER_CREDENTIAL_HELPERS {
        for entry in std::env::split_paths(path) {
            let candidate = match credential_helper_path(&entry, helper, working_dir, private_tmp) {
                Ok(candidate) => candidate,
                Err(error) if capability_path_is_unavailable(&error) => continue,
                Err(error) => return Err(error),
            };
            let Ok(metadata) = std::fs::metadata(candidate) else {
                continue;
            };
            if !metadata.is_dir() && metadata.permissions().mode() & 0o111 != 0 {
                return Err(ExecutionDomainError::ImplicitCredentialStore { helper });
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn credential_helper_path(
    entry: &Path,
    helper: &str,
    cwd: &Path,
    private_tmp: &Path,
) -> Result<PathBuf, ExecutionDomainError> {
    let child_candidate = if entry.is_absolute() {
        entry.join(helper)
    } else {
        let resolved_cwd = resolve_child_path(cwd, private_tmp)?;
        resolved_cwd.join(entry).join(helper)
    };
    let resolved = resolve_child_path(&child_candidate, private_tmp)?;
    Ok(project_private_tmp_path(&resolved, private_tmp))
}

#[cfg(not(target_os = "linux"))]
fn credential_helper_path(
    entry: &Path,
    helper: &str,
    cwd: &Path,
    _private_tmp: &Path,
) -> Result<PathBuf, ExecutionDomainError> {
    let directory = if entry.as_os_str().is_empty() {
        cwd.to_path_buf()
    } else if entry.is_absolute() {
        entry.to_path_buf()
    } else {
        cwd.join(entry)
    };
    Ok(directory.join(helper))
}

#[cfg(target_os = "linux")]
fn capability_path_is_unavailable(error: &ExecutionDomainError) -> bool {
    matches!(
        error,
        ExecutionDomainError::Io { source, .. }
            if source.kind() == io::ErrorKind::PermissionDenied
                || source.raw_os_error() == Some(libc::ELOOP)
    )
}

#[cfg(not(target_os = "linux"))]
fn capability_path_is_unavailable(_error: &ExecutionDomainError) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn resolve_child_path(
    child_path: &Path,
    private_tmp: &Path,
) -> Result<PathBuf, ExecutionDomainError> {
    let absolute = if child_path.is_absolute() {
        child_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| ExecutionDomainError::Io {
                operation: "resolving host capability path",
                path: child_path.to_path_buf(),
                source,
            })?
            .join(child_path)
    };
    let mut pending = child_path_components(&absolute);
    let mut resolved = PathBuf::from("/");
    let mut symlink_hops = 0;

    while let Some(component) = pending.pop_front() {
        if component == OsStr::new("..") {
            resolved.pop();
            continue;
        }

        let child_candidate = resolved.join(&component);
        let host_candidate = project_private_tmp_path(&child_candidate, private_tmp);
        match std::fs::symlink_metadata(&host_candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                symlink_hops += 1;
                if symlink_hops > 40 {
                    return Err(ExecutionDomainError::Io {
                        operation: "resolving host capability symlink",
                        path: child_path.to_path_buf(),
                        source: io::Error::from_raw_os_error(libc::ELOOP),
                    });
                }
                let target = std::fs::read_link(&host_candidate).map_err(|source| {
                    ExecutionDomainError::Io {
                        operation: "reading host capability symlink",
                        path: host_candidate,
                        source,
                    }
                })?;
                let target = if target.is_absolute() {
                    target
                } else {
                    resolved.join(target)
                };
                let mut target_components = child_path_components(&target);
                target_components.append(&mut pending);
                pending = target_components;
                resolved = PathBuf::from("/");
            }
            Ok(_) => resolved.push(component),
            Err(source)
                if matches!(
                    source.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                resolved.push(component);
            }
            Err(source) => {
                return Err(ExecutionDomainError::Io {
                    operation: "resolving host capability path",
                    path: host_candidate,
                    source,
                });
            }
        }
    }

    Ok(resolved)
}

#[cfg(target_os = "linux")]
fn child_path_components(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir => Some(OsString::from("..")),
            Component::Normal(part) => Some(part.to_os_string()),
            Component::Prefix(_) => unreachable!("Unix paths do not have prefixes"),
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn project_private_tmp_path(child_path: &Path, private_tmp: &Path) -> PathBuf {
    match child_path.strip_prefix("/tmp") {
        Ok(relative) => private_tmp.join(relative),
        Err(_) => child_path.to_path_buf(),
    }
}

#[cfg(target_os = "linux")]
fn configure_private_tmp(
    command: &mut Command,
    private_tmp: &Path,
    working_dir: &Path,
) -> Result<(), ExecutionDomainError> {
    let source = CString::new(private_tmp.as_os_str().as_bytes())
        .map_err(|_| failure(FailureCategory::InvalidInput))?;
    let working_dir = CString::new(working_dir.as_os_str().as_bytes())
        .map_err(|_| failure(FailureCategory::InvalidInput))?;
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let uid_map = format!("{uid} {uid} 1\n").into_bytes();
    let gid_map = format!("{gid} {gid} 1\n").into_bytes();
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) == -1 {
                return Err(io::Error::last_os_error());
            }
            write_proc_file(c"/proc/self/setgroups", b"deny\n")?;
            write_proc_file(c"/proc/self/uid_map", &uid_map)?;
            write_proc_file(c"/proc/self/gid_map", &gid_map)?;
            if libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                (libc::MS_PRIVATE | libc::MS_REC) as libc::c_ulong,
                std::ptr::null(),
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if libc::mount(
                source.as_ptr(),
                c"/tmp".as_ptr(),
                std::ptr::null(),
                libc::MS_BIND as libc::c_ulong,
                std::ptr::null(),
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if libc::chdir(working_dir.as_ptr()) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn write_proc_file(path: &CStr, value: &[u8]) -> io::Result<()> {
    let file = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if file < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut written = 0;
    while written < value.len() {
        let count = unsafe {
            libc::write(
                file,
                value[written..].as_ptr().cast(),
                value.len() - written,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { libc::close(file) };
            return Err(error);
        }
        if count == 0 {
            unsafe { libc::close(file) };
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        written += count as usize;
    }
    if unsafe { libc::close(file) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Command,
        category,
        errno: None,
    }
}

fn io_failure(stage: Stage, error: io::Error) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage,
        category: FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}
