use std::collections::HashMap;
use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use super::super::hardening::ChildPolicy;
use crate::job::execution_domain::protocol::OUTPUT_CHUNK_BYTES;
use crate::job::execution_domain::{
    CancelReason, CommandEvent, CommandOutcome, CommandSpec, CommandTarget, DomainEnvironment,
    ExecutionDomainError, FailureCategory, Stage,
};

pub(super) struct PreparedCommand {
    program: CString,
    args: Vec<CString>,
    pub(super) env: Vec<CString>,
    cwd: OwnedFd,
    pub(super) deadline: Instant,
}

impl PreparedCommand {
    pub(super) fn new(spec: CommandSpec) -> Result<Self, ExecutionDomainError> {
        let CommandTarget::Sandboxed { program, args, cwd } = spec.target else {
            return Err(failure(FailureCategory::InvalidInput));
        };
        if spec.state.is_some() {
            return Err(failure(FailureCategory::NotReady));
        }
        let deadline = Instant::now()
            .checked_add(spec.timeout)
            .filter(|_| !spec.timeout.is_zero())
            .ok_or_else(|| failure(FailureCategory::InvalidInput))?;
        let program = cstring(program.as_str())?;
        let executable = open_in_root(&program, false)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        checked(unsafe { libc::fstat(executable.as_raw_fd(), stat.as_mut_ptr()) })?;
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_mode & 0o111 == 0 {
            return Err(failure(FailureCategory::InvalidInput));
        }
        let cwd = open_in_root(&cstring(cwd.as_str())?, true)?;
        let args = std::iter::once(Ok(program.clone()))
            .chain(args.iter().map(|value| cstring(value)))
            .collect::<Result<_, _>>()?;
        let env = environment(spec.env)?;
        Ok(Self {
            program,
            args,
            env,
            cwd,
            deadline,
        })
    }

    pub(super) fn spawn(
        self,
        policy: &ChildPolicy,
        id: u64,
    ) -> Result<RunningCommand, ExecutionDomainError> {
        let (stdout, out_write) = pipe()?;
        let (stderr, err_write) = pipe()?;
        let null = checked(unsafe {
            libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        })?;
        let null = unsafe { OwnedFd::from_raw_fd(null) };
        let argv: Vec<_> = self
            .args
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let env: Vec<_> = self
            .env
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        // Init is single-threaded from bootstrap through this fork. No async runtime
        // or workflow-controlled instruction exists on the setup side of execve.
        let pid = checked(unsafe { libc::fork() })?;
        if pid == 0 {
            let setup = || -> Result<(), ExecutionDomainError> {
                checked(unsafe { libc::setpgid(0, 0) })?;
                checked(unsafe { libc::fchdir(self.cwd.as_raw_fd()) })?;
                for (source, target) in [
                    (null.as_raw_fd(), 0),
                    (out_write.as_raw_fd(), 1),
                    (err_write.as_raw_fd(), 2),
                ] {
                    checked(unsafe { libc::dup2(source, target) })?;
                }
                reset_signals()?;
                policy.apply_before_exec()?;
                unsafe { libc::execve(self.program.as_ptr(), argv.as_ptr(), env.as_ptr()) };
                Err(failure(FailureCategory::Io))
            };
            if setup().is_err() {
                let message = b"chimera: workflow child setup or exec failed\n";
                unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
            }
            unsafe { libc::_exit(126) };
        }
        let group = unsafe { libc::setpgid(pid, pid) };
        if group < 0
            && !matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EACCES | libc::ESRCH)
            )
        {
            // The child also establishes its group before exec. A failed parent
            // race closes the command; its namespace/cgroup remains manager-owned.
            signal(pid, false, libc::SIGKILL)?;
            return Err(failure(FailureCategory::Io));
        }
        Ok(RunningCommand {
            id,
            pid: Some(pid),
            group: pid,
            stdout: Some(stdout.into()),
            stderr: Some(stderr.into()),
            deadline: self.deadline,
            termination: None,
            reaped: None,
            drain_deadline: None,
        })
    }
}

fn environment(supplied: HashMap<String, String>) -> Result<Vec<CString>, ExecutionDomainError> {
    DomainEnvironment::sandboxed()
        .merge(&supplied, "command")?
        .into_iter()
        .map(|(key, value)| {
            if key.is_empty() || key.contains('=') {
                return Err(failure(FailureCategory::InvalidInput));
            }
            cstring(&format!("{key}={value}"))
        })
        .collect()
}

pub(super) struct RunningCommand {
    pub(super) id: u64,
    pub(super) pid: Option<i32>,
    group: i32,
    stdout: Option<std::fs::File>,
    stderr: Option<std::fs::File>,
    deadline: Instant,
    termination: Option<(CommandOutcome, Instant)>,
    reaped: Option<CommandOutcome>,
    drain_deadline: Option<Instant>,
}

impl RunningCommand {
    pub(super) fn cancel(&mut self, reason: CancelReason) -> Result<(), ExecutionDomainError> {
        if self.termination.is_none() {
            self.signal_live(libc::SIGTERM)?;
            let outcome = if reason == CancelReason::Timeout {
                CommandOutcome::TimedOut
            } else {
                CommandOutcome::Cancelled
            };
            self.termination = Some((outcome, Instant::now() + Duration::from_secs(5)));
        }
        Ok(())
    }

    pub(super) fn exited(&mut self, status: i32) {
        self.pid = None;
        self.reaped = Some(super::decode_wait_status(status));
        self.drain_deadline = Some(Instant::now() + Duration::from_secs(2));
    }

    pub(super) fn tick(&mut self) -> Result<Option<CommandOutcome>, ExecutionDomainError> {
        let now = Instant::now();
        if self.reaped.is_none() && now >= self.deadline {
            self.cancel(CancelReason::Timeout)?;
        }
        if let Some((_, deadline)) = &self.termination {
            if now >= *deadline {
                self.signal_live(libc::SIGKILL)?;
            } else if self.pid.is_some() || group_exists(self.group)? {
                return Ok(None);
            }
        }
        let Some(outcome) = &self.reaped else {
            return Ok(None);
        };
        if self.stdout.is_some() || self.stderr.is_some() {
            if self.drain_deadline.is_none_or(|deadline| now < deadline) {
                return Ok(None);
            }
            self.stdout = None;
            self.stderr = None;
        }
        Ok(Some(
            self.termination
                .as_ref()
                .map_or(outcome, |(cancelled, _)| cancelled)
                .clone(),
        ))
    }

    fn signal_live(&self, signal_number: i32) -> Result<(), ExecutionDomainError> {
        signal(self.group, true, signal_number)?;
        // A workflow may join another surviving group. Retain its direct PID
        // only until waitpid reaps it, so cancellation cannot miss that leader
        // or later target a reused PID.
        if let Some(pid) = self.pid {
            signal(pid, false, signal_number)?;
        }
        Ok(())
    }

    pub(super) fn output(
        &mut self,
        stderr: bool,
    ) -> Result<Option<CommandEvent>, ExecutionDomainError> {
        let pipe = if stderr {
            &mut self.stderr
        } else {
            &mut self.stdout
        };
        let Some(file) = pipe else {
            return Ok(None);
        };
        let mut bytes = vec![0; OUTPUT_CHUNK_BYTES];
        match file.read(&mut bytes) {
            Ok(0) => {
                *pipe = None;
                Ok(None)
            }
            Ok(n) => {
                bytes.truncate(n);
                Ok(Some(if stderr {
                    CommandEvent::Stderr(bytes)
                } else {
                    CommandEvent::Stdout(bytes)
                }))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(_) => Err(failure(FailureCategory::Io)),
        }
    }

    pub(super) fn poll_fds(&self) -> impl Iterator<Item = i32> + '_ {
        [&self.stdout, &self.stderr]
            .into_iter()
            .filter_map(|file| file.as_ref().map(AsRawFd::as_raw_fd))
    }
}

fn signal(pid: i32, group: bool, signal: i32) -> Result<(), ExecutionDomainError> {
    if unsafe { libc::kill(if group { -pid } else { pid }, signal) } < 0
        && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Err(failure(FailureCategory::Io));
    }
    Ok(())
}

fn group_exists(pid: i32) -> Result<bool, ExecutionDomainError> {
    if unsafe { libc::kill(-pid, 0) } == 0 {
        return Ok(true);
    }
    if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }
    Err(failure(FailureCategory::Io))
}

fn pipe() -> Result<(OwnedFd, OwnedFd), ExecutionDomainError> {
    let mut fds = [-1; 2];
    checked(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    checked(unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;
    Ok((read, write))
}

fn open_in_root(path: &CString, directory: bool) -> Result<OwnedFd, ExecutionDomainError> {
    #[repr(C)]
    struct How {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let root = checked(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    let root = unsafe { OwnedFd::from_raw_fd(root) };
    let how = How {
        flags: (libc::O_PATH | libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { 0 })
            as u64,
        mode: 0,
        resolve: 0x10 | 0x02,
    }; // IN_ROOT and NO_MAGICLINKS
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<How>(),
        )
    };
    if fd < 0 {
        return Err(failure(FailureCategory::Io));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn reset_signals() -> Result<(), ExecutionDomainError> {
    for signal in [
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGHUP,
        libc::SIGCHLD,
        libc::SIGPIPE,
    ] {
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = libc::SIG_DFL;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        checked(unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) })?;
    }
    let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe { libc::sigemptyset(&mut mask) };
    checked(unsafe { libc::sigprocmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()) })?;
    Ok(())
}

fn cstring(value: &str) -> Result<CString, ExecutionDomainError> {
    CString::new(value).map_err(|_| failure(FailureCategory::InvalidInput))
}
fn checked(value: i32) -> Result<i32, ExecutionDomainError> {
    if value < 0 {
        Err(failure(FailureCategory::Io))
    } else {
        Ok(value)
    }
}
fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Command,
        category,
        errno: io::Error::last_os_error().raw_os_error(),
    }
}

#[cfg(test)]
#[path = "init_command_test.rs"]
mod command_test;
