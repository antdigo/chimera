use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::super::protocol::{ControlConnection, Message, Request, Response, failure};
use super::super::{AttemptIdentity, ExecutionDomainError, FailureCategory};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn signal_received(signal: i32) {
    if signal != libc::SIGCHLD {
        SHUTDOWN.store(true, Ordering::Relaxed);
    }
}

pub(super) fn install_signal_handlers() -> Result<(), ExecutionDomainError> {
    SHUTDOWN.store(false, Ordering::Relaxed);
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD] {
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = signal_received as usize;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } < 0 {
            return Err(io_failure());
        }
    }
    Ok(())
}

pub(super) fn run(
    stream: UnixStream,
    attempt: AttemptIdentity,
) -> Result<(), ExecutionDomainError> {
    if unsafe { libc::getpid() } != 1 {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } < 0 {
        return Err(io_failure());
    }
    let mut connection = ControlConnection::new(stream, attempt)?;
    connection.interrupt_on(&SHUTDOWN);
    serve(connection, attempt)
}

pub(super) fn serve(
    mut connection: ControlConnection,
    attempt: AttemptIdentity,
) -> Result<(), ExecutionDomainError> {
    let deadline = Instant::now() + super::launcher::STARTUP_TIMEOUT;
    let Message::Request(Request::Bootstrap { spec }) = connection.receive(deadline)? else {
        return Err(failure(FailureCategory::NotReady));
    };
    if spec.attempt != attempt {
        return Err(failure(FailureCategory::IdentityMismatch));
    }
    if spec.hostname.is_empty()
        || spec.hostname.len() > 63
        || !spec
            .hostname
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(failure(FailureCategory::InvalidInput));
    }
    // Bootstrap only acknowledges transport and received records. No code can
    // issue KernelReady until Task 6 has produced a RootfsProof.
    let _bootstrap = spec;
    connection.send(Message::Response(Response::Bootstrapped), deadline)?;
    loop {
        reap_orphans()?;
        if SHUTDOWN.load(Ordering::Relaxed) {
            return Ok(());
        }
        let request = connection.receive(Instant::now() + super::launcher::STARTUP_TIMEOUT)?;
        let (response, finished) = match request {
            Message::Request(Request::Shutdown { .. }) => (Response::ShuttingDown, true),
            Message::Request(Request::Bootstrap { .. }) | Message::Response(_) => (
                Response::Rejected {
                    category: FailureCategory::Protocol,
                },
                false,
            ),
            Message::Request(_) => (
                Response::Rejected {
                    category: FailureCategory::NotReady,
                },
                false,
            ),
        };
        connection.send(
            Message::Response(response),
            Instant::now() + super::launcher::STARTUP_TIMEOUT,
        )?;
        if finished {
            return Ok(());
        }
    }
}

fn reap_orphans() -> Result<(), ExecutionDomainError> {
    loop {
        let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if result > 0 {
            continue;
        }
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(());
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(io_failure());
        }
    }
}

pub(super) fn wait_for_init(child: i32) -> Result<i32, ExecutionDomainError> {
    let mut termination = None;
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if result == child {
            return Ok(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            });
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io_failure());
        }
        if SHUTDOWN.load(Ordering::Relaxed) {
            let (signal, deadline) = match termination {
                None => (libc::SIGTERM, Some(Instant::now() + Duration::from_secs(5))),
                Some(deadline) if Instant::now() >= deadline => (libc::SIGKILL, Some(deadline)),
                _ => (0, termination),
            };
            if signal != 0
                && unsafe { libc::kill(child, signal) } < 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(io_failure());
            }
            termination = deadline;
        }
        let mut timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        unsafe { libc::nanosleep(&timeout, &mut timeout) };
    }
}

fn io_failure() -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: super::super::Stage::Launch,
        category: FailureCategory::Io,
        errno: io::Error::last_os_error().raw_os_error(),
    }
}
