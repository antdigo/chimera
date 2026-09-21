use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::super::protocol::{
    CancelDisposition, ControlConnection, EventAssembler, Message, OutboundQueue, Request,
    Response, failure, snapshot_chunks,
};
use super::super::{
    AttemptIdentity, CancelReason, CommandSpec, ExecutionDomainError, FailureCategory, StepFilesId,
};
use super::hardening::{ChildPolicy, retain_init_capabilities};
use super::step_files::StepFiles;
#[path = "init_command.rs"]
mod command;
use command::{PreparedCommand, RunningCommand};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub(super) fn decode_wait_status(status: i32) -> super::super::CommandOutcome {
    if libc::WIFEXITED(status) {
        super::super::CommandOutcome::Exited(libc::WEXITSTATUS(status))
    } else {
        super::super::CommandOutcome::Signalled(libc::WTERMSIG(status))
    }
}

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
    // A transport acknowledgement is deliberately distinct from kernel readiness.
    let mut bootstrap = Some(spec);
    connection.send(Message::Response(Response::Bootstrapped), deadline)?;
    loop {
        reap_orphans()?;
        if SHUTDOWN.load(Ordering::Relaxed) {
            return Ok(());
        }
        let request = connection.receive(Instant::now() + super::launcher::STARTUP_TIMEOUT)?;
        let (response, finished) = match request {
            Message::Request(Request::Hello) => {
                if let Some(spec) = bootstrap.take() {
                    match super::rootfs::assemble_and_pivot(
                        &spec.rootfs,
                        connection.control_fd(),
                        &spec.hostname,
                    ) {
                        Ok(proof) => {
                            let policy = ChildPolicy::workflow(&proof)?;
                            let steps = StepFiles::create(std::path::Path::new("/run/chimera"))?;
                            retain_init_capabilities()?;
                            connection.send(
                                Message::Response(Response::KernelReady),
                                Instant::now() + super::launcher::STARTUP_TIMEOUT,
                            )?;
                            return InitRuntime {
                                connection,
                                policy,
                                active: None,
                                ephemeral_step: None,
                                outbound: OutboundQueue::new(),
                                sending: false,
                                connected: true,
                                stopping: false,
                                write_deadline: None,
                                terminal_error: None,
                                last_command_id: 0,
                                steps,
                                event: None,
                                snapshot: Default::default(),
                            }
                            .run();
                        }
                        Err(_) => {
                            connection.send(
                                Message::Response(Response::Rejected {
                                    category: FailureCategory::NotReady,
                                }),
                                Instant::now() + super::launcher::STARTUP_TIMEOUT,
                            )?;
                            // No retry after a partial assembly. Shutdown is still
                            // usable until the supervisor reclaims this domain.
                            continue;
                        }
                    }
                }
                (
                    Response::Rejected {
                        category: FailureCategory::NotReady,
                    },
                    false,
                )
            }
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

struct InitRuntime {
    connection: ControlConnection,
    policy: ChildPolicy,
    active: Option<RunningCommand>,
    ephemeral_step: Option<StepFilesId>,
    outbound: OutboundQueue,
    sending: bool,
    connected: bool,
    stopping: bool,
    write_deadline: Option<Instant>,
    terminal_error: Option<ExecutionDomainError>,
    last_command_id: u64,
    steps: StepFiles,
    event: Option<EventAssembler>,
    snapshot: std::collections::VecDeque<Response>,
}

impl InitRuntime {
    fn run(mut self) -> Result<(), ExecutionDomainError> {
        loop {
            self.reap()?;
            if SHUTDOWN.load(Ordering::Relaxed) && !self.stopping {
                self.stopping = true;
                self.cancel_active(CancelReason::Shutdown)?;
            }
            if self.connected {
                match self.connection.try_receive() {
                    Ok(Some(message)) => {
                        if let Err(error) = self.request(message) {
                            self.disconnect(error)?;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => self.disconnect(error)?,
                }
            }
            self.output()?;
            if let Some(command) = &mut self.active
                && let Some(outcome) = command.tick()?
            {
                let command_id = command.id;
                self.active = None;
                self.discard_ephemeral_step();
                if self.connected {
                    self.enqueue(Response::CommandFinished {
                        command_id,
                        outcome,
                    })?;
                }
            }
            if self.connected
                && let Err(error) = self.flush()
            {
                self.disconnect(error)?;
            }
            if self.stopping && self.active.is_none() && (!self.connected || !self.sending) {
                return self.terminal_error.map_or(Ok(()), Err);
            }
            self.poll()?;
        }
    }

    fn request(&mut self, message: Message) -> Result<(), ExecutionDomainError> {
        match message {
            Message::Request(Request::Run { command_id, spec }) if !self.stopping => {
                self.run_command(command_id, spec)
            }
            Message::Request(Request::CancelCommand { command_id, reason }) => {
                self.cancel_command(command_id, reason)
            }
            Message::Request(Request::Hello) => self.enqueue(Response::KernelReady),
            Message::Request(Request::Shutdown { .. }) => {
                self.stopping = true;
                self.cancel_active(CancelReason::Shutdown)?;
                self.enqueue(Response::ShuttingDown)
            }
            Message::Request(
                request @ (Request::PrepareStep { .. }
                | Request::PrepareStepChunk { .. }
                | Request::ReadStep { .. }),
            ) => self.state_request(request),
            _ => self.reject(FailureCategory::Protocol),
        }
    }

    fn run_command(&mut self, id: u64, mut spec: CommandSpec) -> Result<(), ExecutionDomainError> {
        if self.active.is_some() || self.event.is_some() || !self.snapshot.is_empty() {
            return self.reject_command(id, FailureCategory::Unavailable);
        }
        if id == 0 || id <= self.last_command_id {
            return self.reject_command(id, FailureCategory::Protocol);
        }
        if spec.state.is_none() {
            let step = StepFilesId::new();
            if self.steps.prepare(step.clone(), b"{}").is_err() {
                return self.reject_command(id, FailureCategory::InvalidInput);
            }
            spec.state = Some(step);
            self.ephemeral_step = spec.state.clone();
        }
        let prepared = match PreparedCommand::with_state(spec, &self.steps) {
            Ok(prepared) => prepared,
            Err(_) => {
                self.discard_ephemeral_step();
                return self.reject_command(id, FailureCategory::InvalidInput);
            }
        };
        let command = match prepared.spawn(&self.policy, id) {
            Ok(command) => command,
            Err(_) => {
                self.discard_ephemeral_step();
                return self.reject_command(id, FailureCategory::Unavailable);
            }
        };
        self.last_command_id = id;
        self.active = Some(command);
        self.enqueue(Response::CommandStarted { command_id: id })
    }

    fn cancel_command(
        &mut self,
        id: u64,
        reason: CancelReason,
    ) -> Result<(), ExecutionDomainError> {
        let disposition = match &mut self.active {
            Some(command) if command.id == id => {
                command.cancel(reason)?;
                CancelDisposition::Applied
            }
            _ => CancelDisposition::NotRunning,
        };
        self.enqueue(Response::CommandCancelAcknowledged {
            command_id: id,
            disposition,
        })
    }

    fn discard_ephemeral_step(&mut self) {
        if let Some(id) = self.ephemeral_step.take() {
            self.steps.discard(&id);
        }
    }

    fn state_request(&mut self, request: Request) -> Result<(), ExecutionDomainError> {
        if self.stopping || self.active.is_some() || !self.snapshot.is_empty() {
            return self.reject(FailureCategory::Unavailable);
        }
        match request {
            Request::PrepareStep { id, event } if self.event.is_none() => {
                if self.steps.prepare(id.clone(), &event).is_err() {
                    return self.reject(FailureCategory::InvalidInput);
                }
                self.enqueue(Response::StepPrepared { id })
            }
            request @ Request::PrepareStepChunk { .. } => {
                let Request::PrepareStepChunk { id, .. } = &request else {
                    unreachable!()
                };
                let id = id.clone();
                let assembler = self.event.get_or_insert_with(|| {
                    EventAssembler::new(self.connection.last_request_id(), id.clone())
                });
                match assembler.push(request) {
                    Ok(Some(event)) => {
                        self.event = None;
                        if self.steps.prepare(id.clone(), &event).is_err() {
                            return self.reject(FailureCategory::InvalidInput);
                        }
                        self.enqueue(Response::StepPrepared { id })
                    }
                    Ok(None) => Ok(()),
                    Err(error) => Err(error),
                }
            }
            Request::ReadStep { id } if self.event.is_none() => {
                let snapshot = match self.steps.read(&id) {
                    Ok(snapshot) => snapshot,
                    Err(_) => return self.reject(FailureCategory::InvalidInput),
                };
                self.snapshot =
                    snapshot_chunks(self.connection.last_request_id(), &id, &snapshot)?.into();
                Ok(())
            }
            _ => self.reject(FailureCategory::Protocol),
        }
    }

    fn cancel_active(&mut self, reason: CancelReason) -> Result<(), ExecutionDomainError> {
        if let Some(command) = &mut self.active {
            command.cancel(reason)?;
        }
        Ok(())
    }

    fn disconnect(&mut self, error: ExecutionDomainError) -> Result<(), ExecutionDomainError> {
        self.connected = false;
        self.stopping = true;
        self.outbound = OutboundQueue::new();
        self.snapshot.clear();
        self.event = None;
        self.terminal_error = Some(error);
        self.cancel_active(CancelReason::HandleDropped)
    }

    fn reject(&mut self, category: FailureCategory) -> Result<(), ExecutionDomainError> {
        self.enqueue(Response::Rejected { category })
    }
    fn reject_command(
        &mut self,
        command_id: u64,
        category: FailureCategory,
    ) -> Result<(), ExecutionDomainError> {
        self.enqueue(Response::CommandRejected {
            command_id,
            category,
        })
    }
    fn enqueue(&mut self, response: Response) -> Result<(), ExecutionDomainError> {
        self.outbound.push(Message::Response(response))
    }

    fn output(&mut self) -> Result<(), ExecutionDomainError> {
        if self.connected
            && self.outbound.has_capacity()
            && let Some(chunk) = self.snapshot.pop_front()
        {
            self.enqueue(chunk)?;
        }
        for stderr in [false, true] {
            if self.connected && !self.outbound.has_capacity() {
                break;
            }
            if let Some(command) = &mut self.active
                && let Some(event) = command.output(stderr)?
            {
                let command_id = command.id;
                if self.connected {
                    self.enqueue(Response::Output { command_id, event })?;
                }
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ExecutionDomainError> {
        if self.sending && self.connection.try_flush()? {
            self.sending = false;
            self.write_deadline = None;
        }
        if !self.sending
            && let Some(message) = self.outbound.pop()
        {
            self.connection.start_send(message)?;
            self.sending = true;
            self.write_deadline = Some(Instant::now() + Duration::from_secs(30));
        }
        if self
            .write_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(failure(FailureCategory::Timeout));
        }
        Ok(())
    }

    fn reap(&mut self) -> Result<(), ExecutionDomainError> {
        // A continuous fork/exit workload must not starve cancellation or pipes.
        for _ in 0..128 {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid > 0 {
                if let Some(command) = &mut self.active
                    && command.pid == Some(pid)
                {
                    command.exited(status);
                }
                continue;
            }
            if pid == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                return Ok(());
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io_failure());
            }
        }
        Ok(())
    }

    fn poll(&self) -> Result<(), ExecutionDomainError> {
        let mut fds = Vec::with_capacity(3);
        if self.connected {
            fds.push(libc::pollfd {
                fd: self.connection.control_fd().as_raw_fd(),
                events: libc::POLLIN | if self.sending { libc::POLLOUT } else { 0 },
                revents: 0,
            });
        }
        if (!self.connected || self.outbound.has_capacity())
            && let Some(command) = &self.active
        {
            fds.extend(command.poll_fds().map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            }));
        }
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return Err(io_failure());
        }
        Ok(())
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

#[cfg(test)]
#[path = "init_test.rs"]
mod init_test;
