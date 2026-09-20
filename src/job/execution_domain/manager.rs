use std::panic::AssertUnwindSafe;
use std::sync::{Arc, OnceLock};

use futures::FutureExt;
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::job::workspace::WorkspaceStatePaths;

use super::{
    AttemptIdentity, CancelReason, CommandEvent, CommandOutcome, CommandSpec, DestroyReport,
    DomainEnvironment, DomainPaths, DomainWorkspaceReader, ExecutionDomain, ExecutionDomainError,
    ExecutionDomainRoot, ExecutionDomainState, StepFilesId, StepStateSnapshot, TrustedBackend,
};

pub(super) enum ManagerRequest {
    BindWorkspace {
        paths: WorkspaceStatePaths,
        work: std::path::PathBuf,
        reply: oneshot::Sender<Result<(), ExecutionDomainError>>,
    },
    MarkRunning {
        reply: oneshot::Sender<Result<(), ExecutionDomainError>>,
    },
    MarkCleaning {
        reply: oneshot::Sender<Result<(), ExecutionDomainError>>,
    },
    Run {
        spec: CommandSpec,
        output: mpsc::Sender<CommandEvent>,
        cancelled: CancellationToken,
        reply: oneshot::Sender<Result<CommandOutcome, ExecutionDomainError>>,
    },
    PrepareStep {
        event: Vec<u8>,
        reply: oneshot::Sender<Result<StepFilesId, ExecutionDomainError>>,
    },
    ReadStep {
        id: StepFilesId,
        reply: oneshot::Sender<Result<StepStateSnapshot, ExecutionDomainError>>,
    },
    Cancel {
        reason: CancelReason,
        reply: oneshot::Sender<Result<(), ExecutionDomainError>>,
    },
    Destroy {
        reply: oneshot::Sender<Result<DestroyReport, ExecutionDomainError>>,
    },
    #[cfg(test)]
    Panic,
}

enum Backend {
    Trusted(Box<TrustedBackend>),
    // The Linux variant remains private until C1 can publish its private
    // Docker endpoint. Its protocol implementation is compiled only on Linux.
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "private until C1 installs the sandbox Docker endpoint"
        )
    )]
    Linux(LinuxBackend),
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
struct LinuxBackend {
    kernel: super::linux::launcher::KernelDomain,
    next_command_id: u64,
}

struct ManagerPermitGuard {
    root_state: Arc<ExecutionDomainState>,
    permit: Option<OwnedSemaphorePermit>,
    clean_exit: bool,
}

impl ManagerPermitGuard {
    fn confirmed_destroyed(&mut self) {
        self.clean_exit = true;
        drop(self.permit.take());
    }

    fn release_without_resources(&mut self) {
        self.clean_exit = true;
        drop(self.permit.take());
    }
}

impl Drop for ManagerPermitGuard {
    fn drop(&mut self) {
        // Struct fields are dropped only after this method returns. Poisoning
        // therefore becomes observable before the permit can wake a waiter.
        if !self.clean_exit {
            self.root_state.poison();
        }
    }
}

pub(super) struct DomainManager;

impl DomainManager {
    pub(super) async fn spawn(
        root: ExecutionDomainRoot,
        permit: OwnedSemaphorePermit,
        attempt: AttemptIdentity,
    ) -> Result<ExecutionDomain, ExecutionDomainError> {
        let (request, mut receiver) = mpsc::channel(32);
        let (ready_tx, ready_rx) = oneshot::channel();
        let response_root = root.canonical_path.clone();
        let state = Arc::clone(&root.state);
        let manager_registry = root.clone();
        let guard = ManagerPermitGuard {
            root_state: Arc::clone(&state),
            permit: Some(permit),
            clean_exit: false,
        };

        // The task is detached before this function first awaits. Cancelling the
        // caller can only drop ready_rx; it cannot abort provision or rollback.
        let manager_task = async move {
            let mut guard = guard;
            let reader = DomainWorkspaceReader::unbound();
            let mut backend_slot: Option<Backend> = None;
            let mut ready_tx = Some(ready_tx);

            let managed = AssertUnwindSafe(async {
                let provision_root = root.clone();
                let provision = tokio::task::spawn_blocking(move || {
                    provision_root.create_domain_with_id(attempt.uuid())
                })
                .await;
                let backend = match provision {
                    Ok(Ok(backend)) => Backend::Trusted(Box::new(backend)),
                    Ok(Err(error)) => {
                        if !*state.poisoned.borrow() {
                            guard.release_without_resources();
                        }
                        let _ = ready_tx.take().expect("ready sender").send(Err(error));
                        return;
                    }
                    Err(_) => {
                        state.poison();
                        let _ = ready_tx.take().expect("ready sender").send(Err(
                            ExecutionDomainError::PoisonedRoot {
                                path: root.canonical_path.clone(),
                            },
                        ));
                        return;
                    }
                };
                backend_slot = Some(backend);
                #[cfg(test)]
                if let Some(pause) = root.take_provision_pause_for_test() {
                    let _ = pause.started.send(());
                    let _ = pause.proceed.await;
                }
                let handle = match build_handle(
                    backend_slot.as_ref().expect("provisioned backend"),
                    attempt,
                    request,
                    reader.clone(),
                ) {
                    Ok(handle) => handle,
                    Err(error) => {
                        let cleanup = backend_slot
                            .as_mut()
                            .expect("provisioned backend")
                            .destroy();
                        if cleanup.is_ok() {
                            guard.confirmed_destroyed();
                        }
                        let _ = ready_tx.take().expect("ready sender").send(Err(error));
                        return;
                    }
                };
                if let Err(undelivered) = ready_tx.take().expect("ready sender").send(Ok(handle)) {
                    if let Ok(mut handle) = undelivered {
                        // The manager, not the unpublished handle's Drop,
                        // owns rollback after caller cancellation.
                        handle.explicit_destroy = true;
                        handle.request.take();
                    }
                    reader.revoke_and_wait();
                    if backend_slot
                        .as_mut()
                        .expect("provisioned backend")
                        .destroy()
                        .is_ok()
                    {
                        guard.confirmed_destroyed();
                    }
                    return;
                }
                manager_loop(
                    backend_slot.as_mut().expect("provisioned backend"),
                    &mut receiver,
                    &reader,
                    attempt,
                    &mut guard,
                )
                .await;
            })
            .catch_unwind()
            .await;

            if managed.is_err() {
                // The guard remains outside the unwind boundary, so cleanup
                // authority and the permit survive a panic in the request loop.
                state.poison();
                reader.revoke_and_wait();
                if backend_slot
                    .as_mut()
                    .is_some_and(|backend| backend.destroy().is_ok())
                {
                    guard.confirmed_destroyed();
                }
            }
        };
        let handle = manager_runtime()
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: response_root.clone(),
            })?
            .spawn(manager_task);
        manager_registry.register_manager(handle);

        ready_rx
            .await
            .map_err(|_| ExecutionDomainError::PoisonedRoot {
                path: response_root,
            })?
    }
}

fn manager_runtime() -> Result<&'static tokio::runtime::Runtime, std::io::Error> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    static INITIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let _initializing = INITIALIZE
        .lock()
        .map_err(|_| std::io::Error::other("manager runtime initialization poisoned"))?;
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("chimera-domain-manager")
        .enable_all()
        .build()?;
    RUNTIME
        .set(runtime)
        .map_err(|_| std::io::Error::other("manager runtime initialized twice"))?;
    RUNTIME
        .get()
        .ok_or_else(|| std::io::Error::other("manager runtime initialization lost"))
}

#[cfg_attr(
    not(target_os = "linux"),
    expect(
        clippy::infallible_destructuring_match,
        reason = "the second private backend is Linux-only"
    )
)]
fn build_handle(
    backend: &Backend,
    attempt: AttemptIdentity,
    request: mpsc::Sender<ManagerRequest>,
    reader: DomainWorkspaceReader,
) -> Result<ExecutionDomain, ExecutionDomainError> {
    let backend = match backend {
        Backend::Trusted(backend) => backend,
        #[cfg(target_os = "linux")]
        Backend::Linux(_) => {
            // C1 must install the private endpoint before this branch is enabled.
            return Err(backend_failure(super::FailureCategory::NotReady));
        }
    };
    Ok(ExecutionDomain {
        request: Some(request),
        state: Arc::clone(&backend.state),
        root: backend.root.clone(),
        attempt_id: attempt,
        docker_endpoint: backend.docker_endpoint.clone(),
        docker_paths: backend.docker_paths.clone(),
        docker_config_dir_env: backend.docker_config_dir_env.clone(),
        docker_config_file: backend.docker_config_file.clone(),
        private_tmp: backend.private_tmp.clone(),
        work_dir: backend.work_dir.clone(),
        attempt_dir: backend.attempt_dir.clone(),
        paths: DomainPaths::trusted(
            &backend.work_dir,
            &backend.private_tmp,
            &backend.attempt_dir,
            backend.docker_paths.config_dir(),
        )?,
        environment: DomainEnvironment::trusted(backend.docker_config_dir_env.clone()),
        workspace_reader: reader,
        explicit_destroy: false,
    })
}

async fn manager_loop(
    backend: &mut Backend,
    receiver: &mut mpsc::Receiver<ManagerRequest>,
    reader: &DomainWorkspaceReader,
    attempt: AttemptIdentity,
    guard: &mut ManagerPermitGuard,
) {
    while let Some(request) = receiver.recv().await {
        match request {
            ManagerRequest::BindWorkspace { paths, work, reply } => {
                let result = reader
                    .bind(work)
                    .and_then(|()| backend.bind_workspace(paths));
                let _ = reply.send(result);
            }
            ManagerRequest::MarkRunning { reply } => {
                let _ = reply.send(backend.mark_running());
            }
            ManagerRequest::MarkCleaning { reply } => {
                let _ = reply.send(backend.mark_cleaning());
            }
            ManagerRequest::Run {
                spec,
                output,
                cancelled,
                reply,
            } => {
                let result = backend.run(spec, output, cancelled).await;
                let _ = reply.send(result);
            }
            ManagerRequest::PrepareStep { event, reply } => {
                let _ = reply.send(backend.prepare_step(&event));
            }
            ManagerRequest::ReadStep { id, reply } => {
                let _ = reply.send(backend.read_step(id));
            }
            ManagerRequest::Cancel { reason, reply } => {
                let _ = reply.send(backend.cancel(reason));
            }
            ManagerRequest::Destroy { reply } => {
                reader.revoke_and_wait();
                let result = backend.destroy();
                if result.is_ok() {
                    guard.confirmed_destroyed();
                }
                let report = result.map(|()| DestroyReport {
                    attempt,
                    forced_kill: false,
                });
                // Cleanup is already terminal; a dropped reply cannot cancel it.
                let _ = reply.send(report);
                return;
            }
            #[cfg(test)]
            ManagerRequest::Panic => panic!("injected execution-domain manager panic"),
        }
    }

    // Conservative dropped-handle policy: poison admission synchronously, then
    // revoke all read leases and perform idempotent cleanup before permit drop.
    guard.root_state.poison();
    reader.revoke_and_wait();
    let _ = backend.destroy();
}

impl Backend {
    fn bind_workspace(&mut self, paths: WorkspaceStatePaths) -> Result<(), ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.bind_workspace(paths),
            #[cfg(target_os = "linux")]
            Self::Linux(_) => Err(backend_failure(super::FailureCategory::NotReady)),
        }
    }

    fn mark_running(&mut self) -> Result<(), ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.mark_running(),
            #[cfg(target_os = "linux")]
            Self::Linux(_) => Ok(()),
        }
    }

    fn mark_cleaning(&mut self) -> Result<(), ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.mark_cleaning(),
            #[cfg(target_os = "linux")]
            Self::Linux(_) => Ok(()),
        }
    }

    async fn run(
        &mut self,
        spec: CommandSpec,
        output: mpsc::Sender<CommandEvent>,
        cancelled: CancellationToken,
    ) -> Result<CommandOutcome, ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.run(spec, output, cancelled).await,
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => backend.run(spec, output, cancelled).await,
        }
    }

    fn prepare_step(&mut self, event: &[u8]) -> Result<StepFilesId, ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.prepare_step(event),
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => backend.prepare_step(event),
        }
    }

    fn read_step(&mut self, id: StepFilesId) -> Result<StepStateSnapshot, ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.read_step(id),
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => backend.read_step(id),
        }
    }

    fn cancel(&mut self, reason: CancelReason) -> Result<(), ExecutionDomainError> {
        match self {
            Self::Trusted(_) => {
                let _ = reason;
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => backend.cancel(reason),
        }
    }

    fn destroy(&mut self) -> Result<(), ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.destroy_in_place(),
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => backend.destroy(),
        }
    }
}

#[cfg(target_os = "linux")]
fn backend_failure(category: super::FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: super::Stage::Protocol,
        category,
        errno: None,
    }
}

#[cfg(target_os = "linux")]
impl LinuxBackend {
    fn next_command_id(&mut self) -> Result<u64, ExecutionDomainError> {
        let id = self.next_command_id;
        if id == 0 {
            return Err(backend_failure(super::FailureCategory::Protocol));
        }
        self.next_command_id = id
            .checked_add(1)
            .ok_or_else(|| backend_failure(super::FailureCategory::Protocol))?;
        Ok(id)
    }

    async fn run(
        &mut self,
        spec: CommandSpec,
        output: mpsc::Sender<CommandEvent>,
        cancelled: CancellationToken,
    ) -> Result<CommandOutcome, ExecutionDomainError> {
        use super::protocol::{Message, Request, Response};

        if !matches!(spec.target, super::CommandTarget::Sandboxed { .. }) {
            return Err(backend_failure(super::FailureCategory::InvalidInput));
        }
        let command_id = self.next_command_id()?;
        let deadline = std::time::Instant::now()
            .checked_add(spec.timeout + std::time::Duration::from_secs(5))
            .ok_or_else(|| backend_failure(super::FailureCategory::InvalidInput))?;
        self.kernel.control.send(
            Message::Request(Request::Run { command_id, spec }),
            deadline,
        )?;
        let mut started = false;
        let mut cancel_sent = false;
        loop {
            if cancelled.is_cancelled() && !cancel_sent {
                self.kernel.control.send(
                    Message::Request(Request::CancelCommand {
                        command_id,
                        reason: CancelReason::User,
                    }),
                    deadline,
                )?;
                cancel_sent = true;
            }
            if output.is_closed() && !cancel_sent {
                self.kernel.control.send(
                    Message::Request(Request::CancelCommand {
                        command_id,
                        reason: CancelReason::HandleDropped,
                    }),
                    deadline,
                )?;
                cancel_sent = true;
            }
            let Some(message) = self.kernel.control.try_receive()? else {
                if std::time::Instant::now() >= deadline {
                    return Err(backend_failure(super::FailureCategory::Timeout));
                }
                tokio::select! {
                    _ = cancelled.cancelled(), if !cancel_sent => {}
                    _ = output.closed(), if !cancel_sent => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {}
                }
                continue;
            };
            let Message::Response(response) = message else {
                return Err(backend_failure(super::FailureCategory::Protocol));
            };
            match response {
                Response::CommandStarted { command_id: actual }
                    if actual == command_id && !started =>
                {
                    started = true;
                }
                Response::CommandRejected {
                    command_id: actual,
                    category,
                } if actual == command_id => return Err(backend_failure(category)),
                Response::Output {
                    command_id: actual,
                    event,
                } if actual == command_id && started => {
                    if !cancel_sent {
                        let send = output.send(event);
                        tokio::pin!(send);
                        tokio::select! {
                            result = &mut send => {
                                if result.is_err() {
                                    self.kernel.control.send(
                                        Message::Request(Request::CancelCommand {
                                            command_id,
                                            reason: CancelReason::HandleDropped,
                                        }),
                                        deadline,
                                    )?;
                                    cancel_sent = true;
                                }
                            }
                            _ = cancelled.cancelled() => {
                                self.kernel.control.send(
                                    Message::Request(Request::CancelCommand {
                                        command_id,
                                        reason: CancelReason::User,
                                    }),
                                    deadline,
                                )?;
                                cancel_sent = true;
                            }
                        }
                    }
                }
                Response::CommandFinished {
                    command_id: actual,
                    outcome,
                } if actual == command_id && started => return Ok(outcome),
                _ => return Err(backend_failure(super::FailureCategory::Protocol)),
            }
        }
    }

    fn prepare_step(&mut self, event: &[u8]) -> Result<StepFilesId, ExecutionDomainError> {
        use super::protocol::{Request, Response};
        let id = StepFilesId::new();
        match self.kernel.control.request(Request::PrepareStep {
            id: id.clone(),
            event: event.to_vec(),
        })? {
            Response::StepPrepared { id: actual } if actual == id => Ok(id),
            Response::Rejected { category } => Err(backend_failure(category)),
            _ => Err(backend_failure(super::FailureCategory::Protocol)),
        }
    }

    fn read_step(&mut self, id: StepFilesId) -> Result<StepStateSnapshot, ExecutionDomainError> {
        use super::protocol::{Request, Response};
        match self
            .kernel
            .control
            .request(Request::ReadStep { id: id.clone() })?
        {
            Response::StepSnapshot {
                id: actual,
                snapshot,
            } if actual == id => Ok(snapshot),
            Response::Rejected { category } => Err(backend_failure(category)),
            _ => Err(backend_failure(super::FailureCategory::Protocol)),
        }
    }

    fn cancel(&mut self, reason: CancelReason) -> Result<(), ExecutionDomainError> {
        use super::protocol::{Request, Response};
        match self.kernel.control.request(Request::Shutdown { reason })? {
            Response::ShuttingDown => Ok(()),
            Response::Rejected { category } => Err(backend_failure(category)),
            _ => Err(backend_failure(super::FailureCategory::Protocol)),
        }
    }

    fn destroy(&mut self) -> Result<(), ExecutionDomainError> {
        let _ = self.cancel(CancelReason::Shutdown);
        if self
            .kernel
            .launcher
            .try_wait()
            .map_err(|error| ExecutionDomainError::Backend {
                attempt: None,
                stage: super::Stage::Destroy,
                category: super::FailureCategory::Io,
                errno: error.raw_os_error(),
            })?
            .is_none()
        {
            self.kernel
                .launcher
                .kill()
                .map_err(|error| ExecutionDomainError::Backend {
                    attempt: None,
                    stage: super::Stage::Destroy,
                    category: super::FailureCategory::Io,
                    errno: error.raw_os_error(),
                })?;
            self.kernel
                .launcher
                .wait()
                .map_err(|error| ExecutionDomainError::Backend {
                    attempt: None,
                    stage: super::Stage::Destroy,
                    category: super::FailureCategory::Io,
                    errno: error.raw_os_error(),
                })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "manager_test.rs"]
mod manager_test;
