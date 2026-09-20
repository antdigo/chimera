use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, OnceLock};

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
    BlockStateForTest {
        started: std::sync::mpsc::Sender<()>,
        proceed: std::sync::mpsc::Receiver<()>,
        reply: oneshot::Sender<()>,
    },
    #[cfg(test)]
    Panic,
}

enum Backend {
    Trusted(Box<TrustedBackend>),
    // The Linux variant remains private until C1 can publish its private
    // Docker endpoint. Its protocol implementation is compiled only on Linux.
    #[cfg(target_os = "linux")]
    Linux(LinuxBackend),
}

#[cfg(target_os = "linux")]
struct LinuxBackend {
    kernel: super::linux::launcher::KernelDomain,
    cleanup: Option<super::linux::StrictCleanupAuthority>,
    path_mappings: Vec<(std::path::PathBuf, super::DomainPath)>,
    next_command_id: u64,
}

enum BackendBuilder {
    Trusted,
    #[cfg(target_os = "linux")]
    Sandboxed(super::linux::StrictBackendBuilder),
}

struct ManagerPermitGuard {
    root_state: Arc<ExecutionDomainState>,
    permit: Option<OwnedSemaphorePermit>,
    clean_exit: bool,
}

#[derive(Clone)]
pub(super) struct ManagerCancellation {
    token: CancellationToken,
    reason: Arc<Mutex<Option<CancelReason>>>,
}

impl ManagerCancellation {
    pub(super) fn new() -> Self {
        Self {
            token: CancellationToken::new(),
            reason: Arc::new(Mutex::new(None)),
        }
    }

    fn cancel(&self, reason: CancelReason) {
        if let Ok(mut stored) = self.reason.lock() {
            stored.get_or_insert(reason);
        }
        self.token.cancel();
    }

    pub(super) async fn cancelled(&self) {
        self.token.cancelled().await;
    }

    pub(super) fn reason(&self) -> CancelReason {
        self.reason
            .lock()
            .ok()
            .and_then(|reason| reason.clone())
            .unwrap_or(CancelReason::Shutdown)
    }
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
        Self::spawn_selected(root, permit, attempt, BackendBuilder::Trusted).await
    }

    #[cfg(target_os = "linux")]
    #[expect(
        dead_code,
        reason = "private strict selector is called by C1 only after endpoint installation"
    )]
    pub(in crate::job::execution_domain) async fn spawn_sandboxed(
        root: ExecutionDomainRoot,
        permit: OwnedSemaphorePermit,
        attempt: AttemptIdentity,
        builder: super::linux::StrictBackendBuilder,
    ) -> Result<ExecutionDomain, ExecutionDomainError> {
        Self::spawn_selected(root, permit, attempt, BackendBuilder::Sandboxed(builder)).await
    }

    async fn spawn_selected(
        root: ExecutionDomainRoot,
        permit: OwnedSemaphorePermit,
        attempt: AttemptIdentity,
        builder: BackendBuilder,
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
                #[cfg(target_os = "linux")]
                let provision_state = Arc::clone(&state);
                let provision = tokio::task::spawn_blocking(move || match builder {
                    BackendBuilder::Trusted => provision_root
                        .create_domain_with_id(attempt.uuid())
                        .map(|backend| Backend::Trusted(Box::new(backend))),
                    #[cfg(target_os = "linux")]
                    BackendBuilder::Sandboxed(builder) => builder
                        .build()
                        .inspect_err(|_| provision_state.poison())
                        .map(|parts| {
                            Backend::Linux(LinuxBackend {
                                kernel: parts.kernel,
                                cleanup: Some(parts.cleanup),
                                path_mappings: parts.path_mappings,
                                next_command_id: 1,
                            })
                        }),
                })
                .await;
                let backend = match provision {
                    Ok(Ok(backend)) => backend,
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
                        let cleanup =
                            with_backend_blocking(&mut backend_slot, Backend::destroy).await;
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
                    revoke_reader(reader.clone()).await;
                    if with_backend_blocking(&mut backend_slot, Backend::destroy)
                        .await
                        .is_ok()
                    {
                        guard.confirmed_destroyed();
                    }
                    return;
                }
                manager_loop(
                    &mut backend_slot,
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
                revoke_reader(reader.clone()).await;
                if backend_slot.is_some()
                    && with_backend_blocking(&mut backend_slot, Backend::destroy)
                        .await
                        .is_ok()
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

async fn run_blocking<T, F>(operation: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .expect("execution-domain blocking operation panicked")
}

async fn with_backend_blocking<T, F>(backend_slot: &mut Option<Backend>, operation: F) -> T
where
    T: Send + 'static,
    F: FnOnce(&mut Backend) -> T + Send + 'static,
{
    let mut backend = backend_slot
        .take()
        .expect("manager backend must be present");
    let (backend, result) = run_blocking(move || {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| operation(&mut backend)));
        (backend, result)
    })
    .await;
    *backend_slot = Some(backend);
    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

async fn revoke_reader(reader: DomainWorkspaceReader) {
    run_blocking(move || reader.revoke_and_wait()).await;
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
    let (paths, environment) = backend.domain_layout()?;
    let command_mapping = backend.command_mapping();
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
        paths,
        environment,
        command_mapping,
        workspace_reader: reader,
        explicit_destroy: false,
    })
}

async fn manager_loop(
    backend_slot: &mut Option<Backend>,
    receiver: &mut mpsc::Receiver<ManagerRequest>,
    reader: &DomainWorkspaceReader,
    attempt: AttemptIdentity,
    guard: &mut ManagerPermitGuard,
) {
    while let Some(request) = receiver.recv().await {
        match request {
            ManagerRequest::BindWorkspace { paths, work, reply } => {
                let owned_reader = reader.clone();
                let result = run_blocking(move || owned_reader.bind(work)).await;
                let result = match result {
                    Ok(()) => {
                        with_backend_blocking(backend_slot, move |backend| {
                            backend.bind_workspace(paths)
                        })
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            ManagerRequest::MarkRunning { reply } => {
                let result = with_backend_blocking(backend_slot, Backend::mark_running).await;
                let _ = reply.send(result);
            }
            ManagerRequest::MarkCleaning { reply } => {
                let result = with_backend_blocking(backend_slot, Backend::mark_cleaning).await;
                let _ = reply.send(result);
            }
            ManagerRequest::Run {
                spec,
                output,
                cancelled,
                reply,
            } => {
                let manager_cancelled = ManagerCancellation::new();
                let mut destroy_reply = None;
                let mut channel_closed = false;
                let result = {
                    let backend = backend_slot
                        .as_mut()
                        .expect("manager backend must be present");
                    let run = backend.run(spec, output, cancelled, manager_cancelled.clone());
                    tokio::pin!(run);
                    loop {
                        tokio::select! {
                            result = &mut run => break result,
                            request = receiver.recv(), if !channel_closed => match request {
                                Some(ManagerRequest::Cancel { reason, reply }) => {
                                    manager_cancelled.cancel(reason);
                                    let _ = reply.send(Ok(()));
                                }
                                Some(ManagerRequest::Destroy { reply }) => {
                                    if destroy_reply.is_none() {
                                        manager_cancelled.cancel(CancelReason::Shutdown);
                                        destroy_reply = Some(reply);
                                    } else {
                                        let _ = reply.send(Err(backend_failure(
                                            super::FailureCategory::Unavailable,
                                        )));
                                    }
                                }
                                #[cfg(test)]
                                Some(ManagerRequest::Panic) => {
                                    panic!("injected execution-domain manager panic")
                                }
                                Some(other) => reject_while_running(other),
                                None => {
                                    manager_cancelled.cancel(CancelReason::Shutdown);
                                    channel_closed = true;
                                }
                            }
                        }
                    }
                };
                let _ = reply.send(result);
                if let Some(reply) = destroy_reply {
                    revoke_reader(reader.clone()).await;
                    let result = with_backend_blocking(backend_slot, Backend::destroy).await;
                    if result.is_ok() {
                        guard.confirmed_destroyed();
                    }
                    let report = result.map(|()| DestroyReport {
                        attempt,
                        forced_kill: true,
                    });
                    let _ = reply.send(report);
                    return;
                }
            }
            ManagerRequest::PrepareStep { event, reply } => {
                let result = with_backend_blocking(backend_slot, move |backend| {
                    backend.prepare_step(&event)
                })
                .await;
                let _ = reply.send(result);
            }
            ManagerRequest::ReadStep { id, reply } => {
                let result =
                    with_backend_blocking(backend_slot, move |backend| backend.read_step(id)).await;
                let _ = reply.send(result);
            }
            ManagerRequest::Cancel { reason, reply } => {
                let result =
                    with_backend_blocking(backend_slot, move |backend| backend.cancel(reason))
                        .await;
                let _ = reply.send(result);
            }
            ManagerRequest::Destroy { reply } => {
                revoke_reader(reader.clone()).await;
                let result = with_backend_blocking(backend_slot, Backend::destroy).await;
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
            ManagerRequest::BlockStateForTest {
                started,
                proceed,
                reply,
            } => {
                run_blocking(move || {
                    let _ = started.send(());
                    let _ = proceed.recv();
                })
                .await;
                let _ = reply.send(());
            }
            #[cfg(test)]
            ManagerRequest::Panic => panic!("injected execution-domain manager panic"),
        }
    }

    // Conservative dropped-handle policy: poison admission synchronously, then
    // revoke all read leases and perform idempotent cleanup before permit drop.
    guard.root_state.poison();
    revoke_reader(reader.clone()).await;
    let _ = with_backend_blocking(backend_slot, Backend::destroy).await;
}

fn reject_while_running(request: ManagerRequest) {
    let error = || backend_failure(super::FailureCategory::Unavailable);
    match request {
        ManagerRequest::BindWorkspace { reply, .. }
        | ManagerRequest::MarkRunning { reply }
        | ManagerRequest::MarkCleaning { reply } => {
            let _ = reply.send(Err(error()));
        }
        ManagerRequest::Run { reply, .. } => {
            let _ = reply.send(Err(error()));
        }
        ManagerRequest::PrepareStep { reply, .. } => {
            let _ = reply.send(Err(error()));
        }
        ManagerRequest::ReadStep { reply, .. } => {
            let _ = reply.send(Err(error()));
        }
        ManagerRequest::Cancel { reply, .. } => {
            let _ = reply.send(Err(error()));
        }
        ManagerRequest::Destroy { reply } => {
            let _ = reply.send(Err(error()));
        }
        #[cfg(test)]
        ManagerRequest::BlockStateForTest { reply, .. } => {
            let _ = reply.send(());
        }
        #[cfg(test)]
        ManagerRequest::Panic => unreachable!("panic requests are handled before rejection"),
    }
}

impl Backend {
    fn command_mapping(&self) -> super::DomainCommandMapping {
        match self {
            Self::Trusted(_) => super::DomainCommandMapping::Trusted,
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => {
                super::DomainCommandMapping::Sandboxed(backend.path_mappings.clone())
            }
        }
    }

    fn domain_layout(&self) -> Result<(DomainPaths, DomainEnvironment), ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => Ok((
                DomainPaths::trusted(
                    &backend.work_dir,
                    &backend.private_tmp,
                    &backend.attempt_dir,
                    backend.docker_paths.config_dir(),
                )?,
                DomainEnvironment::trusted(backend.docker_config_dir_env.clone()),
            )),
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => {
                let paths = DomainPaths::sandboxed();
                for required in [
                    &paths.work,
                    &paths.tmp,
                    &paths.home,
                    &paths.run,
                    &paths.docker_config,
                    &paths.docker_data,
                    &paths.docker_exec,
                ] {
                    if !backend
                        .path_mappings
                        .iter()
                        .any(|(_, target)| target == required)
                    {
                        return Err(backend_failure(super::FailureCategory::IdentityMismatch));
                    }
                }
                Ok((paths, DomainEnvironment::sandboxed()))
            }
        }
    }

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
        manager_cancelled: ManagerCancellation,
    ) -> Result<CommandOutcome, ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => {
                backend
                    .run(spec, output, cancelled, manager_cancelled)
                    .await
            }
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => {
                backend
                    .run(spec, output, cancelled, manager_cancelled)
                    .await
            }
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
        // A command cancellation is meaningful only while `Run` owns a
        // correlated command id. A late/idle cancellation is idempotent and
        // must never be promoted to domain shutdown.
        let _ = (self, reason);
        Ok(())
    }

    fn destroy(&mut self) -> Result<(), ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.destroy_in_place(),
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => backend.destroy(),
        }
    }
}

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
        manager_cancelled: ManagerCancellation,
    ) -> Result<CommandOutcome, ExecutionDomainError> {
        use super::protocol::{Message, Request, Response};

        #[derive(Clone, Copy)]
        enum PendingSend {
            Run,
            Cancel,
        }

        if !matches!(spec.target, super::CommandTarget::Sandboxed { .. }) {
            return Err(backend_failure(super::FailureCategory::InvalidInput));
        }
        let command_id = self.next_command_id()?;
        let deadline = std::time::Instant::now()
            .checked_add(spec.timeout + std::time::Duration::from_secs(5))
            .ok_or_else(|| backend_failure(super::FailureCategory::InvalidInput))?;
        self.kernel
            .control
            .start_send(Message::Request(Request::Run { command_id, spec }))?;
        let mut pending_send = Some(PendingSend::Run);
        let mut run_flushed = false;
        let mut started = false;
        let mut cancel_reason = None;
        let mut cancel_started = false;
        let mut terminal = None;
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(backend_failure(super::FailureCategory::Timeout));
            }
            if pending_send.is_none()
                && let Some(result) = terminal.take()
            {
                return result;
            }
            if cancel_reason.is_none() && cancelled.is_cancelled() {
                cancel_reason = Some(CancelReason::User);
            }
            if cancel_reason.is_none() && manager_cancelled.token.is_cancelled() {
                cancel_reason = Some(manager_cancelled.reason());
            }
            if cancel_reason.is_none() && output.is_closed() {
                cancel_reason = Some(CancelReason::HandleDropped);
            }
            if let Some(sending) = pending_send
                && self.kernel.control.try_flush()?
            {
                if matches!(sending, PendingSend::Run) {
                    run_flushed = true;
                }
                pending_send = None;
            }
            if run_flushed
                && pending_send.is_none()
                && !cancel_started
                && let Some(reason) = cancel_reason.clone()
            {
                self.kernel
                    .control
                    .start_send(Message::Request(Request::CancelCommand {
                        command_id,
                        reason,
                    }))?;
                pending_send = Some(PendingSend::Cancel);
                cancel_started = true;
            }
            if pending_send.is_none()
                && let Some(result) = terminal.take()
            {
                return result;
            }
            if terminal.is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                continue;
            }
            let Some(message) = self.kernel.control.try_receive()? else {
                tokio::select! {
                    _ = cancelled.cancelled(), if cancel_reason.is_none() => {
                        cancel_reason = Some(CancelReason::User);
                    }
                    _ = manager_cancelled.cancelled(), if cancel_reason.is_none() => {
                        cancel_reason = Some(manager_cancelled.reason());
                    }
                    _ = output.closed(), if cancel_reason.is_none() => {
                        cancel_reason = Some(CancelReason::HandleDropped);
                    }
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
                } if actual == command_id => {
                    terminal = Some(Err(backend_failure(category)));
                }
                Response::Output {
                    command_id: actual,
                    event,
                } if actual == command_id && started => {
                    if cancel_reason.is_none() {
                        let send = output.send(event);
                        tokio::pin!(send);
                        tokio::select! {
                            result = &mut send => {
                                if result.is_err() {
                                    cancel_reason = Some(CancelReason::HandleDropped);
                                }
                            }
                            _ = cancelled.cancelled() => {
                                cancel_reason = Some(CancelReason::User);
                            }
                            _ = manager_cancelled.cancelled() => {
                                cancel_reason = Some(manager_cancelled.reason());
                            }
                        }
                    }
                }
                Response::CommandFinished {
                    command_id: actual,
                    outcome,
                } if actual == command_id && started => {
                    terminal = Some(Ok(outcome));
                }
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

    fn shutdown(&mut self) -> Result<(), ExecutionDomainError> {
        use super::protocol::{Request, Response};
        match self.kernel.control.request(Request::Shutdown {
            reason: CancelReason::Shutdown,
        })? {
            Response::ShuttingDown => Ok(()),
            Response::Rejected { category } => Err(backend_failure(category)),
            _ => Err(backend_failure(super::FailureCategory::Protocol)),
        }
    }

    fn destroy(&mut self) -> Result<(), ExecutionDomainError> {
        let _ = self.shutdown();
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
        if let Some(cleanup) = &self.cleanup {
            cleanup.verify()?;
            // Task 10 must kill/prove-empty/unmount/remove before this cleanup
            // authority can be released. Never report a private strict backend
            // as destroyed while that proof is unavailable.
            return Err(backend_failure(super::FailureCategory::NotReady));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "manager_test.rs"]
mod manager_test;
