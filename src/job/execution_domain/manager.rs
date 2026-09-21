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
    AuthorizeExternalRevocation {
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
    Linux(Box<LinuxBackend>),
}

#[derive(Default)]
pub(super) struct RetainedCleanupRegistry {
    entries: Mutex<Vec<RetainedCleanup>>,
}

struct RetainedCleanup {
    authority: RetainedAuthority,
    guard: ManagerPermitGuard,
    attempt: AttemptIdentity,
}

enum RetainedAuthority {
    Backend(Backend),
    #[cfg(target_os = "linux")]
    Partial(super::linux::StrictPartialCleanup),
}

struct ProvisionFailure {
    error: ExecutionDomainError,
    #[cfg(target_os = "linux")]
    partial: Option<super::linux::StrictPartialCleanup>,
}

impl std::fmt::Debug for RetainedCleanupRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedCleanupRegistry")
            .field("entries", &self.len())
            .finish()
    }
}

impl RetainedCleanupRegistry {
    fn retain(&self, backend: Backend, guard: ManagerPermitGuard, attempt: AttemptIdentity) {
        self.retain_authority(RetainedAuthority::Backend(backend), guard, attempt);
    }

    fn retain_authority(
        &self,
        authority: RetainedAuthority,
        guard: ManagerPermitGuard,
        attempt: AttemptIdentity,
    ) {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(RetainedCleanup {
                authority,
                guard,
                attempt,
            });
    }

    pub(super) fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    pub(super) fn retry_all(&self) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut retained = Vec::new();
        for mut entry in std::mem::take(&mut *entries) {
            let result = match &mut entry.authority {
                RetainedAuthority::Backend(backend) => backend.destroy(entry.attempt).map(|_| ()),
                #[cfg(target_os = "linux")]
                RetainedAuthority::Partial(partial) => partial.retry(),
            };
            if result.is_ok() {
                entry.guard.confirmed_destroyed();
            } else {
                retained.push(entry);
            }
        }
        *entries = retained;
    }
}

#[cfg(target_os = "linux")]
struct LinuxBackend {
    cleanup: Option<super::linux::StrictCleanupRecord>,
    #[cfg(test)]
    test_kernel: Option<super::linux::launcher::KernelDomain>,
    path_mappings: Vec<(std::path::PathBuf, super::DomainPath)>,
    next_command_id: u64,
    control_broken: bool,
}

#[cfg(target_os = "linux")]
const CONTROL_CANCEL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

struct BackendBuilder {
    #[cfg(target_os = "linux")]
    sandboxed: Option<super::linux::StrictBackendBuilder>,
}

impl BackendBuilder {
    fn trusted() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            sandboxed: None,
        }
    }
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

fn release_destroyed_backend(backend_slot: &mut Option<Backend>, guard: &mut ManagerPermitGuard) {
    // Closing retained BoundDir/cgroup/socket authority is part of terminal
    // cleanup. A capacity waiter must not wake while the old backend still
    // owns any descriptor capability.
    drop(backend_slot.take());
    guard.confirmed_destroyed();
}

pub(super) struct DomainManager;

impl DomainManager {
    pub(super) async fn spawn(
        root: ExecutionDomainRoot,
        permit: OwnedSemaphorePermit,
        attempt: AttemptIdentity,
    ) -> Result<ExecutionDomain, ExecutionDomainError> {
        Self::spawn_selected(root, permit, attempt, BackendBuilder::trusted()).await
    }

    async fn spawn_selected(
        root: ExecutionDomainRoot,
        permit: OwnedSemaphorePermit,
        attempt: AttemptIdentity,
        _builder: BackendBuilder,
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
            #[cfg(target_os = "linux")]
            let mut partial_slot: Option<super::linux::StrictPartialCleanup> = None;
            let mut ready_tx = Some(ready_tx);

            let managed = AssertUnwindSafe(async {
                let provision_root = root.clone();
                #[cfg(target_os = "linux")]
                let provision_state = Arc::clone(&state);
                let provision = tokio::task::spawn_blocking(move || {
                    #[cfg(not(target_os = "linux"))]
                    {
                        provision_root
                            .create_domain_with_id(attempt.uuid())
                            .map(|backend| Backend::Trusted(Box::new(backend)))
                            .map_err(|error| ProvisionFailure { error })
                    }
                    #[cfg(target_os = "linux")]
                    if let Some(builder) = _builder.sandboxed {
                        match builder.build() {
                            Ok(parts) => Ok(Backend::Linux(Box::new(LinuxBackend {
                                cleanup: Some(parts.cleanup),
                                #[cfg(test)]
                                test_kernel: None,
                                path_mappings: parts.path_mappings,
                                next_command_id: 1,
                                control_broken: false,
                            }))),
                            Err(failure) => {
                                if failure.quarantine() {
                                    provision_state.poison();
                                }
                                let (error, partial) = failure.into_parts();
                                Err(ProvisionFailure { error, partial })
                            }
                        }
                    } else {
                        provision_root
                            .create_domain_with_id(attempt.uuid())
                            .map(|backend| Backend::Trusted(Box::new(backend)))
                            .map_err(|error| ProvisionFailure {
                                error,
                                partial: None,
                            })
                    }
                })
                .await;
                let backend = match provision {
                    Ok(Ok(backend)) => backend,
                    Ok(Err(failure)) => {
                        #[cfg(target_os = "linux")]
                        if let Some(partial) = failure.partial {
                            state.poison();
                            partial_slot = Some(partial);
                            let _ = ready_tx
                                .take()
                                .expect("ready sender")
                                .send(Err(failure.error));
                            return;
                        }
                        if !*state.poisoned.borrow() {
                            guard.release_without_resources();
                        }
                        let _ = ready_tx
                            .take()
                            .expect("ready sender")
                            .send(Err(failure.error));
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
                            destroy_managed(&mut backend_slot, reader.clone(), attempt).await;
                        if cleanup.is_ok() {
                            release_destroyed_backend(&mut backend_slot, &mut guard);
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
                    if destroy_managed(&mut backend_slot, reader.clone(), attempt)
                        .await
                        .is_ok()
                    {
                        release_destroyed_backend(&mut backend_slot, &mut guard);
                    }
                    return;
                }
                with_backend_blocking(&mut backend_slot, Backend::mark_published).await;
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
                if backend_slot.is_some()
                    && destroy_managed(&mut backend_slot, reader.clone(), attempt)
                        .await
                        .is_ok()
                {
                    release_destroyed_backend(&mut backend_slot, &mut guard);
                }
            }
            #[cfg(target_os = "linux")]
            if let Some(partial) = partial_slot.take() {
                root.retained_cleanups.retain_authority(
                    RetainedAuthority::Partial(partial),
                    guard,
                    attempt,
                );
                return;
            }
            if let Some(backend) = backend_slot.take() {
                state.poison();
                root.retained_cleanups.retain(backend, guard, attempt);
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

async fn revoke_reader(reader: DomainWorkspaceReader) -> Result<(), ExecutionDomainError> {
    run_blocking(move || {
        reader.revoke_until(std::time::Instant::now() + std::time::Duration::from_secs(2))
    })
    .await
}

async fn destroy_managed(
    backend_slot: &mut Option<Backend>,
    reader: DomainWorkspaceReader,
    attempt: AttemptIdentity,
) -> Result<DestroyReport, ExecutionDomainError> {
    let reader_result = revoke_reader(reader).await;
    if reader_result.is_err()
        && !backend_slot
            .as_ref()
            .is_some_and(Backend::needs_revocation_failure_neutralization)
    {
        // Trusted cleanup has no separate kill-only phase. Preserve its files
        // while a reader still holds authority; the guard poisons capacity.
        return match reader_result {
            Err(error) => Err(error),
            Ok(()) => unreachable!("branch requires a reader revocation error"),
        };
    }
    let destroy =
        with_backend_blocking(backend_slot, move |backend| backend.destroy(attempt)).await;
    match (reader_result, destroy) {
        (Err(error), _) => Err(error),
        (Ok(()), result) => result,
    }
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
                                        receiver.close();
                                        channel_closed = true;
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
                let control_broken = backend_slot.as_ref().is_some_and(Backend::control_broken);
                if control_broken {
                    guard.root_state.poison();
                }
                let _ = reply.send(result);
                if let Some(reply) = destroy_reply {
                    let result = destroy_managed(backend_slot, reader.clone(), attempt).await;
                    if result.is_ok() {
                        release_destroyed_backend(backend_slot, guard);
                    }
                    let _ = reply.send(result);
                    return;
                }
                if control_broken {
                    let result = destroy_managed(backend_slot, reader.clone(), attempt).await;
                    if result.is_ok() {
                        release_destroyed_backend(backend_slot, guard);
                    }
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
            ManagerRequest::AuthorizeExternalRevocation { reply } => {
                with_backend_blocking(backend_slot, Backend::authorize_external_revocation).await;
                let _ = reply.send(Ok(()));
            }
            ManagerRequest::Destroy { reply } => {
                let result = destroy_managed(backend_slot, reader.clone(), attempt).await;
                if result.is_ok() {
                    receiver.close();
                    release_destroyed_backend(backend_slot, guard);
                }
                // Cleanup is already terminal; a dropped reply cannot cancel it.
                let success = result.is_ok();
                let _ = reply.send(result);
                if success {
                    return;
                }
                guard.root_state.poison();
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
    let _ = destroy_managed(backend_slot, reader.clone(), attempt).await;
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
        ManagerRequest::AuthorizeExternalRevocation { reply } => {
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
    fn mark_published(&mut self) {
        match self {
            Self::Trusted(_) => {}
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => {
                if let Some(cleanup) = &mut backend.cleanup {
                    cleanup.mark_published();
                }
            }
        }
    }

    fn needs_revocation_failure_neutralization(&self) -> bool {
        match self {
            Self::Trusted(_) => false,
            #[cfg(target_os = "linux")]
            Self::Linux(_) => true,
        }
    }

    fn authorize_external_revocation(&mut self) {
        match self {
            Self::Trusted(_) => {}
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => {
                if let Some(cleanup) = &mut backend.cleanup {
                    cleanup.authorize_external_revocation();
                }
            }
        }
    }

    fn control_broken(&self) -> bool {
        match self {
            Self::Trusted(_) => false,
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => backend.control_broken,
        }
    }

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
            Self::Linux(backend) => backend
                .cleanup
                .as_mut()
                .map_or(Ok(()), super::linux::StrictCleanupRecord::mark_running),
        }
    }

    fn mark_cleaning(&mut self) -> Result<(), ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.mark_cleaning(),
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => backend
                .cleanup
                .as_mut()
                .map_or(Ok(()), super::linux::StrictCleanupRecord::mark_cleaning),
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

    fn destroy(&mut self, attempt: AttemptIdentity) -> Result<DestroyReport, ExecutionDomainError> {
        match self {
            Self::Trusted(backend) => backend.destroy_in_place().map(|()| DestroyReport {
                attempt,
                forced_kill: false,
            }),
            #[cfg(target_os = "linux")]
            Self::Linux(backend) => backend.destroy(attempt),
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
    #[cfg(test)]
    fn kernel(&self) -> &super::linux::launcher::KernelDomain {
        if let Some(cleanup) = &self.cleanup {
            return cleanup.kernel();
        }
        #[cfg(test)]
        if let Some(kernel) = &self.test_kernel {
            return kernel;
        }
        unreachable!("production Linux backend always owns a cleanup record")
    }

    fn kernel_mut(&mut self) -> &mut super::linux::launcher::KernelDomain {
        if let Some(cleanup) = &mut self.cleanup {
            return cleanup.kernel_mut();
        }
        #[cfg(test)]
        if let Some(kernel) = &mut self.test_kernel {
            return kernel;
        }
        unreachable!("production Linux backend always owns a cleanup record")
    }

    fn fail_control(&mut self, error: ExecutionDomainError) -> ExecutionDomainError {
        self.kernel_mut().control.abort();
        self.control_broken = true;
        error
    }

    fn break_control(&mut self, category: super::FailureCategory) -> ExecutionDomainError {
        self.fail_control(backend_failure(category))
    }

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
        if let Err(error) = self
            .kernel_mut()
            .control
            .start_send(Message::Request(Request::Run { command_id, spec }))
        {
            return Err(self.fail_control(error));
        }
        let mut pending_send = Some(PendingSend::Run);
        let mut run_flushed = false;
        let mut started = false;
        let mut cancel_reason = None;
        let mut cancel_delivery_deadline = None;
        let mut cancel_started = false;
        let mut cancel_acknowledged = false;
        let mut cancel_ack_deadline = None;
        let mut terminal = None;
        let request_cancel =
            |reason: CancelReason,
             cancel_reason: &mut Option<CancelReason>,
             delivery_deadline: &mut Option<std::time::Instant>| {
                if cancel_reason.is_none() {
                    *cancel_reason = Some(reason);
                    let now = std::time::Instant::now();
                    *delivery_deadline =
                        Some(now.checked_add(CONTROL_CANCEL_TIMEOUT).unwrap_or(now));
                }
            };
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(self.break_control(super::FailureCategory::Timeout));
            }
            if cancel_delivery_deadline
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(self.break_control(super::FailureCategory::Unavailable));
            }
            if cancel_ack_deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Err(self.break_control(super::FailureCategory::Timeout));
            }
            if pending_send.is_none()
                && (!cancel_started || cancel_acknowledged)
                && let Some(result) = terminal.take()
            {
                return result;
            }
            if cancel_reason.is_none() && cancelled.is_cancelled() {
                request_cancel(
                    CancelReason::User,
                    &mut cancel_reason,
                    &mut cancel_delivery_deadline,
                );
            }
            if cancel_reason.is_none() && manager_cancelled.token.is_cancelled() {
                request_cancel(
                    manager_cancelled.reason(),
                    &mut cancel_reason,
                    &mut cancel_delivery_deadline,
                );
            }
            if cancel_reason.is_none() && output.is_closed() {
                request_cancel(
                    CancelReason::HandleDropped,
                    &mut cancel_reason,
                    &mut cancel_delivery_deadline,
                );
            }
            let flushed = if pending_send.is_some() {
                match self.kernel_mut().control.try_flush() {
                    Ok(flushed) => flushed,
                    Err(error) => return Err(self.fail_control(error)),
                }
            } else {
                false
            };
            if let Some(sending) = pending_send
                && flushed
            {
                if matches!(sending, PendingSend::Run) {
                    run_flushed = true;
                } else {
                    cancel_delivery_deadline = None;
                    let now = std::time::Instant::now();
                    cancel_ack_deadline =
                        Some(now.checked_add(CONTROL_CANCEL_TIMEOUT).unwrap_or(now));
                }
                pending_send = None;
            }
            if run_flushed
                && pending_send.is_none()
                && !cancel_started
                && let Some(reason) = cancel_reason.clone()
            {
                if let Err(error) =
                    self.kernel_mut()
                        .control
                        .start_send(Message::Request(Request::CancelCommand {
                            command_id,
                            reason,
                        }))
                {
                    return Err(self.fail_control(error));
                }
                pending_send = Some(PendingSend::Cancel);
                cancel_started = true;
            }
            if pending_send.is_none()
                && (!cancel_started || cancel_acknowledged)
                && let Some(result) = terminal.take()
            {
                return result;
            }
            if terminal.is_some() && (!cancel_started || cancel_acknowledged) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                continue;
            }
            let message = match self.kernel_mut().control.try_receive() {
                Ok(message) => message,
                Err(error) => return Err(self.fail_control(error)),
            };
            let Some(message) = message else {
                tokio::select! {
                    _ = cancelled.cancelled(), if cancel_reason.is_none() => {
                        request_cancel(
                            CancelReason::User,
                            &mut cancel_reason,
                            &mut cancel_delivery_deadline,
                        );
                    }
                    _ = manager_cancelled.cancelled(), if cancel_reason.is_none() => {
                        request_cancel(
                            manager_cancelled.reason(),
                            &mut cancel_reason,
                            &mut cancel_delivery_deadline,
                        );
                    }
                    _ = output.closed(), if cancel_reason.is_none() => {
                        request_cancel(
                            CancelReason::HandleDropped,
                            &mut cancel_reason,
                            &mut cancel_delivery_deadline,
                        );
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {}
                }
                continue;
            };
            let Message::Response(response) = message else {
                return Err(self.break_control(super::FailureCategory::Protocol));
            };
            match response {
                Response::CommandStarted { command_id: actual }
                    if actual == command_id && !started =>
                {
                    started = true;
                }
                Response::CommandCancelAcknowledged {
                    command_id: actual, ..
                } if actual == command_id && cancel_started && !cancel_acknowledged => {
                    cancel_acknowledged = true;
                    cancel_ack_deadline = None;
                }
                Response::CommandRejected {
                    command_id: actual,
                    category,
                } if actual == command_id && terminal.is_none() => {
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
                                    request_cancel(
                                        CancelReason::HandleDropped,
                                        &mut cancel_reason,
                                        &mut cancel_delivery_deadline,
                                    );
                                }
                            }
                            _ = cancelled.cancelled() => {
                                request_cancel(
                                    CancelReason::User,
                                    &mut cancel_reason,
                                    &mut cancel_delivery_deadline,
                                );
                            }
                            _ = manager_cancelled.cancelled() => {
                                request_cancel(
                                    manager_cancelled.reason(),
                                    &mut cancel_reason,
                                    &mut cancel_delivery_deadline,
                                );
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
                _ => return Err(self.break_control(super::FailureCategory::Protocol)),
            }
        }
    }

    fn prepare_step(&mut self, event: &[u8]) -> Result<StepFilesId, ExecutionDomainError> {
        use super::protocol::{Request, Response};
        let id = StepFilesId::new();
        match self.kernel_mut().control.request(Request::PrepareStep {
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
            .kernel_mut()
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

    #[cfg(test)]
    fn shutdown(&mut self) -> Result<(), ExecutionDomainError> {
        use super::protocol::{Request, Response};
        match self.kernel_mut().control.request(Request::Shutdown {
            reason: CancelReason::Shutdown,
        })? {
            Response::ShuttingDown => Ok(()),
            Response::Rejected { category } => Err(backend_failure(category)),
            _ => Err(backend_failure(super::FailureCategory::Protocol)),
        }
    }

    fn destroy(
        &mut self,
        _attempt: AttemptIdentity,
    ) -> Result<DestroyReport, ExecutionDomainError> {
        if let Some(cleanup) = &mut self.cleanup {
            return cleanup.destroy();
        }
        #[cfg(not(test))]
        unreachable!("production Linux backend always owns a cleanup record");
        #[cfg(test)]
        {
            let _ = self.shutdown();
            let mut forced_kill = false;
            if self
                .kernel_mut()
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
                forced_kill = true;
                self.kernel_mut().launcher.kill().map_err(|error| {
                    ExecutionDomainError::Backend {
                        attempt: None,
                        stage: super::Stage::Destroy,
                        category: super::FailureCategory::Io,
                        errno: error.raw_os_error(),
                    }
                })?;
                self.kernel_mut().launcher.wait().map_err(|error| {
                    ExecutionDomainError::Backend {
                        attempt: None,
                        stage: super::Stage::Destroy,
                        category: super::FailureCategory::Io,
                        errno: error.raw_os_error(),
                    }
                })?;
            }
            Ok(DestroyReport {
                attempt: _attempt,
                forced_kill,
            })
        }
    }
}

#[cfg(test)]
#[path = "manager_test.rs"]
mod manager_test;
