#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod cleanup;
#[cfg(all(target_os = "linux", test))]
#[path = "cleanup_test.rs"]
mod cleanup_test;
mod destroy;
#[cfg(test)]
#[path = "destroy_test.rs"]
mod destroy_test;
#[cfg(target_os = "linux")]
pub(super) mod dirfd;
#[cfg(target_os = "linux")]
mod hardening;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
pub(super) mod launcher;
#[cfg(all(target_os = "linux", test))]
#[path = "launcher_test.rs"]
mod launcher_test;
pub(super) mod rootfs;
#[cfg(target_os = "linux")]
mod step_files;

#[cfg(target_os = "linux")]
pub(super) fn internal_entry() -> Option<i32> {
    cleanup::internal_entry().or_else(launcher::internal_entry)
}

#[cfg(all(target_os = "linux", test))]
#[path = "rootfs_test.rs"]
mod rootfs_test;

#[cfg(all(target_os = "linux", test))]
#[path = "cgroup_test.rs"]
mod cgroup_test;

#[cfg(all(target_os = "linux", test))]
#[path = "dirfd_test.rs"]
mod dirfd_test;

#[cfg(target_os = "linux")]
pub(in crate::job::execution_domain) struct StrictBackendBuilder {
    cgroup: cgroup::AttemptCgroup,
    launch: launcher::LaunchSpec,
    mapped_cleanup: Option<(cleanup::MappedIdRange, cleanup::CleanupWorkerConfig)>,
    runtime_socket: Option<cleanup::RuntimeSocketCapability>,
}

#[cfg(target_os = "linux")]
pub(in crate::job::execution_domain) struct StrictCleanupRecord {
    attempt: super::AttemptIdentity,
    kernel: Option<launcher::KernelDomain>,
    cgroup: cgroup::AttemptCgroup,
    active_root: dirfd::BoundDir,
    attempt_name: std::ffi::CString,
    attempt_root: dirfd::BoundDir,
    rootfs: dirfd::BoundDir,
    rootlesskit_state: dirfd::BoundDir,
    rootlesskit_socket: Option<cleanup::RuntimeSocketCapability>,
    writable_roots: Vec<(cleanup::CleanupRootKind, dirfd::BoundDir)>,
    mapped_cleanup: Option<(cleanup::MappedIdRange, cleanup::CleanupWorkerConfig)>,
    runtime_socket: Option<cleanup::RuntimeSocketCapability>,
    lifecycle: Option<super::journal::DomainLifecycle>,
    admission_closed: bool,
    handles_closed: bool,
    external_revocation_proven: bool,
    destroy_report: Option<super::DestroyReport>,
    created_stages: Vec<CreatedStage>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreatedStage {
    AttemptCgroup,
    AttemptFilesystem,
    LifecycleJournal,
    RuntimeSocket,
    KernelDomain,
    RootlessKitSocket,
    Evacuated,
    Ready,
}

#[cfg(target_os = "linux")]
pub(in crate::job::execution_domain) struct StrictBackendParts {
    pub cleanup: StrictCleanupRecord,
    pub path_mappings: Vec<(std::path::PathBuf, super::DomainPath)>,
}

#[cfg(target_os = "linux")]
pub(in crate::job::execution_domain) struct StrictProvisionFailure {
    error: super::ExecutionDomainError,
    quarantine: bool,
}

#[cfg(target_os = "linux")]
impl StrictProvisionFailure {
    pub(in crate::job::execution_domain) fn quarantine(&self) -> bool {
        self.quarantine
    }

    pub(in crate::job::execution_domain) fn into_error(self) -> super::ExecutionDomainError {
        self.error
    }
}

#[cfg(target_os = "linux")]
impl From<super::ExecutionDomainError> for StrictProvisionFailure {
    fn from(error: super::ExecutionDomainError) -> Self {
        Self {
            error,
            quarantine: true,
        }
    }
}

#[cfg(target_os = "linux")]
fn rollback_partial_cgroup(
    cgroup: &cgroup::AttemptCgroup,
    source: super::ExecutionDomainError,
) -> StrictProvisionFailure {
    // Before the attempt/rootfs bindings are proven there is deliberately no
    // pathname fallback. We can still discharge the exact retained cgroup
    // capability, but the attempt is quarantined because filesystem absence
    // could not be proven.
    let error = match cgroup.remove() {
        Ok(()) => source,
        Err(cleanup) => super::ExecutionDomainError::LifecycleAndDestroyFailed {
            lifecycle: Box::new(source),
            destroy: Box::new(cleanup),
        },
    };
    StrictProvisionFailure {
        error,
        quarantine: true,
    }
}

#[cfg(target_os = "linux")]
impl StrictBackendBuilder {
    #[expect(
        dead_code,
        reason = "constructed by the private C1 activation seam after endpoint installation"
    )]
    pub(in crate::job::execution_domain) fn new(
        cgroup: cgroup::AttemptCgroup,
        launch: launcher::LaunchSpec,
        mapped_ids: cleanup::IdMapSpec,
        worker: cleanup::CleanupWorkerConfig,
    ) -> Self {
        Self {
            cgroup,
            launch,
            mapped_cleanup: Some((mapped_ids.range(), worker)),
            runtime_socket: None,
        }
    }

    #[expect(
        dead_code,
        reason = "Plan C supplies the retained socket identity at its private activation seam"
    )]
    pub(in crate::job::execution_domain) fn with_runtime_socket(
        mut self,
        runtime_socket: cleanup::RuntimeSocketCapability,
    ) -> Self {
        self.runtime_socket = Some(runtime_socket);
        self
    }

    pub(in crate::job::execution_domain) fn build(
        self,
    ) -> Result<StrictBackendParts, StrictProvisionFailure> {
        let StrictBackendBuilder {
            cgroup,
            launch,
            mapped_cleanup,
            runtime_socket,
        } = self;
        let pre_record = (|| {
            let attempt_path = launch
                .rootfs
                .staging_root
                .parent()
                .ok_or_else(|| destroy::failure(super::FailureCategory::InvalidInput))?
                .to_owned();
            let active_path = attempt_path
                .parent()
                .ok_or_else(|| destroy::failure(super::FailureCategory::InvalidInput))?
                .to_owned();
            let attempt_name = std::ffi::CString::new(launch.attempt.component())
                .map_err(|_| destroy::failure(super::FailureCategory::InvalidInput))?;
            use std::os::unix::ffi::OsStrExt;
            if attempt_path
                .file_name()
                .is_none_or(|name| name.as_bytes() != attempt_name.as_c_str().to_bytes())
            {
                return Err(destroy::failure(super::FailureCategory::IdentityMismatch));
            }
            let active_root = dirfd::BoundDir::open_root(&active_path)?;
            let attempt_root = active_root.child(&attempt_name)?;
            let rootlesskit_state = dirfd::BoundDir::open_root(&launch.state_directory)?;
            Ok((
                attempt_path,
                attempt_name,
                active_root,
                attempt_root,
                rootlesskit_state,
            ))
        })();
        let (attempt_path, attempt_name, active_root, attempt_root, rootlesskit_state) =
            match pre_record {
                Ok(prepared) => prepared,
                Err(error) => return Err(rollback_partial_cgroup(&cgroup, error)),
            };
        let mut record = StrictCleanupRecord {
            attempt: launch.attempt,
            kernel: None,
            cgroup,
            active_root,
            attempt_name,
            attempt_root,
            rootfs: launch.bound_rootfs.clone_bound(),
            rootlesskit_state,
            rootlesskit_socket: None,
            writable_roots: Vec::new(),
            mapped_cleanup,
            runtime_socket,
            lifecycle: None,
            admission_closed: false,
            handles_closed: false,
            external_revocation_proven: true,
            destroy_report: None,
            created_stages: vec![CreatedStage::AttemptCgroup, CreatedStage::AttemptFilesystem],
        };
        record.lifecycle = match super::journal::DomainLifecycle::create_strict(
            &attempt_path,
            launch.attempt.uuid(),
        ) {
            Ok(lifecycle) => Some(lifecycle),
            Err(error) => return Err(record.rollback(error)),
        };
        record.created_stages.push(CreatedStage::LifecycleJournal);
        if record.runtime_socket.is_some() {
            // The capability may have been captured by Plan C before this
            // builder runs, but ownership becomes part of this transaction
            // only after its durable lifecycle record exists.
            record.created_stages.push(CreatedStage::RuntimeSocket);
        }
        if let Err(error) = cleanup::verify_empty_supplementary_groups() {
            return Err(record.rollback(error));
        }
        for input in &launch.rootfs.inputs {
            let Some(kind) = cleanup_kind(&input.target) else {
                continue;
            };
            let root = match dirfd::BoundDir::open_root(&input.source) {
                Ok(root) => root,
                Err(error) => return Err(record.rollback(error)),
            };
            record.writable_roots.push((kind, root));
        }
        let path_mappings = launch
            .rootfs
            .inputs
            .iter()
            .map(|input| (input.source.clone(), input.target.clone()))
            .collect();
        record.kernel = match launcher::launch(&record.cgroup, &launch) {
            Ok(kernel) => Some(kernel),
            Err(error) => return Err(record.rollback(error)),
        };
        record.rootlesskit_socket = match cleanup::RuntimeSocketCapability::capture(
            cleanup::RuntimeSocketRootKind::RootlessKitState,
            &record.rootlesskit_state,
            c"api.sock",
        ) {
            Ok(socket) => Some(socket),
            Err(error) => {
                // launch created the kernel domain even though its socket
                // capability could not be retained. The common rollback must
                // still neutralize that exact domain.
                record.created_stages.push(CreatedStage::KernelDomain);
                return Err(record.rollback(error));
            }
        };
        // Socket removal is allowed only after the kernel domain is dead, so
        // publish these two dependent capabilities in their teardown order.
        record.created_stages.push(CreatedStage::RootlessKitSocket);
        record.created_stages.push(CreatedStage::KernelDomain);
        let map = record
            .mapped_cleanup
            .as_ref()
            .map(|(map, _)| *map)
            .ok_or_else(|| {
                StrictProvisionFailure::from(destroy::failure(super::FailureCategory::NotReady))
            })?;
        if let Err(error) = cleanup::verify_rootlesskit_map(&record.rootlesskit_state, map) {
            return Err(record.rollback(error));
        }
        if let Err(error) = record.cgroup.finish_evacuation() {
            return Err(record.rollback(error));
        }
        record.created_stages.push(CreatedStage::Evacuated);
        if let Err(error) = record
            .lifecycle
            .as_mut()
            .ok_or_else(|| destroy::failure(super::FailureCategory::NotReady))
            .and_then(|lifecycle| lifecycle.transition(super::journal::DomainState::Ready))
        {
            return Err(record.rollback(error));
        }
        record.created_stages.push(CreatedStage::Ready);
        // Unpublished rollback is internally authorized. Once a handle may be
        // published, manager-side reader/capability revocation must explicitly
        // re-authorize destructive cleanup.
        record.external_revocation_proven = false;
        Ok(StrictBackendParts {
            cleanup: record,
            path_mappings,
        })
    }
}

#[cfg(target_os = "linux")]
impl StrictCleanupRecord {
    fn discharge_stage(
        &mut self,
        expected: CreatedStage,
    ) -> Result<(), super::ExecutionDomainError> {
        if !self.created_stages.contains(&expected) {
            // Retried destroy after a later stage failed.
            return Ok(());
        }
        if self.created_stages.last() != Some(&expected) {
            return Err(destroy::failure(super::FailureCategory::IdentityMismatch));
        }
        self.created_stages.pop();
        Ok(())
    }

    fn rollback(&mut self, source: super::ExecutionDomainError) -> StrictProvisionFailure {
        match self.destroy() {
            Ok(_) => StrictProvisionFailure {
                error: source,
                quarantine: false,
            },
            Err(destroy) => StrictProvisionFailure {
                error: super::ExecutionDomainError::LifecycleAndDestroyFailed {
                    lifecycle: Box::new(source),
                    destroy: Box::new(destroy),
                },
                quarantine: true,
            },
        }
    }

    #[cfg(test)]
    pub(in crate::job::execution_domain) fn kernel(&self) -> &launcher::KernelDomain {
        self.kernel
            .as_ref()
            .expect("kernel handle closed only by destroy")
    }

    pub(in crate::job::execution_domain) fn kernel_mut(&mut self) -> &mut launcher::KernelDomain {
        self.kernel
            .as_mut()
            .expect("kernel handle closed only by destroy")
    }

    pub(in crate::job::execution_domain) fn authorize_external_revocation(&mut self) {
        self.external_revocation_proven = true;
    }

    pub(in crate::job::execution_domain) fn mark_running(
        &mut self,
    ) -> Result<(), super::ExecutionDomainError> {
        self.lifecycle
            .as_mut()
            .ok_or_else(|| destroy::failure(super::FailureCategory::NotReady))?
            .transition(super::journal::DomainState::Running)
    }

    pub(in crate::job::execution_domain) fn mark_cleaning(
        &mut self,
    ) -> Result<(), super::ExecutionDomainError> {
        self.lifecycle
            .as_mut()
            .ok_or_else(|| destroy::failure(super::FailureCategory::NotReady))?
            .transition(super::journal::DomainState::Cleaning)
    }

    pub(in crate::job::execution_domain) fn destroy(
        &mut self,
    ) -> Result<super::DestroyReport, super::ExecutionDomainError> {
        if let Some(report) = &self.destroy_report {
            return Ok(report.clone());
        }
        let result =
            destroy::destroy_kernel(self, self.attempt, destroy::ShutdownBounds::default());
        if result.is_err()
            && let Some(lifecycle) = &mut self.lifecycle
            && lifecycle.state() == super::journal::DomainState::Destroying
        {
            let _ = lifecycle.transition(super::journal::DomainState::Quarantined);
        }
        if let Ok(report) = &result {
            self.destroy_report = Some(report.clone());
        }
        result
    }
}

#[cfg(target_os = "linux")]
impl destroy::DestroyOps for StrictCleanupRecord {
    fn close_admission(&mut self) -> Result<(), super::ExecutionDomainError> {
        self.admission_closed = true;
        if self.external_revocation_proven {
            Ok(())
        } else {
            Err(destroy::failure(super::FailureCategory::Unavailable))
        }
    }

    fn persist_destroying(&mut self) -> Result<(), super::ExecutionDomainError> {
        let lifecycle = self
            .lifecycle
            .as_mut()
            .ok_or_else(|| destroy::failure(super::FailureCategory::NotReady))?;
        match lifecycle.state() {
            super::journal::DomainState::Destroying => Ok(()),
            super::journal::DomainState::Destroyed => Ok(()),
            _ => lifecycle.transition(super::journal::DomainState::Destroying),
        }?;
        self.discharge_stage(CreatedStage::Ready)?;
        self.discharge_stage(CreatedStage::Evacuated)
    }

    fn graceful_shutdown(
        &mut self,
        deadline: std::time::Instant,
    ) -> Result<(), super::ExecutionDomainError> {
        use super::protocol::{Message, Request, Response};
        let Some(kernel) = self.kernel.as_mut() else {
            return Ok(());
        };
        kernel.control.send(
            Message::Request(Request::Shutdown {
                reason: super::CancelReason::Shutdown,
            }),
            deadline,
        )?;
        match kernel.control.receive(deadline)? {
            Message::Response(Response::ShuttingDown) => Ok(()),
            _ => Err(destroy::failure(super::FailureCategory::Protocol)),
        }
    }

    fn term_members(
        &mut self,
        _deadline: std::time::Instant,
    ) -> Result<(), super::ExecutionDomainError> {
        self.cgroup.term()
    }

    fn recursively_empty_until(
        &mut self,
        deadline: std::time::Instant,
    ) -> Result<bool, super::ExecutionDomainError> {
        self.cgroup.recursively_empty_until(deadline)
    }

    fn kill_all(&mut self) -> Result<(), super::ExecutionDomainError> {
        self.cgroup.kill()
    }

    fn reap_launcher(
        &mut self,
        deadline: std::time::Instant,
    ) -> Result<(), super::ExecutionDomainError> {
        let Some(kernel) = self.kernel.as_mut() else {
            return Ok(());
        };
        loop {
            if kernel
                .launcher
                .try_wait()
                .map_err(destroy_io_failure)?
                .is_some()
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(destroy::failure(super::FailureCategory::Timeout));
            }
            std::thread::sleep(
                std::time::Duration::from_millis(10)
                    .min(deadline.saturating_duration_since(std::time::Instant::now())),
            );
        }
    }

    fn drain_diagnostics(
        &mut self,
        _deadline: std::time::Instant,
    ) -> Result<(), super::ExecutionDomainError> {
        // The launcher owns null stdout/stderr. Init command output is drained
        // by the correlated control protocol before domain destruction starts.
        Ok(())
    }

    fn close_handles(&mut self) -> Result<(), super::ExecutionDomainError> {
        if let Some(mut kernel) = self.kernel.take() {
            kernel.control.abort();
            if kernel
                .launcher
                .try_wait()
                .map_err(destroy_io_failure)?
                .is_none()
            {
                self.kernel = Some(kernel);
                return Err(destroy::failure(super::FailureCategory::Unavailable));
            }
        }
        self.handles_closed = true;
        self.discharge_stage(CreatedStage::KernelDomain)
    }

    fn prove_no_mounts(&mut self) -> Result<(), super::ExecutionDomainError> {
        if !self.handles_closed {
            return Err(destroy::failure(super::FailureCategory::Unavailable));
        }
        self.active_root.verify_binding()?;
        self.attempt_root.verify_binding()?;
        self.rootfs.verify_binding()?;
        prove_no_mount_below(self.attempt_root.root_path())
    }

    fn remove_runtime_socket(&mut self) -> Result<(), super::ExecutionDomainError> {
        if let Some(socket) = self.rootlesskit_socket.as_ref() {
            socket.remove()?;
            self.rootlesskit_socket = None;
        } else {
            self.rootlesskit_state.refuse_entry(c"api.sock")?;
        }
        self.discharge_stage(CreatedStage::RootlessKitSocket)?;
        if let Some(socket) = self.runtime_socket.as_ref() {
            socket.remove()?;
            self.runtime_socket = None;
            return self.discharge_stage(CreatedStage::RuntimeSocket);
        }
        if let Some((_, run)) = self
            .writable_roots
            .iter()
            .find(|(kind, _)| *kind == cleanup::CleanupRootKind::Run)
        {
            run.refuse_entry(c"docker.sock")?;
        }
        self.discharge_stage(CreatedStage::RuntimeSocket)
    }

    fn remove_filesystem(&mut self) -> Result<(), super::ExecutionDomainError> {
        if let Some((map, worker)) = self.mapped_cleanup.as_ref() {
            let roots = self
                .writable_roots
                .iter()
                .map(|(kind, root)| cleanup::PinnedCleanupRoot::from_bound(*kind, root))
                .collect::<Result<Vec<_>, _>>()?;
            cleanup::MappedCleanupAuthority::new(*map, roots)?
                .with_worker(worker.clone())
                .cleanup(self.attempt, &self.cgroup, &self.active_root)?;
        }
        self.active_root.remove_tree(&self.attempt_name)?;
        self.discharge_stage(CreatedStage::LifecycleJournal)?;
        self.discharge_stage(CreatedStage::AttemptFilesystem)
    }

    fn remove_cgroup(&mut self) -> Result<(), super::ExecutionDomainError> {
        self.cgroup.remove()?;
        self.discharge_stage(CreatedStage::AttemptCgroup)
    }

    fn fsync_root(&mut self) -> Result<(), super::ExecutionDomainError> {
        self.active_root.sync_directory()
    }

    fn mark_destroyed(&mut self) -> Result<(), super::ExecutionDomainError> {
        self.lifecycle
            .as_mut()
            .ok_or_else(|| destroy::failure(super::FailureCategory::NotReady))?
            .complete_destroyed()?;
        if !self.created_stages.is_empty() {
            return Err(destroy::failure(super::FailureCategory::IdentityMismatch));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn destroy_io_failure(error: std::io::Error) -> super::ExecutionDomainError {
    super::ExecutionDomainError::Backend {
        attempt: None,
        stage: super::Stage::Destroy,
        category: super::FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}

#[cfg(target_os = "linux")]
fn prove_no_mount_below(path: &std::path::Path) -> Result<(), super::ExecutionDomainError> {
    use std::os::unix::ffi::OsStrExt;
    let expected = path.as_os_str().as_bytes();
    let mountinfo = std::fs::read("/proc/self/mountinfo").map_err(destroy_io_failure)?;
    for line in mountinfo.split(|byte| *byte == b'\n') {
        let Some(field) = line.split(|byte| *byte == b' ').nth(4) else {
            continue;
        };
        let mountpoint = unescape_mountinfo(field)?;
        if mountpoint == expected
            || mountpoint
                .strip_prefix(expected)
                .is_some_and(|suffix| suffix.starts_with(b"/"))
        {
            return Err(destroy::failure(super::FailureCategory::Unavailable));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unescape_mountinfo(value: &[u8]) -> Result<Vec<u8>, super::ExecutionDomainError> {
    let mut output = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'\\' {
            output.push(value[index]);
            index += 1;
            continue;
        }
        let digits = value
            .get(index + 1..index + 4)
            .ok_or_else(|| destroy::failure(super::FailureCategory::IdentityMismatch))?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(destroy::failure(super::FailureCategory::IdentityMismatch));
        }
        let decoded = (digits[0] - b'0') * 64 + (digits[1] - b'0') * 8 + digits[2] - b'0';
        output.push(decoded);
        index += 4;
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn cleanup_kind(path: &super::DomainPath) -> Option<cleanup::CleanupRootKind> {
    use cleanup::CleanupRootKind;
    match path.as_str() {
        "/work" => Some(CleanupRootKind::Work),
        "/tmp" => Some(CleanupRootKind::Tmp),
        "/home/chimera" => Some(CleanupRootKind::Home),
        "/run/chimera" => Some(CleanupRootKind::Run),
        "/home/chimera/.docker" => Some(CleanupRootKind::DockerConfig),
        "/var/lib/chimera/docker" => Some(CleanupRootKind::DockerData),
        "/run/chimera/docker-exec" => Some(CleanupRootKind::DockerExec),
        _ => None,
    }
}
