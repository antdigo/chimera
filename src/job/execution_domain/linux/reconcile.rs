use std::collections::BTreeSet;

use uuid::Uuid;

use super::super::{AttemptIdentity, ExecutionDomainError, FailureCategory};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct Inventory {
    pub attempt_directories: BTreeSet<AttemptIdentity>,
    pub cleanup_directories: BTreeSet<AttemptIdentity>,
    pub attempt_cgroups: BTreeSet<AttemptIdentity>,
    pub cleanup_cgroups: BTreeSet<AttemptIdentity>,
    pub attempts: BTreeSet<AttemptIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OwnedKind {
    Attempt,
    Cleanup,
}

impl Inventory {
    fn is_empty(&self) -> bool {
        self.attempt_directories.is_empty()
            && self.cleanup_directories.is_empty()
            && self.attempt_cgroups.is_empty()
            && self.cleanup_cgroups.is_empty()
            && self.attempts.is_empty()
    }
}

#[cfg(test)]
pub(super) fn owned_attempts(
    directory_names: &[String],
    cgroup_names: &[String],
) -> Result<Vec<AttemptIdentity>, ExecutionDomainError> {
    let mut attempts = BTreeSet::new();
    for name in directory_names {
        attempts.insert(parse_owned_name(name, true)?.1);
    }
    for name in cgroup_names {
        if name == "supervisor" {
            continue;
        }
        attempts.insert(parse_owned_name(name, false)?.1);
    }
    Ok(attempts.into_iter().collect())
}

fn parse_component(value: &str) -> Result<AttemptIdentity, ExecutionDomainError> {
    if value.len() != 32
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(invalid_inventory());
    }
    let uuid = Uuid::parse_str(value).map_err(|_| invalid_inventory())?;
    let attempt = AttemptIdentity::from_uuid(uuid)?;
    if attempt.component() != value {
        return Err(invalid_inventory());
    }
    Ok(attempt)
}

pub(super) fn parse_owned_name(
    value: &str,
    directory: bool,
) -> Result<(OwnedKind, AttemptIdentity), ExecutionDomainError> {
    if directory {
        if let Some(component) = value.strip_prefix("cleanup-") {
            return parse_component(component).map(|attempt| (OwnedKind::Cleanup, attempt));
        }
        return parse_component(value).map(|attempt| (OwnedKind::Attempt, attempt));
    }
    if let Some(component) = value.strip_prefix("attempt-") {
        return parse_component(component).map(|attempt| (OwnedKind::Attempt, attempt));
    }
    if let Some(component) = value.strip_prefix("cleanup-") {
        return parse_component(component).map(|attempt| (OwnedKind::Cleanup, attempt));
    }
    Err(invalid_inventory())
}

pub(super) trait ReconcileOps {
    fn neutralize_cleanup(&mut self, attempt: AttemptIdentity) -> Result<(), ExecutionDomainError>;
    fn neutralize_attempt(&mut self, attempt: AttemptIdentity) -> Result<(), ExecutionDomainError>;
    fn prove_filesystem(&mut self, attempt: AttemptIdentity) -> Result<(), ExecutionDomainError>;
    fn remove_cleanup_cgroup(
        &mut self,
        attempt: AttemptIdentity,
    ) -> Result<(), ExecutionDomainError>;
    fn remove_cleanup_bootstrap(
        &mut self,
        attempt: AttemptIdentity,
    ) -> Result<(), ExecutionDomainError>;
    fn remove_attempt_filesystem(
        &mut self,
        attempt: AttemptIdentity,
    ) -> Result<(), ExecutionDomainError>;
    fn remove_attempt_cgroup(
        &mut self,
        attempt: AttemptIdentity,
    ) -> Result<(), ExecutionDomainError>;
    fn fsync_active_root(&mut self) -> Result<(), ExecutionDomainError>;
    fn reinventory(&mut self) -> Result<Inventory, ExecutionDomainError>;
}

#[cfg(test)]
pub(super) fn reconcile_inventory<O: ReconcileOps>(
    inventory: &Inventory,
    operations: &mut O,
) -> Result<(), ExecutionDomainError> {
    reconcile_inventory_with_error(inventory, operations, None)
}

fn reconcile_inventory_with_error<O: ReconcileOps>(
    inventory: &Inventory,
    operations: &mut O,
    mut first_error: Option<ExecutionDomainError>,
) -> Result<(), ExecutionDomainError> {
    for attempt in &inventory.cleanup_cgroups {
        retain_first(&mut first_error, operations.neutralize_cleanup(*attempt));
    }
    for attempt in &inventory.attempt_cgroups {
        retain_first(&mut first_error, operations.neutralize_attempt(*attempt));
    }
    if let Some(error) = first_error {
        return Err(error);
    }

    for attempt in &inventory.attempt_directories {
        retain_first(&mut first_error, operations.prove_filesystem(*attempt));
    }
    if let Some(error) = first_error {
        return Err(error);
    }

    for attempt in &inventory.cleanup_cgroups {
        operations.remove_cleanup_cgroup(*attempt)?;
    }
    for attempt in &inventory.cleanup_directories {
        operations.remove_cleanup_bootstrap(*attempt)?;
    }
    for attempt in &inventory.attempt_directories {
        operations.remove_attempt_filesystem(*attempt)?;
    }
    for attempt in &inventory.attempt_cgroups {
        operations.remove_attempt_cgroup(*attempt)?;
    }
    operations.fsync_active_root()?;
    if !operations.reinventory()?.is_empty() {
        return Err(invalid_inventory());
    }
    Ok(())
}

fn retain_first(
    first: &mut Option<ExecutionDomainError>,
    result: Result<(), ExecutionDomainError>,
) {
    if let Err(error) = result
        && first.is_none()
    {
        *first = Some(error);
    }
}

fn invalid_inventory() -> ExecutionDomainError {
    super::destroy::failure(FailureCategory::IdentityMismatch)
}

#[cfg(target_os = "linux")]
mod native {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::storage::RootLockProof;

    use super::super::cgroup::{CgroupFilesystem, CgroupRoot, RecoveredCgroup};
    use super::super::dirfd::{self, BoundDir};
    use crate::job::execution_domain::journal::{LinuxJournalEvidence, inspect_linux_journal};

    const RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);

    pub(in crate::job::execution_domain) struct LinuxReconcileContext {
        inner: Box<dyn ContextOps>,
        active_path: std::path::PathBuf,
    }

    impl std::fmt::Debug for LinuxReconcileContext {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("LinuxReconcileContext")
        }
    }

    impl LinuxReconcileContext {
        #[cfg(test)]
        pub(in crate::job::execution_domain) fn from_root_lock<F: CgroupFilesystem>(
            lock: RootLockProof,
            cgroups: CgroupRoot<F>,
        ) -> Result<Self, ExecutionDomainError> {
            let root = BoundDir::from_pinned_root(
                lock.try_clone_root().map_err(storage_error)?,
                lock.root_path().to_owned(),
            )?;
            let active = root.child(c"job-resources")?;
            active.verify_private_directory()?;
            let active_path = lock.root_path().join("job-resources");
            Ok(Self {
                inner: Box::new(LockedContext {
                    lock,
                    active,
                    cgroups,
                }),
                active_path,
            })
        }

        pub(in crate::job::execution_domain) fn reconcile(
            &self,
        ) -> Result<(), ExecutionDomainError> {
            self.inner.reconcile()
        }

        #[cfg(test)]
        pub(in crate::job::execution_domain) fn active_path(&self) -> std::path::PathBuf {
            self.active_path.clone()
        }
    }

    trait ContextOps: Send + Sync {
        fn reconcile(&self) -> Result<(), ExecutionDomainError>;
    }

    struct LockedContext<F: CgroupFilesystem> {
        lock: RootLockProof,
        active: BoundDir,
        cgroups: CgroupRoot<F>,
    }

    impl<F: CgroupFilesystem> ContextOps for LockedContext<F> {
        fn reconcile(&self) -> Result<(), ExecutionDomainError> {
            reconcile_locked(&self.lock, &self.active, &self.cgroups)
        }
    }

    struct LinuxOperations<'a, F: CgroupFilesystem> {
        active: &'a BoundDir,
        cgroups: &'a CgroupRoot<F>,
        directories: BTreeMap<AttemptIdentity, BoundDir>,
        cleanup_directories: BTreeMap<AttemptIdentity, BoundDir>,
        attempt_cgroups: BTreeMap<AttemptIdentity, RecoveredCgroup<F>>,
        cleanup_cgroups: BTreeMap<AttemptIdentity, RecoveredCgroup<F>>,
    }

    pub(super) fn reconcile_locked<F: CgroupFilesystem>(
        lock: &RootLockProof,
        active: &BoundDir,
        cgroups: &CgroupRoot<F>,
    ) -> Result<(), ExecutionDomainError> {
        let _single_flight = lock.lock_reconciliation();
        active.verify_private_directory()?;
        let (inventory, mut operations, first_error) = inventory(active, cgroups)?;
        reconcile_inventory_with_error(&inventory, &mut operations, first_error)
    }

    fn inventory<'a, F: CgroupFilesystem>(
        active: &'a BoundDir,
        cgroups: &'a CgroupRoot<F>,
    ) -> Result<
        (
            Inventory,
            LinuxOperations<'a, F>,
            Option<ExecutionDomainError>,
        ),
        ExecutionDomainError,
    > {
        let mut found = Inventory::default();
        let mut directories = BTreeMap::new();
        let mut cleanup_directories = BTreeMap::new();
        let mut first_error = None;
        for name in dirfd::directory_entries(active.fd())? {
            let value = match name.to_str() {
                Ok(value) => value,
                Err(_) => {
                    retain_error(&mut first_error, invalid_inventory());
                    continue;
                }
            };
            let (kind, attempt) = match parse_owned_name(value, true) {
                Ok(owned) => owned,
                Err(error) => {
                    retain_error(&mut first_error, error);
                    continue;
                }
            };
            let directory = match active.child(&name) {
                Ok(directory) => directory,
                Err(error) => {
                    retain_error(&mut first_error, error);
                    continue;
                }
            };
            if let Err(error) = directory.verify_private_directory() {
                retain_error(&mut first_error, error);
                continue;
            }
            found.attempts.insert(attempt);
            match kind {
                OwnedKind::Attempt => {
                    found.attempt_directories.insert(attempt);
                    directories.insert(attempt, directory);
                }
                OwnedKind::Cleanup => {
                    found.cleanup_directories.insert(attempt);
                    cleanup_directories.insert(attempt, directory);
                }
            }
        }
        let cgroup_inventory = cgroups.recovery_inventory()?;
        retain_optional(&mut first_error, cgroup_inventory.first_error);
        let mut attempt_cgroups = BTreeMap::new();
        let mut cleanup_cgroups = BTreeMap::new();
        for entry in cgroup_inventory.entries {
            found.attempts.insert(entry.attempt);
            match entry.kind {
                OwnedKind::Attempt => {
                    found.attempt_cgroups.insert(entry.attempt);
                    attempt_cgroups.insert(entry.attempt, entry);
                }
                OwnedKind::Cleanup => {
                    found.cleanup_cgroups.insert(entry.attempt);
                    cleanup_cgroups.insert(entry.attempt, entry);
                }
            }
        }
        Ok((
            found,
            LinuxOperations {
                active,
                cgroups,
                directories,
                cleanup_directories,
                attempt_cgroups,
                cleanup_cgroups,
            },
            first_error,
        ))
    }

    impl<F: CgroupFilesystem> ReconcileOps for LinuxOperations<'_, F> {
        fn neutralize_cleanup(
            &mut self,
            attempt: AttemptIdentity,
        ) -> Result<(), ExecutionDomainError> {
            neutralize(required_mut(&mut self.cleanup_cgroups, attempt)?)
        }

        fn neutralize_attempt(
            &mut self,
            attempt: AttemptIdentity,
        ) -> Result<(), ExecutionDomainError> {
            neutralize(required_mut(&mut self.attempt_cgroups, attempt)?)
        }

        fn prove_filesystem(
            &mut self,
            attempt: AttemptIdentity,
        ) -> Result<(), ExecutionDomainError> {
            let directory = required(&self.directories, attempt)?;
            match inspect_linux_journal(directory, attempt)? {
                LinuxJournalEvidence::Recoverable(_) => {}
                LinuxJournalEvidence::Missing => directory.verify_empty_partial_attempt()?,
                LinuxJournalEvidence::TrustedV1Diagnostic => return Err(invalid_inventory()),
            }
            directory.verify_attempt_removal_tree()?;
            let path = self.active.root_path().join(attempt.component());
            super::super::prove_no_mount_below(&path)
        }

        fn remove_cleanup_cgroup(
            &mut self,
            attempt: AttemptIdentity,
        ) -> Result<(), ExecutionDomainError> {
            required_mut(&mut self.cleanup_cgroups, attempt)?.remove()
        }

        fn remove_cleanup_bootstrap(
            &mut self,
            attempt: AttemptIdentity,
        ) -> Result<(), ExecutionDomainError> {
            let name = component("cleanup-", attempt)?;
            let directory = required(&self.cleanup_directories, attempt)?;
            self.active.remove_created_child(&name, directory, &[])
        }

        fn remove_attempt_filesystem(
            &mut self,
            attempt: AttemptIdentity,
        ) -> Result<(), ExecutionDomainError> {
            self.active.remove_tree(&component("", attempt)?)
        }

        fn remove_attempt_cgroup(
            &mut self,
            attempt: AttemptIdentity,
        ) -> Result<(), ExecutionDomainError> {
            required_mut(&mut self.attempt_cgroups, attempt)?.remove()
        }

        fn fsync_active_root(&mut self) -> Result<(), ExecutionDomainError> {
            self.active.sync_directory()
        }

        fn reinventory(&mut self) -> Result<Inventory, ExecutionDomainError> {
            let (inventory, _, first_error) = inventory(self.active, self.cgroups)?;
            if let Some(error) = first_error {
                return Err(error);
            }
            Ok(inventory)
        }
    }

    fn neutralize<F: CgroupFilesystem>(
        cgroup: &mut RecoveredCgroup<F>,
    ) -> Result<(), ExecutionDomainError> {
        let deadline = Instant::now()
            .checked_add(RECOVERY_TIMEOUT)
            .ok_or_else(invalid_inventory)?;
        cgroup.neutralize_until(deadline)
    }

    fn component(prefix: &str, attempt: AttemptIdentity) -> Result<CString, ExecutionDomainError> {
        CString::new(format!("{prefix}{}", attempt.component())).map_err(|_| invalid_inventory())
    }

    fn required<T>(
        values: &BTreeMap<AttemptIdentity, T>,
        attempt: AttemptIdentity,
    ) -> Result<&T, ExecutionDomainError> {
        values.get(&attempt).ok_or_else(invalid_inventory)
    }

    fn required_mut<T>(
        values: &mut BTreeMap<AttemptIdentity, T>,
        attempt: AttemptIdentity,
    ) -> Result<&mut T, ExecutionDomainError> {
        values.get_mut(&attempt).ok_or_else(invalid_inventory)
    }

    fn retain_optional(
        first: &mut Option<ExecutionDomainError>,
        error: Option<ExecutionDomainError>,
    ) {
        if let Some(error) = error {
            retain_error(first, error);
        }
    }

    fn retain_error(first: &mut Option<ExecutionDomainError>, error: ExecutionDomainError) {
        if first.is_none() {
            *first = Some(error);
        }
    }

    #[cfg(test)]
    fn storage_error(error: std::io::Error) -> ExecutionDomainError {
        ExecutionDomainError::Backend {
            attempt: None,
            stage: crate::job::execution_domain::Stage::Filesystem,
            category: FailureCategory::Io,
            errno: error.raw_os_error(),
        }
    }
}

#[cfg(target_os = "linux")]
pub(in crate::job::execution_domain) use native::LinuxReconcileContext;
