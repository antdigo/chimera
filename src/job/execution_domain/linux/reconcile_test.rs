use std::collections::BTreeSet;

use uuid::Uuid;

use super::super::{AttemptIdentity, ExecutionDomainError, FailureCategory};
use super::reconcile::{Inventory, ReconcileOps, owned_attempts, reconcile_inventory};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::num::NonZeroUsize;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use super::cgroup::{CgroupFilesystem, CgroupRoot};
#[cfg(target_os = "linux")]
use crate::storage::RootLock;

fn attempt(value: u128) -> AttemptIdentity {
    AttemptIdentity::from_uuid(Uuid::from_u128(value)).unwrap()
}

#[test]
fn owned_attempts_unions_sorts_and_deduplicates_both_roots() {
    let first = attempt(1);
    let second = attempt(2);
    let found = owned_attempts(
        &[second.component(), first.component()],
        &[
            format!("attempt-{}", second.component()),
            format!("cleanup-{}", first.component()),
            "supervisor".to_owned(),
        ],
    )
    .unwrap();

    assert_eq!(found, vec![first, second]);
}

#[test]
fn owned_attempts_refuses_nil_noncanonical_traversal_and_unknown_names() {
    for name in [
        "00000000000000000000000000000000",
        "0000000000000000000000000000000A",
        "../outside",
        "not-an-attempt",
        "attempt-00000000000000000000000000000001",
    ] {
        assert!(owned_attempts(&[name.to_owned()], &[]).is_err(), "{name}");
    }
    for name in [
        "attempt-00000000000000000000000000000000",
        "attempt-0000000000000000000000000000000A",
        "cleanup-../outside",
        "not-an-attempt",
    ] {
        assert!(owned_attempts(&[], &[name.to_owned()]).is_err(), "{name}");
    }
}

#[derive(Default)]
struct FakeRecovery {
    events: Vec<String>,
    fail: Option<&'static str>,
    final_inventory: Inventory,
}

impl FakeRecovery {
    fn event(&mut self, value: String) -> Result<(), ExecutionDomainError> {
        self.events.push(value.clone());
        if self.fail == Some(value.as_str()) {
            return Err(super::destroy::failure(FailureCategory::Unavailable));
        }
        Ok(())
    }
}

impl ReconcileOps for FakeRecovery {
    fn neutralize_cleanup(&mut self, id: AttemptIdentity) -> Result<(), ExecutionDomainError> {
        self.event(format!("neutralize-cleanup-{}", id.component()))
    }

    fn neutralize_attempt(&mut self, id: AttemptIdentity) -> Result<(), ExecutionDomainError> {
        self.event(format!("neutralize-attempt-{}", id.component()))
    }

    fn prove_filesystem(&mut self, id: AttemptIdentity) -> Result<(), ExecutionDomainError> {
        self.event(format!("prove-filesystem-{}", id.component()))
    }

    fn remove_cleanup_bootstrap(
        &mut self,
        id: AttemptIdentity,
    ) -> Result<(), ExecutionDomainError> {
        self.event(format!("remove-cleanup-bootstrap-{}", id.component()))
    }

    fn remove_cleanup_cgroup(&mut self, id: AttemptIdentity) -> Result<(), ExecutionDomainError> {
        self.event(format!("remove-cleanup-cgroup-{}", id.component()))
    }

    fn remove_attempt_filesystem(
        &mut self,
        id: AttemptIdentity,
    ) -> Result<(), ExecutionDomainError> {
        self.event(format!("remove-filesystem-{}", id.component()))
    }

    fn remove_attempt_cgroup(&mut self, id: AttemptIdentity) -> Result<(), ExecutionDomainError> {
        self.event(format!("remove-cgroup-{}", id.component()))
    }

    fn fsync_active_root(&mut self) -> Result<(), ExecutionDomainError> {
        self.event("fsync-active".into())
    }

    fn reinventory(&mut self) -> Result<Inventory, ExecutionDomainError> {
        self.event("reinventoried".into())?;
        Ok(self.final_inventory.clone())
    }
}

#[test]
fn reconcile_neutralizes_all_cgroups_before_any_filesystem_mutation() {
    let first = attempt(1);
    let second = attempt(2);
    let inventory = Inventory {
        attempts: BTreeSet::from([first, second]),
        attempt_directories: BTreeSet::from([first, second]),
        attempt_cgroups: BTreeSet::from([first, second]),
        cleanup_directories: BTreeSet::from([first]),
        cleanup_cgroups: BTreeSet::from([first]),
    };
    let mut recovery = FakeRecovery::default();

    reconcile_inventory(&inventory, &mut recovery).unwrap();

    let first_filesystem = recovery
        .events
        .iter()
        .position(|event| event.starts_with("prove-filesystem"))
        .unwrap();
    assert!(
        recovery.events[..first_filesystem]
            .iter()
            .any(|event| event.starts_with("neutralize-attempt"))
    );
    assert_eq!(recovery.events.last().unwrap(), "reinventoried");
}

#[test]
fn reconcile_failure_never_mutates_filesystem_or_removes_cgroup() {
    let id = attempt(3);
    let inventory = Inventory {
        attempts: BTreeSet::from([id]),
        attempt_directories: BTreeSet::from([id]),
        attempt_cgroups: BTreeSet::from([id]),
        cleanup_directories: BTreeSet::new(),
        cleanup_cgroups: BTreeSet::new(),
    };
    let mut recovery = FakeRecovery {
        fail: Some("neutralize-attempt-00000000000000000000000000000003"),
        ..FakeRecovery::default()
    };

    assert!(reconcile_inventory(&inventory, &mut recovery).is_err());
    assert!(
        !recovery
            .events
            .iter()
            .any(|event| event.starts_with("remove-"))
    );
}

#[test]
fn reconcile_final_union_race_fails_closed() {
    let id = attempt(4);
    let inventory = Inventory {
        attempts: BTreeSet::from([id]),
        attempt_directories: BTreeSet::new(),
        attempt_cgroups: BTreeSet::from([id]),
        cleanup_directories: BTreeSet::new(),
        cleanup_cgroups: BTreeSet::new(),
    };
    let mut recovery = FakeRecovery {
        final_inventory: Inventory {
            attempts: BTreeSet::from([attempt(5)]),
            ..Inventory::default()
        },
        ..FakeRecovery::default()
    };

    assert!(reconcile_inventory(&inventory, &mut recovery).is_err());
}

#[test]
fn every_recovery_failure_stage_preserves_outside_canary() {
    let id = attempt(6);
    let inventory = Inventory {
        attempts: BTreeSet::from([id]),
        attempt_directories: BTreeSet::from([id]),
        attempt_cgroups: BTreeSet::from([id]),
        cleanup_directories: BTreeSet::from([id]),
        cleanup_cgroups: BTreeSet::from([id]),
    };
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("canary"), b"keep").unwrap();
    for stage in [
        "neutralize-cleanup-00000000000000000000000000000006",
        "neutralize-attempt-00000000000000000000000000000006",
        "prove-filesystem-00000000000000000000000000000006",
        "remove-cleanup-cgroup-00000000000000000000000000000006",
        "remove-cleanup-bootstrap-00000000000000000000000000000006",
        "remove-filesystem-00000000000000000000000000000006",
        "remove-cgroup-00000000000000000000000000000006",
        "fsync-active",
        "reinventoried",
    ] {
        let mut recovery = FakeRecovery {
            fail: Some(stage),
            ..FakeRecovery::default()
        };
        assert!(
            reconcile_inventory(&inventory, &mut recovery).is_err(),
            "{stage}"
        );
        assert_eq!(
            std::fs::read(outside.path().join("canary")).unwrap(),
            b"keep",
            "{stage}"
        );
    }
}

#[cfg(target_os = "linux")]
struct FixtureCgroupFs;

#[cfg(target_os = "linux")]
impl CgroupFilesystem for FixtureCgroupFs {
    fn verify_filesystem(&self, _fd: RawFd) -> io::Result<()> {
        Ok(())
    }

    fn remove(&self, parent: RawFd, name: &std::ffi::CStr, child: RawFd) -> io::Result<()> {
        let path = fs::read_link(format!("/proc/self/fd/{child}"))?;
        for entry in fs::read_dir(&path)? {
            fs::remove_file(entry?.path())?;
        }
        let result = unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(target_os = "linux")]
fn seed_cgroup_root(path: &std::path::Path) {
    for (name, value) in [
        ("cgroup.controllers", "cpu memory pids io"),
        ("cgroup.type", "domain"),
        ("cgroup.subtree_control", ""),
        ("cgroup.procs", ""),
        ("cgroup.events", "populated 0\n"),
        ("cgroup.kill", ""),
        ("memory.swap.max", "0"),
    ] {
        fs::write(path.join(name), value).unwrap();
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recovery_root_keeps_admission_closed_until_locked_reconcile_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(temp.path().join("job-resources")).unwrap();
    fs::set_permissions(
        temp.path().join("job-resources"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::create_dir(temp.path().join("cgroup")).unwrap();
    seed_cgroup_root(&temp.path().join("cgroup"));
    let lock = RootLock::acquire(temp.path()).unwrap();
    let proof = lock.reconciliation_proof().unwrap();
    let cgroups =
        CgroupRoot::open_with_filesystem(&temp.path().join("cgroup"), Arc::new(FixtureCgroupFs))
            .unwrap();
    let root = super::super::ExecutionDomainRoot::prepare_linux_recovery_for_test(
        proof,
        cgroups,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();

    assert!(root.reserve().await.is_err());
    root.reconcile().await.unwrap();
    assert!(root.reserve().await.is_ok());
    assert!(root.reconcile().await.is_err());
    assert!(root.reserve().await.is_ok());
    drop(lock);
}

#[cfg(target_os = "linux")]
struct PanickingCgroupFs(std::sync::atomic::AtomicBool);

#[cfg(target_os = "linux")]
impl CgroupFilesystem for PanickingCgroupFs {
    fn verify_filesystem(&self, _fd: RawFd) -> io::Result<()> {
        assert!(
            !self.0.load(std::sync::atomic::Ordering::Acquire),
            "injected blocking task panic"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct ObservedCgroupFs(std::sync::atomic::AtomicUsize);

#[cfg(target_os = "linux")]
impl CgroupFilesystem for ObservedCgroupFs {
    fn verify_filesystem(&self, _fd: RawFd) -> io::Result<()> {
        Ok(())
    }

    fn read(&self, file: &mut fs::File, name: &std::ffi::CStr) -> io::Result<String> {
        if name == c"cgroup.events" {
            let populated = usize::from(self.0.load(std::sync::atomic::Ordering::Acquire) == 0);
            return Ok(format!("populated {populated}\n"));
        }
        let mut text = String::new();
        std::io::Read::read_to_string(file, &mut text)?;
        Ok(text)
    }

    fn write(&self, _file: &mut fs::File, name: &std::ffi::CStr, _value: &str) -> io::Result<()> {
        if name == c"cgroup.kill" {
            self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        Ok(())
    }

    fn remove(&self, parent: RawFd, name: &std::ffi::CStr, child: RawFd) -> io::Result<()> {
        FixtureCgroupFs.remove(parent, name, child)
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn invalid_active_root_still_kills_independently_bound_attempt_cgroup() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    create_private(&temp.path().join("job-resources"));
    create_private(&temp.path().join("cgroup"));
    seed_cgroup_root(&temp.path().join("cgroup"));
    let id = attempt(36);
    let group = temp
        .path()
        .join("cgroup")
        .join(format!("attempt-{}", id.component()));
    create_private(&group);
    seed_cgroup_root(&group);
    let lock = RootLock::acquire(temp.path()).unwrap();
    let observed = Arc::new(ObservedCgroupFs(AtomicUsize::new(0)));
    let cgroups =
        CgroupRoot::open_with_filesystem(&temp.path().join("cgroup"), Arc::clone(&observed))
            .unwrap();
    let root = super::super::ExecutionDomainRoot::prepare_linux_recovery_for_test(
        lock.reconciliation_proof().unwrap(),
        cgroups,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        temp.path().join("job-resources"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    assert!(root.reconcile().await.is_err());
    assert!(
        observed.0.load(Ordering::Acquire) > 0,
        "independent cgroup must be killed"
    );
    assert!(
        group.exists(),
        "invalid filesystem proof must prevent cgroup removal"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reconcile_join_failure_poisons_and_never_opens_admission() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    create_private(&temp.path().join("job-resources"));
    create_private(&temp.path().join("cgroup"));
    seed_cgroup_root(&temp.path().join("cgroup"));
    let lock = RootLock::acquire(temp.path()).unwrap();
    let injected = Arc::new(PanickingCgroupFs(AtomicBool::new(false)));
    let cgroups =
        CgroupRoot::open_with_filesystem(&temp.path().join("cgroup"), Arc::clone(&injected))
            .unwrap();
    let root = super::super::ExecutionDomainRoot::prepare_linux_recovery_for_test(
        lock.reconciliation_proof().unwrap(),
        cgroups,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    injected.0.store(true, Ordering::Release);

    assert!(root.reconcile().await.is_err());
    assert!(matches!(
        root.reserve().await,
        Err(super::super::ExecutionDomainError::PoisonedRoot { .. })
    ));
}

#[cfg(target_os = "linux")]
fn fixture_root(
    setup: impl FnOnce(&std::path::Path, &std::path::Path),
) -> (tempfile::TempDir, super::super::ExecutionDomainRoot) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let active = temp.path().join("job-resources");
    let cgroup = temp.path().join("cgroup");
    fs::create_dir(&active).unwrap();
    fs::set_permissions(&active, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&cgroup).unwrap();
    seed_cgroup_root(&cgroup);
    setup(&active, &cgroup);
    let lock = RootLock::acquire(temp.path()).unwrap();
    let proof = lock.reconciliation_proof().unwrap();
    let cgroups = CgroupRoot::open_with_filesystem(&cgroup, Arc::new(FixtureCgroupFs)).unwrap();
    let root = super::super::ExecutionDomainRoot::prepare_linux_recovery_for_test(
        proof,
        cgroups,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    drop(lock);
    (temp, root)
}

#[cfg(target_os = "linux")]
fn create_private(path: &std::path::Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reconciles_cgroup_only_directory_only_and_exact_partial_orphans() {
    for kind in ["cgroup", "journal", "partial"] {
        let id = attempt(30);
        let (temp, root) = fixture_root(|active, cgroup| match kind {
            "cgroup" => {
                let group = cgroup.join(format!("attempt-{}", id.component()));
                create_private(&group);
                seed_cgroup_root(&group);
            }
            "journal" => {
                let directory = active.join(id.component());
                create_private(&directory);
                super::super::journal::DomainLifecycle::create_strict(&directory, id.uuid())
                    .unwrap();
            }
            "partial" => create_private(&active.join(id.component())),
            _ => unreachable!(),
        });

        root.reconcile().await.unwrap();
        assert!(
            !temp
                .path()
                .join("job-resources")
                .join(id.component())
                .exists()
        );
        assert!(
            !temp
                .path()
                .join("cgroup")
                .join(format!("attempt-{}", id.component()))
                .exists()
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recovery_removes_normal_domain_and_nested_empty_cgroups_bottom_up() {
    let id = attempt(33);
    let (temp, root) = fixture_root(|_, cgroup| {
        let attempt_group = cgroup.join(format!("attempt-{}", id.component()));
        create_private(&attempt_group);
        seed_cgroup_root(&attempt_group);
        let domain = attempt_group.join("domain");
        create_private(&domain);
        seed_cgroup_root(&domain);
        let nested = domain.join("nested");
        create_private(&nested);
        seed_cgroup_root(&nested);
    });

    root.reconcile().await.unwrap();
    assert!(
        !temp
            .path()
            .join("cgroup")
            .join(format!("attempt-{}", id.component()))
            .exists()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recovery_refuses_populated_nested_cgroup_without_removing_parent() {
    let id = attempt(34);
    let (temp, root) = fixture_root(|_, cgroup| {
        let attempt_group = cgroup.join(format!("attempt-{}", id.component()));
        create_private(&attempt_group);
        seed_cgroup_root(&attempt_group);
        let domain = attempt_group.join("domain");
        create_private(&domain);
        seed_cgroup_root(&domain);
        fs::write(domain.join("cgroup.events"), b"populated 1\n").unwrap();
    });

    assert!(root.reconcile().await.is_err());
    assert!(
        temp.path()
            .join("cgroup")
            .join(format!("attempt-{}", id.component()))
            .join("domain")
            .exists()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn recovery_refuses_wrong_nested_directory_and_journal_modes() {
    for entry in ["work", "journal.json"] {
        let id = attempt(35);
        let (temp, root) = fixture_root(|active, _| {
            let directory = active.join(id.component());
            create_private(&directory);
            super::super::journal::DomainLifecycle::create_strict(&directory, id.uuid()).unwrap();
            if entry == "work" {
                create_private(&directory.join("work"));
            }
            fs::set_permissions(directory.join(entry), fs::Permissions::from_mode(0o755)).unwrap();
        });

        assert!(root.reconcile().await.is_err(), "{entry}");
        assert!(
            temp.path()
                .join("job-resources")
                .join(id.component())
                .join(entry)
                .exists()
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn journal_free_partial_layout_must_be_exactly_empty() {
    let id = attempt(32);
    let (temp, root) = fixture_root(|active, _| {
        let directory = active.join(id.component());
        create_private(&directory);
        create_private(&directory.join("work"));
    });

    assert!(root.reconcile().await.is_err());
    assert!(
        temp.path()
            .join("job-resources")
            .join(id.component())
            .join("work")
            .exists()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn corrupt_metadata_is_preserved_after_exact_cgroup_neutralization() {
    let id = attempt(31);
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("canary"), b"keep").unwrap();
    let (temp, root) = fixture_root(|active, cgroup| {
        let directory = active.join(id.component());
        create_private(&directory);
        fs::write(directory.join("journal.json"), b"{").unwrap();
        let group = cgroup.join(format!("attempt-{}", id.component()));
        create_private(&group);
        seed_cgroup_root(&group);
    });

    assert!(root.reconcile().await.is_err());
    assert!(
        temp.path()
            .join("job-resources")
            .join(id.component())
            .exists()
    );
    assert!(
        temp.path()
            .join("cgroup")
            .join(format!("attempt-{}", id.component()))
            .exists()
    );
    assert_eq!(fs::read(outside.path().join("canary")).unwrap(), b"keep");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn unknown_or_wrong_mode_active_entry_preserves_everything() {
    for unsafe_name in ["unknown", "00000000000000000000000000000020"] {
        let (temp, root) = fixture_root(|active, _| {
            create_private(&active.join(unsafe_name));
            if unsafe_name != "unknown" {
                fs::set_permissions(active.join(unsafe_name), fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
        });

        assert!(root.reconcile().await.is_err());
        assert!(temp.path().join("job-resources").join(unsafe_name).exists());
    }
}
