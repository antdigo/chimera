use super::*;

#[test]
fn second_writer_is_rejected_without_blocking() {
    let root = tempfile::tempdir().unwrap();
    let first = RootLock::acquire(root.path()).unwrap();

    let error = RootLock::acquire(root.path()).unwrap_err();

    assert!(matches!(error, RootLockError::Busy));
    drop(first);
    RootLock::acquire(root.path()).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_symlink_and_group_or_world_writable_root() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let parent = tempfile::tempdir().unwrap();
    let real_root = parent.path().join("real-root");
    std::fs::create_dir(&real_root).unwrap();
    std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let linked_root = parent.path().join("linked-root");
    symlink(&real_root, &linked_root).unwrap();

    assert!(matches!(
        RootLock::acquire(&linked_root).unwrap_err(),
        RootLockError::UnsafeRoot(_)
    ));

    std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        RootLock::acquire(&real_root).unwrap_err(),
        RootLockError::UnsafeRoot(_)
    ));
    std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_lock_file_without_touching_target() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = root.path().join("outside");
    std::fs::write(&outside, b"unchanged").unwrap();
    symlink(&outside, root.path().join(".chimera.lock")).unwrap();

    assert!(RootLock::acquire(root.path()).is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");
}

#[cfg(unix)]
#[test]
fn creates_new_root_and_lock_with_private_modes() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("new-root");

    let lock = RootLock::acquire(&root).unwrap();

    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(root.join(".chimera.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(lock);
}
