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
fn rejects_group_or_world_writable_non_sticky_ancestor() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let writable_ancestor = parent.path().join("writable");
    let root = writable_ancestor.join("root");
    std::fs::create_dir(&writable_ancestor).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&writable_ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(matches!(
        RootLock::acquire(&root).unwrap_err(),
        RootLockError::UnsafeRoot(_)
    ));

    std::fs::set_permissions(&writable_ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_symlink_root_with_trailing_separator() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::symlink;

    let parent = tempfile::tempdir().unwrap();
    let real_root = parent.path().join("real-root");
    std::fs::create_dir(&real_root).unwrap();
    let linked_root = parent.path().join("linked-root");
    symlink(&real_root, &linked_root).unwrap();
    let mut spelling = linked_root.as_os_str().as_bytes().to_vec();
    spelling.push(b'/');
    let linked_root_with_separator =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(spelling));

    assert!(matches!(
        RootLock::acquire(&linked_root_with_separator).unwrap_err(),
        RootLockError::UnsafeRoot(_)
    ));
}

#[cfg(unix)]
#[test]
fn rejects_symlink_root_with_terminal_dot() {
    use std::os::unix::fs::symlink;

    let parent = tempfile::tempdir().unwrap();
    let real_root = parent.path().join("real-root");
    std::fs::create_dir(&real_root).unwrap();
    let linked_root = parent.path().join("linked-root");
    symlink(&real_root, &linked_root).unwrap();

    assert!(matches!(
        RootLock::acquire(&linked_root.join(".")).unwrap_err(),
        RootLockError::UnsafeRoot(_)
    ));
}

#[cfg(unix)]
#[test]
fn creates_missing_multi_component_relative_root() {
    let current = std::env::current_dir().unwrap();
    let reservation = tempfile::Builder::new()
        .prefix(".chimera-relative-root-")
        .tempdir_in(&current)
        .unwrap();
    let top_level_name = reservation.path().file_name().unwrap().to_owned();
    drop(reservation);
    let relative_root = std::path::PathBuf::from(&top_level_name)
        .join("nested")
        .join("root");
    let absolute_top_level = current.join(&top_level_name);

    let lock = RootLock::acquire(&relative_root).unwrap();

    assert!(
        absolute_top_level
            .join("nested/root/.chimera.lock")
            .is_file()
    );
    drop(lock);
    std::fs::remove_dir_all(absolute_top_level).unwrap();
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
fn opens_lock_file_relative_to_pinned_root_directory() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    let moved_root = parent.path().join("moved-root");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pinned_root = open_root(&root, false).unwrap();
    std::fs::rename(&root, &moved_root).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let lock_file = open_lock_file(&pinned_root).unwrap();

    assert!(moved_root.join(".chimera.lock").is_file());
    assert!(!root.join(".chimera.lock").exists());
    drop(lock_file);
}

#[cfg(unix)]
#[test]
fn creates_new_root_and_lock_with_private_modes() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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

#[test]
fn successful_missing_component_creation_requires_parent_sync() {
    let parent = tempfile::tempdir().unwrap();
    let parent_directory = open_existing_root(parent.path()).unwrap();
    let name = std::ffi::CString::new("durable-child").unwrap();
    let sync_called = std::cell::Cell::new(false);

    let error = create_directory_at_with_sync(&parent_directory, &name, |_| {
        sync_called.set(true);
        Err(std::io::Error::other("injected parent sync failure"))
    })
    .unwrap_err();

    assert!(sync_called.get());
    assert!(matches!(error, RootLockError::Io(_)));
    assert!(parent.path().join("durable-child").is_dir());
}
