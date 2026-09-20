use std::ffi::CString;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixListener;

use super::dirfd::{BoundDir, SyncKind};

struct Fixture {
    temp: tempfile::TempDir,
    root: BoundDir,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("active")).unwrap();
        fs::create_dir(temp.path().join("outside")).unwrap();
        fs::write(temp.path().join("outside/canary"), b"keep").unwrap();
        let root = BoundDir::open_root(&temp.path().join("active")).unwrap();
        Self { temp, root }
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.temp.path().join("active").join(name)
    }

    fn canary(&self) -> std::path::PathBuf {
        self.temp.path().join("outside/canary")
    }

    fn assert_canary(&self) {
        assert_eq!(fs::read(self.canary()).unwrap(), b"keep");
    }
}

#[test]
fn replacement_never_touches_outside_canary_and_poison_is_shared() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.path("owned")).unwrap();
    let owned = fixture.root.child(c"owned").unwrap();
    fs::rename(fixture.path("owned"), fixture.path("moved")).unwrap();
    symlink(fixture.temp.path().join("outside"), fixture.path("owned")).unwrap();

    assert!(owned.verify_binding().is_err());
    assert!(fixture.root.remove_tree(c"owned").is_err());
    assert!(fixture.root.verify_binding().is_err());
    fixture.assert_canary();
}

#[test]
fn swapped_ancestor_prevents_mutations_through_retained_descendant() {
    let fixture = Fixture::new();
    let child = fixture.root.create_child(c"work", 0o700).unwrap();
    fs::rename(fixture.path(""), fixture.temp.path().join("moved")).unwrap();
    fs::create_dir(fixture.path("")).unwrap();

    assert!(child.write_atomic(c"state", b"must-not-write").is_err());
    assert!(!fixture.temp.path().join("moved/work/state").exists());
    fixture.assert_canary();
}

#[test]
fn regular_reader_refuses_fifo_without_waiting() {
    let fixture = Fixture::new();
    let path = CString::new(fixture.path("state").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let began = std::time::Instant::now();

    assert!(fixture.root.read_regular(c"state", 1024).is_err());
    assert!(began.elapsed() < std::time::Duration::from_secs(1));
    fixture.assert_canary();
}

#[test]
fn regular_reader_rejects_hardlinks_symlinks_and_oversized_files() {
    for entry in ["hardlink", "symlink", "large"] {
        let fixture = Fixture::new();
        match entry {
            "hardlink" => fs::hard_link(fixture.canary(), fixture.path("state")).unwrap(),
            "symlink" => symlink(fixture.canary(), fixture.path("state")).unwrap(),
            _ => fs::write(fixture.path("state"), b"12345").unwrap(),
        }

        assert!(fixture.root.read_regular(c"state", 4).is_err(), "{entry}");
        fixture.assert_canary();
    }
}

#[test]
fn reader_rechecks_size_and_identity_after_eof() {
    for replaced in [false, true] {
        let fixture = Fixture::new();
        fs::write(fixture.path("state"), b"safe").unwrap();
        let result = fixture
            .root
            .read_regular_with(c"state", 4, |reader, bytes| {
                let count = reader.read_to_end(bytes)?;
                if replaced {
                    fs::rename(fixture.path("state"), fixture.path("moved-state")).unwrap();
                    symlink(fixture.canary(), fixture.path("state")).unwrap();
                } else {
                    fs::write(fixture.path("state"), b"grew past the limit").unwrap();
                }
                Ok(count)
            });

        assert!(result.is_err());
        fixture.assert_canary();
    }
}

#[test]
fn reader_limits_bytes_even_when_file_grows_after_initial_stat() {
    let fixture = Fixture::new();
    fs::write(fixture.path("state"), b"safe").unwrap();
    let result = fixture
        .root
        .read_regular_with(c"state", 4, |reader, bytes| {
            fs::write(fixture.path("state"), vec![b'x'; 8192]).unwrap();
            let count = reader.read_to_end(bytes)?;
            assert_eq!(bytes.len(), 5);
            Ok(count)
        });

    assert!(result.is_err());
    fixture.assert_canary();
}

#[test]
fn atomic_write_detects_old_record_swap_after_file_sync() {
    let fixture = Fixture::new();
    fixture.root.write_atomic(c"journal.json", b"old").unwrap();
    let result = fixture
        .root
        .write_atomic_with_sync(c"journal.json", b"new", |_, _| {
            fs::rename(fixture.path("journal.json"), fixture.path("saved-old")).unwrap();
            symlink(fixture.canary(), fixture.path("journal.json")).unwrap();
            Ok(())
        });

    assert!(result.is_err());
    assert_eq!(fs::read(fixture.path("saved-old")).unwrap(), b"old");
    assert_eq!(fs::read(fixture.path("journal.json.next")).unwrap(), b"new");
    fixture.assert_canary();
}

#[test]
fn removal_refuses_symlinks_in_supervisor_only_subtrees() {
    for control in ["rootlesskit", "rootfs"] {
        let fixture = Fixture::new();
        let attempt = fixture.root.create_child(c"attempt", 0o700).unwrap();
        attempt
            .create_child(&CString::new(control).unwrap(), 0o700)
            .unwrap();
        symlink(
            fixture.canary(),
            fixture.path(&format!("attempt/{control}/link")),
        )
        .unwrap();

        assert!(fixture.root.remove_tree(c"attempt").is_err());
        assert!(
            fixture
                .path(&format!("attempt/{control}/link"))
                .is_symlink()
        );
        fixture.assert_canary();
    }
}

#[test]
#[ignore = "native Linux: requires CAP_MKNOD in disposable container"]
fn removal_refuses_device_nodes_everywhere() {
    for directory in ["work", "rootfs"] {
        let fixture = Fixture::new();
        let attempt = fixture.root.create_child(c"attempt", 0o700).unwrap();
        attempt
            .create_child(&CString::new(directory).unwrap(), 0o700)
            .unwrap();
        let path = CString::new(
            fixture
                .path(&format!("attempt/{directory}/device"))
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(
            unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) },
            0
        );

        assert!(fixture.root.remove_tree(c"attempt").is_err());
        assert!(
            fixture
                .path(&format!("attempt/{directory}/device"))
                .exists()
        );
        fixture.assert_canary();
    }
}

#[test]
fn atomic_write_is_private_bounded_and_refuses_unknown_next() {
    let fixture = Fixture::new();
    fixture.root.write_atomic(c"journal.json", b"old").unwrap();
    fixture.root.write_atomic(c"journal.json", b"new").unwrap();
    assert_eq!(
        fixture.root.read_regular(c"journal.json", 3).unwrap(),
        b"new"
    );
    assert_eq!(
        fs::metadata(fixture.path("journal.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fs::write(fixture.path("journal.json.next"), b"evidence").unwrap();

    assert!(
        fixture
            .root
            .write_atomic(c"journal.json", b"replace")
            .is_err()
    );
    assert_eq!(fs::read(fixture.path("journal.json")).unwrap(), b"new");
    assert_eq!(
        fs::read(fixture.path("journal.json.next")).unwrap(),
        b"evidence"
    );
    fixture.assert_canary();
}

#[test]
fn atomic_write_refuses_symlink_or_hardlinked_destination_and_next() {
    for name in ["journal.json", "journal.json.next"] {
        for hardlink in [false, true] {
            let fixture = Fixture::new();
            if hardlink {
                fs::hard_link(fixture.canary(), fixture.path(name)).unwrap();
            } else {
                symlink(fixture.canary(), fixture.path(name)).unwrap();
            }

            assert!(
                fixture
                    .root
                    .write_atomic(c"journal.json", b"replace")
                    .is_err()
            );
            fixture.assert_canary();
        }
    }
}

#[test]
fn atomic_file_sync_failure_preserves_old_journal_and_next_evidence() {
    let fixture = Fixture::new();
    fixture.root.write_atomic(c"journal.json", b"old").unwrap();

    let result = fixture
        .root
        .write_atomic_with_sync(c"journal.json", b"new", |_, kind| {
            assert_eq!(kind, SyncKind::File);
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        });

    assert!(result.is_err());
    assert_eq!(fs::read(fixture.path("journal.json")).unwrap(), b"old");
    assert_eq!(fs::read(fixture.path("journal.json.next")).unwrap(), b"new");
    assert!(fixture.root.verify_binding().is_err());
    fixture.assert_canary();
}

#[test]
fn atomic_directory_sync_failure_is_not_reported_as_committed() {
    let fixture = Fixture::new();
    fixture.root.write_atomic(c"journal.json", b"old").unwrap();
    let result = fixture
        .root
        .write_atomic_with_sync(c"journal.json", b"new", |fd, kind| {
            if kind == SyncKind::Directory {
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            } else if unsafe { libc::fsync(fd) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });

    assert!(result.is_err());
    assert!(fixture.path("journal.json").is_file());
    assert!(fixture.root.verify_binding().is_err());
    fixture.assert_canary();
}

#[test]
fn atomic_write_detects_next_swap_after_file_sync() {
    let fixture = Fixture::new();
    fixture.root.write_atomic(c"journal.json", b"old").unwrap();
    let result = fixture
        .root
        .write_atomic_with_sync(c"journal.json", b"new", |_, _| {
            fs::rename(
                fixture.path("journal.json.next"),
                fixture.path("saved-next"),
            )
            .unwrap();
            symlink(fixture.canary(), fixture.path("journal.json.next")).unwrap();
            Ok(())
        });

    assert!(result.is_err());
    assert_eq!(fs::read(fixture.path("journal.json")).unwrap(), b"old");
    fixture.assert_canary();
}

#[test]
fn creation_never_replaces_existing_directory() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.path("work")).unwrap();
    fs::write(fixture.path("work/owner"), b"first").unwrap();

    assert!(fixture.root.create_child(c"work", 0o700).is_err());
    assert_eq!(fs::read(fixture.path("work/owner")).unwrap(), b"first");
    fixture.assert_canary();
}

#[test]
fn component_apis_reject_traversal_and_absolute_names() {
    for name in ["", ".", "..", "a/b", "/outside"] {
        for operation in 0..5 {
            let fixture = Fixture::new();
            let name = CString::new(name).unwrap();
            let refused = match operation {
                0 => fixture.root.child(&name).is_err(),
                1 => fixture.root.create_child(&name, 0o700).is_err(),
                2 => fixture.root.read_regular(&name, 100).is_err(),
                3 => fixture.root.write_atomic(&name, b"no").is_err(),
                _ => fixture.root.remove_tree(&name).is_err(),
            };
            assert!(refused);
            fixture.assert_canary();
        }
    }
}

#[test]
fn removal_unlinks_writable_symlink_leaves_without_following_them() {
    let fixture = Fixture::new();
    let attempt = fixture.root.create_child(c"attempt", 0o700).unwrap();
    let work = attempt.create_child(c"work", 0o700).unwrap();
    work.create_child(c"nested", 0o700).unwrap();
    fs::write(fixture.path("attempt/work/nested/file"), b"data").unwrap();
    symlink(
        fixture.temp.path().join("outside"),
        fixture.path("attempt/work/link"),
    )
    .unwrap();
    attempt.write_atomic(c"journal.json", b"{}").unwrap();

    fixture.root.remove_tree(c"attempt").unwrap();
    assert!(!fixture.path("attempt").exists());
    fixture.assert_canary();
}

#[test]
fn removal_refuses_unknown_control_entries_and_unowned_sockets() {
    for name in ["unknown", "work/rogue.sock", "run/docker.sock"] {
        let fixture = Fixture::new();
        let attempt = fixture.root.create_child(c"attempt", 0o700).unwrap();
        attempt.create_child(c"work", 0o700).unwrap();
        attempt.create_child(c"run", 0o700).unwrap();
        let socket = if name.ends_with("sock") {
            Some(UnixListener::bind(fixture.path(&format!("attempt/{name}"))).unwrap())
        } else {
            fs::write(fixture.path(&format!("attempt/{name}")), b"unknown").unwrap();
            None
        };

        assert!(fixture.root.remove_tree(c"attempt").is_err());
        assert!(fixture.path(&format!("attempt/{name}")).exists());
        fixture.assert_canary();
        drop(socket);
    }
}

#[test]
#[ignore = "native Linux: requires CAP_SYS_ADMIN in disposable private mount namespace"]
fn removal_refuses_unexpected_mount_without_touching_canary() {
    let fixture = Fixture::new();
    let attempt = fixture.root.create_child(c"attempt", 0o700).unwrap();
    attempt.create_child(c"work", 0o700).unwrap();
    let source = CString::new(
        fixture
            .temp
            .path()
            .join("outside")
            .as_os_str()
            .as_encoded_bytes(),
    )
    .unwrap();
    let target = CString::new(fixture.path("attempt/work").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        0
    );

    let result = fixture.root.remove_tree(c"attempt");
    let unmounted = unsafe { libc::umount2(target.as_ptr(), 0) };
    assert!(result.is_err());
    assert_eq!(unmounted, 0);
    fixture.assert_canary();
}
