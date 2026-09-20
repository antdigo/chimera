use super::*;

#[test]
fn unavailable_mount_setattr_fails_closed() {
    const MARKER: &str = "CHIMERA_B6_NO_MOUNT_SETATTR";
    if std::env::var_os(MARKER).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "job::execution_domain::linux::rootfs::linux::native_test::unavailable_mount_setattr_fails_closed", "--nocapture"])
            .env(MARKER, "1").status().unwrap();
        assert!(status.success());
        return;
    }
    let mut filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_mount_setattr as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                &program,
            )
        },
        0
    );
    assert!(matches!(
        mount_attributes(Path::new("/"), true, true, false, true),
        Err(ExecutionDomainError::Backend {
            errno: Some(libc::ENOSYS),
            ..
        })
    ));
}

fn in_disposable_namespace(name: &str) -> bool {
    if std::env::var_os("CHIMERA_B6_NATIVE_CHILD").is_some() {
        return true;
    }
    let status = std::process::Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--fork",
            "--uts",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CHIMERA_B6_NATIVE_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success(), "native namespace child failed: {status}");
    false
}

#[test]
#[ignore = "disposable Linux user/mount/PID namespace required"]
fn recursive_readonly_covers_a_nested_mount() {
    if !in_disposable_namespace(
        "job::execution_domain::linux::rootfs::linux::native_test::recursive_readonly_covers_a_nested_mount",
    ) {
        return;
    }
    checked_mount_private_recursive().unwrap();
    let temp = tempfile::tempdir().unwrap();
    mount(None, temp.path(), Some("tmpfs"), 0, Some("mode=0700")).unwrap();
    let nested = temp.path().join("nested");
    fs::create_dir(&nested).unwrap();
    mount(None, &nested, Some("tmpfs"), 0, Some("mode=0700")).unwrap();
    fs::write(nested.join("canary"), b"readonly").unwrap();
    mount_attributes(temp.path(), true, true, false, true).unwrap();
    assert_eq!(
        fs::write(temp.path().join("new"), b"x")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    assert_eq!(
        fs::write(nested.join("canary"), b"x")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    assert_eq!(fs::read(nested.join("canary")).unwrap(), b"readonly");
    // Namespace exit is the owner of these disposable mounts.
    std::mem::forget(temp);
}

#[test]
#[ignore = "disposable Linux user/mount/PID namespace required"]
fn pivot_detaches_old_root_and_closes_old_descriptors() {
    if !in_disposable_namespace(
        "job::execution_domain::linux::rootfs::linux::native_test::pivot_detaches_old_root_and_closes_old_descriptors",
    ) {
        return;
    }
    checked_mount_private_recursive().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let sentinel = temp.path().join("outside-secret");
    fs::write(&sentinel, b"host-sentinel").unwrap();
    let old_fd = open_path(temp.path()).unwrap();
    use std::os::fd::IntoRawFd;
    let old_fd = old_fd.into_raw_fd();
    let (control, peer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(peer);
    let root = temp.path().join("rootfs");
    fs::create_dir(&root).unwrap();
    mount(
        None,
        &root,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("mode=0700"),
    )
    .unwrap();
    fs::create_dir(root.join("proc")).unwrap();
    mount(
        None,
        &root.join("proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
    .unwrap();
    fs::create_dir(root.join("dev")).unwrap();
    // Device access comes only from the individual bound null, not a host /dev mount.
    fs::write(root.join("dev/null"), []).unwrap();
    mount(
        Some(Path::new("/dev/null")),
        &root.join("dev/null"),
        None,
        libc::MS_BIND,
        None,
    )
    .unwrap();
    create_oldroot_directory(&root).unwrap();
    checked_chdir_to_new_root(&root).unwrap();
    checked_pivot_root().unwrap();
    checked_chdir_root().unwrap();
    checked_umount_oldroot().unwrap();
    checked_rmdir_oldroot().unwrap();
    close_oldroot_descriptors(control.as_raw_fd()).unwrap();
    assert_eq!(unsafe { libc::fcntl(old_fd, libc::F_GETFD) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    assert!(!sentinel.exists());
    assert!(!Path::new("/.oldroot").exists());
    assert_eq!(fs::read_link("/proc/self/cwd").unwrap(), Path::new("/"));
    assert_eq!(fs::read_link("/proc/1/root").unwrap(), Path::new("/"));
    assert_ne!(
        unsafe { libc::fcntl(control.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    assert!(
        !fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .contains(temp.path().to_str().unwrap())
    );
    std::mem::forget(temp);
}
