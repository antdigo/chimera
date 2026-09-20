use super::*;

// Interpret the actual BPF program, rather than a separate policy model.
fn decision(policy: &SeccompPolicy, arch: u32, nr: i64, flags: u64) -> u32 {
    let mut data = [0u8; 64];
    data[..4].copy_from_slice(&(nr as u32).to_ne_bytes());
    data[4..8].copy_from_slice(&arch.to_ne_bytes());
    data[16..24].copy_from_slice(&flags.to_ne_bytes());
    let mut accumulator = 0;
    let mut pc = 0;
    loop {
        let instruction = &policy.filter[pc];
        pc += 1;
        match instruction.code {
            0x20 => {
                accumulator = u32::from_ne_bytes(
                    data[instruction.k as usize..instruction.k as usize + 4]
                        .try_into()
                        .unwrap(),
                );
            }
            0x15 => {
                pc += if accumulator == instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                } as usize
            }
            0x45 => {
                pc += if accumulator & instruction.k != 0 {
                    instruction.jt
                } else {
                    instruction.jf
                } as usize
            }
            0x06 => return instruction.k,
            code => panic!("unexpected BPF opcode {code}"),
        }
    }
}

#[test]
fn hardening_checks_architecture_clone_flags_and_dangerous_syscalls() {
    let policy = SeccompPolicy::native().unwrap();
    #[cfg(target_arch = "x86_64")]
    let arch = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    let arch = 0xc00000b7;
    assert_eq!(decision(&policy, 0, libc::SYS_read, 0), 0x80000000);
    for nr in [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
    ] {
        assert_eq!(decision(&policy, arch, nr, 0), 0x50001, "syscall {nr}");
    }
    for nr in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_execve,
        libc::SYS_socket,
        libc::SYS_connect,
    ] {
        assert_eq!(decision(&policy, arch, nr, 0), 0x7fff0000);
    }
    for flag in [
        libc::CLONE_NEWCGROUP,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWUTS,
        0x80,
    ] {
        assert_eq!(
            decision(
                &policy,
                arch,
                libc::SYS_clone,
                flag as u64 | libc::SIGCHLD as u64
            ),
            0x50001
        );
    }
    assert_eq!(
        decision(&policy, arch, libc::SYS_clone, libc::SIGCHLD as u64),
        0x7fff0000
    );
    assert_eq!(decision(&policy, arch, libc::SYS_clone3, 0), 0x50026);
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        decision(&policy, arch, libc::SYS_read | 0x40000000, 0),
        0x80000000
    );
}

pub(in crate::job::execution_domain::linux) fn fixture_policy(
    writable: &std::path::Path,
) -> ChildPolicy {
    let mut paths = Vec::new();
    for path in ["/usr", "/bin", "/lib", "/lib64", "/etc", "/proc"] {
        if std::path::Path::new(path).exists() {
            paths.push((CString::new(path).unwrap(), READ | EXECUTE));
        }
    }
    paths.push((CString::new(writable.to_str().unwrap()).unwrap(), WRITE));
    paths.push((CString::new("/dev/null").unwrap(), 6));
    ChildPolicy {
        paths,
        seccomp: SeccompPolicy::native().unwrap(),
    }
}

pub(in crate::job::execution_domain::linux) fn native_child(test: &str) -> bool {
    if std::env::var_os("CHIMERA_B7_NATIVE_CHILD").is_some() {
        return true;
    }
    let status = std::process::Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "--mount-proc",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            test,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CHIMERA_B7_NATIVE_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success(), "native child {test}: {status}");
    false
}

#[test]
#[ignore = "disposable Linux user/PID namespace; irreversible child hardening"]
fn workflow_policy_enforces_caps_fds_landlock_and_seccomp_in_a_child() {
    if !native_child(
        "job::execution_domain::linux::hardening::hardening_test::workflow_policy_enforces_caps_fds_landlock_and_seccomp_in_a_child",
    ) {
        return;
    }
    use std::os::fd::IntoRawFd;
    let root = tempfile::tempdir().unwrap();
    let allowed = root.path().join("allowed");
    std::fs::create_dir(&allowed).unwrap();
    let denied = root.path().join("denied");
    std::fs::write(&denied, "canary").unwrap();
    let policy = fixture_policy(&allowed);
    let (control, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let control_fd = control.into_raw_fd();
    let _peer_fd = _peer.into_raw_fd();
    retain_init_capabilities().unwrap();
    policy.apply_before_exec().unwrap();
    assert_eq!(unsafe { libc::fcntl(control_fd, libc::F_GETFD) }, -1);
    // libtest executes this probe on its worker; Linux credentials are per-thread.
    let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert!(
            status
                .lines()
                .any(|line| line == format!("{name}:\t0000000000000000")),
            "{name} not empty"
        );
    }
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    assert_eq!(unsafe { libc::getgroups(0, std::ptr::null_mut()) }, 0);
    assert_eq!(unsafe { libc::syscall(libc::SYS_ptrace, 0, 0, 0, 0) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOSYS)
    );
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER) },
        -1
    );
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    assert_eq!(
        std::fs::read(&denied).unwrap_err().raw_os_error(),
        Some(libc::EACCES)
    );
    assert_eq!(
        std::fs::write(&denied, "bad").unwrap_err().raw_os_error(),
        Some(libc::EACCES)
    );
    let file = allowed.join("file");
    std::fs::write(&file, "allowed").unwrap();
    std::fs::write(&file, "truncate").unwrap();
    std::fs::rename(&file, allowed.join("renamed")).unwrap();
    std::fs::remove_file(allowed.join("renamed")).unwrap();
    let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
    use std::io::{Read, Write};
    (&a).write_all(b"Docker API Unix socket").unwrap();
    let mut buf = [0; 22];
    b.read_exact(&mut buf).unwrap();
    let shell = std::process::Command::new("/bin/sh")
        .args(["-c", "(exit 0); exit 7"])
        .status()
        .unwrap();
    assert_eq!(shell.code(), Some(7));
    std::mem::forget(root);
}

#[test]
#[ignore = "irreversible seccomp failure injection in disposable user namespace"]
fn unavailable_landlock_and_seccomp_fail_closed() {
    if !native_child(
        "job::execution_domain::linux::hardening::hardening_test::unavailable_landlock_and_seccomp_fail_closed",
    ) {
        return;
    }
    let filter = [
        insn(0x20, 0, 0, 0),
        insn(0x15, 0, 1, libc::SYS_landlock_create_ruleset as u32),
        insn(0x06, 0, 0, 0x50026),
        insn(0x15, 0, 1, libc::SYS_seccomp as u32),
        insn(0x06, 0, 0, 0x50026),
        insn(0x06, 0, 0, 0x7fff0000),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program, 0, 0) },
        0
    );
    assert!(matches!(
        landlock_abi(),
        Err(ExecutionDomainError::Backend {
            category: FailureCategory::Unsupported,
            ..
        })
    ));
    assert!(SeccompPolicy::native().unwrap().install().is_err());
}
