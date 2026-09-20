use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::rootfs::linux::RootfsProof;
use crate::job::execution_domain::{ExecutionDomainError, FailureCategory, Stage};

const READ: u64 = (1 << 2) | (1 << 3);
const EXECUTE: u64 = 1;
const WRITE: u64 = ((1 << 15) - 1) & !((1 << 6) | (1 << 11));
const HANDLED: u64 = (1 << 15) - 1;
const SECUREBITS: libc::c_ulong = 1 | 2 | 4 | 8;
const NEW_NAMESPACES: u32 =
    0x80 | 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000;

pub(super) struct ChildPolicy {
    paths: Vec<(CString, u64)>,
    seccomp: SeccompPolicy,
}

impl ChildPolicy {
    pub(super) fn workflow(proof: &RootfsProof) -> Result<Self, ExecutionDomainError> {
        landlock_abi()?;
        let mut paths = Vec::new();
        for (path, readonly) in proof.workflow_paths() {
            if path == "/sys/fs/cgroup" {
                continue;
            }
            paths.push((
                cstring(path)?,
                if readonly { READ | EXECUTE } else { WRITE },
            ));
        }
        for (path, access) in [
            ("/etc", READ),
            ("/proc", READ),
            ("/sys", READ),
            ("/dev/null", 6),
            ("/dev/zero", 6),
            ("/dev/full", 6),
            ("/dev/random", 6),
            ("/dev/urandom", 6),
            ("/dev/pts", READ | 2),
            ("/dev/shm", WRITE),
        ] {
            paths.push((cstring(path)?, access));
        }
        Ok(Self {
            paths,
            seccomp: SeccompPolicy::native()?,
        })
    }

    pub(super) fn apply_before_exec(&self) -> Result<(), ExecutionDomainError> {
        checked(unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) })?;
        clear_groups()?;
        checked(unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } as i64)?;
        drop_bounding_except(0)?;
        // CAP_SETPCAP is required here, before the final permitted/effective drop.
        checked(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, SECUREBITS, 0, 0, 0) } as i64)?;
        capset(0)?;
        checked(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } as i64)?;
        self.restrict_filesystem()?;
        self.seccomp.install()
    }

    fn restrict_filesystem(&self) -> Result<(), ExecutionDomainError> {
        landlock_abi()?;
        let ruleset = HANDLED;
        let fd = checked(unsafe {
            libc::syscall(libc::SYS_landlock_create_ruleset, &ruleset, 8usize, 0u32)
        })?;
        let ruleset = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        #[repr(C, packed)]
        struct PathBeneath {
            access: u64,
            parent_fd: i32,
        }
        for (path, access) in &self.paths {
            let fd = checked(
                unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) } as i64,
            )?;
            let parent = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            checked(unsafe { libc::fstat(parent.as_raw_fd(), stat.as_mut_ptr()) } as i64)?;
            let is_directory =
                unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFDIR;
            let access = if is_directory {
                *access
            } else {
                access & (EXECUTE | 2 | 4 | (1 << 14))
            };
            let rule = PathBeneath {
                access,
                parent_fd: parent.as_raw_fd(),
            };
            checked(unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset.as_raw_fd(),
                    1u32,
                    &rule,
                    0u32,
                )
            })?;
        }
        checked(unsafe {
            libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32)
        })?;
        Ok(())
    }
}

fn landlock_abi() -> Result<(), ExecutionDomainError> {
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32,
        )
    };
    if abi < 3 {
        return Err(failure(FailureCategory::Unsupported));
    }
    Ok(())
}

pub(super) fn retain_init_capabilities() -> Result<(), ExecutionDomainError> {
    clear_groups()?;
    let keep = (1 << 7) | (1 << 8); // SETGID for groups and SETPCAP for workflow setup.
    checked(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } as i64)?;
    drop_bounding_except(keep)?;
    checked(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, SECUREBITS, 0, 0, 0) } as i64)?;
    capset(keep)
}

fn clear_groups() -> Result<(), ExecutionDomainError> {
    if unsafe { libc::setgroups(0, std::ptr::null()) } == 0 {
        return Ok(());
    }
    // A user namespace with setgroups=deny may already have an empty group set.
    if unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 0 {
        return Ok(());
    }
    Err(failure(FailureCategory::Unavailable))
}

fn drop_bounding_except(keep: u64) -> Result<(), ExecutionDomainError> {
    for capability in 0..64 {
        let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) };
        if present < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            return Ok(());
        }
        checked(present as i64)?;
        if keep & (1u64 << capability) == 0 {
            checked(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } as i64)?;
        }
    }
    Err(failure(FailureCategory::Unsupported))
}

fn capset(mask: u64) -> Result<(), ExecutionDomainError> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let data = [
        Data {
            effective: mask as u32,
            permitted: mask as u32,
            inheritable: 0,
        },
        Data {
            effective: (mask >> 32) as u32,
            permitted: (mask >> 32) as u32,
            inheritable: 0,
        },
    ];
    checked(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) })?;
    Ok(())
}

pub(super) struct SeccompPolicy {
    pub(super) filter: Vec<libc::sock_filter>,
}

impl SeccompPolicy {
    pub(super) fn native() -> Result<Self, ExecutionDomainError> {
        let arch = native_arch()?;
        let mut filter = vec![
            insn(0x20, 0, 0, 4),
            insn(0x15, 1, 0, arch),
            insn(0x06, 0, 0, 0x80000000),
            insn(0x20, 0, 0, 0),
        ];
        #[cfg(target_arch = "x86_64")]
        filter.extend([insn(0x45, 0, 1, 0x40000000), insn(0x06, 0, 0, 0x80000000)]);
        for call in [
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
            libc::SYS_kexec_file_load,
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
            filter.extend([
                insn(0x15, 0, 1, call as u32),
                insn(0x06, 0, 0, 0x50000 | libc::EPERM as u32),
            ]);
        }
        filter.extend([
            insn(0x15, 0, 1, libc::SYS_clone3 as u32),
            insn(0x06, 0, 0, 0x50000 | libc::ENOSYS as u32),
            insn(0x15, 0, 3, libc::SYS_clone as u32),
            insn(0x20, 0, 0, 16),
            insn(0x45, 0, 1, NEW_NAMESPACES),
            insn(0x06, 0, 0, 0x50000 | libc::EPERM as u32),
            insn(0x06, 0, 0, 0x7fff0000),
        ]);
        Ok(Self { filter })
    }

    fn install(&self) -> Result<(), ExecutionDomainError> {
        let program = libc::sock_fprog {
            len: self.filter.len() as u16,
            filter: self.filter.as_ptr().cast_mut(),
        };
        checked(unsafe { libc::syscall(libc::SYS_seccomp, 1u32, 0u32, &program) })?;
        Ok(())
    }
}

fn native_arch() -> Result<u32, ExecutionDomainError> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(0xc000003e)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(0xc00000b7)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(failure(FailureCategory::Unsupported))
    }
}

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn cstring(value: &str) -> Result<CString, ExecutionDomainError> {
    CString::new(value).map_err(|_| failure(FailureCategory::InvalidInput))
}

fn checked(result: i64) -> Result<i64, ExecutionDomainError> {
    if result < 0 {
        Err(failure(FailureCategory::Io))
    } else {
        Ok(result)
    }
}

fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Command,
        category,
        errno: io::Error::last_os_error().raw_os_error(),
    }
}

#[cfg(test)]
#[path = "hardening_test.rs"]
pub(super) mod hardening_test;
