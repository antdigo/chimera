#[cfg(all(target_os = "linux", test))]
mod cgroup;
#[cfg(all(target_os = "linux", test))]
pub(super) mod dirfd;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
pub(super) mod launcher;
#[cfg(all(target_os = "linux", test))]
#[path = "launcher_test.rs"]
mod launcher_test;
pub(super) mod rootfs;

#[cfg(all(target_os = "linux", test))]
#[path = "rootfs_test.rs"]
mod rootfs_test;

#[cfg(all(target_os = "linux", test))]
#[path = "cgroup_test.rs"]
mod cgroup_test;

#[cfg(all(target_os = "linux", test))]
#[path = "dirfd_test.rs"]
mod dirfd_test;
