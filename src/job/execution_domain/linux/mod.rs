#[cfg(target_os = "linux")]
mod cgroup;
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
}

#[cfg(target_os = "linux")]
pub(in crate::job::execution_domain) struct StrictCleanupAuthority {
    cgroup: cgroup::AttemptCgroup,
    rootfs: dirfd::BoundDir,
}

#[cfg(target_os = "linux")]
pub(in crate::job::execution_domain) struct StrictBackendParts {
    pub kernel: launcher::KernelDomain,
    pub cleanup: StrictCleanupAuthority,
    pub path_mappings: Vec<(std::path::PathBuf, super::DomainPath)>,
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
    ) -> Self {
        Self { cgroup, launch }
    }

    pub(in crate::job::execution_domain) fn build(
        self,
    ) -> Result<StrictBackendParts, super::ExecutionDomainError> {
        let path_mappings = self
            .launch
            .rootfs
            .inputs
            .iter()
            .map(|input| (input.source.clone(), input.target.clone()))
            .collect();
        let mut kernel = launcher::launch(&self.cgroup, &self.launch)?;
        if let Err(error) = self.cgroup.finish_evacuation() {
            let _ = kernel.launcher.kill();
            let _ = kernel.launcher.wait();
            return Err(error);
        }
        Ok(StrictBackendParts {
            kernel,
            cleanup: StrictCleanupAuthority {
                cgroup: self.cgroup,
                rootfs: self.launch.bound_rootfs,
            },
            path_mappings,
        })
    }
}

#[cfg(target_os = "linux")]
impl StrictCleanupAuthority {
    pub(in crate::job::execution_domain) fn verify(
        &self,
    ) -> Result<(), super::ExecutionDomainError> {
        self.rootfs.verify_binding()?;
        self.cgroup.limits_match()
    }
}
