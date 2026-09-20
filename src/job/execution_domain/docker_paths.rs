#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerPaths {
    config_dir: std::path::PathBuf,
    run_dir: std::path::PathBuf,
    data_root: std::path::PathBuf,
    exec_root: std::path::PathBuf,
    socket_path: std::path::PathBuf,
}

impl DockerPaths {
    pub(super) fn for_attempt(attempt_dir: &std::path::Path) -> Self {
        Self {
            config_dir: attempt_dir.join("docker"),
            run_dir: attempt_dir.join("run"),
            data_root: attempt_dir.join("docker-data"),
            exec_root: attempt_dir.join("docker-exec"),
            socket_path: attempt_dir.join("run/docker.sock"),
        }
    }

    pub fn config_dir(&self) -> &std::path::Path {
        &self.config_dir
    }

    pub fn run_dir(&self) -> &std::path::Path {
        &self.run_dir
    }

    pub fn data_root(&self) -> &std::path::Path {
        &self.data_root
    }

    pub fn exec_root(&self) -> &std::path::Path {
        &self.exec_root
    }

    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }
}

#[cfg(test)]
#[path = "docker_paths_test.rs"]
mod docker_paths_test;
