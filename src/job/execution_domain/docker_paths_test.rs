use super::*;

#[test]
fn docker_paths_are_deterministic_and_disjoint() {
    let left = DockerPaths::for_attempt(std::path::Path::new(
        "/attempts/00000000000000000000000000000001",
    ));
    let right = DockerPaths::for_attempt(std::path::Path::new(
        "/attempts/00000000000000000000000000000002",
    ));
    let base = std::path::Path::new("/attempts/00000000000000000000000000000001");

    assert_eq!(left.config_dir(), base.join("docker"));
    assert_eq!(left.run_dir(), base.join("run"));
    assert_eq!(left.socket_path(), base.join("run/docker.sock"));
    assert_eq!(left.data_root(), base.join("docker-data"));
    assert_eq!(left.exec_root(), base.join("docker-exec"));
    assert_ne!(left.socket_path(), right.socket_path());
    assert_ne!(left.config_dir(), right.config_dir());
    assert_ne!(left.data_root(), right.data_root());
    assert_ne!(left.exec_root(), right.exec_root());
    assert_eq!(left, DockerPaths::for_attempt(base));
}
