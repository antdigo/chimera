use super::*;

#[test]
fn trusted_host_resolution_preserves_legacy_selection() {
    for value in [
        None,
        Some(""),
        Some("tcp://127.0.0.1:2375"),
        Some("ssh://host"),
        Some("/tmp/docker.sock"),
    ] {
        assert_eq!(
            trusted_host_from_docker_host(value).socket_address(),
            "unix:///var/run/docker.sock"
        );
    }
    for value in ["unix:///tmp/custom.sock", "unix://relative.sock", "unix://"] {
        assert_eq!(
            trusted_host_from_docker_host(Some(value)).socket_address(),
            value
        );
    }
}

#[test]
fn explicit_unix_endpoint_is_validated_without_touching_disk() {
    let path = std::path::Path::new("/not-created-by-chimera/run/docker.sock");
    let endpoint = DockerEndpoint::unix_socket(path).unwrap();
    assert_eq!(
        endpoint.socket_address(),
        "unix:///not-created-by-chimera/run/docker.sock"
    );
    for invalid in [
        "",
        "relative.sock",
        "/run/../docker.sock",
        "/run/./docker.sock",
        "/run//docker.sock",
        "/run/docker.sock/",
        "/",
        "/run/a\0b",
    ] {
        assert!(DockerEndpoint::unix_socket(std::path::Path::new(invalid)).is_err());
    }
}

#[test]
fn explicit_unix_endpoint_rejects_non_utf8_without_echoing_input() {
    use std::os::unix::ffi::OsStringExt;
    let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(b"/run/\xff.sock".to_vec()));
    let error = DockerEndpoint::unix_socket(&path).unwrap_err();
    assert_eq!(error.to_string(), "Docker socket path must be UTF-8");
}
