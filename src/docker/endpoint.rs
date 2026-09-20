#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerEndpoint {
    socket_address: String,
}

fn trusted_host_from_docker_host(value: Option<&str>) -> DockerEndpoint {
    DockerEndpoint {
        socket_address: value
            .filter(|v| v.starts_with("unix://"))
            .unwrap_or("unix:///var/run/docker.sock")
            .to_owned(),
    }
}

impl DockerEndpoint {
    pub fn trusted_host() -> Self {
        trusted_host_from_docker_host(std::env::var("DOCKER_HOST").ok().as_deref())
    }

    pub fn unix_socket(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Docker socket path must be UTF-8"))?;
        anyhow::ensure!(
            path.is_absolute()
                && text != "/"
                && !text.contains('\0')
                && !text[1..]
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == ".."),
            "Docker socket path must be absolute and normalized"
        );
        Ok(Self {
            socket_address: format!("unix://{text}"),
        })
    }

    pub fn socket_address(&self) -> &str {
        &self.socket_address
    }
}

#[cfg(test)]
#[path = "endpoint_test.rs"]
mod endpoint_test;
