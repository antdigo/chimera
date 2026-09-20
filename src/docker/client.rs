use anyhow::{Context, Result};
use bollard::Docker;
use bollard::auth::DockerCredentials;
use bollard::image::CreateImageOptions;
use futures::StreamExt;
use tracing::{debug, info};

use super::container::ContainerCredentials;
use super::endpoint::DockerEndpoint;

/// Connect to the selected Docker Unix endpoint.
pub fn connect(endpoint: &DockerEndpoint) -> Result<Docker> {
    Docker::connect_with_unix(endpoint.socket_address(), 120, bollard::API_DEFAULT_VERSION)
        .context("connecting to selected Docker Unix endpoint")
}

/// Verify the Docker daemon is reachable.
pub async fn ping(docker: &Docker) -> Result<()> {
    docker.ping().await.context("pinging Docker daemon")?;
    debug!("Docker daemon is reachable");
    Ok(())
}

/// Ensure a Docker image is available locally; pull it if missing.
/// Optionally uses credentials for private registry authentication.
pub async fn ensure_image(
    docker: &Docker,
    image: &str,
    credentials: Option<&ContainerCredentials>,
) -> Result<()> {
    match docker.inspect_image(image).await {
        Ok(_) => {
            debug!("Docker image already present");
            return Ok(());
        }
        Err(_) => {
            info!("pulling Docker image");
        }
    }

    let (repo, tag) = parse_image_ref(image);
    let opts = CreateImageOptions {
        from_image: repo,
        tag,
        ..Default::default()
    };

    let docker_creds = credentials.map(|c| DockerCredentials {
        username: c.username.clone(),
        password: c.password.clone(),
        ..Default::default()
    });

    let mut stream = docker.create_image(Some(opts), None, docker_creds);
    while let Some(result) = stream.next().await {
        result.context("pulling Docker image")?;
    }

    info!("Docker image pulled successfully");
    Ok(())
}

/// Split "image:tag" into ("image", "tag"), defaulting tag to "latest".
fn parse_image_ref(image: &str) -> (&str, &str) {
    // Handle images with registry prefix (e.g., ghcr.io/owner/image:tag)
    // The tag separator is the last colon that's not part of a port/registry
    if let Some(colon_pos) = image.rfind(':') {
        let after_colon = &image[colon_pos + 1..];
        // If there's a slash after the colon, it's part of the registry path, not a tag
        if !after_colon.contains('/') {
            return (&image[..colon_pos], after_colon);
        }
    }
    (image, "latest")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn selected_missing_endpoint_fails_without_default_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let endpoint = DockerEndpoint::unix_socket(&temp.path().join("absent.sock")).unwrap();
        assert!(connect(&endpoint).is_err());
    }

    #[test]
    fn parse_simple_image() {
        assert_eq!(parse_image_ref("ubuntu:22.04"), ("ubuntu", "22.04"));
    }

    #[test]
    fn parse_image_no_tag() {
        assert_eq!(parse_image_ref("ubuntu"), ("ubuntu", "latest"));
    }

    #[test]
    fn parse_image_with_registry() {
        assert_eq!(
            parse_image_ref("ghcr.io/owner/image:v1"),
            ("ghcr.io/owner/image", "v1")
        );
    }

    #[test]
    fn parse_image_with_registry_no_tag() {
        assert_eq!(
            parse_image_ref("ghcr.io/owner/image"),
            ("ghcr.io/owner/image", "latest")
        );
    }
}
