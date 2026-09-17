use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;

pub const ALICE_USER: &str = "alice";
pub const ALICE_PASSWORD: &str = "alpha-pass";
pub const BOB_USER: &str = "bob";
pub const BOB_PASSWORD: &str = "beta-pass";

pub struct AuthenticatedRegistry {
    temp: tempfile::TempDir,
    container_name: String,
    address: String,
    setup_docker_config: PathBuf,
    local_images: Mutex<Vec<String>>,
}

impl AuthenticatedRegistry {
    pub async fn start() -> Result<Self> {
        let temp = tempfile::tempdir().context("creating authenticated registry directory")?;
        let auth_dir = temp.path().join("auth");
        let setup_docker_config = temp.path().join("setup-docker");
        std::fs::create_dir(&auth_dir).context("creating registry authentication directory")?;
        std::fs::create_dir(&setup_docker_config)
            .context("creating registry Docker configuration directory")?;
        std::fs::set_permissions(&auth_dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&setup_docker_config, std::fs::Permissions::from_mode(0o700))?;

        let alice = docker_output(
            &[
                "run",
                "--rm",
                "-i",
                "httpd:2.4-alpine",
                "htpasswd",
                "-Bni",
                ALICE_USER,
            ],
            &setup_docker_config,
            Some(ALICE_PASSWORD.as_bytes()),
        )
        .await?;
        let bob = docker_output(
            &[
                "run",
                "--rm",
                "-i",
                "httpd:2.4-alpine",
                "htpasswd",
                "-Bni",
                BOB_USER,
            ],
            &setup_docker_config,
            Some(BOB_PASSWORD.as_bytes()),
        )
        .await?;
        let htpasswd = auth_dir.join("htpasswd");
        std::fs::write(&htpasswd, format!("{alice}{bob}"))
            .context("writing registry password file")?;
        std::fs::set_permissions(&htpasswd, std::fs::Permissions::from_mode(0o600))?;

        let container_name = format!("chimera-registry-{}", uuid::Uuid::new_v4().simple());
        let auth_mount = format!("{}:/auth:ro", auth_dir.display());
        let start_result = docker_output(
            &[
                "run",
                "-d",
                "--name",
                &container_name,
                "-p",
                "127.0.0.1::5000",
                "-v",
                &auth_mount,
                "-e",
                "REGISTRY_AUTH=htpasswd",
                "-e",
                "REGISTRY_AUTH_HTPASSWD_REALM=chimera-test",
                "-e",
                "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
                "registry:2",
            ],
            &setup_docker_config,
            None,
        )
        .await;
        if let Err(error) = start_result {
            let _ = docker_cleanup(
                &registry_container_cleanup_args(&container_name),
                &setup_docker_config,
            );
            return Err(error);
        }

        let mut registry = Self {
            temp,
            container_name,
            address: String::new(),
            setup_docker_config,
            local_images: Mutex::new(Vec::new()),
        };
        let port = docker_output(
            &["port", &registry.container_name, "5000/tcp"],
            &registry.setup_docker_config,
            None,
        )
        .await?;
        registry.address = port
            .lines()
            .find_map(|line| line.trim().strip_prefix("127.0.0.1:"))
            .map(|port| format!("127.0.0.1:{port}"))
            .context("registry did not publish an IPv4 loopback port")?;

        let health_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            match health_client
                .get(format!("http://{}/v2/", registry.address))
                .send()
                .await
            {
                Ok(response) if response.status() == reqwest::StatusCode::UNAUTHORIZED => break,
                _ if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                _ => bail!("authenticated test registry did not become ready"),
            }
        }

        Ok(registry)
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn track_local_image(&self, image: String) {
        let mut images = self
            .local_images
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !images.contains(&image) {
            images.push(image);
        }
    }

    pub async fn remove_local_image(&self, image: &str) -> Result<()> {
        docker_output(
            &["image", "rm", "-f", "--", image],
            &self.setup_docker_config,
            None,
        )
        .await?;
        self.local_images
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|tracked| tracked != image);
        Ok(())
    }

    pub async fn seed_image(&self, repository: &str, tag: &str) -> Result<String> {
        let context = self
            .temp
            .path()
            .join(format!("seed-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&context).context("creating seed image context")?;
        std::fs::write(
            context.join("Dockerfile"),
            "FROM scratch\nCOPY marker /marker\n",
        )?;
        std::fs::write(context.join("marker"), "synthetic-registry-probe\n")?;
        let image = format!("{}/{repository}:{tag}", self.address);
        let context_path = context.to_string_lossy().into_owned();

        docker_output(
            &[
                "login",
                "--username",
                ALICE_USER,
                "--password-stdin",
                &self.address,
            ],
            &self.setup_docker_config,
            Some(ALICE_PASSWORD.as_bytes()),
        )
        .await?;
        self.track_local_image(image.clone());
        let operation = async {
            docker_output(
                &["build", "--tag", &image, &context_path],
                &self.setup_docker_config,
                None,
            )
            .await?;
            docker_output(&["push", &image], &self.setup_docker_config, None).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let logout =
            docker_output(&["logout", &self.address], &self.setup_docker_config, None).await;
        operation?;
        logout?;
        Ok(image)
    }
}

impl Drop for AuthenticatedRegistry {
    fn drop(&mut self) {
        let images = self
            .local_images
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for image in images.drain(..) {
            match docker_cleanup(
                &["image", "rm", "-f", "--", &image],
                &self.setup_docker_config,
            ) {
                Ok(()) => {}
                Err(error) => eprintln!("failed to remove synthetic test image {image}: {error}"),
            }
        }

        if let Err(error) = docker_cleanup(
            &registry_container_cleanup_args(&self.container_name),
            &self.setup_docker_config,
        ) {
            eprintln!(
                "failed to remove test registry {}: {error}",
                self.container_name
            );
        }
    }
}

pub fn registry_container_cleanup_args(container_name: &str) -> [&str; 5] {
    ["rm", "--force", "--volumes", "--", container_name]
}

pub fn docker_cleanup(args: &[&str], docker_config: &Path) -> Result<()> {
    let mut child = std::process::Command::new("docker")
        .args(args)
        .env("DOCKER_CONFIG", docker_config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("starting Docker CLI cleanup command")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            bail!("Docker CLI cleanup command failed with status {status}");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Docker CLI cleanup command timed out");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub async fn docker_output(
    args: &[&str],
    docker_config: &Path,
    stdin: Option<&[u8]>,
) -> Result<String> {
    let mut command = tokio::process::Command::new("docker");
    command
        .args(args)
        .env("DOCKER_CONFIG", docker_config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command
        .spawn()
        .context("starting Docker CLI test command")?;
    let output = tokio::time::timeout(Duration::from_secs(300), async move {
        if let Some(input) = stdin {
            let mut child_stdin = child
                .stdin
                .take()
                .context("Docker CLI stdin was not piped")?;
            child_stdin.write_all(input).await?;
            child_stdin.shutdown().await?;
        }
        child.wait_with_output().await.map_err(anyhow::Error::from)
    })
    .await
    .context("Docker CLI test command timed out")??;
    if !output.status.success() {
        bail!(
            "Docker CLI test command `docker {}` failed with status {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("Docker CLI output was not UTF-8")
}
