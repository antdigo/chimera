use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
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
        assert_local_auth_only(
            &setup_config_json(&self.setup_docker_config)?,
            &self.address,
        )?;
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
        assert_local_auth_absent(
            &setup_config_json(&self.setup_docker_config)?,
            &self.address,
        )?;
        Ok(image)
    }
}

fn setup_config_json(setup_docker_config: &Path) -> Result<String> {
    std::fs::read_to_string(setup_docker_config.join("config.json"))
        .context("reading the harness setup Docker config")
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

/// Resolve the exact docker CLI from a PATH value so harness children run a
/// known executable instead of re-resolving `docker` inside an environment the
/// harness does not control.
pub fn resolve_docker_cli(path_value: &OsStr) -> Result<PathBuf> {
    for dir in std::env::split_paths(path_value) {
        let candidate = dir.join("docker");
        if let Ok(metadata) = std::fs::metadata(&candidate)
            && metadata.is_file()
            && metadata.permissions().mode() & 0o111 != 0
        {
            return Ok(candidate);
        }
    }
    bail!("no executable docker CLI found on the test PATH")
}

/// The exact environment harness docker children run with: the local
/// DOCKER_CONFIG credential store, a PATH that cannot resolve
/// docker-credential-* helpers (credentials must live in config.json, never in
/// an implicit keychain), and the rootless socket variables when the test
/// runner provides them. Everything ambient is deliberately dropped — notably
/// DOCKER_CONTEXT and HOME (an ambient context or user config must not
/// redirect the harness) and HTTP(S)_PROXY/ALL_PROXY/NO_PROXY (the harness
/// talks to loopback endpoints only).
pub fn harness_child_env(
    docker_config: &Path,
    helper_free_path: &Path,
    docker_host: Option<&str>,
    xdg_runtime_dir: Option<&str>,
    tmpdir: Option<&str>,
) -> HashMap<String, String> {
    let mut environment = HashMap::from([
        (
            "DOCKER_CONFIG".to_string(),
            docker_config.to_string_lossy().into_owned(),
        ),
        (
            "PATH".to_string(),
            helper_free_path.to_string_lossy().into_owned(),
        ),
    ]);
    if let Some(value) = docker_host {
        environment.insert("DOCKER_HOST".to_string(), value.to_string());
    }
    if let Some(value) = xdg_runtime_dir {
        environment.insert("XDG_RUNTIME_DIR".to_string(), value.to_string());
    }
    if let Some(value) = tmpdir {
        environment.insert("TMPDIR".to_string(), value.to_string());
    }
    environment
}

/// A private directory that will never contain docker-credential-* helpers;
/// the harness PATH points here so implicit credential helpers cannot load.
fn helper_free_bin_dir() -> Result<PathBuf> {
    static BIN_DIR: OnceLock<PathBuf> = OnceLock::new();
    if let Some(path) = BIN_DIR.get() {
        return Ok(path.clone());
    }
    let dir = std::env::temp_dir().join(format!(
        "chimera-docker-harness-path-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&dir).context("creating helper-free harness PATH directory")?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .context("restricting helper-free harness PATH directory")?;
    // The directory intentionally lives for the whole test process; the OS
    // reclaims it under the system temp dir once the process exits.
    Ok(BIN_DIR.get_or_init(|| dir).clone())
}

fn harness_child_env_from_process(docker_config: &Path) -> Result<HashMap<String, String>> {
    let non_empty = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let docker_host = non_empty("DOCKER_HOST");
    let xdg_runtime_dir = non_empty("XDG_RUNTIME_DIR");
    let tmpdir = non_empty("TMPDIR");
    Ok(harness_child_env(
        docker_config,
        &helper_free_bin_dir()?,
        docker_host.as_deref(),
        xdg_runtime_dir.as_deref(),
        tmpdir.as_deref(),
    ))
}

/// The harness must keep registry credentials in the local DOCKER_CONFIG store
/// only: no credential store or per-registry helper may be configured, and the
/// test registry must have a non-empty inline auth entry. Fails closed without
/// echoing the credential value.
pub fn assert_local_auth_only(config_json: &str, registry: &str) -> Result<()> {
    let config: serde_json::Value =
        serde_json::from_str(config_json).context("Docker config was not valid JSON")?;
    if config
        .get("credsStore")
        .is_some_and(|value| !value.is_null())
    {
        bail!("Docker config must not configure a credential store");
    }
    if config
        .get("credHelpers")
        .is_some_and(|value| !value.is_null())
    {
        bail!("Docker config must not configure per-registry credential helpers");
    }
    let has_inline_auth = config
        .get("auths")
        .and_then(|auths| auths.get(registry))
        .and_then(|entry| entry.get("auth"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.is_empty());
    if !has_inline_auth {
        bail!("Docker config has no non-empty auth entry for the test registry");
    }
    Ok(())
}

/// After logout the local store must no longer carry an entry for the test
/// registry; a remaining entry means the credential flow bypassed config.json.
pub fn assert_local_auth_absent(config_json: &str, registry: &str) -> Result<()> {
    let config: serde_json::Value =
        serde_json::from_str(config_json).context("Docker config was not valid JSON")?;
    if config
        .get("auths")
        .and_then(|auths| auths.get(registry))
        .is_some()
    {
        bail!("Docker config still has an auth entry for the test registry");
    }
    Ok(())
}

fn docker_cli_from_process() -> Result<PathBuf> {
    resolve_docker_cli(
        &std::env::var_os("PATH").context("the test process has no PATH to resolve docker")?,
    )
}

pub fn docker_cleanup(args: &[&str], docker_config: &Path) -> Result<()> {
    let mut child = std::process::Command::new(docker_cli_from_process()?)
        .args(args)
        .env_clear()
        .envs(&harness_child_env_from_process(docker_config)?)
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
    let mut command = tokio::process::Command::new(docker_cli_from_process()?);
    command
        .args(args)
        .env_clear()
        .envs(&harness_child_env_from_process(docker_config)?)
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
