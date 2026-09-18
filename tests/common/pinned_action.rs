use std::ffi::OsString;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chimera::job::action::ActionCache;

pub async fn install_pinned_action(
    actions_dir: &Path,
    owner: &str,
    repo: &str,
    sha: &str,
) -> Result<()> {
    validate_action_name("owner", owner)?;
    validate_action_name("repository", repo)?;
    validate_commit_sha(sha)?;

    let url = format!("https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}");
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?
        .get(url)
        .header("User-Agent", "chimera-test")
        .send()
        .await
        .with_context(|| format!("downloading public action {owner}/{repo}@{sha}"))?;
    if !response.status().is_success() {
        bail!(
            "public action download for {owner}/{repo}@{sha} failed with HTTP {}",
            response.status()
        );
    }
    let bytes = response.bytes().await?;

    // Publish through the production cache layout: get_action resolves
    // remote actions by a content-hash path, so writing an owner/repo/sha
    // directory here would always miss the cache and send the runner to the
    // GitHub API with the harness's non-production token.
    ActionCache::new(actions_dir.to_path_buf(), reqwest::Client::new())
        .install_tarball(owner, repo, sha, &bytes)
        .await
}

fn validate_action_name(label: &str, value: &str) -> Result<()> {
    let mut components = Path::new(value).components();
    let is_single_normal =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    let has_only_url_safe_characters = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if value.is_empty()
        || value == "."
        || value == ".."
        || !is_single_normal
        || !has_only_url_safe_characters
    {
        bail!("unsafe action {label}");
    }
    Ok(())
}

fn validate_commit_sha(sha: &str) -> Result<()> {
    if sha.len() != 40 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("pinned action SHA must be a 40-character hexadecimal commit");
    }
    Ok(())
}

fn path_exists(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

fn action_cache_is_ready(destination: &Path) -> Result<bool> {
    let metadata = match std::fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("reading pinned action cache destination"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("pinned action cache destination is not a directory");
    }

    for name in ["action.yml", "action.yaml"] {
        let path = destination.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("pinned action metadata is a symbolic link");
            }
            Ok(metadata) if metadata.is_file() => return Ok(true),
            Ok(_) => bail!("pinned action metadata is not a regular file"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("reading pinned action metadata at {}", path.display())
                });
            }
        }
    }
    Ok(false)
}

pub fn publish_action_archive(bytes: &[u8], destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .context("action cache destination has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("action"),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&temporary)?;

    let publication = (|| -> Result<()> {
        extract_public_action(bytes, &temporary)?;
        if !action_cache_is_ready(&temporary)? {
            bail!("downloaded pinned action has no action metadata");
        }

        match std::fs::rename(&temporary, destination) {
            Ok(()) => Ok(()),
            Err(_) if path_exists(destination) && action_cache_is_ready(destination)? => Ok(()),
            Err(error) => Err(error).context("publishing pinned action cache directory"),
        }
    })();

    let cleanup = if path_exists(&temporary) {
        std::fs::remove_dir_all(&temporary)
    } else {
        Ok(())
    };
    match (publication, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => {
            Err(cleanup_error).with_context(|| format!("removing {}", temporary.display()))
        }
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "also failed to remove {}: {cleanup_error}",
            temporary.display()
        ))),
    }
}

pub fn extract_public_action(bytes: &[u8], destination: &Path) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut github_prefix: Option<OsString> = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_pax_global_extensions() {
            continue;
        }
        let archive_path = entry.path()?.into_owned();
        if archive_path.is_absolute()
            || archive_path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            bail!("public action archive contains an unsafe path");
        }

        let mut components = archive_path.components();
        let prefix = match components.next() {
            Some(Component::Normal(prefix)) => prefix.to_os_string(),
            _ => bail!("public action archive contains an unsafe path"),
        };
        if let Some(expected) = &github_prefix {
            if expected != &prefix {
                bail!("public action archive contains multiple top-level prefixes");
            }
        } else {
            github_prefix = Some(prefix);
        }

        let relative: PathBuf = components.collect();
        if relative.as_os_str().is_empty() {
            if entry_type.is_dir() {
                continue;
            }
            bail!(
                "public action archive prefix is not a directory: {} ({entry_type:?})",
                archive_path.display()
            );
        }
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            bail!("public action archive contains an unsafe path");
        }

        let target = destination.join(&relative);
        if !target.starts_with(destination) {
            bail!("public action archive escaped extraction root");
        }
        if entry_type.is_dir() {
            std::fs::create_dir_all(&target)?;
            continue;
        }
        if !entry_type.is_file() {
            bail!("public action archive contains a non-file entry");
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        io::copy(&mut entry, &mut file)?;
        let mode = entry.header().mode()? & 0o777;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}
