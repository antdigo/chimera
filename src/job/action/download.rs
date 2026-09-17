use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use std::{
    ffi::{CString, OsStr},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use tracing::{debug, warn};

use super::resolve::ActionSource;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn matches(self, metadata: &fs::Metadata) -> bool {
        self == Self::from_metadata(metadata)
    }
}

#[derive(Clone, Debug)]
pub struct TrustedActionDirectory {
    // Pathname identities are only consulted by the non-Linux fail-closed
    // fallback; Linux pins the directories by open descriptor instead.
    #[cfg(not(target_os = "linux"))]
    source_path: PathBuf,
    action_path: PathBuf,
    source_identity: DirectoryIdentity,
    action_identity: DirectoryIdentity,
    #[cfg(target_os = "linux")]
    _source_descriptor: Arc<fs::File>,
    #[cfg(target_os = "linux")]
    action_descriptor: Arc<fs::File>,
}

impl TrustedActionDirectory {
    pub(crate) fn resolve(source_root: &Path, requested: &Path) -> Result<Self> {
        contained_action_dir(source_root, requested)
    }

    pub fn path(&self) -> &Path {
        &self.action_path
    }

    pub(crate) fn validate_path_identity(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let _ = (self.source_identity, self.action_identity);
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            let source_metadata = fs::metadata(&self.source_path)
                .map_err(|_| anyhow::anyhow!("action directory changed after it was resolved"))?;
            let action_metadata = fs::metadata(&self.action_path)
                .map_err(|_| anyhow::anyhow!("action directory changed after it was resolved"))?;
            if !source_metadata.is_dir()
                || !action_metadata.is_dir()
                || !self.source_identity.matches(&source_metadata)
                || !self.action_identity.matches(&action_metadata)
            {
                bail!("action directory changed after it was resolved");
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn clone_directory_descriptor(&self) -> Result<fs::File> {
        self.action_descriptor
            .try_clone()
            .context("cloning trusted action directory descriptor")
    }

    pub(crate) fn read_optional_regular_file(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = Path::new(name);
        if path.components().count() != 1
            || !matches!(path.components().next(), Some(Component::Normal(_)))
        {
            bail!("action metadata path must name a direct child");
        }

        #[cfg(target_os = "linux")]
        {
            let name = OsStr::new(name);
            let inspected = match open_at_raw(
                &self.action_descriptor,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            ) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error).context("opening action metadata"),
            };
            let inspected_metadata = inspected.metadata().context("reading action metadata")?;
            if !inspected_metadata.is_file() {
                bail!("action metadata must be a regular file");
            }
            let expected = DirectoryIdentity::from_metadata(&inspected_metadata);
            let mut file = open_at_raw(
                &self.action_descriptor,
                name,
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
            .context("opening action metadata")?;
            let opened_metadata = file.metadata().context("reading action metadata")?;
            if !opened_metadata.is_file() || !expected.matches(&opened_metadata) {
                bail!("action metadata changed while it was being read");
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .context("reading action metadata")?;
            return Ok(Some(bytes));
        }

        #[cfg(not(target_os = "linux"))]
        {
            self.validate_path_identity()?;
            let metadata_path = self.action_path.join(name);
            let inspected_metadata = match fs::symlink_metadata(&metadata_path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error).context("reading action metadata"),
            };
            if !inspected_metadata.is_file() {
                bail!("action metadata must be a regular file");
            }
            let expected = DirectoryIdentity::from_metadata(&inspected_metadata);
            self.validate_path_identity()?;
            let mut file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&metadata_path)
                .context("opening action metadata")?;
            let opened_metadata = file.metadata().context("reading action metadata")?;
            if !opened_metadata.is_file() || !expected.matches(&opened_metadata) {
                bail!("action metadata changed while it was being read");
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .context("reading action metadata")?;
            Ok(Some(bytes))
        }
    }
}

pub struct ActionCache {
    cache_dir: PathBuf,
    client: reqwest::Client,
}

impl ActionCache {
    pub fn new(cache_dir: PathBuf, client: reqwest::Client) -> Self {
        Self { cache_dir, client }
    }

    pub async fn get_action(
        &self,
        source: &ActionSource,
        workspace_dir: &Path,
        access_token: &str,
    ) -> Result<TrustedActionDirectory> {
        match source {
            ActionSource::Remote {
                owner,
                repo,
                git_ref,
                path,
            } => {
                let cache_path = remote_cache_path(&self.cache_dir, owner, repo, git_ref);

                if !cache_path.exists() {
                    self.download_tarball(owner, repo, git_ref, &cache_path, access_token)
                        .await?;
                } else {
                    debug!(owner, repo, git_ref, "action cache hit");
                }

                TrustedActionDirectory::resolve(
                    &cache_path,
                    path.as_deref().map(Path::new).unwrap_or(Path::new(".")),
                )
            }
            ActionSource::Local { path } => TrustedActionDirectory::resolve(workspace_dir, path),
            ActionSource::Docker { image } => {
                bail!("Docker action '{image}' should be handled before get_action is called")
            }
        }
    }

    async fn download_tarball(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
        dest: &Path,
        access_token: &str,
    ) -> Result<()> {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/tarball/{git_ref}");
        debug!(%url, "downloading action tarball");

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("token {access_token}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "chimera")
            .send()
            .await
            .with_context(|| format!("requesting tarball for {owner}/{repo}@{git_ref}"))?;

        if !response.status().is_success() {
            bail!(
                "failed to download {owner}/{repo}@{git_ref}: HTTP {}",
                response.status()
            );
        }

        let bytes = response
            .bytes()
            .await
            .context("reading tarball response body")?;

        // Extract to a temp directory, then atomically rename to avoid TOCTOU races.
        // All filesystem I/O runs on the blocking threadpool to avoid starving the runtime.
        let tmp_name = format!(
            "{}.tmp-{}",
            dest.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("action"),
            uuid::Uuid::new_v4()
        );
        let tmp_dir = dest.parent().context("dest has no parent")?.join(&tmp_name);
        let dest = dest.to_path_buf();
        let owner = owner.to_string();
        let repo = repo.to_string();
        let git_ref = git_ref.to_string();

        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&tmp_dir)
                .with_context(|| format!("creating temp action dir {}", tmp_dir.display()))?;

            extract_tarball(&bytes, &tmp_dir)
                .with_context(|| format!("extracting tarball for {owner}/{repo}@{git_ref}"))?;

            match std::fs::rename(&tmp_dir, &dest) {
                Ok(()) => {}
                Err(e) if dest.exists() => {
                    debug!(error = %e, "action cache dir already exists (concurrent download), using existing");
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                }
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    return Err(e).context("renaming temp action dir to final location");
                }
            }

            Ok(())
        })
        .await
        .context("extract task panicked")?
    }
}

fn normalize_relative_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("action path must stay inside its source root");
            }
        }
    }
    Ok(normalized)
}

fn contained_action_dir(root: &Path, requested: &Path) -> Result<TrustedActionDirectory> {
    let relative = normalize_relative_path(requested)?;
    let canonical_root = root
        .canonicalize()
        .context("resolving action source root")?;
    let source_metadata = fs::metadata(&canonical_root).context("reading action source root")?;
    if !source_metadata.is_dir() {
        bail!("action source root is not a directory");
    }
    let canonical_action = canonical_root
        .join(relative)
        .canonicalize()
        .context("resolving action directory")?;
    let action_metadata = fs::metadata(&canonical_action).context("reading action directory")?;

    if !canonical_action.starts_with(&canonical_root) || !action_metadata.is_dir() {
        bail!("action path must stay inside its source root");
    }

    let source_identity = DirectoryIdentity::from_metadata(&source_metadata);
    let action_identity = DirectoryIdentity::from_metadata(&action_metadata);

    #[cfg(target_os = "linux")]
    {
        let source_descriptor =
            open_directory_path(&canonical_root).context("opening trusted action source root")?;
        if !source_identity.matches(
            &source_descriptor
                .metadata()
                .context("reading trusted action source root")?,
        ) {
            bail!("action source root changed while it was being resolved");
        }
        let action_relative = canonical_action
            .strip_prefix(&canonical_root)
            .context("action path must stay inside its source root")?;
        let action_descriptor = open_relative_directory(&source_descriptor, action_relative)
            .context("opening trusted action directory")?;
        if !action_identity.matches(
            &action_descriptor
                .metadata()
                .context("reading trusted action directory")?,
        ) {
            bail!("action directory changed while it was being resolved");
        }

        return Ok(TrustedActionDirectory {
            action_path: canonical_action,
            source_identity,
            action_identity,
            _source_descriptor: Arc::new(source_descriptor),
            action_descriptor: Arc::new(action_descriptor),
        });
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(TrustedActionDirectory {
            source_path: canonical_root,
            action_path: canonical_action,
            source_identity,
            action_identity,
        })
    }
}

#[cfg(target_os = "linux")]
fn open_directory_path(path: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("opening directory")?;
    if !file
        .metadata()
        .context("reading directory metadata")?
        .is_dir()
    {
        bail!("action path must stay inside its source root");
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_relative_directory(root: &fs::File, relative: &Path) -> Result<fs::File> {
    let mut directory = root.try_clone().context("cloning action source root")?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            bail!("action path must stay inside its source root");
        };
        directory = open_at_raw(
            &directory,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .context("opening action directory component")?;
        if !directory
            .metadata()
            .context("reading action directory component")?
            .is_dir()
        {
            bail!("action path must stay inside its source root");
        }
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn open_at_raw(parent: &fs::File, name: &OsStr, flags: libc::c_int) -> std::io::Result<fs::File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // `openat` returned an owned descriptor, so `File` closes it on drop.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

fn remote_cache_path(cache_dir: &Path, owner: &str, repo: &str, git_ref: &str) -> PathBuf {
    let mut hasher = blake3::Hasher::new();
    for field in [
        b"remote-v1".as_slice(),
        owner.as_bytes(),
        repo.as_bytes(),
        git_ref.as_bytes(),
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    cache_dir
        .join("remote-v1")
        .join(hasher.finalize().to_hex().to_string())
}

/// Returns true if the path contains `..` components that could escape the destination.
fn has_path_traversal(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
}

// `pub(crate)` so the Docker build-context end-to-end test can drive the real
// extraction path instead of re-implementing it.
pub(crate) fn extract_tarball(data: &[u8], dest: &Path) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries().context("reading tarball entries")? {
        let mut entry = entry.context("reading tarball entry")?;
        let entry_path = entry.path().context("reading entry path")?.into_owned();

        // Strip the first path component (GitHub adds a prefix like "owner-repo-sha/")
        let stripped: PathBuf = entry_path.components().skip(1).collect();
        if stripped.as_os_str().is_empty() {
            continue;
        }

        if has_path_traversal(&stripped) {
            warn!(path = %entry_path.display(), "skipping tarball entry with path traversal");
            continue;
        }

        let target = dest.join(&stripped);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            let header_mode = entry
                .header()
                .mode()
                .context("reading tarball entry mode")?;
            let mut file = std::fs::File::create(&target)
                .with_context(|| format!("creating {}", target.display()))?;
            std::io::copy(&mut entry, &mut file)
                .with_context(|| format!("writing {}", target.display()))?;
            restore_executable_bits(&file, header_mode)?;
        }
    }

    Ok(())
}

/// Restores only the executable bits from the tar header on the extracted
/// file. Read/write permissions stay governed by the local umask, and setuid,
/// setgid, sticky, and any other header bits never carry over.
fn restore_executable_bits(file: &fs::File, header_mode: u32) -> Result<()> {
    let executable_bits = header_mode & 0o111;
    if executable_bits == 0 {
        return Ok(());
    }
    let mut permissions = file
        .metadata()
        .context("reading extracted file metadata")?
        .permissions();
    let mode = permissions.mode();
    permissions.set_mode((mode & !0o111) | executable_bits);
    file.set_permissions(permissions)
        .context("setting executable bits on extracted file")?;
    Ok(())
}

#[cfg(test)]
#[path = "download_test.rs"]
mod download_test;
