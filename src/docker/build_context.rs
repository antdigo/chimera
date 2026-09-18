use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(target_os = "linux")]
use std::{
    ffi::{CStr, CString, OsStr, OsString},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
};

use anyhow::{Context, Result, bail};

use crate::job::action::TrustedActionDirectory;

#[derive(Debug)]
pub(crate) struct ResolvedBuildPaths {
    // Pathname fields feed the non-Linux fail-closed fallback; Linux resolves
    // and traverses everything relative to the pinned `root` descriptor.
    #[cfg(not(target_os = "linux"))]
    pub action_root: PathBuf,
    #[cfg(not(target_os = "linux"))]
    pub dockerfile_path: PathBuf,
    pub dockerfile_relative: PathBuf,
    #[cfg(not(target_os = "linux"))]
    trusted_action: TrustedActionDirectory,
    #[cfg(target_os = "linux")]
    root: fs::File,
}

pub(crate) fn resolve_build_paths(
    action_dir: &TrustedActionDirectory,
    dockerfile: &str,
) -> Result<ResolvedBuildPaths> {
    let dockerfile_relative = normalize_dockerfile_path(Path::new(dockerfile))?;

    #[cfg(target_os = "linux")]
    {
        let root = action_dir.clone_directory_descriptor()?;
        match resolve_file_chain_linux(&root, &dockerfile_relative) {
            Ok(Some(_)) => {}
            Ok(None) => bail!("resolving Dockerfile"),
            Err(error)
                if error.to_string()
                    == "build context symlink must stay inside the action directory" =>
            {
                bail!("Dockerfile must resolve inside the action directory")
            }
            Err(error) => return Err(error),
        }
        return Ok(ResolvedBuildPaths {
            dockerfile_relative,
            root,
        });
    }

    #[cfg(not(target_os = "linux"))]
    {
        let action_root = action_dir.path().to_path_buf();
        action_dir.validate_path_identity()?;
        let dockerfile_path = action_root
            .join(&dockerfile_relative)
            .canonicalize()
            .context("resolving Dockerfile")?;
        action_dir.validate_path_identity()?;
        if !dockerfile_path.starts_with(&action_root) {
            bail!("Dockerfile must resolve inside the action directory");
        }
        if !dockerfile_path.is_file() {
            bail!("Dockerfile must be a regular file");
        }

        Ok(ResolvedBuildPaths {
            action_root,
            dockerfile_path,
            dockerfile_relative,
            trusted_action: action_dir.clone(),
        })
    }
}

impl ResolvedBuildPaths {
    #[cfg(not(target_os = "linux"))]
    fn validate_path_identity(&self) -> Result<()> {
        self.trusted_action.validate_path_identity()
    }
}

fn normalize_dockerfile_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("Dockerfile path must be relative to the action directory");
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        bail!("Dockerfile path must name a file");
    }
    Ok(normalized)
}

struct IgnoreRule {
    include: bool,
    has_separator: bool,
    pattern: glob::Pattern,
}

#[derive(Default)]
struct IgnoreRules {
    rules: Vec<IgnoreRule>,
}

struct IgnoreFile {
    selected: PathBuf,
    canonical: PathBuf,
}

impl IgnoreRules {
    fn load(paths: &ResolvedBuildPaths) -> Result<(Self, Option<IgnoreFile>)> {
        let dockerfile_name = paths
            .dockerfile_relative
            .file_name()
            .and_then(|name| name.to_str())
            .context("Dockerfile name is not valid UTF-8")?;
        let specific = paths
            .dockerfile_relative
            .with_file_name(format!("{dockerfile_name}.dockerignore"));
        let selected = if let Some(file) = read_optional_regular_file_inside(paths, &specific)? {
            Some((specific, file))
        } else {
            let root = PathBuf::from(".dockerignore");
            read_optional_regular_file_inside(paths, &root)?.map(|file| (root, file))
        };

        let Some((relative, (bytes, canonical))) = selected else {
            return Ok((Self::default(), None));
        };
        let text = std::str::from_utf8(&bytes).context("Docker ignore file is not valid UTF-8")?;
        // A single leading BOM must not corrupt the first rule.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut rules = Vec::new();
        for (line_number, raw) in text.lines().enumerate() {
            let trimmed = raw.trim();
            // Docker escapes a literal leading `#` as `\#`; the escape has to
            // be removed before comment detection so the compiled pattern
            // keeps its literal `#`.
            let (escaped_hash, trimmed) = match trimmed.strip_prefix('\\') {
                Some(rest) if rest.starts_with('#') => (true, rest),
                _ => (false, trimmed),
            };
            if trimmed.is_empty() || trimmed == "." || (!escaped_hash && trimmed.starts_with('#')) {
                continue;
            }
            let (include, body) = match trimmed.strip_prefix('!') {
                Some(pattern) => (true, pattern),
                None => (false, trimmed),
            };
            let cleaned = clean_dockerignore_pattern(body);
            if cleaned.is_empty() || cleaned == "." {
                continue;
            }
            let pattern = glob::Pattern::new(&cleaned).with_context(|| {
                format!("invalid Docker ignore rule at line {}", line_number + 1)
            })?;
            rules.push(IgnoreRule {
                include,
                has_separator: cleaned.contains('/'),
                pattern,
            });
        }
        Ok((
            Self { rules },
            Some(IgnoreFile {
                selected: relative,
                canonical,
            }),
        ))
    }

    fn includes(&self, relative: &Path) -> Result<bool> {
        let slash_path = path_to_slash_string(relative)?;
        let mut included = true;
        for rule in &self.rules {
            if rule_matches(rule, &slash_path) {
                included = rule.include;
            }
        }
        Ok(included)
    }
}

fn clean_dockerignore_pattern(pattern: &str) -> String {
    let rooted = pattern.starts_with('/');
    let mut components = Vec::new();
    for component in pattern.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if matches!(components.last(), Some(previous) if *previous != "..") {
                    components.pop();
                } else if !rooted {
                    components.push(component);
                }
            }
            _ => components.push(component),
        }
    }
    components.join("/")
}

fn rule_matches(rule: &IgnoreRule, slash_path: &str) -> bool {
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    if !rule.has_separator {
        return slash_path
            .split('/')
            .any(|component| rule.pattern.matches_with(component, options));
    }

    slash_path
        .match_indices('/')
        .map(|(index, _)| &slash_path[..index])
        .chain(std::iter::once(slash_path))
        .any(|candidate| rule.pattern.matches_with(candidate, options))
}

fn read_optional_regular_file_inside(
    paths: &ResolvedBuildPaths,
    relative: &Path,
) -> Result<Option<(Vec<u8>, PathBuf)>> {
    #[cfg(target_os = "linux")]
    {
        let Some(resolved) = resolve_descriptor_path_linux(&paths.root, relative)? else {
            return Ok(None);
        };
        if !resolved.canonical_metadata.is_file() {
            return Ok(None);
        }
        let name = resolved
            .canonical_relative
            .file_name()
            .context("build context file has no name")?;
        let parent = resolved
            .canonical_relative
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let parent = open_relative_directory(&paths.root, parent)?;
        let expected = FileIdentity::from_metadata(&resolved.canonical_metadata);
        let file = open_regular_file_at(&parent, name, expected)?;
        let (bytes, _) = read_open_file(file)?;
        return Ok(Some((bytes, resolved.canonical_relative)));
    }

    #[cfg(not(target_os = "linux"))]
    {
        paths.validate_path_identity()?;
        let source = paths.action_root.join(relative);
        let metadata = match fs::metadata(&source) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("reading Docker build context file"),
        };
        if !metadata.is_file() {
            return Ok(None);
        }
        paths.validate_path_identity()?;
        let canonical = source
            .canonicalize()
            .context("resolving Docker build context file")?;
        paths.validate_path_identity()?;
        if !canonical.starts_with(&paths.action_root) {
            bail!("build context file must stay inside the action directory");
        }
        let canonical_relative = canonical
            .strip_prefix(&paths.action_root)
            .context("build context file is outside the action directory")?
            .to_path_buf();
        let (bytes, _) = read_context_file(&paths.action_root, &canonical, None)?;
        paths.validate_path_identity()?;
        Ok(Some((bytes, canonical_relative)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
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

struct DockerfileChain {
    forced_paths: HashSet<PathBuf>,
    expected_links: HashMap<PathBuf, PathBuf>,
    canonical_relative: PathBuf,
    canonical_identity: FileIdentity,
}

impl DockerfileChain {
    fn resolve(paths: &ResolvedBuildPaths) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let resolved = resolve_file_chain_linux(&paths.root, &paths.dockerfile_relative)?
                .context("resolving Dockerfile symlink chain")?;
            return Ok(Self {
                forced_paths: resolved.forced_paths,
                expected_links: resolved.expected_links,
                canonical_relative: resolved.canonical_relative,
                canonical_identity: resolved.canonical_identity,
            });
        }

        #[cfg(not(target_os = "linux"))]
        {
            paths.validate_path_identity()?;
            let canonical_relative = paths
                .dockerfile_path
                .strip_prefix(&paths.action_root)
                .context("resolved Dockerfile is outside the action directory")?
                .to_path_buf();
            let canonical_metadata = fs::metadata(&paths.dockerfile_path)
                .context("reading resolved Dockerfile metadata")?;
            paths.validate_path_identity()?;
            if !canonical_metadata.is_file() {
                bail!("Dockerfile must be a regular file");
            }

            let mut forced_paths = HashSet::from([
                paths.dockerfile_relative.clone(),
                canonical_relative.clone(),
            ]);
            let mut expected_links = HashMap::new();
            let mut remaining = path_components(&paths.dockerfile_relative)?;
            let mut current = PathBuf::new();
            let mut followed_links = 0;

            while let Some(component) = remaining.pop_front() {
                current.push(&component);
                let source = paths.action_root.join(&current);
                paths.validate_path_identity()?;
                let metadata = fs::symlink_metadata(&source)
                    .context("reading Dockerfile path component metadata")?;
                paths.validate_path_identity()?;
                if !metadata.file_type().is_symlink() {
                    continue;
                }

                followed_links += 1;
                if followed_links > 40 {
                    bail!("Dockerfile symlink chain is too deep");
                }
                let target = fs::read_link(&source).context("reading Dockerfile symlink")?;
                paths.validate_path_identity()?;
                validate_symlink(paths, &current, &target)?;
                forced_paths.insert(current.clone());
                expected_links.insert(current.clone(), target.clone());

                let parent = current.parent().unwrap_or_else(|| Path::new(""));
                let target_relative = normalize_contained_target(parent, &target)?;
                let mut expanded = path_components(&target_relative)?;
                expanded.extend(remaining);
                remaining = expanded;
                current = PathBuf::new();
            }

            paths.validate_path_identity()?;
            let resolved = paths
                .action_root
                .join(&current)
                .canonicalize()
                .context("resolving Dockerfile symlink chain")?;
            paths.validate_path_identity()?;
            if resolved != paths.dockerfile_path {
                bail!("Dockerfile changed while the build context was being prepared");
            }

            Ok(Self {
                forced_paths,
                expected_links,
                canonical_relative,
                canonical_identity: FileIdentity::from_metadata(&canonical_metadata),
            })
        }
    }

    fn includes(&self, relative: &Path, ignore_file: Option<&IgnoreFile>) -> bool {
        self.forced_paths.contains(relative)
            || ignore_file.is_some_and(|file| {
                relative == file.selected.as_path() || relative == file.canonical.as_path()
            })
    }

    fn verify_link(
        &self,
        relative: &Path,
        target: &Path,
        seen_links: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        let Some(expected) = self.expected_links.get(relative) else {
            return Ok(());
        };
        if target != expected {
            bail!("Dockerfile changed while the build context was being prepared");
        }
        seen_links.insert(relative.to_path_buf());
        Ok(())
    }

    fn verify_file(
        &self,
        relative: &Path,
        metadata: &fs::Metadata,
        saw_canonical: &mut bool,
    ) -> Result<()> {
        if relative == self.canonical_relative {
            if !self.canonical_identity.matches(metadata) {
                bail!("Dockerfile changed while the build context was being prepared");
            }
            *saw_canonical = true;
        }
        Ok(())
    }

    fn verify_complete(&self, seen_links: &HashSet<PathBuf>, saw_canonical: bool) -> Result<()> {
        if self
            .expected_links
            .keys()
            .all(|path| seen_links.contains(path))
            && saw_canonical
        {
            return Ok(());
        }
        bail!("Dockerfile changed while the build context was being prepared");
    }
}

fn path_components(path: &Path) -> Result<VecDeque<std::ffi::OsString>> {
    let mut components = VecDeque::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => components.push_back(part.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("Dockerfile path must be relative to the action directory");
            }
        }
    }
    Ok(components)
}

#[derive(Debug)]
enum ContextEntryKind {
    Directory,
    File(FileIdentity),
    Symlink(PathBuf),
}

#[derive(Debug)]
struct ContextEntry {
    relative: PathBuf,
    mode: u32,
    kind: ContextEntryKind,
    archive_path: String,
}

#[derive(Default)]
struct TraversalState {
    entries: Vec<ContextEntry>,
    seen_links: HashSet<PathBuf>,
    saw_canonical: bool,
}

struct CollectedContext {
    entries: Vec<ContextEntry>,
    #[cfg(target_os = "linux")]
    root: fs::File,
}

fn collect_context_entries(
    paths: &ResolvedBuildPaths,
    ignore: &IgnoreRules,
    ignore_file: Option<&IgnoreFile>,
) -> Result<CollectedContext> {
    let chain = DockerfileChain::resolve(paths)?;
    let mut state = TraversalState::default();

    #[cfg(target_os = "linux")]
    let root = collect_context_entries_linux(paths, ignore, ignore_file, &chain, &mut state)?;

    #[cfg(not(target_os = "linux"))]
    collect_context_entries_fallback(
        paths,
        ignore,
        ignore_file,
        &chain,
        &paths.action_root,
        &mut state,
    )?;

    chain.verify_complete(&state.seen_links, state.saw_canonical)?;
    Ok(CollectedContext {
        entries: state.entries,
        #[cfg(target_os = "linux")]
        root,
    })
}

#[cfg(not(target_os = "linux"))]
fn collect_context_entries_fallback(
    paths: &ResolvedBuildPaths,
    ignore: &IgnoreRules,
    ignore_file: Option<&IgnoreFile>,
    chain: &DockerfileChain,
    directory: &Path,
    state: &mut TraversalState,
) -> Result<()> {
    paths.validate_path_identity()?;
    for entry in fs::read_dir(directory).context("reading Docker build context directory")? {
        let entry = entry.context("reading Docker build context entry")?;
        let source = entry.path();
        let relative = source
            .strip_prefix(&paths.action_root)
            .context("build context entry is outside the action directory")?
            .to_path_buf();
        let archive_path = path_to_slash_string(&relative)?;
        paths.validate_path_identity()?;
        let metadata = fs::symlink_metadata(&source).context("reading build context metadata")?;
        paths.validate_path_identity()?;
        let file_type = metadata.file_type();
        let forced = chain.includes(&relative, ignore_file);

        if file_type.is_dir() {
            if forced || ignore.includes(&relative)? {
                state.entries.push(ContextEntry {
                    relative: relative.clone(),
                    mode: metadata.mode(),
                    kind: ContextEntryKind::Directory,
                    archive_path,
                });
            }
            collect_context_entries_fallback(paths, ignore, ignore_file, chain, &source, state)?;
            continue;
        }

        if file_type.is_file() {
            chain.verify_file(&relative, &metadata, &mut state.saw_canonical)?;
            if forced || ignore.includes(&relative)? {
                state.entries.push(ContextEntry {
                    relative,
                    mode: metadata.mode(),
                    kind: ContextEntryKind::File(FileIdentity::from_metadata(&metadata)),
                    archive_path,
                });
            }
            continue;
        }

        if file_type.is_symlink() {
            paths.validate_path_identity()?;
            let target = fs::read_link(&source).context("reading build context symlink")?;
            paths.validate_path_identity()?;
            validate_symlink(paths, &relative, &target)?;
            chain.verify_link(&relative, &target, &mut state.seen_links)?;
            if forced || ignore.includes(&relative)? {
                state.entries.push(ContextEntry {
                    relative,
                    mode: metadata.mode(),
                    kind: ContextEntryKind::Symlink(target),
                    archive_path,
                });
            }
            continue;
        }

        bail!("build context contains an unsupported special file");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn collect_context_entries_linux(
    paths: &ResolvedBuildPaths,
    ignore: &IgnoreRules,
    ignore_file: Option<&IgnoreFile>,
    chain: &DockerfileChain,
    state: &mut TraversalState,
) -> Result<fs::File> {
    let root = paths
        .root
        .try_clone()
        .context("cloning trusted action directory descriptor")?;
    collect_directory_entries_linux(
        paths,
        ignore,
        ignore_file,
        chain,
        &root,
        Path::new(""),
        state,
    )?;
    Ok(root)
}

#[cfg(target_os = "linux")]
fn collect_directory_entries_linux(
    paths: &ResolvedBuildPaths,
    ignore: &IgnoreRules,
    ignore_file: Option<&IgnoreFile>,
    chain: &DockerfileChain,
    directory: &fs::File,
    prefix: &Path,
    state: &mut TraversalState,
) -> Result<()> {
    for name in read_directory_names(directory)? {
        let relative = prefix.join(&name);
        let archive_path = path_to_slash_string(&relative)?;
        let inspected = open_at(
            directory,
            &name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        let metadata = inspected
            .metadata()
            .context("reading build context metadata")?;
        let file_type = metadata.file_type();
        let forced = chain.includes(&relative, ignore_file);

        if file_type.is_dir() {
            let child = open_directory_at(directory, &name)?;
            ensure_same_object(
                FileIdentity::from_metadata(&metadata),
                &child.metadata().context("reading build context metadata")?,
            )?;
            if forced || ignore.includes(&relative)? {
                state.entries.push(ContextEntry {
                    relative: relative.clone(),
                    mode: metadata.mode(),
                    kind: ContextEntryKind::Directory,
                    archive_path,
                });
            }
            collect_directory_entries_linux(
                paths,
                ignore,
                ignore_file,
                chain,
                &child,
                &relative,
                state,
            )?;
            continue;
        }

        if file_type.is_file() {
            chain.verify_file(&relative, &metadata, &mut state.saw_canonical)?;
            if forced || ignore.includes(&relative)? {
                state.entries.push(ContextEntry {
                    relative,
                    mode: metadata.mode(),
                    kind: ContextEntryKind::File(FileIdentity::from_metadata(&metadata)),
                    archive_path,
                });
            }
            continue;
        }

        if file_type.is_symlink() {
            let target = read_link_at(directory, &name)?;
            validate_symlink(paths, &relative, &target)?;
            chain.verify_link(&relative, &target, &mut state.seen_links)?;
            if forced || ignore.includes(&relative)? {
                state.entries.push(ContextEntry {
                    relative,
                    mode: metadata.mode(),
                    kind: ContextEntryKind::Symlink(target),
                    archive_path,
                });
            }
            continue;
        }

        bail!("build context contains an unsupported special file");
    }
    Ok(())
}

// Non-Linux fallback reader: Linux context files are read through the
// descriptor-rooted traversal instead of resolved pathnames.
#[cfg(not(target_os = "linux"))]
fn read_context_file(
    action_root: &Path,
    source: &Path,
    expected: Option<FileIdentity>,
) -> Result<(Vec<u8>, u32)> {
    let file = open_regular_file(action_root, source, expected)?;
    read_open_file(file)
}

fn read_open_file(mut file: fs::File) -> Result<(Vec<u8>, u32)> {
    let metadata = file.metadata().context("reading build context metadata")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .context("reading Docker build context file")?;
    Ok((bytes, metadata.mode()))
}

#[cfg(not(target_os = "linux"))]
fn open_regular_file(
    action_root: &Path,
    source: &Path,
    expected: Option<FileIdentity>,
) -> Result<fs::File> {
    let canonical_source = source
        .canonicalize()
        .context("resolving Docker build context file")?;
    if !canonical_source.starts_with(action_root) {
        bail!("build context file must stay inside the action directory");
    }

    let metadata = fs::symlink_metadata(source).context("reading build context metadata")?;
    reject_non_regular(&metadata)?;
    let expected = expected.unwrap_or_else(|| FileIdentity::from_metadata(&metadata));
    ensure_same_object(expected, &metadata)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(source)
        .context("opening Docker build context file")?;
    let opened_metadata = file.metadata().context("reading build context metadata")?;
    reject_non_regular(&opened_metadata)?;
    ensure_same_object(expected, &opened_metadata)?;
    Ok(file)
}

fn reject_non_regular(metadata: &fs::Metadata) -> Result<()> {
    if metadata.is_file() {
        return Ok(());
    }
    if metadata.file_type().is_symlink() {
        bail!("build context entry changed while it was being prepared");
    }
    bail!("build context contains an unsupported special file");
}

fn normalize_contained_target(link_parent: &Path, target: &Path) -> Result<PathBuf> {
    if target.is_absolute() {
        bail!("build context symlink must stay inside the action directory");
    }
    let mut normalized = PathBuf::new();
    for component in link_parent.join(target).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("build context symlink must stay inside the action directory");
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("build context symlink must stay inside the action directory");
            }
        }
    }
    Ok(normalized)
}

fn validate_symlink(paths: &ResolvedBuildPaths, relative: &Path, target: &Path) -> Result<()> {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let contained = normalize_contained_target(parent, target)?;

    #[cfg(target_os = "linux")]
    {
        validate_descriptor_path_linux(&paths.root, &contained)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        paths.validate_path_identity()?;
        let candidate = paths.action_root.join(contained);
        if candidate.exists() {
            paths.validate_path_identity()?;
            let canonical = candidate
                .canonicalize()
                .context("resolving build context symlink target")?;
            paths.validate_path_identity()?;
            if !canonical.starts_with(&paths.action_root) {
                bail!("build context symlink must stay inside the action directory");
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct ResolvedDescriptorPath {
    canonical_relative: PathBuf,
    canonical_metadata: fs::Metadata,
    forced_paths: HashSet<PathBuf>,
    expected_links: HashMap<PathBuf, PathBuf>,
}

#[cfg(target_os = "linux")]
struct ResolvedFileChain {
    canonical_relative: PathBuf,
    canonical_identity: FileIdentity,
    forced_paths: HashSet<PathBuf>,
    expected_links: HashMap<PathBuf, PathBuf>,
}

#[cfg(target_os = "linux")]
fn resolve_file_chain_linux(
    root: &fs::File,
    requested: &Path,
) -> Result<Option<ResolvedFileChain>> {
    let Some(resolved) = resolve_descriptor_path_linux(root, requested)? else {
        return Ok(None);
    };
    if !resolved.canonical_metadata.is_file() {
        bail!("Dockerfile must be a regular file");
    }
    Ok(Some(ResolvedFileChain {
        canonical_relative: resolved.canonical_relative,
        canonical_identity: FileIdentity::from_metadata(&resolved.canonical_metadata),
        forced_paths: resolved.forced_paths,
        expected_links: resolved.expected_links,
    }))
}

#[cfg(target_os = "linux")]
fn validate_descriptor_path_linux(root: &fs::File, requested: &Path) -> Result<()> {
    let _ = resolve_descriptor_path_linux(root, requested)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_descriptor_path_linux(
    root: &fs::File,
    requested: &Path,
) -> Result<Option<ResolvedDescriptorPath>> {
    let mut remaining = path_components(requested)?;
    let mut current = PathBuf::new();
    let mut forced_paths = HashSet::from([requested.to_path_buf()]);
    let mut expected_links = HashMap::new();
    let mut followed_links = 0;
    let mut final_metadata = root.metadata().context("reading build context metadata")?;

    while let Some(component) = remaining.pop_front() {
        let parent = open_relative_directory(root, &current)?;
        let inspected = match open_at_raw(
            &parent,
            &component,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).context("opening Docker build context path component");
            }
        };
        let metadata = inspected
            .metadata()
            .context("reading Docker build context path component")?;
        let candidate = current.join(&component);

        if metadata.file_type().is_symlink() {
            followed_links += 1;
            if followed_links > 40 {
                bail!("Dockerfile symlink chain is too deep");
            }
            let target = read_link_at(&parent, &component)?;
            forced_paths.insert(candidate.clone());
            expected_links.insert(candidate.clone(), target.clone());
            let target_relative = normalize_contained_target(&current, &target)?;
            let mut expanded = path_components(&target_relative)?;
            expanded.extend(remaining);
            remaining = expanded;
            current = PathBuf::new();
            continue;
        }

        current = candidate;
        final_metadata = metadata;
    }

    forced_paths.insert(current.clone());
    Ok(Some(ResolvedDescriptorPath {
        canonical_relative: current,
        canonical_metadata: final_metadata,
        forced_paths,
        expected_links,
    }))
}

#[cfg(target_os = "linux")]
fn open_relative_directory(root: &fs::File, relative: &Path) -> Result<fs::File> {
    let mut directory = root
        .try_clone()
        .context("cloning Docker build context directory descriptor")?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            bail!("build context file is outside the action directory");
        };
        directory = open_directory_at(&directory, name)?;
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn open_directory_at(parent: &fs::File, name: &OsStr) -> Result<fs::File> {
    let directory = open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    if !directory
        .metadata()
        .context("reading build context metadata")?
        .is_dir()
    {
        bail!("build context entry changed while it was being prepared");
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn open_regular_file_at(
    parent: &fs::File,
    name: &OsStr,
    expected: FileIdentity,
) -> Result<fs::File> {
    let inspected = open_at(
        parent,
        name,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    let inspected_metadata = inspected
        .metadata()
        .context("reading build context metadata")?;
    reject_non_regular(&inspected_metadata)?;
    ensure_same_object(expected, &inspected_metadata)?;

    let file = open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    let metadata = file.metadata().context("reading build context metadata")?;
    reject_non_regular(&metadata)?;
    ensure_same_object(expected, &metadata)?;
    Ok(file)
}

fn ensure_same_object(expected: FileIdentity, metadata: &fs::Metadata) -> Result<()> {
    if expected.matches(metadata) {
        return Ok(());
    }
    bail!("build context entry changed while it was being prepared");
}

#[cfg(target_os = "linux")]
fn open_at(parent: &fs::File, name: &OsStr, flags: libc::c_int) -> Result<fs::File> {
    open_at_raw(parent, name, flags).context("opening Docker build context entry")
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

#[cfg(target_os = "linux")]
fn read_directory_names(directory: &fs::File) -> Result<Vec<OsString>> {
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error())
            .context("duplicating Docker build context directory descriptor");
    }
    // Every clone of the trusted directory descriptor shares one file offset:
    // an earlier traversal of the same action (e.g. the pre-entrypoint step)
    // leaves it at EOF, and without a rewind this enumeration would silently
    // observe an empty directory.
    if unsafe { libc::lseek(duplicate, 0, libc::SEEK_SET) } < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(error).context("rewinding Docker build context directory");
    }
    // `fdopendir` owns the duplicate descriptor and `closedir` below closes it.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error())
            .context("reading Docker build context directory");
    }

    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|code| code != 0) {
                unsafe { libc::closedir(stream) };
                return Err(error).context("reading Docker build context directory");
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("closing Docker build context directory");
    }
    names.sort();
    Ok(names)
}

#[cfg(target_os = "linux")]
fn read_link_at(parent: &fs::File, name: &OsStr) -> Result<PathBuf> {
    let name = CString::new(name.as_bytes()).context("build context path contains a NUL byte")?;
    let mut size = 256;
    loop {
        let mut bytes = vec![0; size];
        let length = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(std::io::Error::last_os_error()).context("reading build context symlink");
        }
        let length = length as usize;
        if length < bytes.len() {
            bytes.truncate(length);
            return Ok(PathBuf::from(OsString::from_vec(bytes)));
        }
        size *= 2;
    }
}

#[cfg(target_os = "linux")]
fn append_context_entry(
    builder: &mut tar::Builder<Vec<u8>>,
    root: &fs::File,
    entry: &ContextEntry,
) -> Result<()> {
    match &entry.kind {
        ContextEntryKind::File(expected) => {
            let name = entry
                .relative
                .file_name()
                .context("build context file has no name")?;
            let parent = entry.relative.parent().unwrap_or_else(|| Path::new(""));
            let parent = open_relative_directory(root, parent)?;
            let file = open_regular_file_at(&parent, name, *expected)?;
            append_regular_file(builder, entry, *expected, file)
        }
        ContextEntryKind::Directory | ContextEntryKind::Symlink(_) => {
            append_non_file_entry(builder, entry)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn append_context_entry(
    builder: &mut tar::Builder<Vec<u8>>,
    paths: &ResolvedBuildPaths,
    entry: &ContextEntry,
) -> Result<()> {
    match &entry.kind {
        ContextEntryKind::File(expected) => {
            paths.validate_path_identity()?;
            let source = paths.action_root.join(&entry.relative);
            let file = open_regular_file(&paths.action_root, &source, Some(*expected))?;
            paths.validate_path_identity()?;
            append_regular_file(builder, entry, *expected, file)
        }
        ContextEntryKind::Directory | ContextEntryKind::Symlink(_) => {
            append_non_file_entry(builder, entry)
        }
    }
}

fn append_regular_file(
    builder: &mut tar::Builder<Vec<u8>>,
    entry: &ContextEntry,
    expected: FileIdentity,
    mut file: fs::File,
) -> Result<()> {
    let metadata = file.metadata().context("reading build context metadata")?;
    reject_non_regular(&metadata)?;
    ensure_same_object(expected, &metadata)?;
    if metadata.mode() != entry.mode {
        bail!("build context entry changed while it was being prepared");
    }

    let mut header = tar::Header::new_gnu();
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(entry.mode & 0o7777);
    header.set_size(metadata.len());
    header.set_cksum();
    builder
        .append_data(&mut header, &entry.relative, &mut file)
        .context("adding file to Docker build context")?;
    Ok(())
}

fn append_non_file_entry(builder: &mut tar::Builder<Vec<u8>>, entry: &ContextEntry) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);

    match &entry.kind {
        ContextEntryKind::Directory => {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_mode(entry.mode & 0o7777);
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, &entry.relative, std::io::empty())
                .context("adding directory to Docker build context")?;
        }
        ContextEntryKind::Symlink(target) => {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(entry.mode & 0o7777);
            header.set_size(0);
            header
                .set_link_name(target)
                .context("recording build context symlink")?;
            header.set_cksum();
            builder
                .append_data(&mut header, &entry.relative, std::io::empty())
                .context("adding symlink to Docker build context")?;
        }
        ContextEntryKind::File(_) => bail!("regular build context file was not opened"),
    }
    Ok(())
}

fn path_to_slash_string(path: &Path) -> Result<String> {
    let path = path
        .to_str()
        .context("build context path is not valid UTF-8")?;
    Ok(path.replace(std::path::MAIN_SEPARATOR, "/"))
}

#[derive(Debug)]
pub(crate) struct PreparedBuildContext {
    pub dockerfile: String,
    pub archive: Vec<u8>,
    pub digest: [u8; 32],
}

pub(crate) fn prepare_build_context(
    action_dir: &TrustedActionDirectory,
    dockerfile: &str,
) -> Result<PreparedBuildContext> {
    let paths = resolve_build_paths(action_dir, dockerfile)?;
    let (ignore, ignore_file) = IgnoreRules::load(&paths)?;
    let mut context = collect_context_entries(&paths, &ignore, ignore_file.as_ref())?;
    context
        .entries
        .sort_by(|left, right| left.archive_path.cmp(&right.archive_path));

    let mut builder = tar::Builder::new(Vec::new());
    builder.mode(tar::HeaderMode::Deterministic);
    for entry in &context.entries {
        #[cfg(target_os = "linux")]
        append_context_entry(&mut builder, &context.root, entry)?;

        #[cfg(not(target_os = "linux"))]
        append_context_entry(&mut builder, &paths, entry)?;
    }
    builder.finish().context("finishing Docker build context")?;
    let archive = builder
        .into_inner()
        .context("finalizing Docker build context")?;
    let digest = *blake3::hash(&archive).as_bytes();
    let dockerfile = path_to_slash_string(&paths.dockerfile_relative)?;

    Ok(PreparedBuildContext {
        dockerfile,
        archive,
        digest,
    })
}

#[cfg(test)]
#[path = "build_context_test.rs"]
mod build_context_test;
