# Dockerfile-based GitHub Actions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Научить Chimera безопасно собирать Docker actions с `runs.using: docker` и `runs.image: Dockerfile` либо относительным путём к Dockerfile, после чего запускать проверенный локальный image ID через существующий контейнерный executor.

**Architecture:** Новый Docker build path состоит из трёх изолированных частей: безопасная и детерминированная упаковка action directory, daemon-local single-flight cache и адаптер Docker Engine Build API поверх существующего клиента Bollard. Один `DockerActionBuilder` живёт на уровне daemon и разделяется всеми runner instances, а `JobState` закрепляет первый построенный image ID за конкретным action invocation для фаз pre/main/post. Существующий executor остаётся единственным местом, где создаётся контейнер action; build path только возвращает проверенный локальный image ID.

**Tech Stack:** Rust 2024, Tokio, Bollard 0.18.1 / Docker Engine API, `tar`, `glob`, `blake3`, `anyhow`, `thiserror`, существующие `LogSender`, `CancellationToken`, unit tests и ignored Docker integration tests.

**Spec:** `docs/superpowers/specs/2026-09-16-chimera-dockerfile-actions.md`

## Global Constraints

- Базовая версия — upstream v0.1.3, commit `0b3b1fe8f41b746e9886dfa7b775a145b16b157d`.
- Целевая платформа — Linux/X64 и существующий rootless Docker daemon; `DOCKER_HOST` должен оставаться тем же, который выбирает `crate::docker::client::connect(None)`.
- Сборка выполняется только через Docker Engine build API существующего Bollard client; shell-команда `docker build` не добавляется.
- Build context — ровно канонический action directory; Dockerfile — относительный обычный файл внутри него. Абсолютные пути, `..`, symlink escape и специальные файлы отклоняются до обращения к Docker.
- `.dockerignore` и `<Dockerfile>.dockerignore` соблюдаются на клиенте; Dockerfile-specific файл имеет приоритет над корневым `.dockerignore`.
- Путь Dockerfile передаётся как отдельное поле `BuildImageOptions::dockerfile`, без shell-интерполяции; пробелы в пути сохраняют своё буквальное значение.
- Build progress проходит только через `LogSender`, поэтому использует существующее masking; environment, auth headers, registry credentials, raw tar context и содержимое файлов отдельно не логируются.
- Build args, build secrets, SSH mounts и пользовательские tags не добавляются. Internal tag/labels используют namespace Chimera.
- Registry auth принимается только как явно переданный job-owned `RegistryAuth`; runner передаёт `None`, пока CHM-03 не создаёт per-job Docker config. Глобальные `$DOCKER_CONFIG` и `$HOME/.docker` не читаются.
- Deadline начинается при старте action step; подготовка context, ожидание key lock, build stream и последующий запуск контейнера используют один и тот же deadline. Default остаётся текущим: 360 минут.
- Cancel/timeout прекращают ожидание lock и build stream, не создают container и не публикуют cache entry. Реальная остановка Engine build должна быть доказана ignored integration test; если target Engine продолжает build после закрытия HTTP stream, выполнение плана останавливается на Task 4 для пересмотра adapter.
- Cache живёт только в памяти daemon, изолирован по daemon ID, runner identity, GitHub repository scope, `linux/amd64`, версии схемы/options, Dockerfile path и digest фактически отправленного context.
- Context digest зависит от нормализованных путей, типов, Unix modes, file contents и symlink targets, но не от tar order, uid/gid, mtime или случайных временных имён.
- Один cache key строится не более одного раза одновременно; разные keys не удерживают общий lock во время build.
- Cache публикуется только после завершения stream и повторной проверки image ID через `inspect_image`; исчезнувший image означает miss и rebuild. Built image никогда не pull-ится по ID.
- Один action invocation использует один image для pre/main/post, пока image существует в том же daemon. Порядок фаз остаётся существующим.
- Ошибка build делает step failed, cancel делает step cancelled; main entrypoint не запускается и fallback на старый/pre-built image отсутствует.
- Успешные internal images остаются в локальном daemon. Эта задача не добавляет retention, Docker prune или глобальный garbage collector.
- Точный acceptance pin — `hadolint/hadolint-action@2332a7b74a6de0dda2e2221d575162eba76ba5e5`; workflow/action не модифицируются и не подменяются заранее собранным образом.
- D-01…D-09 покрываются unit/mock и локальными ignored Docker tests; D-10 выполняется только в отдельно разрешённом rootless stand; D-11 использует исключительно synthetic canaries.
- Production rollout, deploy/push/webhook stages, GHES, Windows, multi-platform build, resolver expansion, job containers, общий masking fix и исправление всей post/cancellation semantics остаются вне scope.
- Новые crates не добавляются: используются уже присутствующие `glob`, `tar`, `blake3`, `base64`, `bollard`, `futures`, `tokio` и `libc`.

---

## File Structure

### New files

- `src/docker/build_context.rs` — canonical path validation, Docker ignore matching, safe traversal, deterministic tar generation and context digest.
- `src/docker/build_context_test.rs` — path containment, ignore precedence, symlink/special-file handling and digest determinism.
- `src/docker/build_cache.rs` — cache key, deadline helper, per-key single-flight locks and in-memory image index.
- `src/docker/build_cache_test.rs` — hit/miss, content/options/daemon isolation, concurrency, cancellation and lock release.
- `src/docker/build.rs` — Bollard Build API adapter, progress forwarding, image-ID verification and public `DockerActionBuilder` interface.
- `src/docker/build_test.rs` — adapter unit tests plus ignored real-Engine success/failure/cancellation/stale-image/concurrency tests.
- `tests/dockerfile_actions_test.rs` — execution-engine coverage for D-01…D-04, D-06, D-08, D-09, D-11 and feature-gated D-10.
- `docs/dockerfile-actions.md` — operator-facing behavior, security boundary, cache/retention and CHM-03 dependency.
- `docs/superpowers/reports/2026-09-16-chimera-dockerfile-actions.md` — D-01…D-11 evidence matrix and rollout gates.

### Modified files

- `Cargo.toml` — declare an empty `acceptance-tests` feature; dependencies remain unchanged.
- `src/docker.rs` — export `build`, keep context/cache helpers crate-private.
- `src/job/action/download.rs` — return only canonical action directories contained by workspace or downloaded action root.
- `src/job/action/download_test.rs` — traversal, absolute path and symlink escape regression tests.
- `src/job/action/docker.rs` — classify metadata image source, invoke builder, pin pre/main/post image, and run built IDs without pull.
- `src/job/action/docker_test.rs` — source classification, action-instance key, safe error and legacy image regressions.
- `src/job/action/composite.rs` — pass builder/scope/auth/deadline through nested Docker actions.
- `src/job/action/composite_test.rs` — initialize the new builder/scope arguments in existing composite tests.
- `src/job/execute.rs` — own per-job built-image map, construct build scope, compute the shared action deadline and thread build services to action execution.
- `src/job/execute_test.rs` — initialize builder/auth at every `run_all_steps` call and cover timeout/cancel result mapping.
- `src/daemon.rs` — allocate one `Arc<DockerActionBuilder>` for the daemon and clone it into every `Runner`.
- `src/runner/instance.rs` — retain the shared builder and pass it into job execution; leave registry auth `None` pending CHM-03.
- `src/runner/instance_test.rs` — construct `Runner` with a test builder.
- `tests/common/mod.rs` — retain a shared builder in `TestEnv`, expose cancel/access-token runs, local-action helpers and captured log bodies.
- `tests/basics_test.rs` — initialize the new `run_all_steps` arguments.
- `README.md` — link the Dockerfile action behavior/limitations document.

## Task 1: Contain action and Dockerfile paths

**Files:**
- Create: `src/docker/build_context.rs`
- Create: `src/docker/build_context_test.rs`
- Modify: `src/docker.rs:1-7`
- Modify: `src/job/action/download.rs:17-49,126-170`
- Modify: `src/job/action/download_test.rs`

**Interfaces:**
- Consumes: existing `ActionSource`, `ActionCache::get_action`, `std::fs::canonicalize`.
- Produces: `pub(crate) struct ResolvedBuildPaths { pub action_root: PathBuf, pub dockerfile_path: PathBuf, pub dockerfile_relative: PathBuf }` and `pub(crate) fn resolve_build_paths(action_dir: &Path, dockerfile: &str) -> anyhow::Result<ResolvedBuildPaths>` for Task 2.
- Produces: private `fn contained_action_dir(root: &Path, requested: &Path) -> anyhow::Result<PathBuf>` used by all repository/local action runtimes.
- Produces: private `fn remote_cache_path(cache_dir: &Path, owner: &str, repo: &str, git_ref: &str) -> PathBuf`; workflow-controlled refs never become filesystem components.

- [ ] **Step 1: Write failing action-directory containment tests**

Add tests that prove `ActionCache` cannot turn a workflow-controlled subpath into an arbitrary build root:

```rust
#[tokio::test]
async fn local_action_parent_traversal_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: PathBuf::from("../outside"),
    };

    let error = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "action path must stay inside its source root");
}

#[cfg(unix)]
#[tokio::test]
async fn local_action_symlink_escape_is_rejected() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, workspace.join("linked-action")).unwrap();
    let cache = ActionCache::new(tmp.path().join("actions"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: PathBuf::from("linked-action"),
    };

    let error = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "action path must stay inside its source root");
}

#[test]
fn remote_cache_path_hashes_path_like_refs() {
    let root = Path::new("/runner/actions");
    let escaped = remote_cache_path(root, "owner", "repo", "../../outside");
    let branch = remote_cache_path(root, "owner", "repo", "refs/heads/main");
    let expected_parent = root.join("remote-v1");

    assert_eq!(escaped.parent(), Some(expected_parent.as_path()));
    assert_eq!(branch.parent(), Some(expected_parent.as_path()));
    assert_ne!(escaped, branch);
    assert_eq!(escaped.file_name().unwrap().len(), 64);
}
```

- [ ] **Step 2: Run the containment tests and verify the unsafe joins fail them**

Run:

```bash
cargo test job::action::download_test::local_action_parent_traversal_is_rejected -- --exact
cargo test job::action::download_test::local_action_symlink_escape_is_rejected -- --exact
cargo test job::action::download_test::remote_cache_path_hashes_path_like_refs -- --exact
```

Expected: all three tests fail because current `get_action` joins workflow-controlled paths and refs directly.

- [ ] **Step 3: Replace raw joins with one canonical containment helper**

Implement the helper and route both remote subpaths and local paths through it:

```rust
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

fn contained_action_dir(root: &Path, requested: &Path) -> Result<PathBuf> {
    let relative = normalize_relative_path(requested)?;
    let canonical_root = root
        .canonicalize()
        .context("resolving action source root")?;
    let canonical_action = canonical_root
        .join(relative)
        .canonicalize()
        .context("resolving action directory")?;

    if !canonical_action.starts_with(&canonical_root) || !canonical_action.is_dir() {
        bail!("action path must stay inside its source root");
    }
    Ok(canonical_action)
}

fn remote_cache_path(
    cache_dir: &Path,
    owner: &str,
    repo: &str,
    git_ref: &str,
) -> PathBuf {
    let mut hasher = blake3::Hasher::new();
    for field in [b"remote-v1".as_slice(), owner.as_bytes(), repo.as_bytes(), git_ref.as_bytes()] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    cache_dir
        .join("remote-v1")
        .join(hasher.finalize().to_hex().to_string())
}
```

Replace `self.cache_dir.join(owner).join(repo).join(git_ref)` with `remote_cache_path(&self.cache_dir, owner, repo, git_ref)`. Then use `contained_action_dir(&cache_path, path.as_deref().map(Path::new).unwrap_or(Path::new(".")))` for remote actions and `contained_action_dir(workspace_dir, path)` for local actions. Do not include canonical host paths in the containment error.

- [ ] **Step 4: Run all downloader tests**

Run:

```bash
cargo test job::action::download_test
```

Expected: all downloader tests pass; existing remote/local behavior is preserved for contained directories.

- [ ] **Step 5: Write failing Dockerfile path tests**

Create `build_context_test.rs` and include it from `build_context.rs` with the project-standard `#[path]` attribute:

```rust
#[test]
fn dockerfile_path_with_spaces_is_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("action");
    std::fs::create_dir_all(dir.join("docker files")).unwrap();
    std::fs::write(dir.join("docker files/Dockerfile"), "FROM scratch\n").unwrap();

    let resolved = resolve_build_paths(&dir, "docker files/Dockerfile").unwrap();

    assert_eq!(resolved.dockerfile_relative, Path::new("docker files/Dockerfile"));
}

#[test]
fn absolute_and_parent_dockerfile_paths_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("action");
    std::fs::create_dir_all(&dir).unwrap();

    assert_eq!(
        resolve_build_paths(&dir, "/tmp/Dockerfile")
            .unwrap_err()
            .to_string(),
        "Dockerfile path must be relative to the action directory"
    );
    assert_eq!(
        resolve_build_paths(&dir, "../Dockerfile")
            .unwrap_err()
            .to_string(),
        "Dockerfile path must be relative to the action directory"
    );
}

#[cfg(unix)]
#[test]
fn dockerfile_symlink_outside_action_is_rejected() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("action");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(tmp.path().join("outside.Dockerfile"), "FROM scratch\n").unwrap();
    symlink(tmp.path().join("outside.Dockerfile"), dir.join("Dockerfile")).unwrap();

    let error = resolve_build_paths(&dir, "Dockerfile").unwrap_err();

    assert_eq!(error.to_string(), "Dockerfile must resolve inside the action directory");
}
```

- [ ] **Step 6: Run the new tests and verify the module/API is missing**

Run:

```bash
cargo test docker::build_context_test
```

Expected: compile failure because `build_context` and `resolve_build_paths` do not exist.

- [ ] **Step 7: Implement canonical Dockerfile resolution**

Add the module export and implementation:

```rust
// src/docker.rs
pub(crate) mod build_context;
```

Task 3 adds `pub(crate) mod build_cache;` only after that file exists. Task 4 then adds `pub mod build;` only after its public builder API exists, so every task ends in a compiling state.

```rust
#[derive(Debug)]
pub(crate) struct ResolvedBuildPaths {
    pub action_root: PathBuf,
    pub dockerfile_path: PathBuf,
    pub dockerfile_relative: PathBuf,
}

pub(crate) fn resolve_build_paths(
    action_dir: &Path,
    dockerfile: &str,
) -> Result<ResolvedBuildPaths> {
    let action_root = action_dir
        .canonicalize()
        .context("resolving action directory")?;
    if !action_root.is_dir() {
        bail!("action directory is not a directory");
    }

    let dockerfile_relative = normalize_dockerfile_path(Path::new(dockerfile))?;
    let dockerfile_path = action_root
        .join(&dockerfile_relative)
        .canonicalize()
        .context("resolving Dockerfile")?;
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
    })
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

#[cfg(test)]
#[path = "build_context_test.rs"]
mod build_context_test;
```

- [ ] **Step 8: Run path tests and formatting**

Run:

```bash
cargo test docker::build_context_test
cargo fmt --check
```

Expected: all path tests pass and formatting is clean.

- [ ] **Step 9: Commit the contained path boundary**

```bash
git add src/docker.rs src/docker/build_context.rs src/docker/build_context_test.rs src/job/action/download.rs src/job/action/download_test.rs
git commit -m "fix: 🐞 constrain Docker action paths" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

## Task 2: Build a filtered deterministic context

**Files:**
- Modify: `src/docker/build_context.rs`
- Modify: `src/docker/build_context_test.rs`

**Interfaces:**
- Consumes: `ResolvedBuildPaths` and `resolve_build_paths` from Task 1; existing `glob::Pattern`, `tar::Builder`, `blake3` and Unix metadata APIs.
- Produces: `pub(crate) struct PreparedBuildContext { pub dockerfile: String, pub archive: Vec<u8>, pub digest: [u8; 32] }`.
- Produces: `pub(crate) fn prepare_build_context(action_dir: &Path, dockerfile: &str) -> anyhow::Result<PreparedBuildContext>` for Task 4.
- Internal traversal boundary: `fn collect_context_entries(paths: &ResolvedBuildPaths, ignore: &IgnoreRules, ignore_file: Option<&Path>) -> anyhow::Result<Vec<ContextEntry>>`.
- Internal helpers defined in this task: `IgnoreRules::load`, `IgnoreRules::includes`, `rule_matches`, `read_regular_file_inside`, `validate_symlink`, `open_regular_file`, `append_context_entry`, `normalize_contained_target`, `path_to_slash_string`.

- [ ] **Step 1: Add failing ignore and tar-content tests**

Use a test helper that reads entry paths back from the resulting tar:

```rust
fn archive_paths(archive: &[u8]) -> Vec<String> {
    let mut paths = tar::Archive::new(archive);
    let mut result: Vec<String> = paths
        .entries()
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .path()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    result.sort();
    result
}

#[test]
fn root_dockerignore_filters_files_but_keeps_dockerfile() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("keep.txt"), "keep").unwrap();
    std::fs::write(tmp.path().join("secret.txt"), "synthetic-secret").unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "secret.txt\nDockerfile\n").unwrap();

    let context = prepare_build_context(tmp.path(), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(paths.contains(&"Dockerfile".to_string()));
    assert!(paths.contains(&"keep.txt".to_string()));
    assert!(!paths.contains(&"secret.txt".to_string()));
    let canary = b"synthetic-secret";
    assert!(
        context
            .archive
            .windows(canary.len())
            .all(|window| window != canary)
    );
}

#[test]
fn dockerfile_specific_ignore_replaces_root_ignore() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("docker")).unwrap();
    std::fs::write(tmp.path().join("docker/Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("root-only.txt"), "root").unwrap();
    std::fs::write(tmp.path().join("specific-only.txt"), "specific").unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "root-only.txt\n").unwrap();
    std::fs::write(
        tmp.path().join("docker/Dockerfile.dockerignore"),
        "specific-only.txt\n",
    )
    .unwrap();

    let context = prepare_build_context(tmp.path(), "docker/Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(paths.contains(&"root-only.txt".to_string()));
    assert!(!paths.contains(&"specific-only.txt".to_string()));
}

#[test]
fn negation_and_double_star_follow_last_matching_rule() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("nested/keep")).unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("nested/drop.log"), "drop").unwrap();
    std::fs::write(tmp.path().join("nested/keep/keep.log"), "keep").unwrap();
    std::fs::write(tmp.path().join(".dockerignore"), "**/*.log\n!nested/keep/*.log\n").unwrap();

    let context = prepare_build_context(tmp.path(), "Dockerfile").unwrap();
    let paths = archive_paths(&context.archive);

    assert!(!paths.contains(&"nested/drop.log".to_string()));
    assert!(paths.contains(&"nested/keep/keep.log".to_string()));
}
```

- [ ] **Step 2: Add failing safety and digest tests**

```rust
#[cfg(unix)]
#[test]
fn symlink_outside_context_is_rejected_without_reading_target() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let action = tmp.path().join("action");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(action.join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("canary"), "synthetic-secret").unwrap();
    symlink(tmp.path().join("canary"), action.join("leak")).unwrap();

    let error = prepare_build_context(&action, "Dockerfile").unwrap_err();

    assert_eq!(error.to_string(), "build context symlink must stay inside the action directory");
}

#[cfg(unix)]
#[test]
fn special_file_in_context_is_rejected() {
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    let _socket = UnixListener::bind(tmp.path().join("forbidden.sock")).unwrap();

    let error = prepare_build_context(tmp.path(), "Dockerfile").unwrap_err();

    assert_eq!(error.to_string(), "build context contains an unsupported special file");
}

#[cfg(unix)]
#[test]
fn digest_changes_for_content_mode_and_symlink_target() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    std::fs::write(tmp.path().join("one"), "one").unwrap();
    std::fs::write(tmp.path().join("two"), "two").unwrap();
    std::fs::write(tmp.path().join("payload"), "alpha").unwrap();
    symlink("one", tmp.path().join("link")).unwrap();
    let first = prepare_build_context(tmp.path(), "Dockerfile").unwrap().digest;

    std::fs::write(tmp.path().join("payload"), "beta").unwrap();
    let content = prepare_build_context(tmp.path(), "Dockerfile").unwrap().digest;
    assert_ne!(first, content);

    let mut permissions = std::fs::metadata(tmp.path().join("payload")).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(tmp.path().join("payload"), permissions).unwrap();
    let mode = prepare_build_context(tmp.path(), "Dockerfile").unwrap().digest;
    assert_ne!(content, mode);

    std::fs::remove_file(tmp.path().join("link")).unwrap();
    symlink("two", tmp.path().join("link")).unwrap();
    let target = prepare_build_context(tmp.path(), "Dockerfile").unwrap().digest;
    assert_ne!(mode, target);
}

#[test]
fn digest_ignores_creation_order_and_mtime() {
    fn make(root: &Path, reverse: bool) {
        std::fs::write(root.join("Dockerfile"), "FROM scratch\n").unwrap();
        let files = if reverse { ["b", "a"] } else { ["a", "b"] };
        for file in files {
            std::fs::write(root.join(file), file).unwrap();
        }
    }

    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make(left.path(), false);
    make(right.path(), true);

    let left_digest = prepare_build_context(left.path(), "Dockerfile").unwrap().digest;
    let right_digest = prepare_build_context(right.path(), "Dockerfile").unwrap().digest;

    assert_eq!(left_digest, right_digest);
}
```

- [ ] **Step 3: Run the context tests and verify they fail**

Run:

```bash
cargo test docker::build_context_test
```

Expected: compile failures because `PreparedBuildContext` and `prepare_build_context` are absent.

- [ ] **Step 4: Implement Docker ignore parsing with last-match-wins semantics**

Implement these concrete types and rules:

```rust
struct IgnoreRule {
    include: bool,
    has_separator: bool,
    pattern: glob::Pattern,
}

#[derive(Default)]
struct IgnoreRules {
    rules: Vec<IgnoreRule>,
}

impl IgnoreRules {
    fn load(paths: &ResolvedBuildPaths) -> Result<(Self, Option<PathBuf>)> {
        let dockerfile_name = paths
            .dockerfile_relative
            .file_name()
            .and_then(|name| name.to_str())
            .context("Dockerfile name is not valid UTF-8")?;
        let specific = paths
            .dockerfile_relative
            .with_file_name(format!("{dockerfile_name}.dockerignore"));
        let selected = if paths.action_root.join(&specific).is_file() {
            Some(specific)
        } else if paths.action_root.join(".dockerignore").is_file() {
            Some(PathBuf::from(".dockerignore"))
        } else {
            None
        };

        let Some(relative) = selected else {
            return Ok((Self::default(), None));
        };
        let bytes = read_regular_file_inside(paths, &relative)?;
        let text = std::str::from_utf8(&bytes).context("Docker ignore file is not valid UTF-8")?;
        let mut rules = Vec::new();
        for (line_number, raw) in text.lines().enumerate() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed == "." || trimmed.starts_with('#') {
                continue;
            }
            let (include, body) = match trimmed.strip_prefix('!') {
                Some(pattern) => (true, pattern),
                None => (false, trimmed),
            };
            let cleaned = body.trim_matches('/');
            if cleaned.is_empty() {
                continue;
            }
            let pattern = glob::Pattern::new(cleaned).with_context(|| {
                format!("invalid Docker ignore rule at line {}", line_number + 1)
            })?;
            rules.push(IgnoreRule {
                include,
                has_separator: cleaned.contains('/'),
                pattern,
            });
        }
        Ok((Self { rules }, Some(relative)))
    }

    fn includes(&self, relative: &Path) -> bool {
        let slash_path = path_to_slash_string(relative);
        let mut included = true;
        for rule in &self.rules {
            if rule_matches(rule, &slash_path) {
                included = rule.include;
            }
        }
        included
    }
}
```

`rule_matches` tests the full path and each parent. A pattern containing `/` matches normalized root-relative prefixes; a pattern without `/` matches each component. Negated rules use the same matcher and later matching rules overwrite earlier decisions:

```rust
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

fn read_regular_file_inside(
    paths: &ResolvedBuildPaths,
    relative: &Path,
) -> Result<Vec<u8>> {
    let mut file = open_regular_file(&paths.action_root, &paths.action_root.join(relative))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .context("reading Docker build context file")?;
    Ok(bytes)
}
```

- [ ] **Step 5: Implement safe, sorted traversal**

Represent entries explicitly so no traversal follows a symlink:

```rust
#[derive(Debug)]
enum ContextEntryKind {
    Directory,
    File,
    Symlink(PathBuf),
}

#[derive(Debug)]
struct ContextEntry {
    relative: PathBuf,
    source: PathBuf,
    mode: u32,
    kind: ContextEntryKind,
}
```

`collect_context_entries` must:

1. call `symlink_metadata` rather than `metadata`;
2. recurse only when `file_type().is_dir()`;
3. read a symlink with `read_link`, reject absolute targets, lexically normalize `link_parent.join(target)` and reject any target outside `action_root`;
4. if an existing symlink target canonicalizes, verify the canonical target starts with `action_root`;
5. reject FIFO/socket/block/character device with `build context contains an unsupported special file`;
6. traverse excluded directories so a later `!` rule can re-include a descendant;
7. force-include `dockerfile_relative`, the canonical Dockerfile target relative to `action_root`, and the selected ignore file, so a permitted in-tree Dockerfile symlink cannot lose its target to ignore rules;
8. reject non-UTF-8 archive paths with `build context path is not valid UTF-8`;
9. compare the selected Dockerfile entry's canonical source with `paths.dockerfile_path` to detect replacement after resolution;
10. sort the final entries by slash-normalized relative path before opening file content.

Use `OpenOptionsExt::custom_flags(libc::O_NOFOLLOW)` for regular files, re-check the opened descriptor, and never open symlink targets:

```rust
fn open_regular_file(action_root: &Path, source: &Path) -> Result<std::fs::File> {
    let canonical_source = source
        .canonicalize()
        .context("resolving Docker build context file")?;
    if !canonical_source.starts_with(action_root) {
        bail!("build context file must stay inside the action directory");
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .context("opening Docker build context file")?;
    if !file.metadata().context("reading build context metadata")?.is_file() {
        bail!("build context entry changed while it was being prepared");
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let opened_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .canonicalize()
            .context("verifying opened Docker build context file")?;
        if !opened_path.starts_with(action_root) {
            bail!("build context file must stay inside the action directory");
        }
    }

    Ok(file)
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

fn validate_symlink(
    paths: &ResolvedBuildPaths,
    relative: &Path,
    target: &Path,
) -> Result<()> {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let contained = normalize_contained_target(parent, target)?;
    let candidate = paths.action_root.join(contained);
    if candidate.exists() {
        let canonical = candidate
            .canonicalize()
            .context("resolving build context symlink target")?;
        if !canonical.starts_with(&paths.action_root) {
            bail!("build context symlink must stay inside the action directory");
        }
    }
    Ok(())
}
```

`append_context_entry` reopens every regular file with `open_regular_file`, derives its mode and size from that descriptor, and passes the descriptor directly to the tar writer:

```rust
fn append_context_entry(
    builder: &mut tar::Builder<Vec<u8>>,
    action_root: &Path,
    entry: &ContextEntry,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

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
        ContextEntryKind::File => {
            let mut file = open_regular_file(action_root, &entry.source)?;
            let metadata = file.metadata().context("reading build context metadata")?;
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(metadata.mode() & 0o7777);
            header.set_size(metadata.len());
            header.set_cksum();
            builder
                .append_data(&mut header, &entry.relative, &mut file)
                .context("adding file to Docker build context")?;
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
    }
    Ok(())
}
```

This final descriptor verification makes a final-component or Linux parent-path race fail before any bytes from outside `action_root` enter the archive.

- [ ] **Step 6: Emit a deterministic tar and hash exactly those bytes**

Implement the public preparation function and deterministic header writer:

```rust
pub(crate) struct PreparedBuildContext {
    pub dockerfile: String,
    pub archive: Vec<u8>,
    pub digest: [u8; 32],
}

pub(crate) fn prepare_build_context(
    action_dir: &Path,
    dockerfile: &str,
) -> Result<PreparedBuildContext> {
    let paths = resolve_build_paths(action_dir, dockerfile)?;
    let (ignore, ignore_file) = IgnoreRules::load(&paths)?;
    let mut entries = collect_context_entries(&paths, &ignore, ignore_file.as_deref())?;
    entries.sort_by_key(|entry| path_to_slash_string(&entry.relative));

    let mut builder = tar::Builder::new(Vec::new());
    builder.mode(tar::HeaderMode::Deterministic);
    for entry in &entries {
        append_context_entry(&mut builder, &paths.action_root, entry)?;
    }
    builder.finish().context("finishing Docker build context")?;
    let archive = builder.into_inner().context("finalizing Docker build context")?;
    let digest = *blake3::hash(&archive).as_bytes();
    let dockerfile = path_to_slash_string(&paths.dockerfile_relative);

    Ok(PreparedBuildContext {
        dockerfile,
        archive,
        digest,
    })
}
```

For every tar header set `uid=0`, `gid=0`, `mtime=0`, `mode=entry.mode & 0o7777`, explicit entry type and checksum. Regular-file size comes from the opened descriptor; directories and symlinks have size zero; symlink `link_name` is the literal validated relative target. This makes the tar itself the canonical digest representation.

- [ ] **Step 7: Run all context tests**

Run:

```bash
cargo test docker::build_context_test
```

Expected: all ignore, safety and deterministic digest tests pass.

- [ ] **Step 8: Commit deterministic context generation**

```bash
git add src/docker/build_context.rs src/docker/build_context_test.rs
git commit -m "feat: ✨ package Docker action build contexts" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

## Task 3: Add daemon-scoped single-flight cache and deadline primitive

**Files:**
- Create: `src/docker/build_cache.rs`
- Create: `src/docker/build_cache_test.rs`
- Modify: `src/docker.rs`

**Interfaces:**
- Consumes: context digest `[u8; 32]`, Tokio `Mutex`, `Instant`, `CancellationToken`.
- Produces: `pub struct DockerBuildScope::new(runner_identity: impl Into<String>, github_scope: impl Into<String>)`.
- Produces: `pub(crate) struct BuildCacheKey::new(daemon_id: &str, scope: &DockerBuildScope, platform: &str, dockerfile: &str, context_digest: [u8; 32])`, `fingerprint(&self) -> String` and `internal_tag(&self, namespace: &str) -> String`.
- Produces: `pub(crate) enum BudgetOutcome<T> { Ready(T), Cancelled, TimedOut }` and `within_budget(deadline, cancel, future)` for Task 4.
- Produces: `BuildCache::get_or_build` returning `CacheOutcome::{Ready { image_id, cache_hit }, Cancelled, TimedOut}`.

- [ ] **Step 1: Write failing cache-key and hit/miss tests**

```rust
fn scope() -> DockerBuildScope {
    DockerBuildScope::new("runner-a", "github.com/owner/repo")
}

fn key(daemon: &str, digest_byte: u8) -> BuildCacheKey {
    BuildCacheKey::new(
        daemon,
        &scope(),
        "linux/amd64",
        "Dockerfile",
        [digest_byte; 32],
    )
}

#[test]
fn cache_key_changes_with_daemon_scope_context_and_options() {
    let base = key("daemon-a", 1);
    assert_ne!(base, key("daemon-b", 1));
    assert_ne!(base, key("daemon-a", 2));
    assert_ne!(
        base,
        BuildCacheKey::new(
            "daemon-a",
            &DockerBuildScope::new("runner-b", "github.com/owner/repo"),
            "linux/amd64",
            "Dockerfile",
            [1; 32],
        )
    );
    assert_ne!(
        base,
        BuildCacheKey::new(
            "daemon-a",
            &DockerBuildScope::new("runner-a", "github.com/other/repo"),
            "linux/amd64",
            "Dockerfile",
            [1; 32],
        )
    );
    assert_ne!(
        base,
        BuildCacheKey::new(
            "daemon-a",
            &scope(),
            "linux/arm64",
            "Dockerfile",
            [1; 32],
        )
    );
    assert_ne!(
        base,
        BuildCacheKey::new(
            "daemon-a",
            &scope(),
            "linux/amd64",
            "docker/Dockerfile",
            [1; 32],
        )
    );
    let tag = base.internal_tag("0123456789abcdef");
    assert!(tag.starts_with("chimera-internal/action-cache:"));
    assert!(tag.contains("0123456789abcdef-"));
}

#[tokio::test]
async fn unchanged_valid_image_is_built_once() {
    let cache = BuildCache::new();
    let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let deadline = Instant::now() + Duration::from_secs(5);

    for _ in 0..2 {
        let builds = builds.clone();
        let outcome = cache
            .get_or_build(
                key("daemon-a", 1),
                deadline,
                &cancel,
                |_| async { Ok(true) },
                move || async move {
                    builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok("sha256:image".to_string())
                },
            )
            .await
            .unwrap();
        assert!(matches!(outcome, CacheOutcome::Ready { .. }));
    }

    assert_eq!(builds.load(std::sync::atomic::Ordering::SeqCst), 1);
}
```

- [ ] **Step 2: Write failing concurrency, stale-image and cancellation tests**

```rust
#[tokio::test]
async fn concurrent_same_key_runs_one_build() {
    let cache = std::sync::Arc::new(BuildCache::new());
    let builds = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut tasks = Vec::new();

    for _ in 0..2 {
        let cache = cache.clone();
        let builds = builds.clone();
        let cancel = cancel.clone();
        tasks.push(tokio::spawn(async move {
            cache
                .get_or_build(
                    key("daemon-a", 1),
                    deadline,
                    &cancel,
                    |_| async { Ok(true) },
                    move || async move {
                        builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Ok("sha256:image".to_string())
                    },
                )
                .await
                .unwrap()
        }));
    }

    for task in tasks {
        assert!(matches!(task.await.unwrap(), CacheOutcome::Ready { .. }));
    }
    assert_eq!(builds.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_cached_image_rebuilds_and_replaces_entry() {
    let cache = BuildCache::new();
    let cancel = CancellationToken::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let first = cache
        .get_or_build(
            key("daemon-a", 1),
            deadline,
            &cancel,
            |_| async { Ok(true) },
            || async { Ok("sha256:first".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(first, CacheOutcome::Ready { cache_hit: false, .. }));

    let second = cache
        .get_or_build(
            key("daemon-a", 1),
            deadline,
            &cancel,
            |_| async { Ok(false) },
            || async { Ok("sha256:second".to_string()) },
        )
        .await
        .unwrap();

    assert!(matches!(
        second,
        CacheOutcome::Ready { image_id, cache_hit: false } if image_id == "sha256:second"
    ));
}

#[tokio::test]
async fn cancelled_waiter_does_not_publish_or_poison_key_lock() {
    let cache = std::sync::Arc::new(BuildCache::new());
    let blocker = cache.key_lock_for_test(key("daemon-a", 1)).await;
    let guard = blocker.lock().await;
    let cancel = CancellationToken::new();
    cancel.cancel();

    let outcome = cache
        .get_or_build(
            key("daemon-a", 1),
            Instant::now() + Duration::from_secs(5),
            &cancel,
            |_| async { Ok(true) },
            || async { Ok("sha256:forbidden".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, CacheOutcome::Cancelled));
    drop(guard);

    let outcome = cache
        .get_or_build(
            key("daemon-a", 1),
            Instant::now() + Duration::from_secs(5),
            &CancellationToken::new(),
            |_| async { Ok(true) },
            || async { Ok("sha256:retry".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, CacheOutcome::Ready { .. }));
}
```

Expose both helpers only under `#[cfg(test)]`:

```rust
#[cfg(test)]
pub(super) async fn key_lock_for_test(&self, key: BuildCacheKey) -> Arc<Mutex<()>> {
    self.locks
        .lock()
        .await
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

#[cfg(test)]
pub(super) async fn entry_count_for_test(&self) -> usize {
    self.entries.lock().await.len()
}
```

- [ ] **Step 3: Run the cache tests and verify the module is absent**

Run:

```bash
cargo test docker::build_cache_test
```

Expected: compile failure because the cache types do not exist. Include the test file from the implementation module with:

```rust
#[cfg(test)]
#[path = "build_cache_test.rs"]
mod build_cache_test;
```

- [ ] **Step 4: Implement the explicit cache key and internal tag**

```rust
const CACHE_SCHEMA_VERSION: u8 = 1;
const BUILD_OPTIONS_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DockerBuildScope {
    runner_identity: String,
    github_scope: String,
}

impl DockerBuildScope {
    pub fn new(
        runner_identity: impl Into<String>,
        github_scope: impl Into<String>,
    ) -> Self {
        Self {
            runner_identity: runner_identity.into(),
            github_scope: github_scope.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct BuildCacheKey {
    cache_schema: u8,
    options_schema: u8,
    daemon_id: String,
    runner_identity: String,
    github_scope: String,
    platform: String,
    dockerfile: String,
    context_digest: [u8; 32],
}

impl BuildCacheKey {
    pub(crate) fn new(
        daemon_id: &str,
        scope: &DockerBuildScope,
        platform: &str,
        dockerfile: &str,
        context_digest: [u8; 32],
    ) -> Self {
        Self {
            cache_schema: CACHE_SCHEMA_VERSION,
            options_schema: BUILD_OPTIONS_SCHEMA_VERSION,
            daemon_id: daemon_id.to_string(),
            runner_identity: scope.runner_identity.clone(),
            github_scope: scope.github_scope.clone(),
            platform: platform.to_string(),
            dockerfile: dockerfile.to_string(),
            context_digest,
        }
    }
}
```

Implement the fingerprint and tag without exposing runner/repository names:

```rust
impl BuildCacheKey {
    pub(crate) fn fingerprint(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        for field in [
            vec![self.cache_schema],
            vec![self.options_schema],
            self.daemon_id.as_bytes().to_vec(),
            self.runner_identity.as_bytes().to_vec(),
            self.github_scope.as_bytes().to_vec(),
            self.platform.as_bytes().to_vec(),
            self.dockerfile.as_bytes().to_vec(),
            self.context_digest.to_vec(),
        ] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(&field);
        }
        hasher.finalize().to_hex().to_string()
    }

    pub(crate) fn internal_tag(&self, namespace: &str) -> String {
        format!(
            "chimera-internal/action-cache:{namespace}-{}",
            self.fingerprint()
        )
    }
}
```

`namespace` is the builder-instance UUID introduced in Task 4. It keeps internal tags practically collision-free across daemon processes; the fingerprint still contains `CACHE_SCHEMA_VERSION` and `BUILD_OPTIONS_SCHEMA_VERSION`.

- [ ] **Step 5: Implement a cancellation/deadline wrapper**

```rust
pub(crate) enum BudgetOutcome<T> {
    Ready(T),
    Cancelled,
    TimedOut,
}

pub(crate) async fn within_budget<T>(
    deadline: Instant,
    cancel_token: &CancellationToken,
    future: impl Future<Output = T>,
) -> BudgetOutcome<T> {
    tokio::pin!(future);
    tokio::select! {
        biased;
        _ = cancel_token.cancelled() => BudgetOutcome::Cancelled,
        _ = tokio::time::sleep_until(deadline) => BudgetOutcome::TimedOut,
        value = &mut future => BudgetOutcome::Ready(value),
    }
}
```

- [ ] **Step 6: Implement per-key locking without holding the maps during I/O**

```rust
pub(crate) struct BuildCache {
    entries: Mutex<HashMap<BuildCacheKey, String>>,
    locks: Mutex<HashMap<BuildCacheKey, Arc<Mutex<()>>>>,
}

pub(crate) enum CacheOutcome {
    Ready { image_id: String, cache_hit: bool },
    Cancelled,
    TimedOut,
}

impl BuildCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
        }
    }
}
```

`get_or_build` has this exact generic shape:

```rust
pub(crate) async fn get_or_build<I, IFut, B, BFut>(
    &self,
    key: BuildCacheKey,
    deadline: Instant,
    cancel_token: &CancellationToken,
    inspect: I,
    build: B,
) -> Result<CacheOutcome>
where
    I: Fn(String) -> IFut,
    IFut: Future<Output = Result<bool>>,
    B: FnOnce() -> BFut,
    BFut: Future<Output = Result<String>>,
```

Implement that signature as follows:

```rust
{
    let key_lock = {
        let mut locks = self.locks.lock().await;
        locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let _guard = match within_budget(deadline, cancel_token, key_lock.lock_owned()).await {
        BudgetOutcome::Ready(guard) => guard,
        BudgetOutcome::Cancelled => return Ok(CacheOutcome::Cancelled),
        BudgetOutcome::TimedOut => return Ok(CacheOutcome::TimedOut),
    };

    if let Some(image_id) = self.entries.lock().await.get(&key).cloned() {
        match within_budget(deadline, cancel_token, inspect(image_id.clone())).await {
            BudgetOutcome::Ready(Ok(true)) => {
                return Ok(CacheOutcome::Ready {
                    image_id,
                    cache_hit: true,
                });
            }
            BudgetOutcome::Ready(Ok(false)) => {
                self.entries.lock().await.remove(&key);
            }
            BudgetOutcome::Ready(Err(error)) => return Err(error),
            BudgetOutcome::Cancelled => return Ok(CacheOutcome::Cancelled),
            BudgetOutcome::TimedOut => return Ok(CacheOutcome::TimedOut),
        }
    }

    match within_budget(deadline, cancel_token, build()).await {
        BudgetOutcome::Ready(Ok(image_id)) => {
            self.entries.lock().await.insert(key, image_id.clone());
            Ok(CacheOutcome::Ready {
                image_id,
                cache_hit: false,
            })
        }
        BudgetOutcome::Ready(Err(error)) => Err(error),
        BudgetOutcome::Cancelled => Ok(CacheOutcome::Cancelled),
        BudgetOutcome::TimedOut => Ok(CacheOutcome::TimedOut),
    }
}
```

Error, cancel and timeout never insert an entry and release the per-key guard by RAII. Never remove key locks: their lifetime matches the in-memory index and retaining them prevents a third caller from creating a second lock while an older waiter still owns the first `Arc`.

- [ ] **Step 7: Run the cache suite**

Run:

```bash
cargo test docker::build_cache_test
```

Expected: all cache, concurrency and cancellation tests pass.

- [ ] **Step 8: Commit cache coordination**

```bash
git add src/docker.rs src/docker/build_cache.rs src/docker/build_cache_test.rs
git commit -m "feat: ✨ serialize identical Docker action builds" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

## Task 4: Build and verify images through Docker Engine API

**Files:**
- Create: `src/docker/build.rs`
- Create: `src/docker/build_test.rs`
- Modify: `src/docker.rs`

**Interfaces:**
- Consumes: `prepare_build_context`, `BuildCache`, `BuildCacheKey`, `within_budget`, existing `Docker`, `LogSender`, `CancellationToken`.
- Produces: `pub type RegistryAuth = HashMap<String, bollard::auth::DockerCredentials>`; CHM-03 will populate it, while this plan passes `None` from production runner wiring.
- Produces: `pub use super::build_cache::DockerBuildScope`.
- Produces: `pub struct BuiltDockerImage { pub daemon_id: String, pub image_id: String }`.
- Produces: `pub enum DockerBuildOutcome { Ready(BuiltDockerImage), Cancelled, TimedOut }`.
- Produces: `pub struct DockerBuildRequest<'a>` with fields `docker`, `action_dir`, `dockerfile`, `scope`, `registry_auth`, `log_sender`, `cancel_token`, `deadline`, `reuse`.
- Produces: `DockerActionBuilder::new()` and `pub async fn build(&self, request: DockerBuildRequest<'_>) -> anyhow::Result<DockerBuildOutcome>` for Task 5.
- Produces: `pub async fn require_local_image(docker: &Docker, image_id: &str) -> anyhow::Result<()>` so built IDs never enter pull fallback.
- Internal adapter: `async fn build_archive(docker: &Docker, prepared: PreparedBuildContext, internal_tag: &str, cache_key: &BuildCacheKey, registry_auth: Option<RegistryAuth>, log_sender: &LogSender) -> anyhow::Result<String>`.
- Internal verification: `async fn daemon_id(docker: &Docker) -> anyhow::Result<String>` and `async fn image_exists(docker: &Docker, image_id: String) -> anyhow::Result<bool>`.

- [ ] **Step 1: Write failing success/failure tests against a real Engine**

Create ignored tests that build unique local contexts:

```rust
#[tokio::test]
#[ignore]
async fn engine_build_returns_verified_local_image_id() {
    let docker = crate::docker::client::connect(None).unwrap();
    crate::docker::client::ping(&docker).await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM alpine:3.19\nRUN true\n").unwrap();
    let (logger, _receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/engine-build");

    let outcome = builder
        .build(DockerBuildRequest {
            docker: &docker,
            action_dir: tmp.path(),
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &logger,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(120),
            reuse: None,
        })
        .await
        .unwrap();

    let DockerBuildOutcome::Ready(image) = outcome else {
        panic!("expected a built image");
    };
    assert!(image.image_id.starts_with("sha256:"));
    assert_eq!(
        docker.inspect_image(&image.image_id).await.unwrap().id.as_deref(),
        Some(image.image_id.as_str())
    );
}

#[tokio::test]
#[ignore]
async fn engine_build_failure_does_not_publish_cache_entry() {
    let docker = crate::docker::client::connect(None).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM alpine:3.19\nRUN false\n").unwrap();
    let (logger, _receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/failing-build");

    let result = builder
        .build(DockerBuildRequest {
            docker: &docker,
            action_dir: tmp.path(),
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &logger,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(120),
            reuse: None,
        })
        .await;

    assert_eq!(result.unwrap_err().to_string(), "Docker action image build failed");
    assert_eq!(builder.cache_entry_count_for_test().await, 0);
}
```

Define the logger and inspection helpers in `build_test.rs` / `build.rs`:

```rust
fn test_log_sender() -> (LogSender, tokio::sync::mpsc::Receiver<LogLine>) {
    let (tx, rx) = tokio::sync::mpsc::channel(256);
    let masks = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    (LogSender::new_for_test(tx, masks), rx)
}

#[cfg(test)]
impl DockerActionBuilder {
    async fn cache_entry_count_for_test(&self) -> usize {
        self.cache.entry_count_for_test().await
    }

    async fn internal_tag_for_context_for_test(
        &self,
        docker: &Docker,
        action_dir: &Path,
        dockerfile: &str,
        scope: &DockerBuildScope,
    ) -> Result<String> {
        let prepared = prepare_build_context(action_dir, dockerfile)?;
        let daemon_id = daemon_id(docker).await?;
        let key = BuildCacheKey::new(
            &daemon_id,
            scope,
            DOCKER_ACTION_PLATFORM,
            &prepared.dockerfile,
            prepared.digest,
        );
        Ok(key.internal_tag(&self.tag_namespace))
    }
}
```

- [ ] **Step 2: Write the mandatory real-cancellation gate test**

Use a unique Dockerfile comment so a previous successful image cannot satisfy the cache:

```rust
#[tokio::test]
#[ignore]
async fn cancelling_build_stops_engine_work_and_never_publishes_image() {
    let docker = crate::docker::client::connect(None).unwrap();
    let engine_version = docker.version().await.unwrap();
    eprintln!("D-06 Docker Engine: {engine_version:?}");
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let unique = uuid::Uuid::new_v4();
    std::fs::write(
        tmp.path().join("Dockerfile"),
        format!("# {unique}\nFROM alpine:3.19\nRUN echo CHIMERA_CANCEL_STARTED && sleep 6\n"),
    )
    .unwrap();
    let (logger, mut receiver) = test_log_sender();
    let builder = std::sync::Arc::new(DockerActionBuilder::new());
    let scope = DockerBuildScope::new("test-runner", format!("test/cancel-{unique}"));
    let cancel = CancellationToken::new();

    let task = {
        let docker = docker.clone();
        let action_dir = tmp.path().to_path_buf();
        let builder = builder.clone();
        let scope = scope.clone();
        let logger = logger.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            builder
                .build(DockerBuildRequest {
                    docker: &docker,
                    action_dir: &action_dir,
                    dockerfile: "Dockerfile",
                    scope: &scope,
                    registry_auth: None,
                    log_sender: &logger,
                    cancel_token: &cancel,
                    deadline: Instant::now() + Duration::from_secs(60),
                    reuse: None,
                })
                .await
        })
    };

    loop {
        let line = tokio::time::timeout(Duration::from_secs(30), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        if line.content.contains("CHIMERA_CANCEL_STARTED") {
            break;
        }
    }
    cancel.cancel();

    let outcome = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("build cancellation must be bounded")
        .unwrap()
        .unwrap();
    assert!(matches!(outcome, DockerBuildOutcome::Cancelled));

    let tag = builder
        .internal_tag_for_context_for_test(&docker, tmp.path(), "Dockerfile", &scope)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(matches!(
        docker.inspect_image(&tag).await,
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. })
    ));
    assert_eq!(builder.cache_entry_count_for_test().await, 0);
}
```

This test waits until the Engine reports the long-running `RUN` instruction, cancels the client stream, waits longer than that instruction would need to finish, and proves the tagged result never appears. A Rust `Cancelled` result without the final `inspect_image` assertion is not acceptable evidence.

Add the deadline sibling, using the same pre-pulled base and image/tag checks:

```rust
#[tokio::test]
#[ignore]
async fn timed_out_build_returns_bounded_and_never_publishes_image() {
    let docker = crate::docker::client::connect(None).unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Dockerfile"),
        format!(
            "# {}\nFROM alpine:3.19\nRUN echo CHIMERA_TIMEOUT_STARTED && sleep 6\n",
            uuid::Uuid::new_v4()
        ),
    )
    .unwrap();
    let (logger, _receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/build-timeout");
    let started = Instant::now();

    let outcome = builder
        .build(DockerBuildRequest {
            docker: &docker,
            action_dir: tmp.path(),
            dockerfile: "Dockerfile",
            scope: &scope,
            registry_auth: None,
            log_sender: &logger,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(2),
            reuse: None,
        })
        .await
        .unwrap();

    assert!(matches!(outcome, DockerBuildOutcome::TimedOut));
    assert!(started.elapsed() < Duration::from_secs(4));
    let tag = builder
        .internal_tag_for_context_for_test(&docker, tmp.path(), "Dockerfile", &scope)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(matches!(
        docker.inspect_image(&tag).await,
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. })
    ));
    assert_eq!(builder.cache_entry_count_for_test().await, 0);
}
```

- [ ] **Step 3: Run the new tests and verify the adapter is absent**

Run:

```bash
cargo test docker::build_test -- --ignored --nocapture
```

Expected: compile failure because the builder interface does not exist. Include the test file from `build.rs` with:

```rust
#[cfg(test)]
#[path = "build_test.rs"]
mod build_test;
```

- [ ] **Step 4: Implement the public build request/outcome API**

```rust
pub const DOCKER_ACTION_PLATFORM: &str = "linux/amd64";
pub type RegistryAuth = HashMap<String, DockerCredentials>;

pub use super::build_cache::DockerBuildScope;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltDockerImage {
    pub daemon_id: String,
    pub image_id: String,
}

pub enum DockerBuildOutcome {
    Ready(BuiltDockerImage),
    Cancelled,
    TimedOut,
}

pub struct DockerBuildRequest<'a> {
    pub docker: &'a Docker,
    pub action_dir: &'a Path,
    pub dockerfile: &'a str,
    pub scope: &'a DockerBuildScope,
    pub registry_auth: Option<&'a RegistryAuth>,
    pub log_sender: &'a LogSender,
    pub cancel_token: &'a CancellationToken,
    pub deadline: Instant,
    pub reuse: Option<&'a BuiltDockerImage>,
}

pub struct DockerActionBuilder {
    cache: BuildCache,
    tag_namespace: String,
}

impl DockerActionBuilder {
    pub fn new() -> Self {
        Self {
            cache: BuildCache::new(),
            tag_namespace: uuid::Uuid::new_v4().simple().to_string(),
        }
    }
}

impl Default for DockerActionBuilder {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 5: Implement bounded orchestration and job-local reuse**

`DockerActionBuilder::build` must execute this sequence through `within_budget`:

1. run `prepare_build_context` in `spawn_blocking`, so invalid paths, ignore files, symlink escapes and special files fail before the first Docker API request;
2. call `docker.info()` and require a non-empty `SystemInfo.id`;
3. when `request.reuse` has the same daemon ID, inspect its image ID and return it while discarding the newly validated context;
4. construct `BuildCacheKey` from daemon/scope/platform/path/digest;
5. call `BuildCache::get_or_build` with an `inspect_image` closure and a closure invoking `build_archive`;
6. map cache cancellation/timeout directly to `DockerBuildOutcome`.

Use this control flow; each `Cancelled` / `TimedOut` branch returns the matching `DockerBuildOutcome` immediately:

```rust
pub async fn build(&self, request: DockerBuildRequest<'_>) -> Result<DockerBuildOutcome> {
    request
        .log_sender
        .send("Preparing Docker action build context".into())
        .await;
    let action_dir = request.action_dir.to_path_buf();
    let dockerfile = request.dockerfile.to_string();
    let prepared = match within_budget(
        request.deadline,
        request.cancel_token,
        tokio::task::spawn_blocking(move || prepare_build_context(&action_dir, &dockerfile)),
    )
    .await
    {
        BudgetOutcome::Ready(joined) => joined.context("preparing Docker build context")??,
        BudgetOutcome::Cancelled => return Ok(DockerBuildOutcome::Cancelled),
        BudgetOutcome::TimedOut => return Ok(DockerBuildOutcome::TimedOut),
    };

    let daemon_id = match within_budget(
        request.deadline,
        request.cancel_token,
        daemon_id(request.docker),
    )
    .await
    {
        BudgetOutcome::Ready(result) => result?,
        BudgetOutcome::Cancelled => return Ok(DockerBuildOutcome::Cancelled),
        BudgetOutcome::TimedOut => return Ok(DockerBuildOutcome::TimedOut),
    };

    if let Some(reuse) = request.reuse
        && reuse.daemon_id == daemon_id
    {
        match within_budget(
            request.deadline,
            request.cancel_token,
            image_exists(request.docker, reuse.image_id.clone()),
        )
        .await
        {
            BudgetOutcome::Ready(Ok(true)) => {
                request
                    .log_sender
                    .send("Reusing Docker action image for this job".into())
                    .await;
                return Ok(DockerBuildOutcome::Ready(reuse.clone()));
            }
            BudgetOutcome::Ready(Ok(false)) => {}
            BudgetOutcome::Ready(Err(error)) => return Err(error),
            BudgetOutcome::Cancelled => return Ok(DockerBuildOutcome::Cancelled),
            BudgetOutcome::TimedOut => return Ok(DockerBuildOutcome::TimedOut),
        }
    }

    let key = BuildCacheKey::new(
        &daemon_id,
        request.scope,
        DOCKER_ACTION_PLATFORM,
        &prepared.dockerfile,
        prepared.digest,
    );
    let internal_tag = key.internal_tag(&self.tag_namespace);
    let inspect_docker = request.docker.clone();
    let build_docker = request.docker.clone();
    let build_key = key.clone();
    let logger = request.log_sender.clone();
    let registry_auth = request.registry_auth.cloned();
    let outcome = self
        .cache
        .get_or_build(
            key,
            request.deadline,
            request.cancel_token,
            move |image_id| {
                let docker = inspect_docker.clone();
                async move { image_exists(&docker, image_id).await }
            },
            move || async move {
                logger.send("Building Docker action image".into()).await;
                build_archive(
                    &build_docker,
                    prepared,
                    &internal_tag,
                    &build_key,
                    registry_auth,
                    &logger,
                )
                .await
            },
        )
        .await?;

    match outcome {
        CacheOutcome::Ready { image_id, cache_hit } => {
            if cache_hit {
                request
                    .log_sender
                    .send("Reusing cached Docker action image".into())
                    .await;
            }
            request
                .log_sender
                .send("Docker action image is ready".into())
                .await;
            Ok(DockerBuildOutcome::Ready(BuiltDockerImage {
                daemon_id,
                image_id,
            }))
        }
        CacheOutcome::Cancelled => Ok(DockerBuildOutcome::Cancelled),
        CacheOutcome::TimedOut => Ok(DockerBuildOutcome::TimedOut),
    }
}
```

`daemon_id` rejects an empty `SystemInfo.id`; `image_exists` returns `Ok(false)` only for Docker 404 and propagates every other Engine error. Do not include auth, full context paths or internal tags in progress messages.

- [ ] **Step 6: Implement the Bollard stream adapter and image verification**

Build options are fixed and form `BUILD_OPTIONS_SCHEMA_VERSION = 1`:

```rust
let options = BuildImageOptions {
    dockerfile: prepared.dockerfile.clone(),
    t: internal_tag.to_string(),
    pull: false,
    rm: true,
    forcerm: true,
    platform: DOCKER_ACTION_PLATFORM.to_string(),
    labels: HashMap::from([
        ("io.chimera.action-cache".to_string(), "v1".to_string()),
        ("io.chimera.action-key".to_string(), cache_key.fingerprint()),
    ]),
    version: BuilderVersion::BuilderV1,
    ..Default::default()
};
let mut stream = docker.build_image(
    options,
    registry_auth,
    Some(prepared.archive.into()),
);
```

For each successful `BuildInfo`, split `stream` into lines or send `status` plus `progress` through `LogSender`; ignore `aux` rather than serializing it. Treat either a Bollard stream error or `BuildInfo.error.is_some()` as exactly `anyhow!("Docker action image build failed")` after the already-masked progress stream. When the stream closes cleanly, inspect the internal tag, require label `io.chimera.action-key` to equal `cache_key.fingerprint()`, require a non-empty `id`, then inspect that ID and require the same ID. Only this verified ID is returned to `BuildCache`; a missing/wrong label is `Docker action image verification failed` and never populates the cache.

`require_local_image` must treat 404 as `built Docker action image is no longer present` and propagate other daemon errors; it never calls `ensure_image`.

- [ ] **Step 7: Run the real Engine tests, treating cancellation as a hard gate**

Run:

```bash
cargo test docker::build_test -- --ignored --nocapture
```

Expected: success build returns a `sha256:` ID; failed build leaves zero cache entries; cancel returns within three seconds and no tagged image appears eight seconds later.

If the cancellation test fails on the target Engine/API combination, stop here. Do not continue to executor wiring and do not weaken the test. Rework the adapter or Engine endpoint until D-06 has real bounded cancellation evidence.

- [ ] **Step 8: Add and pass real stale-image and concurrent-build tests**

Add a small request helper, then real stale/concurrent tests:

```rust
async fn test_build(
    builder: &DockerActionBuilder,
    docker: &Docker,
    action_dir: &Path,
    scope: &DockerBuildScope,
    logger: &LogSender,
) -> DockerBuildOutcome {
    builder
        .build(DockerBuildRequest {
            docker,
            action_dir,
            dockerfile: "Dockerfile",
            scope,
            registry_auth: None,
            log_sender: logger,
            cancel_token: &CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(120),
            reuse: None,
        })
        .await
        .unwrap()
}

#[tokio::test]
#[ignore]
async fn missing_cached_image_is_rebuilt() {
    let docker = crate::docker::client::connect(None).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM alpine:3.19\nRUN true\n").unwrap();
    let (logger, mut receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/stale-image");

    let DockerBuildOutcome::Ready(first) =
        test_build(&builder, &docker, tmp.path(), &scope, &logger).await
    else {
        panic!("expected first build");
    };
    docker
        .remove_image(
            &first.image_id,
            Some(bollard::image::RemoveImageOptions {
                force: true,
                noprune: false,
            }),
            None,
        )
        .await
        .unwrap();
    let DockerBuildOutcome::Ready(second) =
        test_build(&builder, &docker, tmp.path(), &scope, &logger).await
    else {
        panic!("expected rebuild");
    };

    docker.inspect_image(&second.image_id).await.unwrap();
    drop(logger);
    let mut build_messages = 0;
    while let Some(line) = receiver.recv().await {
        build_messages += usize::from(line.content == "Building Docker action image");
    }
    assert_eq!(build_messages, 2);
}

#[tokio::test]
#[ignore]
async fn concurrent_same_context_builds_once() {
    let docker = crate::docker::client::connect(None).unwrap();
    crate::docker::client::ensure_image(&docker, "alpine:3.19", None)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Dockerfile"), "FROM alpine:3.19\nRUN sleep 1\n").unwrap();
    let (logger, mut receiver) = test_log_sender();
    let builder = DockerActionBuilder::new();
    let scope = DockerBuildScope::new("test-runner", "test/concurrent");

    let (left, right) = tokio::join!(
        test_build(&builder, &docker, tmp.path(), &scope, &logger),
        test_build(&builder, &docker, tmp.path(), &scope, &logger),
    );
    let DockerBuildOutcome::Ready(left) = left else {
        panic!("expected left image");
    };
    let DockerBuildOutcome::Ready(right) = right else {
        panic!("expected right image");
    };
    assert_eq!(left.image_id, right.image_id);

    drop(logger);
    let mut build_messages = 0;
    while let Some(line) = receiver.recv().await {
        build_messages += usize::from(line.content == "Building Docker action image");
    }
    assert_eq!(build_messages, 1);
}
```

Then run:

```bash
cargo test docker::build_test -- --ignored --nocapture
```

Expected: stale image becomes a miss; the concurrent pair both receive the same verified ID and only one Engine build starts.

- [ ] **Step 9: Commit the Engine adapter**

```bash
git add src/docker.rs src/docker/build.rs src/docker/build_test.rs
git commit -m "feat: ✨ build Docker action images through Engine API" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

## Task 5: Wire built images into the existing action executor

**Files:**
- Modify: `src/job/action/docker.rs`
- Modify: `src/job/action/docker_test.rs`
- Modify: `src/job/action/composite.rs`
- Modify: `src/job/action/composite_test.rs`
- Modify: `src/job/execute.rs`
- Modify: `src/job/execute_test.rs`
- Modify: `src/daemon.rs`
- Modify: `src/runner/instance.rs`
- Modify: `src/runner/instance_test.rs`
- Modify: `tests/common/mod.rs`
- Modify: `tests/basics_test.rs`

**Interfaces:**
- Consumes: `DockerActionBuilder`, `DockerBuildRequest`, `DockerBuildScope`, `RegistryAuth`, `BuiltDockerImage`, `DockerBuildOutcome` from Task 4.
- Produces: daemon-wide `Arc<DockerActionBuilder>` stored by every `Runner`.
- Produces: `JobState::docker_action_images: HashMap<String, BuiltDockerImage>` keyed by base action context.
- Changes: `run_all_steps` takes `docker_action_builder: &DockerActionBuilder` and `registry_auth: Option<&RegistryAuth>` immediately after `action_cache`.
- Changes: Docker/composite action calls carry `docker_build_scope`, `docker_action_builder`, `registry_auth` and a shared `tokio::time::Instant` deadline.

The public executor signature after this task is:

```rust
pub async fn run_all_steps(
    manifest: &JobManifest,
    job_client: &Arc<JobClient>,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    runner_name: &str,
    action_cache: &ActionCache,
    docker_action_builder: &DockerActionBuilder,
    registry_auth: Option<&RegistryAuth>,
    access_token: &str,
    cancel_token: CancellationToken,
    docker_resources: Option<&JobDockerResources>,
    node_runtimes: &NodeRuntimes,
    feed_sender: Option<&FeedSender>,
) -> Result<(JobConclusion, HashMap<String, String>)>
```

The metadata-action boundary is:

```rust
pub(crate) async fn run_docker_metadata_action(
    action_dir: &Path,
    metadata: &ActionMetadata,
    entry_point: &str,
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    docker_action_builder: &DockerActionBuilder,
    docker_build_scope: &DockerBuildScope,
    registry_auth: Option<&RegistryAuth>,
    deadline: Instant,
    cancel_token: &CancellationToken,
    docker_resources: Option<&JobDockerResources>,
) -> Result<StepResult>
```

- [ ] **Step 1: Replace rejection tests with failing image-source classification tests**

```rust
#[test]
fn metadata_image_classifies_dockerfile_and_prebuilt_references() {
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("Dockerfile")).unwrap(),
        MetadataImage::Dockerfile("Dockerfile")
    ));
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("docker/build/Dockerfile")).unwrap(),
        MetadataImage::Dockerfile("docker/build/Dockerfile")
    ));
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("docker://alpine:3.19")).unwrap(),
        MetadataImage::Prebuilt("alpine:3.19")
    ));
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("docker://example/Dockerfile")).unwrap(),
        MetadataImage::Prebuilt("example/Dockerfile")
    ));
    assert!(matches!(
        resolve_metadata_image(&make_docker_metadata("ghcr.io/owner/image:v1")).unwrap(),
        MetadataImage::Prebuilt("ghcr.io/owner/image:v1")
    ));
}

#[test]
fn action_instance_key_is_shared_by_pre_main_and_post() {
    assert_eq!(action_instance_key(Some("lint_pre"), "pre-id"), "lint");
    assert_eq!(action_instance_key(Some("lint"), "main-id"), "lint");
    assert_eq!(action_instance_key(Some("lint_post"), "post-id"), "lint");
    assert_eq!(action_instance_key(None, "plain-id"), "plain-id");
}
```

Only the exact filename `Dockerfile` at the final relative path component selects build mode. Registry references with `/` remain pre-built unless their final component is `Dockerfile`.

- [ ] **Step 2: Run the Docker action unit tests and verify they fail**

Run:

```bash
cargo test job::action::docker_test
```

Expected: classification tests fail because current `resolve_image` rejects Dockerfile metadata.

- [ ] **Step 3: Add per-job image pinning to `JobState`**

```rust
pub struct JobState {
    pub env: HashMap<String, String>,
    pub path_prepends: Vec<String>,
    pub outputs: HashMap<String, String>,
    pub masks: Arc<RwLock<Vec<String>>>,
    pub action_states: HashMap<String, HashMap<String, String>>,
    pub step_outputs: HashMap<String, HashMap<String, String>>,
    pub step_outcomes: HashMap<String, StepOutcome>,
    pub docker_action_images: HashMap<String, BuiltDockerImage>,
    pub secrets: HashMap<String, String>,
    pub context_data: serde_json::Value,
    pub host_workspace: Option<String>,
    pub default_working_directory: Option<String>,
    pub debug_enabled: bool,
}
```

Initialize `docker_action_images` empty in `JobState::new`. Do not put image IDs in action state/environment/output; they are runner-internal data.

- [ ] **Step 4: Construct one explicit build scope per job**

At the beginning of `run_all_steps`, derive a non-secret scope:

```rust
let server = manifest
    .context_data
    .get("github")
    .and_then(|github| github.get("server_url"))
    .and_then(serde_json::Value::as_str)
    .unwrap_or("https://github.com");
let github_scope = match manifest.repository() {
    Ok(repository) => format!("{server}/{repository}"),
    Err(_) => format!(
        "{server}/unknown/{}/{}",
        manifest.plan.plan_id, manifest.plan.job_id
    ),
};
let docker_build_scope = DockerBuildScope::new(runner_name, github_scope);
```

The fallback includes plan/job IDs instead of a shared `unknown/repository`, so missing context cannot merge cache entries from unrelated jobs. Thread `&docker_build_scope`, `docker_action_builder` and `registry_auth` through all three `execute_step` call sites, `run_action_step`, composite recursion and nested Docker actions. No function reads process-global Docker credentials.

- [ ] **Step 5: Compute one deadline at action-step start**

In `execute_step`, before dispatch:

```rust
let timeout = Duration::from_secs(step.timeout_in_minutes.unwrap_or(360) * 60);
let deadline = tokio::time::Instant::now() + timeout;
```

Pass `deadline` into `run_action_step`; pass the same value through composite recursion and nested Docker action calls. For a Dockerfile metadata action, context preparation, lock, build and container log wait all receive this deadline. Existing host/Node behavior remains unchanged in this task.

- [ ] **Step 6: Build once, pin the image, and use local-only execution**

Replace `resolve_image` with:

```rust
enum MetadataImage<'a> {
    Prebuilt(&'a str),
    Dockerfile(&'a str),
}

fn resolve_metadata_image(metadata: &ActionMetadata) -> Result<MetadataImage<'_>> {
    let raw = metadata
        .runs
        .image
        .as_deref()
        .context("docker action has no image field")?;
    if let Some(image) = raw.strip_prefix("docker://") {
        return Ok(MetadataImage::Prebuilt(image));
    }
    let path = Path::new(raw);
    if path.file_name().and_then(|name| name.to_str()) == Some("Dockerfile") {
        return Ok(MetadataImage::Dockerfile(raw));
    }
    Ok(MetadataImage::Prebuilt(raw))
}
```

Compute the stable phase key and select the image before container creation:

```rust
fn action_instance_key(context_name: Option<&str>, step_id: &str) -> String {
    let context = context_name.unwrap_or(step_id);
    context
        .strip_suffix("_pre")
        .or_else(|| context.strip_suffix("_post"))
        .unwrap_or(context)
        .to_string()
}

let (image, pull_if_missing) = match resolve_metadata_image(metadata)? {
    MetadataImage::Prebuilt(image) => (image.to_string(), true),
    MetadataImage::Dockerfile(dockerfile) => {
        let action_key = action_instance_key(step.context_name.as_deref(), &step.id);
        let reusable = job_state.docker_action_images.get(&action_key).cloned();
        let outcome = docker_action_builder
            .build(DockerBuildRequest {
                docker,
                action_dir,
                dockerfile,
                scope: docker_build_scope,
                registry_auth,
                log_sender,
                cancel_token,
                deadline,
                reuse: reusable.as_ref(),
            })
            .await?;
        match outcome {
            DockerBuildOutcome::Ready(built) => {
                let image_id = built.image_id.clone();
                job_state.docker_action_images.insert(action_key, built);
                (image_id, false)
            }
            DockerBuildOutcome::Cancelled => {
                return Ok(StepResult {
                    conclusion: StepConclusion::Cancelled,
                });
            }
            DockerBuildOutcome::TimedOut => {
                log_sender
                    .send("Docker action image build timed out".into())
                    .await;
                return Ok(StepResult {
                    conclusion: StepConclusion::Failed,
                });
            }
        }
    }
};
```

Refactor `RunDockerParams` to add the selected client and build semantics:

```rust
struct RunDockerParams<'a> {
    docker: &'a Docker,
    image: &'a str,
    pull_if_missing: bool,
    deadline: Instant,
    entrypoint: Option<&'a str>,
    args: &'a [String],
    env: &'a HashMap<String, String>,
    step: &'a Step,
    job_state: &'a mut JobState,
    workspace: &'a Workspace,
    log_sender: &'a LogSender,
    cancel_token: &'a CancellationToken,
    docker_resources: Option<&'a JobDockerResources>,
    action_dir: Option<&'a Path>,
}

if params.pull_if_missing {
    crate::docker::client::ensure_image(params.docker, params.image, None).await?;
} else {
    require_local_image(params.docker, params.image).await?;
}
```

Both inline and metadata callers select the client before constructing `RunDockerParams`; metadata build uses that same reference. The same `Docker` client is therefore used for build, inspect, create, logs and cleanup.

- [ ] **Step 7: Make container logging consume the remaining deadline**

Change `start_and_stream_logs` to accept `deadline: Instant`, keep its existing log-stream body, and replace `timeout(timeout, stream_task)` with a borrowed join handle:

```rust
let mut stream_task = tokio::spawn(async move {
    let mut stream = docker_for_logs.logs::<String>(
        &container_id_for_logs,
        Some(LogsOptions {
            follow: true,
            stdout: true,
            stderr: true,
            ..Default::default()
        }),
    );
    while let Some(Ok(output)) = stream.next().await {
        for line in output.to_string().lines() {
            processor_for_logs.process_line(line).await;
        }
    }
});

let stream_result: std::result::Result<(), StepConclusion> = tokio::select! {
    biased;
    _ = cancel_token.cancelled() => {
        stream_task.abort();
        warn!("job cancelled, stopping docker action container");
        Err(StepConclusion::Cancelled)
    }
    _ = tokio::time::sleep_until(deadline) => {
        stream_task.abort();
        warn!("docker action timed out");
        Err(StepConclusion::Failed)
    }
    joined = &mut stream_task => {
        match joined {
            Ok(()) => Ok(()),
            Err(error) => {
                warn!(error = %error, "docker action stream task panicked");
                Ok(())
            }
        }
    }
};

if let Err(conclusion) = stream_result {
    return Ok(StepResult { conclusion });
}
```

Create `docker_for_logs`, `container_id_for_logs` and `processor_for_logs` by cloning the same values used by the current closure. Do not start a fresh duration. On timeout or cancel the task is aborted before `run_docker_container` executes existing `stop_and_remove`.

- [ ] **Step 8: Share one builder across daemon runners**

Create the builder once in `Daemon::run` before the runner loop and extend the runner constructor:

```rust
let docker_action_builder = Arc::new(crate::docker::build::DockerActionBuilder::new());

pub struct Runner {
    pub(super) name: String,
    pub(super) credentials: RunnerCredentials,
    pub(super) paths: ChimeraPaths,
    pub(super) state: Option<Arc<DaemonState>>,
    pub(super) cache_port: u16,
    pub(super) docker_action_builder: Arc<DockerActionBuilder>,
}

pub fn with_state(
    name: String,
    credentials: RunnerCredentials,
    paths: ChimeraPaths,
    state: Arc<DaemonState>,
    cache_port: u16,
    docker_action_builder: Arc<DockerActionBuilder>,
) -> Self {
    Self {
        name,
        credentials,
        paths,
        state: Some(state),
        cache_port,
        docker_action_builder,
    }
}
```

Each daemon loop iteration passes `Arc::clone(&docker_action_builder)` to `Runner::with_state`; `run_job_body` passes `self.docker_action_builder.as_ref()` to `run_all_steps`. Pass `None` for `registry_auth` with a comment referencing CHM-03; do not read inherited `DOCKER_CONFIG`.

Update `make_runner`, `TestEnv`, all direct `run_all_steps` calls and composite tests with a real `DockerActionBuilder::new()` and `None` auth. Keep the builder as an `Arc` field in `TestEnv` so separate test jobs can exercise daemon-memory cache reuse.

- [ ] **Step 9: Run non-Docker tests and fix every signature call site**

Run:

```bash
cargo test --lib
cargo test --test basics_test
cargo clippy -- -D warnings
```

Expected: all tests pass with no warnings; no call site creates a fresh builder inside an individual action phase.

- [ ] **Step 10: Run existing Docker regressions**

Run:

```bash
cargo test --test docker_test -- --ignored --nocapture
```

Expected: existing inline `docker://`, container-mode and service tests pass unchanged.

- [ ] **Step 11: Commit executor wiring**

```bash
git add src/job/action/docker.rs src/job/action/docker_test.rs src/job/action/composite.rs src/job/action/composite_test.rs src/job/execute.rs src/job/execute_test.rs src/daemon.rs src/runner/instance.rs src/runner/instance_test.rs tests/common/mod.rs tests/basics_test.rs
git commit -m "feat: ✨ execute images built from action Dockerfiles" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

## Task 6: Cover D-01…D-09 and D-11 end to end

**Files:**
- Create: `tests/dockerfile_actions_test.rs`
- Modify: `tests/common/mod.rs`
- Modify: `src/docker/build_test.rs`
- Modify: `src/docker/build_cache_test.rs`

**Interfaces:**
- Consumes: shared `TestEnv`, `DockerActionBuilder`, local Docker daemon and executor wiring from Task 5.
- Produces: `local_action_step(id: &str, path: &str, inputs: HashMap<String, String>) -> serde_json::Value`.
- Produces: `TestEnv::run_with_cancel`, `TestEnv::run_with_access_token`, `TestEnv::run_with_registry_auth` and `TestEnv::uploaded_log_text` for explicit cancellation/acceptance/auth/log assertions.

- [ ] **Step 1: Add test-harness helpers**

Add an exact local-action manifest builder:

```rust
pub fn local_action_step(
    id: &str,
    path: &str,
    inputs: HashMap<String, String>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "displayName": format!("Run {path}"),
        "reference": {
            "name": "",
            "type": "repository",
            "repositoryType": "self",
            "path": path
        },
        "inputs": inputs,
        "condition": null,
        "timeoutInMinutes": null,
        "continueOnError": false,
        "order": 1,
        "environment": null,
        "contextName": id
    })
}
```

Keep one builder on `TestEnv` and centralize the expanded call in a private helper:

```rust
pub struct TestEnv {
    pub workspace: Workspace,
    pub job_client: Arc<JobClient>,
    pub mock_server: MockServer,
    pub tmp: tempfile::TempDir,
    actions_dir: PathBuf,
    docker_action_builder: Arc<DockerActionBuilder>,
}

async fn run_with_options(
    &self,
    manifest: &JobManifest,
    access_token: &str,
    cancel_token: CancellationToken,
    registry_auth: Option<&RegistryAuth>,
) -> anyhow::Result<(JobConclusion, HashMap<String, String>)> {
    let base_env = build_base_env(manifest, &self.workspace, "test-runner");
    let action_cache = ActionCache::new(self.actions_dir.clone(), reqwest::Client::new());
    run_all_steps(
        manifest,
        &self.job_client,
        &self.workspace,
        &base_env,
        "test-runner",
        &action_cache,
        self.docker_action_builder.as_ref(),
        registry_auth,
        access_token,
        cancel_token,
        None,
        &chimera::node::NodeRuntimes::single("node".into()),
        None,
    )
    .await
}

pub async fn uploaded_log_text(&self) -> String {
    self.mock_server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|request| {
            request.method.as_str() == "POST"
                && request.url.path().contains("/logs/")
        })
        .map(|request| String::from_utf8_lossy(&request.body).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}
```

`run`, `run_with_cancel`, `run_with_access_token` and `run_with_registry_auth` are thin calls to `run_with_options` with, respectively, the current defaults, caller cancellation token, caller GitHub token, or caller `RegistryAuth`. None of these helpers mutate process-global environment.

- [ ] **Step 2: Write D-01 and D-02 tests**

Create local action fixtures entirely inside `env.workspace.workspace_dir()`:

```rust
#[tokio::test]
#[ignore]
async fn dockerfile_action_builds_and_propagates_exit_code() {
    let env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/dockerfile-basic");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: basic\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY entrypoint.sh /entrypoint.sh\nRUN chmod +x /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join("entrypoint.sh"), "#!/bin/sh\necho result=ok >> \"$GITHUB_OUTPUT\"\n").unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step("docker", ".github/actions/dockerfile-basic", HashMap::new())],
        &env.mock_server.uri(),
    );

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert_eq!(outputs.get("result").map(String::as_str), Some("ok"));
}
```

Add the subdirectory/spaces case:

```rust
#[tokio::test]
#[ignore]
async fn subdirectory_dockerfile_uses_action_root_as_context() {
    let env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/subdir-build");
    std::fs::create_dir_all(action.join("docker files")).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: subdir\nruns:\n  using: docker\n  image: docker files/Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join("payload.txt"), "from-action-root").unwrap();
    std::fs::write(action.join("entrypoint.sh"), "#!/bin/sh\ntest \"$(cat /payload.txt)\" = from-action-root\n").unwrap();
    std::fs::write(
        action.join("docker files/Dockerfile"),
        "FROM alpine:3.19\nCOPY payload.txt /payload.txt\nCOPY entrypoint.sh /entrypoint.sh\nRUN chmod +x /entrypoint.sh\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step("subdir", ".github/actions/subdir-build", HashMap::new())],
        &env.mock_server.uri(),
    );

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
}
```

This proves Dockerfile location does not become context root and also covers spaces without shell splitting.

- [ ] **Step 3: Write D-03 and D-11 filtering/canary tests**

Add one successful precedence fixture and one rejected escape fixture:

```rust
#[tokio::test]
#[ignore]
async fn dockerfile_specific_ignore_overrides_root_ignore() {
    let env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/ignore-rules");
    std::fs::create_dir_all(action.join("docker")).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: ignores\nruns:\n  using: docker\n  image: docker/Dockerfile\n  entrypoint: /context/entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join(".dockerignore"), "root-only.txt\n").unwrap();
    std::fs::write(action.join("docker/Dockerfile.dockerignore"), "specific-only.txt\n").unwrap();
    std::fs::write(action.join("root-only.txt"), "must-be-present").unwrap();
    std::fs::write(action.join("specific-only.txt"), "must-be-absent").unwrap();
    std::fs::write(action.join("entrypoint.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(
        action.join("docker/Dockerfile"),
        "FROM alpine:3.19\nCOPY . /context\nRUN test -f /context/root-only.txt && test ! -e /context/specific-only.txt && chmod +x /context/entrypoint.sh\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step("ignores", ".github/actions/ignore-rules", HashMap::new())],
        &env.mock_server.uri(),
    );

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Succeeded);
}

#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn context_symlink_escape_fails_before_action_container_starts() {
    use std::os::unix::fs::symlink;

    let env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/symlink-escape");
    std::fs::create_dir_all(&action).unwrap();
    let outside = env.tmp.path().join("synthetic-canary");
    std::fs::write(&outside, "CHIMERA_OUTSIDE_CONTEXT_CANARY").unwrap();
    symlink(&outside, action.join("escape")).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: escape\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join("Dockerfile"), "FROM alpine:3.19\n").unwrap();
    std::fs::write(action.join("entrypoint.sh"), "#!/bin/sh\ntouch /github/workspace/main-ran\n").unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step("escape", ".github/actions/symlink-escape", HashMap::new())],
        &env.mock_server.uri(),
    );

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Failed);
    assert!(!env.workspace.workspace_dir().join("main-ran").exists());
    assert!(!env.uploaded_log_text().await.contains("CHIMERA_OUTSIDE_CONTEXT_CANARY"));
}
```

Add the D-11 auth/context canary case:

```rust
#[tokio::test]
#[ignore]
async fn synthetic_secrets_stay_out_of_context_and_logs() {
    let env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/canary");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: canary\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /bin/true\n",
    )
    .unwrap();
    std::fs::write(action.join(".dockerignore"), "synthetic-secret.txt\n").unwrap();
    std::fs::write(
        action.join("synthetic-secret.txt"),
        "CHIMERA_SYNTHETIC_CONTEXT_CANARY",
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY . /context\nRUN test ! -e /context/synthetic-secret.txt\n",
    )
    .unwrap();
    let auth = RegistryAuth::from([(
        "https://synthetic.invalid/v1/".to_string(),
        bollard::auth::DockerCredentials {
            username: Some("synthetic-user".to_string()),
            password: Some("CHIMERA_SYNTHETIC_AUTH_CANARY".to_string()),
            ..Default::default()
        },
    )]);
    let manifest = manifest_with_steps(
        vec![local_action_step("canary", ".github/actions/canary", HashMap::new())],
        &env.mock_server.uri(),
    );

    let (conclusion, _) = env
        .run_with_registry_auth(&manifest, &auth)
        .await
        .unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(!logs.contains("CHIMERA_SYNTHETIC_CONTEXT_CANARY"));
    assert!(!logs.contains("CHIMERA_SYNTHETIC_AUTH_CANARY"));
}
```

The byte-window assertion in `root_dockerignore_filters_files_but_keeps_dockerfile` from Task 2 is the direct tar-level D-11 evidence; keep it enabled in the normal unit suite.

- [ ] **Step 4: Write D-04 cache invalidation test**

Run the same local action three times through one `TestEnv`:

```rust
#[tokio::test]
#[ignore]
async fn changed_context_rebuilds_while_unchanged_context_hits_cache() {
    let env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/cache-key");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: cache\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /bin/true\n",
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY payload.txt /payload.txt\n",
    )
    .unwrap();
    std::fs::write(action.join("payload.txt"), "first").unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step("cache", ".github/actions/cache-key", HashMap::new())],
        &env.mock_server.uri(),
    );

    assert_eq!(env.run(&manifest).await.unwrap().0, JobConclusion::Succeeded);
    assert_eq!(env.run(&manifest).await.unwrap().0, JobConclusion::Succeeded);
    std::fs::write(action.join("payload.txt"), "second").unwrap();
    assert_eq!(env.run(&manifest).await.unwrap().0, JobConclusion::Succeeded);
    let logs = env.uploaded_log_text().await;

    assert_eq!(logs.matches("Building Docker action image").count(), 2);
    assert_eq!(logs.matches("Reusing cached Docker action image").count(), 1);
}
```

Do not add requested git ref to `BuildCacheKey`: a ref with the same filtered bytes is reusable, while a ref resolving to different bytes already changes `context_digest`. The current resolver exposes the checked-out directory, not a separate resolved-commit field.

- [ ] **Step 5: Complete D-05, D-06 and D-07 adapter tests**

The same-key/stale-image real-Engine tests created in Task 4 remain part of D-05/D-07. Add a unit proof that different keys enter their build closures concurrently:

```rust
#[tokio::test]
async fn different_keys_build_concurrently() {
    let cache = Arc::new(BuildCache::new());
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let mut tasks = Vec::new();
    for digest in [1, 2] {
        let cache = cache.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            cache
                .get_or_build(
                    key("daemon-a", digest),
                    Instant::now() + Duration::from_secs(2),
                    &CancellationToken::new(),
                    |_| async { Ok(true) },
                    move || async move {
                        barrier.wait().await;
                        Ok(format!("sha256:{digest}"))
                    },
                )
                .await
                .unwrap()
        }));
    }

    tokio::time::timeout(Duration::from_secs(1), barrier.wait())
        .await
        .expect("different cache keys must reach their builds concurrently");
    for task in tasks {
        assert!(matches!(task.await.unwrap(), CacheOutcome::Ready { .. }));
    }
}
```

Add timeout/failure lock-release coverage:

```rust
#[tokio::test]
async fn timeout_and_failure_leave_key_retryable() {
    let cache = BuildCache::new();
    let cache_key = key("daemon-a", 7);
    let key_lock = cache.key_lock_for_test(cache_key.clone()).await;
    let guard = key_lock.lock().await;
    let wait_outcome = cache
        .get_or_build(
            cache_key.clone(),
            Instant::now() + Duration::from_millis(20),
            &CancellationToken::new(),
            |_| async { Ok(true) },
            || async { Ok("sha256:forbidden".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(wait_outcome, CacheOutcome::TimedOut));
    drop(guard);

    let failure = cache
        .get_or_build(
            cache_key.clone(),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
            |_| async { Ok(true) },
            || async { Err(anyhow::anyhow!("synthetic build failure")) },
        )
        .await;
    assert_eq!(failure.unwrap_err().to_string(), "synthetic build failure");
    assert_eq!(cache.entry_count_for_test().await, 0);

    let retry_outcome = cache
        .get_or_build(
            cache_key,
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
            |_| async { Ok(true) },
            || async { Ok("sha256:retry".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(
        retry_outcome,
        CacheOutcome::Ready { cache_hit: false, .. }
    ));
}
```

Add executor-level build failure coverage:

```rust
#[tokio::test]
#[ignore]
async fn failed_build_does_not_start_action_entrypoint() {
    let env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/failing-build");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: failure\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: /entrypoint.sh\n",
    )
    .unwrap();
    std::fs::write(action.join("Dockerfile"), "FROM alpine:3.19\nRUN false\n").unwrap();
    std::fs::write(
        action.join("entrypoint.sh"),
        "#!/bin/sh\ntouch /github/workspace/main-ran\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step("failure", ".github/actions/failing-build", HashMap::new())],
        &env.mock_server.uri(),
    );

    let (conclusion, _) = env.run(&manifest).await.unwrap();

    assert_eq!(conclusion, JobConclusion::Failed);
    assert!(!env.workspace.workspace_dir().join("main-ran").exists());
}
```

The ignored cancellation test from Task 4 is still mandatory because these unit/executor checks alone do not prove that Engine work stops.

- [ ] **Step 6: Write D-08 pre/main/post reuse test**

Use distinct phase entrypoints in one image; main writes state because the current executor already keys main state for post consumption:

```rust
#[tokio::test]
#[ignore]
async fn dockerfile_action_reuses_image_for_pre_main_post() {
    let env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/phases");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        r#"name: phases
inputs:
  message:
    default: default-message
runs:
  using: docker
  image: Dockerfile
  pre-entrypoint: /pre.sh
  entrypoint: /main.sh
  post-entrypoint: /post.sh
  args:
    - ${{ inputs.message }}
  env:
    ACTION_ENV: env-value
"#,
    )
    .unwrap();
    std::fs::write(
        action.join("Dockerfile"),
        "FROM alpine:3.19\nCOPY pre.sh main.sh post.sh /\nRUN chmod +x /pre.sh /main.sh /post.sh\n",
    )
    .unwrap();
    std::fs::write(action.join("pre.sh"), "#!/bin/sh\necho pre >> /github/workspace/phases\n").unwrap();
    std::fs::write(
        action.join("main.sh"),
        "#!/bin/sh\nset -eu\ntest \"$INPUT_MESSAGE\" = expected\ntest \"$ACTION_ENV\" = env-value\ntest \"$1\" = expected\necho main >> /github/workspace/phases\necho phase=main >> \"$GITHUB_STATE\"\necho result=ok >> \"$GITHUB_OUTPUT\"\n",
    )
    .unwrap();
    std::fs::write(
        action.join("post.sh"),
        "#!/bin/sh\nset -eu\ntest \"$STATE_phase\" = main\necho post >> /github/workspace/phases\n",
    )
    .unwrap();
    let manifest = manifest_with_steps(
        vec![local_action_step(
            "phases",
            ".github/actions/phases",
            HashMap::from([("message".to_string(), "expected".to_string())]),
        )],
        &env.mock_server.uri(),
    );

    let (conclusion, outputs) = env.run(&manifest).await.unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert_eq!(outputs.get("result").map(String::as_str), Some("ok"));
    assert_eq!(
        std::fs::read_to_string(env.workspace.workspace_dir().join("phases")).unwrap(),
        "pre\nmain\npost\n"
    );
    assert_eq!(logs.matches("Docker action image is ready").count(), 1);
    assert_eq!(
        logs.matches("Reusing Docker action image for this job").count(),
        2
    );
}
```

- [ ] **Step 7: Write D-09 pre-built metadata regression**

Run a pre-built metadata action and an inline image in the same job:

```rust
#[tokio::test]
#[ignore]
async fn prebuilt_metadata_and_inline_docker_actions_still_run() {
    let env = TestEnv::setup().await;
    let action = env.workspace.workspace_dir().join(".github/actions/prebuilt");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: prebuilt\nruns:\n  using: docker\n  image: docker://alpine:3.19\n  entrypoint: /bin/sh\n  args: ['-c', 'exit 0']\n",
    )
    .unwrap();
    let inline = serde_json::json!({
        "id": "inline",
        "displayName": "Inline Docker",
        "reference": {
            "name": "docker://alpine:3.19",
            "type": "containerregistry",
            "image": "alpine:3.19"
        },
        "inputs": { "entrypoint": "/bin/sh", "args": "-c \"exit 0\"" },
        "condition": null,
        "timeoutInMinutes": null,
        "continueOnError": false,
        "order": 2,
        "environment": null,
        "contextName": "inline"
    });
    let manifest = manifest_with_steps(
        vec![
            local_action_step("prebuilt", ".github/actions/prebuilt", HashMap::new()),
            inline,
        ],
        &env.mock_server.uri(),
    );

    let (conclusion, _) = env.run(&manifest).await.unwrap();
    let logs = env.uploaded_log_text().await;

    assert_eq!(conclusion, JobConclusion::Succeeded);
    assert!(!logs.contains("Preparing Docker action build context"));
}
```

- [ ] **Step 8: Run focused unit and Docker integration suites**

Run:

```bash
cargo test docker::build_context_test
cargo test docker::build_cache_test
cargo test job::action::docker_test
cargo test --test dockerfile_actions_test -- --ignored --nocapture
cargo test --test docker_test -- --ignored --nocapture
```

Expected: D-01…D-09 and D-11 tests pass; no test performs a push, login, prune or external deployment.

- [ ] **Step 9: Commit the contract-level tests**

```bash
git add tests/common/mod.rs tests/dockerfile_actions_test.rs src/docker/build_test.rs src/docker/build_cache_test.rs
git commit -m "test: ✅ cover Dockerfile action contracts end to end" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

## Task 7: Add exact Hadolint acceptance, documentation and final evidence

**Files:**
- Modify: `Cargo.toml`
- Modify: `tests/dockerfile_actions_test.rs`
- Create: `docs/dockerfile-actions.md`
- Create: `docs/superpowers/reports/2026-09-16-chimera-dockerfile-actions.md`
- Modify: `README.md:81-96`

**Interfaces:**
- Consumes: `TestEnv::run_with_access_token`, exact remote repository step schema and all automated evidence from Task 6.
- Produces: Cargo feature `acceptance-tests = []` and ignored test `hadolint_pinned_sha_acceptance_on_rootless_engine`.
- Produces: operator documentation and an evidence report that does not authorize production rollout.

- [ ] **Step 1: Declare the opt-in acceptance feature**

Add before `[dependencies]`:

```toml
[features]
default = []
acceptance-tests = []
```

This changes no dependency and keeps the networked exact-pin test out of normal `cargo test -- --ignored` CI.

- [ ] **Step 2: Write the exact-pin Hadolint acceptance test**

Guard only this test with `#[cfg(feature = "acceptance-tests")]` and keep it ignored:

```rust
#[cfg(feature = "acceptance-tests")]
#[tokio::test]
#[ignore]
async fn hadolint_pinned_sha_acceptance_on_rootless_engine() {
    let token = std::env::var("CHIMERA_GITHUB_TOKEN")
        .expect("CHIMERA_GITHUB_TOKEN is required for exact-pin acceptance");
    let docker = chimera::docker::client::connect(None).unwrap();
    let info = docker.info().await.unwrap();
    let security = info.security_options.unwrap_or_default().join(" ").to_lowercase();
    assert!(security.contains("rootless"), "acceptance requires a rootless Docker daemon");

    let env = TestEnv::setup().await;
    let infra = env.workspace.workspace_dir().join("infra");
    std::fs::create_dir_all(&infra).unwrap();
    let hadolint = serde_json::json!({
        "id": "hadolint",
        "displayName": "Run pinned Hadolint",
        "reference": {
            "name": "hadolint/hadolint-action",
            "type": "repository",
            "ref": "2332a7b74a6de0dda2e2221d575162eba76ba5e5",
            "path": null
        },
        "inputs": { "dockerfile": "infra/Dockerfile" },
        "condition": null,
        "timeoutInMinutes": 10,
        "continueOnError": false,
        "order": 1,
        "environment": null,
        "contextName": "hadolint"
    });
    let manifest = manifest_with_steps(vec![hadolint.clone()], &env.mock_server.uri());

    std::fs::write(infra.join("Dockerfile"), "FROM alpine:3.19\nRUN true\n").unwrap();
    let (good, _) = env.run_with_access_token(&manifest, &token).await.unwrap();
    assert_eq!(good, JobConclusion::Succeeded);

    std::fs::write(infra.join("Dockerfile"), "FROM ubuntu\nRUN true\n").unwrap();
    let bad_manifest = manifest_with_steps(vec![hadolint], &env.mock_server.uri());
    let (bad, _) = env
        .run_with_access_token(&bad_manifest, &token)
        .await
        .unwrap();
    assert_eq!(bad, JobConclusion::Failed);
}
```

The action metadata and Dockerfile come unchanged from the pinned repository; only the controlled `infra/Dockerfile` under test changes between valid and invalid cases.

- [ ] **Step 3: Run compile-only acceptance coverage before requesting external execution**

Run:

```bash
cargo test --features acceptance-tests --test dockerfile_actions_test --no-run
```

Expected: the exact-pin test compiles without contacting GitHub or Docker.

Before running the next command, obtain explicit approval for network access and the controlled rootless stand. Then run:

```bash
CHIMERA_GITHUB_TOKEN="$CHIMERA_GITHUB_TOKEN" cargo test --features acceptance-tests --test dockerfile_actions_test hadolint_pinned_sha_acceptance_on_rootless_engine -- --ignored --exact --nocapture
```

Expected when authorized: valid Dockerfile succeeds, invalid untagged `FROM ubuntu` produces a failed step. This command does not push an image or deploy anything.

- [ ] **Step 4: Document behavior and explicit limits**

Create `docs/dockerfile-actions.md` with these concrete sections:

```markdown
# Dockerfile-based actions

Chimera supports repository and local actions whose metadata declares
`runs.using: docker` and `runs.image: Dockerfile` or a relative path ending in
`Dockerfile`. The action directory is the build context; a Dockerfile in a
subdirectory does not change the context root.

## Safety and credentials

Dockerfile paths must remain inside the canonical action directory. Context
packing rejects path traversal, symlinks escaping that directory and special
files. `.dockerignore` is applied before bytes are sent to Docker, and a
`<Dockerfile>.dockerignore` next to the selected Dockerfile takes precedence.
Registry credentials are accepted only from the explicit per-job integration
owned by CHM-03; Chimera never falls back to a daemon-wide Docker config. Until
CHM-03 supplies that resource, Dockerfile actions support only public base images.

## Cache and cancellation

The daemon keeps an in-memory, runner/repository/daemon-scoped cache keyed by
the exact filtered context and fixed build options. Identical concurrent
requests share one build. Cache state is lost on restart, missing images are
rebuilt, and successful internal images remain in Docker. The current resolver
does not expose a separate resolved commit; the filtered context bytes, not a
mutable requested ref, are authoritative for reuse.

Build preparation, lock waiting, Engine streaming and action execution share
the step deadline. Cancellation closes the Engine request and prevents action
container startup. Support is gated by the real-Engine cancellation test for
the deployed Docker version.

## Limits

Only `linux/amd64` is supported. Build args, secrets, SSH forwarding,
multi-platform output, cross-daemon cache sharing, retention and automatic
Docker pruning are not implemented. Mutable base-image refresh is governed by
Docker's local layer cache and is not a reproducibility guarantee. Passing the
automated suite does not authorize production rollout or fix unrelated
upstream masking/post-step limitations.
```

Link this document from README's supported Docker action bullet.

- [ ] **Step 5: Write the D-01…D-11 evidence report**

Create the report with the exact test/command mapping below after automated commands pass:

```markdown
# CHM-02 acceptance report — 2026-09-16

This report covers Dockerfile-based action execution only. It does not approve
production rollout, GHCR push, deploy, webhook or poll stages.

## Engine cancellation gate

`cargo test docker::build_test::cancelling_build_stops_engine_work_and_never_publishes_image -- --ignored --exact --nocapture`
passed and printed the target Docker Engine/API metadata as `D-06 Docker Engine` in
the retained command transcript.

| ID | Evidence | Result |
|---|---|---|
| D-01 | `dockerfile_action_builds_and_propagates_exit_code` | PASS |
| D-02 | `subdirectory_dockerfile_uses_action_root_as_context` | PASS |
| D-03 | build-context unit suite plus Docker ignore/symlink integration cases | PASS |
| D-04 | `changed_context_rebuilds_while_unchanged_context_hits_cache` | PASS |
| D-05 | cache unit concurrency plus `concurrent_same_context_builds_once` | PASS |
| D-06 | cache cancel/timeout tests, build failure marker test, `cancelling_build_stops_engine_work_and_never_publishes_image` | PASS |
| D-07 | `missing_cached_image_is_rebuilt` and daemon-ID key isolation | PASS |
| D-08 | `dockerfile_action_reuses_image_for_pre_main_post` | PASS |
| D-09 | existing inline Docker suite plus pre-built metadata regression | PASS |
| D-10 | NOT RUN — requires separately approved exact-pin rootless acceptance command | NOT RUN |
| D-11 | filtered-context and masked-log synthetic canary tests | PASS |

## Open rollout gates

- CHM-03 must provide explicit per-job registry auth before private base images.
- A retention policy is required before mass rollout; global Docker prune is forbidden.
- Upstream masking and broader post/cancellation semantics remain separate gates.
```

If the authorized D-10 command was actually run and passed, replace only its evidence/result cells with the exact command and `PASS`. If it was not run, retain `NOT RUN`; never infer D-10 from synthetic tests.

- [ ] **Step 6: Run the complete repository verification suite**

Run in this order:

```bash
cargo fmt --check
cargo build
cargo clippy -- -D warnings
cargo test
cargo test -- --ignored
```

Expected: every command exits zero. The ignored suite must include the real Docker cancellation proof from Task 4. If any command fails, fix it and rerun the entire sequence before updating the report or committing.

- [ ] **Step 7: Review repository state and documentation diff**

Run:

```bash
git diff --check
git status --short
git diff -- README.md docs/dockerfile-actions.md docs/superpowers/reports/2026-09-16-chimera-dockerfile-actions.md
```

Expected: no whitespace errors; only planned source, tests and documentation are changed; the report does not claim an unrun D-10 or production readiness.

- [ ] **Step 8: Commit acceptance documentation**

```bash
git add Cargo.toml tests/dockerfile_actions_test.rs README.md docs/dockerfile-actions.md docs/superpowers/reports/2026-09-16-chimera-dockerfile-actions.md
git commit -m "docs: 📝 record Dockerfile action acceptance" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```
