# Изолированный DOCKER_CONFIG на каждый job — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> При выборе Subagent-Driven запускать `Agent` без параметра изоляции, как разрешено в `.claude/settings.local.json`; не создавать для субагентов отдельные worktree/remote environments.

**Goal:** Каждый job получает новый приватный Docker config directory, использует его во всех host pre/main/post шагах и удаляет его после post-фазы до публикации окончательного результата job.

**Architecture:** Новый модуль `job::docker_config` владеет двумя capability-объектами: один раз подготовленным `JobResourceRoot` и per-job `JobDockerConfig`. Daemon атомарно захватывает существующий PID/lifecycle lock, проверяет пустой `<chimera-root>/job-resources` до создания broker sessions и передаёт root каждому `Runner`; runner создаёт lease с UUID, явно проводит его через execution context, а затем выполняет проверяемый cleanup до `complete_job`. Host subprocesses получают runner-owned `DOCKER_CONFIG`, несовпадающие workflow overrides отклоняются перед spawn, а Docker action containers и job containers этот host-путь не получают.

**Tech Stack:** Rust 2024, `tokio`, `anyhow`, `thiserror`, `uuid`, `libc`, `bollard`, `wiremock`, `tempfile`, Docker CLI/Buildx в ignored integration suite; новые crates не требуются.

**Spec:** `docs/superpowers/specs/2026-09-16-chimera-job-docker-config.md`

## Global Constraints

- Scope — **per-job attempt**, не per-runner: последовательный retry или следующий job всегда получает новый UUID directory и пустой `config.json`.
- Layout — `<chimera-root>/job-resources/<generated-attempt-id>/docker/config.json`; UUID нельзя заменять repo/runner/user-controlled именем.
- Режимы при создании — directories `0700`, initial `config.json` `0600`, initial bytes ровно `{}`; результат не зависит от daemon umask.
- Нельзя копировать daemon `DOCKER_CONFIG`, `$HOME/.docker/config.json`, `auths`, `credsStore`, `credHelpers`, contexts или CLI plugins.
- Нельзя менять process-global environment через `set_var`; host spawn переопределяет только `DOCKER_CONFIG`, не очищая inherited `DOCKER_HOST`, `XDG_RUNTIME_DIR` и `PATH`.
- Несовпадающий `DOCKER_CONFIG` из manifest/job variables, step env, legacy `::set-env::` или `$GITHUB_ENV` даёт безопасную ошибку до следующего affected spawn; совпадающее значение допустимо.
- Host config не монтируется и не передаётся Docker actions/job containers; поддержка job containers и remap пути внутри Docker actions остаётся вне scope.
- `JobDockerConfig` остаётся жив до завершения всех pre/main/post; cleanup идёт после post и до `complete_job`.
- Cleanup идемпотентен, удаляет только UUID subtree текущего job, не следует symlink и не касается соседей; ошибка cleanup не замалчивается и понижает только `Succeeded` до `Failed`.
- Daemon после захвата единственного lifecycle/PID lock отказывается стартовать с категорией `stale-job-resources`, если root не пуст; автоматического удаления stale directories нет.
- Не логировать `config.json`, auth, password stdin, полное environment или credential-bearing headers; допустимы lifecycle category и локальный UUID.
- C-03/C-10 используют только локальный authenticated registry и синтетические credentials; GHCR push, deploy и production secrets запрещены.
- Для C-10 сохранить pins: `docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5`, `docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee`, `docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf`.
- CHM-02 ещё не реализован в этой базе; execution interface обязан передать `&JobDockerConfig` будущему Engine build adapter явно, а не заставлять его читать process env.
- Новые dependencies не добавлять; если во время реализации стандартной библиотеки и уже имеющихся crates окажется недостаточно, остановиться и отдельно запросить разрешение пользователя.

---

## Scope Check

Спецификация затрагивает filesystem ownership, daemon startup, job execution и Docker acceptance, но эти части не являются независимыми deliverables: environment без lease небезопасен, lease без startup recovery оставляет daemon в неопределённом состоянии, а cleanup должен участвовать в публикации job result. Поэтому используется один план с reviewer-sized задачами и общей acceptance matrix, а не несколько несогласованных планов.

## File Map

### Новые файлы

- `src/job/docker_config.rs` — `JobResourceRoot`, `JobDockerConfig`, typed errors, приватное создание, reserved-env validation и безопасный cleanup.
- `src/job/docker_config_test.rs` — unit tests layout/modes/umask/collision/symlink/cleanup/host-config isolation.
- `tests/job_docker_config_test.rs` — execution-engine tests C-01, C-02, C-04, C-05, C-09 и C-11 без Docker socket.
- `tests/job_docker_config_docker_test.rs` — `#[ignore]` acceptance tests authenticated registry, real Docker CLI atomic rewrite, Docker action boundary и pinned Buildx flow.
- `tests/common/docker_registry.rs` — lifecycle локального authenticated registry и синтетического seed image.
- `tests/common/pinned_action.rs` — загрузка публичных action tarballs по точному SHA в существующий `ActionCache` layout без production token.
- `docs/job-docker-config.md` — runtime contract, ограничения и ручная stale-resource recovery procedure.
- `docs/superpowers/reports/2026-09-16-chimera-job-docker-config.md` — traceability C-01…C-11 к тестам/документации.

### Изменяемые файлы

- `src/job.rs` — экспорт `docker_config`.
- `src/config.rs`, `src/config_test.rs` — `ChimeraPaths::job_resources_dir()`.
- `src/daemon.rs`, `src/daemon_test.rs` — атомарный PID/lifecycle lock, stale gate до sessions, передача `JobResourceRoot` runners.
- `src/runner/instance.rs`, `src/runner/instance_test.rs` — владение per-job lease, cleanup/result ordering и безопасная диагностика.
- `src/runner/env.rs`, `src/runner/env_test.rs` — host base env с обязательным job config и container base env без него.
- `src/job/execute.rs`, `src/job/execute_test.rs` — `JobExecutionContext`, checked env overlays и гарантированный host spawn.
- `src/job/action/node.rs`, `src/job/action/node_test.rs` — execution context для host/container Node actions.
- `src/job/action/composite.rs`, `src/job/action/composite_test.rs` — тот же context для nested host/container steps.
- `src/job/action/docker.rs`, `src/job/action/docker_test.rs` — явный config для будущего CHM-02 adapter, но удаление host `DOCKER_CONFIG` из action container env.
- `tests/common/mod.rs` — reusable job-config lifecycle, cancellation hook и новые Docker helpers.
- `README.md` — operator-facing layout, reserved variable и isolation limits.

`Cargo.toml`, `Cargo.lock` и пользовательские workflow не меняются.

---

### Task 1: Реализовать безопасный filesystem resource

**Files:**
- Create: `src/job/docker_config.rs`
- Create: `src/job/docker_config_test.rs`
- Modify: `src/job.rs:1-10`

**Interfaces:**
- Consumes: существующие `uuid::Uuid`, `thiserror`, `libc`; `<chimera-root>/job-resources` уже передаётся как `Path`.
- Produces:
  - `pub const DOCKER_CONFIG_ENV: &str = "DOCKER_CONFIG"`.
  - `JobResourceRoot::prepare(path: &Path) -> Result<JobResourceRoot, JobDockerConfigError>`.
  - `JobResourceRoot::create_docker_config(&self) -> Result<JobDockerConfig, JobDockerConfigError>`.
  - `JobDockerConfig::{directory, config_file, attempt_id, insert_into_host_env, validate_override, cleanup}`.
  - `JobResourceRoot: Clone`; `JobDockerConfig` намеренно не `Clone` и не делает silent cleanup в `Drop`.

- [ ] **Step 1: Экспортировать модуль и написать failing tests базового контракта**

В `src/job.rs` добавить `pub mod docker_config;`. Создать `src/job/docker_config_test.rs` с helper и первыми тестами:

```rust
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;

use tempfile::TempDir;
use uuid::Uuid;

use super::*;

fn mode(path: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn prepared_root() -> (TempDir, JobResourceRoot) {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("job-resources");
    let root = JobResourceRoot::prepare(&path).unwrap();
    (temp, root)
}

#[test]
fn creates_private_empty_config() {
    let (_temp, root) = prepared_root();

    let config = root.create_docker_config().unwrap();

    assert_eq!(mode(root.path()), 0o700);
    assert_eq!(mode(config.attempt_dir()), 0o700);
    assert_eq!(mode(config.directory()), 0o700);
    assert_eq!(mode(config.config_file()), 0o600);
    assert_eq!(std::fs::read(config.config_file()).unwrap(), b"{}");
    assert_eq!(config.attempt_dir().parent(), Some(root.path()));
}

#[test]
fn concurrent_configs_have_distinct_generated_ids() {
    let (_temp, root) = prepared_root();
    let first_root = root.clone();
    let second_root = root.clone();

    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(move || first_root.create_docker_config().unwrap());
        let second = scope.spawn(move || second_root.create_docker_config().unwrap());
        (first.join().unwrap(), second.join().unwrap())
    });

    assert_ne!(first.attempt_id(), second.attempt_id());
    assert_ne!(first.directory(), second.directory());
}

#[test]
fn new_attempt_is_empty_after_previous_cleanup() {
    let (_temp, root) = prepared_root();
    let mut first = root.create_docker_config().unwrap();
    let first_path = first.directory().to_path_buf();
    std::fs::write(first.config_file(), r#"{"auths":{"registry.test":{"auth":"synthetic"}}}"#)
        .unwrap();
    first.cleanup().unwrap();

    let second = root.create_docker_config().unwrap();

    assert_ne!(first_path, second.directory());
    assert_eq!(std::fs::read(second.config_file()).unwrap(), b"{}");
}

#[test]
fn inserts_and_validates_reserved_host_environment() {
    let (_temp, root) = prepared_root();
    let config = root.create_docker_config().unwrap();
    let mut env = HashMap::new();

    config.insert_into_host_env(&mut env, "job environment").unwrap();
    config
        .validate_override(env.get(DOCKER_CONFIG_ENV).unwrap(), "step environment")
        .unwrap();

    let error = config
        .validate_override("/shared/.docker", "step environment")
        .unwrap_err();
    assert!(matches!(
        error,
        JobDockerConfigError::ReservedEnvironmentOverride {
            source: "step environment"
        }
    ));
    assert!(!error.to_string().contains("synthetic"));
}
```

На этом RED-шаге `src/job/docker_config.rs` содержит только imports и test-module wiring `#[cfg(test)] #[path = "docker_config_test.rs"] mod docker_config_test;`; production types ещё отсутствуют, поэтому compile failure является ожидаемым доказательством RED.

- [ ] **Step 2: Запустить первые unit tests и подтвердить RED**

Run:

```bash
cargo test job::docker_config::docker_config_test::creates_private_empty_config -- --exact
```

Expected: compile FAIL с отсутствующими `JobResourceRoot`/`JobDockerConfig`; тест не должен пройти из-за чтения daemon `$HOME/.docker`.

- [ ] **Step 3: Реализовать creation contract и typed errors**

`src/job/docker_config.rs` должен содержать следующий публичный контракт и использовать только single-component UUID names:

```rust
use std::collections::HashMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;
use uuid::Uuid;

pub const DOCKER_CONFIG_ENV: &str = "DOCKER_CONFIG";

#[derive(Debug, Error)]
pub enum JobDockerConfigError {
    #[error("stale-job-resources: resource root is not empty: {path}")]
    StaleJobResources { path: PathBuf },
    #[error("unsafe-job-resource-root: {reason}: {path}")]
    UnsafeRoot {
        path: PathBuf,
        reason: &'static str,
    },
    #[error("job-resource-collision: generated attempt id already exists: {attempt_id}")]
    AttemptCollision { attempt_id: Uuid },
    #[error("unsafe-job-resource-path: refusing symlink or special file: {path}")]
    UnsafeEntry { path: PathBuf },
    #[error("reserved-environment-variable: DOCKER_CONFIG cannot be changed by {source}")]
    ReservedEnvironmentOverride { source: &'static str },
    #[error("job-docker-config-io: {operation} failed for {path}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("job-resource-cleanup: cleanup failed for {path}")]
    Cleanup {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "job-resource-rollback: creation failed for {path}: {create}; rollback failed: {cleanup}"
    )]
    CreationRollback {
        path: PathBuf,
        create: Box<JobDockerConfigError>,
        cleanup: io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct JobResourceRoot {
    canonical_path: PathBuf,
}

#[derive(Debug)]
pub struct JobDockerConfig {
    root: PathBuf,
    attempt_id: Uuid,
    attempt_dir: PathBuf,
    config_dir: PathBuf,
    config_file: PathBuf,
    cleaned: bool,
}
```

Реализация creation path:

```rust
impl JobResourceRoot {
    pub fn prepare(path: &Path) -> Result<Self, JobDockerConfigError> {
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_dir(path, "creating job resource root")?;
            }
            Err(source) => return Err(io_error("reading job resource root", path, source)),
        }

        validate_private_directory(path)?;
        let canonical_path = fs::canonicalize(path)
            .map_err(|source| io_error("canonicalizing job resource root", path, source))?;
        let mut entries = fs::read_dir(&canonical_path)
            .map_err(|source| io_error("reading job resource root", &canonical_path, source))?;
        if entries
            .next()
            .transpose()
            .map_err(|source| io_error("reading job resource entry", &canonical_path, source))?
            .is_some()
        {
            return Err(JobDockerConfigError::StaleJobResources {
                path: canonical_path,
            });
        }

        Ok(Self { canonical_path })
    }

    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub fn create_docker_config(&self) -> Result<JobDockerConfig, JobDockerConfigError> {
        self.create_with_id(Uuid::new_v4())
    }

    fn create_with_id(
        &self,
        attempt_id: Uuid,
    ) -> Result<JobDockerConfig, JobDockerConfigError> {
        validate_private_directory(&self.canonical_path)?;
        let attempt_dir = self.canonical_path.join(attempt_id.simple().to_string());
        match create_private_dir(&attempt_dir, "creating job attempt directory") {
            Ok(()) => {}
            Err(JobDockerConfigError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                return Err(JobDockerConfigError::AttemptCollision { attempt_id });
            }
            Err(error) => return Err(error),
        }

        let config_dir = attempt_dir.join("docker");
        let config_file = config_dir.join("config.json");
        let creation = (|| {
            create_private_dir(&config_dir, "creating Docker config directory")?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&config_file)
                .map_err(|source| io_error("creating Docker config", &config_file, source))?;
            file.write_all(b"{}")
                .map_err(|source| io_error("writing Docker config", &config_file, source))?;
            file.sync_all()
                .map_err(|source| io_error("syncing Docker config", &config_file, source))?;
            fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600))
                .map_err(|source| io_error("setting Docker config permissions", &config_file, source))?;
            Ok(())
        })();

        if let Err(create) = creation {
            return match fs::remove_dir_all(&attempt_dir) {
                Ok(()) => Err(create),
                Err(cleanup) => Err(JobDockerConfigError::CreationRollback {
                    path: attempt_dir,
                    create: Box::new(create),
                    cleanup,
                }),
            };
        }

        Ok(JobDockerConfig {
            root: self.canonical_path.clone(),
            attempt_id,
            attempt_dir,
            config_dir,
            config_file,
            cleaned: false,
        })
    }
}

impl JobDockerConfig {
    pub fn directory(&self) -> &Path {
        &self.config_dir
    }

    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    pub fn attempt_dir(&self) -> &Path {
        &self.attempt_dir
    }

    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }

    pub fn validate_override(
        &self,
        value: &str,
        source: &'static str,
    ) -> Result<(), JobDockerConfigError> {
        if value == self.directory().to_string_lossy() {
            return Ok(());
        }
        Err(JobDockerConfigError::ReservedEnvironmentOverride { source })
    }

    pub fn insert_into_host_env(
        &self,
        env: &mut HashMap<String, String>,
        source: &'static str,
    ) -> Result<(), JobDockerConfigError> {
        if let Some(existing) = env.get(DOCKER_CONFIG_ENV) {
            self.validate_override(existing, source)?;
        }
        env.insert(
            DOCKER_CONFIG_ENV.to_string(),
            self.directory().to_string_lossy().into_owned(),
        );
        Ok(())
    }
}
```

Private helpers must request restrictive modes at `mkdir/open` time and then restore exact modes if umask removed owner bits:

```rust
fn create_private_dir(
    path: &Path,
    operation: &'static str,
) -> Result<(), JobDockerConfigError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|source| io_error(operation, path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("setting private directory permissions", path, source))
}

fn validate_private_directory(path: &Path) -> Result<(), JobDockerConfigError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading directory metadata", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(JobDockerConfigError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "path is not a real directory",
        });
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(JobDockerConfigError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "directory is owned by another uid",
        });
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(JobDockerConfigError::UnsafeRoot {
            path: path.to_path_buf(),
            reason: "directory mode is not 0700",
        });
    }
    Ok(())
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> JobDockerConfigError {
    JobDockerConfigError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
```

Не читать ни один существующий Docker config в этом модуле.

- [ ] **Step 4: Добавить failing tests cleanup, collision, symlink, host config и umask**

Добавить в `src/job/docker_config_test.rs`:

```rust
#[test]
fn cleanup_is_idempotent_and_keeps_neighbor() {
    let (_temp, root) = prepared_root();
    let mut owned = root.create_docker_config().unwrap();
    let neighbor = root.create_docker_config().unwrap();
    let owned_dir = owned.attempt_dir().to_path_buf();
    let neighbor_dir = neighbor.attempt_dir().to_path_buf();

    owned.cleanup().unwrap();
    owned.cleanup().unwrap();

    assert!(!owned_dir.exists());
    assert!(neighbor_dir.exists());
}

#[test]
fn cleanup_refuses_config_symlink_without_touching_target() {
    let (_temp, root) = prepared_root();
    let mut config = root.create_docker_config().unwrap();
    let outside = root.path().parent().unwrap().join("outside-config.json");
    std::fs::write(&outside, "synthetic-outside").unwrap();
    std::fs::remove_file(config.config_file()).unwrap();
    std::os::unix::fs::symlink(&outside, config.config_file()).unwrap();

    let error = config.cleanup().unwrap_err();

    assert!(matches!(error, JobDockerConfigError::UnsafeEntry { .. }));
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "synthetic-outside");
    assert!(config.attempt_dir().exists());
}

#[test]
fn generated_id_collision_is_rejected() {
    let (_temp, root) = prepared_root();
    let id = Uuid::nil();
    let first = root.create_with_id(id).unwrap();

    let error = root.create_with_id(id).unwrap_err();

    assert!(matches!(
        error,
        JobDockerConfigError::AttemptCollision { attempt_id } if attempt_id == id
    ));
    assert!(first.config_file().exists());
}

#[test]
fn daemon_docker_config_is_not_copied_or_modified() {
    let temp = TempDir::new().unwrap();
    let daemon_dir = temp.path().join("daemon-docker");
    std::fs::create_dir_all(&daemon_dir).unwrap();
    let daemon_file = daemon_dir.join("config.json");
    let marker = r#"{"auths":{"registry.test":{"auth":"synthetic-host"}},"currentContext":"host"}"#;
    std::fs::write(&daemon_file, marker).unwrap();

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "job::docker_config::docker_config_test::daemon_docker_config_child",
            "--nocapture",
        ])
        .env(DOCKER_CONFIG_ENV, &daemon_dir)
        .env("CHIMERA_DAEMON_CONFIG_CHILD", temp.path())
        .status()
        .unwrap();

    assert!(status.success());
    assert_eq!(std::fs::read_to_string(daemon_file).unwrap(), marker);
}

#[test]
fn daemon_docker_config_child() {
    let Some(parent) = std::env::var_os("CHIMERA_DAEMON_CONFIG_CHILD") else {
        return;
    };
    let parent = std::path::PathBuf::from(parent);
    let inherited = std::env::var_os(DOCKER_CONFIG_ENV).unwrap();
    assert_eq!(std::path::PathBuf::from(inherited), parent.join("daemon-docker"));

    let root = JobResourceRoot::prepare(&parent.join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();

    assert_eq!(std::fs::read(config.config_file()).unwrap(), b"{}");
    assert_ne!(config.directory(), parent.join("daemon-docker"));
}

#[test]
fn umask_zero_still_creates_private_paths() {
    let temp = TempDir::new().unwrap();
    let child_test = "job::docker_config::docker_config_test::umask_zero_child";
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", child_test, "--nocapture"])
        .env("CHIMERA_UMASK_ZERO_CHILD", temp.path())
        .status()
        .unwrap();

    assert!(status.success());
    assert_eq!(mode(&temp.path().join("job-resources")), 0o700);
    let attempt = std::fs::read_dir(temp.path().join("job-resources"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(mode(&attempt), 0o700);
    assert_eq!(mode(&attempt.join("docker")), 0o700);
    assert_eq!(mode(&attempt.join("docker/config.json")), 0o600);
}

#[test]
fn umask_zero_child() {
    let Some(root_parent) = std::env::var_os("CHIMERA_UMASK_ZERO_CHILD") else {
        return;
    };
    unsafe {
        libc::umask(0);
    }
    let root = JobResourceRoot::prepare(&std::path::PathBuf::from(root_parent).join("job-resources"))
        .unwrap();
    root.create_docker_config().unwrap();
}
```

В тот же файл добавить три детерминированных regression tests (проверка mode выполняется и под root, поэтому test не полагается на `EACCES`):

```rust
#[test]
fn read_only_root_fails_without_fallback() {
    let (_temp, root) = prepared_root();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

    let result = root.create_docker_config();

    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(result, Err(JobDockerConfigError::UnsafeRoot { .. })));
    assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
}

#[test]
fn prepare_rejects_symlink_root() {
    let temp = TempDir::new().unwrap();
    let target = temp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = temp.path().join("job-resources");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let result = JobResourceRoot::prepare(&link);

    assert!(matches!(result, Err(JobDockerConfigError::UnsafeRoot { .. })));
}

#[test]
fn cleanup_refuses_special_file() {
    let (_temp, root) = prepared_root();
    let mut config = root.create_docker_config().unwrap();
    let socket_path = config.attempt_dir().join("unexpected.sock");
    let socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

    let result = config.cleanup();

    assert!(matches!(result, Err(JobDockerConfigError::UnsafeEntry { .. })));
    assert!(config.attempt_dir().exists());
    drop(socket);
    std::fs::remove_file(socket_path).unwrap();
    config.cleanup().unwrap();
}
```

После read-only test mode всегда возвращается в `0700`, чтобы `TempDir` мог очиститься.

- [ ] **Step 5: Запустить новые security tests и подтвердить RED cleanup**

Run:

```bash
cargo test job::docker_config::docker_config_test -- --nocapture
```

Expected: creation tests PASS, cleanup/security tests FAIL из-за отсутствующего `cleanup` и tree validation.

- [ ] **Step 6: Реализовать idempotent no-symlink cleanup**

Добавить рекурсивную проверку, которая использует `symlink_metadata`, разрешает только regular files/directories и вызывается до `remove_dir_all`. Перед удалением повторно canonicalize root и attempt, потребовать `attempt.parent() == root` и `canonical_attempt.starts_with(canonical_root)`. Root приватен от других UID; same-UID adversary и race после проверки явно остаются вне security boundary согласно spec.

```rust
impl JobDockerConfig {
    pub fn cleanup(&mut self) -> Result<(), JobDockerConfigError> {
        if self.cleaned {
            return Ok(());
        }

        match fs::symlink_metadata(&self.attempt_dir) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.cleaned = true;
                return Ok(());
            }
            Err(source) => {
                return Err(JobDockerConfigError::Cleanup {
                    path: self.attempt_dir.clone(),
                    source,
                });
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(JobDockerConfigError::UnsafeEntry {
                    path: self.attempt_dir.clone(),
                });
            }
            Ok(_) => {}
        }

        let canonical_root = fs::canonicalize(&self.root).map_err(|source| {
            JobDockerConfigError::Cleanup {
                path: self.root.clone(),
                source,
            }
        })?;
        let canonical_attempt = fs::canonicalize(&self.attempt_dir).map_err(|source| {
            JobDockerConfigError::Cleanup {
                path: self.attempt_dir.clone(),
                source,
            }
        })?;
        if self.attempt_dir.parent() != Some(self.root.as_path())
            || canonical_attempt.parent() != Some(canonical_root.as_path())
        {
            return Err(JobDockerConfigError::UnsafeEntry {
                path: self.attempt_dir.clone(),
            });
        }

        validate_removal_tree(&canonical_attempt)?;
        fs::remove_dir_all(&canonical_attempt).map_err(|source| {
            JobDockerConfigError::Cleanup {
                path: canonical_attempt.clone(),
                source,
            }
        })?;
        self.cleaned = true;
        Ok(())
    }
}

fn validate_removal_tree(path: &Path) -> Result<(), JobDockerConfigError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reading cleanup metadata", path, source))?;
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(JobDockerConfigError::UnsafeEntry {
            path: path.to_path_buf(),
        });
    }
    if metadata.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|source| io_error("reading cleanup directory", path, source))?;
        for entry in entries {
            let entry = entry
                .map_err(|source| io_error("reading cleanup entry", path, source))?;
            validate_removal_tree(&entry.path())?;
        }
    }
    Ok(())
}
```

Не реализовывать `Drop` с `let _ = cleanup()`: lifecycle caller обязан увидеть ошибку.

- [ ] **Step 7: Запустить module tests и полный library test subset**

Run:

```bash
cargo test job::docker_config::docker_config_test -- --nocapture
cargo test --lib
```

Expected: PASS; parallel creation имеет разные UUID, symlink target и соседний attempt остаются нетронутыми.

- [ ] **Step 8: Commit filesystem resource**

```bash
git add src/job.rs src/job/docker_config.rs src/job/docker_config_test.rs
git commit -m "feat: add private per-job Docker config resource"
```

---

### Task 2: Захватить daemon root и отказать старт при stale resources

**Files:**
- Modify: `src/config.rs:96-161`
- Modify: `src/config_test.rs:101-129`
- Modify: `src/daemon.rs:17-55,202-275`
- Modify: `src/daemon_test.rs:8-81`
- Modify: `src/runner/instance.rs:29-52`
- Modify: `src/runner/instance_test.rs:39-73`
- Modify: `src/job/docker_config_test.rs`

**Interfaces:**
- Consumes: `JobResourceRoot::prepare` из Task 1.
- Produces:
  - `ChimeraPaths::job_resources_dir(&self) -> PathBuf`.
  - Атомарный `PidLock::acquire` на том же `chimera.pid`; отдельный второй lock не создаётся.
  - `Runner::with_state(name: String, credentials: RunnerCredentials, paths: ChimeraPaths, state: Arc<DaemonState>, job_resources: JobResourceRoot, cache_port: u16) -> Runner` и поле `job_resources`.
  - Startup ordering: PID lock → `JobResourceRoot::prepare` → cache server → credentials/broker sessions.

- [ ] **Step 1: Написать failing path/startup/lock tests**

Добавить к `path_construction`:

```rust
assert_eq!(
    paths.job_resources_dir(),
    PathBuf::from("/home/user/.chimera/job-resources")
);
```

Добавить в `src/daemon_test.rs`:

```rust
#[test]
fn second_lock_cannot_replace_live_lock() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("chimera.pid");
    let first = PidLock::acquire(&path).unwrap();

    let second = PidLock::acquire(&path).unwrap_err();

    assert!(second.to_string().contains("already running"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), std::process::id().to_string());
    drop(first);
}

#[test]
fn dropping_lock_does_not_remove_replacement_inode() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("chimera.pid");
    let lock = PidLock::acquire(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, "replacement").unwrap();

    drop(lock);

    assert_eq!(std::fs::read_to_string(path).unwrap(), "replacement");
}

#[test]
fn startup_preparation_rejects_stale_job_resources_without_deleting_them() {
    let temp = TempDir::new().unwrap();
    let paths = ChimeraPaths::new(temp.path().to_path_buf());
    std::fs::create_dir_all(&paths.root).unwrap();
    let root = JobResourceRoot::prepare(&paths.job_resources_dir()).unwrap();
    let stale = root.create_docker_config().unwrap();
    let stale_dir = stale.attempt_dir().to_path_buf();

    let error = prepare_daemon_root(&paths).unwrap_err();

    assert!(error.to_string().contains("stale-job-resources"));
    assert!(stale_dir.exists());
}
```

В `src/job/docker_config_test.rs` добавить C-07 test. Он намеренно не пытается определить или убить потомка production-кодом: startup gate должен отказать и оставить resource для контролируемой операторской уборки.

```rust
#[test]
fn stale_root_with_live_child_is_not_removed() {
    let (temp, root) = prepared_root();
    let mut config = root.create_docker_config().unwrap();
    let stale_dir = config.attempt_dir().to_path_buf();
    let mut child = std::process::Command::new("sh")
        .args(["-c", "while :; do sleep 1; done"])
        .current_dir(config.directory())
        .spawn()
        .unwrap();

    let result = JobResourceRoot::prepare(root.path());

    assert!(matches!(
        result,
        Err(JobDockerConfigError::StaleJobResources { .. })
    ));
    assert!(stale_dir.exists());

    child.kill().unwrap();
    child.wait().unwrap();
    config.cleanup().unwrap();
    assert!(!stale_dir.exists());
    JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
}
```

- [ ] **Step 2: Запустить tests и подтвердить RED**

Run:

```bash
cargo test config_test::path_construction -- --exact
cargo test daemon_test::second_lock_cannot_replace_live_lock -- --exact
cargo test daemon_test::startup_preparation_rejects_stale_job_resources_without_deleting_them -- --exact
```

Expected: FAIL из-за отсутствующих path/helper и inode-aware lock behavior.

- [ ] **Step 3: Добавить path и сделать PID lock атомарным**

В `ChimeraPaths`:

```rust
pub fn job_resources_dir(&self) -> PathBuf {
    self.root.join("job-resources")
}
```

`PidLock` должен держать открытый file descriptor и inode/device. `OpenOptionsExt::mode(0o600)` + `create_new(true)` устраняют check-then-write race; stale PID удаляется только после проверки inode, затем acquire повторяется.

```rust
#[derive(Debug)]
pub struct PidLock {
    path: PathBuf,
    device: u64,
    inode: u64,
    _file: std::fs::File,
}

impl PidLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(mut file) => {
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))
                        .with_context(|| format!("setting PID file permissions {}", path.display()))?;
                    write!(file, "{}", std::process::id())
                        .with_context(|| format!("writing PID file {}", path.display()))?;
                    file.sync_all()
                        .with_context(|| format!("syncing PID file {}", path.display()))?;
                    let metadata = file.metadata().context("reading acquired PID lock metadata")?;
                    return Ok(Self {
                        path: path.to_path_buf(),
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        _file: file,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = std::fs::symlink_metadata(path)
                        .with_context(|| format!("reading PID file metadata {}", path.display()))?;
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        bail!("unsafe PID lock path: {}", path.display());
                    }
                    let content = std::fs::read_to_string(path)
                        .with_context(|| format!("reading PID file {}", path.display()))?;
                    let pid: u32 = content.trim().parse()
                        .with_context(|| format!("parsing PID from {}", path.display()))?;
                    if is_process_alive(pid) {
                        bail!("chimera daemon already running (pid {pid}). Use 'chimera status' to check.");
                    }
                    remove_if_same_inode(path, metadata.dev(), metadata.ino())?;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("creating PID file {}", path.display()));
                }
            }
        }
    }
}
```

`remove_if_same_inode` повторно читает `symlink_metadata`, сравнивает `dev()/ino()` и удаляет только совпавший regular file. `Drop` вызывает этот helper и только логирует warning при неожиданной ошибке; он не удаляет replacement inode:

```rust
fn remove_if_same_inode(path: &Path, device: u64, inode: u64) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("reading PID lock metadata {}", path.display())),
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.dev() == device
                && metadata.ino() == inode =>
        {
            std::fs::remove_file(path)
                .with_context(|| format!("removing PID lock {}", path.display()))
        }
        Ok(_) => bail!("PID lock changed while held: {}", path.display()),
    }
}

impl Drop for PidLock {
    fn drop(&mut self) {
        if let Err(error) = remove_if_same_inode(&self.path, self.device, self.inode) {
            tracing::warn!(error = %error, path = %self.path.display(), "failed to release PID lock");
        }
    }
}
```

- [ ] **Step 4: Подготовить resource root до любых sessions**

Добавить private helper:

```rust
fn prepare_daemon_root(paths: &ChimeraPaths) -> Result<(PidLock, JobResourceRoot)> {
    let pid_lock = PidLock::acquire(&paths.pid_file()).context("acquiring PID lock")?;
    let job_resources = JobResourceRoot::prepare(&paths.job_resources_dir())
        .context("preparing job resource root")?;
    Ok((pid_lock, job_resources))
}
```

В первой строке `Daemon::run` заменить старый acquire на:

```rust
let (_pid_lock, job_resources) = prepare_daemon_root(&self.paths)?;
```

Эта строка обязана оставаться до `CacheManager::new`, `cache_server::start`, credential loop и `Runner::start`. Передать `job_resources.clone()` в каждый `Runner::with_state`; добавить поле:

```rust
pub(super) job_resources: JobResourceRoot,
```

Обновить `make_runner` в `instance_test.rs`, чтобы helper создавал `TempDir`, `JobResourceRoot::prepare` и возвращал `(TempDir, Runner)`, сохраняя temp directory живым на протяжении test.

- [ ] **Step 5: Запустить startup tests**

Run:

```bash
cargo test daemon_test
cargo test job::docker_config::docker_config_test
cargo test runner::instance_test
```

Expected: PASS; stale directory не удалён, child liveness не влияет на безопасный отказ, второй daemon не захватывает root.

- [ ] **Step 6: Commit startup ownership**

```bash
git add src/config.rs src/config_test.rs src/daemon.rs src/daemon_test.rs src/runner/instance.rs src/runner/instance_test.rs src/job/docker_config_test.rs
git commit -m "feat: gate daemon startup on clean job resources"
```

---

### Task 3: Провести runner-owned env до каждого host spawn

**Files:**
- Modify: `src/runner/env.rs:6-162`
- Modify: `src/runner/env_test.rs:3-189`
- Modify: `src/job/execute.rs:262-520,536-1327`
- Modify: `src/job/execute_test.rs:10-615`
- Modify: `src/job/action/node.rs:20-152`
- Modify: `src/job/action/node_test.rs`
- Modify: `src/job/action/composite.rs:27-395`
- Modify: `src/job/action/composite_test.rs`
- Modify: `src/job/action/docker.rs:22-341`
- Modify: `src/job/action/docker_test.rs:207-224`
- Modify: `tests/common/mod.rs:20-119`

**Interfaces:**
- Consumes: `JobDockerConfig` из Task 1; `Runner.job_resources` из Task 2.
- Produces:
  - `build_base_env(manifest: &JobManifest, workspace: &Workspace, runner_name: &str, docker_config: &JobDockerConfig) -> anyhow::Result<HashMap<String, String>>` для host mode.
  - `build_container_env(manifest: &JobManifest, workspace: &Workspace, runner_name: &str) -> HashMap<String, String>` без host path.
  - `JobExecutionContext<'a>::new(docker_config: &'a JobDockerConfig, docker_resources: Option<&'a JobDockerResources>, node_runtimes: &'a NodeRuntimes) -> JobExecutionContext<'a>`.
  - `build_step_env(step: &Step, job_state: &JobState, workspace: &Workspace, base_env: &HashMap<String, String>, docker_config: Option<&JobDockerConfig>) -> anyhow::Result<HashMap<String, String>>`.
  - `run_all_steps(manifest: &JobManifest, job_client: &Arc<JobClient>, workspace: &Workspace, base_env: &HashMap<String, String>, runner_name: &str, action_cache: &ActionCache, access_token: &str, cancel_token: CancellationToken, execution: &JobExecutionContext<'_>, feed_sender: Option<&FeedSender>) -> anyhow::Result<(JobConclusion, HashMap<String, String>)>`.
  - Все host `run_process` spawn имеют явный runner-owned `DOCKER_CONFIG`; Docker action container env удаляет ключ.

- [ ] **Step 1: Написать failing env-priority tests**

Добавить в `runner/env_test.rs`:

```rust
#[test]
fn host_env_sets_runner_owned_docker_config() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();
    let (resources, config) = test_docker_config();

    let env = build_base_env(&manifest, &ws, "test-runner", &config).unwrap();

    assert_eq!(env[DOCKER_CONFIG_ENV], config.directory().to_string_lossy());
    drop(resources);
}

#[test]
fn host_env_rejects_manifest_override() {
    let mut manifest = minimal_manifest();
    manifest.variables.insert(
        "DOCKER_CONFIG".into(),
        JobVariable { value: "/shared/.docker".into(), is_secret: true },
    );
    let (_tmp, ws) = test_workspace();
    let (_resources, config) = test_docker_config();

    let error = build_base_env(&manifest, &ws, "test-runner", &config).unwrap_err();

    assert!(error.to_string().contains("reserved-environment-variable"));
}

#[test]
fn container_env_never_contains_host_docker_config() {
    let manifest = minimal_manifest();
    let (_tmp, ws) = test_workspace();

    let env = build_container_env(&manifest, &ws, "test-runner");

    assert!(!env.contains_key(DOCKER_CONFIG_ENV));
}
```

В `runner/env_test.rs` добавить helper, который удерживает parent directory живым и не меняет process-global env:

```rust
fn test_docker_config() -> (TempDir, JobDockerConfig) {
    let temp = TempDir::new().unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
    (temp, config)
}
```

В `execute_test.rs` добавить helper и четыре tests для каждого overlay source:

```rust
fn step_with_environment(key: &str, value: &str) -> Step {
    let mut step = test_step();
    step.environment = Some(HashMap::from([(key.to_string(), value.to_string())]));
    step
}

#[test]
fn step_environment_cannot_override_docker_config() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    let state = test_job_state();
    let step = step_with_environment(DOCKER_CONFIG_ENV, "/shared/.docker");
    let base = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        config.directory().to_string_lossy().into_owned(),
    )]);

    let error = build_step_env(&step, &state, &workspace, &base, Some(&config)).unwrap_err();

    assert!(matches!(
        error.downcast_ref::<JobDockerConfigError>(),
        Some(JobDockerConfigError::ReservedEnvironmentOverride {
            source: "step environment"
        })
    ));
}

#[test]
fn job_environment_cannot_override_docker_config() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    let mut state = test_job_state();
    state.env.insert(DOCKER_CONFIG_ENV.into(), "/shared/.docker".into());
    let base = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        config.directory().to_string_lossy().into_owned(),
    )]);

    let error = build_step_env(&test_step(), &state, &workspace, &base, Some(&config))
        .unwrap_err();

    assert!(matches!(
        error.downcast_ref::<JobDockerConfigError>(),
        Some(JobDockerConfigError::ReservedEnvironmentOverride {
            source: "job environment"
        })
    ));
}

#[test]
fn github_env_cannot_override_docker_config() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    std::fs::write(workspace.env_file(), "DOCKER_CONFIG=/shared/.docker\n").unwrap();
    let base = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        config.directory().to_string_lossy().into_owned(),
    )]);

    let error = build_step_env(
        &test_step(),
        &test_job_state(),
        &workspace,
        &base,
        Some(&config),
    )
    .unwrap_err();

    assert!(matches!(
        error.downcast_ref::<JobDockerConfigError>(),
        Some(JobDockerConfigError::ReservedEnvironmentOverride { source: "GITHUB_ENV" })
    ));
}

#[test]
fn matching_override_is_allowed() {
    let (_temp, workspace) = test_workspace();
    let (_resources, config) = test_docker_config();
    let value = config.directory().to_string_lossy().into_owned();
    let step = step_with_environment(DOCKER_CONFIG_ENV, &value);
    let base = HashMap::from([(DOCKER_CONFIG_ENV.to_string(), value.clone())]);

    let env = build_step_env(
        &step,
        &test_job_state(),
        &workspace,
        &base,
        Some(&config),
    )
    .unwrap();

    assert_eq!(env.get(DOCKER_CONFIG_ENV), Some(&value));
}
```

Определить использованные helpers рядом с `make_step`, используя существующие production constructors:

```rust
fn test_step() -> Step {
    make_step("step", "true")
}

fn test_job_state() -> JobState {
    JobState::new(
        Arc::new(RwLock::new(Vec::new())),
        HashMap::new(),
        serde_json::json!({}),
    )
}

fn test_workspace() -> (tempfile::TempDir, Workspace) {
    let temp = tempfile::tempdir().unwrap();
    let workspace = Workspace::create(
        &temp.path().join("work"),
        &temp.path().join("tmp"),
        &temp.path().join("tool-cache"),
        "test-runner",
        "owner/repo",
    )
    .unwrap();
    (temp, workspace)
}

fn test_docker_config() -> (tempfile::TempDir, JobDockerConfig) {
    let temp = tempfile::tempdir().unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
    (temp, config)
}
```

Импортировать `JobDockerConfig`, `JobDockerConfigError`, `JobResourceRoot` и `DOCKER_CONFIG_ENV` из `crate::job::docker_config`.

- [ ] **Step 2: Запустить env tests и подтвердить RED**

Run:

```bash
cargo test runner::env_test
cargo test job::execute::execute_test::step_environment_cannot_override_docker_config -- --exact
cargo test job::execute::execute_test::github_env_cannot_override_docker_config -- --exact
```

Expected: FAIL из-за старых signatures и unchecked `HashMap::extend`.

- [ ] **Step 3: Разделить common host/container env**

В `runner/env.rs` вынести существующее тело в private `build_common_env`. Host wrapper добавляет ресурс после manifest variables и поэтому обнаруживает job-level conflict; container wrapper common env не получает `DOCKER_CONFIG`.

```rust
pub fn build_base_env(
    manifest: &JobManifest,
    workspace: &Workspace,
    runner_name: &str,
    docker_config: &JobDockerConfig,
) -> anyhow::Result<HashMap<String, String>> {
    for (key, variable) in &manifest.variables {
        let env_key = key.replace('.', "_").to_uppercase();
        if env_key == DOCKER_CONFIG_ENV {
            docker_config.validate_override(&variable.value, "job environment")?;
        }
    }
    let mut env = build_common_env(manifest, workspace, runner_name);
    docker_config.insert_into_host_env(&mut env, "job environment")?;
    Ok(env)
}

pub fn build_container_env(
    manifest: &JobManifest,
    workspace: &Workspace,
    runner_name: &str,
) -> HashMap<String, String> {
    let mut env = build_common_env(manifest, workspace, runner_name);
    env.remove(DOCKER_CONFIG_ENV);
    env.insert("RUNNER_OS".into(), "Linux".into());
    env.insert("ImageOS".into(), "ubuntu22".into());
    env.insert("GITHUB_WORKSPACE".into(), "/github/workspace".into());
    env.insert("GITHUB_ENV".into(), "/github/workflow/_env".into());
    env.insert("GITHUB_PATH".into(), "/github/workflow/_path".into());
    env.insert("GITHUB_OUTPUT".into(), "/github/workflow/_output".into());
    env.insert("GITHUB_STATE".into(), "/github/workflow/_state".into());
    env.insert("GITHUB_STEP_SUMMARY".into(), "/github/workflow/_step_summary".into());
    env.insert("GITHUB_EVENT_PATH".into(), "/github/workflow/_event.json".into());
    env.insert("RUNNER_TEMP".into(), "/github/tmp".into());
    env.insert("RUNNER_TOOL_CACHE".into(), "/github/tool-cache".into());
    env.insert(
        "PATH".into(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
    );
    env
}
```

Сохранить текущее поведение `PATH`: host common env читает daemon `PATH`, остальные inherited vars не перечисляет и не очищает.

- [ ] **Step 4: Добавить explicit `JobExecutionContext`**

В `execute.rs`:

```rust
pub struct JobExecutionContext<'a> {
    docker_config: &'a JobDockerConfig,
    docker_resources: Option<&'a JobDockerResources>,
    node_runtimes: &'a NodeRuntimes,
}

impl<'a> JobExecutionContext<'a> {
    pub fn new(
        docker_config: &'a JobDockerConfig,
        docker_resources: Option<&'a JobDockerResources>,
        node_runtimes: &'a NodeRuntimes,
    ) -> Self {
        Self { docker_config, docker_resources, node_runtimes }
    }

    pub fn docker_config(&self) -> &'a JobDockerConfig {
        self.docker_config
    }

    pub fn docker_resources(&self) -> Option<&'a JobDockerResources> {
        self.docker_resources
    }

    pub fn node_runtimes(&self) -> &'a NodeRuntimes {
        self.node_runtimes
    }

    pub fn host_docker_config(&self) -> Option<&'a JobDockerConfig> {
        self.docker_resources
            .and_then(JobDockerResources::job_container_id)
            .is_none()
            .then_some(self.docker_config)
    }
}
```

Заменить два аргумента `docker_resources`, `node_runtimes` одним `&JobExecutionContext` в `run_all_steps`, `execute_step`, `run_action_step`, Node/composite/Docker action functions и recursive composite calls. Точные изменённые signatures (declaration notation; тела сохраняют существующую логику):

```text
pub async fn run_all_steps(
    manifest: &JobManifest,
    job_client: &Arc<JobClient>,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    runner_name: &str,
    action_cache: &ActionCache,
    access_token: &str,
    cancel_token: CancellationToken,
    execution: &JobExecutionContext<'_>,
    feed_sender: Option<&FeedSender>,
) -> Result<(JobConclusion, HashMap<String, String>)>;

pub async fn run_host_step(
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    cancel_token: &CancellationToken,
    docker_config: &JobDockerConfig,
) -> Result<StepResult>;

async fn execute_step(
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    runner_name: &str,
    action_cache: &ActionCache,
    access_token: &str,
    cancel_token: &CancellationToken,
    execution: &JobExecutionContext<'_>,
) -> (StepConclusion, ResultsConclusion);

async fn run_action_step(
    step: &Step,
    job_state: &mut JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    log_sender: &LogSender,
    action_cache: &ActionCache,
    access_token: &str,
    cancel_token: &CancellationToken,
    execution: &JobExecutionContext<'_>,
) -> Result<StepResult>;
```

В `node.rs`, `composite.rs` и обеих public functions `docker.rs` заменить tail `docker_resources`/`node_runtimes` на `execution: &JobExecutionContext<'_>`; внутри брать `execution.docker_resources()`, `execution.node_runtimes()` и передавать тот же reference в recursive composite calls. `run_docker_metadata_action` получает context даже для pre-built image: CHM-02 сможет читать `execution.docker_config()` без process env. Script branch передаёт `execution.docker_config()` только в `run_host_step`; job-container branch вызывает `build_step_env` с `None`. Node/composite host branches используют `execution.host_docker_config()`, а обе Docker action functions всегда вызывают `build_step_env(step, job_state, workspace, base_env, None)`, после чего container-env builder удаляет унаследованный runner-owned key; Docker action не считается host step для reserved-variable enforcement.

- [ ] **Step 5: Реализовать checked overlays**

Изменить `build_step_env` на `Result`. Не вставлять несовпадающее значение ни на одном этапе:

```rust
pub fn build_step_env(
    step: &Step,
    job_state: &JobState,
    workspace: &Workspace,
    base_env: &HashMap<String, String>,
    docker_config: Option<&JobDockerConfig>,
) -> Result<HashMap<String, String>> {
    let mut env = base_env.clone();
    merge_checked(&mut env, &job_state.env, docker_config, "job environment")?;

    if let Some(step_env) = &step.environment {
        for (key, value) in step_env {
            let context = ExprContext::new(&env, job_state, false, false);
            let resolved = super::expression::resolve_expression(value, &context);
            insert_checked(
                &mut env,
                key.clone(),
                resolved,
                docker_config,
                "step environment",
            )?;
        }
    }

    if let Some(ctx_name) = &step.context_name
        && let Some(base_ctx) = ctx_name
            .strip_suffix("_post")
            .or_else(|| ctx_name.strip_suffix("_pre"))
        && let Some(states) = job_state.action_states.get(base_ctx)
    {
        for (key, value) in states {
            env.insert(format!("STATE_{key}"), value.clone());
        }
    }

    if let Ok(file_env) = workspace.read_env_file() {
        merge_checked(&mut env, &file_env, docker_config, "GITHUB_ENV")?;
    }

    if let Ok(extra_paths) = workspace.read_path_file() {
        let mut all_paths = job_state.path_prepends.clone();
        all_paths.extend(extra_paths);
        if !all_paths.is_empty() {
            let prepend = all_paths.join(":");
            let path = match env.get("PATH") {
                Some(existing) if !existing.is_empty() => format!("{prepend}:{existing}"),
                _ => prepend,
            };
            env.insert("PATH".into(), path);
        }
    }

    Ok(env)
}

fn insert_checked(
    env: &mut HashMap<String, String>,
    key: String,
    value: String,
    docker_config: Option<&JobDockerConfig>,
    source: &'static str,
) -> Result<()> {
    if key == DOCKER_CONFIG_ENV
        && let Some(config) = docker_config
    {
        config.validate_override(&value, source)?;
    }
    env.insert(key, value);
    Ok(())
}

fn merge_checked(
    env: &mut HashMap<String, String>,
    values: &HashMap<String, String>,
    docker_config: Option<&JobDockerConfig>,
    source: &'static str,
) -> Result<()> {
    for (key, value) in values {
        insert_checked(env, key.clone(), value.clone(), docker_config, source)?;
    }
    Ok(())
}
```

Все callers используют `?`; `execute_step` уже преобразует error в failed step и пишет безопасный `Step error`, поэтому affected process не запускается. Совпадающее значение проходит.

- [ ] **Step 6: Гарантировать значение на фактическом host spawn**

Вынести построение `tokio::process::Command`:

```rust
fn host_command(
    program: &str,
    args: &[&OsStr],
    env: &HashMap<String, String>,
    working_dir: &Path,
    docker_config: &JobDockerConfig,
) -> Result<Command> {
    let configured = env
        .get(DOCKER_CONFIG_ENV)
        .context("host step is missing runner-owned DOCKER_CONFIG")?;
    docker_config.validate_override(configured, "host spawn")?;

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(working_dir)
        .env_remove(DOCKER_CONFIG_ENV)
        .envs(env)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    Ok(command)
}
```

Добавить `docker_config: &JobDockerConfig` в signature `run_process` сразу после `working_dir` и во все три host callers (`run_host_step`, host branch `run_node_action`, host nested step в `run_composite_action_inner`). `run_process` заменяет текущий inline builder на:

```rust
let mut child = host_command(program, args, env, working_dir, docker_config)?
    .spawn()
    .with_context(|| format!("spawning {program}"))?;
```

Не использовать `env_clear`: daemon `DOCKER_HOST`, `XDG_RUNTIME_DIR` и прочие прежние inherited values остаются. Добавить unit и child-process regressions:

```rust
#[test]
fn host_command_explicitly_overrides_inherited_docker_config() {
    let temp = tempfile::tempdir().unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
    let env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        config.directory().to_string_lossy().into_owned(),
    )]);

    let command = host_command(
        "/usr/bin/true",
        &[],
        &env,
        temp.path(),
        &config,
    )
    .unwrap();
    let configured = command
        .as_std()
        .get_envs()
        .find(|(key, _)| *key == DOCKER_CONFIG_ENV)
        .and_then(|(_, value)| value)
        .unwrap();

    assert_eq!(configured, std::ffi::OsStr::new(&env[DOCKER_CONFIG_ENV]));
}

#[test]
fn host_command_preserves_original_socket_runtime_and_path() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "job::execute::execute_test::host_command_inheritance_child",
            "--nocapture",
        ])
        .env(DOCKER_CONFIG_ENV, "/daemon/shared-docker")
        .env("DOCKER_HOST", "unix:///synthetic/docker.sock")
        .env("XDG_RUNTIME_DIR", "/synthetic/runtime")
        .env("PATH", "/synthetic/path")
        .status()
        .unwrap();

    assert!(status.success());
}

#[tokio::test]
async fn host_command_inheritance_child() {
    if std::env::var_os("DOCKER_HOST").as_deref()
        != Some(std::ffi::OsStr::new("unix:///synthetic/docker.sock"))
    {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = JobResourceRoot::prepare(&temp.path().join("job-resources")).unwrap();
    let config = root.create_docker_config().unwrap();
    let job_config = config.directory().to_path_buf();
    let env = HashMap::from([(
        DOCKER_CONFIG_ENV.to_string(),
        job_config.to_string_lossy().into_owned(),
    )]);
    let script = r#"
        test "$DOCKER_CONFIG" = "$EXPECTED_CONFIG"
        test "$DOCKER_HOST" = 'unix:///synthetic/docker.sock'
        test "$XDG_RUNTIME_DIR" = '/synthetic/runtime'
        test "$PATH" = '/synthetic/path'
    "#;
    let expected = job_config.to_string_lossy().into_owned();
    let mut command = host_command(
        "/bin/sh",
        &[std::ffi::OsStr::new("-c"), std::ffi::OsStr::new(script)],
        &env,
        temp.path(),
        &config,
    )
    .unwrap();
    command.env("EXPECTED_CONFIG", expected);

    let status = command.status().await.unwrap();

    assert!(status.success());
}
```

Parent test меняет environment только дочернего test process через `Command::env`; process-global `set_var` не используется.

- [ ] **Step 7: Не передавать host path Docker action containers**

В private `src/job/action/docker.rs::build_container_env` сразу после clone:

```rust
let mut env = host_env.clone();
env.remove("PATH");
env.remove(DOCKER_CONFIG_ENV);
```

Расширить существующий `container_env_remaps_github_paths`:

```rust
host.insert(DOCKER_CONFIG_ENV.into(), "/private/job/docker".into());
let env = build_container_env(&host);
assert!(!env.contains_key(DOCKER_CONFIG_ENV));
```

Job container base env уже не содержит ключ. Ничего не bind-mount из `job-resources` в `build_bind_mounts` или `JobDockerResources::setup`.

- [ ] **Step 8: Обновить unit/integration harness call sites**

Во всех direct host execution tests создавать real `JobDockerConfig` helper и host base env; не ослаблять `host_command` ради старых `HashMap::new()` tests. В `tests/common/mod.rs` добавить `job_resources: JobResourceRoot`, создавать config на каждый `run`, строить `JobExecutionContext`, а после `run_all_steps` всегда вызывать explicit cleanup. Существующий `TestEnv::run` сохраняет return type `(JobConclusion, HashMap<String, String>)`, чтобы остальные integration tests менялись только внутри helper.

- [ ] **Step 9: Запустить execution/action tests**

Run:

```bash
cargo test runner::env_test
cargo test job::execute::execute_test
cargo test job::action::node::node_test
cargo test job::action::composite::composite_test
cargo test job::action::docker::docker_test
cargo test --tests --no-fail-fast
```

Expected: PASS; host spawn без config даёт error, matching override проходит, Docker action env ключа не содержит.

- [ ] **Step 10: Commit explicit propagation**

```bash
git add src/runner/env.rs src/runner/env_test.rs src/job/execute.rs src/job/execute_test.rs src/job/action/node.rs src/job/action/node_test.rs src/job/action/composite.rs src/job/action/composite_test.rs src/job/action/docker.rs src/job/action/docker_test.rs tests/common/mod.rs
git commit -m "feat: reserve per-job Docker config for host steps"
```

---

### Task 4: Перенести cleanup до публикации job result

**Files:**
- Modify: `src/runner/instance.rs:198-517`
- Modify: `src/runner/instance_test.rs`

**Interfaces:**
- Consumes: `Runner.job_resources`, `JobDockerConfig`, `JobExecutionContext`.
- Produces:
  - private `JobExecutionOutcome { conclusion: JobConclusion, outputs: HashMap<String, String> }`.
  - `Runner::run_job_body(&self, manifest: &JobManifest, job_client: &Arc<JobClient>, client: &reqwest::Client, cancel_token: CancellationToken, repo: &str, docker_config: &JobDockerConfig) -> anyhow::Result<JobExecutionOutcome>` без вызова `complete_job`.
  - `finish_job(job_client: &Arc<JobClient>, manifest: &JobManifest, execution_result: anyhow::Result<JobExecutionOutcome>, cleanup_result: std::result::Result<(), JobDockerConfigError>) -> anyhow::Result<()>`.
  - `conclusion_after_cleanup_failure(JobConclusion) -> JobConclusion`.
  - Порядок: create lease → setup/workspace → pre/main/post → Docker/workspace cleanup → job Docker config cleanup → `complete_job`/`report_setup_failure`.

- [ ] **Step 1: Написать failing conclusion/order tests**

Добавить pure mapping test:

```rust
#[test]
fn cleanup_failure_only_downgrades_success() {
    assert_eq!(
        conclusion_after_cleanup_failure(JobConclusion::Succeeded),
        JobConclusion::Failed
    );
    assert_eq!(
        conclusion_after_cleanup_failure(JobConclusion::Failed),
        JobConclusion::Failed
    );
    assert_eq!(
        conclusion_after_cleanup_failure(JobConclusion::Cancelled),
        JobConclusion::Cancelled
    );
}
```

Для finalization tests добавить helpers в `instance_test.rs`:

```rust
fn finish_manifest(server_url: &str) -> JobManifest {
    serde_json::from_value(serde_json::json!({
        "plan": { "planId": "plan", "jobId": "job", "timelineId": "timeline" },
        "steps": [],
        "variables": {},
        "resources": {
            "endpoints": [{
                "name": "SystemVssConnection",
                "url": server_url,
                "authorization": {
                    "scheme": "OAuth",
                    "parameters": { "AccessToken": "synthetic" }
                },
                "data": { "PipelinesServiceUrl": server_url }
            }]
        },
        "contextData": {},
        "jobContainer": null,
        "serviceContainers": null
    }))
    .unwrap()
}

async fn finish_client(server: &MockServer) -> Arc<JobClient> {
    let private_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let token_manager = Arc::new(TokenManager::new(
        reqwest::Client::new(),
        format!("{}/oauth2/token", server.uri()),
        private_key,
        "test-client".into(),
    ));
    let mut client = JobClient::new(
        reqwest::Client::new(),
        token_manager,
        server.uri(),
        server.uri(),
    );
    client.set_job_access_token("synthetic-job-token".into());
    Arc::new(client)
}
```

Затем проверить failure downgrade без permission-dependent `chmod` — детерминированную cleanup error моделирует тот же typed error, который production `JobDockerConfig::cleanup` возвращает на symlink/special entry:

```rust
#[tokio::test]
async fn successful_job_reports_failed_when_docker_config_cleanup_fails() {
    use wiremock::matchers::{body_json, method, path};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/completejob"))
        .and(body_json(serde_json::json!({
            "planId": "plan",
            "jobId": "job",
            "conclusion": "failed",
            "outputs": {},
            "stepResults": []
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let client = finish_client(&server).await;
    let manifest = finish_manifest(&server.uri());
    let execution = Ok(JobExecutionOutcome {
        conclusion: JobConclusion::Succeeded,
        outputs: HashMap::new(),
    });
    let cleanup = Err(JobDockerConfigError::UnsafeEntry {
        path: "/synthetic/job-resource/entry".into(),
    });

    finish_job(&client, &manifest, execution, cleanup)
        .await
        .unwrap();
}

#[tokio::test]
async fn execution_and_cleanup_errors_are_both_returned_without_early_completion() {
    let server = MockServer::start().await;
    let client = finish_client(&server).await;
    let manifest = finish_manifest(&server.uri());
    let execution = Err(anyhow::anyhow!("job-execution-category"));
    let cleanup = Err(JobDockerConfigError::UnsafeEntry {
        path: "/synthetic/job-resource/entry".into(),
    });

    let error = finish_job(&client, &manifest, execution, cleanup)
        .await
        .unwrap_err();

    let chain = format!("{error:#}");
    assert!(chain.contains("job-execution-category"));
    assert!(chain.contains("unsafe-job-resource-path"));
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().all(|request| request.url.path() != "/completejob"));
}
```

`execute_job` остаётся единственным caller `report_setup_failure`; поэтому returned combined error приводит ровно к одному существующему failure-report path, а `finish_job` на error path не делает ранний `/completejob`.

- [ ] **Step 2: Запустить lifecycle tests и подтвердить RED**

Run:

```bash
cargo test runner::instance_test::cleanup_failure_only_downgrades_success -- --exact
cargo test runner::instance_test::successful_job_reports_failed_when_docker_config_cleanup_fails -- --exact
```

Expected: FAIL, потому что current `run_job_body` вызывает `complete_job` до cleanup.

- [ ] **Step 3: Создавать lease до любой action/setup работы**

В самом начале `Runner::run_job`:

```rust
let mut docker_config = self
    .job_resources
    .create_docker_config()
    .context("creating per-job Docker config")?;
let attempt_id = docker_config.attempt_id();
info!(%attempt_id, "created job Docker config");

let execution_result = self
    .run_job_body(
        manifest,
        job_client,
        client,
        cancel_token,
        repo,
        &docker_config,
    )
    .await;
```

Никакой Node action/pre-step не должен запускаться до successful creation. Любой error после создания проходит через общий cleanup tail, а не через ранний `?` в `run_job`.

- [ ] **Step 4: Разделить execution и completion**

Текущее тело `run_job_body` разделить так:

1. `run_job_body` создаёт workspace/event, затем node runtimes и Docker resources; после появления workspace дальнейшая execution-часть сохраняется в локальный `Result`, чтобы cleanup tail не обходился оператором `?`.
2. Оно строит host/container base env. Точный host call: `build_base_env(manifest, &workspace, &self.name, docker_config)?`; container call остаётся `build_container_env(manifest, &workspace, &self.name)`.
3. Оно создаёт `JobExecutionContext::new(docker_config, docker_resources.as_ref(), &node_runtimes)` и передаёт `&execution` в `run_all_steps`.
4. После возврата закрывает live feed и heartbeat на success/error path.
5. Оно всегда очищает `JobDockerResources` и workspace; прежняя workspace warning policy остаётся неизменной.
6. Оно возвращает `JobExecutionOutcome`, но **не** вызывает `complete_job`.

```rust
struct JobExecutionOutcome {
    conclusion: JobConclusion,
    outputs: HashMap<String, String>,
}

fn conclusion_after_cleanup_failure(conclusion: JobConclusion) -> JobConclusion {
    match conclusion {
        JobConclusion::Succeeded => JobConclusion::Failed,
        JobConclusion::Failed => JobConclusion::Failed,
        JobConclusion::Cancelled => JobConclusion::Cancelled,
    }
}
```

Вызов и teardown оформить без раннего `?`, чтобы heartbeat завершался и при execution error:

```rust
let execution = JobExecutionContext::new(
    docker_config,
    docker_resources.as_ref(),
    &node_runtimes,
);
let job_result = run_all_steps(
    manifest,
    job_client,
    &workspace,
    &base_env,
    &self.name,
    &action_cache,
    &github_token,
    cancel_token.clone(),
    &execution,
    live_feed.as_ref().map(LiveFeed::sender),
)
.await;

if let Some(feed) = live_feed {
    feed.close().await;
}
heartbeat_cancel.cancel();
heartbeat_handle
    .await
    .context("heartbeat task panicked")?;

let (mut conclusion, outputs) = job_result.context("running job steps")?;
if cancel_token.is_cancelled() && conclusion != JobConclusion::Cancelled {
    conclusion = JobConclusion::Cancelled;
}
Ok(JobExecutionOutcome { conclusion, outputs })
```

После завершения этого локального execution result `run_job_body` вызывает `resources.cleanup().await` для имеющихся Docker resources и `workspace.cleanup()` с прежним warning, затем возвращает сохранённый result. Это предотвращает heartbeat leak при execution error.

- [ ] **Step 5: Выполнить cleanup и только затем complete/report**

Добавить единый finalization helper:

```rust
async fn finish_job(
    job_client: &Arc<JobClient>,
    manifest: &JobManifest,
    execution_result: Result<JobExecutionOutcome>,
    cleanup_result: std::result::Result<(), JobDockerConfigError>,
) -> Result<()> {
    let mut outcome = match execution_result {
        Ok(outcome) => outcome,
        Err(execution_error) => {
            return match cleanup_result {
                Ok(()) => Err(execution_error),
                Err(cleanup_error) => Err(execution_error.context(cleanup_error.to_string())),
            };
        }
    };

    if cleanup_result.is_err() {
        outcome.conclusion = conclusion_after_cleanup_failure(outcome.conclusion);
    }

    let outputs = outputs_to_variable_values(&outcome.outputs);
    job_client
        .complete_job(
            &manifest.plan.plan_id,
            &manifest.plan.job_id,
            outcome.conclusion,
            &outputs,
            &[],
        )
        .await
        .context("completing job")
}
```

Общий tail `run_job` сначала вызывает cleanup, безопасно логирует только category/attempt ID/error kind, затем передаёт уже полученный result в `finish_job`:

```rust
let cleanup_result = docker_config.cleanup();
match &cleanup_result {
    Ok(()) => info!(%attempt_id, "cleaned job Docker config"),
    Err(error) => tracing::error!(
        category = "job-resource-cleanup",
        %attempt_id,
        error = %error,
        "job Docker config cleanup failed"
    ),
}
finish_job(job_client, manifest, execution_result, cleanup_result).await
```

`execute_job` по-прежнему вызывает `report_setup_failure` только для returned `Err`. Cleanup failure после нормального step result уже публикуется один раз через downgraded conclusion и возвращает `Ok(())`. Не менять общую upstream semantics post-step failures.

- [ ] **Step 6: Проверить success/failure/cancel/setup-error paths**

Run:

```bash
cargo test runner::instance_test
cargo test job::execute::execute_test
```

Expected: PASS; cleanup failure не превращает cancelled/failed в success, creation/setup error не запускает actions, completion идёт после cleanup attempt.

- [ ] **Step 7: Commit lifecycle ordering**

```bash
git add src/runner/instance.rs src/runner/instance_test.rs
git commit -m "fix: clean job Docker config before completion"
```

---

### Task 5: Покрыть execution lifecycle без Docker socket

**Files:**
- Create: `tests/job_docker_config_test.rs`
- Modify: `tests/common/mod.rs:20-119,209-306`

**Interfaces:**
- Consumes: production `JobResourceRoot`, `JobDockerConfig`, `JobExecutionContext`, существующий manifest/action harness.
- Produces:
  - `ObservedRun { conclusion, outputs, docker_config_dir, attempt_dir }`.
  - `TestEnv::setup_with_job_resources(job_resources: JobResourceRoot) -> TestEnv`, позволяющий двум изолированным workspaces использовать один daemon root.
  - `TestEnv::run_observed(&self, manifest: &JobManifest, cancel_token: CancellationToken) -> anyhow::Result<ObservedRun>`; existing `run` delegates with fresh token.
  - `TestEnv::run_observed_with_runtimes(&self, manifest: &JobManifest, cancel_token: CancellationToken, node_runtimes: &NodeRuntimes) -> anyhow::Result<ObservedRun>` для C-10.
  - Helpers `local_node_action_step(id: &str, path: &str) -> serde_json::Value` и `write_docker_config_probe_action(workspace: &Workspace) -> anyhow::Result<()>`.

- [ ] **Step 1: Расширить harness, сохранив существующий API**

Добавить:

```rust
pub struct ObservedRun {
    pub conclusion: JobConclusion,
    pub outputs: HashMap<String, String>,
    pub docker_config_dir: std::path::PathBuf,
    pub attempt_dir: std::path::PathBuf,
}

impl TestEnv {
    pub fn actions_dir(&self) -> &std::path::Path {
        &self.actions_dir
    }
}
```

Добавить `job_resources: JobResourceRoot` в `TestEnv`, а создание fixture разделить так, чтобы concurrent tests могли клонировать один root:

```rust
pub async fn setup() -> Self {
    let tmp = tempfile::tempdir().unwrap();
    let job_resources =
        JobResourceRoot::prepare(&tmp.path().join("job-resources")).unwrap();
    Self::setup_with_tmp(tmp, job_resources).await
}

pub async fn setup_with_job_resources(job_resources: JobResourceRoot) -> Self {
    let tmp = tempfile::tempdir().unwrap();
    Self::setup_with_tmp(tmp, job_resources).await
}

async fn setup_with_tmp(
    tmp: tempfile::TempDir,
    job_resources: JobResourceRoot,
) -> Self {
    let work_dir = tmp.path().join("work");
    let tmp_dir = tmp.path().join("tmp");
    let tool_cache = tmp.path().join("tool-cache");
    let actions_dir = tmp.path().join("actions");
    let workspace = Workspace::create(
        &work_dir,
        &tmp_dir,
        &tool_cache,
        "test-runner",
        "owner/repo",
    )
    .unwrap();
    let mock_server = MockServer::start().await;
    mount_default_mocks(&mock_server).await;
    let job_client = create_job_client(&mock_server).await;
    Self {
        workspace,
        job_client,
        mock_server,
        tmp,
        actions_dir,
        job_resources,
    }
}
```

Реализовать observed host run с обязательным cleanup и сохранением обоих уже удалённых paths:

```rust
pub async fn run_observed(
    &self,
    manifest: &JobManifest,
    cancel_token: CancellationToken,
) -> anyhow::Result<ObservedRun> {
    let node_runtimes = chimera::node::NodeRuntimes::single("node".into());
    self.run_observed_with_runtimes(manifest, cancel_token, &node_runtimes)
        .await
}

pub async fn run_observed_with_runtimes(
    &self,
    manifest: &JobManifest,
    cancel_token: CancellationToken,
    node_runtimes: &chimera::node::NodeRuntimes,
) -> anyhow::Result<ObservedRun> {
    let mut docker_config = self.job_resources.create_docker_config()?;
    let docker_config_dir = docker_config.directory().to_path_buf();
    let attempt_dir = docker_config.attempt_dir().to_path_buf();
    let base_env = build_base_env(
        manifest,
        &self.workspace,
        "test-runner",
        &docker_config,
    )?;
    let action_cache = ActionCache::new(self.actions_dir.clone(), reqwest::Client::new());
    let execution = JobExecutionContext::new(&docker_config, None, node_runtimes);
    let run_result = run_all_steps(
        manifest,
        &self.job_client,
        &self.workspace,
        &base_env,
        "test-runner",
        &action_cache,
        "fake-token",
        cancel_token,
        &execution,
        None,
    )
    .await;
    drop(execution);
    let cleanup_result = docker_config.cleanup();

    let (conclusion, outputs) = match (run_result, cleanup_result) {
        (Ok(value), Ok(())) => value,
        (Err(run_error), Ok(())) => return Err(run_error),
        (Ok(_), Err(cleanup_error)) => return Err(cleanup_error.into()),
        (Err(run_error), Err(cleanup_error)) => {
            return Err(run_error.context(cleanup_error.to_string()));
        }
    };

    Ok(ObservedRun {
        conclusion,
        outputs,
        docker_config_dir,
        attempt_dir,
    })
}

pub async fn run(
    &self,
    manifest: &JobManifest,
) -> anyhow::Result<(JobConclusion, HashMap<String, String>)> {
    let observed = self
        .run_observed(manifest, CancellationToken::new())
        .await?;
    Ok((observed.conclusion, observed.outputs))
}
```

Импортировать `anyhow::Context`, `JobDockerConfig`, `JobExecutionContext`, `JobResourceRoot`. Обновить `run_with_docker` тем же lifecycle: создать config, построить container base env, создать `JobExecutionContext::new(&config, Some(docker_resources), &node_runtimes)`, выполнить `run_all_steps`, drop context, cleanup config и объединить оба results тем же `match`; host path в container env при этом отсутствует.

- [ ] **Step 2: Написать C-01 и C-02 tests**

Создать `tests/job_docker_config_test.rs`:

```rust
mod common;

use chimera::job::client::JobConclusion;
use chimera::job::docker_config::JobResourceRoot;
use common::*;

#[tokio::test]
async fn concurrent_jobs_use_distinct_configs() {
    let daemon_root = tempfile::tempdir().unwrap();
    let job_resources = JobResourceRoot::prepare(
        &daemon_root.path().join("job-resources"),
    )
    .unwrap();
    let first = TestEnv::setup_with_job_resources(job_resources.clone()).await;
    let second = TestEnv::setup_with_job_resources(job_resources).await;
    let first_manifest = manifest_with_steps(
        vec![script_step("first", r#"printf '%s' "$DOCKER_CONFIG" > "$GITHUB_WORKSPACE/docker-config-path""#)],
        &first.mock_server.uri(),
    );
    let second_manifest = manifest_with_steps(
        vec![script_step("second", r#"printf '%s' "$DOCKER_CONFIG" > "$GITHUB_WORKSPACE/docker-config-path""#)],
        &second.mock_server.uri(),
    );

    let (first_run, second_run) = tokio::join!(
        first.run_observed(&first_manifest, tokio_util::sync::CancellationToken::new()),
        second.run_observed(&second_manifest, tokio_util::sync::CancellationToken::new()),
    );
    let first_run = first_run.unwrap();
    let second_run = second_run.unwrap();

    assert_eq!(first_run.conclusion, JobConclusion::Succeeded);
    assert_eq!(second_run.conclusion, JobConclusion::Succeeded);
    assert_ne!(first_run.docker_config_dir, second_run.docker_config_dir);
    let first_seen = std::fs::read_to_string(
        first.workspace.workspace_dir().join("docker-config-path"),
    )
    .unwrap();
    let second_seen = std::fs::read_to_string(
        second.workspace.workspace_dir().join("docker-config-path"),
    )
    .unwrap();
    assert_eq!(std::path::Path::new(&first_seen), first_run.docker_config_dir);
    assert_eq!(std::path::Path::new(&second_seen), second_run.docker_config_dir);
    assert!(!first_run.attempt_dir.exists());
    assert!(!second_run.attempt_dir.exists());
}

#[tokio::test]
async fn sequential_jobs_start_empty_and_use_new_paths() {
    let env = TestEnv::setup().await;
    let first_manifest = manifest_with_steps(
        vec![script_step(
            "write",
            r#"printf '%s' '{"auths":{"registry.test":{"auth":"synthetic"}}}' > "$DOCKER_CONFIG/config.json""#,
        )],
        &env.mock_server.uri(),
    );
    let first = env
        .run_observed(&first_manifest, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    let second_manifest = manifest_with_steps(
        vec![script_step(
            "read",
            r#"test "$(cat "$DOCKER_CONFIG/config.json")" = '{}'"#,
        )],
        &env.mock_server.uri(),
    );

    let second = env
        .run_observed(&second_manifest, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(second.conclusion, JobConclusion::Succeeded);
    assert_ne!(first.docker_config_dir, second.docker_config_dir);
}
```

- [ ] **Step 3: Запустить C-01/C-02 и подтвердить PASS**

Run:

```bash
cargo test --test job_docker_config_test concurrent_jobs_use_distinct_configs -- --exact
cargo test --test job_docker_config_test sequential_jobs_start_empty_and_use_new_paths -- --exact
```

Expected: PASS.

- [ ] **Step 4: Добавить local pre/main/post probe для C-04**

Helper создаёт `.github/actions/docker-config-probe/action.yml`:

```yaml
name: docker-config-probe
runs:
  using: node20
  pre: pre.js
  main: main.js
  post: post.js
  post-if: always()
```

Каждый JS file использует только Node built-ins:

```javascript
const fs = require('fs');
const path = require('path');
const phase = path.basename(__filename, '.js');
const config = process.env.DOCKER_CONFIG;
if (!config || !fs.existsSync(path.join(config, 'config.json'))) process.exit(1);
fs.writeFileSync(path.join(process.env.GITHUB_WORKSPACE, `${phase}-docker-config`), config);
```

Реализовать helpers и test полностью:

```rust
fn write_docker_config_probe_action(workspace: &Workspace) -> anyhow::Result<()> {
    let action_dir = workspace
        .workspace_dir()
        .join(".github/actions/docker-config-probe");
    std::fs::create_dir_all(&action_dir)?;
    std::fs::write(
        action_dir.join("action.yml"),
        "name: docker-config-probe\nruns:\n  using: node20\n  pre: pre.js\n  main: main.js\n  post: post.js\n  post-if: always()\n",
    )?;
    let source = r#"
const fs = require('fs');
const path = require('path');
const phase = path.basename(__filename, '.js');
const config = process.env.DOCKER_CONFIG;
if (!config || !fs.existsSync(path.join(config, 'config.json'))) process.exit(1);
fs.writeFileSync(path.join(process.env.GITHUB_WORKSPACE, `${phase}-docker-config`), config);
"#;
    for phase in ["pre", "main", "post"] {
        std::fs::write(action_dir.join(format!("{phase}.js")), source)?;
    }
    Ok(())
}

fn local_node_action_step(id: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "displayName": format!("Run {path}"),
        "reference": {
            "name": "",
            "type": "repository",
            "repositoryType": "self",
            "path": path
        },
        "inputs": {},
        "condition": null,
        "timeoutInMinutes": null,
        "continueOnError": false,
        "order": 1,
        "environment": null,
        "contextName": id
    })
}

#[tokio::test]
async fn pre_main_post_share_config_until_post_finishes() {
    let env = TestEnv::setup().await;
    write_docker_config_probe_action(&env.workspace).unwrap();
    let manifest = manifest_with_steps(
        vec![local_node_action_step(
            "probe",
            ".github/actions/docker-config-probe",
        )],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    for phase in ["pre", "main", "post"] {
        let path = std::fs::read_to_string(
            env.workspace
                .workspace_dir()
                .join(format!("{phase}-docker-config")),
        )
        .unwrap();
        assert_eq!(std::path::Path::new(&path), observed.docker_config_dir);
    }
    assert!(!observed.attempt_dir.exists());
}
```

Импортировать `Workspace` и `CancellationToken`. Проверка существования `config.json` выполняется внутри каждого phase, поэтому test доказывает не только равенство сохранённых строк после cleanup.

- [ ] **Step 5: Добавить cleanup matrix C-05 и override matrix C-09**

Добавить один table-driven test с success/failure/cancel/pre-error. Все четыре job используют один root, рядом всё время существует чужой lease:

```rust
#[tokio::test]
async fn cleanup_runs_for_all_job_outcomes() {
    let daemon_root = tempfile::tempdir().unwrap();
    let job_resources = JobResourceRoot::prepare(
        &daemon_root.path().join("job-resources"),
    )
    .unwrap();
    let mut neighbor = job_resources.create_docker_config().unwrap();
    let neighbor_dir = neighbor.attempt_dir().to_path_buf();

    for case in ["success", "failure", "cancelled", "pre-error"] {
        let env = TestEnv::setup_with_job_resources(job_resources.clone()).await;
        let cancel = CancellationToken::new();
        let steps = match case {
            "success" => vec![script_step("success", "true")],
            "failure" => vec![script_step("failure", "exit 1")],
            "cancelled" => {
                cancel.cancel();
                vec![script_step("cancelled", "sleep 10")]
            }
            "pre-error" => {
                let action_dir = env
                    .workspace
                    .workspace_dir()
                    .join(".github/actions/failing-pre");
                std::fs::create_dir_all(&action_dir).unwrap();
                std::fs::write(
                    action_dir.join("action.yml"),
                    "name: failing-pre\nruns:\n  using: node20\n  pre: pre.js\n  main: main.js\n",
                )
                .unwrap();
                std::fs::write(action_dir.join("pre.js"), "process.exit(1);\n").unwrap();
                std::fs::write(action_dir.join("main.js"), "process.exit(0);\n").unwrap();
                vec![local_node_action_step(
                    "failing-pre",
                    ".github/actions/failing-pre",
                )]
            }
            _ => unreachable!(),
        };
        let manifest = manifest_with_steps(steps, &env.mock_server.uri());

        let observed = env.run_observed(&manifest, cancel).await.unwrap();

        let expected = match case {
            "success" => JobConclusion::Succeeded,
            "cancelled" => JobConclusion::Cancelled,
            "failure" | "pre-error" => JobConclusion::Failed,
            _ => unreachable!(),
        };
        assert_eq!(observed.conclusion, expected, "case {case}");
        assert!(!observed.attempt_dir.exists(), "case {case}");
        assert!(neighbor_dir.exists(), "case {case}");
    }

    neighbor.cleanup().unwrap();
}
```

Этот test не заявляет, что `Cancelled` уничтожил уже открытые file descriptors потомков; он проверяет только штатный cleanup вызванного resource owner.

Отдельные tests:

```rust
#[tokio::test]
async fn step_env_override_fails_before_spawn() {
    let env = TestEnv::setup().await;
    let sentinel = env.workspace.workspace_dir().join("spawned");
    let manifest = manifest_with_steps(
        vec![script_step_env(
            "override",
            "touch spawned",
            std::collections::HashMap::from([(
                "DOCKER_CONFIG".into(),
                "/shared/.docker".into(),
            )]),
        )],
        &env.mock_server.uri(),
    );

    let result = env.run(&manifest).await.unwrap();

    assert_eq!(result.0, JobConclusion::Failed);
    assert!(!sentinel.exists());
}

#[tokio::test]
async fn github_env_override_fails_before_next_spawn() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step("write", r#"echo 'DOCKER_CONFIG=/shared/.docker' >> "$GITHUB_ENV""#),
            script_step("affected", "touch affected-step-ran"),
        ],
        &env.mock_server.uri(),
    );

    let result = env.run(&manifest).await.unwrap();

    assert_eq!(result.0, JobConclusion::Failed);
    assert!(!env.workspace.workspace_dir().join("affected-step-ran").exists());
}
```

Добавить matching step/GITHUB_ENV variants и legacy mismatch regression:

```rust
#[tokio::test]
async fn matching_step_environment_is_allowed() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step_env(
            "matching",
            r#"test -f "$DOCKER_CONFIG/config.json""#,
            HashMap::from([(
                "DOCKER_CONFIG".into(),
                "${{ env.DOCKER_CONFIG }}".into(),
            )]),
        )],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn matching_github_env_is_allowed() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "write",
                r#"printf 'DOCKER_CONFIG=%s\n' "$DOCKER_CONFIG" >> "$GITHUB_ENV""#,
            ),
            script_step("affected", r#"test -f "$DOCKER_CONFIG/config.json""#),
        ],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
}

#[tokio::test]
async fn legacy_set_env_override_fails_before_next_spawn() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![
            script_step(
                "write",
                "echo '::set-env name=DOCKER_CONFIG::/shared/.docker'",
            ),
            script_step("affected", "touch legacy-affected-step-ran"),
        ],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Failed);
    assert!(!env
        .workspace
        .workspace_dir()
        .join("legacy-affected-step-ran")
        .exists());
}
```

Проверки используют generated value самого job и не вычисляют/подменяют случайный путь вне execution engine.

- [ ] **Step 6: Добавить C-11 process-level regression без global mutation**

Parent test запускает этот же integration-test binary с заполненным inherited daemon config; child выполняет настоящий host step:

```rust
#[test]
fn inherited_daemon_config_is_neither_used_nor_modified() {
    let temp = tempfile::tempdir().unwrap();
    let daemon_dir = temp.path().join("daemon-docker");
    std::fs::create_dir_all(&daemon_dir).unwrap();
    let daemon_file = daemon_dir.join("config.json");
    let marker = r#"{"auths":{"registry.test":{"auth":"synthetic-host"}},"currentContext":"host"}"#;
    std::fs::write(&daemon_file, marker).unwrap();

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inherited_daemon_config_child",
            "--nocapture",
        ])
        .env("DOCKER_CONFIG", &daemon_dir)
        .env("CHIMERA_C11_DAEMON_CONFIG", &daemon_dir)
        .status()
        .unwrap();

    assert!(status.success());
    assert_eq!(std::fs::read_to_string(daemon_file).unwrap(), marker);
}

#[tokio::test]
async fn inherited_daemon_config_child() {
    let Some(daemon_config) = std::env::var_os("CHIMERA_C11_DAEMON_CONFIG") else {
        return;
    };
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![script_step(
            "probe",
            r#"
                test "$DOCKER_CONFIG" != "$CHIMERA_C11_DAEMON_CONFIG"
                test "$(cat "$DOCKER_CONFIG/config.json")" = '{}'
            "#,
        )],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
    assert_ne!(observed.docker_config_dir, std::path::PathBuf::from(daemon_config));
}
```

Не вызывать `std::env::set_var` в parallel test process. В report связать C-11 с этим process-level test и unit test `daemon_docker_config_is_not_copied_or_modified` из Task 1.

- [ ] **Step 7: Запустить весь non-Docker acceptance file**

Run:

```bash
cargo test --test job_docker_config_test -- --nocapture
cargo test --tests --no-fail-fast
```

Expected: PASS; ни один test не требует Docker socket или реального token.

- [ ] **Step 8: Commit execution acceptance**

```bash
git add tests/common/mod.rs tests/job_docker_config_test.rs
git commit -m "test: cover per-job Docker config lifecycle"
```

---

### Task 6: Проверить concurrent login/logout и pinned Buildx на локальном registry

**Files:**
- Create: `tests/common/docker_registry.rs`
- Create: `tests/common/pinned_action.rs`
- Create: `tests/job_docker_config_docker_test.rs`
- Modify: `tests/common/mod.rs`
- Modify: `src/job/action/docker_test.rs`

**Interfaces:**
- Consumes: inherited Docker endpoint (`DOCKER_HOST`/`XDG_RUNTIME_DIR`), Docker CLI/Buildx, `registry:2`, `httpd:2.4-alpine`, public pinned GitHub tarballs.
- Produces:
  - `AuthenticatedRegistry::start() -> anyhow::Result<AuthenticatedRegistry>` (`async fn`), `address(&self) -> &str`, `seed_image(&self, repository: &str, tag: &str) -> anyhow::Result<String>` (`async fn`) и cleanup exact container в `Drop`.
  - `install_pinned_action(actions_dir: &Path, owner: &str, repo: &str, sha: &str) -> anyhow::Result<()>` (`async fn`) в exact ActionCache layout.
  - Ignored tests C-03/C-10 и atomic rewrite evidence.

- [ ] **Step 1: Написать local registry helper**

Создать `tests/common/docker_registry.rs`. Все Docker CLI calls получают отдельный setup config и наследуют исходные `DOCKER_HOST`/`XDG_RUNTIME_DIR`; helper не печатает args/stdin/stderr:

```rust
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

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
    local_images: std::sync::Mutex<Vec<String>>,
}

impl AuthenticatedRegistry {
    pub async fn start() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let auth_dir = temp.path().join("auth");
        let setup_docker_config = temp.path().join("setup-docker");
        std::fs::create_dir(&auth_dir)?;
        std::fs::create_dir(&setup_docker_config)?;
        let alice = docker_output(
            &[
                "run", "--rm", "-i", "httpd:2.4-alpine",
                "htpasswd", "-Bni", ALICE_USER,
            ],
            &setup_docker_config,
            Some(ALICE_PASSWORD.as_bytes()),
        )
        .await?;
        let bob = docker_output(
            &[
                "run", "--rm", "-i", "httpd:2.4-alpine",
                "htpasswd", "-Bni", BOB_USER,
            ],
            &setup_docker_config,
            Some(BOB_PASSWORD.as_bytes()),
        )
        .await?;
        std::fs::write(auth_dir.join("htpasswd"), format!("{alice}{bob}"))?;

        let container_name = format!("chimera-registry-{}", uuid::Uuid::new_v4().simple());
        let auth_mount = format!("{}:/auth:ro", auth_dir.display());
        docker_output(
            &[
                "run", "-d", "--name", &container_name,
                "-p", "127.0.0.1::5000",
                "-v", &auth_mount,
                "-e", "REGISTRY_AUTH=htpasswd",
                "-e", "REGISTRY_AUTH_HTPASSWD_REALM=chimera-test",
                "-e", "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
                "registry:2",
            ],
            &setup_docker_config,
            None,
        )
        .await?;

        let mut registry = Self {
            temp,
            container_name,
            address: String::new(),
            setup_docker_config,
            local_images: std::sync::Mutex::new(Vec::new()),
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

    pub async fn seed_image(&self, repository: &str, tag: &str) -> Result<String> {
        let context = self.temp.path().join(format!("seed-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&context)?;
        std::fs::write(context.join("Dockerfile"), "FROM scratch\nCOPY marker /marker\n")?;
        std::fs::write(context.join("marker"), "synthetic-registry-probe\n")?;
        let image = format!("{}/{repository}:{tag}", self.address);
        let context_path = context.to_string_lossy().into_owned();

        docker_output(
            &["login", "--username", ALICE_USER, "--password-stdin", &self.address],
            &self.setup_docker_config,
            Some(ALICE_PASSWORD.as_bytes()),
        )
        .await?;
        let operation = async {
            docker_output(
                &["build", "--tag", &image, &context_path],
                &self.setup_docker_config,
                None,
            )
            .await?;
            docker_output(
                &["push", &image],
                &self.setup_docker_config,
                None,
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let logout = docker_output(
            &["logout", &self.address],
            &self.setup_docker_config,
            None,
        )
        .await;
        operation?;
        self.local_images.lock().unwrap().push(image.clone());
        logout?;
        Ok(image)
    }
}

impl Drop for AuthenticatedRegistry {
    fn drop(&mut self) {
        for image in self.local_images.get_mut().unwrap().drain(..) {
            let result = std::process::Command::new("docker")
                .args(["image", "rm", "-f", &image])
                .env("DOCKER_CONFIG", &self.setup_docker_config)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            match result {
                Ok(status) if status.success() => {}
                Ok(status) => eprintln!(
                    "failed to remove synthetic test image {image}: status {status}"
                ),
                Err(error) => eprintln!(
                    "failed to remove synthetic test image {image}: {error}"
                ),
            }
        }

        let result = std::process::Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .env("DOCKER_CONFIG", &self.setup_docker_config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match result {
            Ok(status) if status.success() => {}
            Ok(status) => eprintln!(
                "failed to remove test registry {}: status {status}",
                self.container_name
            ),
            Err(error) => eprintln!(
                "failed to remove test registry {}: {error}",
                self.container_name
            ),
        }
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
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().context("starting Docker CLI test command")?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .context("Docker CLI stdin was not piped")?
            .write_all(input)
            .await?;
    }
    let output = tokio::time::timeout(
        Duration::from_secs(300),
        child.wait_with_output(),
    )
    .await
    .context("Docker CLI test command timed out")??;
    if !output.status.success() {
        bail!("Docker CLI test command failed with status {}", output.status);
    }
    String::from_utf8(output.stdout).context("Docker CLI output was not UTF-8")
}
```

`Drop` удаляет только exact generated container name; network, glob, volume prune и `docker system prune` не используются. В `tests/common/mod.rs` объявить `mod docker_registry; pub use docker_registry::*;`.

- [ ] **Step 2: Написать pinned action cache helper**

Создать `tests/common/pinned_action.rs`. Helper скачивает public codeload URL без Authorization header, отбрасывает GitHub prefix, разрешает только directory/regular-file entries и атомарно публикует exact ActionCache layout:

```rust
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

pub async fn install_pinned_action(
    actions_dir: &Path,
    owner: &str,
    repo: &str,
    sha: &str,
) -> Result<()> {
    let destination = actions_dir.join(owner).join(repo).join(sha);
    if destination.join("action.yml").exists()
        || destination.join("action.yaml").exists()
    {
        return Ok(());
    }

    let url = format!("https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}");
    let response = reqwest::Client::new()
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
    let destination_for_task = destination.clone();
    tokio::task::spawn_blocking(move || {
        let parent = destination_for_task
            .parent()
            .context("action cache destination has no parent")?;
        std::fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(
            ".{}.tmp-{}",
            destination_for_task
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("action"),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&temporary)?;

        let extraction = extract_public_action(&bytes, &temporary);
        if let Err(error) = extraction {
            let cleanup = std::fs::remove_dir_all(&temporary);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(error.context(format!(
                    "also failed to remove {}: {cleanup_error}",
                    temporary.display()
                ))),
            };
        }

        match std::fs::rename(&temporary, &destination_for_task) {
            Ok(()) => Ok(()),
            Err(_) if destination_for_task.exists() => {
                std::fs::remove_dir_all(&temporary)?;
                Ok(())
            }
            Err(error) => {
                let cleanup = std::fs::remove_dir_all(&temporary);
                if let Err(cleanup_error) = cleanup {
                    return Err(anyhow::Error::new(error).context(format!(
                        "also failed to remove {}: {cleanup_error}",
                        temporary.display()
                    )));
                }
                Err(error).context("publishing pinned action cache directory")
            }
        }
    })
    .await
    .context("pinned action extraction task panicked")??;

    if !destination.join("action.yml").exists()
        && !destination.join("action.yaml").exists()
    {
        bail!("pinned action {owner}/{repo}@{sha} has no action metadata");
    }
    Ok(())
}

fn extract_public_action(bytes: &[u8], destination: &Path) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let archive_path = entry.path()?.into_owned();
        let relative: PathBuf = archive_path.components().skip(1).collect();
        if relative.as_os_str().is_empty() {
            continue;
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
        let entry_type = entry.header().entry_type();
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
```

В `tests/common/mod.rs` объявить `mod pinned_action; pub use pinned_action::*;`. Никакой GitHub token не передаётся downloader-у или child process.

- [ ] **Step 3: Написать C-03 test конкурентного login/logout**

```rust
fn registry_login_manifest(
    username: &str,
    password: &str,
    registry: &str,
    sync: &std::path::Path,
    body: &str,
    server_url: &str,
) -> JobManifest {
    let script = format!(
        "printf '%s' \"$PASSWORD\" | docker login --username \"$USERNAME\" --password-stdin \"$REGISTRY\"\n{body}"
    );
    let mut step = script_step_env(
        "registry",
        &script,
        HashMap::from([
            ("USERNAME".into(), username.into()),
            ("PASSWORD".into(), password.into()),
            ("REGISTRY".into(), registry.into()),
            ("SYNC".into(), sync.to_string_lossy().into_owned()),
        ]),
    );
    step["timeoutInMinutes"] = serde_json::json!(1);
    manifest_with_steps(vec![step], server_url)
}

#[tokio::test]
#[ignore]
async fn concurrent_logout_does_not_remove_other_job_credentials() {
    let registry = AuthenticatedRegistry::start().await.unwrap();
    let seeded = registry.seed_image("probe", "seed").await.unwrap();
    assert_eq!(seeded, format!("{}/probe:seed", registry.address()));
    let sync = tempfile::tempdir().unwrap();
    let daemon_root = tempfile::tempdir().unwrap();
    let job_resources = JobResourceRoot::prepare(
        &daemon_root.path().join("job-resources"),
    )
    .unwrap();
    let first = TestEnv::setup_with_job_resources(job_resources.clone()).await;
    let second = TestEnv::setup_with_job_resources(job_resources).await;

    let first_manifest = registry_login_manifest(
        ALICE_USER,
        ALICE_PASSWORD,
        registry.address(),
        sync.path(),
        r#"
          touch "$SYNC/a-ready"
          while [ ! -f "$SYNC/b-ready" ]; do sleep 0.05; done
          docker logout "$REGISTRY"
          touch "$SYNC/a-logout"
        "#,
        &first.mock_server.uri(),
    );
    let second_manifest = registry_login_manifest(
        BOB_USER,
        BOB_PASSWORD,
        registry.address(),
        sync.path(),
        r#"
          touch "$SYNC/b-ready"
          while [ ! -f "$SYNC/a-logout" ]; do sleep 0.05; done
          docker pull "$REGISTRY/probe:seed"
        "#,
        &second.mock_server.uri(),
    );

    let (first_run, second_run) = tokio::join!(
        first.run(&first_manifest),
        second.run(&second_manifest),
    );

    assert_eq!(first_run.unwrap().0, JobConclusion::Succeeded);
    assert_eq!(second_run.unwrap().0, JobConclusion::Succeeded);
}
```

Импортировать `HashMap`, `JobManifest` и `JobResourceRoot`. Credentials синтетические, password не выводится. Отличимые accounts реально проверяет htpasswd server, а B делает registry operation после logout A. Helper ставит `timeoutInMinutes: 1`; при ошибке handshake test завершается по timeout вместо бесконечного ожидания suite.

- [ ] **Step 4: Написать Docker CLI atomic rewrite test**

Добавить real Docker CLI test. Он не выводит JSON/auth value в assertion messages — проверяет только structure/key presence:

```rust
#[tokio::test]
#[ignore]
async fn docker_cli_atomic_rewrite_stays_private() {
    use std::os::unix::fs::PermissionsExt;

    let registry = AuthenticatedRegistry::start().await.unwrap();
    let root_parent = tempfile::tempdir().unwrap();
    let root = JobResourceRoot::prepare(
        &root_parent.path().join("job-resources"),
    )
    .unwrap();
    let mut config = root.create_docker_config().unwrap();
    let attempt = config.attempt_dir().to_path_buf();

    docker_output(
        &[
            "login",
            "--username",
            ALICE_USER,
            "--password-stdin",
            registry.address(),
        ],
        config.directory(),
        Some(ALICE_PASSWORD.as_bytes()),
    )
    .await
    .unwrap();

    let metadata = std::fs::symlink_metadata(config.config_file()).unwrap();
    assert!(metadata.is_file());
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(
        std::fs::symlink_metadata(config.directory())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    let parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config.config_file()).unwrap()).unwrap();
    let auths = parsed.get("auths").and_then(serde_json::Value::as_object).unwrap();
    assert_eq!(auths.len(), 1);
    assert!(auths.contains_key(registry.address()));

    docker_output(
        &["logout", registry.address()],
        config.directory(),
        None,
    )
    .await
    .unwrap();
    assert!(attempt.exists());

    config.cleanup().unwrap();
    assert!(!attempt.exists());
}
```

- [ ] **Step 5: Написать Docker action boundary test**

В `src/job/action/docker_test.rs` unit проверка из Task 3 остаётся. Добавить ignored integration regression:

```rust
#[tokio::test]
#[ignore]
async fn docker_action_does_not_receive_host_config() {
    let env = TestEnv::setup().await;
    let manifest = manifest_with_steps(
        vec![serde_json::json!({
            "id": "docker-config-boundary",
            "displayName": "Docker config boundary",
            "reference": {
                "name": "docker://alpine:3.19",
                "type": "containerregistry",
                "image": "alpine:3.19"
            },
            "inputs": {
                "entrypoint": "/bin/sh",
                "args": "-c 'test -z \"$DOCKER_CONFIG\"'"
            },
            "condition": null,
            "timeoutInMinutes": 2,
            "continueOnError": false,
            "order": 1,
            "environment": null,
            "contextName": "docker-config-boundary"
        })],
        &env.mock_server.uri(),
    );

    let observed = env
        .run_observed(&manifest, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
}
```

Это доказывает отсутствие exposure через environment; production mount list отдельно остаётся без `job-resources`.

- [ ] **Step 6: Написать pinned Buildx C-10 test**

Добавить remote action builder и полный pinned flow:

```rust
fn remote_action_step(
    id: &str,
    name: &str,
    sha: &str,
    inputs: HashMap<String, String>,
    order: u32,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "displayName": format!("Run {name}@{sha}"),
        "reference": {
            "name": name,
            "type": "repository",
            "ref": sha
        },
        "inputs": inputs,
        "condition": null,
        "timeoutInMinutes": 15,
        "continueOnError": false,
        "order": order,
        "environment": null,
        "contextName": id
    })
}

#[tokio::test]
#[ignore]
async fn pinned_buildx_flow_uses_job_config_and_original_socket() {
    const SETUP_BUILDX_SHA: &str =
        "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5";
    const LOGIN_SHA: &str =
        "650006c6eb7dba73a995cc03b0b2d7f5ca915bee";
    const BUILD_PUSH_SHA: &str =
        "f9f3042f7e2789586610d6e8b85c8f03e5195baf";

    let registry = AuthenticatedRegistry::start().await.unwrap();
    let env = TestEnv::setup().await;
    std::fs::write(
        env.workspace.workspace_dir().join("Dockerfile"),
        "FROM scratch\nCOPY marker /marker\n",
    )
    .unwrap();
    std::fs::write(
        env.workspace.workspace_dir().join("marker"),
        "synthetic-buildx-probe\n",
    )
    .unwrap();
    install_pinned_action(
        env.actions_dir(),
        "docker",
        "setup-buildx-action",
        SETUP_BUILDX_SHA,
    )
    .await
    .unwrap();
    install_pinned_action(
        env.actions_dir(),
        "docker",
        "login-action",
        LOGIN_SHA,
    )
    .await
    .unwrap();
    install_pinned_action(
        env.actions_dir(),
        "docker",
        "build-push-action",
        BUILD_PUSH_SHA,
    )
    .await
    .unwrap();

    let tag = format!(
        "{}/buildx-probe:{}",
        registry.address(),
        uuid::Uuid::new_v4().simple()
    );
    let expected = HashMap::from([
        (
            "EXPECTED_DOCKER_HOST".into(),
            std::env::var("DOCKER_HOST").unwrap_or_default(),
        ),
        (
            "EXPECTED_XDG_RUNTIME_DIR".into(),
            std::env::var("XDG_RUNTIME_DIR").unwrap_or_default(),
        ),
        (
            "EXPECTED_PATH".into(),
            std::env::var("PATH").unwrap_or_default(),
        ),
    ]);
    let probe = script_step_env(
        "environment-probe",
        r#"
            test -f "$DOCKER_CONFIG/config.json"
            test "${DOCKER_HOST-}" = "$EXPECTED_DOCKER_HOST"
            test "${XDG_RUNTIME_DIR-}" = "$EXPECTED_XDG_RUNTIME_DIR"
            test "${PATH-}" = "$EXPECTED_PATH"
        "#,
        expected,
    );
    let setup = remote_action_step(
        "buildx",
        "docker/setup-buildx-action",
        SETUP_BUILDX_SHA,
        HashMap::from([
            ("driver-opts".into(), "network=host".into()),
            (
                "buildkitd-config-inline".into(),
                format!(
                    "[registry.\"{}\"]\n  http = true\n  insecure = true\n",
                    registry.address()
                ),
            ),
        ]),
        2,
    );
    let mut record_builder = script_step(
        "record-builder",
        r#"printf '%s' '${{ steps.buildx.outputs.name }}' > buildx-builder-name"#,
    );
    record_builder["order"] = serde_json::json!(3);
    let login = remote_action_step(
        "login",
        "docker/login-action",
        LOGIN_SHA,
        HashMap::from([
            ("registry".into(), registry.address().into()),
            ("username".into(), ALICE_USER.into()),
            ("password".into(), "${{ secrets.REGISTRY_PASSWORD }}".into()),
        ]),
        4,
    );
    let build = remote_action_step(
        "build",
        "docker/build-push-action",
        BUILD_PUSH_SHA,
        HashMap::from([
            ("context".into(), ".".into()),
            ("file".into(), "Dockerfile".into()),
            ("push".into(), "true".into()),
            ("provenance".into(), "false".into()),
            ("tags".into(), tag.clone()),
        ]),
        5,
    );
    let mut pull = script_step_env(
        "pull",
        "docker pull \"$IMAGE\"",
        HashMap::from([("IMAGE".into(), tag.clone())]),
    );
    pull["order"] = serde_json::json!(6);
    let manifest = manifest_with_steps_and_context(
        vec![probe, setup, record_builder, login, build, pull],
        &env.mock_server.uri(),
        serde_json::json!({
            "secrets": { "REGISTRY_PASSWORD": ALICE_PASSWORD }
        }),
    );
    let node_runtimes = chimera::node::ensure_node(
        &env.tmp.path().join("buildx-node-runtimes"),
    )
    .await
    .unwrap();

    let observed = env
        .run_observed_with_runtimes(
            &manifest,
            CancellationToken::new(),
            &node_runtimes,
        )
        .await
        .unwrap();

    assert_eq!(observed.conclusion, JobConclusion::Succeeded);
    assert!(!observed.attempt_dir.exists());
    let builder_name = std::fs::read_to_string(
        env.workspace.workspace_dir().join("buildx-builder-name"),
    )
    .unwrap();
    let builder_name = builder_name.trim();
    assert!(!builder_name.is_empty());
    let inspection_config = tempfile::tempdir().unwrap();
    std::fs::write(inspection_config.path().join("config.json"), "{}").unwrap();
    let inspect = docker_output(
        &["buildx", "inspect", builder_name],
        inspection_config.path(),
        None,
    )
    .await;
    assert!(inspect.is_err(), "setup-buildx post did not remove its builder");
    docker_output(
        &["image", "rm", "-f", &tag],
        inspection_config.path(),
        None,
    )
    .await
    .unwrap();
}
```

`record-builder` получает output через runner expression state; failed setup/build/login/pull остаются main-step failures, а отдельный `buildx inspect` после `ObservedRun` подтверждает side effect setup-buildx post, поскольку upstream post failures сами по себе не меняют job conclusion. Не обращаться к GHCR или deploy endpoints.

- [ ] **Step 7: Запустить targeted Docker tests**

Run:

```bash
cargo test --test job_docker_config_docker_test concurrent_logout_does_not_remove_other_job_credentials -- --ignored --exact --nocapture
cargo test --test job_docker_config_docker_test docker_cli_atomic_rewrite_stays_private -- --ignored --exact --nocapture
cargo test --test job_docker_config_docker_test pinned_buildx_flow_uses_job_config_and_original_socket -- --ignored --exact --nocapture
cargo test --test job_docker_config_docker_test docker_action_does_not_receive_host_config -- --ignored --exact --nocapture
```

Expected: PASS against the selected Docker endpoint. Если BuildKit на целевой rootless Engine не может reach/auth local registry даже с `network=host` и inline registry config, задача остаётся незавершённой: сохранить evidence и пересмотреть harness/adapter, а не заменять test unauthenticated registry или GHCR.

- [ ] **Step 8: Запустить всю ignored suite**

Run:

```bash
cargo test -- --ignored --nocapture
```

Expected: PASS; helper удаляет только exact generated containers/images tags и не делает `docker system prune`/global cleanup.

- [ ] **Step 9: Commit Docker acceptance**

```bash
git add tests/common/mod.rs tests/common/docker_registry.rs tests/common/pinned_action.rs tests/job_docker_config_docker_test.rs src/job/action/docker_test.rs
git commit -m "test: verify isolated Docker credentials and Buildx"
```

---

### Task 7: Документировать recovery, ограничения и acceptance evidence

**Files:**
- Create: `docs/job-docker-config.md`
- Create: `docs/superpowers/reports/2026-09-16-chimera-job-docker-config.md`
- Modify: `README.md:38-50,69-97,98-138`

**Interfaces:**
- Consumes: финальные test names/commands Tasks 1–6.
- Produces: операторский контракт без automatic deletion и полная traceability C-01…C-11.

- [ ] **Step 1: Написать operator document**

`docs/job-docker-config.md` должен явно зафиксировать:

```markdown
# Per-job Docker configuration

Chimera creates `<root>/job-resources/<local-attempt-uuid>/docker/config.json`
for every acquired job. The directory is private to the daemon UID and is removed
only after all post actions finish. `DOCKER_CONFIG` is reserved for host steps;
a workflow may repeat the generated value but may not redirect it.

The directory prevents accidental credential sharing between jobs. It does not
isolate processes running under the same UID, Docker daemon access, or descendants
that escape Chimera's current process-tree cancellation.

Docker actions and job containers do not receive or mount this host path. Named
contexts, credential helpers, CLI plugins, and credentials from `$HOME/.docker`
are not imported.

## `stale-job-resources` recovery

1. Stop the Chimera service and do not restart it while inspection is in progress.
2. Identify the service cgroup with `systemctl show chimera.service -p ControlGroup`
   and verify that it contains no processes. A stopped daemon PID alone is not proof
   that job descendants exited.
3. Verify that no related Docker build/push operation is still consuming the exact
   local attempt UUID. If process ownership is uncertain, stop; do not delete or restart.
4. Without opening `config.json`, verify the exact root/attempt owner, mode and path:
   `stat -c '%U:%G %a %n' <root>/job-resources <root>/job-resources/<uuid>`.
   Reject symlinks or a path outside the canonical Chimera root.
5. Obtain explicit authorization to remove only
   `<root>/job-resources/<uuid>`. Do not glob, prune Docker, inspect credential
   contents, or remove neighboring/user Docker directories.
6. Remove that exact generated attempt directory, confirm `job-resources` is empty,
   then start Chimera again. A cleanup error is handled by the same procedure.
```

Добавить Debian/systemd note: service должен передавать rootless `DOCKER_HOST`, `XDG_RUNTIME_DIR`, `PATH`; daemon-level `DOCKER_CONFIG` не является job config и не должен использоваться как fallback.

- [ ] **Step 2: Обновить README**

Добавить краткий раздел после Config: layout, reserved env, no-copy behavior, startup refusal, ссылка на operator doc. В Supported features заменить/уточнить cleanup claim, чтобы README не обещал orphaned process cleanup, которого код не гарантирует. Не заявлять tenant isolation.

- [ ] **Step 3: Создать acceptance report с точной матрицей**

`docs/superpowers/reports/2026-09-16-chimera-job-docker-config.md`:

```markdown
# CHM-03 Acceptance Report

| ID | Evidence |
|---|---|
| C-01 | `tests/job_docker_config_test.rs::concurrent_jobs_use_distinct_configs` |
| C-02 | `tests/job_docker_config_test.rs::sequential_jobs_start_empty_and_use_new_paths` |
| C-03 | `tests/job_docker_config_docker_test.rs::concurrent_logout_does_not_remove_other_job_credentials` |
| C-04 | `tests/job_docker_config_test.rs::pre_main_post_share_config_until_post_finishes` |
| C-05 | `tests/job_docker_config_test.rs::cleanup_runs_for_all_job_outcomes`; `src/job/docker_config_test.rs::cleanup_is_idempotent_and_keeps_neighbor` |
| C-06 | `src/job/docker_config_test.rs::read_only_root_fails_without_fallback`; `src/runner/instance_test.rs::successful_job_reports_failed_when_docker_config_cleanup_fails` |
| C-07 | `src/job/docker_config_test.rs::stale_root_with_live_child_is_not_removed`; `src/daemon_test.rs::startup_preparation_rejects_stale_job_resources_without_deleting_them`; `docs/job-docker-config.md#stale-job-resources-recovery` |
| C-08 | `src/job/docker_config_test.rs::{umask_zero_still_creates_private_paths,prepare_rejects_symlink_root,cleanup_refuses_config_symlink_without_touching_target,generated_id_collision_is_rejected}`; `src/daemon_test.rs::{second_lock_cannot_replace_live_lock,dropping_lock_does_not_remove_replacement_inode}` |
| C-09 | `src/job/execute_test.rs::{step_environment_cannot_override_docker_config,job_environment_cannot_override_docker_config,github_env_cannot_override_docker_config,matching_override_is_allowed}`; override tests in `tests/job_docker_config_test.rs`; no process-global mutation |
| C-10 | `tests/job_docker_config_docker_test.rs::pinned_buildx_flow_uses_job_config_and_original_socket` |
| C-11 | `src/job/docker_config_test.rs::daemon_docker_config_is_not_copied_or_modified`; `tests/job_docker_config_test.rs::inherited_daemon_config_is_neither_used_nor_modified`; `src/job/execute_test.rs::host_command_explicitly_overrides_inherited_docker_config` |

All credentials used by the suite are synthetic. C-03 and C-10 target a local
registry; no GHCR push, deployment, or unchanged-workflow production canary is
part of this report. Process-tree escape remains an explicitly documented
limitation, so file unlink after cancellation is not presented as proof that a
surviving child forgot previously opened credentials.
```

Сверить names с фактическими test names; report создаётся только после их PASS.

- [ ] **Step 4: Запустить formatter и обязательную полную verification suite**

Run:

```bash
cargo fmt
cargo fmt -- --check
cargo build
cargo clippy -- -D warnings
cargo test
cargo test -- --ignored --nocapture
```

Expected: все команды exit 0, build без errors, clippy без warnings, обычные и ignored tests PASS. Если Docker endpoint недоступен, Task 6 и весь план остаются незавершёнными; не отмечать C-03/C-10 как passed.

- [ ] **Step 5: Проверить diff на секреты и scope drift**

Run:

```bash
git diff --check
git diff --stat
git grep -nE 'ghcr\.io|docker system prune|std::env::set_var|production[-_ ]?token' -- src tests docs README.md
```

Expected:

- `git diff --check` без output;
- `docker system prune` отсутствует в executable code (допустимо только отрицательное упоминание в docs/plan);
- `std::env::set_var` отсутствует;
- GHCR встречается только в scope/negative documentation, не в acceptance execution;
- нет real token/password, кроме фиксированных synthetic `alpha-pass`/`beta-pass` test values.

- [ ] **Step 6: Commit docs и acceptance report**

```bash
git add README.md docs/job-docker-config.md docs/superpowers/reports/2026-09-16-chimera-job-docker-config.md
git commit -m "docs: describe per-job Docker config recovery"
```

- [ ] **Step 7: Зафиксировать финальный verification evidence**

Run:

```bash
git status --short
git log -7 --oneline
```

Expected: clean working tree; отдельные commits Tasks 1–7 видны в истории. Не push и не создавать PR без отдельного запроса пользователя.
