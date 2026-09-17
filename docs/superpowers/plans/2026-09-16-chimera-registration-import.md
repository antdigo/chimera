# Official Runner Registration Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить полностью offline-команду `chimera import-official`, которая безопасно импортирует одну persistent repo-scoped регистрацию официального Linux/X64 GitHub runner, не меняя её server-side identity.

**Architecture:** Импорт разделяется на три фазы: строгий no-follow parser/eligibility gate читает официальный формат, read-only planner проверяет имя, пересечение путей и конфликты локального состояния, а transactional commit публикует приватный каталог credentials и лишь затем атомарно обновляет `config.toml`. Общая advisory-блокировка root используется daemon и всеми командами, меняющими локальную конфигурацию; dry-run блокировку не создаёт и остаётся побочно-эффектно свободным. Текущий broker session исправляется на persistent semantics (`ephemeral: false`), потому что и штатная регистрация Chimera, и поддерживаемый импорт являются persistent.

**Tech Stack:** Rust 2024, `clap`, `serde`/`serde_json`, `toml`, `rsa`, `base64`, `uuid`, `thiserror`, `anyhow`, POSIX `flock`/permissions через уже подключённый `libc`; unit tests, `tempfile`, black-box CLI integration tests через `std::process::Command`.

**Spec:** `docs/superpowers/specs/2026-09-16-chimera-registration-import.md`

## Global Constraints

- Scope: только Linux/X64, `github.com`, persistent repo-scoped OAuth-регистрации с рабочим V2 flow; GHES, Windows, ephemeral/JIT и legacy-only flow отклоняются. Official credential JSON не содержит OS/architecture/labels, поэтому offline gate проверяет формат/identity, а Linux/X64 source и сохранность labels остаются обязательным operator precondition и I-09 canary check.
- Импорт одной регистрации за вызов; `--name` — только локальный ключ и не меняет сохранённый `agentName`.
- `--name` имеет длину 1–128 ASCII-символов из `[A-Za-z0-9._-]`; `.` и `..` запрещены.
- Dry-run и обычный импорт полностью offline: не получают registration token, не вызывают GitHub API и не доказывают online-валидность identity.
- Dry-run не создаёт и не изменяет ни одного файла, включая отсутствующий `config.toml`; он не вызывает `load_config`, который сохраняет defaults.
- Стабильные категории ошибок: `invalid-source`, `unsupported-registration`, `identity-conflict`, `target-busy`, `write-failed`.
- stdout/stderr не содержат RSA-параметры, client ID, authorization URL, OAuth metadata, токены или исходный JSON.
- Credential-файлы источника и назначения открываются без следования symlink; source канонизируется, а пересечение source с target отклоняется.
- RSA private parameters не заменяются и не регенерируются; проверяются `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `inverseQ` и их математическая согласованность.
- Identity key равен `(canonical GitHub repo scope, pool ID, agent ID)`; одинаковый agent ID в разных repo scopes допустим.
- Новые credential-каталоги создаются с `0700`, JSON-файлы с `0600` с момента создания, независимо от umask.
- Полный credential set сначала создаётся во временном приватном каталоге на той же filesystem и проверяется штатным loader; `config.toml` обновляется последним атомарной заменой.
- Повтор идентичного импорта — успешный no-op; same name/different data и same identity/different name — конфликты; `--force` не добавляется.
- Существующие каталоги, source-файлы и опубликованные credentials не удаляются и не перезаписываются; удаляется только staging текущего неуспешного вызова до его публикации.
- labels остаются server-side и importer их не читает, не синтезирует и не переустанавливает.
- I-09 выполняется оператором только после отдельного разрешения оунера; до него формулировка результата: «offline-импорт реализован; online-перенос не подтверждён».
- Новые crates не нужны: использовать уже подключённые `libc`, `uuid`, `rsa`, `base64`, `serde`, `reqwest::Url`; если во время реализации всё же понадобится dependency, сначала получить разрешение пользователя согласно `CLAUDE.md`.

---

## File Structure

### Новые production-файлы

- `src/storage.rs` — проверка безопасности существующего root, создание приватного root и неблокирующая эксклюзивная `RootLock` на `.chimera.lock`.
- `src/storage_test.rs` — ownership/mode/symlink и contention-тесты общей блокировки.
- `src/import.rs` — публичный API импорта, типизированные категории ошибок, outcome и orchestration dry-run/apply.
- `src/import/source.rs` — official runner 2.337.0 JSON schema, no-follow чтение, eligibility gate, endpoint/auth/RSA validation и преобразование в `RunnerCredentials`.
- `src/import/source_test.rs` — parser/eligibility/redaction tests на synthetic fixture.
- `src/import/test_support.rs` — общие synthetic-fixture helpers только для importer unit tests.
- `src/import/target.rs` — read-only name/path/config/identity conflict planning без побочных эффектов.
- `src/import/target_test.rs` — dry-run, collision, traversal, symlink и source/target overlap tests.
- `src/import/commit.rs` — staging, secure JSON creation, loader verification, publish-without-overwrite, atomic config replacement и fault checkpoints.
- `src/import/commit_test.rs` — permissions, idempotency, crash-window и retry tests.
- `src/import_test.rs` — orchestration и безопасный формат outcome/error.

### Новые fixtures и integration/docs-файлы

- `tests/fixtures/official-runner-v2/.runner` — synthetic persistent repo-scoped V2 settings в точном official casing.
- `tests/fixtures/official-runner-v2/.credentials` — synthetic OAuth metadata с FIPS=false.
- `tests/fixtures/official-runner-v2/.credentials_rsaparams` — synthetic, математически согласованный RSA key в official PascalCase.
- `tests/import_official_test.rs` — black-box CLI acceptance для I-01… I-08, включая umask 000 и network-dead proxy.
- `docs/registration-import.md` — supported metadata allowlist, dry-run/import, переключение, возврат и acceptance report I-01… I-09.
- `src/cli_test.rs` — clap parsing нового subcommand.

### Изменяемые файлы

- `src/config.rs:48-95,170-279` — equality для credential models, side-effect-free config loader и полная RSA consistency validation.
- `src/config_test.rs:4-177` — тесты нового loader и производных RSA-компонентов.
- `src/config.rs:97-162` — путь `.chimera.lock` в `ChimeraPaths`.
- `src/lib.rs:1-10` — подключить `import` и внутренний `storage` modules.
- `src/daemon.rs:18-55,203-216` — оставить PID-файл для status, но в `Daemon::load` брать `RootLock` до config read и хранить guard всю жизнь daemon.
- `src/daemon_test.rs:9-82` — подтвердить, что daemon и writer используют одну root-блокировку.
- `src/cli.rs:91-129` — строить locked daemon до чтения его tracing config, исключая start/import race.
- `src/github/registration.rs:194-289` — брать root lock до сетевой регистрации/локального удаления и больше не проглатывать ошибки config через `unwrap_or_default`.
- `src/github/registration_test.rs:101-123` — lock contention для unregister и сохранение состояния при busy root.
- `src/github/broker.rs:108-195` — persistent session request (`ephemeral: false`).
- `src/github/broker_test.rs:42-118` — request-body regression test для persistent semantics.
- `src/cli.rs:22-99` — clap interface и dispatch `import-official`.
- `README.md:39-80` — краткий CLI пример, offline guarantees и ссылка на operator guide.
- `docs/gh-protocol.md:301-340` — исправить описание broker session с ephemeral на persistent.

---

### Task 1: Strengthen Credential and RSA Primitives

**Files:**
- Modify: `src/config.rs:48-95,170-279`
- Modify: `src/config_test.rs:4-177`

**Interfaces:**
- Consumes: существующие `RsaParameters`, `RunnerCredentials`, `rsa_params_to_private_key`.
- Produces: `RunnerInfo: PartialEq + Eq`, `OAuthCredentials: PartialEq + Eq`, `RsaParameters: PartialEq + Eq`, `RunnerCredentials: PartialEq + Eq`; `rsa_params_to_private_key(&RsaParameters) -> anyhow::Result<RsaPrivateKey>` валидирует все восемь компонентов.

- [ ] **Step 1: Write failing tests for all derived RSA values**

Добавить к `src/config_test.rs` тест, который сначала подтверждает валидный key, затем независимо портит `dp`, `dq` и `inverseQ`:

```rust
#[test]
fn rsa_validation_rejects_inconsistent_derived_parameters() {
    let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let params = private_key_to_rsa_params(&key).unwrap();

    let corruptions: [(&str, fn(&mut RsaParameters) -> &mut String); 3] = [
        ("dp", |value| &mut value.dp),
        ("dq", |value| &mut value.dq),
        ("inverseQ", |value| &mut value.inverse_q),
    ];

    for (field, select) in corruptions {
        let mut invalid = params.clone();
        *select(&mut invalid) = BASE64.encode([1_u8]);

        let error = rsa_params_to_private_key(&invalid).unwrap_err();

        assert!(error.to_string().contains(field), "got: {error:#}");
    }
}

#[test]
fn runner_credentials_have_structural_equality() {
    let credentials = test_credentials();

    assert_eq!(credentials.clone(), credentials);
}
```

Вынести существующее создание `RunnerCredentials` из `credentials_save_load_roundtrip` в локальный `fn test_credentials() -> RunnerCredentials`, чтобы тесты не дублировали fixture setup.

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `cargo test config::config_test::rsa_validation_rejects_inconsistent_derived_parameters -- --exact`

Expected: FAIL, потому что текущий loader игнорирует `dp`, `dq`, `inverseQ` (и до добавления derives тест equality не компилируется).

- [ ] **Step 3: Derive structural equality and validate every RSA component**

В `src/config.rs` добавить `PartialEq, Eq` к четырём credential structs. Обновить `rsa_params_to_private_key` по следующей схеме; сообщения называют только поле, никогда его значение:

```rust
pub fn rsa_params_to_private_key(params: &RsaParameters) -> Result<RsaPrivateKey> {
    let n = decode_biguint(&params.modulus, "modulus")?;
    let e = decode_biguint(&params.exponent, "exponent")?;
    let d = decode_biguint(&params.d, "d")?;
    let p = decode_biguint(&params.p, "p")?;
    let q = decode_biguint(&params.q, "q")?;
    let dp = decode_biguint(&params.dp, "dp")?;
    let dq = decode_biguint(&params.dq, "dq")?;
    let inverse_q = decode_biguint(&params.inverse_q, "inverseQ")?;

    let key = RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .context("constructing RSA private key from parameters")?;
    key.validate().context("validating RSA private key")?;

    let expected_dp = key.dp().context("RSA key missing dp component")?;
    let expected_dq = key.dq().context("RSA key missing dq component")?;
    let expected_inverse_q = key
        .qinv()
        .context("RSA key missing inverseQ component")?
        .to_biguint()
        .context("RSA inverseQ is negative")?;

    anyhow::ensure!(&dp == expected_dp, "RSA parameter 'dp' is inconsistent");
    anyhow::ensure!(&dq == expected_dq, "RSA parameter 'dq' is inconsistent");
    anyhow::ensure!(
        inverse_q == expected_inverse_q,
        "RSA parameter 'inverseQ' is inconsistent"
    );

    Ok(key)
}
```

Существующие `rsa_key_roundtrip` и `jwt_signing_survives_key_roundtrip` должны продолжить использовать этот же единственный validation path.

- [ ] **Step 4: Run config tests**

Run: `cargo test config_test`

Expected: PASS; corrupted derived values отклоняются, валидный round-trip/JWT остаются зелёными.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs src/config_test.rs
git commit -m "fix: validate complete RSA parameters"
```

---

### Task 2: Parse and Validate Official Runner Sources

**Files:**
- Create: `src/import.rs`
- Create: `src/import/source.rs`
- Create: `src/import/source_test.rs`
- Create: `src/import/test_support.rs`
- Create: `tests/fixtures/official-runner-v2/.runner`
- Create: `tests/fixtures/official-runner-v2/.credentials`
- Create: `tests/fixtures/official-runner-v2/.credentials_rsaparams`
- Modify: `src/lib.rs:1-10`

**Interfaces:**
- Consumes: `RunnerCredentials`, `RunnerInfo`, `OAuthCredentials`, `RsaParameters`, `rsa_params_to_private_key` from Task 1; official runner 2.337.0 field names.
- Produces:
  - `pub enum ImportError` with exact variants/categories listed below.
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub(crate) struct RunnerIdentity { scope: String, pool_id: u64, agent_id: u64 }`.
  - `#[derive(Debug, Clone)] pub(crate) struct ValidatedRegistration { credentials: RunnerCredentials, identity: RunnerIdentity, canonical_source: PathBuf }`.
  - `pub(crate) fn read_regular_no_follow(path: &Path) -> std::io::Result<Vec<u8>>` for shared source/target reads.
  - `pub(crate) fn read_official_registration(source: &Path) -> Result<ValidatedRegistration, ImportError>`.

- [ ] **Step 1: Add exact synthetic official-runner fixtures**

Создать `.runner`:

```json
{
  "agentId": 42,
  "agentName": "official-runner",
  "poolId": 1,
  "poolName": "Default",
  "disableUpdate": true,
  "serverUrl": "https://pipelines.actions.githubusercontent.com/tenant-id",
  "gitHubUrl": "https://github.com/example/repository",
  "workFolder": "_work",
  "useV2Flow": true,
  "serverUrlV2": "https://broker.actions.githubusercontent.com"
}
```

Создать `.credentials`:

```json
{
  "scheme": "OAuth",
  "data": {
    "clientId": "00000000-0000-4000-8000-000000000042",
    "authorizationUrl": "https://vstoken.actions.githubusercontent.com/tenant-id",
    "requireFipsCryptography": "False"
  }
}
```

Создать `.credentials_rsaparams` с детерминированным synthetic RSA example (`p=61`, `q=53`, `n=3233`, `e=17`, `d=2753`, `dp=53`, `dq=49`, `qInv=38`):

```json
{
  "D": "CsE=",
  "DP": "NQ==",
  "DQ": "MQ==",
  "Exponent": "EQ==",
  "InverseQ": "Jg==",
  "Modulus": "DKE=",
  "P": "PQ==",
  "Q": "NQ=="
}
```

Эти значения тестовые и не используются для подписи production JWT.

- [ ] **Step 2: Define typed errors and write failing happy-path parser test**

В `src/import.rs` определить категории так, чтобы `Display` всегда начинался со стабильной строки:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("invalid-source: {0}")]
    InvalidSource(String),
    #[error("unsupported-registration: {0}")]
    UnsupportedRegistration(String),
    #[error("identity-conflict: {0}")]
    IdentityConflict(String),
    #[error("target-busy: {0}")]
    TargetBusy(String),
    #[error("write-failed: {0}")]
    WriteFailed(String),
}

impl ImportError {
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidSource(_) => "invalid-source",
            Self::UnsupportedRegistration(_) => "unsupported-registration",
            Self::IdentityConflict(_) => "identity-conflict",
            Self::TargetBusy(_) => "target-busy",
            Self::WriteFailed(_) => "write-failed",
        }
    }
}
```

Подключить `pub mod import;` в `src/lib.rs`. В `source_test.rs` написать:

```rust
use std::path::Path;

use rsa::traits::PublicKeyParts;

use crate::config::rsa_params_to_private_key;
use crate::import::test_support::fixture_path;

use super::*;

#[test]
fn reads_supported_v2_registration_without_changing_identity() {
    let registration = read_official_registration(&fixture_path()).unwrap();

    assert_eq!(registration.credentials.info.agent_id, 42);
    assert_eq!(registration.credentials.info.agent_name, "official-runner");
    assert_eq!(registration.credentials.info.pool_id, 1);
    assert_eq!(
        registration.credentials.info.server_url,
        "https://pipelines.actions.githubusercontent.com/tenant-id"
    );
    assert_eq!(
        registration.credentials.info.server_url_v2,
        "https://broker.actions.githubusercontent.com"
    );
    assert_eq!(
        registration.credentials.info.git_hub_url,
        "https://github.com/example/repository"
    );
    assert_eq!(registration.credentials.info.work_folder, "_work");
    assert!(registration.credentials.info.use_v2_flow);
    assert_eq!(registration.credentials.oauth.scheme, "OAuth");
    assert_eq!(registration.identity.scope, "github.com/example/repository");

    let key = rsa_params_to_private_key(&registration.credentials.rsa_params).unwrap();
    assert_eq!(key.n().to_bytes_be(), [0x0c, 0xa1]);
    assert_eq!(key.e().to_bytes_be(), [0x11]);
}
```

- [ ] **Step 3: Write the full failing eligibility matrix**

В `src/import/test_support.rs` добавить общие helpers, доступные всем четырём importer unit-test modules:

```rust
use std::path::{Path, PathBuf};

pub(crate) fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/official-runner-v2")
}

pub(crate) fn copy_fixture() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    for name in [".runner", ".credentials", ".credentials_rsaparams"] {
        std::fs::copy(fixture_path().join(name), temp.path().join(name)).unwrap();
    }
    temp
}

pub(crate) fn mutate_json(
    source: &Path,
    name: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let path = source.join(name);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    mutate(&mut value);
    std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

pub(crate) fn fixture_credentials() -> crate::config::RunnerCredentials {
    crate::import::source::read_official_registration(&fixture_path())
        .unwrap()
        .credentials
}

pub(crate) fn write_chimera_credentials(root: &Path, name: &str) {
    crate::config::save_runner_credentials(
        &root.join("runners"),
        name,
        &fixture_credentials(),
    )
    .unwrap();
}
```

В `import.rs` подключить его как `#[cfg(test)] pub(crate) mod test_support;`. В `source_test.rs` добавить `use crate::import::test_support::{copy_fixture, mutate_json};` (`fixture_path` уже импортирован в Step 2) и локальный category assertion:

```rust
fn assert_category(source: &Path, category: &str) -> String {
    let error = read_official_registration(source).unwrap_err();
    assert_eq!(error.category(), category);
    format!("{error:#}")
}
```

Реализовать отдельные tests со следующими точными действиями и assertions:

| Test | Mutation | Expected category |
|---|---|---|
| `rejects_missing_or_symlinked_required_file` | удалить `.runner`; во втором temp удалить `.credentials` и создать на её месте symlink на fixture | `invalid-source` в обоих случаях |
| `rejects_malformed_json_and_base64_without_echoing_values` | записать `{` в `.runner`; во втором temp поставить `D = "not-base64-SECRET_RSA"` | `invalid-source`; diagnostic не содержит `SECRET_RSA` |
| `rejects_zero_agent_or_pool_id` | отдельные cases `agentId = 0`, `poolId = 0` | `invalid-source` |
| `rejects_non_oauth_and_unknown_auth_metadata` | `scheme = "PAT"`; отдельный case `data.SECRET_AUTH_KEY = "SECRET_CLIENT_ID"` | `unsupported-registration`; diagnostic не содержит secret key/value markers |
| `rejects_fips_required_and_auth_migration` | `requireFipsCryptography = "True"`; `enableAuthMigrationByDefault = "true"`; `authorizationUrlV2 = "SECRET_AUTH_URL"`; отдельный case с пустым `authorizationUrlV2`; отдельные empty sibling files `.runner_migrated` и `.credentials_migrated` | `unsupported-registration`; diagnostic не содержит `SECRET_AUTH_URL` |
| `rejects_ephemeral_jit_legacy_and_ghes` | отдельные cases `ephemeral = true`; `gitHubUrl = ""`; удалить `gitHubUrl`; `useV2Flow = false`; удалить `useV2Flow`; удалить `serverUrlV2`; `IsHostedServer = false`; `gitHubUrl = "https://ghe.example/org/repo"`; `gitHubUrl = "https://github.com/org"` | `unsupported-registration` |
| `rejects_non_https_or_non_actions_endpoints` | по одному case для `serverUrl`, `serverUrlV2`, `authorizationUrl`: HTTP URL и HTTPS host `example.invalid` | `unsupported-registration` |
| `accepts_inactive_auth_migration_flag` | добавить `enableAuthMigrationByDefault="false"` без `authorizationUrlV2` | success, output OAuth fields равны baseline |
| `accepts_known_non_auth_runner_fields` | добавить `skipSessionRecover=true`, `monitorSocketAddress="/tmp/runner.sock"`, `IsHostedServer=true`, `useRunnerAdminFlow=true`; оставить fixture `poolName`/`disableUpdate` | success, output credentials равны baseline |
| `allows_same_numeric_agent_id_to_be_scoped_by_repo` | загрузить два source с agent ID 42 и repo URLs `github.com/example/one`, `github.com/example/two` | `RunnerIdentity` различаются только `scope` |

Symlink test пометить `#[cfg(unix)]` и создать ссылку через `std::os::unix::fs::symlink`. Каждый redaction assertion проверяет, что `format!("{error:#}")` не содержит injected strings `SECRET_RSA`, `SECRET_AUTH_KEY`, `SECRET_CLIENT_ID` и `SECRET_AUTH_URL`.

- [ ] **Step 4: Run parser tests and verify they fail**

Run: `cargo test import::source::source_test`

Expected: FAIL/compile failure, потому что `source.rs` и parser types ещё отсутствуют.

- [ ] **Step 5: Implement exact official schemas and no-follow reads**

В `source.rs` объявить structs с `#[serde(deny_unknown_fields)]`; casing задавать явно, не выводить из C# property names:

```rust
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OfficialRunnerSettings {
    agent_id: u64,
    agent_name: String,
    pool_id: u64,
    #[serde(default)]
    pool_name: Option<String>,
    #[serde(default)]
    skip_session_recover: bool,
    #[serde(default)]
    disable_update: bool,
    #[serde(default)]
    ephemeral: bool,
    server_url: String,
    #[serde(default)]
    git_hub_url: String,
    work_folder: String,
    #[serde(default)]
    use_v2_flow: bool,
    #[serde(default)]
    use_runner_admin_flow: bool,
    #[serde(default)]
    server_url_v2: String,
    #[serde(default)]
    monitor_socket_address: Option<String>,
    #[serde(default, rename = "IsHostedServer")]
    is_hosted_server: Option<bool>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OfficialCredentialData {
    scheme: String,
    data: std::collections::BTreeMap<String, String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OfficialRsaParameters {
    #[serde(rename = "D")] d: String,
    #[serde(rename = "DP")] dp: String,
    #[serde(rename = "DQ")] dq: String,
    #[serde(rename = "Exponent")] exponent: String,
    #[serde(rename = "InverseQ")] inverse_q: String,
    #[serde(rename = "Modulus")] modulus: String,
    #[serde(rename = "P")] p: String,
    #[serde(rename = "Q")] q: String,
}
```

`read_regular_no_follow` обязан сделать обе проверки и убедиться, что path не сменил inode между ними:

```rust
pub(crate) fn read_regular_no_follow(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential path is not a regular file",
        ));
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let after = file.metadata()?;
    if !after.is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential path changed while opening",
        ));
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
```

Ошибки парсинга оборачивать безопасным сообщением вида `unable to parse .credentials at line N column M`, без исходной строки JSON. В `src/import.rs` объявить `mod source;`, а внизу `source.rs` подключить тесты стандартным project pattern:

```rust
#[cfg(test)]
#[path = "source_test.rs"]
mod source_test;
```

- [ ] **Step 6: Implement the eligibility gate with a closed auth allowlist**

Реализовать следующие точные правила:

```rust
const REQUIRED_AUTH_KEYS: [&str; 2] = ["clientId", "authorizationUrl"];
const RECOGNIZED_AUTH_KEYS: [&str; 5] = [
    "clientId",
    "authorizationUrl",
    "requireFipsCryptography",
    "enableAuthMigrationByDefault",
    "authorizationUrlV2",
];
```

- `scheme == "OAuth"`; `clientId` — непустой UUID, но сохраняется исходной строкой.
- `requireFipsCryptography` отсутствует либо case-insensitive `false`; `true` даёт `unsupported-registration`, невалидная boolean-строка — `invalid-source`.
- case-insensitive `true` в `enableAuthMigrationByDefault`, любое присутствие `authorizationUrlV2` (включая пустое значение), либо наличие `.runner_migrated`/`.credentials_migrated` даёт `unsupported-registration`; невалидная boolean-строка migration flag даёт `invalid-source`.
- Любой ключ вне `RECOGNIZED_AUTH_KEYS` даёт generic `unsupported-registration`; ни имя, ни значение неизвестного ключа не включаются в ошибку.
- `ephemeral=true`, пустой repo URL/JIT, `useV2Flow=false`, `IsHostedServer=false`, не-`OAuth`, org scope и GHES дают `unsupported-registration`.
- `useRunnerAdminFlow`, `poolName`, `skipSessionRecover`, `disableUpdate`, `monitorSocketAddress` — documented non-auth provenance/local settings; они допускаются, но не переносятся, поскольку runtime Chimera их не использует.
- `agentId > 0`, `poolId > 0`, `agentName` и `workFolder` непустые.
- `gitHubUrl` — ровно `https://github.com/{owner}/{repo}` без query/fragment/userinfo/port; identity scope — lowercased `github.com/owner/repo`, сохранённый URL остаётся byte-for-byte исходным.
- `serverUrl`, `serverUrlV2`, `authorizationUrl` парсятся через `reqwest::Url`, имеют `https`, без userinfo/query/fragment/explicit port и host `actions.githubusercontent.com` либо suffix `.actions.githubusercontent.com`; `serverUrl` и `authorizationUrl` требуют non-root path.
- RSA преобразуется в `RsaParameters`, проходит Task 1 validation, затем канонизируется через `private_key_to_rsa_params`; decoded значения всех восьми компонентов сравниваются с source до возврата.

- [ ] **Step 7: Run parser tests**

Run: `cargo test import::source::source_test`

Expected: PASS; fixture принимается, весь unsupported/malformed matrix отклоняется с правильной категорией и без secret values.

- [ ] **Step 8: Commit**

```bash
git add src/import.rs src/import tests/fixtures/official-runner-v2 src/lib.rs
git commit -m "feat: validate official runner registrations"
```

---

### Task 3: Send Persistent Broker Session Semantics

**Files:**
- Modify: `src/github/broker.rs:108-195`
- Modify: `src/github/broker_test.rs:42-118`

**Interfaces:**
- Consumes: текущий `BrokerClient::connect(client, server_url, token_manager, agent_id, agent_name)`.
- Produces: та же сигнатура `BrokerClient::connect`; JSON `agent.ephemeral` всегда `false`, поскольку поддерживаемые registration paths создают/import persistent runners.

- [ ] **Step 1: Change the request-shape test first**

В `connect_request_body_shape` заменить ожидание и усилить matcher:

```rust
.and(body_partial_json(serde_json::json!({
    "useFipsEncryption": false,
    "agent": {
        "id": 1,
        "name": "r0",
        "version": RUNNER_VERSION,
        "ephemeral": false,
        "status": 0
    }
})))
```

Переименовать test в `connect_marks_persistent_runner_as_non_ephemeral`.

- [ ] **Step 2: Run the regression test and verify it fails**

Run: `cargo test github::broker::broker_test::connect_marks_persistent_runner_as_non_ephemeral -- --exact`

Expected: FAIL; current request sends `"ephemeral": true`.

- [ ] **Step 3: Make the minimal protocol fix**

В `CreateSessionRequest` construction заменить только значение:

```rust
agent: SessionAgent {
    id: agent_id,
    name: agent_name.to_string(),
    version: RUNNER_VERSION.to_string(),
    os_description: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
    ephemeral: false,
    status: 0,
},
```

Не добавлять registration/unregistration API calls и не менять stored identity.

- [ ] **Step 4: Run broker tests**

Run: `cargo test github::broker::broker_test`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/github/broker.rs src/github/broker_test.rs
git commit -m "fix: create persistent broker sessions"
```

---

### Task 4: Add a Shared Exclusive Root Lock

**Files:**
- Create: `src/storage.rs`
- Create: `src/storage_test.rs`
- Modify: `src/config.rs:97-162`
- Modify: `src/lib.rs:1-10`
- Modify: `src/daemon.rs:13-16,203-216`
- Modify: `src/daemon_test.rs:9-82`
- Modify: `src/cli.rs:8-10,91-129`
- Modify: `src/github/registration.rs:194-289`
- Modify: `src/github/registration_test.rs:101-123`

**Interfaces:**
- Consumes: existing `libc`, `ChimeraPaths`, daemon/register/unregister entry points.
- Produces:
  - `ChimeraPaths::root_lock_file(&self) -> PathBuf` returning `<root>/.chimera.lock`.
  - `#[derive(Debug)] pub(crate) struct RootLock { _file: std::fs::File }`.
  - `pub(crate) enum RootLockError { Busy, UnsafeRoot(String), Io(std::io::Error) }`.
  - `RootLock::acquire(root: &Path) -> Result<RootLock, RootLockError>`.
  - `validate_existing_root(root: &Path) -> Result<(), RootLockError>` with no writes.

- [ ] **Step 1: Write lock and root-safety tests**

Создать `src/storage_test.rs`:

```rust
#[test]
fn second_writer_is_rejected_without_blocking() {
    let root = tempfile::tempdir().unwrap();
    let first = RootLock::acquire(root.path()).unwrap();

    let error = RootLock::acquire(root.path()).unwrap_err();

    assert!(matches!(error, RootLockError::Busy));
    drop(first);
    RootLock::acquire(root.path()).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_symlink_and_group_or_world_writable_root() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let parent = tempfile::tempdir().unwrap();
    let real_root = parent.path().join("real-root");
    std::fs::create_dir(&real_root).unwrap();
    std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let linked_root = parent.path().join("linked-root");
    symlink(&real_root, &linked_root).unwrap();

    assert!(matches!(
        RootLock::acquire(&linked_root).unwrap_err(),
        RootLockError::UnsafeRoot(_)
    ));

    std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        RootLock::acquire(&real_root).unwrap_err(),
        RootLockError::UnsafeRoot(_)
    ));
    std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_lock_file_without_touching_target() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = root.path().join("outside");
    std::fs::write(&outside, b"unchanged").unwrap();
    symlink(&outside, root.path().join(".chimera.lock")).unwrap();

    assert!(RootLock::acquire(root.path()).is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");
}

#[cfg(unix)]
#[test]
fn creates_new_root_and_lock_with_private_modes() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("new-root");

    let lock = RootLock::acquire(&root).unwrap();

    assert_eq!(std::fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(
        std::fs::metadata(root.join(".chimera.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(lock);
}
```

Добавить async test в `registration_test.rs`: удержать `RootLock`, создать runner dir/config, вызвать `unregister`, проверить ошибку и неизменность каталога/config.

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test storage_test && cargo test github::registration::registration_test::unregister_refuses_busy_root -- --exact`

Expected: FAIL/compile failure, потому что `storage` и root lock отсутствуют.

- [ ] **Step 3: Implement root validation and POSIX flock without a new crate**

Определить safe diagnostics, которые не включают содержимое файлов:

```rust
#[derive(Debug, thiserror::Error)]
pub(crate) enum RootLockError {
    #[error("root storage is busy")]
    Busy,
    #[error("unsafe root: {0}")]
    UnsafeRoot(String),
    #[error("root storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
```

`validate_existing_root` проверяет `symlink_metadata`: final component не symlink, это directory, `metadata.uid() == unsafe { libc::geteuid() }`, `(metadata.mode() & 0o022) == 0`. Для отсутствующего root подняться до ближайшего существующего ancestor и создать каждый missing component по очереди non-recursive `DirBuilderExt::mode(0o700)`, сразу выставляя `Permissions::from_mode(0o700)` до перехода к следующему component. Если component возник параллельно, не chmod-ить его: повторно проверить `symlink_metadata`, ownership/type и отсутствие group/world-write; symlink либо unsafe directory отклонить. После построения цепочки повторный `symlink_metadata` + `validate_existing_root` закрывает substitution между create и use. Restrictive umask может убрать owner bits из `mkdir/open`, поэтому каждый **новый** объект получает `set_permissions`/`File::set_permissions` до первой записи; существующие объекты никогда не chmod-ятся.

Lock file открывать через `create_new` с fallback на existing, чтобы точно знать, когда допустим `fchmod`:

```rust
fn open_lock_file(path: &Path) -> Result<std::fs::File, RootLockError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let open_new = || {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok::<_, std::io::Error>(file)
    };

    match open_new() {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)
                .map_err(RootLockError::Io)
        }
        Err(error) => Err(RootLockError::Io(error)),
    }
}

let file = open_lock_file(&root.join(".chimera.lock"))?;
let metadata = file.metadata()?;
if !metadata.is_file()
    || metadata.uid() != unsafe { libc::geteuid() }
    || metadata.mode() & 0o077 != 0
{
    return Err(RootLockError::UnsafeRoot(
        "lock file is not private regular storage owned by the current user".into(),
    ));
}

let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
if result != 0 {
    let error = std::io::Error::last_os_error();
    let code = error.raw_os_error();
    if code == Some(libc::EWOULDBLOCK) || code == Some(libc::EAGAIN) {
        return Err(RootLockError::Busy);
    }
    return Err(RootLockError::Io(error));
}
```

Добавить нужные `MetadataExt`/`AsRawFd` imports. File descriptor удерживается полем `_file`; отдельный `Drop`/unlink не нужен, чтобы inode lock не менялся между writers. Внизу `storage.rs` подключить `storage_test.rs` через обязательный `#[cfg(test)] #[path = "storage_test.rs"] mod storage_test;`, а в `lib.rs` объявить private `mod storage;`.

- [ ] **Step 4: Wire the same lock into every mutating lifecycle**

Заменить `Daemon::new` на constructor, который берёт lock **до** чтения config и хранит guard в `Daemon`; иначе `start` может прочитать старый config, проиграть race importer-у, затем получить lock и запустить stale runner list:

Добавить `load_config` к импорту из `crate::config` и `use crate::storage::RootLock;`, затем заменить поля `Daemon` и `Daemon::new` следующим кодом; существующий `Daemon::run` остаётся без изменений и удерживает guard через поле struct:

```rust
pub struct Daemon {
    paths: ChimeraPaths,
    config: ChimeraConfig,
    _root_lock: RootLock,
}

impl Daemon {
    pub fn load(paths: ChimeraPaths) -> Result<Self> {
        let root_lock =
            RootLock::acquire(&paths.root).context("acquiring root storage lock")?;
        let config = load_config(&paths.config_file()).context("loading config")?;

        Ok(Self {
            paths,
            config,
            _root_lock: root_lock,
        })
    }

    pub fn config(&self) -> &ChimeraConfig {
        &self.config
    }
}
```

В `cli.rs` убрать `ChimeraConfig` и `load_config` из imports и не читать config отдельно: locked `Daemon` должен существовать до обращения к tracing config и жить до завершения `run_start`:

```rust
Command::Start { root } => {
    let daemon = Daemon::load(ChimeraPaths::new(root))?;
    init_tracing(&daemon.config().daemon);
    run_start(daemon).await
}

async fn run_start(daemon: Daemon) -> Result<()> {
    if daemon.config().runners.is_empty() {
        bail!("no runners registered. Use 'chimera register' first.");
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => info!("received SIGINT"),
                    _ = sigterm.recv() => info!("received SIGTERM"),
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to register SIGTERM handler, using SIGINT only");
                let _ = ctrl_c.await;
                info!("received SIGINT");
            }
        }
        let _ = shutdown_tx.send(true);
    });

    daemon.run(shutdown_rx).await
}
```

Дополнительно:

- `register`: получить `RootLock` до первого HTTP request, чтобы remote registration не произошла при работающем daemon.
- `unregister`: получить `RootLock` до проверки/удаления runner directory.
- В register/unregister не проглатывать malformed config через `unwrap_or_default()`. До появления `load_config_if_exists` в Task 5 использовать `let mut config = if config_path.exists() { load_config(&config_path)? } else { ChimeraConfig::default() };` в `register` и `if config_path.exists() { let mut config = load_config(&config_path)?; config.runners.retain(|runner| runner != name); save_config(&config_path, &config)?; }` в `unregister`; Task 5 заменит обе ветки новым no-follow API.
- `PidLock` оставить: он нужен существующему status display, но больше не является concurrency primitive.

- [ ] **Step 5: Test daemon and registration contention**

Добавить в `daemon_test.rs` оба теста, чтобы доказать порядок read/lock и lifetime guard:

```rust
#[test]
fn daemon_load_refuses_busy_root_before_reading_config() {
    let root = TempDir::new().unwrap();
    let paths = ChimeraPaths::new(root.path().to_path_buf());
    let config_path = paths.config_file();
    let _held = RootLock::acquire(root.path()).unwrap();

    let error = match Daemon::load(paths) {
        Ok(_) => panic!("daemon unexpectedly acquired a busy root"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("root storage is busy"));
    assert!(!config_path.exists(), "config was read/created before locking");
}

#[test]
fn daemon_holds_root_lock_for_its_lifetime() {
    let root = TempDir::new().unwrap();
    let paths = ChimeraPaths::new(root.path().to_path_buf());
    let daemon = Daemon::load(paths).unwrap();

    assert!(matches!(
        RootLock::acquire(root.path()).unwrap_err(),
        RootLockError::Busy
    ));
    drop(daemon);
    RootLock::acquire(root.path()).unwrap();
}
```

В `registration_test.rs` проверить, что busy unregister не удаляет ни файлы, ни runner name.

Run: `cargo test storage_test && cargo test daemon::daemon_test::daemon_load_refuses_busy_root_before_reading_config -- --exact && cargo test daemon::daemon_test::daemon_holds_root_lock_for_its_lifetime -- --exact && cargo test github::registration::registration_test::unregister_refuses_busy_root -- --exact`

Expected: PASS.

- [ ] **Step 6: Run affected module tests**

Run: `cargo test daemon_test && cargo test github::registration::registration_test`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/storage.rs src/storage_test.rs src/config.rs src/lib.rs src/daemon.rs src/daemon_test.rs src/cli.rs src/github/registration.rs src/github/registration_test.rs
git commit -m "feat: lock chimera root mutations"
```

---

### Task 5: Build a Side-Effect-Free Import Plan

**Files:**
- Create: `src/import/target.rs`
- Create: `src/import/target_test.rs`
- Modify: `src/import.rs`
- Modify: `src/config.rs:170-206`
- Modify: `src/config_test.rs:55-100`
- Modify: `src/github/registration.rs:9-12,248-285`

**Interfaces:**
- Consumes: `read_official_registration`, `ValidatedRegistration`, `RunnerIdentity`; `validate_existing_root` from Task 4.
- Produces:
  - `pub fn load_config_if_exists(path: &Path) -> anyhow::Result<Option<ChimeraConfig>>` (never writes).
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub(crate) enum TargetDisposition { New, Resume, AlreadyImported }`.
  - `#[derive(Debug)] pub(crate) struct PreservedConfig { model: ChimeraConfig, document: toml::Table, original_mode: Option<u32> }`; `document` удерживает unknown settings, которые не входят в `ChimeraConfig`.
  - `#[derive(Debug)] pub(crate) struct PreparedImport { name: String, registration: ValidatedRegistration, paths: ChimeraPaths, config: PreservedConfig, disposition: TargetDisposition }`.
  - `pub(crate) fn prepare_import(source: &Path, name: &str, root: &Path) -> Result<PreparedImport, ImportError>` (strictly read-only).

- [ ] **Step 1: Write a failing no-side-effect config test**

Добавить в `config_test.rs`:

```rust
#[test]
fn optional_config_load_does_not_create_missing_file() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");

    let config = load_config_if_exists(&config_path).unwrap();

    assert!(config.is_none());
    assert!(!config_path.exists());
}

#[cfg(unix)]
#[test]
fn optional_config_load_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside.toml");
    std::fs::write(&outside, "runners = []\n").unwrap();
    let config_path = tmp.path().join("config.toml");
    symlink(&outside, &config_path).unwrap();

    assert!(load_config_if_exists(&config_path).is_err());
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "runners = []\n");
}
```

- [ ] **Step 2: Implement the optional config loader and preserve existing behavior**

```rust
pub fn load_config_if_exists(path: &Path) -> Result<Option<ChimeraConfig>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("checking {}", path.display())),
    };
    anyhow::ensure!(
        !metadata.file_type().is_symlink() && metadata.file_type().is_file(),
        "config path is not a regular file"
    );

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening config from {}", path.display()))?;
    let opened = file.metadata()?;
    anyhow::ensure!(
        opened.is_file() && metadata.dev() == opened.dev() && metadata.ino() == opened.ino(),
        "config path changed while opening"
    );
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("reading config from {}", path.display()))?;
    let config = toml::from_str(&text)
        .with_context(|| format!("parsing config from {}", path.display()))?;
    Ok(Some(config))
}

pub fn load_config(path: &Path) -> Result<ChimeraConfig> {
    if let Some(config) = load_config_if_exists(path)? {
        return Ok(config);
    }
    let config = ChimeraConfig::default();
    save_config(path, &config)
        .with_context(|| format!("writing default config to {}", path.display()))?;
    Ok(config)
}
```

Перевести registration call sites с промежуточного Task 4 `exists()` branch на новый API, не проглатывая malformed config:

```rust
// register
let mut config = load_config_if_exists(&config_path)?.unwrap_or_default();
if !config.runners.contains(&name.to_string()) {
    config.runners.push(name.to_string());
}
save_config(&config_path, &config).context("saving config")?;

// unregister
if let Some(mut config) = load_config_if_exists(&config_path)? {
    config.runners.retain(|runner| runner != name);
    save_config(&config_path, &config)?;
}
```

Run: `cargo test config::config_test::optional_config_load_does_not_create_missing_file -- --exact && cargo test config::config_test::load_config_creates_default_file_when_missing -- --exact && cargo test github::registration::registration_test`

Expected: PASS; новый API side-effect-free, старый `load_config` contract сохранён, malformed registration config больше не заменяется defaults.

- [ ] **Step 3: Write failing local-name and target-state tests**

В `target_test.rs` импортировать `crate::import::test_support::{copy_fixture, fixture_path, mutate_json, write_chimera_credentials}` и сначала реализовать boundary и missing-root cases полностью:

```rust
#[test]
fn accepts_ascii_local_name_boundaries() {
    for name in ["a".to_string(), "a".repeat(128)] {
        let root_parent = tempfile::tempdir().unwrap();
        let root = root_parent.path().join("missing-root");
        let prepared = prepare_import(&fixture_path(), &name, &root).unwrap();
        assert_eq!(prepared.disposition, TargetDisposition::New);
        assert!(!root.exists());
    }
}

#[test]
fn rejects_invalid_local_names() {
    let long_name = "a".repeat(129);
    for name in ["", ".", "..", "../runner", "runner/name", "/absolute", "раннер", long_name.as_str()] {
        let root_parent = tempfile::tempdir().unwrap();
        let root = root_parent.path().join("missing-root");
        let error = prepare_import(&fixture_path(), name, &root).unwrap_err();
        assert_eq!(error.category(), "invalid-source");
        assert!(!root.exists());
    }
}

#[test]
fn dry_plan_for_missing_root_does_not_create_root_or_config() {
    let root_parent = tempfile::tempdir().unwrap();
    let root = root_parent.path().join("missing-root");

    let prepared = prepare_import(&fixture_path(), "local", &root).unwrap();

    assert_eq!(prepared.disposition, TargetDisposition::New);
    assert!(!root.exists());
    assert!(!root.join("config.toml").exists());
}
```

Остальные tests используют Task 2 `copy_fixture`/`mutate_json` helpers и следующие exact arrangements/assertions:

| Test | Arrange | Assert |
|---|---|---|
| `rejects_source_equal_to_inside_or_containing_target` | три roots: target равен source; target nested под source; source nested под `<root>/runners/<name>` | `invalid-source`; before/after recursive entry list и file bytes равны |
| `exact_target_plus_config_is_already_imported` | скопировать ожидаемые Chimera JSON в `runners/local`, config `runners=["local"]` | `TargetDisposition::AlreadyImported` |
| `exact_target_without_config_entry_is_resume` | тот же полный каталог, config без `local` | `TargetDisposition::Resume`; inode/bytes не меняются |
| `same_name_with_different_credentials_is_conflict` | existing `runners/local` с другим RSA modulus | `identity-conflict`; target/config bytes не меняются |
| `same_identity_under_another_name_is_conflict` | exact credentials в `runners/other`, source импортируется как `local` | `identity-conflict`; оба каталога неизменны |
| `same_agent_id_in_another_repo_is_not_conflict` | existing agent 42 с `gitHubUrl=https://github.com/example/other`, source agent 42 с fixture repo | `TargetDisposition::New` |
| `config_name_without_credentials_is_conflict` | config содержит `local`, `runners/local` отсутствует | `identity-conflict`; missing directory не создаётся |
| `rejects_symlink_in_runners_target_or_credential_file` | Unix cases: `runners` symlink; target dir symlink; `runner.json` symlink | `write-failed`; link target bytes не меняются |
| `malformed_existing_config_or_runner_is_not_replaced` | malformed TOML с marker `SECRET_CONFIG`; отдельный root с malformed existing `credentials.json`, содержащим `SECRET_EXISTING_CREDENTIAL` | `write-failed`; malformed bytes остаются byte-for-byte; formatted errors не содержат оба marker |

Для unchanged assertions читать source, target и config bytes и `MetadataExt::ino()` до/после `prepare_import`; missing-root tests проверяют `!root.exists()`.

- [ ] **Step 4: Run target tests and verify they fail**

Run: `cargo test import::target::target_test`

Expected: FAIL/compile failure, потому что `target.rs`, `PreparedImport` и `prepare_import` отсутствуют.

- [ ] **Step 5: Implement name/path planning without filesystem writes**

Name validation должна быть независимой от path joining:

```rust
fn validate_local_name(name: &str) -> Result<(), ImportError> {
    let valid_length = (1..=128).contains(&name.len());
    let valid_chars = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid_length || !valid_chars || matches!(name, "." | "..") {
        return Err(ImportError::InvalidSource(
            "local name must be 1-128 ASCII characters from [A-Za-z0-9._-] and not '.' or '..'"
                .into(),
        ));
    }
    Ok(())
}
```

Реализовать `canonicalize_allow_missing`: подняться до ближайшего существующего ancestor, `canonicalize` его, затем вернуть missing normal components; `ParentDir`, `RootDir` или `Prefix` в missing suffix отклонять. `prepare_import` обязан сохранить `ChimeraPaths::new(canonical_root)`, а не исходный spelling `root`, и строить target из этого canonical path. Пересечение определяется обеими проверками `source.starts_with(target)` и `target.starts_with(source)`.

- [ ] **Step 6: Implement secure target inspection and identity collision rules**

- Existing root проходит read-only `validate_existing_root`; missing root не создаётся.
- Existing config читается no-follow одним string: отдельно parse в `ChimeraConfig` для validation и в `toml::Table` для value-preserving rewrite; сохранить `PermissionsExt::mode() & 0o777`. Любую TOML parse error сворачивать в generic `WriteFailed("unable to parse existing config.toml")`, не включая `toml::de::Error`, source line или raw text. Для missing config построить `toml::Table` сериализацией `ChimeraConfig::default()` только в памяти и поставить `original_mode=None`.
- `runners/`, каждый runner directory и три credential files проверяются через `symlink_metadata`; symlink отклоняется до `load`.
- Для JSON использовать тот же no-follow helper, вынесенный из `source.rs` в `pub(crate)` внутри `import`, чтобы source и target не расходились по безопасности; serde errors existing target превращать в generic `WriteFailed` с именем файла и line/column, но без source snippet/underlying error chain.
- Сканировать все каталоги непосредственно под `runners/`, а не только `config.runners`, чтобы orphan после crash тоже участвовал в identity conflict detection.
- Дубликаты в `config.runners`, имя в config без полного каталога и malformed existing credentials дают `write-failed`/`identity-conflict`, никогда `unwrap_or_default`.
- Exact credentials comparison использует `RunnerCredentials: Eq` из Task 1.
- Exact target + name in config => `AlreadyImported`; exact target + name absent => `Resume`; absent target + absent name => `New`.
- Existing target с другими credentials или config name без target => `IdentityConflict`.
- Для каждого existing credential set вычислять identity тем же canonical github.com repo parser, что и для source; malformed/non-repo existing URL даёт safe `WriteFailed`, а не raw URL в сообщении. Полный `(scope, pool_id, agent_id)` match под другим local name => `IdentityConflict`; match только `agent_id` при другом canonical scope => допустим.
- В `import.rs` объявить `mod target;`; внизу `target.rs` подключить `#[cfg(test)] #[path = "target_test.rs"] mod target_test;`.

После filesystem inspection свести решение к чистой функции; `existing` содержит только полностью и no-follow прочитанные sets, а duplicates/dangling config entries уже отклонены:

```rust
fn classify_disposition(
    name: &str,
    registration: &ValidatedRegistration,
    config: &PreservedConfig,
    existing: &std::collections::BTreeMap<String, RunnerCredentials>,
) -> Result<TargetDisposition, ImportError> {
    for (existing_name, credentials) in existing {
        if existing_name == name {
            continue;
        }
        let identity = identity_from_credentials(credentials).map_err(|()| {
            ImportError::WriteFailed(
                "unable to derive identity from existing runner credentials".into(),
            )
        })?;
        if identity == registration.identity {
            return Err(ImportError::IdentityConflict(
                "registration identity already exists under another local name".into(),
            ));
        }
    }

    let name_in_config = config.model.runners.iter().any(|runner| runner == name);
    match (existing.get(name), name_in_config) {
        (Some(credentials), true) if credentials == &registration.credentials => {
            Ok(TargetDisposition::AlreadyImported)
        }
        (Some(credentials), false) if credentials == &registration.credentials => {
            Ok(TargetDisposition::Resume)
        }
        (Some(_), _) => Err(ImportError::IdentityConflict(
            "local name already stores different credentials".into(),
        )),
        (None, true) => Err(ImportError::IdentityConflict(
            "local name is configured without a complete credential set".into(),
        )),
        (None, false) => Ok(TargetDisposition::New),
    }
}
```

`identity_from_credentials(&RunnerCredentials) -> Result<RunnerIdentity, ()>` вызывает shared repo-scope parser Task 2 и проверяет positive pool/agent IDs; unit error intentionally не несёт URL либо credential values.

- [ ] **Step 7: Run all read-only planning tests**

Run: `cargo test config_test && cargo test import::source::source_test && cargo test import::target::target_test`

Expected: PASS; ни один planning test не создаёт missing root/config и не меняет bytes существующих файлов.

- [ ] **Step 8: Commit**

```bash
git add src/config.rs src/config_test.rs src/github/registration.rs src/import.rs src/import/target.rs src/import/target_test.rs
git commit -m "feat: plan registration imports safely"
```

---

### Task 6: Commit Imports Transactionally and Recover on Retry

**Files:**
- Create: `src/import/commit.rs`
- Create: `src/import/commit_test.rs`
- Create: `src/import_test.rs`
- Modify: `src/import.rs`

**Interfaces:**
- Consumes: `PreparedImport` and `TargetDisposition` from Task 5; `RootLock` from Task 4; existing `save/load` models.
- Produces:
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum ImportStatus { Eligible, Imported, AlreadyImported }` и `ImportStatus::as_str() -> &'static str`, возвращающий соответственно `eligible`, `imported`, `already-imported`.
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct ImportOutcome { pub status: ImportStatus, pub local_name: String, pub agent_id: u64 }` with safe `Display`.
  - `fn map_root_lock_error(error: RootLockError) -> ImportError`: только `Busy` становится `TargetBusy("chimera root is locked by another writer")`; `UnsafeRoot` и `Io` становятся safe `WriteFailed` без raw credential content.
  - `pub fn import_official(source: &Path, name: &str, root: &Path, dry_run: bool) -> Result<ImportOutcome, ImportError>`.
  - `PreparedImport::outcome(&self, status: ImportStatus) -> ImportOutcome`.
  - Internal `enum CommitPoint` и `fn commit_with_checkpoint<F>(prepared: PreparedImport, checkpoint: F) -> Result<ImportOutcome, ImportError> where F: FnMut(CommitPoint) -> std::io::Result<()>`; production передаёт no-op closure, tests — deterministic failure.

- [ ] **Step 1: Write failing outcome, dry-run, idempotency and resume tests**

В `import_test.rs` импортировать `crate::import::test_support::fixture_path` и `super::*`:

```rust
#[cfg(unix)]
fn snapshot(path: &Path) -> (Vec<u8>, u64, std::time::SystemTime) {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).unwrap();
    (
        std::fs::read(path).unwrap(),
        metadata.ino(),
        metadata.modified().unwrap(),
    )
}

#[test]
fn dry_run_returns_eligible_without_creating_missing_root() {
    let root_parent = tempfile::tempdir().unwrap();
    let root = root_parent.path().join("missing-root");

    let outcome = import_official(&fixture_path(), "local-runner", &root, true).unwrap();

    assert_eq!(outcome.status, ImportStatus::Eligible);
    assert_eq!(outcome.local_name, "local-runner");
    assert!(!root.exists());
    assert_eq!(
        outcome.to_string(),
        "eligible: local-name=local-runner, agent-id=42; offline validation only"
    );
}

#[cfg(unix)]
#[test]
fn import_then_repeat_is_noop_without_rewriting_credentials_or_config() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("chimera");
    let first = import_official(&fixture_path(), "local-runner", &root, false).unwrap();
    assert_eq!(first.status, ImportStatus::Imported);

    let paths = [
        root.join("config.toml"),
        root.join("runners/local-runner/runner.json"),
        root.join("runners/local-runner/credentials.json"),
        root.join("runners/local-runner/rsa_params.json"),
    ];
    let before: Vec<_> = paths.iter().map(|path| snapshot(path)).collect();

    let second = import_official(&fixture_path(), "local-runner", &root, false).unwrap();
    let after: Vec<_> = paths.iter().map(|path| snapshot(path)).collect();

    assert_eq!(second.status, ImportStatus::AlreadyImported);
    assert_eq!(before, after);
    let config = load_config(&root.join("config.toml")).unwrap();
    assert_eq!(config.runners, vec!["local-runner".to_string()]);
}
```

В `import_test.rs` также добавить `busy_root_returns_target_busy_without_changes`: удержать `RootLock`, вызвать non-dry import, проверить category `target-busy`, отсутствие target runner directory и неизменные config/source bytes.

В `commit_test.rs` импортировать `crate::import::test_support::{copy_fixture, fixture_path, write_chimera_credentials}` и добавить три полных test cases:

- `published_credentials_without_config_are_completed_on_retry`: подготовить exact target без config entry, выполнить import, получить `Imported`, один runner name и неизменные credential inode/bytes.
- `config_update_preserves_daemon_cache_unknown_settings_and_existing_runners`: сохранить config с `daemon.log_format="json"`, `daemon.shutdown_timeout_secs=17`, `cache.max_gb=23`, `cache.cache_port=12345`, existing runner и unknown table `[future] enabled=true`; после import сравнить все known fields, повторно parse raw TOML и проверить `future.enabled=true`, а новый name добавлен последним ровно один раз.
- `target_created_after_prepare_is_never_replaced`: в callback на `AfterStagingValidation` создать final target directory с marker file и вернуть `Ok(())`; no-replace publish возвращает `identity-conflict`, marker inode/bytes остаются, config не содержит name, staging текущего вызова удалён.

- [ ] **Step 2: Write exhaustive fault-checkpoint tests**

Определить ожидаемые checkpoints:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitPoint {
    BeforeCreateStaging,
    AfterCreateStaging,
    AfterRunnerJson,
    AfterCredentialsJson,
    AfterRsaJson,
    AfterStagingValidation,
    AfterCredentialPublish,
    AfterConfigTempWrite,
    BeforeConfigPublish,
    AfterConfigPublish,
}
```

Table-driven test для каждого checkpoint создаёт новый root и заставляет callback вернуть `io::ErrorKind::Other` ровно в этой точке. Callback вызывается после события, обозначенного `After*`, и непосредственно до события, обозначенного `Before*`. Assertions:

- `BeforeCreateStaging`…`AfterStagingValidation`: final runner dir отсутствует, config unchanged/absent, staging текущего вызова удалён.
- `AfterCredentialPublish`, `AfterConfigTempWrite`, `BeforeConfigPublish`: final runner dir содержит полный loader-readable set, config не ссылается на name, config temp текущего вызова удалён.
- `AfterConfigPublish`: credentials полны, config уже содержит name ровно один раз; функция может сообщить `write-failed`, но состояние согласовано.
- Retry после `AfterConfigPublish` возвращает `AlreadyImported`; retry после остальных injected errors возвращает `Imported`; итоговый config содержит name ровно один раз.
- Existing source и ранее опубликованные directories не удаляются.

- [ ] **Step 3: Run commit tests and verify they fail**

Run: `cargo test import::commit::commit_test && cargo test import::import_test`

Expected: FAIL/compile failure, потому что transactional commit и публичный API отсутствуют.

- [ ] **Step 4: Implement secure staging and exact file modes**

Staging path: `<root>/.import-<uuid-v4>`; он находится на той же filesystem, что target. Создавать `create_dir` с `DirBuilderExt::mode(0o700)`, затем до создания JSON явно вызвать `std::fs::set_permissions(&staging_path, std::fs::Permissions::from_mode(0o700))?`, чтобы restrictive umask не снял owner bits. Каждый JSON писать через:

```rust
fn write_private_json<T: serde::Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()
}
```

После трёх файлов получить staging parent/basename без panic и проверить каталог штатным loader:

```rust
let staging_parent = staging_path.parent().ok_or_else(|| {
    ImportError::WriteFailed("staging directory has no parent".into())
})?;
let staging_name = staging_path
    .file_name()
    .and_then(std::ffi::OsStr::to_str)
    .ok_or_else(|| ImportError::WriteFailed("staging directory name is invalid".into()))?;
let loaded = load_runner_credentials(staging_parent, staging_name)
    .map_err(|_| ImportError::WriteFailed("staging credential validation failed".into()))?;
if loaded != prepared.registration.credentials {
    return Err(ImportError::WriteFailed(
        "staging credentials changed during serialization".into(),
    ));
}
std::fs::File::open(&staging_path)
    .and_then(|directory| directory.sync_all())
    .map_err(|_| ImportError::WriteFailed("unable to sync staging directory".into()))?;
```

Production-код не использует `unwrap`/`expect`. Cleanup guard удаляет только этот staging path и disarm-ится сразу после успешного rename.

- [ ] **Step 5: Publish credentials without overwriting**

- Создать/проверить `runners/` как owned non-symlink directory без group/world write; для нового `runners/` после `DirBuilderExt::mode(0o700)` вызвать `set_permissions(0o700)` до публикации credentials.
- Непосредственно перед rename повторно проверить `!target.try_exists()`; root lock сериализует cooperating writers, а OS no-replace primitive закрывает race с non-cooperating process.
- Публиковать каталог атомарным `renameat2(RENAME_NOREPLACE)` на Linux и `renamex_np(RENAME_EXCL)` на macOS; отсутствие primitive/unsupported filesystem даёт `write-failed`, но **никогда** fallback на overwrite-capable `std::fs::rename`. После success disarm staging cleanup guard и вызвать `sync_all()` на `runners/` до подготовки config.
- Никогда не вызывать `remove_dir_all(target)` и не использовать overwrite path.

```rust
fn c_path(path: &Path) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, target: &Path) -> std::io::Result<()> {
    let source = c_path(source)?;
    let target = c_path(target)?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace(source: &Path, target: &Path) -> std::io::Result<()> {
    let source = c_path(source)?;
    let target = c_path(target)?;
    let result = unsafe { libc::renamex_np(source.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(_source: &Path, _target: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace directory publish is unsupported on this platform",
    ))
}
```

Если `rename_noreplace` возвращает `AlreadyExists`/`EEXIST`, вернуть safe `IdentityConflict`; остальные ошибки — safe `WriteFailed`.
- Для `Resume` staging/publish полностью пропустить: exact existing directory остаётся нетронутым.

- [ ] **Step 6: Write and atomically replace config last**

Склонировать `PreparedImport.config.model.runners`, добавить `name` только если его нет, заменить только top-level `runners` в `PreparedImport.config.document` на `toml::Value::Array` из итоговых strings; все остальные known/unknown TOML values остаются в document. Temp path: `<root>/.config.toml.<uuid>.tmp`; сериализовать весь document, открыть через `create_new` + `O_NOFOLLOW`, затем до первой записи вызвать `File::set_permissions` с `original_mode` для существующего config или `0600` для нового, записать и вызвать `sync_all`. Это сохраняет прежний mode и гарантирует exact `0600` нового config даже при restrictive umask. Затем:

```rust
std::fs::rename(&temp_path, paths.config_file())?;
std::fs::File::open(&paths.root)?.sync_all()?;
```

Вызвать `checkpoint(CommitPoint::BeforeConfigPublish)` непосредственно перед `rename`, а `checkpoint(CommitPoint::AfterConfigPublish)` — сразу после него и до root `sync_all()`. Cleanup guard удаляет только config temp текущего вызова при ошибке. Ошибка до rename оставляет старый config; ошибка после credential publication оставляет полный orphan, который Task 5 распознаёт как `Resume`; ошибка после config rename оставляет полное согласованное состояние, которое retry распознаёт как `AlreadyImported`.

- [ ] **Step 7: Orchestrate dry-run and locked apply without TOCTOU**

Реализовать точную последовательность:

```rust
pub fn import_official(
    source: &Path,
    name: &str,
    root: &Path,
    dry_run: bool,
) -> Result<ImportOutcome, ImportError> {
    let initial = prepare_import(source, name, root)?;
    if dry_run {
        return Ok(initial.outcome(ImportStatus::Eligible));
    }

    let canonical_root = initial.paths.root.clone();
    let _lock = RootLock::acquire(&canonical_root).map_err(map_root_lock_error)?;
    let prepared = prepare_import(source, name, &canonical_root)?;

    match prepared.disposition {
        TargetDisposition::AlreadyImported => {
            Ok(prepared.outcome(ImportStatus::AlreadyImported))
        }
        TargetDisposition::New | TargetDisposition::Resume => {
            commit_with_checkpoint(prepared, |_| Ok(()))
        }
    }
}
```

Первый `prepare_import` гарантирует, что invalid source не создаёт root/lock file; второй запуск под lock закрывает race. `RootLockError::Busy` отображается в `target-busy`, остальные target I/O failures — в `write-failed`. В `import.rs` объявить `mod commit;` и подключить тесты через `#[cfg(test)] #[path = "import_test.rs"] mod import_test;`; внизу `commit.rs` подключить `#[cfg(test)] #[path = "commit_test.rs"] mod commit_test;`.

Safe `Display` использует только validated local name и numeric agent ID:

```rust
write!(
    formatter,
    "{}: local-name={}, agent-id={}; offline validation only",
    self.status.as_str(),
    self.local_name,
    self.agent_id
)
```

- [ ] **Step 8: Run transactional tests**

Run: `cargo test import::commit::commit_test && cargo test import::import_test`

Expected: PASS; каждый injected failure сохраняет invariant «config никогда не указывает на partial credentials», retry завершает согласованное состояние.

- [ ] **Step 9: Run all importer unit tests**

Run: `cargo test import::`

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/import.rs src/import/commit.rs src/import/commit_test.rs src/import_test.rs
git commit -m "feat: commit registration imports atomically"
```

---

### Task 7: Expose the CLI and Prove I-01… I-08 Black-Box Behavior

**Files:**
- Modify: `src/cli.rs:22-99`
- Create: `src/cli_test.rs`
- Create: `tests/import_official_test.rs`

**Interfaces:**
- Consumes: `import_official(source, name, root, dry_run)` and `ImportOutcome` from Task 6.
- Produces: `chimera import-official --source <dir> --name <name> --root <root> [--dry-run]`; exit 0 with one safe summary line, non-zero with stable error category.

- [ ] **Step 1: Write the failing clap parsing test**

Добавить в конце `src/cli.rs`:

```rust
#[cfg(test)]
#[path = "cli_test.rs"]
mod cli_test;
```

Создать test:

```rust
#[test]
fn parses_import_official_arguments() {
    let cli = Cli::try_parse_from([
        "chimera",
        "import-official",
        "--source", "/official",
        "--name", "local.runner-1",
        "--root", "/chimera",
        "--dry-run",
    ])
    .unwrap();

    assert!(matches!(
        cli.command,
        Command::ImportOfficial { source, name, root, dry_run }
            if source == PathBuf::from("/official")
                && name == "local.runner-1"
                && root == PathBuf::from("/chimera")
                && dry_run
    ));
}
```

Run: `cargo test cli::cli_test::parses_import_official_arguments -- --exact`

Expected: FAIL; subcommand отсутствует.

- [ ] **Step 2: Add the subcommand and offline dispatch**

В `Command` добавить:

```rust
/// Import an existing official runner registration without contacting GitHub
ImportOfficial {
    /// Official runner installation directory
    #[arg(long)]
    source: PathBuf,
    /// Local Chimera runner key; does not rename the GitHub agent
    #[arg(long)]
    name: String,
    /// Chimera root directory
    #[arg(long)]
    root: PathBuf,
    /// Validate and report eligibility without writing files
    #[arg(long)]
    dry_run: bool,
},
```

Dispatch:

```rust
Command::ImportOfficial { source, name, root, dry_run } => {
    init_tracing(&DaemonConfig::default());
    let outcome = crate::import::import_official(&source, &name, &root, dry_run)?;
    println!("{outcome}");
    Ok(())
}
```

Не создавать `reqwest::Client` и не вызывать registration module в этой ветке.

- [ ] **Step 3: Write black-box helpers and dry-run test**

В `tests/import_official_test.rs` использовать только standard library, `tempfile` и static fixture. Helper запускает `env!("CARGO_BIN_EXE_chimera")` и выставляет dead proxies:

```rust
fn run_import(source: &Path, name: &str, root: &Path, dry_run: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chimera"));
    command
        .arg("import-official")
        .arg("--source").arg(source)
        .arg("--name").arg(name)
        .arg("--root").arg(root)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("http_proxy", "http://127.0.0.1:9")
        .env("https_proxy", "http://127.0.0.1:9")
        .env("all_proxy", "http://127.0.0.1:9")
        .env("NO_PROXY", "")
        .env("no_proxy", "");
    if dry_run {
        command.arg("--dry-run");
    }
    command.output().unwrap()
}
```

`dry_run_is_offline_and_does_not_create_new_root` утверждает exit 0, stdout начинается `eligible:`, target root не существует, stderr не содержит fixture client ID/authorization URL/RSA strings.

- [ ] **Step 4: Add black-box acceptance tests I-01 through I-08**

Создать точные tests:

1. `imports_fixture_and_chimera_loader_preserves_every_field` — обычный import, затем `load_runner_credentials`; сравнить все identity/OAuth URL/client ID строки и decoded восемь RSA values с official fixture; public key `n/e` совпадает.
2. `dry_run_is_offline_and_does_not_create_new_root` — I-02.
3. `repeat_reports_already_imported_without_duplicate_or_rewrite` — I-03; config содержит name один раз, inode/mtime/bytes трёх файлов неизменны.
4. `same_name_or_same_identity_conflict_leaves_target_unchanged` — I-04; обе ошибки `identity-conflict`.
5. `invalid_inputs_fail_before_publish_and_redact_secrets` — I-05; missing field, malformed JSON/Base64/RSA, unsupported auth/flow; injected secret strings отсутствуют в stdout+stderr.
6. `traversal_symlink_and_unsafe_root_fail_closed` — black-box часть I-06: категории `invalid-source`/`write-failed`, за root ничего не создано; parallel writer отдельно доказывают unit tests `second_writer_is_rejected_without_blocking` и importer mapping `busy_root_returns_target_busy_without_changes`.
7. `fault_matrix_never_exposes_partial_config_and_retry_recovers` остаётся unit test Task 6 и указывается в acceptance mapping как I-07; CLI test повторяет crash-window fixture «published dir без config».
8. `umask_zero_still_creates_private_credentials` — I-08: permissive umask не добавляет group/world bits.
9. `restrictive_umask_still_creates_exact_private_modes` — umask `0o777` не снимает необходимые owner bits, потому что новый inode получает explicit mode до записи.

Для обоих umask tests менять umask только child process, не test runner:

```rust
use std::os::unix::process::CommandExt;

unsafe {
    command.pre_exec(|| {
        libc::umask(0);
        Ok(())
    });
}
```

После каждого child exit проверить `PermissionsExt::mode() & 0o777`: root, `runners/` и runner dir — `0o700`; `.chimera.lock`, новый `config.toml`, `runner.json`, `credentials.json`, `rsa_params.json` — `0o600`. Проверки одинаковы для umask `0o000` и `0o777`; это доказывает exact modes, а не только отсутствие слишком широких прав.

- [ ] **Step 5: Run CLI and importer acceptance tests**

Run: `cargo test cli_test && cargo test --test import_official_test`

Expected: PASS; ни один test не обращается к сети и не требует Docker.

- [ ] **Step 6: Check help and stable output manually with synthetic fixture**

Run:

```bash
cargo run -- import-official --help
cargo run -- import-official \
  --source tests/fixtures/official-runner-v2 \
  --name plan-smoke \
  --root "$(mktemp -d)/chimera" \
  --dry-run
```

Expected help: обязательные `--source`, `--name`, `--root`; optional `--dry-run`; smoke output ровно одна safe summary line, начинающаяся `eligible:`. Команда не печатает client ID, authorization URL или RSA.

- [ ] **Step 7: Commit**

```bash
git add src/cli.rs src/cli_test.rs tests/import_official_test.rs
git commit -m "feat: add official registration import CLI"
```

---

### Task 8: Document Operations, Acceptance Status, and Verify the Branch

**Files:**
- Create: `docs/registration-import.md`
- Modify: `README.md:39-80`
- Modify: `docs/gh-protocol.md:301-340`

**Interfaces:**
- Consumes: окончательный CLI/status/error vocabulary и automated test names Tasks 1–7.
- Produces: operator-facing offline import/switch/rollback guide и явный I-01… I-09 report; кодовых API не добавляет.

- [ ] **Step 1: Add the concise README entry**

Добавить в CLI block:

```text
chimera import-official --source <official-runner-dir> --name <local-name> --root <chimera-root> --dry-run
chimera import-official --source <official-runner-dir> --name <local-name> --root <chimera-root>
```

Под CLI descriptions написать: команда импортирует существующую persistent repo-scoped github.com identity полностью offline; `--name` не переименовывает GitHub agent; сначала обязателен dry-run; подробная процедура — `docs/registration-import.md`.

- [ ] **Step 2: Write the metadata and security contract in the operator guide**

`docs/registration-import.md` должен дословно перечислить:

- Input files `.runner`, `.credentials`, `.credentials_rsaparams` и outputs `runner.json`, `credentials.json`, `rsa_params.json`.
- Поддерживаемые auth keys: required `clientId`, `authorizationUrl`; optional `requireFipsCryptography=false`.
- Recognized migration metadata: `enableAuthMigrationByDefault=false` допускается как inactive; `true`, любое присутствие `authorizationUrlV2` и migration sibling files rejected.
- Любой иной auth key rejected; known non-auth runner fields `poolName`, `skipSessionRecover`, `disableUpdate`, `monitorSocketAddress`, `useRunnerAdminFlow`, `IsHostedServer=true` допускаются и не переносятся.
- Eligibility: positive IDs, nonempty agent/work folder, UUID client ID, exact `https://github.com/{owner}/{repo}` scope, approved HTTPS `actions.githubusercontent.com`/`*.actions.githubusercontent.com` endpoints, persistent non-FIPS V2 flow и математически согласованный RSA key.
- Exact local-name grammar, permissions, no-symlink/no-overwrite, root lock, outcome strings и пять error categories.
- Offline limitation: importer не может проверить, что официальный runner на другом host остановлен, не получает labels/OS/architecture и не доказывает online compatibility; оператор подтверждает Linux/X64 source до dry-run, а labels — в I-09.

- [ ] **Step 3: Document dry-run, controlled switch, rollback, and session conflict**

Guide содержит точную последовательность:

```text
1. Убедиться, что job не выполняется; штатно остановить один разрешённый official runner.
2. Запустить import-official с --dry-run и проверить eligible/already-imported.
3. Запустить import-official без --dry-run. Не запускать config.sh remove,
   chimera register или chimera unregister.
4. Только после отдельного разрешения оунера запустить Chimera с этой одной identity.
5. Выполнить job, перезапустить Chimera, выполнить второй job, проверить прежние
   GitHub agent identity и labels.
6. Для rollback остановить Chimera и дождаться удаления session, затем запустить
   official runner на нетронутом source directory.
7. При session conflict не запускать два клиента и не удалять регистрацию; остановить
   эксперимент и исследовать причину.
```

Не вставлять реальные пути, IDs, URLs, токены или credential values оператора.

- [ ] **Step 4: Add the explicit acceptance report**

Таблица в guide:

| ID | Статус до canary | Доказательство |
|---|---|---|
| I-01 | PASS automated | `imports_fixture_and_chimera_loader_preserves_every_field` |
| I-02 | PASS automated | `dry_run_is_offline_and_does_not_create_new_root` |
| I-03 | PASS automated | `repeat_reports_already_imported_without_duplicate_or_rewrite` |
| I-04 | PASS automated | `same_name_or_same_identity_conflict_leaves_target_unchanged` |
| I-05 | PASS automated | `invalid_inputs_fail_before_publish_and_redact_secrets` + source unit matrix |
| I-06 | PASS automated | path/symlink/root tests + `second_writer_is_rejected_without_blocking` |
| I-07 | PASS automated | `fault_matrix_never_exposes_partial_config_and_retry_recovers` |
| I-08 | PASS automated | `umask_zero_still_creates_private_credentials` + `restrictive_umask_still_creates_exact_private_modes` |
| I-09 | NOT RUN — owner authorization required | manual `job → restart → job → rollback` canary |

Под таблицей обязательная формулировка: **«Offline-импорт реализован; online-перенос не подтверждён, пока I-09 не выполнен отдельно.»**

- [ ] **Step 5: Correct the protocol document’s session flag**

В `docs/gh-protocol.md` заменить broker request example `"ephemeral": true` на `false`, а пояснение — на: persistent registrations, создаваемые `chimera register` и принимаемые `import-official`, создают non-ephemeral broker sessions; registration deletion никогда не выполняется при session disconnect.

- [ ] **Step 6: Format and run the required full verification suite**

Run:

```bash
cargo fmt --all -- --check
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
```

Expected: все четыре команды exit 0, zero warnings, все I-01… I-08 tests PASS. `cargo test -- --ignored` не требуется: Docker-related code/tests не менялись.

- [ ] **Step 7: Verify no credential material or forbidden placeholder entered the diff**

Run:

```bash
git diff --check
git grep -nE 'T[B]D|T[O]DO|implement[[:space:]]+later|fill[[:space:]]+in[[:space:]]+details' -- \
  src tests docs/registration-import.md README.md
git status --short
```

Expected: `git diff --check` exit 0; grep не находит новых placeholder markers в изменённых importer/docs files; status показывает только ожидаемые source/test/docs изменения. Synthetic fixture UUID/RSA values явно помечены в guide как test-only.

- [ ] **Step 8: Commit documentation and acceptance evidence**

```bash
git add README.md docs/gh-protocol.md docs/registration-import.md
git commit -m "docs: add registration import runbook"
```

- [ ] **Step 9: Record final implementation state without claiming I-09**

В PR/hand-off summary перечислить выполненные команды из Step 6, PASS I-01… I-08 и отдельно `I-09: NOT RUN — owner authorization required`. Не утверждать online compatibility, rollout readiness или сохранность labels до реального canary.
