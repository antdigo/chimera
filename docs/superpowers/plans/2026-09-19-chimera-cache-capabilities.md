# DPL-08 Cache API Capabilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Авторизовать legacy cache REST API через job-scoped `ACTIONS_RUNTIME_TOKEN`, привязать uploads и downloads к server-side authority и сохранить текущую repo/ref/default-branch семантику при 20 параллельных clients.

**Architecture:** Новый `cache::auth::CacheAuthority` хранит только BLAKE3 digest runtime token, server-side scope/job claims и opaque download grants. Axum router сначала аутентифицирует bearer и сверяет URL scope, затем передаёт `CapabilityId` в upload path; runner регистрирует capability перед пользовательскими steps и отзывает её до публикации completion.

**Tech Stack:** Rust 2024, Tokio, Axum 0.8, Chrono, BLAKE3, UUID v4, Tower `ServiceExt`, Reqwest.

**Spec:** `docs/superpowers/specs/2026-09-19-chimera-cache-capabilities.md`

## Global Constraints

- Legacy REST routes и выбор протокола через `ACTIONS_CACHE_URL` сохраняются; `ACTIONS_CACHE_SERVICE_V2` не добавляется.
- Источником capability остаётся существующий `SystemVssConnection.Authorization.AccessToken`, уже экспортируемый как `ACTIONS_RUNTIME_TOKEN`; новый secret/env не вводится.
- Capability lifetime — ровно 6 часов 10 минут от регистрации; success, failure и cancellation дополнительно вызывают немедленный revoke.
- Исходный runtime token, его digest, capability ID и download grant ID не логируются и не сохраняются на диск.
- URL scope является только compatibility metadata и всегда сверяется с server-side `repo`, `git_ref`, `default_ref`.
- Download URL не содержит runtime token или blob hash; grant связан с одним parent capability и одним blob.
- Entries/blobs остаются совместимыми с текущим on-disk format; authority state остаётся только в памяти.
- Locks authority не удерживаются во время file I/O, upload writes или blob streaming.
- Не добавлять новые crates: `chrono`, `blake3` и `uuid` уже присутствуют в `Cargo.toml`.

## Review Focus

- Пустой, malformed или повторяющийся `Authorization` header должен дать `401` до обращения к cache/upload state; это фиксирует Task 2.
- Повторная регистрация одного активного runtime token для другой job/scope должна fail closed и сохранить исходные claims; это фиксирует Task 1.
- Чужой PATCH/commit, включая конкурентную попытку, не должен удалить или изменить upload session владельца; это фиксирует Task 3.
- Malformed/unknown download grant и исчезнувший blob должны дать `404` без panic и без раскрытия hash; это фиксирует Task 4.
- Ошибка job body, cleanup failure и cancellation не должны оставлять capability активной к моменту completion/reporting; это фиксирует Task 5.

---

## File Structure

- Create `src/cache/auth.rs`: типы scope/capability, регистрация, expiry/revoke, bearer authorization и download grants.
- Create `src/cache/auth_test.rs`: изолированные lifecycle/expiry/collision/grant tests authority.
- Modify `src/cache.rs`: экспорт нового `auth` module.
- Modify `src/cache/server.rs`: `CacheServerState`, единый auth gate handlers, grant-based download route.
- Modify `src/cache/server_test.rs`: router security regressions, roundtrip/default fallback/restart/concurrency acceptance.
- Modify `src/cache/upload.rs`: owner fields и owner checks до file/session mutation.
- Modify `src/cache/upload_test.rs`: ownership tests на tracker boundary.
- Modify `src/cache/manager.rs`: проведение `CapabilityId` через reserve/write/commit.
- Modify `src/cache/manager_test.rs`: обновление fixtures под обязательного owner.
- Modify `src/cache/error.rs`: одинаковая `UploadNotFound` семантика для unknown и чужого owner.
- Modify `src/runner/instance.rs`: scope derivation, capability registration/revoke и общая authority с server.
- Modify `src/runner/instance_test.rs`: scope/TTL/revoke-before-completion regressions и обновление constructors.
- Modify `src/daemon.rs`: создание одного `Arc<CacheAuthority>` и передача server/runner.
- Modify `docs/gh-protocol.md`: bearer contract, server-side scope и opaque `archiveLocation`.

### Task 1: In-memory CacheAuthority и lifecycle capabilities

**Files:**
- Create: `src/cache/auth.rs`
- Create: `src/cache/auth_test.rs`
- Modify: `src/cache.rs:1-7`

**Interfaces:**
- Consumes: `chrono::{DateTime, Duration, Utc}`, `uuid::Uuid`, `blake3::hash`, `tokio::sync::RwLock`.
- Produces: `CacheScope`, `JobCapabilityClaims`, `CapabilityId`, `AuthorizedJob`, `CacheAuthority`, `CacheAuthError`, `JOB_CAPABILITY_LIFETIME`, `register_job`, `authorize`, `revoke`, `issue_download`, `resolve_download`.

- [ ] **Step 1: Экспортировать ещё отсутствующий module и написать failing lifecycle tests**

Добавить в `src/cache.rs`:

```rust
pub mod auth;
```

Создать `src/cache/auth_test.rs`:

```rust
use chrono::{Duration, Utc};

use super::*;

fn scope(repo: &str, git_ref: &str, default_ref: &str) -> CacheScope {
    CacheScope {
        repo: repo.into(),
        git_ref: git_ref.into(),
        default_ref: default_ref.into(),
    }
}

fn claims(job_id: &str, repo: &str) -> JobCapabilityClaims {
    JobCapabilityClaims {
        scope: scope(repo, "refs/heads/feature", "refs/heads/main"),
        job_id: job_id.into(),
    }
}

#[tokio::test]
async fn capability_authorizes_only_its_registered_scope_until_revoked() {
    let authority = CacheAuthority::new();
    let issued_at = Utc::now();
    let id = authority
        .register_job("runtime-a", claims("job-a", "org/repo-a"), issued_at.to_owned())
        .await
        .unwrap();

    let authorized = authority
        .authorize(
            "runtime-a",
            &scope("org/repo-a", "refs/heads/feature", "refs/heads/main"),
        )
        .await
        .unwrap();
    assert_eq!(authorized.capability_id(), &id);
    assert_eq!(authorized.job_id(), "job-a");
    assert_eq!(authorized.expires_at(), issued_at + JOB_CAPABILITY_LIFETIME);

    assert_eq!(
        authority
            .authorize(
                "runtime-a",
                &scope("org/repo-b", "refs/heads/feature", "refs/heads/main"),
            )
            .await
            .unwrap_err(),
        CacheAuthError::ScopeMismatch,
    );

    authority.revoke(&id).await;
    assert_eq!(
        authority
            .authorize(
                "runtime-a",
                &scope("org/repo-a", "refs/heads/feature", "refs/heads/main"),
            )
            .await
            .unwrap_err(),
        CacheAuthError::Unauthorized,
    );
}

#[tokio::test]
async fn capability_expires_after_ghr_six_hours_plus_ten_minutes() {
    let authority = CacheAuthority::new();
    let issued_at = Utc::now() - Duration::hours(6) - Duration::minutes(11);
    authority
        .register_job("runtime-expired", claims("job-expired", "org/repo"), issued_at)
        .await
        .unwrap();

    assert_eq!(
        authority
            .authorize(
                "runtime-expired",
                &scope("org/repo", "refs/heads/feature", "refs/heads/main"),
            )
            .await
            .unwrap_err(),
        CacheAuthError::Unauthorized,
    );
}

#[tokio::test]
async fn duplicate_active_token_cannot_replace_original_claims() {
    let authority = CacheAuthority::new();
    authority
        .register_job("same-token", claims("job-a", "org/repo-a"), Utc::now())
        .await
        .unwrap();

    assert_eq!(
        authority
            .register_job("same-token", claims("job-b", "org/repo-b"), Utc::now())
            .await
            .unwrap_err(),
        CacheAuthError::DuplicateToken,
    );
    assert!(
        authority
            .authorize(
                "same-token",
                &scope("org/repo-a", "refs/heads/feature", "refs/heads/main"),
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn download_grant_is_blob_bound_and_dies_with_parent() {
    let authority = CacheAuthority::new();
    let id = authority
        .register_job("runtime-a", claims("job-a", "org/repo"), Utc::now())
        .await
        .unwrap();
    let job = authority
        .authorize(
            "runtime-a",
            &scope("org/repo", "refs/heads/feature", "refs/heads/main"),
        )
        .await
        .unwrap();
    let grant = authority.issue_download(&job, "a".repeat(64)).await.unwrap();

    assert_eq!(authority.resolve_download(grant).await.unwrap(), "a".repeat(64));
    authority.revoke(&id).await;
    assert_eq!(
        authority.resolve_download(grant).await.unwrap_err(),
        CacheAuthError::DownloadNotFound,
    );
}

#[tokio::test]
async fn empty_token_is_never_registered() {
    let authority = CacheAuthority::new();
    assert_eq!(
        authority
            .register_job("", claims("job-a", "org/repo"), Utc::now())
            .await
            .unwrap_err(),
        CacheAuthError::EmptyToken,
    );
}
```

- [ ] **Step 2: Запустить tests и подтвердить RED**

Run:

```bash
cargo test cache::auth::auth_test -- --nocapture
```

Expected: compilation FAIL, потому что `src/cache/auth.rs` и перечисленные типы ещё отсутствуют.

- [ ] **Step 3: Реализовать минимальный authority state без raw tokens**

Создать `src/cache/auth.rs` с такими публичными сигнатурами и состоянием:

```rust
use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

pub const JOB_CAPABILITY_LIFETIME: Duration = Duration::minutes(6 * 60 + 10);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityId([u8; 32]);

impl CapabilityId {
    pub(crate) fn from_token(token: &str) -> Self {
        Self(*blake3::hash(token.as_bytes()).as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheScope {
    pub repo: String,
    pub git_ref: String,
    pub default_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobCapabilityClaims {
    pub scope: CacheScope,
    pub job_id: String,
}

#[derive(Clone, Debug)]
pub struct AuthorizedJob {
    capability_id: CapabilityId,
    claims: JobCapabilityClaims,
    expires_at: DateTime<Utc>,
}

impl AuthorizedJob {
    pub fn capability_id(&self) -> &CapabilityId { &self.capability_id }
    pub fn scope(&self) -> &CacheScope { &self.claims.scope }
    pub fn job_id(&self) -> &str { &self.claims.job_id }
    pub fn expires_at(&self) -> DateTime<Utc> { self.expires_at.to_owned() }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CacheAuthError {
    #[error("runtime token is empty")]
    EmptyToken,
    #[error("runtime token already has an active capability")]
    DuplicateToken,
    #[error("cache capability is not active")]
    Unauthorized,
    #[error("cache URL scope does not match the capability")]
    ScopeMismatch,
    #[error("download grant not found")]
    DownloadNotFound,
}

struct JobCapability {
    claims: JobCapabilityClaims,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

struct DownloadGrant {
    parent: CapabilityId,
    blob_hash: String,
    expires_at: DateTime<Utc>,
}

#[derive(Default)]
struct AuthorityState {
    jobs: HashMap<CapabilityId, JobCapability>,
    downloads: HashMap<Uuid, DownloadGrant>,
}

pub struct CacheAuthority {
    state: RwLock<AuthorityState>,
    now: std::sync::Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

impl CacheAuthority {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(AuthorityState::default()),
            now: std::sync::Arc::new(Utc::now),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_clock(
        now: std::sync::Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    ) -> Self {
        Self { state: RwLock::new(AuthorityState::default()), now }
    }

    fn now(&self) -> DateTime<Utc> { (self.now)() }

    pub async fn register_job(
        &self,
        token: &str,
        claims: JobCapabilityClaims,
        issued_at: DateTime<Utc>,
    ) -> Result<CapabilityId, CacheAuthError> {
        if token.is_empty() {
            return Err(CacheAuthError::EmptyToken);
        }
        let now = self.now();
        let id = CapabilityId::from_token(token);
        let mut state = self.state.write().await;
        state.jobs.retain(|_, capability| {
            !capability.revoked && capability.expires_at > now
        });
        let active_parents: std::collections::HashSet<_> =
            state.jobs.keys().cloned().collect();
        state.downloads.retain(|_, grant| {
            grant.expires_at > now && active_parents.contains(&grant.parent)
        });
        if state.jobs.contains_key(&id) {
            return Err(CacheAuthError::DuplicateToken);
        }
        state.jobs.insert(
            id.clone(),
            JobCapability {
                claims,
                expires_at: issued_at + JOB_CAPABILITY_LIFETIME,
                revoked: false,
            },
        );
        Ok(id)
    }

    pub async fn authorize(
        &self,
        token: &str,
        requested_scope: &CacheScope,
    ) -> Result<AuthorizedJob, CacheAuthError> {
        if token.is_empty() {
            return Err(CacheAuthError::Unauthorized);
        }
        let id = CapabilityId::from_token(token);
        let state = self.state.read().await;
        let capability = state.jobs.get(&id).ok_or(CacheAuthError::Unauthorized)?;
        if capability.revoked || capability.expires_at <= self.now() {
            return Err(CacheAuthError::Unauthorized);
        }
        if &capability.claims.scope != requested_scope {
            return Err(CacheAuthError::ScopeMismatch);
        }
        Ok(AuthorizedJob {
            capability_id: id,
            claims: capability.claims.clone(),
            expires_at: capability.expires_at.to_owned(),
        })
    }

    pub async fn revoke(&self, id: &CapabilityId) {
        let mut state = self.state.write().await;
        if let Some(capability) = state.jobs.get_mut(id) {
            capability.revoked = true;
        }
        state.downloads.retain(|_, grant| &grant.parent != id);
    }

    pub async fn issue_download(
        &self,
        job: &AuthorizedJob,
        blob_hash: String,
    ) -> Result<Uuid, CacheAuthError> {
        let mut state = self.state.write().await;
        let parent = state
            .jobs
            .get(job.capability_id())
            .ok_or(CacheAuthError::Unauthorized)?;
        if parent.revoked || parent.expires_at <= self.now() {
            return Err(CacheAuthError::Unauthorized);
        }
        let expires_at = parent.expires_at.to_owned();
        let grant = Uuid::new_v4();
        state.downloads.insert(
            grant,
            DownloadGrant {
                parent: job.capability_id().clone(),
                blob_hash,
                expires_at,
            },
        );
        Ok(grant)
    }

    pub async fn resolve_download(&self, grant: Uuid) -> Result<String, CacheAuthError> {
        let mut state = self.state.write().await;
        let Some(download) = state.downloads.get(&grant) else {
            return Err(CacheAuthError::DownloadNotFound);
        };
        let parent = download.parent.clone();
        let blob_hash = download.blob_hash.clone();
        let now = self.now();
        let grant_expired = download.expires_at <= now;
        let parent_active = state.jobs.get(&parent).is_some_and(|capability| {
            !capability.revoked && capability.expires_at > now
        });
        if grant_expired || !parent_active {
            state.downloads.remove(&grant);
            return Err(CacheAuthError::DownloadNotFound);
        }
        Ok(blob_hash)
    }
}

#[cfg(test)]
#[path = "auth_test.rs"]
mod auth_test;
```

Реализовать методы без `await` внутри захваченного guard, кроме самого `read/write().await`:

```rust
let now = Utc::now();
let id = CapabilityId::from_token(token);
```

`register_job` отклоняет пустой token, opportunistically удаляет expired/revoked jobs и их grants, запрещает существующий active ID и вставляет `expires_at = issued_at + JOB_CAPABILITY_LIFETIME`. `authorize` возвращает `Unauthorized` для empty/unknown/revoked/expired и `ScopeMismatch` только после успешной capability lookup. `revoke` выставляет `revoked = true` и удаляет все `downloads`, где `parent == id`. `issue_download` повторно проверяет active/non-expired parent и использует `expires_at = parent.expires_at`. `resolve_download` возвращает hash только если grant и parent существуют, active и не expired; иначе удаляет grant и возвращает `DownloadNotFound`.

- [ ] **Step 4: Запустить authority tests и подтвердить GREEN**

Run:

```bash
cargo test cache::auth::auth_test -- --nocapture
```

Expected: 5 PASS; raw token отсутствует в `JobCapability`, `AuthorizedJob` и `DownloadGrant`.

- [ ] **Step 5: Commit authority module**

```bash
git add src/cache.rs src/cache/auth.rs src/cache/auth_test.rs
git commit -m "feat: add job-scoped cache authority"
```

### Task 2: Bearer gate и server-side scope для cache API

**Files:**
- Modify: `src/cache/server.rs:1-284`
- Modify: `src/cache/server_test.rs:1-388`

**Interfaces:**
- Consumes: `CacheAuthority::authorize(&str, &CacheScope)`, `AuthorizedJob`, `CacheManager`.
- Produces: `CacheServerState { manager, authority }`, `router(manager, authority)`, `start(manager, authority, port)`, единый `authorize_request` helper.

- [ ] **Step 1: Перестроить test fixture и написать failing auth/scope tests**

Изменить fixture в `src/cache/server_test.rs`, чтобы каждый обычный request явно использовал bearer:

```rust
use chrono::Utc;
use crate::cache::auth::{
    CacheAuthority, CacheScope, CapabilityId, JobCapabilityClaims,
    JOB_CAPABILITY_LIFETIME,
};

const TOKEN_A: &str = "runtime-token-a";

fn scope_prefix(repo: &str, git_ref: &str, default_ref: &str) -> String {
    format!(
        "/cache/{}/{}/{}",
        encode_scope(repo),
        encode_scope(git_ref),
        encode_scope(default_ref),
    )
}

fn bearer(request: axum::http::request::Builder, token: &str) -> axum::http::request::Builder {
    request.header("authorization", format!("Bearer {token}"))
}

async fn make_test_manager(tmp: &TempDir) -> SharedManager {
    Arc::new(
        CacheManager::new(
            tmp.path().join("entries"),
            tmp.path().join("data"),
            tmp.path().join("tmp"),
            1024 * 1024,
        )
        .await
        .unwrap(),
    )
}

async fn make_test_app(tmp: &TempDir) -> (Router, SharedManager, Arc<CacheAuthority>) {
    let manager = make_test_manager(tmp).await;
    let authority = Arc::new(CacheAuthority::new());
    authority
        .register_job(
            TOKEN_A,
            JobCapabilityClaims {
                scope: CacheScope {
                    repo: SCOPE_REPO.into(),
                    git_ref: SCOPE_REF.into(),
                    default_ref: DEFAULT_REF.into(),
                },
                job_id: "job-a".into(),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    (router(manager.clone(), authority.clone()), manager, authority)
}
```

Добавить router regressions:

```rust
#[tokio::test]
async fn every_cache_api_handler_rejects_missing_bearer() {
    let tmp = TempDir::new().unwrap();
    let (app, _, _) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let cases = [
        Request::builder()
            .uri(format!("{prefix}/_apis/artifactcache/cache?keys=k&version=v1"))
            .body(Body::empty()).unwrap(),
        Request::builder().method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"key":"k","version":"v1"}"#)).unwrap(),
        Request::builder().method("PATCH")
            .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
            .header("content-range", "bytes 0-0/*")
            .body(Body::from("x")).unwrap(),
        Request::builder().method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"size":1}"#)).unwrap(),
    ];
    for request in cases {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
        );
    }
}

#[tokio::test]
async fn duplicate_or_malformed_authorization_is_unauthorized() {
    let tmp = TempDir::new().unwrap();
    let (app, _, _) = make_test_app(&tmp).await;
    let uri = format!(
        "{}/_apis/artifactcache/cache?keys=k&version=v1",
        scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF),
    );
    for values in [vec!["Basic abc"], vec!["Bearer"], vec!["Bearer "]] {
        let mut builder = Request::builder().uri(&uri);
        for value in values { builder = builder.header("authorization", value); }
        assert_eq!(
            app.clone().oneshot(builder.body(Body::empty()).unwrap()).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
        );
    }

    let request = Request::builder().uri(uri)
        .header("authorization", "Bearer runtime-token-a")
        .header("authorization", "Bearer runtime-token-b")
        .body(Body::empty()).unwrap();
    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_token_cannot_select_another_repo_ref_or_default_ref() {
    let tmp = TempDir::new().unwrap();
    let (app, _, _) = make_test_app(&tmp).await;
    for prefix in [
        scope_prefix("org/other", SCOPE_REF, DEFAULT_REF),
        scope_prefix(SCOPE_REPO, "refs/heads/other", DEFAULT_REF),
        scope_prefix(SCOPE_REPO, SCOPE_REF, "refs/heads/other"),
    ] {
        let request = bearer(
            Request::builder().uri(format!(
                "{prefix}/_apis/artifactcache/cache?keys=k&version=v1"
            )),
            TOKEN_A,
        ).body(Body::empty()).unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN,
        );
    }
}
```

Обновить существующие happy-path requests: каждый `Request::builder()` обернуть вызовом `bearer(request_builder, TOKEN_A)`, а destructuring fixture изменить на `(app, manager, authority)`.

- [ ] **Step 2: Запустить router tests и подтвердить RED**

Run:

```bash
cargo test cache::server::server_test -- --nocapture
```

Expected: новые tests FAIL — baseline принимает missing bearer и доверяет URL scope. `concurrent_http_clients` может отдельно упасть на bind с `Operation not permitted` внутри sandbox; это не заменяет RED auth assertions.

- [ ] **Step 3: Ввести CacheServerState и общий authorize_request**

В `src/cache/server.rs` заменить state alias:

```rust
use axum::http::header::AUTHORIZATION;
use super::auth::{AuthorizedJob, CacheAuthError, CacheAuthority, CacheScope};

pub type SharedManager = Arc<CacheManager>;

#[derive(Clone)]
pub struct CacheServerState {
    manager: SharedManager,
    authority: Arc<CacheAuthority>,
}

pub fn router(manager: SharedManager, authority: Arc<CacheAuthority>) -> Router {
    let state = CacheServerState { manager, authority };
    // existing routes, then .with_state(state)
}

pub async fn start(
    manager: SharedManager,
    authority: Arc<CacheAuthority>,
    port: u16,
) -> Result<SocketAddr> {
    let app = router(manager, authority);
    // existing bind/spawn body
}
```

Заменить локальный `CacheScope` тип на `auth::CacheScope` и добавить helpers:

```rust
fn bearer_token(headers: &HeaderMap) -> Result<&str, StatusCode> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(StatusCode::UNAUTHORIZED)?;
    if values.next().is_some() { return Err(StatusCode::UNAUTHORIZED); }
    let value = value.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let (scheme, token) = value.split_once(' ').ok_or(StatusCode::UNAUTHORIZED)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() || token.contains(char::is_whitespace) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(token)
}

async fn authorize_request(
    state: &CacheServerState,
    headers: &HeaderMap,
    encoded_scope: (&str, &str, &str),
) -> Result<AuthorizedJob, StatusCode> {
    let token = bearer_token(headers)?;
    let scope = extract_scope(encoded_scope.0, encoded_scope.1, encoded_scope.2)?;
    state.authority.authorize(token, &scope).await.map_err(|error| match error {
        CacheAuthError::ScopeMismatch => StatusCode::FORBIDDEN,
        _ => StatusCode::UNAUTHORIZED,
    })
}
```

Каждый lookup/reserve/PATCH/commit handler получает `State(state): State<CacheServerState>`, `HeaderMap` и все три scope segments, вызывает `authorize_request` первым и использует `authorized.scope()` для manager calls/log scope. Не переносить bearer, digest или grant в tracing fields.

- [ ] **Step 4: Запустить router tests и подтвердить GREEN для API gate**

Run:

```bash
cargo test cache::server::server_test -- --nocapture
```

Expected: auth/scope и обновлённые in-process tests PASS; единственный допустимый sandbox-only failure — real TCP bind в ещё не обновлённом concurrency test.

- [ ] **Step 5: Commit API authorization gate**

```bash
git add src/cache/server.rs src/cache/server_test.rs
git commit -m "fix: authorize cache API scope"
```

### Task 3: Job ownership upload sessions

**Files:**
- Modify: `src/cache/error.rs:3-16`
- Modify: `src/cache/upload.rs:1-145`
- Modify: `src/cache/upload_test.rs:1-135`
- Modify: `src/cache/manager.rs:141-204`
- Modify: `src/cache/manager_test.rs:22-45`
- Modify: `src/cache/server.rs:201-284`
- Modify: `src/cache/server_test.rs`

**Interfaces:**
- Consumes: `CapabilityId`, `AuthorizedJob::capability_id()`, `AuthorizedJob::job_id()`.
- Produces: owner-aware `reserve_upload`, `write_chunk`, `commit_upload`; owner mismatch indistinguishable from unknown ID.

- [ ] **Step 1: Написать failing UploadTracker ownership test**

В `src/cache/upload_test.rs` добавить helper IDs и regression:

```rust
use crate::cache::auth::CapabilityId;

fn owner(token: &str) -> CapabilityId {
    CapabilityId::from_token(token)
}

#[tokio::test]
async fn foreign_owner_cannot_write_or_consume_upload_session() {
    let tmp = TempDir::new().unwrap();
    let tracker = make_tracker(&tmp);
    let owner_a = owner("runtime-a");
    let owner_b = owner("runtime-b");
    let id = tracker
        .reserve(
            owner_a.clone(),
            "job-a".into(),
            "k".into(),
            "v".into(),
            "org/repo".into(),
            "refs/heads/main".into(),
        )
        .await
        .unwrap();

    let write_error = tracker.write_chunk(&owner_b, id, 0, b"evil").await.unwrap_err();
    assert!(write_error.downcast_ref::<CacheError>().is_some_and(
        |error| matches!(error, CacheError::UploadNotFound(value) if *value == id)
    ));
    let commit_error = tracker.commit(&owner_b, id, 4).await.unwrap_err();
    assert!(commit_error.downcast_ref::<CacheError>().is_some_and(
        |error| matches!(error, CacheError::UploadNotFound(value) if *value == id)
    ));

    tracker.write_chunk(&owner_a, id, 0, b"owner").await.unwrap();
    let (_, _, _, _, path, size) = tracker.commit(&owner_a, id, 5).await.unwrap();
    assert_eq!(size, 5);
    assert_eq!(std::fs::read(path).unwrap(), b"owner");
}
```

Обновить существующие tracker/manager test helpers так, чтобы они передавали стабильный `CapabilityId::from_token("manager-test-owner")` и `job_id`.

- [ ] **Step 2: Запустить ownership test и подтвердить RED**

Run:

```bash
cargo test cache::upload::upload_test::foreign_owner_cannot_write_or_consume_upload_session -- --nocapture
```

Expected: compilation FAIL из-за старых signatures `reserve/write_chunk/commit`.

- [ ] **Step 3: Провести owner через UploadTracker и CacheManager**

Изменить `UploadSession`:

```rust
struct UploadSession {
    owner_capability_id: CapabilityId,
    owner_job_id: String,
    key: String,
    version: String,
    scope_repo: String,
    scope_ref: String,
    tmp_path: PathBuf,
    bytes_written: u64,
}
```

Установить точные signatures:

```rust
pub async fn reserve(
    &self,
    owner_capability_id: CapabilityId,
    owner_job_id: String,
    key: String,
    version: String,
    scope_repo: String,
    scope_ref: String,
) -> Result<u64>;

pub async fn write_chunk(
    &self,
    owner: &CapabilityId,
    id: u64,
    offset: u64,
    data: &[u8],
) -> Result<()>;

pub async fn commit(
    &self,
    owner: &CapabilityId,
    id: u64,
    expected_size: u64,
) -> Result<(String, String, String, String, PathBuf, u64)>;
```

В `write_chunk` выполнять owner comparison сразу после `get_mut`, до `OpenOptions::open`. В `commit` сначала читать session через `get`, сравнивать owner и только после успешного сравнения вызывать `remove`; чужая попытка не должна consume session. Для mismatch возвращать тот же `CacheError::UploadNotFound(id)`.

Провести те же аргументы через manager:

```rust
pub async fn reserve_upload(
    &self,
    owner: CapabilityId,
    owner_job_id: String,
    key: String,
    version: String,
    scope_repo: String,
    scope_ref: String,
) -> Result<u64>;

pub async fn write_chunk(
    &self,
    owner: &CapabilityId,
    id: u64,
    offset: u64,
    data: &[u8],
) -> Result<()>;

pub async fn commit_upload(
    &self,
    owner: &CapabilityId,
    id: u64,
    expected_size: u64,
) -> Result<()>;
```

Handlers передают `authorized.capability_id()`; reserve также передаёт `authorized.job_id()` и scope из `authorized.scope()`. В commit handler распознавать `CacheError::UploadNotFound` через `error.downcast_ref::<CacheError>()` и возвращать `404`; остальные commit errors сохраняют `500`.

- [ ] **Step 4: Добавить router regression на same-scope foreign job**

В `src/cache/server_test.rs` сначала добавить request helpers:

```rust
async fn reserve(app: &Router, prefix: &str, token: &str, key: &str, version: &str) -> u64 {
    let request = bearer(
        Request::builder().method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches"))
            .header("content-type", "application/json"),
        token,
    ).body(Body::from(serde_json::json!({ "key": key, "version": version }).to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["cacheId"]
        .as_u64().unwrap()
}

async fn upload(
    app: &Router,
    prefix: &str,
    token: &str,
    cache_id: u64,
    data: &[u8],
) -> StatusCode {
    let request = bearer(
        Request::builder().method("PATCH")
            .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
            .header("content-range", format!("bytes 0-{}/*", data.len() - 1)),
        token,
    ).body(Body::from(Bytes::copy_from_slice(data))).unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

async fn commit(
    app: &Router,
    prefix: &str,
    token: &str,
    cache_id: u64,
    size: usize,
) -> StatusCode {
    let request = bearer(
        Request::builder().method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
            .header("content-type", "application/json"),
        token,
    ).body(Body::from(serde_json::json!({ "size": size }).to_string())).unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn another_job_in_same_scope_cannot_write_or_commit_upload() {
    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app(&tmp).await;
    authority.register_job(
        "runtime-token-b",
        JobCapabilityClaims {
            scope: CacheScope {
                repo: SCOPE_REPO.into(),
                git_ref: SCOPE_REF.into(),
                default_ref: DEFAULT_REF.into(),
            },
            job_id: "job-b".into(),
        },
        Utc::now(),
    ).await.unwrap();

    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let cache_id = reserve(&app, &prefix, TOKEN_A, "owned", "v1").await;
    assert_eq!(upload(&app, &prefix, "runtime-token-b", cache_id, b"evil").await, StatusCode::NOT_FOUND);
    assert_eq!(commit(&app, &prefix, "runtime-token-b", cache_id, 4).await, StatusCode::NOT_FOUND);
    assert_eq!(upload(&app, &prefix, TOKEN_A, cache_id, b"owner").await, StatusCode::NO_CONTENT);
    assert_eq!(commit(&app, &prefix, TOKEN_A, cache_id, 5).await, StatusCode::NO_CONTENT);
}
```

- [ ] **Step 5: Запустить upload, manager и router suites**

Run:

```bash
cargo test cache::upload -- --nocapture
cargo test cache::manager -- --nocapture
cargo test cache::server::server_test::another_job_in_same_scope_cannot_write_or_commit_upload -- --nocapture
```

Expected: все PASS; чужая commit попытка не мешает последующей owner commit.

- [ ] **Step 6: Commit upload ownership**

```bash
git add src/cache/error.rs src/cache/upload.rs src/cache/upload_test.rs src/cache/manager.rs src/cache/manager_test.rs src/cache/server.rs src/cache/server_test.rs
git commit -m "fix: bind cache uploads to job capabilities"
```

### Task 4: Opaque download grants и default-branch authorization

**Files:**
- Modify: `src/cache/server.rs:47-65,140-199,286-322`
- Modify: `src/cache/server_test.rs`

**Interfaces:**
- Consumes: `CacheAuthority::issue_download`, `CacheAuthority::resolve_download`, authorized `CacheEntry::blob_hash`.
- Produces: `/download/{grant_id}` route, `archiveLocation` без hash/token, `404` для любого invalid grant/blob.

- [ ] **Step 1: Написать failing direct-hash/revoke/default-fallback tests**

Добавить в `src/cache/server_test.rs` lookup/roundtrip helpers и tests:

```rust
async fn lookup(
    app: &Router,
    prefix: &str,
    token: &str,
    key: &str,
    version: &str,
) -> String {
    let request = bearer(
        Request::builder().uri(format!(
            "{prefix}/_apis/artifactcache/cache?keys={key}&version={version}"
        )),
        token,
    ).header("host", "localhost:9999")
        .body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["archiveLocation"]
        .as_str().unwrap().to_string()
}

async fn authorized_roundtrip(
    app: &Router,
    prefix: &str,
    token: &str,
    key: &str,
    data: &[u8],
) -> (CapabilityId, String) {
    let cache_id = reserve(app, prefix, token, key, "v1").await;
    assert_eq!(upload(app, prefix, token, cache_id, data).await, StatusCode::NO_CONTENT);
    assert_eq!(commit(app, prefix, token, cache_id, data.len()).await, StatusCode::NO_CONTENT);
    let archive_location = lookup(app, prefix, token, key, "v1").await;
    (CapabilityId::from_token(token), archive_location)
}

#[tokio::test]
async fn blob_hash_is_not_a_download_authority() {
    let tmp = TempDir::new().unwrap();
    let (app, manager, _) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let (_, archive_location) = authorized_roundtrip(&app, &prefix, TOKEN_A, "k", b"secret").await;
    let grant_path = archive_location.strip_prefix("http://localhost:9999").unwrap();
    let granted = app.clone().oneshot(Request::builder().uri(grant_path).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(granted.status(), StatusCode::OK);

    let entry = manager.lookup(&["k".into()], "v1", SCOPE_REPO, SCOPE_REF, DEFAULT_REF)
        .await.unwrap();
    let direct_hash_path = format!("/download/{}", entry.blob_hash);
    let direct = app.oneshot(Request::builder().uri(direct_hash_path).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(direct.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoke_invalidates_previously_issued_download_grant() {
    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let (capability_id, archive_location) = authorized_roundtrip(&app, &prefix, TOKEN_A, "k", b"secret").await;
    authority.revoke(&capability_id).await;
    let path = archive_location.strip_prefix("http://localhost:9999").unwrap();
    assert_eq!(
        app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap().status(),
        StatusCode::NOT_FOUND,
    );
}

#[tokio::test]
async fn expired_parent_invalidates_previously_issued_download_grant() {
    let tmp = TempDir::new().unwrap();
    let manager = make_test_manager(&tmp).await;
    let started_at = Utc::now();
    let clock_value = Arc::new(std::sync::Mutex::new(started_at.to_owned()));
    let clock_reader = clock_value.clone();
    let authority = Arc::new(CacheAuthority::with_clock(Arc::new(move || {
        clock_reader.lock().unwrap().to_owned()
    })));
    authority.register_job(
        TOKEN_A,
        JobCapabilityClaims {
            scope: CacheScope {
                repo: SCOPE_REPO.into(),
                git_ref: SCOPE_REF.into(),
                default_ref: DEFAULT_REF.into(),
            },
            job_id: "job-a".into(),
        },
        started_at.to_owned(),
    ).await.unwrap();
    let app = router(manager, authority);
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let (_, archive_location) = authorized_roundtrip(&app, &prefix, TOKEN_A, "k", b"secret").await;

    *clock_value.lock().unwrap() = started_at + JOB_CAPABILITY_LIFETIME + chrono::Duration::seconds(1);
    let path = archive_location.strip_prefix("http://localhost:9999").unwrap();
    assert_eq!(
        app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap().status(),
        StatusCode::NOT_FOUND,
    );
}

#[tokio::test]
async fn feature_job_can_download_authorized_default_branch_fallback() {
    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app(&tmp).await;
    let main_prefix = scope_prefix(SCOPE_REPO, DEFAULT_REF, DEFAULT_REF);
    authorized_roundtrip(&app, &main_prefix, TOKEN_A, "shared", b"main-cache").await;

    authority.register_job(
        "runtime-feature",
        JobCapabilityClaims {
            scope: CacheScope {
                repo: SCOPE_REPO.into(),
                git_ref: "refs/heads/feature".into(),
                default_ref: DEFAULT_REF.into(),
            },
            job_id: "job-feature".into(),
        },
        Utc::now(),
    ).await.unwrap();
    let feature_prefix = scope_prefix(SCOPE_REPO, "refs/heads/feature", DEFAULT_REF);
    let archive_location = lookup(&app, &feature_prefix, "runtime-feature", "shared", "v1").await;
    let path = archive_location.strip_prefix("http://localhost:9999").unwrap();
    let response = app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(axum::body::to_bytes(response.into_body(), 1024).await.unwrap(), b"main-cache"[..]);
}
```

`authorized_roundtrip` возвращает зарегистрированный `CapabilityId` и фактический `archiveLocation`; fixture token A имеет main/main claims и подходит для main upload в fallback test.

- [ ] **Step 2: Запустить новые download tests и подтвердить RED**

Run:

```bash
cargo test cache::server::server_test::blob_hash_is_not_a_download_authority -- --nocapture
cargo test cache::server::server_test::revoke_invalidates_previously_issued_download_grant -- --nocapture
cargo test cache::server::server_test::feature_job_can_download_authorized_default_branch_fallback -- --nocapture
```

Expected: первые два FAIL, потому что baseline `archiveLocation` содержит hash и не связан с parent capability; fallback helper может потребовать обновлённую fixture регистрацию, но не должен обходить bearer gate.

- [ ] **Step 3: Заменить hash route на grant route**

В lookup после успешного `CacheManager::lookup` создать grant:

```rust
let grant = match state
    .authority
    .issue_download(&authorized, entry.blob_hash.clone())
    .await
{
    Ok(grant) => grant,
    Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
};
let location = format!("http://{host}/download/{grant}");
```

Не включать `location`, grant или hash в `debug!`; достаточно `cache_key` и server-side scope.

Заменить handler:

```rust
async fn handle_download(
    State(state): State<CacheServerState>,
    Path(grant): Path<String>,
) -> Response {
    let grant = match Uuid::parse_str(&grant) {
        Ok(grant) => grant,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let hash = match state.authority.resolve_download(grant).await {
        Ok(hash) => hash,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let blob_path = match state.manager.blob_path(&hash) {
        Ok(path) => path,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    // существующие metadata/open/ReaderStream; любая ошибка остаётся 404
}
```

Route остаётся `GET /download/{grant}`, но старый hash больше не разрешается как blob ID. Удалить прямую проверку `is_valid_blob_hash` из handler; store продолжает валидировать server-side hash из grant.

- [ ] **Step 4: Добавить missing-blob и cross-repo-dedup regressions**

Добавить tests, использующие реальные router handlers:

```rust
#[tokio::test]
async fn valid_grant_returns_not_found_when_bound_blob_disappears() {
    let tmp = TempDir::new().unwrap();
    let (app, manager, _) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let (_, archive_location) =
        authorized_roundtrip(&app, &prefix, TOKEN_A, "missing", b"bytes").await;
    let entry = manager
        .lookup(
            &["missing".into()],
            "v1",
            SCOPE_REPO,
            SCOPE_REF,
            DEFAULT_REF,
        )
        .await
        .unwrap();
    std::fs::remove_file(manager.blob_path(&entry.blob_hash).unwrap()).unwrap();

    let path = archive_location.strip_prefix("http://localhost:9999").unwrap();
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn repository_cannot_lookup_another_repository_entry_even_when_blob_exists() {
    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app(&tmp).await;
    let repo_a_prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    authorized_roundtrip(&app, &repo_a_prefix, TOKEN_A, "shared", b"same-bytes").await;

    authority.register_job(
        "runtime-repo-b",
        JobCapabilityClaims {
            scope: CacheScope {
                repo: "org/repo-b".into(),
                git_ref: SCOPE_REF.into(),
                default_ref: DEFAULT_REF.into(),
            },
            job_id: "job-repo-b".into(),
        },
        Utc::now(),
    ).await.unwrap();
    let repo_b_prefix = scope_prefix("org/repo-b", SCOPE_REF, DEFAULT_REF);
    assert_eq!(
        lookup_status(&app, &repo_b_prefix, "runtime-repo-b", "shared", "v1").await,
        StatusCode::NO_CONTENT,
    );
}
```

- [ ] **Step 5: Запустить полный in-process server suite**

Run:

```bash
cargo test cache::server::server_test -- --nocapture
```

Expected: все in-process tests PASS; real TCP concurrency test может требовать разрешения loopback bind.

- [ ] **Step 6: Commit download grants**

```bash
git add src/cache/server.rs src/cache/server_test.rs
git commit -m "fix: authorize cache blob downloads"
```

### Task 5: Runner registration/revoke и daemon wiring

**Files:**
- Modify: `src/runner/instance.rs:1-27,149-178,460-535,665-713`
- Modify: `src/runner/instance_test.rs:1-85,490-533` and lifecycle tests near existing `finish_job` tests
- Modify: `src/daemon.rs:388-430`

**Interfaces:**
- Consumes: shared `Arc<CacheAuthority>`, `register_job`, `revoke`, `CacheScope`, `JobCapabilityClaims`, `JOB_CAPABILITY_LIFETIME`.
- Produces: one authority shared by daemon/server/runners; deterministic `cache_scope_for_job`; revoke before `finish_job` publishes completion.

- [ ] **Step 1: Написать failing scope and registration tests**

В `src/runner/instance_test.rs` добавить:

```rust
use crate::cache::auth::{CacheAuthError, CacheAuthority, CacheScope};

#[test]
fn cache_scope_is_derived_once_from_manifest_context() {
    let manifest: JobManifest = serde_json::from_str(include_str!("../../tests/fixtures/job_manifest.json")).unwrap();
    assert_eq!(
        cache_scope_for_job(&manifest, "owner/test-repo"),
        CacheScope {
            repo: "owner/test-repo".into(),
            git_ref: "refs/heads/main".into(),
            default_ref: "refs/heads/main".into(),
        },
    );
}

#[tokio::test]
async fn register_job_cache_capability_uses_manifest_runtime_token_and_job_id() {
    let authority = CacheAuthority::new();
    let manifest: JobManifest = serde_json::from_str(include_str!("../../tests/fixtures/job_manifest.json")).unwrap();
    let scope = cache_scope_for_job(&manifest, "owner/test-repo");
    let id = register_job_cache_capability(&authority, &manifest, scope.clone(), Utc::now())
        .await
        .unwrap();

    let authorized = authority.authorize("job-token-xyz", &scope).await.unwrap();
    assert_eq!(authorized.capability_id(), &id);
    assert_eq!(authorized.job_id(), "job-001");
}
```

Добавить `cache_authority: Arc<CacheAuthority>` в оба test `Runner` literals (`make_runner`, `make_startup_runner`) с новым пустым authority.

- [ ] **Step 2: Запустить tests и подтвердить RED**

Run:

```bash
cargo test runner::instance::instance_test::cache_scope_is_derived_once_from_manifest_context -- --nocapture
cargo test runner::instance::instance_test::register_job_cache_capability_uses_manifest_runtime_token_and_job_id -- --nocapture
```

Expected: compilation FAIL — helpers и поле runner ещё отсутствуют.

- [ ] **Step 3: Реализовать единый scope derivation и registration helper**

В `src/runner/instance.rs` добавить:

```rust
use crate::cache::auth::{
    CacheAuthority, CacheScope, CapabilityId, JobCapabilityClaims,
};

fn cache_scope_for_job(manifest: &JobManifest, repo: &str) -> CacheScope {
    let git_ref = manifest.context_data.get("github")
        .and_then(|github| github.get("ref"))
        .and_then(|value| value.as_str())
        .unwrap_or("refs/heads/main");
    let default_branch = manifest.context_data.get("github")
        .and_then(|github| github.get("event"))
        .and_then(|event| event.get("repository"))
        .and_then(|repository| repository.get("default_branch"))
        .and_then(|value| value.as_str())
        .unwrap_or("main");
    let default_ref = if default_branch.starts_with("refs/") {
        default_branch.to_string()
    } else {
        format!("refs/heads/{default_branch}")
    };
    CacheScope {
        repo: repo.to_string(),
        git_ref: git_ref.to_string(),
        default_ref,
    }
}

async fn register_job_cache_capability(
    authority: &CacheAuthority,
    manifest: &JobManifest,
    scope: CacheScope,
    issued_at: chrono::DateTime<Utc>,
) -> Result<CapabilityId> {
    authority.register_job(
        manifest.access_token().context("reading cache runtime token")?,
        JobCapabilityClaims {
            scope,
            job_id: manifest.plan.job_id.clone(),
        },
        issued_at,
    ).await.context("registering cache capability")
}
```

Добавить `cache_authority: Arc<CacheAuthority>` в `Runner` и параметр `Runner::with_state` сразу после `cache_port`. В `run_job_steps` принимать `cache_scope: &CacheScope` и строить URL только из него, удалив повторное чтение manifest context.

- [ ] **Step 4: Написать failing revoke-before-completion test**

Рядом с существующими `finish_job` tests создать wrapper `finish_job_after_cache_revoke` в production и test, где capability активна до вызова и неактивна после него даже при failed execution result:

```rust
#[tokio::test]
async fn cache_capability_is_revoked_before_failure_is_reported() {
    let authority = CacheAuthority::new();
    let server = MockServer::start().await;
    let manifest = finish_manifest(&server.uri());
    let scope = cache_scope_for_job(&manifest, "owner/test-repo");
    let id = register_job_cache_capability(&authority, &manifest, scope.clone(), Utc::now())
        .await.unwrap();
    let execution = Err(anyhow::anyhow!("setup failed"));
    let cleanup = Ok(());
    let client = finish_client(&server).await;

    let result = finish_job_after_cache_revoke(
        &authority,
        &id,
        &client,
        &manifest,
        execution,
        cleanup,
    ).await;
    assert!(result.is_err());
    assert_eq!(
        authority.authorize("synthetic", &scope).await.unwrap_err(),
        CacheAuthError::Unauthorized,
    );
}
```

Также перевести существующие tests `successful_job_reports_failed_when_docker_config_cleanup_fails` и `execution_and_cleanup_errors_are_both_returned_without_early_completion` на `finish_job_after_cache_revoke`: перед вызовом зарегистрировать `synthetic`, а после результата проверить `CacheAuthError::Unauthorized`. Добавить cancellation case без второго mock protocol:

```rust
#[tokio::test]
async fn cancelled_job_revokes_cache_capability_before_completion() {
    use wiremock::matchers::body_json;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/completejob"))
        .and(body_json(serde_json::json!({
            "planId": "plan",
            "jobId": "job",
            "conclusion": "cancelled",
            "outputs": {},
            "stepResults": []
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let authority = CacheAuthority::new();
    let client = finish_client(&server).await;
    let manifest = finish_manifest(&server.uri());
    let scope = cache_scope_for_job(&manifest, "owner/test-repo");
    let id = register_job_cache_capability(&authority, &manifest, scope.clone(), Utc::now())
        .await.unwrap();
    let execution = Ok(JobExecutionOutcome {
        conclusion: JobConclusion::Cancelled,
        outputs: HashMap::new(),
    });

    finish_job_after_cache_revoke(
        &authority,
        &id,
        &client,
        &manifest,
        execution,
        Ok(()),
    ).await.unwrap();
    assert_eq!(
        authority.authorize("synthetic", &scope).await.unwrap_err(),
        CacheAuthError::Unauthorized,
    );
}
```

- [ ] **Step 5: Реализовать register → execution/cleanup → revoke → completion ordering**

Добавить wrapper:

```rust
async fn finish_job_after_cache_revoke(
    authority: &CacheAuthority,
    capability_id: &CapabilityId,
    job_client: &Arc<JobClient>,
    manifest: &JobManifest,
    execution_result: Result<JobExecutionOutcome>,
    cleanup_result: std::result::Result<(), JobDockerConfigError>,
) -> Result<()> {
    authority.revoke(capability_id).await;
    finish_job(job_client, manifest, execution_result, cleanup_result).await
}
```

В `run_job`:

1. вычислить `cache_scope`;
2. зарегистрировать capability до `run_job_body`;
3. передать `&cache_scope` до `run_job_steps` для URL;
4. выполнить существующий Docker config cleanup;
5. вызвать `finish_job_after_cache_revoke` вместо `finish_job`.

Если регистрация не удалась после создания Docker config, выполнить тот же config cleanup и вернуть ошибку через существующий setup-failure path; unauthenticated `run_job_body` не вызывать. Не логировать token/digest.

- [ ] **Step 6: Создать одну authority в daemon и передать обоим consumers**

В `src/daemon.rs`:

```rust
let cache_authority = Arc::new(crate::cache::auth::CacheAuthority::new());
let cache_addr = cache_server::start(
    Arc::clone(&cache_manager),
    Arc::clone(&cache_authority),
    cache_config.cache_port,
).await.context("starting cache server")?;
```

Передать `Arc::clone(&cache_authority)` в каждый `Runner::with_state`. Обновить все compile errors constructors явно, не вводить global/static authority.

- [ ] **Step 7: Запустить runner/daemon/cache compilation tests**

Run:

```bash
cargo test runner::instance::instance_test -- --nocapture
cargo test daemon -- --nocapture
cargo test cache::auth -- --nocapture
```

Expected: PASS; failure/cancellation/cleanup variants текущих `finish_job` tests сохраняют прежние conclusions, capability после wrapper всегда unauthorized.

- [ ] **Step 8: Commit runner lifecycle integration**

```bash
git add src/runner/instance.rs src/runner/instance_test.rs src/daemon.rs
git commit -m "fix: scope cache capabilities to job lifecycle"
```

### Task 6: Acceptance — expiry/restart, 20 clients и protocol documentation

**Files:**
- Modify: `src/cache/server_test.rs`
- Modify: `docs/gh-protocol.md:1197-1265,1624-1654`

**Interfaces:**
- Consumes: complete authorized cache server and runner lifecycle.
- Produces: issue #42 acceptance evidence and user-facing protocol contract.

- [ ] **Step 1: Добавить router expiry и in-memory restart tests**

Добавить helpers и tests:

```rust
async fn make_test_app_without_registration(
    tmp: &TempDir,
) -> (Router, SharedManager, Arc<CacheAuthority>) {
    let manager = make_test_manager(tmp).await;
    let authority = Arc::new(CacheAuthority::new());
    (router(manager.clone(), authority.clone()), manager, authority)
}

async fn lookup_status(
    app: &Router,
    prefix: &str,
    token: &str,
    key: &str,
    version: &str,
) -> StatusCode {
    let request = bearer(
        Request::builder().uri(format!(
            "{prefix}/_apis/artifactcache/cache?keys={key}&version={version}"
        )),
        token,
    ).body(Body::empty()).unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

async fn assert_all_cache_handlers_reject(
    app: &Router,
    token: &str,
    expected: StatusCode,
) {
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let requests = [
        bearer(Request::builder().uri(format!(
            "{prefix}/_apis/artifactcache/cache?keys=k&version=v1"
        )), token).body(Body::empty()).unwrap(),
        bearer(Request::builder().method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches"))
            .header("content-type", "application/json"), token)
            .body(Body::from(r#"{"key":"k","version":"v1"}"#)).unwrap(),
        bearer(Request::builder().method("PATCH")
            .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
            .header("content-range", "bytes 0-0/*"), token)
            .body(Body::from("x")).unwrap(),
        bearer(Request::builder().method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
            .header("content-type", "application/json"), token)
            .body(Body::from(r#"{"size":1}"#)).unwrap(),
    ];
    for request in requests {
        assert_eq!(app.clone().oneshot(request).await.unwrap().status(), expected);
    }
}

#[tokio::test]
async fn expired_capability_is_unauthorized_on_all_cache_api_handlers() {
    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app_without_registration(&tmp).await;
    authority.register_job(
        "expired-token",
        JobCapabilityClaims {
            scope: CacheScope {
                repo: SCOPE_REPO.into(),
                git_ref: SCOPE_REF.into(),
                default_ref: DEFAULT_REF.into(),
            },
            job_id: "expired-job".into(),
        },
        Utc::now() - chrono::Duration::hours(6) - chrono::Duration::minutes(11),
    ).await.unwrap();
    assert_all_cache_handlers_reject(&app, "expired-token", StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn authority_restart_rejects_old_token_but_preserves_scoped_entries() {
    let tmp = TempDir::new().unwrap();
    let (first_app, manager, first_authority) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    authorized_roundtrip(&first_app, &prefix, TOKEN_A, "persisted", b"bytes").await;
    drop(first_app);
    drop(first_authority);

    let second_authority = Arc::new(CacheAuthority::new());
    let second_app = router(manager, second_authority.clone());
    assert_eq!(lookup_status(&second_app, &prefix, TOKEN_A, "persisted", "v1").await, StatusCode::UNAUTHORIZED);
    second_authority.register_job(
        "new-runtime-token",
        JobCapabilityClaims {
            scope: CacheScope {
                repo: SCOPE_REPO.into(),
                git_ref: SCOPE_REF.into(),
                default_ref: DEFAULT_REF.into(),
            },
            job_id: "new-job".into(),
        },
        Utc::now(),
    ).await.unwrap();
    assert_eq!(lookup_status(&second_app, &prefix, "new-runtime-token", "persisted", "v1").await, StatusCode::OK);
}
```

- [ ] **Step 2: Запустить acceptance edge tests и подтвердить GREEN**

Run:

```bash
cargo test cache::server::server_test::expired_capability_is_unauthorized_on_all_cache_api_handlers -- --nocapture
cargo test cache::server::server_test::authority_restart_rejects_old_token_but_preserves_scoped_entries -- --nocapture
```

Expected: PASS.

- [ ] **Step 3: Заменить 5-client test на 20-client mixed-scope roundtrips**

В `concurrent_http_clients` заранее положить по одной default-branch entry для двух repositories, затем зарегистрировать 20 уникальных `runtime-{i}` с `job-{i}`. Чётные clients используют `org/repo-a`, нечётные `org/repo-b`; каждый четвёртый использует feature ref с `default_ref=main`, остальные main. Каждый task делает reserve → upload → commit → lookup → GET `archiveLocation` и проверяет собственные bytes; feature clients дополнительно читают default-branch fixture своего repository:

```rust
#[tokio::test]
async fn concurrent_http_clients() {
    let tmp = TempDir::new().unwrap();
    let manager = make_test_manager(&tmp).await;
    let authority = Arc::new(CacheAuthority::new());
    for (repo, token, bytes) in [
        ("org/repo-a", "seed-a", b"fallback-a".as_slice()),
        ("org/repo-b", "seed-b", b"fallback-b".as_slice()),
    ] {
        let owner = CapabilityId::from_token(token);
        let id = manager.reserve_upload(
            owner.clone(),
            format!("{token}-job"),
            "default-fallback".into(),
            "v1".into(),
            repo.into(),
            "refs/heads/main".into(),
        ).await.unwrap();
        manager.write_chunk(&owner, id, 0, bytes).await.unwrap();
        manager.commit_upload(&owner, id, bytes.len() as u64).await.unwrap();
    }
    let addr = start(manager, authority.clone(), 0).await.unwrap();
    let base_url = format!("http://{addr}");
    let client = reqwest::Client::new();
    let mut handles = Vec::new();

    for i in 0..20 {
        let token = format!("runtime-{i}");
        let job_id = format!("job-{i}");
        let repo = if i % 2 == 0 { "org/repo-a" } else { "org/repo-b" };
        let git_ref = if i % 4 == 0 { "refs/heads/feature" } else { "refs/heads/main" };
        let prefix = scope_prefix(repo, git_ref, "refs/heads/main");
        authority.register_job(
            &token,
            JobCapabilityClaims {
                scope: CacheScope {
                    repo: repo.into(),
                    git_ref: git_ref.into(),
                    default_ref: "refs/heads/main".into(),
                },
                job_id,
            },
            Utc::now(),
        ).await.unwrap();

        let client = client.clone();
        let base_url = base_url.clone();
        handles.push(tokio::spawn(async move {
            let key = format!("concurrent-{i}");
            let data = format!("concurrent-data-{i}");
            let response = client
                .post(format!("{base_url}{prefix}/_apis/artifactcache/caches"))
                .bearer_auth(&token)
                .json(&serde_json::json!({ "key": key, "version": "v1" }))
                .send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let cache_id = response.json::<serde_json::Value>().await.unwrap()["cacheId"]
                .as_u64().unwrap();

            let response = client
                .patch(format!("{base_url}{prefix}/_apis/artifactcache/caches/{cache_id}"))
                .bearer_auth(&token)
                .header("content-range", format!("bytes 0-{}/*", data.len() - 1))
                .body(data.clone())
                .send().await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            let response = client
                .post(format!("{base_url}{prefix}/_apis/artifactcache/caches/{cache_id}"))
                .bearer_auth(&token)
                .json(&serde_json::json!({ "size": data.len() }))
                .send().await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            let response = client
                .get(format!("{base_url}{prefix}/_apis/artifactcache/cache?keys={key}&version=v1"))
                .bearer_auth(&token)
                .send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let archive_location = response.json::<serde_json::Value>().await.unwrap()
                ["archiveLocation"].as_str().unwrap().to_string();
            let downloaded = client.get(archive_location).send().await.unwrap();
            assert_eq!(downloaded.status(), StatusCode::OK);
            assert_eq!(downloaded.bytes().await.unwrap(), data.as_bytes());

            if git_ref == "refs/heads/feature" {
                let response = client
                    .get(format!("{base_url}{prefix}/_apis/artifactcache/cache?keys=default-fallback&version=v1"))
                    .bearer_auth(&token)
                    .send().await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let archive_location = response.json::<serde_json::Value>().await.unwrap()
                    ["archiveLocation"].as_str().unwrap().to_string();
                let restored = client.get(archive_location).send().await.unwrap();
                let expected = if repo == "org/repo-a" { b"fallback-a".as_slice() } else { b"fallback-b".as_slice() };
                assert_eq!(restored.bytes().await.unwrap(), expected);
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
```

После join проверить 20 успешных bodies. Keys должны включать `i`, чтобы тест проверял concurrency/ownership, а отдельные C-02/C-11 tests продолжали проверять изоляцию одинаковых key/version.

- [ ] **Step 4: Запустить 20-client acceptance test с loopback bind**

Run:

```bash
cargo test cache::server::server_test::concurrent_http_clients -- --nocapture
```

Expected: PASS, 20/20 roundtrips. Если sandbox запрещает `TcpListener::bind`, повторить ту же команду с разрешённым loopback/network execution; `Operation not permitted` не считать продуктовым failure и не ослаблять test до 5 clients.

- [ ] **Step 5: Обновить protocol documentation**

В `docs/gh-protocol.md` заменить утверждение “No authentication” и hash download contract следующими точными положениями:

```markdown
Every cache REST request sends `Authorization: Bearer $ACTIONS_RUNTIME_TOKEN`.
Chimera registers that token as an in-memory job capability before steps start,
binds it server-side to repository, current ref, default ref and job ID, expires it
after 6 hours 10 minutes, and revokes it when the job finishes.

The base64url path segments remain part of `ACTIONS_CACHE_URL` for legacy-client
compatibility. They are checked against the registered capability and are not an
authorization mechanism.

On a cache hit, `archiveLocation` is `/download/{grant_id}`. The opaque UUID v4
grant is bound server-side to the authorized job and one blob; it contains neither
the runtime token nor the blob hash and stops working when its parent job capability
is revoked or expires.
```

Обновить примеры `http://host:port/download/{hash}` на `http://host:port/download/{grant_id}` и описать статусы `401`, `403`, `404` согласно спецификации.

- [ ] **Step 6: Запустить format, lints и полный suite**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Expected: все команды exit 0, без warnings. Для полного `cargo test` использовать разрешённый loopback bind, потому что baseline `concurrent_http_clients` требует локальный TCP listener.

- [ ] **Step 7: Сопоставить tests с issue acceptance и проверить diff**

Run:

```bash
git diff --check
git status --short
git diff --stat 09146be..HEAD
```

Expected: no whitespace errors; modified files ограничены перечисленной File Structure; C-01…C-14 из spec представлены именованными tests или существующими storage tests.

- [ ] **Step 8: Commit acceptance tests and docs**

```bash
git add src/cache/server_test.rs docs/gh-protocol.md
git commit -m "test: verify authorized cache concurrency"
```

### Task 7: Финальная проверка по DPL-08

**Files:**
- Verify only: весь branch относительно `09146be`

**Interfaces:**
- Consumes: Tasks 1–6.
- Produces: проверенный implementation branch без дополнительных функциональных изменений.

- [ ] **Step 1: Проверить историю и отсутствие несвязанных изменений**

Run:

```bash
git log --oneline 09146be..HEAD
git diff --name-only 09146be..HEAD
git status --short
```

Expected commits: authority, API scope, upload ownership, download grants, runner lifecycle, acceptance/docs; worktree clean.

- [ ] **Step 2: Выполнить targeted security matrix**

Run:

```bash
cargo test cache::auth -- --nocapture
cargo test cache::upload -- --nocapture
cargo test cache::server::server_test -- --nocapture
cargo test runner::instance::instance_test -- --nocapture
```

Expected: PASS, включая missing/foreign/expired/revoked capability, owner mismatch, direct-hash rejection, default fallback и 20 clients.

- [ ] **Step 3: Выполнить финальный полный verification**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Expected: exit 0 для всех команд. Сохранить точные totals и длительность для итогового отчёта; любой unrelated baseline failure указать по имени, не скрывать.

- [ ] **Step 4: Провести whole-branch review относительно spec**

Проверить diff `09146be..HEAD` по двум осям:

```text
Standards: Rust ownership/locking/error mapping/log secrecy и отсутствие I/O под authority locks.
Spec: C-01…C-14, GHR 6h10m, revoke ordering, opaque download grant, 20 clients.
```

Исправления review выполнять отдельными TDD red-green циклами и отдельным commit; не добавлять refactoring вне DPL-08.
