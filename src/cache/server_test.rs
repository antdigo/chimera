use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use tempfile::TempDir;
use tower::ServiceExt;

use super::*;
use crate::cache::auth::{
    CacheAuthority, CacheScope, CapabilityId, JOB_CAPABILITY_LIFETIME, JobCapabilityClaims,
};
use crate::cache::manager::CacheManager;

const SCOPE_REPO: &str = "owner/repo";
const SCOPE_REF: &str = "refs/heads/main";
const DEFAULT_REF: &str = "refs/heads/main";
const TOKEN_A: &str = "runtime-token-a";
const TOKEN_B: &str = "runtime-token-b";

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

async fn reserve(app: &Router, prefix: &str, token: &str, key: &str, version: &str) -> u64 {
    let request = bearer(
        Request::builder()
            .method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches"))
            .header("content-type", "application/json"),
        token,
    )
    .body(Body::from(
        serde_json::json!({ "key": key, "version": version }).to_string(),
    ))
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["cacheId"]
        .as_u64()
        .unwrap()
}

async fn upload(app: &Router, prefix: &str, token: &str, cache_id: u64, data: &[u8]) -> StatusCode {
    let request = bearer(
        Request::builder()
            .method("PATCH")
            .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
            .header("content-range", format!("bytes 0-{}/*", data.len() - 1)),
        token,
    )
    .body(Body::from(Bytes::copy_from_slice(data)))
    .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

async fn commit(app: &Router, prefix: &str, token: &str, cache_id: u64, size: usize) -> StatusCode {
    let request = bearer(
        Request::builder()
            .method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
            .header("content-type", "application/json"),
        token,
    )
    .body(Body::from(serde_json::json!({ "size": size }).to_string()))
    .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
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
    )
    .header("host", "localhost:9999")
    .body(Body::empty())
    .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

async fn lookup(app: &Router, prefix: &str, token: &str, key: &str, version: &str) -> String {
    let request = bearer(
        Request::builder().uri(format!(
            "{prefix}/_apis/artifactcache/cache?keys={key}&version={version}"
        )),
        token,
    )
    .header("host", "localhost:9999")
    .body(Body::empty())
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["archiveLocation"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn authorized_roundtrip(
    app: &Router,
    prefix: &str,
    token: &str,
    key: &str,
    data: &[u8],
) -> (CapabilityId, String) {
    let cache_id = reserve(app, prefix, token, key, "v1").await;
    assert_eq!(
        upload(app, prefix, token, cache_id, data).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        commit(app, prefix, token, cache_id, data.len()).await,
        StatusCode::NO_CONTENT
    );
    let archive_location = lookup(app, prefix, token, key, "v1").await;
    (CapabilityId::from_token(token), archive_location)
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
    (
        router(manager.clone(), authority.clone()),
        manager,
        authority,
    )
}

async fn make_test_app_without_registration(
    tmp: &TempDir,
) -> (Router, SharedManager, Arc<CacheAuthority>) {
    let manager = make_test_manager(tmp).await;
    let authority = Arc::new(CacheAuthority::new());
    (
        router(manager.clone(), authority.clone()),
        manager,
        authority,
    )
}

async fn assert_all_cache_handlers_reject(app: &Router, token: &str, expected: StatusCode) {
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let requests = [
        bearer(
            Request::builder().uri(format!(
                "{prefix}/_apis/artifactcache/cache?keys=k&version=v1"
            )),
            token,
        )
        .body(Body::empty())
        .unwrap(),
        bearer(
            Request::builder()
                .method("POST")
                .uri(format!("{prefix}/_apis/artifactcache/caches"))
                .header("content-type", "application/json"),
            token,
        )
        .body(Body::from(r#"{"key":"k","version":"v1"}"#))
        .unwrap(),
        bearer(
            Request::builder()
                .method("PATCH")
                .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
                .header("content-range", "bytes 0-0/*"),
            token,
        )
        .body(Body::from("x"))
        .unwrap(),
        bearer(
            Request::builder()
                .method("POST")
                .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
                .header("content-type", "application/json"),
            token,
        )
        .body(Body::from(r#"{"size":1}"#))
        .unwrap(),
    ];

    for request in requests {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            expected,
        );
    }
}

#[tokio::test]
async fn expired_capability_is_unauthorized_on_all_cache_api_handlers() {
    let tmp = TempDir::new().unwrap();
    let manager = make_test_manager(&tmp).await;
    let issued_at = Utc::now();
    let clock_value = Arc::new(std::sync::Mutex::new(issued_at));
    let clock_reader = clock_value.clone();
    let authority = Arc::new(CacheAuthority::with_clock(Arc::new(move || {
        *clock_reader.lock().unwrap()
    })));
    let app = router(manager, authority.clone());
    authority
        .register_job(
            "expired-token",
            JobCapabilityClaims {
                scope: CacheScope {
                    repo: SCOPE_REPO.into(),
                    git_ref: SCOPE_REF.into(),
                    default_ref: DEFAULT_REF.into(),
                },
                job_id: "expired-job".into(),
            },
            issued_at,
        )
        .await
        .unwrap();

    *clock_value.lock().unwrap() = issued_at + JOB_CAPABILITY_LIFETIME;
    assert_all_cache_handlers_reject(&app, "expired-token", StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn authority_restart_rejects_old_token_but_preserves_scoped_entries() {
    let tmp = TempDir::new().unwrap();
    let (first_app, manager, first_authority) = make_test_app_without_registration(&tmp).await;
    first_authority
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
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    authorized_roundtrip(&first_app, &prefix, TOKEN_A, "persisted", b"bytes").await;
    drop(first_app);
    drop(first_authority);

    let second_authority = Arc::new(CacheAuthority::new());
    let second_app = router(manager, second_authority.clone());
    assert_eq!(
        lookup_status(&second_app, &prefix, TOKEN_A, "persisted", "v1").await,
        StatusCode::UNAUTHORIZED,
    );
    second_authority
        .register_job(
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
        )
        .await
        .unwrap();
    assert_eq!(
        lookup_status(&second_app, &prefix, "new-runtime-token", "persisted", "v1",).await,
        StatusCode::OK,
    );
}

#[tokio::test]
async fn every_cache_api_handler_rejects_missing_bearer() {
    let tmp = TempDir::new().unwrap();
    let (app, _, _) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let cases = [
        Request::builder()
            .uri(format!(
                "{prefix}/_apis/artifactcache/cache?keys=k&version=v1"
            ))
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"key":"k","version":"v1"}"#))
            .unwrap(),
        Request::builder()
            .method("PATCH")
            .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
            .header("content-range", "bytes 0-0/*")
            .body(Body::from("x"))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"size":1}"#))
            .unwrap(),
    ];
    for request in cases {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
        );
    }
}

#[tokio::test]
async fn unauthenticated_requests_reject_before_parsing_or_body_buffering() {
    let tmp = TempDir::new().unwrap();
    let (app, _, _) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let cases = [
        Request::builder()
            .uri(format!("{prefix}/_apis/artifactcache/cache?keys=k"))
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches"))
            .header("content-type", "text/plain")
            .body(Body::from("not json"))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches"))
            .header("content-type", "application/json")
            .body(Body::from("not json"))
            .unwrap(),
        Request::builder()
            .method("PATCH")
            .uri(format!("{prefix}/_apis/artifactcache/caches/not-a-number"))
            .header("content-range", "bytes 0-0/*")
            .body(Body::from("x"))
            .unwrap(),
        Request::builder()
            .method("PATCH")
            .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
            .header("content-range", "bytes 0-0/*")
            .header("content-length", "268435457")
            .body(Body::empty())
            .unwrap(),
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
        for value in values {
            builder = builder.header("authorization", value);
        }
        assert_eq!(
            app.clone()
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED,
        );
    }

    let request = Request::builder()
        .uri(uri)
        .header("authorization", "Bearer runtime-token-a")
        .header("authorization", "Bearer runtime-token-b")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
    );
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
        )
        .body(Body::empty())
        .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN,
        );
    }
}

#[tokio::test]
async fn another_job_in_same_scope_cannot_write_or_commit_upload() {
    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app(&tmp).await;
    authority
        .register_job(
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
        )
        .await
        .unwrap();

    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let cache_id = reserve(&app, &prefix, TOKEN_A, "owned", "v1").await;
    assert_eq!(
        upload(&app, &prefix, "runtime-token-b", cache_id, b"evil").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        commit(&app, &prefix, "runtime-token-b", cache_id, 4).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        upload(&app, &prefix, TOKEN_A, cache_id, b"owner").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        commit(&app, &prefix, TOKEN_A, cache_id, 5).await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn lookup_miss() {
    let tmp = TempDir::new().unwrap();
    let (app, _mgr, _) = make_test_app(&tmp).await;

    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let req = bearer(Request::builder(), TOKEN_A)
        .uri(format!(
            "{prefix}/_apis/artifactcache/cache?keys=nonexistent&version=v1"
        ))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn full_http_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let (app, _mgr, _) = make_test_app(&tmp).await;

    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let data = b"test cache data for http roundtrip";

    // 1. Reserve
    let req = bearer(Request::builder(), TOKEN_A)
        .method("POST")
        .uri(format!("{prefix}/_apis/artifactcache/caches"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "key": "http-key",
                "version": "v1"
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let reserve_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cache_id = reserve_resp["cacheId"].as_u64().unwrap();

    // 2. Upload chunk
    let req = bearer(Request::builder(), TOKEN_A)
        .method("PATCH")
        .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
        .header("content-range", format!("bytes 0-{}/*", data.len() - 1))
        .body(Body::from(Bytes::from_static(data)))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 3. Commit
    let req = bearer(Request::builder(), TOKEN_A)
        .method("POST")
        .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "size": data.len()
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 4. Lookup
    let req = bearer(Request::builder(), TOKEN_A)
        .uri(format!(
            "{prefix}/_apis/artifactcache/cache?keys=http-key&version=v1"
        ))
        .header("host", "localhost:9999")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let lookup_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(lookup_resp["cacheKey"], "http-key");
    assert_eq!(lookup_resp["scope"], SCOPE_REF);

    let archive_location = lookup_resp["archiveLocation"].as_str().unwrap();
    assert!(archive_location.starts_with("http://localhost:9999/download/"));

    // 5. Download (global, no scope prefix)
    let download_path = archive_location
        .strip_prefix("http://localhost:9999")
        .unwrap();
    let req = Request::builder()
        .uri(download_path)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    assert_eq!(&body[..], data);
}

#[tokio::test]
async fn invalid_download_grants_return_not_found() {
    let tmp = TempDir::new().unwrap();
    let (app, _mgr, _) = make_test_app(&tmp).await;

    let req = Request::builder()
        .uri("/download/nonexistent")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let fake_hash = "a".repeat(64);
    let req = Request::builder()
        .uri(format!("/download/{fake_hash}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .uri("/download/%FF")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn blob_hash_is_not_a_download_authority() {
    let tmp = TempDir::new().unwrap();
    let (app, manager, _) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let (_, archive_location) = authorized_roundtrip(&app, &prefix, TOKEN_A, "k", b"secret").await;
    let grant_path = archive_location
        .strip_prefix("http://localhost:9999")
        .unwrap();
    let granted = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(grant_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(granted.status(), StatusCode::OK);

    let entry = manager
        .lookup(&["k".into()], "v1", SCOPE_REPO, SCOPE_REF, DEFAULT_REF)
        .await
        .unwrap();
    let direct_hash_path = format!("/download/{}", entry.blob_hash);
    let direct = app
        .oneshot(
            Request::builder()
                .uri(direct_hash_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(direct.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoke_invalidates_previously_issued_download_grant() {
    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let (capability_id, archive_location) =
        authorized_roundtrip(&app, &prefix, TOKEN_A, "k", b"secret").await;
    authority.revoke(&capability_id).await;
    let path = archive_location
        .strip_prefix("http://localhost:9999")
        .unwrap();
    assert_eq!(
        app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
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
            started_at.to_owned(),
        )
        .await
        .unwrap();
    let app = router(manager, authority);
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let (_, archive_location) = authorized_roundtrip(&app, &prefix, TOKEN_A, "k", b"secret").await;

    *clock_value.lock().unwrap() =
        started_at + JOB_CAPABILITY_LIFETIME + chrono::Duration::seconds(1);
    let path = archive_location
        .strip_prefix("http://localhost:9999")
        .unwrap();
    assert_eq!(
        app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
    );
}

#[tokio::test]
async fn feature_job_can_download_authorized_default_branch_fallback() {
    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app(&tmp).await;
    let main_prefix = scope_prefix(SCOPE_REPO, DEFAULT_REF, DEFAULT_REF);
    authorized_roundtrip(&app, &main_prefix, TOKEN_A, "shared", b"main-cache").await;

    authority
        .register_job(
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
        )
        .await
        .unwrap();
    let feature_prefix = scope_prefix(SCOPE_REPO, "refs/heads/feature", DEFAULT_REF);
    let archive_location = lookup(&app, &feature_prefix, "runtime-feature", "shared", "v1").await;
    let path = archive_location
        .strip_prefix("http://localhost:9999")
        .unwrap();
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        b"main-cache"[..]
    );
}

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

    let path = archive_location
        .strip_prefix("http://localhost:9999")
        .unwrap();
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

    authority
        .register_job(
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
        )
        .await
        .unwrap();
    let repo_b_prefix = scope_prefix("org/repo-b", SCOPE_REF, DEFAULT_REF);
    assert_eq!(
        lookup_status(&app, &repo_b_prefix, "runtime-repo-b", "shared", "v1").await,
        StatusCode::NO_CONTENT,
    );
}

#[tokio::test]
async fn upload_chunk_missing_content_range() {
    let tmp = TempDir::new().unwrap();
    let (app, _mgr, _) = make_test_app(&tmp).await;

    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let req = bearer(Request::builder(), TOKEN_A)
        .method("PATCH")
        .uri(format!("{prefix}/_apis/artifactcache/caches/1"))
        .body(Body::from(Bytes::from_static(b"data")))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn v4_twirp_request_returns_404() {
    let tmp = TempDir::new().unwrap();
    let (app, _mgr, _) = make_test_app(&tmp).await;

    let req = Request::builder()
        .method("POST")
        .uri("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_path_returns_404() {
    let tmp = TempDir::new().unwrap();
    let (app, _mgr, _) = make_test_app(&tmp).await;

    let req = Request::builder()
        .uri("/some/random/path")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

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
        let id = manager
            .reserve_upload(
                owner.clone(),
                format!("{token}-job"),
                "default-fallback".into(),
                "v1".into(),
                repo.into(),
                "refs/heads/main".into(),
            )
            .await
            .unwrap();
        manager.write_chunk(&owner, id, 0, bytes).await.unwrap();
        manager
            .commit_upload(&owner, id, bytes.len() as u64)
            .await
            .unwrap();
    }

    let addr = start(manager, authority.clone(), 0).await.unwrap();
    let base_url = format!("http://{addr}");
    let client = reqwest::Client::new();
    let mut handles = Vec::new();

    for i in 0..20 {
        let token = format!("runtime-{i}");
        let job_id = format!("job-{i}");
        let repo = if i % 2 == 0 {
            "org/repo-a"
        } else {
            "org/repo-b"
        };
        let git_ref = if i % 4 == 0 {
            "refs/heads/feature"
        } else {
            "refs/heads/main"
        };
        let prefix = scope_prefix(repo, git_ref, "refs/heads/main");
        authority
            .register_job(
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
            )
            .await
            .unwrap();

        let client = client.clone();
        let base_url = base_url.clone();
        handles.push(tokio::spawn(async move {
            let key = format!("concurrent-{i}");
            let data = format!("concurrent-data-{i}");
            let response = client
                .post(format!(
                    "{base_url}{prefix}/_apis/artifactcache/caches"
                ))
                .bearer_auth(&token)
                .json(&serde_json::json!({ "key": key, "version": "v1" }))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let cache_id = response.json::<serde_json::Value>().await.unwrap()["cacheId"]
                .as_u64()
                .unwrap();

            let response = client
                .patch(format!(
                    "{base_url}{prefix}/_apis/artifactcache/caches/{cache_id}"
                ))
                .bearer_auth(&token)
                .header("content-range", format!("bytes 0-{}/*", data.len() - 1))
                .body(data.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            let response = client
                .post(format!(
                    "{base_url}{prefix}/_apis/artifactcache/caches/{cache_id}"
                ))
                .bearer_auth(&token)
                .json(&serde_json::json!({ "size": data.len() }))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            let response = client
                .get(format!(
                    "{base_url}{prefix}/_apis/artifactcache/cache?keys={key}&version=v1"
                ))
                .bearer_auth(&token)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let archive_location = response.json::<serde_json::Value>().await.unwrap()
                ["archiveLocation"]
                .as_str()
                .unwrap()
                .to_string();
            let downloaded = client.get(archive_location).send().await.unwrap();
            assert_eq!(downloaded.status(), StatusCode::OK);
            let downloaded = downloaded.bytes().await.unwrap();
            assert_eq!(downloaded, data.as_bytes());

            if git_ref == "refs/heads/feature" {
                let response = client
                    .get(format!(
                        "{base_url}{prefix}/_apis/artifactcache/cache?keys=default-fallback&version=v1"
                    ))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let archive_location = response.json::<serde_json::Value>().await.unwrap()
                    ["archiveLocation"]
                    .as_str()
                    .unwrap()
                    .to_string();
                let restored = client.get(archive_location).send().await.unwrap();
                assert_eq!(restored.status(), StatusCode::OK);
                let expected = if repo == "org/repo-a" {
                    b"fallback-a".as_slice()
                } else {
                    b"fallback-b".as_slice()
                };
                assert_eq!(restored.bytes().await.unwrap(), expected);
            }

            (i, downloaded)
        }));
    }

    let mut completed = Vec::with_capacity(20);
    for handle in handles {
        completed.push(handle.await.unwrap());
    }
    completed.sort_by_key(|(i, _)| *i);
    assert_eq!(completed.len(), 20);
    for (i, body) in completed {
        assert_eq!(body, format!("concurrent-data-{i}").as_bytes());
    }
}

#[tokio::test]
async fn scope_isolation_between_repos() {
    let tmp = TempDir::new().unwrap();
    let (app, _mgr, authority) = make_test_app(&tmp).await;
    authority
        .register_job(
            TOKEN_B,
            JobCapabilityClaims {
                scope: CacheScope {
                    repo: "org/repo-b".into(),
                    git_ref: SCOPE_REF.into(),
                    default_ref: DEFAULT_REF.into(),
                },
                job_id: "job-b".into(),
            },
            Utc::now(),
        )
        .await
        .unwrap();

    let data = b"scoped data";
    let repo_a_prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let repo_b_prefix = scope_prefix("org/repo-b", SCOPE_REF, DEFAULT_REF);

    // Upload cache under repo-a
    let req = bearer(Request::builder(), TOKEN_A)
        .method("POST")
        .uri(format!("{repo_a_prefix}/_apis/artifactcache/caches"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "key": "shared-key",
                "version": "v1"
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let reserve_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cache_id = reserve_resp["cacheId"].as_u64().unwrap();

    let req = bearer(Request::builder(), TOKEN_A)
        .method("PATCH")
        .uri(format!(
            "{repo_a_prefix}/_apis/artifactcache/caches/{cache_id}"
        ))
        .header("content-range", format!("bytes 0-{}/*", data.len() - 1))
        .body(Body::from(Bytes::from_static(data)))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let req = bearer(Request::builder(), TOKEN_A)
        .method("POST")
        .uri(format!(
            "{repo_a_prefix}/_apis/artifactcache/caches/{cache_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({ "size": data.len() })).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Lookup from repo-a should succeed
    let req = bearer(Request::builder(), TOKEN_A)
        .uri(format!(
            "{repo_a_prefix}/_apis/artifactcache/cache?keys=shared-key&version=v1"
        ))
        .header("host", "localhost:9999")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // A separately authorized repo-b job cannot see repo-a's cache.
    let req = bearer(Request::builder(), TOKEN_B)
        .uri(format!(
            "{repo_b_prefix}/_apis/artifactcache/cache?keys=shared-key&version=v1"
        ))
        .header("host", "localhost:9999")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[test]
fn scope_encode_decode_roundtrip() {
    let values = [
        "owner/repo",
        "refs/heads/main",
        "refs/heads/feature/my-branch",
        "refs/tags/v1.0.0",
        "",
    ];
    for val in values {
        let encoded = encode_scope(val);
        let decoded = decode_scope(&encoded).unwrap();
        assert_eq!(decoded, val);
    }
}

#[test]
fn decode_scope_invalid_base64() {
    let result = decode_scope("!!!invalid!!!");
    assert!(result.is_err());
}
