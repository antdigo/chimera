use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Utc};
use tempfile::TempDir;
use tower::ServiceExt;

use super::*;
use crate::cache::auth::{
    CacheAuthority, CacheScope, CapabilityEpoch, CapabilityHandle, CapabilityId,
    JOB_CAPABILITY_LIFETIME, JobCapabilityClaims,
};
use crate::cache::manager::CacheManager;
use crate::cache::test_support::Pause;

const SCOPE_REPO: &str = "owner/repo";
const SCOPE_REF: &str = "refs/heads/main";
const DEFAULT_REF: &str = "refs/heads/main";
const TOKEN_A: &str = "runtime-token-a";
const TOKEN_B: &str = "runtime-token-b";

#[derive(Clone, Copy)]
enum Invalidation {
    Revoke,
    Expire,
}

impl Invalidation {
    fn label(self) -> &'static str {
        match self {
            Self::Revoke => "revoke",
            Self::Expire => "expiry",
        }
    }
}

#[derive(Clone, Copy)]
enum QueuedUploadOperation {
    Patch,
    Commit,
}

impl QueuedUploadOperation {
    fn label(self) -> &'static str {
        match self {
            Self::Patch => "PATCH",
            Self::Commit => "commit",
        }
    }

    fn request(self, prefix: &str, cache_id: u64) -> Request<Body> {
        match self {
            Self::Patch => bearer(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
                    .header("content-range", "bytes 0-0/*"),
                TOKEN_A,
            )
            .body(Body::from("y"))
            .unwrap(),
            Self::Commit => bearer(
                Request::builder()
                    .method("POST")
                    .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
                    .header("content-type", "application/json"),
                TOKEN_A,
            )
            .body(Body::from(r#"{"size":1}"#))
            .unwrap(),
        }
    }
}

fn test_claims() -> JobCapabilityClaims {
    JobCapabilityClaims {
        scope: CacheScope {
            repo: SCOPE_REPO.into(),
            git_ref: SCOPE_REF.into(),
            default_ref: DEFAULT_REF.into(),
        },
        job_id: "job-a".into(),
    }
}

fn paused_body(bytes: &'static [u8]) -> (Body, Arc<Pause>) {
    let pause = Arc::new(Pause::default());
    let body_pause = pause.clone();
    let stream = futures::stream::once(async move {
        body_pause.reached.notify_one();
        body_pause.resume.notified().await;
        Ok::<Bytes, Infallible>(Bytes::from_static(bytes))
    });
    (Body::from_stream(stream), pause)
}

async fn make_clocked_test_app(
    tmp: &TempDir,
) -> (
    Router,
    SharedManager,
    Arc<CacheAuthority>,
    Arc<Mutex<DateTime<Utc>>>,
    CapabilityHandle,
) {
    let manager = make_test_manager(tmp).await;
    let started_at = Utc::now();
    let clock_value = Arc::new(Mutex::new(started_at));
    let clock_reader = clock_value.clone();
    let authority = Arc::new(CacheAuthority::with_clock(Arc::new(move || {
        *clock_reader.lock().unwrap()
    })));
    let capability_id = authority
        .register_job(TOKEN_A, test_claims(), started_at)
        .await
        .unwrap();
    (
        router(manager.clone(), authority.clone()),
        manager,
        authority,
        clock_value,
        capability_id,
    )
}

async fn invalidate(
    invalidation: Invalidation,
    authority: &CacheAuthority,
    capability_id: &CapabilityHandle,
    clock: &Mutex<DateTime<Utc>>,
) {
    match invalidation {
        Invalidation::Revoke => authority.revoke(capability_id).await,
        Invalidation::Expire => {
            let mut now = clock.lock().unwrap();
            *now = *now + JOB_CAPABILITY_LIFETIME + chrono::Duration::seconds(1);
        }
    }
}

async fn reactivate(authority: &CacheAuthority, clock: &Mutex<DateTime<Utc>>) {
    let issued_at = *clock.lock().unwrap();
    authority
        .register_job(TOKEN_A, test_claims(), issued_at)
        .await
        .unwrap();
}

#[tokio::test]
async fn invalid_json_is_bad_request_after_authentication() {
    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    for suffix in ["", "/1"] {
        for body in ["{", r#"{"key":42,"version":false,"size":"wrong"}"#] {
            for token in [TOKEN_A, "unknown", ""] {
                let request = bearer(
                    Request::builder()
                        .method("POST")
                        .uri(format!("{prefix}/_apis/artifactcache/caches{suffix}"))
                        .header("content-type", "application/json"),
                    token,
                )
                .body(Body::from(body))
                .unwrap();
                let expected = if token == TOKEN_A {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::UNAUTHORIZED
                };
                assert_eq!(
                    app.clone().oneshot(request).await.unwrap().status(),
                    expected
                );
            }
        }
    }
    let handle = authority
        .authenticate(TOKEN_A)
        .await
        .unwrap()
        .lifecycle_handle();
    authority.revoke(&handle).await;
    let request = bearer(
        Request::builder()
            .method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches"))
            .header("content-type", "application/json"),
        TOKEN_A,
    )
    .body(Body::from("{"))
    .unwrap();
    assert_eq!(
        app.oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn delayed_reserve_rechecks_revocation_and_expiry_before_mutation() {
    for invalidation in [Invalidation::Revoke, Invalidation::Expire] {
        let tmp = TempDir::new().unwrap();
        let (app, _, authority, clock, capability_id) = make_clocked_test_app(&tmp).await;
        let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
        let (body, pause) = paused_body(br#"{"key":"late","version":"v1"}"#);
        let request = bearer(
            Request::builder()
                .method("POST")
                .uri(format!("{prefix}/_apis/artifactcache/caches"))
                .header("content-type", "application/json"),
            TOKEN_A,
        )
        .body(body)
        .unwrap();
        let request_app = app.clone();
        let response = tokio::spawn(async move { request_app.oneshot(request).await });
        pause.reached.notified().await;

        invalidate(invalidation, &authority, &capability_id, &clock).await;
        pause.resume.notify_one();

        assert_eq!(
            response.await.unwrap().unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "{} after reserve authentication",
            invalidation.label(),
        );
        reactivate(&authority, &clock).await;
        assert_eq!(reserve(&app, &prefix, TOKEN_A, "valid", "v1").await, 1);
    }
}

#[tokio::test]
async fn delayed_patch_rechecks_revocation_and_expiry_before_mutation() {
    for invalidation in [Invalidation::Revoke, Invalidation::Expire] {
        let tmp = TempDir::new().unwrap();
        let (app, _, authority, clock, capability_id) = make_clocked_test_app(&tmp).await;
        let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
        let cache_id = reserve(&app, &prefix, TOKEN_A, "late-patch", "v1").await;
        let (body, pause) = paused_body(b"x");
        let request = bearer(
            Request::builder()
                .method("PATCH")
                .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
                .header("content-range", "bytes 0-0/*"),
            TOKEN_A,
        )
        .body(body)
        .unwrap();
        let request_app = app.clone();
        let response = tokio::spawn(async move { request_app.oneshot(request).await });
        pause.reached.notified().await;

        invalidate(invalidation, &authority, &capability_id, &clock).await;
        pause.resume.notify_one();

        assert_eq!(
            response.await.unwrap().unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "{} after PATCH authentication",
            invalidation.label(),
        );
        assert_eq!(
            tokio::fs::read(
                tmp.path()
                    .join("tmp")
                    .join(format!("upload-{cache_id}.tmp"))
            )
            .await
            .unwrap(),
            b"",
            "{} allowed a delayed PATCH to mutate the session",
            invalidation.label(),
        );
    }
}

#[tokio::test]
async fn delayed_commit_rechecks_revocation_and_expiry_before_publication() {
    for invalidation in [Invalidation::Revoke, Invalidation::Expire] {
        let tmp = TempDir::new().unwrap();
        let (app, manager, authority, clock, capability_id) = make_clocked_test_app(&tmp).await;
        let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
        let cache_id = reserve(&app, &prefix, TOKEN_A, "late-commit", "v1").await;
        assert_eq!(
            upload(&app, &prefix, TOKEN_A, cache_id, b"x").await,
            StatusCode::NO_CONTENT,
        );
        let (body, pause) = paused_body(br#"{"size":1}"#);
        let request = bearer(
            Request::builder()
                .method("POST")
                .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
                .header("content-type", "application/json"),
            TOKEN_A,
        )
        .body(body)
        .unwrap();
        let request_app = app.clone();
        let response = tokio::spawn(async move { request_app.oneshot(request).await });
        pause.reached.notified().await;

        invalidate(invalidation, &authority, &capability_id, &clock).await;
        pause.resume.notify_one();

        assert_eq!(
            response.await.unwrap().unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "{} after commit authentication",
            invalidation.label(),
        );
        assert!(
            manager
                .lookup(
                    &["late-commit".into()],
                    "v1",
                    SCOPE_REPO,
                    SCOPE_REF,
                    DEFAULT_REF,
                )
                .await
                .is_none(),
            "{} allowed a delayed commit to publish an entry",
            invalidation.label(),
        );
        assert_eq!(
            tokio::fs::read(
                tmp.path()
                    .join("tmp")
                    .join(format!("upload-{cache_id}.tmp"))
            )
            .await
            .unwrap(),
            b"x",
            "{} consumed the session before rejecting delayed commit",
            invalidation.label(),
        );
        reactivate(&authority, &clock).await;
        assert_eq!(
            commit(&app, &prefix, TOKEN_A, cache_id, 1).await,
            StatusCode::NOT_FOUND,
            "{} let a replacement epoch inherit the old session",
            invalidation.label(),
        );
    }
}

#[tokio::test]
async fn reused_token_cannot_mutate_or_publish_previous_epoch_uploads() {
    for invalidation in [Invalidation::Revoke, Invalidation::Expire] {
        let tmp = TempDir::new().unwrap();
        let (app, manager, authority, clock, capability_id) = make_clocked_test_app(&tmp).await;
        let old_prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
        let patch_id = reserve(&app, &old_prefix, TOKEN_A, "old-patch", "v1").await;
        let commit_id = reserve(&app, &old_prefix, TOKEN_A, "old-commit", "v1").await;
        assert_eq!(
            upload(&app, &old_prefix, TOKEN_A, commit_id, b"old").await,
            StatusCode::NO_CONTENT,
        );

        invalidate(invalidation, &authority, &capability_id, &clock).await;
        let reused_at = *clock.lock().unwrap();
        authority
            .register_job(
                TOKEN_A,
                JobCapabilityClaims {
                    scope: CacheScope {
                        repo: "other/repo".into(),
                        git_ref: SCOPE_REF.into(),
                        default_ref: DEFAULT_REF.into(),
                    },
                    job_id: "job-b".into(),
                },
                reused_at,
            )
            .await
            .unwrap();
        let new_prefix = scope_prefix("other/repo", SCOPE_REF, DEFAULT_REF);

        assert_eq!(
            upload(&app, &new_prefix, TOKEN_A, patch_id, b"evil").await,
            StatusCode::NOT_FOUND,
            "{} let a new epoch write an old upload",
            invalidation.label(),
        );
        assert_eq!(
            tokio::fs::read(
                tmp.path()
                    .join("tmp")
                    .join(format!("upload-{patch_id}.tmp"))
            )
            .await
            .unwrap(),
            b"",
            "{} mutated the old upload",
            invalidation.label(),
        );
        assert_eq!(
            commit(&app, &new_prefix, TOKEN_A, commit_id, 3).await,
            StatusCode::NOT_FOUND,
            "{} let a new epoch commit an old upload",
            invalidation.label(),
        );
        assert!(
            manager
                .lookup(
                    &["old-commit".into()],
                    "v1",
                    SCOPE_REPO,
                    SCOPE_REF,
                    DEFAULT_REF,
                )
                .await
                .is_none(),
            "{} published the old upload",
            invalidation.label(),
        );
    }
}

#[tokio::test]
async fn queued_lookup_rechecks_revocation_and_expiry_before_mutating_index() {
    for invalidation in [Invalidation::Revoke, Invalidation::Expire] {
        let tmp = TempDir::new().unwrap();
        let (app, manager, authority, clock, capability) = make_clocked_test_app(&tmp).await;
        let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
        authorized_roundtrip(&app, &prefix, TOKEN_A, "queued-hit", b"data").await;
        let entry_path = std::fs::read_dir(tmp.path().join("entries"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let persisted_before = std::fs::read(&entry_path).unwrap();
        let hits_before = manager.stats.hits.load(Ordering::Relaxed);
        let misses_before = manager.stats.misses.load(Ordering::Relaxed);

        let index_pause = manager.arm_before_lookup_index();
        let blocker_manager = manager.clone();
        let blocker = tokio::spawn(async move {
            blocker_manager
                .lookup(
                    &["blocker-miss".into()],
                    "v1",
                    SCOPE_REPO,
                    SCOPE_REF,
                    DEFAULT_REF,
                )
                .await
        });
        index_pause.reached.notified().await;

        let index_wait = manager.arm_before_lookup_index_wait();
        let request_app = app.clone();
        let request_prefix = prefix.clone();
        let response = tokio::spawn(async move {
            lookup_status(&request_app, &request_prefix, TOKEN_A, "queued-hit", "v1").await
        });
        index_wait.reached.notified().await;

        let status = match invalidation {
            Invalidation::Revoke => {
                let mut revoke = Box::pin(authority.revoke(&capability));
                let revoke_pending = futures::poll!(&mut revoke).is_pending();
                assert!(
                    revoke_pending,
                    "lookup barrier was reached without retaining its operation permit",
                );
                index_wait.resume.notify_one();
                index_pause.resume.notify_one();
                blocker.await.unwrap();
                if revoke_pending {
                    let (response, ()) = tokio::join!(response, revoke);
                    response.unwrap()
                } else {
                    response.await.unwrap()
                }
            }
            Invalidation::Expire => {
                {
                    let mut now = clock.lock().unwrap();
                    *now = *now + JOB_CAPABILITY_LIFETIME + chrono::Duration::seconds(1);
                }
                index_wait.resume.notify_one();
                index_pause.resume.notify_one();
                blocker.await.unwrap();
                response.await.unwrap()
            }
        };

        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", invalidation.label());
        assert_eq!(manager.stats.hits.load(Ordering::Relaxed), hits_before);
        assert_eq!(
            manager.stats.misses.load(Ordering::Relaxed),
            misses_before + 1,
            "only the explicit blocker miss may mutate statistics",
        );
        assert_eq!(std::fs::read(entry_path).unwrap(), persisted_before);
    }
}

#[tokio::test]
async fn lookup_expiring_during_persistence_does_not_issue_a_download_grant() {
    let tmp = TempDir::new().unwrap();
    let (app, manager, authority, clock, _) = make_clocked_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    authorized_roundtrip(&app, &prefix, TOKEN_A, "expiring-hit", b"secret").await;

    let persistence = manager.arm_before_lookup_persist();
    let request = bearer(
        Request::builder().uri(format!(
            "{prefix}/_apis/artifactcache/cache?keys=expiring-hit&version=v1"
        )),
        TOKEN_A,
    )
    .header("host", "localhost:9999")
    .body(Body::empty())
    .unwrap();
    let response = tokio::spawn(async move { app.oneshot(request).await });
    persistence.reached.notified().await;

    {
        let mut now = clock.lock().unwrap();
        *now = *now + JOB_CAPABILITY_LIFETIME + chrono::Duration::seconds(1);
    }
    persistence.resume.notify_one();

    assert_eq!(
        response.await.unwrap().unwrap().status(),
        StatusCode::UNAUTHORIZED,
    );
    assert_eq!(authority.download_count().await, 0);
}

#[tokio::test]
async fn stalled_lookup_persistence_does_not_block_an_unrelated_job_lookup() {
    let tmp = TempDir::new().unwrap();
    let (app, manager, authority) = make_test_app(&tmp).await;
    let first_prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    authorized_roundtrip(&app, &first_prefix, TOKEN_A, "slow-hit", b"data").await;
    authority
        .register_job(
            TOKEN_B,
            JobCapabilityClaims {
                scope: CacheScope {
                    repo: "other/repo".into(),
                    git_ref: SCOPE_REF.into(),
                    default_ref: DEFAULT_REF.into(),
                },
                job_id: "job-b".into(),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    let other_prefix = scope_prefix("other/repo", SCOPE_REF, DEFAULT_REF);

    let persistence = manager.arm_before_lookup_persist();
    let first_app = app.clone();
    let first = tokio::spawn(async move {
        lookup_status(&first_app, &first_prefix, TOKEN_A, "slow-hit", "v1").await
    });
    persistence.reached.notified().await;

    let independent = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        lookup_status(&app, &other_prefix, TOKEN_B, "independent-miss", "v1"),
    )
    .await;
    persistence.resume.notify_one();
    assert_eq!(first.await.unwrap(), StatusCode::OK);
    assert_eq!(
        independent.expect("global index lock blocked unrelated lookup"),
        StatusCode::NO_CONTENT,
    );
}

#[tokio::test]
async fn aborted_commit_keeps_permit_until_blocking_io_and_publication_finish() {
    let tmp = TempDir::new().unwrap();
    let (app, manager, authority) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let cache_id = reserve(&app, &prefix, TOKEN_A, "cancelled-waiter", "v1").await;
    assert_eq!(
        upload(&app, &prefix, TOKEN_A, cache_id, b"data").await,
        StatusCode::NO_CONTENT,
    );
    let handle = authority
        .authenticate(TOKEN_A)
        .await
        .unwrap()
        .lifecycle_handle();
    let blocking_io = manager.arm_before_blob_store_io();
    let request = bearer(
        Request::builder()
            .method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
            .header("content-type", "application/json"),
        TOKEN_A,
    )
    .body(Body::from(r#"{"size":4}"#))
    .unwrap();
    let response = tokio::spawn(async move { app.oneshot(request).await });
    blocking_io.reached.notified().await;

    response.abort();
    assert!(response.await.unwrap_err().is_cancelled());
    let mut revoke = Box::pin(authority.revoke(&handle));
    let revoke_pending = futures::poll!(&mut revoke).is_pending();
    blocking_io.resume();
    if revoke_pending {
        revoke.await;
    }

    assert!(
        revoke_pending,
        "handler cancellation released the permit while blocking I/O was still running",
    );
    assert!(
        manager
            .lookup(
                &["cancelled-waiter".into()],
                "v1",
                SCOPE_REPO,
                SCOPE_REF,
                DEFAULT_REF,
            )
            .await
            .is_some(),
        "the admitted commit did not finish publication before revoke returned",
    );
}

#[tokio::test]
async fn queued_patch_rechecks_authority_after_waiting_for_its_session() {
    let tmp = TempDir::new().unwrap();
    let (app, manager, authority) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let cache_id = reserve(&app, &prefix, TOKEN_A, "queued", "v1").await;
    let pause = manager.arm_before_upload_write();
    let first_request = bearer(
        Request::builder()
            .method("PATCH")
            .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
            .header("content-range", "bytes 0-0/*"),
        TOKEN_A,
    )
    .body(Body::from("a"))
    .unwrap();
    let first_app = app.clone();
    let first_response = tokio::spawn(async move { first_app.oneshot(first_request).await });
    pause.reached.notified().await;

    let session_wait = manager.arm_before_upload_session_wait();
    let second_request = bearer(
        Request::builder()
            .method("PATCH")
            .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
            .header("content-range", "bytes 0-0/*"),
        TOKEN_A,
    )
    .body(Body::from("b"))
    .unwrap();
    let second_response = app.clone().oneshot(second_request);
    tokio::pin!(second_response);
    assert!(futures::poll!(&mut second_response).is_pending());
    session_wait.reached.notified().await;
    session_wait.resume.notify_one();
    assert!(futures::poll!(&mut second_response).is_pending());

    let capability_id = authority
        .authenticate(TOKEN_A)
        .await
        .unwrap()
        .lifecycle_handle();
    let mut revoke = Box::pin(authority.revoke(&capability_id));
    let revoke_pending = futures::poll!(&mut revoke).is_pending();
    pause.resume.notify_one();
    assert_eq!(
        first_response.await.unwrap().unwrap().status(),
        StatusCode::NO_CONTENT,
    );
    if revoke_pending {
        revoke.await;
    }
    let second_status = second_response.await.unwrap().status();

    assert!(
        revoke_pending,
        "revoke returned while an admitted write was in flight"
    );
    assert_eq!(second_status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn queued_uploads_check_authority_before_disclosing_a_consumed_session() {
    for invalidation in [Invalidation::Revoke, Invalidation::Expire] {
        for operation in [QueuedUploadOperation::Patch, QueuedUploadOperation::Commit] {
            let tmp = TempDir::new().unwrap();
            let (app, manager, authority, clock, capability) = make_clocked_test_app(&tmp).await;
            let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
            let cache_id = reserve(&app, &prefix, TOKEN_A, "consumed", "v1").await;
            assert_eq!(
                upload(&app, &prefix, TOKEN_A, cache_id, b"x").await,
                StatusCode::NO_CONTENT,
            );

            let before_commit = manager.arm_before_upload_commit();
            let consumer_request = bearer(
                Request::builder()
                    .method("POST")
                    .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
                    .header("content-type", "application/json"),
                TOKEN_A,
            )
            .body(Body::from(r#"{"size":1}"#))
            .unwrap();
            let consumer_app = app.clone();
            let consumer =
                tokio::spawn(async move { consumer_app.oneshot(consumer_request).await });
            before_commit.reached.notified().await;

            let session_wait = manager.arm_before_upload_session_wait();
            let queued_request = operation.request(&prefix, cache_id);
            let queued_app = app.clone();
            let queued = tokio::spawn(async move { queued_app.oneshot(queued_request).await });
            session_wait.reached.notified().await;

            let mut revoke = None;
            match invalidation {
                Invalidation::Revoke => {
                    revoke = Some(Box::pin(authority.revoke(&capability)));
                    assert!(
                        futures::poll!(revoke.as_mut().unwrap().as_mut()).is_pending(),
                        "revoke returned while admitted operations were paused",
                    );
                }
                Invalidation::Expire => {
                    let mut now = clock.lock().unwrap();
                    *now = *now + JOB_CAPABILITY_LIFETIME + chrono::Duration::seconds(1);
                }
            }

            session_wait.resume.notify_one();
            before_commit.resume.notify_one();
            assert_eq!(
                consumer.await.unwrap().unwrap().status(),
                StatusCode::NO_CONTENT,
            );
            assert_eq!(
                queued.await.unwrap().unwrap().status(),
                StatusCode::UNAUTHORIZED,
                "{} after {}",
                operation.label(),
                invalidation.label(),
            );
            if let Some(revoke) = revoke {
                revoke.await;
            }
        }
    }
}

#[tokio::test]
async fn revoke_waits_for_admitted_commit_publication() {
    let tmp = TempDir::new().unwrap();
    let (app, manager, authority) = make_test_app(&tmp).await;
    let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
    let cache_id = reserve(&app, &prefix, TOKEN_A, "admitted", "v1").await;
    assert_eq!(
        upload(&app, &prefix, TOKEN_A, cache_id, b"x").await,
        StatusCode::NO_CONTENT,
    );
    let pause = manager.arm_before_entry_publish();
    let request = bearer(
        Request::builder()
            .method("POST")
            .uri(format!("{prefix}/_apis/artifactcache/caches/{cache_id}"))
            .header("content-type", "application/json"),
        TOKEN_A,
    )
    .body(Body::from(r#"{"size":1}"#))
    .unwrap();
    let response = tokio::spawn(async move { app.oneshot(request).await });
    pause.reached.notified().await;

    let capability_id = authority
        .authenticate(TOKEN_A)
        .await
        .unwrap()
        .lifecycle_handle();
    let mut revoke = Box::pin(authority.revoke(&capability_id));
    let revoke_pending = futures::poll!(&mut revoke).is_pending();
    pause.resume.notify_one();
    assert_eq!(
        response.await.unwrap().unwrap().status(),
        StatusCode::NO_CONTENT,
    );
    if revoke_pending {
        revoke.await;
    }

    assert!(
        revoke_pending,
        "revoke returned before an admitted commit finished publication",
    );
    assert!(
        manager
            .lookup(
                &["admitted".into()],
                "v1",
                SCOPE_REPO,
                SCOPE_REF,
                DEFAULT_REF,
            )
            .await
            .is_some(),
    );
}

#[tokio::test]
async fn download_rechecks_revocation_and_expiry_before_response_start() {
    for invalidation in [Invalidation::Revoke, Invalidation::Expire] {
        let tmp = TempDir::new().unwrap();
        let (app, _, authority, clock, capability_id) = make_clocked_test_app(&tmp).await;
        let prefix = scope_prefix(SCOPE_REPO, SCOPE_REF, DEFAULT_REF);
        let (_, archive_location) =
            authorized_roundtrip(&app, &prefix, TOKEN_A, "download-race", b"secret").await;
        let path = archive_location
            .strip_prefix("http://localhost:9999")
            .unwrap();
        let pause = authority.before_download_start.arm();
        let request = Request::builder().uri(path).body(Body::empty()).unwrap();
        let request_app = app.clone();
        let response = tokio::spawn(async move { request_app.oneshot(request).await });
        pause.reached.notified().await;

        invalidate(invalidation, &authority, &capability_id, &clock).await;
        pause.resume.notify_one();

        assert_eq!(
            response.await.unwrap().unwrap().status(),
            StatusCode::NOT_FOUND,
            "{} before download start",
            invalidation.label(),
        );
    }
}

#[tokio::test]
async fn unmatched_download_paths_do_not_log_live_grants() {
    use tracing::instrument::WithSubscriber;

    let tmp = TempDir::new().unwrap();
    let (app, _, authority) = make_test_app(&tmp).await;
    let job = authority
        .authorize(
            TOKEN_A,
            &CacheScope {
                repo: SCOPE_REPO.into(),
                git_ref: SCOPE_REF.into(),
                default_ref: DEFAULT_REF.into(),
            },
        )
        .await
        .unwrap();
    let grant = authority
        .issue_download(&job, "b".repeat(64))
        .await
        .unwrap();
    for path in [
        format!("/download/{grant}/"),
        format!("/download/{grant}/twirp/CacheService"),
    ] {
        let logs = crate::testing::CapturedLogs::default();
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!logs.text().is_empty());
        assert!(
            !logs.text().contains(&grant.to_string()),
            "fallback logged a live download grant"
        );
        assert_eq!(
            authority.resolve_download(grant).await.unwrap(),
            "b".repeat(64)
        );
    }
    let logs = crate::testing::CapturedLogs::default();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL")
                .body(Body::empty())
                .unwrap(),
        )
        .with_subscriber(logs.subscriber())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(logs.text().contains("ACTIONS_CACHE_SERVICE_V2"));
}

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
    assert_scoped_handlers_reject(app, token, &prefix, expected).await;
}

async fn assert_scoped_handlers_reject(
    app: &Router,
    token: &str,
    prefix: &str,
    expected: StatusCode,
) {
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
async fn scoped_handlers_authenticate_before_decoding_scope() {
    let tmp = TempDir::new().unwrap();
    let manager = make_test_manager(&tmp).await;
    let issued_at = Utc::now();
    let clock_value = Arc::new(std::sync::Mutex::new(issued_at));
    let now = clock_value.clone();
    let authority = Arc::new(CacheAuthority::with_clock(Arc::new(move || {
        *now.lock().unwrap()
    })));
    let claims = JobCapabilityClaims {
        scope: CacheScope {
            repo: SCOPE_REPO.into(),
            git_ref: SCOPE_REF.into(),
            default_ref: DEFAULT_REF.into(),
        },
        job_id: "scope-order-job".into(),
    };
    let revoked = authority
        .register_job("revoked", claims.clone(), issued_at)
        .await
        .unwrap();
    authority
        .register_job("expired", claims.clone(), issued_at)
        .await
        .unwrap();
    authority
        .register_job("active", claims, issued_at + chrono::Duration::seconds(1))
        .await
        .unwrap();
    authority.revoke(&revoked).await;
    *clock_value.lock().unwrap() = issued_at + JOB_CAPABILITY_LIFETIME;
    let app = router(manager, authority);
    let malformed = format!(
        "/cache/!/{}/{}",
        encode_scope(SCOPE_REF),
        encode_scope(DEFAULT_REF)
    );

    for token in ["unknown", "expired", "revoked"] {
        assert_scoped_handlers_reject(&app, token, &malformed, StatusCode::UNAUTHORIZED).await;
    }
    assert_scoped_handlers_reject(&app, "active", &malformed, StatusCode::BAD_REQUEST).await;
    let wrong_scope = scope_prefix("other/repo", SCOPE_REF, DEFAULT_REF);
    assert_scoped_handlers_reject(&app, "active", &wrong_scope, StatusCode::FORBIDDEN).await;
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
    let (_, old_archive_location) =
        authorized_roundtrip(&first_app, &prefix, TOKEN_A, "persisted", b"bytes").await;
    drop(first_app);
    drop(manager);
    drop(first_authority);

    let reopened_manager = make_test_manager(&tmp).await;
    let second_authority = Arc::new(CacheAuthority::new());
    let second_app = router(reopened_manager, second_authority.clone());
    let old_download_path = old_archive_location
        .strip_prefix("http://localhost:9999")
        .unwrap();
    assert_eq!(
        second_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(old_download_path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
    );
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
    let new_archive_location =
        lookup(&second_app, &prefix, "new-runtime-token", "persisted", "v1").await;
    let new_download_path = new_archive_location
        .strip_prefix("http://localhost:9999")
        .unwrap();
    let response = second_app
        .oneshot(
            Request::builder()
                .uri(new_download_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        b"bytes"[..],
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
async fn every_cache_api_handler_rejects_unknown_bearer() {
    let tmp = TempDir::new().unwrap();
    let (app, _, _) = make_test_app(&tmp).await;
    assert_all_cache_handlers_reject(&app, "unknown-runtime-token", StatusCode::UNAUTHORIZED).await;
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
    let (_, archive_location) = authorized_roundtrip(&app, &prefix, TOKEN_A, "k", b"secret").await;
    let handle = authority
        .authenticate(TOKEN_A)
        .await
        .unwrap()
        .lifecycle_handle();
    authority.revoke(&handle).await;
    assert_all_cache_handlers_reject(&app, TOKEN_A, StatusCode::UNAUTHORIZED).await;
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
    for (repo, git_ref, key, token, bytes) in [
        (
            "org/repo-a",
            "refs/heads/main",
            "default-fallback",
            "seed-main-a",
            b"fallback-a".as_slice(),
        ),
        (
            "org/repo-b",
            "refs/heads/main",
            "default-fallback",
            "seed-main-b",
            b"fallback-b".as_slice(),
        ),
        (
            "org/repo-a",
            "refs/heads/feature",
            "feature-only",
            "seed-feature-a",
            b"feature-a".as_slice(),
        ),
        (
            "org/repo-b",
            "refs/heads/feature",
            "feature-only",
            "seed-feature-b",
            b"feature-b".as_slice(),
        ),
    ] {
        let owner = CapabilityEpoch::for_test(token);
        let id = manager
            .reserve_upload(
                owner.clone(),
                format!("{token}-job"),
                key.into(),
                "v1".into(),
                repo.into(),
                git_ref.into(),
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
        let git_ref = if i % 4 < 2 {
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

                let response = client
                    .get(format!(
                        "{base_url}{prefix}/_apis/artifactcache/cache?keys=feature-only&version=v1"
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
                    b"feature-a".as_slice()
                } else {
                    b"feature-b".as_slice()
                };
                assert_eq!(restored.bytes().await.unwrap(), expected);
            } else {
                let response = client
                    .get(format!(
                        "{base_url}{prefix}/_apis/artifactcache/cache?keys=feature-only&version=v1"
                    ))
                    .bearer_auth(&token)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::NO_CONTENT);
            }

            (i, downloaded, repo, git_ref)
        }));
    }

    let mut completed = Vec::with_capacity(20);
    for handle in handles {
        completed.push(handle.await.unwrap());
    }
    completed.sort_by_key(|(i, _, _, _)| *i);
    assert_eq!(completed.len(), 20);
    assert_eq!(
        completed
            .iter()
            .filter(|(_, _, repo, git_ref)| {
                *repo == "org/repo-a" && *git_ref == "refs/heads/feature"
            })
            .count(),
        5,
    );
    assert_eq!(
        completed
            .iter()
            .filter(|(_, _, repo, git_ref)| {
                *repo == "org/repo-a" && *git_ref == "refs/heads/main"
            })
            .count(),
        5,
    );
    assert_eq!(
        completed
            .iter()
            .filter(|(_, _, repo, git_ref)| {
                *repo == "org/repo-b" && *git_ref == "refs/heads/main"
            })
            .count(),
        5,
    );
    assert_eq!(
        completed
            .iter()
            .filter(|(_, _, repo, git_ref)| {
                *repo == "org/repo-b" && *git_ref == "refs/heads/feature"
            })
            .count(),
        5,
    );
    for (i, body, _, _) in completed {
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
