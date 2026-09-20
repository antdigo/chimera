use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, Duration, TimeZone, Utc};

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

fn clock(at: DateTime<Utc>) -> (Arc<AtomicI64>, Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>) {
    let timestamp = Arc::new(AtomicI64::new(at.timestamp()));
    let now_timestamp = timestamp.clone();
    let now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync> = Arc::new(move || {
        Utc.timestamp_opt(now_timestamp.load(Ordering::SeqCst), 0)
            .single()
            .unwrap()
    });
    (timestamp, now)
}

#[tokio::test]
async fn capability_authorizes_only_its_registered_scope_until_revoked() {
    let authority = CacheAuthority::new();
    let issued_at = Utc::now();
    let id = authority
        .register_job(
            "runtime-a",
            claims("job-a", "org/repo-a"),
            issued_at.to_owned(),
        )
        .await
        .unwrap();

    let authorized = authority
        .authorize(
            "runtime-a",
            &scope("org/repo-a", "refs/heads/feature", "refs/heads/main"),
        )
        .await
        .unwrap();
    assert_eq!(authorized.capability_id(), id.capability_id());
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
        .register_job(
            "runtime-expired",
            claims("job-expired", "org/repo"),
            issued_at,
        )
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
async fn authorization_rechecks_expiration_after_waiting_for_lock() {
    let issued_at = Utc.timestamp_opt(0, 0).single().unwrap();
    let (timestamp, now) = clock(issued_at);
    let authority = CacheAuthority::with_clock(now);
    authority
        .register_job("runtime-a", claims("job-a", "org/repo"), issued_at)
        .await
        .unwrap();

    let lock = authority.state.write().await;
    let requested_scope = scope("org/repo", "refs/heads/feature", "refs/heads/main");
    let mut authorization = Box::pin(authority.authorize("runtime-a", &requested_scope));
    assert!(futures::poll!(authorization.as_mut()).is_pending());

    timestamp.store(
        (issued_at + JOB_CAPABILITY_LIFETIME + Duration::seconds(1)).timestamp(),
        Ordering::SeqCst,
    );
    drop(lock);

    assert_eq!(
        authorization.await.unwrap_err(),
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
async fn token_reuse_waits_for_old_epoch_revoke_and_old_cleanup_cannot_revoke_new_epoch() {
    let authority = CacheAuthority::new();
    let issued_at = Utc::now();
    let old = authority
        .register_job("reused-token", claims("old-job", "org/old"), issued_at)
        .await
        .unwrap();
    let old_job = authority.authenticate("reused-token").await.unwrap();
    let old_operation = authority.admit(&old_job).await.unwrap();

    let revoke = authority.revoke(&old);
    tokio::pin!(revoke);
    assert!(futures::poll!(&mut revoke).is_pending());
    assert_eq!(
        authority
            .register_job(
                "reused-token",
                claims("new-job", "org/new"),
                issued_at + Duration::seconds(1),
            )
            .await
            .unwrap_err(),
        CacheAuthError::DuplicateToken,
    );

    drop(old_operation);
    revoke.await;
    let _new = authority
        .register_job(
            "reused-token",
            claims("new-job", "org/new"),
            issued_at + Duration::seconds(1),
        )
        .await
        .unwrap();

    // A delayed cleanup using the old lifecycle handle must target only the old epoch.
    let authorized = authority
        .authorize(
            "reused-token",
            &scope("org/new", "refs/heads/feature", "refs/heads/main"),
        )
        .await
        .unwrap();
    let grant = authority
        .issue_download(&authorized, "a".repeat(64))
        .await
        .unwrap();
    authority.revoke_immediately(&old);
    assert!(
        authority
            .authorize(
                "reused-token",
                &scope("org/new", "refs/heads/feature", "refs/heads/main"),
            )
            .await
            .is_ok()
    );
    authority.revoke(&old).await;
    let authorized = authority
        .authorize(
            "reused-token",
            &scope("org/new", "refs/heads/feature", "refs/heads/main"),
        )
        .await
        .unwrap();
    assert_eq!(authorized.job_id(), "new-job");
    assert_eq!(
        authority.resolve_download(grant).await.unwrap(),
        "a".repeat(64)
    );
}

#[tokio::test]
async fn late_cleanup_of_expired_epoch_does_not_revoke_reused_token() {
    let issued_at = Utc.timestamp_opt(0, 0).single().unwrap();
    let (timestamp, now) = clock(issued_at);
    let authority = CacheAuthority::with_clock(now);
    let old = authority
        .register_job("reused-token", claims("old-job", "org/old"), issued_at)
        .await
        .unwrap();

    let reused_at = issued_at + JOB_CAPABILITY_LIFETIME + Duration::seconds(1);
    timestamp.store(reused_at.timestamp(), Ordering::SeqCst);
    let _new = authority
        .register_job("reused-token", claims("new-job", "org/new"), reused_at)
        .await
        .unwrap();

    authority.revoke(&old).await;
    let authorized = authority
        .authorize(
            "reused-token",
            &scope("org/new", "refs/heads/feature", "refs/heads/main"),
        )
        .await
        .unwrap();
    assert_eq!(authorized.job_id(), "new-job");
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
    let grant = authority
        .issue_download(&job, "a".repeat(64))
        .await
        .unwrap();

    assert_eq!(
        authority.resolve_download(grant).await.unwrap(),
        "a".repeat(64)
    );
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

#[tokio::test]
async fn grant_issuance_prunes_unrelated_inactive_authority_state() {
    assert_opportunistic_pruning(true).await;
}

#[tokio::test]
async fn registration_prunes_unrelated_inactive_authority_state() {
    assert_opportunistic_pruning(false).await;
}

async fn assert_opportunistic_pruning(issue_grant: bool) {
    let issued_at = Utc.timestamp_opt(0, 0).single().unwrap();
    let (timestamp, now) = clock(issued_at);
    let authority = CacheAuthority::with_clock(now);
    let requested_scope = scope("org/repo", "refs/heads/feature", "refs/heads/main");
    let mut ids = Vec::new();
    let mut grants = Vec::new();
    for token in ["expired", "revoked", "dropped", "orphaned"] {
        let registration_time = issued_at + Duration::seconds(i64::from(token != "expired"));
        timestamp.store(registration_time.timestamp(), Ordering::SeqCst);
        let id = authority
            .register_job(token, claims(token, "org/repo"), registration_time)
            .await
            .unwrap();
        let job = authority.authorize(token, &requested_scope).await.unwrap();
        grants.push(
            authority
                .issue_download(&job, "a".repeat(64))
                .await
                .unwrap(),
        );
        ids.push(id);
    }
    timestamp.store(issued_at.timestamp() + 1, Ordering::SeqCst);
    authority
        .register_job(
            "active",
            claims("active-job", "org/repo"),
            issued_at + Duration::seconds(1),
        )
        .await
        .unwrap();
    let active = authority
        .authorize("active", &requested_scope)
        .await
        .unwrap();
    let active_grant = authority
        .issue_download(&active, "b".repeat(64))
        .await
        .unwrap();

    authority.revoke(&ids[1]).await;
    authority.revoke_immediately(&ids[2]);
    // An orphan must not survive even if its parent was already removed.
    authority
        .state
        .write()
        .await
        .jobs
        .remove(ids[3].capability_id());
    authority.revoke_immediately(&ids[3]);
    timestamp.store(
        (issued_at + JOB_CAPABILITY_LIFETIME).timestamp(),
        Ordering::SeqCst,
    );

    if issue_grant {
        authority
            .issue_download(&active, "c".repeat(64))
            .await
            .unwrap();
    } else {
        authority
            .register_job(
                "new",
                claims("new-job", "org/repo"),
                issued_at + JOB_CAPABILITY_LIFETIME,
            )
            .await
            .unwrap();
    }

    let state = authority.state.read().await;
    assert_eq!(state.jobs.len(), if issue_grant { 1 } else { 2 });
    assert!(
        authority.revoked().is_empty(),
        "pruning must reclaim tombstones"
    );
    assert_eq!(state.downloads.len(), if issue_grant { 2 } else { 1 });
    drop(state);
    for grant in grants {
        assert_eq!(
            authority.resolve_download(grant).await.unwrap_err(),
            CacheAuthError::DownloadNotFound
        );
    }
    assert_eq!(
        authority.resolve_download(active_grant).await.unwrap(),
        "b".repeat(64)
    );
    assert!(
        authority
            .authorize("active", &requested_scope)
            .await
            .is_ok()
    );
}
