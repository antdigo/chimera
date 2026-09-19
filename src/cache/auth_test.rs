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
