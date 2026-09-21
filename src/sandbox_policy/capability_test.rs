use chrono::{Duration, Utc};

use crate::cache::auth::{CacheAuthority, CacheScope, JobCapabilityClaims};
use crate::sandbox_policy::{
    CacheCapabilityBinding, CapabilityDescriptor, CapabilityService, PolicyError,
    validate_descriptor,
};
use uuid::Uuid;

fn descriptor(attempt_id: Uuid, grant_id: Uuid) -> CapabilityDescriptor {
    CapabilityDescriptor {
        attempt_id,
        service: CapabilityService::Cache,
        grant_id,
        expires_at: Utc::now() + Duration::minutes(1),
        local_path: format!("/run/chimera/capabilities/{grant_id}.sock"),
    }
}

#[test]
fn descriptor_accepts_only_generated_attempt_scoped_socket_metadata() {
    let now = Utc::now();
    let attempt_id = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    for service in [
        CapabilityService::Cache,
        CapabilityService::Artifact,
        CapabilityService::Deploy,
    ] {
        let mut candidate = descriptor(attempt_id, grant_id);
        candidate.service = service;
        candidate.expires_at = now + Duration::minutes(1);
        assert_eq!(validate_descriptor(&candidate, attempt_id, now), Ok(()));
    }
}

#[test]
fn descriptor_rejects_wrong_attempt_and_noncanonical_or_expired_metadata() {
    let now = Utc::now();
    let attempt_id = Uuid::new_v4();
    let grant_id = Uuid::new_v4();
    let valid_descriptor = descriptor(attempt_id, grant_id);

    assert_eq!(
        validate_descriptor(&valid_descriptor, Uuid::new_v4(), now),
        Err(PolicyError::InvalidCapabilityDescriptor)
    );

    for local_path in [
        format!("/run/chimera/capabilities/{grant_id}/../escape.sock"),
        "/run/chimera/capabilities/%2e%2e%2fescape.sock".into(),
        "/var/run/docker.sock".into(),
        "/run/docker.sock".into(),
        "/run/chimera/capabilities/production.sock".into(),
        format!("/run/chimera/capabilities/{grant_id}.sock\0suffix"),
    ] {
        let mut candidate = descriptor(attempt_id, grant_id);
        candidate.local_path = local_path;
        assert_eq!(
            validate_descriptor(&candidate, attempt_id, now),
            Err(PolicyError::InvalidCapabilityDescriptor)
        );
    }

    for (candidate_attempt, candidate_grant, expiry) in [
        (Uuid::nil(), grant_id, now + Duration::minutes(1)),
        (attempt_id, Uuid::nil(), now + Duration::minutes(1)),
        (attempt_id, grant_id, now),
        (attempt_id, grant_id, now - Duration::nanoseconds(1)),
    ] {
        let mut candidate = descriptor(candidate_attempt, candidate_grant);
        candidate.expires_at = expiry;
        candidate.local_path = format!("/run/chimera/capabilities/{candidate_grant}.sock");
        assert_eq!(
            validate_descriptor(&candidate, attempt_id, now),
            Err(PolicyError::InvalidCapabilityDescriptor)
        );
    }
}

fn claims() -> JobCapabilityClaims {
    JobCapabilityClaims {
        scope: CacheScope {
            repo: "synthetic/repo".into(),
            git_ref: "refs/heads/main".into(),
            default_ref: "refs/heads/main".into(),
        },
        job_id: "synthetic-job".into(),
    }
}

#[tokio::test]
async fn binding_revokes_only_its_existing_cache_epoch() {
    let authority = CacheAuthority::new();
    let handle = authority
        .register_job("synthetic-old", claims(), Utc::now())
        .await
        .unwrap();
    let old = CacheCapabilityBinding::new(Uuid::new_v4(), handle).unwrap();
    authority
        .register_job("synthetic-new", claims(), Utc::now())
        .await
        .unwrap();

    old.revoke(&authority).await;

    assert!(authority.authenticate("synthetic-old").await.is_err());
    assert!(authority.authenticate("synthetic-new").await.is_ok());
}

#[tokio::test]
async fn stale_binding_cannot_revoke_a_reused_cache_token_in_a_new_epoch() {
    let authority = CacheAuthority::new();
    let handle = authority
        .register_job("synthetic-token", claims(), Utc::now())
        .await
        .unwrap();
    let stale_handle = handle.clone();
    CacheCapabilityBinding::new(Uuid::new_v4(), handle)
        .unwrap()
        .revoke(&authority)
        .await;

    authority
        .register_job("synthetic-token", claims(), Utc::now())
        .await
        .unwrap();
    CacheCapabilityBinding::new(Uuid::new_v4(), stale_handle)
        .unwrap()
        .revoke(&authority)
        .await;

    assert!(authority.authenticate("synthetic-token").await.is_ok());
}

#[tokio::test]
async fn binding_rejects_nil_attempt_and_redacts_its_handle() {
    let authority = CacheAuthority::new();
    let handle = authority
        .register_job("synthetic-token", claims(), Utc::now())
        .await
        .unwrap();

    assert!(matches!(
        CacheCapabilityBinding::new(Uuid::nil(), handle.clone()),
        Err(PolicyError::InvalidCapabilityDescriptor)
    ));
    let binding = CacheCapabilityBinding::new(Uuid::new_v4(), handle).unwrap();
    assert_eq!(format!("{binding:?}"), "CacheCapabilityBinding([redacted])");
}
