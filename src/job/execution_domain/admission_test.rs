use std::num::NonZeroUsize;
use std::time::Duration;

use super::{ExecutionDomainError, ExecutionDomainRoot};

fn prepared_root_with_capacity(temp: &tempfile::TempDir, capacity: usize) -> ExecutionDomainRoot {
    ExecutionDomainRoot::prepare(
        &temp.path().join("job-resources"),
        NonZeroUsize::new(capacity).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn second_reservation_waits_until_first_domain_is_destroyed() {
    let temp = tempfile::tempdir().unwrap();
    let root = prepared_root_with_capacity(&temp, 1);
    let first = root.reserve().await.unwrap().provision().unwrap();
    let mut waiting = Box::pin(root.reserve());

    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    first.destroy().unwrap();
    tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cancelled_wait_does_not_consume_capacity() {
    let temp = tempfile::tempdir().unwrap();
    let root = prepared_root_with_capacity(&temp, 1);
    let held = root.reserve().await.unwrap();
    let mut waiting = Box::pin(root.reserve());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    drop(waiting);
    drop(held);
    tokio::time::timeout(Duration::from_secs(1), root.reserve())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn poisoning_wakes_blocked_waiter() {
    let temp = tempfile::tempdir().unwrap();
    let root = prepared_root_with_capacity(&temp, 1);
    let _held = root.reserve().await.unwrap();
    let mut waiting = Box::pin(root.reserve());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    root.poison_for_test();
    let error = tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, ExecutionDomainError::PoisonedRoot { .. }));
}

#[tokio::test]
async fn dropping_undestroyed_domain_poisons_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = prepared_root_with_capacity(&temp, 1);
    let domain = root.reserve().await.unwrap().provision().unwrap();
    let attempt = domain.attempt_dir().to_path_buf();
    drop(domain);
    let error = root.reserve().await.unwrap_err();
    assert!(matches!(error, ExecutionDomainError::PoisonedRoot { .. }));
    assert!(
        attempt.exists(),
        "drop must retain the attempt for recovery"
    );
}

#[tokio::test]
async fn poison_rejects_waiter_when_capacity_also_becomes_available() {
    // Both select branches become ready together. Repetition covers Tokio's
    // randomized branch order without making a specific winner contractual.
    for _ in 0..32 {
        let temp = tempfile::tempdir().unwrap();
        let root = prepared_root_with_capacity(&temp, 1);
        let held = root.reserve().await.unwrap();
        let mut waiting = Box::pin(root.reserve());
        assert!(futures::poll!(&mut waiting).is_pending());
        root.poison_for_test();
        drop(held);
        assert!(matches!(
            waiting.await,
            Err(ExecutionDomainError::PoisonedRoot { .. })
        ));
    }
}

#[tokio::test]
async fn reservation_cannot_provision_after_root_is_poisoned() {
    let temp = tempfile::tempdir().unwrap();
    let root = prepared_root_with_capacity(&temp, 1);
    let held = root.reserve().await.unwrap();
    root.poison_for_test();
    assert!(matches!(
        held.provision(),
        Err(ExecutionDomainError::PoisonedRoot { .. })
    ));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
