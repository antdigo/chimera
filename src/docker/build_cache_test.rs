use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Barrier;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::*;

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
        BuildCacheKey::new("daemon-a", &scope(), "linux/arm64", "Dockerfile", [1; 32],)
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
    let builds = Arc::new(AtomicUsize::new(0));
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
                    builds.fetch_add(1, Ordering::SeqCst);
                    Ok("sha256:image".to_string())
                },
            )
            .await
            .unwrap();
        assert!(matches!(outcome, CacheOutcome::Ready { .. }));
    }

    assert_eq!(builds.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_same_key_runs_one_build() {
    let cache = Arc::new(BuildCache::new());
    let builds = Arc::new(AtomicUsize::new(0));
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
                        builds.fetch_add(1, Ordering::SeqCst);
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
    assert_eq!(builds.load(Ordering::SeqCst), 1);
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
    assert!(matches!(
        first,
        CacheOutcome::Ready {
            cache_hit: false,
            ..
        }
    ));

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
    assert_eq!(cache.entry_count_for_test().await, 1);

    let inspected_image_id = Arc::new(std::sync::Mutex::new(None));
    let recorded_image_id = inspected_image_id.clone();
    let third = cache
        .get_or_build(
            key("daemon-a", 1),
            deadline,
            &cancel,
            move |image_id| {
                let recorded_image_id = recorded_image_id.clone();
                async move {
                    *recorded_image_id.lock().unwrap() = Some(image_id);
                    Ok(true)
                }
            },
            || async { panic!("cache hit must not rebuild") },
        )
        .await
        .unwrap();

    assert_eq!(
        inspected_image_id.lock().unwrap().as_deref(),
        Some("sha256:second")
    );
    assert!(matches!(
        third,
        CacheOutcome::Ready { image_id, cache_hit: true } if image_id == "sha256:second"
    ));
}

#[tokio::test]
async fn cancelled_waiter_does_not_publish_or_poison_key_lock() {
    let cache = Arc::new(BuildCache::new());
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
    assert_eq!(cache.entry_count_for_test().await, 0);
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

#[tokio::test]
async fn timed_out_build_does_not_publish_and_can_retry() {
    let cache = BuildCache::new();
    let cancel = CancellationToken::new();

    let outcome = cache
        .get_or_build(
            key("daemon-a", 1),
            Instant::now() - Duration::from_secs(1),
            &cancel,
            |_| async { Ok(true) },
            || async { Ok("sha256:forbidden".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, CacheOutcome::TimedOut));
    assert_eq!(cache.entry_count_for_test().await, 0);

    let retry = cache
        .get_or_build(
            key("daemon-a", 1),
            Instant::now() + Duration::from_secs(5),
            &cancel,
            |_| async { Ok(true) },
            || async { Ok("sha256:retry".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(retry, CacheOutcome::Ready { .. }));
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_during_publication_does_not_index_built_image() {
    let cache = Arc::new(BuildCache::new());
    let cancel = CancellationToken::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (build_started_tx, build_started_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_build_tx, release_build_rx) = tokio::sync::oneshot::channel::<()>();
    let (build_resolved_tx, build_resolved_rx) = tokio::sync::oneshot::channel::<()>();

    let runner = {
        let cache = cache.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            cache
                .get_or_build(
                    key("daemon-a", 1),
                    deadline,
                    &cancel,
                    |_| async { Ok(true) },
                    move || async move {
                        build_started_tx
                            .send(())
                            .expect("test waits for build start");
                        release_build_rx.await.expect("test holds the entries lock");
                        build_resolved_tx
                            .send(())
                            .expect("test waits for the resolved build");
                        Ok("sha256:built".to_string())
                    },
                )
                .await
        })
    };

    build_started_rx.await.expect("build closure must run");
    let entries_guard = cache.entries_guard_for_test().await;
    release_build_tx
        .send(())
        .expect("runner still waits for the release signal");
    // The current-thread flavour parks the runner on the entries mutex (its
    // build result already delivered) before this task resumes, so the cancel
    // below can only abort the publication wait, never the build wait.
    build_resolved_rx
        .await
        .expect("build result must be delivered for publication");
    cancel.cancel();

    let outcome = tokio::time::timeout(Duration::from_secs(1), runner)
        .await
        .expect("publication must honour the cancel token")
        .expect("runner task must not panic")
        .unwrap();
    assert!(matches!(outcome, CacheOutcome::Cancelled));

    drop(entries_guard);
    assert_eq!(cache.entry_count_for_test().await, 0);

    let retry = cache
        .get_or_build(
            key("daemon-a", 1),
            deadline,
            &CancellationToken::new(),
            |_| async { Ok(true) },
            || async { Ok("sha256:retry".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(
        retry,
        CacheOutcome::Ready {
            cache_hit: false,
            ..
        }
    ));
    assert_eq!(cache.entry_count_for_test().await, 1);
}

#[tokio::test]
async fn deadline_during_publication_does_not_index_built_image() {
    let cache = Arc::new(BuildCache::new());
    let (build_started_tx, build_started_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_build_tx, release_build_rx) = tokio::sync::oneshot::channel::<()>();
    // Long enough for the runner to reach the build closure, short enough to
    // expire while the entries mutex is unavailable.
    let deadline = Instant::now() + Duration::from_millis(250);

    let runner = {
        let cache = cache.clone();
        tokio::spawn(async move {
            cache
                .get_or_build(
                    key("daemon-a", 1),
                    deadline,
                    &CancellationToken::new(),
                    |_| async { Ok(true) },
                    move || async move {
                        build_started_tx
                            .send(())
                            .expect("test waits for build start");
                        release_build_rx
                            .await
                            .expect("test releases the built result");
                        Ok("sha256:built".to_string())
                    },
                )
                .await
        })
    };

    tokio::time::timeout(Duration::from_secs(1), build_started_rx)
        .await
        .expect("build must start before the deadline matters")
        .expect("build closure must not be dropped");
    let entries_guard = cache.entries_guard_for_test().await;
    release_build_tx
        .send(())
        .expect("runner still waits for the release signal");

    let outcome = tokio::time::timeout(Duration::from_secs(2), runner)
        .await
        .expect("publication must honour the deadline")
        .expect("runner task must not panic")
        .unwrap();
    assert!(matches!(outcome, CacheOutcome::TimedOut));

    drop(entries_guard);
    assert_eq!(cache.entry_count_for_test().await, 0);

    let retry = cache
        .get_or_build(
            key("daemon-a", 1),
            Instant::now() + Duration::from_secs(5),
            &CancellationToken::new(),
            |_| async { Ok(true) },
            || async { Ok("sha256:retry".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(
        retry,
        CacheOutcome::Ready {
            cache_hit: false,
            ..
        }
    ));
    assert_eq!(cache.entry_count_for_test().await, 1);
}

#[tokio::test]
async fn failed_build_does_not_publish_and_can_retry() {
    let cache = BuildCache::new();
    let cancel = CancellationToken::new();
    let deadline = Instant::now() + Duration::from_secs(5);

    let failure = cache
        .get_or_build(
            key("daemon-a", 1),
            deadline,
            &cancel,
            |_| async { Ok(true) },
            || async { anyhow::bail!("build failed") },
        )
        .await;
    assert!(failure.is_err());
    assert_eq!(cache.entry_count_for_test().await, 0);

    let retry = cache
        .get_or_build(
            key("daemon-a", 1),
            deadline,
            &cancel,
            |_| async { Ok(true) },
            || async { Ok("sha256:retry".to_string()) },
        )
        .await
        .unwrap();
    assert!(matches!(retry, CacheOutcome::Ready { .. }));
}

#[tokio::test]
async fn different_keys_build_without_blocking_each_other() {
    let cache = Arc::new(BuildCache::new());
    let cancel = CancellationToken::new();
    let barrier = Arc::new(Barrier::new(2));

    let first_cache = cache.clone();
    let first_cancel = cancel.clone();
    let first_barrier = barrier.clone();
    let first = tokio::spawn(async move {
        first_cache
            .get_or_build(
                key("daemon-a", 1),
                Instant::now() + Duration::from_secs(5),
                &first_cancel,
                |_| async { Ok(true) },
                move || async move {
                    first_barrier.wait().await;
                    Ok("sha256:first".to_string())
                },
            )
            .await
            .unwrap()
    });

    let second_cache = cache.clone();
    let second_cancel = cancel.clone();
    let second_barrier = barrier.clone();
    let second = tokio::spawn(async move {
        second_cache
            .get_or_build(
                key("daemon-a", 2),
                Instant::now() + Duration::from_secs(5),
                &second_cancel,
                |_| async { Ok(true) },
                move || async move {
                    second_barrier.wait().await;
                    Ok("sha256:second".to_string())
                },
            )
            .await
            .unwrap()
    });

    let outcomes = tokio::time::timeout(Duration::from_secs(1), async {
        (first.await.unwrap(), second.await.unwrap())
    })
    .await
    .unwrap();
    assert!(matches!(outcomes.0, CacheOutcome::Ready { .. }));
    assert!(matches!(outcomes.1, CacheOutcome::Ready { .. }));
}

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
    let error = match failure {
        Ok(_) => panic!("synthetic build failure must not succeed"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "synthetic build failure");
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
        CacheOutcome::Ready {
            cache_hit: false,
            ..
        }
    ));
}

#[tokio::test]
async fn cancellation_wins_when_the_wrapped_future_is_ready() {
    let cancel = CancellationToken::new();
    cancel.cancel();

    let outcome = within_budget(Instant::now() + Duration::from_secs(5), &cancel, async {
        "ready"
    })
    .await;

    assert!(matches!(outcome, BudgetOutcome::Cancelled));
}

#[tokio::test]
async fn deadline_wins_when_the_wrapped_future_is_ready() {
    let cancel = CancellationToken::new();

    let outcome = within_budget(Instant::now() - Duration::from_secs(1), &cancel, async {
        "ready"
    })
    .await;

    assert!(matches!(outcome, BudgetOutcome::TimedOut));
}

#[tokio::test]
async fn just_expired_deadline_wins_when_the_wrapped_future_is_ready() {
    let cancel = CancellationToken::new();

    // A deadline that expired microseconds ago still sits Pending in the
    // millisecond-granular timer wheel, so the wrapped future's completion is
    // polled while the sleep branch has not fired — the wakeup race that let
    // a Docker connect error outrank the expired deadline (#12). The variant
    // above cannot catch this: its long-expired timer fires on the first poll.
    let outcome = within_budget(Instant::now(), &cancel, async { "ready" }).await;

    assert!(matches!(outcome, BudgetOutcome::TimedOut));
}
