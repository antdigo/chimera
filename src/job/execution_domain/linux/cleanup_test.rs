use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, symlink};
use std::os::unix::process::ExitStatusExt;

use tempfile::TempDir;

use super::cleanup::IdMapSpec;
use super::cleanup::{
    CleanupRootKind, MappedCleanupAuthority, MappedIdRange, PinnedCleanupRoot,
    RuntimeSocketCapability, RuntimeSocketRootKind,
};

#[test]
fn timed_out_child_is_killed_and_reaped_within_the_same_deadline() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);

    assert!(super::cleanup::wait_child_for_test(&mut child, deadline).is_err());

    assert!(child.try_wait().unwrap().is_some());
    assert!(std::time::Instant::now() <= deadline + std::time::Duration::from_millis(50));
}

struct DelayedReap {
    killed: bool,
    remaining_polls: usize,
    reaped: bool,
    try_wait_errors: usize,
}

impl super::cleanup::ReapableChild for DelayedReap {
    fn try_wait_status(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        if self.try_wait_errors > 0 {
            self.try_wait_errors -= 1;
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        if !self.killed {
            return Ok(None);
        }
        if self.remaining_polls > 0 {
            self.remaining_polls -= 1;
            return Ok(None);
        }
        self.reaped = true;
        Ok(Some(std::process::ExitStatus::from_raw(libc::SIGKILL)))
    }

    fn kill_process(&mut self) -> std::io::Result<()> {
        self.killed = true;
        Ok(())
    }
}

#[test]
fn timeout_uses_a_separate_bounded_window_to_prove_reap() {
    let mut child = DelayedReap {
        killed: false,
        remaining_polls: 8,
        reaped: false,
        try_wait_errors: 0,
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(5);

    assert!(super::cleanup::wait_reapable_child_for_test(&mut child, deadline).is_err());

    assert!(child.killed);
    assert!(child.reaped);
}

#[test]
fn pending_retry_reinserts_child_after_try_wait_observation_error() {
    let mut pending = vec![DelayedReap {
        killed: false,
        remaining_polls: 2,
        reaped: false,
        try_wait_errors: 2,
    }];

    assert!(
        super::cleanup::retry_pending_children_for_test(
            &mut pending,
            std::time::Instant::now() + std::time::Duration::from_millis(5),
        )
        .is_err()
    );
    assert_eq!(
        pending.len(),
        1,
        "observation error must retain exact child"
    );

    super::cleanup::retry_pending_children_for_test(
        &mut pending,
        std::time::Instant::now() + std::time::Duration::from_millis(20),
    )
    .unwrap();
    assert!(
        pending.is_empty(),
        "successful retry discharges child authority"
    );
}

fn fixture() -> (TempDir, MappedIdRange, PinnedCleanupRoot) {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path().join("work");
    std::fs::create_dir(&root).unwrap();
    let metadata = std::fs::metadata(&root).unwrap();
    let map = MappedIdRange::new(
        metadata.uid(),
        metadata.gid(),
        100_000,
        65_536,
        200_000,
        65_536,
    )
    .unwrap();
    let root = PinnedCleanupRoot::open_for_test(CleanupRootKind::Work, &root).unwrap();
    (temporary, map, root)
}

#[test]
fn exact_map_rejects_empty_overflowing_and_overlapping_ranges() {
    let _all_roots = [
        CleanupRootKind::Work,
        CleanupRootKind::Tmp,
        CleanupRootKind::Home,
        CleanupRootKind::Run,
        CleanupRootKind::DockerConfig,
        CleanupRootKind::DockerData,
        CleanupRootKind::DockerExec,
    ];
    assert!(MappedIdRange::new(1000, 1000, 100_000, 0, 200_000, 1).is_err());
    assert!(MappedIdRange::new(1000, 1000, u32::MAX, 2, 200_000, 1).is_err());
    assert!(MappedIdRange::new(1000, 1000, 999, 2, 200_000, 1).is_err());
    let map = MappedIdRange::new(1000, 1000, 100_000, 65_536, 200_000, 65_536).unwrap();
    assert!(map.owns_for_test(1000, 1000));
    assert!(map.owns_for_test(100_001, 200_001));
    assert!(!map.owns_for_test(99_999, 200_001));
    assert!(!map.owns_for_test(100_001, 265_536));
}

#[test]
fn exact_map_requires_one_static_range_for_each_id_kind() {
    let spec = IdMapSpec::parse(
        "chimera",
        1000,
        1000,
        "other:300000:65536\nchimera:100000:65536\n",
        "chimera:200000:65536\n",
    )
    .unwrap();
    assert_eq!(spec.subuid_start(), 100000);
    assert!(
        IdMapSpec::parse(
            "chimera",
            1000,
            1000,
            "chimera:100000:65536\nchimera:300000:65536\n",
            "chimera:200000:65536\n",
        )
        .is_err()
    );
    assert!(
        IdMapSpec::parse(
            "chimera",
            1000,
            1000,
            "chimera:100000:65535\n",
            "chimera:200000:65536\n",
        )
        .is_err()
    );
}

#[test]
fn proc_map_must_match_both_exact_extents() {
    assert!(
        super::cleanup::verify_map_text_for_test("0 1000 1\n1 100000 65536\n", 1000, 100000, 65536)
            .is_ok()
    );
    for changed in [
        "0 1000 1\n1 100000 65535\n",
        "0 1000 1\n1 100001 65536\n",
        "0 1000 1\n",
        "0 1000 1\n1 100000 65536\n65537 300000 1\n",
    ] {
        assert!(
            super::cleanup::verify_map_text_for_test(changed, 1000, 100000, 65536).is_err(),
            "{changed:?}"
        );
    }
}

#[test]
fn seqpacket_protocol_binds_peer_credentials_and_descriptor_identity() {
    let temporary = TempDir::new().unwrap();
    let file = std::fs::File::open(temporary.path()).unwrap();

    super::cleanup::protocol_roundtrip_for_test(file.as_raw_fd()).unwrap();
}

#[test]
fn runtime_socket_capability_is_scope_and_inode_exact() {
    use std::os::unix::net::UnixListener;

    let temporary = TempDir::new().unwrap();
    let state = temporary.path().join("state");
    std::fs::create_dir(&state).unwrap();
    let first = UnixListener::bind(state.join("api.sock")).unwrap();
    let bound = super::dirfd::BoundDir::open_root(&state).unwrap();
    let capability = RuntimeSocketCapability::capture(
        RuntimeSocketRootKind::RootlessKitState,
        &bound,
        c"api.sock",
    )
    .unwrap();
    assert!(
        RuntimeSocketCapability::capture(
            RuntimeSocketRootKind::RootlessKitState,
            &bound,
            c"docker.sock",
        )
        .is_err()
    );

    std::fs::remove_file(state.join("api.sock")).unwrap();
    let replacement = UnixListener::bind(state.join("api.sock")).unwrap();
    assert!(capability.remove().is_err());
    assert!(state.join("api.sock").exists());
    drop((first, replacement));
}

#[test]
fn inventory_completes_before_removing_symlink_fifo_and_hardlinks() {
    let (temporary, map, root) = fixture();
    let work = temporary.path().join("work");
    std::fs::create_dir(work.join("nested")).unwrap();
    std::fs::write(work.join("nested/file"), b"canary").unwrap();
    std::fs::hard_link(work.join("nested/file"), work.join("hardlink")).unwrap();
    symlink("outside", work.join("symlink")).unwrap();
    let fifo = std::ffi::CString::new(work.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let authority = MappedCleanupAuthority::new(map, vec![root]).unwrap();

    authority.cleanup_for_test_current_map().unwrap();

    assert!(std::fs::read_dir(work).unwrap().next().is_none());
}

#[test]
fn unowned_socket_refuses_before_any_mutation() {
    use std::os::unix::net::UnixListener;

    let (temporary, map, root) = fixture();
    let work = temporary.path().join("work");
    std::fs::write(work.join("must-remain"), b"canary").unwrap();
    let _socket = UnixListener::bind(work.join("docker.sock")).unwrap();
    let authority = MappedCleanupAuthority::new(map, vec![root]).unwrap();

    assert!(authority.cleanup_for_test_current_map().is_err());

    assert_eq!(std::fs::read(work.join("must-remain")).unwrap(), b"canary");
}

#[test]
fn duplicate_root_kind_is_rejected() {
    let (temporary, map, root) = fixture();
    let second =
        PinnedCleanupRoot::open_for_test(CleanupRootKind::Work, &temporary.path().join("work"))
            .unwrap();

    assert!(MappedCleanupAuthority::new(map, vec![root, second]).is_err());
}

#[test]
fn budget_exhaustion_happens_before_first_mutation() {
    let (temporary, map, root) = fixture();
    let work = temporary.path().join("work");
    std::fs::write(work.join("one"), b"one").unwrap();
    std::fs::write(work.join("two"), b"two").unwrap();
    let authority = MappedCleanupAuthority::new(map, vec![root])
        .unwrap()
        .with_entry_limit_for_test(1);

    assert!(authority.cleanup_for_test_current_map().is_err());

    assert_eq!(std::fs::read(work.join("one")).unwrap(), b"one");
    assert_eq!(std::fs::read(work.join("two")).unwrap(), b"two");
}

#[test]
fn pinned_root_cannot_reach_peer_attempt_canary() {
    let (temporary, map, root) = fixture();
    let peer = temporary.path().join("peer");
    std::fs::create_dir(&peer).unwrap();
    std::fs::write(peer.join("canary"), b"peer").unwrap();
    std::fs::write(temporary.path().join("work/owned"), b"owned").unwrap();
    let authority = MappedCleanupAuthority::new(map, vec![root]).unwrap();

    authority.cleanup_for_test_current_map().unwrap();

    assert_eq!(std::fs::read(peer.join("canary")).unwrap(), b"peer");
}

#[test]
fn directory_swap_after_inventory_is_refused_before_recursing() {
    let (temporary, map, root) = fixture();
    let work = temporary.path().join("work");
    std::fs::create_dir(work.join("nested")).unwrap();
    std::fs::write(work.join("nested/original"), b"original").unwrap();
    let authority = MappedCleanupAuthority::new(map, vec![root]).unwrap();

    let result = authority.cleanup_with_hook_for_test(|| {
        std::fs::rename(work.join("nested"), work.join("moved")).unwrap();
        std::fs::create_dir(work.join("nested")).unwrap();
        std::fs::write(work.join("nested/canary"), b"replacement").unwrap();
    });

    assert!(result.is_err());
    assert_eq!(
        std::fs::read(work.join("nested/canary")).unwrap(),
        b"replacement"
    );
    assert_eq!(
        std::fs::read(work.join("moved/original")).unwrap(),
        b"original"
    );
}
