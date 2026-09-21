use super::*;
use crate::config::{StorageBoundConfig, StorageMechanism};
use crate::sandbox_policy::PolicyError;

fn dedicated() -> (StorageBoundConfig, StorageObservation) {
    (
        StorageBoundConfig {
            mechanism: StorageMechanism::DedicatedFilesystem,
            max_bytes: "64GiB".parse().unwrap(),
        },
        StorageObservation {
            root: StorageIdentity {
                device: 0x802,
                inode: 7,
                mount_id: 9,
            },
            mount_point: "/srv/chimera".into(),
            filesystem_root: "/".into(),
            filesystem_type: "ext4".into(),
            total_bytes: 64 << 30,
            available_bytes: 1 << 30,
            parent_device: 0x801,
            writable_nested_mounts: vec![],
            aliases_outside_root: vec![],
        },
    )
}

#[test]
fn dedicated_capacity_is_total_size_not_available_space() {
    let (config, mut observation) = dedicated();
    let evidence = validate_storage_bound(&config, &observation).unwrap();
    assert_eq!(evidence.hard_limit_bytes(), 64 << 30);
    assert_eq!(evidence.identity(), &observation.root);
    observation.total_bytes = 1 << 40;
    assert!(validate_storage_bound(&config, &observation).is_err());
}

#[test]
fn dedicated_storage_rejects_unbounded_or_aliased_roots() {
    let (config, observation) = dedicated();
    let mut changed = observation.clone();
    changed.total_bytes = 65 << 30;
    assert!(validate_storage_bound(&config, &changed).is_err());
    changed = observation.clone();
    changed.filesystem_root = "/subdir".into();
    assert!(validate_storage_bound(&config, &changed).is_err());
    changed = observation.clone();
    changed.parent_device = changed.root.device;
    assert!(validate_storage_bound(&config, &changed).is_err());
    changed = observation.clone();
    changed
        .writable_nested_mounts
        .push("/srv/chimera/cache".into());
    assert!(validate_storage_bound(&config, &changed).is_err());
    changed = observation.clone();
    changed
        .aliases_outside_root
        .push("/mnt/chimera-alias".into());
    assert!(validate_storage_bound(&config, &changed).is_err());
    changed = observation.clone();
    changed.filesystem_type = "tmpfs".into();
    assert!(validate_storage_bound(&config, &changed).is_err());
    changed = observation;
    changed.total_bytes = 0;
    assert!(validate_storage_bound(&config, &changed).is_err());
}

#[test]
fn unsupported_quota_collectors_do_not_accept_operator_assertions() {
    let (_, observation) = dedicated();
    for mechanism in [StorageMechanism::ProjectQuota, StorageMechanism::BtrfsQuota] {
        let config = StorageBoundConfig {
            mechanism,
            max_bytes: "64GiB".parse().unwrap(),
        };
        assert!(matches!(
            validate_storage_bound(&config, &observation),
            Err(PolicyError::UnsupportedStorageProbe)
        ));
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn live_storage_probe_is_explicitly_unsupported_off_linux() {
    let temp = tempfile::tempdir().unwrap();
    assert_eq!(
        probe_storage(temp.path()),
        Err(PolicyError::UnsupportedPlatform)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn revalidation_rejects_replaced_and_symlink_roots() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let evidence = StorageBoundEvidence {
        identity: linux::path_identity(&root).unwrap(),
        hard_limit_bytes: 64 << 30,
    };
    assert!(linux::verify_pinned_identity(&root, &evidence.identity).is_ok());
    std::fs::rename(&root, temp.path().join("old")).unwrap();
    std::fs::create_dir(&root).unwrap();
    assert!(linux::verify_pinned_identity(&root, &evidence.identity).is_err());
    assert!(revalidate_storage_identity(&root, &evidence).is_err());
    std::fs::remove_dir(&root).unwrap();
    std::os::unix::fs::symlink(temp.path().join("old"), &root).unwrap();
    assert!(probe_storage(&root).is_err());
    assert!(linux::verify_pinned_identity(&root, &evidence.identity).is_err());
    assert!(revalidate_storage_identity(&root, &evidence).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn mountinfo_decodes_path_escapes_and_rejects_bad_ids() {
    let line = b"9 1 8:2 / /srv/chimera\\040x\\011y\\134z rw,relatime - ext4 /dev/vg rw\n";
    let mounts = parse_mountinfo(line).unwrap();
    assert_eq!(
        mounts[0].point,
        std::path::Path::new("/srv/chimera x\ty\\z")
    );
    for bad in [
        b"x 1 8:2 / /srv/chimera rw - ext4 /dev/vg rw\n".as_slice(),
        b"9 1 8:x / /srv/chimera rw - ext4 /dev/vg rw\n",
    ] {
        assert!(parse_mountinfo(bad).is_err());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn mountinfo_input_and_capacity_multiplication_are_bounded() {
    let oversized = vec![b'x'; MAX_MOUNTINFO_BYTES + 1];
    assert!(read_mountinfo_limited(&mut oversized.as_slice()).is_err());
    assert_eq!(checked_capacity(64, 1 << 30).unwrap(), 64 << 30);
    assert!(checked_capacity(u64::MAX, 2).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn mount_scan_finds_writable_nested_mount_and_outside_same_device_alias() {
    let mounts = parse_mountinfo(b"9 1 8:2 / /srv/chimera rw - ext4 /dev/vg rw\n10 9 0:3 / /srv/chimera/cache rw - tmpfs tmpfs rw\n11 1 8:2 / /mnt/alias ro - ext4 /dev/vg rw\n").unwrap();
    let (nested, aliases) = linux::mount_conflicts(
        &mounts,
        std::path::Path::new("/srv/chimera"),
        9,
        mounts[0].device,
    );
    assert_eq!(nested, vec![std::path::PathBuf::from("/srv/chimera/cache")]);
    assert_eq!(aliases, vec![std::path::PathBuf::from("/mnt/alias")]);
}

#[cfg(all(target_os = "linux", feature = "acceptance-tests"))]
#[test]
#[ignore = "serialized native qualification on provisioned dedicated storage only"]
fn native_dedicated_storage_bound() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let root = std::env::var_os("CHIMERA_QUALIFICATION_ROOT")
        .expect("inconclusive: CHIMERA_QUALIFICATION_ROOT is not provisioned");
    let max_bytes: crate::config::StorageBytes =
        std::env::var("CHIMERA_QUALIFICATION_STORAGE_MAX_BYTES")
            .expect("inconclusive: CHIMERA_QUALIFICATION_STORAGE_MAX_BYTES is absent")
            .parse()
            .expect("inconclusive: invalid qualification storage maximum");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/lock/chimera-qualification.lock")
        .expect("inconclusive: qualification lock is not provisioned");
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(
        result, 0,
        "inconclusive: qualification lock is held or unusable"
    );

    let config = StorageBoundConfig {
        mechanism: StorageMechanism::DedicatedFilesystem,
        max_bytes,
    };
    let root = std::path::Path::new(&root);
    let observation = probe_storage(root).expect("inconclusive: dedicated storage probe failed");
    let evidence = validate_storage_bound(&config, &observation)
        .expect("inconclusive: no proven dedicated ext4/XFS capacity bound");
    revalidate_storage_identity(root, &evidence)
        .expect("inconclusive: dedicated storage identity changed");
}
