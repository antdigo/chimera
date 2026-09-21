use super::rootfs::{MountInput, generated_etc, validate_inputs};

#[test]
fn rootfs_rejects_broad_exports_and_writable_tools() {
    for source in [
        "/",
        "/usr",
        "/usr/local",
        "/home",
        "/root",
        "/run",
        "/var/run",
    ] {
        assert!(validate_inputs(&[MountInput::readonly(source, source).unwrap()]).is_err());
    }
    assert!(validate_inputs(&[MountInput::readonly("/usr/bin", "/usr/bin").unwrap()]).is_ok());
    assert!(validate_inputs(&[MountInput::writable("/usr/bin", "/usr/bin").unwrap()]).is_err());
}

#[test]
fn minimal_etc_contains_no_host_accounts_or_resolver_copy() {
    let files = generated_etc("attempt-test").unwrap();
    assert_eq!(files["passwd"], b"root:x:0:0:root:/home/chimera:/bin/sh\n");
    assert_eq!(files["group"], b"root:x:0:\n");
    assert_eq!(
        files["nsswitch.conf"],
        b"passwd: files\ngroup: files\nhosts: files dns\n"
    );
    assert_eq!(files.len(), 5);
    assert!(!files.contains_key("shadow"));
    assert!(!files.contains_key("resolv.conf"));
    assert!(generated_etc("bad\n127.0.0.1 evil").is_err());
}

#[test]
fn readonly_target_aliases_and_duplicate_mounts_are_rejected() {
    for target in [
        "/etc",
        "/usr",
        "/bin",
        "/work",
        "/opt/chimera-tools",
        "/opt/chimera-tools/a/b",
    ] {
        assert!(validate_inputs(&[MountInput::readonly("/usr/bin", target).unwrap()]).is_err());
    }
    let input = MountInput::readonly("/usr/bin", "/usr/bin").unwrap();
    assert!(validate_inputs(&[input.clone(), input]).is_err());
}

#[test]
fn immutable_cache_refuses_writable_files_and_replaced_identity() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let cache = temp.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    let tool = cache.join("tool");
    std::fs::write(&tool, b"executable").unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o555)).unwrap();
    let input = MountInput::readonly(&cache, "/opt/hostedtoolcache").unwrap();
    assert!(super::rootfs::verify_immutable(&input).is_err());
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o555)).unwrap();
    assert!(super::rootfs::verify_immutable(&input).is_err());
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&cache, temp.path().join("old")).unwrap();
    std::fs::create_dir(&cache).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o555)).unwrap();
    assert!(super::rootfs::verify_immutable(&input).is_err());
}

#[test]
fn readonly_mode_does_not_hide_a_service_owned_writable_hardlink_alias() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let input_path = temp.path().join("tool");
    let alias = temp.path().join("writable-alias");
    std::fs::write(&input_path, b"canary").unwrap();
    std::fs::hard_link(&input_path, &alias).unwrap();
    std::fs::set_permissions(&input_path, std::fs::Permissions::from_mode(0o444)).unwrap();
    let input = MountInput::readonly(&input_path, "/opt/chimera-tools/tool").unwrap();
    assert!(super::rootfs::verify_immutable(&input).is_err());
    std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&alias, b"changed").unwrap();
    assert_eq!(std::fs::read(&input_path).unwrap(), b"changed");
}

#[test]
fn operator_owned_inputs_are_accepted_and_walk_budget_is_enforced() {
    let input = MountInput::readonly(
        super::rootfs::linux::immutable_test_input(),
        "/opt/chimera-tools/zoneinfo",
    )
    .unwrap();
    super::rootfs::verify_immutable(&input).unwrap();
    assert!(super::rootfs::linux::verify_immutable_with_budget(&input, 1, 128).is_err());
    assert!(super::rootfs::linux::verify_immutable_with_budget(&input, 100_000, 1).is_err());
}

#[test]
fn debian_builder_rejects_mutable_cache_without_modifying_it() {
    use super::rootfs::linux::ImmutableInputs;
    let temp = tempfile::tempdir().unwrap();
    let inputs = ImmutableInputs {
        tool_cache: temp.path().into(),
        actions_cache: temp.path().into(),
        extra_tools: vec![],
    };
    assert!(super::rootfs::RootfsPlan::debian(&inputs).is_err());
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
#[ignore = "Debian fixture without injected foreign Docker init submounts"]
fn debian_builder_accepts_readonly_caches_and_preserves_modes() {
    use super::rootfs::linux::ImmutableInputs;
    use std::os::unix::fs::PermissionsExt;
    let cache = std::path::PathBuf::from("/usr/share/zoneinfo/Etc");
    let before = std::fs::metadata(&cache).unwrap().permissions().mode();
    let inputs = ImmutableInputs {
        tool_cache: cache.clone(),
        actions_cache: cache.clone(),
        extra_tools: vec![],
    };
    let plan = super::rootfs::RootfsPlan::debian(&inputs).unwrap();
    assert!(plan.inputs.iter().all(|i| i.readonly));
    assert_eq!(
        std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
        before & 0o777
    );
}

#[test]
fn immutable_input_refuses_external_symlinks_and_special_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let cache = temp.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    symlink("/etc/passwd", cache.join("leak")).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o555)).unwrap();
    let input = MountInput::readonly(&cache, "/opt/chimera-actions").unwrap();
    assert!(super::rootfs::verify_immutable(&input).is_err());
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_file(cache.join("leak")).unwrap();
    let fifo = std::ffi::CString::new(cache.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o400) }, 0);
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o555)).unwrap();
    assert!(super::rootfs::verify_immutable(&input).is_err());
}

#[test]
fn system_target_does_not_exempt_service_owned_writable_executables() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let tool = temp.path().join("tool");
    std::fs::write(&tool, b"tool").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let input = MountInput::readonly(temp.path(), "/usr/bin").unwrap();
    assert!(super::rootfs::verify_immutable(&input).is_err());
}

#[test]
fn attempt_layout_cannot_export_control_root_or_peer_writables() {
    use super::rootfs::RootfsPlan;
    let temp = tempfile::tempdir().unwrap();
    let attempt = temp.path().join("active/00000000000000000000000000000007");
    std::fs::create_dir_all(attempt.join("rootfs")).unwrap();
    std::fs::create_dir(attempt.join("rootlesskit")).unwrap();
    for source in [&attempt, &attempt.join("rootlesskit")] {
        let plan = RootfsPlan {
            staging_root: attempt.join("rootfs"),
            inputs: vec![MountInput::writable(source, "/work").unwrap()],
        };
        assert!(plan.validate().is_err());
    }
}

#[test]
fn full_layout_refuses_peer_control_roots_and_wrong_cgroup() {
    let attempt = "/var/lib/chimera/active/00000000000000000000000000000007";
    let mut inputs = Vec::new();
    for (source, target, readonly) in [
        ("/usr/bin".to_owned(), "/usr/bin", true),
        ("/usr/lib".to_owned(), "/usr/lib", true),
        (
            "/var/cache/chimera/tools".to_owned(),
            "/opt/hostedtoolcache",
            true,
        ),
        (
            "/var/cache/chimera/actions".to_owned(),
            "/opt/chimera-actions",
            true,
        ),
        (
            "/sys/fs/cgroup/chimera/attempt-00000000000000000000000000000007/domain".to_owned(),
            "/sys/fs/cgroup",
            false,
        ),
    ]
    .into_iter()
    .chain(
        [
            ("work", "/work"),
            ("tmp", "/tmp"),
            ("home", "/home/chimera"),
            ("run", "/run/chimera"),
            ("docker", "/home/chimera/.docker"),
            ("docker-data", "/var/lib/chimera/docker"),
            ("docker-exec", "/run/chimera/docker-exec"),
        ]
        .into_iter()
        .map(|(name, target)| (format!("{attempt}/{name}"), target, false)),
    ) {
        inputs.push(MountInput {
            source: source.into(),
            target: crate::job::execution_domain::DomainPath::parse(target).unwrap(),
            readonly,
            expected_device: 1,
            expected_inode: 1,
            immutable_fingerprint: None,
        });
    }
    let plan = super::rootfs::RootfsPlan {
        staging_root: format!("{attempt}/rootfs").into(),
        inputs,
    };
    plan.validate_layout().unwrap();
    for (target, source) in [
        ("/work", format!("{attempt}/rootlesskit")),
        (
            "/work",
            "/var/lib/chimera/active/00000000000000000000000000000008/work".to_owned(),
        ),
        ("/opt/hostedtoolcache", format!("{attempt}/rootlesskit")),
        (
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/chimera/attempt-00000000000000000000000000000008/domain".to_owned(),
        ),
    ] {
        let mut bad = plan.clone();
        bad.inputs
            .iter_mut()
            .find(|i| i.target.as_str() == target)
            .unwrap()
            .source = source.into();
        assert!(bad.validate_layout().is_err());
    }
    let mut missing = plan.clone();
    missing.inputs.retain(|i| i.target.as_str() != "/tmp");
    assert!(missing.validate_layout().is_err());
}

#[test]
fn mountinfo_rejects_shared_unknown_and_writable_readonly_mounts() {
    use super::rootfs::linux::{ExpectedMount, verify_mountinfo};
    let expected = vec![ExpectedMount {
        target: "/".into(),
        root: "/".into(),
        filesystem: "tmpfs".into(),
        readonly: true,
        nodev: true,
        noexec: false,
    }];
    let valid = "10 2 0:9 / / ro,nosuid,nodev - tmpfs chimera-rootfs ro\n";
    verify_mountinfo(valid, &expected).unwrap();
    for bad in [
        "10 2 0:9 / / rw,nosuid,nodev - tmpfs chimera-rootfs rw\n",
        "10 2 0:9 / / ro,nosuid,nodev shared:1 - tmpfs chimera-rootfs ro\n",
        "10 2 0:9 / / ro,nosuid,nodev master:1 - tmpfs chimera-rootfs ro\n",
        "10 2 0:9 /host/rootlesskit / ro,nosuid,nodev - tmpfs chimera-rootfs ro\n",
    ] {
        assert!(verify_mountinfo(bad, &expected).is_err());
    }
    assert!(
        verify_mountinfo(
            &format!("{valid}11 10 0:9 /secret /leak ro - tmpfs tmpfs ro\n"),
            &expected
        )
        .is_err()
    );
}

#[test]
fn assembling_outside_pid_one_refuses_before_any_mount() {
    use std::os::fd::AsFd;
    let (control, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let before = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let plan = super::rootfs::RootfsPlan {
        inputs: vec![],
        staging_root: "/never-created".into(),
    };
    assert!(super::rootfs::assemble_and_pivot(&plan, control.as_fd(), "test").is_err());
    assert_eq!(
        std::fs::read_to_string("/proc/self/mountinfo").unwrap(),
        before
    );
    assert!(!std::path::Path::new("/never-created").exists());
}
