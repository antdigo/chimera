use super::*;

#[test]
fn executable_metadata_rejects_group_or_other_write() {
    let file = std::fs::File::open("/usr/bin/true").unwrap();
    let mut metadata = dirfd::metadata(file.as_raw_fd()).unwrap();
    assert!(validate_executable_metadata(&metadata, false).is_ok());

    metadata.stx_mode |= 0o022;

    assert!(validate_executable_metadata(&metadata, false).is_err());
}

#[test]
fn executable_metadata_rejects_service_ownership() {
    let file = std::fs::File::open("/usr/bin/true").unwrap();
    let mut metadata = dirfd::metadata(file.as_raw_fd()).unwrap();
    assert!(validate_executable_metadata(&metadata, false).is_ok());

    metadata.stx_uid = 1000;

    assert!(validate_executable_metadata(&metadata, false).is_err());
}

#[test]
fn pinned_root_owned_elf_executes_with_cloexec() {
    let executable =
        VerifiedExecutable::open(std::path::Path::new("/usr/bin/true"), false).unwrap();
    assert_ne!(
        unsafe { libc::fcntl(executable.fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    assert!(executable.command().unwrap().status().unwrap().success());
}

#[test]
fn retained_executable_refuses_in_place_content_change() {
    use std::io::Write;
    // Constructor ownership is checked independently. A mutable test inode
    // models an operator changing a retained executable after verification.
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"original").unwrap();
    let fd: OwnedFd = file.as_file().try_clone().unwrap().into();
    let metadata = dirfd::metadata(fd.as_raw_fd()).unwrap();
    let executable = VerifiedExecutable {
        fd,
        identity: identity(&metadata),
        size: metadata.stx_size,
        changed: (metadata.stx_ctime.tv_sec, metadata.stx_ctime.tv_nsec),
    };
    assert!(executable.command().is_ok());
    file.write_all(b"changed").unwrap();
    assert!(executable.command().is_err());
}
