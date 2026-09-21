fn main() {
    println!("cargo:rerun-if-changed=src/job/execution_domain/linux/native_fd_probe.c");
    if std::env::var_os("CARGO_FEATURE_ACCEPTANCE_TESTS").is_none()
        || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
    {
        return;
    }
    // Qualification executes the prebuilt test binary directly. Build its
    // static probe here so fixture preparation never launches a host compiler.
    assert_eq!(
        std::env::var("HOST"),
        std::env::var("TARGET"),
        "native acceptance probes must be built for the build host"
    );
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo OUT_DIR"))
        .join("chimera-native-fd-probe");
    let status = std::process::Command::new("cc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-static",
            "-O2",
            "-fno-ident",
            "-Wl,--build-id=none",
            "-o",
        ])
        .arg(output)
        .arg("src/job/execution_domain/linux/native_fd_probe.c")
        .status()
        .expect("native acceptance probe requires a C compiler and static libc at build time");
    assert!(
        status.success(),
        "native acceptance probe compilation failed"
    );
}
