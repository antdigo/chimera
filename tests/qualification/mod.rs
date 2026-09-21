pub mod catalog;
pub mod docker;
pub mod driver;
pub mod fixtures;
pub mod host;
pub mod isolation;
pub mod lifecycle;
pub mod report;
pub mod resources;

pub fn blocked_report(
    identity: report::RunIdentity,
    reason: catalog::Reason,
) -> report::QualificationReport {
    let results = catalog::required_cases()
        .into_iter()
        .map(|key| report::CaseResult {
            provenance: report::EvidenceProvenance {
                identity: identity.clone(),
                key: key.clone(),
                driver_commit: identity.commit.clone(),
                driver_digest: String::new(),
            },
            key,
            verdict: report::Verdict::Blocked,
            reason: Some(reason),
            checks: vec![],
            duration_ms: 0,
        })
        .collect();
    report::QualificationReport {
        schema_version: 1,
        identity,
        driver_digest: String::new(),
        activation_available: false,
        results,
        cleanup_confirmed: false,
        resource_summaries: vec![],
    }
}
pub async fn run_native(
    config: host::NativeConfig,
) -> Result<report::QualificationReport, catalog::Reason> {
    config.validate()?;
    let output = std::process::Command::new("/usr/bin/git")
        .args([
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            "rev-parse",
            "--verify",
            "HEAD",
        ])
        .env_clear()
        .output()
        .map_err(|_| catalog::Reason::MissingEvidence)?;
    let commit = String::from_utf8(output.stdout).map_err(|_| catalog::Reason::MissingEvidence)?;
    if !output.status.success()
        || !(report::valid_hex(commit.trim(), 40) || report::valid_hex(commit.trim(), 64))
    {
        return Err(catalog::Reason::MissingEvidence);
    }
    // Acquire before any report publication; never invoke a workload driver.
    // E1 must establish authenticated ownership before runtime execution exists.
    let lease = host::acquire_native(&config, uuid::Uuid::new_v4())?;
    publish_unavailable(lease, commit.trim().into())
}
fn publish_unavailable(
    lease: host::NativeLease,
    commit: String,
) -> Result<report::QualificationReport, catalog::Reason> {
    let mut report = blocked_report(
        lease.run_identity(commit),
        catalog::Reason::BackendUnavailable,
    );
    // This exact E0 branch has no workload side effects. Generic blocked reports
    // retain cleanup=false; a crash/error never reaches this release operation.
    report.cleanup_confirmed = true;
    lease.publish_blocked_and_release(&report)?;
    Ok(report)
}
pub fn read_native_config(path: &std::path::Path) -> Result<host::NativeConfig, catalog::Reason> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
    if !path.is_absolute() {
        return Err(catalog::Reason::InvalidConfig);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| catalog::Reason::InvalidConfig)?;
    let metadata = file
        .metadata()
        .map_err(|_| catalog::Reason::InvalidConfig)?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(catalog::Reason::InvalidConfig);
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| catalog::Reason::InvalidConfig)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(catalog::Reason::InvalidConfig);
    }
    let config: host::NativeConfig =
        serde_json::from_slice(&bytes).map_err(|_| catalog::Reason::InvalidConfig)?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod catalog_test;
#[cfg(test)]
mod docker_test;
#[cfg(test)]
mod driver_test;
#[cfg(test)]
mod fixtures_test;
#[cfg(test)]
mod host_test;
#[cfg(test)]
mod isolation_test;
#[cfg(test)]
mod lifecycle_test;
#[cfg(test)]
mod orchestrator_test;
#[cfg(test)]
mod report_test;
#[cfg(test)]
mod resources_test;
