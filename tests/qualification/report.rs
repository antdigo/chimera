use serde::{Deserialize, Serialize};

use super::catalog::{
    CaseKey, CheckId, Reason, ScenarioId, required_cases, required_checks, validate_coverage,
};
use super::resources::{CaseMetrics, valid_summary};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceMode {
    Fixture,
    NestedSmoke,
    NativeDebian,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Passed,
    Failed,
    Blocked,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunIdentity {
    pub run_id: uuid::Uuid,
    pub commit: String,
    pub config_digest: String,
    pub host_boot_id: uuid::Uuid,
    pub mode: EvidenceMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub id: CheckId,
    pub passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub identity: RunIdentity,
    pub key: CaseKey,
    pub driver_commit: String,
    pub driver_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseResult {
    pub key: CaseKey,
    pub verdict: Verdict,
    pub reason: Option<Reason>,
    pub provenance: EvidenceProvenance,
    pub checks: Vec<Check>,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReport {
    pub schema_version: u32,
    pub identity: RunIdentity,
    pub driver_digest: String,
    pub activation_available: bool,
    pub results: Vec<CaseResult>,
    pub cleanup_confirmed: bool,
    pub resource_summaries: Vec<CaseMetrics>,
}

pub(super) fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn valid_identity(identity: &RunIdentity) -> bool {
    !identity.run_id.is_nil()
        && !identity.host_boot_id.is_nil()
        && (valid_hex(&identity.commit, 40) || valid_hex(&identity.commit, 64))
        && valid_hex(&identity.config_digest, 64)
}

/// Structural validity is necessary, never sufficient, for release evidence.
pub fn validate_report_structure(report: &QualificationReport) -> Result<(), Reason> {
    if report.schema_version != 1
        || report.activation_available
        || !valid_identity(&report.identity)
        || !valid_hex(&report.driver_digest, 64)
    {
        return Err(Reason::ProtocolViolation);
    }
    validate_coverage(&report.results)?;
    if !report.cleanup_confirmed {
        return Err(Reason::CleanupUnconfirmed);
    }
    for row in &report.results {
        if row.provenance.identity != report.identity
            || row.provenance.key != row.key
            || row.provenance.driver_commit != report.identity.commit
            || row.provenance.driver_digest != report.driver_digest
        {
            return Err(Reason::StaleEvidence);
        }
        if row.verdict != Verdict::Passed
            || row.reason.is_some()
            || row.checks.iter().any(|check| !check.passed)
            || row.checks.iter().map(|check| check.id).collect::<Vec<_>>()
                != required_checks(&row.key)
        {
            return Err(Reason::MissingEvidence);
        }
    }
    if !valid_metrics(report, report.identity.mode == EvidenceMode::NativeDebian) {
        return Err(Reason::MissingEvidence);
    }
    Ok(())
}

fn valid_metrics(report: &QualificationReport, complete: bool) -> bool {
    let expected: std::collections::BTreeSet<_> = required_cases()
        .into_iter()
        .filter(|key| matches!(key.scenario, ScenarioId::S09 | ScenarioId::S16))
        .collect();
    let actual: std::collections::BTreeSet<_> = report
        .resource_summaries
        .iter()
        .map(|metrics| metrics.key.clone())
        .collect();
    actual.len() == report.resource_summaries.len()
        && actual.is_subset(&expected)
        && (!complete || actual == expected)
        && report.resource_summaries.iter().all(|metrics| {
            valid_summary(&metrics.summary)
                && report.results.iter().any(|row| row.key == metrics.key)
        })
}

pub fn qualifies(report: &QualificationReport) -> bool {
    if report.identity.mode != EvidenceMode::NativeDebian
        || validate_report_structure(report).is_err()
    {
        return false;
    }
    // E0 provides fixture evaluators and typed summaries, but no authenticated
    // run-owned native sampler. Numeric summaries and all-true checklists do
    // not establish native provenance; E1 must supply independent collection.
    false
}

/// Only closed enums, catalogue keys, bounded digests and synthetic UUIDs reach
/// disk. Incomplete/blocked rows may be written; raw observations cannot be.
fn safe_to_serialize(report: &QualificationReport) -> bool {
    let catalogue = required_cases();
    report.schema_version == 1
        && !report.activation_available
        && valid_identity(&report.identity)
        && (report.driver_digest.is_empty() || valid_hex(&report.driver_digest, 64))
        && report.results.len() <= catalogue.len()
        && valid_metrics(report, false)
        && report.results.iter().all(|row| {
            catalogue.contains(&row.key)
                && catalogue.contains(&row.provenance.key)
                && valid_identity(&row.provenance.identity)
                && (valid_hex(&row.provenance.driver_commit, 40)
                    || valid_hex(&row.provenance.driver_commit, 64))
                && (row.provenance.driver_digest.is_empty()
                    || valid_hex(&row.provenance.driver_digest, 64))
                && row.checks.len() <= 32
        })
}

fn markdown(report: &QualificationReport) -> String {
    use std::fmt::Write;
    let heading = match report.identity.mode {
        EvidenceMode::Fixture => "FIXTURE / NOT RELEASE EVIDENCE",
        EvidenceMode::NestedSmoke => "NESTED SMOKE / NOT RELEASE EVIDENCE",
        EvidenceMode::NativeDebian => "NATIVE / INCOMPLETE",
    };
    let mut text = format!(
        "# {heading}\n\nActivation available: false\n\nCleanup confirmed: {}\n\n| Scenario | Passed | Required |\n| --- | ---: | ---: |\n",
        report.cleanup_confirmed
    );
    let cases = required_cases();
    for scenario in ScenarioId::ALL {
        let id = serde_json::to_string(&scenario).expect("enum serialization");
        let count = cases.iter().filter(|key| key.scenario == scenario).count();
        let passed = report
            .results
            .iter()
            .filter(|row| row.key.scenario == scenario && row.verdict == Verdict::Passed)
            .count();
        writeln!(text, "| {} | {passed} | {count} |", id.trim_matches('"')).unwrap();
    }
    text.push_str("\n| Scenario | Case | Wave | Concurrency | Status | Reason |\n| --- | --- | --- | ---: | --- | --- |\n");
    for key in cases {
        let id = serde_json::to_string(&key.scenario).unwrap();
        let (status, reason) = match report.results.iter().find(|row| row.key == key) {
            Some(row) => (
                format!("{:?}", row.verdict),
                row.reason.map(|r| format!("{r:?}")).unwrap_or_default(),
            ),
            None => ("Inconclusive".into(), "MissingEvidence".into()),
        };
        writeln!(
            text,
            "| {} | {} | {} | {} | {status} | {reason} |",
            id.trim_matches('"'),
            key.case,
            key.wave.as_str(),
            key.concurrency
        )
        .unwrap();
    }
    if !report.resource_summaries.is_empty() {
        text.push_str("\n| Scenario | Case | Wave | Concurrency | PSS (bytes) | Peak PIDs (count) | Sentinel p99 (µs) | Read (ops/s) | Write (ops/s) | Minimum host available (bytes) | CPU (µs) | Throttled periods (count) | Throttled (µs) | Startup (ms) | Cleanup (ms) |\n| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        for metrics in &report.resource_summaries {
            let key = &metrics.key;
            let s = &metrics.summary;
            let id = serde_json::to_string(&key.scenario).unwrap();
            writeln!(text,"| {} | {} | {} | {} | {} | {} | {} | {:.3} | {:.3} | {} | {} | {} | {} | {} | {} |",id.trim_matches('"'),key.case,key.wave.as_str(),key.concurrency,s.peak_pss_bytes,s.peak_pids,s.sentinel_p99_us,s.read_iops,s.write_iops,s.minimum_host_mem_available_bytes,s.total_cpu_usage_usec,s.cpu_throttled_periods,s.cpu_throttled_usec,s.startup_ms,s.cleanup_ms).unwrap();
        }
    }
    text
}

pub fn write_report(
    directory: &std::path::Path,
    report: &QualificationReport,
) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    // Hold the run directory across creation, publication and directory fsync;
    // path replacement cannot redirect subsequent writes.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)?;
    write_report_at(&directory, report)
}

pub(super) fn write_report_at(
    directory: &std::fs::File,
    report: &QualificationReport,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    if !safe_to_serialize(report) {
        return Err(Error::new(ErrorKind::InvalidInput, "unsafe report fields"));
    }
    let json = serde_json::to_vec_pretty(report)?;
    let md = markdown(report);
    for (name, contents) in [
        ("report.json", json.as_slice()),
        ("report.md", md.as_bytes()),
    ] {
        let temporary =
            std::ffi::CString::new(format!(".{name}.{}.tmp", uuid::Uuid::new_v4())).unwrap();
        let destination = std::ffi::CString::new(name).unwrap();
        // SAFETY: valid held directory FD, NUL-terminated synthetic names; a
        // successful open returns a new owned FD transferred exactly once.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(contents)?;
            file.sync_all()?;
            let renamed = unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    directory.as_raw_fd(),
                    destination.as_ptr(),
                )
            };
            if renamed < 0 {
                return Err(Error::last_os_error());
            }
            directory.sync_all()
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0);
            }
        }
        result?;
    }
    Ok(())
}
