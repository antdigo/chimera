use serde::{Deserialize, Serialize};

use super::catalog::{
    CaseKey, CheckId, Reason, ScenarioId, required_cases, required_checks, validate_coverage,
};

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReport {
    pub schema_version: u32,
    pub identity: RunIdentity,
    pub driver_digest: String,
    pub activation_available: bool,
    pub results: Vec<CaseResult>,
    pub cleanup_confirmed: bool,
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
    Ok(())
}

pub fn qualifies(report: &QualificationReport) -> bool {
    if report.identity.mode != EvidenceMode::NativeDebian
        || validate_report_structure(report).is_err()
    {
        return false;
    }
    // Tasks 4–7 provide typed evaluators, independently captured native facts and
    // bounded S-09/S-16 metric summaries. Raw responses or caller-constructed
    // all-true checklists must never substitute for that evidence in Task 2.
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
    text
}

pub fn write_report(
    directory: &std::path::Path,
    report: &QualificationReport,
) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::{Error, ErrorKind, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    if !safe_to_serialize(report) {
        return Err(Error::new(ErrorKind::InvalidInput, "unsafe report fields"));
    }
    // Hold the run directory across creation, publication and directory fsync;
    // path replacement cannot redirect subsequent writes.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)?;
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
