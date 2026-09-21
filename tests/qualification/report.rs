use serde::{Deserialize, Serialize};

use super::catalog::{CaseKey, CheckId, Reason};

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
pub struct RunIdentity {
    pub run_id: uuid::Uuid,
    pub commit: String,
    pub config_digest: String,
    pub host_boot_id: uuid::Uuid,
    pub mode: EvidenceMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Check {
    pub id: CheckId,
    pub passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceProvenance {
    pub identity: RunIdentity,
    pub key: CaseKey,
    pub driver_commit: String,
    pub driver_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaseResult {
    pub key: CaseKey,
    pub verdict: Verdict,
    pub reason: Option<Reason>,
    pub provenance: EvidenceProvenance,
    pub checks: Vec<Check>,
    pub duration_ms: u64,
}
