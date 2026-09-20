use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use super::super::{
    DomainEnvironment, ExecutionDomainError, FailureCategory, Stage, StepFilesId, StepStateSnapshot,
};
use super::dirfd::{BoundDir, metadata};

pub(super) const EVENT_LIMIT: usize = 4 * 1024 * 1024;
const FIELD_LIMIT: usize = 1024 * 1024;
const NAMES: [&CStr; 6] = [
    c"env",
    c"path",
    c"output",
    c"state",
    c"summary",
    c"event.json",
];
const ENV_KEYS: [&str; 6] = [
    "GITHUB_ENV",
    "GITHUB_PATH",
    "GITHUB_OUTPUT",
    "GITHUB_STATE",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_EVENT_PATH",
];

pub(super) struct StepFiles {
    root: BoundDir,
    steps: HashMap<uuid::Uuid, PreparedStep>,
}

struct PreparedStep {
    directory: BoundDir,
    // Keep the original inode alive, preventing unlink/recreate inode reuse.
    files: Vec<OwnedFd>,
}

impl StepFiles {
    pub(super) fn create(domain_run: &Path) -> Result<Self, ExecutionDomainError> {
        let run = BoundDir::open_root(domain_run)?;
        Ok(Self {
            root: run.create_child(c"steps", 0o700)?,
            steps: HashMap::new(),
        })
    }

    #[cfg(test)]
    pub(super) fn open(root: &Path) -> Result<Self, ExecutionDomainError> {
        Ok(Self {
            root: BoundDir::open_root(root)?,
            steps: HashMap::new(),
        })
    }

    pub(super) fn prepare(
        &mut self,
        id: StepFilesId,
        event: &[u8],
    ) -> Result<(), ExecutionDomainError> {
        if event.len() > EVENT_LIMIT || self.steps.contains_key(&id.uuid()) {
            return Err(state_failure(FailureCategory::InvalidInput));
        }
        let name = CString::new(id.component())
            .map_err(|_| state_failure(FailureCategory::InvalidInput))?;
        let directory = self.root.create_child(&name, 0o700)?;
        let mut files = Vec::with_capacity(6);
        for (index, name) in NAMES.iter().enumerate() {
            files.push(directory.write_new(name, if index == 5 { event } else { &[] })?);
        }
        self.steps
            .insert(id.uuid(), PreparedStep { directory, files });
        Ok(())
    }

    pub(super) fn environment(
        &self,
        id: &StepFilesId,
        supplied: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>, ExecutionDomainError> {
        let step = self
            .steps
            .get(&id.uuid())
            .ok_or_else(|| state_failure(FailureCategory::InvalidInput))?;
        step.verify()?;
        let mut env = DomainEnvironment::sandboxed().merge(supplied, "command")?;
        for (name, key) in NAMES.iter().zip(ENV_KEYS) {
            let value = format!(
                "/run/chimera/steps/{}/{}",
                id.component(),
                name.to_string_lossy()
            );
            if supplied.get(key).is_some_and(|supplied| *supplied != value) {
                return Err(ExecutionDomainError::ReservedDomainEnvironment {
                    key: key.into(),
                    source: "command",
                });
            }
            env.insert(key.into(), value);
        }
        Ok(env)
    }

    pub(super) fn read(&self, id: &StepFilesId) -> Result<StepStateSnapshot, ExecutionDomainError> {
        let step = self
            .steps
            .get(&id.uuid())
            .ok_or_else(|| state_failure(FailureCategory::InvalidInput))?;
        step.verify()?;
        let mut values = Vec::with_capacity(5);
        for (name, original) in NAMES[..5].iter().zip(&step.files) {
            values.push(
                String::from_utf8(step.directory.read_bound_regular(
                    name,
                    original,
                    FIELD_LIMIT,
                )?)
                .map_err(|_| state_failure(FailureCategory::InvalidInput))?,
            );
        }
        step.verify()?;
        let mut values = values.into_iter();
        let mut next = || {
            values
                .next()
                .ok_or_else(|| state_failure(FailureCategory::InvalidInput))
        };
        let snapshot = StepStateSnapshot {
            env: next()?,
            path: next()?,
            output: next()?,
            state: next()?,
            summary: next()?,
        };
        DomainEnvironment::sandboxed().merge(&snapshot.parse()?.env, "GITHUB_ENV")?;
        Ok(snapshot)
    }
}

impl PreparedStep {
    fn verify(&self) -> Result<(), ExecutionDomainError> {
        for (name, fd) in NAMES.iter().zip(&self.files) {
            let original = metadata(fd.as_raw_fd())?;
            if original.stx_nlink != 1 || original.stx_mode & 0o777 != 0o600 {
                return Err(state_failure(FailureCategory::IdentityMismatch));
            }
            self.directory.verify_entry(name, &original)?;
        }
        Ok(())
    }
}

fn state_failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::State,
        category,
        errno: None,
    }
}

#[cfg(test)]
#[path = "step_files_test.rs"]
mod step_files_test;
