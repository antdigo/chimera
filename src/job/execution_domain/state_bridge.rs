use std::collections::HashMap;
use std::fmt;

use super::{ExecutionDomainError, FailureCategory, Stage, StepStateSnapshot};
use crate::job::workspace::{parse_context_file, parse_env_file, parse_path_file};

pub struct ParsedStepState {
    pub env: HashMap<String, String>,
    pub path: Vec<String>,
    pub output: HashMap<String, String>,
    pub state: HashMap<String, String>,
    pub summary: String,
}

impl fmt::Debug for ParsedStepState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedStepState")
    }
}

impl StepStateSnapshot {
    pub fn parse(&self) -> Result<ParsedStepState, ExecutionDomainError> {
        let invalid = |_| ExecutionDomainError::Backend {
            attempt: None,
            stage: Stage::State,
            category: FailureCategory::InvalidInput,
            errno: None,
        };
        Ok(ParsedStepState {
            env: parse_env_file(&self.env).map_err(invalid)?,
            path: parse_path_file(&self.path),
            output: parse_context_file(&self.output).map_err(invalid)?,
            state: parse_context_file(&self.state).map_err(invalid)?,
            summary: self.summary.clone(),
        })
    }
}
