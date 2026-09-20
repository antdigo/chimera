use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use uuid::Uuid;

use super::ExecutionDomainError;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AttemptIdentity(Uuid);

impl AttemptIdentity {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(id: Uuid) -> Result<Self, ExecutionDomainError> {
        if id.is_nil() {
            return Err(ExecutionDomainError::InvalidAttemptIdentity);
        }
        Ok(Self(id))
    }

    pub fn uuid(&self) -> Uuid {
        self.0
    }

    pub(crate) fn component(&self) -> String {
        self.0.simple().to_string()
    }
}

impl Default for AttemptIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for AttemptIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.component().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AttemptIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_uuid(Uuid::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainPath(String);

impl DomainPath {
    pub fn parse(value: &str) -> Result<Self, ExecutionDomainError> {
        if !valid_absolute_path(value) {
            return Err(ExecutionDomainError::InvalidDomainPath);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn join(&self, relative: &str) -> Result<Self, ExecutionDomainError> {
        if !valid_relative_path(relative) {
            return Err(ExecutionDomainError::InvalidDomainPath);
        }
        let separator = if self.0 == "/" { "" } else { "/" };
        Self::parse(&format!("{}{separator}{relative}", self.0))
    }

    fn known(value: &'static str) -> Self {
        Self(value.to_owned())
    }
}

impl Serialize for DomainPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DomainPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

fn valid_absolute_path(value: &str) -> bool {
    if value == "/" {
        return true;
    }
    value.starts_with('/')
        && !value.starts_with("//")
        && !value.ends_with('/')
        && !value.contains('\0')
        && valid_components(&value[1..])
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\0')
        && valid_components(value)
}

fn valid_components(value: &str) -> bool {
    value
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainPaths {
    pub work: DomainPath,
    pub tmp: DomainPath,
    pub home: DomainPath,
    pub run: DomainPath,
    pub docker_config: DomainPath,
    pub docker_data: DomainPath,
    pub docker_exec: DomainPath,
    docker_socket: DomainPath,
}

impl DomainPaths {
    pub(crate) fn sandboxed() -> Self {
        Self {
            work: DomainPath::known("/work"),
            tmp: DomainPath::known("/tmp"),
            home: DomainPath::known("/home/chimera"),
            run: DomainPath::known("/run/chimera"),
            docker_config: DomainPath::known("/home/chimera/.docker"),
            docker_data: DomainPath::known("/var/lib/chimera/docker"),
            docker_exec: DomainPath::known("/run/chimera/docker-exec"),
            docker_socket: DomainPath::known("/run/chimera/docker.sock"),
        }
    }

    pub(crate) fn docker_socket(&self) -> &DomainPath {
        &self.docker_socket
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DomainEnvironment {
    values: HashMap<String, String>,
}

impl DomainEnvironment {
    pub fn sandboxed() -> Self {
        let paths = DomainPaths::sandboxed();
        Self {
            values: HashMap::from([
                ("HOME".to_owned(), paths.home.as_str().to_owned()),
                ("XDG_RUNTIME_DIR".to_owned(), paths.run.as_str().to_owned()),
                (
                    "DOCKER_CONFIG".to_owned(),
                    paths.docker_config.as_str().to_owned(),
                ),
                (
                    "DOCKER_HOST".to_owned(),
                    format!("unix://{}", paths.docker_socket().as_str()),
                ),
            ]),
        }
    }

    pub fn merge(
        &self,
        supplied: &HashMap<String, String>,
        source: &'static str,
    ) -> Result<HashMap<String, String>, ExecutionDomainError> {
        for (key, owned) in &self.values {
            if supplied.get(key).is_some_and(|value| value != owned) {
                return Err(ExecutionDomainError::ReservedDomainEnvironment {
                    key: key.clone(),
                    source,
                });
            }
        }
        let mut result = supplied.clone();
        result.extend(self.values.clone());
        Ok(result)
    }
}

impl fmt::Debug for DomainEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DomainEnvironment")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepFilesId(Uuid);

impl StepFilesId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn uuid(&self) -> Uuid {
        self.0
    }

    pub(crate) fn component(&self) -> String {
        self.0.simple().to_string()
    }

    fn from_uuid(id: Uuid) -> Result<Self, ExecutionDomainError> {
        if id.is_nil() {
            return Err(ExecutionDomainError::InvalidStepFilesIdentity);
        }
        Ok(Self(id))
    }
}

impl Default for StepFilesId {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for StepFilesId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.component().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StepFilesId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_uuid(Uuid::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Stage {
    Preflight,
    Filesystem,
    Cgroup,
    Launch,
    Rootfs,
    Protocol,
    Command,
    State,
    Destroy,
    Reconcile,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FailureCategory {
    Unsupported,
    InvalidInput,
    Unavailable,
    IdentityMismatch,
    Timeout,
    Io,
    Protocol,
    NotReady,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepStateSnapshot {
    pub env: String,
    pub path: String,
    pub output: String,
    pub state: String,
    pub summary: String,
}

impl fmt::Debug for StepStateSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StepStateSnapshot")
    }
}
