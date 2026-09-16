use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use reqwest::Url;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::config::{
    OAuthCredentials, RsaParameters, RunnerCredentials, RunnerInfo, private_key_to_rsa_params,
    rsa_params_to_private_key,
};

use super::{ImportError, RunnerIdentity, ValidatedRegistration};

const REQUIRED_AUTH_KEYS: [&str; 2] = ["clientId", "authorizationUrl"];
const RECOGNIZED_AUTH_KEYS: [&str; 5] = [
    "clientId",
    "authorizationUrl",
    "requireFipsCryptography",
    "enableAuthMigrationByDefault",
    "authorizationUrlV2",
];

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OfficialRunnerSettings {
    agent_id: u64,
    agent_name: String,
    pool_id: u64,
    #[serde(default)]
    pool_name: Option<String>,
    #[serde(default)]
    skip_session_recover: bool,
    #[serde(default)]
    disable_update: bool,
    #[serde(default)]
    ephemeral: bool,
    server_url: String,
    #[serde(default)]
    git_hub_url: String,
    work_folder: String,
    #[serde(default)]
    use_v2_flow: bool,
    #[serde(default)]
    use_runner_admin_flow: bool,
    #[serde(default)]
    server_url_v2: String,
    #[serde(default)]
    monitor_socket_address: Option<String>,
    #[serde(default, rename = "IsHostedServer")]
    is_hosted_server: Option<bool>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OfficialCredentialData {
    scheme: String,
    data: BTreeMap<String, String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OfficialRsaParameters {
    #[serde(rename = "D")]
    d: String,
    #[serde(rename = "DP")]
    dp: String,
    #[serde(rename = "DQ")]
    dq: String,
    #[serde(rename = "Exponent")]
    exponent: String,
    #[serde(rename = "InverseQ")]
    inverse_q: String,
    #[serde(rename = "Modulus")]
    modulus: String,
    #[serde(rename = "P")]
    p: String,
    #[serde(rename = "Q")]
    q: String,
}

pub(crate) fn read_regular_no_follow(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential path is not a regular file",
        ));
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let after = file.metadata()?;
    if !after.is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "credential path changed while opening",
        ));
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn read_official_registration(
    source: &Path,
) -> Result<ValidatedRegistration, ImportError> {
    let canonical_source = canonical_source(source)?;
    let runner: OfficialRunnerSettings = parse_source_file(&canonical_source, ".runner")?;
    let credentials: OfficialCredentialData = parse_source_file(&canonical_source, ".credentials")?;
    let rsa: OfficialRsaParameters =
        parse_source_file(&canonical_source, ".credentials_rsaparams")?;

    validate_runner_settings(&runner)?;
    let identity = runner_identity(&runner.git_hub_url, runner.pool_id, runner.agent_id)?;
    validate_actions_url(&runner.server_url, true)?;
    validate_actions_url(&runner.server_url_v2, false)?;
    let oauth = validate_oauth(&credentials, &canonical_source)?;
    let rsa_params = validate_and_canonicalize_rsa(rsa)?;

    let _ignored_provenance_settings = (
        &runner.pool_name,
        runner.skip_session_recover,
        runner.disable_update,
        runner.use_runner_admin_flow,
        &runner.monitor_socket_address,
    );

    Ok(ValidatedRegistration {
        credentials: RunnerCredentials {
            info: RunnerInfo {
                agent_id: runner.agent_id,
                agent_name: runner.agent_name,
                pool_id: runner.pool_id,
                server_url: runner.server_url,
                server_url_v2: runner.server_url_v2,
                git_hub_url: runner.git_hub_url,
                work_folder: runner.work_folder,
                use_v2_flow: runner.use_v2_flow,
            },
            oauth,
            rsa_params,
        },
        identity,
        canonical_source,
    })
}

fn canonical_source(source: &Path) -> Result<PathBuf, ImportError> {
    let canonical_source = std::fs::canonicalize(source)
        .map_err(|_| ImportError::InvalidSource("unable to access source directory".into()))?;
    let metadata = std::fs::metadata(&canonical_source)
        .map_err(|_| ImportError::InvalidSource("unable to inspect source directory".into()))?;
    if !metadata.is_dir() {
        return Err(ImportError::InvalidSource(
            "source path is not a directory".into(),
        ));
    }
    Ok(canonical_source)
}

fn parse_source_file<T: DeserializeOwned>(source: &Path, name: &str) -> Result<T, ImportError> {
    let bytes = read_regular_no_follow(&source.join(name)).map_err(|_| {
        ImportError::InvalidSource(format!("unable to read required credential file {name}"))
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        ImportError::InvalidSource(format!(
            "unable to parse {name} at line {} column {}",
            error.line(),
            error.column()
        ))
    })
}

fn validate_runner_settings(runner: &OfficialRunnerSettings) -> Result<(), ImportError> {
    if runner.agent_id == 0 {
        return Err(ImportError::InvalidSource(
            "agentId must be positive".into(),
        ));
    }
    if runner.pool_id == 0 {
        return Err(ImportError::InvalidSource("poolId must be positive".into()));
    }
    if runner.agent_name.is_empty() {
        return Err(ImportError::InvalidSource(
            "agentName must not be empty".into(),
        ));
    }
    if runner.work_folder.is_empty() {
        return Err(ImportError::InvalidSource(
            "workFolder must not be empty".into(),
        ));
    }
    if runner.ephemeral {
        return Err(ImportError::UnsupportedRegistration(
            "ephemeral registrations are not supported".into(),
        ));
    }
    if !runner.use_v2_flow {
        return Err(ImportError::UnsupportedRegistration(
            "legacy registration flow is not supported".into(),
        ));
    }
    if runner.server_url_v2.is_empty() {
        return Err(ImportError::UnsupportedRegistration(
            "V2 broker endpoint is not supported".into(),
        ));
    }
    if runner.is_hosted_server == Some(false) {
        return Err(ImportError::UnsupportedRegistration(
            "non-hosted servers are not supported".into(),
        ));
    }
    Ok(())
}

fn runner_identity(
    git_hub_url: &str,
    pool_id: u64,
    agent_id: u64,
) -> Result<RunnerIdentity, ImportError> {
    let url = Url::parse(git_hub_url).map_err(|_| {
        ImportError::UnsupportedRegistration("repository scope is not supported".into())
    })?;
    let host_is_github = url
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("github.com"));
    let path_segments: Vec<_> = url
        .path()
        .strip_prefix('/')
        .unwrap_or_default()
        .split('/')
        .collect();

    if url.scheme() != "https"
        || !host_is_github
        || has_userinfo(&url)
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || path_segments.len() != 2
        || path_segments.iter().any(|segment| segment.is_empty())
    {
        return Err(ImportError::UnsupportedRegistration(
            "repository scope is not supported".into(),
        ));
    }

    Ok(RunnerIdentity {
        scope: format!(
            "github.com/{}/{}",
            path_segments[0].to_ascii_lowercase(),
            path_segments[1].to_ascii_lowercase()
        ),
        pool_id,
        agent_id,
    })
}

fn validate_oauth(
    credentials: &OfficialCredentialData,
    source: &Path,
) -> Result<OAuthCredentials, ImportError> {
    if credentials.scheme != "OAuth" {
        return Err(ImportError::UnsupportedRegistration(
            "credential scheme is not supported".into(),
        ));
    }
    if credentials
        .data
        .keys()
        .any(|key| !RECOGNIZED_AUTH_KEYS.contains(&key.as_str()))
    {
        return Err(ImportError::UnsupportedRegistration(
            "credential metadata is not supported".into(),
        ));
    }

    let [client_id, authorization_url] = REQUIRED_AUTH_KEYS.map(|key| {
        credentials.data.get(key).ok_or_else(|| {
            ImportError::InvalidSource("required credential metadata is missing".into())
        })
    });
    let client_id = client_id?;
    let authorization_url = authorization_url?;

    if client_id.is_empty() || Uuid::parse_str(client_id).is_err() {
        return Err(ImportError::InvalidSource(
            "clientId must be a non-empty UUID".into(),
        ));
    }

    if let Some(fips) = credentials.data.get("requireFipsCryptography")
        && parse_bool(fips, "requireFipsCryptography")?
    {
        return Err(ImportError::UnsupportedRegistration(
            "FIPS credential mode is not supported".into(),
        ));
    }
    if let Some(migration) = credentials.data.get("enableAuthMigrationByDefault")
        && parse_bool(migration, "enableAuthMigrationByDefault")?
    {
        return Err(ImportError::UnsupportedRegistration(
            "credential auth migration is not supported".into(),
        ));
    }
    if credentials.data.contains_key("authorizationUrlV2") {
        return Err(ImportError::UnsupportedRegistration(
            "credential auth migration is not supported".into(),
        ));
    }
    if migration_marker_exists(source, ".runner_migrated")
        || migration_marker_exists(source, ".credentials_migrated")
    {
        return Err(ImportError::UnsupportedRegistration(
            "credential auth migration is not supported".into(),
        ));
    }

    validate_actions_url(authorization_url, true)?;

    Ok(OAuthCredentials {
        scheme: credentials.scheme.clone(),
        client_id: client_id.clone(),
        authorization_url: authorization_url.clone(),
    })
}

fn parse_bool(value: &str, field: &str) -> Result<bool, ImportError> {
    if value.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    Err(ImportError::InvalidSource(format!(
        "{field} must be a boolean string"
    )))
}

fn migration_marker_exists(source: &Path, name: &str) -> bool {
    std::fs::symlink_metadata(source.join(name)).is_ok()
}

fn validate_actions_url(value: &str, require_non_root_path: bool) -> Result<(), ImportError> {
    let url = Url::parse(value)
        .map_err(|_| ImportError::InvalidSource("credential endpoint is not a URL".into()))?;
    let host_is_actions = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("actions.githubusercontent.com")
            || host
                .to_ascii_lowercase()
                .ends_with(".actions.githubusercontent.com")
    });

    if url.scheme() != "https"
        || !host_is_actions
        || has_userinfo(&url)
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (require_non_root_path && (url.path().is_empty() || url.path() == "/"))
    {
        return Err(ImportError::UnsupportedRegistration(
            "credential endpoint is not supported".into(),
        ));
    }
    Ok(())
}

fn has_userinfo(url: &Url) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return true;
    }

    url.as_str()
        .split_once("://")
        .map(|(_, remainder)| {
            let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
            authority.contains('@')
        })
        .unwrap_or(false)
}

fn validate_and_canonicalize_rsa(rsa: OfficialRsaParameters) -> Result<RsaParameters, ImportError> {
    let source_params = RsaParameters {
        d: rsa.d,
        dp: rsa.dp,
        dq: rsa.dq,
        exponent: rsa.exponent,
        inverse_q: rsa.inverse_q,
        modulus: rsa.modulus,
        p: rsa.p,
        q: rsa.q,
    };
    let key = rsa_params_to_private_key(&source_params)
        .map_err(|_| ImportError::InvalidSource("RSA parameters are invalid".into()))?;
    let canonical_params = private_key_to_rsa_params(&key)
        .map_err(|_| ImportError::InvalidSource("RSA parameters are invalid".into()))?;

    for (source_value, canonical_value) in rsa_components(&source_params)
        .into_iter()
        .zip(rsa_components(&canonical_params))
    {
        let source_bytes = BASE64
            .decode(source_value)
            .map_err(|_| ImportError::InvalidSource("RSA parameters are invalid".into()))?;
        let canonical_bytes = BASE64
            .decode(canonical_value)
            .map_err(|_| ImportError::InvalidSource("RSA parameters are invalid".into()))?;
        if source_bytes != canonical_bytes {
            return Err(ImportError::InvalidSource(
                "RSA parameters are not canonical".into(),
            ));
        }
    }

    Ok(canonical_params)
}

fn rsa_components(params: &RsaParameters) -> [&str; 8] {
    [
        &params.d,
        &params.dp,
        &params.dq,
        &params.exponent,
        &params.inverse_q,
        &params.modulus,
        &params.p,
        &params.q,
    ]
}

#[cfg(test)]
#[path = "source_test.rs"]
mod source_test;
