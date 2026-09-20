use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::sync::RwLock;
use tracing::warn;

use super::masking::{SecretMask, append_regex, append_value, apply, contains_secret};
use super::schema::JobManifest;

/// Job-scoped facade around the masking engine.
///
/// This owns manifest validation and source collection, while `job::masking`
/// provides the official-runner-compatible encoders and range matching.
#[derive(Debug, Default)]
pub(crate) struct SecretMasker {
    masks: Vec<SecretMask>,
}

pub(crate) type SharedSecretMasker = Arc<RwLock<SecretMasker>>;

#[cfg(test)]
pub(crate) fn shared_masker_for_test(values: &[&str]) -> SharedSecretMasker {
    shared_masker_with_regex_for_test(values, &[])
}

#[cfg(test)]
pub(crate) fn shared_masker_with_regex_for_test(
    values: &[&str],
    patterns: &[&str],
) -> SharedSecretMasker {
    let mut masker = SecretMasker::default();
    for value in values {
        masker.add_value(value);
    }
    for pattern in patterns {
        append_regex(&mut masker.masks, pattern).expect("test regex must be valid");
    }
    Arc::new(RwLock::new(masker))
}

impl SecretMasker {
    pub(crate) fn from_manifest(manifest: &JobManifest) -> Result<Self> {
        let mut masker = Self::default();

        for variable in manifest.variables.values().filter(|value| value.is_secret) {
            masker.add_value(&variable.value);
        }

        if let Some(secrets) = manifest
            .context_data
            .get("secrets")
            .and_then(serde_json::Value::as_object)
        {
            for secret in secrets.values().filter_map(serde_json::Value::as_str) {
                masker.add_value(secret);
            }
        }

        for endpoint in &manifest.resources.endpoints {
            if let Some(authorization) = &endpoint.authorization {
                for parameter in authorization.parameters.values() {
                    masker.add_value(parameter);
                }
            }
        }

        if let Some(token) = manifest.github_token() {
            masker.add_value(token);
        }

        for (index, hint) in manifest.mask_regexes().iter().enumerate() {
            let kind = hint.get("type").and_then(serde_json::Value::as_str);
            let pattern = hint.get("value").and_then(serde_json::Value::as_str);
            if kind != Some("regex") {
                warn!(index, "unsupported mask hint ignored");
                continue;
            }
            let pattern = pattern.ok_or_else(|| anyhow!("invalid mask hint at index {index}"))?;
            append_regex(&mut masker.masks, pattern)
                .map_err(|_| anyhow!("invalid mask hint at index {index}"))?;
            masker.add_value(pattern);
        }

        Ok(masker)
    }

    pub(crate) fn add_value(&mut self, value: &str) {
        append_value(&mut self.masks, value);
    }

    pub(crate) fn contains_secret(&self, input: &str) -> bool {
        contains_secret(&self.masks, input)
    }

    pub(crate) fn mask(&self, input: &str) -> String {
        apply(&self.masks, input)
    }
}

#[cfg(test)]
#[path = "secret_masker_test.rs"]
mod secret_masker_test;
