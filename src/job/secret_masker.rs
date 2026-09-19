use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use base64::Engine;
use regex::Regex;
use tokio::sync::RwLock;

use super::schema::JobManifest;

#[derive(Debug, Default)]
pub(crate) struct SecretMasker {
    originals: HashSet<String>,
    values: HashSet<String>,
    regexes: Vec<Regex>,
}

pub(crate) type SharedSecretMasker = Arc<RwLock<SecretMasker>>;

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
                return Err(anyhow!("unsupported mask hint at index {index}"));
            }
            let pattern = pattern.ok_or_else(|| anyhow!("invalid mask hint at index {index}"))?;
            let regex =
                Regex::new(pattern).map_err(|_| anyhow!("invalid mask hint at index {index}"))?;
            masker.regexes.push(regex);
            masker.add_value(pattern);
        }

        Ok(masker)
    }

    pub(crate) fn add_value(&mut self, value: &str) {
        if value.is_empty() {
            return;
        }

        let mut candidates = HashSet::from([value.to_string()]);
        candidates.insert(value.trim().to_string());
        candidates.extend(
            value
                .split(['\r', '\n'])
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string),
        );

        for candidate in candidates
            .into_iter()
            .filter(|candidate| !candidate.is_empty())
        {
            if !self.originals.insert(candidate.clone()) {
                continue;
            }

            let encoded = [
                candidate.clone(),
                json_escape(&candidate),
                uri_data_escape(&candidate),
                xml_escape(&candidate),
                command_line_escape(&candidate),
                expression_escape(&candidate),
                base64_escape(&candidate, 0),
                base64_escape(&candidate, 1),
                base64_escape(&candidate, 2),
                trim_double_quotes(&candidate),
                powershell_pre_ampersand(&candidate),
                powershell_post_ampersand(&candidate),
            ];
            self.values
                .extend(encoded.into_iter().filter(|encoded| !encoded.is_empty()));
        }
    }

    pub(crate) fn mask(&self, input: &str) -> String {
        let mut ranges = Vec::new();
        for value in &self.values {
            ranges.extend(
                input
                    .match_indices(value)
                    .map(|(start, matched)| (start, start + matched.len())),
            );
        }
        for regex in &self.regexes {
            ranges.extend(
                regex
                    .find_iter(input)
                    .map(|found| (found.start(), found.end())),
            );
        }

        if ranges.is_empty() {
            return input.to_string();
        }

        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            if let Some((_, current_end)) = merged.last_mut()
                && start <= *current_end
            {
                *current_end = (*current_end).max(end);
            } else {
                merged.push((start, end));
            }
        }

        let mut output = String::with_capacity(input.len());
        let mut cursor = 0;
        for (start, end) in merged {
            output.push_str(&input[cursor..start]);
            output.push_str("***");
            cursor = end;
        }
        output.push_str(&input[cursor..]);
        output
    }
}

fn json_escape(value: &str) -> String {
    let quoted = serde_json::to_string(value).expect("serializing a string cannot fail");
    quoted[1..quoted.len() - 1].to_string()
}

fn uri_data_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            escaped.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut escaped, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    escaped
}

fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\'' => escaped.push_str("&apos;"),
            '"' => escaped.push_str("&quot;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn command_line_escape(value: &str) -> String {
    value.replace('"', "\\\"")
}

fn expression_escape(value: &str) -> String {
    value.replace('\'', "''")
}

fn base64_escape(value: &str, shift: usize) -> String {
    let bytes = value.as_bytes();
    if bytes.len() <= shift {
        return String::new();
    }
    base64::engine::general_purpose::STANDARD.encode(&bytes[shift..])
}

fn trim_double_quotes(value: &str) -> String {
    if value.len() > 8 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn powershell_pre_ampersand(value: &str) -> String {
    let prefix = value.split_once('&').map_or(value, |(prefix, _)| prefix);
    if prefix.len() >= 6 {
        prefix.to_string()
    } else {
        value.to_string()
    }
}

fn powershell_post_ampersand(value: &str) -> String {
    let suffix = value.rsplit_once('&').map_or(value, |(_, suffix)| suffix);
    if suffix.len() >= 6 {
        suffix.to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
#[path = "secret_masker_test.rs"]
mod secret_masker_test;
