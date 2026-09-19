use std::sync::Arc;

use anyhow::Context;
use base64::Engine;
use regex::Regex;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub enum SecretMask {
    Value(String),
    Regex(Regex),
}

pub type SharedSecretMasker = Arc<RwLock<Vec<SecretMask>>>;

pub fn empty_masker() -> SharedSecretMasker {
    Arc::new(RwLock::new(Vec::new()))
}

#[cfg(test)]
pub fn masker_from_values(values: impl IntoIterator<Item = String>) -> SharedSecretMasker {
    let mut masks = Vec::new();
    for value in values {
        append_value(&mut masks, &value);
    }
    Arc::new(RwLock::new(masks))
}

pub async fn add_value(masks: &SharedSecretMasker, value: &str) {
    let mut masks = masks.write().await;
    append_value(&mut masks, value);
}

pub fn append_value(masks: &mut Vec<SecretMask>, value: &str) {
    let mut originals = vec![value];
    originals.extend(value.split(['\r', '\n']).map(str::trim));

    let mut candidates = Vec::new();
    for original in &originals {
        candidates.push((*original).to_string());
        candidates.push(json_escape(original));
        candidates.push(newtonsoft_json_escape(original));
    }
    for original in originals {
        candidates.extend(github_runner_encodings(original));
    }

    for candidate in candidates {
        if !candidate.is_empty()
            && !masks
                .iter()
                .any(|mask| matches!(mask, SecretMask::Value(existing) if existing == &candidate))
        {
            masks.push(SecretMask::Value(candidate));
        }
    }
}

pub fn append_regex(masks: &mut Vec<SecretMask>, pattern: &str) -> anyhow::Result<()> {
    if pattern.is_empty() {
        return Ok(());
    }
    if masks
        .iter()
        .any(|mask| matches!(mask, SecretMask::Regex(existing) if existing.as_str() == pattern))
    {
        return Ok(());
    }
    let regex = Regex::new(pattern).context("invalid secret mask regex")?;
    masks.push(SecretMask::Regex(regex));
    Ok(())
}

pub fn contains_secret(masks: &[SecretMask], content: &str) -> bool {
    masks.iter().any(|mask| match mask {
        SecretMask::Value(value) => !value.is_empty() && content.contains(value),
        SecretMask::Regex(regex) => regex.is_match(content),
    })
}

pub fn apply(masks: &[SecretMask], content: &str) -> String {
    let mut ranges = Vec::new();
    for mask in masks {
        match mask {
            SecretMask::Value(value) if !value.is_empty() => {
                ranges.extend(overlapping_value_ranges(value, content));
            }
            SecretMask::Value(_) => {}
            SecretMask::Regex(regex) => {
                ranges.extend(overlapping_regex_ranges(regex, content));
            }
        }
    }
    if ranges.is_empty() {
        return content.to_string();
    }

    ranges.sort_unstable_by_key(|&(start, end)| (start, end));
    let mut merged = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, previous_end)) = merged.last_mut()
            && start <= *previous_end
        {
            *previous_end = (*previous_end).max(end);
        } else {
            merged.push((start, end));
        }
    }

    let mut result = String::with_capacity(content.len());
    let mut cursor = 0;
    for (start, end) in merged {
        result.push_str(&content[cursor..start]);
        result.push_str("***");
        cursor = end;
    }
    result.push_str(&content[cursor..]);
    result
}

fn json_escape(value: &str) -> String {
    // Serializing a Rust string has no fallible JSON values (numbers, maps, or custom serializers).
    let encoded = serde_json::to_string(value).expect("serializing a string to JSON cannot fail");
    let escaped = encoded
        .strip_prefix('"')
        .and_then(|encoded| encoded.strip_suffix('"'))
        .expect("serialized JSON string has surrounding quotes");
    escaped.to_string()
}

fn newtonsoft_json_escape(value: &str) -> String {
    let escaped = json_escape(value);
    let mut newtonsoft_compatible = String::with_capacity(escaped.len());
    for character in escaped.chars() {
        match character {
            '\u{0085}' => newtonsoft_compatible.push_str("\\u0085"),
            '\u{2028}' => newtonsoft_compatible.push_str("\\u2028"),
            '\u{2029}' => newtonsoft_compatible.push_str("\\u2029"),
            _ => newtonsoft_compatible.push(character),
        }
    }
    newtonsoft_compatible
}

fn github_runner_encodings(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let base64 = base64::engine::general_purpose::STANDARD;
    vec![
        base64.encode(bytes),
        base64.encode(if bytes.len() > 1 { &bytes[1..] } else { bytes }),
        base64.encode(if bytes.len() > 2 { &bytes[2..] } else { bytes }),
        value.replace('"', "\\\""),
        value.replace('\'', "''"),
        newtonsoft_json_escape(value),
        uri_data_escape(value),
        xml_data_escape(value),
        trim_double_quotes(value),
        powershell_pre_ampersand_escape(value),
        powershell_post_ampersand_escape(value),
    ]
}

fn uri_data_escape(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn xml_data_escape(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for character in value.chars() {
        encoded.push_str(match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&apos;",
            _ => {
                encoded.push(character);
                continue;
            }
        });
    }
    encoded
}

fn trim_double_quotes(value: &str) -> String {
    if value.encode_utf16().count() > 8 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        String::new()
    }
}

fn powershell_pre_ampersand_escape(value: &str) -> String {
    let end = value
        .find("&+")
        .map(|index| index + 2)
        .or_else(|| value.rfind('&').map(|index| index + 1));
    let Some(end) = end else {
        return String::new();
    };
    let section = &value[..end];
    if section.encode_utf16().count() >= 6 {
        section.to_string()
    } else {
        String::new()
    }
}

fn powershell_post_ampersand_escape(value: &str) -> String {
    let section = if let Some(index) = value.find("&+") {
        let tail = &value[index + 2..];
        let Some((skip, character)) = tail.char_indices().next() else {
            return String::new();
        };
        &tail[skip + character.len_utf8()..]
    } else if let Some(index) = value.rfind('&') {
        &value[index + 1..]
    } else {
        return String::new();
    };
    if section.encode_utf16().count() >= 6 {
        section.to_string()
    } else {
        String::new()
    }
}

fn overlapping_regex_ranges(regex: &Regex, content: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < content.len() {
        let Some(matched) = regex.find_at(content, start) else {
            break;
        };
        ranges.push((matched.start(), matched.end()));
        let Some(character) = content[matched.start()..].chars().next() else {
            break;
        };
        start = matched.start() + character.len_utf8();
    }
    ranges
}

fn overlapping_value_ranges(value: &str, content: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < content.len() {
        let Some(relative_start) = content[start..].find(value) else {
            break;
        };
        let match_start = start + relative_start;
        ranges.push((match_start, match_start + value.len()));
        let Some(character) = content[match_start..].chars().next() else {
            break;
        };
        start = match_start + character.len_utf8();
    }
    ranges
}

#[cfg(test)]
#[path = "masking_test.rs"]
mod masking_test;
