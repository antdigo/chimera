use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer};

/// Deserialize a bool that might be null in JSON (treat null as false).
pub fn deserialize_nullable_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<bool>::deserialize(deserializer).map(|opt| opt.unwrap_or(false))
}

/// RFC3339 with 7 decimal places (100ns precision), used for timeline records.
pub fn format_timeline_timestamp(ts: DateTime<Utc>) -> String {
    let frac = ts.timestamp_subsec_nanos() / 100;
    format!("{}.{:07}Z", ts.format("%Y-%m-%dT%H:%M:%S"), frac)
}

/// RFC3339 with 7 decimal places, used for log lines.
pub fn format_log_timestamp(ts: DateTime<Utc>) -> String {
    format_timeline_timestamp(ts)
}

/// RFC3339 with 3 decimal places (millisecond precision), used for Results API.
pub fn format_results_timestamp(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// GitHub Actions OS label for the current platform.
pub fn os_label() -> &'static str {
    match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "macOS",
        "windows" => "Windows",
        other => other,
    }
}

/// GitHub Actions architecture label for the current platform.
pub fn arch_label() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "X64",
        "aarch64" => "ARM64",
        "arm" => "ARM",
        other => other,
    }
}

/// Case-insensitive map lookup. Context dictionaries in the official runner
/// use `StringComparer.OrdinalIgnoreCase` (`env` on Linux is the one
/// case-sensitive exception), so context property lookups must ignore case.
/// Comparison is ASCII-only: context and secret identifiers are ASCII.
pub fn find_case_insensitive<'a, V>(
    map: &'a std::collections::HashMap<String, V>,
    key: &str,
) -> Option<&'a V> {
    map.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v)
}

/// Insert a value, replacing any existing key that differs only by ASCII case
/// while preserving the stored key's casing. This mirrors the write semantics
/// of the official runner's OrdinalIgnoreCase context dictionaries: the last
/// write wins and no two keys differing only by case ever coexist.
pub fn insert_case_insensitive(
    map: &mut std::collections::HashMap<String, String>,
    key: String,
    value: String,
) {
    let stored_key = map
        .keys()
        .find(|k| k.eq_ignore_ascii_case(&key))
        .cloned()
        .unwrap_or(key);
    map.insert(stored_key, value);
}

/// Merge `from` into `map` with `insert_case_insensitive` semantics.
pub fn merge_case_insensitive(
    map: &mut std::collections::HashMap<String, String>,
    from: std::collections::HashMap<String, String>,
) {
    for (key, value) in from {
        insert_case_insensitive(map, key, value);
    }
}

#[cfg(test)]
#[path = "utils_test.rs"]
mod utils_test;
