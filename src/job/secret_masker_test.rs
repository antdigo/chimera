use super::SecretMasker;
use crate::job::schema::JobManifest;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

impl CapturedWriter {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

#[test]
fn masks_multiline_value_and_each_nonempty_trimmed_line() {
    let mut masker = SecretMasker::default();
    masker.add_value("  alpha-line\r\n\r\nbeta-\"slash\\line  ");

    assert_eq!(
        masker.mask("raw=  alpha-line\r\n\r\nbeta-\"slash\\line  "),
        "raw=***"
    );
    assert_eq!(masker.mask("one=alpha-line"), "one=***");
    assert_eq!(masker.mask("two=beta-\"slash\\line"), "two=***");
    assert_eq!(
        masker.mask(r#"json=alpha-line\r\n\r\nbeta-\"slash\\line"#),
        "json=***"
    );
}

#[test]
fn masks_supported_encoded_forms_with_literal_expectations() {
    let mut masker = SecretMasker::default();
    masker.add_value("ab'cd\"ef&gh");

    for encoded in [
        "YWInY2QiZWYmZ2g=",
        "YidjZCJlZiZnaA==",
        "J2NkImVmJmdo",
        "ab%27cd%22ef%26gh",
        "ab&apos;cd&quot;ef&amp;gh",
        "ab''cd\"ef&gh",
        "ab'cd\\\"ef&gh",
    ] {
        assert_eq!(masker.mask(&format!("value={encoded}")), "value=***");
    }
}

#[test]
fn masks_manifest_values_context_secrets_endpoint_auth_and_system_token() {
    let manifest = manifest(serde_json::json!({
        "variables": {
            "SECRET_VARIABLE": { "value": "variable-canary", "isSecret": true },
            "VISIBLE_VARIABLE": { "value": "visible-value", "isSecret": false },
            "system.github.token": { "value": "system-token-canary", "isSecret": false }
        },
        "resources": {
            "endpoints": [{
                "name": "SystemVssConnection",
                "url": "https://example.invalid",
                "authorization": {
                    "scheme": "OAuth",
                    "parameters": {
                        "AccessToken": "endpoint-token-canary",
                        "Secondary": "endpoint-secondary-canary"
                    }
                }
            }]
        },
        "contextData": {
            "secrets": { "CONTEXT_SECRET": "context-canary" }
        }
    }));

    let masker = SecretMasker::from_manifest(&manifest).unwrap();
    let output = masker.mask(
        "variable-canary context-canary endpoint-token-canary endpoint-secondary-canary system-token-canary visible-value",
    );

    assert_eq!(output, "*** *** *** *** *** visible-value");
}

#[test]
fn masks_regex_hint_and_literal_pattern() {
    let manifest = manifest(serde_json::json!({
        "mask": [{ "type": "regex", "value": "secret-[0-9]+" }]
    }));

    let masker = SecretMasker::from_manifest(&manifest).unwrap();

    assert_eq!(
        masker.mask("match=secret-123 pattern=secret-[0-9]+"),
        "match=*** pattern=***"
    );
}

#[test]
fn rejects_invalid_regex_without_echoing_type_or_pattern() {
    let manifest = manifest(serde_json::json!({
        "mask": [{ "type": "regex", "value": "[CANARY" }]
    }));

    let error = SecretMasker::from_manifest(&manifest)
        .unwrap_err()
        .to_string();

    assert!(error.contains("mask hint at index 0"));
    assert!(!error.contains("CANARY"));
    assert!(!error.contains("regex"));
}

#[test]
fn unsupported_hint_is_ignored_with_safe_index_only_warning() {
    let manifest = manifest(serde_json::json!({
        "mask": [{ "type": "CANARY_TYPE", "value": "CANARY_PATTERN" }]
    }));
    let captured = CapturedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .without_time()
        .with_writer(captured.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);

    let masker = SecretMasker::from_manifest(&manifest).unwrap();
    let warning = captured.text();

    assert_eq!(masker.mask("safe"), "safe");
    assert!(warning.contains("index=0"), "{warning}");
    assert!(!warning.contains("CANARY_TYPE"), "{warning}");
    assert!(!warning.contains("CANARY_PATTERN"), "{warning}");
}

#[test]
fn merges_overlapping_and_adjacent_ranges_once() {
    let mut masker = SecretMasker::default();
    masker.add_value("abc");
    masker.add_value("bcde");
    masker.add_value("f");

    assert_eq!(masker.mask("abcdef"), "***");
}

#[test]
fn merges_self_overlapping_literal_matches() {
    let mut masker = SecretMasker::default();
    masker.add_value("abab");

    assert_eq!(masker.mask("value=ababab"), "value=***");
}

#[test]
fn zero_width_regex_terminates_and_preserves_remaining_text() {
    let manifest = manifest(serde_json::json!({
        "mask": [{ "type": "regex", "value": "^" }]
    }));
    let masker = SecretMasker::from_manifest(&manifest).unwrap();

    assert_eq!(masker.mask("abc"), "***abc");
}

#[test]
fn duplicate_values_do_not_change_output() {
    let mut once = SecretMasker::default();
    once.add_value("duplicate-canary");
    let mut twice = SecretMasker::default();
    twice.add_value("duplicate-canary");
    twice.add_value("duplicate-canary");

    assert_eq!(
        once.mask("duplicate-canary"),
        twice.mask("duplicate-canary")
    );
}

#[test]
fn trim_double_quotes_requires_more_than_eight_characters() {
    let mut long = SecretMasker::default();
    long.add_value("\"1234567\"");
    assert_eq!(long.mask("value=1234567"), "value=***");

    let mut short = SecretMasker::default();
    short.add_value("\"123456\"");
    assert_eq!(short.mask("value=123456"), "value=123456");
}

#[test]
fn powershell_ampersand_fragments_match_official_runner_boundaries() {
    let mut masker = SecretMasker::default();
    masker.add_value("alpha&bravo&charlie");
    masker.add_value("before&+xafter-fragment");

    assert_eq!(masker.mask("prefix=alpha&bravo&"), "prefix=***");
    assert_eq!(masker.mask("suffix=charlie"), "suffix=***");
    assert_eq!(masker.mask("special-prefix=before&+"), "special-prefix=***");
    assert_eq!(
        masker.mask("special-suffix=after-fragment"),
        "special-suffix=***"
    );
}

fn manifest(overrides: serde_json::Value) -> JobManifest {
    let mut value = serde_json::json!({
        "variables": {},
        "resources": { "endpoints": [] },
        "contextData": {},
        "jobContainer": null,
        "serviceContainers": null,
        "mask": []
    });
    let object = value.as_object_mut().unwrap();
    for (key, value) in overrides.as_object().unwrap() {
        object.insert(key.clone(), value.clone());
    }
    serde_json::from_value(value).unwrap()
}
