use std::collections::HashMap;

use serde_json::json;

use super::*;

#[test]
fn builds_self_hosted_runner_context_without_exported_label_env() {
    let environment = HashMap::from([
        ("RUNNER_OS".to_string(), "Linux".to_string()),
        ("RUNNER_ARCH".to_string(), "X64".to_string()),
        ("RUNNER_NAME".to_string(), "chimera-1".to_string()),
        ("RUNNER_TEMP".to_string(), "/tmp/chimera-1".to_string()),
        (
            "RUNNER_TOOL_CACHE".to_string(),
            "/opt/chimera/tool-cache".to_string(),
        ),
        ("UNRELATED".to_string(), "not-runner-context".to_string()),
    ]);

    let runner = build_runner_context(&environment);

    assert_eq!(runner["labels"], json!(["self-hosted"]));
    assert_eq!(runner["environment"], "self-hosted");
    assert_eq!(runner["os"], "Linux");
    assert_eq!(runner["arch"], "X64");
    assert_eq!(runner["name"], "chimera-1");
    assert_eq!(runner["temp"], "/tmp/chimera-1");
    assert_eq!(runner["tool_cache"], "/opt/chimera/tool-cache");
    assert!(runner.get("unrelated").is_none());
    assert!(!environment.contains_key("RUNNER_LABELS"));
    assert!(!environment.contains_key("RUNNER_ENVIRONMENT"));
}

#[test]
fn canonical_suffixes_win_over_non_canonical_lookalikes() {
    let environment = HashMap::from([
        ("RUNNER_OS".to_string(), "Linux".to_string()),
        ("RUNNER_os".to_string(), "other".to_string()),
        ("RUNNER_custom".to_string(), "value".to_string()),
    ]);

    let runner = build_runner_context(&environment);

    assert_eq!(runner["os"], "Linux");
    assert!(runner.get("custom").is_none());
}

#[test]
fn a_non_canonical_suffix_never_creates_a_property() {
    let environment = HashMap::from([("RUNNER_os".to_string(), "other".to_string())]);

    let runner = build_runner_context(&environment);

    assert!(runner.get("os").is_none());
}

#[test]
fn runner_owned_properties_override_environment_values() {
    let environment = HashMap::from([
        ("RUNNER_LABELS".to_string(), "host,sandbox-prod".to_string()),
        (
            "RUNNER_ENVIRONMENT".to_string(),
            "github-hosted".to_string(),
        ),
    ]);

    let runner = build_runner_context(&environment);

    assert_eq!(runner["labels"], json!(["self-hosted"]));
    assert_eq!(runner["environment"], "self-hosted");
}
