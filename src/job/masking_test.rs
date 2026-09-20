use super::*;

fn literal_masks(masks: &[SecretMask]) -> Vec<&str> {
    masks
        .iter()
        .filter_map(|mask| match mask {
            SecretMask::Value(value) => Some(value.as_str()),
            SecretMask::Regex(_) => None,
        })
        .collect()
}

#[test]
fn append_value_registers_raw_escaped_and_trimmed_multiline_forms_once() {
    let mut masks = Vec::new();

    append_value(&mut masks, " first \"quoted\" line \n second line ");
    append_value(&mut masks, " first \"quoted\" line \n second line ");

    let values = literal_masks(&masks);
    assert_eq!(
        &values[..5],
        vec![
            " first \"quoted\" line \n second line ",
            " first \\\"quoted\\\" line \\n second line ",
            "first \"quoted\" line",
            "first \\\"quoted\\\" line",
            "second line",
        ]
    );
    assert_eq!(
        values.len(),
        values
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
}

#[test]
fn append_value_ignores_empty_values() {
    let mut masks = Vec::new();

    append_value(&mut masks, "");

    assert!(masks.is_empty());
}

#[test]
fn append_regex_reports_invalid_pattern_with_context() {
    let mut masks = Vec::new();

    let error = append_regex(&mut masks, "[").unwrap_err();

    assert!(error.to_string().contains("invalid secret mask regex"));
    assert!(masks.is_empty());
}

#[test]
fn append_regex_ignores_empty_patterns() {
    let mut masks = Vec::new();

    append_regex(&mut masks, "").unwrap();

    assert!(masks.is_empty());
    assert_eq!(apply(&masks, "public-output"), "public-output");
    assert!(!contains_secret(&masks, "public-output"));
}

#[test]
fn apply_merges_overlapping_unicode_value_and_regex_ranges() {
    let mut masks = Vec::new();
    append_value(&mut masks, "секрет");
    append_regex(&mut masks, r"секрет-[0-9]+").unwrap();

    let masked = apply(&masks, "ключ: секрет-12345 готов");

    assert_eq!(masked, "ключ: *** готов");
}

#[test]
fn apply_masks_overlapping_matches_from_the_same_regex() {
    let mut masks = Vec::new();
    append_regex(&mut masks, r"token-[a-z]+-token").unwrap();

    let masked = apply(&masks, "token-abc-token-def-token");

    assert_eq!(masked, "***");
}

#[test]
fn apply_masks_overlapping_matches_from_the_same_literal() {
    let mut masks = Vec::new();
    append_value(&mut masks, "abcabc");

    let masked = apply(&masks, "abcabcabc");

    assert_eq!(masked, "***");
}

#[test]
fn append_value_registers_newtonsoft_unicode_json_escapes() {
    let mut masks = Vec::new();
    append_value(&mut masks, "next\u{0085}line\u{2028}paragraph\u{2029}end");

    let masked = apply(&masks, r"next\u0085line\u2028paragraph\u2029end");

    assert_eq!(masked, "***");
}

#[test]
fn append_value_masks_local_tojson_unicode_form() {
    let secret = "prefix\\sep\u{2028}suffix";
    let mut masks = Vec::new();
    append_value(&mut masks, secret);
    let serialized = serde_json::to_string(secret).unwrap();
    let escaped = serialized
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap();

    assert_eq!(apply(&masks, escaped), "***");
}

#[test]
fn append_value_registers_github_runner_encoded_forms() {
    use base64::Engine;

    let secret = "synthetic secret<&'\"";
    let mut masks = Vec::new();

    append_value(&mut masks, secret);

    let values = literal_masks(&masks);
    let base64 = base64::engine::general_purpose::STANDARD.encode(secret);
    assert!(values.contains(&base64.as_str()));
    assert!(values.contains(&"synthetic%20secret%3C%26%27%22"));
    assert!(values.contains(&"synthetic secret&lt;&amp;&apos;&quot;"));
    assert!(values.contains(&"synthetic secret<&''\""));
}

#[test]
fn contains_secret_checks_literal_and_regex_masks_against_original_value() {
    let mut masks = Vec::new();
    append_value(&mut masks, "literal");
    append_regex(&mut masks, r"credential-[0-9]+").unwrap();

    assert!(contains_secret(&masks, "prefix-literal-suffix"));
    assert!(contains_secret(&masks, "credential-12345"));
    assert!(!contains_secret(&masks, "public-value"));
}
