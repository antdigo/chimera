use std::collections::HashMap;

use serde_json::{Map, Value, json};

const SELF_HOSTED: &str = "self-hosted";
const RUNNER_PREFIX: &str = "RUNNER_";

pub(super) fn build_runner_context(environment: &HashMap<String, String>) -> Value {
    let mut runner = Map::new();

    for (name, value) in environment {
        let Some(suffix) = name.strip_prefix(RUNNER_PREFIX) else {
            continue;
        };
        // Property lookup only ever asks for RUNNER_{property.to_uppercase()}, so
        // a suffix that isn't already uppercase (e.g. RUNNER_os) would either
        // collide with its canonical key or invent a property nobody resolves.
        if !is_canonical_suffix(suffix) {
            continue;
        }
        runner.insert(suffix.to_ascii_lowercase(), Value::String(value.clone()));
    }

    runner.insert("labels".to_string(), json!([SELF_HOSTED]));
    runner.insert("environment".to_string(), json!(SELF_HOSTED));

    Value::Object(runner)
}

fn is_canonical_suffix(suffix: &str) -> bool {
    suffix
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
#[path = "runner_test.rs"]
mod runner_test;
