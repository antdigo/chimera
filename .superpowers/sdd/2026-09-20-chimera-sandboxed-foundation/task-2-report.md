# Task 2 report: execution profile configuration

## Outcome

Added the serialized execution configuration contract without activating any
sandboxed behavior:

- `ExecutionProfile` supports exactly `trusted-host` and `sandboxed`.
- `trusted-host` remains the default profile.
- `ExecutionConfig::max_active_domains` is a `NonZeroUsize` and defaults to 1.
- `ChimeraConfig` now contains a defaulted `[execution]` section.
- The execution types are re-exported from `config`.

## TDD evidence

Added tests for defaults, sandboxed capacity parsing, unknown profile rejection,
zero-capacity rejection, config round-trip persistence, and generated default
file contents. Before implementation, the requested focused test run failed to
compile because `ExecutionConfig`, `ExecutionProfile`, and the `execution`
field did not exist.

## Verification

- `cargo test config::execution::execution_test -- --nocapture`: passed (4 tests).
- `cargo test config::config_test:: -- --nocapture`: passed (15 tests).
- `cargo fmt -- --check`: passed.
- `git diff --check`: passed.
- `cargo test`: 820 passed, 15 ignored, 103 failed due to the sandbox's
  permission restrictions (OS port binding and special-file operations). The
  failures are outside this configuration change; execution and config tests
  passed in that run.

## Files changed

- `src/config/execution.rs`
- `src/config/execution_test.rs`
- `src/config.rs`
- `src/config_test.rs`
