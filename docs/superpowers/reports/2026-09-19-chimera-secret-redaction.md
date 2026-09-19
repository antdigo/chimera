# DPL-07 — отчёт о проверке сквозной защиты секретов

Дата проверки: 2026-09-19. Целевой issue: [#41](https://github.com/antdigo/chimera/issues/41).

## Проверенный диапазон

- baseline: `be6adc97e5429689365d79c91cc9953b085892ef`;
- проверенный implementation commit: `dacbf07`;
- baseline `cargo test`: PASS — 788 unit tests, 15 ignored; integration и doc tests также завершились без ошибок;
- итоговый `cargo test`: exit 0 — 825 unit tests passed, 15 ignored; по всем cargo test binaries суммарно 992 passed, 44 ignored, 0 failed;
- `cargo fmt --check`: PASS;
- `cargo clippy --all-targets --all-features -- -D warnings`: PASS;
- `cargo build --all-features`: PASS.

Проверка использовала только synthetic canaries. Production secrets и действующие
credentials не использовались.

## Матрица R-01…R-16

| ID | Проверка и test | Команда | Результат |
|---|---|---|---|
| R-01 | plain secret в stdout/stderr — `synthetic_canaries_are_absent_from_uploaded_logs` | `cargo test --test secrets_test synthetic_canaries_are_absent_from_uploaded_logs -- --nocapture` | PASS |
| R-02 | CR/LF multiline — `masks_multiline_value_and_each_nonempty_trimmed_line`, black-box canary test | `cargo test`; отдельный black-box command R-01 | PASS |
| R-03 | raw и JSON-escaped quotes/backslash/newline — `legacy_vss_masks_multiline_and_json_encoded_canaries`, black-box canary test | `cargo test job::logs::logs_test -- --nocapture`; command R-01 | PASS |
| R-04 | URI/XML/Base64/expression/command-line/PowerShell variants — `masks_supported_encoded_forms_with_literal_expectations`, `powershell_ampersand_fragments_match_official_runner_boundaries` | `cargo test` | PASS |
| R-05 | manifest regex hint — `masks_regex_hint_and_literal_pattern` | `cargo test` | PASS |
| R-06 | invalid/unsupported hint без echo payload — `rejects_invalid_regex_without_echoing_type_or_pattern`, `unsupported_hint_is_ignored_with_safe_index_only_warning` | `cargo test` | PASS |
| R-07 | overlapping/adjacent/self-overlapping literal и regex ranges — `merges_overlapping_and_adjacent_ranges_once`, `merges_self_overlapping_literal_matches`, `merges_self_overlapping_regex_matches`, `zero_width_regex_terminates_and_preserves_remaining_text` | `cargo test` | PASS |
| R-08 | runtime `add-mask`, включая encoded variants и clones — `add_mask_registers_encoded_variants_for_all_sender_clones`, `split_add_mask_command_is_processed_only_after_complete_line` | `cargo test docker::output::output_test -- --nocapture` | PASS |
| R-09 | line/secret split во всех byte offsets — `line_framer_reassembles_secret_at_every_byte_split`, `build_progress_reassembles_split_stream_before_masking` | `cargo test docker::output::output_test -- --nocapture`; `cargo test` | PASS |
| R-10 | split CRLF/UTF-8 и invalid UTF-8 at EOF — `line_framer_handles_empty_lf_split_crlf_and_repeated_finish`, `line_framer_decodes_invalid_utf8_lossily_at_eof_once` | `cargo test docker::output::output_test -- --nocapture` | PASS |
| R-11 | независимые stdout/stderr partial lines — `docker_log_framer_keeps_stdout_and_stderr_partial_lines_separate` | `cargo test docker::output::output_test -- --nocapture` | PASS |
| R-12 | фактические Results step/job blobs, legacy VSS и WebSocket live feed — `results_step_and_job_blobs_receive_identical_masked_content`, `legacy_vss_masks_multiline_and_json_encoded_canaries`, `log_sender_masks_before_websocket_feed_fan_out` | `cargo test job::logs::logs_test -- --nocapture`; `cargo test job::live_feed::live_feed_test -- --nocapture` | PASS |
| R-13 | setup/action failure сохраняют safe message — `setup_failure_blob_masks_nested_error_chain`, `masked_error_chain_hides_nested_source`, `failing_node_action_masks_secret_in_collected_log` | `cargo test` | PASS |
| R-14 | debug + malformed/semantic/HTTP manifest failures без body canary — `acquire_job_semantic_error_omits_raw_and_normalized_canary`, `acquire_job_syntax_error_reports_category_and_position_without_body`, `acquire_job_http_error_reports_status_and_length_without_response_body`, `acquired_job_trace_contains_only_safe_structural_fields` | `cargo test` | PASS |
| R-15 | Docker health/tail/error/options daemon diagnostics — `health_diagnostic_omits_probe_output`, `container_tail_summary_discards_payload_bytes`, `docker_error_diagnostic_discards_daemon_payload`, `unknown_options_warning_omits_manifest_tokens`, Docker trace canary tests | `cargo test` | PASS |
| R-16 | два concurrent jobs с независимыми secret sets — `concurrent_jobs_keep_secret_sets_isolated` | `cargo test runner::instance::instance_test -- --nocapture` | PASS |

## Проверка sink boundaries

- Results step blob и job blob получили один и тот же уже замаскированный content;
- legacy VSS request body не содержит multiline, raw или JSON-escaped canaries;
- WebSocket server получил `safe=***`, а не исходное значение;
- black-box job upload не содержит synthetic canaries из stdout, stderr, workflow
  warning/error commands и failing step; безопасная строка `safe-before-failure`
  сохранена;
- synthetic setup-failure append blob содержит safe stage и `***`, но не содержит
  raw либо JSON-escaped source secret;
- daemon traces до создания masker содержат только status/length,
  serde category/position и structural counts; raw/normalized manifest отсутствуют;
- Docker health/tail diagnostics сохраняют container identifier, exit code и
  record/chunk/byte counts, но отбрасывают payload bytes;
- Docker action traces сохраняют только image source, наличие entrypoint и число
  аргументов; image reference, entrypoint/args и daemon error payload отсутствуют;
- предупреждения о неизвестных Docker options сохраняют только индекс token и не
  выводят manifest option/value.

## Отдельные failure/framing сценарии

- Malformed manifest: возвращаются `serde_json` category, line и column; response
  body и canary не попадают ни в error, ни в debug trace.
- Setup failure: весь готовый `anyhow` error block маскируется один раз до
  вычисления line count и отправки append blob.
- Action failure: stdout/stderr и итоговый collected log проходят через тот же
  job-scoped masker; safe failure line остаётся видимой.
- Docker frame splits: `LineFramer` проверен для каждого split offset; CRLF и
  многобайтовый UTF-8 восстанавливаются после byte framing, stdout/stderr имеют
  отдельное состояние. Docker build stream также проверен split-canary тестом.

## Docker E2E environment

`docker info` выполнен успешно для Docker Desktop 29.7.2 (`linux/arm64`). В
`Security Options` присутствуют `seccomp` и `cgroupns`, но отсутствует `rootless`.
По условию плана следующие ignored tests не запускались и не заменялись
privileged-прогоном:

- `cargo test docker::exec::exec_test -- --ignored --nocapture` — **NOT RUN**:
  доступный daemon не rootless;
- `cargo test job::action::docker::docker_test -- --ignored --nocapture` —
  **NOT RUN**: доступный daemon не rootless.

Детерминированные framing/redaction tests не требуют Docker daemon и прошли.

## Граница гарантии

Masker покрывает известные значения, manifest regex hints, runtime `add-mask` и
поддержанные official-runner-compatible encoded representations. Произвольные
HMAC, hash, ciphertext и пользовательские необратимые преобразования не могут
быть автоматически выведены из исходного secret и этой гарантией не покрываются.

Production rollout, online GitHub/rootless Docker/registry/Deploy API E2E и серия
из 20 параллельных production-like runs в рамках этой проверки не выполнялись.
