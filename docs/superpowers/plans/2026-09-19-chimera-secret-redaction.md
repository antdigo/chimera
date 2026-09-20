# DPL-07 Secret Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Исключить известные job secrets из daemon diagnostics и всех GitHub log sinks, включая multiline/encoded формы и Docker output, разрезанный на произвольные frames.

**Architecture:** Новый job-scoped `SecretMasker` инкапсулирует регистрацию values/regex hints, официальные encoders и объединение диапазонов. `LogSender` маскирует данные до fan-out, а stateful Docker framers восстанавливают полные строки до workflow-command parsing и redaction. До построения masker diagnostics остаются структурными и не содержат payload; setup errors используют тот же job masker.

**Tech Stack:** Rust 2024, Tokio, tracing/tracing-subscriber, serde/serde_json, regex, base64, Bollard, Wiremock, tokio-tungstenite.

**Spec:** `docs/superpowers/specs/2026-09-19-chimera-secret-redaction.md`

## Global Constraints

- База реализации — `be6adc97e5429689365d79c91cc9953b085892ef` плюс commits документации `71ec0b6` и `9df19e3`.
- Masker строго job-scoped; secrets разных concurrent jobs не объединяются.
- Redaction происходит до live feed, Results step/job blobs и legacy VSS upload.
- До безопасной десериализации manifest нельзя логировать body, normalized value, URL, image, filenames или response body.
- Multiline secret регистрируется целиком, в trimmed-виде и по непустым trimmed CR/LF-строкам.
- Encoders соответствуют списку из §4.2 спецификации; HMAC/hash/шифротекст автоматически не выводятся.
- Docker stdout и stderr используют независимые byte buffers; incomplete UTF-8 декодируется только после сборки строки.
- Raw container tail и health-check output не попадают в daemon trace.
- Production code пишется только после наблюдаемого RED для соответствующего поведения.
- Не выполнять Docker/GHCR/deploy операции с production credentials; тестовые canaries синтетические.

## Review Focus

- Zero-width regex hint (`^`) должен завершаться детерминированно и не зациклить masking; тест закреплён в Task 1.
- Дубликаты raw/trimmed/encoded values не должны менять результат или порядок замены; тест закреплён в Task 1.
- Docker frame может разрезать CRLF, UTF-8 code point и secret одновременно; тест всех split offsets закреплён в Task 3.
- `add-mask` после клонирования `LogSender` должен немедленно действовать на все sinks; тест закреплён в Task 2.
- Secret может находиться только во вложенном `anyhow` source; setup blob и daemon error chain проверяются в Task 5.

---

### Task 1: Глубокий модуль `SecretMasker`

**Files:**
- Modify: `Cargo.toml:12-41`
- Modify: `Cargo.lock`
- Modify: `src/job.rs:1-12`
- Create: `src/job/secret_masker.rs`
- Create: `src/job/secret_masker_test.rs`

**Interfaces:**
- Consumes: `JobManifest`, `manifest.variables`, `context_data.secrets`, endpoint authorization parameters и `manifest.mask`.
- Produces: `SecretMasker::{from_manifest, add_value, mask}` и `SharedSecretMasker = Arc<RwLock<SecretMasker>>` для Tasks 2 и 5.

- [ ] **Step 1: Написать падающие unit tests для value registration и encoders**

Добавить `pub(crate) mod secret_masker;` в `src/job.rs`, подключить test-файл из нового module и зафиксировать literal expectations:

```rust
#[test]
fn masks_multiline_value_and_each_nonempty_trimmed_line() {
    let mut masker = SecretMasker::default();
    masker.add_value("  alpha-line\r\n\r\nbeta-\"slash\\line  ");

    assert_eq!(masker.mask("raw=  alpha-line\r\n\r\nbeta-\"slash\\line  "), "raw=***");
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
        "YWInY2QiZWYmZ2g=",       // Base64 UTF-8
        "YidjZCJlZiZnaA==",       // shift 1
        "J2NkImVmJmdo",           // shift 2
        "ab%27cd%22ef%26gh",      // URI data escape
        "ab&apos;cd&quot;ef&amp;gh", // XML
        "ab''cd\"ef&gh",         // expression escape
        "ab'cd\\\"ef&gh",       // command-line escape
    ] {
        assert_eq!(masker.mask(&format!("value={encoded}")), "value=***");
    }
}
```

Отдельные tests в том же файле:

```text
masks_manifest_values_context_secrets_endpoint_auth_and_system_token
masks_regex_hint_and_literal_pattern
rejects_invalid_regex_without_echoing_type_or_pattern
unsupported_hint_reports_only_its_index
merges_overlapping_and_adjacent_ranges_once
zero_width_regex_terminates_and_preserves_remaining_text
duplicate_values_do_not_change_output
trim_double_quotes_requires_more_than_eight_characters
powershell_ampersand_fragments_require_six_characters
```

Для manifest test fixture использовать `serde_json::from_value::<JobManifest>` с
двумя synthetic secrets и endpoint `authorization.parameters.AccessToken`.
`rejects_invalid_regex_without_echoing_type_or_pattern` проверяет
`!error.to_string().contains("CANARY")`.

- [ ] **Step 2: Запустить RED и проверить причину падения**

Run:

```bash
cargo test job::secret_masker::secret_masker_test -- --nocapture
```

Expected: compile/test failure, потому что `SecretMasker` и его behavior ещё не
реализованы; ни один failure не должен быть вызван неверным test fixture.

- [ ] **Step 3: Реализовать минимальный masker и добавить `regex`**

Добавить `regex = "1"` в dependencies и реализовать модуль в следующей форме:

```rust
#[derive(Default)]
pub(crate) struct SecretMasker {
    originals: HashSet<String>,
    values: HashSet<String>,
    regexes: Vec<Regex>,
}

pub(crate) type SharedSecretMasker = Arc<RwLock<SecretMasker>>;
```

Реализовать методы `from_manifest(&JobManifest) -> Result<Self>`,
`add_value(&mut self, &str)` и `mask(&self, &str) -> String`. `from_manifest`
обязан пройти источники ровно в таком порядке, не полагаясь на него для результата:
secret variables, `contextData.secrets`, endpoint auth parameters,
`manifest.github_token()`, mask hints. Для hint разрешён только `type == "regex"`;
ошибки используют `mask hint at index {index}` и не включают JSON value.

`add_value` сначала формирует unique candidates: original, `trim()`, затем каждый
непустой `split(['\r', '\n']).map(str::trim)`. Для каждого candidate один раз
добавить raw и результаты функций:

```rust
fn json_escape(value: &str) -> String;
fn uri_data_escape(value: &str) -> String;
fn xml_escape(value: &str) -> String;
fn command_line_escape(value: &str) -> String;
fn expression_escape(value: &str) -> String;
fn base64_escape(value: &str, shift: usize) -> String;
fn trim_double_quotes(value: &str) -> String;
fn powershell_pre_ampersand(value: &str) -> String;
fn powershell_post_ampersand(value: &str) -> String;
```

URI escaping оставляет только ASCII `A-Z a-z 0-9 - _ . ~`; остальные UTF-8 bytes
кодируются `%HH` uppercase. XML replacement выполняется по chars без повторного
escaping. Base64 использует существующий `base64::engine::general_purpose::STANDARD`.

`mask` собирает byte ranges через `str::match_indices` и `Regex::find_iter`,
сортирует `(start, end)`, объединяет диапазоны при `next.start <= current.end` и
собирает новый `String` с одним `***` на объединённый диапазон. Zero-width match
вставляет один `***` в соответствующую позицию и не запускает собственный цикл.

- [ ] **Step 4: Запустить GREEN и mutation check**

Run:

```bash
cargo test job::secret_masker::secret_masker_test -- --nocapture
cargo test job::manifest::manifest_test -- --nocapture
```

Expected: PASS. Мысленно удалить JSON encoder, endpoint loop, range merge и
zero-width handling; каждый mutation должен ломать именованный test.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/job.rs src/job/secret_masker.rs src/job/secret_masker_test.rs
git commit -m "feat: add job-scoped secret masker"
```

### Task 2: Mask-before-fan-out для всех job log sinks

**Files:**
- Modify: `src/job/logs.rs:1-225`
- Modify: `src/job/logs_test.rs:1-330`
- Modify: `src/job/execute.rs:1-160,737-800,1350-1450`
- Modify: `src/job/execute_test.rs`
- Modify: `src/docker/output.rs:1-90`
- Modify: `src/docker/output_test.rs:1-140`
- Modify: `src/job/action/docker_test.rs`
- Modify: `src/job/action/node_test.rs`
- Modify: `src/job/action/composite_test.rs`
- Modify: `src/docker/build_test.rs`
- Modify: `src/docker/exec_test.rs`
- Modify: `src/job/live_feed.rs:1-235`
- Modify: `src/job/live_feed_test.rs`
- Modify: `tests/secrets_test.rs`
- Modify: `tests/common/mod.rs`

**Interfaces:**
- Consumes: `SharedSecretMasker` из Task 1.
- Produces: `LogSender` и `JobState`, разделяющие один masker; internal функция
  `run_all_steps_with_masker`, принимающая `SharedSecretMasker`, для Task 5.

- [ ] **Step 1: Добавить RED tests на реальные sink payloads**

В `logs_test.rs` добавить tests
`legacy_vss_masks_multiline_and_json_encoded_canaries` и
`results_step_and_job_blobs_receive_identical_masked_content` с raw mask
`two-lines\nquote-\"slash\\`.

Оба tests отправляют отдельные строки `two-lines`, `quote-"slash\` и literal JSON
representation `two-lines\\nquote-\\\"slash\\\\`; assertions проверяют наличие
safe prefixes, наличие `***` и отсутствие каждой raw/encoded canary.

В `tests/secrets_test.rs` добавить black-box test
`synthetic_canaries_are_absent_from_uploaded_logs`: manifest передаёт plain,
`LINE_ONE_41\nLINE_TWO_41` и `quote-"slash\\-41` через `contextData.secrets`, а
script выводит plain canary отдельно в stdout и stderr, raw multiline lines,
JSON-escaped representation, warning/error commands и `safe-before-failure`. Через
`TestEnv::uploaded_log_text` проверить отсутствие всех canaries, наличие `***` и
сохранение safe line. В `tests/common/mod.rs` добавить
helpers, возвращающие legacy POST и Results PUT bodies раздельно, чтобы assertions
не могли пройти за счёт другого sink.

В `src/job/action/node_test.rs` добавить
`failing_node_action_masks_secret_in_collected_log`: временный Node action пишет
known canary в stdout и stderr, затем завершает process с code 1. Проверить failure
conclusion, safe error line и отсутствие raw/JSON-escaped canary в `CollectedLog`.

В `output_test.rs` добавить:

```rust
#[tokio::test]
async fn add_mask_registers_encoded_variants_for_all_sender_clones() {
    let (processor, mut rx) = make_processor(false);
    let clone = processor.clone();
    processor.process_line("::add-mask::quote-\"slash\\").await;
    clone.process_line(r#"json=quote-\"slash\\"#).await;
    assert_eq!(rx.recv().await.unwrap().content, "json=***");
}
```

В `live_feed_test.rs` поднять local `TcpListener`, принять соединение через
`tokio_tungstenite::accept_async`, подключить настоящий `LiveFeed::connect`, создать
test `LogSender` с `feed.sender().clone()`, отправить canary и проверить фактический
WebSocket JSON `Value == ["safe=***"]`.

- [ ] **Step 2: Запустить RED**

Run:

```bash
cargo test job::logs::logs_test -- --nocapture
cargo test docker::output::output_test::add_mask_registers_encoded_variants_for_all_sender_clones -- --nocapture
cargo test job::live_feed::live_feed_test -- --nocapture
cargo test --test secrets_test synthetic_canaries_are_absent_from_uploaded_logs -- --nocapture
```

Expected: legacy/Results bodies и cloned sender содержат encoded canary; live-feed
test также видит unmasked value.

- [ ] **Step 3: Заменить `Arc<RwLock<Vec<String>>>` единым masker**

В `LogSender`, `StepLogger::{results,legacy,results_for_test}`, `JobState` и
`OutputProcessor` заменить field/parameters `masks` на `secret_masker`.

Критические реализации:

```rust
async fn apply_masks(&self, content: &str) -> String {
    self.secret_masker.read().await.mask(content)
}

WorkflowCommand::AddMask(secret) => {
    self.secret_masker.write().await.add_value(&secret);
}
```

`collect_secret_masks` удалить. `collect_secrets` больше не мутирует masker и
становится синхронной функцией.
Публичный `run_all_steps` создаёт `Arc::new(RwLock::new(
SecretMasker::from_manifest(manifest)?))` и делегирует новой функции
`run_all_steps_with_masker`, которая содержит прежнее тело и принимает готовый
`SharedSecretMasker`. Это сохраняет interface integration tests и позволяет Runner
из Task 5 создать masker раньше Docker setup.

Во всех unit tests заменить `Arc<RwLock<Vec<String>>>` на
`Arc<RwLock<SecretMasker>>`; values добавлять только через `add_value`, не прямым
доступом к implementation collections.

Добавить `LogSender::new_for_test_with_feed` только под `#[cfg(test)]`; он должен
использовать production `send`, а не отдельную masking реализацию.

- [ ] **Step 4: Запустить GREEN для sinks и существующих action tests**

Run:

```bash
cargo test job::logs::logs_test -- --nocapture
cargo test docker::output::output_test -- --nocapture
cargo test job::live_feed::live_feed_test -- --nocapture
cargo test job::execute::execute_test -- --nocapture
cargo test job::action -- --nocapture
```

Expected: PASS; existing simple secret tests остаются зелёными, а actual VSS,
Results и WebSocket payloads содержат одинаковый masked content.

- [ ] **Step 5: Commit**

```bash
git add src/job src/docker/output.rs src/docker/output_test.rs src/docker/build_test.rs src/docker/exec_test.rs tests/secrets_test.rs tests/common/mod.rs
git commit -m "fix: redact before log fan-out"
```

### Task 3: Stateful framing всех Docker text streams

**Files:**
- Modify: `src/docker/output.rs:1-100`
- Modify: `src/docker/output_test.rs`
- Modify: `src/docker/exec.rs:45-75`
- Modify: `src/job/action/docker.rs:830-875`
- Modify: `src/docker/build.rs:320-390,410-455`
- Modify: `src/docker/build_test.rs`

**Interfaces:**
- Consumes: полные byte chunks от Bollard `LogOutput`/`BuildInfo.stream`.
- Produces: `LineFramer::{push,finish}` и `DockerLogFramer::{push,finish}`; callers
  получают только восстановленные строки и передают их в `OutputProcessor`.

- [ ] **Step 1: Написать RED tests на произвольные frame splits**

В `output_test.rs` добавить:

```rust
#[test]
fn line_framer_reassembles_secret_at_every_byte_split() {
    let bytes = "safe=α-canary-secret\r\nnext=line\n".as_bytes();
    for split in 0..=bytes.len() {
        let mut framer = LineFramer::default();
        let mut got = framer.push(&bytes[..split]);
        got.extend(framer.push(&bytes[split..]));
        got.extend(framer.finish());
        assert_eq!(got, ["safe=α-canary-secret", "next=line"]);
    }
}

#[test]
fn docker_log_framer_keeps_stdout_and_stderr_partial_lines_separate() {
    let mut framer = DockerLogFramer::default();
    assert!(framer.push(LogOutput::StdOut { message: b"out-".to_vec().into() }).is_empty());
    assert!(framer.push(LogOutput::StdErr { message: b"err-".to_vec().into() }).is_empty());
    assert_eq!(framer.push(LogOutput::StdOut { message: b"done\n".to_vec().into() }), ["out-done"]);
    assert_eq!(framer.push(LogOutput::StdErr { message: b"done\n".to_vec().into() }), ["err-done"]);
}
```

Добавить tests для empty chunks, LF, CRLF разрезанного между chunks, invalid UTF-8
на EOF (`String::from_utf8_lossy`) и повторного `finish` без дубликата.

В `build_test.rs` добавить test, передающий две последовательные `BuildInfo.stream`
части `"token=frame-"` и `"secret\n"`; production helper должен вернуть ровно
`"token=frame-secret"` один раз, после чего `LogSender` маскирует canary.

- [ ] **Step 2: Запустить RED**

Run:

```bash
cargo test docker::output::output_test -- --nocapture
cargo test docker::build::build_test::build_progress_reassembles_split_stream_before_masking -- --nocapture
```

Expected: missing `LineFramer`/`DockerLogFramer` или прежний per-frame output не
может восстановить expected lines.

- [ ] **Step 3: Реализовать framers и подключить callers**

`LineFramer` хранит `Vec<u8>`. `push` добавляет chunk, находит последний LF,
отделяет complete prefix через `split_off`, делит prefix по LF и удаляет один CR.
`finish` делает `mem::take`, возвращает `None` для пустого buffer и одну lossy UTF-8
строку иначе.

`DockerLogFramer` содержит `stdout: LineFramer` и `stderr: LineFramer`; принимает
только `StdOut`/`StdErr`, остальные `LogOutput` возвращают пустой `Vec`.

В `docker_exec` и Docker action stream создать один `DockerLogFramer` внутри stream
task, обрабатывать `for line in framer.push(output)`, затем на нормальном EOF
обработать `framer.finish()`. Abort/cancel не публикует incomplete tail.

В Docker build держать один `LineFramer` на весь `build_image` stream. Для
`BuildInfo.stream` передавать bytes во framer и применять
`sanitize_build_progress` только к complete lines. На успешном конце вызвать
`finish`; `status`/`progress` остаются record-oriented и идут сразу.

- [ ] **Step 4: Запустить GREEN и регрессию workflow commands**

Run:

```bash
cargo test docker::output::output_test -- --nocapture
cargo test docker::build::build_test -- --nocapture
cargo test job::action::docker::docker_test -- --nocapture
cargo test job::commands::commands_test -- --nocapture
```

Expected: PASS; split `::add-mask::` command распознаётся только после полной
строки, а stdout/stderr не склеиваются.

- [ ] **Step 5: Commit**

```bash
git add src/docker/output.rs src/docker/output_test.rs src/docker/exec.rs src/docker/build.rs src/docker/build_test.rs src/job/action/docker.rs
git commit -m "fix: frame Docker output before redaction"
```

### Task 4: Безопасные diagnostics до построения masker

**Files:**
- Modify: `src/job/client.rs:105-550`
- Modify: `src/job/client_test.rs:1-100`
- Modify: `src/job/manifest.rs:70-90`
- Modify: `src/job/manifest_test.rs`
- Modify: `src/runner/instance.rs:350-460`
- Modify: `src/runner/instance_test.rs`

**Interfaces:**
- Consumes: untrusted HTTP status/body и normalized manifest.
- Produces: safe acquisition errors, содержащие только status/body length либо
  serde category/line/column; structured counts вместо manifest payloads.

- [ ] **Step 1: Добавить RED tests с захватом debug trace**

В `client_test.rs` определить test-only `CapturedWriter(Arc<Mutex<Vec<u8>>>)`,
реализующий `std::io::Write`, и current-thread Tokio test с локальным
`tracing_subscriber::fmt().with_max_level(DEBUG)` dispatcher.

Добавить tests:

```text
acquire_job_semantic_error_omits_raw_and_normalized_canary
acquire_job_syntax_error_reports_category_and_position_without_body
acquire_job_http_error_reports_status_and_length_without_response_body
job_api_error_responses_never_include_response_body
```

Semantic body должен быть валидным JSON, содержать
`"jobContainer":{"image":"CANARY-MANIFEST"}` и несовместимый
`"variables":"CANARY-MANIFEST"`. Собрать `error.to_string()` и captured trace;
оба не содержат `CANARY-MANIFEST`, но error содержит `deserializing normalized job
manifest`.

В `instance_test.rs` test safe acquisition log проверяет, что helper structured
fields содержит `steps`, `has_container`, `has_services`, `variable_count`, но не
container image, endpoint URL, filenames или variable names из fixture.

- [ ] **Step 2: Запустить RED**

Run:

```bash
cargo test job::client::client_test::acquire_job_semantic_error_omits_raw_and_normalized_canary -- --nocapture
cargo test runner::instance::instance_test -- --nocapture
```

Expected: current debug trace содержит normalized manifest, а semantic error
содержит raw preview.

- [ ] **Step 3: Заменить payload diagnostics структурными**

В `acquire_job`:

```rust
if !status.is_success() {
    bail!("acquire job failed ({status}, response body {} bytes)", body_text.len());
}
let raw = serde_json::from_str(&body_text).map_err(|error| anyhow!(
    "parsing raw job manifest JSON failed ({:?} at line {}, column {})",
    error.classify(), error.line(), error.column()
))?;
let normalized = manifest::normalize_manifest(&raw);
serde_json::from_value(normalized).map_err(|error| anyhow!(
    "deserializing normalized job manifest failed ({:?})", error.classify()
))
```

Сохранить `debug!(manifest_length = body_text.len(), "received job manifest")`; удалить debug поля с
`normalized`, `raw jobContainer` и `normalized jobContainer`.

Во всех остальных non-success paths `JobClient` (`renew_job`, `complete_job`,
`update_steps`, signed URL, log metadata, create/upload log и timeline update)
заменить включение `body_text` на status и `body_text.len()`. Table-driven test
`job_api_error_responses_never_include_response_body` вызывает каждый доступный
метод с ответом `500 CANARY-API-BODY` и проверяет returned error либо captured
warning; canary не должен появиться ни в одном результате.

В `Runner::execute_job` убрать `run_service_url`, `container_image`, `file_table`,
variable names и endpoint URL из trace. Оставить identifiers и counts:

```rust
info!(
    plan_id = %manifest.plan.plan_id,
    job_id = %manifest.plan.job_id,
    steps = manifest.steps.len(),
    variable_count = manifest.variables.len(),
    endpoint_count = manifest.resources.endpoints.len(),
    has_container = manifest.has_container(),
    has_services = manifest.has_services(),
    mask_hint_count = manifest.mask_regexes().len(),
    "job acquired"
);
```

Endpoint debug допускает только index и `data.len()`, не name/url/data keys.

- [ ] **Step 4: Запустить GREEN**

Run:

```bash
cargo test job::client::client_test -- --nocapture
cargo test job::manifest::manifest_test -- --nocapture
cargo test runner::instance::instance_test -- --nocapture
```

Expected: PASS; safe structural diagnostics сохранены, все manifest canaries
отсутствуют в error и trace buffers.

- [ ] **Step 5: Commit**

```bash
git add src/job/client.rs src/job/client_test.rs src/job/manifest.rs src/job/manifest_test.rs src/runner/instance.rs src/runner/instance_test.rs
git commit -m "fix: remove manifest payloads from diagnostics"
```

### Task 5: Один masker для execution, setup failure и daemon errors

**Files:**
- Modify: `src/runner/instance.rs:400-760`
- Modify: `src/runner/instance_test.rs`
- Modify: `src/runner/report.rs:1-100`
- Create: `src/runner/report_test.rs`
- Modify: `src/docker/resources.rs:450-575`
- Modify: `src/docker/resources_test.rs`
- Modify: `src/job/execute.rs:737-800`

**Interfaces:**
- Consumes: `SharedSecretMasker` из Task 1 и internal
  `run_all_steps_with_masker` из Task 2.
- Produces: единый masker lifetime от successful manifest parse до cleanup/report;
  masked setup blob и masked daemon error chain.

- [ ] **Step 1: Написать RED test на вложенный setup error**

Подключить `report_test.rs` в `report.rs`. Wiremock fixture монтирует реальные
`update_steps`, signed blob URL, create/append/seal blob, metadata и complete-job
endpoints. Test создаёт:

```rust
let source = anyhow!("source contains CANARY-SETUP and CANARY\\nJSON");
let error = source.context("safe setup stage");
let mut masker = SecretMasker::default();
masker.add_value("CANARY-SETUP and CANARY\nJSON");
let masker = Arc::new(RwLock::new(masker));

report_setup_failure(&client, &manifest, &error, &masker).await.unwrap();
```

Проверить фактический blob body: содержит `safe setup stage` и `***`, не содержит
`CANARY-SETUP`, `CANARY`, `JSON` как secret line и JSON-escaped representation.

В `instance_test.rs` добавить async test `masked_error_chain_hides_nested_source`
для той же source chain. Test `concurrent_jobs_keep_secret_sets_isolated` создаёт
два masker и два `LogSender`, одновременно отправляет строки через `tokio::join!`,
затем проверяет `job-a=***` и `job-b=***` в соответствующих receivers без общего
lock/state.

В `resources_test.rs` построить health inspect с output `CANARY-HEALTH`, захватить
trace вызова health diagnostic helper и проверить отсутствие canary при наличии
container id, exit code и record count. Отдельный test
`container_tail_summary_discards_payload_bytes` передаёт `LogOutput` с
`CANARY-TAIL`, проверяет только chunk/byte counts и отсутствие payload в summary.

- [ ] **Step 2: Запустить RED**

Run:

```bash
cargo test runner::report::report_test -- --nocapture
cargo test runner::instance::instance_test::masked_error_chain_hides_nested_source -- --nocapture
cargo test docker::resources::resources_test -- --nocapture
```

Expected: setup blob и current health trace содержат canaries; Runner ещё не имеет
общего masker для execution/reporting.

- [ ] **Step 3: Поднять masker lifetime в `Runner::execute_job`**

Сразу после `acquire_job` выполнить:

```rust
let secret_masker = Arc::new(RwLock::new(SecretMasker::from_manifest(&manifest)?));
```

Передать clone через `run_job`, `run_job_body`, `run_job_steps` до
`run_all_steps_with_masker`. Не создавать второй masker внутри этого пути.

Для daemon error chain добавить private helper:

```rust
async fn mask_error_chain(error: &anyhow::Error, masker: &SharedSecretMasker) -> String {
    let rendered = format!("{error:#}");
    masker.read().await.mask(&rendered)
}
```

Во всех post-manifest error branches `execute_job` логировать только полученную
строку; убрать `cause = ?error`. Для ошибки до manifest сохранить safe error Task 4.

Добавить к `report_setup_failure` последний параметр
`masker: &SharedSecretMasker` и после построения полного `error_log` вызвать masker
один раз до вычисления `line_count` и upload.

- [ ] **Step 4: Удалить raw Docker setup payloads из daemon trace**

`log_container_tail` больше не собирает `String`: считать `chunk_count` и
`byte_count`, затем логировать только эти counts и container identifier.

`log_health_check_results` агрегирует `record_count` и last exit code; поле
`entry.output` не читается и не логируется. Сохранить сообщения `no container logs
available` и `health check probe summary`, чтобы безопасная диагностика не исчезла.

- [ ] **Step 5: Запустить GREEN и lifecycle regression**

Run:

```bash
cargo test runner::report::report_test -- --nocapture
cargo test runner::instance::instance_test -- --nocapture
cargo test docker::resources::resources_test -- --nocapture
cargo test job::execute::execute_test -- --nocapture
```

Expected: PASS; setup blob/daemon trace не содержат canaries, а safe stage/status,
exit code и counts остаются.

- [ ] **Step 6: Commit**

```bash
git add src/runner/instance.rs src/runner/instance_test.rs src/runner/report.rs src/runner/report_test.rs src/docker/resources.rs src/docker/resources_test.rs src/job/execute.rs
git commit -m "fix: redact setup and daemon diagnostics"
```

### Task 6: Black-box canary acceptance и verification report

**Files:**
- Create: `docs/superpowers/reports/2026-09-19-chimera-secret-redaction.md`
- Review: `tests/secrets_test.rs`
- Review: `src/job/logs_test.rs`
- Review: `src/job/live_feed_test.rs`
- Review: `src/docker/output_test.rs`

**Interfaces:**
- Consumes: завершённые interfaces и RED→GREEN tests Tasks 1–5.
- Produces: black-box evidence по критериям issue #41 и verification report.

- [ ] **Step 1: Повторить black-box и sink acceptance tests**

Run:

```bash
cargo test --test secrets_test synthetic_canaries_are_absent_from_uploaded_logs -- --nocapture
cargo test job::logs::logs_test -- --nocapture
cargo test job::live_feed::live_feed_test -- --nocapture
cargo test docker::output::output_test -- --nocapture
```

Expected: PASS. Эти tests уже наблюдались RED до production changes в Tasks 1–5;
повторный запуск служит acceptance evidence, а не tests-after заменой TDD.

- [ ] **Step 2: Запустить форматирование и статический анализ**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: exit 0, без warnings.

- [ ] **Step 3: Запустить полный test suite**

Run:

```bash
cargo test
```

Expected: exit 0. Любой red test, включая существующий и не связанный с DPL-07,
записать по полному имени в report; не скрывать его сокращённой формулировкой.

- [ ] **Step 4: Проверить ignored Docker tests при доступном daemon**

Сначала выполнить read-only probe:

```bash
docker info
```

Если daemon доступен и сообщает rootless security option, запустить:

```bash
cargo test docker::exec::exec_test -- --ignored --nocapture
cargo test job::action::docker::docker_test -- --ignored --nocapture
```

Если daemon недоступен или не rootless, не запускать privileged substitute;
зафиксировать `NOT RUN` и точную причину в report.

- [ ] **Step 5: Создать verification report**

Создать `docs/superpowers/reports/2026-09-19-chimera-secret-redaction.md` с:

```text
- baseline и итоговый commit;
- таблица R-01…R-16: test name, command, PASS/NOT RUN;
- подтверждение отсутствия synthetic canaries по каждому sink;
- отдельно: malformed manifest, setup failure, action failure, frame splits;
- Docker E2E environment и ограничения;
- явная граница: arbitrary HMAC не покрывается автоматически.
```

Report не заявляет production rollout или 20-run online E2E, если они фактически не
выполнялись.

- [ ] **Step 6: Commit**

```bash
git add docs/superpowers/reports/2026-09-19-chimera-secret-redaction.md
git commit -m "docs: report secret redaction verification"
```

### Task 7: Финальная проверка diff и issue coverage

**Files:**
- Review only: все изменённые файлы Tasks 1–6
- Modify only if a failing test demonstrates a gap.

**Interfaces:**
- Consumes: commits Tasks 1–6 и spec acceptance matrix.
- Produces: готовый к review branch без незакоммиченных изменений.

- [ ] **Step 1: Сопоставить acceptance matrix со tests**

Для R-01…R-16 выписать точное имя хотя бы одного автоматического test. Проверить,
что R-12 ссылается на отдельные VSS, Results step/job и WebSocket assertions, а
R-14 — одновременно на returned error и captured debug trace.

- [ ] **Step 2: Проверить опасные паттерны в diff**

Run:

```bash
rg -n "normalized = %|raw = %|logs = %|output = %|RwLock<Vec<String>>|\.to_string\(\)\.lines\(\)" src/job/client.rs src/job/manifest.rs src/job/logs.rs src/job/execute.rs src/runner/instance.rs src/docker/resources.rs src/docker/exec.rs src/docker/output.rs src/docker/build.rs src/job/action/docker.rs
rg -n "\{body_text\}" src/job/client.rs
git diff be6adc97e542 --check
git status --short
```

Expected: `rg` не находит старых secret-bearing/job-output patterns; `diff --check`
чистый; status не содержит незакоммиченных файлов.

- [ ] **Step 3: Повторить обязательную verification gate**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Expected: все команды exit 0. Использовать
`superpowers:verification-before-completion` перед любым заявлением о готовности.

- [ ] **Step 4: Подготовить handoff**

Сообщить итоговые commits, test evidence, Docker `PASS/NOT RUN`, оставшиеся границы
и предложенное имя branch `codex/dpl-07-secret-redaction`. Поскольку текущий
worktree находится на detached HEAD, не создавать branch/push/PR без отдельной
команды пользователя или native App action.
