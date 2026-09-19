# DPL-07 — Сквозная защита секретов в diagnostics и job logs

Дата: 2026-09-19. Статус: проект спецификации, реализация не начата.
Целевой issue: [#41](https://github.com/antdigo/chimera/issues/41).
База исследования: commit `be6adc97e5429689365d79c91cc9953b085892ef`.

## 1. Задача и результат

Chimera не должна сохранять или отправлять известные job secrets ни через daemon
diagnostics, ни через GitHub log sinks. Гарантия распространяется на host и Docker
stdout/stderr, live feed, Results blobs, legacy VSS logs и synthetic setup-failure
log. Разбиение Docker transport frames не влияет на результат redaction.

Безопасные части диагностики сохраняются: категория и стадия ошибки, HTTP status,
идентификаторы job/step, exit code, количество записей и координаты malformed JSON.
Secret-bearing payloads, response bodies, container output и значения manifest в
daemon trace не выводятся до создания job-scoped masker.

Целевой эксплуатационный профиль — 20 одновременно выполняемых host jobs. Masker
принадлежит одному job и не разделяет secret set между параллельными jobs.

## 2. Подтверждённая причина

Дефект образуют три независимых разрыва одной цепочки:

1. `JobClient::acquire_job` пишет полный normalized manifest в debug и добавляет
   preview исходного body в ошибку десериализации. `normalize_manifest` отдельно
   пишет raw и normalized `jobContainer`. На этом этапе masker ещё не создан.
2. `LogSender` выполняет последовательный `String::replace` только по исходным
   строкам. Multiline secret распадается на строки до вызова sender, JSON-escaped
   значение отличается от исходного, endpoint authorization и manifest mask hints
   не входят в единый набор правил.
3. Docker exec и Docker action вызывают `.lines()` отдельно на каждом `LogOutput`.
   Если одна строка или secret разделены между frames, части уходят на masking до
   восстановления исходной строки. Setup failure и часть Docker diagnostics вообще
   обходят `LogSender`.

Простое добавление нескольких `replace` не устраняет причину: registration,
framing и sink routing должны иметь один контракт.

## 3. Граница гарантии

Входит:

- значения secret variables, `contextData.secrets`, endpoint authorization и
  runtime-команды `add-mask`;
- regex hints из manifest;
- multiline и поддержанные encoded-представления известных значений;
- stdout и stderr host processes, Docker exec, Docker actions и Docker build
  progress;
- step/job Results blobs, legacy VSS, live feed, setup-failure log и daemon
  diagnostics, затронутые job lifecycle;
- malformed manifest при включённом debug;
- детерминированные тесты с synthetic canaries и произвольным дроблением frames.

Не входит:

- поиск неизвестных secrets эвристиками;
- автоматическое распознавание произвольных производных значений, включая HMAC,
  hash, шифротекст и пользовательское преобразование;
- сокрытие данных, которые workflow намеренно отправляет во внешний сервис мимо
  log sinks Chimera;
- новый лимит длины stdout/stderr line. Framer сохраняет существующее поведение
  host `BufReader::lines`; отдельное memory-hardening требует собственной задачи;
- изменение semantics workflow commands, кроме регистрации `add-mask` через общий
  masker.

## 4. Архитектура masker

Добавить глубокий модуль `src/job/secret_masker.rs`. Его внешний interface:

```rust
pub(crate) struct SecretMasker;
pub(crate) type SharedSecretMasker = Arc<RwLock<SecretMasker>>;

impl SecretMasker {
    pub(crate) fn from_manifest(manifest: &JobManifest) -> Result<Self>;
    pub(crate) fn add_value(&mut self, value: &str);
    pub(crate) fn mask(&self, input: &str) -> String;
}
```

Regex registration и построение encoded variants остаются implementation details.
Callers знают только три операции: построить job masker, добавить runtime value и
маскировать строку/блок. `LogSender` и `JobState` хранят `SharedSecretMasker`, а не
сырой `Vec<String>`.

### 4.1 Источники значений

`from_manifest` регистрирует:

- все непустые `variables[*].value` с `isSecret=true`;
- все непустые строки из `contextData.secrets`;
- authorization parameters каждого service endpoint;
- system GitHub token независимо от пути, которым он попал в secrets context;
- regex hints типа `regex` из `manifest.mask`.

Для value secret сохраняются исходное значение, его непустая trimmed форма и
каждая непустая строка после разделения по CR/LF. Это закрывает как цельный вывод,
так и построчную обработку stdout/stderr. Дубликаты удаляются.

Regex hint компилируется Rust `regex`, поэтому matching имеет линейную сложность.
Неподдержанный hint type даёт safe warning только с индексом hint: само значение
type считается untrusted payload. Невалидный regex завершает setup контролируемой
ошибкой с индексом hint, не печатая type или pattern.
Сам pattern дополнительно регистрируется как literal value по поведению official
runner.

### 4.2 Encoded-представления

Для исходного value, его trimmed-формы и каждой multiline-строки masker заранее
вычисляет варианты, совместимые с официальным runner:

- JSON string escaping без внешних кавычек;
- RFC 3986 URI data escaping;
- XML escaping;
- escaping двойных кавычек для command-line argument;
- удвоение апострофов для expression string;
- Base64 UTF-8 и Base64 со сдвигом на один и два исходных байта;
- содержимое значения длиной больше 8 символов в двойных кавычках без этих
  кавычек;
- PowerShell pre/post-ampersand fragments с официальным минимумом длины 6.

Пустой или совпадающий с уже известным вариант не добавляется. HMAC и другие
необратимые производные не вычисляются: без знания transform/key они не могут быть
надёжно связаны с исходным secret.

### 4.3 Замена совпадений

`mask` находит все literal и regex совпадения в исходном input, сортирует диапазоны
по началу и объединяет пересекающиеся/соприкасающиеся диапазоны. Каждый объединённый
диапазон заменяется одним `***`. Matching выполняется над исходным input, поэтому
результат не зависит от порядка регистрации и одна замена не создаёт новое
совпадение для следующего правила.

## 5. Framing Docker output

Добавить в `src/docker/output.rs` stateful byte-oriented `LineFramer`:

```rust
impl LineFramer {
    fn push(&mut self, chunk: &[u8]) -> Vec<String>;
    fn finish(&mut self) -> Option<String>;
}
```

`push` сохраняет incomplete bytes между вызовами, выдаёт только строки с найденным
LF и удаляет один завершающий CR. UTF-8 преобразуется после сборки полной строки,
поэтому multibyte code point также может пересекать frame. `finish` один раз отдаёт
последнюю строку без newline.

Docker stdout и stderr используют независимые framers: данные разных streams не
склеиваются. Framer применяется к:

- `docker_exec`;
- log stream Docker action container;
- последовательным `BuildInfo.stream` сообщениям Docker build.

После framing каждая строка проходит существующий `OutputProcessor`, чтобы workflow
commands разбирались только из полной строки. На EOF оба stream buffers обязательно
flush-ятся. `status` и `progress` Docker build остаются отдельными records и сразу
проходят `LogSender`.

## 6. Routing и diagnostics

### 6.1 Job log sinks

`LogSender::send` остаётся единственной точкой fan-out. Он сначала вызывает
job-scoped `SecretMasker::mask`, затем отправляет один и тот же masked content в:

1. live feed;
2. job-level Results collector;
3. step Results collector либо legacy VSS uploader.

Ни один sink повторно не принимает unmasked content. Runtime `add-mask` вызывает
`SecretMasker::add_value`, поэтому новые значения получают те же line splitting и
encoded variants, что manifest secrets.

### 6.2 Setup failure

Job-scoped masker создаётся сразу после безопасной десериализации manifest и живёт
до завершения cleanup/reporting. `format_setup_error_log` маскирует весь готовый
error block до `append_blob_block`; daemon trace получает отдельно сформированную
masked error chain. Raw `anyhow::Error` через `%error`/`?error` в этом пути не
логируется.

### 6.3 До создания masker

`acquire_job` не включает response body, raw JSON, normalized JSON или offending
value в trace/error. Ошибки содержат только:

- HTTP status и body length для неуспешного ответа;
- `serde_json::error::Category`, line и column для malformed JSON;
- безопасную стадию `normalizing`/`deserializing`.

Manifest normalizer не пишет raw container specs. Runner diagnostics не выводит
manifest URLs, container image, filenames, variable values или целые collections;
вместо них используются boolean/count fields.

### 6.4 Docker setup diagnostics

Raw container tail и health-check output не пишутся в daemon trace, поскольку этот
путь не является пользовательским job log sink. Сохраняются container identifier,
exit code, факт наличия output и количество последних health records. Видимое
setup-failure сообщение проходит masker по §6.2.

## 7. Ошибки и конкурентность

- Masker одного job создаётся до Docker resource setup и передаётся по `Arc` только
  в операции этого job.
- Чтение для каждой log line берёт shared read lock; `add-mask` кратковременно берёт
  write lock. Между jobs lock и secret set не общие.
- Ошибка sink/upload логируется без request/response payload и не отменяет уже
  выполненную redaction.
- Ошибка masker construction не запускает steps и не выводит secret/pattern.
- Потеря Docker stream или cancellation flush-ит только уже завершённые строки;
  incomplete content не отправляется после abort. Нормальный EOF flush-ит остаток.

## 8. TDD и приёмочные проверки

Все production changes выполняются red-green-refactor. Для каждого теста сначала
фиксируется ожидаемое падение на baseline `be6adc97e542`.

| ID | Проверка | Ожидаемый результат |
|---|---|---|
| R-01 | plain secret в stdout и stderr | canary заменён на `***` |
| R-02 | secret из двух CR/LF-строк | обе непустые строки отсутствуют в sinks |
| R-03 | кавычки, backslash и newline в JSON representation | raw и JSON-escaped canaries отсутствуют |
| R-04 | URI/XML/Base64/expression/command-line variants | каждый поддержанный вариант маскируется |
| R-05 | manifest regex hint | match маскируется; safe соседний текст сохраняется |
| R-06 | invalid/unsupported hint | safe failure/warning без pattern и secret |
| R-07 | overlapping literal и regex ranges | один `***`, соседний текст не повреждён |
| R-08 | `add-mask` во время step | последующие raw/encoded строки маскируются |
| R-09 | одна Docker line и secret разрезаны во всех byte offsets | output совпадает с unsplit case; canary отсутствует |
| R-10 | CRLF и UTF-8 code point разрезаны между frames | строка восстанавливается без corruption |
| R-11 | отдельные stdout/stderr partial lines | streams не склеиваются; оба flush корректны |
| R-12 | Results step/job blobs, VSS и live feed | фактически отправленные payloads не содержат canaries |
| R-13 | setup/action failure | safe message остаётся; raw/encoded canaries отсутствуют |
| R-14 | debug + malformed manifest | daemon output и returned error не содержат body canary |
| R-15 | Docker health/tail diagnostics | daemon output не содержит container canary |
| R-16 | два concurrent jobs с разными secrets | каждый маскирует свой secret без меж-job state |

Sink tests проверяют реальные request/WebSocket/blob payloads на границе Chimera,
а не только внутренний вызов mock. Docker framing тестируется реальным `LineFramer`
с таблицей всех split offsets; сетевой Docker daemon для этой семантики не нужен.

Обязательная проверка завершения:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Ignored Docker acceptance tests запускаются отдельно только при доступном rootless
daemon; отсутствие этого окружения явно указывается в отчёте и не подменяется
утверждением о полном Docker E2E.

## 9. Изменяемые модули

- создать `src/job/secret_masker.rs`: registration, encoders, matching;
- изменить `src/job/logs.rs`: `SharedSecretMasker` и redaction-before-fan-out;
- изменить `src/job/execute.rs` и `src/docker/output.rs`: runtime registration и
  framing interface;
- изменить `src/docker/exec.rs`, `src/job/action/docker.rs`, `src/docker/build.rs`:
  stateful framing на Docker paths;
- изменить `src/job/client.rs`, `src/job/manifest.rs`, `src/runner/instance.rs`,
  `src/runner/report.rs`, `src/docker/resources.rs`: безопасные diagnostics и setup;
- добавить dependency `regex`; переиспользовать существующие `base64`,
  `serde_json` и стандартные UTF-8/escaping primitives;
- расширить unit/integration tests рядом с соответствующими modules и в `tests/`.

## 10. Источники

- [Issue DPL-07](https://github.com/antdigo/chimera/issues/41).
- [Official SecretMasker](https://github.com/actions/runner/blob/main/src/Sdk/DTLogging/Logging/SecretMasker.cs).
- [Official ValueEncoders](https://github.com/actions/runner/blob/main/src/Sdk/DTLogging/Logging/ValueEncoders.cs).
- [Official Worker mask initialization](https://github.com/actions/runner/blob/main/src/Runner.Worker/Worker.cs).
- [Official HostContext encoder registration](https://github.com/actions/runner/blob/main/src/Runner.Common/HostContext.cs).

Спецификация заимствует observable masking semantics official runner, но не его
process-global lifetime: Chimera обслуживает конкурентные jobs в одном daemon,
поэтому ownership masker остаётся строго job-scoped.
