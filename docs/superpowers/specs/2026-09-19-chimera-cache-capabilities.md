# DPL-08 — Авторизация cache API через job-scoped capabilities

Дата: 2026-09-19. Статус: проект спецификации, реализация не начата.
Целевой репозиторий: `antdigo/chimera`.
База исследования: commit `be6adc97e5429689365d79c91cc9953b085892ef`.
Исходная задача: [GitHub issue #42](https://github.com/antdigo/chimera/issues/42).

## 1. Задача и критерий результата

Cache service принимает запросы только от активной job и определяет допустимые
`repo`, `ref`, `default_ref` и владельца upload по server-side записи, связанной с
`ACTIONS_RUNTIME_TOKEN`. Значения scope в URL, числовой upload ID и blob hash не
являются полномочиями сами по себе.

После изменения:

- job читает и записывает cache только в своём repository/ref scope;
- чтение cache default branch остаётся разрешённым по прежней fallback-политике;
- upload нельзя продолжить или commit-ить из другой job, даже если известен ID;
- blob нельзя скачать по одному известному hash;
- отсутствующая, чужая, просроченная или отозванная capability отклоняется;
- нормальный cache roundtrip работает при 20 одновременно выполняемых clients.

## 2. Причина дефекта и границы

В baseline router принимает base64url-encoded `repo`, `ref` и `default_ref` из
пути запроса без аутентификации. Lookup использует эти значения как scope,
reserve сохраняет их в upload session, а PATCH и commit игнорируют scope пути и
работают только по глобальному числовому ID. Download открывает blob по hash без
проверки cache entry или caller authority.

Таким образом, существующая scope-фильтрация защищает только от случайного чтения
при честно сформированном URL. Она не создаёт security boundary: любой сетевой
клиент может выбрать чужой namespace, продолжить чужой upload или запросить blob.

Входит:

- server-side регистрация и проверка job capability;
- авторизация lookup/reserve/PATCH/commit;
- job ownership upload session;
- предварительно авторизованный download URL без раскрытия runtime token;
- expiry, штатный revoke и fail-closed поведение после restart;
- сохранение repo/ref/default-branch семантики и concurrency profile из issue.

Не входит:

- внедрение cache service v2/Twirp или `ACTIONS_CACHE_SERVICE_V2`;
- изменение GitHub-issued token, его cryptographic validation или refresh;
- новая read/write policy по event trust, fork или `cache-mode`;
- TLS для loopback/bridge соединения и process isolation jobs под одним UID;
- изменение cache eviction, blob deduplication и persistence format entries;
- общий сетевой firewall или смена bind address cache listener.

Listener продолжает быть доступен контейнерным jobs через host gateway. Поэтому
исправление опирается на application-layer capability, а не на недоступность порта.

## 3. Authority и capability contract

Добавить отдельный модуль `cache::auth`, не смешивая authorization state с
`CacheManager`, который отвечает за entries, blobs, uploads и eviction.

`CacheAuthority` хранит две in-memory таблицы:

1. job capabilities, индексированные cryptographic digest runtime token;
2. download grants, индексированные случайным непрогнозируемым идентификатором.

Исходный `ACTIONS_RUNTIME_TOKEN` не сохраняется и не логируется. Для lookup в
таблице вычисляется keyed-independent cryptographic digest существующей библиотекой
`blake3`; digest рассматривается только как внутренний непрозрачный идентификатор,
не передаётся клиенту и не является заменой проверки bearer token.

Server-side запись job capability содержит:

- `capability_id` — digest runtime token;
- точные `repo`, `git_ref`, `default_ref`;
- `job_id` для ownership и безопасной диагностики;
- `expires_at`;
- состояние active/revoked.

Runner регистрирует capability после получения manifest и до запуска пользовательских
steps. Токен берётся из `SystemVssConnection.Authorization.AccessToken`, то есть из
того же источника, который Chimera уже экспортирует как `ACTIONS_RUNTIME_TOKEN`.
Новый secret или переменная окружения не добавляются, и runtime token продолжает
использоваться другими Actions endpoints без изменения.

Повторная регистрация того же token для другой активной job или другого scope
отклоняется fail-closed. Идемпотентная регистрация идентичной записи не нужна:
каждая acquired job проходит lifecycle ровно один раз.

### 3.1 Срок действия

Контракт следует GHR: expiry равен времени регистрации плюс 6 часов 10 минут —
стандартный job timeout 6 часов и 10-минутный service grace period. Нормальный
lifecycle не ждёт expiry: capability отзывается сразу после завершения, ошибки или
cancellation job. Expiry остаётся предохранителем для потерянного cleanup path.

Capability state неперсистентен. После restart daemon обе таблицы пусты; ранее
выданные tokens и download URLs недействительны. Cache entries и blobs при этом
остаются на диске и доступны новым авторизованным jobs по обычной scope policy.

## 4. API authentication и scope

Legacy REST routes и формат `ACTIONS_CACHE_URL` сохраняются для совместимости с
закреплёнными `@actions/cache` clients:

```text
/cache/{scope_repo}/{scope_ref}/{default_ref}/_apis/artifactcache/...
```

Lookup, reserve, PATCH и commit выполняют одну общую проверку до обращения к
manager/upload store:

1. извлечь ровно один `Authorization: Bearer <token>`;
2. вычислить capability ID и найти server-side запись;
3. проверить active state и `expires_at`;
4. декодировать URL scope и сравнить все три значения с claims capability;
5. передать handlers уже авторизованный `AuthorizedJob`, а не независимые строки
   из URL и headers.

Base64 scope остаётся routing/compatibility metadata. Источником разрешённого
scope является только server-side capability record. Несовпадение любого поля,
включая `default_ref`, запрещает запрос; caller не может расширить fallback policy.

Результаты проверки:

- нет header, неверная схема, неизвестный, expired или revoked token — `401`;
- валидная capability с несовпадающим URL scope — `403`;
- malformed base64 scope или некорректный request body/range — `400`;
- secrets, header values, capability IDs и download grant IDs не попадают в logs.

Эти статусы применяются одинаково к lookup, reserve, PATCH и commit. Handler не
должен сообщать, существует ли cache key или upload ID, пока authority не проверена.

## 5. Upload ownership

При reserve `UploadSession` сохраняет `owner_capability_id` и `owner_job_id` вместе
с key/version/repo/ref. `repo` и `ref` берутся из `AuthorizedJob`, не из URL.

`write_chunk` и `commit_upload` получают owner capability ID. `UploadTracker`
проверяет equality до открытия temp file или удаления session:

- owner может последовательно загружать chunks и commit-ить session;
- другая capability той же repo/ref не получает доступ;
- capability другой repo/ref также не получает доступ;
- чужой или неизвестный upload ID возвращает `404`, не раскрывая его наличие;
- revoked/expired owner получает `401` на уровне router до проверки ID.

При неуспешной чужой попытке session не изменяется и остаётся доступна владельцу.
При size mismatch сохраняется существующая cleanup/error семантика.

## 6. Авторизованный download

Legacy cache v1 возвращает `archiveLocation`, которое клиент может скачивать как
предварительно авторизованный URL без повторной передачи bearer header. Поэтому
нельзя требовать `Authorization` только на `/download` и нельзя помещать исходный
runtime token в URL.

После успешного lookup `CacheAuthority` создаёт случайный download grant. Запись
grant содержит:

- непрозрачный random ID с не менее чем 122 битами энтропии (`UUID v4`);
- parent job capability ID;
- точный blob hash найденной cache entry;
- `expires_at`, не превышающий expiry parent capability.

`archiveLocation` имеет вид:

```text
http://{host}/download/{grant_id}
```

Download handler по grant ID проверяет, что grant существует, parent capability
active и не expired, а затем открывает только связанный blob. Blob hash отсутствует
в публичном URL и не принимается от caller. Grant допускает повторные GET в пределах
срока для client retry, но не другой blob. Revoke job capability немедленно делает
все её grants недействительными. Неизвестный, expired или связанный с revoked
parent grant возвращает `404`, чтобы не создавать oracle существования
blob/capability.

Перед выдачей grant lookup уже подтвердил, что entry принадлежит `repo` capability
и текущему `ref` либо разрешённому `default_ref`. Поэтому доступ к blob является
следствием авторизованного lookup, а не знания content hash. Dedup одинакового
содержимого между repositories не расширяет authority.

## 7. Lifecycle и интеграция runner

Daemon создаёт один `Arc<CacheAuthority>` и передаёт его cache server state и всем
`Runner` instances. `CacheManager` остаётся общим storage service.

Job path:

```text
acquire manifest
  → derive repo/ref/default_ref/job_id
  → register ACTIONS_RUNTIME_TOKEN capability
  → prepare/run pre-main-post steps
  → cleanup job resources
  → revoke cache capability
  → publish final completion
```

Регистрация выполняется до того, как `ACTIONS_CACHE_URL` и
`ACTIONS_RUNTIME_TOKEN` становятся доступны action process. Если manifest не
содержит корректный access token или capability зарегистрировать нельзя, job не
запускает steps и завершается явной internal failure; unauthenticated fallback
запрещён.

Revoke должен находиться в общем cleanup path и выполняться для success, failure,
cancellation и ошибок подготовки после регистрации. Ошибка/отсутствие capability
при повторном revoke трактуется идемпотентно. Финальный completion не публикуется
как success до локального revoke, хотя сама операция in-memory и не требует I/O.

## 8. Concurrency и очистка authority state

Authority tables используют короткие `tokio::sync::RwLock` critical sections;
file I/O, blob streaming и upload writes не выполняются под этими locks. Один
lookup атомарно проверяет parent и вставляет grant, затем освобождает lock до
обращения к файлу.

Expired/revoked записи удаляются при регистрации и выдаче grant opportunistically;
дополнительный background task в первой версии не нужен. Revoke удаляет download
grants данной capability. Число активных записей ограничено числом текущих jobs и
их успешных lookups; завершение job освобождает их сразу.

20 параллельных clients должны выполнять независимые reserve/upload/commit/lookup
без глобального lock на время I/O. Тест обязан использовать 20, а не существующие
5 clients, и смешивать как минимум два repositories и feature/default refs.

## 9. Проверки и приёмка

Все security regression tests проходят через реальный Axum router, а не вызывают
только внутренние методы authority.

| ID | Проверка | Ожидаемый результат |
|---|---|---|
| C-01 | Lookup/reserve/PATCH/commit без bearer или с неизвестным token | `401`, storage state не изменён |
| C-02 | Token repo A + URL scope repo B | `403`, lookup/read/write отсутствуют |
| C-03 | Token ref/default A + подменённый ref/default в URL | `403`, fallback policy не расширена |
| C-04 | Upload создан capability A; PATCH/commit выполняет B | `404`, session A не изменена и остаётся рабочей |
| C-05 | Expired capability на всех API handlers | `401`, cache и upload state не изменены |
| C-06 | Revoked capability и ранее выданный download grant | API даёт `401`, download — `404` |
| C-07 | Знание валидного blob hash без grant | скачать blob невозможно; старый hash route отсутствует |
| C-08 | Grant A изменён/неизвестен или используется после expiry | `404`; другой blob не раскрывается |
| C-09 | Полный roundtrip текущего ref | reserve → chunks → commit → lookup → download сохраняет bytes |
| C-10 | Feature ref lookup после cache miss | разрешённый cache default branch найден и скачан |
| C-11 | Repo B с теми же key/version/hash | не получает entry/grant repo A |
| C-12 | 20 параллельных авторизованных clients | все собственные roundtrips успешны, ownership не смешивается |
| C-13 | Revoke после success/failure/cancel/setup error | capability и grants более не работают |
| C-14 | Restart с сохранёнными entries/blobs | старые tokens/grants отвергнуты, новая job читает свой допустимый cache |

TDD-порядок: сначала добавить минимальные router regression tests, наблюдать их
падение на baseline по ожидаемой причине, затем реализовывать authority, ownership,
download grants и lifecycle отдельными red-green циклами. После локальных tests
выполнить полный `cargo test` и форматирование/lints проекта.

## 10. Совместимость и документация

`docs/gh-protocol.md` обновляется вместе с реализацией:

- `ACTIONS_RUNTIME_TOKEN` обязателен как bearer capability cache API;
- URL scope — metadata, проверяемая против server-side claims;
- `archiveLocation` содержит opaque pre-authorized download grant;
- lifetime соответствует job token contract GHR;
- v1 REST selection через `ACTIONS_CACHE_URL` не меняется.

Существующие entries на диске не мигрируют: их repo/ref metadata уже достаточно
для авторизованного lookup. Незавершённые uploads после restart и сейчас очищаются;
capability state после restart намеренно не восстанавливается.

## 11. Источники

- [DPL-08 / issue #42](https://github.com/antdigo/chimera/issues/42).
- [GHR authentication design: per-job token, 6h + 10m и revoke после job](https://github.com/actions/runner/blob/main/docs/design/auth.md).
- [Baseline cache router](https://github.com/antdigo/chimera/blob/be6adc97e5429689365d79c91cc9953b085892ef/src/cache/server.rs).
- [Baseline runner cache environment](https://github.com/antdigo/chimera/blob/be6adc97e5429689365d79c91cc9953b085892ef/src/runner/instance.rs#L665-L713).
- [Baseline runtime token export](https://github.com/antdigo/chimera/blob/be6adc97e5429689365d79c91cc9953b085892ef/src/runner/env.rs#L151-L157).
- [Legacy cache API notes](https://github.com/tonistiigi/go-actions-cache/blob/master/api.md).
