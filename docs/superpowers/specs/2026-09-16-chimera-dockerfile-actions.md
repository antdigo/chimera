# CHM-02 — Поддержка Dockerfile-based GitHub Actions

Дата: 2026-09-16. Статус: проект спецификации, реализация не начата.
Целевой проект: форк `quinck-io/chimera`, не приложение sandbox-admin.
База исследования: upstream v0.1.3, commit `0b3b1fe8f41b746e9886dfa7b775a145b16b157d`.

## 1. Задача и критерий результата

Выполнять Docker actions с `runs.using: docker` и `runs.image: Dockerfile` либо
относительным путём к Dockerfile, не изменяя пользовательский workflow и action.
После сборки использовать существующий путь исполнения контейнерного action.

Обязательный реальный пример — неизменённый
`hadolint/hadolint-action@2332a7b74a6de0dda2e2221d575162eba76ba5e5` (v3.3.0)
из шаблона vibecoder. Он должен проверить `infra/Dockerfile`, передать результат
шага и сохранить поведение action при корректном и некорректном Dockerfile.

Функциональная приёмка не равна разрешению production rollout: исправление
masking upstream в эту задачу не входит. Canary использует контролируемые данные.

## 2. Основания и границы

В upstream `src/job/action/docker.rs::resolve_image` явно отклоняет `Dockerfile`
и пути с суффиксом `/Dockerfile`. При этом запуск готового образа, inputs, args,
mounts, обработка логов и удаление контейнера уже реализованы. Добавляется сборка,
а не второй независимый executor.

Входит:

- Linux/X64 и существующий rootless Docker daemon;
- repository actions, полученные текущим resolver/downloader;
- локальные actions, если текущий resolver уже возвращает их каталог;
- безопасное разрешение пути, Docker build context, сборка, кеш и конкурентность;
- bounded timeout/cancellation добавленной сборки;
- регрессия существующих `docker://` и pre-built metadata actions.

Не входит:

- изменения deploy.yml, action.yml или pins в пользовательских репозиториях;
- hardcoded подмена Hadolint заранее собранным образом;
- multi-platform/cross-platform builds, Windows, GHES;
- новая поддержка resolver, private registry credential helpers и job containers;
- новые build args/secrets/SSH mounts, не предусмотренные текущим action contract;
- исправление всей cancellation/post-result семантики upstream executor;
- глобальный сборщик мусора Docker/BuildKit или автоматический `docker prune`.

## 3. Контракт разрешения action

1. Resolver получает action directory и metadata по существующему пути.
2. `docker://...` и готовые image references проходят прежнюю ветку.
3. Для Dockerfile-based action разрешается только относительный путь к обычному
   файлу внутри канонического action directory. Абсолютные пути, выход через `..`
   и symlink за пределы directory отклоняются до обращения к Docker.
4. Build context — action directory, а не workspace пользовательского приложения
   и не весь Chimera root. Для `subdir/Dockerfile` корень context остаётся directory
   данного action; `COPY` трактуется относительно этого context.
5. Соблюдаются `.dockerignore` и применимые Dockerfile-specific ignore rules.
   Credential/temp/cache каталоги Chimera не должны попадать в context.
6. Symlink и специальные файлы обрабатываются без чтения содержимого за пределами
   context; Dockerfile, указывающий наружу через symlink, запрещён.

Путь передаётся Docker без shell-интерполяции. Наличие пробелов в допустимом пути
не должно менять смысл аргументов. Отказ содержит безопасную причину, не содержимое
файлов и не environment.

## 4. Сборка и исполнение

Использовать Docker Engine build API через существующий Docker-клиент Chimera;
не запускать shell с конкатенированной командой. Соединение должно выбирать тот
же rootless endpoint, что остальные Docker-операции runner. Настройка host
`DOCKER_HOST` не заменяется `/var/run/docker.sock` и не требует root/privileged.

- Перед сборкой подготовить ограниченный context и параметры Dockerfile/platform.
- Credentials для необходимых registry-запросов брать только из job-owned
  Docker config по [CHM-03](2026-09-16-chimera-job-docker-config.md), никогда из
  общего auth-файла daemon. Для публичного Hadolint registry auth не обязателен.
- Тестом подтвердить, что поддерживаемый Engine API путь соблюдает ignore rules;
  простая упаковка всего directory без фильтрации контракт не выполняет.
- Стримить build progress через существующий masking/logging pipeline job.
  Не добавлять debug-вывод environment, auth headers или raw context.
- При успешной сборке получить и проверить локальный image ID; передавать именно
  его существующему запуску, без повторного pull по имени.
- Inputs, `runs.args`, `runs.env`, entrypoint, workspace mounts и файловые команды
  продолжают обрабатываться существующим executor. Не встраивать inputs/secrets
  в Dockerfile, build args или кеш-ключ.
- Один action в пределах job использует тот же образ для pre/main/post, когда
  соответствующие entrypoints объявлены. Сохранить прежний порядок этих фаз.
- Ошибка сборки делает шаг failed; контейнер action и его main-entrypoint не
  запускаются. Нельзя fallback-ить на старый образ или объявлять успех по одному
  факту закрытия log stream.

Новая сборка должна укладываться в доступный deadline шага/job. Если deadline
не передаётся текущими интерфейсами, провести его до build path; при отсутствии
явного значения использовать существующий default timeout executor, не бесконечное
ожидание. Время ожидания lock входит в тот же бюджет.

При cancel/timeout прекратить ожидание и клиентский build stream, не запускать
контейнер и не публиковать кеш. На целевой версии Engine проверить прекращение
сборки; закрытие HTTP stream само по себе не считается доказательством. Если
выбранный API не позволяет обеспечить bounded cancellation, приёмка заблокирована:
нужен пересмотр build adapter, а не замалчивание ограничения.

## 5. Минимальный кеш и параллельность

Кеш локальный для выбранного Docker daemon. В первой версии он изолирован по
runner identity/GitHub scope; межрепозиторный общий кеш не нужен. Это исключает
выдачу образа private action другому scope и упрощает контроль auth.

Ключ включает:

- версию схемы кеша и формат build options;
- runner identity/scope и целевую OS/architecture;
- digest фактически отправленного context, включая Dockerfile и ignore semantics;
- относительный путь Dockerfile и параметры сборки, влияющие на результат.

Ref/tag сам по себе не является ключом: он может измениться. Для remote action
сохраняется resolved commit, если его предоставляет resolver; для локального
обязательно учитывается изменение содержимого. Хешировать стабильные пути,
содержимое, режимы и symlink targets, а не случайные tar timestamps/порядок файлов.

- Один daemon выполняет не более одной сборки одного ключа одновременно.
- Разные keys/runners могут собираться параллельно.
- Lock ожидается с поддержкой cancel/deadline; ошибка сборки освобождает lock.
- Кеш публикуется только после успеха и проверки image ID. Нет образа в daemon —
  cache miss и пересборка. Смена endpoint не должна использовать чужой image ID.
- Используется уникальный internal image tag/label namespace Chimera; пользовательские
  теги и образы не заменяются. Авторизация в registry не кешируется вместе с образом.
- В первой версии индекс кеша можно держать в памяти daemon; после restart cache
  miss допустим. Не обещать воспроизводимость base image с mutable tag: refresh
  базовых образов и cross-restart cache policy — отдельная задача.
- Не удалять image, используемый main/post другого job. В рамках этой задачи
  временные context-файлы убираются, успешные образы остаются в локальном Docker.

Ограничение: долговременное накопление образов не решено данной задачей. Перед
массовым rollout требуется отдельная политика retention; глобальный prune на
общем daemon не является допустимым обходным решением.

## 6. Проверки и приёмка

| ID | Проверка | Ожидаемый результат |
|---|---|---|
| D-01 | Action с `image: Dockerfile` | сборка → существующий executor → корректный exit code |
| D-02 | Dockerfile в подкаталоге; `COPY` из context | пути и build context соответствуют §3 |
| D-03 | `.dockerignore`, Dockerfile-specific ignore, symlink наружу | запрещённые данные не отправлены daemon, выход наружу отклонён |
| D-04 | Одинаковый ключ дважды; изменение файла/ref | reuse только неизменного context, иначе новая сборка |
| D-05 | Два одновременных запроса одного ключа | одна сборка; оба получают проверенный image ID |
| D-06 | Ошибка/timeout/cancel при build и ожидании lock | нет запуска main и cache entry; bounded завершение и освобождение lock |
| D-07 | Образ исчез/сменился daemon | cache miss без запуска постороннего образа |
| D-08 | Action с pre/main/post, inputs, args, env и output | один образ и корректный порядок; данные доходят существующим механизмом |
| D-09 | Существующие `docker://` и pre-built metadata actions | поведение не изменилось |
| D-10 | Hadolint по точному SHA на rootless host | корректный Dockerfile проходит; намеренно ошибочный даёт failed step |
| D-11 | Context/logs/artifacts на synthetic-secret canaries | runner не добавил auth/config/secrets в context или служебный вывод |

Тесты D-01… D-09: unit/mock плюс локальная Docker integration suite, без чужих
репозиториев. Для D-06 отдельно проверяется реальное поведение Engine, а не только
возврат `Cancelled` из Rust-функции. D-10/D-11 выполняются в разрешённом стенде;
настоящие production secrets для них не нужны.

Общая end-to-end приёмка после CHM-01/CHM-03: неизменённые pins checkout → Hadolint
→ Buildx → login → build/push → webhook/poll в контролируемом окружении. Последние
этапы имеют внешние эффекты и требуют отдельного разрешения. Успех Docker build
сам по себе не доказывает успех этого pipeline.

## 7. Выдача, зависимости и оценка

Выдача: build adapter, интеграция в существующий executor, минимальный кеш,
unit/integration tests, отчёт D-01… D-11 и документированные ограничения.
Оценка: 2–3 человеко-дня при пригодности существующего Docker API; изменение
build adapter для cancellation/ignore semantics требует пересмотра оценки.
Общая интеграционная проверка не включается повторно в эту цифру.

Разрабатывать можно на synthetic/local actions независимо от
[CHM-01](2026-09-16-chimera-registration-import.md).
Для реального общего daemon использовать job config из
[CHM-03](2026-09-16-chimera-job-docker-config.md).
Не расширять задачу до исправления всех upstream masking/post/cancellation проблем;
они остаются отдельными production gates.

## 8. Источники

- [Chimera Docker executor и отказ от Dockerfile](https://github.com/quinck-io/chimera/blob/0b3b1fe8f41b746e9886dfa7b775a145b16b157d/src/job/action/docker.rs).
- [Тесты ограничения](https://github.com/quinck-io/chimera/blob/0b3b1fe8f41b746e9886dfa7b775a145b16b157d/src/job/action/docker_test.rs).
- [Action downloader/cache](https://github.com/quinck-io/chimera/blob/0b3b1fe8f41b746e9886dfa7b775a145b16b157d/src/job/action/download.rs).
- [Job executor](https://github.com/quinck-io/chimera/blob/0b3b1fe8f41b746e9886dfa7b775a145b16b157d/src/job/execute.rs).
- [Hadolint action на требуемом SHA](https://github.com/hadolint/hadolint-action/blob/2332a7b74a6de0dda2e2221d575162eba76ba5e5/action.yml).

Локальная база сопоставления: `sandbox/vibecoder/.github/workflows/deploy.yml`
и `sandbox/infra/aspect-6/systemd/actions-runner@.service`, прочитанные 2026-09-16.
Это снимок требований шаблона, не доказательство идентичности всех старых клонов.
