# CHM-03 — Изолированный DOCKER_CONFIG на каждый job

Дата: 2026-09-16. Статус: проект спецификации, реализация не начата.
Целевой проект: форк `quinck-io/chimera`, не приложение sandbox-admin.
База исследования: upstream v0.1.3, commit `0b3b1fe8f41b746e9886dfa7b775a145b16b157d`.

## 1. Задача и результат

Каждый job одного Chimera daemon получает отдельный Docker config directory.
Login/logout одного job не изменяет авторизацию другого, а credentials не
сохраняются для следующего job. Пользовательские workflow менять не требуется.

Выбран per-job, а не per-runner scope: два последовательных job одной регистрации
также не должны наследовать credentials. Внутри одного job все pre/main/post
используют один directory до завершения последнего post-step.

## 2. Контекст и границы

Сейчас платформа задаёт отдельным официальным сервисам:

```text
DOCKER_HOST=unix:///run/user/1501/docker.sock
DOCKER_CONFIG=/opt/runners/<owner>--<repo>/.docker
```

Chimera запускает host-процессы через `Command::envs`, не очищая inherited process
environment. Поэтому socket можно передать через окружение daemon; отсутствие
`DOCKER_HOST` в явной map не является доказанным дефектом. Но один daemon наследует
один `DOCKER_CONFIG`, а штатной per-runner настройки нет.

Входит:

- private directory на каждую попытку выполнения job;
- явная передача пути host Node actions и shell steps;
- сохранение пути для pre/main/post и локального build adapter CHM-02;
- cleanup на штатных путях и безопасная операторская уборка остатков после crash;
- тестирование конкурентного login/logout и Buildx.

Не входит:

- полноценная изоляция tenants под общим UID, PID/mount namespaces или отдельные VMs;
- миграция содержимого старых `.docker`, tokens или credential helpers;
- поддержка job containers и переназначение пути внутри Docker actions;
- исправление общей cancellation/process-tree или post-result семантики Chimera;
- общий Docker garbage collector и очистка пользовательских config directories.

Docker actions продолжают использовать своё контейнерное окружение. Host-путь
нового `DOCKER_CONFIG` не монтируется в них автоматически: это раскрыло бы registry
credentials стороннему action. Если такой action требует registry login изнутри,
это отдельный неподдержанный в данной задаче сценарий.

## 3. Ресурс job и файловый контракт

Добавить явный job-owned ресурс, например `JobDockerConfig`, создаваемый до первого
pre-step. Жизненный цикл принадлежит обработчику job, а не action login.

Рекомендуемый layout:

```text
<chimera-root>/job-resources/<generated-attempt-id>/docker/config.json
```

`generated-attempt-id` — уникальное локальное значение, не необработанное имя repo,
runner или пользовательский путь. GitHub job ID/attempt можно хранить отдельно
как несекретные metadata для диагностики, не использовать как единственную защиту
от коллизии. Повторная попытка получает новый directory.

- Ресурс находится вне checkout и action build context; workflow cleanup workspace
  не должен удалить его перед post-actions.
- Каталоги создаются сразу с mode `0700`, initial `config.json` — `0600`, содержимое
  `{}`. Права не зависят от umask daemon. Последующие файлы Docker CLI защищены
  приватностью directory; реальное поведение atomic rewrite проверяется тестом.
- Не копировать исходный `DOCKER_CONFIG`, `$HOME/.docker/config.json`, auths,
  credHelpers/credsStore, CLI plugins или Docker contexts.
- Initial config пустой; проверяется наш сценарий с прямым `DOCKER_HOST` и установкой
  Buildx действием workflow. Зависимость workflow от заранее настроенного named
  context/helper считается отдельной несовместимостью, не скрытым fallback.
- Создание не удалось — job не начинает actions. Не fallback-ить на общий config.
- Root ресурсного поддерева не должен быть доступен на запись другим UID. Symlink
  на directory/config и выход за канонический root при создании/уборке запрещены.

## 4. Окружение и приоритеты

1. Путь помещается в явное окружение конкретного job. Не менять process-global env
   через `set_var` и аналоги: daemon обслуживает несколько jobs одновременно.
2. На фактическом host spawn гарантировать `DOCKER_CONFIG=<job directory>` для
   всех Node/shell pre/main/post. Остальные environment values сохраняют прежние
   правила; `DOCKER_HOST`, `XDG_RUNTIME_DIR` и `PATH` не теряются.
3. Переменная зарезервирована runner для host steps. Попытка изменить её через
   job/step env или `$GITHUB_ENV` на другой путь завершается явной безопасной
   ошибкой до запуска затронутого шага. Совпадающее значение допустимо.
4. Не переписывать shell-скрипты. Явные `docker --config ...` либо `export` внутри
   пользовательского процесса технически могут обойти настройку; это не security
   boundary от злонамеренного job под тем же UID.
5. Node action и его post получают идентичный путь; сохранённые action states не
   должны ссылаться на уже удалённый directory.
6. Build adapter CHM-02, работающий через Engine API, получает ресурс явно. Сам
   Engine API не читает `DOCKER_CONFIG` из environment: при необходимости adapter
   читает поддержанные auth entries именно из этого job config и формирует запрос,
   не используя глобальные credentials. Для public pulls auth не требуется.

Зарезервированная переменная — осознанное ограничение форка, документируемое
оператору. В проверенном шаблоне vibecoder переопределений `DOCKER_CONFIG` нет;
совместимость всех исторических клонов этим не доказана.

## 5. Жизненный цикл и ошибки

Нормальный путь:

```text
создать ресурс → pre/main steps → post steps → cleanup ресурса → завершить job
```

- Cleanup вызывается и при failed/cancelled job и ошибке pre-step. Он выполняется
  после завершения post-фазы, а не после успешного main или первого logout.
- Не полагаться только на `docker/login-action` logout или workflow cleanup.
- Удаляется только сгенерированное поддерево текущего job, без обхода symlink и
  без глобальных glob/prune операций. Общий daemon config и соседние jobs не трогаются.
- Cleanup идемпотентен: отсутствующий directory означает успех.
- Ошибка удаления не замалчивается: безопасная диагностика и отметка незавершённой
  уборки; успешный job нельзя объявлять полностью очищенным. Если итог ещё не
  опубликован, cleanup failure переводит успешный job в failed; cancelled/failed
  не превращаются в success. Это локальная семантика нового ресурса, не изменение
  трактовки всех upstream post-actions.
- При restart daemon получает exclusive ownership root и проверяет ресурсное
  поддерево до подключения runner sessions. Любой оставшийся directory вызывает
  отказ старта с категорией `stale-job-resources`; автоматического удаления в v1
  нет. Это относится и к остатку после ошибки cleanup, не только после crash.
- Для root используется единый lifecycle lock; при наличии CHM-01 переиспользуется
  его блокировка, без второго несовместимого механизма. Второй daemon с тем же
  root отказывается стартовать, а не убирает ресурсы первого.
- Операторская процедура: остановить сервис, обеспечить завершение всех процессов
  его изолированной service cgroup и связанных с экспериментом Docker-операций,
  проверить владельца и точный путь оставшегося generated directory, получить
  разрешение на удаление только этого directory и повторить старт. Credential-файлы
  для диагностики не открывать. Пользовательские/соседние каталоги не удалять.
- Если сервис не имеет контролируемой process boundary или процессы могли её
  покинуть, оператор сначала устанавливает отсутствие потребителей; при
  неопределённости cleanup и restart не выполняются. PID одного daemon не служит
  доказательством отсутствия потомков. Автоматическое определение всех reparented
  процессов и durable ownership protocol вынесены за scope v1.

Приватный directory не устраняет известный upstream пробел process-tree kill.
Проверка cancellation должна отмечать оставшихся потомков; нельзя заявлять
секреты уничтоженными только по возврату `Cancelled` или unlink файла.

## 6. Безопасность и диагностика

В логах допустимы этап lifecycle, категория ошибки и несекретный локальный ID.
Не логировать содержимое `config.json`, registry auth, stdin `docker login`,
полное окружение или credential-bearing HTTP headers. Тестовые маркеры — только
синтетические, не production tokens.

Ожидаемый эффект — отсутствие случайных конфликтов credentials между jobs.
Это не защита от чтения чужого файла процессом с тем же `sandbox-builder` UID,
не изоляция Docker daemon и не решение известного дефекта masking Chimera.

## 7. Приёмочные проверки

| ID | Проверка | Ожидаемый результат |
|---|---|---|
| C-01 | Два job одновременно | разные directories; каждый process видит собственный config |
| C-02 | Два последовательных job одного runner | новый пустой config; credentials предыдущего не наследуются |
| C-03 | Login A и B в один registry, logout A | B сохраняет свои credentials и успешно выполняет следующую registry-операцию |
| C-04 | Main завершился, post ещё работает | directory существует; main и post видят один путь |
| C-05 | Success/failure/cancel/pre-error | cleanup вызывается после post; соседние каталоги не затронуты |
| C-06 | Read-only root, ошибка создания/удаления | нет fallback на shared config; ошибка/неполная уборка явно отражены |
| C-07 | Остаток после crash/cleanup failure, в том числе при живом потомке | отказ старта до подключения sessions; directory нетронут; после контролируемой операторской уборки старт разрешён |
| C-08 | umask 000, symlink, коллизия ID, второй daemon | приватные права с момента создания; небезопасные операции отклонены |
| C-09 | Переопределение через env/GITHUB_ENV | безопасный отказ по §4; нет утечки глобального environment между jobs |
| C-10 | Rootless Buildx и pins нашего workflow | setup → login → build/push → post работают с job config и исходным socket |
| C-11 | Host config заполнен synthetic auth/contexts | job стартует пустым; host config не прочитан для копирования и не изменён |

C-03 проверяется на локальном тестовом registry с различимыми синтетическими
учётными данными; проверка только различия строк путей недостаточна. C-10 —
rootless integration на этом же локальном registry и synthetic account, включая
установку/cleanup Buildx plugin. Версии actions сохраняются, но в тестовом harness
registry/image inputs направляются локально; пользовательский workflow не меняется.
Это не end-to-end проверка неизменённого deploy.yml. GHCR push и deploy в C-10
запрещены; реальный unchanged-workflow canary — отдельный разрешаемый этап.

## 8. Выдача, зависимости и оценка

Выдача: job resource lifecycle, явная env propagation, cleanup/recovery policy,
конкурентные тесты, инструкция нового layout и отчёт C-01… C-11.

Оценка полного заявленного scope v1, включая C-01… C-11 и отказ старта при
остаточных ресурсах: 1,5–2,5 человеко-дня. Это уточнение ранней оценки 0,5–1 дня,
которая покрывала только базовый job config и штатный cleanup. Автоматическое
восстановление после crash с определением живых потомков в эту оценку не входит.
Общий online canary считается отдельно; принимать задачу только по happy path нельзя.

[CHM-01 — импорт](2026-09-16-chimera-registration-import.md) не нужен для local
unit/integration tests. [CHM-02 — Dockerfile actions](2026-09-16-chimera-dockerfile-actions.md)
использует этот ресурс для job-scoped auth. Полный unchanged workflow проверяется
после обеих доработок. Массовый rollout не входит в задачу.

## 9. Источники

- [Job subprocess environment и post-loop](https://github.com/quinck-io/chimera/blob/0b3b1fe8f41b746e9886dfa7b775a145b16b157d/src/job/execute.rs).
- [Runner base environment](https://github.com/quinck-io/chimera/blob/0b3b1fe8f41b746e9886dfa7b775a145b16b157d/src/runner/env.rs).
- [Runner job lifecycle](https://github.com/quinck-io/chimera/blob/0b3b1fe8f41b746e9886dfa7b775a145b16b157d/src/runner/instance.rs).
- [Config и paths](https://github.com/quinck-io/chimera/blob/0b3b1fe8f41b746e9886dfa7b775a145b16b157d/src/config.rs).

Локальный контракт: `sandbox/infra/aspect-6/systemd/actions-runner@.service` и
`sandbox/vibecoder/.github/workflows/deploy.yml`, прочитанные 2026-09-16. Существующие
`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp` не переносятся в один новый service
автоматически; его проектирование и rollout требуют отдельного согласования.
