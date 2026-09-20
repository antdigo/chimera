# CHM-08 — Sandboxed execution domain на один job attempt

Дата: 2026-09-20. Статус: согласованный дизайн, реализация не начата.
Целевые issues: [#36](https://github.com/antdigo/chimera/issues/36),
[#38](https://github.com/antdigo/chimera/issues/38).
Связанные lifecycle и resource issues: #40, #43–#46, #49–#51 и #54.
База: `main` commit `18961b485914330f6fafd1bf016909ffe994b71b`,
feasibility spike commit `61abcb7809257eeb9bf840a82da5129e06603b2d`.

## 1. Задача и результат

Chimera должна запускать каждый job attempt в отдельном ephemeral execution
domain на одном Linux-сервере. Domain изолирует filesystem, процессы, Docker
authority, сеть и resource accounting текущего attempt от host и соседних jobs,
а после job подтверждённо уничтожается.

Целевой deployment сохраняет ограничения оператора:

- один физический Debian/Linux server одновременно обслуживает Chimera и
  развернутые проекты;
- VM на каждый job отсутствуют;
- один `chimera` service account и один systemd unit;
- нет пула из 20–40 системных пользователей, per-job systemd services или
  собственного privileged helper;
- host jobs сохраняют произвольный Docker API, включая Buildx;
- число параллельных jobs управляется конфигурацией и масштабируется с 20 до 40;
- после job не остаётся Docker daemon, процессов или writable state.

Название production-профиля — `sandboxed`. Оно намеренно не содержит обещания
VM-grade isolation: все domains разделяют kernel production host.

## 2. Профили и граница гарантии

### 2.1 `trusted-host`

`trusted-host` сохраняет существующую модель обычного self-hosted runner. Host
steps выполняются на host, а Docker endpoint выбирается из конфигурации host.
Private `/tmp`, отдельный `DOCKER_CONFIG`, secret masking и cleanup остаются
defense-in-depth, но не образуют tenant security boundary.

Профиль остаётся default для обратной совместимости существующих установок.
Документация не называет его изолированным и рекомендует только для доверенных
workflow.

### 2.2 `sandboxed`

`sandboxed` создаёт новый shared-kernel sandbox для каждого attempt:

- private user, mount, PID, IPC, UTS, cgroup и network namespaces;
- allowlisted rootfs после `pivot_root` и отсоединения старого root;
- private rootless Docker daemon, socket и stores;
- отдельная cgroup с CPU, memory, PID и I/O limits;
- ограниченный egress и явные capability endpoints;
- fail-closed teardown и startup reconciliation.

Это container-grade, а не VM-grade isolation. Уязвимость общего kernel может
затронуть production host. В отличие от стандартного GitHub-hosted runner здесь
нет отдельной VM, настоящего host root и passwordless `sudo`.

### 2.3 Поддерживаемая платформа v1

Первый выпуск `sandboxed` поддерживает bare-metal Linux с systemd и unified
cgroup v2. macOS, запуск Chimera внутри контейнера и Linux без необходимых kernel
features получают явный preflight error. Ослабленный fallback не выполняется.

## 3. Выбранный модуль

Существующий `JobDockerConfig` уже владеет attempt directory, `work`, `tmp`,
Docker config и cleanup. Создавать рядом второй lifecycle owner нельзя. Он
эволюционирует в глубокий модуль `ExecutionDomain`, который инкапсулирует все
per-attempt ресурсы и заменяет разрозненные обязанности `JobDockerConfig`, Linux
`pre_exec`, Docker endpoint selection и process-tree cleanup.

Ожидаемый внешний interface:

```rust
pub(crate) struct ExecutionDomainRoot;
pub(crate) struct DomainPermit;
pub(crate) struct ExecutionDomain;

impl ExecutionDomainRoot {
    pub(crate) fn prepare(config: ExecutionConfig) -> Result<Self, PreflightError>;
    pub(crate) async fn reserve(&self) -> Result<DomainPermit, AdmissionError>;
    pub(crate) async fn reconcile(&self) -> Result<(), ReconcileError>;
}

impl DomainPermit {
    pub(crate) async fn provision(
        self,
        identity: AttemptIdentity,
    ) -> Result<ExecutionDomain, ProvisionError>;
}

impl ExecutionDomain {
    pub(crate) fn paths(&self) -> &DomainPaths;
    pub(crate) fn environment(&self) -> &DomainEnvironment;
    pub(crate) async fn run(&self, command: CommandSpec) -> Result<ExitStatus>;
    pub(crate) fn docker_endpoint(&self) -> &DockerEndpoint;
    pub(crate) async fn cancel(&self, reason: CancelReason) -> Result<()>;
    pub(crate) async fn destroy(self) -> Result<DestroyReport, DestroyError>;
}
```

Имена типов иллюстрируют seam, а не фиксируют каждую Rust signature. Внешний
код не получает namespace PIDs, mount handles, cgroup paths или daemon process
handles. У него есть только attempt identity, paths/capabilities, command
execution и явное уничтожение.

`ExecutionDomain` не полагается на async `Drop`. Отдельная manager task владеет
реальными ресурсами. Потеря runner-side handle инициирует cancellation и teardown;
успех фиксируется только результатом `destroy()`.

## 4. Process и trust model

```text
chimera supervisor
└── rootlesskit / execution domain
    ├── domain-init (PID 1)
    ├── rootless dockerd
    │   ├── containerd
    │   ├── BuildKit
    │   └── job containers
    └── host steps и actions
```

Supervisor остаётся снаружи namespaces. `domain-init` получает при создании
закрытый control FD; FD не присутствует в rootfs, помечен close-on-exec для
workflow children и не может быть открыт по pathname.

Workflow считается полностью недоверенным и получает полный контроль над своим
domain, включая полный API private dockerd. Security boundary проходит между
domain и host/peer attempts, а не между workflow и Docker daemon этого workflow.

Job processes запускаются с очищенным environment, `no_new_privs`, пустым
capability set, seccomp и Landlock policy. Они не могут использовать namespace
capabilities `domain-init`. Init process не dumpable, reaps descendants и является
единственной точкой запуска новых host commands.

## 5. Provisioning

Нормальный порядок:

1. Runner получает admission permit до Online polling.
2. После получения job request создаётся UUID attempt и durable journal.
3. Создаётся attempt cgroup и применяются limits.
4. RootlessKit создаёт user, mount, PID, IPC, UTS, cgroup и network namespaces.
5. В mount namespace собирается allowlisted rootfs.
6. Выполняется `pivot_root`, старый root отсоединяется через lazy unmount.
7. Запускается `domain-init` и readiness protocol.
8. Eager запускается private rootless dockerd.
9. Выполняются отрицательные filesystem/network probes и Docker ping.
10. Только после всех проверок domain переходит в `Ready` и может исполнять job.

Любая ошибка запускает rollback в обратном порядке. Shared/rootful Docker endpoint
не используется как fallback.

### 5.1 Почему Docker daemon eager

Произвольный shell-код может обратиться к Docker API без предварительного сигнала
runner. Прозрачный lazy start потребовал бы собственного Unix-socket activation
proxy с корректной обработкой параллельных соединений, readiness и timeouts.

В v1 daemon поэтому запускается на каждую активную job. Он отсутствует до job и
после подтверждённого teardown. Socket activation может появиться только как
последующая измеренная оптимизация, не как часть security boundary.

### 5.2 UID/GID prerequisites

Все domains работают от одного dedicated service account. Для него один раз
настраивается один диапазон минимум 65 536 subordinate UID/GID и устанавливаются
стандартные `newuidmap`/`newgidmap`. Feasibility spike подтвердил параллельный
запуск 40 daemon с одинаковым mapping; отдельные host users и ranges не нужны.

## 6. Rootfs contract

Rootfs строится allowlist-ом, а не overlay всего `/`. Цель — сохранить стандартные
host tools, не раскрывая host state.

Read-only inputs:

- системные executable и runtime libraries из точного allowlist (`/usr/bin`,
  `/usr/lib*`, `/bin`, `/sbin`, `/lib*`); весь `/usr` не экспортируется,
  `/usr/local` требует отдельного явного allowlist;
- проверенный immutable tool cache и actions cache;
- CA certificates и необходимые timezone/locale assets.

Generated/private state:

- минимальный `/etc` без host users, credentials и service configuration;
- новый `/proc`, относящийся к PID namespace;
- минимальный `/dev` без physical devices и Docker/containerd sockets;
- private `home`, `tmp`, `run`, `work`, Docker config/data/exec roots;
- attempt-scoped capability sockets.

Не монтируются host `/home`, `/root`, `/var/run`, `/run`, production Docker state,
kubelet/containerd sockets, SSH keys и каталоги соседних attempts.

`chroot` не используется как security boundary: prototype показал, что nested
runc может вернуться к старому mount root. Обязательны отдельный mount namespace,
`pivot_root` и отсоединение старого root.

Docker bind mounts разрешаются относительно private rootfs. Попытка bind mount
host или peer path завершается как отсутствующий source path.

## 7. Docker compatibility contract

Внутри domain задаются attempt-owned `DOCKER_HOST`, `DOCKER_CONFIG`, `HOME` и
`XDG_RUNTIME_DIR`. Эти переменные зарезервированы и не могут быть подменены через
job/step env или `$GITHUB_ENV`.

Workflow получает прямой Docker Engine endpoint без authorization proxy или
урезанного BuildKit-only protocol. Здесь «произвольный Docker API» означает
возможность клиента вызывать любые endpoints daemon; это не обещание rootful
семантики для операций, которые сам rootless Docker не поддерживает.

Обязательный compatibility set:

- pull/push/login/logout;
- build и Buildx с `docker-container` driver;
- run/create/start/stop/exec;
- images, networks и named volumes;
- bind mounts путей, присутствующих в private rootfs;
- job containers, service containers и Docker actions.

Изменённая host-семантика документируется явно:

- `--privileged` даёт полномочия только внутри user namespace;
- `--network host` означает network namespace attempt;
- `-p` публикует порт для процессов того же domain, но не на physical host;
- production Docker socket и stores недоступны;
- прямое управление host systemd и `sudo` не поддерживается.

Существующий `connect_docker(None)` в `sandboxed` запрещён. Все runner-side Docker
операции получают `DockerEndpoint` текущего domain явно.

## 8. Сеть и capability endpoints

RootlessKit запускается с private network namespace, `slirp4netns`,
`--disable-host-loopback`, выключенным IPv6 и без outer port driver. Это закрывает
прямой host loopback, но само по себе не закрывает LAN и production CIDRs.

Второй уровень — cgroup eBPF policy на `chimera.service`, установленная systemd:

- deny loopback, link-local, multicast, RFC1918, IPv6 ULA;
- deny все обнаруженные адреса host;
- deny дополнительные production CIDRs из operator policy;
- allow public Internet для registries и package repositories.

Политика относится ко всем descendants сервиса, включая host-side slirp4netns.
`sandboxed` preflight проверяет наличие cgroup eBPF support и выполняет
negative-connect probes к sentinel listeners на host addresses. Неподдерживаемая
или неработающая policy блокирует Online polling.

Доступ к локальным функциям не открывает host network. Cache, artifact и deploy
интеграции получают attempt-scoped capability и domain-local HTTP proxy либо
Unix-socket bridge. Capability отзывается до teardown. Production Docker API не
может быть таким endpoint: deploy использует отдельный узкий protocol.

Static systemd network policy генерируется/обновляется штатной install-командой
Chimera. Изменение production CIDRs требует повторного применения unit drop-in и
restart; daemon проверяет согласованность policy при старте.

## 9. Resource control и admission

Один systemd unit получает delegated cgroup v2 subtree:

```text
chimera.service
├── supervisor
├── attempt-<uuid>
└── attempt-<uuid>
```

Global service limits резервируют ресурсы production workloads. Per-attempt limits
задают fairness и предел ущерба одной job.

Обязательные controllers:

- global и per-attempt memory high/max и swap max;
- CPU quota/weight;
- process/thread limit (`pids.max`);
- I/O weight и, когда задано block device, `io.max`;
- `cgroup.kill` для teardown.

Значения не зашиваются в код. До rollout они выбираются по native benchmark на
целевом server.

Конфигурация v1:

```toml
[execution]
profile = "sandboxed"
max_active_domains = 20

[execution.resources.global]
memory_high = "..."
memory_max = "..."
memory_swap_max = "0"
cpu_quota = "..."
pids_max = "..."

[execution.resources.attempt]
memory_high = "..."
memory_max = "..."
memory_swap_max = "0"
cpu_quota = "..."
cpu_weight = 100
pids_max = "..."
```

Точный parser type и единицы будут зафиксированы implementation plan; design
требует human-readable validated values и отказ от silent fallback.

`max_active_domains` реализуется semaphore. Permit получается до Online broker
polling и удерживается до `Destroyed`. Эффективная конкурентность равна минимуму
из количества зарегистрированных runner identities и `max_active_domains`.

Переход 20→40 требует увеличить список `runners` и `max_active_domains`, затем
перезапустить daemon. Схема UID/GID и deployment topology не меняются.

Cgroups не ограничивают занимаемый filesystem space. Поэтому `sandboxed` требует
capacity-bounded Chimera storage root: отдельный filesystem/LV, project quota или
btrfs subvolume quota. Без доказанного global storage bound strong profile не
стартует. Per-attempt `io.max` ограничивает нагрузку, но не заменяет disk quota.

## 10. State machine и durable ownership

```text
Reserved
  -> Provisioning
  -> Ready
  -> Running
  -> Cleaning
  -> Destroying
  -> Destroyed
```

Ошибка после первого side effect переводит attempt в `Destroying`. Неподтверждённый
teardown переводит его в `Quarantined` и poison-ит общий `ExecutionDomainRoot`.

Имена attempt directory, RootlessKit state, Docker roots, socket и cgroup
детерминированы по UUID. Journal хранит state transitions и безопасные metadata,
но не является единственным источником ownership. Поэтому crash между созданием
ресурса и записью journal не делает ресурс недоступным reconciliation.

Journal не содержит manifest, secrets, Docker credentials или command lines.
Запись выполняется atomic replace с fsync file и parent directory для важных
переходов.

## 11. Job lifecycle и teardown

Нормальный порядок:

```text
steps
-> post-actions
-> зафиксировать JobExecutionOutcome
-> отозвать cache/deploy/artifact capabilities
-> остановить новые domain commands
-> TERM domain и bounded grace period
-> cgroup.kill / KILL fallback
-> проверить отсутствие процессов, mounts и sockets
-> удалить Docker state, rootfs и cgroup
-> опубликовать completion
-> освободить admission permit
```

Teardown идемпотентен и удаляет только ресурсы точного attempt identity. Filesystem
операции используют dirfd/openat2-style traversal без следования по symlinks и с
повторной проверкой directory identity.

Если workflow execution завершился ошибкой, но teardown подтверждён, runner может
вернуться к polling. Если teardown не подтверждён, result публикуется как failure,
после чего все runners с общим resource root прекращают polling.

## 12. Startup reconciliation

Reconciliation выполняется до GitHub sessions и Online polling:

1. daemon получает exclusive root lock;
2. сканирует только допустимые UUID attempt entries;
3. для каждого deterministic cgroup выполняет `cgroup.kill`;
4. проверяет пустой `cgroup.procs`;
5. удаляет известные sockets/state/filesystem через safe dirfd operations;
6. удаляет cgroup;
7. подтверждает пустой active resource root.

Сохранённый PID служит только диагностикой: после restart он мог быть повторно
использован. Неизвестная, symlinked или подменённая структура не удаляется
эвристически. Она переводится в quarantine, daemon не запускает jobs до ручного
разбора.

Reconciliation гарантирует local cleanup. Повторная публикация GitHub completion
и broker lease semantics относятся к #48 и не выводятся из одного filesystem
journal.

## 13. Ошибки

- `PreflightError`: отсутствуют kernel/systemd/cgroup/eBPF/storage prerequisites.
  Daemon не начинает polling.
- `AdmissionError`: лимит или global budget не позволяет зарезервировать domain.
  Runner остаётся Offline и ждёт permit.
- `ProvisionError`: domain не готов. Выполняется rollback; acquired job получает
  setup failure только после подтверждённой очистки.
- `ExecutionError`: обычная ошибка workflow; teardown остаётся обязательным.
- `PolicyViolation`: workflow пытается заменить зарезервированный endpoint/env
  или использовать запрещённую capability.
- `DestroyError`: cleanup не доказан; shared root terminally poisoned.
- `ReconcileError`: stale domain не обезврежен; daemon не стартует.

Ошибки содержат attempt ID, stage и безопасную категорию. Environment, command
payloads, registry auth, Docker config и response bodies не логируются.

## 14. Изменения существующих seams

- `JobResourceRoot` становится `ExecutionDomainRoot`; его shared poison state и
  startup ownership сохраняются.
- `JobDockerConfig` поглощается `ExecutionDomain`, а не оборачивается вторым
  lifecycle object.
- `src/job/execute.rs` делегирует host spawn в `ExecutionDomain::run`; текущий
  частичный Linux `pre_exec` удаляется после parity.
- `src/docker/client.rs` требует явный `DockerEndpoint` в `sandboxed`; local
  defaults допустимы только в `trusted-host`.
- `Runner::run_job` владеет одним domain handle от provisioning до completion.
- Cache/deploy/artifact integrations получают attempt identity и отзываемую
  capability, но не paths/sockets других modules.
- Daemon создаёт один admission controller и один domain root, общие для runners.

Новый production mode не включается частично. `profile = "sandboxed"`
принимается и валидируется конфигурацией, чтобы Plan A мог единообразно
отклонить его fail-closed при старте — до подготовки domain root, cache
listeners, runner construction или sessions. До прохождения Plans B–E и полного
release gate S-01…S-16 этот профиль не активируется и не запускает job.

## 15. Проверка и release gate

Production changes выполняются test-first. Обязательные группы:

| ID | Проверка | Ожидаемый результат |
|---|---|---|
| S-01 | Preflight без userns/cgroup v2/eBPF/quota | отказ до Online polling |
| S-02 | Fault injection после каждого provisioning шага | reverse rollback; root снова чист |
| S-03 | Host и peer filesystem sentinels | paths отсутствуют; bind mount отклонён |
| S-04 | PID/IPC/UTS isolation | peer/host процессы и IPC не видны |
| S-05 | Host/LAN/production sentinel endpoints | соединение запрещено; public registry доступен |
| S-06 | Docker run/exec/volumes/networks/binds | полный API работает внутри domain |
| S-07 | Exact pinned setup-buildx/login/build-push | BuildKit driver проходит без workflow rewrite |
| S-08 | `--privileged`, `--network host`, `-p` | полномочия и сеть не выходят из domain |
| S-09 | OOM, PID bomb, CPU и I/O saturation | лимит срабатывает; production sentinel сохраняет SLO |
| S-10 | Cancel во время step/post/BuildKit/teardown | bounded destroy; нет остаточных процессов |
| S-11 | `SIGKILL` daemon на каждой lifecycle phase | restart reconciliation очищает известные resources |
| S-12 | Symlink/path/inode replacement | чужой path не читается и не удаляется; fail closed |
| S-13 | 20 и 40 параллельных attempts | admission соблюдён; state не пересекается |
| S-14 | Две последовательные tenant waves | нет filesystem/process/Docker/credential leakage |
| S-15 | После полной idle wave | ноль dockerd/rootlesskit/containerd/BuildKit processes |
| S-16 | Native storage benchmark | startup, CPU, PSS, IOPS и cleanup измерены |

Security acceptance выполняется на native Debian/systemd host. Privileged nested
Docker может использоваться только как быстрый CI smoke test и не заменяет native
gate. Exact action tests используют synthetic registry credentials и не выполняют
production deploy.

Release #54 требует cold, warm, failure, cancel и restart waves, затем повторную
tenant wave. Профиль не считается готовым только по happy path.

## 16. Нефункциональные критерии

- Ноль per-job daemon processes после `Destroyed`.
- Никакого persistent pool Docker daemons.
- Startup и memory sizing принимаются только по PSS/native measurements, не по
  aggregate RSS nested VFS spike.
- Cleanup имеет bounded TERM phase и обязательный kill fallback.
- Любое ослабление filesystem, Docker, network или cgroup boundary является
  startup/provisioning error, а не warning.
- Работа production services на том же server должна оставаться внутри заранее
  заданного reserve/SLO во всех resource stress tests.

## 17. Не входит в первую реализацию

- VM, microVM или отдельный kernel на job;
- Windows/macOS sandboxed backend;
- запуск sandboxed Chimera внутри Kubernetes/Docker;
- transparent lazy Docker socket activation;
- внешний inbound port publishing из workflow;
- выдача workflow production Docker socket;
- автоматическое изменение произвольных deployment workflows;
- доказательство отсутствия kernel vulnerabilities;
- live reload количества runner registrations и systemd egress policy.

## 18. Источники и evidence

- [Feasibility results](../../../prototypes/attempt-isolation/RESULTS.md).
- [Prototype runbook](../../../prototypes/attempt-isolation/README.md).
- [Связанные issues и threat model](../reports/2026-09-20-chimera-attempt-isolation-related-issues.md).
- [GitHub: secure use of self-hosted runners](https://docs.github.com/en/actions/reference/security/secure-use).
- [GitHub-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners).
- [Docker rootless prerequisites](https://docs.docker.com/engine/security/rootless/).
- [RootlessKit](https://github.com/rootless-containers/rootlesskit).
- [slirp4netns filtering](https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md#filtering-connections).
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).
- [systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).
