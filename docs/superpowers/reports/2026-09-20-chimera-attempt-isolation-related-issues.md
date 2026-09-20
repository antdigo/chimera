# Связанные требования к изоляции job/attempt в Chimera

- Дата: 2026-09-20
- Репозиторий: `antdigo/chimera`
- Исходная точка кода: [`b83fd177de25656facc464bdfb0ea9cd67749c15`](https://github.com/antdigo/chimera/commit/b83fd177de25656facc464bdfb0ea9cd67749c15)
- Основные задачи: [#36](https://github.com/antdigo/chimera/issues/36), [#38](https://github.com/antdigo/chimera/issues/38)

## Итог

#36 и #38 следует проектировать как одно изменение: **одноразовый execution
domain на каждый job attempt**. Граница должна одновременно охватывать процессы,
файловую систему, writable runtime state, Docker/BuildKit API и stores, сетевую
доступность внутренних сервисов, лимиты ресурсов и весь lifecycle от acquisition
до cleanup/reconciliation.

Исправление только mount namespace, UID, `DOCKER_CONFIG`, имён builder или labels
не выполняет требования. Полный Docker API общей daemon остаётся обходом любой
файловой изоляции: job может попросить daemon прочитать или примонтировать host
path. Обратное тоже верно: отдельный Docker endpoint без изоляции host-процессов
не закрывает чтение workspace, credentials, `/proc` и writable tool state.

Для рассматриваемого deployment действует дополнительное ограничение: имеется
только один Linux server, он одновременно является build host и размещает
production workloads; отдельные VM, 20 системных пользователей и отдельный
привилегированный Chimera helper неприемлемы. Поэтому практический target —
**один Chimera service account и создаваемый самим daemon per-attempt sandbox на
общем kernel**. Он всё равно требует отдельного root filesystem/overlay,
user+mount+PID+network namespaces, cgroup и отдельного rootless Docker daemon без
доступа к production Docker socket.

Host jobs обязаны сохранять совместимость с произвольным Docker API, а не только
с `login` и `buildx build/push`. Поэтому узкий BuildKit-only endpoint исключён:
каждый attempt должен получать полный Docker-compatible API собственного daemon.

Это более слабая граница, чем VM: kernel и физические CPU/RAM/disk/network
остаются общими с production. Её нельзя описывать как VM-equivalent или как
защиту от kernel escape. Текущая реализация user+mount namespace только для
`/tmp` до такого профиля не дотягивает.

## Результат feasibility prototype

После исходного исследования выполнен throwaway-прототип:
[`prototypes/attempt-isolation`](../../../prototypes/attempt-isolation/README.md).
Полные результаты и ограничения зафиксированы в
[`RESULTS.md`](../../../prototypes/attempt-isolation/RESULTS.md).

В nested Linux-стенде 20 и 40 rootless Docker daemon одновременно стартовали под
одним UID и одним одинаковым subordinate-ID mapping. Прогоны заняли 11 и 22
секунды соответственно; после cleanup осталось 0 процессов. Это подтверждает
техническую возможность масштабировать число endpoints без 20/40 host users.

Прототип также подтвердил обязательность единой filesystem/Docker границы:
раздельные socket и stores не мешают daemon прочитать peer path через bind mount.
`chroot` тоже недостаточен — runc вернулся к старому mount-root. После настоящего
`pivot_root` с detach старого корня сохранились `run`, `exec`, volumes, собственные
bind mounts и `buildx` с `docker-container` driver, а host/peer paths стали
недоступны.

Idle cost оказался существенным: 20 daemon дали 100 процессов и суммарный RSS
3 380 760 KiB, 40 daemon — 200 процессов и 6 733 028 KiB. Это nested `vfs` RSS,
не Debian sizing, но направление однозначно: daemon должен создаваться лениво и
уничтожаться после job; держать pool daemon в простое нельзя.

## Ограничения single-server deployment и проверка реализуемости

### Что можно сделать одним сервисом без 20 host users

Один непривилегированный процесс Chimera может создавать per-attempt user, mount,
PID, UTS, IPC и network namespaces. В каждом sandbox можно собрать минимальный
rootfs, примонтировать только immutable runtime inputs и private writable areas,
смонтировать новый `/proc`, очистить env, сбросить capabilities, применить
`no_new_privs`, seccomp и Landlock. Landlock предназначен для unprivileged
sandboxing, наследуется дочерними процессами и может дополнительно ограничить
filesystem, TCP ports, UNIX sockets и signals, но имеет ABI-dependent coverage и
не заменяет namespaces/rootfs: [Linux kernel Landlock documentation](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html).

Per-attempt cgroups можно создавать из одного systemd service без отдельного
helper, если unit один раз установлен с `Delegate=` и нужными controllers;
официальная документация systemd прямо связывает delegation с управлением
дочерними cgroups: [systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).

Таким образом, host-process часть #36 реализуема как self-contained Rust launcher
внутри текущего daemon. Не нужны 20 `/etc/passwd` entries. Обязательные host
prerequisites при этом всё равно остаются: подходящий Linux kernel/LSM, разрешённые
unprivileged user namespaces и cgroup delegation.

### Жёсткое ограничение: Docker-compatible rootless daemon

Exact workflows используют Docker API и `setup-buildx`/`docker-container` driver,
поэтому sandbox нуждается не только в BuildKit RPC, а в принадлежащем attempt
Docker-compatible endpoint. Доступ к production/shared Docker socket недопустим:
Docker документирует, что клиент полного daemon API может примонтировать host `/`
и фактически получает власть уровня host daemon:
[Docker daemon attack surface](https://docs.docker.com/engine/security/#docker-daemon-attack-surface).

Официальный rootless Docker требует `newuidmap`/`newgidmap` и минимум 65 536
subordinate UID/GID для запускающего пользователя. Без capability в parent user
namespace Linux разрешает записать в `uid_map`/`gid_map` только одну строку,
отображающую собственный effective ID. Поэтому single-ID namespace достаточно
для простого host command sandbox, но не является поддерживаемой основой
полноценного Docker image/runtime с несколькими UID/GID:
[Docker Rootless prerequisites](https://docs.docker.com/engine/security/rootless/),
[user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html).

Отсюда следует важная граница решения:

- не нужны 20 системных users и 20 отдельных subuid configurations;
- потенциально достаточно **одного** dedicated `chimera` account с одним
  выделенным subuid/subgid range и установленными стандартными `uidmap` helpers;
- per-attempt daemons должны иметь разные namespace/rootfs, socket, state/data
  roots и cgroups, а workflow видит только свой socket;
- stock RootlessKit отображает в создаваемый user namespace все найденные ranges,
  а не распределяет непересекающиеся slices между параллельными instances.
  Поэтому повторное использование одного mapping 20 rootless-daemon instances,
  его достаточность для принятого threat model и совместимость exact actions
  нельзя считать доказанными заранее — нужен отдельный feasibility prototype под
  #38/#49/#50 до утверждения design;
- если запрещены даже один subuid/subgid range и стандартные
  `newuidmap`/`newgidmap`, то strong #38 для неизменённых Docker workflows
  **неразрешим при заданных ограничениях**. Тогда требуется ослабить threat model,
  изменить workflows/build backend либо разрешить один из исключённых механизмов.

Запуск `docker:dind-rootless` через production Docker не является простым
безопасным обходом: официальный Docker требует для rootless DinD `--privileged`,
чтобы отключить seccomp, AppArmor и mount masks:
[Docker Rootless DinD](https://docs.docker.com/engine/security/rootless/tips/#rootless-docker-in-docker).
Docker также предупреждает, что privileged container способен получить контроль
над host, поэтому такой sidecar неприемлем рядом с production workloads:
[docker run --privileged](https://docs.docker.com/reference/cli/docker/container/run/#privileged).

### Оценка вариантов

| Вариант | Deployment | Выполнение #36/#38 | Вывод |
|---|---|---|---|
| Один Chimera service + встроенный namespace/Landlock/seccomp launcher + per-attempt rootless dockerd | Один systemd unit и один service account; требуются kernel features, `Delegate=`, rootless Docker prerequisites и, вероятно, один subuid/subgid range | Наиболее близкий вариант; сохраняет shared-kernel risk, требует prototype Docker concurrency и network policy | Рекомендуемый design candidate |
| Один Chimera service + single-ID user namespaces, без subuid/helpers | Самый простой | Может существенно закрыть host FS/process часть #36, но не даёт поддерживаемый generic rootless Docker domain для exact workflows | Только частичное решение; #38 остаётся open |
| Shared production Docker + authorization proxy/labels | Просто | Не создаёт security boundary для широкого API, bind mounts и BuildKit; ошибки proxy затрагивают production daemon | Не принимать как закрытие P0 |
| Per-attempt `docker:dind-rootless` containers через production daemon | Внешне просто | Официальный путь требует `--privileged`; повышает риск production host и оставляет общий outer daemon | Не использовать |
| Общий Docker/BuildKit, но private `DOCKER_CONFIG` | Уже реализовано | Изолирует credentials от случайных коллизий, не API authority и stores | Defense-in-depth, не #38 |
| Host sandbox + изменённый workflow, который отправляет build в ограниченный builder service | Один server возможен | Может убрать Docker API из job, но требует нового узкого build protocol и нарушает exact-workflow compatibility | Отдельный продуктовый выбор, не прозрачный fix |

Последний вариант также не удовлетворяет подтверждённому требованию произвольного
Docker API в host jobs, поэтому не рассматривается как целевой backend.

### Риски для production workloads на том же host

Даже рекомендуемый single-service candidate обязан явно зафиксировать остаточные
риски:

- общий kernel означает общий kernel attack surface; namespace/Landlock/seccomp
  только снижают его, но не устраняют;
- CPU, memory, PIDs, page cache, disk space/IOPS и network bandwidth физически
  общие, поэтому cgroups/admission/reserve из #50 обязательны до rollout;
- production Docker/Podman/containerd sockets, kubelet sockets, host `/proc`,
  `/sys`, devices и service credentials не должны присутствовать в sandbox rootfs;
- network namespace должен запрещать доступ к localhost/host bridge и production
  control/data services, кроме явно выданных endpoints. Rootless user-mode
  networking или заранее настроенная host policy становятся deployment
  prerequisite; один Landlock port filter не выражает полный destination policy;
- build cache и image layers нельзя размещать в production daemon stores;
- ошибка destroy/reconciliation блокирует новый assignment, но не должна запускать
  global Docker prune или затронуть production resources.

Если оператор не принимает эти shared-kernel residual risks, при запрете VM на
одном host нет технически честного способа сохранить сильный tenant-isolation
claim; тогда jobs должны считаться trusted относительно этого server.

## Что подтверждает текущий код

1. `JobDockerConfig` уже создаёт UUID attempt directory, но внутри него находятся
   только Docker CLI config и private temp directory. Workspace остаётся путём
   `work/<runner>/<repo>/<repo>`, runner temp — `tmp/<runner>`, а tool cache общий:
   [docker_config.rs:207-219](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/docker_config.rs#L207-L219),
   [workspace.rs:19-45](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/workspace.rs#L19-L45).
2. Linux host spawn делает только `CLONE_NEWUSER | CLONE_NEWNS`, после чего bind
   mounts private directory на `/tmp`. PID и network namespaces, отдельный rootfs
   и cgroup здесь не создаются; README прямо говорит, что это не полная tenant
   isolation: [execute.rs:762-815](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/execute.rs#L762-L815),
   [README.md:119-150](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/README.md#L119-L150).
3. `Command` не вызывает `env_clear()`: он удаляет только унаследованный
   `DOCKER_CONFIG`, затем добавляет job env. Поэтому не перечисленные в base env
   переменные daemon, включая `HOME`, `XDG_*` и возможный `DOCKER_HOST`, продолжают
   наследоваться: [execute.rs:700-724](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/execute.rs#L700-L724),
   [env.rs:61-161](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/runner/env.rs#L61-L161).
4. Внутренние container/service workloads подключаются к local-default Docker
   endpoint; host Docker CLI также получает унаследованный endpoint. Это общий
   authority, а не job boundary: [instance.rs:774-803](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/runner/instance.rs#L774-L803),
   [client.rs:10-18](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/docker/client.rs#L10-L18).
5. Workspace command files имеют фиксированные имена; чтение следует текущему
   path, а очистка обычной записью следует symlink и игнорирует ошибки. Workspace
   cleanup пропускает runner temp failure как warning, а вызывающий код также
   продолжает после этой ошибки: [workspace.rs:38-69](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/workspace.rs#L38-L69),
   [workspace.rs:145-214](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/workspace.rs#L145-L214),
   [instance.rs:821-829](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/runner/instance.rs#L821-L829).
6. При timeout/cancel `run_process` убивает непосредственный child и сразу
   возвращается; отдельной process group/cgroup и ожидания всего дерева нет:
   [execute.rs:855-931](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/execute.rs#L855-L931).
   Cancellation poller извлекает `job_id`, но не сравнивает его с активной job:
   [cancel.rs:16-53](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/runner/cancel.rs#L16-L53).
7. Post steps идут в обратном порядке, но получают исходный уже отменённый token;
   их failure не меняет conclusion: [execute.rs:1509-1656](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/execute.rs#L1509-L1656).
   По shutdown timeout daemon вызывает `abort_all`, поэтому async cleanup после
   следующего `.await` не гарантирован: [daemon.rs:564-584](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/daemon.rs#L564-L584).
8. Cache API после #58 проверяет bearer capability и точный repo/ref scope и
   отзывает capability на job unwind; это хороший образец control-plane
   capability, но сам сервер по-прежнему слушает все интерфейсы и не является
   заменой execution isolation: [cache/server.rs:49-96](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/cache/server.rs#L49-L96),
   [cache/server.rs:149-204](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/cache/server.rs#L149-L204),
   [instance.rs:143-205](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/runner/instance.rs#L143-L205).
9. В конфигурации нет глобальных CPU/RAM/IO/PID/admission budgets, только daemon,
   cache и список runners: [config.rs:16-45](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/config.rs#L16-L45).

Это подтверждает единую гипотезу первопричины: Chimera имеет набор локальных
job-scoped каталогов и cleanup guards, но пока не имеет одного объекта владения,
который представляет весь attempt и атомарно ограничивает/уничтожает все его
ресурсы.

## Требования, которые должны войти в единое архитектурное решение

### 1. Attempt как единица security и lifecycle

Один неизменяемый `attempt_id` должен связывать job identity, execution domain,
filesystem, process tree/cgroup, Docker endpoint и stores, network policy,
capabilities, logs, artifacts, resource accounting и recovery journal. Все
операции должны принимать этот identity явно; поздняя cancel/cleanup команда
старого attempt не должна затронуть новый.

Минимальная модель состояний:

```text
acquired -> provisioning -> running -> post-cleanup -> destroying
         -> finalizing -> released
                         \-> quarantined/reconcile
```

`released` разрешён только после доказанного уничтожения execution domain и
отзыва job-scoped capabilities. Неопределённый результат cleanup переводит слот
в `quarantined`, а не в повторное использование.

Это объединяет требования [#36](https://github.com/antdigo/chimera/issues/36),
[#38](https://github.com/antdigo/chimera/issues/38),
[#40](https://github.com/antdigo/chimera/issues/40),
[#44](https://github.com/antdigo/chimera/issues/44),
[#45](https://github.com/antdigo/chimera/issues/45) и
[#46](https://github.com/antdigo/chimera/issues/46).

### 2. Полная data-plane граница

Внутри attempt должны находиться:

- private root filesystem/workspace, `/tmp`, `HOME`, `XDG_*`, runner temp и
  writable tool overlay;
- отдельные PID/process tree и cgroup с TERM -> KILL -> confirmed-dead contract;
- очищенное окружение по allowlist; supervisor registration credentials и host
  service environment не передаются;
- собственный Docker/BuildKit endpoint и private container/image/volume/build
  state;
- job network namespace/policy с доступом только к необходимым GitHub, registry,
  proxy/Deploy API и выданным capability services;
- CPU, RAM, IO, PID и disk/cache quota, учитываемые общим admission controller.

В выбранном single-host namespace-профиле эти свойства должны быть реализованы
вместе; проброс общего Docker socket запрещён. Полный Docker API допустим только
к daemon, чья authority и mount view не выходят за границы данного attempt.

Эта часть покрывает [#36](https://github.com/antdigo/chimera/issues/36),
[#38](https://github.com/antdigo/chimera/issues/38) и resource ownership из
[#50](https://github.com/antdigo/chimera/issues/50). Закрытая
[#37](https://github.com/antdigo/chimera/issues/37) становится defense-in-depth
инвариантом private `/tmp`, а не самостоятельной границей безопасности.

### 3. Безопасный command/state bridge

`GITHUB_OUTPUT`, `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_STATE` и
`GITHUB_STEP_SUMMARY` — протокол между недоверенным step и runner. Они должны
жить внутри execution domain и читаться trusted guest agent по per-step
непредсказуемым именам через уже открытый directory handle, с `O_NOFOLLOW`,
проверкой regular-file identity, лимитами размера и явными ошибками. Прямой
writable bind mount host command files в guest создаст privileged confused-deputy
boundary и не должен быть основным дизайном.

State разрешён только для main -> post той же action instance. Summary и
declared outputs передаются supervisor как типизированный bounded result, а не
как произвольный host path. Это обязательная часть execution-domain API из
[#43](https://github.com/antdigo/chimera/issues/43) и основа для
[#52](https://github.com/antdigo/chimera/issues/52).

### 4. Cancellation, post и cleanup — разные фазы

Workload cancellation token не должен немедленно запрещать cleanup. После cancel
нужен отдельный ограниченный cleanup budget внутри общего GitHub grace:

1. остановить новые side effects и обычные steps;
2. выполнить reverse-order posts с сохранённым action state;
3. независимо удалить job-owned Docker/process resources;
4. отозвать cache/runtime capabilities;
5. уничтожить execution domain и подтвердить отсутствие процессов;
6. только затем завершить finalization/release либо quarantine.

Post failure обязан быть видим и влиять на итог по контракту runner, но security
cleanup не может зависеть от успешности action post. Требования происходят из
[#44](https://github.com/antdigo/chimera/issues/44),
[#45](https://github.com/antdigo/chimera/issues/45),
[#40](https://github.com/antdigo/chimera/issues/40) и
[#46](https://github.com/antdigo/chimera/issues/46).

### 5. Supervisor остаётся вне execution domain

GitHub broker credentials, registration keys, lease/completion state, recovery
journal, cache authority и capacity accounting остаются у supervisor. Внутрь
передаются только job-scoped/expiring tokens и необходимые job data. Lease должен
стартовать сразу после acquisition, существовать через provisioning, execution,
cleanup и finalization; подтверждённая потеря lease останавливает side effects
данного attempt. Completion retry/reconciliation не должен повторно запускать
steps.

Это связывает execution domain с [#48](https://github.com/antdigo/chimera/issues/48).
Текущий код подключает live feed до запуска heartbeat и считает non-success renew
обычным `Ok(())`, что подтверждает необходимость отдельного supervisor lifecycle:
[instance.rs:905-920](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/runner/instance.rs#L905-L920),
[job/client.rs:150-175](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/client.rs#L150-L175).

### 6. Shared caches только как сервисы или immutable inputs

- Cache API из закрытой #42 сохраняется как отдельный capability service:
  scope/owner/expiry/revocation проверяются server-side. Execution domain получает
  только capability своей job; network policy дополнительно ограничивает ingress.
- Node/action cache из #51 нельзя оставлять writable mount внутри job. Supervisor
  делает single-flight download, проверяет exact artifact identity и публикует
  immutable content. Attempt получает read-only mount/image layer либо private
  copy/overlay.
- Exact Node 24 и системные зависимости из #49 должны входить в versioned guest
  image/runtime profile. Provisioning failure завершает setup до deploy side
  effects, без runtime fallback.

Текущий `ensure_node` допускает fallback отсутствующего major на default, а Node
и action downloads выполняют отдельную check-then-download последовательность:
[node.rs:39-58](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/node.rs#L39-L58),
[node.rs:84-113](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/node.rs#L84-L113),
[action/download.rs:177-200](https://github.com/antdigo/chimera/blob/b83fd177de25656facc464bdfb0ea9cd67749c15/src/job/action/download.rs#L177-L200).

## Матрица связанных DPL issues

| Issue | Состояние | Роль в дизайне |
|---|---:|---|
| [#35 DPL-01](https://github.com/antdigo/chimera/issues/35) | closed | Отдельная expression compatibility. Сохранить как regression gate: разные attempts не смешивают secrets context. |
| [#36 DPL-02](https://github.com/antdigo/chimera/issues/36) | open | Ядро: filesystem/process/env/tool-state/supervisor isolation. |
| [#37 DPL-03](https://github.com/antdigo/chimera/issues/37) | closed | Private `/tmp` уже реализован; инвариант общего domain, но не его замена. |
| [#38 DPL-04](https://github.com/antdigo/chimera/issues/38) | open | Ядро: отдельная Docker/BuildKit authority и private stores. |
| [#39 DPL-05](https://github.com/antdigo/chimera/issues/39) | closed | Отдельная output/export policy; результат должен пройти typed domain bridge. |
| [#40 DPL-06](https://github.com/antdigo/chimera/issues/40) | open | Ядро lifecycle: attempt-unique paths, fail-closed cleanup, quarantine. |
| [#41 DPL-07](https://github.com/antdigo/chimera/issues/41) | closed | Cross-cutting redaction; сохранить на всех новых domain/control-plane sinks. |
| [#42 DPL-08](https://github.com/antdigo/chimera/issues/42) | closed | Отдельный capability service; интегрировать выдачу/отзыв с attempt lifecycle. |
| [#43 DPL-09](https://github.com/antdigo/chimera/issues/43) | open | Ядро interface: безопасный command/state bridge без host-path confused deputy. |
| [#44 DPL-10](https://github.com/antdigo/chimera/issues/44) | open | Ядро lifecycle: identity-aware cancel и остановка всего domain/process tree. |
| [#45 DPL-11](https://github.com/antdigo/chimera/issues/45) | open | Ядро lifecycle: отдельный cleanup token/budget, posts и supervisor cleanup. |
| [#46 DPL-12](https://github.com/antdigo/chimera/issues/46) | open | Ядро lifecycle: shutdown journal, bounded drain, startup reconciliation. |
| [#47 DPL-13](https://github.com/antdigo/chimera/issues/47) | open | Отдельный control-plane transport: bounded/non-blocking logs. Domain API должен поддержать backpressure/drop policy. |
| [#48 DPL-14](https://github.com/antdigo/chimera/issues/48) | open | Supervisor orchestration: lease от acquisition до finalization и идемпотентный completion. |
| [#49 DPL-15](https://github.com/antdigo/chimera/issues/49) | open | Runtime image/profile qualification; влияет на provisioning, но не является isolation mechanism. |
| [#50 DPL-16](https://github.com/antdigo/chimera/issues/50) | open | Часть domain/admission architecture: per-attempt quotas и общий capacity budget. |
| [#51 DPL-17](https://github.com/antdigo/chimera/issues/51) | open | Отдельный immutable provisioning cache; нельзя отдавать job writable shared cache. |
| [#52 DPL-18](https://github.com/antdigo/chimera/issues/52) | open | Отдельный Results/artifact protocol; требует scoped typed egress из domain. |
| [#53 DPL-19](https://github.com/antdigo/chimera/issues/53) | open | Отдельная правка внешних workflow templates/Deploy API polling; выполнять параллельно, не включать в sandbox implementation. |
| [#54 DPL-20](https://github.com/antdigo/chimera/issues/54) | open | Обязательный release gate для всего решения: 20 concurrent attempts и следующая tenant wave. |

## Что остаётся отдельными задачами

Не следует расширять реализацию #36/#38 до полного исправления всех DPL issues:

- #35, #39, #41 и #42 уже закрыты отдельными изменениями. Их контракты становятся
  regression requirements, но не должны переписываться вместе с sandbox.
- #47 требует независимого bounded transport/backpressure design. Изоляция лишь
  задаёт канал и запрещает блокировать domain lifecycle.
- #48 — control-plane state machine. Она должна использовать attempt identity и
  уничтожение domain, но GitHub lease/retry semantics остаются отдельным модулем.
- #49 и #51 — provisioning/image/cache. Они обязаны предоставить проверенные
  immutable inputs, но могут разрабатываться независимо от sandbox launcher.
- #52 — Results/artifact compatibility и authorization. Sandbox задаёт safe egress,
  но не реализует GitHub artifact protocol автоматически.
- #53 находится во внешних workflow repositories и не зависит от деталей
  namespace launcher, кроме общей cancellation deadline.
- #54 — не implementation issue, а финальная квалификация и release gate.

## Рекомендуемый порядок реализации

### Этап 0. Зафиксировать threat model и backend contract

Зафиксировать единственный целевой профиль
`single-host-rootless-attempt`: один service account, один daemon process,
per-attempt namespaces/rootfs/cgroup/private Docker и явная оговорка shared-kernel
risk. Отдельно определить degraded `trusted-workflow` mode без private Docker:
он может быть полезен эксплуатационно, но не закрывает #36/#38 и не должен иметь
тот же security label.

Launcher должен реализовать интерфейс `AttemptDomain`: `provision`,
`exec_step`, `cancel_workload`, `run_cleanup`, `collect_result`, `destroy`,
`reconcile`. Одновременно зафиксировать quotas и hardware assumptions из #50,
runtime prerequisites из #49 и capability/egress contract из #42/#43/#52.

До основного плана выполнить короткий feasibility gate: один service account,
20 параллельных isolated rootless Docker daemons с exact setup-buildx/build-push,
раздельными sockets/stores и synthetic cross-attempt probes. Gate должен отдельно
проверить stock RootlessKit mapping одного subuid/subgid range, реальную
недоступность sibling sockets/stores/processes и полный Docker API (`run`, `exec`,
volumes, bind mounts, Buildx). Отрицательный результат фиксирует несовместимость
требований, а не повод перейти к shared production daemon.

### Этап 1. Создать attempt ownership model

Ввести journal/state machine, attempt-scoped resource registry и quarantine без
ещё одного частичного sandbox. Это общая основа #36/#38/#40/#44/#46 и защита от
stale operations.

### Этап 2. Реализовать неделимое ядро #36 + #38 + #43 + #50

Создать execution domain, private filesystem/env, private Docker daemon/stores,
cgroup/quota/network policy и безопасный command bridge. Эти части нельзя
выпускать раздельно: любая отсутствующая грань оставляет прямой обход остальных.

Startup latency уменьшается immutable подготовленным rootfs/runtime layer и
supervisor-owned single-flight cache. Writable rootfs, daemon data-root и overlay
attempt не переиспользуются. Число одновременно активных builds `B` и допустимое
число rootless daemons выбираются только по измерениям #50 на том же production
server с заранее заданным reserve для deployed projects.

### Этап 3. Завершить lifecycle #44 + #45 + #40 + #46

Привязать job-id-aware cancellation к domain, добавить отдельный cleanup grace,
reverse-order posts, подтверждённое уничтожение и startup reconciliation. Только
после этого разрешать повторное назначение runner/slot.

### Этап 4. Подключить control-plane services

Интегрировать уже реализованный cache capability (#42), lease/completion (#48),
bounded logs (#47), immutable runtime/action provisioning (#49/#51) и scoped
summary/artifact egress (#52). Каждый сервис получает attempt identity и
отзываемую capability; ни один не получает общий writable host mount.

### Этап 5. Внешний workflow и квалификация

#53 исправляется и тестируется в своих workflow repositories. Затем #54 запускает
минимум cold, warm и failure/cancel/restart waves по 20 attempts, после каждой —
следующую tenant wave. Gate должен проверять не только happy path, но и отсутствие
cross-run файлов, процессов, credentials, cache/artifact access и Docker state,
а также отсутствие действий старой job после cancel/lease loss.

Зависимости в кратком виде:

```text
#49 runtime profile ----\
#50 quotas/admission ----+--> #36 + #38 + #43
#42 cache capability ----/             |
                                      v
                           #44 + #45 + #40
                                      |
                                      v
                                    #46

#47 logs -------\
#48 lease --------+--> интеграция AttemptDomain --> #54 qualification
#51 input cache --+
#52 artifacts ----/

#53 workflow polling -----------------> #54 qualification
```

## Acceptance requirements для объединённого решения

1. Двадцать одновременных attempts получают разные filesystem, process/cgroup,
   env, HOME/XDG/tmp/tool writable state, Docker endpoint и stores.
2. Job A не может читать/изменять B или supervisor через filesystem, `/proc`,
   process signals, Docker API, cache/artifact API либо command-file bridge даже
   при известных synthetic IDs/paths/hashes.
3. Полный Docker API A не позволяет bind-mount host/supervisor/B paths; после
   завершения A её containers/images/volumes/builders недоступны следующему tenant.
4. Cancel, timeout, lease loss, action post failure, SIGTERM supervisor и crash
   приводят к bounded terminal state. Неопределённость означает quarantine;
   unknown resources никогда не удаляются глобальным prune.
5. Cache, log, artifact и completion capabilities отзываются по lifecycle; stale
   attempt не может продолжить side effects или повлиять на новый attempt.
6. При 20 active jobs и измеренном build cap `B` нет OOM/ENOSPC/PID exhaustion,
   starvation heartbeat/log cleanup или неограниченного роста caches/queues.
7. Exact pinned checkout/setup-buildx/login/build-push/hadolint actions проходят
   на заявленном runtime; profile A сохраняет требуемую proxy/network доступность.
8. Следующая tenant wave не обнаруживает ни одного canary предыдущей волны.

## Граница доказательств

Исследование основано на текущих bodies и состояниях issues #35–#54, полученных
через GitHub CLI 2026-09-20, и на исходном коде HEAD `b83fd177`. Оно не выполняло
20-run GitHub/rootless Docker/registry/Deploy API E2E и не подтверждает capacity
или безопасность нескольких rootless Docker daemons одного service account.
Численные quotas, production reserve и build concurrency `B` должны быть получены
измерениями #50/#54, а не выбраны из предположений.
