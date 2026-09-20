# Sandboxed Execution Delivery Roadmap

**Spec:**
[`docs/superpowers/specs/2026-09-20-chimera-sandboxed-execution-domain.md`](../specs/2026-09-20-chimera-sandboxed-execution-domain.md)

## Почему не один implementation plan

Спецификация затрагивает пять независимо ревьюируемых подсистем: ownership и
lifecycle, Linux launcher/rootfs, private Docker, network/capability policy и
release qualification. Один линейный план скрыл бы зависимости и сделал бы
review gates слишком крупными.

Каждый этап ниже получает отдельный детальный plan после стабилизации interfaces
предыдущего этапа. Ни один промежуточный этап не разрешает
`profile = "sandboxed"` в production.

## Plan A — Execution-domain foundation

Результат:

- `JobResourceRoot`/`JobDockerConfig` углублены в единый `ExecutionDomain`;
- добавлены config types, lifecycle journal, admission permit и deterministic
  attempt identity;
- текущий `trusted-host` lifecycle использует новый interface без изменения
  поведения;
- `sandboxed` parse-ится, но fail-closed отклоняется до запуска runner sessions.

Документ:
[`2026-09-20-chimera-sandboxed-foundation.md`](2026-09-20-chimera-sandboxed-foundation.md).

## Plan B — Linux launcher, rootfs и cgroup

Результат:

- RootlessKit/domain-init control protocol;
- user/mount/PID/IPC/UTS/cgroup namespaces;
- allowlisted rootfs, `pivot_root`, private `/proc`, `/dev`, `home/tmp/run/work`;
- host commands исполняются через domain-init;
- per-attempt cgroup limits, cancellation, `cgroup.kill` и crash reconciliation.

Gate: filesystem/process/cgroup tests проходят на native Debian; production
profile всё ещё недоступен.

## Plan C — Private rootless Docker domain

Результат:

- eager rootless dockerd внутри attempt rootfs/cgroup;
- явный `DockerEndpoint` во всех runner Docker paths;
- private socket/config/data/exec roots;
- job containers, services, Docker actions и Buildx используют один endpoint;
- отсутствует fallback на `connect_docker(None)` или production socket.

Gate: exact rootless Docker/Buildx acceptance и 20/40 concurrency tests проходят;
production profile всё ещё недоступен.

## Plan D — Network, capabilities и bounded storage

Результат:

- RootlessKit/slirp network namespace без host port publishing;
- systemd cgroup eBPF deny policy и startup negative probes;
- domain-local bridges для cache/artifact/deploy capabilities;
- проверка capacity-bounded storage root;
- install/doctor workflow для одного systemd unit и одного service account.

Gate: host/LAN/production sentinel endpoints недоступны, public registry и scoped
capabilities работают; production profile всё ещё недоступен.

## Plan E — Atomic activation и release qualification

Результат:

- удаляется временный `sandboxed unavailable` gate;
- добавляются operator docs и migration path;
- выполняются S-01…S-16, cold/warm/failure/cancel/restart waves;
- проверяются две последовательные tenant waves и production reserve/SLO;
- `profile = "sandboxed"` становится поддерживаемым только после полного gate.

## Инварианты между планами

- Один service account, один systemd unit и один `subuid/subgid` range.
- Нет per-job users, VMs, privileged DinD или custom privileged helper.
- Нет shared/rootful Docker fallback.
- Один lifecycle owner — `ExecutionDomain`.
- Любая неподтверждённая очистка poison-ит общий domain root.
- Docker daemon и writable attempt state отсутствуют после завершения job.
- Shared-kernel residual risk документируется и не называется VM-grade isolation.
