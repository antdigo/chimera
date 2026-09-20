# Результаты feasibility spike

Дата: 2026-09-20.

Среда: macOS arm64, Docker Desktop 4.88.1, LinuxKit 7.0.12, outer image
`docker:29-dind-rootless`, Docker Engine 29.8.1, RootlessKit 3.1.0. Outer
container был privileged только как лабораторная Linux-среда.

## Результаты прогонов

| Slots | Cold start | Процессы idle | Суммарный RSS idle | Cleanup |
|---:|---:|---:|---:|---:|
| 2 | 1 с | 10 | 339 436 KiB | 0 процессов |
| 20 | 11 с | 100 | 3 380 760 KiB | 0 процессов |
| 40 | 22 с | 200 | 6 733 028 KiB | 0 процессов |

RSS — сумма resident set всех `rootlesskit`, child, `slirp4netns`, `dockerd` и
`containerd`, а не PSS. Эти значения завышают уникальную физическую память и
характеризуют только nested `vfs` стенд. Их нельзя использовать как sizing для
Debian без native benchmark.

Все daemon работали под одним UID и получили одинаковый mapping:

```text
         0       1000          1
         1     100000      65536
```

40 параллельных экземпляров не потребовали 40 host users или 40 непересекающихся
`subuid/subgid` ranges.

## Что подтверждено

- Раздельные socket/data/exec directories изолируют Docker metadata: container,
  image и volume одного endpoint не видны через другой endpoint.
- Этого недостаточно для security boundary: daemon без private rootfs успешно
  прочитал известный peer path через полный Docker bind-mount API.
- `chroot` недостаточен. Вложенный runc вернулся к старому mount-root, поэтому
  контейнер увидел host sentinel и peer tree.
- `pivot_root` отдельного mount namespace с lazy detach старого корня сохранил
  полный Docker API и закрыл host/peer paths.
- Внутри private rootfs прошли `run`, `exec`, named volume, собственный bind
  mount, pull и cleanup.
- `buildx` с `docker-container` driver поднял отдельный BuildKit container,
  собрал образ с `--load`, после чего образ успешно запустился.
- После TERM с bounded wait и KILL fallback процессы прототипа отсутствовали.
  Поэтому после job daemon не обязан потреблять CPU/RAM/PIDs; disk state должен
  удаляться или карантинироваться отдельным lifecycle-шагом.

## Лабораторные ограничения

- Nested `overlay2` не смонтировался в LinuxKit. `fuse-overlayfs` позволил daemon
  стартовать, но payload `execve` возвращал `EINVAL`. Для отделения API и
  namespace-проверок использован медленный `vfs`.
- Не проверены systemd `Delegate=`, реальные cgroup v2 CPU/RAM/IO/PID limits,
  native overlay/fuse performance и disk quotas.
- Не проверена полная destination network policy относительно production
  сервисов. RootlessKit `--disable-host-loopback` закрывает host loopback, но не
  является полной egress policy.
- Не запускались сами pinned GitHub Actions `setup-buildx`, login и build-push;
  проверены underlying Docker/Buildx API operations. Exact action flow остаётся
  обязательным native acceptance test.
- Общий kernel и одинаковый subordinate mapping остаются residual risk. Граница
  зависит от корректности user/mount/PID/network namespaces, `pivot_root`, LSM,
  seccomp и kernel; она не эквивалентна VM.

## Вывод для дизайна

Продолжать стоит с одним service account и **ленивым per-attempt execution
domain**. Docker daemon запускается только когда job впервые требует Docker API,
живёт внутри того же private rootfs/namespace/cgroup, что и host steps, и всегда
уничтожается до освобождения attempt slot.

Число runner slots, одновременно активных attempts и одновременно активных
Docker domains должно быть тремя отдельными лимитами. 20→40 не требует другой
схемы UID mapping, но удваивает startup/process/memory cost; admission controller
должен ограничивать Docker concurrency по реальному native benchmark.
