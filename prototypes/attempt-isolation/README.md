# ПРОТОТИП: изоляция Docker domain на job attempt

Этот каталог содержит **одноразовый feasibility spike**, а не production-код
Chimera. Он отвечает на два вопроса из #36/#38:

1. Могут ли несколько rootless Docker daemon работать параллельно под одним
   Unix UID и одним `subuid/subgid` range?
2. Может ли daemon сохранить полный Docker API, но не видеть host и соседние
   attempt paths через bind mount?

Лабораторный запуск использует privileged outer container только для эмуляции
Linux-host на macOS/Docker Desktop. Это не вариант deployment и не оправдание
для privileged DinD рядом с production workloads.

## Запуск

Требуются Docker и локальный образ `docker:29-dind-rootless` (скрипт скачает его,
если образ отсутствует):

```sh
./prototypes/attempt-isolation/run-docker-lab.sh 20
```

Аргумент — число одновременно стартующих rootless daemon. По умолчанию `20`.

Прототип намеренно использует storage driver `vfs`: nested `fuse-overlayfs` в
Docker Desktop позволяет daemon стартовать, но `execve` payload возвращает
`EINVAL`. На целевом Debian нужно отдельно измерить `overlay2`/`fuse-overlayfs`.

## Что считается успехом

- все daemon стартуют под UID 1000 с одинаковым subordinate-ID mapping;
- metadata Docker (`containers`, `volumes`, `images`) между endpoints не видны;
- контрольный daemon без private rootfs читает соседний path через bind mount —
  это ожидаемый отрицательный тест;
- daemon после `pivot_root` выполняет `run`, `exec`, volumes и собственные bind
  mounts, но отвергает host path, peer path и production-style Docker socket;
- `buildx` с `docker-container` driver собирает и загружает образ;
- после TERM/KILL cleanup не остаётся процессов rootlesskit/dockerd/containerd,
  принадлежащих прототипу.

## Ограничения вывода

Успех в Docker Desktop подтверждает совместимость механизма и Docker API, но не
доказывает production-готовность. Перед утверждением дизайна тот же probe должен
быть повторён нативно на целевом Debian с cgroup v2 delegation, реальным
storage driver, network policy и 20/40 slots.
