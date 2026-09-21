# CHM-08 — Native qualification без остановки production Chimera

Дата: 2026-09-21. Статус: дизайн согласован в диалоге; требуется review этого документа перед implementation plan.

Дополнение к [основной спецификации](2026-09-20-chimera-sandboxed-execution-domain.md),
заменяющее только операционную схему native qualification. Изоляция attempt,
release gate S-01…S-16 и запрет частичной активации остаются неизменными.

## Цель и инвариант доступности

Qualification выполняется на том же bare-metal Debian/systemd сервере, где
работают Chimera и развернутые проекты. Действующий `chimera.service` не
останавливается, не перезапускается, не получает временный `ExecStart` и не
переводится в `sandboxed` ради теста. Никакой тест не использует production
Docker socket, deployment credentials, runner identity или storage root.

Один отдельный `chimera-qualification.service` обслуживает весь запрошенный
прогон. Это не unit и не Unix user на каждый job. Он использует тот же
непривилегированный service account, но отдельную delegated cgroup subtree,
отдельный capacity-bounded filesystem/storage root, отдельные lock и
отчётный каталог. Unit устанавливается disabled; старт — только явным
операторским запросом, никогда после boot, update или рестарта production
Chimera. Наличие общего UID означает, что сам qualification supervisor
является доверенным кодом оператора, а не security boundary от production;
недоверенные workflow ограничены внутри проверяемых execution domains.

Публикация кода и зелёный CI не разрешают доступ к целевому серверу. Любое
подключение к нему, даже read-only preflight, и тем более установка unit или
запуск workload требуют отдельного явного согласия оператора на конкретные
команды и их ресурсный бюджет. Имя хоста не является таким согласием.

## Два способа запуска одного квалификационного контура

1. **B / локальные native-тесты.** Оператор заранее собирает и закрепляет
   acceptance-test executable вне delegated cgroup, затем запускает
   `systemctl start chimera-qualification.service` после `doctor`/preflight.
   `ExecStart` указывает непосредственно на этот executable и точный native
   test filter; `cargo`, shell-wrapper и другие процессы не остаются рядом с
   тестовым supervisor в корне delegated cgroup. Это сохраняет инвариант
   `CgroupRoot::prepare_supervisor`: перед созданием дочерних cgroups корень
   содержит ровно текущий supervisor. Тесты сами создают
   синтетические attempts, запускают production-private Linux backend и
   сохраняют отчёт. GitHub workflow или новая runner registration на этом
   этапе не нужны.
2. **Финальный E2E.** Тот же qualification unit поднимает отдельную временную
   runner identity с уникальным тестовым label. Синтетический
   `workflow_dispatch` направляет jobs только на это label. Identity никогда
   не переиспользует уже работающую production registration. Workflows
   содержат только pinned test actions, синтетические credentials и
   test-local registry/deploy endpoints; production deploy не вызывается.
   После теста identity снимается, а следующий tenant и idle-пробы
   подтверждают отсутствие daemon, процессов и writable state.

Команда старта B не диспатчит GitHub workflow. E2E dispatch разрешается
только после успешных B–D preflight и readiness test unit. Отсутствующая
runner identity, неподтверждённый label routing или невозможность её
удаления блокируют соответствующий E2E case; это не fixture pass.

## Ограничение воздействия на работающий сервер

Перед каждым native запуском operator config задаёт конечные и положительные
верхние границы длительности, `MemoryHigh/MemoryMax`, `MemorySwapMax`,
`CPUQuota/CPUWeight`, `TasksMax`, `IOWeight` и device-qualified `IOReadBandwidthMax`
и `IOWriteBandwidthMax` либо эквивалентные cgroup v2 пределы. Parent unit
ограничивает весь qualification run, а per-attempt cgroups внутри него —
каждый workload. Отдельный filesystem/LV/quota ограничивает байты и inode;
`io.max` не считается заменой квоты. Нельзя расширять лимиты автоматически,
чтобы добиться прохождения 20/40-wave теста.

Preflight сверяет эффективные значения systemd и cgroup readback, физическое
устройство bounded storage, свободный объём, контроллеры и production reserve.
Независимый production sentinel вне qualification cgroup получает baseline
до нагрузки и измеряется в ходе и после теста. Если заданный reserve или
абсолютный SLO нарушен, нет положительного контроля sentinel, или данные
неполны, нагрузка прекращается и case остаётся nonqualifying. Волны 20/40
могут быть признаны `Blocked/Inconclusive`, если их нельзя выполнить в
утверждённом бюджете без воздействия на production. Это безопаснее ложного
release pass и не меняет требование самой волны.

Для сетевого gate test unit получает ту же утверждённую cgroup eBPF/CIDR
policy, что и production unit, с проверкой идентичности эффективной политики.
Network sentinel listeners размещаются вне тестовой cgroup и имеют положительный
контроль доступности. Отдельный unit без этой parity не подтверждает D/E gate.

## Crash, cleanup и отказ

Crash-тесты завершают только дочерний qualification supervisor по его
удостоверенной PID/start/cgroup identity. Внешний coordinator и watchdog
остаются живы в qualification unit, собирают доказательства, затем запускают
новый тестовый supervisor для authenticated reconciliation. Они никогда не
посылают сигнал production `chimera.service`, systemd manager или процессам
по сохранённому PID без проверки identity. `systemctl stop` не заменяет
доказательство Chimera teardown: итог требует пустых exact run cgroups,
mount/socket/process inventory и bounded storage root.

При ошибке, timeout или неподтверждённой очистке unit оставляет marker,
журнал и отчёты как forensic artifacts; следующий запуск fail-closed.
Автоматические `docker system prune`, reboot, host-wide kill, remount,
очистка общего cache или удаление неизвестных путей запрещены. Очистка
производственных ресурсов не входит в qualification interface.

## Изменение существующего runbook

Текущий `docs/testing-sandboxed-native.md` предписывает остановить production
unit и временно заменить его `ExecStart`. Этот раздел устарел для согласованной
no-downtime схемы и должен быть заменён **до любого native запуска**. Скрипт
E0 пока остаётся blocked-only; переписывание runbook само по себе не создаёт
runtime driver, watchdog или acceptance evidence. `install/doctor` должен
создавать/проверять только disabled qualification unit и отдельные roots,
показывать точную команду запуска и не модифицировать `chimera.service`.

## Критерии принятия схемы

- До и после B/E run production `chimera.service` сохраняет тот же PID/health
  и продолжает обслуживать существующие jobs; его конфигурация не меняется.
- У test unit подтверждены отдельный cgroup/storage/lock, конечные parent
  bounds, policy parity, положительный sentinel control и внешний watchdog.
- B native matrix исполняет ненулевое число реальных cases через production
  Linux backend и доказывает exact-resource cleanup; compile, fixture и
  Docker Desktop results не заменяют этот gate.
- E2E dispatch привязан только к тестовой identity/label, выполняет pinned
  workflows и удаляет identity после двух tenant waves; production runner
  registrations и deploy остаются нетронутыми.
- S-01…S-16, cold/warm/failure/cancel/restart, 20/40 concurrency и
  production reserve/SLO подтверждены отчётом с commit/config provenance.
  Любой отсутствующий или неполный пункт оставляет `sandboxed` недоступным.
