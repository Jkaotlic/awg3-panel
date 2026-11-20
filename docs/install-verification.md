# Проверка установки personal-stun-v1

Воспроизводимый локальный полигон: Ubuntu24.04 или Debian13, systemd, отдельная сеть,
TUN/CAP_NET_ADMIN. Команды ниже требуют Docker на доверенной Linux/Windows-машине.
Не запускайте smoke.sh на действующем VPS: он специально создаёт конфликты,
маршруты и тестовые службы.

## Сборка и полигон

```bash
docker build --build-arg VERSION=verify -f deploy/Dockerfile.build --target artifact --output type=local,dest=dist .
docker build -t awg3panel-smoke:local -f deploy/tests/Dockerfile .
docker run -d --name awg3panel-disposable-check --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock awg3panel-smoke:local
docker exec awg3panel-disposable-check touch /run/awg3panel-disposable-test
docker cp dist/awg3panel-linux-amd64-verify.tar.gz awg3panel-disposable-check:/root/bundle.tar.gz
docker cp deploy/tests/smoke.sh awg3panel-disposable-check:/root/smoke.sh
docker exec awg3panel-disposable-check tar -xzf /root/bundle.tar.gz -C /root
docker exec awg3panel-disposable-check bash /root/smoke.sh /root/awg3panel-linux-amd64-verify
```

Тест считает успешным только финальное `ALL SMOKE CHECKS PASSED` и exit0.
Привилегированный контейнер нужен только для разработки; установка на VPS
Docker не использует. Полигон проверяет systemd, но не заменяет отдельную
проверку настоящей перезагрузки VM у выбранного хостера.
Не bind-mount-ите корень host `/sys/fs/cgroup`: иначе одноимённые unit-ы разных
стендов делят лимиты потоков/памяти. Современный privileged Docker предоставляет
отдельное записываемое дерево cgroup при `--cgroupns=private`.

## Что проверяется

- Dry-run не создаёт каталоги/lock-файл, не меняет пакеты и сеть.
- Занятые UDP-порт, имя интерфейса и пересекающийся более широкий маршрут
  приводят к отказу до изменения сети.
- Проверяются wildcard TCP8081, маршруты во всех таблицах, загруженные unit-ы
  из /run и /usr/lib и systemd drop-ins. Runtime preflight повторяет сетевые проверки.
- Пустой/подменённый первый профиль отвергается; при выдаче приватный ключ
  сохраняется до применения. Имитация обрыва после syncconf сохраняет экспорт.
- Удаление firewall требует текущей метки внутри каждой цепочки. Чужие цепочки
  с теми же именами сохраняются после отказа, маркер после отката удаляется.
- Конфликтующий файл после частичной подготовки не перезаписывается;
  продолжение сохраняет первоначальные ключи и запускает службы.
- Повтор завершённой установки сохраняет серверный конфиг и байты первого
  профиля, файлы секретов имеют режим0600.
- Второй реальный userspace AWG работает в отдельном network namespace.
  Через зашифрованный туннель проходят ICMP payload1000 и HTTP401 панели;
  серверные RX/TX подтверждают двустороннюю передачу.
- Перезапуск служб сохраняет конфиги/профиль.
- Runtime rollback создаёт защищённый архив, останавливает службы и удаляет
  свои правила; повтор установки восстанавливает работу с теми же ключами.

Unit-тесты отдельно проверяют прерывание после каждого создаваемого файла,
симлинки/чужие файлы, изменение аргументов, подмену конфига, плохой источник
случайности, правильность DTLS lengths и паритет bootstrap с обычным issuer.

## Дополнительные проверки

На Linux:

```bash
go test ./... -count=1
go test -tags readonly ./... -count=1
go vet ./...
go vet -tags readonly ./...
go test -race ./... -count=1
go test -race -tags readonly ./... -count=1
```

Из распакованного комплекта проверить бинарники `bin/awg3panel`,
`bin/awg3setup`, `bin/awg3panel-readonly` и `bin/amneziawg-go` с
`govulncheck -mode binary FILE`.
Сборщик уже выполняет такой gate для всех четырёх файлов с закреплённой версией
govulncheck и не создаёт комплект при находках; при выдаче старого комплекта
сканер следует запустить повторно по актуальной базе.
Go-версию и закреплённые upstream commits сверить с BUILD_INFO и deploy/engine.lock.
Runtime-вывод --version движка может
нести старую константу: настоящую module version видно в `go version -m`.

## Ограничения доказательств

Набор не доказывает доступность UDP3478 из сети пользователя или отсутствие
фильтрации конкретным ТСПУ. Провайдерский firewall, DNS, IPv6/KillSwitch,
мобильный интернет и настоящая перезагрузка внешнего VPS проверяются отдельно.
CI запускает один и тот же systemd smoke на Ubuntu24.04 и Debian13.
Локально 2026-11-20 обе системы прошли полный smoke после исправлений ревью;
журналы сборки и прогонов сохраняются вне Git. Это не тест конкретного провайдера.

После проверки удалите **только свой** полигон:

```bash
docker rm -f awg3panel-disposable-check
```

Архивы и журналы с настоящими ключами не коммитятся и не публикуются. Сохранять
в отчёте достаточно версии, хешей публичных артефактов и результатов проверок.
