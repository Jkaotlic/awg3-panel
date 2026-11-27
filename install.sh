#!/usr/bin/env bash
# Download a verified release, then delegate to the packaged bootstrap.
set -euo pipefail
umask 077
export LC_ALL=C
REPOSITORY=Jkaotlic/awg3-panel
RELEASE=latest
DRY=0
WIZARD=0
ENDPOINT=
SUBNET_ARG=
EGRESS_ARG=
args=()
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_BOLD=$'\033[1m' C_DIM=$'\033[2m' C_GREEN=$'\033[32m' C_CYAN=$'\033[36m' C_YELLOW=$'\033[33m' C_RED=$'\033[31m' C_RESET=$'\033[0m'
else
  C_BOLD= C_DIM= C_GREEN= C_CYAN= C_YELLOW= C_RED= C_RESET=
fi
fail() { printf '%sinstaller: %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }
step() { printf '\n%s%s%s\n' "$C_BOLD$C_CYAN" "$*" "$C_RESET"; }
ok() { printf '  %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
usage() {
  printf 'Мастер установки: sudo bash install.sh\n'
  printf 'Для автоматизации: sudo bash install.sh --endpoint IPV4 [--version vX.Y.Z] [--dry-run] [--subnet CIDR] [--egress IFACE] [--dns IP,IP]\n'
  printf 'Target: fresh Ubuntu 24.04 / Debian 13, amd64, systemd and TUN. Existing installations are not upgraded.\n'
}
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --version) (($#>=2)) || fail '--version requires a release tag'; RELEASE=$2; shift 2 ;;
    --dry-run) DRY=1; args+=("$1"); shift ;;
    --endpoint|--subnet|--egress|--dns)
      (($#>=2)) && [[ -n "$2" ]] || fail "missing value: $1"
      case "$1" in
        --endpoint) ENDPOINT=$2 ;;
        --subnet) SUBNET_ARG=$2 ;;
        --egress) EGRESS_ARG=$2 ;;
      esac
      args+=("$1" "$2"); shift 2 ;;
    *) fail 'unknown option; use --help' ;;
  esac
done
[[ "$RELEASE" == latest || "$RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]] || fail 'invalid release tag'
[[ $(id -u) == 0 ]] || fail 'Запустите от имени root: sudo bash install.sh'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Нужен сервер Linux amd64 (x86-64).'
for cmd in curl tar sha256sum awk stat mktemp flock; do command -v "$cmd" >/dev/null || fail "missing prerequisite: $cmd"; done
if [[ -z "$ENDPOINT" ]]; then
  [[ -t 0 && -t 1 ]] || fail 'Откройте интерактивный SSH-терминал или передайте --endpoint IPV4.'
  WIZARD=1
  printf '\n%s  AWG3 Panel — Мастер установки%s\n' "$C_BOLD" "$C_RESET"
  printf '%s  Установит AmneziaWG 3.1 (UDP 3478) и веб-панель управления (доступ только через VPN).%s\n' "$C_DIM" "$C_RESET"
  printf '%s  Сначала проверим сервер и покажем предпросмотр — до подтверждения ничего не меняется.%s\n' "$C_DIM" "$C_RESET"
  step '[1/5] Проверяем сервер'
  [[ -r /etc/os-release ]] || fail 'Не удалось определить версию ОС.'
  source /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in ubuntu:24.04|debian:13) ;; *) fail 'Нужна чистая Ubuntu 24.04 или Debian 13.' ;; esac
  ok "ОС: ${PRETTY_NAME:-${ID:-} ${VERSION_ID:-}}"
  [[ -c /dev/net/tun ]] || fail 'На сервере нет /dev/net/tun. Включите TUN в панели хостинга или используйте KVM VPS.'
  ok 'TUN-устройство (/dev/net/tun) доступно'
  systemctl show-environment >/dev/null 2>&1 || fail 'На сервере не работает systemd.'
  ok 'systemd работает'
  command -v ip >/dev/null && command -v ss >/dev/null || fail 'Установите iproute2: sudo apt-get install -y iproute2'
  ok 'Сетевые утилиты (ip, ss) найдены'
  detected_egress=${EGRESS_ARG:-$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}' || true)}
  if [[ -n "$detected_egress" && "$detected_egress" != lo ]]; then
    ok "Исходящий интерфейс: $detected_egress"
  else
    warn 'Исходящий интерфейс не определён автоматически (можно задать через --egress IFACE)'
  fi
  step '[2/5] Адрес сервера для подключения'
  # Only use the server address in SSH_CONNECTION or local route src, never the client address.
  read -r _ _ ssh_server _ <<< "${SSH_CONNECTION:-}"
  route_src=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}' || true)
  ipv4() {
    local octet
    local -a octets
    [[ "$1" =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]] || return 1
    IFS=. read -ra octets <<< "$1"
    for octet in "${octets[@]}"; do (( octet <= 255 )) || return 1; done
    (( octets[0] > 0 && octets[0] < 224 && octets[0] != 10 && octets[0] != 127 )) || return 1
    [[ "$1" != 192.168.* && "$1" != 169.254.* ]] &&
      ! (( octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 )) &&
      ! (( octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127 ))
  }
  hint=
  if ipv4 "${ssh_server:-}"; then
    hint=$ssh_server
  elif ipv4 "${route_src:-}"; then
    hint=$route_src
  fi
  if [[ -n "$hint" ]]; then
    printf '  Обнаружен публичный IPv4: %s%s%s\n' "$C_BOLD" "$hint" "$C_RESET"
    printf '  Нажмите Enter, чтобы использовать его, или введите адрес из панели хостинга.\n'
  else
    printf '  Сервер, похоже, за NAT — введите внешний (публичный) IPv4 из панели хостинга.\n'
  fi
  while :; do
    if [[ -n "$hint" ]]; then printf '  Публичный IPv4 [%s]: ' "$hint"; else printf '  Публичный IPv4: '; fi
    IFS= read -r answer || fail 'Ввод прерван.'
    ENDPOINT=${answer:-$hint}
    if ipv4 "$ENDPOINT"; then break; fi
    if [[ "$ENDPOINT" == *:* ]]; then
      printf '  Введите только IPv4 без порта (порт 3478 добавится сам).\n'
    else
      printf '  Нужен публичный IPv4-адрес, например 203.0.113.10 (не локальный 10.x / 192.168.x).\n'
    fi
  done
  args+=(--endpoint "$ENDPOINT")
  step '[3/5] Загружаем комплект и проверяем настройки'
fi
if [[ "$RELEASE" == latest ]]; then base="https://github.com/$REPOSITORY/releases/latest/download"; else base="https://github.com/$REPOSITORY/releases/download/$RELEASE"; fi
tmp=$(mktemp -d /tmp/awg3panel-download.XXXXXX)
cacheStage=
trap 'rm -rf -- "$tmp"; if [[ -n "$cacheStage" ]]; then rm -rf -- "$cacheStage"; fi' EXIT
archive=awg3panel-linux-amd64.tar.gz
trusted() {
  local p=$1 mode
  while [[ "$p" != / ]]; do
    [[ ! -L "$p" ]] || fail 'symlink in installer cache path'
    if [[ -e "$p" ]]; then
      [[ $(stat -c %u "$p") == 0 ]] || fail 'untrusted installer cache owner'
      mode=$(stat -c %a "$p"); (( (8#$mode & 0022) == 0 )) || fail 'writable installer cache path'
    fi
    p=$(dirname -- "$p")
  done
}
fetch() { curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 2 --retry-delay 2 --retry-connrefused --connect-timeout 15 --max-time 300 "$1" --output "$2"; }
printf 'Checking %s (%s)...\n' "$REPOSITORY" "$RELEASE"
fetch "$base/$archive.sha256" "$tmp/$archive.sha256" || fail 'checksum download failed; check the selected release and network access'
awk -v file="$archive" 'NR!=1 || NF!=2 || length($1)!=64 || $1 !~ /^[a-fA-F0-9]+$/ || $2!=file {bad=1} END{exit bad || NR!=1}' "$tmp/$archive.sha256" || fail 'invalid release checksum file'
sum=$(awk '{print tolower($1)}' "$tmp/$archive.sha256")
cache=/var/lib/awg3panel-installer
package=
if [[ -e "$cache/$sum" ]]; then
  trusted "$cache/$sum"
  if [[ -d "$cache/$sum" && -f "$cache/$sum/bundle/install.sh" && ! -L "$cache/$sum/bundle/install.sh" && -f "$cache/$sum/.release-sha256" && ! -L "$cache/$sum/.release-sha256" && $(cat "$cache/$sum/.release-sha256") == "$sum" ]]; then
    package="$cache/$sum/bundle"
    printf 'Using cached bundle: %s\n' "$package"
  elif (( ! DRY )); then
    fail 'unmanaged installer cache entry'
  fi
fi
if [[ -z "$package" ]]; then
  printf 'Downloading %s (%s)...\n' "$REPOSITORY" "$RELEASE"
  fetch "$base/$archive" "$tmp/$archive" || fail 'release download failed; check the selected release and network access'
  (cd "$tmp" && sha256sum -c "$archive.sha256" >/dev/null) || fail 'release checksum mismatch'
  # Accept only regular files/directories below one expected product directory.
  top=
  while IFS= read -r name; do
    [[ "$name" =~ ^[a-zA-Z0-9_./+-]+$ && "$name" != /* && "/$name/" != *'/../'* && "/$name/" != *'/./'* ]] || fail 'unsafe release archive path'
    root=${name%%/*}
    [[ "$root" =~ ^awg3panel-linux-amd64-[a-zA-Z0-9._+-]+$ ]] || fail 'unexpected release directory'
    [[ -z "$top" || "$top" == "$root" ]] || fail 'multiple release roots'
    top=$root
  done < <(tar --quoting-style=escape -tzf "$tmp/$archive")
  [[ -n "$top" ]] || fail 'empty release archive'
  tar -tvzf "$tmp/$archive" | awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" {bad=1} END{exit bad}' || fail 'release archive contains links or special files'
  mkdir "$tmp/unpacked"
  tar --no-same-owner --no-same-permissions -xzf "$tmp/$archive" -C "$tmp/unpacked"
  package="$tmp/unpacked/$top"
  [[ -f "$package/install.sh" && ! -L "$package/install.sh" ]] || fail 'packaged installer missing'
fi
if (( WIZARD && ! DRY )); then
  if ! bash "$package/install.sh" "${args[@]}" --dry-run; then
    fail 'Проверка не прошла. Устраните причину выше и запустите мастер снова.'
  fi
  subnet_show=${SUBNET_ARG:-10.66.0.1/24}
  panel_ip=${subnet_show%%/*}
  printf '\n%sПредпросмотр прошёл.%s Настройки сервера пока не менялись.\n\n' "$C_GREEN$C_BOLD" "$C_RESET"
  printf '  План установки:\n'
  printf '    • Адрес подключения: %s:3478 (UDP)\n' "$ENDPOINT"
  printf '    • VPN-подсеть:       %s\n' "$subnet_show"
  if [[ -n "${detected_egress:-}" ]]; then printf '    • Исходящий канал:   %s\n' "$detected_egress"; fi
  printf '    • Панель управления: http://%s:8081/ (только через VPN)\n\n' "$panel_ip"
  warn 'Для подключения нужен входящий UDP 3478 — разрешите его в сетевом экране (firewall) хостинга.'
  printf '\n  Установить на %s%s%s? [д/Н, Enter — отмена] ' "$C_BOLD" "$ENDPOINT" "$C_RESET"
  IFS= read -r answer || answer=
  case "$answer" in д|Д|да|Да|ДА|y|Y|yes|Yes|YES) ;; *) printf 'Установка отменена.\n'; exit 0 ;; esac
  step '[4/5] Устанавливаем и проверяем службы'
fi
if (( ! DRY )); then
  lock=/run/awg3panel-download.lock
  trusted "$cache/$sum"
  trusted "$lock"
  [[ ! -e "$lock" || -f "$lock" ]] || fail 'download lock is not a regular file'
  exec 8>>"$lock"
  flock -n 8 || fail 'another download installation is running'
  if [[ ! -e "$cache" ]]; then
    mkdir -m 0700 "$cache"
  elif [[ ! -d "$cache" ]]; then
    fail 'installer cache path is not a directory'
  fi
  if [[ "$package" != "$cache/$sum/bundle" ]]; then
    if [[ -e "$cache/$sum" ]]; then
      [[ -d "$cache/$sum" && -f "$cache/$sum/bundle/install.sh" && ! -L "$cache/$sum/bundle/install.sh" && -f "$cache/$sum/.release-sha256" && ! -L "$cache/$sum/.release-sha256" && $(cat "$cache/$sum/.release-sha256") == "$sum" ]] || fail 'unmanaged installer cache entry'
    else
      cacheStage=$(mktemp -d "$cache/.stage-XXXXXX")
      mv "$package" "$cacheStage/bundle"
      # Publish a complete cache atomically; keep the marker outside the bundle.
      printf '%s\n' "$sum" > "$cacheStage/.release-sha256"
      mv -T "$cacheStage" "$cache/$sum"
      cacheStage=
    fi
    package="$cache/$sum/bundle"
    printf 'Cached bundle: %s\n' "$package"
  fi
fi
bash "$package/install.sh" "${args[@]}" || {
  status=$?
  if (( WIZARD )); then
    printf '\n%sУстановка остановилась.%s После исправления ошибки повторите запуск с теми же настройками.\n' "$C_RED$C_BOLD" "$C_RESET" >&2
    printf 'Логи служб: journalctl -u awgtop -u awg3panel -n 30 --no-pager\n' >&2
  fi
  exit "$status"
}
if (( WIZARD && ! DRY )); then
  doc_ref=main
  if [[ "$RELEASE" != latest ]]; then doc_ref=$RELEASE; fi
  panel_ip=${SUBNET_ARG:-10.66.0.1/24}
  panel_ip=${panel_ip%%/*}
  if [[ -r /etc/awg3panel/bootstrap.env ]]; then
    env_panel=$(awk -F= '$1=="AWG_PANEL"{gsub(/["'\'']/,"",$2); print $2}' /etc/awg3panel/bootstrap.env || true)
    if [[ -n "$env_panel" ]]; then panel_ip=$env_panel; fi
  fi
  step '[5/5] Готово! Первое подключение'
  printf '  %s1.%s Скачайте VPN-профиль на свой компьютер (выполните у себя в терминале):\n' "$C_BOLD" "$C_RESET"
  printf '     %sscp root@%s:/root/awg3panel-admin.conf ./awg3panel-admin.conf%s\n\n' "$C_CYAN" "$ENDPOINT" "$C_RESET"
  printf '  %s2.%s Импортируйте awg3panel-admin.conf в клиент AmneziaWG 3.1 и включите туннель.\n' "$C_BOLD" "$C_RESET"
  printf '     %sЕсли не подключается — откройте входящий UDP 3478 в панели хостинга.%s\n\n' "$C_DIM" "$C_RESET"
  printf '  %s3.%s Посмотрите логин и пароль панели на этом сервере:\n' "$C_BOLD" "$C_RESET"
  printf '     %scat /root/awg3panel-access.txt%s\n\n' "$C_CYAN" "$C_RESET"
  printf '  %s4.%s Откройте панель в браузере (при включённом VPN):\n' "$C_BOLD" "$C_RESET"
  printf '     %shttp://%s:8081/%s\n\n' "$C_CYAN" "$panel_ip" "$C_RESET"
  printf '  Полезные команды:\n'
  printf '    • Диагностика:  sudo /usr/local/libexec/awg3panel/doctor\n'
  printf '    • Откат:        sudo bash %s/deploy/rollback.sh --dry-run\n' "$package"
  printf '    • Инструкция:   https://github.com/Jkaotlic/awg3-panel/blob/%s/docs/install.md#первое-подключение\n' "$doc_ref"
fi
