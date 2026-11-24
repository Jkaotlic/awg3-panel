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
args=()
fail() { printf 'installer: %s\n' "$*" >&2; exit 1; }
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
      if [[ "$1" == --endpoint ]]; then ENDPOINT=$2; fi
      args+=("$1" "$2"); shift 2 ;;
    *) fail 'unknown option; use --help' ;;
  esac
done
[[ "$RELEASE" == latest || "$RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]] || fail 'invalid release tag'
[[ $(id -u) == 0 ]] || fail 'Запустите: sudo bash install.sh'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Нужен сервер Linux amd64 (x86-64).'
for cmd in curl tar sha256sum awk stat mktemp flock; do command -v "$cmd" >/dev/null || fail "missing prerequisite: $cmd"; done
if [[ -z "$ENDPOINT" ]]; then
  [[ -t 0 && -t 1 ]] || fail 'Откройте интерактивный SSH-терминал или передайте --endpoint IPV4.'
  WIZARD=1
  printf '\n  Configuration Lab\n  Мастер установки\n\n'
  printf '[1/5] Проверяем сервер\n'
  [[ -r /etc/os-release ]] || fail 'Не удалось определить версию ОС.'
  source /etc/os-release
  case "$ID:$VERSION_ID" in ubuntu:24.04|debian:13) ;; *) fail 'Нужна чистая Ubuntu 24.04 или Debian 13.' ;; esac
  [[ -c /dev/net/tun ]] || fail 'На сервере нет /dev/net/tun. Включите TUN в панели хостинга или используйте KVM VPS.'
  systemctl show-environment >/dev/null 2>&1 || fail 'На сервере не работает systemd.'
  command -v ip >/dev/null && command -v ss >/dev/null || fail 'Установите iproute2: sudo apt-get install iproute2'
  printf '[2/5] Указываем адрес подключения\n'
  printf 'Найдите публичный IPv4 сервера в панели хостинга. Если он совпадает с адресом из SSH, нажмите Enter.\n'
  # Only use the server address in SSH_CONNECTION, never the client address.
  read -r _ _ ssh_server _ <<< "${SSH_CONNECTION:-}"
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
  if ipv4 "${ssh_server:-}"; then hint=$ssh_server; fi
  while :; do
    if [[ -n "$hint" ]]; then printf 'Публичный IPv4 [%s]: ' "$hint"; else printf 'Публичный IPv4: '; fi
    IFS= read -r answer || fail 'Ввод прерван.'
    ENDPOINT=${answer:-$hint}
    if ipv4 "$ENDPOINT"; then break; fi
    printf 'Введите публичный IPv4 без порта, например 203.0.113.10.\n'
  done
  args+=(--endpoint "$ENDPOINT")
  printf '\n[3/5] Загружаем комплект и проверяем настройки\n'
fi
if [[ "$RELEASE" == latest ]]; then base="https://github.com/$REPOSITORY/releases/latest/download"; else base="https://github.com/$REPOSITORY/releases/download/$RELEASE"; fi
tmp=$(mktemp -d /tmp/awg3panel-download.XXXXXX)
cacheStage=
trap 'rm -rf -- "$tmp"; if [[ -n "$cacheStage" ]]; then rm -rf -- "$cacheStage"; fi' EXIT
archive=awg3panel-linux-amd64.tar.gz
printf 'Downloading %s (%s)...\n' "$REPOSITORY" "$RELEASE"
fetch() { curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 2 --connect-timeout 15 --max-time 300 "$1" --output "$2"; }
fetch "$base/$archive" "$tmp/$archive" || fail 'release download failed; check the selected release and network access'
fetch "$base/$archive.sha256" "$tmp/$archive.sha256" || fail 'checksum download failed'
awk -v file="$archive" 'NR!=1 || NF!=2 || length($1)!=64 || $1 !~ /^[a-fA-F0-9]+$/ || $2!=file {bad=1} END{exit bad || NR!=1}' "$tmp/$archive.sha256" || fail 'invalid release checksum file'
(cd "$tmp" && sha256sum -c "$archive.sha256" >/dev/null) || fail 'release checksum mismatch'
sum=$(sha256sum "$tmp/$archive" | awk '{print $1}')
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
if (( WIZARD && ! DRY )); then
  if ! bash "$package/install.sh" "${args[@]}" --dry-run; then
    fail 'Проверка не прошла. Устраните причину выше и запустите мастер снова.'
  fi
  printf '\nПредпросмотр прошёл. Настройки сервера пока не менялись.\nДля подключения нужен входящий UDP 3478. Если у хостинга есть сетевой экран, разрешите этот порт в панели хостинга.\n'
  printf 'Установить на %s? [д/Н, Enter — отмена] ' "$ENDPOINT"
  IFS= read -r answer || answer=
  case "$answer" in д|Д|да|Да|ДА|y|Y|yes|Yes|YES) ;; *) printf 'Установка отменена.\n'; exit 0 ;; esac
  printf '\n[4/5] Устанавливаем и проверяем службы\n'
fi
if (( ! DRY )); then
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
  cache=/var/lib/awg3panel-installer
  trusted "$cache/$sum"
  trusted /run/awg3panel-download.lock
  exec 8>/run/awg3panel-download.lock
  flock -n 8 || fail 'another download installation is running'
  [[ ! -e "$cache" ]] && mkdir -m 0700 "$cache"
  if [[ -e "$cache/$sum" ]]; then
    [[ -d "$cache/$sum" && -f "$cache/$sum/bundle/install.sh" && -f "$cache/$sum/.release-sha256" && ! -L "$cache/$sum/.release-sha256" && $(cat "$cache/$sum/.release-sha256") == "$sum" ]] || fail 'unmanaged installer cache entry'
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
bash "$package/install.sh" "${args[@]}" || {
  status=$?
  if (( WIZARD )); then printf '%s\n' 'Установка остановилась. После исправления ошибки повторите запуск с теми же настройками.' >&2; fi
  exit "$status"
}
if (( WIZARD && ! DRY )); then
  printf '\n[5/5] Первое подключение\nГотово. Как подключиться с телефона или компьютера:\n'
  printf '  1. Скачайте /root/awg3panel-admin.conf через SFTP и импортируйте в клиент AmneziaWG 3.1.\n'
  printf '  2. Включите туннель. Если он не подключается, проверьте UDP 3478 в панели хостинга.\n'
  printf '  3. Откройте /root/awg3panel-access.txt на сервере. Там адрес панели, логин и пароль.\n'
  printf 'Подсказки по скачиванию и первому входу: https://github.com/Jkaotlic/awg3-panel/blob/main/docs/install.md#первое-подключение\n'
fi
