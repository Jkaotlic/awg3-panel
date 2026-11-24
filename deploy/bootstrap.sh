#!/usr/bin/env bash
# Fresh-VPS installer. No GitHub authentication/downloads and no source build on target.
set -euo pipefail
umask 077
export LC_ALL=C WG_COLOR_MODE=never
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
ENDPOINT= SUBNET=10.66.0.1/24 EGRESS= DNS= DRY=0
fail() { printf 'awg3-panel install: %s\n' "$*" >&2; exit 1; }
usage() { printf 'Usage: sudo ./deploy/bootstrap.sh --endpoint PUBLIC_IPV4 [--subnet 10.66.0.1/24] [--egress eth0] [--dns IP,IP] [--dry-run]\n'; }
while (($#)); do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --endpoint|--subnet|--egress|--dns) (($#>=2)) || fail "missing argument: $1"; case "$1" in --endpoint) ENDPOINT=$2;; --subnet) SUBNET=$2;; --egress) EGRESS=$2;; --dns) DNS=$2;; esac; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument (see --help)" ;;
  esac
done
[[ $(id -u) == 0 ]] || fail 'root required'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'supported target: Linux amd64'
source /etc/os-release
case "${ID}:${VERSION_ID}" in ubuntu:24.04|debian:13) ;; *) fail 'supported target: Ubuntu 24.04 or Debian 13';; esac
[[ -c /dev/net/tun ]] || fail '/dev/net/tun unavailable'
systemctl show-environment >/dev/null 2>&1 || fail 'systemd is not running'
for service in firewalld.service nftables.service; do
  if systemctl is-active --quiet "$service"; then fail "active firewall manager: $service (manual integration required)"; fi
done
if command -v ufw >/dev/null; then
  ufw_state=$(ufw status 2>/dev/null) || fail 'cannot determine UFW state'
  case "$ufw_state" in
    'Status: inactive'*) ;;
    'Status: active'*) fail 'active UFW requires manual integration' ;;
    *) fail 'unknown UFW state; manual integration required' ;;
  esac
fi
for c in sha256sum awk sort cmp find ip ss flock; do command -v "$c" >/dev/null || fail "missing prerequisite: $c (install iproute2/util-linux first)"; done
[[ -n "$ENDPOINT" ]] || { if [[ -t 0 ]]; then read -r -p 'Public IPv4 address: ' ENDPOINT; else fail '--endpoint PUBLIC_IPV4 required'; fi; }
[[ -f "$BASE/SHA256SUMS" && ! -L "$BASE/SHA256SUMS" ]] || fail 'use a verified installation bundle, not a source checkout'
[[ -z $(find "$BASE" -type l -print -quit) ]] || fail 'bundle must not contain symlinks'
# Restrict manifest syntax before sha256sum interprets filenames.
awk 'length($1)!=64 || $1 !~ /^[0-9a-f]+$/ || NF!=2 || $2 ~ /(^\/|\.\.|[^A-Za-z0-9_.\/-])/ {bad=1} END {exit bad}' "$BASE/SHA256SUMS" || fail 'invalid checksum manifest'
if [[ $(cut -c 67- "$BASE/SHA256SUMS" | sort | uniq -d | wc -l) != 0 ]]; then fail 'duplicate checksum entry'; fi
(cd "$BASE" && sha256sum -c SHA256SUMS >/dev/null 2>&1) || fail 'bundle checksum verification failed'
expected=$(cut -c 67- "$BASE/SHA256SUMS" | sort)
actual=$(cd "$BASE" && find . -type f ! -path ./SHA256SUMS -printf '%P\n' | sort)
[[ "$expected" == "$actual" ]] || fail 'bundle contains unverified extra or missing files'
[[ -x "$BASE/bin/awg3setup" ]] || fail 'setup executable missing'
[[ -n "$EGRESS" ]] || EGRESS=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
[[ "$EGRESS" != lo ]] && ip link show "$EGRESS" >/dev/null 2>&1 || fail 'egress interface is unavailable or loopback'
trusted_path() {
  local p=$1 mode
  while [[ "$p" != / ]]; do
    [[ ! -L "$p" ]] || fail "symlink in privileged destination: $p"
    if [[ -e "$p" ]]; then
      [[ $(stat -c %u "$p") == 0 ]] || fail "untrusted destination owner: $p"
      mode=$(stat -c %a "$p")
      (( (8#$mode & 0022) == 0 )) || fail "writable privileged destination: $p"
    fi
    p=$(dirname -- "$p")
  done
}
trusted_path /root/awg3panel-admin.conf
# Apply holds the shared lock from state preflight through service verification.
# Preview never creates the lock file.
if (( ! DRY )); then
  lock=/run/awg3panel-install.lock
  trusted_path "$lock"
  [[ ! -e "$lock" || -f "$lock" ]] || fail 'install lock is not a regular file'
  exec 9>>"$lock"
  flock -n 9 || fail 'another installation or rollback is running'
fi
args=(--endpoint "$ENDPOINT" --subnet "$SUBNET" --egress "$EGRESS" --dns "$DNS")
"$BASE/bin/awg3setup" prepare --dry-run "${args[@]}" >/dev/null || fail 'configuration preflight failed'
STATE=/var/lib/awg3panel-bootstrap
OWNED=0
[[ ! -f "$STATE/manifest.json" ]] || OWNED=1
source "$BASE/deploy/preflight.sh"
check_units
if (( ! OWNED )); then
  for p in /usr/local/bin/awg3panel /usr/local/bin/awg3setup /opt/awgtop /etc/systemd/system/awgtop.service /etc/systemd/system/awg3panel.service /usr/local/libexec/awg3panel; do [[ ! -e "$p" && ! -L "$p" ]] || fail "existing resource: $p"; done
  ip link show awgtop >/dev/null 2>&1 && fail 'interface awgtop already exists'
fi
check_socket udp 3478 awgtop.service /opt/awgtop/bin/amneziawg-go
check_socket tcp 8081 awg3panel.service /usr/local/bin/awg3panel
check_routes
if command -v iptables >/dev/null; then
  if (( ! OWNED )); then
    for pair in 'filter AWG3P_IN' 'filter AWG3P_FWD' 'nat AWG3P_NAT' 'mangle AWG3P_MSS'; do read -r table name <<< "$pair"; if iptables -w 10 -t "$table" -nL "$name" >/dev/null 2>&1; then fail 'firewall namespace occupied'; fi; done
  fi
fi
check_destination() {
  local src=$1 dst=$2 mode=$3
  trusted_path "$dst"
  [[ ! -L "$dst" ]] || fail "symlink destination: $dst"
  if [[ -e "$dst" ]]; then
    [[ -f "$dst" ]] || fail "non-regular destination: $dst"
    cmp -s "$src" "$dst" || fail "existing file differs: $dst"
    [[ $(stat -c %a "$dst") == "${mode#0}" ]] || fail "existing file has unexpected permissions: $dst"
  fi
}

bundle_files() {
  local action=$1 name
  "$action" "$BASE/bin/awg3panel" /usr/local/bin/awg3panel 0755
  "$action" "$BASE/bin/awg3setup" /usr/local/bin/awg3setup 0755
  for name in amneziawg-go awg awg-quick; do "$action" "$BASE/bin/$name" "/opt/awgtop/bin/$name" 0755; done
  "$action" "$BASE/deploy/awgtop-runtime.sh" /usr/local/libexec/awg3panel/awgtop-runtime 0755
  "$action" "$BASE/deploy/doctor.sh" /usr/local/libexec/awg3panel/doctor 0755
  "$action" "$BASE/deploy/preflight.sh" /usr/local/libexec/awg3panel/preflight 0755
  "$action" "$BASE/deploy/awgtop.service" /etc/systemd/system/awgtop.service 0644
  "$action" "$BASE/deploy/awg3panel.service" /etc/systemd/system/awg3panel.service 0644
}
bundle_files check_destination
if (( DRY )); then
  printf 'Dry run OK: %s, personal-stun-v1, UDP3478, MTU1280, egress %s. No files/packages/network changed.\n' "$ENDPOINT" "$EGRESS"
  exit 0
fi
missing=()
command -v iptables >/dev/null || missing+=(iptables)
command -v curl >/dev/null || missing+=(curl)
command -v sysctl >/dev/null || missing+=(procps)
if ((${#missing[@]})); then apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=15 update -qq; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends "${missing[@]}"; fi
"$BASE/bin/awg3setup" prepare "${args[@]}"
copy_new() {
  local src=$1 dst=$2 mode=$3
  check_destination "$src" "$dst" "$mode"
  [[ ! -e "$dst" ]] || return 0
  [[ -d $(dirname "$dst") ]] || install -d -m 0755 "$(dirname "$dst")"
  local tmp; tmp=$(mktemp "$(dirname "$dst")/.awg3panel-install.XXXXXX")
  install -m "$mode" "$src" "$tmp"
  ln "$tmp" "$dst" || { rm -f -- "$tmp"; fail "cannot publish: $dst"; }
  rm -f -- "$tmp"
}
bundle_files copy_new
install -d -m 0700 /var/lib/awg3panel/awgtop/backups /var/lib/awg3panel/awgtop/keys
systemctl daemon-reload
systemctl enable --now awgtop.service >/dev/null
ADMIN=/root/awg3panel-admin.conf
if [[ ! -e "$ADMIN" && ! -L "$ADMIN" ]]; then
  systemctl is-active --quiet awg3panel.service && fail 'panel is running but bootstrap profile is missing; stop it to recover the profile'
  list=$(/usr/local/bin/awg3panel list)
  peer=$(awk '$2=="bootstrap-admin" {print $1}' <<< "$list")
  [[ $(wc -w <<< "$peer") -le 1 ]] || fail 'ambiguous bootstrap-admin peer'
  tmp=$(mktemp /root/.awg3panel-admin.XXXXXX)
  if [[ -z "$peer" ]]; then
    /usr/local/bin/awg3panel add bootstrap-admin >/dev/null
    peer=$(/usr/local/bin/awg3panel list | awk '$2=="bootstrap-admin" {print $1}')
  fi
  [[ $(wc -w <<< "$peer") == 1 ]] || fail 'cannot identify first peer'
  /usr/local/bin/awg3panel export "$peer" > "$tmp"
  [[ -s "$tmp" ]] || fail 'admin profile not created'
  chmod 0600 "$tmp"
  ln "$tmp" "$ADMIN" || fail 'cannot publish admin profile'
  rm -f -- "$tmp"
elif [[ -L "$ADMIN" || ! -f "$ADMIN" || $(stat -c %a "$ADMIN") != 600 ]]; then fail 'bootstrap profile path or permissions are unsafe'; fi
/usr/local/bin/awg3setup admin-record || fail 'bootstrap admin profile ownership check failed'
systemctl enable --now awg3panel.service >/dev/null
/usr/local/libexec/awg3panel/doctor
printf 'Installation verified locally. First profile: %s\nCredentials: /root/awg3panel-access.txt\nAllow UDP3478 in the provider firewall, import the profile and connect before opening the panel.\n' "$ADMIN"
