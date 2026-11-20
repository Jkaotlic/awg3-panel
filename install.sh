#!/usr/bin/env bash
# Download a verified release, then delegate to the packaged bootstrap.
set -euo pipefail
umask 077
export LC_ALL=C
REPOSITORY=Jkaotlic/awg3-panel
RELEASE=latest
DRY=0
args=()
fail() { printf 'installer: %s\n' "$*" >&2; exit 1; }
usage() {
  printf 'Usage: sudo bash install.sh [--version vX.Y.Z] [--endpoint IPV4] [--dry-run] [--subnet CIDR] [--egress IFACE] [--dns IP,IP]\n'
  printf 'Target: fresh Ubuntu 24.04 / Debian 13, amd64, systemd and TUN. Existing installations are not upgraded.\n'
}
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --version) (($#>=2)) || fail '--version requires a release tag'; RELEASE=$2; shift 2 ;;
    --dry-run) DRY=1; args+=("$1"); shift ;;
    --endpoint|--subnet|--egress|--dns) (($#>=2)) || fail "missing value: $1"; args+=("$1" "$2"); shift 2 ;;
    *) fail 'unknown option; use --help' ;;
  esac
done
[[ "$RELEASE" == latest || "$RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]] || fail 'invalid release tag'
[[ $(id -u) == 0 ]] || fail 'root required'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Linux amd64 required'
for cmd in curl tar sha256sum awk stat mktemp flock; do command -v "$cmd" >/dev/null || fail "missing prerequisite: $cmd"; done
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
bash "$package/install.sh" "${args[@]}"
