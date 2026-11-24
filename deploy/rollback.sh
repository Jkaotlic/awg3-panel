#!/usr/bin/env bash
# Runtime rollback preserves all keys/configs for resume and recovery.
set -euo pipefail
umask 077
export LC_ALL=C

fail() { printf 'awg3-panel rollback: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || { echo 'root required' >&2; exit 1; }
case "${1:---dry-run}" in
  --dry-run) /usr/local/bin/awg3setup verify >/dev/null; echo 'Would back up the owned installation, stop/disable awg3panel and awgtop, and verify their network chains and jumps are gone after cleaning up any owned rules. Keys, configs, packages and forwarding remain.'; exit 0 ;;
  --apply)
    lock=/run/awg3panel-install.lock
    [[ ! -L "$lock" ]] || fail 'symlink install lock'
    if [[ -e "$lock" ]]; then
      [[ -f "$lock" && $(stat -c %u "$lock") == 0 ]] || fail 'untrusted install lock'
      mode=$(stat -c %a "$lock")
      (( (8#$mode & 0022) == 0 )) || fail 'writable install lock'
    fi
    exec 9>>"$lock"
    flock -n 9 || fail 'another installation or rollback is running'
    ;;
  *) echo 'usage: rollback.sh --dry-run|--apply' >&2; exit 2 ;;
esac
/usr/local/bin/awg3setup verify >/dev/null
# Inspect whole tables so a failed query cannot be mistaken for a missing chain.
firewall_state() {
  local table rules
  local remaining=0
  for table in filter nat mangle; do
    rules=$(iptables -w 10 -t "$table" -S) || return 2
    if grep -Eq '(^-N | -(j|g) )AWG3P_(IN|FWD|NAT|MSS)$' <<< "$rules"; then
      remaining=1
    fi
  done
  return "$remaining"
}

was_active=0
systemctl is-active --quiet awg3panel.service && was_active=1
systemctl stop awg3panel.service
trap 'if (( was_active )); then systemctl start awg3panel.service; fi' ERR
archive=$(mktemp /root/awg3panel-backup-XXXXXXXX.tar.gz)
inputs=()
for p in etc/awg3panel etc/amnezia/amneziawg/awgtop.conf var/lib/awg3panel var/lib/awg3panel-bootstrap root/awg3panel-admin.conf root/awg3panel-access.txt; do
  [[ ! -e "/$p" ]] || inputs+=("$p")
done
tar -czf "$archive" -C / "${inputs[@]}"
chmod 0600 "$archive"
trap - ERR
systemctl disable --now awg3panel.service
systemctl disable --now awgtop.service
if firewall_state; then
  :
else
  [[ $? == 1 ]] || fail "cannot inspect firewall; protected backup: $archive"
  # ExecStopPost may not have run for an already inactive unit. The installed
  # runtime validates the current boot token and each chain marker before deletion.
  /usr/local/libexec/awg3panel/awgtop-runtime down ||
    fail "firewall cleanup refused or failed; protected backup: $archive"
  firewall_state || fail "cannot verify removal of firewall chains and jumps; protected backup: $archive"
fi
printf 'Runtime stopped; owned network rules removed. Protected backup: %s\nConfigs/keys retained. IPv4 forwarding not reset because other services may now depend on it.\n' "$archive"
