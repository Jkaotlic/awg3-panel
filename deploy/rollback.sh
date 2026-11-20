#!/usr/bin/env bash
# Runtime rollback preserves all keys/configs for resume and recovery.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'root required' >&2; exit 1; }
case "${1:---dry-run}" in
  --dry-run) /usr/local/bin/awg3setup verify >/dev/null; echo 'Would back up the owned installation, stop/disable awg3panel and awgtop, and remove their owned network rules. Keys, configs, packages and forwarding remain.'; exit 0 ;;
  --apply) ;;
  *) echo 'usage: rollback.sh --dry-run|--apply' >&2; exit 2 ;;
esac
/usr/local/bin/awg3setup verify >/dev/null
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
printf 'Runtime stopped; owned network rules removed. Protected backup: %s\nConfigs/keys retained. IPv4 forwarding not reset because other services may now depend on it.\n' "$archive"
