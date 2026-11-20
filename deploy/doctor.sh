#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C WG_COLOR_MODE=never
/usr/local/bin/awg3setup verify >/dev/null
source /etc/awg3panel/bootstrap.env
systemctl is-active --quiet awgtop.service
systemctl is-active --quiet awg3panel.service
[[ $(/opt/awgtop/bin/awg show awgtop listen-port) == 3478 ]]
[[ $(cat /sys/class/net/awgtop/mtu) == 1280 ]]
[[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]
code=000
for _ in {1..20}; do
  code=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --connect-timeout 1 --max-time 2 "http://${AWG_PANEL}:8081/" || true)
  [[ "$code" != 401 ]] || break
  sleep .2
done
[[ "$code" == 401 ]] || { printf 'FAIL: panel did not become ready with HTTP401\n' >&2; exit 1; }
iptables -w 10 -t nat -C AWG3P_NAT -s "$AWG_NETWORK" -o "$AWG_EGRESS" -j MASQUERADE
printf 'OK: userspace AWG, UDP3478, MTU1280, forwarding, scoped NAT, VPN-only panel HTTP401.\n'
printf 'External client/ISP, DNS, IPv6 and provider firewall still require verification.\n'
