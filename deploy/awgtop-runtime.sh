#!/usr/bin/env bash
# Owns only the new awgtop interface and AWG3P_* chains. Never sourced by the web daemon.
set -euo pipefail
umask 077
export LC_ALL=C
export WG_COLOR_MODE=never
SETUP=/usr/local/bin/awg3setup
BIN=/opt/awgtop/bin
STATE=/var/lib/awg3panel-bootstrap
fail() { printf '%s\n' "awgtop: $*" >&2; exit 1; }
"$SETUP" verify >/dev/null || fail 'configuration ownership check failed'
# Verified root-owned generated input, not user-provided shell text.
source /etc/awg3panel/bootstrap.env
STAMP=$(sha256sum "$STATE/manifest.json" | cut -d ' ' -f1)
BOOT=$(cat /proc/sys/kernel/random/boot_id)
TAG=
owned() {
  [[ -f "$STATE/network.owned" && ! -L "$STATE/network.owned" ]] || return 1
  TAG=$(cat "$STATE/network.owned")
  [[ "$TAG" == "awg3p:${STAMP:0:16}:$BOOT:"* && "$TAG" =~ ^awg3p:[a-f0-9]{16}:[a-f0-9-]{36}:[a-f0-9-]{36}$ ]]
}
check_chains() {
  local table name
  for pair in 'filter AWG3P_IN' 'filter AWG3P_FWD' 'nat AWG3P_NAT' 'mangle AWG3P_MSS'; do
    read -r table name <<< "$pair"
    if iptables -w 10 -t "$table" -nL "$name" >/dev/null 2>&1; then
      owned && iptables -w 10 -t "$table" -C "$name" -m comment --comment "$TAG" 2>/dev/null || fail 'firewall chain lacks current ownership proof'
    fi
  done
}
chain() {
  local table=$1 name=$2
  if ! iptables -w 10 -t "$table" -nL "$name" >/dev/null 2>&1; then
    iptables -w 10 -t "$table" -N "$name"
    iptables -w 10 -t "$table" -A "$name" -m comment --comment "$TAG"
  fi
}
rule() { local table=$1 name=$2; shift 2; iptables -w 10 -t "$table" -C "$name" "$@" 2>/dev/null || iptables -w 10 -t "$table" -A "$name" "$@"; }
jump() { local table=$1 name=$2 dest=$3; iptables -w 10 -t "$table" -C "$name" -m comment --comment "$TAG" -j "$dest" 2>/dev/null || iptables -w 10 -t "$table" -I "$name" 1 -m comment --comment "$TAG" -j "$dest"; }
case "${1:-}" in
  preflight)
    [[ -c /dev/net/tun ]] || fail '/dev/net/tun unavailable'
    if ip link show "$AWG_IFACE" >/dev/null 2>&1; then fail 'interface already exists; refusing to take it over'; fi
    check_chains
    source /usr/local/libexec/awg3panel/preflight
    SUBNET=$AWG_ADDRESS OWNED=0
    check_routes
    check_socket udp 3478 awgtop.service "$BIN/amneziawg-go"
    OWNED=1
    check_socket tcp 8081 awg3panel.service /usr/local/bin/awg3panel
    ;;
  up)
    for _ in {1..100}; do
      if "$BIN/awg" show "$AWG_IFACE" listen-port >/dev/null 2>&1; then break; fi
      sleep .1
    done
    "$BIN/awg" show "$AWG_IFACE" listen-port >/dev/null 2>&1 || fail 'userspace control socket did not become ready'
    stripped=$(mktemp /run/awg3panel-strip.XXXXXX)
    trap 'rm -f -- "$stripped"' EXIT
    "$BIN/awg-quick" strip /etc/amnezia/amneziawg/awgtop.conf > "$stripped"
    "$BIN/awg" syncconf "$AWG_IFACE" "$stripped" >/dev/null 2>&1 || fail 'syncconf failed (no secret output)'
    ip address replace "$AWG_ADDRESS" dev "$AWG_IFACE"
    ip link set dev "$AWG_IFACE" mtu 1280 up
    check_chains
    # Each active period gets a boot-specific token, also present in every
    # chain. A stale file alone never authorizes adoption or deletion.
    if ! owned; then
      for pair in 'filter AWG3P_IN' 'filter AWG3P_FWD' 'nat AWG3P_NAT' 'mangle AWG3P_MSS'; do
        read -r table name <<< "$pair"
        if iptables -w 10 -t "$table" -nL "$name" >/dev/null 2>&1; then fail 'firewall namespace appeared during startup'; fi
      done
      TAG="awg3p:${STAMP:0:16}:$BOOT:$(cat /proc/sys/kernel/random/uuid)"
      printf '%s\n' "$TAG" > "$STATE/network.owned"
    fi
    for pair in 'filter AWG3P_IN' 'filter AWG3P_FWD' 'nat AWG3P_NAT' 'mangle AWG3P_MSS'; do read -r table name <<< "$pair"; chain "$table" "$name"; done
    rule filter AWG3P_IN -p udp --dport 3478 -j ACCEPT
    rule filter AWG3P_IN -i lo -d "$AWG_PANEL" -p tcp --dport 8081 -j ACCEPT
    rule filter AWG3P_IN -i "$AWG_IFACE" -d "$AWG_PANEL" -p tcp --dport 8081 -j ACCEPT
    rule filter AWG3P_IN -i "$AWG_IFACE" -d "$AWG_PANEL" -p icmp --icmp-type echo-request -j ACCEPT
    rule filter AWG3P_IN -i "$AWG_IFACE" -j DROP
    rule filter AWG3P_IN -d "$AWG_PANEL" -p tcp --dport 8081 -j DROP
    rule filter AWG3P_FWD -i "$AWG_IFACE" -o "$AWG_IFACE" -j DROP
    rule filter AWG3P_FWD -i "$AWG_IFACE" -d 169.254.0.0/16 -j DROP
    for private in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do rule filter AWG3P_FWD -i "$AWG_IFACE" -d "$private" -j DROP; done
    rule filter AWG3P_FWD -i "$AWG_IFACE" -o "$AWG_EGRESS" -s "$AWG_NETWORK" -j ACCEPT
    rule filter AWG3P_FWD -i "$AWG_EGRESS" -o "$AWG_IFACE" -d "$AWG_NETWORK" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    rule nat AWG3P_NAT -s "$AWG_NETWORK" -o "$AWG_EGRESS" -j MASQUERADE
    rule mangle AWG3P_MSS -i "$AWG_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rule mangle AWG3P_MSS -o "$AWG_IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    jump filter INPUT AWG3P_IN
    jump filter FORWARD AWG3P_FWD
    jump nat POSTROUTING AWG3P_NAT
    jump mangle FORWARD AWG3P_MSS
    # Do not reset other sysctls or disable IPv6. Only this network namespace's
    # forwarding flag is required; stop deliberately does not turn it off.
    if [[ ! -f "$STATE/forwarding.previous" ]]; then sysctl -n net.ipv4.ip_forward > "$STATE/forwarding.previous"; fi
    sysctl -q -w net.ipv4.ip_forward=1
    ;;
  down)
    check_chains
    if ! owned; then rm -f -- "$STATE/network.owned"; exit 0; fi
    for tuple in 'filter INPUT AWG3P_IN' 'filter FORWARD AWG3P_FWD' 'nat POSTROUTING AWG3P_NAT' 'mangle FORWARD AWG3P_MSS'; do
      read -r table parent name <<< "$tuple"
      while iptables -w 10 -t "$table" -C "$parent" -m comment --comment "$TAG" -j "$name" 2>/dev/null; do iptables -w 10 -t "$table" -D "$parent" -m comment --comment "$TAG" -j "$name"; done
      if iptables -w 10 -t "$table" -nL "$name" >/dev/null 2>&1; then
        # Flush ONLY this ownership-stamped chain, never a shared table/chain.
        iptables -w 10 -t "$table" -F "$name"
        iptables -w 10 -t "$table" -X "$name"
      fi
    done
    rm -f -- "$STATE/network.owned"
    ;;
  *) fail 'usage: awgtop-runtime preflight|up|down' ;;
esac
