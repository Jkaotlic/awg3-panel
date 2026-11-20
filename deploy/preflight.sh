#!/usr/bin/env bash
# Shared read-only checks; caller supplies fail(), SUBNET and OWNED.
check_routes() {
  ip -4 route show table all | awk -v candidate="$SUBNET" -v owned="$OWNED" '
function lo(s, a,n,b){split(s,a,"/");b=(a[2]==""?32:a[2]);split(a[1],n,".");return int((n[1]*16777216+n[2]*65536+n[3]*256+n[4])/2^(32-b))*2^(32-b)}
function hi(s,a){split(s,a,"/");return lo(s)+2^(32-(a[2]==""?32:a[2]))-1}
{p=$1;if(p ~ /^(local|broadcast|unreachable|blackhole|prohibit|throw|anycast)$/)p=$2;
if(p=="default" || p !~ /^[0-9]+\./)next;
if(owned && $0 ~ /dev awgtop( |$)/)next;
if(lo(p)<=hi(candidate) && hi(p)>=lo(candidate))bad=1}
END {exit bad}' || fail 'VPN subnet overlaps a route (all routing tables checked)'
}

check_socket() {
  local proto=$1 port=$2 unit=$3 exe=$4 sockets pid line
  if [[ "$proto" == udp ]]; then sockets=$(ss -H -lunp "( sport = :$port )"); else sockets=$(ss -H -ltnp "( sport = :$port )"); fi
  [[ -n "$sockets" ]] || return 0
  (( OWNED )) && systemctl is-active --quiet "$unit" || fail "$proto port $port is occupied"
  pid=$(systemctl show "$unit" -p MainPID --value)
  [[ "$pid" =~ ^[1-9][0-9]*$ && $(readlink -f "/proc/$pid/exe") == "$exe" ]] || fail "cannot attribute port $port to owned service"
  while IFS= read -r line; do
    [[ "$line" == *"pid=$pid,"* ]] || fail "foreign listener on port $port"
  done <<< "$sockets"
}

check_units() {
  local unit fragment drop path dir
  for unit in awgtop.service awg3panel.service; do
    fragment=$(systemctl show "$unit" -p FragmentPath --value)
    drop=$(systemctl show "$unit" -p DropInPaths --value)
    [[ -z "$drop" ]] || fail "systemd overrides require manual review: $unit"
    if [[ -n "$fragment" ]]; then
      (( OWNED )) && [[ "$fragment" == "/etc/systemd/system/$unit" ]] || fail "existing systemd unit: $unit"
    fi
    while IFS= read -r path; do
      [[ -n "$path" ]] || continue
      for dir in "$path/$unit.d" "$path/service.d"; do
        [[ ! -e "$dir" && ! -L "$dir" ]] || fail "systemd drop-in directory requires manual review: $dir"
      done
      if [[ -e "$path/$unit" || -L "$path/$unit" ]]; then
        (( OWNED )) && [[ "$path" == /etc/systemd/system ]] || fail "existing systemd unit path: $path/$unit"
      fi
    done < <(systemd-analyze unit-paths)
  done
}
