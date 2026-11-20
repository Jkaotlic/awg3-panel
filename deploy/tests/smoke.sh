#!/usr/bin/env bash
# Run ONLY in an expendable privileged Linux VM/container, never a user's VPS.
set -euo pipefail
umask 077
BASE=${1:?bundle directory required}
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ -e /run/awg3panel-disposable-test ]] || fail 'explicit disposable-test marker missing'
[[ ! -e /etc/awg3panel && ! -e /var/lib/awg3panel-bootstrap ]] || fail 'test requires a fresh system'
expect_fail() { if "$@" >/tmp/awg3panel-expected-error 2>&1; then fail 'expected refusal did not happen'; fi; }
mkdir -p /dev/net
[[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200
chmod 0666 /dev/net/tun
args=(--endpoint 172.30.1.1 --egress eth0)
for location in /run/systemd/system /usr/lib/systemd/system; do
  printf '[Service]\nExecStart=/bin/sleep infinity\n' > "$location/awgtop.service"
  systemctl daemon-reload
  expect_fail bash "$BASE/install.sh" "${args[@]}" --dry-run
  rm "$location/awgtop.service"
  systemctl daemon-reload
done
mkdir -p /run/systemd/system/awg3panel.service.d
printf '[Service]\nEnvironment=FOREIGN=1\n' > /run/systemd/system/awg3panel.service.d/foreign.conf
systemctl daemon-reload
expect_fail bash "$BASE/install.sh" "${args[@]}" --dry-run
rm /run/systemd/system/awg3panel.service.d/foreign.conf
rmdir /run/systemd/system/awg3panel.service.d
systemctl daemon-reload
ip route add table 100 10.66.0.0/16 dev lo
expect_fail bash "$BASE/install.sh" "${args[@]}" --dry-run
ip route del table 100 10.66.0.0/16 dev lo
socat TCP-LISTEN:8081,fork EXEC:/bin/cat >/dev/null 2>&1 & busy=$!
sleep .2
kill -0 "$busy" || fail 'TCP test listener did not start'
expect_fail bash "$BASE/install.sh" "${args[@]}" --dry-run
kill "$busy"; wait "$busy" 2>/dev/null || true
printf 'PASS: systemd units/drop-ins, policy route and wildcard TCP conflicts\n'
before=$(sha256sum /var/lib/dpkg/status)
cat >/run/systemd/system/firewalld.service <<'UNIT'
[Service]
ExecStart=/bin/sleep infinity
UNIT
systemctl daemon-reload
systemctl start firewalld.service
expect_fail bash "$BASE/install.sh" "${args[@]}" --dry-run
systemctl stop firewalld.service
rm /run/systemd/system/firewalld.service
systemctl daemon-reload
expect_fail bash "$BASE/install.sh" --endpoint 172.30.1.1 --egress missing-wan --dry-run
bash "$BASE/install.sh" "${args[@]}" --dry-run
[[ ! -e /etc/awg3panel && ! -e /var/lib/awg3panel-bootstrap && ! -e /run/awg3panel-install.lock ]] || fail 'dry-run wrote installation files'
[[ $(sha256sum /var/lib/dpkg/status) == "$before" ]] || fail 'dry-run changed packages'
bad=$(mktemp -d /root/awg3-bad-bundle.XXXXXX)
cp -a "$BASE/." "$bad/"
printf 'corruption\n' >> "$bad/bin/awg3setup"
expect_fail bash "$bad/install.sh" "${args[@]}" --dry-run
cp "$BASE/bin/awg3setup" "$bad/bin/awg3setup"
printf 'unverified\n' > "$bad/extra.txt"
expect_fail bash "$bad/install.sh" "${args[@]}" --dry-run
[[ ! -e /etc/awg3panel && ! -e /var/lib/awg3panel-bootstrap ]] || fail 'invalid bundle produced installation state'
mkdir -p /root/awg3-symlink-target /usr/local/libexec
ln -s /root/awg3-symlink-target /usr/local/libexec/awg3panel
expect_fail bash "$BASE/install.sh" "${args[@]}" --dry-run
rm /usr/local/libexec/awg3panel
[[ -z $(find /root/awg3-symlink-target -mindepth 1 -print -quit) ]] || fail 'wrote through a symlink'
ip route add 10.66.0.0/16 dev lo
expect_fail bash "$BASE/install.sh" "${args[@]}" --dry-run
ip route del 10.66.0.0/16 dev lo
ip link add awgtop type dummy
expect_fail bash "$BASE/install.sh" "${args[@]}" --dry-run
ip link del awgtop
socat UDP-RECVFROM:3478,fork EXEC:/bin/cat >/dev/null 2>&1 & busy=$!
sleep .2
kill -0 "$busy" || fail 'test UDP listener did not start'
expect_fail bash "$BASE/install.sh" "${args[@]}" --dry-run
kill "$busy"; wait "$busy" 2>/dev/null || true
printf 'PASS: dry-run, route/interface/socket conflicts\n'
# Exercise the package-install path as well: these are disposable test packages.
DEBIAN_FRONTEND=noninteractive apt-get remove -y curl iptables >/tmp/awg3-remove-test-packages.log
# Interrupt after preparation with an intentionally conflicting executable.
"$BASE/bin/awg3setup" prepare --endpoint 172.30.1.1 --egress eth0 >/dev/null
identity=$(sha256sum /etc/amnezia/amneziawg/awgtop.conf)
mkdir -p /usr/local/libexec/awg3panel
printf 'foreign-test-file\n' > /usr/local/libexec/awg3panel/doctor
expect_fail bash "$BASE/install.sh" "${args[@]}"
[[ $(cat /usr/local/libexec/awg3panel/doctor) == foreign-test-file ]] || fail 'foreign file was overwritten'
rm /usr/local/libexec/awg3panel/doctor
[[ $(sha256sum /etc/amnezia/amneziawg/awgtop.conf) == "$identity" ]] || fail 'partial resume rotated configuration'
bash "$BASE/install.sh" "${args[@]}"
printf 'PASS: partial failure retained state, successful resume\n'
cp /root/awg3panel-admin.conf /root/first-profile.saved
: > /root/awg3panel-admin.conf
expect_fail bash "$BASE/install.sh" "${args[@]}"
cp /root/first-profile.saved /root/awg3panel-admin.conf
rm /root/first-profile.saved
"$BASE/bin/awg3setup" admin-verify
printf 'PASS: unrelated or empty first profile refused\n'
profile=$(sha256sum /root/awg3panel-admin.conf)
identity=$(sha256sum /etc/amnezia/amneziawg/awgtop.conf)
bash "$BASE/install.sh" "${args[@]}"
[[ $(sha256sum /etc/amnezia/amneziawg/awgtop.conf) == "$identity" && $(sha256sum /root/awg3panel-admin.conf) == "$profile" ]] || fail 'repeat changed keys or profile'
[[ $(stat -c %a /root/awg3panel-admin.conf) == 600 && $(stat -c %a /root/awg3panel-access.txt) == 600 ]] || fail 'secret permissions wrong'
printf 'PASS: repeat preserves keys/profile and 0600 permissions\n'
ip netns add awg3client
ip link add veth-server type veth peer name veth-client
ip link set veth-client netns awg3client
ip address add 172.30.1.1/24 dev veth-server
ip link set veth-server up
ip netns exec awg3client ip link set lo up
ip netns exec awg3client ip address add 172.30.1.2/24 dev veth-client
ip netns exec awg3client ip link set veth-client up
ip netns exec awg3client /opt/awgtop/bin/amneziawg-go -f awgtest >/tmp/awg3client.log 2>&1 & client=$!
trap 'kill "$client" 2>/dev/null || true; ip netns del awg3client 2>/dev/null || true' EXIT
for _ in {1..50}; do ip netns exec awg3client /opt/awgtop/bin/awg show awgtest listen-port >/dev/null 2>&1 && break; sleep .1; done
/opt/awgtop/bin/awg-quick strip /root/awg3panel-admin.conf > /tmp/awg3client.stripped
ip netns exec awg3client /opt/awgtop/bin/awg syncconf awgtest /tmp/awg3client.stripped
ip netns exec awg3client ip address add 10.66.0.2/32 dev awgtest
ip netns exec awg3client ip link set awgtest mtu 1280 up
ip netns exec awg3client ip route add 10.66.0.1/32 dev awgtest
ip netns exec awg3client ping -c 4 -W 4 -s 1000 10.66.0.1 >/tmp/awg3client-ping.log
[[ $(ip netns exec awg3client curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 10 http://10.66.0.1:8081/) == 401 ]] || fail 'panel inaccessible through VPN'
/opt/awgtop/bin/awg show awgtop transfer | awk '$2>0 && $3>0 {ok=1} END{exit !ok}' || fail 'no bidirectional encrypted payload'
printf 'PASS: real userspace AWG handshake, 1000-byte payload, panel HTTP401 through encrypted tunnel\n'
systemctl restart awg3panel.service
/usr/local/libexec/awg3panel/doctor
[[ $(sha256sum /root/awg3panel-admin.conf) == "$profile" ]] || fail 'panel restart changed profile'
systemctl restart awgtop.service
/usr/local/libexec/awg3panel/doctor
[[ $(sha256sum /etc/amnezia/amneziawg/awgtop.conf) == "$identity" ]] || fail 'interface restart changed configuration'
printf 'PASS: service restarts preserve keys/configuration\n'
bash "$BASE/deploy/rollback.sh" --dry-run
bash "$BASE/deploy/rollback.sh" --apply
systemctl is-active --quiet awgtop.service && fail 'runtime rollback left interface active'
iptables -t nat -nL AWG3P_NAT >/dev/null 2>&1 && fail 'rollback left owned NAT chain'
[[ $(sha256sum /etc/amnezia/amneziawg/awgtop.conf) == "$identity" ]] || fail 'rollback lost configuration'
[[ ! -e /var/lib/awg3panel-bootstrap/network.owned ]] || fail 'stale network ownership marker'
iptables -t filter -N AWG3P_IN
iptables -t filter -A AWG3P_IN -s 192.0.2.1 -j RETURN
expect_fail /usr/local/libexec/awg3panel/awgtop-runtime preflight
expect_fail /usr/local/libexec/awg3panel/awgtop-runtime down
iptables -t filter -C AWG3P_IN -s 192.0.2.1 -j RETURN || fail 'foreign chain changed'
iptables -t filter -F AWG3P_IN
iptables -t filter -X AWG3P_IN
ip route add table 100 10.66.0.0/16 dev lo
expect_fail /usr/local/libexec/awg3panel/awgtop-runtime preflight
ip route del table 100 10.66.0.0/16 dev lo
bash "$BASE/install.sh" "${args[@]}"
# A failure before publishing the first profile must still permit rollback.
mv /root/awg3panel-admin.conf /root/first-profile.saved
bash "$BASE/deploy/rollback.sh" --apply
systemctl is-active --quiet awgtop.service && fail 'partial rollback left runtime active'
mv /root/first-profile.saved /root/awg3panel-admin.conf
bash "$BASE/install.sh" "${args[@]}"
printf 'PASS: protected backup, runtime rollback and recovery\nALL SMOKE CHECKS PASSED\n'
