ARG TEST_BASE=ubuntu:24.04
FROM ${TEST_BASE}
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus iproute2 iptables curl ca-certificates util-linux iputils-ping socat python3 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
