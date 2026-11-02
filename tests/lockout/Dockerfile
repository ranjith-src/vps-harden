# A fresh VPS to test vps-harden on: real systemd, sshd and sudo.
# Everything the script would install is baked in, so its runs take seconds.
# Where sudo-rs exists it gets installed next to sudo, as ubuntu-minimal does on Ubuntu 26.04.
# Its alternatives priority is higher, so that is the sudo these tests run against there.
ARG BASE=ubuntu:24.04
FROM ${BASE}
ENV container=docker
RUN export DEBIAN_FRONTEND=noninteractive \
 && apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv dbus openssh-server openssh-client sudo \
      iproute2 procps ca-certificates kmod rsyslog cron expect \
      curl wget jq htop tree unzip ufw iptables fail2ban python3-systemd \
      auditd audispd-plugins logwatch unattended-upgrades \
 && (apt-get install -y -qq --no-install-recommends age || true) \
 && if apt-cache show sudo-rs >/dev/null 2>&1; then apt-get install -y -qq --no-install-recommends sudo-rs; fi \
 && curl -fsSL -o /usr/local/bin/sops \
      "https://github.com/getsops/sops/releases/download/v3.9.4/sops-v3.9.4.linux.$(dpkg --print-architecture)" \
 && chmod 755 /usr/local/bin/sops \
 && rm -f /usr/sbin/policy-rc.d \
 && rm -rf /var/lib/apt/lists/*
# Units that have no job in a container.
RUN systemctl mask getty.target console-getty.service systemd-udevd.service \
      systemd-udev-trigger.service systemd-modules-load.service systemd-sysctl.service \
      sys-kernel-debug.mount sys-kernel-tracing.mount sys-kernel-config.mount \
      systemd-logind.service 2>/dev/null || true
RUN systemctl enable ssh 2>/dev/null || true
COPY entrypoint.sh /usr/local/sbin/vps-entrypoint
COPY answer.exp /usr/local/sbin/answer
RUN chmod 755 /usr/local/sbin/vps-entrypoint /usr/local/sbin/answer
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/sbin/vps-entrypoint"]
