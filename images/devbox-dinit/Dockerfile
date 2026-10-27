# devbox-dinit — experimental rootfs: dinit as the in-VM service manager
# behind fc-agent, with a systemctl→dinitctl shim for package compat.
#
# This is a TEST image to validate the dinit + shim architecture:
#   - dinit supervises services (sd_notify + cgroup support)
#   - /usr/bin/systemctl is a shim mapping verbs to dinitctl
#   - busybox crond runs as a dinit service
#   - a dummy "critical" service halts the VM on exit (finish script)
#
# Build / bake:
#   docker build -t devbox-dinit:1 images/devbox-dinit/
#   docker save devbox-dinit:1 -o /tmp/devbox-dinit.tar
#   ./bin/image rootfs -o images/devbox-dinit.ext4 docker-archive:/tmp/devbox-dinit.tar
FROM debian:13-slim

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 DEBIAN_FRONTEND=noninteractive

# ── build deps + dinit from source ───────────────────────────────────
# dinit isn't packaged in Debian; compile the release tag. It's a small
# C++ project — builds in ~30s. m4 + g++ + the dinit build system.
ARG DINIT_VERSION=0.19.4
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git g++ make m4 \
      busybox procps iproute2 \
 && curl -fsSL "https://github.com/davmac314/dinit/archive/refs/tags/v${DINIT_VERSION}.tar.gz" \
      | tar -xz -C /tmp \
 && cd "/tmp/dinit-${DINIT_VERSION}" \
 && make \
 && make install \
 && cd / && rm -rf "/tmp/dinit-${DINIT_VERSION}" \
 && apt-get purge -y g++ make m4 git \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && dinit --version

# ── dinit service directory ──────────────────────────────────────────
RUN mkdir -p /etc/dinit.d /etc/dinit.d/boot.d /var/log/dinit

# boot bundle — the top-level target dinit brings up.
COPY dinit.d/boot          /etc/dinit.d/boot
COPY dinit.d/crond         /etc/dinit.d/crond
COPY dinit.d/critical      /etc/dinit.d/critical
COPY dinit.d/critical-finish /etc/dinit.d/critical-finish
COPY critical-svc          /usr/local/bin/critical-svc
RUN chmod 0755 /etc/dinit.d/critical-finish /usr/local/bin/critical-svc

# ── systemctl → dinitctl shim ────────────────────────────────────────
COPY systemctl-shim /usr/bin/systemctl
RUN chmod 0755 /usr/bin/systemctl

# busybox applet links for crond etc.
RUN busybox --install -s /usr/local/bin 2>/dev/null || true \
 && mkdir -p /var/spool/cron/crontabs

WORKDIR /workspace
