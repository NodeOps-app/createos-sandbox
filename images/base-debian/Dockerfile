# syntax=docker/dockerfile:1
# createos base image — Debian slim + sshd, ready to extend.
#
# Use as a starting point for your own rootfs:
#
#   FROM createos/base-debian
#   RUN apt-get update && apt-get install -y --no-install-recommends \
#         your-packages \
#    && rm -rf /var/lib/apt/lists/*
#
# Then bake into ext4:
#
#   docker build -t myapp:latest .
#   createos bake -o myapp.ext4 docker-daemon:myapp:latest
#
# Notes:
#   - fc-agent runs as PID 1 inside the microVM (lives in the initrd, not
#     this rootfs). No init scripts run; sshd is started on demand by
#     `createos-cli shell` or by your own exec call.
#   - sshd is configured for key-only root login — drop a pubkey at
#     /root/.ssh/authorized_keys (or use `createos-cli shell`, which does it for
#     you).
FROM debian:12-slim

# Avoid two common slim-image papercuts:
#   LANG=en_US.UTF-8 is inherited but the locale isn't generated → perl/apt
#     warn "Setting locale failed". C.UTF-8 is a builtin libc locale, always
#     available, behaves like UTF-8 without needing locale-gen.
#   DEBIAN_FRONTEND=dialog is the default → apt/dpkg try to start `dialog`
#     which isn't installed → "unable to initialize frontend: Dialog". Pinning
#     to noninteractive makes apt non-interactive and skips the frontend probe.
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive

# ENV alone only affects RUN/CMD layers — sshd login sessions don't
# inherit it. PAM reads /etc/environment; bash reads /etc/profile.d/.
# Write both so every shell (ssh, exec-it, direct exec) sees the vars.
RUN printf '%s\n' \
      'LANG=C.UTF-8' \
      'LC_ALL=C.UTF-8' \
      'DEBIAN_FRONTEND=noninteractive' \
      > /etc/environment \
 && printf '%s\n' \
      'export LANG=C.UTF-8' \
      'export LC_ALL=C.UTF-8' \
      'export DEBIAN_FRONTEND=noninteractive' \
      > /etc/profile.d/00-createos-locale.sh

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server \
      ca-certificates \
      curl \
      fuse3 \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /root/.ssh /etc/createos/pre-pause.d /etc/createos/post-resume.d \
 && chmod 700 /root/.ssh \
 && ssh-keygen -A \
 && sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config \
 && sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
 && sed -ri 's/^#?UsePAM.*/UsePAM no/' /etc/ssh/sshd_config

# geesefs (yandex-cloud/geesefs) — parallel FUSE S3 client written in Go.
# Used by the fc-agent as the preferred S3 backend (s3fs above is kept
# as a fallback for old initrds + as a debugging aid). Pinned to a
# release for build reproducibility; bump when upstream ships fixes.
# Static binary, no runtime deps beyond fuse3 (already installed).
ARG GEESEFS_VERSION=0.43.9
RUN ARCH=$(dpkg --print-architecture) \
 && case "$ARCH" in \
        amd64) GEESE_ARCH=linux-amd64 ;; \
        arm64) GEESE_ARCH=linux-arm64 ;; \
        *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac \
 && curl -fSL -o /usr/local/bin/geesefs \
      "https://github.com/yandex-cloud/geesefs/releases/download/v${GEESEFS_VERSION}/geesefs-${GEESE_ARCH}" \
 && chmod 0755 /usr/local/bin/geesefs \
 && /usr/local/bin/geesefs --version

# Pre-pause hook: lazy-unmount every createos S3 disk so the snapshot
# doesn't capture a live FUSE socket. The agent leaves a `mount_path`
# file under /run/createos/disks/<disk_id>/ for each active mount; this
# hook walks those and fusermount-u's them. Best-effort: a failed
# unmount doesn't block pause — the next resume will remount cleanly
# anyway when applyDisks fires off the post-resume MMDS push.
COPY pre-pause-10-disks /etc/createos/pre-pause.d/10-disks
RUN chmod 0755 /etc/createos/pre-pause.d/10-disks
