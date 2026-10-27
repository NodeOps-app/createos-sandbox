# syntax=docker/dockerfile:1
# createos base image — Alpine + sshd, ready to extend.
#
# Use as a starting point for your own rootfs:
#
#   FROM createos/base-alpine
#   RUN apk add --no-cache your-packages
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
FROM alpine:3.21

# busybox login reads /etc/environment via PAM-equivalent path; ash sources
# /etc/profile + /etc/profile.d/*.sh. Mirror Debian image's locale wiring so
# `createos-cli shell` users get a sane LANG regardless of distro.
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN printf '%s\n' \
      'LANG=C.UTF-8' \
      'LC_ALL=C.UTF-8' \
      > /etc/environment \
 && mkdir -p /etc/profile.d \
 && printf '%s\n' \
      'export LANG=C.UTF-8' \
      'export LC_ALL=C.UTF-8' \
      > /etc/profile.d/00-createos-locale.sh

RUN apk add --no-cache \
      openssh-server \
      ca-certificates \
      curl \
      fuse3 \
 && mkdir -p /run/sshd /root/.ssh /etc/createos/pre-pause.d /etc/createos/post-resume.d \
 && chmod 700 /root/.ssh \
 && ssh-keygen -A \
 && sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config \
 && sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
 && sed -ri 's/^#?UsePAM.*/UsePAM no/' /etc/ssh/sshd_config

# geesefs — preferred S3 FUSE backend (parallel by default, no tmpfs
# reservation, ~10x faster on small-file workloads than s3fs). Pinned;
# bump for upstream fixes. See base-debian/Dockerfile for rationale.
ARG GEESEFS_VERSION=0.43.9
RUN ARCH=$(apk --print-arch) \
 && case "$ARCH" in \
        x86_64)  GEESE_ARCH=linux-amd64 ;; \
        aarch64) GEESE_ARCH=linux-arm64 ;; \
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
