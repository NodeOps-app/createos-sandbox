# syntax=docker/dockerfile:1
# ubuntu:26.04 — minimal Ubuntu 26.04 LTS rootfs for createos microVMs.
#
# Direct FROM ubuntu:26.04 (no base-debian wrapper). Only critical binaries
# for a functional sandbox:
#   - shell (bash) + coreutils (already in the base)
#   - ca-certificates + curl (HTTPS downloads)
#   - openssh-server (createos SSH tunnel via gateway)
#   - geesefs (S3 disk mounts — /v1/disks feature)
#   - iproute2 (network diagnostics inside guest)
#
# Add language runtimes/dev tools per template on top of this.
#
# fc-agent runs as PID 1 (lives in initrd, not this rootfs). No CMD.
#
# Build / bake / register:
#   docker build -t 'ubuntu:26.04' 'images/ubuntu:26.04/'
#   docker save 'ubuntu:26.04' -o /tmp/ubuntu-26.tar
#   ./bin/image rootfs --size 4000 -o 'images/ubuntu:26.04.ext4' docker-archive:/tmp/ubuntu-26.tar
#   # serve.yaml: { name: "ubuntu:26.04", path: "images/ubuntu:26.04.ext4" }
#   # rootfs_catalog row: name='ubuntu:26.04'

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

# Critical packages only. --no-install-recommends keeps the rootfs slim.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        fuse3 \
        openssh-server \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# geesefs (S3 fuse mount) — required for /v1/disks. Not in apt; pulled
# from upstream release. Pinned to a specific version so rebuilds are
# reproducible; bump here when upstream ships a new stable.
ARG GEESEFS_VERSION=0.43.9
RUN curl -fsSL -o /usr/local/bin/geesefs \
        "https://github.com/yandex-cloud/geesefs/releases/download/v${GEESEFS_VERSION}/geesefs-linux-amd64" \
    && chmod +x /usr/local/bin/geesefs

# sshd key-only root login. Host keys are generated on first boot (small
# ssh-keygen run inside the guest — negligible boot cost).
RUN mkdir -p /run/sshd /root/.ssh \
    && chmod 700 /root/.ssh \
    && sed -i \
        -e 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' \
        -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
        /etc/ssh/sshd_config

# Pause/resume hook dirs (createos convention). Empty — templates or
# user scripts drop executables here to run before pause / after resume.
RUN mkdir -p /etc/createos/pre-pause.d /etc/createos/post-resume.d

# Agent unmountDisk calls `fusermount` (v2 name). fuse3 pkg ships
# `fusermount3` — symlink so live-detach works without agent change.
RUN [ -e /usr/bin/fusermount ] || ln -sf /usr/bin/fusermount3 /usr/bin/fusermount
