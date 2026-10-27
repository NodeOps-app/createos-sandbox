# syntax=docker/dockerfile:1
# debian:13 — minimal Debian (Debian 13 trixie — pinned) rootfs for createos microVMs.
# Same critical bins as ubuntu:26 — bash, curl, sshd, geesefs, iproute2.
#
# Build / bake / register:
#   docker build -t 'debian:13' 'images/debian:13/'
#   docker save 'debian:13' -o /tmp/debian-13.tar
#   ./bin/image rootfs --size 4000 -o 'images/debian:13.ext4' docker-archive:/tmp/debian-13.tar
#   # serve.yaml: { name: "debian:13", path: "/var/lib/createos/images/debian:13.ext4" }

FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        fuse3 \
        openssh-server \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

ARG GEESEFS_VERSION=0.43.9
RUN curl -fsSL -o /usr/local/bin/geesefs \
        "https://github.com/yandex-cloud/geesefs/releases/download/v${GEESEFS_VERSION}/geesefs-linux-amd64" \
    && chmod +x /usr/local/bin/geesefs

RUN mkdir -p /run/sshd /root/.ssh \
    && chmod 700 /root/.ssh \
    && sed -i \
        -e 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' \
        -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
        /etc/ssh/sshd_config

RUN mkdir -p /etc/createos/pre-pause.d /etc/createos/post-resume.d

# Agent unmountDisk calls `fusermount` (v2 name). fuse3 pkg ships
# `fusermount3` — symlink so live-detach works without agent change.
RUN [ -e /usr/bin/fusermount ] || ln -sf /usr/bin/fusermount3 /usr/bin/fusermount
