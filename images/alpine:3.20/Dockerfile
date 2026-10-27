# syntax=docker/dockerfile:1
# alpine:3.20 — minimal Alpine (musl + busybox) rootfs for createos microVMs.
# ~5x smaller than debian/ubuntu variants. Package names differ:
#   openssh-server → openssh; apt → apk. bash NOT default shell (busybox
#   sh works), installed explicitly for script portability.
#
# Build / bake / register:
#   docker build -t 'alpine:3.20' 'images/alpine:3.20/'
#   docker save 'alpine:3.20' -o /tmp/alpine-3.20.tar
#   ./bin/image rootfs --size 2000 -o 'images/alpine:3.20.ext4' docker-archive:/tmp/alpine-3.20.tar

FROM alpine:3.20

RUN apk add --no-cache \
        bash \
        ca-certificates \
        curl \
        fuse3 \
        openssh \
        iproute2 \
        util-linux

ARG GEESEFS_VERSION=0.43.9
RUN curl -fsSL -o /usr/local/bin/geesefs \
        "https://github.com/yandex-cloud/geesefs/releases/download/v${GEESEFS_VERSION}/geesefs-linux-amd64" \
    && chmod +x /usr/local/bin/geesefs

RUN mkdir -p /run/sshd /root/.ssh \
    && chmod 700 /root/.ssh \
    && ssh-keygen -A \
    && sed -i \
        -e 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' \
        -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
        /etc/ssh/sshd_config

RUN mkdir -p /etc/createos/pre-pause.d /etc/createos/post-resume.d

# Agent unmountDisk calls `fusermount` (v2 name). fuse3 pkg ships
# `fusermount3` — symlink so live-detach works without agent change.
RUN [ -e /usr/bin/fusermount ] || ln -sf /usr/bin/fusermount3 /usr/bin/fusermount
