# syntax=docker/dockerfile:1
# devbox — multi-runtime workspace (bun, node, python, go, rust) + sshd
# + Docker engine (containerd + buildx + compose). fc-agent is PID 1;
# sshd is started by `createos-cli shell` (or manually via exec); Docker is
# started on demand via `start-docker` (mounts cgroup2, bind-mounts
# data dirs onto raw ext4, launches dockerd+containerd).
#
# History: Docker used to live in a separate `devbox-docker:1` rootfs.
# Merged into devbox:1 since the engine is ~350 MB on disk and zero
# CPU/memory cost when not running — no reason to maintain two
# rootfses for users who might want either.
#
# Build / bake / register pipeline. Directory name, image tag, ext4
# filename, serve.yaml entry, and rootfs_catalog row all share the
# `devbox:1` identifier:
#
#   docker build -t devbox:1 'images/devbox:1/'
#   docker save devbox:1 -o /tmp/devbox.tar
#   ./bin/image rootfs -o 'images/devbox:1.ext4' docker-archive:/tmp/devbox.tar
#   # NOTE: docker-daemon:devbox:1 doesn't work — skopeo's URI parser
#   # treats the second colon as a separator. Use docker-archive: with
#   # an intermediate tarball.
#   # serve.yaml: { name: "devbox:1", path: "images/devbox:1.ext4" }
#   # rootfs_catalog row: name='devbox:1'
#
# Bumping: copy this dir to images/devbox:2/, build devbox:2, bake to
# images/devbox:2.ext4, register under name='devbox:2', then mark
# devbox:1 deprecated/disabled with successor='devbox:2'. Ext4 binaries
# stay out of git (.gitignore); this Dockerfile is the only source of
# truth.
FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b

LABEL org.createos.rootfs="devbox:1" \
      org.createos.runtimes="bun,node,python,go,rust,docker" \
      org.createos.sshd="true"

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/root \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# System deps + sshd + FUSE userspace + s3fs (S3 mount). Debian names fd as
# fdfind to avoid a package-name collision, so expose the conventional command
# expected by development tools and shell snippets.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git wget ca-certificates zstd tmux unzip zip jq build-essential \
        ripgrep fd-find fzf tree htop less file rsync socat sqlite3 strace \
        libssl-dev pkg-config gpg libbz2-dev libreadline-dev libsqlite3-dev \
        zlib1g-dev libffi-dev liblzma-dev tk-dev gnupg lsof procps \
        openssh-server \
        fuse3 s3fs rclone \
        iputils-ping dnsutils netcat-openbsd \
        python3-setuptools \
    && : "keep /var/lib/apt/lists/ so users can 'apt install X' without update" \
    && mkdir -p /etc/createos/pre-pause.d /etc/createos/post-resume.d \
    && ln -sfn /usr/bin/fdfind /usr/local/bin/fd

# mikefarah/yq is the jq-compatible YAML processor users generally expect from
# the `yq` command. Ubuntu's package with that name is a different Python tool.
ARG YQ_VERSION=4.53.3
ARG YQ_SHA256=fa52a4e758c63d38299163fbdd1edfb4c4963247918bf9c1c5d31d84789eded4
RUN curl -fsSL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" \
        -o /usr/local/bin/yq \
    && echo "${YQ_SHA256}  /usr/local/bin/yq" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/yq \
    && yq --version

# sshd config + locale propagation to PAM/profile
RUN mkdir -p /run/sshd /root/.ssh \
    && chmod 700 /root/.ssh \
    && ssh-keygen -A \
    && sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?UsePAM.*/UsePAM no/' /etc/ssh/sshd_config \
    && printf 'LANG=C.UTF-8\nLC_ALL=C.UTF-8\nDEBIAN_FRONTEND=noninteractive\n' > /etc/environment \
    && printf 'export LANG=C.UTF-8\nexport LC_ALL=C.UTF-8\nexport DEBIAN_FRONTEND=noninteractive\nexport PATH=/usr/local/bin:/root/.asdf/shims:/root/.opencode/bin:/root/.local/bin:$PATH\n' \
        > /etc/profile.d/00-createos-devbox.sh

# asdf core
ARG ASDF_VERSION=0.19.0
ENV PATH=/usr/local/bin:/root/.asdf/shims:$PATH
RUN set -xe && \
    mkdir -p /root/.asdf/shims && \
    wget -q https://github.com/asdf-vm/asdf/releases/download/v${ASDF_VERSION}/asdf-v${ASDF_VERSION}-linux-amd64.tar.gz && \
    tar -xzf asdf-v${ASDF_VERSION}-linux-amd64.tar.gz && \
    mv asdf /bin/asdf && \
    rm asdf-v${ASDF_VERSION}-linux-amd64.tar.gz && \
    asdf version && \
    asdf plugin add nodejs && \
    asdf plugin add bun && \
    asdf plugin add golang && \
    asdf plugin add rust && \
    asdf plugin add python

# Node.js — LTS (currently 22.x "Jod"). node-gyp is installed later,
# AFTER the direct-binary symlink overrides land, so it resolves the
# real npm binary rather than the asdf bash shim.
ARG NODEJS_VERSION=lts
RUN asdf install nodejs ${NODEJS_VERSION} && \
    NODE_RESOLVED=$(asdf list nodejs | tr -d ' *') && \
    asdf set nodejs ${NODE_RESOLVED} --home && \
    node --version && \
    asdf reshim nodejs

# Bun — stable (no LTS concept)
RUN asdf install bun latest && \
    BUN_RESOLVED=$(asdf list bun | tr -d ' *') && \
    asdf set bun ${BUN_RESOLVED} --home && \
    bun --version

# Python — match the version used by the HPC benchmark toolchain.
ARG PYTHON_VERSION=3.13.14
COPY python-packages.txt /opt/createos/devbox-python-packages.txt
RUN asdf install python ${PYTHON_VERSION} && \
    asdf set python ${PYTHON_VERSION} --home && \
    python --version && \
    pip install --no-cache-dir setuptools \
        -r /opt/createos/devbox-python-packages.txt && \
    python -c 'import importlib.metadata as m; import matplotlib, numpy, pandas, pyarrow, scipy; assert m.version("anchorbrowser")'

# Go — 1.26.0
ARG GOLANG_VERSION=1.26.0
RUN asdf install golang ${GOLANG_VERSION} && \
    asdf set golang ${GOLANG_VERSION} --home && \
    go version

# Rust — stable channel (no LTS)
ARG RUST_VERSION=1.83.0
RUN asdf install rust ${RUST_VERSION} && \
    asdf set rust ${RUST_VERSION} --home && \
    rustc --version

# Expose asdf-managed runtimes to non-login shells (e.g. `ssh host 'cmd'`,
# which doesn't source /etc/profile.d). Symlink every shim into a directory
# that's on the default PATH baked into login.defs.
RUN ln -sf /root/.asdf/shims/* /usr/local/bin/

# Override the shim symlinks for node/npm/npx/corepack with direct
# pointers to the real binaries. Reason: bun (and other tools that spawn
# via execve() without a shell) can't run bash-script shims; they fail
# with exit code 126. Direct binaries fix that. asdf stays intact for
# everything else; only these four (plus `python`/`python3` → the real asdf
# Python) go
# through /usr/local/bin as real executables.
RUN NODE_DIR=$(asdf where nodejs) && \
    PYTHON_DIR=$(asdf where python) && \
    ln -sfn "$NODE_DIR/bin/node"     /usr/local/bin/node && \
    ln -sfn "$NODE_DIR/bin/npm"      /usr/local/bin/npm && \
    ln -sfn "$NODE_DIR/bin/npx"      /usr/local/bin/npx && \
    ln -sfn "$NODE_DIR/bin/corepack" /usr/local/bin/corepack && \
    ln -sfn "$PYTHON_DIR/bin/python"  /usr/local/bin/python && \
    ln -sfn "$PYTHON_DIR/bin/python3" /usr/local/bin/python3

# Fix 3: install node-gyp globally, AFTER the direct-binary symlinks
# are in place so `npm` resolves to the real binary (bun-compatible)
# instead of the asdf bash shim. Also symlink node-gyp itself so
# execve()-based spawners (bun, tree-sitter build) hit a real script
# with a normal shebang.
RUN npm install -g node-gyp && \
    ln -sfn "$(asdf where nodejs)/bin/node-gyp" /usr/local/bin/node-gyp

# Docker CE (engine + CLI + containerd + buildx + compose) from
# Docker's official Ubuntu apt repo.
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
            https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
    && : "keep /var/lib/apt/lists/ so users can 'apt install X' without update" \
    && systemctl disable docker.service docker.socket containerd.service 2>/dev/null || true

# Docker startup helper + post-resume hook. fc-agent is PID 1, not
# systemd, so dockerd doesn't auto-start at boot. The /usr/local/bin/docker
# wrapper auto-starts it on first invocation; explicit `start-docker`
# remains for users who want to bring up the daemon ahead of time.
COPY start-docker /usr/local/bin/start-docker
RUN chmod 0755 /usr/local/bin/start-docker
COPY post-resume-docker /etc/createos/post-resume.d/10-docker
RUN chmod 0755 /etc/createos/post-resume.d/10-docker

# geesefs — high-performance S3 FUSE mount used by fc-agent for the
# /v1/disks feature. Pinned to a specific release for reproducibility;
# bump manually when a new version brings a fix or feature we want.
ARG GEESEFS_VERSION=0.43.9
RUN curl -fsSL "https://github.com/yandex-cloud/geesefs/releases/download/v${GEESEFS_VERSION}/geesefs-linux-amd64" \
        -o /usr/local/bin/geesefs \
    && chmod 0755 /usr/local/bin/geesefs \
    && /usr/local/bin/geesefs --version 2>&1 | head -1

# Pre-pause hook for createos S3 disks: lazy-unmounts every active
# mount the agent recorded under /run/createos/disks/*/mount_path so the
# snapshot doesn't capture a live FUSE socket.
COPY pre-pause-disks /etc/createos/pre-pause.d/10-disks
RUN chmod 0755 /etc/createos/pre-pause.d/10-disks

# Self-lifecycle: the fc-agent creates a FIFO at /run/self so any process
# in the sandbox can end its own life without curl:
#     echo park   > /run/self   # snapshot + tear down
#     echo retire > /run/self   # destroy permanently
# Nothing to install here — the FIFO is created by fc-agent at boot.

# Wrapper at /usr/local/bin/docker (earlier in PATH than the
# docker-ce-installed /usr/bin/docker) auto-starts the daemon on
# first invocation. Result: `docker ps` from a freshly-shelled
# sandbox just works, no `start-docker` required.
COPY docker-wrapper /usr/local/bin/docker
RUN chmod 0755 /usr/local/bin/docker

# OpenRC — a real, lightweight service manager. fc-agent is PID 1 (not
# systemd), but installers like `curl … get.k3s.io | sh` need a
# recognised service supervisor. k3s natively supports OpenRC: its
# installer detects /sbin/openrc-run and writes an /etc/init.d/ service.
# OpenRC is honest (no faked systemd marker) and Docker doesn't mistake
# it for systemd — so Docker stays on the cgroupfs driver and works
# with no configuration. Container data dirs + cgroup2 are set up by
# fc-agent at boot.
#
# Ubuntu 26.04 (dev branch) has no openrc package — build from source.
ARG OPENRC_VERSION=0.62.6
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        meson ninja-build gcc pkg-config curl ca-certificates libcap-dev \
    && curl -fsSL "https://github.com/OpenRC/openrc/archive/refs/tags/${OPENRC_VERSION}.tar.gz" \
        | tar -xz -C /tmp \
    && cd "/tmp/openrc-${OPENRC_VERSION}" \
    && meson setup build -Dpam=false -Dselinux=disabled --prefix=/usr \
    && ninja -C build \
    # Install into a DESTDIR staging tree, then copy into /. A direct
    # ninja-install fails: meson_runlevels.sh (set -e) chokes when it
    # populates /etc/runlevels against the live root. Staged into a
    # clean tree it succeeds, and openrc-run lands at /sbin/openrc-run
    # — exactly where the k3s installer's verify_system() looks.
    && DESTDIR=/tmp/oc-dest ninja -C build install \
    # Copy each top-level dir's *contents* into the live tree. Plain
    # `cp -a oc-dest/. /` fails on Ubuntu's usrmerge (/sbin, /bin are
    # symlinks → "cannot overwrite non-directory"). Copying into the
    # dir follows the symlink (oc-dest/sbin → /sbin → /usr/sbin).
    && (cd /tmp/oc-dest && for top in *; do cp -a "$top/." "/$top/"; done) \
    && ldconfig \
    && cd / && rm -rf "/tmp/openrc-${OPENRC_VERSION}" /tmp/oc-dest \
    && apt-get purge -y meson ninja-build \
    && apt-get autoremove -y \
    && : "keep /var/lib/apt/lists/ so users can 'apt install X' without update" \
    && test -x /sbin/openrc-run && echo "openrc-run installed"

# AI coding CLIs. Pi, OpenCode, Codex, and Claude Code use their official npm
# packages on the Node runtime already baked above. Pin every npm release so
# rebuilding devbox:1 cannot silently change these tools. Cursor's installer
# exposes both `agent` (current
# command) and `cursor-agent` (compatibility command) under /root/.local/bin.
#
# Re-sync every tool directory into /usr/local/bin so commands work from
# non-login shells (`ssh host 'cmd'`, createos exec), not only root's profile.
ARG CODEX_VERSION=0.160.0
ARG CLAUDE_CODE_VERSION=2.1.289
ARG PI_VERSION=1.0.3
ARG OPENCODE_VERSION=1.18.34
ARG AGENT_BROWSER_VERSION=0.27.3
RUN curl -fsSL https://cursor.com/install | bash \
 && npm install -g \
      "@openai/codex@${CODEX_VERSION}" \
      "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
      "@earendil-works/pi-coding-agent@${PI_VERSION}" \
      "opencode-ai@${OPENCODE_VERSION}" \
      "agent-browser@${AGENT_BROWSER_VERSION}" \
 && asdf reshim nodejs
RUN for d in /root/.asdf/shims /root/.opencode/bin /root/.local/bin; do \
        [ -d "$d" ] && ln -sf "$d"/* /usr/local/bin/ 2>/dev/null || true; \
    done; \
    pi --version \
    && opencode --version \
    && agent --version \
    && cursor-agent --version \
    && codex --version \
    && claude --version \
    && agent-browser --version

# Global AnchorBrowser agent skill. Keep one canonical, read-only copy and
# expose it through the discovery paths used by the bundled coding agents.
COPY anchorbrowser-skill /usr/local/share/agent-skills/anchorbrowser
RUN for dir in \
        /root/.agents/skills \
        /root/.codex/skills \
        /root/.claude/skills \
        /root/.cursor/skills \
        /root/.config/opencode/skills; do \
      mkdir -p "$dir"; \
      ln -sfn /usr/local/share/agent-skills/anchorbrowser "$dir/anchorbrowser"; \
    done

# Re-apply Fix 1 + Fix 3 symlink overrides AFTER the AI CLI re-sync
# above (which uses `ln -sf` over /root/.asdf/shims and would clobber
# any earlier direct-binary symlinks). This block must be the LAST
# writer to /usr/local/bin/{node,npm,npx,corepack,node-gyp,python,python3}.
RUN NODE_DIR=$(asdf where nodejs) && \
    PYTHON_DIR=$(asdf where python) && \
    ln -sfn "$NODE_DIR/bin/node"     /usr/local/bin/node && \
    ln -sfn "$NODE_DIR/bin/npm"      /usr/local/bin/npm && \
    ln -sfn "$NODE_DIR/bin/npx"      /usr/local/bin/npx && \
    ln -sfn "$NODE_DIR/bin/corepack" /usr/local/bin/corepack && \
    ln -sfn "$NODE_DIR/bin/node-gyp" /usr/local/bin/node-gyp && \
    ln -sfn "$PYTHON_DIR/bin/python"  /usr/local/bin/python && \
    ln -sfn "$PYTHON_DIR/bin/python3" /usr/local/bin/python3

# Record the installed runtime's file pages, not a running user process.
# This optional image manifest is consumed before the VM template snapshot.
COPY warmup.py /opt/createos/warmup.py
RUN /usr/bin/python3 /opt/createos/warmup.py \
    --output /etc/createos/warmup.json /usr/local/bin/node --version

WORKDIR /workspace
EXPOSE 22 2375 4096
