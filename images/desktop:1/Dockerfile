# syntax=docker/dockerfile:1
# desktop:1 — prebuilt graphical environment for the computer-use API.
#
# Build / bake:
#   docker build -t desktop:1 'images/desktop:1/'
#   docker save desktop:1 -o /tmp/desktop-1.tar
#   ./bin/image rootfs -o 'images/desktop:1.ext4' docker-archive:/tmp/desktop-1.tar
FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b

LABEL org.createos.rootfs="desktop:1" \
      org.createos.desktop="xfce" \
      org.createos.browser="google-chrome"

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/root \
    LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    DISPLAY=:0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl wget gnupg locales dbus dbus-x11 git xz-utils \
        xvfb xfce4 xfce4-terminal openbox desktop-file-utils libgtk-3-bin \
        xdotool wmctrl scrot x11-xserver-utils x11-utils xclip \
        x11vnc novnc websockify \
        fonts-dejavu fonts-liberation fonts-noto-core fonts-noto-cjk \
        fonts-noto-color-emoji \
        adwaita-icon-theme-full hicolor-icon-theme \
        procps iproute2 iputils-ping dnsutils netcat-openbsd \
        openssh-server fuse3 python3 python3-venv \
    && sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
    && locale-gen \
    && wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
        -O /tmp/google-chrome.deb \
    && apt-get install -y --no-install-recommends /tmp/google-chrome.deb \
    && rm -f /tmp/google-chrome.deb \
    && fc-cache -f \
    && mkdir -p /etc/createos/post-resume.d /run/dbus /run/sshd /root/.ssh \
    && chmod 0700 /root/.ssh

# Match the Python library environment available in devbox:1. Use a dedicated
# venv rather than writing into Ubuntu's OS-managed Python installation.
COPY python-packages.txt /opt/createos/desktop-python-packages.txt
RUN python3 -m venv /opt/createos/python \
    && /opt/createos/python/bin/pip install --no-cache-dir \
        -r /opt/createos/desktop-python-packages.txt \
    && ln -sfn /opt/createos/python/bin/python /usr/local/bin/python \
    && ln -sfn /opt/createos/python/bin/python /usr/local/bin/python3 \
    && ln -sfn /opt/createos/python/bin/pip /usr/local/bin/pip \
    && ln -sfn /opt/createos/python/bin/pip /usr/local/bin/pip3 \
    && /opt/createos/python/bin/python -c 'import importlib.metadata as m; import matplotlib, numpy, pandas, pyarrow, scipy; assert m.version("anchorbrowser")'
COPY python-wrapper /usr/local/libexec/createos-python
COPY pip-wrapper /usr/local/libexec/createos-pip
RUN chmod 0755 /usr/local/libexec/createos-python /usr/local/libexec/createos-pip \
    && rm -f /usr/local/bin/python /usr/local/bin/python3 \
        /usr/local/bin/pip /usr/local/bin/pip3 \
    && ln -s /usr/local/libexec/createos-python /usr/local/bin/python \
    && ln -s /usr/local/libexec/createos-python /usr/local/bin/python3 \
    && ln -s /usr/local/libexec/createos-pip /usr/local/bin/pip \
    && ln -s /usr/local/libexec/createos-pip /usr/local/bin/pip3

# Node 22 is required by Claude Code and also provides the runtime used by
# Codex and Pi. Install the official archive system-wide so both root API
# execs and the unprivileged desktop terminal use the same runtime.
ARG NODEJS_VERSION=22.23.2
ARG NODEJS_LINUX_X64_SHA256=d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307
RUN curl -fsSL "https://nodejs.org/dist/v${NODEJS_VERSION}/node-v${NODEJS_VERSION}-linux-x64.tar.xz" \
        -o /tmp/node.tar.xz \
    && echo "${NODEJS_LINUX_X64_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
    && rm -f /tmp/node.tar.xz \
    && node --version \
    && npm --version

# AI coding CLIs. Cursor and OpenCode use their official installers; Pi,
# Codex, and Claude Code use pinned official npm releases. Copy the native
# Cursor/OpenCode installations out of root's private home so they also work
# in xfce4-terminal as the unprivileged `desktop` user. Cursor's launcher
# loads its bundled Node runtime and JavaScript files relative to itself, so
# preserve the complete version directory rather than copying one file.
ARG CODEX_VERSION=0.150.1
ARG CLAUDE_CODE_VERSION=2.1.247
ARG PI_VERSION=0.84.3
ARG OPENCODE_VERSION=1.18.23
RUN curl -fsSL https://opencode.ai/install | VERSION="${OPENCODE_VERSION}" bash \
    && curl -fsSL https://cursor.com/install | bash \
    && npm install -g \
         "@openai/codex@${CODEX_VERSION}" \
         "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
         "@earendil-works/pi-coding-agent@${PI_VERSION}" \
    && install -m 0755 "$(readlink -f /root/.opencode/bin/opencode)" /usr/local/bin/opencode \
    && mkdir -p /usr/local/lib/cursor-agent \
    && cp -a "$(dirname "$(readlink -f /root/.local/bin/agent)")"/. /usr/local/lib/cursor-agent/ \
    && ln -sfn /usr/local/lib/cursor-agent/cursor-agent /usr/local/bin/cursor-agent \
    && ln -sfn /usr/local/lib/cursor-agent/cursor-agent /usr/local/bin/agent \
    && command -v pi >/dev/null \
    && pi --version \
    && opencode --version \
    && agent --version \
    && cursor-agent --version \
    && codex --version \
    && claude --version

RUN useradd --create-home --shell /bin/bash desktop \
    && install -d -o desktop -g desktop -m 0700 \
        /home/desktop/.config /home/desktop/.cache /home/desktop/.local \
        /home/desktop/.local/share \
    && install -d -o desktop -g desktop -m 0755 /home/desktop/Desktop \
    && printf 'LANG=en_US.UTF-8\nLC_ALL=en_US.UTF-8\nDISPLAY=:0\n' > /etc/environment

# Install one canonical global AnchorBrowser skill and expose it to every
# bundled coding agent for both root API sessions and the desktop user.
COPY anchorbrowser-skill /usr/local/share/agent-skills/anchorbrowser
RUN for home in /root /home/desktop; do \
      for rel in \
          .agents/skills \
          .codex/skills \
          .claude/skills \
          .cursor/skills \
          .config/opencode/skills; do \
        mkdir -p "$home/$rel"; \
        ln -sfn /usr/local/share/agent-skills/anchorbrowser "$home/$rel/anchorbrowser"; \
      done; \
    done \
    && chown -R desktop:desktop \
        /home/desktop/.agents \
        /home/desktop/.codex \
        /home/desktop/.claude \
        /home/desktop/.cursor \
        /home/desktop/.config/opencode

# Stable browser defaults: no first-run wizard, translation popup, password
# manager, notifications, or background network chatter. Chrome runs as the
# unprivileged desktop user so its normal namespace sandbox remains enabled.
COPY chrome-policy.json /etc/opt/chrome/policies/managed/createos.json
COPY desktop-browser /usr/local/bin/desktop-browser
COPY xdg-open /usr/local/bin/xdg-open
COPY google-chrome.desktop /usr/share/applications/google-chrome.desktop
COPY start-desktop /usr/local/bin/start-fc-desktop
COPY fc-screen /usr/local/bin/fc-screen
COPY restart-screens /usr/local/bin/restart-fc-screens
COPY post-resume-desktop /etc/createos/post-resume.d/20-desktop
RUN chmod 0755 /usr/local/bin/desktop-browser /usr/local/bin/xdg-open \
        /usr/local/bin/fc-screen /usr/local/bin/restart-fc-screens \
        /usr/local/bin/start-fc-desktop \
        /etc/createos/post-resume.d/20-desktop \
    && update-desktop-database /usr/share/applications \
    && install -d -o desktop -g desktop -m 0700 /home/desktop/.config \
    && runuser -u desktop -- xdg-mime default google-chrome.desktop x-scheme-handler/http \
    && runuser -u desktop -- xdg-mime default google-chrome.desktop x-scheme-handler/https \
    && runuser -u desktop -- xdg-mime default google-chrome.desktop text/html

WORKDIR /home/desktop
