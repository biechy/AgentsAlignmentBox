# The sandbox: where Claude Code and Codex agents work, reached over SSH (user `agent`).
# Its only network is `agentnet` (no route out): every request goes through the proxy.
# Build context: the repository root (see docker-compose.yml).
FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq ripgrep procps less unzip nano vim-tiny tmux \
      openssh-server python3 python3-pip python3-venv \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
 && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd

ARG CLAUDE_CODE_VERSION=latest
ARG CODEX_VERSION=latest
ARG INSTALL_CODEX=1
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
 && if [ "$INSTALL_CODEX" = "1" ]; then npm install -g @openai/codex@${CODEX_VERSION}; fi \
 && npm cache clean --force

# The login user is `agent` (the image's `node` user, uid 1000, renamed).
RUN usermod -l agent -d /home/agent -m -s /bin/bash node && groupmod -n agent node

COPY sandbox/claude-home/ /opt/aab/claude-home/
COPY sandbox/codex-home/ /opt/aab/codex-home/
# Root-owned: agents can read but not change or disable them.
COPY sandbox/sandbox/tag_tool_call.py /opt/sandbox/tag_tool_call.py
COPY sandbox/sandbox/managed-settings.json /etc/claude-code/managed-settings.json
COPY common/ssh/sshd_config /etc/ssh/sshd_config.d/aab.conf
COPY sandbox/sshd_launcher.conf /etc/ssh/sshd_config.d/aab-launcher.conf
COPY common/ssh/setup-sshd.sh /usr/local/sbin/setup-sshd
COPY sandbox/bin/ /usr/local/bin/
COPY sandbox/motd.sh /etc/profile.d/aab-motd.sh
COPY sandbox/session-env.sh /etc/profile.d/00-aab-session.sh
# Also for non-login shells (`ssh host command`, IDE / app connections): first line of bash.bashrc.
RUN sed -i '1i [ -r /etc/profile.d/00-aab-session.sh ] && . /etc/profile.d/00-aab-session.sh' /etc/bash.bashrc
COPY sandbox/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /usr/local/sbin/setup-sshd /usr/local/bin/aab-* \
 && mkdir -p /workspace && chown agent:agent /workspace

WORKDIR /workspace
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
