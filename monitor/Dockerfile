# The monitor: rules + a model reviewer over the activity log, reached over SSH (user
# `monitor`) to log Claude Code in with a Claude Pro / Max plan. Outside the sandbox:
# on `dbnet` + `egress`, never `agentnet`. Build context: the repository root.
FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl jq procps less nano openssh-server python3 python3-pip libgomp1 \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
 && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd

COPY monitor/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /app/requirements.txt

# Tabular model (tabular.py): TabPFN v2 on CPU-only PyTorch, weights fetched at build
# time so the monitor needs no download at run time. INSTALL_TABPFN=0 skips it (the
# monitor then uses scikit-learn's ExtraTrees, from requirements.txt).
ARG INSTALL_TABPFN=1
ENV TABPFN_MODEL_CACHE_DIR=/opt/tabpfn TABPFN_NO_BROWSER=1
RUN if [ "$INSTALL_TABPFN" = "1" ]; then \
      pip install --no-cache-dir --break-system-packages --index-url https://download.pytorch.org/whl/cpu torch \
   && pip install --no-cache-dir --break-system-packages "tabpfn>=9,<10" \
   && python3 -c "import numpy as np; from tabpfn import TabPFNClassifier; from tabpfn.constants import ModelVersion; \
c = TabPFNClassifier.create_default_for_version(ModelVersion.V2, device='cpu'); \
c.fit(np.eye(4), [0, 1, 0, 1]); c.predict_proba(np.eye(4))" \
   && chmod -R a+rX /opt/tabpfn; \
    fi

ARG CLAUDE_CODE_VERSION=latest
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} && npm cache clean --force

RUN useradd -m -u 1002 -s /bin/bash monitor && mkdir -p /state && chown monitor:monitor /state
COPY monitor/db.py monitor/rules.py monitor/tools.py monitor/agent.py monitor/cc_backend.py \
     monitor/mcp_server.py monitor/tabular.py monitor/run.py /app/
COPY monitor/console/ /opt/aab/console/
COPY monitor/claude-settings.json /opt/aab/claude-settings.json
COPY common/ssh/sshd_config /etc/ssh/sshd_config.d/aab.conf
COPY common/ssh/setup-sshd.sh /usr/local/sbin/setup-sshd
COPY monitor/motd.sh /etc/profile.d/aab-motd.sh
COPY monitor/entrypoint.sh /entrypoint.sh
COPY monitor/aab-monitor /usr/local/bin/aab-monitor
RUN chmod 755 /entrypoint.sh /usr/local/sbin/setup-sshd /usr/local/bin/aab-monitor

WORKDIR /app
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
