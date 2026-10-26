#!/bin/bash
# Sandbox entrypoint (root): trust the proxy CA, publish the environment to SSH
# sessions, prepare sshd and the agent's home, then run sshd in the foreground.
set -euo pipefail

CA=/ca-public/mitmproxy-ca-cert.pem
for _ in $(seq 1 120); do [ -s "$CA" ] && break; sleep 0.5; done
if [ ! -s "$CA" ]; then
  echo "proxy CA certificate not found at $CA (is the proxy running?)" >&2
  exit 1
fi
cp "$CA" /usr/local/share/ca-certificates/sandbox-proxy.crt
update-ca-certificates >/dev/null 2>&1

# SSH sessions do not inherit the container environment: pam_env reads /etc/environment.
BUNDLE=/etc/ssl/certs/ca-certificates.crt
{
  for v in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy AAB_WEB_PORT; do
    echo "$v=${!v}"
  done
  echo "NODE_EXTRA_CA_CERTS=$CA"
  for v in SSL_CERT_FILE REQUESTS_CA_BUNDLE PIP_CERT CODEX_CA_CERTIFICATE CURL_CA_BUNDLE GIT_SSL_CAINFO; do
    echo "$v=$BUNDLE"
  done
  # Credentials and settings for Claude Code / Codex (ANTHROPIC_*, CLAUDE_*, OPENAI_*,
  # CODEX_*); empty ones are left out so the CLIs fall back to /login.
  for v in $(compgen -e | grep -E '^(ANTHROPIC_|CLAUDE_|OPENAI_|CODEX_)' | grep -v '^CODEX_CA_CERTIFICATE$'); do
    [ -n "${!v:-}" ] && echo "$v=${!v}"
  done
} > /etc/environment
chmod 644 /etc/environment

setup-sshd agent

# Agent home (a volume): default settings, copied only when missing so logins and
# user changes survive restarts and image updates.
H=/home/agent
mkdir -p "$H/.claude/agents" "$H/.codex"
cp -rn /opt/aab/claude-home/. "$H/.claude/"
cp -rn /opt/aab/codex-home/. "$H/.codex/"
chown -R agent:agent "$H"
chown agent:agent /workspace 2>/dev/null || true

# Skip Claude Code's first-run screens and pre-approve the provided API key.
setpriv --reuid=1000 --regid=1000 --init-groups env HOME="$H" python3 - <<'PY'
import json, os
p = os.path.expanduser("~/.claude.json")
cfg = json.load(open(p)) if os.path.exists(p) else {}
cfg.update(hasCompletedOnboarding=True, bypassPermissionsModeAccepted=True)
key = os.environ.get("ANTHROPIC_API_KEY")
if key:
    r = cfg.setdefault("customApiKeyResponses", {"approved": [], "rejected": []})
    if key[-20:] not in r["approved"]:
        r["approved"].append(key[-20:])
proj = cfg.setdefault("projects", {}).setdefault("/workspace", {})
proj["hasTrustDialogAccepted"] = True
json.dump(cfg, open(p, "w"), indent=2)
PY

# Codex with an API key: log in once, non-interactively.
if [ -n "${OPENAI_API_KEY:-}" ] && command -v codex >/dev/null && [ ! -s "$H/.codex/auth.json" ]; then
  printenv OPENAI_API_KEY | setpriv --reuid=1000 --regid=1000 --init-groups \
    env HOME="$H" codex login --with-api-key >/dev/null 2>&1 || true
fi

# `docker compose exec` sessions: no empty credentials either.
for v in ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_MODEL OPENAI_API_KEY; do
  [ -n "${!v:-}" ] || unset "$v"
done

echo "[aab] sandbox ready: ssh -p ${AAB_SSH_PORT:-2222} agent@localhost"
exec "$@"
