#!/bin/bash
# Monitor entrypoint (root): sshd in the background for the operator, then the
# review loop as the unprivileged `monitor` user (PID 1).
set -euo pipefail

PW=$(cat /run/aab-secrets/monitor.pw)
export MONITOR_DB_DSN="postgresql://monitor_reader:${PW}@db:5432/obs"
export MONITOR_STATE_FILE=${MONITOR_STATE_FILE:-/state/monitor_state.json}

# SSH sessions get the same settings through pam_env.
{
  echo "MONITOR_DB_DSN=$MONITOR_DB_DSN"
  for v in MONITOR_BACKEND MONITOR_MODEL MONITOR_API_MODEL MONITOR_EFFORT MONITOR_TRIGGER \
           MONITOR_AUTO_KILL MONITOR_INTERVAL_S MONITOR_STATE_FILE MONITOR_ANTHROPIC_API_KEY MONITOR_CC_API_KEY \
           MONITOR_TABULAR MONITOR_TABULAR_THRESHOLD TABPFN_MODEL_CACHE_DIR TABPFN_NO_BROWSER \
           CLAUDE_CODE_OAUTH_TOKEN; do
    [ -n "${!v:-}" ] && echo "$v=${!v}"
  done
  echo "PYTHONPATH=/app"
} > /etc/environment
chmod 600 /etc/environment

setup-sshd monitor

H=/home/monitor
mkdir -p "$H/.claude" "$H/console"
cp -rn /opt/aab/console/. "$H/console/"
[ -s "$H/.claude/settings.json" ] || cp /opt/aab/claude-settings.json "$H/.claude/settings.json"
[ -s "$H/.claude.json" ] || echo '{"hasCompletedOnboarding": true}' > "$H/.claude.json"
chown -R monitor:monitor "$H" /state

/usr/sbin/sshd -e
echo "[aab] monitor ready: ssh -p ${AAB_MONITOR_SSH_PORT:-2223} monitor@localhost"

for v in CLAUDE_CODE_OAUTH_TOKEN MONITOR_ANTHROPIC_API_KEY ANTHROPIC_API_KEY; do
  [ -n "${!v:-}" ] || unset "$v"
done
export HOME=$H USER=monitor PYTHONPATH=/app
exec setpriv --reuid=1002 --regid=1002 --init-groups -- \
  python3 /app/run.py --loop "${MONITOR_INTERVAL_S:-60}"
