#!/bin/sh
# Create .env from .env.example with your SSH public key, then start everything.
#   ./setup.sh            create .env if missing, build and start
#   ./setup.sh --no-up    only create .env
set -eu
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  cp .env.example .env
  key=""
  for f in "$HOME"/.ssh/id_ed25519.pub "$HOME"/.ssh/id_ecdsa.pub "$HOME"/.ssh/id_rsa.pub; do
    [ -s "$f" ] && { key=$(head -n1 "$f"); break; }
  done
  if [ -z "$key" ]; then
    echo "No SSH key found in ~/.ssh; creating ~/.ssh/id_ed25519"
    mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
    ssh-keygen -q -t ed25519 -N '' -f "$HOME/.ssh/id_ed25519"
    key=$(head -n1 "$HOME/.ssh/id_ed25519.pub")
  fi
  # Replace the empty AAB_SSH_PUBKEY= line (portable sed: write to a temp file).
  awk -v k="$key" '/^AAB_SSH_PUBKEY=$/ {print "AAB_SSH_PUBKEY=" k; next} {print}' .env > .env.tmp
  mv .env.tmp .env
  chmod 600 .env
  echo "Created .env with your SSH public key."
else
  echo ".env already exists: left unchanged."
fi
mkdir -p workspace

[ "${1:-}" = "--no-up" ] && exit 0
docker compose up -d --build
# Ports from .env (or the defaults).
port() { v=$(grep -E "^$1=" .env | tail -n1 | cut -d= -f2); echo "${v:-$2}"; }
cat <<TXT

AgentsAlignmentBox is starting (the first build takes a few minutes).
  Dashboard:  http://localhost:$(port AAB_WEB_PORT 4141)
  Sandbox:    ssh -p $(port AAB_SSH_PORT 2222) agent@localhost      (then: claude, or codex)
  Monitor:    ssh -p $(port AAB_MONITOR_SSH_PORT 2223) monitor@localhost    (once: claude, then /login)
TXT
