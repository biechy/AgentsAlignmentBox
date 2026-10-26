# Welcome message for interactive SSH logins to the sandbox.
case $- in *i*) ;; *) return ;; esac
[ -n "${AAB_MOTD_SHOWN:-}" ] && return
export AAB_MOTD_SHOWN=1
cat <<TXT

  AgentsAlignmentBox sandbox: everything you and your agents do here is logged.
  Dashboard: http://localhost:${AAB_WEB_PORT:-4141}

  claude            Claude Code   (first time: type /login, or set an API key in .env)
  codex             Codex CLI     (first time: codex login --device-auth)
  claude -p "…"     headless run; sub-agents are started with the Agent tool

  Files: /workspace (shared with ./workspace on the host)

TXT
cd /workspace 2>/dev/null || true
