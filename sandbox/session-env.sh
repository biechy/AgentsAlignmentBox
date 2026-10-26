# AgentsAlignmentBox: tag this login session's traffic for the proxy.
# Sourced by every shell (login, interactive and `ssh host command`). The first shell of a
# session picks a random session id and puts it in the proxy credentials; every process it
# starts inherits it (claude, codex, their sub-agents...), so the proxy can tell the agents
# of different SSH sessions apart. Shell commands run by an agent still get their own,
# more precise, tool-call tag from the Claude Code hook.
if [ -z "${AAB_SESSION:-}" ] && [ -n "${HTTPS_PROXY:-}" ]; then
  AAB_SESSION="aabs-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  _aab_hp=${HTTPS_PROXY#*://}
  _aab_hp=${_aab_hp#*@}
  _aab_p="http://${AAB_SESSION}:x@${_aab_hp}"
  export AAB_SESSION HTTP_PROXY="$_aab_p" HTTPS_PROXY="$_aab_p" http_proxy="$_aab_p" https_proxy="$_aab_p"
  unset _aab_hp _aab_p
fi
