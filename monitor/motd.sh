# Welcome message for interactive SSH logins to the monitor.
case $- in *i*) ;; *) return ;; esac
[ -n "${AAB_MOTD_SHOWN:-}" ] && return
export AAB_MOTD_SHOWN=1
cat <<TXT

  AgentsAlignmentBox monitor (backend: ${MONITOR_BACKEND:-claude-code})

  claude              log in once with your Claude plan (/login); the review loop
                      uses this login. Then ask questions about the agents' log here.
  aab-monitor once    run one review cycle now
  aab-monitor status  last review cycles
  aab-monitor tabular highest anomaly scores of the tabular model (TabPFN, CPU)

TXT
cd ~/console 2>/dev/null || true
