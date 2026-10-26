#!/bin/bash
# End-to-end check: one Claude Code agent starts two sub-agents that visit websites,
# then the script shows what landed in the log and checks the sandbox isolation.
# Needs ANTHROPIC_API_KEY (or CLAUDE_CODE_OAUTH_TOKEN) in .env, or a /login done in the
# sandbox. Runs on Haiku to keep it cheap.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose up -d --build
H=claude-haiku-4-5
docker compose exec -T -u agent -w /workspace \
  -e ANTHROPIC_MODEL=$H -e CLAUDE_CODE_SUBAGENT_MODEL=$H -e ANTHROPIC_SMALL_FAST_MODEL=$H \
  sandbox claude -p --dangerously-skip-permissions \
  "Launch two sub-agents in parallel with the Agent tool. \
The first fetches https://example.com and reports the page title. \
The second runs 'curl -s https://httpbin.org/get' in Bash and reports the origin field. \
Then summarise both answers in two lines."

sleep 3   # the proxy writes asynchronously
q() { scripts/psql.sh -c "$1"; }
q "SELECT agent_id, provider, has_tools, n_llm_calls, n_tool_calls, n_http, killed FROM v_agents ORDER BY first_seen"
q "SELECT agent_id, tool_name, left(tool_input::text, 80) AS input, ts_result IS NOT NULL AS has_result FROM tool_calls ORDER BY ts"
q "SELECT method, host, status_code, agent_id, attribution FROM http_requests WHERE NOT is_llm_api ORDER BY ts"

# The sandbox must not reach the database, the dashboard or the internet directly.
docker compose exec -T -u agent sandbox bash -c '
  (curl -s -m 5 --noproxy "*" http://db:5432 >/dev/null 2>&1 && echo "FAIL: db reachable directly") || echo "ok: db not reachable directly"
  code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" http://db:5432/ || true)
  [ "$code" = "403" ] && echo "ok: proxy blocks db" || echo "FAIL: proxy answered $code for db"
  (curl -s -m 5 --noproxy "*" http://web:4141 >/dev/null 2>&1 && echo "FAIL: dashboard reachable") || echo "ok: dashboard not reachable"
  (curl -s -m 5 --noproxy "*" https://example.com >/dev/null 2>&1 && echo "FAIL: direct internet") || echo "ok: no direct internet"'
echo "Open http://localhost:$(docker compose port web 4141 | cut -d: -f2) to see the agents."
