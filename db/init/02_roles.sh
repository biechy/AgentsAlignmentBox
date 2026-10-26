#!/bin/bash
# Least-privilege roles. Their passwords are generated on first start by the `init`
# service into the secrets volume (one file per role, readable by that service only).
#   proxy_writer   - the proxy: writes the activity log, reads the kill switch
#   monitor_reader - the monitor: reads everything, writes flags, its own cycles and the
#                    tabular scores (and kill switches when auto-kill is on)
#   web_operator   - the dashboard: reads everything, reviews flags, kills and revives agents
set -euo pipefail

SECRETS=${AAB_SECRETS_DIR:-/run/aab-secrets}
pw() { tr -d '\n' < "$SECRETS/$1.pw"; }

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v proxy_pw="$(pw proxy)" -v monitor_pw="$(pw monitor)" -v web_pw="$(pw web)" <<'SQL'
CREATE ROLE proxy_writer   LOGIN PASSWORD :'proxy_pw';
CREATE ROLE monitor_reader LOGIN PASSWORD :'monitor_pw';
CREATE ROLE web_operator   LOGIN PASSWORD :'web_pw';

GRANT USAGE ON SCHEMA obs TO proxy_writer, monitor_reader, web_operator;
ALTER ROLE proxy_writer   SET search_path = obs;
ALTER ROLE monitor_reader SET search_path = obs;
ALTER ROLE web_operator   SET search_path = obs;

GRANT SELECT, INSERT, UPDATE ON obs.agents, obs.llm_calls, obs.tool_calls,
                                obs.http_requests, obs.connections TO proxy_writer;
GRANT SELECT ON obs.agent_controls TO proxy_writer;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA obs TO proxy_writer;

GRANT SELECT ON ALL TABLES IN SCHEMA obs TO monitor_reader;
GRANT INSERT, UPDATE ON obs.flags TO monitor_reader;
GRANT INSERT, UPDATE ON obs.monitor_runs TO monitor_reader;
GRANT INSERT, UPDATE ON obs.tabular_scores TO monitor_reader;
GRANT INSERT ON obs.agent_controls TO monitor_reader;
GRANT USAGE ON SEQUENCE obs.flags_id_seq, obs.monitor_runs_id_seq TO monitor_reader;

GRANT SELECT ON ALL TABLES IN SCHEMA obs TO web_operator;
GRANT UPDATE (status, reviewed_by, reviewed_at) ON obs.flags TO web_operator;
GRANT INSERT, UPDATE, DELETE ON obs.agent_controls TO web_operator;
SQL
