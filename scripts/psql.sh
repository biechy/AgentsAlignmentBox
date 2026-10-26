#!/bin/bash
# Open a SQL shell on the activity log as the read-only monitor role.
#   scripts/psql.sh                 # interactive
#   scripts/psql.sh -c "SELECT * FROM v_agents"
cd "$(dirname "$0")/.." && exec docker compose exec db psql -U monitor_reader -d obs "$@"
