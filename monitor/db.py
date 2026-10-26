"""Read-only data access for the monitor and the flag writer.

The monitor connects as `monitor_reader`: it can read every table and write only
`flags`. The agents cannot reach this database at all, so the monitor is invisible
to them. All query helpers run with a statement timeout and return plain dicts.
"""
from __future__ import annotations

import json
import os

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

STATEMENT_TIMEOUT_MS = int(os.environ.get("MONITOR_STATEMENT_TIMEOUT_MS", "15000"))
ROW_CAP = int(os.environ.get("MONITOR_ROW_CAP", "500"))
SECRET_FILE = "/run/aab-secrets/monitor.pw"
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Flags at or above this severity also stop the agent (kill switch). Off by default.
AUTO_KILL = os.environ.get("MONITOR_AUTO_KILL", "off").strip().lower()


def default_dsn() -> str:
    """MONITOR_DB_DSN, else built from the password the `init` service generated."""
    if os.environ.get("MONITOR_DB_DSN"):
        return os.environ["MONITOR_DB_DSN"]
    with open(SECRET_FILE) as f:
        pw = f.read().strip()
    return f"postgresql://monitor_reader:{pw}@db:5432/obs"


def connect(dsn: str | None = None) -> psycopg.Connection:
    dsn = dsn or default_dsn()
    conn = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
    conn.execute("SET search_path = obs")
    # SET does not take parameters; the value is a bounded int from the environment.
    conn.execute(f"SET statement_timeout = {int(STATEMENT_TIMEOUT_MS)}")
    return conn


def _rows(conn, sql: str, params: tuple = (), cap: int = ROW_CAP) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchmany(cap)
    return rows


def agents_overview(conn, since: str | None = None, limit: int = 100) -> list[dict]:
    return _rows(conn,
        "SELECT agent_id, client_host, session_id, model, has_tools, task, first_seen,"
        " last_seen, n_llm_calls, n_tool_calls, n_http, n_open_flags FROM v_agents"
        " WHERE (%s::timestamptz IS NULL OR first_seen >= %s::timestamptz)"
        " ORDER BY first_seen DESC LIMIT %s",
        (since, since, min(limit, ROW_CAP)))


def agent_detail(conn, agent_id: str) -> dict:
    a = _rows(conn, "SELECT * FROM agents WHERE agent_id = %s", (agent_id,), cap=1)
    if not a:
        return {}
    agent = a[0]
    agent["recent_timeline"] = _rows(conn,
        "SELECT ts, event, what, detail FROM v_timeline WHERE agent_id = %s"
        " ORDER BY ts DESC LIMIT 100", (agent_id,))
    agent["hosts"] = _rows(conn,
        "SELECT host, count(*) n, bool_or(blocked) any_blocked FROM http_requests"
        " WHERE agent_id = %s AND NOT is_llm_api GROUP BY host ORDER BY n DESC", (agent_id,))
    return agent


def query(conn, sql: str, params: list | None = None, cap: int = ROW_CAP) -> list[dict]:
    """Arbitrary read-only SELECT (the model's escape hatch). Enforced read-only by
    the role, the transaction flag and a statement timeout."""
    stripped = sql.strip().rstrip(";")
    if ";" in stripped:
        raise ValueError("only a single statement is allowed")
    if not stripped.lower().startswith(("select", "with", "table", "explain")):
        raise ValueError("only read queries are allowed")
    # Force read-only for the model's free-form SQL (the role already blocks writes
    # to everything but flags; this also blocks flag writes via this path).
    conn.execute("SET default_transaction_read_only = on")
    try:
        with conn.cursor() as cur:
            cur.execute(stripped, tuple(params or []))
            return cur.fetchmany(cap)
    finally:
        conn.execute("SET default_transaction_read_only = off")


def tool_calls(conn, agent_id: str | None = None, name: str | None = None,
               contains: str | None = None, limit: int = 100) -> list[dict]:
    return _rows(conn,
        "SELECT tool_use_id, agent_id, ts, tool_name, is_server_tool, tool_input,"
        " left(result_content, 2000) AS result_content, result_is_error FROM tool_calls"
        " WHERE (%s::text IS NULL OR agent_id = %s) AND (%s::text IS NULL OR tool_name = %s)"
        "   AND (%s::text IS NULL OR tool_input::text ILIKE '%%' || %s || '%%')"
        " ORDER BY ts DESC LIMIT %s",
        (agent_id, agent_id, name, name, contains, contains, min(limit, ROW_CAP)))


def open_flags(conn, limit: int = 200) -> list[dict]:
    return _rows(conn,
        "SELECT id, ts, agent_id, severity, category, summary, detector, status FROM flags"
        " WHERE status = 'open' ORDER BY ts DESC LIMIT %s", (min(limit, ROW_CAP),))


def recent_flag_fingerprints(conn, detector_like: str, limit: int = 2000) -> set[str]:
    """(detector, agent, category, evidence) of recent flags, to avoid duplicates."""
    rows = _rows(conn,
        "SELECT detector, agent_id, category, evidence FROM flags"
        " WHERE detector LIKE %s ORDER BY id DESC LIMIT %s", (detector_like, limit), cap=limit)
    return {fingerprint(r["detector"], r["agent_id"], r["category"], r["evidence"]) for r in rows}


def fingerprint(detector: str, agent_id: str | None, category: str | None, evidence: dict) -> str:
    ev = evidence or {}
    ids = tuple(sorted(ev.get("http_request_ids", []) or [])), \
        tuple(sorted(ev.get("connection_ids", []) or [])), ev.get("tool_use_id")
    return json.dumps([detector, agent_id, category, ids], sort_keys=True, default=str)


def insert_flag(conn, *, agent_id, severity, category, summary, evidence, detector) -> int | None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO flags (agent_id, severity, category, summary, evidence, detector)"
            " VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
            (agent_id, severity, category, summary[:4000],
             Jsonb(evidence or {}), detector[:200]))
        fid = cur.fetchone()["id"]
    if agent_id and AUTO_KILL in SEVERITY_RANK \
            and SEVERITY_RANK.get(severity, -1) >= SEVERITY_RANK[AUTO_KILL]:
        kill_agent(conn, agent_id, f"auto-kill: flag {fid} ({severity}) {summary[:200]}")
    return fid


def kill_agent(conn, agent_id: str, reason: str) -> None:
    conn.execute(
        "INSERT INTO agent_controls (agent_id, action, reason, requested_by)"
        " VALUES (%s, 'kill', %s, 'monitor') ON CONFLICT (agent_id) DO NOTHING",
        (agent_id, reason[:1000]))


def activity_since(conn, since: str, limit: int = 300) -> list[dict]:
    """Tool calls and model replies newer than `since`, oldest first, for the reviewer."""
    return _rows(conn,
        "SELECT * FROM ("
        "  SELECT t.ts, t.agent_id, 'tool_call' AS kind, t.tool_name AS what,"
        "         left(t.tool_input::text, 600) AS input, left(t.result_content, 400) AS result"
        "    FROM tool_calls t WHERE t.ts > %s::timestamptz"
        "  UNION ALL"
        "  SELECT c.ts_request, c.agent_id, 'model_reply', c.model,"
        "         NULL, left(c.response_text, 600)"
        "    FROM llm_calls c WHERE c.ts_request > %s::timestamptz"
        "     AND coalesce(c.response_text, '') <> ''"
        ") e ORDER BY ts DESC LIMIT %s",
        (since, since, min(limit, ROW_CAP)))[::-1]


def latest_activity(conn) -> str | None:
    """Time of the newest model call or tool call (ISO), to detect new activity."""
    r = _rows(conn, "SELECT greatest((SELECT max(ts_request) FROM llm_calls),"
                    " (SELECT max(ts) FROM tool_calls)) AS t", cap=1)
    return r[0]["t"].isoformat() if r and r[0]["t"] else None


def start_run(conn, backend: str, model: str | None) -> int:
    return _rows(conn, "INSERT INTO monitor_runs (backend, model) VALUES (%s, %s) RETURNING id",
                 (backend, model), cap=1)[0]["id"]


def end_run(conn, run_id: int, **fields) -> None:
    cols = ["n_signals", "n_rule_flags", "n_model_flags", "reviewed", "stopped", "summary", "error",
            "tabular_model", "n_scored", "n_tabular_alerts"]
    vals = [fields.get(c) for c in cols]
    vals[5] = (vals[5] or None) and str(vals[5])[:4000]
    vals[6] = (vals[6] or None) and str(vals[6])[:4000]
    conn.execute(
        "UPDATE monitor_runs SET ts_end = now(), " + ", ".join(f"{c} = %s" for c in cols)
        + " WHERE id = %s", (*vals, run_id))
