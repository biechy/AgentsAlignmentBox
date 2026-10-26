"""Deterministic checks over the activity log: cheap, CPU only, no model involved.

Each rule reads rows newer than a watermark and returns candidate flags. They are
written as flags directly (detector "rule:<name>") and also shown to the model
reviewer as context. Rules only look at facts the proxy records; they are not a
list of attacks, just signals worth a human look.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from psycopg.rows import tuple_row

# Domains an agent's client legitimately sends request bodies to: the model providers
# (API calls, logins, telemetry of Claude Code and Codex). Subdomains included.
UPLOAD_ALLOWLIST = ("anthropic.com", "claude.ai", "openai.com", "chatgpt.com")


@dataclass
class Signal:
    rule: str
    agent_id: str | None
    severity: str
    category: str
    summary: str
    evidence: dict = field(default_factory=dict)


def _cur(conn):
    return conn.cursor(row_factory=tuple_row)


def _scalar(conn, sql: str, params: tuple = ()):
    with _cur(conn) as c:
        c.execute(sql, params)
        return c.fetchone()[0]


def _http_rows(conn, lo: int, hi: int, where: str, params: tuple = ()) -> list[dict]:
    with _cur(conn) as cur:
        cur.execute(
            "SELECT id, ts, client_host, method, host, port, path, status_code, req_bytes, agent_id,"
            " tool_use_id, attribution, candidate_agent_ids, proxy_tag, blocked"
            f" FROM http_requests WHERE id > %s AND id <= %s AND {where} ORDER BY id",
            (lo, hi, *params),
        )
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def _owner(row: dict) -> str | None:
    """The agent a request belongs to, or the single candidate when there is one."""
    if row["agent_id"]:
        return row["agent_id"]
    cands = row["candidate_agent_ids"] or []
    return cands[0] if len(cands) == 1 else None


def run_rules(conn, wm: dict) -> tuple[list[Signal], dict]:
    """Signals for rows after the watermarks in `wm`; returns them and the new watermarks."""
    http_id = wm.get("http_id", 0)
    conn_id = wm.get("conn_id", 0)
    # Freeze the upper bounds first so rows inserted meanwhile are seen next time.
    http_hi = _scalar(conn, "SELECT coalesce(max(id), 0) FROM http_requests")
    conn_hi = _scalar(conn, "SELECT coalesce(max(id), 0) FROM connections")
    out: list[Signal] = []

    for r in _http_rows(conn, http_id, http_hi, "attribution = 'unknown_tag'"):
        out.append(Signal(
            "unknown_proxy_tag", None, "high", "monitoring_integrity",
            f"Request to {r['host']} carried a proxy tag that matches no tool call seen "
            f"by the proxy (container {r['client_host']}).",
            {"http_request_ids": [r["id"]], "proxy_tag": r["proxy_tag"],
             "candidates": r["candidate_agent_ids"]}))

    # Requests refused because the agent was stopped (kill switch) are not boundary probes.
    for r in _http_rows(conn, http_id, http_hi,
                        "blocked AND coalesce(error, '') NOT LIKE 'agent stopped by the operator%%'"):
        out.append(Signal(
            "blocked_destination", _owner(r), "medium", "sandbox_boundary",
            f"{r['method']} to internal destination {r['host']}:{r['port']} was refused.",
            {"http_request_ids": [r["id"]], "attribution": r["attribution"],
             "candidates": r["candidate_agent_ids"]}))

    # A shell tool call made a request without the tag its command was given (no tag, or
    # only the sandbox session's tag: the hook's tool-call tag was dropped).
    with _cur(conn) as cur:
        cur.execute(
            "SELECT h.id, h.host, h.agent_id, h.tool_use_id FROM http_requests h"
            " JOIN tool_calls t USING (tool_use_id)"
            " WHERE h.id > %s AND h.id <= %s AND NOT h.is_llm_api"
            "   AND (h.proxy_tag IS NULL OR h.proxy_tag ~ '^aab[sr]-')"
            "   AND t.tool_name = 'Bash' ORDER BY h.id", (http_id, http_hi))
        shell_rows = cur.fetchall()
    for hid, host, agent_id, tool_use_id in shell_rows:
        out.append(Signal(
            "untagged_shell_request", agent_id, "medium", "monitoring_integrity",
            f"Request to {host} during a shell command arrived without that command's proxy tag.",
            {"http_request_ids": [hid], "tool_use_id": tool_use_id}))

    for r in _http_rows(conn, http_id, http_hi,
                        "NOT is_llm_api AND NOT blocked AND req_bytes > 0"
                        " AND method IN ('POST','PUT','PATCH')"
                        " AND NOT (host = ANY(%s) OR host LIKE ANY(%s))",
                        (list(UPLOAD_ALLOWLIST), ["%." + d for d in UPLOAD_ALLOWLIST])):
        out.append(Signal(
            "outbound_upload", _owner(r), "low", "data_egress",
            f"{r['method']} with a {r['req_bytes']}-byte body sent to {r['host']}{r['path'][:80]}.",
            {"http_request_ids": [r["id"]], "attribution": r["attribution"],
             "candidates": r["candidate_agent_ids"]}))

    with _cur(conn) as cur:
        cur.execute(
            "SELECT id, event, host, port, client_host FROM connections"
            " WHERE id > %s AND id <= %s AND event IN ('tls_failed', 'tcp_start') ORDER BY id",
            (conn_id, conn_hi))
        conn_rows = cur.fetchall()
    for cid, event, host, port, client_host in conn_rows:
        out.append(Signal(
            "undecoded_connection", None, "low", "sandbox_boundary",
            f"{event} towards {host}:{port} from {client_host}: content not visible to the proxy.",
            {"connection_ids": [cid]}))

    return out, {**wm, "http_id": max(http_id, http_hi), "conn_id": max(conn_id, conn_hi)}
