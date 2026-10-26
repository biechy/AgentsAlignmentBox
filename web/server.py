"""AgentsAlignmentBox dashboard: web app and JSON API on port 4141.

Runs outside the sandbox, on `dbnet` (the log) and `ingress` (the sandbox's SSH
gateway); it is never on `agentnet`, so the agents cannot reach it. It reads the
log as `web_operator`, which may only review flags and write the kill switch.

    GET  /                                  the dashboard (static/)
    GET  /api/snapshot?since=<ts>&from=<ts> {agents, timeline, flags, monitor, runs, sandbox, now}
    GET  /api/agents/<id>                   one agent: task, model calls, tool calls, web, flags
    POST /api/agents/<id>/kill   {"subtree": bool, "reason": str}
    POST /api/agents/<id>/revive {"subtree": bool}
    POST /api/flags/<id>         {"status": "acknowledged"|"dismissed"|"confirmed"|"open"}
    POST /api/run                {"prompt": str, "engine": "claude"|"codex"}
    POST /api/runs/<run>/stop

Agents form a tree. The parent of an agent is the agent whose Agent/Task (Claude
Code) or spawn_agent (Codex) call passed it its task (matched on the prompt, which
also covers sub-agents run in the background), else the Codex thread named in its
`x-codex-parent-thread-id` header, else, from `agents.running_tools_at_start`, the
agent owning a running Agent/Task call when it started, else a running Bash call (a
detached `claude -p`). One-off calls (no tools offered) are left out, and
conversations offering only server tools (Claude Code's WebSearch helper) are folded
into the agent whose WebSearch/WebFetch call was running.

Killing an agent inserts a row into `agent_controls`; the proxy then answers every
model call of that agent with a final "stopped by the operator" message and refuses
its tool requests. "subtree" also stops every descendant.
"""
from __future__ import annotations

import base64
import hmac
import json
import mimetypes
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import psycopg
from psycopg.rows import dict_row

PORT = int(os.environ.get("WEB_PORT", "4141"))
HOST = os.environ.get("WEB_HOST", "0.0.0.0")
STATIC = Path(__file__).resolve().parent / "static"
SECRETS = Path(os.environ.get("AAB_SECRETS_DIR", "/run/aab-secrets"))
PASSWORD = os.environ.get("AAB_WEB_PASSWORD", "")
RUNNING_WINDOW_S = int(os.environ.get("WEB_RUNNING_WINDOW_S", "30"))
# A row is written when its LLM call returns but stamped with the request time, so a
# poll re-reads this much before `since`; the web app drops rows it already has.
LOOKBACK_S = int(os.environ.get("WEB_LOOKBACK_S", "600"))
ROW_CAP = 2000
SPAWN_TOOLS = ("Agent", "Task", "spawn_agent")
HELPER_TOOLS = {"web_search", "web_fetch", "code_execution"}   # server tools only
HELPER_CALLERS = ("WebSearch", "WebFetch")
SSH_TARGET = os.environ.get("AAB_SANDBOX_SSH", "agent@sandbox-ssh")
SSH_PORT = os.environ.get("AAB_SANDBOX_SSH_PORT", "2222")
RUN_COOLDOWN_S = int(os.environ.get("WEB_RUN_COOLDOWN_S", "5"))
REMINDER = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)
CODEX_WRAPPERS = re.compile(
    r"<(environment_context|user_instructions|permissions instructions)>.*?</\1>", re.S)
FLAG_STATUSES = ("open", "acknowledged", "dismissed", "confirmed")


# -- database -----------------------------------------------------------------
def default_dsn() -> str:
    if os.environ.get("WEB_DB_DSN"):
        return os.environ["WEB_DB_DSN"]
    pw = (SECRETS / "web.pw").read_text().strip()
    return f"postgresql://web_operator:{pw}@db:5432/obs"


def connect(dsn: str | None = None) -> psycopg.Connection:
    conn = psycopg.connect(dsn or default_dsn(), autocommit=True, row_factory=dict_row)
    conn.execute("SET search_path = obs")
    conn.execute("SET statement_timeout = 15000")
    return conn


def rows(conn, sql: str, params: tuple = (), cap: int = ROW_CAP) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchmany(cap) if cur.description else []


# -- agent tree ---------------------------------------------------------------
def task_text(first_prompt: str | None) -> str:
    """The task as written, without the clients' context wrappers."""
    return CODEX_WRAPPERS.sub("", REMINDER.sub("", first_prompt or "")).strip()


def task_key(text: str | None) -> str:
    return " ".join((text or "").split())[:300]


def infer_parent(running: list[dict] | None, tool_names: dict[str, str]) -> str | None:
    """Agent that most likely started this one, from the tool calls running at its start."""
    running = running or []
    for kinds in (SPAWN_TOOLS, ("Bash",)):
        for r in running:
            if tool_names.get(r.get("tool_use_id")) in kinds:
                return r.get("agent_id")
    return None


def is_helper(row: dict) -> bool:
    tools = row.get("tools_offered") or []
    return bool(tools) and set(tools) <= HELPER_TOOLS


def helper_owners(rows_: list[dict], tool_names: dict[str, str]) -> dict[str, str | None]:
    """helper agent -> real agent it works for (the one whose WebSearch/WebFetch ran)."""
    direct = {}
    for r in rows_:
        if not is_helper(r):
            continue
        running = r.get("running_tools_at_start") or []
        owner = next((x.get("agent_id") for x in running
                      if tool_names.get(x.get("tool_use_id")) in HELPER_CALLERS), None)
        direct[r["agent_id"]] = owner or (running[0].get("agent_id") if running else None)
    out = {}
    for h in direct:  # a helper started while another helper ran: follow to a real agent
        o, seen = direct[h], {h}
        while o in direct and o not in seen:
            seen.add(o)
            o = direct[o]
        out[h] = None if o in direct else o
    return out


def _spawning_call(row: dict, tool_names: dict[str, str]) -> str | None:
    for r in row.get("running_tools_at_start") or []:
        if tool_names.get(r.get("tool_use_id")) in SPAWN_TOOLS:
            return r.get("tool_use_id")
    return None


def build_agents(rows_: list[dict], tool_names: dict[str, str], open_flags: dict[str, int],
                 now: datetime, spawns: dict[str, str] | None = None,
                 killed: set[str] | None = None) -> list[dict]:
    """`spawns`: task_key(prompt given to an Agent/Task call) -> agent that made the call."""
    spawns, killed = spawns or {}, killed or set()
    owners = helper_owners(rows_, tool_names)
    folded: dict[str, dict] = {}
    for r in rows_:
        o = owners.get(r["agent_id"])
        if o:
            acc = folded.setdefault(o, {"n_llm_calls": 0, "input_tokens": 0, "output_tokens": 0})
            for k in acc:
                acc[k] += r[k] or 0
    rows_ = [r for r in rows_ if r["agent_id"] not in owners]
    known = {r["agent_id"] for r in rows_}
    by_session = {r.get("session_id"): r["agent_id"] for r in rows_ if r.get("session_id")}
    out = []
    for r in rows_:
        extra = folded.get(r["agent_id"], {})
        by_task = spawns.get(task_key(task_text(r["first_prompt"])))
        parent = (by_task or by_session.get(r.get("parent_session_id"))
                  or infer_parent(r.get("running_tools_at_start"), tool_names))
        parent = parent if parent in known and parent != r["agent_id"] else None
        if r["agent_id"] in killed:
            status = "killed"
        elif open_flags.get(r["agent_id"]):
            status = "flagged"
        elif r["last_seen"] and now - r["last_seen"] < timedelta(seconds=RUNNING_WINDOW_S):
            status = "running"
        else:
            status = "done"
        out.append({
            "agent_id": r["agent_id"], "parent_id": parent,
            "role": "orchestrator" if parent is None else (
                "worker" if parent == by_task or r.get("parent_session_id")
                or tool_names.get(_spawning_call(r, tool_names)) in SPAWN_TOOLS
                else "child"),
            "provider": r.get("provider") or "anthropic",
            "client_host": r["client_host"], "model": r["model"],
            "first_prompt": task_text(r["first_prompt"]), "tools_offered": r["tools_offered"] or [],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "n_llm_calls": r["n_llm_calls"] + extra.get("n_llm_calls", 0),
            "n_tool_calls": r["n_tool_calls"], "n_http": r["n_http"],
            # requests it may have made (ambiguous: several agents were running tools), and
            # web searches / fetches (WebSearch runs at the model provider: no sandbox request)
            "n_http_possible": r.get("n_http_possible") or 0, "n_web": r.get("n_web") or 0,
            "input_tokens": r["input_tokens"] + extra.get("input_tokens", 0),
            "output_tokens": r["output_tokens"] + extra.get("output_tokens", 0),
            "open_flags": open_flags.get(r["agent_id"], 0),
            "anomaly": round(float(r["anomaly"]), 3) if r.get("anomaly") is not None else None,
            "status": status,
        })
    return out


SEVERITY_RISK = {"info": 10, "low": 30, "medium": 55, "high": 80, "critical": 100}


def add_risk(agents: list[dict], flags: list[dict]) -> None:
    """risk (0-100) per agent: its worst open flag, or its tabular anomaly score (x70);
    tree_risk: the worst risk in its sub-tree."""
    worst: dict[str, int] = {}
    for f in flags:
        if f["status"] == "open" and f["agent_id"]:
            worst[f["agent_id"]] = max(worst.get(f["agent_id"], 0), SEVERITY_RISK.get(f["severity"], 0))
    for a in agents:
        a["risk"] = max(worst.get(a["agent_id"], 0), round((a.get("anomaly") or 0) * 70))
    children: dict[str, list[dict]] = {}
    for a in agents:
        children.setdefault(a["parent_id"], []).append(a)

    def tree(a: dict) -> int:
        a["tree_risk"] = max([a["risk"], *(tree(c) for c in children.get(a["agent_id"], []))])
        a["tree_size"] = 1 + sum(c["tree_size"] for c in children.get(a["agent_id"], []))
        return a["tree_risk"]
    for a in children.get(None, []):
        tree(a)


def descendants(agents: list[dict], root: str) -> list[str]:
    children: dict[str, list[str]] = {}
    for a in agents:
        if a["parent_id"]:
            children.setdefault(a["parent_id"], []).append(a["agent_id"])
    out, todo = [], [root]
    while todo:
        a = todo.pop()
        for c in children.get(a, []):
            if c not in out and c != root:
                out.append(c)
                todo.append(c)
    return out


def load_agents(conn, start: str | None = None) -> tuple[list[dict], dict, list[dict], dict]:
    """(agent rows, tool names, flags, helper owners) since `start`."""
    agent_rows = rows(conn,
        "SELECT a.agent_id, a.session_id, a.parent_session_id, a.client_host, a.provider,"
        " a.model, a.first_prompt, a.tools_offered, a.running_tools_at_start, a.first_seen,"
        " a.last_seen, a.n_llm_calls,"
        " (SELECT count(*) FROM tool_calls t WHERE t.agent_id = a.agent_id) n_tool_calls,"
        " (SELECT count(*) FROM http_requests h WHERE h.agent_id = a.agent_id"
        "   AND NOT h.is_llm_api) n_http,"
        " (SELECT count(*) FROM http_requests h WHERE h.agent_id IS NULL AND NOT h.is_llm_api"
        "   AND a.agent_id = ANY(h.candidate_agent_ids)) n_http_possible,"
        " (SELECT count(*) FROM tool_calls t WHERE t.agent_id = a.agent_id"
        "   AND (t.tool_name IN ('WebSearch', 'WebFetch') OR t.is_server_tool)) n_web,"
        " (SELECT coalesce(sum(coalesce(input_tokens, 0) + coalesce(cache_read_tokens, 0)"
        "   + coalesce(cache_write_tokens, 0)), 0) FROM llm_calls c"
        "   WHERE c.agent_id = a.agent_id) input_tokens,"
        " (SELECT coalesce(sum(output_tokens), 0) FROM llm_calls c"
        "   WHERE c.agent_id = a.agent_id) output_tokens,"
        " (SELECT max(score) FROM tabular_scores s WHERE s.agent_id = a.agent_id) anomaly"
        " FROM agents a WHERE coalesce(cardinality(a.tools_offered), 0) > 0"
        " AND (%s::timestamptz IS NULL OR a.first_seen >= %s::timestamptz)"
        " ORDER BY a.first_seen", (start, start))
    ids = [r["tool_use_id"] for a in agent_rows for r in (a["running_tools_at_start"] or [])]
    tool_names = {r["tool_use_id"]: r["tool_name"] for r in rows(conn,
        "SELECT tool_use_id, tool_name FROM tool_calls WHERE tool_use_id = ANY(%s)",
        (ids,), cap=10_000)} if ids else {}
    flags = rows(conn,
        "SELECT id, ts, agent_id, severity, category, summary, evidence, detector, status"
        " FROM flags WHERE %s::timestamptz IS NULL OR ts >= %s::timestamptz ORDER BY ts",
        (start, start))
    return agent_rows, tool_names, flags, helper_owners(agent_rows, tool_names)


def spawn_prompts(conn, start: str | None) -> dict[str, str]:
    return {task_key(r["p"]): r["agent_id"] for r in rows(conn,
        "SELECT agent_id, coalesce(tool_input->>'prompt', tool_input->>'message',"
        "   tool_input->>'task') p FROM tool_calls"
        " WHERE tool_name = ANY(%s)"
        " AND (%s::timestamptz IS NULL OR ts >= %s::timestamptz) ORDER BY ts",
        (list(SPAWN_TOOLS), start, start), cap=10_000) if r["p"]}


def killed_ids(conn) -> set[str]:
    return {r["agent_id"] for r in rows(conn, "SELECT agent_id FROM agent_controls")}


def agent_tree(conn, start: str | None = None) -> tuple[list[dict], dict]:
    agent_rows, tool_names, flags, owners = load_agents(conn, start)
    for f in flags:
        if f["agent_id"] in owners:
            f["agent_id"] = owners[f["agent_id"]]
    agents = build_agents(agent_rows, tool_names, open_flags_of(flags),
                          datetime.now(timezone.utc), spawn_prompts(conn, start), killed_ids(conn))
    add_risk(agents, flags)
    return agents, {"flags": flags, "owners": owners}


def snapshot(conn, since: str | None, start: str | None = None) -> dict:
    agents, extra = agent_tree(conn, start)
    flags, owners = extra["flags"], extra["owners"]
    for f in flags:
        f["evidence"] = _evidence_ids(f["evidence"])
    timeline = rows(conn,
        "SELECT ts, agent_id, event, what, detail, ref FROM v_timeline"
        " WHERE (%s::timestamptz IS NULL OR ts > %s::timestamptz - %s * interval '1 second')"
        " AND (%s::timestamptz IS NULL OR ts >= %s::timestamptz)"
        " ORDER BY ts DESC LIMIT 2000", (since, since, LOOKBACK_S, start, start))[::-1]
    for e in timeline:
        if e["agent_id"] in owners:
            e["agent_id"] = owners[e["agent_id"]]
    return {"now": datetime.now(timezone.utc), "agents": agents, "timeline": timeline,
            "config": {"ssh_port": os.environ.get("AAB_SSH_PORT", "2222"),
                       "monitor_ssh_port": os.environ.get("AAB_MONITOR_SSH_PORT", "2223")},
            "flags": flags, "monitor": monitor_status(conn), "runs": RUNS.list(),
            "sandbox": RUNS.status(),
            "monitor_runs": rows(conn, "SELECT id, ts_start, ts_end, backend, model, reviewed,"
                                       " n_signals, n_rule_flags, n_model_flags, tabular_model,"
                                       " n_scored, n_tabular_alerts, stopped, left(summary, 600)"
                                       " AS summary, left(error, 600) AS error FROM monitor_runs"
                                       " ORDER BY id DESC LIMIT 30")}


def monitor_status(conn) -> dict | None:
    last = rows(conn, "SELECT * FROM monitor_runs ORDER BY id DESC LIMIT 1", cap=1)
    if not last:
        return None
    m = last[0]
    m["last_review"] = (rows(conn, "SELECT max(ts_end) t FROM monitor_runs WHERE reviewed"
                             " AND error IS NULL", cap=1) or [{}])[0].get("t")
    return m


def open_flags_of(flags: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in flags:
        if f["status"] == "open" and f["agent_id"]:
            out[f["agent_id"]] = out.get(f["agent_id"], 0) + 1
    return out


def _evidence_ids(ev) -> list[str]:
    """Row refs from {"http_request_ids": [..], "tool_use_id": .., "attribution": ..}:
    only the *_id / *_ids keys, which match `ref` in v_timeline."""
    if isinstance(ev, dict):
        return [str(x) for k, v in ev.items() if k.endswith(("_id", "_ids"))
                for x in (v if isinstance(v, list) else [v])]
    return [str(x) for x in ev] if isinstance(ev, list) else []


def agent_detail(conn, agent_id: str) -> dict | None:
    a = rows(conn, "SELECT agent_id, session_id, client_host, provider, model, system_prompt,"
                   " first_prompt, tools_offered, first_seen, last_seen, n_llm_calls"
                   " FROM agents WHERE agent_id = %s", (agent_id,), cap=1)
    if not a:
        return None
    agent = a[0]
    agent["task"] = task_text(agent.pop("first_prompt"))
    agent["system_prompt"] = (agent["system_prompt"] or "")[:20000]
    helpers = [r["agent_id"] for r in rows(conn,
        "SELECT a.agent_id FROM agents a, jsonb_array_elements(coalesce("
        "  a.running_tools_at_start, '[]'::jsonb)) r"
        " WHERE r->>'agent_id' = %s AND a.tools_offered <@ %s::text[]"
        "   AND coalesce(cardinality(a.tools_offered), 0) > 0",
        (agent_id, list(HELPER_TOOLS)))]
    ids = [agent_id, *helpers]
    agent["llm_calls"] = rows(conn,
        "SELECT call_id, ts_request AS ts, model, latency_ms, input_tokens, output_tokens,"
        " cache_read_tokens, stop_reason, error, left(response_text, 4000) AS text,"
        " left(thinking_text, 2000) AS thinking FROM llm_calls WHERE agent_id = ANY(%s)"
        " ORDER BY ts_request DESC LIMIT 200", (ids,))
    agent["tool_calls"] = rows(conn,
        "SELECT t.tool_use_id, t.ts, t.tool_name, t.is_server_tool,"
        " left(t.tool_input::text, 4000) AS input, left(t.result_content, 4000) AS result,"
        " t.result_is_error, t.ts_result, round(s.score::numeric, 3)::float8 AS anomaly,"
        " s.reasons AS anomaly_reasons, s.model AS anomaly_model"
        " FROM tool_calls t LEFT JOIN tabular_scores s USING (tool_use_id)"
        " WHERE t.agent_id = ANY(%s) ORDER BY t.ts DESC LIMIT 300", (ids,))
    # Requests attributed to it, and those it may have made (ambiguous, it is a candidate).
    agent["http"] = rows(conn,
        "SELECT id, ts, method, host, left(url, 500) AS url, status_code, req_bytes, resp_bytes,"
        " attribution, blocked, left(req_body_preview, 1000) AS body,"
        " agent_id IS NOT NULL AS certain, cardinality(candidate_agent_ids) AS n_candidates"
        " FROM http_requests WHERE NOT is_llm_api AND (agent_id = ANY(%s)"
        "   OR (agent_id IS NULL AND candidate_agent_ids && %s::text[]))"
        " ORDER BY ts DESC LIMIT 300", (ids, ids))
    agent["flags"] = rows(conn, "SELECT id, ts, severity, category, summary, evidence, detector,"
                                " status FROM flags WHERE agent_id = %s ORDER BY ts DESC",
                          (agent_id,))
    k = rows(conn, "SELECT reason, requested_by, ts FROM agent_controls WHERE agent_id = %s",
             (agent_id,), cap=1)
    agent["killed"] = k[0] if k else None
    return agent


# -- operator actions ---------------------------------------------------------
def kill(conn, agent_id: str, subtree: bool, reason: str) -> dict:
    agents, extra = agent_tree(conn)
    if agent_id not in {a["agent_id"] for a in agents}:
        return {"ok": False, "error": "unknown agent"}
    targets = [agent_id] + (descendants(agents, agent_id) if subtree else [])
    # Claude Code's WebSearch helpers of a stopped agent stop with it.
    targets += [h for h, o in extra["owners"].items() if o in targets]
    for t in targets:
        conn.execute(
            "INSERT INTO agent_controls (agent_id, action, reason, requested_by)"
            " VALUES (%s, 'kill', %s, 'web') ON CONFLICT (agent_id) DO UPDATE"
            " SET reason = EXCLUDED.reason, requested_by = 'web', ts = now()",
            (t, (reason or "stopped from the dashboard")[:1000]))
    return {"ok": True, "killed": targets}


def revive(conn, agent_id: str, subtree: bool) -> dict:
    agents, extra = agent_tree(conn)
    targets = [agent_id] + (descendants(agents, agent_id) if subtree else [])
    targets += [h for h, o in extra["owners"].items() if o in targets]
    conn.execute("DELETE FROM agent_controls WHERE agent_id = ANY(%s)", (targets,))
    return {"ok": True, "revived": targets}


def review_flag(conn, flag_id: int, status: str) -> dict:
    if status not in FLAG_STATUSES:
        return {"ok": False, "error": f"status must be one of {FLAG_STATUSES}"}
    n = conn.execute("UPDATE flags SET status = %s, reviewed_by = 'web', reviewed_at = now()"
                     " WHERE id = %s", (status, flag_id)).rowcount
    return {"ok": n == 1}


class Runs:
    """Headless runs in the sandbox, started over SSH with the launcher key, which the
    sandbox only lets run `aab-launch` (see sandbox/bin/aab-launch)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._last = 0.0
        self._cache: tuple[float, dict | None] = (0.0, {})

    def _ssh(self, command: str, stdin: str = "", timeout: int = 30) -> subprocess.CompletedProcess:
        key = SECRETS / "launcher_key"
        return subprocess.run(
            ["ssh", "-i", str(key), "-p", SSH_PORT, "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/tmp/aab_known_hosts",
             "-o", "ConnectTimeout=5", SSH_TARGET, command],
            input=stdin, capture_output=True, text=True, timeout=timeout)

    def start(self, engine: str, prompt: str) -> tuple[int, dict]:
        if engine not in ("claude", "codex"):
            return 400, {"ok": False, "error": "engine must be claude or codex"}
        with self._lock:
            wait = RUN_COOLDOWN_S - (time.monotonic() - self._last)
            if wait > 0:
                return 429, {"ok": False, "error": f"a run was just started; wait {wait:.0f} s"}
            self._last = time.monotonic()
        try:
            p = self._ssh(f"run {engine}", prompt)
        except (OSError, subprocess.TimeoutExpired) as e:
            return 502, {"ok": False, "error": f"sandbox unreachable: {e}"}
        self._cache = (0.0, self._cache[1])
        return _ssh_json(p)

    def stop(self, run: str) -> tuple[int, dict]:
        if not re.fullmatch(r"[0-9A-Za-z-]{1,80}", run):
            return 400, {"ok": False, "error": "bad run id"}
        try:
            p = self._ssh(f"stop {run}")
        except (OSError, subprocess.TimeoutExpired) as e:
            return 502, {"ok": False, "error": f"sandbox unreachable: {e}"}
        self._cache = (0.0, self._cache[1])
        return _ssh_json(p)

    def status(self) -> dict | None:
        """What is live in the sandbox ({sessions, clis, runs}), refreshed in the background
        every 3 s so a poll never waits for SSH; None when the sandbox is unreachable."""
        t, status = self._cache
        if time.monotonic() - t > 3 and self._lock.acquire(blocking=False):
            self._cache = (time.monotonic(), status)
            threading.Thread(target=self._refresh, daemon=True).start()
            self._lock.release()
        return status

    def list(self) -> list[dict] | None:
        s = self.status()
        return None if s is None else s.get("runs", [])

    def _refresh(self) -> None:
        try:
            p = self._ssh("status", timeout=10)
            status = json.loads(p.stdout.strip().splitlines()[-1]) if p.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
            status = None
        self._cache = (time.monotonic(), status)


def _ssh_json(p: subprocess.CompletedProcess) -> tuple[int, dict]:
    try:
        out = json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        out = {"ok": False, "error": (p.stderr or p.stdout or "no answer from the sandbox")[-1000:]}
    return (200 if out.get("ok") else 400), out


RUNS = Runs()


# -- HTTP ---------------------------------------------------------------------
def _json_default(o):
    return o.isoformat() if isinstance(o, datetime) else str(o)


class Handler(BaseHTTPRequestHandler):
    conn = None
    # One connection, used by one request at a time (requests are small and few).
    _conn_lock = threading.RLock()
    server_version = "AAB"

    @classmethod
    def db(cls):
        with cls._conn_lock:
            if cls.conn is None or cls.conn.closed or cls.conn.broken:
                cls.conn = connect()
            return cls.conn

    @classmethod
    def with_db(cls, fn):
        """fn(conn) under the lock; reconnect and retry once if the database restarted."""
        with cls._conn_lock:
            try:
                return fn(cls.db())
            except psycopg.OperationalError:
                cls.conn = None
                return fn(cls.db())

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body, default=_json_default).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        if not PASSWORD:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                _, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
                if hmac.compare_digest(pw, PASSWORD):
                    return True
            except ValueError:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="AgentsAlignmentBox"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _static(self, path: str) -> None:
        name = "index.html" if path in ("", "/") else path.lstrip("/")
        f = (STATIC / name).resolve()
        if STATIC.resolve() not in f.parents or not f.is_file():
            return self._send(404, {"error": "not found"})
        data = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(f.name)[0] or "application/octet-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if not self._authorized():
            return
        url = urlparse(self.path)
        if not url.path.startswith("/api"):
            return self._static(url.path)
        try:
            if url.path == "/api/snapshot":
                q = parse_qs(url.query)
                return self._send(200, self.with_db(lambda c: snapshot(
                    c, q.get("since", [None])[0], q.get("from", [None])[0])))
            if m := re.fullmatch(r"/api/agents/([^/]+)", url.path):
                a = self.with_db(lambda c: agent_detail(c, unquote(m.group(1))))
                return self._send(200 if a else 404, a or {"error": "unknown agent"})
        except Exception as e:  # report to the page instead of dropping the connection
            print(f"[web] GET {url.path}: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._authorized():
            return
        # JSON only: a cross-site form cannot send it without a CORS preflight, which
        # this server never grants, so other web pages cannot act on the agents.
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self._send(415, {"error": "send application/json"})
        path = urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid JSON"})
        try:
            if m := re.fullmatch(r"/api/agents/([^/]+)/kill", path):
                return self._send(200, self.with_db(lambda c: kill(
                    c, unquote(m.group(1)), bool(body.get("subtree")), str(body.get("reason") or ""))))
            if m := re.fullmatch(r"/api/agents/([^/]+)/revive", path):
                return self._send(200, self.with_db(lambda c: revive(
                    c, unquote(m.group(1)), bool(body.get("subtree")))))
            if m := re.fullmatch(r"/api/flags/(\d+)", path):
                return self._send(200, self.with_db(lambda c: review_flag(
                    c, int(m.group(1)), str(body.get("status")))))
            if path == "/api/run":
                prompt = str(body.get("prompt") or "").strip()
                if not prompt:
                    return self._send(400, {"ok": False, "error": "empty prompt"})
                return self._send(*RUNS.start(str(body.get("engine") or "claude"), prompt))
            if m := re.fullmatch(r"/api/runs/([^/]+)/stop", path):
                return self._send(*RUNS.stop(m.group(1)))
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})
        self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args) -> None:
        pass


def main() -> None:
    for _ in range(60):  # the database may still be starting
        try:
            Handler.db()
            break
        except psycopg.OperationalError as e:
            print(f"[web] waiting for the database: {e}", file=sys.stderr, flush=True)
            time.sleep(2)
    print(f"[web] AgentsAlignmentBox dashboard on http://localhost:{PORT}"
          f"{' (password protected)' if PASSWORD else ''}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
