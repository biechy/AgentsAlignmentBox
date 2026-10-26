"""Drive the mitmproxy addon with real flow objects.

test_scenario_statements runs everywhere (statements captured in memory).
test_scenario_postgres runs the same scenario against a real Postgres when
TEST_PG_DSN points to a database (the obs schema is recreated by the test).
"""
from __future__ import annotations

import base64
import os
import socket
from pathlib import Path

import pytest
from helpers import assistant, request_body, results, sse, tool_use

pytest.importorskip("mitmproxy")
from mitmproxy import http  # noqa: E402
from mitmproxy.test import tflow  # noqa: E402

import obs_addon  # noqa: E402
from store import Store  # noqa: E402

IP = "172.30.0.5"
ROOT = Path(__file__).resolve().parent.parent
TASK = "Find the title of https://example.com"   # given to two agents at once


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Public names resolve to a public address, `db-alias` to a private one; no real DNS."""
    real = socket.getaddrinfo
    fake = {"db-alias": "172.30.1.2", "example.com": "93.184.215.14", "httpbin.org": "93.184.215.14",
            "pypi.org": "93.184.215.14", "files.example.net": "93.184.215.14"}

    def getaddrinfo(host, *a, **k):
        if host not in fake:  # e.g. the test database
            return real(host, *a, **k)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (fake[host], 0))]
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def flow(method: str, url: str, body: bytes = b"", headers: dict | None = None):
    f = tflow.tflow()
    f.request = http.Request.make(method, url, body, headers or {"content-type": "application/json"})
    f.response = None
    f.client_conn.peername = (IP, 40000)
    return f


def llm(addon, messages, blocks, tools=None, stop="tool_use", status=200):
    kw = {} if tools is None else {"tools": tools}
    f = flow("POST", "https://api.anthropic.com/v1/messages", request_body(messages, **kw))
    addon.request(f)
    if status >= 400:
        f.response = http.Response.make(status, b'{"type":"error","error":{"type":"overloaded_error"}}',
                                        {"content-type": "application/json"})
    else:
        f.response = http.Response.make(200, sse(blocks, stop), {"content-type": "text/event-stream",
                                                                 "request-id": "req_x"})
    addon.response(f)
    return f


def proxy_auth(tag):
    return {"user-agent": "curl", "proxy-authorization": "Basic " + base64.b64encode(f"{tag}:x".encode()).decode()}


def web(addon, url, method="GET", body=b"", headers=None, client_conn=None):
    f = flow(method, url, body, headers=headers or {"user-agent": "curl"})
    if client_conn is not None:
        f.client_conn = client_conn
    addon.request(f)
    if f.response is None:
        f.response = http.Response.make(200, b"<title>ok</title>", {"content-type": "text/html"})
    addon.response(f)
    return f


def run_scenario(addon) -> dict:
    """Three agents in one container, two of them with the same task, interleaved."""
    a_task = [{"role": "user", "content": TASK}]
    b_task = [{"role": "user", "content": TASK}]
    o_task = [{"role": "user", "content": "Coordinate the work."}]

    # O starts a long tool (whatever it does: the proxy does not care)
    o_tool = tool_use("anything", {"what": "wait for the others"})
    llm(addon, o_task, [o_tool])
    # A fails once (overloaded) then retries
    llm(addon, a_task, [], status=529)
    fa = tool_use("http_get", {"url": "https://example.com"})
    llm(addon, a_task, [fa])
    fb = tool_use("shell", {"cmd": "curl -s https://httpbin.org/get"})
    llm(addon, b_task, [fb])

    w_example = web(addon, "https://example.com/")
    w_httpbin = web(addon, "https://httpbin.org/get")
    w_unknown = web(addon, "https://pypi.org/simple/", "POST", b"leak=\x00secret")
    # same untagged-ambiguous situation, but tagged by the hook: exact
    w_tagged = web(addon, "http://pypi.org/simple/", headers=proxy_auth(fb["id"]))
    # HTTPS: the tag comes with the CONNECT, then applies to the requests in the tunnel
    connect_a = flow("CONNECT", "http://files.example.net:443/", headers=proxy_auth(fa["id"]))
    connect_a.request.host, connect_a.request.port = "files.example.net", 443
    addon.http_connect(connect_a)
    w_tunnel = web(addon, "https://files.example.net/blob", client_conn=connect_a.client_conn)
    w_forged = web(addon, "http://pypi.org/x", headers=proxy_auth("toolu_forged"))

    # B answers first, then A: follow-ups must still go to the right agent
    llm(addon, b_task + [assistant([fb]), results((fb, '{"origin": "1.2.3.4"}'))],
        [{"type": "text", "text": "1.2.3.4"}], stop="end_turn")
    llm(addon, a_task + [assistant([fa]), results((fa, "Example Domain"))],
        [{"type": "text", "text": "Example Domain"}], stop="end_turn")
    w_only_o = web(addon, "https://pypi.org/simple/")
    llm(addon, [{"role": "user", "content": "Write a 5-word title"}],
        [{"type": "text", "text": "Title"}], tools=[], stop="end_turn")
    llm(addon, o_task + [assistant([o_tool]), results((o_tool, "done"))],
        [{"type": "text", "text": "All done."}], stop="end_turn")
    w_after = web(addon, "https://pypi.org/simple/")

    blocked = web(addon, "http://db:5432/")
    blocked_ip = web(addon, "http://10.1.2.3/secret")
    connect = flow("CONNECT", "http://db-alias:5432/")
    connect.request.host, connect.request.port = "db-alias", 5432
    addon.http_connect(connect)
    return {"fa": fa, "fb": fb, "o_tool": o_tool, "w_example": w_example, "w_httpbin": w_httpbin,
            "w_unknown": w_unknown, "w_tagged": w_tagged, "w_tunnel": w_tunnel, "w_forged": w_forged,
            "w_only_o": w_only_o, "w_after": w_after,
            "blocked": blocked, "blocked_ip": blocked_ip, "connect": connect}


AGENT_COLS = ["agent_id", "session_id", "parent_session_id", "client_ip", "client_host", "provider",
              "model", "system_prompt_hash", "system_prompt", "first_prompt", "tools_offered",
              "running_tools_at_start"]
HTTP_COLS = ["ts", "client_ip", "client_host", "method", "scheme", "host", "port", "path", "url",
             "user_agent", "req_content_type", "req_bytes", "req_body_preview", "status_code",
             "resp_content_type", "resp_bytes", "duration_ms", "is_llm_api", "llm_call_id",
             "agent_id", "tool_use_id", "attribution", "candidate_agent_ids", "proxy_tag", "blocked", "error"]


def test_scenario_statements():
    stmts: list[tuple[str, tuple]] = []
    addon = obs_addon.ObsAddon(Store(None, sink=lambda s, p: stmts.append((s, p))), resolve_names=False)
    ids = run_scenario(addon)

    agents = [dict(zip(AGENT_COLS, p)) for s, p in stmts if s.startswith("INSERT INTO agents")]
    assert len(agents) == 4                       # O, A, B (same task as A), one-off title call
    same_task = [a for a in agents if a["first_prompt"] == TASK]
    assert len(same_task) == 2 and same_task[0]["agent_id"] != same_task[1]["agent_id"]

    tools = {p[0]: p[1] for s, p in stmts if s.startswith("INSERT INTO tool_calls")}
    a_id, b_id, o_id = tools[ids["fa"]["id"]], tools[ids["fb"]["id"]], tools[ids["o_tool"]["id"]]
    assert len({a_id, b_id, o_id}) == 3

    calls = [p for s, p in stmts if s.startswith("INSERT INTO llm_calls")]
    by_agent = {}
    for c in calls:
        by_agent.setdefault(c[1], []).append(c[3])
    assert by_agent[a_id] == ["new_conversation", "retry", "tool_chain"]
    assert by_agent[b_id] == ["new_conversation", "tool_chain"]
    assert by_agent[o_id] == ["new_conversation", "tool_chain"]

    http_rows = [dict(zip(HTTP_COLS, p)) for s, p in stmts if s.startswith("INSERT INTO http_requests")]

    def row(f):
        return next(r for r in http_rows if r["url"] == f.request.pretty_url and r["ts"] == f.metadata["obs_ts"])

    r = row(ids["w_example"])
    assert (r["agent_id"], r["tool_use_id"], r["attribution"]) == (a_id, ids["fa"]["id"], "content_match")
    assert set(r["candidate_agent_ids"]) == {o_id, a_id, b_id}
    r = row(ids["w_httpbin"])
    assert (r["agent_id"], r["attribution"]) == (b_id, "content_match")
    r = row(ids["w_unknown"])
    assert (r["agent_id"], r["attribution"]) == (None, "ambiguous")
    assert set(r["candidate_agent_ids"]) == {o_id, a_id, b_id}
    assert "\x00" not in r["req_body_preview"] and "secret" in r["req_body_preview"]
    r = row(ids["w_tagged"])
    assert (r["agent_id"], r["tool_use_id"], r["attribution"], r["proxy_tag"]) == (
        b_id, ids["fb"]["id"], "tool_tag", ids["fb"]["id"])
    assert "proxy-authorization" not in ids["w_tagged"].request.headers   # not forwarded
    r = row(ids["w_tunnel"])
    assert (r["agent_id"], r["attribution"]) == (a_id, "tool_tag")
    r = row(ids["w_forged"])
    assert (r["agent_id"], r["attribution"], r["proxy_tag"]) == (None, "unknown_tag", "toolu_forged")
    r = row(ids["w_only_o"])
    assert (r["agent_id"], r["attribution"]) == (o_id, "single_running_agent")
    r = row(ids["w_after"])
    assert (r["agent_id"], r["attribution"], r["candidate_agent_ids"]) == (None, "no_running_tool", [o_id])

    llm_rows = [r for r in http_rows if r["is_llm_api"]]
    assert len(llm_rows) == len(calls) == 8
    assert all(r["agent_id"] for r in llm_rows)

    assert ids["blocked"].response.status_code == 403
    assert ids["blocked_ip"].response.status_code == 403
    assert ids["connect"].response.status_code == 403
    assert sum(1 for r in http_rows if r["blocked"]) == 2

    updates = [p for s, p in stmts if s.startswith("UPDATE tool_calls SET ts_result")]
    assert {p[3] for p in updates} == {ids["fa"]["id"], ids["fb"]["id"], ids["o_tool"]["id"]}
    assert not any(isinstance(v, str) and "\x00" in v for _, p in stmts for v in p)


@pytest.mark.skipif(not os.environ.get("TEST_PG_DSN"), reason="TEST_PG_DSN not set")
def test_scenario_postgres():
    import psycopg

    dsn = os.environ["TEST_PG_DSN"]
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS obs CASCADE")
        c.execute((ROOT / "db/init/01_schema.sql").read_text())

    store = Store(dsn + " options=-csearch_path=obs")
    ids = run_scenario(obs_addon.ObsAddon(store, resolve_names=False))
    store.close()

    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute("SET search_path = obs")
        assert c.execute("SELECT count(*) FROM agents").fetchone() == (4,)
        assert c.execute("SELECT count(DISTINCT agent_id) FROM agents WHERE first_prompt = %s",
                         (TASK,)).fetchone() == (2,)
        rows = c.execute("SELECT has_tools, n_llm_calls, n_tool_calls FROM v_agents"
                         " ORDER BY first_seen").fetchall()
        assert rows == [(True, 2, 1), (True, 3, 1), (True, 2, 1), (False, 1, 0)]
        page = c.execute("SELECT t.tool_name, h.attribution FROM http_requests h JOIN tool_calls t"
                         " USING (tool_use_id) WHERE h.host = 'example.com'").fetchone()
        assert page == ("http_get", "content_match")
        assert c.execute("SELECT result_content FROM tool_calls WHERE tool_use_id = %s",
                         (ids["fb"]["id"],)).fetchone() == ('{"origin": "1.2.3.4"}',)
        assert c.execute("SELECT attribution, count(*) FROM http_requests WHERE agent_id IS NULL"
                         " AND NOT blocked GROUP BY 1 ORDER BY 1").fetchall() == [
            ("ambiguous", 1), ("no_running_tool", 1), ("unknown_tag", 1)]
        assert c.execute("SELECT identified_by, count(*) FROM llm_calls GROUP BY 1 ORDER BY 1"
                         ).fetchall() == [("new_conversation", 4), ("retry", 1), ("tool_chain", 3)]
        assert c.execute("SELECT event, host FROM connections").fetchall() == [("blocked_connect", "db-alias")]
        tl = c.execute("SELECT DISTINCT event FROM v_timeline").fetchall()
        assert {e for (e,) in tl} == {"llm_call", "tool", "http", "http_blocked"}
