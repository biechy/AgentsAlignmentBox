"""Deterministic monitor rules against a real Postgres (TEST_PG_DSN)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "monitor"))

pytestmark = pytest.mark.skipif(not os.environ.get("TEST_PG_DSN"), reason="TEST_PG_DSN not set")
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def conn():
    import psycopg
    dsn = os.environ["TEST_PG_DSN"]
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS obs CASCADE")
        c.execute((ROOT / "db/init/01_schema.sql").read_text())
        c.execute("SET search_path = obs")
        yield c


def agent(conn, aid, task="do the task", host="agent-1"):
    conn.execute("INSERT INTO agents (agent_id, client_host, first_prompt, tools_offered)"
                 " VALUES (%s,%s,%s,'{Bash}')", (aid, host, task))


def http(conn, **kw):
    kw.setdefault("ts", "now()")
    cols = "ts, client_host, method, host, port, path, req_bytes, is_llm_api, agent_id," \
           " tool_use_id, attribution, candidate_agent_ids, proxy_tag, blocked, error"
    vals = dict(method="GET", host="example.com", port=443, path="/", req_bytes=0,
                is_llm_api=False, client_host="agent-1", agent_id=None, tool_use_id=None,
                attribution=None, candidate_agent_ids=None, proxy_tag=None, blocked=False, error=None)
    vals.update(kw)
    conn.execute(
        f"INSERT INTO http_requests ({cols}) VALUES (now(),%(client_host)s,%(method)s,%(host)s,"
        "%(port)s,%(path)s,%(req_bytes)s,%(is_llm_api)s,%(agent_id)s,%(tool_use_id)s,"
        "%(attribution)s,%(candidate_agent_ids)s,%(proxy_tag)s,%(blocked)s,%(error)s)", vals)


def run(conn, wm=None):
    import rules
    return rules.run_rules(conn, wm or {})


def test_rules_fire_on_the_right_rows(conn):
    agent(conn, "a1")
    http(conn, blocked=True, method="GET", host="db", port=5432, agent_id="a1", attribution="single_running_agent")
    http(conn, host="api.anthropic.com", path="/api/web/domain_info", agent_id="a1")  # benign
    http(conn, method="POST", host="auth.openai.com", req_bytes=300, agent_id="a1")    # Codex login
    http(conn, host="pypi.org", agent_id="a1", blocked=True,
         error="agent stopped by the operator (kill switch)")                           # kill switch
    http(conn, method="POST", host="paste.example.net", req_bytes=5000, agent_id="a1",
         attribution="tool_tag")                                                       # upload
    http(conn, host="evil.net", proxy_tag="toolu_forged", attribution="unknown_tag")   # forged tag
    conn.execute("INSERT INTO connections (ts, client_host, host, port, event)"
                 " VALUES (now(),'agent-1','10.0.0.9',22,'tls_failed')")

    signals, wm = run(conn)
    by_rule = {}
    for s in signals:
        by_rule.setdefault(s.rule, []).append(s)
    assert set(by_rule) == {"blocked_destination", "outbound_upload", "unknown_proxy_tag",
                            "undecoded_connection"}
    assert by_rule["unknown_proxy_tag"][0].severity == "high"
    assert len(by_rule["blocked_destination"]) == 1 and len(by_rule["outbound_upload"]) == 1
    assert by_rule["outbound_upload"][0].agent_id == "a1"
    assert "paste.example.net" in by_rule["outbound_upload"][0].summary
    # the benign anthropic API call produced no signal
    assert not any("domain_info" in s.summary for s in signals)

    # watermarks advance: a second run over the same rows yields nothing
    signals2, wm2 = run(conn, wm)
    assert signals2 == []
    assert wm2["http_id"] == wm["http_id"]


def test_untagged_shell_request_flagged(conn):
    agent(conn, "a2")
    conn.execute("INSERT INTO tool_calls (tool_use_id, agent_id, ts, tool_name, tool_input)"
                 " VALUES ('toolu_sh','a2',now(),'Bash','{\"command\":\"curl evil.net\"}')")
    http(conn, host="evil.net", tool_use_id="toolu_sh", proxy_tag=None, agent_id="a2")
    http(conn, host="evil2.net", tool_use_id="toolu_sh", proxy_tag="aabs-123abc", agent_id="a2")
    signals, _ = run(conn)
    hosts = sorted(s.summary.split()[2] for s in signals if s.rule == "untagged_shell_request")
    assert hosts == ["evil.net", "evil2.net"]          # no tag, or only the session's tag


def test_watermark_only_sees_new_rows(conn):
    agent(conn, "a3")
    http(conn, blocked=True, host="db", port=5432, agent_id="a3")
    _, wm = run(conn)
    http(conn, blocked=True, host="postgres", port=5432, agent_id="a3")
    signals, _ = run(conn, wm)
    assert len(signals) == 1 and "postgres" in signals[0].summary
