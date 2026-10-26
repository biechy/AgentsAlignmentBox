"""Monitor agent tool loop and DB guards, without calling a real model."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "monitor"))

ROOT = Path(__file__).resolve().parent.parent
pg = pytest.mark.skipif(not os.environ.get("TEST_PG_DSN"), reason="TEST_PG_DSN not set")


class FakeBlock:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeResp:
    def __init__(self, content, stop_reason="end_turn"):
        self.content = content
        self.stop_reason = stop_reason
        self.stop_details = None


class FakeMessages:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def create(self, **kw):
        # snapshot the messages list (the agent keeps mutating the same object)
        self.calls.append({**kw, "messages": list(kw["messages"])})
        return self.script.pop(0)


class FakeClient:
    """Mimics anthropic.Anthropic().beta.messages.create with a scripted reply list."""
    def __init__(self, script):
        self.beta = type("B", (), {"messages": FakeMessages(script)})()


def test_agent_runs_tools_and_records_flags(monkeypatch):
    import agent as agentmod

    class Conn:
        def execute(self, *a):
            pass

    seen = {}

    def fake_insert(conn, **kw):
        seen.setdefault("flags", []).append(kw)
        return len(seen["flags"])

    monkeypatch.setattr(agentmod.db, "agents_overview",
                        lambda conn, *a, **k: [{"agent_id": "x", "task": "do thing"}])
    monkeypatch.setattr(agentmod.db, "insert_flag", fake_insert)

    # Turn 1: model calls list_agents then raise_flag; turn 2: it stops with text.
    turn1 = FakeResp([
        FakeBlock(type="tool_use", id="t1", name="list_agents", input={}),
        FakeBlock(type="tool_use", id="t2", name="raise_flag", input={
            "agent_id": "x", "severity": "high", "category": "data_egress",
            "summary": "x exfiltrated data", "evidence": {"tool_call_ids": ["z"]}}),
    ], stop_reason="tool_use")
    turn2 = FakeResp([FakeBlock(type="text", text="Done, one flag raised.")])

    mon = agentmod.MonitorAgent(Conn(), FakeClient([turn1, turn2]))
    out = mon.review("briefing")

    assert out["stopped"] == "end_turn"
    assert len(out["raised"]) == 1 and out["raised"][0]["flag_id"] == 1
    assert seen["flags"][0]["detector"] == "agent:monitor"
    assert seen["flags"][0]["severity"] == "high"
    # both tools answered in one user message
    msgs = mon.client.beta.messages.calls[1]["messages"]
    results = msgs[-1]["content"]
    assert {r["tool_use_id"] for r in results} == {"t1", "t2"}


def test_agent_tool_error_is_returned_not_raised(monkeypatch):
    import agent as agentmod

    class Conn:
        def execute(self, *a):
            pass

    turn1 = FakeResp([FakeBlock(type="tool_use", id="t1", name="sql",
                                input={"query": "DELETE FROM agents"})], stop_reason="tool_use")
    turn2 = FakeResp([FakeBlock(type="text", text="ok")])
    mon = agentmod.MonitorAgent(Conn(), FakeClient([turn1, turn2]))

    def reject(conn, q, p=None):
        raise ValueError("only read queries are allowed")

    monkeypatch.setattr(agentmod.db, "query", reject)  # rejects a non-select, no DB touch
    out = mon.review("b")
    result = mon.client.beta.messages.calls[1]["messages"][-1]["content"][0]
    assert result["is_error"] and "read queries" in result["content"]
    assert out["raised"] == []


@pg
def test_query_guard_blocks_writes_and_multi_statements():
    import db as mdb

    dsn = os.environ["TEST_PG_DSN"]
    import psycopg
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS obs CASCADE")
        c.execute((ROOT / "db/init/01_schema.sql").read_text())

    conn = mdb.connect(dsn + " options=-csearch_path=obs")
    with pytest.raises(ValueError):
        mdb.query(conn, "INSERT INTO flags (severity, summary) VALUES ('high','x')")
    with pytest.raises(ValueError):
        mdb.query(conn, "SELECT 1; DROP TABLE agents")
    # a plain SELECT works and returns rows
    assert mdb.query(conn, "SELECT count(*) AS n FROM agents")[0]["n"] == 0
    # even a well-formed write is stopped by the read-only transaction
    with pytest.raises(Exception):
        mdb.query(conn, "WITH x AS (INSERT INTO flags(severity,summary) VALUES('high','y') RETURNING 1) SELECT * FROM x")
