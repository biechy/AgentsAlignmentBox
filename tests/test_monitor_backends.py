"""Claude Code backend (command line, result parsing) and the MCP server, no model, no DB."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "monitor"))

import cc_backend  # noqa: E402
import mcp_server  # noqa: E402
import tools  # noqa: E402


def test_claude_code_runs_with_mcp_tools_only():
    cmd = cc_backend.command("/tmp/mcp.json")
    assert cmd[:2] == ["claude", "-p"]
    assert cmd[cmd.index("--tools") + 1] == ""                       # no built-in tool
    assert cmd[cmd.index("--allowedTools") + 1] == "mcp__aab"
    assert cmd[cmd.index("--permission-mode") + 1] == "dontAsk"
    assert "--strict-mcp-config" in cmd and "--no-session-persistence" in cmd
    cfg = cc_backend.mcp_config()["mcpServers"]["aab"]
    assert cfg["command"] == "python3" and cfg["args"][0].endswith("mcp_server.py")


def test_parse_result():
    ok = json.dumps({"type": "result", "subtype": "success", "is_error": False,
                     "result": "Reviewed 3 agents, no drift.", "total_cost_usd": 0.01})
    r = cc_backend.parse_result(ok, "", 0)
    assert r["summary"].startswith("Reviewed") and r["error"] is None and not r["not_logged_in"]
    bad = json.dumps({"type": "result", "subtype": "success", "is_error": True,
                      "result": "Not logged in · Please run /login"})
    r = cc_backend.parse_result(bad, "", 1)
    assert r["not_logged_in"] and "login" in r["error"]
    r = cc_backend.parse_result("", "boom", 1)
    assert r["error"] == "boom" and not r["not_logged_in"]


def test_review_never_bills_a_stray_api_key(monkeypatch):
    seen = {}

    def fake_run(cmd, input, capture_output, text, cwd, env, timeout):
        seen["env"], seen["input"] = env, input
        cfg = json.loads(Path(cmd[cmd.index("--mcp-config") + 1]).read_text())
        seen["cfg"] = cfg
        return type("P", (), {"stdout": json.dumps({"subtype": "success", "is_error": False,
                                                     "result": "ok"}), "stderr": "", "returncode": 0})()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-be-used")
    monkeypatch.setattr(cc_backend.subprocess, "run", fake_run)
    out = cc_backend.review("briefing text")
    assert out["summary"] == "ok"
    assert "ANTHROPIC_API_KEY" not in seen["env"] and seen["input"] == "briefing text"
    assert "aab" in seen["cfg"]["mcpServers"]


def test_mcp_server_protocol(monkeypatch):
    calls = []
    monkeypatch.setattr(mcp_server, "call_tool", lambda conn, name, args: calls.append((name, args))
                        or [{"agent_id": "a1"}])
    s = mcp_server.Server(conn_factory=lambda: type("C", (), {"closed": False})())
    init = s.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18"}})
    assert init["result"]["protocolVersion"] == "2025-06-18" and "tools" in init["result"]["capabilities"]
    assert s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    listed = s.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    assert {t["name"] for t in listed} == {t["name"] for t in tools.TOOLS}
    assert all("inputSchema" in t for t in listed)
    res = s.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "list_agents", "arguments": {"limit": 5}}})["result"]
    assert not res["isError"] and json.loads(res["content"][0]["text"]) == [{"agent_id": "a1"}]
    assert calls == [("list_agents", {"limit": 5})]
    assert s.handle({"jsonrpc": "2.0", "id": 4, "method": "nope"})["error"]["code"] == -32601


def test_mcp_tool_errors_are_results(monkeypatch):
    def boom(conn, name, args):
        raise ValueError("only read queries are allowed")
    monkeypatch.setattr(mcp_server, "call_tool", boom)
    s = mcp_server.Server(conn_factory=lambda: type("C", (), {"closed": False})())
    res = s.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "sql", "arguments": {"query": "DELETE FROM agents"}}})
    assert res["result"]["isError"] and "read queries" in res["result"]["content"][0]["text"]
