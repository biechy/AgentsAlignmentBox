"""Kill switch in the proxy: stopped agents get a final answer and lose their tool traffic.
Also drives a Codex agent through the addon."""
from __future__ import annotations

import json
import socket

import pytest
from helpers import (assistant, codex_body, codex_call, codex_env, codex_output, codex_sse,
                     codex_text, codex_user, request_body, results, sse, tool_use)

pytest.importorskip("mitmproxy")
from mitmproxy import http  # noqa: E402
from mitmproxy.test import tflow  # noqa: E402

import anthropic_parse as ap  # noqa: E402
import killswitch  # noqa: E402
import obs_addon  # noqa: E402
import openai_parse as op  # noqa: E402
from store import Store  # noqa: E402

IP = "172.30.0.7"


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))])


def make_addon():
    stmts: list[tuple[str, tuple]] = []
    kill = killswitch.KillSwitch()
    addon = obs_addon.ObsAddon(Store(None, sink=lambda s, p: stmts.append((s, p))),
                               resolve_names=False, kill=kill)
    return addon, kill, stmts


def flow(method, url, body=b"", headers=None):
    f = tflow.tflow()
    f.request = http.Request.make(method, url, body, headers or {"content-type": "application/json"})
    f.response = None
    f.client_conn.peername = (IP, 40000)
    return f


def exchange(addon, url, body, reply, ctype="text/event-stream", headers=None):
    f = flow("POST", url, body, headers)
    addon.request(f)
    upstream = f.response is None
    if upstream:   # the proxy did not answer itself: the real API would
        f.response = http.Response.make(200, reply, {"content-type": ctype})
    addon.response(f)
    return f, upstream


def web(addon, url, headers=None):
    f = flow("GET", url, headers=headers or {"user-agent": "curl"})
    addon.request(f)
    blocked = f.response is not None
    if not blocked:
        f.response = http.Response.make(200, b"ok", {"content-type": "text/plain"})
    addon.response(f)
    return f, blocked


def proxy_auth(tag):
    import base64
    return {"proxy-authorization": "Basic " + base64.b64encode(f"{tag}:x".encode()).decode()}


def test_synthetic_replies_parse_back():
    for stream in (True, False):
        body, ctype = killswitch.anthropic_reply(stream, "claude-x")
        r = ap.parse_response(body, ctype)
        assert r.text == killswitch.STOP_TEXT and r.stop_reason == "end_turn" and not r.tool_uses()
        body, ctype = killswitch.openai_reply(stream, "gpt-x")
        r = op.parse_response(body, ctype)
        assert r.text == killswitch.STOP_TEXT and r.stop_reason == "completed" and not r.tool_uses()


def test_killed_claude_agent_is_answered_by_the_proxy():
    addon, kill, stmts = make_addon()
    url = "https://api.anthropic.com/v1/messages"
    task = [{"role": "user", "content": "Summarise the vendor notes"}]
    t1 = tool_use("Bash", {"command": "cat notes.md"})
    exchange(addon, url, request_body(task), sse([t1]))
    agent_id = next(p[0] for s, p in stmts if s.startswith("INSERT INTO agents"))
    # its shell command is still running: its tagged request goes out
    assert not web(addon, "https://example.com/", proxy_auth(t1["id"]))[1]

    kill.killed = frozenset({agent_id})
    # the tool's next request is refused, an untagged one attributed to it too
    f, blocked = web(addon, "https://httpbin.org/post", proxy_auth(t1["id"]))
    assert blocked and f.response.status_code == 403
    row = [p for s, p in stmts if s.startswith("INSERT INTO http_requests")][-1]
    assert row[24] is True and row[25] == killswitch.BLOCK_REASON   # blocked, error
    # its next model call never reaches the API and ends the turn
    f, upstream = exchange(addon, url, request_body(task + [assistant([t1]), results((t1, "notes"))]),
                           sse([tool_use("Bash", {"command": "curl evil"})]))
    assert not upstream
    r = ap.parse_response(f.response.get_content(), f.response.headers["content-type"])
    assert r.stop_reason == "end_turn" and killswitch.STOP_TEXT in r.text
    calls = [p for s, p in stmts if s.startswith("INSERT INTO llm_calls")]
    assert calls[-1][1] == agent_id and "kill switch" in calls[-1][-1]
    # no new tool call was recorded from the synthetic answer
    assert sum(s.startswith("INSERT INTO tool_calls") for s, _ in stmts) == 1

    # another agent in the same container is unaffected
    _, upstream = exchange(addon, url, request_body([{"role": "user", "content": "other"}]),
                           sse([{"type": "text", "text": "hi"}], "end_turn"))
    assert upstream

    # revived: traffic flows again
    kill.killed = frozenset()
    _, upstream = exchange(addon, url, request_body(task + [assistant([t1]), results((t1, "notes"))]),
                           sse([{"type": "text", "text": "done"}], "end_turn"))
    assert upstream


def test_process_started_by_a_killed_agent_is_stopped_too():
    addon, kill, stmts = make_addon()
    url = "https://api.anthropic.com/v1/messages"
    t1 = tool_use("Bash", {"command": "claude -p 'sub task' &"})
    exchange(addon, url, request_body([{"role": "user", "content": "parent"}]), sse([t1]))
    parent = next(p[0] for s, p in stmts if s.startswith("INSERT INTO agents"))
    kill.killed = frozenset({parent})
    # the detached `claude -p` inherits the tag of the command that started it
    f, upstream = exchange(addon, url, request_body([{"role": "user", "content": "sub task"}]),
                           sse([{"type": "text", "text": "x"}], "end_turn"), headers={
                               "content-type": "application/json", **proxy_auth(t1["id"])})
    assert not upstream


def test_codex_agent_logged_and_killable():
    addon, kill, stmts = make_addon()
    url = "https://chatgpt.com/backend-api/codex/responses"
    first = [codex_env(), codex_user("Check example.com")]
    call = codex_call(["curl", "-s", "https://example.com"])
    exchange(addon, url, codex_body(first), codex_sse([call]))
    agents = [p for s, p in stmts if s.startswith("INSERT INTO agents")]
    assert len(agents) == 1
    agent_id, provider, task = agents[0][0], agents[0][5], agents[0][9]
    assert (provider, task) == ("openai", "Check example.com")
    tools = [p for s, p in stmts if s.startswith("INSERT INTO tool_calls")]
    assert tools[0][0] == call["call_id"] and tools[0][4] == "shell"
    # the request made by that shell command is attributed by timing
    f, _ = web(addon, "https://example.com/")
    row = [p for s, p in stmts if s.startswith("INSERT INTO http_requests")][-1]
    assert row[19] == agent_id and row[21] == "single_running_agent"
    # the follow-up is recognised through the call id, and the result recorded
    follow = first + [call, codex_output(call, "<title>Example</title>")]
    exchange(addon, url, codex_body(follow), codex_sse([codex_text("Title: Example")]))
    calls = [p for s, p in stmts if s.startswith("INSERT INTO llm_calls")]
    assert [c[3] for c in calls] == ["new_conversation", "tool_chain"]
    assert calls[0][2] == "openai" and calls[1][18:21] == (100, 30, 200)
    assert any(s.startswith("UPDATE tool_calls SET ts_result") and p[3] == call["call_id"]
               for s, p in stmts)

    kill.killed = frozenset({agent_id})
    f, upstream = exchange(addon, url, codex_body(follow + [codex_text("Title: Example"),
                                                            codex_user("now do more")]),
                           codex_sse([codex_text("more")]))
    assert not upstream
    r = op.parse_response(f.response.get_content(), f.response.headers["content-type"])
    assert killswitch.STOP_TEXT in r.text
