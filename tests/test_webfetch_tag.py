"""WebFetch URL marker: exact attribution of identical requests sent at the same moment
by parallel sub-agents of one Claude Code process."""
from __future__ import annotations

import base64
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import request_body, sse, tool_use

import urltag

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "sandbox/sandbox/tag_tool_call.py"


def hook(tool_name, tool_input, tool_use_id="toolu_01AB"):
    out = subprocess.run([sys.executable, str(HOOK)], input=json.dumps({
        "tool_name": tool_name, "tool_use_id": tool_use_id, "tool_input": tool_input,
        "permission_mode": "bypassPermissions"}), capture_output=True, text=True, check=True).stdout
    return json.loads(out)["hookSpecificOutput"]["updatedInput"] if out.strip() else None


def test_hook_marks_webfetch_urls_only():
    up = hook("WebFetch", {"url": "https://example.com/a?x=1&aab_tag=forged", "prompt": "title?"})
    assert up == {"url": "https://example.com/a?x=1&aab_tag=toolu_01AB", "prompt": "title?"}
    assert hook("WebFetch", {"url": "file:///etc/passwd"}) is None
    assert hook("Read", {"file_path": "/workspace/x"}) is None


def test_strip_and_redirects():
    assert urltag.strip_url_tag("/a?x=%2F1&aab_tag=toolu_1&y") == ("/a?x=%2F1&y", "toolu_1")
    assert urltag.strip_url_tag("/a?aab_tag=t") == ("/a", "t")
    assert urltag.strip_url_tag("/a?x=1") == ("/a?x=1", None)
    t = [0.0]
    r = urltag.Redirects(clock=lambda: t[0])
    r.remember("ip", "https://e.com/old", "/new?q=1", "toolu_1")
    assert r.take("ip", "https://e.com/new?q=1#frag") == "toolu_1"
    assert r.take("ip", "https://e.com/new?q=1") is None                 # used once
    r.remember("ip", "https://e.com/a", "https://e.com/same", "toolu_1")
    r.remember("ip", "https://e.com/b", "https://e.com/same", "toolu_2")
    assert r.take("ip", "https://e.com/same") is None                    # collision: nobody
    r.remember("ip", "https://e.com/a", "https://e.com/late", "toolu_1")
    t[0] = 120.0
    assert r.take("ip", "https://e.com/late") is None                    # expired


pytest.importorskip("mitmproxy")
from mitmproxy import http  # noqa: E402
from mitmproxy.test import tflow  # noqa: E402

import obs_addon  # noqa: E402
from store import Store  # noqa: E402

IP = "172.30.0.9"


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))])


def flow(method, url, body=b"", headers=None):
    f = tflow.tflow()
    f.request = http.Request.make(method, url, body, headers or {"content-type": "application/json"})
    f.response = None
    f.client_conn.peername = (IP, 40000)
    return f


def test_parallel_identical_webfetch_requests_are_told_apart():
    stmts = []
    addon = obs_addon.ObsAddon(Store(None, sink=lambda s, p: stmts.append((s, p))), resolve_names=False)
    agents = {}
    for name in ("worker one", "worker two"):        # same process, same container, same session
        f = flow("POST", "https://api.anthropic.com/v1/messages",
                 request_body([{"role": "user", "content": name}]),
                 {"content-type": "application/json",
                  "proxy-authorization": "Basic " + base64.b64encode(b"aabs-abc123:x").decode()})
        addon.request(f)
        tu = tool_use("WebFetch", {"url": "https://example.com/", "prompt": "title?"})
        f.response = http.Response.make(200, sse([tu]), {"content-type": "text/event-stream"})
        addon.response(f)
        agents[name] = (f.metadata["obs_llm"]["agent_id"], tu["id"])

    def fetch(url, status=200, location=None):
        f = flow("GET", url, headers={"user-agent": "claude-code",
                 "proxy-authorization": "Basic " + base64.b64encode(b"aabs-abc123:x").decode()})
        addon.request(f)
        sent = f.request.pretty_url                  # what the site receives
        f.response = http.Response.make(status, b"<title>x</title>",
                                        {"content-type": "text/html", **({"location": location} if location else {})})
        addon.response(f)
        row = [p for s, p in stmts if s.startswith("INSERT INTO http_requests")][-1]
        return sent, row[19], row[20], row[21], row[8]     # agent_id, tool_use_id, attribution, url

    (a1, t1), (a2, t2) = agents["worker one"], agents["worker two"]
    # identical URL, same moment, both tools running: the marker decides
    sent, aid, tid, how, logged = fetch(f"https://example.com/?aab_tag={t2}")
    assert (aid, tid, how) == (a2, t2, "url_tag")
    assert sent == logged == "https://example.com/"   # marker never forwarded nor logged
    assert fetch(f"https://example.com/?aab_tag={t1}")[1:4] == (a1, t1, "url_tag")
    # without a marker the same request stays ambiguous between them
    assert fetch("https://example.com/")[3] == "ambiguous"
    # a redirect of a marked request belongs to the same tool call
    fetch(f"http://example.com/?aab_tag={t1}", status=301, location="https://www.example.com/home")
    assert fetch("https://www.example.com/home")[1:4] == (a1, t1, "redirect")
    # a marker naming no tool call the proxy saw is a forgery
    assert fetch("https://example.com/?aab_tag=toolu_forged")[3] == "unknown_tag"
