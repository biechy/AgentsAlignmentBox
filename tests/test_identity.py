"""Which agent sent each request: pure tests of identity.AgentTracker."""
from helpers import assistant, results, tool_use

from identity import AgentTracker

IP, IP2 = "172.30.0.5", "172.30.0.9"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def call(tr, ip, msgs, tools_out=(), ok=True, user="u"):
    """One request/response round trip; returns (agent, method, is_new)."""
    agent, method, new = tr.identify(ip, user, msgs)
    tr.request_sent(agent, msgs)
    tr.response_received(agent, ok, [{"id": t["id"], "input": t["input"]} for t in tools_out])
    return agent, method, new


def test_identical_first_messages_are_distinct_agents_and_followups_stay_attached():
    tr = AgentTracker(clock=Clock(), boot_nonce="b")
    task = [{"role": "user", "content": "Count the files in /tmp"}]
    ga, gb = tool_use("Bash", {"command": "ls /tmp | wc -l"}), tool_use("Bash", {"command": "ls /tmp"})
    a, m1, n1 = call(tr, IP, task, [ga])
    b, m2, n2 = call(tr, IP, task, [gb])
    assert (m1, n1, m2, n2) == ("new_conversation", True, "new_conversation", True)
    assert a.agent_id != b.agent_id
    # follow-ups come in the "wrong" order: still exact, through the tool_use ids
    b2, mb, _ = call(tr, IP, task + [assistant([gb]), results((gb, "x"))])
    a2, ma, _ = call(tr, IP, task + [assistant([ga]), results((ga, "3"))])
    assert (a2.agent_id, ma, b2.agent_id, mb) == (a.agent_id, "tool_chain", b.agent_id, "tool_chain")


def test_retry_after_failure_is_the_same_agent_but_parallel_duplicates_are_not():
    tr = AgentTracker(clock=Clock(), boot_nonce="b")
    msgs = [{"role": "user", "content": "hello"}]
    a, _, _ = call(tr, IP, msgs, ok=False)            # 529 overloaded
    r, method, new = call(tr, IP, msgs)               # retried
    assert (r.agent_id, method, new) == (a.agent_id, "retry", False)
    x, _, _ = tr.identify(IP, "u", msgs)              # in flight, not answered yet
    tr.request_sent(x, msgs)
    y, method, new = tr.identify(IP, "u", msgs)       # a parallel twin
    assert new and y.agent_id not in (a.agent_id, x.agent_id)


def test_text_only_conversation_falls_back_to_first_message():
    tr = AgentTracker(clock=Clock(), boot_nonce="b")
    m = [{"role": "user", "content": "hi"}]
    a, _, _ = call(tr, IP, m)
    b, method, new = call(tr, IP, m + [assistant([{"type": "text", "text": "hey"}]),
                                       {"role": "user", "content": "again"}])
    assert (b.agent_id, method, new) == (a.agent_id, "first_message", False)


def test_web_request_attribution_from_running_tools():
    clock = Clock()
    tr = AgentTracker(clock=clock, boot_nonce="b")
    ta, tb = [{"role": "user", "content": "task A"}], [{"role": "user", "content": "task B"}]
    fa = tool_use("WebFetch", {"url": "https://example.com"})
    a, _, _ = call(tr, IP, ta, [fa])
    # only A has a running tool -> sure, even if the host is not in the input
    at = tr.attribute(IP, "cdn.other.net")
    assert (at.agent_id, at.method, at.tool_use_id) == (a.agent_id, "single_running_agent", fa["id"])
    # nothing runs in another container
    assert tr.attribute(IP2, "example.com").method == "none"

    clock.t += 1
    fb = tool_use("Bash", {"command": "curl -s https://httpbin.org/get"})
    b, _, _ = call(tr, IP, tb, [fb])
    at = tr.attribute(IP, "example.com")
    assert (at.agent_id, at.method, at.tool_use_id) == (a.agent_id, "content_match", fa["id"])
    assert set(at.candidates) == {a.agent_id, b.agent_id}
    at = tr.attribute(IP, "httpbin.org")
    assert (at.agent_id, at.method) == (b.agent_id, "content_match")
    at = tr.attribute(IP, "pypi.org")
    assert (at.agent_id, at.method) == (None, "ambiguous")
    assert set(at.candidates) == {a.agent_id, b.agent_id}

    # A's tool returns -> only B runs
    call(tr, IP, ta + [assistant([fa]), results((fa, "Example Domain"))])
    assert tr.attribute(IP, "pypi.org").method == "single_running_agent"
    # B's tool returns -> nothing runs: weak fallback to the last tool caller
    call(tr, IP, tb + [assistant([fb]), results((fb, "{}"))])
    at = tr.attribute(IP, "pypi.org")
    assert (at.agent_id, at.method, at.candidates) == (None, "no_running_tool", [b.agent_id])


def test_same_command_in_parallel_is_ambiguous_not_guessed():
    tr = AgentTracker(clock=Clock(), boot_nonce="b")
    task = [{"role": "user", "content": "curl https://httpbin.org/uuid"}]
    agents = [call(tr, IP, task, [tool_use("Bash", {"command": "curl -s https://httpbin.org/uuid"})])[0]
              for _ in range(3)]
    at = tr.attribute(IP, "httpbin.org")
    assert (at.agent_id, at.method) == (None, "ambiguous")
    assert set(at.candidates) == {a.agent_id for a in agents}


def test_tagged_requests_are_exact_even_with_identical_parallel_commands():
    tr = AgentTracker(clock=Clock(), boot_nonce="b")
    task = [{"role": "user", "content": "curl https://httpbin.org/uuid"}]
    tools = [tool_use("Bash", {"command": "curl -s https://httpbin.org/uuid"}) for _ in range(3)]
    agents = [call(tr, IP, task, [t])[0] for t in tools]
    for a, t in zip(agents, tools):
        at = tr.attribute(IP, "httpbin.org", tag=t["id"])
        assert (at.agent_id, at.tool_use_id, at.method) == (a.agent_id, t["id"], "tool_tag")
    # a tag the proxy never saw in the API traffic: forged or stale
    at = tr.attribute(IP, "httpbin.org", tag="toolu_forged")
    assert (at.agent_id, at.method) == (None, "unknown_tag")
    # background job: still exact after the tool call returned
    call(tr, IP, task + [assistant([tools[0]]), results((tools[0], "started"))])
    assert tr.attribute(IP, "evil.example", tag=tools[0]["id"]).agent_id == agents[0].agent_id


def test_agent_started_by_a_tagged_command_inherits_the_tag():
    tr = AgentTracker(clock=Clock(), boot_nonce="b")
    launch = tool_use("Bash", {"command": "my-agent run 'fetch the docs'"})
    parent, _, _ = call(tr, IP, [{"role": "user", "content": "orchestrate"}], [launch])
    # the child's own API calls carry the parent's tag (inherited proxy settings)
    child, _, _ = tr.identify(IP, "u", [{"role": "user", "content": "fetch the docs"}])
    tr.request_sent(child, [{"role": "user", "content": "fetch the docs"}])
    tr.note_llm_tag(child, launch["id"])
    fetch = tool_use("WebFetch", {"url": "https://docs.python.org"})
    tr.response_received(child, True, [{"id": fetch["id"], "input": fetch["input"]}])
    # an in-process request of the child, still carrying the inherited tag
    at = tr.attribute(IP, "docs.python.org", tag=launch["id"])
    assert (at.agent_id, at.method) == (child.agent_id, "content_match")
    at = tr.attribute(IP, "elsewhere.org", tag=launch["id"])
    assert (at.agent_id, at.method) == (None, "ambiguous")
    assert set(at.candidates) == {parent.agent_id, child.agent_id}


def test_url_domains_resolve_parallel_webfetch():
    """Two sub-agents fetch at once; Claude Code's untagged domain check names the domain
    in its query string, and a www. host matches a bare domain in the tool input."""
    from identity import AgentTracker, url_hints
    assert url_hints("api.anthropic.com", "https://api.anthropic.com/api/web/domain_info?domain=python.org") \
        >= {"api.anthropic.com", "python.org"}
    assert "example.com" in url_hints("www.example.com", "https://www.example.com/")
    t = AgentTracker(clock=lambda: 0.0, boot_nonce="x")
    a, _, _ = t.identify("ip", None, [{"role": "user", "content": "a"}])
    b, _, _ = t.identify("ip", None, [{"role": "user", "content": "b"}])
    t.response_received(a, True, [{"id": "tu_a", "name": "WebFetch", "input": {"url": "https://python.org/downloads"}}])
    t.response_received(b, True, [{"id": "tu_b", "name": "WebFetch", "input": {"url": "https://example.com"}}])
    r = t.attribute("ip", "api.anthropic.com", url="https://api.anthropic.com/api/web/domain_info?domain=python.org")
    assert (r.agent_id, r.tool_use_id, r.method) == (a.agent_id, "tu_a", "content_match")
    r = t.attribute("ip", "www.example.com", url="https://www.example.com/")
    assert (r.agent_id, r.method) == (b.agent_id, "content_match")
    r = t.attribute("ip", "cdn.other.net", url="https://cdn.other.net/x.js")
    assert (r.agent_id, r.method) == (None, "ambiguous")


def test_session_tags_separate_ssh_sessions():
    """Two SSH sessions in the one sandbox container: a WebFetch request carrying session
    S1's tag is attributed among S1's agents only, even while S2's agent runs a tool."""
    from identity import AgentTracker, is_session_tag
    assert is_session_tag("aabs-1a2b3c") and is_session_tag("aabr-20261023-085800-claude-1165")
    assert not is_session_tag("toolu_01ABC") and not is_session_tag(None)
    t = AgentTracker(clock=lambda: 0.0, boot_nonce="x")
    a, _, _ = t.identify("ip", None, [{"role": "user", "content": "session one"}])
    b, _, _ = t.identify("ip", None, [{"role": "user", "content": "session two"}])
    t.note_llm_tag(a, "aabs-111111")
    t.note_llm_tag(b, "aabs-222222")
    t.response_received(a, True, [{"id": "tu_a", "name": "WebFetch", "input": {"url": "https://a.example"}}])
    t.response_received(b, True, [{"id": "tu_b", "name": "WebFetch", "input": {"url": "https://b.example"}}])
    r = t.attribute("ip", "cdn.net", tag="aabs-111111", url="https://cdn.net/x")   # named by nobody
    assert (r.agent_id, r.method, r.candidates) == (a.agent_id, "single_running_agent", [a.agent_id])
    assert t.attribute("ip", "cdn.net", url="https://cdn.net/x").method == "ambiguous"   # untagged
    # a session the proxy has not seen on any model call yet: whole container, as before
    assert t.attribute("ip", "cdn.net", tag="aabs-999999").method == "ambiguous"
    # never treated as a forged tool-call tag
    assert t.attribute("ip", "cdn.net", tag="aabs-111111").method != "unknown_tag"


def test_hook_replaces_the_session_tag_with_the_tool_call_tag():
    import json
    import subprocess
    import sys
    from pathlib import Path
    hook = Path(__file__).resolve().parent.parent / "sandbox/sandbox/tag_tool_call.py"
    env = {"HTTPS_PROXY": "http://aabs-111111:x@proxy:8080", "PATH": "/usr/bin:/bin"}
    out = subprocess.run([sys.executable, str(hook)], input=json.dumps({
        "tool_use_id": "toolu_01X", "tool_input": {"command": "curl https://a.example"},
        "permission_mode": "bypassPermissions"}), capture_output=True, text=True, env=env, check=True)
    cmd = json.loads(out.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
    assert "HTTPS_PROXY=http://toolu_01X:x@proxy:8080" in cmd and "aabs-" not in cmd
