"""mitmproxy addon: log every agent's LLM calls, tool calls and web traffic to SQL.

All egress of the sandbox goes through this proxy (its Docker network has no
other route out). TLS is intercepted, so the proxy sees the model API traffic in
clear (Anthropic Messages API for Claude Code, OpenAI Responses API for Codex)
and records, without any help from the agents and without assuming anything
about how they are organised:
  - which agent sent each request (see identity.py; every agent is treated
    the same, orchestrator or sub-agent),
  - every tool call (name, input, result) and every server tool (web search),
  - every other HTTP(S) request (sites visited, downloads, uploads), attributed exactly
    when it carries a tool call's tag (shell commands: proxy credentials; WebFetch: an
    ?aab_tag= marker removed before forwarding; their redirects, see urltag.py).
It also enforces the kill switch (killswitch.py): an agent the operator stopped
gets a final "stopped" answer to each model call, and its tool requests are refused.

Run: mitmdump -s obs_addon.py
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import os
import socket
import sys
import time
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import anthropic_parse as ap  # noqa: E402
import killswitch  # noqa: E402
import openai_parse as op  # noqa: E402
import urltag  # noqa: E402
from identity import AgentTracker, is_session_tag  # noqa: E402
from store import Store, jsonb  # noqa: E402

MAX_TEXT = int(os.environ.get("OBS_MAX_TEXT", "200000"))
BODY_PREVIEW = int(os.environ.get("OBS_BODY_PREVIEW", "4096"))
# Hostnames the agents may never reach through the proxy (the log database...).
BLOCKED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("OBS_BLOCKED_HOSTS", "db,postgres,localhost,proxy").split(",")
    if h.strip()
}
BLOCK_PRIVATE = os.environ.get("OBS_BLOCK_PRIVATE", "1") == "1"
DNS_CACHE_TTL_S = 60.0
TAG_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")


def now() -> datetime:
    return datetime.now(timezone.utc)


def trunc(s: str | None, n: int = MAX_TEXT) -> str | None:
    if s is None:
        return None
    s = s.replace("\x00", "")
    return s if len(s) <= n else s[:n] + f"...[truncated {len(s) - n} chars]"


def proxy_tag(headers) -> str | None:
    """Username of the Proxy-Authorization header: the tool call that sent the request."""
    auth = headers.get("proxy-authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    try:
        user = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace").split(":", 1)[0]
    except (binascii.Error, ValueError):
        return None
    return user if TAG_RE.fullmatch(user) else None


def llm_provider(method: str, host: str, path: str) -> str | None:
    """`anthropic` / `openai` for a model generation call, else None."""
    if ap.is_messages_call(method, host, path):
        return "anthropic"
    if op.is_responses_call(method, host, path):
        return "openai"
    return None


def norm_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    return ip[7:] if ip.startswith("::ffff:") else ip


class ObsAddon:
    def __init__(self, store: Store, resolve_names: bool = True,
                 kill: killswitch.KillSwitch | None = None):
        self.store = store
        self.resolve_names = resolve_names
        self.kill = kill or killswitch.KillSwitch()
        self.tracker = AgentTracker()
        self.redirects = urltag.Redirects()
        self.conn_tag: dict[str, str] = {}             # client connection -> proxy tag (CONNECT)
        self.resolved_results: set[str] = set()        # tool_use_ids whose result is logged
        self._host_cache: dict[str, tuple[float, str | None]] = {}
        self._blocked_cache: dict[str, tuple[float, bool]] = {}

    # -- helpers ------------------------------------------------------------
    def client_host(self, ip: str | None) -> str | None:
        """Container name of a client, by reverse DNS on the Docker network."""
        if not ip or not self.resolve_names:
            return None
        hit = self._host_cache.get(ip)
        if hit and time.monotonic() - hit[0] < DNS_CACHE_TTL_S:
            return hit[1]
        try:
            name = socket.gethostbyaddr(ip)[0].split(".")[0]
        except OSError:
            name = None
        self._host_cache[ip] = (time.monotonic(), name)
        return name

    def is_blocked(self, host: str) -> bool:
        h = (host or "").lower().strip("[]")
        hit = self._blocked_cache.get(h)
        if hit and time.monotonic() - hit[0] < DNS_CACHE_TTL_S:
            return hit[1]
        blocked = self._is_blocked_uncached(h)
        self._blocked_cache[h] = (time.monotonic(), blocked)
        return blocked

    @staticmethod
    def _is_blocked_uncached(h: str) -> bool:
        if h in BLOCKED_HOSTS:
            return True
        if not BLOCK_PRIVATE:
            return False
        try:
            addrs = [ipaddress.ip_address(h)]
        except ValueError:
            try:
                addrs = [ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(h, None)]
            except OSError:
                return False  # unresolvable: let upstream fail normally
        return any(a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                   or a.is_unspecified for a in addrs)

    def stopped(self, agent_id: str | None, tag: str | None) -> bool:
        """The agent was killed, or its process was started by a tool call of a killed agent."""
        return self.kill.is_killed(agent_id) or (
            bool(tag) and self.kill.is_killed(self.tracker.tool_owner.get(tag)))

    def _deny(self, flow, why: str) -> None:
        from mitmproxy import http
        flow.response = http.Response.make(
            403, f"Blocked by sandbox proxy: {why}\n".encode(), {"Content-Type": "text/plain"}
        )
        flow.metadata["obs_blocked"] = True
        flow.metadata["obs_block_reason"] = why

    # -- mitmproxy hooks ----------------------------------------------------
    def http_connect(self, flow) -> None:
        tag = proxy_tag(flow.request.headers)
        if tag:
            self.conn_tag[flow.client_conn.id] = tag
        if self.is_blocked(flow.request.host):
            ip = norm_ip(flow.client_conn.peername[0])
            self.store.execute(
                "INSERT INTO connections (ts, client_ip, client_host, host, port, event, detail)"
                " VALUES (%s,%s,%s,%s,%s,'blocked_connect',NULL)",
                (now(), ip, self.client_host(ip), flow.request.host, flow.request.port),
            )
            self._deny(flow, "internal host")

    def client_disconnected(self, client) -> None:
        self.conn_tag.pop(client.id, None)

    def request(self, flow) -> None:
        flow.metadata["obs_ts"] = now()
        flow.metadata["obs_t0"] = time.monotonic()
        # Plain HTTP carries the tag on each request, HTTPS on its CONNECT. Never forward it.
        tag = proxy_tag(flow.request.headers) or self.conn_tag.get(flow.client_conn.id)
        flow.request.headers.pop("proxy-authorization", None)
        flow.metadata["obs_tag"] = tag
        if self.is_blocked(flow.request.host):
            self._deny(flow, "internal host")
            return
        req = flow.request
        provider = llm_provider(req.method, req.pretty_host, req.path)
        if provider:
            try:
                self._on_llm_request(flow, provider)
                return
            except Exception as e:  # noqa: BLE001  never break traffic
                print(f"[obs] llm request parse error: {e!r}", file=sys.stderr)
        # WebFetch marker (?aab_tag=<tool call>): read it, never forward it. It names the tool
        # call unless the proxy credentials already do (a shell command's own tag wins).
        ip = norm_ip(flow.client_conn.peername[0])
        via = None
        path, url_tag = urltag.strip_url_tag(req.path)
        if url_tag is not None:
            req.path = path
            if TAG_RE.fullmatch(url_tag) and (not tag or is_session_tag(tag)):
                tag, via = url_tag, "url_tag"
        elif not tag or is_session_tag(tag):
            followed = self.redirects.take(ip, req.pretty_url)   # redirect of a tagged request
            if followed:
                tag, via = followed, "redirect"
        flow.metadata["obs_tag"] = tag
        # Attribute at request time: which agents have a tool running right now.
        attr = self.tracker.attribute(ip, req.pretty_host, tag, req.pretty_url)
        if via and attr.method == "tool_tag":
            attr.method = via
        flow.metadata["obs_attr"] = attr
        if self.stopped(attr.agent_id, tag):
            self._deny(flow, killswitch.BLOCK_REASON)

    def response(self, flow) -> None:
        try:
            if "obs_llm" in flow.metadata:
                self._on_llm_response(flow)
        except Exception as e:  # noqa: BLE001
            print(f"[obs] llm response parse error: {e!r}", file=sys.stderr)
        self._remember_redirect(flow)
        self._log_http(flow)

    def _remember_redirect(self, flow) -> None:
        """A tool call's request answered by a redirect: the follow-up is that call's too."""
        attr, resp = flow.metadata.get("obs_attr"), flow.response
        if (attr is None or attr.tool_use_id is None or resp is None
                or resp.status_code not in urltag.REDIRECT_STATUS
                or attr.method not in ("tool_tag", "url_tag", "redirect")):
            return
        location = resp.headers.get("location")
        if location:
            self.redirects.remember(norm_ip(flow.client_conn.peername[0]),
                                    flow.request.pretty_url, location, attr.tool_use_id)

    def error(self, flow) -> None:
        if flow.response is None:
            try:
                if "obs_llm" in flow.metadata:
                    self._on_llm_response(flow)
            except Exception as e:  # noqa: BLE001
                print(f"[obs] llm error handling: {e!r}", file=sys.stderr)
            self._log_http(flow)

    def tls_failed_client(self, data) -> None:
        ip = norm_ip(data.context.client.peername[0])
        server = data.context.server
        host, port = (server.address or (None, None))
        self.store.execute(
            "INSERT INTO connections (ts, client_ip, client_host, host, port, event, detail)"
            " VALUES (%s,%s,%s,%s,%s,'tls_failed',%s)",
            (now(), ip, self.client_host(ip), server.sni or host, port,
             str(data.conn.error or "")),
        )

    def tcp_start(self, flow) -> None:
        ip = norm_ip(flow.client_conn.peername[0])
        host, port = flow.server_conn.address or (None, None)
        self.store.execute(
            "INSERT INTO connections (ts, client_ip, client_host, host, port, event, detail)"
            " VALUES (%s,%s,%s,%s,%s,'tcp_start',NULL)",
            (now(), ip, self.client_host(ip), host, port),
        )

    # -- LLM traffic --------------------------------------------------------
    def _on_llm_request(self, flow, provider: str = "anthropic") -> None:
        body = json.loads(flow.request.get_content() or b"{}")
        headers = dict(flow.request.headers)
        if provider == "openai":
            messages = op.to_messages(body)
            session = op.session_id_from(body, headers)
            info = {"system": op.system_text(body), "task": op.task_text(messages),
                    "tools": op.tool_names(body), "parent": op.parent_session_from(headers)}
        else:
            messages = body.get("messages") or []
            session = ap.session_id_from(body, headers)
            info = {"system": ap.system_text(body.get("system")),
                    "task": ap.first_user_text(messages),
                    "tools": [t.get("name") for t in (body.get("tools") or [])
                              if isinstance(t, dict)], "parent": None}
        ip = norm_ip(flow.client_conn.peername[0])
        ts = flow.metadata["obs_ts"]
        tag = flow.metadata.get("obs_tag")
        agent, method, is_new = self.tracker.identify(ip, session, messages)
        if is_new:
            self._register_agent(agent.agent_id, provider, body.get("model"), info, ip, session, ts)
        delta = self.tracker.request_sent(agent, messages)
        self.tracker.note_llm_tag(agent, tag)
        stream = bool(body.get("stream"))
        flow.metadata["obs_llm"] = {
            "call_id": str(uuid.uuid4()), "agent": agent, "agent_id": agent.agent_id,
            "identified_by": method, "client_ip": ip, "stream": stream, "provider": provider,
            "n_messages": len(messages), "request_delta": delta,
        }
        self.store.execute(
            "UPDATE agents SET last_seen=%s, n_llm_calls=n_llm_calls+1, model=%s WHERE agent_id=%s",
            (ts, body.get("model"), agent.agent_id),
        )
        # Tool results the agent sends back = outcome of its previous tool calls.
        for r in ap.tool_results(delta):
            tid = r["tool_use_id"]
            if not tid or tid in self.resolved_results:
                continue
            self.resolved_results.add(tid)
            self.store.execute(
                "UPDATE tool_calls SET ts_result=%s, result_content=%s, result_is_error=%s"
                " WHERE tool_use_id=%s AND ts_result IS NULL",
                (ts, trunc(r["content"]), r["is_error"], tid),
            )
        if self.stopped(agent.agent_id, tag):
            reply = killswitch.openai_reply if provider == "openai" else killswitch.anthropic_reply
            content, ctype = reply(stream, body.get("model"))
            from mitmproxy import http
            flow.response = http.Response.make(200, content, {"content-type": ctype})
            flow.metadata["obs_killed"] = True
            flow.metadata["obs_blocked"] = True
            flow.metadata["obs_block_reason"] = killswitch.BLOCK_REASON

    def _register_agent(self, agent_id, provider, model, info, ip, session, ts) -> None:
        running = [{"agent_id": r["agent_id"], "tool_use_id": r["tool_use_id"]}
                   for r in self.tracker.running_tools(ip)]
        self.store.execute(
            "INSERT INTO agents (agent_id, session_id, parent_session_id, client_ip, client_host,"
            " provider, model, system_prompt_hash, system_prompt, first_prompt, tools_offered,"
            " running_tools_at_start, first_seen, last_seen, n_llm_calls)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)"
            " ON CONFLICT (agent_id) DO NOTHING",
            (agent_id, session, info.get("parent"), ip, self.client_host(ip), provider, model,
             ap.sha(info["system"]),
             trunc(info["system"]), trunc(info["task"]), info["tools"], jsonb(running), ts, ts),
        )

    def _on_llm_response(self, flow) -> None:
        meta = flow.metadata["obs_llm"]
        ts_resp = now()
        latency = int((time.monotonic() - flow.metadata["obs_t0"]) * 1000)
        resp = flow.response
        if resp is None:  # connection error, timeout...
            parsed = ap.ParsedResponse(error=flow.error.msg if flow.error else "no response")
            status, request_id = None, None
        else:
            parse = op.parse_response if meta.get("provider") == "openai" else ap.parse_response
            parsed = parse(resp.get_content() or b"", resp.headers.get("content-type", ""))
            if flow.metadata.get("obs_killed"):
                parsed.error = "stopped by the operator (kill switch)"
            if resp.status_code >= 400 and not parsed.error:
                parsed.error = trunc(resp.get_text(strict=False), 4000)
            status, request_id = resp.status_code, resp.headers.get("request-id")
        self.tracker.response_received(meta["agent"], ok=status is not None and status < 400
                                       and not parsed.error, tool_uses=parsed.tool_uses())
        u = parsed.usage
        self.store.execute(
            "INSERT INTO llm_calls (call_id, agent_id, provider, identified_by, ts_request,"
            " ts_response, latency_ms, status_code, api_request_id, message_id, model, stream,"
            " n_messages, request_delta, response_content, response_text, thinking_text,"
            " stop_reason, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,"
            " error) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (meta["call_id"], meta["agent_id"], meta.get("provider", "anthropic"),
             meta["identified_by"], flow.metadata["obs_ts"],
             ts_resp, latency, status, request_id, parsed.message_id, parsed.model,
             meta["stream"], meta["n_messages"], jsonb(meta["request_delta"]),
             jsonb(parsed.content), trunc(parsed.text), trunc(parsed.thinking),
             parsed.stop_reason, u.get("input_tokens"), u.get("output_tokens"),
             u.get("cache_read_input_tokens"), u.get("cache_creation_input_tokens"),
             parsed.error),
        )
        for tu in parsed.tool_uses():
            if not tu["id"]:
                continue
            self.store.execute(
                "INSERT INTO tool_calls (tool_use_id, agent_id, call_id, ts, tool_name,"
                " is_server_tool, tool_input) VALUES (%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (tool_use_id) DO NOTHING",
                (tu["id"], meta["agent_id"], meta["call_id"], ts_resp, tu["name"] or "?",
                 tu["server"], jsonb(tu["input"])),
            )
        for r in parsed.server_tool_results():
            self.resolved_results.add(r["tool_use_id"])
            self.store.execute(
                "UPDATE tool_calls SET ts_result=%s, result_content=%s, result_is_error=%s"
                " WHERE tool_use_id=%s",
                (ts_resp, trunc(json.dumps(r["content"], ensure_ascii=False)),
                 isinstance(r["content"], dict)
                 and str(r["content"].get("type", "")).endswith("_error"),
                 r["tool_use_id"]),
            )

    # -- all HTTP traffic ---------------------------------------------------
    def _log_http(self, flow) -> None:
        req, resp = flow.request, flow.response
        ip = norm_ip(flow.client_conn.peername[0])
        meta = flow.metadata.get("obs_llm")
        is_llm = meta is not None
        if is_llm:
            agent_id, tool_use_id = meta["agent_id"], None
            attribution, candidates = meta["identified_by"], [meta["agent_id"]]
        else:
            a = flow.metadata.get("obs_attr") or self.tracker.attribute(
                ip, req.pretty_host, flow.metadata.get("obs_tag"), req.pretty_url)
            agent_id, tool_use_id, attribution, candidates = (
                a.agent_id, a.tool_use_id, a.method, a.candidates)
        preview = None
        if not is_llm and req.raw_content:
            preview = req.raw_content[:BODY_PREVIEW].decode("utf-8", "replace")
        t0 = flow.metadata.get("obs_t0")
        err = flow.error.msg if flow.error else flow.metadata.get("obs_block_reason")
        self.store.execute(
            "INSERT INTO http_requests (ts, client_ip, client_host, method, scheme, host, port,"
            " path, url, user_agent, req_content_type, req_bytes, req_body_preview, status_code,"
            " resp_content_type, resp_bytes, duration_ms, is_llm_api, llm_call_id, agent_id,"
            " tool_use_id, attribution, candidate_agent_ids, proxy_tag, blocked, error)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (flow.metadata.get("obs_ts") or now(), ip, self.client_host(ip), req.method,
             req.scheme, req.pretty_host, req.port, trunc(req.path, 8000),
             trunc(req.pretty_url, 8000), req.headers.get("user-agent"),
             req.headers.get("content-type"), len(req.raw_content or b""), preview,
             resp.status_code if resp else None,
             resp.headers.get("content-type") if resp else None,
             len(resp.raw_content or b"") if resp else None,
             int((time.monotonic() - t0) * 1000) if t0 else None,
             is_llm, meta and meta["call_id"], agent_id, tool_use_id, attribution, candidates,
             flow.metadata.get("obs_tag"), bool(flow.metadata.get("obs_blocked")), err),
        )


def _make_default() -> ObsAddon:
    dsn = os.environ.get("OBS_DB_DSN")
    if not dsn:
        raise RuntimeError("OBS_DB_DSN is not set")
    return ObsAddon(Store(dsn), kill=killswitch.KillSwitch(dsn))


addons = [_make_default()] if os.environ.get("OBS_DB_DSN") else []
