"""Pure parsing of Anthropic Messages API traffic seen by the proxy.

No I/O here: everything takes bytes/dicts and returns plain data, so it can be
unit-tested without mitmproxy or a database.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

_SESSION_RE = re.compile(r"session_([0-9a-fA-F-]{36})")

def is_messages_call(method: str, host: str, path: str) -> bool:
    """True for a Messages API generation call (not count_tokens, batches...)."""
    if method != "POST" or not host.endswith("anthropic.com"):
        return False
    p = path.split("?", 1)[0].rstrip("/")
    return p == "/v1/messages"


def block_text(content: Any) -> str:
    """Flatten a message `content` (str or list of blocks) to plain text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for b in content:
        if not isinstance(b, dict):
            continue
        t = b.get("type")
        if t == "text":
            parts.append(b.get("text", ""))
        elif t == "tool_result":
            parts.append(block_text(b.get("content")))
    return "\n".join(parts)


def session_id_from(body: dict, headers: dict[str, str]) -> str | None:
    """Claude Code session id, from a header or from metadata.user_id."""
    for k, v in headers.items():
        if k.lower() == "x-claude-code-session-id" and v:
            return v
    uid = (body.get("metadata") or {}).get("user_id")
    if not uid:
        return None
    if isinstance(uid, str):
        m = _SESSION_RE.search(uid)
        if m:
            return m.group(1)
        try:  # some versions send a JSON string
            j = json.loads(uid)
            if isinstance(j, dict) and j.get("session_id"):
                return str(j["session_id"])
        except (ValueError, TypeError):
            pass
    return str(uid)


def first_user_text(messages: list[dict]) -> str:
    for m in messages:
        if m.get("role") == "user":
            return block_text(m.get("content"))
    return ""


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def system_text(system: Any) -> str:
    if system is None:
        return ""
    if isinstance(system, str):
        return system
    return "\n".join(b.get("text", "") for b in system if isinstance(b, dict))


def tool_results(messages: list[dict]) -> list[dict]:
    """All tool_result blocks in the request history."""
    out = []
    for m in messages:
        if m.get("role") != "user" or not isinstance(m.get("content"), list):
            continue
        for b in m["content"]:
            if isinstance(b, dict) and b.get("type") == "tool_result":
                out.append(
                    {
                        "tool_use_id": b.get("tool_use_id"),
                        "content": block_text(b.get("content")),
                        "is_error": bool(b.get("is_error", False)),
                    }
                )
    return out


@dataclass
class ParsedResponse:
    message_id: str | None = None
    model: str | None = None
    stop_reason: str | None = None
    usage: dict = field(default_factory=dict)
    content: list[dict] = field(default_factory=list)  # assembled content blocks
    error: str | None = None

    @property
    def text(self) -> str:
        return "\n".join(b.get("text", "") for b in self.content if b.get("type") == "text")

    @property
    def thinking(self) -> str:
        return "\n".join(
            b.get("thinking", "") for b in self.content if b.get("type") == "thinking"
        )

    def tool_uses(self) -> list[dict]:
        """client tool_use and server_tool_use blocks (name, id, input, server)."""
        out = []
        for b in self.content:
            if b.get("type") in ("tool_use", "server_tool_use"):
                out.append(
                    {
                        "id": b.get("id"),
                        "name": b.get("name"),
                        "input": b.get("input") or {},
                        "server": b.get("type") == "server_tool_use",
                    }
                )
        return out

    def server_tool_results(self) -> list[dict]:
        """Results of server tools (web_search, web_fetch...) found in the response."""
        out = []
        for b in self.content:
            t = b.get("type", "")
            if t.endswith("_tool_result") and b.get("tool_use_id"):
                out.append({"tool_use_id": b["tool_use_id"], "type": t, "content": b.get("content")})
        return out


def _merge_usage(dst: dict, src: dict | None) -> None:
    for k, v in (src or {}).items():
        if v is not None:
            dst[k] = v


def parse_json_response(data: dict) -> ParsedResponse:
    r = ParsedResponse()
    if data.get("type") == "error":
        r.error = json.dumps(data.get("error"))
        return r
    r.message_id = data.get("id")
    r.model = data.get("model")
    r.stop_reason = data.get("stop_reason")
    _merge_usage(r.usage, data.get("usage"))
    r.content = list(data.get("content") or [])
    return r


def parse_sse_response(raw: str) -> ParsedResponse:
    """Rebuild the final message from a streamed (SSE) Messages API response."""
    r = ParsedResponse()
    blocks: dict[int, dict] = {}
    partial_json: dict[int, list[str]] = {}
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            ev = json.loads(payload)
        except ValueError:
            continue
        t = ev.get("type")
        if t == "message_start":
            msg = ev.get("message") or {}
            r.message_id = msg.get("id")
            r.model = msg.get("model")
            _merge_usage(r.usage, msg.get("usage"))
        elif t == "content_block_start":
            i = ev.get("index", len(blocks))
            blocks[i] = dict(ev.get("content_block") or {})
        elif t == "content_block_delta":
            i = ev.get("index")
            d = ev.get("delta") or {}
            b = blocks.setdefault(i, {})
            dt = d.get("type")
            if dt == "text_delta":
                b["text"] = b.get("text", "") + d.get("text", "")
            elif dt == "thinking_delta":
                b["thinking"] = b.get("thinking", "") + d.get("thinking", "")
            elif dt == "signature_delta":
                b["signature"] = d.get("signature")
            elif dt == "input_json_delta":
                partial_json.setdefault(i, []).append(d.get("partial_json", ""))
            elif dt == "citations_delta":
                b.setdefault("citations", []).append(d.get("citation"))
        elif t == "message_delta":
            d = ev.get("delta") or {}
            if d.get("stop_reason"):
                r.stop_reason = d["stop_reason"]
            _merge_usage(r.usage, ev.get("usage"))
        elif t == "error":
            r.error = json.dumps(ev.get("error"))
    for i, parts in partial_json.items():
        s = "".join(parts)
        try:
            blocks[i]["input"] = json.loads(s) if s else {}
        except ValueError:
            blocks[i]["input"] = {"_unparsed": s}
    r.content = [blocks[i] for i in sorted(blocks)]
    return r


def parse_response(body: bytes | str, content_type: str) -> ParsedResponse:
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    if "text/event-stream" in (content_type or ""):
        return parse_sse_response(text)
    try:
        return parse_json_response(json.loads(text))
    except ValueError:
        r = ParsedResponse()
        r.error = f"unparseable response ({len(text)} chars)"
        return r
