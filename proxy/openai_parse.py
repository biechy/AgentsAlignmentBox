"""Pure parsing of OpenAI Responses API traffic (Codex CLI) seen by the proxy.

Codex talks to `POST api.openai.com/v1/responses` (API key) or
`POST chatgpt.com/backend-api/codex/responses` (ChatGPT sign-in). Both use the
Responses API: the request carries the whole conversation as `input` items, the
response is a stream of `response.*` events.

Everything is converted to the Anthropic shape used by the rest of the proxy
(anthropic_parse.ParsedResponse, messages with text / tool_use / tool_result
blocks), so identity.py, the database and the monitor treat Claude Code and Codex
agents the same way. A Responses API `call_id` plays the role of a `tool_use` id.
No I/O here.
"""
from __future__ import annotations

import json
from typing import Any

import anthropic_parse as ap

CALL_TYPES = ("function_call", "custom_tool_call", "local_shell_call")
OUTPUT_TYPES = ("function_call_output", "custom_tool_call_output", "local_shell_call_output")
SERVER_TYPES = ("web_search_call", "file_search_call", "image_generation_call",
                "code_interpreter_call")
# User messages Codex adds around the real task (environment, AGENTS.md, permissions).
WRAPPER_PREFIXES = ("<environment_context>", "<user_instructions>", "# AGENTS.md instructions",
                    "<permissions instructions>", "<user_shell_command>", "<turn_aborted>")


def is_responses_call(method: str, host: str, path: str) -> bool:
    if method != "POST":
        return False
    p = path.split("?", 1)[0].rstrip("/")
    if host == "api.openai.com" or host.endswith(".openai.com"):
        return p == "/v1/responses"
    if host == "chatgpt.com" or host.endswith(".chatgpt.com"):
        return p.endswith("/codex/responses")
    return False


def _text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts = []
    for c in content:
        if isinstance(c, dict) and c.get("type") in ("input_text", "output_text", "text",
                                                      "summary_text", "reasoning_text"):
            parts.append(c.get("text", ""))
    return "\n".join(parts)


def _args(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return {"_raw": raw}
    return raw if raw is not None else {}


def call_block(item: dict) -> dict | None:
    """A tool call item as an Anthropic tool_use / server_tool_use block."""
    t = item.get("type")
    if t == "function_call":
        return {"type": "tool_use", "id": item.get("call_id"), "name": item.get("name"),
                "input": _args(item.get("arguments"))}
    if t == "custom_tool_call":
        return {"type": "tool_use", "id": item.get("call_id"), "name": item.get("name"),
                "input": {"input": item.get("input")}}
    if t == "local_shell_call":
        return {"type": "tool_use", "id": item.get("call_id") or item.get("id"),
                "name": "local_shell", "input": item.get("action") or {}}
    if t in SERVER_TYPES:
        inp = {k: v for k, v in item.items() if k not in ("type", "id", "status")}
        return {"type": "server_tool_use", "id": item.get("id"), "name": t.removesuffix("_call"),
                "input": inp}
    return None


def system_text(body: dict) -> str:
    parts = [body.get("instructions") or ""]
    for item in body.get("input") or []:
        if isinstance(item, dict) and item.get("type", "message") == "message" \
                and item.get("role") in ("system", "developer"):
            parts.append(_text(item.get("content")))
    return "\n\n".join(p for p in parts if p)


def to_messages(body: dict) -> list[dict]:
    """The request's `input` as Anthropic-style messages (consecutive roles merged)."""
    items = body.get("input")
    if isinstance(items, str):
        items = [{"type": "message", "role": "user", "content": items}]
    out: list[dict] = []

    def add(role: str, block: dict) -> None:
        if out and out[-1]["role"] == role:
            out[-1]["content"].append(block)
        else:
            out.append({"role": role, "content": [block]})

    for item in items or []:
        if not isinstance(item, dict):
            continue
        t = item.get("type", "message")
        if t == "message":
            role = item.get("role")
            if role in ("user", "assistant"):
                add(role, {"type": "text", "text": _text(item.get("content"))})
        elif t in CALL_TYPES or t in SERVER_TYPES:
            b = call_block(item)
            if b and b["id"]:
                add("assistant", b)
        elif t in OUTPUT_TYPES:
            output = item.get("output")
            if isinstance(output, dict):  # local shell / structured output
                output = output.get("output", json.dumps(output))
            add("user", {"type": "tool_result", "tool_use_id": item.get("call_id"),
                         "content": output if isinstance(output, str) else _text(output),
                         "is_error": False})
    return out


def task_text(messages: list[dict]) -> str:
    """First user text that is not one of Codex's context wrappers."""
    for m in messages:
        if m.get("role") != "user":
            continue
        for b in m["content"]:
            if b.get("type") == "text":
                t = (b.get("text") or "").strip()
                if t and not t.startswith(WRAPPER_PREFIXES):
                    return t
    return ap.first_user_text(messages)


def session_id_from(body: dict, headers: dict[str, str]) -> str | None:
    """Codex conversation id: `prompt_cache_key`, else the session / conversation header."""
    if body.get("prompt_cache_key"):
        return str(body["prompt_cache_key"])
    low = {k.lower(): v for k, v in headers.items()}
    return low.get("session_id") or low.get("conversation_id") or None


def parent_session_from(headers: dict[str, str]) -> str | None:
    """Thread id of the Codex agent that started this one (Codex sub-agents)."""
    low = {k.lower(): v for k, v in headers.items()}
    return low.get("x-codex-parent-thread-id") or None


def tool_names(body: dict) -> list[str]:
    names = []
    for t in body.get("tools") or []:
        if isinstance(t, dict):
            names.append(t.get("name") or (t.get("function") or {}).get("name") or t.get("type"))
    return [n for n in names if n]


def _usage(u: dict | None) -> dict:
    """OpenAI counts cached tokens inside input_tokens; Anthropic counts them apart."""
    u = u or {}
    cached = (u.get("input_tokens_details") or {}).get("cached_tokens")
    inp = u.get("input_tokens")
    return {"input_tokens": inp - (cached or 0) if inp is not None else None,
            "output_tokens": u.get("output_tokens"), "cache_read_input_tokens": cached}


def _from_response(resp: dict, r: ap.ParsedResponse) -> None:
    r.message_id = resp.get("id") or r.message_id
    r.model = resp.get("model") or r.model
    r.stop_reason = resp.get("status") or r.stop_reason
    if resp.get("usage"):
        r.usage = {k: v for k, v in _usage(resp["usage"]).items() if v is not None}
    if resp.get("error"):
        r.error = json.dumps(resp["error"])
    if resp.get("output"):
        r.content = output_blocks(resp["output"])


def output_blocks(items: list[dict]) -> list[dict]:
    blocks = []
    for item in items:
        if not isinstance(item, dict):
            continue
        t = item.get("type")
        if t == "message":
            blocks.append({"type": "text", "text": _text(item.get("content"))})
        elif t == "reasoning":
            text = _text(item.get("summary")) or _text(item.get("content"))
            if text:
                blocks.append({"type": "thinking", "thinking": text})
        else:
            b = call_block(item)
            if b:
                blocks.append(b)
    return blocks


def parse_sse_response(raw: str) -> ap.ParsedResponse:
    r = ap.ParsedResponse()
    done_items: list[dict] = []
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
        t = ev.get("type", "")
        if t in ("response.created", "response.in_progress"):
            _from_response(ev.get("response") or {}, r)
        elif t == "response.output_item.done":
            done_items.append(ev.get("item") or {})
        elif t in ("response.completed", "response.incomplete", "response.failed"):
            _from_response(ev.get("response") or {}, r)
            if t == "response.failed" and not r.error:
                r.error = json.dumps((ev.get("response") or {}).get("error") or "response.failed")
        elif t == "error":
            r.error = json.dumps(ev.get("error") or ev)
    if not r.content and done_items:  # the final event may omit `output`
        r.content = output_blocks(done_items)
    return r


def parse_response(body: bytes | str, content_type: str) -> ap.ParsedResponse:
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    if "text/event-stream" in (content_type or ""):
        return parse_sse_response(text)
    try:
        data = json.loads(text)
    except ValueError:
        r = ap.ParsedResponse()
        r.error = f"unparseable response ({len(text)} chars)"
        return r
    r = ap.ParsedResponse()
    if isinstance(data, dict) and data.get("error") and not data.get("output"):
        r.error = json.dumps(data["error"])
        return r
    _from_response(data if isinstance(data, dict) else {}, r)
    return r
